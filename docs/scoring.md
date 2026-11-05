# VulnHQ Risk Score

Every finding (an asset that has a specific CVE) receives a **VulnHQ Risk Score from 0 to 100**. The score ranks the Fix List and sets the remediation tier and due date.

The model favors **real-world exploitation and business impact over theoretical severity**, consistent with CISA BOD 22-01, NIST SP 800-40 Rev. 4 and NIST CSF 2.0 ID.RA-04 / ID.RA-05.

---

## Score Factors

| Factor | Max Points | How It's Scored | Data Source |
|---|---|---|---|
| **Known exploited (KEV)** | 25 | 25 if the CVE is in the CISA KEV catalog, otherwise 0 | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **Exploit likelihood (EPSS)** | 20 | EPSS probability (0 to 1) × 20 | [FIRST EPSS](https://www.first.org/epss/) |
| **Ransomware use** | 10 | 10 if KEV lists known ransomware campaign use, otherwise 0 | CISA KEV |
| **Application criticality** | 20 | Criticality 1 to 5, scaled: (criticality ÷ 5) × 20 | Applications table |
| **Internet exposure** | 10 | 10 if the application or asset is internet-facing, otherwise 0 | Applications / Assets |
| **Money movement** | 10 | Based on the application's money movement level (below) | Applications table |
| **Data sensitivity** | 5 | 5 if data classification is `confidential` or `restricted`, otherwise 0 | Applications table |
| **Total** | **100** | | |

### Money Movement Levels

Money movement measures whether an application can **move funds**. It is scored separately from internet exposure: a public marketing site is internet-facing but moves no money, while an internal wire system moves money but is not internet-facing.

| Level | Meaning | Points |
|---|---|---|
| `none` | Does not move money | 0 |
| `internal_transfers` | Moves money between the organization's own accounts (e.g., general ledger, internal transfers) | 5 |
| `outbound_payments` | Sends money outside the organization (e.g., ACH, wires, card payments, bill pay, treasury) | 10 |

| Application | Internet-Facing | Money Movement | Exposure Points | Money Points |
|---|---|---|---|---|
| Public marketing site | Yes | `none` | 10 | 0 |
| Customer bill pay portal | Yes | `outbound_payments` | 10 | 10 |
| Internal wire transfer system | No | `outbound_payments` | 0 | 10 |
| General ledger | No | `internal_transfers` | 0 | 5 |
| HR intranet | No | `none` | 0 | 0 |

### Example

A KEV-listed CVE with ransomware use and an EPSS of 0.94, on an internet-facing, criticality-5 customer bill pay application holding confidential data:

| Factor | Points |
|---|---|
| KEV | 25 |
| EPSS (0.94 × 20) | 18.8 |
| Ransomware | 10 |
| Criticality (5 ÷ 5 × 20) | 20 |
| Internet-facing | 10 |
| Money movement (`outbound_payments`) | 10 |
| Confidential data | 5 |
| **Risk Score** | **98.8 → Critical, fix within 7 days** |

---

## Remediation Tiers and SLAs

| Tier | Score Range | Fix Within | Color |
|---|---|---|---|
| **Critical** | 80 to 100 | 7 days | Red |
| **High** | 60 to 79 | 30 days | Orange |
| **Medium** | 40 to 59 | 60 days | Yellow |
| **Low** | Below 40 | 90 days | Green |

The due date is calculated from the date the finding was first seen. Severity colors follow the [design guide](design-guide.md).

---

## Configuration

All weights, tier thresholds and SLA days live in one settings file in the backend so they can be tuned to an organization's risk appetite (NIST CSF 2.0 GV.RM) without code changes elsewhere.

---

## Planned Enhancements

| Enhancement | Purpose |
|---|---|
| **CVSS base score** | Add theoretical severity from NVD as a secondary factor |
| **Age vs. SLA** | Raise priority as a finding approaches or passes its due date |
| **Public exploit available** | Boost findings with published exploit code |
| **Production vs. non-production** | Lower priority for test and development assets |
| **OWASP Risk Rating** | Optional likelihood × impact scoring for AppSec findings without a CVE |
