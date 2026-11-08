# VulnHQ Risk Score

Every finding (an asset that has a specific CVE) receives a **VulnHQ Risk Score from 0 to 100**. The score ranks the Fix List and sets the remediation tier and due date.

The model favors **real-world exploitation and business impact over theoretical severity**, consistent with CISA BOD 26-04, NIST SP 800-40 Rev. 4 and NIST CSF 2.0 ID.RA-04 / ID.RA-05.

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

## CISA BOD 26-04 Deadline (Shown Next to the Score)

The VulnHQ score and tier are the company's own ranking and SLA. Each finding also shows the federal deadline from [CISA BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk), which replaced BOD 22-01 in June 2026. The two are kept separate so a finding can be inside the company SLA and still past CISA's date, or the other way around.

The BOD 26-04 tier comes from four inputs, looked up in the versioned matrix file [`bod2604_matrix.json`](../backend/data/bod2604_matrix.json) (CISA Table 1):

| Input | Source in VulnHQ |
|---|---|
| **Exposed** | Asset or application `internet_facing` |
| **In KEV** | CISA KEV catalog |
| **Automatable** | CISA Vulnrichment SSVC, stored on each vetted rule in `vuln_rules.json` |
| **Technical impact** | CISA Vulnrichment SSVC (`total` or `partial`) |

| BOD tier | Remediation timeline |
|---|---|
| 1 | 3 days and forensic triage |
| 2 | 3 days |
| 3 | 14 days |
| 4 | 60 days |
| 5 | Fix on system upgrade |

- **Clock start:** the earlier of the date the finding was first seen and the date CISA added the CVE to KEV.
- **Unknown inputs:** when CISA has not scored a CVE, VulnHQ evaluates every possible value and uses the most urgent tier, then labels the finding "Assumed worst case" with the assumed fields listed.
- **Effective date:** BOD 26-04 timelines apply to federal agencies from December 7, 2026 ([FedRAMP notice 0014](https://www.fedramp.gov/notices/0014/)). Before then, the dates show what the deadline will be.

### KEV Past Due

Separately, every KEV finding shows CISA's KEV due date, and a **KEV past due** flag when that date has passed. The KPI card counts past-due findings and affected assets. This is independent of the VulnHQ "Overdue" flag, which measures the company SLA.

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
