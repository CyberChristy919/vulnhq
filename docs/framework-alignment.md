# VulnHQ Framework Alignment

VulnHQ is aligned to two framework families:

1. **NIST Cybersecurity Framework (CSF) 2.0**, which covers **what the program achieves**. VulnHQ features map to CSF outcomes, so teams can show progress in CSF terms.
2. **OWASP**, which covers **how application risk is classified and how VulnHQ itself is built**. Findings are tagged to the OWASP Top 10, risk can be scored with the OWASP Risk Rating Methodology, and VulnHQ is developed against OWASP ASVS.

It also supports NIST SP 800-40 Rev. 4, Executive Order 14028, CISA BOD 26-04 (which replaced BOD 22-01 in June 2026) and Gartner CTEM (see the [README](../README.md#framework-alignment)).

---

## 1. NIST CSF 2.0

Reference: [NIST CSWP 29, The NIST Cybersecurity Framework (CSF) 2.0](https://doi.org/10.6028/NIST.CSWP.29) (February 26, 2024).

### 1.1 Feature-to-Outcome Mapping

| CSF Function | Category / Subcategory | VulnHQ Capability |
|---|---|---|
| **Govern (GV)** | GV.RM: Risk Management Strategy | Configurable risk appetite, SLA targets by severity and asset tier |
| | GV.RR: Roles, Responsibilities, and Authorities | Finding owners, team assignment, approvers for risk acceptance |
| | GV.OV: Oversight | Executive dashboards: closure rate, MTTR, risk trend, SLA compliance |
| **Identify (ID)** | ID.AM-01 / ID.AM-02: Hardware and software inventories | Asset inventory (hosts, applications, cloud resources, software components) |
| | ID.AM-05: Assets prioritized by classification, criticality and impact | Asset criticality tiers feed the VulnHQ Risk Score |
| | **ID.RA-01**: Vulnerabilities in assets are identified, validated, and recorded | Import and de-duplicate scanner, SAST, DAST, SCA and pentest findings; validation status |
| | **ID.RA-02**: Cyber threat intelligence is received | CISA KEV and EPSS enrichment |
| | **ID.RA-03**: Internal and external threats are identified and recorded | Threat context on findings (known exploitation, ransomware use, exploit availability) |
| | **ID.RA-04**: Impacts and likelihoods are identified and recorded | Likelihood (EPSS, KEV, exposure) × impact (asset criticality, data sensitivity) |
| | **ID.RA-05**: Threats, vulnerabilities, likelihoods and impacts inform risk response prioritization | **VulnHQ Risk Score and ranked Fix List**, the core of the product |
| | **ID.RA-06**: Risk responses are chosen, prioritized, planned, tracked and communicated | Remediate / mitigate / accept / transfer decisions, status workflow, notifications |
| | **ID.RA-07**: Changes and exceptions are managed, assessed, recorded and tracked | Exception and risk-acceptance workflow with approver, justification and expiration date |
| | **ID.RA-08**: Processes for receiving, analyzing and responding to vulnerability disclosures | Intake for externally reported vulnerabilities (VDP / bug bounty) into the same workflow |
| | ID.IM: Improvement | Trend reporting and lessons learned from recurring findings |
| **Protect (PR)** | PR.PS-01: Configuration management practices | Misconfiguration findings tracked alongside CVEs |
| | PR.PS-02: Software maintained, replaced and removed commensurate with risk | Patch and upgrade tracking; end-of-life software flags |
| | PR.PS-03: Hardware maintained, replaced and removed commensurate with risk | End-of-life hardware and firmware findings |
| **Detect (DE)** | DE.CM: Continuous Monitoring | Recurring imports and rescans; new-finding and regression alerts |
| **Respond (RS)** | RS.MI: Incident Mitigation | Emergency "drop everything" queue for actively exploited vulnerabilities |
| **Recover (RC)** | N/A | Out of scope. VulnHQ is a prevention and risk-reduction tool. |

### 1.2 CSF Reporting in VulnHQ

- Every finding, exception and report can be **tagged with CSF subcategory IDs**.
- A **CSF coverage view** shows which ID.RA outcomes have supporting evidence (findings recorded, risks prioritized, responses tracked, exceptions managed).
- Executive reports can be grouped by CSF Function for board and leadership audiences.

---

## 2. OWASP

### 2.1 OWASP Top 10:2025, Finding Classification

Reference: [OWASP Top 10:2025](https://top10.owasp.org/2025/).

Application security findings (SAST, DAST, pentest, bug bounty) are mapped to an OWASP Top 10:2025 category using their **CWE ID**.

| ID | Category | VulnHQ Use |
|---|---|---|
| A01:2025 | Broken Access Control | Tag, trend and prioritize |
| A02:2025 | Security Misconfiguration | Tag; also links to PR.PS-01 configuration findings |
| A03:2025 | Software Supply Chain Failures | Tag SCA / dependency findings; links to SBOM data |
| A04:2025 | Cryptographic Failures | Tag, trend and prioritize |
| A05:2025 | Injection | Tag, trend and prioritize |
| A06:2025 | Insecure Design | Tag; flag for architecture review rather than patching alone |
| A07:2025 | Authentication Failures | Tag, trend and prioritize |
| A08:2025 | Software or Data Integrity Failures | Tag, trend and prioritize |
| A09:2025 | Security Logging and Alerting Failures | Tag, trend and prioritize |
| A10:2025 | Mishandling of Exceptional Conditions | Tag, trend and prioritize |

**Features**
- CWE → OWASP Top 10 mapping table (`data/owasp-top10-2025-cwe-map.json`, planned).
- AppSec dashboard: open findings by Top 10 category, by application and by team.
- Recurring categories trigger a **"fix the root cause"** recommendation (for example, secure coding training or a shared library fix), not just ticket closure.

### 2.2 OWASP Risk Rating Methodology, Scoring Input

Reference: [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology).

For application findings without a reliable CVSS score (for example, business-logic flaws from a pentest), VulnHQ supports **OWASP Risk Rating** as an optional scoring method:

- **Likelihood** = threat agent factors + vulnerability factors
- **Impact** = technical impact + business impact
- **Overall severity** = Likelihood × Impact, mapped to Critical / High / Medium / Low / Info

### 2.3 OWASP ASVS 5.0, Building VulnHQ Securely

Reference: [OWASP Application Security Verification Standard 5.0.0](https://github.com/OWASP/ASVS) (May 2025).

VulnHQ stores highly sensitive data: a map of an organization's weaknesses. It must be secure by design.

- **Target:** ASVS 5.0 **Level 2** for all releases.
- **Verification:** ASVS requirements are tracked as GitHub issues and checked before each major release.
- **Priority controls:**

| Area | VulnHQ Requirement |
|---|---|
| Access control | Role-based access (Admin, Security Analyst, Remediation Owner, Executive Viewer); deny by default; per-team data scoping |
| Authentication | SSO (SAML / OIDC) and MFA; no shared accounts |
| Data protection | Encryption in transit (TLS 1.2+) and at rest; secrets in a vault, never in code |
| Input handling | Validate and sanitize all imported files (CSV, JSON, XML); parameterized queries only |
| Supply chain | Dependency scanning in CI, SBOM generated per release, pinned dependencies |
| Logging and alerting | Audit log for every status change, exception approval, export and login |
| Error handling | Fail closed; no stack traces or sensitive data in error messages |

### 2.4 OWASP Top 10:2025, Self-Check for VulnHQ

The same Top 10 list VulnHQ uses to classify findings also applies to VulnHQ's own code. Each category is covered in the CI/CD pipeline:

| Practice | Covers |
|---|---|
| SAST on every pull request | A01, A04, A05, A07, A10 |
| Dependency / SCA scanning and SBOM | A03, A08 |
| Infrastructure-as-code and config scanning | A02 |
| Threat modeling for new features | A06 |
| Audit-log tests | A09 |

### 2.5 Related OWASP Projects (Integration Candidates)

- **[OWASP Dependency-Track](https://dependencytrack.org/)**: import SBOM-based component vulnerabilities.
- **[OWASP ZAP](https://www.zaproxy.org/)**: import DAST findings.
- **[OWASP SAMM](https://owaspsamm.org/)**: optional maturity view for AppSec program reporting.

---

## 3. How It Shows Up in the UI

- **Framework tags** appear on findings as small outline chips (for example `CSF ID.RA-05`, `OWASP A05:2025`).
- Framework chips use the **calm palette** (Harbor background, Slate text), never severity colors. See the [design guide](design-guide.md#58-framework-tags).
- Reports can be filtered and grouped by CSF Function or OWASP Top 10 category.

---

© 2026 Cyber Christy LLC. All rights reserved.
