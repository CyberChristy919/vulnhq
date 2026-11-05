# VulnHQ

> **Find it. Rank it. Fix it. Prove it.**

VulnHQ is the headquarters for vulnerability management. Turn scanner noise into a ranked fix list, prioritize by real risk, drive remediation, and track every exposure to closure.

![Status](https://img.shields.io/badge/status-in%20development-orange)
![License](https://img.shields.io/badge/license-TBD-lightgrey)

---

## Why VulnHQ

Most security teams don't have a finding problem. They have a **prioritization problem**. Scanners produce thousands of results, CVSS scores treat everything as urgent, and remediation teams can't tell what to fix first.

VulnHQ flips the model: **stop patching everything and fix what matters first.**

- **Signal over noise:** Consolidate findings from multiple sources into one view.
- **Risk-based ranking:** Prioritize by exploitability, asset criticality, and exposure, not CVSS alone.
- **Remediation that moves:** Assign owners, track SLAs, and break down the backlog.
- **Proof for leadership:** Show risk reduction, closure rates, and mean time to remediate (MTTR).

---

## Features

### Current (MVP)
- [ ] Import vulnerability findings (CSV / JSON)
- [ ] Asset inventory with business criticality ratings
- [ ] Risk-based prioritization score
- [ ] Ranked fix list dashboard
- [ ] Remediation status tracking (Open → In Progress → Fixed → Verified)

### Planned
- [x] CISA Known Exploited Vulnerabilities (KEV) catalog enrichment
- [x] EPSS (Exploit Prediction Scoring System) enrichment
- [ ] SLA tracking by severity and asset tier
- [ ] Owner assignment and notifications
- [ ] Executive reporting: closure rate, MTTR, risk trend
- [ ] Scanner integrations (e.g., Tenable, Qualys, Rapid7, Snyk)
- [ ] Ticketing integrations (e.g., Jira, ServiceNow)
- [ ] Exception and risk-acceptance workflow
- [ ] NIST CSF 2.0 subcategory tagging and coverage view
- [ ] OWASP Top 10:2025 classification for AppSec findings
- [ ] OWASP Risk Rating scoring option

---

## Framework Alignment

VulnHQ is designed to support practices from:

| Framework | How VulnHQ Supports It |
|---|---|
| **NIST SP 800-40 Rev. 4** | Enterprise patch management planning, prioritization, and remediation tracking |
| **Executive Order 14028** | Faster vulnerability response and improved visibility into software risk |
| **CISA BOD 22-01** | Prioritizing Known Exploited Vulnerabilities with defined remediation timelines |
| **Gartner CTEM** | Continuous scoping, discovery, prioritization, validation, and mobilization |
| **NIST CSF 2.0** | Identify / Risk Assessment outcomes (ID.RA-01 to ID.RA-08), asset prioritization (ID.AM-05), governance oversight and reporting |
| **OWASP Top 10:2025** | AppSec findings classified by Top 10 category via CWE mapping |
| **OWASP Risk Rating Methodology** | Optional likelihood × impact scoring for findings without CVSS |
| **OWASP ASVS 5.0** | VulnHQ itself is built and verified to ASVS Level 2 |

See the full [framework alignment](docs/framework-alignment.md) mapping.

---

## Prioritization Model

Each finding receives a **VulnHQ Risk Score from 0 to 100**, weighted toward real-world exploitation and business impact:

| Factor | Max Points | Source |
|---|---|---|
| **Known exploited (CISA KEV)** | 25 | CISA KEV catalog |
| **Exploit likelihood (EPSS)** | 20 | FIRST EPSS probability × 20 |
| **Ransomware use** | 10 | CISA KEV |
| **Application criticality (1 to 5)** | 20 | Application inventory |
| **Internet exposure** | 10 | Application or asset |
| **Money movement** | 10 | None (0), internal transfers (5), outbound payments (10) |
| **Sensitive data (confidential / restricted)** | 5 | Application inventory |

### Remediation Tiers

| Tier | Score | Fix Within |
|---|---|---|
| **Critical** | 80 to 100 | 7 days |
| **High** | 60 to 79 | 30 days |
| **Medium** | 40 to 59 | 60 days |
| **Low** | Below 40 | 90 days |

Weights, thresholds and SLA days are configurable. See the full [scoring model](docs/scoring.md), including money movement levels, a worked example and planned enhancements (CVSS, age vs. SLA, exploit availability).

---

## Design

VulnHQ uses a calming base palette with standard red / orange / yellow / green severity colors. See the [design guide](docs/design-guide.md) for colors, typography, layout, components, voice and accessibility.

![VulnHQ color palette](docs/images/color-palette.png)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React + TypeScript (Vite) |
| Backend | Python 3.12, FastAPI, SQLAlchemy |
| Database | PostgreSQL 16 |
| Testing | pytest (backend); frontend testing TBD |
| CI/CD | GitHub Actions |

---

## Getting Started

### Prerequisites
- Git
- Python 3.11+ *(if using a Python backend)*
- Node.js 20+ *(if using a JavaScript frontend)*

### Installation

```bash
# Clone the repository
git clone https://github.com/CyberChristy919/vulnhq.git
cd vulnhq

# Install dependencies (update once the stack is finalized)
# pip install -r requirements.txt
# npm install
```

### Running Locally

```bash
# Update with the actual start commands
# python app.py
# npm run dev
```

### Running Tests

```bash
# Update with the actual test commands
# pytest
# npm test
```

---

## Project Structure

```
vulnhq/
├── docs/              # Documentation, scoring model, architecture
├── src/               # Application source code
├── tests/             # Unit, integration, and end-to-end tests
├── sample-data/       # Sample findings and assets for demos
├── .github/workflows/ # CI/CD pipelines
└── README.md
```

---

## Roadmap

1. **Foundation:** Data model, finding import, asset inventory
2. **Prioritization:** Risk scoring, KEV and EPSS enrichment, ranked fix list
3. **Remediation:** Status workflow, owners, SLAs
4. **Reporting:** Dashboards, MTTR, closure rate, risk trend
5. **Integrations:** Scanners, ticketing, notifications

---

## Contributing

Contributions, ideas, and feedback are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push the branch: `git push origin feature/your-feature`
5. Open a pull request

---

## Security

If you discover a security issue in VulnHQ, please **do not open a public issue**. Report it privately via the repository's [Security tab](https://github.com/CyberChristy919/vulnhq/security) and see the [security policy](SECURITY.md).

---

## License

License to be determined.

© 2026 Cyber Christy LLC. All rights reserved.
