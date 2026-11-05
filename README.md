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
- [ ] CISA Known Exploited Vulnerabilities (KEV) catalog enrichment
- [ ] EPSS (Exploit Prediction Scoring System) enrichment
- [ ] SLA tracking by severity and asset tier
- [ ] Owner assignment and notifications
- [ ] Executive reporting: closure rate, MTTR, risk trend
- [ ] Scanner integrations (e.g., Tenable, Qualys, Rapid7, Snyk)
- [ ] Ticketing integrations (e.g., Jira, ServiceNow)
- [ ] Exception and risk-acceptance workflow

---

## Framework Alignment

VulnHQ is designed to support practices from:

| Framework | How VulnHQ Supports It |
|---|---|
| **NIST SP 800-40 Rev. 4** | Enterprise patch management planning, prioritization, and remediation tracking |
| **Executive Order 14028** | Faster vulnerability response and improved visibility into software risk |
| **CISA BOD 22-01** | Prioritizing Known Exploited Vulnerabilities with defined remediation timelines |
| **Gartner CTEM** | Continuous scoping, discovery, prioritization, validation, and mobilization |

---

## Prioritization Model (Draft)

Each finding receives a VulnHQ Risk Score based on:

| Factor | Example Inputs |
|---|---|
| **Severity** | CVSS base score |
| **Exploitability** | CISA KEV listing, EPSS probability, public exploit available |
| **Asset criticality** | Business tier, data sensitivity, production vs. non-production |
| **Exposure** | Internet-facing, internal, segmented |
| **Age** | Days open vs. SLA target |

> The scoring weights are configurable and will be documented in `docs/scoring.md` (coming soon).

---

## Tech Stack

> Update as the stack is finalized.

| Layer | Technology |
|---|---|
| Frontend | TBD (e.g., React) |
| Backend | TBD (e.g., Python / Flask or FastAPI) |
| Database | TBD (e.g., PostgreSQL) |
| Testing | TBD (e.g., pytest, Jest, Playwright) |
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

If you discover a security issue in VulnHQ, please **do not open a public issue**. Report it privately via the repository's Security tab (a `SECURITY.md` policy is coming soon).

---

## License

License to be determined.

© 2026 Cyber Christy LLC. All rights reserved.
