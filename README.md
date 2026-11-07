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
- [x] Import assets and findings (JSON), with software-version to CVE matching (vetted rules plus live NVD lookup). See [importing](docs/importing.md).
- [x] Asset inventory with business criticality ratings (business context file)
- [x] Risk-based prioritization score (0 to 100, with factor breakdown)
- [x] Ranked fix list page with tier filters (Critical / High / Medium / Low)
- [x] Score details panel showing why each finding ranks where it does
- [x] Dashboard KPI cards (critical open, known exploited, overdue, stale scans, open findings)
- [x] Confidence column on every finding (confirmed / conditional / nvd)
- [x] Assets page with stale-scan flags, asset details panel and an "Add software" form
- [x] JSON import page in the UI (inventory and business context), with a check for files that have no software
- [x] Sidebar navigation; side panels close with Escape
- [ ] Dark mode
- [ ] Remediation status tracking (Open → In Progress → Fixed → Verified)

### Planned
- [x] CISA Known Exploited Vulnerabilities (KEV) catalog enrichment
- [x] EPSS (Exploit Prediction Scoring System) enrichment
- [x] SLA due dates by remediation tier (fix-by date, days remaining, overdue flag)
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
| CI/CD | GitHub Actions (planned) |

---

## Getting Started

### Prerequisites
- Git
- Python 3.12
- Node.js 20+
- PostgreSQL 16

### Installation (Windows PowerShell)

```powershell
# Clone the repository
git clone https://github.com/CyberChristy919/vulnhq.git
cd vulnhq

# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Frontend
cd ..\frontend
npm install
```

Create `backend/.env` (never commit it):

```
DATABASE_URL=postgresql+psycopg://postgres:<password>@localhost:5432/vulnapp
NVD_API_KEY=
```

A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) makes live NVD lookups about 10 times faster. It is optional.

### Loading Data

Run these from the `backend` folder with the virtual environment active:

```powershell
python -m scripts.migrate_db        # add any new database columns
python -m scripts.load_kev          # CISA KEV catalog
python -m scripts.import_inventory <inventory.json> --context <context.json>
python -m scripts.load_epss         # EPSS scores (takes a few minutes)
```

Other helpers:

| Script | What it does |
|---|---|
| `scripts.check_nvd` | Checks that the NVD API is reachable before a demo |
| `scripts.add_software` | Adds one software item to an asset and matches it to CVEs |
| `scripts.reset_demo` | Clears all demo data (type `RESET` to confirm) |

See [importing](docs/importing.md) for file formats.

### Running Locally

Use two terminals.

```powershell
# Terminal 1: API on http://127.0.0.1:8000 (docs at /docs)
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload

# Terminal 2: UI on http://localhost:5173
cd frontend
npm run dev
```

The Vite dev server forwards `/api/*` requests to the FastAPI backend.

**Troubleshooting:** If the API hangs after terminals were closed, stuck Python processes may be holding the database. Run `Stop-Process -Name python -Force`, then start uvicorn again.

### Using VulnHQ

| Page | What it shows |
|---|---|
| **Fix list** | KPI cards, then findings ranked by risk score, with tier filters. Click a row for the score breakdown. |
| **Assets** | Every asset, riskiest first. Scans older than 90 days are flagged. Click an asset to see its software and add new software, which is checked for CVEs right away. |
| **Import** | Upload an asset inventory JSON, then a business context JSON. Shows what was created, plus software that couldn't be checked or needs review. |

**Confidence** tells you how sure VulnHQ is that a CVE applies to that software version:

| Confidence | Meaning |
|---|---|
| **confirmed** | A vetted rule matches this exact version, with no special configuration needed |
| **conditional** | The version is affected, but exploitation needs a specific setting; check the configuration |
| **nvd** | Matched from a live NVD lookup and not yet reviewed by a vetted rule |

The risk score says how bad a finding would be. Confidence says how sure we are that it applies.

### Demo Walkthrough

1. Reset: `python -m scripts.reset_demo` (type `RESET`). CVE, KEV and EPSS data are kept.
2. **Import** page: import the inventory file, then the business context file. Context moves findings on payment and sensitive-data systems up a tier.
3. **Fix list**: walk through the top findings and open one to show why it ranks there.
4. **Assets**: point out stale scans on critical systems.
5. Add software live on the **Assets** page and show the new finding appear in the fix list.

### Running Tests

```powershell
cd backend
pytest
```

---

## Project Structure

```
vulnhq/
├── backend/
│   ├── app/           # FastAPI app: models, scoring, KEV/EPSS/NVD matching, API
│   ├── data/          # Matching rules and CPE aliases
│   ├── scripts/       # Load, import, migrate and reset scripts
│   └── tests/         # pytest tests
├── frontend/
│   └── src/           # React UI: App.tsx (sidebar), FixListPage, AssetsPage, ImportPage,
│                      #   KpiCards, ScoreDetails and AssetDetails panels, useEscape hook
├── src/styles/        # Shared design tokens (base.css)
├── docs/              # Scoring model, design guide, importing, framework alignment
├── sample-data/       # Demo assets (private/ is gitignored and never committed)
└── README.md
```

---

## Progress

**Done so far**
- Backend: data model, KEV and EPSS enrichment, risk scoring, SLA due dates, inventory import with vetted rules plus live NVD lookup, business context import
- Backend API: fix list (with tier and hostname filters), assets summary, dashboard stats, add software, JSON imports
- Frontend: sidebar navigation; Fix list with KPI cards, tier filters, confidence column and score details panel; Assets page with details panel and "Add software" form; Import page; Escape closes panels

**Next up**
- Dark mode
- Compare progress against the assignment and the SRS
- GitHub Actions CI
- Remediation status tracking

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
