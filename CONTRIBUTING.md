# Contributing to VulnHQ

Thank you for your interest in VulnHQ. This is a volunteer project: contributors build real experience on a working vulnerability-management app and get public credit for their work.

Before you start, please read:

- [Contributor agreement](CONTRIBUTOR_AGREEMENT.md): volunteer terms and rights to your contribution
- [Code of conduct](CODE_OF_CONDUCT.md): how we treat each other
- [Security policy](SECURITY.md): how to report security issues privately (never in a public issue)

---

## How Volunteering Works

| What you get | How it works |
|---|---|
| **Real-world experience** | Work on a FastAPI + React app built around CISA KEV, EPSS, NVD and BOD 26-04 |
| **Public credit** | Your name in the README contributors list and in release notes |
| **Recognition points** | Each merged pull request earns points (see below), shown on the contributors list |
| **References** | Consistent contributors can ask the maintainer for a LinkedIn recommendation or a reference |

VulnHQ contributions are **unpaid**. Points are for recognition only and have no cash value. See the [contributor agreement](CONTRIBUTOR_AGREEMENT.md) for details.

---

## Recognition Points

The maintainer adds a `points:*` label to each pull request when it is merged.

| Label | Contribution size | Examples |
|---|---|---|
| `points:1` | Small | Docs fixes, typos, small UI tweaks |
| `points:3` | Medium | A new test file, a bug fix, a new sample data set |
| `points:8` | Large | A new feature, a new import format, a significant refactor |
| `points:13` | Critical | A security fix, or approved changes to core ranking logic |

Reviewing pull requests, triaging issues and design work can also earn points through a tracking issue. Point values are set by the maintainer, and the maintainer's decision is final.

---

## Finding Something to Work On

1. Browse issues labeled [`good first issue`](https://github.com/CyberChristy919/vulnhq/labels/good%20first%20issue) or [`help wanted`](https://github.com/CyberChristy919/vulnhq/labels/help%20wanted).
2. Comment on the issue to ask for it. Wait for the maintainer to assign it before starting, so two people don't build the same thing.
3. For a new idea, open a **Feature request** issue first and wait for a go-ahead.

**Maintainer-owned areas.** Changes to the scoring weights and tiers (`backend/app/scoring.py`, `docs/scoring.md`), the BOD 26-04 matrix (`backend/data/bod2604_matrix.json`), the vetted rules (`backend/data/vuln_rules.json`) and the Ask router design need an approved issue first. Tests and documentation for these areas are always welcome.

---

## Setting Up Locally

Follow [Getting Started](README.md#getting-started) in the README, or the step-by-step [Setup Lab Guide](docs/lab-guide.md) for Windows.

**Use only fictional data.** Use the files in [`sample-data/`](sample-data/). Never commit real company data, real hostnames or IP addresses, scan exports, or secrets. `backend/.env` and `sample-data/private/` are ignored by Git and must stay that way.

---

## Making a Change

1. **Fork** the repository and clone your fork.
2. **Create a branch** from `main`:

   | Type | Branch name |
   |---|---|
   | Feature | `feature/short-description` |
   | Bug fix | `fix/short-description` |
   | Docs | `docs/short-description` |
   | Tests | `test/short-description` |

3. **Make focused changes.** One issue per pull request. Keep unrelated formatting changes out.
4. **Run the checks** (see below).
5. **Commit** with a clear message in the present tense, for example `Add tests for KEV past-due calculation`.
6. **Push** to your fork and open a pull request against `main`. Fill in the pull request template and link the issue (`Closes #123`).

---

## Checks Before You Open a Pull Request

**Backend** (from `backend/` with the virtual environment active):

```powershell
pytest
```

All tests must pass. Tests use SQLite and a fake AI model, so you don't need PostgreSQL or Ollama to run them. Add or update tests for any backend behavior you change.

**Frontend** (from `frontend/`):

```powershell
npm run lint
npm run build
```

Both must finish without errors. For UI changes, add a screenshot to the pull request and check keyboard access (Tab and Escape) and color contrast. See the [design guide](docs/design-guide.md).

---

## Style

- **Python:** Follow the existing code. Keep functions small, use type hints, and explain *why* in comments rather than *what*.
- **TypeScript and React:** Match the existing component patterns in `frontend/src/`.
- **Writing:** Plain language. Explain security terms the first time you use them. Match the voice in the [design guide](docs/design-guide.md).
- **Numbers come from code.** The local AI model only picks the question type. Don't add features where an AI model calculates or invents numbers.

---

## Reviews

- Every pull request needs approval from the maintainer before it is merged (see [CODEOWNERS](.github/CODEOWNERS)).
- Expect a first response within about a week. Reviews are about the code, not the person.
- The maintainer may ask for changes, merge, or close a pull request that doesn't fit the roadmap. Closing a pull request isn't a judgment on you.

---

## Questions

Open an issue labeled `question`. For anything security-related, use the private process in the [security policy](SECURITY.md).
