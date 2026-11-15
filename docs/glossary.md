# Glossary

Terms and acronyms used in VulnHQ code, docs and pages. Each entry links to the source that defines it.

## Data sources

| Term | Meaning in VulnHQ | Source |
|------|-------------------|--------|
| **CVE** (Common Vulnerabilities and Exposures) | The public ID for one vulnerability, for example `CVE-2021-44228` (Log4Shell). Findings, KEV, NVD and OSV all join on it. | [CVE Program glossary](https://www.cve.org/ResourcesSupport/Glossary) |
| **KEV** (Known Exploited Vulnerabilities) | CISA's list of CVEs with evidence of exploitation in the wild. KEV findings always rank first in the Fix list and Patch plan. | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **requiredAction** | The KEV field that tells agencies what to do. VulnHQ reads it only for "end-of-life" or "disconnect", which means the product has to be replaced. | [KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) |
| **NVD** (National Vulnerability Database) | NIST's database of CVE details, including affected products and versions. VulnHQ uses it to match software versions to CVEs and to find a fixed version. | [NVD](https://nvd.nist.gov/) |
| **versionEndExcluding** | An NVD range field meaning "affected up to, but not including, this version". That version is the first fixed release. An inclusive end (`versionEndIncluding`) doesn't name a fix. | [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities) |
| **CPE** (Common Platform Enumeration) | NVD's naming scheme for products, for example `cpe:2.3:a:google:chrome`. NVD lists affected products as CPEs. | [NVD CPE](https://nvd.nist.gov/products/cpe) |
| **OSV** (Open Source Vulnerabilities) | An open database of vulnerabilities in open-source packages, with the package ecosystem and fixed versions. VulnHQ calls the OSV.dev API and caches results in `backend/data/osv_cache.json`. | [OSV.dev](https://osv.dev), [OSV schema](https://ossf.github.io/osv-schema/) |
| **Alias** | Another ID for the same vulnerability in an OSV record. Log4Shell's CVE record has no package data, so VulnHQ merges in its GHSA alias. | [OSV schema](https://ossf.github.io/osv-schema/) |
| **GHSA** (GitHub Security Advisory) | GitHub's advisory ID, for example `GHSA-jfh8-c2jp-5v3q` for Log4Shell in Maven. | [GitHub Advisory Database](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database) |
| **Ecosystem** | The package manager an OSV record belongs to, such as Maven, PyPI or npm. An ecosystem means the CVE is in a library that apps bundle. See `LIBRARY_ECOSYSTEMS` in `backend/app/fix_type.py`. | [OSV schema](https://ossf.github.io/osv-schema/) |

## Fix type

How hard a fix is likely to be, from easiest to hardest. Fix type explains the order; it doesn't change the ranking. See `backend/app/fix_type.py`.

The Patch plan shows it as **Effort**: in the Effort column, and at the end of each "Why this order" line, with the note in the last column below (`EFFORT_NOTE` in `backend/app/explain.py`).

| Value | When VulnHQ uses it | "Why this order" note |
|-------|---------------------|-----------------------|
| **vendor update** | NVD names a fixed version, so the vendor ships an update (for example, Google Chrome 124.0.6367.201). | install the vendor's update |
| **library update** | OSV lists the installed package in a library ecosystem, so every app that bundles it needs a rebuild and testing (for example, log4j-core). | rebuild and test every app that bundles it |
| **replace** | KEV `requiredAction` says end-of-life or disconnect, so there's no patch. | end-of-life, so replace it |
| **unknown** | No source answered. VulnHQ says so instead of guessing. | (nothing added) |

A package with several CVEs gets the hardest known type across them.

**Package matching:** an OSV record also lists other products that bundle the same library. For example, Chrome's libwebp CVE (CVE-2023-4863) lists NuGet SkiaSharp, and its libvpx CVE (CVE-2023-5217) lists npm electron. VulnHQ counts an OSV package only when its name matches the installed package (`matches_package` in `backend/app/fix_type.py`). Otherwise, Chrome would show as a library update. Sources: [GHSA-j7hp-h8jx-5ppr](https://osv.dev/vulnerability/GHSA-j7hp-h8jx-5ppr), [GHSA-qqvq-6xgj-jw8g](https://osv.dev/vulnerability/GHSA-qqvq-6xgj-jw8g).

## VulnHQ terms

| Term | Meaning |
|------|---------|
| **Finding** | One CVE on one host. The counts on the Patch plan and in "Why this order" are findings, not distinct flaws: Google Chrome's 14 KEV findings are 5 CVEs across 5 hosts. |
| **Actively exploited** | A finding whose CVE is in CISA KEV. It's the first sort key on the Fix list and Patch plan. |
| **Risk removed** | The sum of the risk scores of a package's findings, so it's what patching that package takes off the board. It's the second sort key. See the [scoring model](scoring.md). |

## Scoring and security terms

| Term | Meaning | Source |
|------|---------|--------|
| **CVSS** (Common Vulnerability Scoring System) | FIRST's standard for rating a vulnerability's severity. | [CVSS v4.0 specification](https://www.first.org/cvss/specification-document) |
| **RE** (Vulnerability Response Effort) | An optional CVSS v4.0 supplemental metric for how hard a response is (Low, Moderate, High). Few CVEs have it; NVD has none for Log4Shell, so VulnHQ doesn't depend on it. | [CVSS v4.0 specification](https://www.first.org/cvss/specification-document) |
| **ReDoS** (Regular expression Denial of Service) | A regular expression that slows down badly on crafted input. GitHub code scanning flags one in `backend/app/ask.py`. | [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) |
