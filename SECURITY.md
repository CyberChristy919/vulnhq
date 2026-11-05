# Security Policy

VulnHQ is a vulnerability management tool, so we hold it to the standard it helps others reach. Thank you for helping keep VulnHQ and its users safe.

## Supported Versions

VulnHQ is in early development. Security fixes are applied to the latest code on the `main` branch.

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Older commits / forks | No |

## Reporting a Vulnerability

**Please do not report security issues through public GitHub issues, discussions or pull requests.**

Report privately through GitHub:

1. Go to the **[Security tab](https://github.com/CyberChristy919/vulnhq/security)** of this repository.
2. Select **Report a vulnerability**.
3. Complete the advisory form.

Please include as much of the following as you can:

- Type of issue (for example, broken access control or injection), with the OWASP Top 10:2025 category or CWE ID if known
- Affected file paths, endpoints or components
- Commit or branch where the issue exists
- Step-by-step instructions to reproduce
- Proof of concept or exploit code, if available
- Impact: what an attacker could do

## What to Expect

| Stage | Target timeline |
|---|---|
| Acknowledgment of your report | Within 3 business days |
| Initial assessment and severity rating | Within 7 business days |
| Status updates | At least every 14 days until resolved |
| Fix for Critical / High issues | Prioritized for the next release |

Severity is rated using CVSS, or the OWASP Risk Rating Methodology where CVSS doesn't fit. Reporters are credited in the published security advisory unless they prefer to stay anonymous.

## Scope

**In scope**
- Source code in this repository
- VulnHQ application functionality, including authentication, authorization, data import and reporting
- Dependencies as used by VulnHQ (please also report upstream)

**Out of scope**
- Denial-of-service or volumetric attacks
- Social engineering or phishing
- Findings from automated scanners without a demonstrated impact
- Vulnerabilities in third-party services not controlled by this project
- Any testing against systems or data you don't own or aren't authorized to test

## Safe Harbor

We support good-faith security research. If you act in good faith, follow this policy, avoid privacy violations and data destruction, and give us reasonable time to fix the issue before public disclosure, we will not pursue legal action against you for your research.

## Coordinated Disclosure

Please allow us to release a fix before you share details publicly. We aim to publish a GitHub Security Advisory once a fix is available, and we're happy to coordinate disclosure timing with you.

## Framework Alignment

This policy supports **NIST CSF 2.0 ID.RA-08**: processes for receiving, analyzing and responding to vulnerability disclosures are established. See [docs/framework-alignment.md](docs/framework-alignment.md).

---

© 2026 Cyber Christy LLC. All rights reserved.
