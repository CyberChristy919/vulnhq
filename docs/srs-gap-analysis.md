# SRS Gap Analysis

Compares the code in this repository (as of 2026-11-06) with the two SRS versions in the project:

- **SRS v1:** `VulnHQ_SRS_v1.docx`
- **SRS v1.2:** `VulnHQ_SRS_v2.docx` (adds Section 5.24 Preventive Maintenance Planning, FR-PMP-01 to FR-PMP-19, and FR-MRV-10; FR-TRM-05 now also sends untranslated findings to the manual review queue)

Status key: **Done** = built and tested · **Partial** = started but missing parts of the requirement · **Missing** = not in the code or the README plan before this review · **Planned** = already on the README plan.

---

## Summary

The MVP covers the core loop well: inventory import, vetted-rule plus NVD matching, KEV and EPSS enrichment, a 0 to 100 score with a factor breakdown, SLA due dates, and a ranked fix list. The biggest gaps against the SRS are:

1. **Prioritization model differs from SRS Section 9.** The SRS uses two layers: a BOD 26-04 tier (policy deadline) plus an Exposure Priority Score to order work within the tier. The code uses one score with fixed tiers (7 / 30 / 60 / 90 days) and no CVSS or time-pressure factor.
2. **BOD 22-01 is out of date.** CISA's [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) revoked BOD 22-01 on June 10, 2026. Full timelines take effect December 7, 2026 ([FedRAMP notice](https://www.fedramp.gov/notices/0014/)). The README, `docs/scoring.md`, `docs/framework-alignment.md` and the design guide still cite BOD 22-01.
3. **Match honesty rules.** The SRS requires Confirmed / Likely / Uncertain / Ruled out, a separate "needs verification" lane, and stored ruled-out candidates with reasons. The code uses confirmed / conditional / nvd and skips NVD matches below CVSS 7 unless they are in KEV.
4. **Natural-language query agent (FR-NLQ, FR-VAL, Section 8).** The 10 assignment questions (SRS Section 11, Q1 to Q10) are the acceptance tests, and none of the agent, router, verifier or citation features exist yet.
5. **Remediation workflow, reporting and integrations.** These are on the plan at a high level, but the SRS adds detail the plan did not list (patch plan by package, response types, forensic triage, BU and CISO summaries, CWE root cause).
6. **Owner sections 5.11 to 5.24** (configuration, scan standards, manual review, notifications, multi-source ingestion, correlation, SLA policy, lifecycle, orphans, vendors, VM reports, target dates, terminology, preventive maintenance) were not on the plan at all.

---

## Area-by-Area Comparison

### Core pipeline (SRS Sections 4, 5.1 to 5.10)

| SRS area | Status | What exists | What's missing |
|---|---|---|---|
| **Ingestion and scoping (FR-ING)** | Partial | JSON inventory and business context import; Pydantic validation; stale scan flag at 90 days | Data-quality report (record count vs. metadata, departments vs. BUs, missing fields) (FR-ING-02); configurable as-of date (FR-ING-03); explicit Unknown exposure and environment fields, since `internet_facing` defaults to False (FR-ING-04); maintenance groups (FR-ING-05); end-of-support flags (FR-ING-06) |
| **Vulnerability intelligence (FR-VUL)** | Partial | KEV, EPSS and NVD loaders; NVD results cached | Store KEV `catalogVersion` and `dateReleased` (FR-VUL-01); store raw NVD responses and query by CPE `virtualMatchString` (FR-VUL-02); KEV cross-check by vendor/product (FR-VUL-03); EPSS percentile and model version (FR-VUL-04); SSVC Automatable and Technical Impact from CISA Vulnrichment (FR-VUL-05) |
| **Matching (FR-MAT)** | Partial | Curated rules (61 CVEs), CPE aliases, version comparison, conditional flag | Vendor version translators (Java updates, Exchange CU, Cisco trains, OpenSSL letters) (FR-MAT-02); re-check NVD configuration ranges and AND nodes (FR-MAT-03/04); four-level confidence with distro backport handling (FR-MAT-05); never drop candidates, store ruled-out with reason (FR-MAT-06); coverage gaps with recommended data source (FR-MAT-07) |
| **Prioritization (FR-PRI, Section 9)** | Partial | 0 to 100 score with breakdown; configurable weights; SLA due dates | BOD 26-04 tier from exposure, KEV, automatable and technical impact (FR-PRI-01); versioned BOD 26-04 matrix config file (FR-PRI-02); KEV due date shown and flagged past due separately from company SLA (FR-PRI-03); Section 9.2 weights (CVSS, time pressure) (FR-PRI-04); plain-language "why" sentence (FR-PRI-05); separate needs-verification lane (FR-PRI-06); dual-assumption tier when exposure is Unknown (FR-PRI-08) |
| **Framework mapping (FR-MAP)** | Missing | Framework table in docs only | CWE per finding, ATT&CK technique (CTID-curated, derived, AI-suggested labels), CTEM stage IDs, NIST CSF tags on findings |
| **Natural-language query (FR-NLQ, Section 8)** | Missing | None | Tool catalog, deterministic intent router, LLM synthesis, simulate-patch, adversarial and prompt-injection tests |
| **Traceability (FR-TRC)** | Missing | Score details panel | Per-answer citations (asset, CVE, source, CVSS version, KEV due date); NVD links; KEV catalog version; evidence bundle per finding |
| **Ambiguity and honesty (FR-AMB)** | Partial | Confidence column; "not checked" and "needs review" lists on import | Counts by confidence in answers; stale-data and assumption disclosures; source conflicts (NVD vs. KEV CWE, CVSS v3.1 vs. v4.0); "What this tool does not do" statement |
| **Validation (FR-VAL)** | Missing | pytest suite | Answer verifier (every number traced to data), Pass / Fail shown |
| **Mobilization (FR-MOB)** | Missing | None | Package-level patch plan (FR-MOB-01); risk response type (FR-MOB-02); scenario: routine, emergency patch, emergency mitigation, unpatchable (FR-MOB-03); forensic triage checklist routed to the SOC (FR-MOB-04) |
| **Reporting (FR-RPT)** | Planned | KPI cards | Business-unit summary (FR-RPT-01); 3-sentence cited CISO summary (FR-RPT-02); CWE root-cause view (FR-RPT-03) |

### Owner requirements (SRS Sections 5.11 to 5.24)

| SRS area | Status | Notes |
|---|---|---|
| **Organization configuration (FR-CFG)** | Missing | Custom fields, tags, ID schemes (CMDB CI, application IDs), criticality model, formula editor with preview, approval and versioning |
| **Scan standards (FR-SCN)** | Partial | 90-day stale flag exists. Missing: Scan Standards settings page, default and CIS v8 presets, warnings W1 to W9, "Cannot evaluate" when a field is missing |
| **Manual review (FR-MRV)** | Partial | Import shows "needs review." Missing: ticket queue for components that can't be assessed (Microsoft KB-serviced), no duplicates on re-run, "Cannot confirm" answers; FR-MRV-10 is new in v1.2 |
| **Notifications (FR-NTF)** | Planned (high level) | Plan says "notifications." SRS adds email, Teams Workflows and Slack, routing rules, delivery log, retries, report templates |
| **Multi-source ingestion (FR-SRC)** | Planned (high level) | Plan lists scanner integrations. SRS adds an ingestion API with idempotency, SARIF, CycloneDX SBOM and Burp parsers, provenance, pentest test-type checkboxes |
| **Cross-tool correlation (FR-COR)** | Missing | Group SAST, DAST, WAF and pentest detections into one issue; CWE-only matches suggested for review; detection timeline |
| **SLA policy and rating levels (FR-SLA)** | Partial | Fixed tier SLAs exist. Missing: rating schemes (VERIBANC template plus custom levels), SLA matrix, clock rules, BOD 26-04 and KEV dates shown next to company SLA, extensions and risk acceptance, SLA attainment reports, plan required after breach |
| **Lifecycle rules (FR-LCM)** | Missing | Container rotation (90-day default), image digest checks, "No container data source configured" |
| **Orphan queue (FR-ORP)** | Missing | Findings for hosts not in inventory, reason codes, triage, escalation after repeated rejection |
| **Vendor fix tracking and TPRM (FR-VND)** | Missing | Vendor records, fix dates and slips, non-responsive status, won't-fix decisions, VEX import, vendor scorecard |
| **VM reports (FR-VMR)** | Missing | Five standard reports (discovery type, missing target dates, ownership, past SLA, dedup counts), snapshots and trends |
| **Target remediation date rules (FR-TDR)** | Missing | Rule builder, default rules TD1 to TD7, 50%-of-SLA set-by deadline, attack-path imports (CrowdStrike, CyCognito, Cortex Cloud, Wiz) |
| **Terminology translator (FR-TRM)** | Missing | Company glossary, per-tool severity translation (for example "High (Qualys: 4 Critical)"), Untranslated Terms queue |
| **Preventive maintenance planning (FR-PMP, new in v1.2)** | Missing | Maintenance group profiles, severity-SLA defaults with cycle-fit warnings, auto-update policy, maintenance calendar and window-fit check, cycle and emergency packages, maintenance debt, post-window verification, integrated or manual change management |

### Non-functional requirements (SRS Section 7)

| SRS area | Status | Notes |
|---|---|---|
| **Security (NFR-SEC)** | Partial | Secrets in `.env`, SECURITY.md, read-only toward assets. Missing: pinned dependencies plus an SBOM for VulnHQ itself (NFR-SEC-05); prompt-injection defense for feed text once the agent exists; ASVS L2 verification evidence |
| **Data freshness (NFR-FRS)** | Missing | Daily KEV refresh; mark NVD cache entries older than 7 days stale; show the as-of date on every page and answer |
| **Auditability (NFR-AUD)** | Missing | Log questions, tool calls and answers; replay from pinned feed versions; config change log with before and after values |
| **Accessibility, usability, performance** | Partial | Design guide covers accessibility. Missing: measured performance targets and accessibility checks in tests |
| **Maintainability (NFR-MNT)** | Partial | Tests exist; GitHub Actions CI is planned but not built; frontend tests TBD |

### Implementation plan (SRS Section 12)

| SRS phase | Status |
|---|---|
| 0. Foundations (repo, README, config, feed cache, SBOM) | Partial: SBOM and CI missing |
| 1. Scoping (ingestion, data-quality report, maintenance groups) | Partial |
| 2. Discovery (normalization, KEV/NVD, matcher, evidence bundles, coverage gaps) | Partial |
| 3. Enrichment and mapping (EPSS, SSVC, CWE, ATT&CK, CTEM IDs) | Partial: EPSS only |
| 4. Prioritization (BOD 26-04 matrix, score, reasoning, uncertain lane) | Partial |
| 5. Agent and UI (tool catalog, router, LLM, verifier, trace view) | Missing |
| 6. Mobilization (patch plan, response types, scenarios, triage, exports) | Missing |
| 6b to 6l. Owner sections | Missing |
| 7. Demo prep (walkthrough, trust and limitations notes, what's next) | Partial: walkthrough exists |

The SRS suggests this order if time is tight: Phases 1, 2, 4, 5 (deterministic router first), then 3 and 6.

---

## Doc Fixes Needed

- Replace BOD 22-01 with BOD 26-04 in `README.md`, `docs/scoring.md`, `docs/framework-alignment.md` and `docs/design-guide.md`.
- Add MITRE ATT&CK, CWE and CISA SSVC to the framework table (SRS Sections 3.6 and 3.7).
- Rename confidence levels to match the SRS (Confirmed / Likely / Uncertain / Ruled out), or record the mapping.
- Add a "What this tool does not do" section (FR-AMB-06).
