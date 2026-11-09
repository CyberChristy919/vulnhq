# Assignment Checklist

How VulnHQ measures up against the Deloitte Cyber Engineering interview assignment. The checklist uses the requirements that SRS v2.0 traces to the assignment brief: the 10 assignment questions, requirements whose source is "Assignment brief", the known issues in the assignment data and the trust rules for the AI.

Status as of November 9, 2026. Answers were checked on the fictional lab data set (`sample-data/lab-inventory.json`) with the keyword router. 179 automated tests pass.

**Status key:** ✅ Done · 🟡 Partial (works, with a gap noted) · ⬜ Not started

## Summary

| Area | ✅ Done | 🟡 Partial | ⬜ Not started |
|---|---|---|---|
| The 10 assignment questions | 6 | 4 | 0 |
| Answer quality from the brief | 3 | 5 | 1 |
| Assignment data issues | 0 | 4 | 1 |
| Trust and AI rules | 6 | 2 | 2 |
| **Total (34 items)** | **15** | **15** | **4** |

All 10 questions are answered from the data in under a tenth of a second. Most of the partial items are a missing detail, like a note or one more number, not a missing feature.

**The main reason items are partial:** the build followed the SRS Section 12 order for a short timeline. That meant getting the questions answered correctly from the data first, keeping the AI out of the numbers, and moving owner features and polish to the roadmap. The stop rule was: "If the tier and patch plan aren't working by Sunday evening, freeze and demo what works." Both are working.

---

## 1. The 10 assignment questions (SRS Section 11)

| # | Question | Status | What works | Why not complete | Plan |
|---|---|---|---|---|---|
| Q1 | Which of our assets have critical unpatched CVEs? | ✅ | Assets with CVSS 9.0+ findings, counts by match confidence, NVD links | — | Add a coverage-gap note (for example, "Windows patch level can't be assessed") |
| Q2 | What is our highest-risk server right now and why? | ✅ | One server, top CVE, risk score, criticality, KEV count; score breakdown on the Fix list | — | — |
| Q3 | Which software package should we patch first? | 🟡 | Package-level ranking with hosts, findings removed, KEV count and risk removed, plus the next two packages. The full plan is also available at `GET /patch-plan` (added November 9) | No target version ("upgrade to X"). The vetted rules store affected version ranges, not a fixed version for each product. | Add `fixed_version` to `vuln_rules.json` and show "Upgrade to X" in the answer |
| Q4 | How many Finance assets are affected by actively exploited vulnerabilities? | ✅ | Count of Finance assets plus the list of KEV findings with due dates | — | — |
| Q5 | Are any assets past a CISA KEV due date? | ✅ | Findings past the KEV due date, days overdue, oldest first; KPI card and Fix list column. A note says how many due dates were set under BOD 22-01 vs. BOD 26-04 | — | — |
| Q6 | Summarise our posture for the CISO in 3 sentences | 🟡 | Three sentences built by code from the data, so every number is exact | Numbers are not cited one by one and there is no verifier "Pass" badge. No AI writes the text, so there is nothing for a verifier to catch yet. | Add citations under the summary; add the verifier when the AI writes summaries |
| Q7 | Which business unit has the most critical exposure? | ✅ | Business unit ranking with Critical, KEV and total counts; the metric definition is stated | — | Option to rank by total risk score (the SRS metric) |
| Q8 | What would patching Apache HTTP Server reduce our CVE count by? | 🟡 | Before and after CVE and finding counts; asks "which one?" when "Apache" is ambiguous | KEV and risk-score before and after are not shown. The patch plan already has those numbers. | Add KEV count and total risk score before and after |
| Q9 | List all CVEs on network devices sorted by CVSS | ✅ | Network-device CVEs sorted by CVSS, with confidence counts for findings that need a configuration check | — | — |
| Q10 | Assets not scanned in 30 days with high-severity CVEs? | 🟡 | Answered with 30 days as asked, with the caveat that findings on stale assets may be understated; Assets page flags scans older than 90 days | Scan age isn't shown in the answer, and there's no company scan-standard view | Add scan age to the evidence rows; add scan standards (FR-SCN) on the roadmap |

## 2. Answer quality required by the brief

| Requirement | Status | What works | Why not complete | Plan |
|---|---|---|---|---|
| Quality bar: a CISO can hand the list to the patching team Monday morning | 🟡 | Ranked fix list with risk score, CISA deadline, KEV past due, SLA date, confidence and a "why" breakdown | No export file and no owner field to hand off. Remediation workflow was a planned scope cut. | CSV export, then owner assignment and status (Open → In progress → Fixed → Verified) |
| FR-NLQ-01: Free-text questions mapped to a question type | ✅ | Shortcut buttons plus any typed question; keywords first, local AI for new wording | — | — |
| FR-NLQ-04: What-if ("patch X on all hosts") | 🟡 | Before and after CVE and finding counts | KEV and score deltas missing (see Q8) | Same as Q8 |
| FR-NLQ-08: How exposure has changed over time | ⬜ | — | Needs history. The assignment data is one point-in-time file, so there is nothing to compare yet. | Save a daily snapshot and add "What's new since last week?" |
| FR-TRC-01: Every answer cites asset, CVE, source, CVSS and version, KEV due date | 🟡 | Asset ID, CVE with NVD link, source, CVSS, KEV due date, CISA deadline and confidence on every evidence row | CVSS version is not stored; non-KEV rows show a blank instead of "Not in KEV" | Store the CVSS version from NVD; label blanks "Not in KEV" |
| FR-PRI-03: KEV due date flagged past due, separate from the company SLA | ✅ | KEV past-due KPI card, Fix list column and sort, kept separate from the VulnHQ SLA | — | — |
| FR-AMB-01: Counts by match confidence in every answer | 🟡 | Every list answer reports confirmed and conditional counts | The app uses confirmed / conditional / nvd instead of the SRS labels (Confirmed / Likely / Uncertain / Ruled out). There is no "Needs verification" tab. | Map the labels to the SRS terms and add the Needs verification tab |
| FR-RPT-02: Three-sentence CISO summary with every figure cited | 🟡 | Three sentences from data | Per-figure citations missing (see Q6) | Same as Q6 |
| NFR-PERF-01: Answer in 10 seconds or less (2 minutes maximum from the brief) | ✅ | Keyword answers in 0.01 to 0.06 seconds on the lab data; the AI path stops at 30 seconds and falls back to keywords | — | — |

## 3. Assignment data issues (SRS Section 2.6)

| Issue | Status | What works | Why not complete | Plan |
|---|---|---|---|---|
| D1: The brief says 25 assets and 5 business units; the file has 23 assets and 6 departments | 🟡 | Uses the 23 actual records and treats departments as business units | No data-quality panel that reports the mismatch. The data-quality report (FR-ING-02) was cut for time. | Data-quality report on import (record count vs. metadata, missing fields). For the demo, call it out out loud. |
| D2: Scan dates are 24 days to 8 months old | 🟡 | Stale-scan flag at 90 days on the KPIs and Assets page; Q10 uses 30 days as asked | No company scan standard or presets (default, CIS v8) | Scan Standards settings page (FR-SCN) |
| D3: Microsoft components patched through KB updates can't be assessed from version strings | 🟡 | Windows versions are listed as "not checked" with the reason and a recommended tool (WSUS, Intune, Tenable) | No manual-review ticket queue | Manual review queue (FR-MRV), one ticket per asset and component, no duplicates |
| D4: Some products need version translation (Java, Exchange, Cisco IOS, F5) | 🟡 | Java is flagged "not checked" with guidance on NVD's update-number format | Version translators are not built, so these stay as gaps instead of matches | Vendor version translators (FR-MAT-02), with unclear mappings marked "Uncertain" |
| D5: Several operating systems are past vendor end of support | ⬜ | — | End-of-support dates have to be checked against vendor lifecycle pages, and the flag is context only, not scored. It came after the scoring work. | End-of-support flag on the Assets page from vendor lifecycle data |

## 4. Trust and AI rules (SRS Sections 5.9 and 8)

| Requirement | Status | What works | Why not complete | Plan |
|---|---|---|---|---|
| AI-07: Keywords run first; AI only when no match; AI choices limited to real values | ✅ | Tested: made-up departments and packages are discarded | — | — |
| AI-08: Local model (Granite 4.2 8B on Ollama); keyword result stands if the AI is down or slow | ✅ | Tested: AI down, server error, slow model and bad reply all fall back | — | — |
| AI-09: AI only picks the question type and never sees findings or writes numbers | ✅ | Answers picked by the AI say so in their notes | — | — |
| FR-NLQ-02: Every number comes from code, not free text | ✅ | All answers are calculated from the scored findings | — | — |
| FR-NLQ-03: Show the trace (question type → tools → result) | 🟡 | Notes say when the AI picked the question type | No expandable trace view | "How this was answered" panel under each answer |
| AI-06: Test set of the 10 questions plus 10 adversarial questions | 🟡 | All 10 questions tested; tests also cover made-up values and a failing AI | No prompt-injection test. The AI never sees CVE text, which lowers the risk. | Add an adversarial test file: fake CVE, out-of-scope product, injected instructions |
| FR-VAL-01/02: Verifier checks IDs and numbers in every answer | ⬜ | — | No AI writes answer text, so every ID and number already comes straight from the database | Build the verifier together with AI-written summaries |
| FR-TRC-04: Every answer stamped with the as-of date and data freshness | ⬜ | The KEV catalog version is printed when it loads | It was a Sunday stretch item that wasn't reached | "Data as of KEV 2026.11.06, EPSS <date>" in the header and on each answer |
| NFR-AVL-02: Demo runs offline from cached data | ✅ | Tested November 8 with Wi-Fi off: all 10 questions answered. KEV, EPSS and NVD results are stored in the database and the AI runs locally. | — | — |
| FR-AMB-06: "What this tool does not do" statement | ✅ | Published in the README | — | Also show it in the app |

---

## Quick wins (small fixes, about 5 to 20 minutes each)

1. ~~Q10 caveat~~ (done November 8)
2. ~~Q5 note: which due dates were set under BOD 22-01 vs. BOD 26-04~~ (done November 8)
3. Q8: add KEV count and risk score before and after
4. ~~Test offline~~ (done November 8: all 10 questions work with Wi-Fi off)
5. Settings fix: allow `OLLAMA_MODEL` in `backend\.env` (add `extra="ignore"` in `app/config.py`)

## Roadmap (after the interview)

| Phase | Items |
|---|---|
| Trust | As-of stamp, trace panel, verifier, adversarial test set, CVSS version, SRS confidence labels and Needs verification tab |
| Data quality | Data-quality report, scan standards, end-of-support flags, version translators, manual review queue |
| Hand-off | CSV export, owners, remediation status, target versions in the patch plan |
| Change over time | Daily snapshots and "What's new since last week?" |
| Owner features | SRS Sections 5.11 to 5.24 (configuration, notifications, SLA policy, vendors, preventive maintenance) |
