"""Tests for looking up each CVE's fix type from KEV, OSV and NVD.

These tests describe the code before it exists. Build it in app/fix_lookup.py.
No network calls here: OSV is passed in as a function, so tests use a fake.

    nvd_fixed_versions(rules, nvd_cache) -> dict[str, str]
        CVE ID -> a first fixed version, from both places NVD data lives:
            rules:     the "rules" list from data/vuln_rules.json (ranges from NVD).
                       Use fix_type.fixed_version(rule["max_version"], rule["max_inclusive"]).
            nvd_cache: data/nvd_cache.json as a dict. Its "cves" key maps
                       "product|version" -> list of saved NvdMatch dicts; read each
                       one's "fixed_version" (older entries don't have it).
        Leave out CVEs with no fixed version. A CVE can have several ranges
        (one per release branch); keep the first fixed version found.

    lookup_fix_types(cve_ids, required_actions, nvd_fixed, osv_record) -> dict[str, str]
        cve_ids:          the CVEs to look up (duplicates are fine)
        required_actions: CVE ID -> KEV requiredAction text (missing = not in KEV)
        nvd_fixed:        the dict from nvd_fixed_versions()
        osv_record:       a function, CVE ID -> OSV record or None (OsvClient().record)
        Returns CVE ID -> fix_type.fix_type(required_action, osv record, fixed version, False).
        Look up each CVE once.
        If OSV raises osv.OsvUnavailable, keep going without OSV: use None for
        that CVE and every CVE after it, and stop calling OSV (so one outage
        doesn't mean dozens of slow timeouts). The page still loads.

Until app/fix_lookup.py exists, these tests are skipped.
"""

import pytest

from app.osv import OsvUnavailable

fl = pytest.importorskip("app.fix_lookup")
nvd_fixed_versions = fl.nvd_fixed_versions
lookup_fix_types = fl.lookup_fix_types

# Real values: Log4Shell ranges from data/vuln_rules.json, Chrome from
# https://nvd.nist.gov/vuln/detail/CVE-2024-4671, Maven from
# https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q
LOG4J = "CVE-2021-44228"
CHROME = "CVE-2024-4671"
APACHE = "CVE-2021-41773"

MAVEN_RECORD = {"id": LOG4J, "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}}]}
CHROME_RECORD = {"id": CHROME, "affected": []}

# requiredAction text from the CISA KEV feed:
# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
KEV_MITIGATE = "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable."
KEV_LOG4J = ("For all affected software assets for which updates exist, the only acceptable remediation "
             "actions are: 1) Apply updates; OR 2) remove affected assets from agency networks.")
KEV_END_OF_LIFE = "The impacted product is end-of-life and should be disconnected if still in use."


def rule(cve, max_version, max_inclusive):
    return {"cve": cve, "max_version": max_version, "max_inclusive": max_inclusive}


# ---------- nvd_fixed_versions ----------

def test_rule_with_exclusive_end():
    assert nvd_fixed_versions([rule(LOG4J, "2.15.0", False)], {}) == {LOG4J: "2.15.0"}


def test_rule_with_inclusive_end_is_left_out():
    # Apache 2.4.49 "through 2.4.49" says what's broken, not what's fixed
    assert nvd_fixed_versions([rule(APACHE, "2.4.49", True)], {}) == {}


def test_first_branch_with_a_fix_wins():
    # CVE-2021-45105: 2.13.0 through 2.16.0, and 2.12.3 as a separate fix
    rules = [rule("CVE-2021-45105", "2.16.0", True), rule("CVE-2021-45105", "2.12.3", False)]
    assert nvd_fixed_versions(rules, {}) == {"CVE-2021-45105": "2.12.3"}


def test_cache_fixed_version():
    cache = {"cves": {"a:google:chrome|124.0.6367.60": [{"cve_id": CHROME, "fixed_version": "124.0.6367.201"}]}}
    assert nvd_fixed_versions([], cache) == {CHROME: "124.0.6367.201"}


def test_old_cache_entries_without_fixed_version():
    cache = {"cves": {"a:google:chrome|124.0.6367.60": [{"cve_id": CHROME, "title": "Old entry"}]}}
    assert nvd_fixed_versions([], cache) == {}


def test_cache_with_no_cves_key():
    # The cache can hold only product lookups so far
    assert nvd_fixed_versions([], {"products": {"google chrome": "a:google:chrome"}}) == {}


def test_rules_and_cache_together():
    cache = {"cves": {"a:google:chrome|124.0.6367.60": [{"cve_id": CHROME, "fixed_version": "124.0.6367.201"}]}}
    result = nvd_fixed_versions([rule(LOG4J, "2.15.0", False)], cache)
    assert result == {LOG4J: "2.15.0", CHROME: "124.0.6367.201"}


# ---------- lookup_fix_types ----------

def fake_osv(records):
    """An OSV lookup that answers from a dict and counts its calls."""
    def record(cve_id):
        record.calls.append(cve_id)
        return records.get(cve_id)
    record.calls = []
    return record


def test_chrome_is_a_vendor_update():
    # KEV says "Apply mitigations", OSV has no package, NVD names 124.0.6367.201
    result = lookup_fix_types([CHROME], {CHROME: KEV_MITIGATE}, {CHROME: "124.0.6367.201"},
                              fake_osv({CHROME: CHROME_RECORD}))
    assert result == {CHROME: "vendor update"}


def test_log4j_is_a_library_update():
    result = lookup_fix_types([LOG4J], {LOG4J: KEV_LOG4J}, {LOG4J: "2.15.0"},
                              fake_osv({LOG4J: MAVEN_RECORD}))
    assert result == {LOG4J: "library update"}


def test_end_of_life_is_replace():
    result = lookup_fix_types([APACHE], {APACHE: KEV_END_OF_LIFE}, {APACHE: "2.4.51"}, fake_osv({}))
    assert result == {APACHE: "replace"}


def test_no_sources_answer():
    # Not in KEV, OSV doesn't have it, NVD names no fix
    assert lookup_fix_types([APACHE], {}, {}, fake_osv({})) == {APACHE: "unknown"}


def test_each_cve_looked_up_once():
    osv = fake_osv({LOG4J: MAVEN_RECORD})
    lookup_fix_types([LOG4J, LOG4J, LOG4J], {}, {}, osv)
    assert osv.calls == [LOG4J]


def test_osv_outage_falls_back_and_stops_calling():
    calls = []

    def down(cve_id):
        calls.append(cve_id)
        raise OsvUnavailable("OSV returned 503. Try again shortly.")

    result = lookup_fix_types([CHROME, LOG4J, APACHE], {}, {CHROME: "124.0.6367.201"}, down)
    # NVD still answers for Chrome; the others have no source left
    assert result == {CHROME: "vendor update", LOG4J: "unknown", APACHE: "unknown"}
    # One failed call, then no more
    assert len(calls) == 1


def test_no_cves():
    assert lookup_fix_types([], {}, {}, fake_osv({})) == {}
