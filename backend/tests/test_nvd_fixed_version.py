"""Tests for saving NVD's fixed version, so fix type can say "vendor update".

These tests describe the code before it exists. Change app/nvd.py:

    fixed_in(cve, product, version) -> str | None
        The first fixed version for this product and installed version, read from
        the NVD range that contains it: that range's versionEndExcluding.
        Only use cpeMatch entries where the product is listed as vulnerable,
        the same checks affects() makes. Return None when:
            - the matching range ends with versionEndIncluding ("through 2.16.0")
            - the range has no end at all
            - the version is only listed exactly (no range)
            - no range for this product contains the version
        A CVE can list one range per release branch (Tomcat 8.5.x and 9.0.x);
        use the one that contains the installed version.

    NvdMatch gets one new field, last in the list:
        fixed_version: str | None = None
        The default keeps older entries in data/nvd_cache.json loading.

    NvdClient.lookup() fills in fixed_version with fixed_in() for each match,
    so it's saved in the cache too.

Real example: CVE-2024-4671 lists Google Chrome versionEndExcluding 124.0.6367.201
(https://nvd.nist.gov/vuln/detail/CVE-2024-4671).

Until app/nvd.py has fixed_in(), these tests are skipped.
"""

from dataclasses import asdict

import pytest

from app import nvd

if not hasattr(nvd, "fixed_in"):
    pytest.skip("app/nvd.py has no fixed_in() yet", allow_module_level=True)

fixed_in = nvd.fixed_in

CHROME = "a:google:chrome"
TOMCAT = "a:apache:tomcat"


def cve(*matches, cve_id="CVE-TEST-0001"):
    """A minimal NVD CVE record with the given cpeMatch entries."""
    return {"id": cve_id, "configurations": [{"nodes": [{"cpeMatch": list(matches)}]}]}


def match(product, vulnerable=True, version="*", **ranges):
    """One cpeMatch entry, e.g. match(CHROME, versionEndExcluding="124.0.6367.201")."""
    return {"criteria": f"cpe:2.3:{product}:{version}:*:*:*:*:*:*:*", "vulnerable": vulnerable, **ranges}


# ---------- fixed_in ----------

def test_exclusive_end_is_the_fix():
    c = cve(match(CHROME, versionEndExcluding="124.0.6367.201"))
    assert fixed_in(c, CHROME, "124.0.6367.60") == "124.0.6367.201"


def test_inclusive_end_names_no_fix():
    # "Through 2.16.0" says what's broken, not what's fixed
    c = cve(match(TOMCAT, versionStartIncluding="2.0", versionEndIncluding="2.16.0"))
    assert fixed_in(c, TOMCAT, "2.14.1") is None


def test_range_with_no_end_names_no_fix():
    c = cve(match(TOMCAT, versionStartIncluding="9.0.0"))
    assert fixed_in(c, TOMCAT, "9.0.30") is None


def test_exact_version_names_no_fix():
    c = cve(match("a:grafana:grafana", version="8.2.6"))
    assert fixed_in(c, "a:grafana:grafana", "8.2.6") is None


def test_version_outside_the_range():
    # The fixed version itself isn't affected, so there's nothing to fix
    c = cve(match(CHROME, versionEndExcluding="124.0.6367.201"))
    assert fixed_in(c, CHROME, "124.0.6367.201") is None


def test_picks_the_branch_that_contains_the_version():
    c = cve(
        match(TOMCAT, versionStartIncluding="8.5.0", versionEndExcluding="8.5.51"),
        match(TOMCAT, versionStartIncluding="9.0.0", versionEndExcluding="9.0.31"),
    )
    assert fixed_in(c, TOMCAT, "9.0.30") == "9.0.31"
    assert fixed_in(c, TOMCAT, "8.5.40") == "8.5.51"


def test_other_products_are_ignored():
    c = cve(match("a:microsoft:edge_chromium", versionEndExcluding="124.0.2478.97"))
    assert fixed_in(c, CHROME, "124.0.6367.60") is None


def test_platform_only_is_ignored():
    # Listed as the platform it runs on, not as vulnerable
    c = cve(match(CHROME, vulnerable=False, versionEndExcluding="124.0.6367.201"))
    assert fixed_in(c, CHROME, "124.0.6367.60") is None


def test_no_configurations():
    # Brand-new CVEs often have no product data yet
    assert fixed_in({"id": "CVE-TEST-0002"}, CHROME, "124.0.6367.60") is None


# ---------- NvdMatch ----------

def test_match_defaults_to_no_fixed_version():
    m = nvd.NvdMatch("CVE-TEST-0001", "Test", 9.8, CHROME)
    assert m.fixed_version is None


def test_old_cache_entries_still_load():
    # Saved before fixed_version existed
    old = {"cve_id": "CVE-TEST-0001", "title": "Test", "cvss": 9.8, "product": CHROME, "broad": False}
    assert nvd.NvdMatch(**old).fixed_version is None


# ---------- NvdClient.lookup ----------

def test_lookup_saves_fixed_version(monkeypatch):
    record = cve(match(CHROME, versionEndExcluding="124.0.6367.201"), cve_id="CVE-2024-4671")
    page = {"vulnerabilities": [{"cve": record}], "resultsPerPage": 1, "totalResults": 1}

    client = nvd.NvdClient(api_key="test")
    client.cache = {}
    # No network and no file writes
    monkeypatch.setattr(client, "_get", lambda url, params: page)
    monkeypatch.setattr(nvd, "_save_cache", lambda cache: None)

    results = client.lookup(CHROME, "124.0.6367.60", use_cache=False)
    assert results[0].fixed_version == "124.0.6367.201"
    # Saved in the cache, so the next lookup has it offline
    assert client.cache["cves"][f"{CHROME}|124.0.6367.60"][0] == asdict(results[0])
