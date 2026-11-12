"""Tests for fix type: how hard a fix is, using only facts from public sources.

These tests describe the code before it exists. Build it in app/fix_type.py.
Nothing here is typed in by hand; every answer comes from one of these sources:

    CISA KEV requiredAction   "end-of-life" or "disconnect" means the product must be replaced.
                              (Other wording isn't used: newer entries, including Chrome's,
                              all say "Apply mitigations..." whether the fix is easy or hard.)
    OSV.dev record            An affected package in a library ecosystem (Maven, PyPI, npm...)
                              means the fix is a library update inside apps: rebuild and test.
    NVD affected range        versionEndExcluding (max_version with max_inclusive False)
                              is the first fixed version, so a vendor update exists.

Functions:

    LIBRARY_ECOSYSTEMS: set[str]
        {"Maven", "PyPI", "npm", "NuGet", "Go", "crates.io", "RubyGems", "Packagist", "Hex", "Pub"}

    kev_says_replace(required_action) -> bool
        True if the text mentions "end-of-life" or "disconnect" (any capitalization).
        None or "" -> False.

    is_library(osv_vuln) -> bool
        True if any affected package's ecosystem is in LIBRARY_ECOSYSTEMS.
        None, no "affected", or affected entries with no "package" -> False.

    fixed_version(max_version, max_inclusive) -> str | None
        The first fixed version when the range ends before it (max_inclusive False).
        Inclusive end or no max_version -> None (the source doesn't name a fix).

    fix_type(required_action, osv_vuln, max_version, max_inclusive) -> str
        Checked in this order; the first match wins:
            KEV says replace   -> "replace"
            OSV says library   -> "library update"
            NVD names a fix    -> "vendor update"
            none of the above  -> "unknown"

    package_fix_type(types) -> str
        One package can have many CVEs. Return the hardest known fix type:
            "replace" > "library update" > "vendor update"
        No types, or only "unknown" -> "unknown".

The sample records below are trimmed from the real sources (November 2026):
    Log4j:  OSV GHSA-jfh8-c2jp-5v3q, KEV CVE-2021-44228
    Chrome: OSV CVE-2024-4671, NVD CVE-2024-4671 (fixed in 124.0.6367.201)

Until app/fix_type.py exists, these tests are skipped.
"""

import pytest

ft = pytest.importorskip("app.fix_type")

# ---------- Sample records, trimmed from the real sources ----------

# OSV GHSA-jfh8-c2jp-5v3q (Log4Shell): affected package is in the Maven ecosystem
OSV_LOG4J = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["CVE-2021-44228"],
    "affected": [
        {
            "package": {
                "name": "org.apache.logging.log4j:log4j-core",
                "ecosystem": "Maven",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
            },
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}],
        }
    ],
}

# OSV CVE-2024-4671 (Chrome): affected entry has no package ecosystem
OSV_CHROME = {"id": "CVE-2024-4671", "affected": [{"ranges": []}]}

# KEV requiredAction for CVE-2021-44228 (Log4j)
KEV_LOG4J = (
    "For all affected software assets for which updates exist, the only acceptable remediation "
    "actions are: 1) Apply updates; OR 2) remove affected assets from agency networks."
)

# KEV requiredAction wording for end-of-life products
KEV_EOL = "The impacted product is end-of-life and should be disconnected if still in use."

# KEV requiredAction for recent entries, including Chrome
KEV_MITIGATE = "Apply mitigations in accordance with vendor instructions."


# ---------- kev_says_replace ----------

def test_kev_end_of_life_means_replace():
    assert ft.kev_says_replace(KEV_EOL) is True


def test_kev_ignores_capitalization():
    assert ft.kev_says_replace("Product is END-OF-LIFE.") is True


def test_kev_update_or_mitigate_is_not_replace():
    assert ft.kev_says_replace(KEV_LOG4J) is False
    assert ft.kev_says_replace(KEV_MITIGATE) is False


def test_kev_missing_text_is_not_replace():
    assert ft.kev_says_replace(None) is False
    assert ft.kev_says_replace("") is False


# ---------- is_library ----------

def test_maven_package_is_a_library():
    assert ft.is_library(OSV_LOG4J) is True


def test_no_package_ecosystem_is_not_a_library():
    assert ft.is_library(OSV_CHROME) is False


def test_os_package_ecosystem_is_not_a_library():
    # Debian packages are installed software, not libraries built into apps
    osv = {"affected": [{"package": {"name": "chromium", "ecosystem": "Debian:12"}}]}
    assert ft.is_library(osv) is False


def test_missing_osv_record_is_not_a_library():
    assert ft.is_library(None) is False
    assert ft.is_library({}) is False


def test_library_ecosystems_include_the_common_ones():
    assert {"Maven", "PyPI", "npm", "NuGet", "Go"} <= ft.LIBRARY_ECOSYSTEMS


# ---------- fixed_version ----------

def test_exclusive_end_is_the_fixed_version():
    assert ft.fixed_version("124.0.6367.201", False) == "124.0.6367.201"


def test_inclusive_end_names_no_fix():
    # "through 2.16.0" says what's affected, not what fixes it
    assert ft.fixed_version("2.16.0", True) is None


def test_no_end_names_no_fix():
    assert ft.fixed_version(None, False) is None


# ---------- fix_type ----------

def test_log4j_is_a_library_update():
    assert ft.fix_type(KEV_LOG4J, OSV_LOG4J, "2.15.0", False) == "library update"


def test_chrome_is_a_vendor_update():
    assert ft.fix_type(KEV_MITIGATE, OSV_CHROME, "124.0.6367.201", False) == "vendor update"


def test_end_of_life_wins_over_everything():
    assert ft.fix_type(KEV_EOL, OSV_LOG4J, "2.15.0", False) == "replace"


def test_no_facts_means_unknown():
    assert ft.fix_type(None, None, None, False) == "unknown"


def test_not_in_kev_still_uses_osv_and_nvd():
    # Most findings aren't in KEV; OSV and NVD still answer
    assert ft.fix_type(None, OSV_LOG4J, None, False) == "library update"
    assert ft.fix_type(None, None, "1.2.3", False) == "vendor update"


# ---------- package_fix_type ----------

def test_package_takes_the_hardest_fix():
    assert ft.package_fix_type(["vendor update", "library update"]) == "library update"
    assert ft.package_fix_type(["library update", "replace", "vendor update"]) == "replace"


def test_package_ignores_unknown_when_something_is_known():
    assert ft.package_fix_type(["unknown", "vendor update"]) == "vendor update"


def test_package_with_nothing_known_is_unknown():
    assert ft.package_fix_type([]) == "unknown"
    assert ft.package_fix_type(["unknown", "unknown"]) == "unknown"
