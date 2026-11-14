"""Tests for matching OSV packages to the installed package.

Why: OSV lists every product that bundles a vulnerable library. CVE-2023-4863
(libwebp) lists NuGet SkiaSharp and Go webp; CVE-2023-5217 (libvpx) lists npm
electron. None of those is Google Chrome, but the old is_library() saw "a library
ecosystem" and called Chrome a library update. So only count an OSV package
whose name matches the package installed here.

These tests describe the code before it exists. Change app/fix_type.py:

    matches_package(osv_name, package) -> bool
        Take the last part of the OSV name, after the last ":" or "/":
            "org.apache.logging.log4j:log4j-core" -> "log4j-core"
            "github.com/chai2010/webp"            -> "webp"
        Compare it to the package name with spaces turned into "-",
        ignoring upper/lower case. None or "" on either side -> False.

    is_library(osv_vuln, installed=None)
        installed: the package name on the Patch plan row, e.g. "Google Chrome".
        (Not called "package": the loop already uses that name for OSV's package.)
        With installed: only affected entries whose package name passes
        matches_package(name, installed) count. Without it: same as before.

    fix_type(required_action, osv_vuln, max_version, max_inclusive, package=None)
        Passes package to is_library() as installed. Nothing else changes.

Records are trimmed from api.osv.dev (November 2026):
https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q
https://osv.dev/vulnerability/GHSA-j7hp-h8jx-5ppr
https://osv.dev/vulnerability/GHSA-qqvq-6xgj-jw8g

Until is_library() takes installed, these tests are skipped.
"""

import inspect

import pytest

from app import fix_type as ft

if "installed" not in inspect.signature(ft.is_library).parameters:
    pytest.skip("is_library() doesn't take an installed package yet", allow_module_level=True)

matches_package = ft.matches_package


def record(*packages):
    """An OSV record with one affected entry per (ecosystem, name)."""
    return {"affected": [{"package": {"ecosystem": e, "name": n}} for e, n in packages]}


LOG4J = record(("Maven", "org.apache.logging.log4j:log4j-core"), ("Maven", "org.ops4j.pax.logging:pax-logging-log4j2"))
WEBP = record(("NuGet", "SkiaSharp"), ("Go", "github.com/chai2010/webp"), ("Android", "platform/external/webp"))
ELECTRON = record(("npm", "electron"))

KEV_MITIGATE = "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable."


# ---------- matches_package ----------

@pytest.mark.parametrize("osv_name, package, expected", [
    ("org.apache.logging.log4j:log4j-core", "log4j-core", True),
    ("com.guicedee.services:log4j-core", "log4j-core", True),
    ("electron", "Google Chrome", False),
    ("SkiaSharp", "Google Chrome", False),
    ("github.com/chai2010/webp", "Google Chrome", False),
    ("Pillow", "pillow", True),
    ("google-chrome", "Google Chrome", True),
    (None, "log4j-core", False),
    ("log4j-core", "", False),
    ("log4j-core", None, False),
])
def test_matches_package(osv_name, package, expected):
    assert matches_package(osv_name, package) is expected


# ---------- is_library with a package ----------

def test_log4j_core_matches_its_maven_package():
    assert ft.is_library(LOG4J, "log4j-core") is True


def test_chrome_is_not_skiasharp_or_webp():
    assert ft.is_library(WEBP, "Google Chrome") is False


def test_chrome_is_not_electron():
    assert ft.is_library(ELECTRON, "Google Chrome") is False


def test_without_a_package_works_as_before():
    assert ft.is_library(ELECTRON) is True


def test_entry_with_no_package_name():
    assert ft.is_library({"affected": [{"package": {"ecosystem": "npm"}}]}, "electron") is False


# ---------- fix_type with a package ----------

def test_chrome_falls_through_to_vendor_update():
    # NVD rule: CVE-2023-4863 is fixed in Chrome 116.0.5845.187
    assert ft.fix_type(KEV_MITIGATE, WEBP, "116.0.5845.187", False, package="Google Chrome") == "vendor update"


def test_log4j_core_is_still_a_library_update():
    assert ft.fix_type(None, LOG4J, "2.15.0", False, package="log4j-core") == "library update"


def test_fix_type_without_package_works_as_before():
    assert ft.fix_type(None, ELECTRON, "117.0.5938.132", False) == "library update"
