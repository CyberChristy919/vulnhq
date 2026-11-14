"""Tests for passing the installed package through lookup_fix_types().

These tests describe the code before it exists. Change app/fix_lookup.py:

    lookup_fix_types(cve_ids, required_actions, nvd_fixed, osv_record, package=None)
        Pass package to fix_type(). Nothing else changes.

Until lookup_fix_types() takes a package, these tests are skipped.
"""

import inspect

import pytest

fl = pytest.importorskip("app.fix_lookup")
if "package" not in inspect.signature(fl.lookup_fix_types).parameters:
    pytest.skip("lookup_fix_types() doesn't take a package yet", allow_module_level=True)

# Trimmed from https://osv.dev/vulnerability/GHSA-j7hp-h8jx-5ppr
WEBP = {"affected": [{"package": {"ecosystem": "NuGet", "name": "SkiaSharp"}}]}
LOG4J = {"affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}}]}


def test_chrome_with_a_webp_cve_is_a_vendor_update():
    result = fl.lookup_fix_types(["CVE-2023-4863"], {}, {"CVE-2023-4863": "116.0.5845.187"},
                                 lambda cve: WEBP, package="Google Chrome")
    assert result == {"CVE-2023-4863": "vendor update"}


def test_log4j_core_is_a_library_update():
    result = fl.lookup_fix_types(["CVE-2021-44228"], {}, {"CVE-2021-44228": "2.15.0"},
                                 lambda cve: LOG4J, package="log4j-core")
    assert result == {"CVE-2021-44228": "library update"}


def test_without_a_package_works_as_before():
    result = fl.lookup_fix_types(["CVE-2023-4863"], {}, {}, lambda cve: WEBP)
    assert result == {"CVE-2023-4863": "library update"}
