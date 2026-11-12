"""Tests for the fix type on each Patch plan row.

These tests describe the code before it exists. Change app/patch_plan.py:

    PackagePlan gets one new field, last in the list:
        fix_type: str = "unknown"
        The default keeps every PackagePlan(...) built without it working
        (test_explain.py builds them that way).

    patch_plan(items, fix_types=None) -> list[PackagePlan]
        fix_types: a dict of CVE ID -> fix type from fix_type.fix_type(),
                   e.g. {"CVE-2021-44228": "library update"}.
                   None means no lookups were done.
        Each row's fix_type is package_fix_type() over the fix types of its CVEs.
        A CVE missing from the dict counts as "unknown".
        Fix type explains the order; it never changes it. The sort stays
        most KEV findings first, then biggest risk_removed, then name A to Z.

This step only takes the answers in. Getting them from KEV, OSV and NVD
comes next, so nothing here makes a network call.

Until PackagePlan has a fix_type field, these tests are skipped.
"""

import pytest

from app import patch_plan as pp
from tests.test_patch_plan import ITEMS, Item

if "fix_type" not in pp.PackagePlan.__dataclass_fields__:
    pytest.skip("PackagePlan has no fix_type field yet", allow_module_level=True)

patch_plan = pp.patch_plan


def by_package(plan):
    """{package name: fix type} so tests don't depend on row order."""
    return {p.package: p.fix_type for p in plan}


def test_no_fix_types_means_unknown():
    # Called the old way, every row says "unknown"
    assert set(by_package(patch_plan(ITEMS)).values()) == {"unknown"}


def test_fix_type_comes_from_its_cves():
    fix_types = {
        "CVE-2021-41773": "vendor update",
        "CVE-2021-42013": "vendor update",
        "CVE-2021-44228": "library update",
    }
    result = by_package(patch_plan(ITEMS, fix_types))
    assert result["Apache HTTP Server"] == "vendor update"
    assert result["Log4j"] == "library update"


def test_cve_missing_from_dict_is_unknown():
    # OpenSSL's CVE wasn't looked up, so don't guess
    fix_types = {"CVE-2021-44228": "library update"}
    assert by_package(patch_plan(ITEMS, fix_types))["OpenSSL"] == "unknown"


def test_hardest_fix_wins_for_a_package():
    # One Apache CVE needs a vendor update, the other a replacement
    fix_types = {"CVE-2021-41773": "vendor update", "CVE-2021-42013": "replace"}
    assert by_package(patch_plan(ITEMS, fix_types))["Apache HTTP Server"] == "replace"


def test_known_fix_beats_unknown():
    fix_types = {"CVE-2021-41773": "unknown", "CVE-2021-42013": "vendor update"}
    assert by_package(patch_plan(ITEMS, fix_types))["Apache HTTP Server"] == "vendor update"


def test_fix_type_never_changes_the_order():
    # Even when the top package is the hardest to fix, it stays on top
    fix_types = {
        "CVE-2021-41773": "replace",
        "CVE-2021-42013": "replace",
        "CVE-2021-44228": "library update",
        "CVE-2022-0778": "vendor update",
    }
    before = [p.package for p in patch_plan(ITEMS)]
    after = [p.package for p in patch_plan(ITEMS, fix_types)]
    assert after == before


def test_same_cve_on_many_hosts():
    # Chrome on two hosts, one CVE: one answer covers both findings
    items = [
        Item("Google Chrome 124.0.6367.60", "CVE-2024-4671", "pc01", True),
        Item("Google Chrome 124.0.6367.91", "CVE-2024-4671", "pc02", True),
    ]
    row = patch_plan(items, {"CVE-2024-4671": "vendor update"})[0]
    assert row.findings == 2
    assert row.fix_type == "vendor update"


def test_empty_items():
    assert patch_plan([], {"CVE-2024-4671": "vendor update"}) == []


def test_default_when_built_by_hand():
    # Rows built without fix_type (like in test_explain.py) still work
    row = pp.PackagePlan("X", 1, ["CVE-1"], ["h"], ["X 1"], 0, 0, 1.0)
    assert row.fix_type == "unknown"
