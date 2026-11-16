"""Tests for converting a CrowdStrike Falcon Spotlight export into VulnHQ's import format.

Build it in app/spotlight.py:

    spotlight_to_import(data) -> tuple[ImportFile, list[str]]
        data: the parsed JSON from GET /spotlight/combined/vulnerabilities/v1,
              either the API envelope {"resources": [...]} or a bare list.
        Returns (import_file, skipped):
            import_file: app.importer.ImportFile with one AssetImport per hostname,
                         ready for import_data()
            skipped:     one message per record that couldn't be used, so nothing
                         is dropped silently

    Rules:
        - Only status "open" or "reopen" counts. "closed" and "expired" are left out
          (not an error, so not in skipped).
        - A record with no cve.id or no host_info.hostname is skipped, with a message
          that includes the record's "id".
        - One asset per hostname, in the order first seen. Its CVEs keep their order,
          with no duplicates.
        - ip_address comes from host_info.local_ip.
        - internet_facing: host_info.internet_exposure "Yes" -> True, "No" -> False,
          anything else or missing -> None.
        - criticality: host_info.asset_criticality "Critical" 5, "High" 4, "Medium" 3,
          "Low" 2; anything else or missing -> None. Case doesn't matter.

Record shape based on the Spotlight API reference and the BSD-licensed DefectDojo
sample files (unittests/scans/crowdstrike_spotlight). All values here are fictional.
"""

import pytest

from app.importer import ImportFile

spotlight = pytest.importorskip("app.spotlight")
spotlight_to_import = spotlight.spotlight_to_import


def record(rid, cve="CVE-2021-44228", host="fin-pay01.example.com", status="open", **host_info):
    """One Spotlight vulnerability record with only the fields VulnHQ reads."""
    info = {"hostname": host, "local_ip": "192.0.2.11", **host_info}
    return {"id": rid, "status": status, "cve": {"id": cve}, "host_info": info}


# ---------- Shape of the result ----------


def test_returns_import_file_and_skipped_list():
    result, skipped = spotlight_to_import({"resources": [record("v1")]})
    assert isinstance(result, ImportFile)
    assert skipped == []


def test_accepts_api_envelope_and_bare_list():
    data = [record("v1")]
    from_envelope, _ = spotlight_to_import({"resources": data})
    from_list, _ = spotlight_to_import(data)
    assert from_envelope == from_list


def test_empty_export():
    result, skipped = spotlight_to_import({"resources": []})
    assert result.assets == []
    assert skipped == []


# ---------- Grouping by host ----------


def test_groups_cves_by_hostname_in_order():
    data = [
        record("v1", "CVE-2021-44228", "fin-pay01.example.com"),
        record("v2", "CVE-2023-4966", "fin-gl01.example.com"),
        record("v3", "CVE-2021-41773", "fin-pay01.example.com"),
    ]
    result, _ = spotlight_to_import(data)
    assert [a.hostname for a in result.assets] == ["fin-pay01.example.com", "fin-gl01.example.com"]
    assert result.assets[0].cves == ["CVE-2021-44228", "CVE-2021-41773"]
    assert result.assets[1].cves == ["CVE-2023-4966"]


def test_same_cve_twice_on_one_host_listed_once():
    # Spotlight reports one record per CVE per app, so a CVE can repeat on a host
    result, _ = spotlight_to_import([record("v1"), record("v2")])
    assert result.assets[0].cves == ["CVE-2021-44228"]


def test_ip_address_from_local_ip():
    result, _ = spotlight_to_import([record("v1", local_ip="198.51.100.7")])
    assert result.assets[0].ip_address == "198.51.100.7"


# ---------- Status ----------


@pytest.mark.parametrize("status", ["open", "reopen"])
def test_open_and_reopened_are_imported(status):
    result, _ = spotlight_to_import([record("v1", status=status)])
    assert result.assets[0].cves == ["CVE-2021-44228"]


@pytest.mark.parametrize("status", ["closed", "expired"])
def test_closed_and_expired_are_left_out(status):
    result, skipped = spotlight_to_import([record("v1", status=status)])
    assert result.assets == []
    assert skipped == []


# ---------- Records that can't be used ----------


def test_missing_cve_is_skipped_with_message():
    bad = record("v9")
    bad["cve"] = {}
    result, skipped = spotlight_to_import([bad, record("v1")])
    assert [a.hostname for a in result.assets] == ["fin-pay01.example.com"]
    assert len(skipped) == 1
    assert "v9" in skipped[0]


def test_missing_hostname_is_skipped_with_message():
    bad = record("v8", host="")
    result, skipped = spotlight_to_import([bad])
    assert result.assets == []
    assert len(skipped) == 1
    assert "v8" in skipped[0]


def test_missing_host_info_is_skipped():
    bad = {"id": "v7", "status": "open", "cve": {"id": "CVE-2021-44228"}}
    result, skipped = spotlight_to_import([bad])
    assert result.assets == []
    assert "v7" in skipped[0]


# ---------- Business context ----------


@pytest.mark.parametrize("exposure, expected", [("Yes", True), ("No", False), ("Unknown", None), (None, None)])
def test_internet_exposure(exposure, expected):
    extra = {} if exposure is None else {"internet_exposure": exposure}
    result, _ = spotlight_to_import([record("v1", **extra)])
    assert result.assets[0].internet_facing is expected


@pytest.mark.parametrize(
    "level, expected",
    [("Critical", 5), ("High", 4), ("Medium", 3), ("Low", 2), ("critical", 5), ("Unassigned", None), (None, None)],
)
def test_asset_criticality(level, expected):
    extra = {} if level is None else {"asset_criticality": level}
    result, _ = spotlight_to_import([record("v1", **extra)])
    assert result.assets[0].criticality == expected
