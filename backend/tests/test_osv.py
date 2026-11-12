"""Tests for the OSV.dev lookup that feeds fix_type.is_library().

These tests describe the code before it exists. Build it in app/osv.py.
No real network calls: httpx.get is replaced with a fake that returns trimmed real records.

Why aliases matter:
    OSV's record for CVE-2021-44228 (Log4j) has no package ecosystem. The Maven details
    live in its alias GHSA-jfh8-c2jp-5v3q (a GitHub advisory). So the lookup fetches the
    CVE record, then each ID in its "aliases", and merges their "affected" lists.
    "related" IDs (distro advisories like SUSE-SU-...) are a different thing; don't follow them.

app/osv.py:

    VULN_URL = "https://api.osv.dev/v1/vulns/{}"          # .format(vuln_id)
    CACHE_PATH = DATA_DIR / "osv_cache.json"               # DATA_DIR like app/nvd.py

    class OsvUnavailable(Exception)
        OSV couldn't be reached: network error, 429, or any 5xx.

    class OsvClient:
        __init__(self, timeout=30, cache_path=CACHE_PATH)
            Loads the cache file if it exists (bad JSON -> empty cache), like app/nvd.py.
            self.requests_made = 0

        _get(vuln_id) -> dict | None
            httpx.get(VULN_URL.format(vuln_id), timeout=self.timeout); add 1 to requests_made.
            200 -> resp.json()   404 -> None
            429 or 5xx, or httpx.HTTPError -> raise OsvUnavailable

        record(cve_id, use_cache=True) -> dict | None
            Not found -> None.
            Found -> {"id": cve_id,
                      "aliases": the CVE record's aliases,
                      "affected": the CVE record's affected + each alias record's affected}
            An alias that's not found is skipped.
            Saves the answer (including None) to the cache file, so repeat lookups
            make no requests and work offline. use_cache=False always asks OSV again.
            An outage raises OsvUnavailable and saves nothing.

Until app/osv.py exists, these tests are skipped.
"""

import json

import httpx
import pytest

osv = pytest.importorskip("app.osv")
from app.fix_type import is_library

# ---------- Trimmed real records (api.osv.dev, November 2026) ----------

RECORDS = {
    # The CVE record has no ecosystem; the Maven package is only in the GHSA alias
    "CVE-2021-44228": {
        "id": "CVE-2021-44228",
        "aliases": ["GHSA-jfh8-c2jp-5v3q"],
        "related": ["SUSE-SU-2021:4096-1"],
        "affected": [{"ranges": []}],
    },
    "GHSA-jfh8-c2jp-5v3q": {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "aliases": ["CVE-2021-44228"],
        "affected": [
            {
                "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}],
            }
        ],
    },
    # Chrome: no aliases, no package ecosystem
    "CVE-2024-4671": {
        "id": "CVE-2024-4671",
        "related": ["openSUSE-SU-2024:0142-1"],
        "affected": [{"ranges": []}],
    },
}


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


@pytest.fixture
def calls(monkeypatch):
    """Replace httpx.get with RECORDS; returns the list of URLs requested."""
    urls = []

    def fake_get(url, **kwargs):
        urls.append(url)
        vuln_id = url.rsplit("/", 1)[-1]
        if vuln_id in RECORDS:
            return FakeResponse(200, RECORDS[vuln_id])
        return FakeResponse(404, {"code": 5, "message": "Vulnerability not found"})

    monkeypatch.setattr(osv.httpx, "get", fake_get)
    return urls


@pytest.fixture
def client(tmp_path):
    # A fresh cache file per test, so tests don't share answers
    return osv.OsvClient(cache_path=tmp_path / "osv_cache.json")


# ---------- Looking up records ----------

def test_url_uses_the_vuln_id(calls, client):
    client.record("CVE-2024-4671")
    assert calls[0] == "https://api.osv.dev/v1/vulns/CVE-2024-4671"


def test_log4j_follows_its_ghsa_alias(calls, client):
    rec = client.record("CVE-2021-44228")
    assert "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q" in calls
    assert rec["id"] == "CVE-2021-44228"
    assert rec["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]


def test_log4j_merged_record_is_a_library(calls, client):
    # Without the alias, Log4j would wrongly look like it isn't a library
    assert is_library(client.record("CVE-2021-44228")) is True


def test_merged_affected_keeps_both_lists(calls, client):
    # 1 entry from the CVE record + 1 from the GHSA alias
    assert len(client.record("CVE-2021-44228")["affected"]) == 2


def test_chrome_is_not_a_library(calls, client):
    assert is_library(client.record("CVE-2024-4671")) is False


def test_related_ids_are_not_followed(calls, client):
    client.record("CVE-2021-44228")
    assert not any("SUSE" in url for url in calls)


def test_not_found_returns_none(calls, client):
    assert client.record("CVE-0000-00000") is None


def test_missing_alias_is_skipped(monkeypatch, calls, client):
    # The alias points at a record OSV doesn't have
    monkeypatch.setitem(RECORDS, "CVE-2099-0001", {"id": "CVE-2099-0001", "aliases": ["GHSA-none"], "affected": []})
    rec = client.record("CVE-2099-0001")
    assert rec is not None
    assert rec["affected"] == []


def test_counts_requests(calls, client):
    client.record("CVE-2021-44228")  # the CVE plus its one alias
    assert client.requests_made == 2


# ---------- Cache ----------

def test_second_lookup_uses_the_cache(calls, client):
    client.record("CVE-2021-44228")
    before = len(calls)
    client.record("CVE-2021-44228")
    assert len(calls) == before


def test_not_found_is_cached_too(calls, client):
    client.record("CVE-0000-00000")
    client.record("CVE-0000-00000")
    assert len(calls) == 1


def test_cache_file_works_for_a_new_client(calls, tmp_path):
    path = tmp_path / "osv_cache.json"
    osv.OsvClient(cache_path=path).record("CVE-2024-4671")
    before = len(calls)
    rec = osv.OsvClient(cache_path=path).record("CVE-2024-4671")
    assert len(calls) == before
    assert rec["id"] == "CVE-2024-4671"


def test_cache_file_is_json(calls, client, tmp_path):
    client.record("CVE-2024-4671")
    saved = json.loads((tmp_path / "osv_cache.json").read_text(encoding="utf-8"))
    assert "CVE-2024-4671" in saved


def test_bad_cache_file_starts_empty(calls, tmp_path):
    path = tmp_path / "osv_cache.json"
    path.write_text("not json", encoding="utf-8")
    assert osv.OsvClient(cache_path=path).record("CVE-2024-4671")["id"] == "CVE-2024-4671"


def test_use_cache_false_asks_again(calls, client):
    client.record("CVE-2024-4671")
    client.record("CVE-2024-4671", use_cache=False)
    assert len(calls) == 2


# ---------- Outages ----------

@pytest.mark.parametrize("status", [429, 500, 503])
def test_busy_or_down_raises_unavailable(monkeypatch, client, status):
    monkeypatch.setattr(osv.httpx, "get", lambda url, **kwargs: FakeResponse(status))
    with pytest.raises(osv.OsvUnavailable):
        client.record("CVE-2024-4671")


def test_network_error_raises_unavailable(monkeypatch, client):
    def no_network(url, **kwargs):
        raise httpx.ConnectError("connection reset")

    monkeypatch.setattr(osv.httpx, "get", no_network)
    with pytest.raises(osv.OsvUnavailable):
        client.record("CVE-2024-4671")


def test_outage_is_not_cached(monkeypatch, calls, client):
    real_get = osv.httpx.get  # the RECORDS fake from the calls fixture
    monkeypatch.setattr(osv.httpx, "get", lambda url, **kwargs: FakeResponse(503))
    with pytest.raises(osv.OsvUnavailable):
        client.record("CVE-2024-4671")
    # OSV is back; the next lookup must ask again, not reuse a saved failure
    monkeypatch.setattr(osv.httpx, "get", real_get)
    assert client.record("CVE-2024-4671")["id"] == "CVE-2024-4671"
