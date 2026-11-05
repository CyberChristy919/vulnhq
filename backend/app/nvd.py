"""Live NVD lookup for software that isn't covered by data/vuln_rules.json.

How it works:
1. Find the NVD product ID (CPE) for the software name:
   the item's own "cpe" field, then data/cpe_aliases.json, then an NVD product search.
2. Ask NVD for CVEs affecting that product and version (virtualMatchString).
3. Double-check each CVE: the product must be listed as vulnerable (not just the
   platform it runs on) and the version must fall inside the published range.

Results are cached in data/nvd_cache.json so repeat lookups are instant
and work offline. NVD allows 5 requests per 30 seconds without an API key and
50 with one; set NVD_API_KEY in .env for faster lookups.
"""

import json
import re
import time
import urllib.parse
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

import httpx

from app.config import settings
from app.versions import in_range, parse_version

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
ALIASES_PATH = DATA_DIR / "cpe_aliases.json"
CACHE_PATH = DATA_DIR / "nvd_cache.json"

CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class NvdUnavailable(Exception):
    """NVD couldn't be reached (network blocked, timeout, or rate limit)."""


class NotSupported(Exception):
    """The software can't be checked reliably against NVD (see cpe_aliases.json)."""


@dataclass
class NvdMatch:
    cve_id: str
    title: str
    cvss: float | None
    product: str  # part:vendor:product, e.g. a:apache:tomcat
    broad: bool = False  # matched only by a wide range like 15.0 through 15.6


# ---------- Name to product ID ----------

def normalize(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


@lru_cache
def load_aliases() -> dict:
    return json.loads(ALIASES_PATH.read_text(encoding="utf-8"))


def parse_cpe(value: str) -> str:
    """Accepts vendor:product, a:vendor:product, or a full cpe:2.3 string."""
    parts = value.strip().split(":")
    if parts[:2] == ["cpe", "2.3"]:
        parts = parts[2:5]
    if len(parts) == 2:
        parts = ["a", *parts]
    if len(parts) < 3 or parts[0] not in ("a", "o", "h"):
        raise ValueError(f"Can't read CPE '{value}'. Use vendor:product, e.g. apache:tomcat")
    return ":".join(p.lower() for p in parts[:3])


def escape_version(version: str) -> str:
    """CPE format: lowercase, with special characters backslash-escaped, e.g. 15.2\\(7\\)e3."""
    return re.sub(r"([^a-z0-9._-])", r"\\\1", version.strip().lower())


# ---------- Cache ----------

def _load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    CACHE_PATH.write_text(json.dumps(cache, indent=1), encoding="utf-8")


# ---------- Version check on NVD data ----------

def affects(cve: dict, product: str, version: str) -> str | None:
    """How the CVE matches this product and version: "exact", "range", "broad", or None.

    "broad" means the only matching range has short bounds (e.g., 15.0 through 15.6)
    while the installed version is more specific, so the vendor advisory should confirm it.
    """
    want = product.lower()
    best = None
    depth = len(parse_version(version))
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                crit = m["criteria"].split(":")
                if ":".join(crit[2:5]).lower() != want:
                    continue
                listed = crit[5]
                has_range = any(k in m for k in (
                    "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding"))
                if listed not in ("*", "-"):
                    if parse_version(listed) == parse_version(version):
                        return "exact"
                    continue
                if not has_range:
                    continue  # "all versions" entries are too broad to trust
                lo = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                hi = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                if in_range(version, lo, "versionStartIncluding" in m, hi, "versionEndIncluding" in m):
                    bound = max(len(parse_version(lo or "")), len(parse_version(hi or "")))
                    if bound >= min(depth, 3):
                        best = "range"
                    elif best is None:
                        best = "broad"
    return best


def _cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        primary = [e for e in entries if e.get("type") == "Primary"] or entries
        if primary:
            return primary[0]["cvssData"]["baseScore"]
    return None


def _title(cve: dict) -> str:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    first = desc.split(". ")[0].strip()
    return (first[:197] + "...") if len(first) > 200 else first


# ---------- NVD client ----------

class NvdClient:
    def __init__(self, api_key: str | None = None, timeout: float = 30):
        self.api_key = settings.nvd_api_key if api_key is None else api_key
        self.delay = 0.7 if self.api_key else 6.5
        self.timeout = timeout
        self._last = 0.0
        self.cache = _load_cache()
        self.requests_made = 0

    def _get(self, url: str, params: str) -> dict:
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            resp = httpx.get(f"{url}?{params}", headers=headers, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise NvdUnavailable(f"Can't reach NVD: {exc.__class__.__name__}") from exc
        finally:
            self._last = time.monotonic()
            self.requests_made += 1
        if resp.status_code in (403, 429, 503):
            raise NvdUnavailable(f"NVD returned {resp.status_code} (rate limit or outage). Try again shortly.")
        if resp.status_code == 404:
            raise NotSupported("NVD couldn't read this product or version format.")
        if resp.status_code >= 400:
            raise NvdUnavailable(f"NVD returned {resp.status_code}.")
        return resp.json()

    def resolve(self, name: str, cpe: str | None = None) -> str:
        """Returns part:vendor:product for a software name."""
        if cpe:
            return parse_cpe(cpe)
        key = normalize(name)
        aliases = load_aliases()
        if key in aliases.get("unsupported", {}):
            raise NotSupported(aliases["unsupported"][key])
        if key in aliases["products"]:
            return aliases["products"][key]
        cached = self.cache.get("products", {}).get(key)
        if cached:
            return cached
        found = self._search_product(name)
        self.cache.setdefault("products", {})[key] = found
        _save_cache(self.cache)
        return found

    def _search_product(self, name: str) -> str:
        params = urllib.parse.urlencode({"keywordSearch": name, "resultsPerPage": 200})
        data = self._get(CPE_URL, params)
        counts: dict[str, int] = {}
        name_tokens = set(re.findall(r"[a-z0-9]+", name.lower()))
        for p in data.get("products", []):
            if p["cpe"].get("deprecated"):
                continue
            pvp = ":".join(p["cpe"]["cpeName"].split(":")[2:5])
            prod_tokens = set(re.findall(r"[a-z0-9]+", pvp.split(":")[2]))
            if prod_tokens & name_tokens:
                counts[pvp] = counts.get(pvp, 0) + 1
        if not counts:
            raise NotSupported("No matching product found in NVD. Add a 'cpe' (vendor:product) to this item.")
        return max(counts, key=counts.get)

    def lookup(self, product: str, version: str, use_cache: bool = True) -> list[NvdMatch]:
        key = f"{product}|{version}"
        cves = self.cache.get("cves", {})
        if use_cache and key in cves:
            return [NvdMatch(**m) for m in cves[key]]

        part, vendor, prod = product.split(":")
        match_string = f"cpe:2.3:{part}:{vendor}:{prod}:{escape_version(version)}"
        results: list[NvdMatch] = []
        start = 0
        while True:
            params = urllib.parse.urlencode(
                {"virtualMatchString": match_string, "resultsPerPage": 2000, "startIndex": start}
            )
            data = self._get(CVE_URL, params)
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                if cve.get("vulnStatus") == "Rejected":
                    continue
                how = affects(cve, product, version)
                if how:
                    results.append(NvdMatch(cve["id"], _title(cve), _cvss(cve), product, how == "broad"))
            start += data.get("resultsPerPage", 0)
            if start >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
                break

        self.cache.setdefault("cves", {})[key] = [asdict(m) for m in results]
        _save_cache(self.cache)
        return results
