"""OSV.dev lookup: is the affected software a library? Feeds fix_type.is_library().

OSV's record for a CVE often has no package ecosystem; the details live in its
aliases (e.g. GHSA-... GitHub advisories). So record() fetches the CVE, then each
alias, and merges their "affected" lists. Answers are cached in data/osv_cache.json
so repeat lookups are instant and work offline.
"""

import json
from pathlib import Path

import httpx

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CACHE_PATH = DATA_DIR / "osv_cache.json"

VULN_URL = "https://api.osv.dev/v1/vulns/{}"


class OsvUnavailable(Exception):
    """OSV couldn't be reached (network error, rate limit, or outage)."""


class OsvClient:
    def __init__(self, timeout: float = 30, cache_path: Path = CACHE_PATH):
        self.timeout = timeout
        self.cache_path = Path(cache_path)
        self.requests_made = 0
        # Load saved answers; a missing or broken file starts empty
        self.cache = {}
        if self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.cache = {}

    def _get(self, vuln_id: str) -> dict | None:
        """One OSV record by ID, or None if OSV doesn't have it."""
        try:
            resp = httpx.get(VULN_URL.format(vuln_id), timeout=self.timeout)
        except httpx.HTTPError as exc:
            # No network, timeout, or connection reset
            raise OsvUnavailable(f"Can't reach OSV: {exc.__class__.__name__}") from exc
        finally:
            # Count every attempt, whether it worked or not
            self.requests_made += 1
        # OSV doesn't have this ID; that's an answer, not an error
        if resp.status_code == 404:
            return None
        # Rate limit or outage: try again later, and don't save anything
        if resp.status_code == 429 or resp.status_code >= 500:
            raise OsvUnavailable(f"OSV returned {resp.status_code}. Try again shortly.")
        return resp.json()

    def record(self, cve_id: str, use_cache: bool = True) -> dict | None:
        """The CVE's OSV record with its aliases' "affected" lists merged in."""
        # Already looked up: no request needed, works offline
        if use_cache and cve_id in self.cache:
            return self.cache[cve_id]

        base = self._get(cve_id)
        if base is None:
            answer = None
        else:
            affected = list(base.get("affected", []))
            # Aliases (like GHSA-...) often hold the package ecosystem the CVE record lacks
            for alias in base.get("aliases", []):
                alias_record = self._get(alias)
                if alias_record:
                    affected += alias_record.get("affected", [])
            answer = {"id": cve_id, "aliases": base.get("aliases", []), "affected": affected}

        # Save the answer, even None, so the next lookup is instant
        self.cache[cve_id] = answer
        self.cache_path.write_text(json.dumps(self.cache, indent=1), encoding="utf-8")
        return answer