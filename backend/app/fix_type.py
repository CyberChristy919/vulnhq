"""Fix type: how hard a fix is, using only facts from CISA KEV, OSV.dev and NVD."""

# OSV ecosystems for libraries that get built into apps (fix = rebuild and test)
LIBRARY_ECOSYSTEMS = {"Maven", "PyPI", "npm", "NuGet", "Go", "crates.io", "RubyGems", "Packagist", "Hex", "Pub"}

# Easiest to hardest; package_fix_type() picks the last one it finds
EFFORT_ORDER = ["vendor update", "library update", "replace"]


def kev_says_replace(required_action):
    """True if KEV says the product is end-of-life and must be replaced."""
    # None or "" becomes "", so the checks below just return False
    text = (required_action or "").lower()
    return "end-of-life" in text or "disconnect" in text


def is_library(osv_vuln):
    """True if OSV lists an affected package in a library ecosystem."""
    # None becomes {}, and a missing "affected" becomes [], so the loop just doesn't run
    for entry in (osv_vuln or {}).get("affected", []):
        # Chrome's entry has no "package", so fall back to {}
        package = entry.get("package") or {}
        if package.get("ecosystem") in LIBRARY_ECOSYSTEMS:
            return True
    return False


def fixed_version(max_version, max_inclusive):
    """The first fixed version, or None if the source doesn't name one."""
    # An exclusive end ("before 124.0.6367.201") is the first version with the fix
    if max_version and not max_inclusive:
        return max_version
    # An inclusive end ("through 2.16.0") or no end doesn't name a fix
    return None


def fix_type(required_action, osv_vuln, max_version, max_inclusive):
    """'replace', 'library update', 'vendor update' or 'unknown'; first match wins."""
    # KEV says end-of-life: no patch will come, so the product must be replaced
    if kev_says_replace(required_action):
        return "replace"
    # OSV says it's a library: every app that bundles it needs a rebuild and testing
    if is_library(osv_vuln):
        return "library update"
    # NVD names a fixed version: the vendor has an update to install
    if fixed_version(max_version, max_inclusive):
        return "vendor update"
    # No source answered, so say so and don't guess
    return "unknown"


def package_fix_type(types):
    """The hardest known fix type across a package's CVEs."""
    # Drop "unknown" by keeping only types in EFFORT_ORDER
    known = [t for t in types if t in EFFORT_ORDER]
    # Nothing known about any CVE in this package
    if not known:
        return "unknown"
    # The type that sits furthest right in EFFORT_ORDER is the hardest
    return max(known, key=EFFORT_ORDER.index)