"""Package-level patch plan (SRS FR-MOB-01, Q3 and Q8).

Groups open findings by software package so users can see which patch
removes the most risk, and what patching one package would change.
"""

from dataclasses import dataclass


def package_name(label: str | None) -> str:
    """'Apache HTTP Server 2.4.49' -> 'Apache HTTP Server'."""
    # No label means we can't tell the package; keep the finding under Unknown
    if not label:
        return "Unknown"
    words = []
    for word in label.split():
        # The version starts at the first word that begins with a digit
        if word[0].isdigit():
            break
        words.append(word)
    # If the label was only a version, keep the whole label
    return " ".join(words) or label


@dataclass
class PackagePlan:
    package: str
    findings: int
    cves: list[str]
    hosts: list[str]
    versions: list[str]
    kev_findings: int
    critical_findings: int
    # Total risk score that goes away if this package is patched everywhere
    risk_removed: float


def patch_plan(items) -> list[PackagePlan]:
    """One row per package, biggest risk reduction first (Q3)."""
    # Put every finding in a group named after its package
    groups: dict[str, list] = {}
    for item in items:
        groups.setdefault(package_name(item.software), []).append(item)

    plan = []
    for name, group in groups.items():
        plan.append(
            PackagePlan(
                package=name,
                findings=len(group),
                cves=sorted({i.cve_id for i in group}),
                hosts=sorted({i.hostname for i in group}),
                versions=sorted({i.software for i in group}),
                kev_findings=sum(i.in_kev for i in group),
                critical_findings=sum(i.tier == "Critical" for i in group),
                risk_removed=round(sum(i.risk_score for i in group), 1),
            )
        )
    # Biggest risk reduction first; ties go A to Z by package name
    plan.sort(key=lambda p: (-p.kev_findings, -p.risk_removed, p.package))
    return plan


def patch_impact(items, package: str) -> dict:
    """What patching one package on every host would remove (Q8)."""
    wanted = package.lower()
    patched = [i for i in items if package_name(i.software).lower() == wanted]
    remaining = [i for i in items if package_name(i.software).lower() != wanted]

    # Distinct CVE IDs; a CVE on several hosts counts once
    cves_before = len({i.cve_id for i in items})
    cves_after = len({i.cve_id for i in remaining})
    return {
        "package": package,
        "hosts": sorted({i.hostname for i in patched}),
        "findings_before": len(items),
        "findings_after": len(remaining),
        "cves_before": cves_before,
        "cves_after": cves_after,
        "cves_removed": cves_before - cves_after,
    }