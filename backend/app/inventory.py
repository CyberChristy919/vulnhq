"""Imports an asset inventory with installed software and matches it to CVEs.

Expected format (extra fields are ignored):
{
  "metadata": {...},
  "assets": [
    {
      "asset_id": "FIN-SRV-001",
      "hostname": "fin-app01.corp.local",
      "ip_address": "10.10.1.11",
      "asset_type": "server",
      "department": "Finance",
      "criticality": "critical",            # critical / high / medium / low, or 1 to 5
      "os": "Windows Server 2019",
      "os_version": "10.0.17763",
      "last_scan_date": "2026-10-12",
      "installed_software": [{"name": "Apache HTTP Server", "version": "2.4.49"}]
    }
  ]
}

Software is matched in two ways:
1. data/vuln_rules.json: vetted rules (confirmed or conditional findings).
2. Live NVD lookup for products the rules don't cover (confidence "nvd").
   An item can include "cpe": "vendor:product" to tell NVD exactly what it is.

Re-importing the same file updates assets and replaces their software list.
Existing findings are kept; new matches are added.
"""

import re
from datetime import date

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.matcher import covered_products, match_software
from app.nvd import NotSupported, NvdClient, NvdUnavailable
from app.models import Asset, Finding, InstalledSoftware, Vulnerability
from app.schemas import MoneyMovement

CRITICALITY_MAP = {"critical": 5, "high": 4, "medium": 3, "low": 2}


class SoftwareIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    version: str
    cpe: str | None = None  # optional NVD product ID, e.g. "apache:tomcat"


class InventoryAsset(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asset_id: str | None = None
    hostname: str
    ip_address: str | None = None
    asset_type: str | None = None
    department: str | None = None
    criticality: int = 3
    os: str | None = None
    os_version: str | None = None
    last_scan_date: date | None = None
    installed_software: list[SoftwareIn] = []
    # Optional business context
    internet_facing: bool | None = None
    money_movement: MoneyMovement | None = None
    data_classification: str | None = None

    @field_validator("criticality", mode="before")
    @classmethod
    def map_criticality(cls, value):
        if isinstance(value, str):
            key = value.strip().lower()
            if key in CRITICALITY_MAP:
                return CRITICALITY_MAP[key]
            raise ValueError(f"criticality must be one of {', '.join(CRITICALITY_MAP)} or 1 to 5")
        return value

    @field_validator("criticality")
    @classmethod
    def check_range(cls, value: int) -> int:
        if not 1 <= value <= 5:
            raise ValueError("criticality must be between 1 and 5")
        return value


class InventoryFile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    metadata: dict | None = None
    assets: list[InventoryAsset]


class InventorySummary(BaseModel):
    assets_created: int = 0
    assets_updated: int = 0
    software_items: int = 0
    findings_created: int = 0
    kev_findings: int = 0
    conditional_findings: int = 0
    assets_with_findings: int = 0
    nvd_findings: int = 0
    nvd_lookups: int = 0
    new_cves_added: list[str] = []
    # Software that couldn't be checked, with the reason
    not_checked: list[str] = []
    # Software with no match but whose product appears in CISA KEV
    needs_review: list[str] = []


class ContextEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hostname: str
    internet_facing: bool | None = None
    money_movement: MoneyMovement | None = None
    data_classification: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)


class ContextFile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    assets: list[ContextEntry]


class ContextSummary(BaseModel):
    assets_updated: int = 0
    not_found: list[str] = []


class Options(BaseModel):
    use_nvd: bool = True
    # NVD matches below this CVSS are skipped unless the CVE is in KEV
    min_cvss: float = 7.0


def import_inventory(
    db: Session, data: InventoryFile, options: Options | None = None, client: NvdClient | None = None
) -> InventorySummary:
    options = options or Options()
    summary = InventorySummary()
    checker = SoftwareChecker(db, options, summary, client)

    for item in data.assets:
        asset = db.scalar(select(Asset).where(Asset.hostname == item.hostname))
        if asset is None:
            asset = Asset(hostname=item.hostname)
            db.add(asset)
            summary.assets_created += 1
        else:
            summary.assets_updated += 1

        asset.external_id = item.asset_id
        asset.ip_address = item.ip_address
        asset.asset_type = item.asset_type
        asset.department = item.department
        asset.owner = asset.owner or item.department
        asset.criticality = item.criticality
        asset.os = item.os
        asset.os_version = item.os_version
        asset.last_scan_date = item.last_scan_date
        if item.internet_facing is not None:
            asset.internet_facing = item.internet_facing
        if item.money_movement is not None:
            asset.money_movement = item.money_movement
        if item.data_classification is not None:
            asset.data_classification = item.data_classification

        # Replace the software list with what's in the file
        asset.software = [InstalledSoftware(name=s.name, version=s.version) for s in item.installed_software]
        summary.software_items += len(item.installed_software)
        db.flush()

        # Check installed software plus the operating system itself
        to_check = list(item.installed_software)
        if item.os and item.os_version:
            to_check.append(SoftwareIn(name=item.os, version=item.os_version))

        before = summary.findings_created
        for software in to_check:
            checker.check(asset, software)
        if summary.findings_created > before or db.scalar(
            select(Finding.id).where(Finding.asset_id == asset.id).limit(1)
        ):
            summary.assets_with_findings += 1

    db.commit()
    summary.nvd_lookups = checker.client.requests_made if checker.client else 0
    return summary


def add_software(
    db: Session, hostname: str, software: SoftwareIn, options: Options | None = None,
    client: NvdClient | None = None,
) -> tuple[InventorySummary, list[Finding]] | None:
    """Adds one software item to an existing asset and checks it. None if the asset doesn't exist."""
    asset = db.scalar(select(Asset).where(Asset.hostname == hostname))
    if asset is None:
        return None
    summary = InventorySummary(assets_updated=1, software_items=1)
    checker = SoftwareChecker(db, options or Options(), summary, client)
    db.add(InstalledSoftware(asset_id=asset.id, name=software.name, version=software.version))
    created = checker.check(asset, software)
    if created:
        summary.assets_with_findings = 1
    db.commit()
    summary.nvd_lookups = checker.client.requests_made if checker.client else 0
    return summary, created


class SoftwareChecker:
    def __init__(self, db: Session, options: Options, summary: InventorySummary, client: NvdClient | None):
        self.db = db
        self.options = options
        self.summary = summary
        self.client = client if client is not None else (NvdClient() if options.use_nvd else None)
        self.nvd_down: str | None = None

    def check(self, asset: Asset, software: SoftwareIn) -> list[Finding]:
        created = self._match(asset, software)
        label = software_label(software)
        if not created and not self.db.scalar(
            select(Finding.id).where(Finding.asset_id == asset.id, Finding.software == label).limit(1)
        ):
            self._kev_hint(software)
        return created

    def _match(self, asset: Asset, software: SoftwareIn) -> list[Finding]:
        label = software_label(software)
        created: list[Finding] = []

        # 1. Vetted rules
        for match in match_software(software.name, software.version):
            finding = self._add(asset, match.cve_id, match.title, match.cvss, label,
                                "conditional" if match.condition else "confirmed", match.condition)
            if finding:
                created.append(finding)
                if match.condition:
                    self.summary.conditional_findings += 1

        # 2. NVD for products the rules don't cover (or when a cpe is given)
        covered = software.name.strip().lower() in covered_products()
        if covered and not software.cpe:
            return created
        if not self.options.use_nvd:
            self._not_checked(label, "not in vuln_rules.json and NVD lookup is off")
            return created
        if self.nvd_down:
            self._not_checked(label, self.nvd_down)
            return created
        try:
            product = self.client.resolve(software.name, software.cpe)
            matches = self.client.lookup(product, software.version)
        except NvdUnavailable as exc:
            # Stop calling NVD for the rest of this import
            self.nvd_down = str(exc)
            self._not_checked(label, self.nvd_down)
            return created
        except (NotSupported, ValueError) as exc:
            self._not_checked(label, str(exc))
            return created

        note = f"Matched by NVD version data for {product}. Not yet vendor-verified."
        broad_note = (f"NVD lists a wide version range for {product}, not a specific fixed version. "
                      "Confirm with the vendor advisory.")
        for m in matches:
            vuln = self.db.get(Vulnerability, m.cve_id)
            in_kev = bool(vuln and vuln.in_kev)
            if not in_kev and (m.cvss is None or m.cvss < self.options.min_cvss):
                continue
            finding = self._add(asset, m.cve_id, m.title, m.cvss, label, "nvd",
                                broad_note if m.broad else note)
            if finding:
                created.append(finding)
                self.summary.nvd_findings += 1
        return created

    def _add(self, asset, cve_id, title, cvss, label, confidence, note) -> Finding | None:
        vuln = self.db.get(Vulnerability, cve_id)
        if vuln is None:
            vuln = Vulnerability(cve_id=cve_id, name=title, in_kev=False)
            self.db.add(vuln)
            self.summary.new_cves_added.append(cve_id)
        if vuln.cvss_score is None:
            vuln.cvss_score = cvss
        self.db.flush()

        exists = self.db.scalar(select(Finding).where(Finding.asset_id == asset.id, Finding.cve_id == cve_id))
        if exists is not None:
            return None
        finding = Finding(asset_id=asset.id, cve_id=cve_id, status="open", software=label,
                          confidence=confidence, match_note=note)
        self.db.add(finding)
        self.db.flush()
        self.summary.findings_created += 1
        if vuln.in_kev:
            self.summary.kev_findings += 1
        return finding

    def _not_checked(self, label: str, reason: str) -> None:
        line = f"{label}: {reason}"
        if line not in self.summary.not_checked:
            self.summary.not_checked.append(line)

    def _kev_hint(self, software: SoftwareIn) -> None:
        """Flags software with no match whose product appears in KEV, so a person can check the version."""
        if not hasattr(self, "_kev"):
            self._kev = [
                (v.cve_id, tokens(v.vendor), tokens(v.product))
                for v in self.db.scalars(select(Vulnerability).where(Vulnerability.in_kev.is_(True)))
            ]
        name = set(tokens(software.name))
        # Product's first word must be in the name, plus the vendor (or a long, distinctive product word)
        hits = [cve for cve, vendor, product in self._kev
                if product and len(product[0]) >= 3 and product[0] in name
                and ((vendor and vendor[0] in name) or len(product[0]) >= 5)]
        if hits:
            line = (f"{software_label(software)}: no version match, but {len(hits)} known exploited "
                    f"CVEs list this product (e.g., {', '.join(hits[-3:])}). Check the version manually.")
            if line not in self.summary.needs_review:
                self.summary.needs_review.append(line)


def software_label(software: SoftwareIn) -> str:
    """'Apache Tomcat 9.0.30', without repeating a version already in the name."""
    if software.name.strip().endswith(software.version.strip()):
        return software.name.strip()
    return f"{software.name} {software.version}"


def tokens(text: str | None) -> list[str]:
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def apply_context(db: Session, data: ContextFile) -> ContextSummary:
    summary = ContextSummary()
    for entry in data.assets:
        asset = db.scalar(select(Asset).where(Asset.hostname == entry.hostname))
        if asset is None:
            summary.not_found.append(entry.hostname)
            continue
        for field in ("internet_facing", "money_movement", "data_classification", "criticality"):
            value = getattr(entry, field)
            if value is not None:
                setattr(asset, field, value)
        summary.assets_updated += 1
    db.commit()
    return summary
