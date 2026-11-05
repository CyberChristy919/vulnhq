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

Re-importing the same file updates assets and replaces their software list.
Existing findings are kept; new matches are added.
"""

from datetime import date

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.matcher import match_software
from app.models import Asset, Finding, InstalledSoftware, Vulnerability
from app.schemas import MoneyMovement

CRITICALITY_MAP = {"critical": 5, "high": 4, "medium": 3, "low": 2}


class SoftwareIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    version: str


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
    new_cves_added: list[str] = []


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


def import_inventory(db: Session, data: InventoryFile) -> InventorySummary:
    summary = InventorySummary()

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
        to_check = [(s.name, s.version) for s in item.installed_software]
        if item.os and item.os_version:
            to_check.append((item.os, item.os_version))

        seen: set[str] = set()
        asset_has_findings = False
        for name, version in to_check:
            for match in match_software(name, version):
                if match.cve_id in seen:
                    continue
                seen.add(match.cve_id)
                asset_has_findings = True

                vuln = db.get(Vulnerability, match.cve_id)
                if vuln is None:
                    vuln = Vulnerability(cve_id=match.cve_id, name=match.title, in_kev=False)
                    db.add(vuln)
                    summary.new_cves_added.append(match.cve_id)
                if vuln.cvss_score is None:
                    vuln.cvss_score = match.cvss
                db.flush()

                exists = db.scalar(
                    select(Finding).where(Finding.asset_id == asset.id, Finding.cve_id == match.cve_id)
                )
                if exists is None:
                    db.add(
                        Finding(
                            asset_id=asset.id,
                            cve_id=match.cve_id,
                            status="open",
                            software=match.software,
                            confidence="conditional" if match.condition else "confirmed",
                            match_note=match.condition,
                        )
                    )
                    summary.findings_created += 1
                    if vuln.in_kev:
                        summary.kev_findings += 1
                    if match.condition:
                        summary.conditional_findings += 1

        if asset_has_findings:
            summary.assets_with_findings += 1

    db.commit()
    return summary


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
