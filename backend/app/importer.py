"""Imports applications, assets and their CVEs from a JSON document.

Matching rules (safe to re-import the same file):
- Applications are matched by name and updated with the values in the file.
- Assets are matched by hostname and updated with the values in the file.
- Each CVE listed on an asset becomes an open finding (skipped if it already exists).
- CVEs not yet in the database are added so they can be enriched by load_epss.
"""

import re

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Application, Asset, Finding, Vulnerability
from app.schemas import ApplicationCreate

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class AssetImport(BaseModel):
    hostname: str
    ip_address: str | None = None
    owner: str | None = None
    # Name of an application in this file or already in VulnHQ
    application: str | None = None
    # If left out, the asset inherits these from its application
    criticality: int | None = Field(default=None, ge=1, le=5)
    internet_facing: bool | None = None
    cves: list[str] = []

    @field_validator("cves")
    @classmethod
    def check_cve_format(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip().upper() for v in values]
        bad = [v for v in cleaned if not CVE_PATTERN.match(v)]
        if bad:
            raise ValueError(f"Invalid CVE IDs: {', '.join(bad)}")
        return cleaned


class ImportFile(BaseModel):
    applications: list[ApplicationCreate] = []
    assets: list[AssetImport] = []


class ImportSummary(BaseModel):
    applications_created: int = 0
    applications_updated: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    findings_created: int = 0
    new_cves_added: list[str] = []
    errors: list[str] = []


def import_data(db: Session, data: ImportFile) -> ImportSummary:
    summary = ImportSummary()

    # 1. Applications (create or update by name)
    for app_in in data.applications:
        app_ = db.scalar(select(Application).where(Application.name == app_in.name))
        if app_ is None:
            db.add(Application(**app_in.model_dump()))
            summary.applications_created += 1
        else:
            for field, value in app_in.model_dump().items():
                setattr(app_, field, value)
            summary.applications_updated += 1
    db.flush()

    # 2. Assets (create or update by hostname)
    for asset_in in data.assets:
        app_ = None
        if asset_in.application:
            app_ = db.scalar(select(Application).where(Application.name == asset_in.application))
            if app_ is None:
                summary.errors.append(
                    f"{asset_in.hostname}: application '{asset_in.application}' not found, asset skipped"
                )
                continue

        criticality = asset_in.criticality or (app_.criticality if app_ else 3)
        internet_facing = (
            asset_in.internet_facing
            if asset_in.internet_facing is not None
            else (app_.internet_facing if app_ else False)
        )

        asset = db.scalar(select(Asset).where(Asset.hostname == asset_in.hostname))
        if asset is None:
            asset = Asset(hostname=asset_in.hostname)
            db.add(asset)
            summary.assets_created += 1
        else:
            summary.assets_updated += 1

        asset.ip_address = asset_in.ip_address
        asset.owner = asset_in.owner or (app_.technical_owner if app_ else None)
        asset.application_id = app_.id if app_ else None
        asset.criticality = criticality
        asset.internet_facing = internet_facing
        db.flush()

        # 3. Findings for each CVE on the asset
        for cve_id in dict.fromkeys(asset_in.cves):  # removes duplicates, keeps order
            if db.get(Vulnerability, cve_id) is None:
                db.add(Vulnerability(cve_id=cve_id, in_kev=False))
                summary.new_cves_added.append(cve_id)
                db.flush()
            exists = db.scalar(
                select(Finding).where(Finding.asset_id == asset.id, Finding.cve_id == cve_id)
            )
            if exists is None:
                db.add(Finding(asset_id=asset.id, cve_id=cve_id, status="open"))
                summary.findings_created += 1

    db.commit()
    return summary
