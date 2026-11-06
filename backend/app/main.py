from contextlib import asynccontextmanager
from datetime import date

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, joinedload

from app import models
from app.database import Base, engine, get_db
from app.importer import ImportFile, ImportSummary, import_data
from app.inventory import (
    ContextFile,
    ContextSummary,
    InventoryFile,
    InventorySummary,
    Options,
    SoftwareIn,
    add_software,
    apply_context,
    import_inventory,
)
from app.schemas import (
    ApplicationCreate,
    ApplicationOut,
    AssetSummary,
    FixListItem,
    SoftwareOut,
    VulnerabilityOut,
)
from app.scoring import ScoreInput, calculate_score, due_date


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Creates tables if they don't exist yet (Alembic migrations come later)
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="VulnHQ API", lifespan=lifespan)

# Lets the React dev server call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected"}


# ---------- Vulnerabilities ----------

@app.get("/vulnerabilities", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    kev_only: bool = False,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db),
):
    stmt = select(models.Vulnerability)
    if kev_only:
        stmt = stmt.where(models.Vulnerability.in_kev.is_(True))
    stmt = stmt.order_by(models.Vulnerability.kev_date_added.desc().nulls_last()).limit(limit)
    return db.scalars(stmt).all()


# ---------- Applications ----------

@app.get("/applications", response_model=list[ApplicationOut])
def list_applications(db: Session = Depends(get_db)):
    stmt = select(models.Application).order_by(models.Application.criticality.desc())
    return db.scalars(stmt).all()


@app.post("/applications", response_model=ApplicationOut, status_code=201)
def create_application(payload: ApplicationCreate, db: Session = Depends(get_db)):
    # Block duplicate application names
    existing = db.scalar(select(models.Application).where(models.Application.name == payload.name))
    if existing:
        raise HTTPException(status_code=409, detail="Application already exists")

    application = models.Application(**payload.model_dump())
    db.add(application)
    db.commit()
    db.refresh(application)
    return application


# ---------- Import ----------

@app.post("/import/assets", response_model=ImportSummary)
def import_assets(payload: ImportFile, db: Session = Depends(get_db)):
    # Accepts the JSON format in sample-data/demo-assets.json
    return import_data(db, payload)


@app.post("/import/inventory", response_model=InventorySummary)
def import_inventory_file(
    payload: InventoryFile,
    use_nvd: bool = True,
    min_cvss: float = Query(7.0, ge=0, le=10),
    db: Session = Depends(get_db),
):
    # Asset inventory with installed software. CVEs are matched with the vetted
    # rules first, then a live NVD lookup for products the rules don't cover.
    return import_inventory(db, payload, Options(use_nvd=use_nvd, min_cvss=min_cvss))


@app.post("/assets/{hostname}/software")
def add_asset_software(
    hostname: str,
    payload: SoftwareIn,
    use_nvd: bool = True,
    min_cvss: float = Query(7.0, ge=0, le=10),
    db: Session = Depends(get_db),
):
    # Adds one software item to an existing asset and checks it right away
    result = add_software(db, hostname, payload, Options(use_nvd=use_nvd, min_cvss=min_cvss))
    if result is None:
        raise HTTPException(status_code=404, detail=f"No asset named {hostname}. Import it first.")
    summary, findings = result
    return {
        "summary": summary,
        "findings": [
            {
                "cve_id": f.cve_id,
                "name": f.vulnerability.name,
                "in_kev": f.vulnerability.in_kev,
                "cvss_score": f.vulnerability.cvss_score,
                "confidence": f.confidence,
                "match_note": f.match_note,
            }
            for f in sorted(findings, key=lambda f: (not f.vulnerability.in_kev, -(f.vulnerability.cvss_score or 0)))
        ],
    }


@app.post("/import/context", response_model=ContextSummary)
def import_context_file(payload: ContextFile, db: Session = Depends(get_db)):
    # Business context (internet exposure, money movement, data classification) by hostname
    return apply_context(db, payload)


# ---------- Fix List (ranked findings) ----------

def scored_findings(db: Session, status: str = "open", hostname: str | None = None) -> list[FixListItem]:
    """All findings with their VulnHQ Risk Score, highest risk first."""
    stmt = (
        select(models.Finding)
        .options(
            joinedload(models.Finding.asset).joinedload(models.Asset.application),
            joinedload(models.Finding.vulnerability),
        )
        .where(models.Finding.status == status)
    )
    if hostname:
        stmt = stmt.join(models.Asset).where(models.Asset.hostname == hostname)
    findings = db.scalars(stmt).unique().all()

    today = date.today()
    items = []
    for f in findings:
        asset, vuln, app_ = f.asset, f.vulnerability, f.asset.application
        # Application values win; fall back to the asset when there is no application
        result = calculate_score(
            ScoreInput(
                in_kev=vuln.in_kev,
                epss=vuln.epss_score,
                ransomware=vuln.ransomware_use,
                criticality=app_.criticality if app_ else asset.criticality,
                internet_facing=asset.internet_facing or (app_.internet_facing if app_ else False),
                money_movement=app_.money_movement if app_ else asset.money_movement,
                data_classification=app_.data_classification if app_ else asset.data_classification,
            )
        )
        first_seen = f.first_seen.date()
        due = due_date(first_seen, result.sla_days)
        items.append(
            FixListItem(
                finding_id=f.id,
                cve_id=vuln.cve_id,
                vulnerability_name=vuln.name,
                in_kev=vuln.in_kev,
                ransomware=bool(vuln.ransomware_use),
                cvss_score=vuln.cvss_score,
                epss_score=vuln.epss_score,
                hostname=asset.hostname,
                asset_id=asset.external_id,
                department=asset.department,
                application=app_.name if app_ else None,
                software=f.software,
                confidence=f.confidence,
                match_note=f.match_note,
                last_scan_date=asset.last_scan_date,
                scan_age_days=(today - asset.last_scan_date).days if asset.last_scan_date else None,
                status=f.status,
                risk_score=result.score,
                tier=result.tier,
                first_seen=first_seen,
                due_date=due,
                days_remaining=(due - today).days,
                overdue=due < today,
                breakdown=result.breakdown,
            )
        )

    # Highest risk first; earliest due date breaks ties
    items.sort(key=lambda i: (-i.risk_score, i.due_date))
    return items


@app.get("/fix-list", response_model=list[FixListItem])
def fix_list(
    status: str = "open",
    tier: str | None = None,
    hostname: str | None = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
):
    items = scored_findings(db, status, hostname)
    if tier:
        items = [i for i in items if i.tier.lower() == tier.lower()]
    return items[:limit]


# ---------- Assets ----------

STALE_SCAN_DAYS = 90


@app.get("/assets", response_model=list[AssetSummary])
def list_assets(db: Session = Depends(get_db)):
    assets = db.scalars(
        select(models.Asset).options(joinedload(models.Asset.software)).order_by(models.Asset.hostname)
    ).unique().all()
    by_host: dict[str, list[FixListItem]] = {}
    for item in scored_findings(db):
        by_host.setdefault(item.hostname, []).append(item)

    today = date.today()
    out = []
    for a in assets:
        items = by_host.get(a.hostname, [])
        tiers = {t: 0 for t in ("Critical", "High", "Medium", "Low")}
        for i in items:
            tiers[i.tier] += 1
        out.append(
            AssetSummary(
                hostname=a.hostname,
                asset_id=a.external_id,
                asset_type=a.asset_type,
                department=a.department,
                os=a.os,
                os_version=a.os_version,
                criticality=a.criticality,
                internet_facing=bool(a.internet_facing),
                money_movement=a.money_movement or "none",
                data_classification=a.data_classification,
                last_scan_date=a.last_scan_date,
                scan_age_days=(today - a.last_scan_date).days if a.last_scan_date else None,
                software=[SoftwareOut(name=s.name, version=s.version) for s in a.software],
                open_findings=len(items),
                kev_findings=sum(i.in_kev for i in items),
                tiers=tiers,
                top_score=max((i.risk_score for i in items), default=0),
            )
        )
    # Riskiest assets first
    out.sort(key=lambda a: (-a.top_score, -a.open_findings, a.hostname))
    return out


# ---------- Dashboard stats ----------

@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    V = models.Vulnerability
    total = db.scalar(select(func.count()).select_from(V))
    kev = db.scalar(select(func.count()).select_from(V).where(V.in_kev.is_(True)))
    ransomware = db.scalar(select(func.count()).select_from(V).where(V.ransomware_use.is_(True)))
    apps = db.scalar(select(func.count()).select_from(models.Application))
    assets = db.scalars(select(models.Asset)).all()
    items = scored_findings(db)

    today = date.today()
    tiers = {t: 0 for t in ("Critical", "High", "Medium", "Low")}
    for i in items:
        tiers[i.tier] += 1
    return {
        "total_vulnerabilities": total,
        "kev_count": kev,
        "ransomware_linked": ransomware,
        "applications": apps,
        "assets": len(assets),
        "assets_with_findings": len({i.hostname for i in items}),
        "stale_scan_assets": sum(
            1 for a in assets if a.last_scan_date and (today - a.last_scan_date).days > STALE_SCAN_DAYS
        ),
        "stale_scan_days": STALE_SCAN_DAYS,
        "open_findings": len(items),
        "kev_findings": sum(i.in_kev for i in items),
        "overdue_findings": sum(i.overdue for i in items),
        "findings_by_tier": tiers,
    }