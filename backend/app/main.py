from contextlib import asynccontextmanager
from datetime import date

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, joinedload

from app import models
from app.database import Base, engine, get_db
from app.schemas import ApplicationCreate, ApplicationOut, FixListItem, VulnerabilityOut
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
    allow_origins=["http://localhost:5173"],
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


# ---------- Fix List (ranked findings) ----------

@app.get("/fix-list", response_model=list[FixListItem])
def fix_list(
    status: str = "open",
    tier: str | None = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
):
    stmt = (
        select(models.Finding)
        .options(
            joinedload(models.Finding.asset).joinedload(models.Asset.application),
            joinedload(models.Finding.vulnerability),
        )
        .where(models.Finding.status == status)
    )
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
                money_movement=app_.money_movement if app_ else "none",
                data_classification=app_.data_classification if app_ else None,
            )
        )
        if tier and result.tier.lower() != tier.lower():
            continue
        first_seen = f.first_seen.date()
        due = due_date(first_seen, result.sla_days)
        items.append(
            FixListItem(
                finding_id=f.id,
                cve_id=vuln.cve_id,
                vulnerability_name=vuln.name,
                hostname=asset.hostname,
                application=app_.name if app_ else None,
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
    return items[:limit]


# ---------- Dashboard stats ----------

@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    V = models.Vulnerability
    total = db.scalar(select(func.count()).select_from(V))
    kev = db.scalar(select(func.count()).select_from(V).where(V.in_kev.is_(True)))
    ransomware = db.scalar(select(func.count()).select_from(V).where(V.ransomware_use.is_(True)))
    apps = db.scalar(select(func.count()).select_from(models.Application))
    return {
        "total_vulnerabilities": total,
        "kev_count": kev,
        "ransomware_linked": ransomware,
        "applications": apps,
    }