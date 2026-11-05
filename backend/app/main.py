from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import models
from app.database import Base, engine, get_db
from app.schemas import ApplicationCreate, ApplicationOut, VulnerabilityOut


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