from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    business_owner: Mapped[str | None] = mapped_column(String(255))
    technical_owner: Mapped[str | None] = mapped_column(String(255))
    # 1 = low business impact, 5 = crown jewel
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    # e.g. public, internal, confidential, restricted
    data_classification: Mapped[str | None] = mapped_column(String(50))
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    # none, internal_transfers, or outbound_payments (see docs/scoring.md)
    money_movement: Mapped[str] = mapped_column(String(30), default="none", server_default="none")

    assets: Mapped[list["Asset"]] = relationship(back_populates="application")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    owner: Mapped[str | None] = mapped_column(String(255))
    # Which application this server supports (optional)
    application_id: Mapped[int | None] = mapped_column(ForeignKey("applications.id"))
    # 1 = low business impact, 5 = crown jewel
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)

    application: Mapped["Application | None"] = relationship(back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(255))
    product: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    required_action: Mapped[str | None] = mapped_column(Text)
    # Filled in later from NVD and EPSS
    cvss_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    # From CISA KEV
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)

    findings: Mapped[list["Finding"]] = relationship(back_populates="vulnerability")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"))
    status: Mapped[str] = mapped_column(String(20), default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    # Calculated by the prioritization engine later
    risk_score: Mapped[float | None] = mapped_column(Float)

    asset: Mapped["Asset"] = relationship(back_populates="findings")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="findings")