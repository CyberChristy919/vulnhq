from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict

# Allowed money movement levels (see docs/scoring.md)
MoneyMovement = Literal["none", "internal_transfers", "outbound_payments"]


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    vendor: str | None
    product: str | None
    name: str | None
    description: str | None
    cvss_score: float | None
    epss_score: float | None
    in_kev: bool
    kev_date_added: date | None
    kev_due_date: date | None
    ransomware_use: bool


class ApplicationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    business_owner: str | None
    technical_owner: str | None
    criticality: int
    data_classification: str | None
    internet_facing: bool
    money_movement: MoneyMovement


class ApplicationCreate(BaseModel):
    name: str
    description: str | None = None
    business_owner: str | None = None
    technical_owner: str | None = None
    criticality: int = 3
    data_classification: str | None = None
    internet_facing: bool = False
    money_movement: MoneyMovement = "none"
