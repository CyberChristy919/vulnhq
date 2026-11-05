from datetime import date

from pydantic import BaseModel, ConfigDict


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


class ApplicationCreate(BaseModel):
    name: str
    description: str | None = None
    business_owner: str | None = None
    technical_owner: str | None = None
    criticality: int = 3
    data_classification: str | None = None
    internet_facing: bool = False