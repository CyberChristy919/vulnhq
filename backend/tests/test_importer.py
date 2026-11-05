import pytest
from pydantic import ValidationError

from app.importer import AssetImport, ImportFile


def test_cves_are_normalized():
    asset = AssetImport(hostname="h1", cves=[" cve-2021-44228 "])
    assert asset.cves == ["CVE-2021-44228"]


def test_invalid_cve_rejected():
    with pytest.raises(ValidationError):
        AssetImport(hostname="h1", cves=["LOG4J"])


def test_invalid_money_movement_rejected():
    with pytest.raises(ValidationError):
        ImportFile.model_validate({"applications": [{"name": "X", "money_movement": "some"}]})


def test_criticality_range_enforced():
    with pytest.raises(ValidationError):
        AssetImport(hostname="h1", criticality=9)


def test_demo_file_is_valid():
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "sample-data" / "demo-assets.json"
    data = ImportFile.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert len(data.applications) == 5
    assert len(data.assets) == 10
