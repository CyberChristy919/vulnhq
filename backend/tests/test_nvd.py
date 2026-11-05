import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.inventory import InventoryFile, Options, SoftwareIn, add_software, import_inventory
from app.models import Vulnerability
from app.nvd import NotSupported, NvdMatch, NvdUnavailable, affects, parse_cpe


def cve(criteria, vulnerable=True, **ranges):
    return {"configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": criteria, "vulnerable": vulnerable, **ranges}]}]}]}


# ---------- Version check on NVD data ----------

def test_range_match():
    c = cve("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", versionStartIncluding="9.0.0", versionEndExcluding="9.0.31")
    assert affects(c, "a:apache:tomcat", "9.0.30")
    assert not affects(c, "a:apache:tomcat", "9.0.31")


def test_exact_version_match():
    c = cve("cpe:2.3:a:grafana:grafana:8.2.6:*:*:*:*:*:*:*")
    assert affects(c, "a:grafana:grafana", "8.2.6")
    assert not affects(c, "a:grafana:grafana", "8.2.7")


def test_platform_only_is_ignored():
    # The product is listed only as the platform it runs on, not as vulnerable
    c = cve("cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*", vulnerable=False, versionEndExcluding="99")
    assert not affects(c, "o:microsoft:windows", "10")


def test_all_versions_without_range_is_ignored():
    assert not affects(cve("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"), "a:x:y", "1.0")


def test_parse_cpe_formats():
    assert parse_cpe("apache:tomcat") == "a:apache:tomcat"
    assert parse_cpe("o:fortinet:fortios") == "o:fortinet:fortios"
    assert parse_cpe("cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*") == "a:apache:tomcat"
    with pytest.raises(ValueError):
        parse_cpe("tomcat")


# ---------- Importer with a fake NVD ----------

class FakeNvd:
    def __init__(self, results=None, down=False):
        self.results = results or []
        self.down = down
        self.requests_made = 0

    def resolve(self, name, cpe=None):
        if name == "Mystery App":
            raise NotSupported("No matching product found in NVD.")
        return parse_cpe(cpe) if cpe else "a:atlassian:confluence_data_center"

    def lookup(self, product, version, use_cache=True):
        self.requests_made += 1
        if self.down:
            raise NvdUnavailable("Can't reach NVD: ConnectError")
        return self.results


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Vulnerability(cve_id="CVE-2023-22515", name="Confluence access control", in_kev=True,
                                  vendor="Atlassian", product="Confluence Data Center and Server"))
        session.commit()
        yield session


def inventory(*software):
    return InventoryFile.model_validate({"assets": [{"hostname": "h1", "installed_software": list(software)}]})


MATCHES = [
    NvdMatch("CVE-2023-22515", "Broken access control", 10.0, "a:atlassian:confluence_data_center"),
    NvdMatch("CVE-2023-22518", "Improper authorization", 9.8, "a:atlassian:confluence_data_center"),
    NvdMatch("CVE-2023-99999", "Low severity bug", 4.3, "a:atlassian:confluence_data_center"),
]


def test_unknown_product_is_checked_with_nvd(db):
    s = import_inventory(db, inventory({"name": "Atlassian Confluence", "version": "8.5.1"}),
                         client=FakeNvd(MATCHES))
    # The CVSS 4.3 match is below the 7.0 cutoff and not in KEV
    assert s.findings_created == 2
    assert s.nvd_findings == 2
    assert s.kev_findings == 1


def test_kev_kept_even_below_cvss_cutoff(db):
    low_kev = [NvdMatch("CVE-2023-22515", "Broken access control", 5.0, "a:x:y")]
    s = import_inventory(db, inventory({"name": "Atlassian Confluence", "version": "8.5.1"}),
                         client=FakeNvd(low_kev))
    assert s.findings_created == 1


def test_covered_products_skip_nvd(db):
    fake = FakeNvd(MATCHES)
    import_inventory(db, inventory({"name": "Apache HTTP Server", "version": "2.4.49"}), client=fake)
    assert fake.requests_made == 0


def test_nvd_outage_is_reported_not_fatal(db):
    fake = FakeNvd(down=True)
    s = import_inventory(db, inventory({"name": "Atlassian Confluence", "version": "8.5.1"},
                                       {"name": "Splunk Enterprise", "version": "9.0.4"}), client=fake)
    # Stops calling NVD after the first failure
    assert fake.requests_made == 1
    assert len(s.not_checked) == 2
    # Confluence appears in KEV, so it's flagged for a manual version check
    assert any("Confluence" in line for line in s.needs_review)


def test_unidentified_product_listed_as_not_checked(db):
    s = import_inventory(db, inventory({"name": "Mystery App", "version": "1.0"}), client=FakeNvd())
    assert s.not_checked == ["Mystery App 1.0: No matching product found in NVD."]


def test_nvd_off_lists_not_checked(db):
    s = import_inventory(db, inventory({"name": "Atlassian Confluence", "version": "8.5.1"}),
                         Options(use_nvd=False))
    assert s.findings_created == 0
    assert "NVD lookup is off" in s.not_checked[0]


def test_add_software_to_existing_asset(db):
    import_inventory(db, inventory({"name": "Apache HTTP Server", "version": "2.4.51"}), Options(use_nvd=False))
    result = add_software(db, "h1", SoftwareIn(name="Atlassian Confluence", version="8.5.1"),
                          client=FakeNvd(MATCHES))
    summary, findings = result
    assert {f.cve_id for f in findings} == {"CVE-2023-22515", "CVE-2023-22518"}
    assert add_software(db, "missing-host", SoftwareIn(name="X", version="1"), client=FakeNvd()) is None


def test_cisco_version_is_escaped_for_nvd():
    from app.nvd import escape_version
    assert escape_version("15.2(7)E3") == "15.2\\(7\\)e3"
    assert escape_version("2.4.49") == "2.4.49"


def test_wide_cisco_style_range_is_marked_broad():
    c = cve("cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*", versionStartIncluding="15.0", versionEndIncluding="15.6")
    assert affects(c, "o:cisco:ios", "15.2(7)E3") == "broad"
    exact_range = cve("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", versionStartIncluding="9.0.0", versionEndExcluding="9.0.31")
    assert affects(exact_range, "a:apache:tomcat", "9.0.30") == "range"
