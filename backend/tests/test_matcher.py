from app.matcher import match_software


def cves(name, version):
    return {m.cve_id for m in match_software(name, version)}


def test_apache_2_4_49_path_traversal():
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= cves("Apache HTTP Server", "2.4.49")


def test_apache_2_4_51_not_path_traversal():
    found = cves("Apache HTTP Server", "2.4.51")
    assert "CVE-2021-41773" not in found
    assert "CVE-2021-42013" not in found


def test_log4shell_versions():
    assert "CVE-2021-44228" in cves("log4j-core", "2.14.1")
    assert "CVE-2021-44228" not in cves("log4j-core", "2.15.0")
    assert "CVE-2021-45046" in cves("log4j-core", "2.15.0")


def test_name_matching_is_case_insensitive():
    assert cves("GOOGLE CHROME", "94.0.4606.81") == cves("Google Chrome", "94.0.4606.81")


def test_unknown_software_has_no_matches():
    assert cves("Homebrew", "3.6.5") == set()


def test_conditional_match_has_note():
    tomcat = [m for m in match_software("Apache Tomcat", "9.0.52") if m.cve_id == "CVE-2025-24813"]
    assert tomcat and tomcat[0].condition
