from app.versions import in_range, parse_version


def test_numeric_ordering():
    assert parse_version("2.4.49") < parse_version("2.4.50")
    assert parse_version("2.10") > parse_version("2.9")


def test_trailing_zero_equal():
    assert parse_version("2.4") == parse_version("2.4.0")


def test_openssl_letters():
    assert parse_version("1.0.2u") < parse_version("1.0.2zd")
    assert parse_version("1.1.1k") < parse_version("1.1.1l")
    assert parse_version("1.1.1") < parse_version("1.1.1a")


def test_openssh_and_cisco_formats():
    assert parse_version("7.6p1") <= parse_version("7.7")
    assert parse_version("8.0p1") < parse_version("9.3p2")
    assert parse_version("15.2(7)E3") > parse_version("15.2(7)E2")


def test_in_range_inclusive_and_exclusive():
    assert in_range("2.4.49", "2.4.49", True, "2.4.49", True)
    assert not in_range("2.4.51", "2.4.49", True, "2.4.50", True)
    assert in_range("2.14.1", "2.13.0", True, "2.15.0", False)
    assert not in_range("2.15.0", "2.13.0", True, "2.15.0", False)
    assert in_range("11.0.0.837", None, True, "11.0.1.1261", False)
