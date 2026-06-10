from osint.domain import normalize_domain


def test_normalize_domain_removes_scheme_and_path():
    assert normalize_domain("https://Example.com/path") == "example.com"


def test_normalize_domain_rejects_spaces():
    try:
        normalize_domain("bad domain")
    except ValueError as exc:
        assert "Domain" in str(exc)
    else:
        raise AssertionError("Expected ValueError")

