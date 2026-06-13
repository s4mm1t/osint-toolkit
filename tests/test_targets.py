import pytest

from osint.targets import assert_public_hostname, assert_public_url


def test_localhost_targets_are_blocked():
    with pytest.raises(ValueError):
        assert_public_hostname("127.0.0.1:5000")

    with pytest.raises(ValueError):
        assert_public_url("http://localhost:5000/search?q=test")


def test_private_ranges_are_blocked():
    for target in ["10.0.0.5", "192.168.1.10", "172.16.0.20", "::1"]:
        with pytest.raises(ValueError):
            assert_public_hostname(target)

