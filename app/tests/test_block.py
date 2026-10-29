import pytest

from netmon.block import BlockError, validate_target


@pytest.mark.parametrize("addr", ["10.40.0.5", "10.0.0.161", "203.0.113.180", "198.51.100.0/24",
                                  "1.1.1.1", "8.8.8.0/24", "0.0.0.0/0", "203.0.0.0/8", "127.0.0.1",
                                  "not-an-ip", "1.2.3.4; rm -rf /", "fe80::1", "2001:db8::/32"])
def test_refused(cfg, addr):
    with pytest.raises(BlockError):
        validate_target(cfg, addr)


def test_allowed(cfg):
    assert validate_target(cfg, " 45.83.64.1 ") == "45.83.64.1"
    assert validate_target(cfg, "45.83.64.7/24") == "45.83.64.0/24"
    assert validate_target(cfg, "45.83.64.1/32") == "45.83.64.1"
