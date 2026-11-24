import ipaddress

import sg_ipintel


def _slow(cls, s):
    try:
        return int(cls(s))
    except ValueError:
        return None


def test_the_fast_ip_address_parser_agrees_with_ipaddress():
    v4 = ["10.0.0.1", "0.0.0.0", "255.255.255.255", "1.2.3", "01.2.3.4", "1.2.3.04", "256.1.1.1", "", "a.b.c.d", "10.0.0.0"]
    v6 = ["::", "::1", "2001:db8::1", "fe80::1%eth0", "::ffff:1.2.3.4", "2001:db8::g", "", "1:2:3:4:5:6:7:8"]
    for s in v4:
        assert sg_ipintel._v4(s) == _slow(ipaddress.IPv4Address, s), s
    for s in v6:
        assert sg_ipintel._v6(s) == _slow(ipaddress.IPv6Address, s), s
