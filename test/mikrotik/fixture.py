"""fixture.py - a MikroTik that is not there: RouterOS 7's default configuration (defconf) of the firewall,
IPv4 and IPv6, as the REST API answers it - and a home's own rules on top of it:

  nat #1  dst-nat udp 9308 -> 192.168.40.95 (Remote Play)                       the PS5's port: open
  nat #2  dst-nat tcp 3478-3480 -> 192.168.40.50 (a game server)                 shadows #4 for tcp 3478
  nat #3  accept udp 3479 (keep it on the router)                                ends the translation for udp 3479
  nat #4  dst-nat tcp,udp 3478-3479 -> 192.168.40.95                              shadowed
  nat #5  dst-nat udp 3074 -> 192.168.40.95, DISABLED                            disabled
  filter: defconf, plus a drop of a block list (blacklist) and one of udp 3544 (Teredo) from the WAN
  ipv6:   defconf (drops what does not come from the LAN), the PS5 at 2a00:1028:8640:40::95
  /ip upnp enabled=yes - two UPnP routers on one network

Each menu as {"path": [entries]}; values as RouterOS gives them, strings.
"""
import copy

_n = [0]


def _id():
    _n[0] += 1
    return "*%X" % _n[0]


def rule(**kw):
    r = {".id": _id(), "disabled": "false", "dynamic": "false", "invalid": "false", "bytes": "0", "packets": "0"}
    for k, v in kw.items():
        r[k.replace("_", "-")] = str(v)
    return r


FILTER4 = [
    rule(chain="forward", action="passthrough", comment="special dummy rule to show fasttrack counters",
         dynamic="true", bytes="912345678", packets="812345"),
    rule(chain="input", action="accept", connection_state="established,related,untracked",
         comment="defconf: accept established,related,untracked", bytes="80123456", packets="512345"),
    rule(chain="input", action="drop", connection_state="invalid", comment="defconf: drop invalid", bytes="1234", packets="21"),
    rule(chain="input", action="accept", protocol="icmp", comment="defconf: accept ICMP", bytes="34567", packets="400"),
    rule(chain="input", action="accept", dst_address="127.0.0.1", comment="defconf: accept to local loopback (for CAPsMAN)"),
    rule(chain="input", action="drop", in_interface_list="!LAN", comment="defconf: drop all not coming from LAN",
         bytes="4567890", packets="61234"),
    rule(chain="forward", action="accept", ipsec_policy="in,ipsec", comment="defconf: accept in ipsec policy"),
    rule(chain="forward", action="accept", ipsec_policy="out,ipsec", comment="defconf: accept out ipsec policy"),
    rule(chain="forward", action="fasttrack-connection", connection_state="established,related", hw_offload="yes",
         comment="defconf: fasttrack", bytes="812345678", packets="712345"),
    rule(chain="forward", action="accept", connection_state="established,related,untracked",
         comment="defconf: accept established,related, untracked", bytes="98765432", packets="99876"),
    rule(chain="forward", action="drop", connection_state="invalid", comment="defconf: drop invalid", bytes="23456", packets="310"),
    rule(chain="forward", action="drop", src_address_list="blacklist", in_interface_list="WAN",
         comment="drop the block list", bytes="7890", packets="96"),
    rule(chain="forward", action="drop", protocol="udp", dst_port="3544", in_interface_list="WAN",
         comment="no Teredo", bytes="0", packets="0"),
    rule(chain="forward", action="drop", connection_state="new", connection_nat_state="!dstnat",
         in_interface_list="WAN", comment="defconf: drop all from WAN not DSTNATed", bytes="345678", packets="4567"),
]
NAT4 = [
    rule(chain="srcnat", action="masquerade", ipsec_policy="out,none", out_interface_list="WAN",
         comment="defconf: masquerade", bytes="123456789", packets="234567"),
    rule(chain="dstnat", action="dst-nat", protocol="udp", dst_port="9308", in_interface_list="WAN",
         to_addresses="192.168.40.95", to_ports="9308", comment="PS5 Remote Play", bytes="56789", packets="345"),
    rule(chain="dstnat", action="dst-nat", protocol="tcp", dst_port="3478-3480", in_interface_list="WAN",
         to_addresses="192.168.40.50", comment="game server", bytes="1234", packets="12"),
    rule(chain="dstnat", action="accept", protocol="udp", dst_port="3479", in_interface_list="WAN",
         comment="keep 3479 on the router"),
    rule(chain="dstnat", action="dst-nat", protocol="tcp", dst_port="3478-3479", in_interface_list="WAN",
         to_addresses="192.168.40.95", comment="PS5 PSN tcp"),
    rule(chain="dstnat", action="dst-nat", protocol="udp", dst_port="3478-3479", in_interface_list="WAN",
         to_addresses="192.168.40.95", comment="PS5 PSN udp"),
    rule(chain="dstnat", action="dst-nat", protocol="udp", dst_port="3074", in_interface_list="WAN",
         to_addresses="192.168.40.95", to_ports="3074", comment="PS5 3074 (off)", disabled="true"),
]
MANGLE4 = [rule(chain="prerouting", action="mark-connection", new_connection_mark="games", passthrough="yes",
                protocol="udp", dst_port="3478-3480", comment="mark the games", bytes="8765", packets="87")]
RAW4 = [rule(chain="prerouting", action="drop", src_address_list="bogons", in_interface_list="WAN", comment="drop bogons")]
LISTS4 = [
    {".id": "*A1", "list": "blacklist", "address": "198.51.100.0/24", "comment": "scanners", "disabled": "false",
     "dynamic": "false"},
    {".id": "*A2", "list": "blacklist", "address": "203.0.113.99", "comment": "", "disabled": "false", "dynamic": "false"},
    {".id": "*A3", "list": "bogons", "address": "10.0.0.0/8", "comment": "", "disabled": "false", "dynamic": "false"},
    {".id": "*A4", "list": "bogons", "address": "192.168.0.0/16", "comment": "", "disabled": "false", "dynamic": "false"},
]
FILTER6 = [
    rule(chain="input", action="accept", connection_state="established,related,untracked",
         comment="defconf: accept established,related,untracked"),
    rule(chain="input", action="drop", connection_state="invalid", comment="defconf: drop invalid"),
    rule(chain="input", action="accept", protocol="icmpv6", comment="defconf: accept ICMPv6"),
    rule(chain="input", action="accept", dst_port="33434-33534", protocol="udp", comment="defconf: accept UDP traceroute"),
    rule(chain="input", action="accept", dst_port="546", protocol="udp", src_address="fe80::/10",
         comment="defconf: accept DHCPv6-Client prefix delegation."),
    rule(chain="input", action="accept", dst_port="500,4500", protocol="udp", comment="defconf: accept IKE"),
    rule(chain="input", action="accept", protocol="ipsec-ah", comment="defconf: accept ipsec AH"),
    rule(chain="input", action="accept", protocol="ipsec-esp", comment="defconf: accept ipsec ESP"),
    rule(chain="input", action="accept", ipsec_policy="in,ipsec", comment="defconf: accept all that matches ipsec policy"),
    rule(chain="input", action="drop", in_interface_list="!LAN", comment="defconf: drop everything else not coming from LAN"),
    rule(chain="forward", action="accept", connection_state="established,related,untracked",
         comment="defconf: accept established,related,untracked", bytes="45678901", packets="45678"),
    rule(chain="forward", action="drop", connection_state="invalid", comment="defconf: drop invalid"),
    rule(chain="forward", action="drop", src_address_list="bad_ipv6", comment="defconf: drop packets with bad src ipv6"),
    rule(chain="forward", action="drop", dst_address_list="bad_ipv6", comment="defconf: drop packets with bad dst ipv6"),
    rule(chain="forward", action="drop", hop_limit="equal:1", protocol="icmpv6", comment="defconf: rfc4890 drop hop-limit=1"),
    rule(chain="forward", action="accept", protocol="icmpv6", comment="defconf: accept ICMPv6"),
    rule(chain="forward", action="accept", protocol="139", comment="defconf: accept HIP"),
    rule(chain="forward", action="accept", dst_port="500,4500", protocol="udp", comment="defconf: accept IKE"),
    rule(chain="forward", action="accept", protocol="ipsec-ah", comment="defconf: accept ipsec AH"),
    rule(chain="forward", action="accept", protocol="ipsec-esp", comment="defconf: accept ipsec ESP"),
    rule(chain="forward", action="accept", ipsec_policy="in,ipsec", comment="defconf: accept all that matches ipsec policy"),
    rule(chain="forward", action="drop", in_interface_list="!LAN", comment="defconf: drop everything else not coming from LAN",
         bytes="98765", packets="1234"),
]
LISTS6 = [{".id": "*B%d" % i, "list": "bad_ipv6", "address": a, "comment": "defconf: " + c, "disabled": "false",
           "dynamic": "false"} for i, (a, c) in enumerate([
               ("::/128", "unspecified address"), ("::1/128", "lo"), ("fec0::/10", "site-local"),
               ("::ffff:0.0.0.0/96", "ipv4-mapped"), ("::/96", "ipv4 compat"), ("100::/64", "discard only "),
               ("2001:db8::/32", "documentation"), ("2001:10::/28", "ORCHID"), ("3ffe::/16", "6bone")])]

ROUTER = {
    "/system/identity": [{"name": "MockTik"}],
    "/system/resource": [{"version": "7.16.2 (stable)", "board-name": "hAP ax3", "uptime": "3w2d4h5m",
                          "cpu-load": "4", "free-memory": "812345678", "total-memory": "1073741824",
                          "architecture-name": "arm64"}],
    "/system/routerboard": [{"model": "C53UiG+5HPaxD2HPaxD", "serial-number": "HF1234ABCDE", "routerboard": "true"}],
    "/interface": [{".id": "*1", "name": "ether1", "type": "ether", "running": "true", "disabled": "false",
                    "mac-address": "48:A9:8A:00:00:01", "comment": "to the ISP"},
                   {".id": "*2", "name": "ether2", "type": "ether", "running": "true", "disabled": "false",
                    "mac-address": "48:A9:8A:00:00:02"},
                   {".id": "*3", "name": "ether3", "type": "ether", "running": "false", "disabled": "false",
                    "mac-address": "48:A9:8A:00:00:03"},
                   {".id": "*4", "name": "wifi1", "type": "wifi", "running": "true", "disabled": "false",
                    "mac-address": "48:A9:8A:00:00:04"},
                   {".id": "*9", "name": "bridge", "type": "bridge", "running": "true", "disabled": "false",
                    "mac-address": "48:A9:8A:00:00:02", "comment": "defconf"}],
    "/interface/list": [{"name": "WAN", "comment": "defconf"}, {"name": "LAN", "comment": "defconf"}],
    "/interface/list/member": [{"list": "LAN", "interface": "bridge", "disabled": "false"},
                               {"list": "WAN", "interface": "ether1", "disabled": "false"}],
    "/ip/address": [{"address": "192.168.40.1/24", "interface": "bridge", "disabled": "false"},
                    {"address": "198.51.100.7/24", "interface": "ether1", "disabled": "false", "dynamic": "true"}],
    "/ipv6/address": [{"address": "2a00:1028:8640:40::1/64", "interface": "bridge", "disabled": "false"},
                      {"address": "fe80::4aa9:8aff:fe00:1/64", "interface": "ether1", "disabled": "false"}],
    "/ip/route": [{"dst-address": "0.0.0.0/0", "gateway": "198.51.100.1", "immediate-gateway": "198.51.100.1%ether1",
                   "active": "true", "disabled": "false", "dynamic": "true"},
                  {"dst-address": "192.168.40.0/24", "gateway": "bridge", "active": "true", "disabled": "false"}],
    "/ip/arp": [{"address": "192.168.40.95", "mac-address": "AA:BB:CC:00:00:95", "interface": "bridge"},
                {"address": "192.168.40.50", "mac-address": "AA:BB:CC:00:00:50", "interface": "bridge"},
                {"address": "198.51.100.1", "mac-address": "00:11:22:33:44:55", "interface": "ether1"}],
    "/ipv6/neighbor": [{"address": "2a00:1028:8640:40::95", "mac-address": "AA:BB:CC:00:00:95", "interface": "bridge"},
                       {"address": "fe80::a8bb:ccff:fe00:95", "mac-address": "AA:BB:CC:00:00:95", "interface": "bridge"}],
    "/ip/firewall/filter": FILTER4,
    "/ip/firewall/nat": NAT4,
    "/ip/firewall/mangle": MANGLE4,
    "/ip/firewall/raw": RAW4,
    "/ip/firewall/address-list": LISTS4,
    "/ipv6/firewall/filter": FILTER6,
    "/ipv6/firewall/nat": [],
    "/ipv6/firewall/mangle": [],
    "/ipv6/firewall/raw": [],
    "/ipv6/firewall/address-list": LISTS6,
    "/ip/upnp": [{"enabled": "true", "allow-disable-external-interface": "false", "show-dummy-rule": "true"}],
    "/ip/upnp/interfaces": [{"interface": "bridge", "type": "internal", "disabled": "false"},
                            {"interface": "ether1", "type": "external", "disabled": "false"}],
    "/ip/firewall/connection/tracking": [{"enabled": "auto", "total-entries": "1234", "max-entries": "262144"}],
    "/user": [{"name": "admin", "group": "full"}, {"name": "fake-igd-read", "group": "fake-igd-read"}],
    "/user/group": [{"name": "full", "policy": "local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,password,web,"
                                               "sniff,sensitive,api,romon,rest-api"},
                    {"name": "fake-igd-read", "policy": "read,rest-api,api,ssh,!local,!telnet,!ftp,!reboot,!write,!policy,"
                                                        "!test,!winbox,!password,!web,!sniff,!sensitive,!romon"}],
}

WANTS = [
    {"device": "192.168.40.95", "name": "PS5 Pro", "proto": "udp", "port": 9308, "to_port": 9308},
    {"device": "192.168.40.95", "name": "PS5 Pro", "proto": "tcp", "port": 3478, "to_port": 3478},
    {"device": "192.168.40.95", "name": "PS5 Pro", "proto": "udp", "port": 3479, "to_port": 3479},
    {"device": "192.168.40.95", "name": "PS5 Pro", "proto": "udp", "port": 3074, "to_port": 3074},
    {"device": "192.168.40.95", "name": "PS5 Pro", "proto": "tcp", "port": 9295, "to_port": 9295},
    {"device": "192.168.40.95", "name": "PS5 Pro", "proto": "udp", "port": 3544, "to_port": 3544},
]


def router():
    return copy.deepcopy(ROUTER)


def terse(path):
    """The menu as RouterOS 6's `print terse without-paging` puts it - number, flags, key=value words."""
    out = []
    for i, r in enumerate(ROUTER.get(path) or []):
        flags = ("X" if r.get("disabled") == "true" else "") + ("D" if r.get("dynamic") == "true" else "")
        words = []
        for k, v in r.items():
            if k.startswith(".") or k in ("disabled", "dynamic", "invalid", "bytes", "packets"):
                continue
            if any(c in v for c in ' ";') or v == "":
                v = '"%s"' % v.replace("\\", "\\\\").replace('"', '\\"')
            words.append("%s=%s" % (k, v))
        out.append("%2d %-2s %s" % (i, flags, " ".join(words)))
    return "\n".join(out) + "\n"


def as_value(path):
    """The menu as `:foreach r in=[... print as-value] do={:put $r}` puts it: key=value;key=value a line."""
    lines = []
    for r in ROUTER.get(path) or []:
        lines.append(";".join("%s=%s" % (k, v) for k, v in r.items()))
    if path in ("/system/identity", "/system/resource", "/system/routerboard", "/ip/upnp",
                "/ip/firewall/connection/tracking"):
        return lines[0] + "\n" if lines else "\n"
    return "\n".join(lines) + "\n"


# 1.9.2: menus of RouterOS 7 only (the ssh stand-in can be told to not know them: FAKE_SSH_UNKNOWN)
ROUTER.setdefault("/ip/vrf", [])
ROUTER.setdefault("/routing/rule", [])
