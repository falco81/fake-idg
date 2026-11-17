#!/usr/bin/env python3
"""test_mikrotik.py - the MikroTik reader and its checks, against a MikroTik that is not there.

  python3 test/mikrotik/test_mikrotik.py         (from the source tree; openssl makes a certificate)

What it proves:
  - nothing but a read can leave: the menus, the REST GET, the API's print, the ssh console lines -
    anything else Refused before it is sent; and the fake routers saw no write at all
  - REST over HTTPS, the API over TLS and plain, ssh with a key and with a password, each against a fake router
  - the certificate: not trusted -> its fingerprint said and NOTHING sent (not even the password); trusted ->
    read; another certificate -> refused before the password
  - the ssh host key: unknown -> refused; trusted (shown by ssh-keyscan, chosen by fingerprint) -> read; changed
    -> refused with words that say so
  - the parsers: print as-value (isemon's), print terse / detail with comments, quotes, flags X D I, wrapped lines
  - the matcher: port ranges and lists, negation, interface lists, connection-state / connection-nat-state,
    address lists, ipsec-policy, hop-limit, "cannot tell"; first match wins; jumps; the default
    "drop all from WAN not DSTNATed"
  - the checks of fixture.py's router: open, shadowed (by a dst-nat elsewhere / an accept), disabled, missing,
    blocked by the filter, IPv6 blocked - and the commands they say
"""
import base64
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(os.path.dirname(HERE)), "src")
sys.path[:0] = [SRC, HERE]
os.environ["PATH"] = os.path.join(HERE, "bin") + os.pathsep + os.environ.get("PATH", "")
import fakerouter   # noqa: E402
import fixture      # noqa: E402
import igd_mikrotik as M   # noqa: E402
import igd_mtcheck as C    # noqa: E402

TMP = tempfile.mkdtemp(prefix="fake-igd-mt-test-")
WRITES = os.path.join(TMP, "writes")
os.environ["FAKE_ROUTER_WRITES"] = WRITES
os.environ["FAKE_ROUTER_LOG"] = os.path.join(TMP, "log")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_cert(name):
    cert, key = os.path.join(TMP, name + ".pem"), os.path.join(TMP, name + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
                    "/CN=" + name, "-keyout", key, "-out", cert], check=True, capture_output=True)
    return cert, key


def fp_of(cert):
    import hashlib
    import ssl
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(cert).read())).hexdigest()


class ReadOnly(unittest.TestCase):
    def test_menus(self):
        for bad in ("/ip/firewall/filter/add", "/system/reboot", "/user/set", "/ip/firewall/nat/remove", "/file",
                    "/system/script", "/tool/fetch", "", "/ip/firewall/filter/../../system/reboot", "/user/active"):
            with self.assertRaises(M.Refused, msg=bad):
                M.menu(bad)
        self.assertEqual(M.menu("/ip/firewall/filter/"), "/ip/firewall/filter")

    def test_api_talk(self):
        api = M.RosApi("127.0.0.1")
        api.sock = object()
        for cmd, args in (("/ip/firewall/filter/add", {"chain": "input"}), ("/system/reboot", None),
                          ("/ip/firewall/filter/set", {"numbers": "0"}), ("/ip/firewall/filter/print", {"x": "1"}),
                          ("/login", {"name": "a", "password": "b", "extra": "c"}), ("/user/print2", None)):
            with self.assertRaises(M.Refused, msg=cmd):
                api.talk(cmd, args)

    def test_ssh_lines(self):
        ok = M.ssh_command("/ip/firewall/filter")
        self.assertEqual(ok, ":foreach r in=[/ip firewall filter print as-value] do={:put $r}")
        self.assertEqual(M.ssh_command("/system/identity"), ":put [/system identity print as-value]")
        self.assertEqual(M.ssh_check(M.ssh_command("/user", ["name=fake-igd-read"])),
                         ':foreach r in=[/user print as-value where name="fake-igd-read"] do={:put $r}')
        for bad in ("/system reboot", ":put [/system reboot]", ":foreach r in=[/ip firewall filter print as-value] do={/system reboot}",
                    ":foreach r in=[/ip firewall filter print as-value] do={:put $r}; /system reboot",
                    ":put [/ip firewall filter print as-value]\n/system reboot",
                    ':foreach r in=[/user print as-value where name="a;b"] do={:put $r}',
                    ':foreach r in=[/ip firewall filter remove as-value] do={:put $r}',
                    ':foreach r in=[/file print as-value] do={:put $r}', ""):
            with self.assertRaises(M.Refused, msg=bad):
                M.ssh_check(bad)
        with self.assertRaises(M.Refused):
            M.ssh_command("/user", ["name=a;/system reboot"])
        with self.assertRaises(M.Refused):
            M.ssh_command("/user", ['name="x"'])

    def test_rest_get_only(self):
        self.assertFalse(hasattr(M.RosRest, "post") or hasattr(M.RosRest, "put") or hasattr(M.RosRest, "delete"))
        r = M.RosRest("127.0.0.1")
        r.ready = True
        with self.assertRaises(M.Refused):
            r.get("/system/reboot")
        with self.assertRaises(M.Refused):
            r.get("/user", ["name=a&b=c"])


class Parsers(unittest.TestCase):
    def test_as_value(self):
        text = (".id=*1;action=accept;chain=input;comment=defconf: accept established,related;disabled=false\r\n"
                ".id=*2;action=drop;chain=forward;comment=a;b with a semicolon;disabled=true;dst-port=3478-3480,9308\n"
                ".id=*3;action=dst-nat;chain=dstnat;comment=wrapped by the\n"
                "console;to-addresses=192.168.40.95\n")
        got = M.ssh_answers(text)
        self.assertEqual(len(got), 3)
        self.assertEqual(got[0]["comment"], "defconf: accept established,related")
        self.assertEqual(got[1]["comment"], "a;b with a semicolon")
        self.assertEqual(got[1]["dst-port"], "3478-3480,9308")
        self.assertEqual(got[2]["comment"], "wrapped by theconsole")
        self.assertEqual(got[2]["to-addresses"], "192.168.40.95")

    def test_terse(self):
        text = ("Flags: X - disabled, I - invalid; D - dynamic \n"
                " 0  D ;;; special dummy rule to show fasttrack counters\n"
                "      chain=forward action=passthrough \n"
                " 1    ;;; defconf: accept established,related,untracked\n"
                "      chain=input action=accept connection-state=established,related,untracked\n"
                " 2 X  chain=dstnat action=dst-nat protocol=udp dst-port=3074 to-addresses=192.168.40.95 "
                "comment=\"PS5 \\\"3074\\\" (off)\"\n"
                " 3    chain=dstnat action=dst-nat dst-port=3478-3480,9308 comment=no quotes here at all\n"
                " 4 XI chain=forward action=drop in-interface-list=!LAN\n"
                "      log=no log-prefix=\"\"\n")
        got = M.terse_answers(text)
        self.assertEqual([g[".n"] for g in got], ["0", "1", "2", "3", "4"])
        self.assertEqual(got[0]["dynamic"], "true")
        self.assertEqual(got[0]["comment"], "special dummy rule to show fasttrack counters")
        self.assertEqual(got[0]["action"], "passthrough")
        self.assertEqual(got[1]["connection-state"], "established,related,untracked")
        self.assertEqual(got[2]["disabled"], "true")
        self.assertEqual(got[2]["comment"], 'PS5 "3074" (off)')
        self.assertEqual(got[3]["comment"], "no quotes here at all")
        self.assertEqual(got[3]["dst-port"], "3478-3480,9308")
        self.assertEqual(got[4]["invalid"], "true")
        self.assertEqual(got[4]["log"], "no")
        self.assertEqual(got[4]["log-prefix"], "")
        # fixture's own terse print, every menu, read back as it was
        for path in ("/ip/firewall/filter", "/ip/firewall/nat", "/ipv6/firewall/filter"):
            back = M.terse_answers(fixture.terse(path))
            want = fixture.ROUTER[path]
            self.assertEqual(len(back), len(want), path)
            for b, w in zip(back, want):
                for k, v in w.items():
                    if not k.startswith(".") and k not in ("bytes", "packets", "invalid"):
                        self.assertEqual(b.get(k), v, "%s %s" % (path, k))

    def test_keyvalue(self):
        got = M.keyvalue_answers("  name: Mock\n      Tik\n  version: 7.16.2 (stable)\n")
        self.assertEqual(got[0]["name"], "MockTik")


def pkt(**kw):
    d = dict(family="ip", proto="udp", dport=9308, dst=[ipaddress.ip_address("198.51.100.7")], in_ifs={"ether1"},
             in_lists={"WAN", "all"}, chain="dstnat")
    d.update(kw)
    return C.Packet(**d)


class Matcher(unittest.TestCase):
    def m(self, rule, p=None):
        return C.match(rule, p or pkt())[0]

    def test_ports(self):
        self.assertTrue(C.ports_in("3478-3480,9308", 9308))
        self.assertTrue(C.ports_in("3478-3480,9308", 3479))
        self.assertFalse(C.ports_in("3478-3480,9308", 3481))
        self.assertTrue(self.m({"protocol": "udp", "dst-port": "9300-9310"}))
        self.assertFalse(self.m({"protocol": "udp", "dst-port": "!9300-9310"}))
        self.assertTrue(self.m({"protocol": "!tcp"}))
        self.assertTrue(self.m({"protocol": "17"}))
        self.assertIsNone(self.m({"src-port": "1024-65535"}))

    def test_interfaces(self):
        self.assertTrue(self.m({"in-interface-list": "WAN"}))
        self.assertFalse(self.m({"in-interface-list": "!WAN"}))
        self.assertTrue(self.m({"in-interface-list": "!LAN"}))
        self.assertTrue(self.m({"in-interface": "ether1"}))
        self.assertTrue(self.m({"in-interface": "ether*"}))
        self.assertFalse(self.m({"in-interface": "pppoe-out1"}))
        self.assertIsNone(self.m({"in-interface-list": "WAN"}, pkt(in_lists=None)))

    def test_states(self):
        self.assertFalse(self.m({"connection-state": "established,related"}))
        self.assertTrue(self.m({"connection-state": "new"}))
        self.assertTrue(self.m({"connection-state": "!invalid"}))
        fw = pkt(chain="forward", nat_state="dstnat")
        self.assertFalse(self.m({"connection-nat-state": "!dstnat"}, fw))
        self.assertTrue(self.m({"connection-nat-state": "dstnat"}, fw))
        self.assertTrue(self.m({"connection-nat-state": "!dstnat"}))
        self.assertFalse(self.m({"ipsec-policy": "in,ipsec"}))
        self.assertTrue(self.m({"ipsec-policy": "out,none"}))
        self.assertFalse(self.m({"hop-limit": "equal:1"}))
        self.assertIsNone(self.m({"limit": "10,5:packet"}))
        self.assertIsNone(self.m({"connection-mark": "games"}))
        self.assertTrue(self.m({"protocol": "udp", "hits": "5", "bytes": "9", "comment": "x"}))   # not matchers

    def test_addresses(self):
        self.assertTrue(self.m({"dst-address": "198.51.100.0/24"}))
        self.assertTrue(self.m({"dst-address": "198.51.100.1-198.51.100.9"}))
        self.assertFalse(self.m({"dst-address": "!198.51.100.0/24"}))
        self.assertTrue(self.m({"dst-address-type": "local"}))
        self.assertFalse(self.m({"src-address": "192.168.0.0/16"}))          # the internet is never private
        self.assertTrue(self.m({"src-address": "!192.168.0.0/16"}))
        self.assertIsNone(self.m({"src-address": "203.0.113.0/24", "action": "dst-nat"}))   # some sources only
        p = pkt(lists={"blacklist": [ipaddress.ip_network("198.51.100.0/24")], "lan": [ipaddress.ip_network("10.0.0.0/8")]})
        self.assertFalse(self.m({"src-address-list": "blacklist", "action": "drop"}, p))   # the usual peer is not on it
        self.assertIsNone(self.m({"src-address-list": "blacklist", "action": "accept"}, p))
        self.assertFalse(self.m({"src-address-list": "lan"}, p))
        self.assertFalse(self.m({"src-address-list": "nosuch"}, p))
        self.assertTrue(self.m({"src-address-list": "!nosuch", "action": "drop"}, p))

    def test_walk(self):
        rules = [{"chain": "dstnat", "action": "log", "n": 0},
                 {"chain": "dstnat", "action": "jump", "jump-target": "games", "in-interface-list": "WAN", "n": 1},
                 {"chain": "games", "action": "return", "protocol": "tcp", "n": 2},
                 {"chain": "games", "action": "dst-nat", "to-addresses": "192.168.40.95", "protocol": "udp", "n": 3},
                 {"chain": "dstnat", "action": "accept", "n": 4}]
        self.assertEqual(C.walk(rules, "dstnat", pkt())["rule"]["n"], 3)
        self.assertEqual(C.walk(rules, "dstnat", pkt(proto="tcp"))["rule"]["n"], 4)
        rules[1]["disabled"] = True
        self.assertEqual(C.walk(rules, "dstnat", pkt())["rule"]["n"], 4)
        unsure = [{"chain": "dstnat", "action": "drop", "limit": "1,1", "n": 0}]
        self.assertEqual(C.walk(unsure, "dstnat", pkt())["verdict"], "unsure")


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        R = fixture.router()
        raw = {n: R.get(p, []) for n, (p, _s, _x) in M.READ.items()}
        cls.snap = M.snapshot(raw, {}, "test")
        cls.res = C.check_all(cls.snap, fixture.WANTS)
        cls.by = {(r["proto"], r["port"]): r for r in cls.res["rows"]}

    def test_states(self):
        st = {k: v["state"] for k, v in self.by.items()}
        self.assertEqual(st[("udp", 9308)], "ok")
        self.assertEqual(st[("tcp", 3478)], "shadowed")     # rule #2 sends it to .50 first
        self.assertEqual(st[("udp", 3479)], "shadowed")     # rule #3 accepts it in dstnat
        self.assertEqual(st[("udp", 3074)], "disabled")
        self.assertEqual(st[("tcp", 9295)], "no_dnat")
        self.assertEqual(self.by[("udp", 3544)]["forward"], "blocked")   # "no Teredo", once translated

    def test_words_and_commands(self):
        ok = self.by[("udp", 9308)]
        self.assertIn("drop all from WAN not DSTNATed", ok["forward_why"])
        self.assertEqual(ok["commands"], [])
        sh = self.by[("tcp", 3478)]
        self.assertIn("place-before=*11", sh["commands"][0])
        self.assertTrue(sh["commands"][0].startswith("/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-port=3478 in-interface-list=WAN to-addresses=192.168.40.95"))
        self.assertEqual(self.by[("udp", 3074)]["commands"], ["/ip firewall nat enable *15"])
        te = self.by[("udp", 3544)]
        self.assertTrue(any("connection-nat-state=dstnat" in c and "place-before=*D" in c for c in te["commands"]))
        for c in sum((r["commands"] + r.get("v6_commands", []) for r in self.res["rows"]), []):
            self.assertNotIn(";", c)

    def test_v6(self):
        r = self.by[("udp", 9308)]
        self.assertEqual(r["v6"], "blocked")
        self.assertEqual(r["v6_addrs"], ["2a00:1028:8640:40::95"])
        self.assertIn("drop everything else not coming from LAN", r["v6_why"])
        self.assertIn("dst-address=2a00:1028:8640:40::95/128", r["v6_commands"][0])

    def test_warnings(self):
        self.assertTrue(any("own UPnP is ON" in w for w in self.res["warnings"]))
        self.assertEqual(self.res["wan"]["ifs"], ["ether1"])

    def test_merged(self):
        rows = [{"device": "d", "proto": "udp", "port": p, "to_port": p, "state": "no_dnat"} for p in (3478, 3479, 3480, 9308)]
        self.assertEqual(C.merged_commands(rows)[0]["ports"], "3478-3480,9308")



class WanWithoutList(unittest.TestCase):
    """1.9.2: a router with no interface list WAN (as the one this was made for): the WAN told by the
    default route of RouterOS 7 (immediate-gw), by the gateway's network, or by the public address."""

    def snap(self, routes, public=""):
        return {"iflists": {"all": ["VLAN108", "bridge"]}, "public_ip": public,
                "addresses4": [{"address": "195.189.0.26/29", "interface": "VLAN108", "disabled": False},
                               {"address": "192.168.40.1/24", "interface": "bridge", "disabled": False}],
                "routes4": routes}

    def test_immediate_gw(self):
        raw = {"routes4": [{"dst-address": "0.0.0.0/0", "gateway": "195.189.0.25",
                            "immediate-gw": "195.189.0.25%VLAN108", "active": "true", "routing-table": "main"}]}
        snap = M.snapshot(raw, {}, "test")
        self.assertEqual(snap["routes4"][0]["immediate"], "195.189.0.25%VLAN108")
        w = C.wan_of(dict(self.snap(snap["routes4"])))
        self.assertEqual(w["ifs"], {"VLAN108"})
        self.assertEqual([str(a) for a in w["addrs4"]], ["195.189.0.26"])

    def test_gateway_network(self):
        w = C.wan_of(self.snap([{"dst": "0.0.0.0/0", "gateway": "195.189.0.25", "immediate": "", "active": True,
                                 "disabled": False, "table": "main"}]))
        self.assertEqual(w["ifs"], {"VLAN108"})

    def test_public_address(self):
        w = C.wan_of(self.snap([], public="195.189.0.26"))
        self.assertEqual(w["ifs"], {"VLAN108"})
        self.assertIn("195.189.0.26", w["how"])

    def test_dst_address_rule(self):
        snap = self.snap([], public="195.189.0.26")
        snap.update({"rules": {"ip": {"nat": [{"chain": "dstnat", "action": "dst-nat", "protocol": "udp",
                                               "dst-port": "9308", "dst-address": "195.189.0.26",
                                               "in-interface": "VLAN108", "to-addresses": "192.168.40.95",
                                               "n": 71, ".id": "*47", "disabled": False}],
                                      "filter": [], "raw": [], "mangle": []}}, "lists": {}})
        res = C.check_all(snap, [{"device": "192.168.40.95", "proto": "udp", "port": 9308, "to_port": 9308}])
        self.assertEqual(res["rows"][0]["state"], "ok", res["rows"][0])
        self.assertFalse(any("cannot be told" in w for w in res["warnings"]))

class Live(unittest.TestCase):
    """The three ways, each against a fake router."""

    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = make_cert("mocktik")
        cls.other = make_cert("intruder")
        cls.rest_port, cls.api_port, cls.plain_port = free_port(), free_port(), free_port()
        fakerouter.serve("rest", cls.rest_port, cls.cert, cls.key, background=True)
        fakerouter.serve("api", cls.api_port, cls.cert, cls.key, background=True)
        fakerouter.serve("api", cls.plain_port, background=True)
        cls.pin = fp_of(cls.cert)

    def conf(self, **kw):
        c = {"host": "127.0.0.1", "mode": "rest", "tls": "pin", "port": self.rest_port, "user": fakerouter.USER,
             "timeout": 5}
        c.update(kw)
        return c

    def test_rest_trust_flow(self):
        open(os.environ["FAKE_ROUTER_LOG"], "w").close()
        got = M.probe(M.session(self.conf(), password=fakerouter.PASSWORD), fakerouter.USER)
        self.assertFalse(got["ok"])
        self.assertIn("not trusted yet", got["trouble"])
        self.assertEqual(got["fingerprint"], self.pin)
        self.assertEqual(open(os.environ["FAKE_ROUTER_LOG"]).read(), "", "nothing - not the password - before it is trusted")
        got = M.probe(M.session(self.conf(), password=fakerouter.PASSWORD, pin=self.pin), fakerouter.USER)
        self.assertTrue(got["ok"], got)
        self.assertEqual((got["identity"], got["version"], got["group"], got["can_write"]),
                         ("MockTik", "7.16.2 (stable)", "fake-igd-read", False))
        got = M.probe(M.session(self.conf(), password=fakerouter.PASSWORD, pin=fp_of(self.other[0])), fakerouter.USER)
        self.assertIn("another certificate than the one trusted", got["trouble"])
        got = M.probe(M.session(self.conf(), password="wrong", pin=self.pin), fakerouter.USER)
        self.assertIn("401", got["trouble"])

    def test_rest_ca(self):
        c = self.conf(tls="ca", ca=open(self.cert).read(), tls_name="mocktik")
        got = M.probe(M.session(c, password=fakerouter.PASSWORD), fakerouter.USER)
        self.assertTrue(got["ok"], got)
        c = self.conf(tls="ca", ca=open(self.other[0]).read(), tls_name="mocktik")
        got = M.probe(M.session(c, password=fakerouter.PASSWORD), fakerouter.USER)
        self.assertIn("not one this trusts", got["trouble"])

    def read_whole(self, sess):
        sess.connect()
        raw, missing = M.read_all(sess)
        sess.close()
        snap = M.snapshot(raw, missing, "x")
        self.assertEqual(len(snap["rules"]["ip"]["nat"]), len(fixture.NAT4))
        self.assertEqual(len(snap["rules"]["ipv6"]["filter"]), len(fixture.FILTER6))
        self.assertEqual(snap["identity"], "MockTik")
        res = C.check_all(snap, fixture.WANTS)
        self.assertEqual(res["counts"].get("ok"), 1)
        return snap

    def test_read_rest_api_plain(self):
        self.read_whole(M.session(self.conf(), password=fakerouter.PASSWORD, pin=self.pin))
        self.read_whole(M.session(self.conf(mode="api", port=self.api_port), password=fakerouter.PASSWORD, pin=self.pin))
        self.read_whole(M.session(self.conf(mode="api", tls="plain", port=self.plain_port), password=fakerouter.PASSWORD))
        got = M.probe(M.session(self.conf(mode="api", tls="plain", port=self.plain_port), password="no"), fakerouter.USER)
        self.assertIn("refused the sign-in", got["trouble"])

    def test_ssh(self):
        kh = os.path.join(TMP, "known_hosts")
        if os.path.exists(kh):
            os.unlink(kh)
        c = self.conf(mode="ssh", port=2222, auth="key")
        key, pub = M.make_key()
        self.assertIn("ssh-ed25519", pub)
        os.environ["FAKE_SSH_LOG"] = os.path.join(TMP, "sshlog")
        got = M.probe(M.session(c, key=key, known_hosts=kh), fakerouter.USER)
        self.assertFalse(got["ok"])
        self.assertIn("host key", got["trouble"])
        keys = M.host_key_scan("127.0.0.1", 2222)
        self.assertTrue(keys[0]["fingerprint"].startswith("SHA256:"))
        with self.assertRaises(M.MtError):
            M.host_key_trust(kh, "127.0.0.1", 2222, keys, "SHA256:not-this-one")
        M.host_key_trust(kh, "127.0.0.1", 2222, keys, keys[0]["fingerprint"])
        self.assertEqual(oct(os.stat(kh).st_mode & 0o777), "0o600")
        self.assertEqual(M.host_keys_known(kh, "127.0.0.1", 2222)[0]["fingerprint"], keys[0]["fingerprint"])
        self.read_whole(M.session(c, key=key, known_hosts=kh))
        got = M.probe(M.session(c, key=key, known_hosts=kh), fakerouter.USER)
        self.assertTrue(got["ok"], got)
        # with a password, on a terminal of its own
        snap = self.read_whole(M.session(dict(c, auth="password"), password=fakerouter.PASSWORD, known_hosts=kh))
        self.assertTrue(snap["rules"]["ip"]["nat"][-1]["disabled"])
        got = M.probe(M.session(dict(c, auth="password"), password="wrong", known_hosts=kh), fakerouter.USER)
        self.assertFalse(got["ok"])
        # another host key: refused, said so
        os.environ["FAKE_SSH_HOSTKEY"] = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519another-key-entirely!").decode()
        try:
            got = M.probe(M.session(c, key=key, known_hosts=kh), fakerouter.USER)
            self.assertIn("other than the one trusted", got["trouble"])
        finally:
            del os.environ["FAKE_SSH_HOSTKEY"]
        self.assertTrue(M.host_key_forget(kh, "127.0.0.1", 2222))
        for line in open(os.environ["FAKE_SSH_LOG"]):
            M.ssh_check(line.split(" ", 3)[3].rstrip("\n"))

    @classmethod
    def tearDownClass(cls):
        writes = open(WRITES).read() if os.path.exists(WRITES) else ""
        assert writes == "", "the fake routers saw something that is not a read:\n" + writes


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
