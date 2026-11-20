#!/usr/bin/env python3
"""test_fixes_199.py - the MikroTik reader, its checks and Gateway for devices: what 1.9.9 put right.

  python3 test/mikrotik/test_fixes_199.py

Each test fails on 1.9.8 and passes now (documentation addresses only: 192.0.2/24, 198.51.100/24,
203.0.113/24, 2001:db8::/32).
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "deploy"), HERE]
os.environ["PATH"] = os.path.join(HERE, "bin") + os.pathsep + os.environ.get("PATH", "")
import fakerouter   # noqa: E402
import fixture      # noqa: E402
import igd_mikrotik as M   # noqa: E402
import igd_mtcheck as C    # noqa: E402

TMP = tempfile.mkdtemp(prefix="fake-igd-mt-fix-")


def snap_of(raw):
    full = {n: [] for n in M.READ}
    full.update(raw)
    return M.snapshot(full, {}, "test")


class InterfaceLists(unittest.TestCase):
    def test_dynamic_is_the_flag_not_the_name(self):
        s = snap_of({"interfaces": [{"name": "ether1"}, {"name": "pppoe-out1", "dynamic": "false"},
                                    {"name": "ovpn-server1"}, {"name": "<pppoe-alice>", "dynamic": "true"},
                                    {"name": "l2tp-in1", "dynamic": "true"}]})
        self.assertEqual(sorted(s["iflists"]["dynamic"]), ["<pppoe-alice>", "l2tp-in1"])
        self.assertIn("pppoe-out1", s["iflists"]["static"])
        self.assertIn("ovpn-server1", s["iflists"]["static"])

    def test_include_exclude(self):
        s = snap_of({"interfaces": [{"name": n} for n in ("ether1", "ether2", "bridge", "wg0", "lte1")],
                     "iflists": [{"name": "WAN"}, {"name": "LAN"}, {"name": "VPN"},
                                 {"name": "INSIDE", "include": "LAN,VPN"},
                                 {"name": "NOTWAN", "include": "all", "exclude": "WAN"},
                                 {"name": "OUTER", "include": "INSIDE,WAN", "exclude": "VPN"}],
                     "iflist_members": [{"list": "WAN", "interface": "ether1"}, {"list": "WAN", "interface": "lte1"},
                                        {"list": "LAN", "interface": "bridge"}, {"list": "VPN", "interface": "wg0"}]})
        L = s["iflists"]
        self.assertEqual(sorted(L["INSIDE"]), ["bridge", "wg0"])
        self.assertEqual(sorted(L["NOTWAN"]), ["bridge", "ether2", "wg0"])
        self.assertEqual(sorted(L["OUTER"]), ["bridge", "ether1", "lte1"])
        # and the checks see it: a forward accept for in-interface-list=NOTWAN does not hold for the WAN
        self.assertNotIn("NOTWAN", C.lists_of(s, {"ether1"}))
        self.assertIn("INSIDE", C.lists_of(s, {"wg0"}))


class SshBatch(unittest.TestCase):
    def test_a_comment_cannot_fake_a_mark(self):
        nonce = "0123456789abcdef"
        line = M.ssh_batch(["identity", "filter4"], nonce)
        self.assertIn('==fake-igd-%s=identity==' % nonce, line)
        M.ssh_batch_check(line)
        text = ("==fake-igd-%s=identity==\r\nname=gw\r\n==fake-igd-%s=filter4==\r\n"
                ".id=*1;chain=forward;action=accept;comment=x\r\n==fake-igd=identity==\r\nname=evil\r\n"
                "==fake-igd-ffffffffffffffff=identity==\r\nname=evil2\r\n" % (nonce, nonce))
        parts = M.ssh_split(text, nonce)
        self.assertEqual(sorted(parts), ["filter4", "identity"])
        self.assertNotIn("evil", parts["identity"])
        self.assertIn("name=evil2", parts["filter4"])   # the fake marks stay in the menu whose comment held them
        with self.assertRaises(M.Refused):
            M.ssh_batch(["identity"], "NOT-hex; /system reboot")

    def test_a_line_with_a_newline_is_refused(self):
        with self.assertRaises(M.Refused):
            M.ssh_check(":put [/system identity print as-value]\n")
        with self.assertRaises(M.Refused):
            M.ssh_batch_check(':put "==fake-igd=identity=="\n; :put [/system identity print as-value]')

    def test_refused_while_running(self):
        """/log refused (not enough permissions) ends RouterOS's line there: what came after it is read again."""
        kh = os.path.join(TMP, "kh")
        keys = M.host_key_scan("127.0.0.1", 2222)
        M.host_key_trust(kh, "127.0.0.1", 2222, keys, keys[0]["fingerprint"])
        key, _pub = M.make_key()
        c = {"host": "127.0.0.1", "mode": "ssh", "port": 2222, "user": fakerouter.USER, "auth": "key", "timeout": 5}
        os.environ["FAKE_SSH_DENY"] = "/log"
        log = os.environ["FAKE_SSH_LOG"] = os.path.join(TMP, "sshlog")
        try:
            sess = M.session(c, key=key, known_hosts=kh)
            sess.connect()
            raw, missing = M.read_all(sess)
        finally:
            del os.environ["FAKE_SSH_DENY"]
            del os.environ["FAKE_SSH_LOG"]
        self.assertIn("not enough permissions", missing.get("log", ""))
        self.assertTrue(raw.get("filter4"))     # after /log in READ: read again, not "not answered"
        self.assertTrue(raw.get("nat4"))
        self.assertEqual([n for n, why in missing.items() if why == "not answered"], [])
        with open(log) as f:
            lines = f.read().splitlines()
        self.assertTrue(all("fake-igd-" in ln for ln in lines if "; " in ln))   # each batch with its nonce
        for ln in lines:
            M.ssh_batch_check(ln.split(" ", 3)[3])


class RestTimeout(unittest.TestCase):
    def test_a_router_that_stopped_answering_ends_the_read(self):
        class Slow(object):
            n = 0

            def read(self, path):
                if path == "/system/identity":
                    return [{"name": "gw"}]
                Slow.n += 1
                raise M.MtError("192.0.2.1: timed out")
        raw, missing = M.read_all(Slow())
        self.assertEqual(Slow.n, 1)             # not every menu waiting its timeout


class FwLog(unittest.TestCase):
    def test_lines(self):
        lines = [
            {"time": "10:00:00", "topics": "firewall,info", "message":
             "DROPforward: in:ether1 out:bridge, connection-state:new proto TCP (SYN), "
             "198.51.100.7:5000->192.0.2.10:3074, len 60"},
            {"time": "10:00:01", "topics": "firewall,info", "message":
             "v6 drop forward: in:ether1 out:bridge, connection-state:new proto ICMP (type 128, code 0), "
             "2001:db8:1::7->2001:db8::95, len 104"},
            {"time": "10:00:02", "topics": "firewall,info", "message":
             "out output: in:(unknown 0) out:ether1, connection-state:new proto UDP, 192.0.2.1:123->203.0.113.5:123, len 76"},
            {"time": "10:00:03", "topics": "firewall,info", "message":
             "wan-input: in:ether1 out:(unknown 0), proto TCP (SYN), 198.51.100.7:5000->203.0.113.26:22, len 60"}]
        got = M.fw_log(lines, chains={"forward", "wan-input"})
        self.assertEqual(len(got), 4)
        self.assertEqual((got[0]["prefix"], got[0]["chain"], got[0]["dport"]), ("DROP", "forward", 3074))
        self.assertEqual((got[1]["family"], got[1]["dst"], got[1]["src"]), ("ipv6", "2001:db8::95", "2001:db8:1::7"))
        self.assertEqual((got[2]["in"], got[2]["chain"], got[2]["prefix"]), ("(unknown 0)", "output", "out"))
        self.assertEqual((got[3]["chain"], got[3]["prefix"]), ("wan-input", ""))   # a chain of its own, kept whole
        # and its drops are told as the rule that wrote them says: log-prefix=DROP is a drop rule
        snap = {"at": time.time(), "fwlog": got, "rules": {"ip": {"filter": [
            {"chain": "forward", "action": "drop", "log": True, "log-prefix": "DROP"}]}}}
        self.assertEqual(C.drops_of(snap, ["192.0.2.10"], "tcp", {3074})["by"], {"DROP": 1})


class LogEpoch(unittest.TestCase):
    def test_new_year(self):
        import datetime as d
        ref = d.datetime(2027, 1, 1, 0, 5, 0).timestamp()
        at = C.log_epoch("dec/31 23:59:00", ref)
        self.assertEqual(d.datetime.fromtimestamp(at).year, 2026)
        self.assertLess(at, ref)
        self.assertEqual(d.datetime.fromtimestamp(C.log_epoch("12-31 23:59:00", ref)).year, 2026)
        self.assertEqual(d.datetime.fromtimestamp(C.log_epoch("jan/01 00:01:00", ref)).year, 2027)
        self.assertEqual(d.datetime.fromtimestamp(C.log_epoch("dec/31/2026 23:59:00", ref)).year, 2026)


class Wan(unittest.TestCase):
    def test_ecmp_and_gateway_interface(self):
        s = {"addresses4": [{"address": "192.0.2.2/30", "interface": "ether1"},
                            {"address": "198.51.100.2/30", "interface": "ether2"}],
             "routes4": [{"dst": "0.0.0.0/0", "gateway": "192.0.2.1,198.51.100.1", "active": True, "table": "main"}]}
        self.assertEqual(C.wan_of(s)["ifs"], {"ether1", "ether2"})
        s["routes4"] = [{"dst": "0.0.0.0/0", "gateway": "203.0.113.1%lte1", "active": True, "table": "main"}]
        self.assertEqual(C.wan_of(s)["ifs"], {"lte1"})


# ---- api_mikrotik: a ctx of its own --------------------------------------------------------------------------
class Store(object):
    def __init__(self):
        self.meta = {}

    def get_meta(self, k):
        return self.meta.get(k)

    def set_meta(self, k, v):
        self.meta[k] = v


class Ctx(object):
    def __init__(self, **settings):
        self.store, self.cfg, self.events, self.me = Store(), {"state_dir": TMP}, [], {"name": "t"}
        self.s = dict({"mikrotik": True, "mikrotik_host": "192.0.2.1", "mikrotik_mode": "rest"}, **settings)

    def setting(self, k):
        if k in self.s and isinstance(self.s[k], Exception):
            raise self.s[k]
        return self.s.get(k)

    def event(self, words, level="info"):
        self.events.append(words)


class ApiMikrotik(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import api_mikrotik as A
        cls.A = A
        R = fixture.router()
        cls.snap = M.snapshot({n: R.get(p, []) for n, (p, _s, _x) in M.READ.items()}, {}, "test")

    def setUp(self):
        self.A.READING["busy"] = False

    def test_busy_cleared_when_the_settings_cannot_be_read(self):
        ctx = Ctx(mikrotik_port=ValueError("a broken setting"))
        self.A.read_now(ctx)
        self.assertFalse(self.A.READING["busy"])

    def test_another_router(self):
        ctx = Ctx()
        ctx.store.set_meta("mikrotik:snap", json.dumps(dict(self.snap, host="198.51.100.1")))
        was = self.A.wants
        self.A.wants = lambda ctx: list(fixture.WANTS)
        try:
            self.assertIsNone(self.A.checks(ctx))           # the old router's firewall is not this one's
            self.assertNotIn("checks", self.A.view(ctx))
            ctx.s["mikrotik_host"] = "198.51.100.1"
            self.assertTrue(self.A.checks(ctx)["rows"])
        finally:
            self.A.wants = was

    def test_opened_keeps_only_what_is_asked(self):
        ctx = Ctx()
        ctx.store.set_meta("mikrotik:snap", json.dumps(dict(self.snap, host="192.0.2.1")))
        old = {"192.0.2.%d/udp/%d/4" % (i % 250, 1000 + i): {"ok": True, "since": 0} for i in range(3000)}
        ctx.store.set_meta("mikrotik:opened", json.dumps(old))
        was = self.A.wants
        self.A.wants = lambda ctx: list(fixture.WANTS)
        try:
            res = self.A.checks(ctx)
        finally:
            self.A.wants = was
        seen = json.loads(ctx.store.get_meta("mikrotik:opened"))
        self.assertEqual(len(seen), 2 * len(res["rows"]))
        self.assertTrue(all(k.split("/")[0] in {w["device"] for w in fixture.WANTS} for k in seen))


class GatewayTab(unittest.TestCase):
    def test_mikrotik_off_says_nothing(self):
        import types
        import api_gateway as G
        keep = {k: getattr(G, k) for k in ("state", "view", "today_of", "series_of")}
        G.state = lambda: {}
        G.view = lambda ctx: {"devices": [{"ip": "192.0.2.50", "name": "PS5"}], "on": True, "net": {}, "applied": {},
                              "live": {}, "trial": {}, "now": 0, "neigh": {}}
        G.today_of = lambda store, ip, key="out": {"bytes": 0, "pkts": 0, "rate": 0.0}
        G.series_of = lambda store, ip, since, until: {"step": 60, "series": []}
        was = sys.modules.get("api_mikrotik")
        on = {"on": False}
        sys.modules["api_mikrotik"] = types.SimpleNamespace(
            conf=lambda ctx: dict(on), checks=lambda ctx: {"rows": [{"device": "192.0.2.50", "state": "no_dnat"}]})
        ctx = Ctx()
        ctx.need = lambda level: {"name": "t", "role": "readonly"}
        ctx.arg = lambda k: None
        try:
            self.assertFalse(G.tab(ctx)["mikrotik"])        # switched off: its last read is not its word
            self.assertIsNone(G.tab(ctx)["devices"][0]["mikrotik"])
            on["on"] = True
            self.assertEqual(len(G.tab(ctx)["devices"][0]["mikrotik"]), 1)
        finally:
            for k, v in keep.items():
                setattr(G, k, v)
            if was is not None:
                sys.modules["api_mikrotik"] = was
            else:
                del sys.modules["api_mikrotik"]


class GatewayIp6(unittest.TestCase):
    def test_ip6_checked(self):
        import root_gateway as R
        net = {"ifaces": {"eth0": ["192.0.2.2/24"]}, "defif": "eth0", "router": "192.0.2.1"}
        base = {"name": "PS5", "ip": "192.0.2.50"}
        for bad in ("::ffff:192.0.2.50", "fec0::5", "64:ff9b::c000:232", "fe80::1", "ff02::1"):
            got, why = R.device_checked(dict(base, ip6=[bad]), net)
            self.assertIsNone(got, bad)
            self.assertIn("not an IPv6 address of a device", why)
        got, why = R.device_checked(dict(base, ip6="2001:db8::50, fd00::50"), net)
        self.assertEqual(got["ip6"], ["2001:db8::50", "fd00::50"], why)


if __name__ == "__main__":
    import shutil
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
