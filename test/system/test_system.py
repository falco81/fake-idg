#!/usr/bin/env python3
"""test_system.py - the Settings panes that drive the OS through root's helpers (TLS, SSH, local users,
SELinux, Network, Proxy, Time, The service, Power, Disks): what 1.9.11 put right.

  python3 test/system/test_system.py

No root, no network: each helper is pointed at files of a folder of its own, its programs at small
scripts. Each test fails on 1.9.10 and passes now (documentation addresses only: 192.0.2/24,
198.51.100/24, 203.0.113/24, 2001:db8::/32).
"""
import importlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "deploy")]
os.environ["FAKE_IGD_NO_SERVICES"] = "1"

TMP = tempfile.mkdtemp(prefix="fake-igd-system-")


def folder(name):
    p = os.path.join(TMP, name)
    shutil.rmtree(p, ignore_errors=True)
    os.makedirs(p)
    return p


def script(path, body):
    """A small program standing in for one of the system's."""
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, 0o755)
    return path


def write(path, text):
    with open(path, "w") as f:
        f.write(text)
    return path


def read(path):
    with open(path) as f:
        return f.read()


class FakeStore(object):
    def __init__(self):
        self.meta = {}

    def get_meta(self, k):
        return self.meta.get(k)

    def set_meta(self, k, v):
        self.meta[k] = v

    def meta_json(self, k):
        try:
            got = json.loads(self.meta.get(k) or "null")
        except ValueError:
            return None
        return got if isinstance(got, dict) else None


class FakeCtx(object):
    """What a pane's API function is given - with a store in memory and root's answer as set."""

    def __init__(self, settings=None, result=None, body=None, cfg=None):
        self.store, self.settings, self.result = FakeStore(), dict(settings or {}), dict(result or {})
        self._body, self.cfg, self.events, self.asked = dict(body or {}), dict(cfg or {}), [], []
        self.me, self.addr, self.q = {"name": "admin", "role": "fulladmin"}, "192.0.2.50", {}

    def setting(self, k):
        return self.settings.get(k)

    def root_result(self, kind=None, ident=None):
        return self.result

    def ask_root(self, payload, kind=None):
        self.asked.append(payload)
        return "1700000000000-0123abcd"

    def event(self, words, level="info", kind=None):
        self.events.append((words, level))

    def need(self, role="fulladmin"):
        return self.me

    def body(self):
        return self._body

    def arg(self, name, default=""):
        return default


# ---- Disks and logs (root_disks) ------------------------------------------------------------
class Disks(unittest.TestCase):
    def setUp(self):
        import root_disks
        self.D = importlib.reload(root_disks)
        d = folder("disks")
        self.D.DROPIN = os.path.join(d, "journald.conf.d", "00-fake-igd.conf")
        self.D.LOGROTATE = write(os.path.join(d, "fake-igd"),
                                 "/var/log/fake-igd/*.log {\n    daily\n    rotate 30\n    maxsize 200M\n}\n")
        self.D.JOURNALCTL = os.path.join(d, "no-journalctl")
        self.bin = d

    def test_logrotate_refusing_is_not_ok(self):
        # logrotate -d says no: the file goes back, the answer is not ok and carries no hash - the pages
        # must not show the limits "as set" (1.9.10 answered ok with the hash).
        self.D.LOGROTATE_BIN = script(os.path.join(self.bin, "logrotate"),
                                      'echo "error: fake-igd:3 bad rotate count" >&2; exit 1')
        was = read(self.D.LOGROTATE)
        got = self.D.serve({"do": "apply", "journal_mb": 0, "journal_days": 0, "keep": 7, "every": "daily",
                            "max_mb": 50, "hash": "0123456789abcdef"}, {})
        self.assertFalse(got["ok"])
        self.assertNotIn("hash", got)
        self.assertEqual(read(self.D.LOGROTATE), was)
        self.assertTrue(any(s.endswith("bad rotate count") for s in got["said"]), got["said"])

    def test_logrotate_taking_it_is_ok(self):
        self.D.LOGROTATE_BIN = script(os.path.join(self.bin, "logrotate"), "exit 0")
        got = self.D.serve({"do": "apply", "journal_mb": 0, "journal_days": 0, "keep": 7, "every": "daily",
                            "max_mb": 50, "hash": "0123456789abcdef"}, {})
        self.assertTrue(got["ok"])
        self.assertEqual(got["hash"], "0123456789abcdef")
        self.assertIn("rotate 7", read(self.D.LOGROTATE))


# ---- TLS (root_tls) -------------------------------------------------------------------------
class TlsProgress(unittest.TestCase):
    def test_progress_done_never_through_a_link_for_web(self):
        import root_tls
        T = importlib.reload(root_tls)
        d = folder("tls")
        other = os.path.join(d, "elsewhere")
        os.makedirs(other)
        write(os.path.join(other, "progress-tls.json"), "{}")
        state = os.path.join(d, "state")
        os.makedirs(state)
        os.symlink(other, os.path.join(state, "web"))         # laid by the API's account in web/'s place
        T.WEB_DIR = os.path.join(state, "web")
        T.progress_done()
        self.assertTrue(os.path.exists(os.path.join(other, "progress-tls.json")))

    def test_progress_done_takes_its_own_file(self):
        import root_tls
        T = importlib.reload(root_tls)
        d = folder("tls2")
        T.WEB_DIR = d
        write(os.path.join(d, "progress-tls.json"), "{}")
        T.progress_done()
        self.assertFalse(os.path.exists(os.path.join(d, "progress-tls.json")))


# ---- Network (root_net) ---------------------------------------------------------------------
HOSTS = ("127.0.0.1 localhost\n::1 localhost\n192.0.2.10 vm.example.com vm\n192.0.2.11 www.example.com\n"
         "2001:db8::10 vm.example.com vm\n")


class NetHosts(unittest.TestCase):
    def setUp(self):
        import root_net
        self.R = importlib.reload(root_net)
        d = folder("net")
        self.d = d
        self.R.HOSTS_FILE = write(os.path.join(d, "hosts"), HOSTS)
        self.R.SYSCTL6 = os.path.join(d, "90-fake-igd-ipv6.conf")
        self.R.WEB_DIR = os.path.join(d, "web")
        self.R.TRIAL_FILE = os.path.join(d, "web", "net-trial.json")
        self.log = os.path.join(d, "nmcli.log")
        fields = "manual\n192.0.2.10/24, 192.0.2.11/24\n192.0.2.1\n192.0.2.53\n\nmanual\n2001\\:db8\\:\\:10/64\n\n"
        self.R.NMCLI = script(os.path.join(d, "nmcli"), (
            'echo "$@" >> %s\n'
            'case "$*" in\n'
            '  "-t -g NAME connection show") echo eth0 ;;\n'
            '  "-t -g ipv4.method,"*) printf "%s" ;;\n'
            'esac\nexit 0') % (self.log, fields))
        self.R.HOSTNAMECTL = script(os.path.join(d, "hostnamectl"), "echo vm.example.com")
        self.R.SYSCTL = script(os.path.join(d, "sysctl"), "exit 0")

    def test_ipv6_kept_and_a_second_address_keep_their_lines(self):
        got = self.R.serve({"do": "apply", "con": "eth0", "ipv4": {"method": "manual", "addr": "192.0.2.20/24",
                                                                   "gw": "192.0.2.1"},
                            "ipv6": {"mode": "keep"}, "hostname": "vm.example.com"}, {})
        self.assertTrue(got["ok"], got)
        hosts = read(self.R.HOSTS_FILE)
        self.assertIn("192.0.2.20 vm.example.com vm\n", hosts)
        self.assertIn("192.0.2.11 www.example.com\n", hosts)        # 1.9.10: 192.0.2.20 www.example.com
        self.assertIn("2001:db8::10 vm.example.com vm\n", hosts)    # 1.9.10: the line was gone
        self.assertNotIn("192.0.2.10 ", hosts)
        # the second address stays in the connection, as before
        self.assertIn("192.0.2.20/24,192.0.2.11/24", read(self.log))

    def test_dhcp_takes_the_lines_of_the_addresses_it_takes_away(self):
        got = self.R.serve({"do": "apply", "con": "eth0", "ipv4": {"method": "auto"},
                            "ipv6": {"mode": "auto"}, "hostname": "vm.example.com"}, {})
        self.assertTrue(got["ok"], got)
        hosts = read(self.R.HOSTS_FILE)
        self.assertNotIn("192.0.2.10", hosts)
        self.assertNotIn("2001:db8::10", hosts)


# ---- Proxy (igd_proxy) ----------------------------------------------------------------------
class ProxyNo(unittest.TestCase):
    def test_an_address_in_brackets_is_reached_straight(self):
        import igd_proxy as P
        c = {"proxy_no": "localhost, [2001:db8::1], 192.0.2.0/24"}
        self.assertTrue(P.skips(c, "[2001:db8::1]"))      # 1.9.10: through the proxy
        self.assertTrue(P.skips(c, "2001:db8::1"))
        self.assertTrue(P.skips(c, "192.0.2.7"))
        self.assertFalse(P.skips(c, "2001:db8::2"))
        self.assertFalse(P.skips(c, "198.51.100.1"))


class NetCheck(unittest.TestCase):
    def now(self, m6):
        conf = {"ipv4_method": "manual", "ipv4_addresses": ["192.0.2.10/24"], "ipv4_gateway": "192.0.2.1",
                "ipv4_dns": [], "ipv4_search": [], "ipv6_method": m6, "ipv6_addresses": [], "ipv6_gateway": "",
                "ipv6_dns": []}
        return {"nm": True, "hostname": "vm.example.com", "page_dev": "",
                "devices": [{"dev": "eth0", "con": "eth0", "addrs4": ["192.0.2.10/24"], "addrs6": [],
                             "answers": False, "conf": conf}]}

    def test_ipv4_changed_beside_an_ipv6_method_as_found(self):
        import api_net as N
        want = {"dev": "eth0", "hostname": "vm.example.com",
                "ipv4": {"method": "manual", "addr": "192.0.2.20/24", "gw": "192.0.2.1"},
                "ipv6": {"method": "shared", "dns": ""}}
        got = N.check(FakeCtx(), self.now("shared"), want, 5)   # 1.9.10: "IPv6 is one of: ..."
        self.assertEqual(got["ipv6"]["mode"], "keep")
        self.assertEqual(got["ipv4"]["addr"], "192.0.2.20/24")

    def test_a_method_not_found_is_still_refused(self):
        import api_net as N
        want = {"dev": "eth0", "ipv4": {"method": "auto"}, "ipv6": {"method": "shared"}}
        with self.assertRaises(ValueError):
            N.check(FakeCtx(), self.now("auto"), want, 5)


# ---- Restart and power off (api_power) ------------------------------------------------------
class Power(unittest.TestCase):
    def test_an_ask_root_never_answers_does_not_stay_asked(self):
        import api_power as P
        import time
        ctx = FakeCtx(result={"id": "another", "ok": True})
        ctx.store.set_meta("power:plan", json.dumps({"ask": "1700000000000-0123abcd", "how": "reboot", "in": 0,
                                                     "at": time.time() - 600, "state": "asked",
                                                     "words": "a restart now"}))
        p = P.plan(ctx)
        self.assertEqual(p["state"], "failed")
        self.assertIn("did not answer", p["said"][0])
        self.assertEqual(ctx.store.meta_json("power:plan")["state"], "failed")

    def test_a_fresh_ask_stays_asked(self):
        import api_power as P
        import time
        ctx = FakeCtx(result={})
        ctx.store.set_meta("power:plan", json.dumps({"ask": "x", "how": "reboot", "in": 0, "at": time.time() - 5,
                                                     "state": "asked"}))
        self.assertEqual(P.plan(ctx)["state"], "asked")


# ---- Time (pane-time.js) --------------------------------------------------------------------
class TimeWords(unittest.TestCase):
    def test_the_pane_does_not_say_the_firewall_opens_udp_123(self):
        # fake-igd's chain FAKE-IGD-IN has no rule for the time; the pane said "The firewall opens it by
        # itself" while the setting itself says to open it.
        with open(os.path.join(ROOT, "web", "assets", "pane-time.js"), encoding="utf-8") as f:
            js = f.read()
        with open(os.path.join(ROOT, "deploy", "fake_igd_web.py"), encoding="utf-8") as f:
            fw = f.read()
        self.assertNotIn("dport 123", fw)
        self.assertNotIn("The firewall opens it by itself", js)
        self.assertIn("Open UDP 123 in the firewall for them too", js)


# ---- asks root never answers: Time's "sync now", Disks (1.9.11) ------------------------------
class Unanswered(unittest.TestCase):
    def test_time_sync_not_asked_for_ever(self):
        import api_time as T
        import time
        T.read = lambda: {}
        T.applied = lambda ctx: {}
        ctx = FakeCtx(result={"id": "another"})
        ctx.store.set_meta("time:sync", json.dumps({"ask": "x", "at": time.time() - 600}))
        sync = T.view(ctx)["sync"]
        self.assertTrue(sync["done"])
        self.assertFalse(sync["ok"])
        ctx.store.set_meta("time:sync", json.dumps({"ask": "x", "at": time.time() - 5}))
        self.assertFalse(T.view(ctx)["sync"].get("done"))

    def test_disks_not_waiting_for_ever(self):
        import api_disks as D
        import time
        D.filesystems = lambda: []
        D.log_files = lambda folder: []
        D.dir_size = lambda folder: 0
        ctx = FakeCtx(result={"id": "another", "ok": True}, cfg={"state_dir": "/nonexistent"})
        ctx.store.set_meta("disks:asked", json.dumps({"id": "x", "at": time.time() - 600}))
        d = D.view(ctx)
        self.assertFalse(d["waiting"])
        self.assertTrue(d["unanswered"])
        ctx.store.set_meta("disks:asked", json.dumps({"id": "x", "at": time.time() - 5}))
        d = D.view(ctx)
        self.assertTrue(d["waiting"])
        self.assertFalse(d["unanswered"])


class TlsExportPassword(unittest.TestCase):
    def test_a_carriage_return_is_refused(self):
        src = open(os.path.join(ROOT, "deploy", "root_tls.py"), encoding="utf-8").read()
        self.assertIn("ord(c) < 32", src)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
