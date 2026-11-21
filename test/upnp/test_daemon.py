#!/usr/bin/env python3
"""test_daemon.py - the UPnP daemon (src/fake-igd.py) and the upnp command, against bugs fixed in 1.9.9.

  python3 test/upnp/test_daemon.py         (from the source tree; no root, no network: the SOAP parser and the
                                           SSDP handler are called as functions, the HTTP server on 127.0.0.1)

What it proves:
  - a SOAP request with a DOCTYPE (an external entity - XXE -, or "billion laughs") is refused 402 and
    nothing is added; an ordinary one is read
  - the log line of a SOAP request is cut: a 64 KB description is not a 64 KB line
  - an M-SEARCH whose lines end by LF alone is answered as one ended by CRLF
  - fake-igd.py --summary passes by request-log lines that are not a request (it stopped with a traceback)
  - upnp requests / log -n: a negative N is refused (it showed all but the first N); upnp requests passes by
    a line that is not a request; upnp mappings shows an added_at in seconds (it stopped with a traceback)
  - IGD:2 AddAnyPortMapping with the external port 0 (a wildcard): a port is picked (it was 402); AddPortMapping
    with 0 stays 402
  - mappings.json of another shape ({...}, [1, "x"]): upnp mappings and the pages' Mappings show none, not a
    traceback / a 500
  - upnp updates with no run yet: no "the last run None, None None%"
  - the pages' API: a time picker's since/until/hours past what the clock can say (1e20, inf, nan, 1e300) is
    no end, not a 500 "the API broke on that"
"""
import importlib.util
import io
import json
import logging
import os
import socket
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(os.path.dirname(HERE)), "src")
sys.path.insert(0, SRC)
spec = importlib.util.spec_from_file_location("fake_igd", os.path.join(SRC, "fake-igd.py"))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

V1 = "urn:schemas-upnp-org:service:WANIPConnection:1"


def envelope(action, args, pre='<?xml version="1.0"?>'):
    a = "".join("<%s>%s</%s>" % (k, v, k) for k, v in args)
    return (pre + '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:%s xmlns:u="%s">%s'
            '</u:%s></s:Body></s:Envelope>' % (action, V1, a, action)).encode()


def add_args(port, desc="d"):
    return [("NewRemoteHost", ""), ("NewExternalPort", port), ("NewProtocol", "TCP"), ("NewInternalPort", "22"),
            ("NewInternalClient", "127.0.0.1"), ("NewEnabled", "1"), ("NewPortMappingDescription", desc),
            ("NewLeaseDuration", "0")]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        D.CFG = dict(D.DEFAULTS, state_dir=cls.tmp, request_log=os.path.join(cls.tmp, "r.jsonl"),
                     log_file=os.path.join(cls.tmp, "f.log"), external_ip="81.30.40.50", http_port=5000)
        D.EXTERNAL_IP = "81.30.40.50"
        D.set_version(1)
        D.UUID_ROOT = D.UUID_WAN = D.UUID_CONN = "00000000-0000-0000-0000-000000000000"
        D.ADVERTS = [("upnp:rootdevice", "uuid:%s::upnp:rootdevice" % D.UUID_ROOT), (D.S_IPC, "uuid:x::" + D.S_IPC)]
        D.NOTE.send = lambda *a, **k: None          # no ntfy
        D.mappings.clear()


class Soap(Base):
    def test_ordinary(self):
        self.assertEqual(D.parse_soap(envelope("GetExternalIPAddress", [])), ("GetExternalIPAddress", {}))

    def test_doctype_refused(self):
        xxe = '<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        lol = ('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
               '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>')
        plain = '<?xml version="1.0"?><!DOCTYPE s>'
        for pre, ent in ((xxe, "&x;"), (lol, "&d;"), (plain, "d")):
            with self.assertRaises(ValueError):
                D.parse_soap(envelope("AddPortMapping", add_args("3000", ent), pre))
        # UTF-16 does not hide it
        with self.assertRaises(ValueError):
            D.parse_soap(envelope("AddPortMapping", add_args("3000", "&d;"), lol).decode().replace(
                'version="1.0"?>', 'version="1.0" encoding="UTF-16"?>', 1).encode("utf-16"))


class Http(Base):
    """The HTTP server on 127.0.0.1, an ephemeral port."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.buf = io.StringIO()
        h = logging.StreamHandler(cls.buf)
        h.setFormatter(D.OtpFormatter())
        D.log.handlers[:] = [h]
        D.log.setLevel(logging.INFO)
        cls.srv = D.Server(("127.0.0.1", 0), D.Handler)
        D.CFG["http_port"] = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def post(self, body, action):
        s = socket.create_connection(self.srv.server_address, timeout=10)
        s.sendall(("POST /ctl/IPConn HTTP/1.1\r\nHost: x\r\nSOAPAction: \"%s#%s\"\r\nContent-Length: %d\r\n\r\n"
                   % (V1, action, len(body))).encode() + body)
        out = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
        s.close()
        return out.decode("utf-8", "replace")

    def test_billion_laughs_refused(self):
        lol = ('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
               '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
               '<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">]>')
        r = self.post(envelope("AddPortMapping", add_args("3001", "&f;"), lol), "AddPortMapping")
        self.assertIn("<errorCode>402</errorCode>", r)
        self.assertNotIn(("", 3001, "TCP"), D.mappings)
        r = self.post(envelope("AddPortMapping", add_args("3002")), "AddPortMapping")
        self.assertIn("200 OK", r)
        self.assertIn(("", 3002, "TCP"), D.mappings)

    def test_log_line_cut(self):
        self.buf.truncate(0)
        r = self.post(envelope("AddPortMapping", add_args("3003", "x" * 60000)), "AddPortMapping")
        self.assertIn("200 OK", r)
        self.assertEqual(len(D.mappings[("", 3003, "TCP")]["description"]), D.DESC_MOST)
        longest = max(len(ln) for ln in self.buf.getvalue().splitlines())
        self.assertLess(longest, 2000, "a log line of %d characters" % longest)
        with open(D.CFG["request_log"], encoding="utf-8") as f:
            self.assertTrue(all(len(json.loads(ln)["description"]) <= D.DESC_MOST for ln in f
                                if json.loads(ln).get("description")))


class AnyPort(Base):
    def test_wildcard(self):
        D.set_version(2)
        try:
            a = dict(add_args("0"))
            got = D.handle_ipc("AddAnyPortMapping", a, "127.0.0.1")
            port = got[0][1]
            self.assertTrue(1024 <= port <= 65535, got)
            self.assertIn(("", port, "TCP"), D.mappings)
            with self.assertRaises(D.UPnPError) as e:
                D.handle_ipc("AddPortMapping", dict(add_args("0")), "127.0.0.1")
            self.assertEqual(e.exception.code, 402)
        finally:
            D.set_version(1)


class Ssdp(Base):
    def handler(self):
        ss = object.__new__(D.SSDP)
        ss.joined = {"eth9": "192.0.2.2"}
        ss.seen = {}
        ss.lock = threading.Lock()
        sent = []
        ss._reply = lambda src, sport, ip, answers, loud=False: sent.append(answers)
        return ss, sent

    def search(self, eol):
        ss, sent = self.handler()
        msg = eol.join(["M-SEARCH * HTTP/1.1", "HOST: 192.0.2.2:1900", 'MAN: "ssdp:discover"', "MX: 1",
                        "ST: upnp:rootdevice"]) + eol + eol
        real = D.local_ip_for
        D.local_ip_for = lambda src: "192.0.2.2"
        try:
            ss.handle(msg.encode(), "192.0.2.50", 40000, "eth9")
        finally:
            D.local_ip_for = real
        return sent

    def test_crlf(self):
        self.assertEqual(self.search("\r\n"), [[D.ADVERTS[0]]])

    def test_lf_only(self):
        self.assertEqual(self.search("\n"), [[D.ADVERTS[0]]])


class Summary(Base):
    def test_odd_lines(self):
        with open(D.CFG["request_log"], "w", encoding="utf-8") as f:
            f.write('5\n[1]\n{"action": "AddPortMapping"}\n{"action": "AddPortMapping", "protocol": "TCP", '
                    '"external_port": "x"}\nnot json\n{"action": "AddPortMapping", "protocol": "UDP", '
                    '"external_port": 3074, "internal_client": "192.168.1.5", "time": "2026-11-20T10:00:00+01:00", '
                    '"description": "PS5"}\n')
        out = io.StringIO()
        real = sys.stdout
        sys.stdout = out
        try:
            D.summary()
        finally:
            sys.stdout = real
        self.assertIn("UDP   3074", out.getvalue())
        self.assertIn("--dports 3074 -j DNAT --to-destination 192.168.1.5", out.getvalue())


class Cli(Base):
    def test_n(self):
        import upnp
        parser, _sp = upnp.build_parser()
        self.assertEqual(parser.parse_args(["requests", "-n", "0"]).n, 0)
        self.assertEqual(parser.parse_args(["log", "-n", "7"]).n, 7)
        for cmd in ("requests", "log"):
            with self.assertRaises(SystemExit), open(os.devnull, "w") as null:
                real, sys.stderr = sys.stderr, null
                try:
                    parser.parse_args([cmd, "-n", "-2"])
                finally:
                    sys.stderr = real

    def test_odd_lines_and_times(self):
        import upnp
        path = os.path.join(self.tmp, "cli.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write('5\n[1]\n{"action": "GetStatusInfo", "time": 7}\n{"action": "AddPortMapping", "time": '
                    '"2026-11-20T10:00:00+01:00"}\n')
        ev = upnp.read_events({"request_log": path})
        self.assertEqual([e["action"] for e in ev], ["GetStatusInfo", "AddPortMapping"])
        self.assertRegex(upnp.fmt_time(1794854519.7), r"^20\d\d-\d\d-\d\d \d\d:\d\d:\d\d$")
        self.assertEqual(upnp.fmt_time("2026-11-20T10:00:00"), "2026-11-20 10:00:00")
        self.assertEqual(upnp.fmt_time(None), "-")


class OddMappings(Base):
    def test_shapes(self):
        import argparse
        import upnp
        import fake_igd_api as A
        upnp.PAL = upnp.Palette(False)
        upnp.NO_DNS = True
        st = os.path.join(self.tmp, "odd")
        os.makedirs(st, exist_ok=True)
        for raw in ('{"a": 1}', '[1, "x", null]', '{}'):
            with open(os.path.join(st, "mappings.json"), "w", encoding="utf-8") as f:
                f.write(raw)
            out = io.StringIO()
            stdout, sys.stdout = sys.stdout, out
            try:
                upnp.cmd_mappings(argparse.Namespace(json=False), {"state_dir": st})
                upnp.cmd_mappings(argparse.Namespace(json=True), {"state_dir": st})
            finally:
                sys.stdout = stdout
            self.assertIn("No active mappings", out.getvalue())
            real = A.load_cfg
            A.load_cfg = lambda force=False: {"state_dir": st}
            try:
                self.assertEqual(A.mappings_view()["mappings"], [])
            finally:
                A.load_cfg = real


class CliUpdates(unittest.TestCase):
    def test_no_run(self):
        import argparse
        import upnp
        import upnp_admin
        upnp.PAL = upnp.Palette(False)
        real = upnp_admin.api
        out = io.StringIO()
        for job, want in (({"id": None, "kind": None, "state": None, "pct": None}, None),
                          ({"kind": "update", "state": "done", "pct": 100}, "update, done 100%")):
            upnp_admin.api = lambda M, method, path, body=None, **k: {"check": {}, "job": job}
            out.seek(0)
            out.truncate()
            stdout, sys.stdout = sys.stdout, out
            try:
                upnp_admin.cmd_updates(upnp, argparse.Namespace(what=None, json=False), {})
            finally:
                sys.stdout = stdout
                upnp_admin.api = real
            self.assertNotIn("None", out.getvalue())
            if want:
                self.assertIn(want, out.getvalue())
            else:
                self.assertNotIn("the last run", out.getvalue())


class ApiWindow(unittest.TestCase):
    def test_window(self):
        import fake_igd_api as A
        self.assertEqual(A.window({"since": ["1e20"], "until": ["inf"]}), (None, None))
        self.assertEqual(A.window({"since": ["1e12"]})[0], None)
        self.assertIsNone(A.since_hours({"hours": ["1e300"]}))
        self.assertIsNotNone(A.since_hours({"hours": ["nan"]}))
        since, until = A.window({"since": ["1700000000"], "until": ["1700003600"]})
        self.assertEqual((since.timestamp(), until.timestamp()), (1700000000, 1700003600))


class DnatClash(Base):
    """1.9.9: one external port asked for by two clients - upnp dnat says so (only the first rule works)."""
    def test_clash(self):
        import upnp
        path = os.path.join(self.tmp, "clash.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for cl, port in (("192.0.2.5", 3074), ("192.0.2.10", 3074), ("192.0.2.5", 9308)):
                f.write(json.dumps({"action": "AddPortMapping", "client": cl, "internal_client": cl,
                                    "protocol": "UDP", "external_port": port, "time": "2026-11-20T10:00:00"}) + "\n")
        ev = upnp.read_events({"request_log": path})
        ports = upnp.aggregate_ports(ev)
        self.assertEqual(upnp.port_clashes(ports), {("udp", 3074): ["192.0.2.5", "192.0.2.10"]})
        parser, _sp = upnp.build_parser()
        args = parser.parse_args(["dnat", "--no-color", "--no-dns"])
        args.from_pages = True
        out, real = io.StringIO(), sys.stdout
        sys.stdout = out
        try:
            got = upnp.cmd_dnat(args, dict(upnp.DEFAULTS, request_log=path))
        finally:
            sys.stdout = real
        self.assertEqual(list(got), [("udp", 3074)])
        self.assertIn("# WARNING:   UDP 3074: 192.0.2.5, 192.0.2.10", out.getvalue())
        self.assertIn("# WARNING: UDP 3074 also asked for by 192.0.2.10", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
