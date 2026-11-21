#!/usr/bin/env python3
"""test_ops.py - mail, alerts, monitoring and upgrades: what 1.9.11 put right.

  python3 test/ops/test_ops.py

Each test fails on 1.9.10 and passes now. No root, no network but 127.0.0.1 (a mail sink of its own);
documentation addresses and example.com only.
"""
import json
import os
import secrets
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "deploy")]
TMP = tempfile.mkdtemp(prefix="fake-igd-ops-")
os.environ.setdefault("FAKE_IGD_STATE", TMP)
os.environ.setdefault("FAKE_IGD_LIB", os.path.join(TMP, "lib"))

import api_alerts as AL       # noqa: E402
import api_mail as AM         # noqa: E402
import api_monitor as MON     # noqa: E402
import api_siem as SI         # noqa: E402
import igd_mail as M          # noqa: E402
import igd_online as ON       # noqa: E402
import igd_snmp as SN         # noqa: E402
import igd_store as ST        # noqa: E402


def setting(settings, key):
    return [s for s in settings if s["key"] == key][0]


# ---- a mail sink on 127.0.0.1 --------------------------------------------------------------------
class Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.mails = []
        socketserver.ThreadingTCPServer.__init__(self, ("127.0.0.1", 0), SinkTalk)


class SinkTalk(socketserver.StreamRequestHandler):
    def handle(self):
        def say(words):
            self.wfile.write((words + "\r\n").encode())
            self.wfile.flush()
        say("220 sink.example.com ESMTP")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode("utf-8", "replace").strip().upper()
            if cmd.startswith("EHLO"):
                say("250-sink.example.com")
                say("250 8BITMIME")
            elif cmd == "DATA":
                say("354 go on")
                data = b""
                while True:
                    ln = self.rfile.readline()
                    if ln in (b".\r\n", b""):
                        break
                    data += ln
                self.server.mails.append(data)
                say("250 queued")
            elif cmd == "QUIT":
                say("221 bye")
                return
            else:
                say("250 ok")


class MailHeaders(unittest.TestCase):
    """A From name saved with a new line in it: every mail - alerts, report, test - failed with the email
    package's "Header values may not contain linefeed"; now the name is one line and a new one is refused."""

    def setUp(self):
        self.sink = Sink()
        threading.Thread(target=self.sink.serve_forever, daemon=True).start()
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.S = ST.Store(os.path.join(self.dir, "fake-igd.db"))
        self.S.set_meta("settings", json.dumps({
            "mail_mode": "smtp", "smtp_host": "127.0.0.1", "smtp_port": self.sink.server_address[1],
            "smtp_security": "none", "smtp_auth": "none", "mail_from": "igd@example.com",
            "mail_from_name": "Fake IGD\r\nBcc: someone@example.com", "smtp_timeout_s": 5}))

    def tearDown(self):
        self.sink.shutdown()
        self.sink.server_close()

    def test_a_name_with_a_new_line_still_sends(self):
        got = M.send_and_wait(self.S, ["admin@example.com"], "line one\nline two", "the text", kind="test")
        self.assertTrue(got["sent"], got)
        raw = self.sink.mails[-1].decode("utf-8", "replace")
        head = raw.split("\r\n\r\n", 1)[0]
        self.assertNotIn("\r\nBcc:", head)
        self.assertIn("From: Fake IGD Bcc: someone@example.com <igd@example.com>", head.replace('"', ""))
        self.assertIn("Subject: line one line two", head)

    def test_the_setting_refuses_a_new_line(self):
        check = setting(AM.SETTINGS, "mail_from_name").get("check")
        self.assertIsNotNone(check)
        self.assertTrue(check("Fake\nBcc: x@example.com"))
        self.assertEqual(check("Fake IGD - Brno"), "")


class UpgradeBusy(unittest.TestCase):
    """request.taken left by a run that never ended (the machine restarted under it) kept the pages "busy"
    for good: no upgrade could be asked for, and the alert of fake-igd.service down was held back."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.was = ON.UPGRADE_DIR
        ON.UPGRADE_DIR = self.dir

    def tearDown(self):
        ON.UPGRADE_DIR = self.was

    def _write(self, name, data):
        with open(os.path.join(self.dir, name), "w") as f:
            f.write(json.dumps(data) if data is not None else "")

    def test_a_taken_request_left_behind_is_not_busy_for_ever(self):
        now = time.time()
        self._write("status.json", {"state": "running", "id": "1-ab", "version": "1.9.11", "at": now})
        self._write("request.taken", None)
        self.assertTrue(ON.status()["busy"])                        # while root is at it: busy
        later = type("T", (), {"time": staticmethod(lambda: now + 3 * 3600)})
        with mock.patch.object(ON, "time", later):
            st = ON.status()
        self.assertFalse(st["busy"], st)
        self.assertEqual(st["state"], "failed")


class AlertWords(unittest.TestCase):
    """"it lasted just now" in the Over section of an alert mail (and "never" with no start)."""

    class Ctx(object):
        cfg = {"site_name": "lab"}
        me = None
        store = None

    def test_how_long_it_lasted(self):
        with mock.patch.object(AL, "admin_url", lambda ctx: "https://igd.example.com/admin/"):
            gone = [{"key": "disk:/", "level": "warn", "title": "/ is filling up", "said": "90 % full.",
                     "pane": "disks", "since": time.time() - 40}]
            subject, text, page = AL.alert_mail(self.Ctx(), [], [], gone, [])
        self.assertNotIn("just now", text)
        self.assertNotIn("just now", page)
        self.assertRegex(text, r"\(it lasted 4\d s\)")


class MetricsToken(unittest.TestCase):
    """A token typed shorter than 24 characters, or with a space, was saved - and web/metrics.php never hands
    such a one on: Prometheus got a 401 for ever."""

    def test_only_a_token_metrics_php_takes(self):
        check = setting(MON.SETTINGS, "metrics_token").get("check")
        self.assertIsNotNone(check)
        self.assertTrue(check("short-token"))
        self.assertTrue(check("a token with spaces in it, long enough"))
        self.assertEqual(check(secrets.token_urlsafe(32)), "")


class SyslogHost(unittest.TestCase):
    """RFC 5424's HOSTNAME is printable US-ASCII: a name with a Czech letter made a line syslog servers
    do not parse."""

    def test_hostname_is_ascii(self):
        line = SI.frame({"siem_hostname": "Brno-sklep-č", "siem_format": "json"}, "event", 6, {}, "a test",
                        at=1700000000)
        host = line.split(" ")[2]
        self.assertEqual(host, "Brno-sklep-_")
        host.encode("ascii")


class SnmpDisplayString(unittest.TestCase):
    """A DisplayString is 255 octets at most: 255 characters with an arrow in them were more."""

    def test_at_most_255_octets(self):
        raw = SN.snmp_value("str", "→" * 200)
        tag, start, end = SN.ber_read(raw, 0)
        self.assertEqual(tag, 4)
        self.assertLessEqual(end - start, 255)
        raw[start:end].decode("utf-8")                              # cut between characters, never in one
        self.assertEqual(SN.snmp_value("str", b"\x80" * 300)[-300:], b"\x80" * 300)     # bytes: as they are


if __name__ == "__main__":
    unittest.main(verbosity=2)
