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
import api_backup as BK       # noqa: E402
import api_carry as CARRY     # noqa: E402
import api_mail as AM         # noqa: E402
import api_monitor as MON     # noqa: E402
import api_ntfy as NT         # noqa: E402
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


# ---- round 2 (1.9.11): what the coordinator asked to be put right as well -------------------------
class FakeStore(object):
    def __init__(self):
        self.meta, self.events = {}, []

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

    def add_event(self, *a, **k):
        self.events.append(a)


class FakeCtx(object):
    def __init__(self, settings=None, cfg=None, body=None, store=None):
        self.store = store or FakeStore()
        self.settings, self.cfg, self._body = dict(settings or {}), dict(cfg or {}), dict(body or {})
        self.me, self.addr, self.q, self.events = {"name": "admin", "role": "fulladmin"}, "192.0.2.50", {}, []

    def setting(self, k):
        return self.settings.get(k)

    def event(self, words, level="info", kind=None):
        self.events.append((words, level))

    def body(self, most=0):
        return self._body

    def need(self, role="fulladmin"):
        return self.me


ALERTS_ON = {"alerts": True, "alerts_to": "admin@example.com", "alerts_delay_min": 0, "alerts_repeat_h": 0,
             "alerts_resolved": True, "alerts_api": True, "alerts_new_port": False, "alerts_trial": False}


class AlertsNotLost(unittest.TestCase):
    """Events (the API away ...) were marked seen before the mail went, and the "over" taken out: a mail that
    failed, or was held back, lost them for good."""

    def run_with(self, ctx, problems, ok):
        sent = []

        def send(ctx_, subject, text, page, to, kind, keys):
            sent.append(text)
            return {"ok": ok}
        with mock.patch.object(AL, "cfg_of", lambda store: dict(ALERTS_ON)), \
                mock.patch.object(AL, "problems", lambda ctx_, c=None: dict(problems)), \
                mock.patch.object(AL, "admin_url", lambda ctx_: "https://igd.example.com/admin/"), \
                mock.patch.object(AL, "send", send):
            AL.evaluate(ctx)
        return sent

    def test_an_event_waits_for_a_mail_that_goes(self):
        ctx = FakeCtx(cfg={"site_name": "lab"})
        AL.put_state(ctx.store, {"problems": {}, "log": [], "beat": time.time() - 3600})
        self.assertEqual(len(self.run_with(ctx, {}, ok=False)), 1)          # the mail with it fails
        sent = self.run_with(ctx, {}, ok=True)
        self.assertEqual(len(sent), 1)
        self.assertIn("The pages' API was away", sent[0])
        self.assertEqual(self.run_with(ctx, {}, ok=True), [])               # and once only

    def test_over_waits_for_a_mail_that_goes(self):
        ctx = FakeCtx(cfg={"site_name": "lab"})
        AL.put_state(ctx.store, {"problems": {"disk:/": {"key": "disk:/", "level": "warn", "title": "/ is filling up",
                                                         "said": "90 % full.", "pane": "disks", "sent": True,
                                                         "since": time.time() - 600}},
                                 "log": [], "beat": time.time()})
        self.run_with(ctx, {}, ok=False)
        sent = self.run_with(ctx, {}, ok=True)
        self.assertEqual(len(sent), 1)
        self.assertIn("/ is filling up", sent[0])


class OneAlertForOneProblem(unittest.TestCase):
    """backup:<time of the run> and newer:<version>: a new alert and an "over" mail every time the value changed."""

    def test_failed_backups_are_one_alert(self):
        ctx = FakeCtx()
        values = {"db_copy_daily": False, "rbackup": True, "rbackup_every": "daily"}
        keys = []
        for at, why in ((time.time() - 7200, "no room"), (time.time() - 60, "the server did not answer")):
            with mock.patch("igd_panes.value", lambda store, k: values.get(k)), \
                    mock.patch.object(BK, "runs", lambda ctx_: [{"at": at, "ok": False, "error": why}]), \
                    mock.patch.object(BK, "targets", lambda ctx_: []):
                got = AL.backup_problems(ctx)
            keys.append(sorted(got))
            self.assertIn(why, got["backup:failed"]["said"])
        self.assertEqual(keys[0], keys[1])

    def test_a_key_kept_from_before_is_the_same_problem(self):
        ctx = FakeCtx(cfg={"site_name": "lab"})
        AL.put_state(ctx.store, {"problems": {"newer:1.9.11": {"key": "newer:1.9.11", "level": "warn", "sent": True,
                                                               "title": "fake-igd 1.9.11 is out", "said": "",
                                                               "since": time.time() - 86400}},
                                 "log": [], "beat": time.time()})
        sent = AlertsNotLost.run_with(None, ctx, {"newer": {"level": "warn", "title": "fake-igd 1.9.12 is out",
                                                            "said": "", "pane": "upgrade"}}, ok=True)
        self.assertEqual(sent, [])                                          # not "over" + new again
        self.assertTrue(AL.state(ctx.store)["problems"]["newer"]["sent"])


class ScheduledBackupStopped(unittest.TestCase):
    """A scheduled backup that stopped before it began (no destination, no password, no room) left no run:
    the alert said only, 36 hours later, that none went in time."""

    def test_it_is_a_failed_run_with_its_reason(self):
        ctx = FakeCtx(settings={"rbackup": True})
        with self.assertRaises(BK.RbError):
            BK.run(ctx, "")
        rows = BK.runs(ctx)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ok"])
        self.assertIn("no destination", rows[0]["error"])


class WeeklyCaughtUp(unittest.TestCase):
    """A weekly backup or report whose day went by while the API was away waited for the next week."""

    def test_the_backup(self):
        now = time.time()
        today = time.localtime(now).tm_wday + 1
        ctx = FakeCtx(settings={"rbackup": True, "rbackup_at": "00:00", "rbackup_every": "weekly",
                                "rbackup_day": today % 7 + 1})                 # tomorrow: not today
        ctx.store.set_meta("backup:day", time.strftime("%Y-%m-%d", time.localtime(now - 10 * 86400)))
        started = []
        with mock.patch.object(BK, "seal_old", lambda ctx_: None), \
                mock.patch.object(BK, "start_job", lambda *a: started.append(a)):
            BK.background(ctx)
        self.assertEqual(len(started), 1)
        ctx.store.set_meta("backup:day", time.strftime("%Y-%m-%d", time.localtime(now - 86400)))
        started[:] = []
        with mock.patch.object(BK, "seal_old", lambda ctx_: None), \
                mock.patch.object(BK, "start_job", lambda *a: started.append(a)):
            BK.background(ctx)
        self.assertEqual(started, [])                                       # made on its day: nothing to catch up

    def test_the_report(self):
        c = {"report": True, "report_every": "weekly", "report_day": "5", "report_at": "07:30"}
        wed = time.mktime((2026, 11, 18, 12, 0, 0, 0, 0, -1))                # a Wednesday; its day is Friday
        last_week = AL.period(c, wed - 7 * 86400)
        self.assertEqual(AL.report_due(c, AL.period(c, wed - 14 * 86400)[2], wed), last_week)
        self.assertIsNone(AL.report_due(c, last_week[2], wed))


class ReportTriedAgain(unittest.TestCase):
    """report:sent was set before the report was made: one that failed to be made was never tried again."""

    def test_marked_sent_once_it_went(self):
        ctx = FakeCtx(cfg={"site_name": "lab"})
        c = {"report": True, "report_to": "admin@example.com", "report_every": "daily", "report_at": "00:00"}
        calls = []

        def build(ctx_, since, until):
            calls.append(since)
            if len(calls) == 1:
                raise OSError("the request log cannot be read")
            return "subject", "text", "<p>page</p>"
        with mock.patch.object(AL, "report_build", build), \
                mock.patch.object(AL, "send", lambda *a: {"ok": True}):
            try:
                AL.report_tick(ctx, c)
            except OSError:
                pass
            self.assertNotEqual(ctx.store.get_meta("report:sent"), AL.period(c)[2])
            tries = ctx.store.meta_json("report:tries") or {}
            tries["at"] = time.time() - 3600
            ctx.store.set_meta("report:tries", json.dumps(tries))
            AL.report_tick(ctx, c)
        self.assertEqual(len(calls), 2)
        self.assertEqual(ctx.store.get_meta("report:sent"), AL.period(c)[2])


class NtfyOverWaits(unittest.TestCase):
    """ntfy said "over" the first minute a problem was missing; the mail and the traps wait alerts_delay_min."""

    def test_over_waits_as_the_mail_does(self):
        ctx = FakeCtx(cfg={"ntfy_url": "https://ntfy.example.com/igd",
                           "ntfy_events": {"alerts": {"on": True}, "alerts_over": {"on": True}}})
        ctx.store.set_meta("ntfy:alerts", json.dumps({"disk:/": {"since": time.time() - 3600, "sent": True,
                                                                "title": "/ is filling up", "said": "90 %"}}))
        said = []
        with mock.patch.object(AL, "cfg_of", lambda store: {"alerts_delay_min": 5}), \
                mock.patch.object(AL, "problems", lambda ctx_, c=None: {}), \
                mock.patch.object(NT.NOTE, "send", lambda kind, *a, **k: said.append(kind)):
            NT._alerts(ctx, time.time())
            self.assertEqual(said, [])
            self.assertIn("disk:/", json.loads(ctx.store.get_meta("ntfy:alerts")))
            NT._alerts(ctx, time.time() + 6 * 60)
        self.assertEqual(said, ["alerts_over"])


class TestMailOutcome(MailHeaders):
    """A mail sent and waited for (the test mail, the alerts) was "sent" whenever another try had it."""
    test_a_name_with_a_new_line_still_sends = test_the_setting_refuses_a_new_line = None     # MailHeaders' own

    def test_the_tick_leaves_it_to_its_sender(self):
        qid = M.send(self.S, ["admin@example.com"], "a test", "text", kind="test", now=False)
        M.tick(self.S)
        self.assertEqual(M.one(self.S, qid)["state"], "waiting")
        self.assertEqual(self.sink.mails, [])

    def test_not_tried_here_is_not_sent(self):
        def taken(store, qid, raise_err=False):
            store.run("UPDATE mailq SET state = 'failed', said = 'refused for good' WHERE qid = ?", (qid,))
            return None
        with mock.patch.object(M, "attempt", taken):
            got = M.send_and_wait(self.S, ["admin@example.com"], "a test", "text", kind="test")
        self.assertFalse(got["sent"])
        self.assertEqual(got["said"], "refused for good")


class SnmpAlertRows(unittest.TestCase):
    """fakeIgdAlertTable was indexed by the row's number: another alert sorted before it moved every row, and
    Zabbix read a neighbour's level; its item keys held the raw key (a , or ] breaks one)."""

    def rows(self, probs):
        MON.AGENT["problems"], MON.AGENT["problems_at"] = probs, time.time()
        got = {}
        for oid, kind, v in MON._mib_alerts(FakeCtx(), MON.SNMP_BASE):
            if oid[len(MON.SNMP_BASE):len(MON.SNMP_BASE) + 4] == (5, 3, 1, 2):
                got[v] = oid[-1]
        return got

    def test_the_index_stays(self):
        one = {"service": {"level": "bad", "title": "t", "said": ""}}
        before = self.rows(one)["service"]
        after = self.rows(dict(one, **{"disk:/": {"level": "warn", "title": "d", "said": ""}}))
        self.assertEqual(after["service"], before)
        self.assertNotEqual(after["disk:/"], before)

    def test_zabbix_items_keyed_by_the_index(self):
        with open(os.path.join(ROOT, "deploy", "zabbix", "fake_igd_by_snmp_zabbix7.yaml"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotRegex(text, r"(key: |/)fakeigd\.alert\.\w+\[\{#KEY\}\]")
        self.assertIn("key: fakeigd.alert.level[{#SNMPINDEX}]", text)
        self.assertIn("1.3.6.1.4.1.8072.9999.9999.8.5.3.1.3.{#SNMPINDEX}", text)
        self.assertEqual(".".join(str(x) for x in MON.SNMP_BASE), "1.3.6.1.4.1.8072.9999.9999.8")


class ImportCount(unittest.TestCase):
    """The import said "3 account(s)" for a file with your own account and one left out in it."""

    def test_only_the_accounts_taken(self):
        d = tempfile.mkdtemp(dir=TMP)
        store = ST.Store(os.path.join(d, "fake-igd.db"))
        store.add_user("admin", "a long password 1", "fulladmin")
        conf = {"kind": CARRY.KIND, "users": [{"name": "admin", "role": "fulladmin"},
                                              {"name": "not a name!", "role": "readonly"},
                                              {"name": "bob", "role": "readonly"}]}
        ctx = FakeCtx(store=store, body={"config": conf})
        with mock.patch.object(CARRY, "import_conf", lambda *a: {"saved": []}), \
                mock.patch.object(CARRY, "import_targets", lambda *a: 0), \
                mock.patch.object(CARRY, "import_system", lambda *a: []):
            got = CARRY.post_import(ctx)
        self.assertIn("1 account(s)", got["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
