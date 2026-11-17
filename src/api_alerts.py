"""api_alerts.py - Settings → Alerts and reports (1.6.0), as otp's.

A mail when something is wrong - and again when it is over; and a report of the period
(the week, or the day, or the month): the ports asked for, the devices, the events. Both
off until switched on; both go through igd_mail (Settings → Mail).

What the alerts look at, every minute (each switched on or off by itself):
  fake-igd.service down · avahi-daemon down (where it is installed and enabled) ·
  another UPnP router on the network · a new version of fake-igd out · a disk filling ·
  the pages' certificate running out · an upgrade that failed · mail that does not go ·
  system updates waiting or a restart needed (as System updates last found them) · a clock that
  is off · an address or name held back for guessing (off by default) · a certificate the ACME
  CA did not renew
and, as they happen: the pages' API was away (seen when it is back - nothing on this
machine can mail while it is away) · a new port asked for (off by default) · a change on
trial (the network, the firewall, the SSH server) that went back by itself.

State in the database: meta "alerts:state" (what is wrong and since when, what was mailed,
the mails sent), "report:sent" (the last period whose report went).
"""
import collections
import html
import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timedelta

NAME = "alerts"
STATE_KEY = "alerts:state"
LOCK = threading.Lock()
API_AWAY_S = 180
AL_FONT = "font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
AL_COLORS = {"bad": ("#dc2626", "#fef2f2", "#991b1b"), "warn": ("#d97706", "#fffbeb", "#92400e"),
             "good": ("#16a34a", "#f0fdf4", "#166534"), "info": ("#2563eb", "#eff6ff", "#1e3a8a")}


def _addrs(v):
    import igd_mail as M
    try:
        M.addresses(v)
    except ValueError as e:
        return str(e)
    return ""


def _url(v):
    v = str(v or "").strip()
    if v and not re.match(r'^https?://[^\s"<>]+\Z', v):
        return "an address starting https://"
    return ""


def _hhmm(v):
    try:
        hh, mm = v.split(":")
        if 0 <= int(hh) <= 23 and 0 <= int(mm) <= 59 and len(mm) == 2:
            return ""
    except ValueError:
        pass
    return "HH:MM, e.g. 07:30"


ON = ("alerts", True)
SETTINGS = [
    {"key": "alerts", "name": "Alerts by mail", "kind": "bool", "default": False,
     "says": "A mail when something is wrong - fake-igd.service, the pages' API, avahi-daemon, another UPnP "
             "router, a backup, a disk, the certificate, the syslog servers, an upgrade - and when it is over. "
             "Off until switched on."},
    {"key": "alerts_to", "name": "Send them to", "kind": "text", "default": "", "check": _addrs, "most": 1000,
     "only_when": ON, "says": "Addresses, separated by commas. The mail goes the way Settings → Mail says."},
    {"key": "alerts_delay_min", "name": "Only once it has lasted (min)", "kind": "int", "default": 5, "min": 0,
     "max": 120, "only_when": ON,
     "says": "A problem shorter than this is not mailed - a service restarted by an upgrade is back in a few "
             "seconds. 0: at once."},
    {"key": "alerts_repeat_h", "name": "Remind every (hours)", "kind": "int", "default": 24, "min": 0, "max": 168,
     "only_when": ON, "says": "While it lasts, said again this often at most. 0: once only."},
    {"key": "alerts_resolved", "name": "Say when it is over", "kind": "bool", "default": True, "only_when": ON,
     "says": "A mail when what was mailed is over."},
    {"key": "alerts_service", "name": "fake-igd.service down", "kind": "bool", "default": True, "only_when": ON,
     "says": "The UPnP service is not running: nothing on the network is answered."},
    {"key": "alerts_api", "name": "The pages' API was away", "kind": "bool", "default": True, "only_when": ON,
     "says": "fake-igd-api was not running for more than three minutes. Said when it is back - while it is away, "
             "nothing here can send mail; Prometheus (Monitoring) sees it at once."},
    {"key": "alerts_avahi", "name": "avahi-daemon down", "kind": "bool", "default": True, "only_when": ON,
     "says": "The mDNS reflector is enabled but not running (only where avahi-daemon is installed)."},
    {"key": "alerts_other_igd", "name": "Another UPnP router on the network", "kind": "bool", "default": True,
     "only_when": ON, "says": "Something else answers as a UPnP router - the PS5 may ask it instead."},
    {"key": "alerts_new_port", "name": "A new port asked for", "kind": "bool", "default": False, "only_when": ON,
     "says": "A device asked for a port (AddPortMapping) it never asked for before - said as it happens."},
    {"key": "alerts_backup", "name": "A backup that failed or did not come", "kind": "bool", "default": True,
     "only_when": ON, "says": "A nightly copy older than 36 hours; a backup to the destinations that failed, or "
                              "none that went in time."},
    {"key": "alerts_logs", "name": "Logs not reaching the syslog servers", "kind": "bool", "default": True,
     "only_when": ON, "says": "Sending to the syslog servers (SIEM) failing - not reached, refused."},
    {"key": "alerts_snmp", "name": "The SNMP agent not listening", "kind": "bool", "default": True,
     "only_when": ON, "says": "SNMPv3 switched on and its agent not listening (the port taken, refused), "
                              "or its traps not going out."},
    {"key": "alerts_newer", "name": "A new version is out", "kind": "bool", "default": True, "only_when": ON,
     "says": "A newer fake-igd at the address of Upgrades (looked for every day, when that is on)."},
    {"key": "alerts_disk_pct", "name": "A disk fuller than (%)", "kind": "int", "default": 85, "min": 0, "max": 99,
     "only_when": ON, "says": "A file system fake-igd lives on (/, its state, its logs) fuller than this. 0: never."},
    {"key": "alerts_cert_days", "name": "A certificate running out within (days)", "kind": "int", "default": 21,
     "min": 0, "max": 120, "only_when": ON,
     "says": "The certificate of these pages (nginx) running out within so many days. 0: never."},
    {"key": "alerts_gateway", "name": "The gateway for devices not forwarding", "kind": "bool", "default": True,
     "only_when": ON, "says": "The gateway for devices is on, but net.ipv4.ip_forward was turned off by something "
                              "else, or fake-igd's chain is no longer first in FORWARD (Settings → Gateway for devices)."},
    {"key": "alerts_mikrotik", "name": "A port asked for not open on the MikroTik", "kind": "bool", "default": False,
     "only_when": ON, "says": "Settings → MikroTik reads the real router: a port a device asked for that the MikroTik does "
                              "not carry (no dst-nat, shadowed, disabled, dropped by the filter), the MikroTik that "
                              "cannot be read, or its own UPnP switched on. Off by default."},
    {"key": "alerts_upgrade", "name": "An upgrade that failed", "kind": "bool", "default": True, "only_when": ON,
     "says": "An upgrade of fake-igd (Settings → Upgrades) that failed, or never said that it ended."},
    {"key": "alerts_mailq", "name": "Mails that do not go", "kind": "bool", "default": True, "only_when": ON,
     "says": "Mails refused for good or given up in the outgoing mail in the last day (Settings → Outgoing mail)."},
    {"key": "alerts_updates", "name": "System updates and a restart waiting", "kind": "bool", "default": False,
     "only_when": ON, "says": "Security updates waiting, or a restart an update left - as System updates last "
                              "found them."},
    {"key": "alerts_time", "name": "A clock that is off", "kind": "bool", "default": True, "only_when": ON,
     "says": "chrony out of sync, or the clock off by more than half a second - the times of the requests, "
             "the log and the certificates are read from it."},
    {"key": "alerts_guard", "name": "A source blocked for guessing", "kind": "bool", "default": False,
     "only_when": ON, "says": "Each address or name held back by wrong passwords at the sign-in to these pages, "
                              "as it is held back (Settings → Accounts)."},
    {"key": "alerts_acme", "name": "A certificate the CA did not renew", "kind": "bool", "default": True,
     "only_when": ON, "says": "ACME ordered a certificate and none came - said at once, not only once it is about "
                              "to run out."},
    {"key": "alerts_trial", "name": "A change on trial that went back", "kind": "bool", "default": True,
     "only_when": ON, "says": "A change of the network, the firewall or the SSH server on trial that was not kept "
                              "and went back by itself - whoever made it may have lost the way in."},
    {"key": "alerts_selinux", "name": "SELinux refusing", "kind": "bool", "default": False, "only_when": ON,
     "says": "The SELinux card (Settings → SELinux) finds something not as fake-igd needs it - a refusal, a "
             "label, a boolean, the module."},
    {"key": "alerts_url", "name": "The administration\u2019s address in the mails", "kind": "text", "default": "",
     "check": _url, "most": 300,
     "says": "Where the links in the mails lead, <code>https://fake-igd.example.cz/admin/</code>. "
             "Empty: this machine\u2019s name."},
    {"key": "report", "name": "A report by mail", "kind": "bool", "default": False,
     "says": "A report of the period by mail: the ports asked for, by whom and what they were answered, the "
             "devices, the events worth a look and what is wrong now."},
    {"key": "report_to", "name": "Send it to", "kind": "text", "default": "", "check": _addrs, "most": 1000,
     "only_when": ("report", True), "says": "Addresses, separated by commas. Empty: the ones the alerts go to."},
    {"key": "report_every", "name": "How often", "kind": "choice", "default": "weekly",
     "only_when": ("report", True),
     "choices": [("daily", "every day, of the day before"), ("weekly", "every week, of the week before"),
                 ("monthly", "every month, of the month before")],
     "says": "A day, a week (Monday to Sunday) or a month - the one that has just ended."},
    {"key": "report_day", "name": "On the day", "kind": "choice", "default": "1",
     "only_when": ("report_every", "weekly"),
     "choices": [("1", "Monday"), ("2", "Tuesday"), ("3", "Wednesday"), ("4", "Thursday"), ("5", "Friday"),
                 ("6", "Saturday"), ("7", "Sunday")],
     "says": "The day a weekly report goes."},
    {"key": "report_at", "name": "At", "kind": "text", "default": "07:30", "check": _hhmm,
     "only_when": ("report", True), "says": "When, as <code>HH:MM</code> on this machine’s clock."},
]


def cfg_of(store):
    import igd_panes as PN
    return {s["key"]: PN.value(store, s["key"]) for s in SETTINGS}


def _to(c, key="alerts_to"):
    import igd_mail as M
    try:
        got = M.addresses(c.get(key) or "")
    except ValueError:
        got = []
    if not got and key == "report_to":
        return _to(c)
    return got


def _h(t):
    return html.escape(str(t if t is not None else ""), quote=True)


def _site(ctx):
    return str(ctx.cfg.get("site_name") or socket.gethostname())


def state(store):
    st = store.meta_json(STATE_KEY) or {}
    if not isinstance(st.get("problems"), dict):
        st["problems"] = {}
    if not isinstance(st.get("log"), list):
        st["log"] = []
    return st


def put_state(store, st):
    store.set_meta(STATE_KEY, json.dumps(st, default=str))


# ---- what is wrong now -------------------------------------------------------------------
def problems(ctx, c=None):
    """{key: {level, title, said, pane}} - what is wrong now, of what is switched on."""
    import upnp as U
    c = c or cfg_of(ctx.store)
    out = {}
    mon = __import__("api_monitor")
    if c.get("alerts_service") or c.get("alerts_avahi"):
        units = mon.unit_states()
        st = units.get("fake-igd.service")
        import igd_online as UPG_ON
        if c.get("alerts_service") and st != "active" and not UPG_ON.status().get("busy"):
            out["service"] = {"level": "bad", "title": "fake-igd.service is %s" % st, "pane": "service",
                              "said": "Nothing on the network is answered - Settings → The service, or sudo upnp start."}
        av = units.get("avahi-daemon.service")
        if c.get("alerts_avahi") and av is not None and av != "active":
            try:
                import upnp_mdns as MD
                enabled = MD.systemd_state("avahi-daemon").get("UnitFileState") == "enabled"
            except Exception:                           # noqa: BLE001
                enabled = False
            if enabled:
                out["avahi"] = {"level": "warn", "title": "avahi-daemon is %s" % av, "pane": "mdns",
                                "said": "The mDNS reflector is enabled but not running: the devices of one network "
                                        "do not see those of the other."}
    if c.get("alerts_other_igd"):
        try:
            for o in U.status_data(ctx.cfg).get("other_igd") or []:
                out["other:%s" % o] = {"level": "warn", "title": "Another UPnP router: %s" % o, "pane": "network",
                                       "said": "%s answers as a UPnP router - switch UPnP off on it, or the PS5 may "
                                               "ask it instead." % o}
        except (SystemExit, Exception):                # noqa: BLE001
            pass
    if c.get("alerts_newer"):
        try:
            import igd_online as ON
            row = ON.view(ctx.store.meta_json("upgrade:online") or {}, U.VERSION)
            if row.get("newer"):
                v = (row.get("newest") or {}).get("version")
                out["newer:%s" % v] = {"level": "warn", "title": "fake-igd %s is out" % v, "pane": "upgrade",
                                       "said": "This is %s; %s is at %s." % (U.VERSION, v, row.get("url"))}
        except Exception:                               # noqa: BLE001
            pass
    pct = int(c.get("alerts_disk_pct") or 0)
    if pct:
        for d in mon.disks(ctx.cfg):
            if d["pct"] >= pct:
                out["disk:%s" % d["path"]] = {
                    "level": "bad" if d["pct"] >= 95 else "warn", "title": "%s is filling up" % d["path"],
                    "pane": "disks", "said": "%.1f %% full - %s free of %s." % (d["pct"], _bytes(d["free"]),
                                                                              _bytes(d["total"]))}
    days = int(c.get("alerts_cert_days") or 0)
    if days:
        crt = mon.certificate()
        if crt.get("until") is not None and crt["days"] < days:
            out["cert"] = {"level": "bad" if crt["days"] < 3 else "warn",
                           "title": "The pages' certificate %s" % ("has run out" if crt["days"] < 0 else
                                                                 "runs out in %d day(s)" % int(crt["days"])),
                           "pane": "tls", "said": "%s (%s) is good until %s." % (
                               crt["file"], crt.get("subject") or "?",
                               time.strftime("%Y-%m-%d %H:%M", time.localtime(crt["until"])))}
    if c.get("alerts_gateway"):
        try:
            gw = __import__("api_gateway").problem(ctx)
        except Exception:                               # noqa: BLE001
            gw = ""
        if gw:
            out["gateway"] = {"level": "bad", "title": "The gateway for devices does not forward", "pane": "gateway",
                              "said": gw}
    if c.get("alerts_mikrotik"):
        try:
            out.update(__import__("api_mikrotik").problems(ctx))
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_upgrade"):
        try:
            import igd_online as ON
            up = ON.status()
            if up.get("state") == "failed":
                out["upgrade:%s" % (up.get("id") or up.get("at") or "")] = {
                    "level": "bad", "title": "An upgrade to fake-igd %s failed" % (up.get("version") or "?"),
                    "pane": "upgrade", "said": str(up.get("said") or "see Settings → Upgrades - its log")}
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_mailq"):
        try:
            import igd_mail as M
            M.ready(ctx.store)
            n = ctx.store.one("SELECT COUNT(*) AS n FROM mailq WHERE state IN ('failed', 'expired') AND "
                              "COALESCE(last_try, created) > ?", (time.time() - 86400,))["n"]
            if n:
                out["mailq"] = {"level": "warn", "title": "%d mail(s) did not go" % n, "pane": "mailq",
                                "said": "Refused for good or given up in the last day - Settings → Outgoing mail says why."}
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_backup"):
        try:
            out.update(backup_problems(ctx))
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_logs"):
        try:
            si = __import__("api_siem")
            if si._settings(ctx).get("siem"):
                for k, why in (si.state(ctx.store).get("trouble") or {}).items():
                    out["siem:%s" % k] = {"level": "warn", "title": "Logs not reaching %s" % k, "pane": "siem",
                                          "said": str(why)[:300]}
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_updates"):
        osup = ctx.store.meta_json("osup:check") or {}
        if osup.get("reboot_now") or osup.get("reboot"):
            out["reboot"] = {"level": "warn", "title": "A restart is needed", "pane": "osup",
                             "said": "An update put in something only a restart brings into use."}
        if osup.get("security"):
            out["updates"] = {"level": "warn", "title": "%d security update(s) waiting" % osup["security"],
                              "pane": "osup", "said": "As System updates found them %s." % _ago(osup.get("at"))}
    if c.get("alerts_time", True):
        try:
            out.update(time_problems())
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_guard"):
        try:
            for r in ctx.store.lockouts():
                if r.get("locked"):
                    who = str(r.get("who") or "?")
                    pw = str(r.get("kind") or "").startswith("password")
                    out["guard:%s:%s:%s" % (r.get("kind"), r.get("by"), who)] = {
                        "level": "warn", "title": "%s %s is held back for guessing" % (
                            "The name" if r.get("by") == "name" else "The address", who), "pane": "people",
                        "said": "%d %s, %s - no %s %s until %s. Settings → Accounts lets it in again." % (
                            int(r.get("fails") or 0), r.get("words") or "wrong passwords", r.get("what") or "",
                            "change of the password" if pw else "sign-in", "by this name" if r.get("by") == "name" else "from it", _when(r.get("until")))}
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_acme", True):
        try:
            import igd_panes as PN
            if PN.value(ctx.store, "acme"):
                st = __import__("api_acme").state(ctx.store)
                if st.get("ok") is False and time.time() - float(st.get("failed_at") or 0) <= 14 * 86400:
                    out["acme"] = {"level": "warn", "title": "The CA did not renew the certificate", "pane": "acme",
                                   "said": str(st.get("said") or "see Settings → Automatic certificates")[:300]}
        except Exception:                               # noqa: BLE001
            pass
    # SELinux (off by default, as otp's alerts_selinux).
    if c.get("alerts_selinux"):
        try:
            import api_selinux as SEL
            probs = [p for p in SEL.problems(ctx.store) if "ready for enforcing" not in p]
            if probs:
                n = SEL.node_name()
                # The card's words say how many can be put right there (Put in what is selected).
                out["selinux:" + n] = {"level": "warn", "title": "SELinux on %s: something is not as fake-igd needs it"
                                       % n, "pane": "selinux", "said": "; ".join(probs)[:300]}
        except Exception:                               # noqa: BLE001
            pass
    if c.get("alerts_snmp", True):
        try:
            mon = __import__("api_monitor")
            if mon._setting(ctx.store, "snmp"):
                sn = mon.snmp_view(ctx).get("agent") or {}
                if sn and "listening" in sn and not sn.get("listening"):
                    out["snmp"] = {"level": "warn", "title": "The SNMP agent is not listening", "pane": "monitor",
                                   "said": str(sn.get("error") or "Its port could not be opened.")[:300]}
                elif sn.get("trap_error") and mon._setting(ctx.store, "snmp_traps"):
                    out["snmp:trap"] = {"level": "warn", "title": "SNMP traps do not go", "pane": "monitor",
                                        "said": str(sn["trap_error"])[:300]}
        except Exception:                               # noqa: BLE001
            pass
    return out


def time_problems():
    """otp's: chrony out of sync, or the clock off by more than half a second; without chrony,
    what timedatectl says."""
    t = __import__("api_time").read()
    tr = t.get("tracking") or {}
    if not t.get("chrony") or not tr:
        if t.get("ntp") == "yes" and t.get("ntpsynchronized") == "no":
            return {"time": {"level": "bad", "title": "The clock is off", "pane": "time",
                             "said": "The clock is not synchronised (timedatectl: NTPSynchronized=no)."}}
        return {}
    try:
        off = abs(float(tr.get("offset") or 0))
    except (TypeError, ValueError):
        off = 0.0
    unsynced = str(tr.get("leap") or "").lower().startswith("not")
    if not unsynced and off <= 0.5:
        return {}
    return {"time": {"level": "bad" if off > 5 or unsynced else "warn", "title": "The clock is off", "pane": "time",
                     "said": "chrony %s, off by %.2f s - the times of the requests and the log are read from the "
                             "clock." % ("is not in sync" if unsynced else "OK", off)}}


def trials_back(ctx, st):
    """Changes on trial that went back by themselves since the last look (otp's alerts_trial events):
    the network (root_net's trial file), the firewall (root_fw's), the SSH server (root's answer)."""
    import igd_panes as PN
    found = []
    try:
        t = __import__("api_net").trial(ctx)
        if t.get("state") == "back" and t.get("why") == "not kept in time":
            found.append(("net:%s" % t.get("snapshot"), "net",
                          "The new network of %s was not kept in time and went back to the one it had before."
                          % (t.get("con") or "?")))
    except Exception:                                   # noqa: BLE001
        pass
    try:
        t = __import__("api_fw").trial_read()
        if t.get("done") == "back" and str(t.get("done_by") or "").startswith("not kept"):
            found.append(("fw:%s" % t.get("id"), "web", "The firewall and access went back to what they were "
                          "before - the change was %s." % t.get("done_by")))
    except Exception:                                   # noqa: BLE001
        pass
    r = PN.root_result(ctx.cfg.get("state_dir"), "sshd")
    if r.get("back_at") and "not kept" in str(r.get("back_why") or "not kept"):
        found.append(("sshd:%s" % r.get("back_at"), "sshd", "The change of the SSH server went back - it was "
                      "not kept in time."))
    seen = st.get("trials_seen")
    keys = [k for k, _p, _w in found]
    st["trials_seen"] = keys
    if seen is None:                                    # the first look: what is there was before
        return []
    return [{"level": "warn", "title": "A change on trial went back", "pane": pane, "since": time.time(),
             "said": words} for k, pane, words in found if k not in seen]


def backup_problems(ctx):
    """otp's: the nightly copy older than 36 h; the last backup to the destinations failed, or none in time."""
    import igd_panes as PN
    out = {}
    now = time.time()
    if PN.value(ctx.store, "db_copy_daily"):
        last = float(ctx.store.get_meta("db:copy:at") or 0)
        made = float(ctx.store.get_meta("db:copy:first") or 0)
        if not made:
            ctx.store.set_meta("db:copy:first", str(now))
            made = now
        if now - max(last, made) > 36 * 3600:
            out["dbcopy"] = {"level": "warn", "title": ("The last copy of the database was made %s" % _ago(last))
                             if last else "No copy of the database in 36 hours", "pane": "db",
                             "said": "The copy of every day did not come - Settings → The database."}
    if PN.value(ctx.store, "rbackup"):
        bk = __import__("api_backup")
        rows = bk.runs(ctx)
        on = [t for t in bk.targets(ctx) if t.get("enabled")]
        if rows and not rows[0].get("ok"):
            out["backup:%s" % int(rows[0].get("at") or 0)] = {
                "level": "bad", "title": "The backup failed", "pane": "backup",
                "said": str(rows[0].get("error") or "; ".join("%s: %s" % (x.get("name"), x.get("error"))
                                                                for x in rows[0].get("targets") or []
                                                                if not x.get("ok")))[:300]}
        every = 8 * 86400 if PN.value(ctx.store, "rbackup_every") == "weekly" else 36 * 3600
        ok = [r for r in rows if r.get("ok")]
        since = ok[0]["at"] if ok else float(ctx.store.get_meta("backup:first") or 0)
        if not since:
            ctx.store.set_meta("backup:first", str(now))
            since = now
        if on and now - float(since) > every:
            out["backup:late"] = {"level": "warn", "title": "No backup went in time", "pane": "backup",
                                  "said": "The last good one %s." % (_ago(ok[0]["at"]) if ok else "- none yet")}
    return out


def _bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%.0f %s" if u == "B" else "%.1f %s") % (n, u)
        n /= 1024.0


def _ago(t):
    if not t:
        return "never"
    s = max(0, int(time.time() - float(t)))
    if s < 90:
        return "just now"
    if s < 5400:
        return "%d min ago" % (s // 60)
    if s < 172800:
        return "%d h ago" % (s // 3600)
    return "%d days ago" % (s // 86400)


def _when(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t or 0)))


# ---- the mails -----------------------------------------------------------------------------
def _page(title, kicker, band, body, foot, width=640):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>'
            '</head><body style="margin:0;padding:0;background:#f3f4f6;%s">'
            '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" bgcolor="#f3f4f6" '
            'style="background:#f3f4f6"><tr><td align="center" style="padding:24px 10px">'
            '<table role="presentation" width="%d" cellspacing="0" cellpadding="0" border="0" bgcolor="#ffffff" '
            'style="max-width:%dpx;width:100%%;background:#ffffff;border-radius:14px;overflow:hidden;'
            'border:1px solid #e5e7eb">'
            '<tr><td bgcolor="%s" style="background:%s;padding:20px 28px;color:#ffffff;%s">'
            '<p style="margin:0;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:#ffffff;'
            'opacity:.85">%s</p><p style="margin:4px 0 0;font-size:21px;font-weight:700;color:#ffffff">%s</p>'
            '</td></tr><tr><td style="padding:22px 28px;%s">%s</td></tr>'
            '<tr><td style="padding:14px 28px 22px;font-size:12px;color:#9ca3af;%sborder-top:1px solid #f3f4f6">'
            '%s</td></tr></table></td></tr></table></body></html>'
            % (_h(title), AL_FONT, width, width, band, band, AL_FONT, _h(kicker), _h(title), AL_FONT, body,
               AL_FONT, foot))


def _card(level, title, lines, link=""):
    edge, back, ink = AL_COLORS.get(level, AL_COLORS["info"])
    rows = "".join('<div style="margin-top:4px;font-size:13.5px;line-height:1.5;color:#374151">%s</div>' % ln
                   for ln in lines if ln)
    if link:
        rows += ('<div style="margin-top:8px;font-size:13px"><a href="%s" style="color:#1d4ed8;'
                 'text-decoration:none;font-weight:600">%s</a></div>' % (_h(link[0]), _h(link[1])))
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:0 0 10px"><tr><td bgcolor="%s" style="background:%s;border-left:4px solid %s;'
            'border-radius:8px;padding:12px 16px;%s"><div style="font-size:15px;font-weight:700;color:%s">%s</div>'
            '%s</td></tr></table>' % (back, back, edge, AL_FONT, ink, _h(title), rows))


def _head(text):
    return ('<p style="margin:18px 0 8px;font-size:12px;font-weight:700;letter-spacing:1px;'
            'text-transform:uppercase;color:#6b7280">%s</p>' % _h(text))


def _tiles(tiles):
    cells = "".join(
        '<td width="%d%%" valign="top" style="padding:4px"><table role="presentation" width="100%%" '
        'cellspacing="0" cellpadding="0" border="0"><tr><td bgcolor="%s" style="background:%s;border-radius:10px;'
        'padding:12px 12px;%s"><div style="font-size:22px;font-weight:700;color:%s">%s</div>'
        '<div style="margin-top:2px;font-size:12px;color:#4b5563">%s</div></td></tr></table></td>'
        % (100 // len(tiles), AL_COLORS[lv][1], AL_COLORS[lv][1], AL_FONT, AL_COLORS[lv][2], _h(v), _h(k))
        for k, v, lv in tiles)
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:0 0 8px"><tr>%s</tr></table>' % cells)


def _table(head, rows):
    th = "".join('<td style="padding:6px 10px;white-space:nowrap;font-size:11.5px;font-weight:700;letter-spacing:.5px;'
                 'text-transform:uppercase;color:#6b7280;border-bottom:1px solid #e5e7eb;%s">%s</td>'
                 % ("text-align:right;" if i and str(h).startswith("#") else "", _h(str(h).lstrip("#")))
                 for i, h in enumerate(head))
    trs = []
    for r in rows:
        trs.append("<tr>%s</tr>" % "".join(
            '<td style="padding:6px 10px;font-size:13px;color:#111827;border-bottom:1px solid #f3f4f6;%s">%s</td>'
            % ("text-align:right;" if i and str(head[i]).startswith("#") else "", cell) for i, cell in enumerate(r)))
    if not rows:
        trs.append('<tr><td colspan="%d" style="padding:8px;font-size:13px;color:#9ca3af">–</td></tr>' % len(head))
    return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" '
            'style="margin:0 0 6px;%s"><tr>%s</tr>%s</table>' % (AL_FONT, th, "".join(trs)))


def admin_url(ctx):
    """otp's alerts_link: The administration's address in the mails, or this machine's name."""
    import igd_panes as PN
    url = str(PN.value(ctx.store, "alerts_url") or "").strip()
    return url or "https://%s/admin/" % socket.getfqdn()


def _link(ctx, pane):
    return "%s#settings/%s" % (admin_url(ctx), pane)


def alert_mail(ctx, new, still, gone, events, test=False, left=0):
    """(subject, text, html) of one alert mail - as otp's alert_mail."""
    site = _site(ctx)
    bad = [p for p in new + still if p["level"] == "bad"]
    if test:
        subject, band, title = "[fake-igd] A test alert - %s" % site, AL_COLORS["info"][0], "Alerts come through"
    elif new or (still and not gone):
        # (otp's said "N problems" also when the mail is about something over - what is still wrong is
        # named in it too; the subject then said nothing of what was over)
        n = len(new) + len(still)
        subject = "[fake-igd] %s %d %s - %s" % ("✖" if bad else "⚠", n, "problem" if n == 1 else "problems", site)
        band, title = AL_COLORS["bad" if bad else "warn"][0], "Something is wrong"
    elif gone and left:
        subject = "[fake-igd] ✔ %d over, %d still so - %s" % (len(gone), left, site)
        band, title = AL_COLORS["good"][0], "Some of it is over"
    elif gone:
        subject, band, title = "[fake-igd] ✔ Back to normal - %s" % site, AL_COLORS["good"][0], "All is well again"
    else:
        subject, band, title = "[fake-igd] Events - %s" % site, AL_COLORS["info"][0], "What happened"
    body, text = [], [title, ""]

    def section(head, items, level=None):
        if not items:
            return
        body.append(_head(head))
        text.append(head.upper())
        for p in items:
            lines = [_h(p["said"])]
            if p.get("since"):
                lines.append('<span style="color:#6b7280">Since: %s</span>' % _h(_when(p["since"])))
            link = (_link(ctx, p["pane"]), "Open in the administration →") \
                if p.get("pane") and (level or p["level"]) != "good" else ""
            body.append(_card(level or p["level"], p["title"], lines, link))
            text.append("- %s: %s" % (p["title"], p["said"]))
        text.append("")
    if test:
        body.append(_card("info", "This is a test", [_h("The alerts of %s arrive here. Problems now: %d."
                                                        % (site, len(still)))]))
        section("What is wrong now", still)
    else:
        allp = new + still
        body.append(_tiles([("down", str(len([p for p in allp if p["level"] == "bad"])),
                             "bad" if any(p["level"] == "bad" for p in allp) else "good"),
                            ("warnings", str(len([p for p in allp if p["level"] != "bad"])),
                             "warn" if any(p["level"] != "bad" for p in allp) else "good"),
                            ("over", str(len(gone)), "good")]))
        section("New", new)
        section("Still so", still)
        section("Over", [dict(p, said=p["said"] + " (it lasted %s)" % _ago(p.get("since")).replace(" ago", ""))
                         for p in gone], "good")
        section("Events", events, "info")
    foot = _h("Sent by fake-igd on %s, %s. Settings → Alerts and reports." % (socket.gethostname(), _when(time.time())))
    text += ["-- ", "Sent by fake-igd on %s, %s. Settings → Alerts and reports." % (socket.gethostname(),
                                                                                     _when(time.time())),
             admin_url(ctx)]
    return subject, "\n".join(text), _page(title, "fake-igd · " + site, band, "".join(body), foot)


def send(ctx, subject, text, page, to, kind, keys):
    """Into the outgoing mail; the row of what was sent kept. A mail waiting for another try counts as sent."""
    import igd_mail as M
    entry = {"at": time.time(), "kind": kind, "keys": keys[:20], "to": to, "ok": True, "subject": subject[:200]}
    try:
        got = M.send_and_wait(ctx.store, to, subject, text, page, kind=kind, by=(ctx.me or {}).get("name", ""))
        if not got["sent"]:
            entry.update(ok=False, said=got["said"][:200], queued=got.get("queued") or "")
    except Exception as e:                              # noqa: BLE001
        entry.update(ok=False, said=str(e)[:200])
    st = state(ctx.store)
    if not entry["ok"] and entry.get("queued") != "waiting" and kind != "test":
        # mail failing holds the alerts back for 15 min - not a test to a wrong address (1.7.5)
        st["fail_at"] = entry["at"]
    st["log"] = ([entry] + st["log"])[:50]
    put_state(ctx.store, st)
    return entry


def _new_ports(ctx, st):
    """Ports never asked for before, since the last look: [(t, client, proto, port, desc)]."""
    import upnp as U
    try:
        ev = U.read_events(ctx.cfg)
    except SystemExit:
        return []
    seen = set(st.get("ports_seen") or [])
    first = "ports_seen" not in st
    last = float(st.get("ports_at") or 0)
    out = []
    for e in ev:
        if e.get("action") != "AddPortMapping" or not e.get("_t"):
            continue
        k = "%s %s/%s" % (e.get("client"), e.get("external_port"), str(e.get("protocol") or "").lower())
        t = e["_t"].timestamp()
        if k not in seen:
            seen.add(k)
            if not first and t > last:
                out.append((t, e, k))
        last = max(last, t)
    st["ports_seen"] = sorted(seen)[-5000:]
    st["ports_at"] = last
    return out


def evaluate(ctx, force=False):
    """The alerts' turn: what is wrong compared with what was said, mailed (as otp's)."""
    with LOCK:
        c = cfg_of(ctx.store)
        now = time.time()
        cur = problems(ctx, c)
        st = state(ctx.store)
        known = st["problems"]
        delay = 60 * int(c.get("alerts_delay_min") or 0)
        repeat = 3600 * int(c.get("alerts_repeat_h") or 0)
        new, still, gone = [], [], []
        for k, p in cur.items():
            was = known.get(k) or {}
            p["key"] = k
            p["since"] = was.get("since") or now
            p["sent"] = bool(was.get("sent"))
            p["sent_at"] = was.get("sent_at")
            p["mailed"] = was.get("mailed") or (was.get("level") if was.get("sent") else None)
            if not p["sent"] and now - p["since"] >= delay:
                new.append(p)
            elif p["sent"] and repeat and now - float(was.get("sent_at") or 0) >= repeat:
                still.append(p)
            elif p["sent"] and p["mailed"] == "warn" and p["level"] == "bad":
                new.append(p)
            known[k] = dict(p)
        for k in list(known):
            if k not in cur:
                if known[k].get("sent") and delay and not force:
                    gone_at = float(known[k].get("missing_since") or 0) or now
                    known[k]["missing_since"] = gone_at
                    if now - gone_at < delay:
                        continue
                p = known.pop(k)
                if p.get("sent") and c.get("alerts_resolved", True):
                    gone.append(p)
        events = []
        beat = float(st.get("beat") or 0)
        if c.get("alerts_api") and beat and now - beat > API_AWAY_S:
            events.append({"level": "bad", "title": "The pages' API was away", "pane": "service", "since": beat,
                           "said": "fake-igd-api did not run from %s to %s (%s)." % (
                               _when(beat), _when(now), _ago(beat).replace(" ago", ""))})
        st["beat"] = now
        if c.get("alerts_new_port"):
            for t, e, k in _new_ports(ctx, st)[:20]:
                events.append({"level": "info", "title": "A new port asked for: %s" % k, "pane": "", "since": t,
                               "said": "%s asked for %s/%s (%s) - answered %s." % (
                                   e.get("client"), e.get("external_port"), str(e.get("protocol") or "").lower(),
                                   e.get("description") or "-", e.get("result") or "?")})
        else:
            st.pop("ports_seen", None)
        if c.get("alerts_trial", True):
            events += trials_back(ctx, st)
        else:
            st.pop("trials_seen", None)
        to = _to(c)
        mailing = bool(to and c.get("alerts"))
        held_back = mailing and now - float(st.get("fail_at") or 0) <= 900
        if held_back and gone:
            for p in gone:
                known[p["key"]] = p
            gone = []
        st["problems"] = known
        st["checked"] = now
        put_state(ctx.store, st)
        if (new or still or gone or events) and mailing and not held_back:
            said = {p["key"] for p in new + still}
            others = [p for p in cur.values() if p["key"] not in said and p["sent"]] if new or gone else []
            subject, text, page = alert_mail(ctx, new, still + others, gone, events,
                                             left=len([p for p in cur.values() if p["sent"] or p["key"] in said]))
            entry = send(ctx, subject, text, page, to, "alert",
                         sorted(said) + ["over:" + str(p.get("key") or "") for p in gone])
            if entry["ok"] or entry.get("queued") == "waiting":
                st = state(ctx.store)
                for k in said | {p["key"] for p in others}:
                    if k in st["problems"]:
                        one = st["problems"][k]
                        one.update(sent=True, sent_at=now,
                                   mailed="bad" if "bad" in (one.get("mailed"), one.get("level")) else one.get("level"))
                put_state(ctx.store, st)
        return cur


# ---- the report ----------------------------------------------------------------------------
def period(c, now=None):
    """(since, until, id) of the last period that has ended, as report_every says (as otp's)."""
    now = datetime.fromtimestamp(now or time.time())
    every = c.get("report_every") or "weekly"
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if every == "daily":
        until = day0
        since = until - timedelta(days=1)
    elif every == "monthly":
        until = day0.replace(day=1)
        since = (until - timedelta(days=1)).replace(day=1)
    else:
        until = day0 - timedelta(days=(day0.isoweekday() - 1))
        since = until - timedelta(days=7)
    return time.mktime(since.timetuple()), time.mktime(until.timetuple()), "%s:%s" % (every, since.strftime("%Y-%m-%d"))


def period_now(c):
    since, until, _pid = period(c)
    return until, time.time()


def due(c, now=None):
    n = datetime.fromtimestamp(now or time.time())
    try:
        hh, mm = (int(x) for x in str(c.get("report_at") or "07:30").split(":", 1))
    except ValueError:
        hh, mm = 7, 30
    every = c.get("report_every") or "weekly"
    late = (n.hour, n.minute) >= (hh, mm)
    if every == "weekly":
        day = int(c.get("report_day") or 1)
        return n.isoweekday() > day or (n.isoweekday() == day and late)
    if every == "monthly":
        return n.day > 1 or late
    return late


def report_build(ctx, since, until):
    """(subject, text, html) of the report of a period: the ports asked for, the devices, the events."""
    import upnp as U
    site = _site(ctx)
    try:
        ev = [e for e in U.read_events(ctx.cfg, datetime.fromtimestamp(since).astimezone())
              if e.get("_t") and e["_t"].timestamp() < until]
    except SystemExit:
        ev = []
    adds = [e for e in ev if e.get("action") == "AddPortMapping"]
    agg = collections.OrderedDict()
    for e in adds:
        k = (e.get("client"), str(e.get("protocol") or "").upper(), e.get("external_port"))
        a = agg.setdefault(k, {"n": 0, "desc": set(), "res": collections.Counter(), "last": 0})
        a["n"] += 1
        if e.get("description"):
            a["desc"].add(str(e["description"]))
        a["res"][str(e.get("result") or "?")] += 1
        a["last"] = max(a["last"], e["_t"].timestamp())
    clients = collections.Counter(e.get("client") for e in ev)
    actions = collections.Counter(e.get("action") for e in ev)
    evs = ctx.store.rows("SELECT * FROM events WHERE at >= ? AND at < ? ORDER BY id DESC", (since, until))
    kinds = collections.Counter(r["kind"] for r in evs)
    worth = [r for r in evs if r["level"] in ("warn", "bad", "crit", "error")][:40]
    signins = [r for r in evs if r["kind"] == "sign-in"]
    refused = [r for r in signins if "could not" in r["words"]]
    try:
        before = U.read_events(ctx.cfg, None)
        old = {(e.get("client"), str(e.get("protocol") or "").upper(), e.get("external_port"))
               for e in before if e.get("action") == "AddPortMapping" and e.get("_t") and e["_t"].timestamp() < since}
    except SystemExit:
        old = set()
    fresh = [k for k in agg if k not in old]
    cur = problems(ctx)
    day = lambda t: time.strftime("%Y-%m-%d", time.localtime(t))    # noqa: E731
    title = "The report of %s - %s" % (day(since), day(until - 1))
    body = [_tiles([("requests", str(len(ev)), "info"), ("ports asked for", str(len(adds)), "info"),
                    ("new ports", str(len(fresh)), "warn" if fresh else "good"),
                    ("devices", str(len([c for c in clients if c])), "info"),
                    ("wrong now", str(len(cur)), "bad" if any(p["level"] == "bad" for p in cur.values())
                     else ("warn" if cur else "good"))])]
    body.append(_head("The ports asked for"))
    rows = []
    for (cl, pr, port), a in sorted(agg.items(), key=lambda kv: (-kv[1]["n"], str(kv[0]))):
        rows.append([_h(cl), _h("%s/%s" % (port, pr.lower())) + (' <b style="color:#d97706">new</b>'
                                                                   if (cl, pr, port) in fresh else ""),
                     _h(", ".join(sorted(a["desc"]))[:80]), str(a["n"]),
                     _h(", ".join("%s %d" % kv for kv in a["res"].most_common()))])
    body.append(_table(["Device", "Port", "Description", "#Times", "Answered"], rows[:60]))
    body.append(_head("The devices"))
    body.append(_table(["Device", "#Requests"], [[_h(c), str(n)] for c, n in clients.most_common(20) if c]))
    body.append(_head("What they asked"))
    body.append(_table(["Action", "#Times"], [[_h(a), str(n)] for a, n in actions.most_common(12)]))
    body.append(_head("Events"))
    body.append(_table(["Kind", "#Times"], [[_h(k), str(n)] for k, n in kinds.most_common(12)]))
    if refused:
        body.append(_head("Sign-ins refused (%d of %d)" % (len(refused), len(signins))))
        body.append(_table(["When", "From", "What"], [[_h(_when(r["at"])), _h(r["addr"]), _h(r["words"])]
                                                      for r in refused[:20]]))
    if worth:
        body.append(_head("Events worth a look"))
        body.append(_table(["When", "Kind", "What"], [[_h(_when(r["at"])), _h(r["kind"]), _h(r["words"][:160])]
                                                      for r in worth]))
    body.append(_head("What is wrong now"))
    if cur:
        for p in cur.values():
            body.append(_card(p["level"], p["title"], [_h(p["said"])]))
    else:
        body.append(_card("good", "Nothing", [_h("fake-igd.service, the disks, the certificate - all is as it should be.")]))
    text = [title, "", "Requests: %d, ports asked for: %d (%d new), devices: %d" % (
        len(ev), len(adds), len(fresh), len([c for c in clients if c])), "", "THE PORTS ASKED FOR"]
    for (cl, pr, port), a in sorted(agg.items(), key=lambda kv: (-kv[1]["n"], str(kv[0])))[:60]:
        text.append("- %s %s/%s x%d (%s)%s" % (cl, port, pr.lower(), a["n"], ", ".join(sorted(a["desc"])),
                                                " NEW" if (cl, pr, port) in fresh else ""))
    text += ["", "WHAT IS WRONG NOW"] + ["- %s: %s" % (p["title"], p["said"]) for p in cur.values()] + \
        (["- nothing"] if not cur else [])
    foot = _h("Sent by fake-igd on %s, %s. Settings → Alerts and reports." % (socket.gethostname(), _when(time.time())))
    subject = "[fake-igd] %s - %s" % (title, site)
    return subject, "\n".join(text), _page(title, "fake-igd · " + site, AL_COLORS["info"][0], "".join(body), foot, 760)


def report_tick(ctx, c):
    if not c.get("report") or not due(c):
        return
    since, until, pid = period(c)
    if ctx.store.get_meta("report:sent") == pid:
        return
    to = _to(c, "report_to")
    if not to:
        return
    ctx.store.set_meta("report:sent", pid)
    subject, text, page = report_build(ctx, since, until)
    send(ctx, subject, text, page, to, "report", [pid])


# ---- the routes ----------------------------------------------------------------------------
def view(ctx):
    import igd_mail as M
    c = cfg_of(ctx.store)
    st = state(ctx.store)
    now = problems(ctx, c)
    since, until, pid = period(c)
    mon = __import__("api_monitor")
    return {"problems": [dict(p, key=k, since=(st["problems"].get(k) or {}).get("since"),
                              sent=bool((st["problems"].get(k) or {}).get("sent")))
                         for k, p in sorted(now.items(), key=lambda kv: (kv[1]["level"] != "bad", kv[0]))],
            "log": st["log"][:30], "checked": st.get("checked"), "on": bool(c.get("alerts")),
            "to": _to(c), "report_to": _to(c, "report_to"), "report_on": bool(c.get("report")),
            "mail": (M.settings(ctx.store).get("mail_mode") or "off") != "off",
            "report": {"since": since, "until": until, "sent": ctx.store.get_meta("report:sent") == pid},
            "disks": mon.disks(ctx.cfg), "cert": mon.certificate(), "node": socket.gethostname().split(".")[0]}


def alerts_get(ctx):
    return view(ctx)


def alerts_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    c = cfg_of(ctx.store)
    if act == "check":
        evaluate(ctx, force=True)
        d = view(ctx)
        d["message"] = "looked again - %d thing(s) wrong" % len(d["problems"])
        return d
    if act == "test":
        to = _to(c)
        if not to:
            raise ValueError("no address to send the alerts to - Send them to, above")
        cur = list(problems(ctx, c).values())
        subject, text, page = alert_mail(ctx, [], cur, [], [], test=True)
        entry = send(ctx, subject, text, page, to, "test", [])
        ctx.event("%s sent a test alert to %s: %s" % (me["name"], ", ".join(to), "sent" if entry["ok"]
                                                       else entry.get("said", "")), "info" if entry["ok"] else "warn")
        d = view(ctx)
        d["message"] = ("the test alert went to %s" % ", ".join(to)) if entry["ok"] else \
            ("not sent yet: %s" % entry.get("said", ""))
        return d
    if act == "preview":
        since, until = (period_now(c) if b.get("period") == "now" else period(c)[:2])
        subject, _text, page = report_build(ctx, since, until)
        return {"subject": subject, "html": page}
    if act == "report":
        to = _to(c, "report_to")
        if not to:
            raise ValueError("no address to send the report to")
        since, until = (period_now(c) if b.get("period") == "now" else period(c)[:2])
        subject, text, page = report_build(ctx, since, until)
        entry = send(ctx, subject, text, page, to, "report", ["by hand"])
        ctx.event("%s sent the report to %s" % (me["name"], ", ".join(to)), "info" if entry["ok"] else "warn")
        d = view(ctx)
        d["message"] = ("the report went to %s" % ", ".join(to)) if entry["ok"] else \
            ("not sent yet: %s" % entry.get("said", ""))
        return d
    if act == "forget":
        st = state(ctx.store)
        st["log"] = []
        put_state(ctx.store, st)
        ctx.event("%s forgot the list of alert mails sent" % me["name"])
        d = view(ctx)
        d["message"] = "the list is empty"
        return d
    raise ValueError("no such action")


ROUTES = {
    ("GET", "/api/alerts"): alerts_get,
    ("POST", "/api/alerts"): alerts_post,
}


def background(ctx):
    c = cfg_of(ctx.store)
    if c.get("alerts") or c.get("alerts_api"):
        evaluate(ctx)
    report_tick(ctx, c)
