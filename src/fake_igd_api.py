#!/usr/bin/env python3
"""fake_igd_api.py - the API the web pages ask (1.4.0).

otp's shape: nginx → php-fpm (pages that only relay) → this, on 127.0.0.1.
It runs as the fake-igd account (fake-igd-api.service), apart from the UPnP
service itself, so that the pages stay up while fake-igd.service is restarted
after a change of its settings.

  * Every request carries the API token from /run/fake-igd-api/api-token,
    which only this account and the pages' group (fake-igd-web) can read.
  * Whoever is signed in is the session in X-IGD-Session - local accounts in
    the SQLite database (igd_store.py), checked here, never by the pages.
  * It reads what fake-igd wrote (the logs, the requests, the mappings) with
    the same code as the `upnp` command, writes /etc/fake-igd/config.json
    when a setting is changed, and asks root (fake-igd-web.path) to restart
    the service, put nginx's allow list and the firewall in place, and
    (fake-igd-upgrade.path) to put in a new version.

  fake_igd_api.py [--config /etc/fake-igd/config.json]
"""
import argparse
import base64
import collections
import contextlib
import fcntl
import grp
import hmac
import io
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import upnp as U             # noqa: E402 - the command line's own readers and checks
import igd_online as ON      # noqa: E402
import igd_store as ST       # noqa: E402
import igd_panes as PN       # noqa: E402 - the panes of Settings, each a module of its own (1.6.0)

VERSION = U.VERSION
RUN_DIR = os.environ.get("FAKE_IGD_RUN", "/run/fake-igd-api")
TOKEN_FILE = os.path.join(RUN_DIR, "api-token")
PORT_FILE = os.path.join(RUN_DIR, "api-port")
# The command line's own key (1.7.4, otp's --api): `sudo upnp api ...` and the commands built on it
# ask this API as a full administrator with it. Readable by this account alone (and root) - never
# by the pages' group, so the pages cannot pass for the command line.
CLI_FILE = os.path.join(RUN_DIR, "cli-token")
CLI_TOKEN = [""]
WEB_GROUP = "fake-igd-web"
STARTED = time.time()

CFG_PATH = U.DEFAULT_CONFIG
CFG = {}
CFG_AT = [0.0]
STORE = [None]
TOKEN = [""]
# What a sign-in whose password is to be changed may still ask (otp's MUST_CHANGE_ALLOWED).
MUST_CHANGE_ALLOWED = ("/api/auth/password", "/api/auth/passwd", "/api/auth/logout", "/api/auth/whoami")
LOCK = threading.RLock()

NAMES = {
    "mode": "Mode", "mapping_response": "The answer to AddPortMapping", "igd_version": "UPnP version (InternetGatewayDevice)", "http_port": "Description and SOAP port",
    "external_ip": "Public IP reported", "interfaces": "Interfaces", "exclude_interfaces": "Interfaces left out",
    "allowed_clients": "Who is answered", "ntfy_url": "ntfy topic URL", "ntfy_token": "ntfy access token",
    "ntfy_user": "ntfy user", "ntfy_password": "ntfy password", "ntfy_priority": "Priority",
    "ntfy_tags": "Tags", "ntfy_ca_file": "CA certificate of the ntfy server", "notify_on_renew": "Notify renewals",
    "notify_other_router": "Notify another UPnP router", "log_level": "Log level", "log_file": "Main log",
    "request_log": "Request log", "state_dir": "State folder", "interface_rescan_seconds": "Interfaces looked at every",
    "notify_interval_seconds": "SSDP announcements every", "site_name": "What to call this installation",
    "api_port": "API port (localhost)", "session_idle_minutes": "Sign-in ends after idle",
    "web_allow": "Who may reach the pages", "firewall": "Firewall (iptables, FAKE-IGD-IN)",
    "firewall_ssh": "Let SSH in", "firewall_icmp": "Let ping in", "upgrade_url": "Where new versions are looked for",
    "upgrade_check": "Look for a new version every day",
}
CHOICE_WORDS = {
    "mode": {"active": "active - answer like a UPnP router", "passive": "passive - only listen and log"},
    "mapping_response": {"accept": "accept - confirm it (nothing is opened)", "reject": "reject - error 501"},
}
PANES = {"answer": "How it answers", "network": "Network", "ntfy": "Notifications (ntfy)",
         "logs": "Logs and state", "web": "Web pages and firewall", "upgrade": "Upgrades", "about": "About"}
PANE_OF_GROUP = {g: p for p, g in PANES.items()}


# ---- settings ------------------------------------------------------------------------
def load_cfg(force=False):
    with LOCK:
        try:
            m = os.stat(CFG_PATH).st_mtime
        except OSError:
            m = 0
        if force or m != CFG_AT[0] or not CFG:
            cfg = dict(U.DEFAULTS)
            try:
                with open(CFG_PATH, encoding="utf-8") as f:
                    got = json.load(f)
                cfg.update(got if isinstance(got, dict) else {})
                cfg["_in_file"] = sorted(got) if isinstance(got, dict) else []
            except (OSError, ValueError) as e:
                cfg["_error"] = str(e)
                cfg["_in_file"] = []
            CFG.clear()
            CFG.update(cfg)
            CFG_AT[0] = m
        return CFG


def save_cfg(changes):
    """The changed keys into config.json - written in place (the folder is root's), locked."""
    with LOCK:
        with open(CFG_PATH, "r+", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
            except ValueError:
                raise ValueError("%s does not read as JSON - put it right on the server first" % CFG_PATH)
            data.update(changes)
            ordered = {k: data[k] for k in U.DEFAULTS if k in data}
            ordered.update({k: v for k, v in data.items() if k not in ordered})
            text = json.dumps(ordered, ensure_ascii=False, indent=2) + "\n"
            f.seek(0)
            f.write(text)
            f.truncate()
            f.flush()
            os.fsync(f.fileno())
        load_cfg(force=True)


def ask_root(restart=False, extra=None):
    """apply.ask for fake-igd-web.path: root restarts the service and puts the rest in place
    (or, with extra, changes the mDNS reflector)."""
    folder = os.path.join(CFG.get("state_dir") or "/var/lib/fake-igd", "web")
    os.makedirs(folder, mode=0o750, exist_ok=True)
    ident = secrets.token_hex(6)
    tmp = os.path.join(folder, ".ask.%s" % ident)
    with open(tmp, "w") as f:
        body = {"id": ident, "restart": bool(restart), "at": time.time()}
        body.update(extra or {})
        json.dump(body, f)
    os.replace(tmp, os.path.join(folder, "apply.ask"))
    return ident


def root_result():
    try:
        with open(os.path.join(CFG.get("state_dir") or "/var/lib/fake-igd", "web", "result.json"),
                  encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def settings_view(full=False):
    cfg = load_cfg()
    out = []
    infile = set(cfg.get("_in_file") or [])
    for key, default in U.DEFAULTS.items():
        v = cfg.get(key, default)
        s = {"key": key, "name": NAMES.get(key, key), "says": U.KEY_HELP.get(key, ""),
             "default": default, "secret": key in U.SECRET_KEYS,
             "source": "config" if key in infile else "default",
             "source_says": ("set in %s" % CFG_PATH) if key in infile else "as it comes",
             "list": isinstance(default, list), "bool": isinstance(default, bool),
             "restarts": key in U.SERVICE_KEYS, "root": key in U.ROOT_KEYS}
        if s["secret"]:
            s["value"] = PN.shown(v) if full else ""
            s["set"] = bool(v)
        elif isinstance(default, list):
            s["value"] = ", ".join(str(x) for x in (v or []))
            s["default"] = ", ".join(str(x) for x in default)
        else:
            s["value"] = v
        if key in U.ALLOWED_VALUES:
            s["choices"] = list(U.ALLOWED_VALUES[key])
            s["choice_words"] = CHOICE_WORDS.get(key, {})
        if key in U.NUMBER_RANGES:
            s["min"], s["max"] = U.NUMBER_RANGES[key]
        out.append(s)
    panes = {}
    for group, keys in U.SETTING_GROUPS:
        panes[PANE_OF_GROUP.get(group, group)] = list(keys)
    more, more_panes = PN.view(STORE[0], full=full)
    out += more
    for pane, keys in more_panes.items():
        panes.setdefault(pane, []).extend(keys)
    only_when = {s["key"]: s["only_when"] for s in more if s.get("only_when")}
    return {"settings": out, "panes": panes, "pane_names": PANES, "config_file": CFG_PATH,
            "error": cfg.get("_error"), "only_when": only_when}


def settings_save(changes, who, addr, handler=None):
    if not isinstance(changes, dict) or not changes:
        raise ValueError("nothing to save")
    cfg = load_cfg()
    good = {}
    theirs = {k: changes.pop(k) for k in list(changes) if k in PN.SETTINGS}
    # Every value of config.json checked before anything is kept (1.7.4): one that is refused
    # no longer leaves the panes' settings of the same save changed behind it.
    for key, raw in changes.items():
        if key not in U.DEFAULTS:
            raise ValueError("%s is not a setting" % key)
        if key in U.SECRET_KEYS and (raw is None or PN.masked(raw)):
            continue
        if isinstance(U.DEFAULTS[key], bool):
            raw = "on" if raw in (True, "true", "1", "on") else "off"
        elif isinstance(U.DEFAULTS[key], list) and isinstance(raw, list):
            raw = ",".join(str(x) for x in raw)
        raw = "" if raw is None else str(raw)
        if key in ("state_dir", "log_file", "request_log") and raw != str(cfg.get(key)):
            raise ValueError("%s is changed on the server only (sudo upnp config set %s ...): the service's "
                             "sandbox would need it too" % (key, key))
        try:
            v, err = U.check_value(key, raw)
        except SystemExit:
            err, v = "%s: not a value it takes" % key, None
        if err:
            raise ValueError(err)
        if v != cfg.get(key):
            good[key] = v
    mod_changed = PN.save(STORE[0], theirs) if theirs else {}
    for name, ch in mod_changed.items():
        shown = ", ".join("%s=%s" % (k, "(hidden)" if PN.SETTINGS[k].get("kind") == "secret" else v)
                          for k, v in ch.items())
        STORE[0].add_event("setting", "%s changed %s" % (who, shown), "info", who, addr)
        mod = PN.module(name)
        if mod is not None and hasattr(mod, "on_saved"):
            mod.on_saved(PN.Ctx(handler, "POST", "", {}, {"name": who, "role": "fulladmin"}, STORE[0], CFG, mod,
                                STORE[0].add_event), ch)
    mod_saved = sorted(k for ch in mod_changed.values() for k in ch)
    if not good:
        return {"saved": mod_saved, "restart": False}
    save_cfg(good)
    restart = any(k in U.SERVICE_KEYS for k in good)
    root = any(k in U.ROOT_KEYS for k in good)
    shown = ", ".join("%s=%s" % (k, U.shown_value(k, v)) for k, v in good.items())
    STORE[0].add_event("setting", "%s changed %s" % (who, shown), "info", who, addr)
    if restart or root:
        ask_root(restart=restart)
    return {"saved": sorted(good) + mod_saved, "restart": restart, "root": root}


# ---- what fake-igd wrote -------------------------------------------------------------
CACHE = {}


def cached(key, seconds, fn):
    now = time.time()
    with LOCK:
        hit = CACHE.get(key)
        if hit and now - hit[0] < seconds:
            return hit[1]
    val = fn()
    with LOCK:
        CACHE[key] = (now, val)
    return val


def serial():
    cfg = load_cfg()
    parts = []
    for p in (cfg["request_log"], cfg["log_file"], os.path.join(cfg["state_dir"], "mappings.json"), CFG_PATH):
        try:
            st = os.stat(p)
            parts.append("%d.%d" % (st.st_mtime_ns // 1000000, st.st_size))
        except OSError:
            parts.append("-")
    return ":".join(parts)


def guarded(fn, *a, **kw):
    """The command line's readers end the program on a file they may not read: here an error."""
    try:
        return fn(*a, **kw)
    except SystemExit as e:
        raise ValueError("a file of fake-igd could not be read (%s)" % (e.code or "permission"))


def ts(v):
    if not v:
        return None
    if isinstance(v, datetime):
        return v.timestamp()
    t = U.parse_time(v)
    return t.timestamp() if t else None


EVENT_GROUPS = {
    "sign-in": "sign-ins", "account": "accounts", "people": "accounts", "osusers": "accounts",
    "service": "starting and stopping", "upnp": "starting and stopping", "power": "starting and stopping",
    "upgrade": "upgrades", "backup": "backups", "carry": "backups", "db": "backups",
    "mail": "mail", "mailq": "mail", "alerts": "mail", "alert": "mail",
    "notify": "notifications", "ntfy": "notifications", "mdns": "mdns",
    "tls": "certificates", "acme": "certificates", "sshd": "ssh", "sshkeys": "ssh",
}


def event_group(kind):
    """otp's words for a kind of event: the group it belongs to; every other change is 'settings'."""
    return EVENT_GROUPS.get(str(kind or ""), "settings")


def window(q, default_s=None):
    """(since, until) as aware datetimes from otp's time picker (since=, until= in epoch seconds);
    None for an open end. No since and no default: all time."""
    def one(name):
        try:
            v = float((q.get(name) or ["0"])[0])
        except ValueError:
            v = 0
        return datetime.fromtimestamp(v).astimezone() if v > 0 else None
    since, until = one("since"), one("until")
    if since is None and "hours" in q:
        return since_hours(q, 24), until
    if since is None and default_s:
        since = datetime.now().astimezone() - timedelta(seconds=default_s)
    return since, until


def before(ev, until):
    if until is None:
        return ev
    return [e for e in ev if not e.get("_t") or e["_t"] <= until]


def since_hours(q, default=24):
    try:
        h = float((q.get("hours") or [default])[0])
    except ValueError:
        h = default
    if h <= 0:
        return None
    return datetime.now().astimezone() - timedelta(hours=h)


PHP_FIXED = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
PHP_STATE = {"at": 0.0, "state": None}


def php_state():
    """PHP and php2shell (CVE-2026-109618/109619), as otp's php_state: the version of the command line's
    php, and whether the fix is in - by the number, or (a distribution that backported it keeps the old
    number) by the packages' changelog. Once an hour."""
    if time.time() - PHP_STATE["at"] < 3600 and PHP_STATE["state"] is not None:
        return PHP_STATE["state"]
    import shutil
    import subprocess
    out = {"version": "", "fixed": None, "how": ""}
    php = shutil.which("php") or next((p for p in ("/usr/bin/php", "/usr/local/bin/php") if os.path.exists(p)), None)
    if php:
        try:
            out["version"] = subprocess.run([php, "-r", "echo PHP_VERSION;"], stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, universal_newlines=True,
                                            timeout=10).stdout.strip()[:40]
        except (OSError, subprocess.SubprocessError):
            pass
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", out["version"])
    if m:
        v = tuple(int(x) for x in m.groups())
        want = PHP_FIXED.get("%d.%d" % v[:2])
        if (want and v >= want) or (not want and v[:2] > (8, 5)):
            out.update(fixed=True, how="version")
    if not out["fixed"]:
        said = ""
        rpm = shutil.which("rpm")
        if rpm:
            for pkg in ("php-fpm", "php-common"):
                try:
                    said += subprocess.run([rpm, "-q", "--changelog", pkg], stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, universal_newlines=True, timeout=20).stdout
                except (OSError, subprocess.SubprocessError):
                    pass
        else:
            import glob
            import gzip
            for f in glob.glob("/usr/share/doc/php*-fpm/changelog.Debian.gz") + glob.glob(
                    "/usr/share/doc/php*-common/changelog.Debian.gz"):
                try:
                    with gzip.open(f, "rt", errors="replace") as g:
                        said += g.read(200000)
                except OSError:
                    pass
        if "CVE-2026-109618" in said:
            out.update(fixed=True, how="changelog")
        elif out["version"]:
            out["fixed"] = False
    PHP_STATE.update(at=time.time(), state=out)
    return out


def status_view():
    def make():
        cfg = load_cfg()
        d = guarded(U.status_data, cfg)
        s = d["service"]
        problems = []
        up_now = ON.status()
        if s["state"] != "active":
            if up_now.get("busy"):
                problems.append("fake-igd is being upgraded to %s - fake-igd.service restarts once and is back "
                                "in a moment" % (up_now.get("version") or "a new version"))
            else:
                problems.append("fake-igd.service is %s - nothing on the network is answered (Settings → The "
                                "service, or sudo upnp start)" % s["state"])
        for o in d.get("other_igd") or []:
            problems.append("Another UPnP router is on the network: %s - switch UPnP off on it, or the PS5 may ask "
                            "it instead" % o)
        if d.get("mdns") and d["mdns"].get("state") not in (None, "active"):
            problems.append("avahi-daemon (the mDNS reflector) is %s" % d["mdns"]["state"])
        if cfg.get("_error"):
            problems.append("%s does not read: %s" % (CFG_PATH, cfg["_error"]))
        up = ON.status()
        online = ON.view(STORE[0].meta_json("upgrade:online") or {}, VERSION)
        d.update({"node": socket.gethostname().split(".")[0], "site": cfg.get("site_name") or "",
                  "serial": serial(), "problems": problems, "now": time.time(),
                  "upgrade": {"state": up.get("state"), "busy": up.get("busy"), "version": up.get("version"),
                              "newer": online.get("newer"),
                              "newest": (online.get("newest") or {}).get("version")},
                  "web": {"api_since": STARTED}, "php": php_state()})
        return d
    return cached("status", 2.5, make)


def overview(q):
    since, until = window(q, 86400)
    cfg = load_cfg()
    ev = before(guarded(U.read_events, cfg, since), until)
    end = until.timestamp() if until else time.time()
    if since is None:
        first = min((e["_t"].timestamp() for e in ev if e.get("_t")), default=end - 86400)
        since = datetime.fromtimestamp(first).astimezone()
    start = since.timestamp()
    hours = max(1.0, (end - start) / 3600.0)
    step = 3600 if hours <= 72 else (6 * 3600 if hours <= 24 * 14 else 86400)
    buckets = collections.OrderedDict()
    t = start - (start % step)
    while t <= end:
        buckets[int(t)] = {"at": int(t), "accepted": 0, "rejected": 0, "other": 0}
        t += step
    by_client, by_port, by_action = collections.Counter(), collections.Counter(), collections.Counter()
    for e in ev:
        x = ts(e.get("_t"))
        if x is None:
            continue
        b = buckets.get(int(x - (x % step)))
        act = e.get("action") or "?"
        by_action[act] += 1
        by_client[e.get("client") or "?"] += 1
        if act == "AddPortMapping":
            by_port["%s/%s" % (e.get("external_port"), str(e.get("protocol") or "").lower())] += 1
            kind = "rejected" if str(e.get("result", "")).startswith(("rej", "err", "fail", "conf")) else "accepted"
        else:
            kind = "other"
        if b:
            b[kind] += 1
    searches = 0
    for ln in guarded(U.read_log_lines, cfg, 20000) or []:
        if "is looking for a UPnP device" in ln:
            m = U.LOG_RE.match(ln.rstrip("\n"))
            if m:
                t2 = U.parse_time(m.group(1).replace(" ", "T"))
                if t2 and t2 >= since and (until is None or t2 <= until):
                    searches += 1
    names = U.ptr_names(list(by_client)) if not U.NO_DNS else {}
    return {"hours": hours, "step": step, "chart": list(buckets.values()),
            "requests": len(ev), "add": by_action.get("AddPortMapping", 0), "searches": searches,
            "clients": [{"client": c, "name": names.get(c, ""), "n": n} for c, n in by_client.most_common(10)],
            "ports": [{"port": p, "n": n} for p, n in by_port.most_common(10)],
            "actions": [{"action": a, "n": n} for a, n in by_action.most_common(10)]}


def ports_view(q):
    cfg = load_cfg()
    since, until = window(q)
    ev = before(guarded(U.read_events, cfg, since), until)
    agg = U.aggregate_ports(ev, (q.get("proto") or [None])[0] or None)
    names = U.ptr_names([k[0] for k in agg])
    rows = []
    for (client, proto, port), p in agg.items():
        rows.append({"client": client, "name": names.get(client, ""), "proto": proto, "port": port,
                     "count": p["count"], "first": ts(p["first"]), "last": ts(p["last"]),
                     "description": ", ".join(sorted(p["desc"])),
                     "internal_port": ", ".join(str(x) for x in sorted(p["internal_port"], key=str) if x),
                     "results": dict(p["results"]), "requested_by": sorted(x for x in p["requested_by"] if x)})
    rows.sort(key=lambda r: (r["client"], r["proto"], r["port"]))
    return {"ports": rows}


def requests_view(q):
    cfg = load_cfg()
    since, until = window(q, 86400)
    ev = before(guarded(U.read_events, cfg, since), until)
    want = (q.get("q") or [""])[0].strip().lower()
    act = (q.get("action") or [""])[0]
    rows = []
    for e in reversed(ev):
        if act and e.get("action") != act:
            continue
        row = {k: v for k, v in e.items() if not k.startswith("_")}
        row["at"] = ts(e.get("_t"))
        if want and want not in json.dumps(row, ensure_ascii=False).lower():
            continue
        rows.append(row)
    page, per = pager(q)
    names = U.ptr_names(list({r.get("client") for r in rows[page * per:(page + 1) * per]}))
    out = rows[page * per:(page + 1) * per]
    for r in out:
        r["name"] = names.get(r.get("client"), "")
    actions = sorted({e.get("action") for e in ev if e.get("action")})
    return {"requests": out, "total": len(rows), "page": page, "per": per, "actions": actions}


def pager(q):
    try:
        page = max(0, int((q.get("page") or ["0"])[0]))
        per = max(10, min(1000, int((q.get("per") or ["100"])[0])))
    except ValueError:
        page, per = 0, 100
    return page, per


def mappings_view():
    cfg = load_cfg()
    try:
        with open(os.path.join(cfg["state_dir"], "mappings.json"), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = []
    names = U.ptr_names([m.get("internal_client") for m in data])
    for m in data:
        m["name"] = names.get(m.get("internal_client"), "")
    return {"mappings": data, "now": time.time()}


def log_view(q):
    cfg = load_cfg()
    try:
        n = max(50, min(20000, int((q.get("lines") or ["600"])[0])))
    except ValueError:
        n = 600
    lines = guarded(U.read_log_lines, cfg, n) or []
    want = (q.get("q") or [""])[0][:200]
    if want:
        try:
            # A pattern that may take for ever (nested repeats) is looked for as plain words.
            if re.search(r"[+*}]\)?[+*{]|\)[+*{].*\)[+*{]|\([^)]*[+*][^)]*\)[+*{]", want):
                raise re.error("nested repeats")
            rx = re.compile(want, re.I)
            lines = [x for x in lines if rx.search(x)]
        except re.error:
            lines = [x for x in lines if want.lower() in x.lower()]
    return {"lines": [x.rstrip("\n") for x in lines], "file": cfg["log_file"]}


def dnat_view(q):
    cfg = load_cfg()
    fmt = (q.get("format") or ["iptables"])[0]
    if fmt not in ("iptables", "nft", "mikrotik", "firewalld"):
        raise ValueError("format: iptables, nft, mikrotik or firewalld")
    wan = (q.get("wan") or [""])[0]
    if wan and not re.match(r"^[A-Za-z0-9_.:@-]{1,32}\Z", wan):
        raise ValueError("wan: an interface name")
    argv = ["dnat", "--format", fmt, "--no-color", "--no-dns"] + (["--wan", wan] if wan else [])
    parser, _sp = U.build_parser()
    args = parser.parse_args(argv)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            U.cmd_dnat(args, cfg)
        except SystemExit:
            pass
    return {"text": buf.getvalue(), "format": fmt}


def notify_test(who):
    cfg = load_cfg()
    if not cfg.get("ntfy_url"):
        raise ValueError("ntfy_url is not set - Settings → Notifications (ntfy)")
    import importlib.util
    spec = importlib.util.spec_from_file_location("fake_igd_daemon",
                                                  os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                               "fake-igd.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    good, words = mod.ntfy_send(cfg, "fake-igd test", "A test notification from the fake-igd pages on %s, asked by %s."
                                % (socket.gethostname(), who), tags="white_check_mark")
    return good, "%s - %s" % (mod.ntfy_words(cfg), words)


def upgrade_view():
    here = VERSION
    row = ON.view(STORE[0].meta_json("upgrade:online") or {}, here)
    st = ON.status()
    lines = ON.log_lines(400)
    pc, words = ON.progress(lines) if st.get("busy") else (100 if st.get("state") in ("done", "failed") else 0, "")
    return {"here": here, "url": CFG.get("upgrade_url") or ON.DEFAULT_URL, "check": bool(CFG.get("upgrade_check")),
            "online": row, "status": st, "percent": pc, "words": words, "log": lines[-200:],
            "helper": os.path.exists(ON.HELPER), "path_unit": os.path.exists(ON.PATH_UNIT),
            "package": STORE[0].meta_json("upgrade:pkg")}


# ---- the mDNS reflector (avahi-daemon) ------------------------------------------------
AVAHI_NAMES = {
    "use-ipv4": "mDNS over IPv4", "use-ipv6": "mDNS over IPv6", "allow-interfaces": "Interfaces it uses",
    "deny-interfaces": "Interfaces it never uses", "cache-entries-max": "Records in the cache",
    "ratelimit-interval-usec": "Rate limit: the interval (µs)", "ratelimit-burst": "Rate limit: packets in it",
    "enable-wide-area": "Wide-area browsing (unicast DNS-SD)", "publish-hinfo": "Publish HINFO",
    "publish-workstation": "Publish as a workstation", "disable-publishing": "Publish nothing of this machine",
    "enable-reflector": "The reflector", "reflect-ipv": "Reflect between IPv4 and IPv6",
    "reflect-filters": "Reflect only these service types",
}
AVAHI_PANE_ORDER = ["enable-reflector", "allow-interfaces", "deny-interfaces", "reflect-filters", "reflect-ipv",
                    "use-ipv4", "use-ipv6", "cache-entries-max", "ratelimit-interval-usec", "ratelimit-burst",
                    "enable-wide-area", "publish-hinfo", "publish-workstation", "disable-publishing"]


def mdns_view():
    import upnp_mdns as M
    try:
        st = M.status()
    except M.MdnsError as e:
        return {"installed": False, "error": str(e)}
    vals, _l = M.read_conf()
    eff = M.effective(vals)
    keys = []
    for k in AVAHI_PANE_ORDER:
        sect, kind, words = M.KNOWN[k]
        keys.append({"key": k, "name": AVAHI_NAMES.get(k, k), "says": words,
                     "section": sect, "kind": kind, "bool": kind == "bool",
                     "value": (eff.get(k) == "yes") if kind == "bool" else (eff.get(k) or ""),
                     "default": M.DEFAULT.get(k, ""), "source": "config" if k in vals else "default",
                     "source_says": ("[%s] %s, set in %s" % (sect, k, M.CONF)) if k in vals
                     else "[%s] %s - not set in %s: as avahi has it" % (sect, k, M.CONF)})
    st.update({"installed": True, "keys": keys, "system_interfaces": sorted(M.system_ifaces()),
               "root": root_result()})
    return st


def mdns_services(q):
    import upnp_mdns as M
    try:
        rows = M.services(resolve=(q.get("resolve") or ["1"])[0] != "0", timeout=12)
    except M.MdnsError as e:
        raise ValueError(str(e))
    hint = ""
    if not rows:
        try:
            vals, _l = M.read_conf()
            if str(vals.get("cache-entries-max", "")).strip() == "0":
                hint = ("Nothing seen - cache-entries-max=0: avahi-daemon keeps no record, so avahi-browse is "
                        "shown nothing (the reflector reflects all the same). Settings - mDNS reflector - Records "
                        "in the cache, e.g. 4096, lets it be seen.")
        except M.MdnsError:
            pass
    return {"services": rows, "at": time.time(), "hint": hint}


def mdns_log(q):
    import subprocess
    try:
        n = max(20, min(5000, int((q.get("lines") or ["300"])[0])))
    except ValueError:
        n = 300
    try:
        r = subprocess.run(["journalctl", "-u", "avahi-daemon", "-n", str(n), "--no-pager", "-o", "short-iso"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=20)
        lines = r.stdout.splitlines()
    except (OSError, subprocess.SubprocessError) as e:
        lines = ["journalctl could not be asked: %s" % e]
    return {"lines": lines}


def look_now(who):
    return ON.look(CFG.get("upgrade_url") or ON.DEFAULT_URL, VERSION, STORE[0], who)


# ---- the server ----------------------------------------------------------------------
class Refused(Exception):
    def __init__(self, status, words, code=""):
        Exception.__init__(self, words)
        self.status, self.words, self.code = status, words, code


class Handler(BaseHTTPRequestHandler):
    server_version = "fake-igd-api"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def answer(self, status, data):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def body(self, most=1024 * 1024):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise Refused(400, "Content-Length is not a number")
        if n < 0:
            raise Refused(400, "Content-Length is not a number")
        if n > most:
            raise Refused(413, "that is more than the API takes")
        raw = self.rfile.read(n) if n else b""
        try:
            got = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            raise Refused(400, "the body is not JSON")
        if not isinstance(got, dict):
            raise Refused(400, "the body is not a JSON object")
        return got

    def addr(self):
        a = self.headers.get("X-IGD-Client") or ""
        return a if re.match(r"^[0-9A-Fa-f:.]{2,45}\Z", a) else "?"

    def cli_who(self):
        """root on the command line (upnp api ...), with the key only it may read: a full administrator."""
        got = self.headers.get("X-IGD-Cli") or ""
        if not got or not CLI_TOKEN[0] or not hmac.compare_digest(got.encode(), CLI_TOKEN[0].encode()):
            return None
        name = re.sub(r"[^A-Za-z0-9._@-]", "", self.headers.get("X-IGD-Cli-Who") or "")[:32] or "root"
        return {"name": "%s (command line)" % name, "role": "fulladmin", "must_change": 0, "note": "",
                "source": "cli"}

    def who(self, need=None):
        cli = self.cli_who()
        if cli is not None:
            return cli
        tok = self.headers.get("X-IGD-Session") or ""
        idle = 60 * int(CFG.get("session_idle_minutes") or 120)
        u = STORE[0].session(tok, idle) if tok else None
        if not u:
            raise Refused(401, "not signed in", "signed_out")
        # A password to change at sign-in is changed first (otp's MUST_CHANGE_ALLOWED): until then
        # the sign-in may change it, sign out and say who it is - nothing else, here as on the pages.
        if u.get("must_change") and urlparse(self.path).path not in MUST_CHANGE_ALLOWED:
            raise Refused(403, "change the password first", "must_change")
        if need == "fulladmin" and u["role"] != "fulladmin":
            raise Refused(403, "this account may look, not change (read only)", "read_only")
        return u

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        try:
            if not hmac.compare_digest((self.headers.get("X-IGD-Token") or "").encode(), TOKEN[0].encode()):
                raise Refused(403, "no API token - only the pages may ask")
            u = urlparse(self.path)
            q = parse_qs(u.query)
            load_cfg()
            self.answer(200, self.serve(method, u.path, q))
        except Refused as e:
            self.answer(e.status, {"ok": False, "error": e.words, "code": e.code})
        except ValueError as e:
            self.answer(400, {"ok": False, "error": str(e)})
        except ST.StoreError as e:
            self.answer(400, {"ok": False, "error": str(e)})
        except Exception as e:                          # noqa: BLE001 - said, logged, never a dead page
            sys.stderr.write("api: %s %s: %s\n%s" % (method, self.path, e, traceback.format_exc()))
            self.answer(500, {"ok": False, "error": "the API broke on that: %s" % e})

    def serve(self, method, path, q):
        S = STORE[0]
        hit = PN.route(method, path)
        if hit is not None:
            mod, fn = hit
            me = None
            if not getattr(fn, "PUBLIC", False):
                me = self.who()
            ctx = PN.Ctx(self, method, path, q, me, S, CFG, mod, S.add_event)
            try:
                got = fn(ctx)
            except PermissionError as e:
                raise Refused(403, str(e), "read_only")
            if isinstance(got, dict):
                got.setdefault("ok", True)
            return got
        if path == "/api/health":
            return {"ok": True, "version": VERSION, "users": S.count_users(), "database": {"ok": S.ok()},
                    "site": CFG.get("site_name") or "", "node": socket.gethostname().split(".")[0]}
        if path == "/api/auth/login" and method == "POST":
            b = self.body()
            try:
                token, usr = S.login(b.get("name"), str(b.get("password") or ""), self.addr(),
                                     self.headers.get("User-Agent") or "",
                                     60 * int(CFG.get("session_idle_minutes") or 120))
            except ST.StoreError as e:
                S.add_event("sign-in", "%s could not sign in: %s" % (str(b.get("name") or "?")[:64], e), "warn",
                            str(b.get("name") or "")[:64], self.addr())
                raise Refused(401, str(e), "refused")
            S.add_event("sign-in", "%s signed in" % usr["name"], "info", usr["name"], self.addr())
            return {"ok": True, "token": token, "must_change": bool(usr["must_change"])}
        if path == "/api/auth/logout" and method == "POST":
            tok = self.headers.get("X-IGD-Session") or ""
            u = S.session(tok, touch=False)
            if u:
                S.logout(tok)
                S.add_event("sign-in", "%s signed out" % u["name"], "info", u["name"], self.addr())
            return {"ok": True}
        if path == "/api/auth/whoami":
            try:
                u = self.who()
            except Refused:
                return {"ok": True, "who": None}
            return {"ok": True, "who": {"name": u["name"], "role": u["role"],
                                        "role_words": ST.ROLE_WORDS.get(u["role"]),
                                        "must_change": bool(u["must_change"]), "note": u["note"]}}
        me = self.who()
        if path == "/api/auth/passwd" and method == "POST":
            b = self.body()
            full = S.user(me["name"])
            if not ST.check_password(str(b.get("old") or ""), full["hash"]):
                raise Refused(400, "the password now is not that")
            S.set_password(me["name"], str(b.get("new") or ""))
            S.add_event("account", "%s changed their own password" % me["name"], "info", me["name"], self.addr())
            return {"ok": True, "message": "your password is changed"}
        if path == "/api/status":
            return status_view()
        if path == "/api/overview":
            return overview(q)
        if path == "/api/ports":
            return ports_view(q)
        if path == "/api/requests":
            return requests_view(q)
        if path == "/api/clients":
            since, until = window(q)
            rows = guarded(U.clients_data, load_cfg(), since)
            if until is not None:
                rows = [c for c in rows if not c.get("last") or datetime.fromisoformat(c["last"]) <= until]
            return {"clients": rows}
        if path == "/api/mappings":
            return mappings_view()
        if path == "/api/log":
            return log_view(q)
        if path == "/api/dnat":
            return dnat_view(q)
        if path == "/api/events":
            page, per = pager(q)
            since, until = window(q)
            want = (q.get("kind") or [""])[0]
            raw = [k for k in S.events("", "", 0, 1, 0)["kinds"] if event_group(k) == want] if want else ""
            if want and not raw:
                raw = [want]                     # an old link with a raw kind still filters
            d = S.events((q.get("q") or [""])[0], raw,
                         since.timestamp() if since else 0, per, page * per,
                         until.timestamp() if until else 0)
            for r in d["events"]:
                r["kind_raw"], r["kind"] = r["kind"], event_group(r["kind"])
            d["kinds"] = sorted({event_group(k) for k in d["kinds"]})
            d.update({"page": page, "per": per})
            return d
        if path == "/api/settings" and method == "GET":
            d = settings_view(full=me["role"] == "fulladmin")
            d["root"] = root_result()
            return d
        if path == "/api/settings" and method == "POST":
            self.who("fulladmin")
            d = settings_save(self.body().get("changes"), me["name"], self.addr(), self)
            d["ok"] = True
            # otp's words: how many were saved, and what follows from it.
            d["message"] = " ".join(["%d setting(s) saved." % len(d["saved"])] + (
                ["fake-igd.service is restarted with them."] if d.get("restart") else []) + (
                ["Root puts nginx's allow list and the firewall in place."] if d.get("root") else []))
            return d
        if path == "/api/apply" and method == "POST":
            self.who("fulladmin")
            b = self.body()
            ident = ask_root(restart=b.get("restart") is True)
            S.add_event("service", "%s asked root to %s" % (
                me["name"], "restart fake-igd.service" if b.get("restart") is True
                else "put nginx's allow list and the firewall in place"), "info", me["name"], self.addr())
            return {"ok": True, "id": ident}
        if path == "/api/mdns" and method == "GET":
            return mdns_view()
        if path == "/api/mdns/services":
            return mdns_services(q)
        if path == "/api/mdns/log":
            return mdns_log(q)
        if path == "/api/mdns" and method == "POST":
            self.who("fulladmin")
            import upnp_mdns as M
            b = self.body()
            changes = b.get("changes") or {}
            action = str(b.get("action") or "")
            if not isinstance(changes, dict) or (not changes and action not in ("restart", "start", "stop",
                                                                                   "enable", "disable")):
                raise ValueError("nothing to do")
            sysif = M.system_ifaces()
            clean = {}
            for k, v in changes.items():
                if isinstance(v, bool):
                    v = "yes" if v else "no"
                try:
                    clean[k] = M.check(k, v, sysif)
                except M.MdnsError as e:
                    raise ValueError(str(e))
            ident = ask_root(extra={"avahi": clean, "avahi_action": action})
            S.add_event("mdns", "%s asked root: %s" % (me["name"], ", ".join(
                ["%s=%s" % (k, v or "(as it comes)") for k, v in clean.items()] + ([action] if action else []))),
                "info", me["name"], self.addr())
            return {"ok": True, "id": ident, "message": "asked root - avahi-daemon is changed in a moment"}
        if path == "/api/root-result":
            return {"ok": True, "result": root_result()}
        if path == "/api/notify-test" and method == "POST":
            self.who("fulladmin")
            good, words = notify_test(me["name"])
            S.add_event("notify", "%s sent a test notification: %s" % (me["name"], words),
                        "info" if good else "warn", me["name"], self.addr())
            if not good:
                raise ValueError(words)
            return {"ok": True, "message": words}
        if path == "/api/users" and method == "GET":
            return {"users": S.users(), "sessions": S.sessions() if me["role"] == "fulladmin" else [],
                    "me": me["name"], "roles": [{"role": r, "words": ST.ROLE_WORDS[r]} for r in ST.ROLES]}
        if path == "/api/users" and method == "POST":
            self.who("fulladmin")
            return self.users_post(self.body(), me)
        if path == "/api/upgrade" and method == "GET":
            return upgrade_view()
        if path == "/api/upgrade" and method == "POST":
            self.who("fulladmin")
            return self.upgrade_post(self.body(), me)
        if path == "/api/upgrade-package" and method == "POST":
            self.who("fulladmin")
            b = self.body(most=96 * 1024 * 1024)
            try:
                data = base64.b64decode(str(b.get("data") or ""), validate=True)
            except ValueError:
                raise ValueError("the package did not come whole")
            info = ON.take_bytes(data)
            meta = {k: info.get(k) for k in ("version", "sha", "signed_by", "files", "bytes", "changelog",
                                              "installed", "newer", "older", "file", "from")}
            meta.update({"by": me["name"], "at": time.time()})
            S.set_meta("upgrade:pkg", json.dumps(meta))
            S.add_event("upgrade", "%s sent fake-igd %s (signed by %s)" % (me["name"], info["version"],
                                                                            info.get("signed_by")),
                        "info", me["name"], self.addr())
            return {"ok": True, "package": meta}
        raise Refused(404, "no such question: %s" % path)

    def users_post(self, b, me):
        S = STORE[0]
        act = b.get("action")
        name = str(b.get("name") or "").strip()
        if act == "add":
            pw = str(b.get("password") or "")
            made = ""
            if not pw:
                pw = made = secrets.token_urlsafe(12)
            S.add_user(name, pw, b.get("role") or "readonly", b.get("note") or "")
            S.add_event("account", "%s made the account %s (%s)" % (me["name"], name, b.get("role") or "readonly"),
                        "info", me["name"], self.addr())
            return {"ok": True, "message": "%s may sign in" % name, "password": made}
        if act == "passwd":
            pw = str(b.get("password") or "")
            made = ""
            if not pw:
                pw = made = secrets.token_urlsafe(12)
            S.set_password(name, pw)
            S.add_event("account", "%s gave %s a new password" % (me["name"], name), "info", me["name"], self.addr())
            return {"ok": True, "message": "%s has a new password" % name, "password": made}
        if act == "role":
            S.set_role(name, str(b.get("role") or ""))
            S.add_event("account", "%s made %s %s" % (me["name"], name, ST.ROLE_WORDS.get(b.get("role"))),
                        "info", me["name"], self.addr())
            return {"ok": True, "message": "%s is %s" % (name, ST.ROLE_WORDS.get(b.get("role")))}
        if act == "note":
            S.set_note(name, b.get("note") or "")
            return {"ok": True, "message": "kept"}
        if act == "delete":
            if name.lower() == me["name"].lower():
                raise ValueError("an account does not take itself away - another full admin does")
            S.delete_user(name)
            S.add_event("account", "%s took the account %s away" % (me["name"], name), "warn", me["name"],
                        self.addr())
            return {"ok": True, "message": "%s is gone" % name}
        if act == "end-session":
            S.end_session(str(b.get("id") or ""))
            S.add_event("account", "%s ended a sign-in" % me["name"], "info", me["name"], self.addr())
            return {"ok": True, "message": "that sign-in is over"}
        raise ValueError("no such action")

    def upgrade_post(self, b, me):
        S = STORE[0]
        act = b.get("action")
        if act == "look":
            row = look_now(me["name"])
            if row.get("error"):
                raise ValueError("%s: %s" % (row.get("url"), row["error"]))
            return {"ok": True, "online": ON.view(row, VERSION)}
        if act in ("online", "fetch"):
            want = str(b.get("version") or "")
            row = look_now(me["name"])
            if row.get("error"):
                raise ValueError("%s: %s" % (row.get("url"), row["error"]))
            pk = row.get("newest") if not want else next(
                (x for x in row.get("packages") or [] if x["version"] == want), None)
            if not pk:
                raise ValueError("fake-igd %s is not at %s" % (want or "", row.get("url")))
            info = ON.fetch(row["url"], pk["version"], VERSION)
            meta = {k: info.get(k) for k in ("version", "sha", "signed_by", "files", "bytes", "changelog",
                                              "installed", "newer", "older", "file", "from")}
            meta.update({"by": me["name"], "at": time.time()})
            S.set_meta("upgrade:pkg", json.dumps(meta))
            S.add_event("upgrade", "%s fetched fake-igd %s from %s (signed by %s)" % (
                me["name"], info["version"], info.get("from"), info.get("signed_by")), "warn", me["name"],
                self.addr())
            if act == "fetch":
                return {"ok": True, "package": meta, "message": "fake-igd %s fetched and checked" % info["version"]}
            act = "start"
        if act == "start":
            meta = S.meta_json("upgrade:pkg")
            if not meta or not meta.get("file") or not os.path.exists(meta["file"]):
                raise ValueError("no package is waiting - fetch one or send one first")
            ident = ON.ask_root(meta, me["name"])
            S.add_event("upgrade", "%s started the upgrade to fake-igd %s" % (me["name"], meta["version"]), "warn",
                        me["name"], self.addr())
            return {"ok": True, "id": ident, "message": "root puts fake-igd %s in - the pages may be away for a "
                    "moment while it restarts them" % meta["version"]}
        if act == "forget":
            meta = S.meta_json("upgrade:pkg") or {}
            if meta.get("file"):
                try:
                    os.unlink(meta["file"])
                except OSError:
                    pass
            S.set_meta("upgrade:pkg", "")
            return {"ok": True, "message": "the package is forgotten"}
        raise ValueError("no such action")


def write_run_files(port):
    """The token and the port, for the pages: this account's and the pages' group's alone."""
    os.makedirs(RUN_DIR, exist_ok=True)
    try:
        gid = grp.getgrnam(WEB_GROUP).gr_gid
        os.chown(RUN_DIR, -1, gid)
        os.chmod(RUN_DIR, 0o750)
    except (KeyError, OSError):
        gid = None
    for name, text, mode in ((TOKEN_FILE, TOKEN[0], 0o640), (PORT_FILE, str(port), 0o640),
                             (CLI_FILE, CLI_TOKEN[0], 0o600)):
        tmp = name + ".new"
        try:
            os.unlink(tmp)
        except OSError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text + "\n")
        if gid is not None and mode & 0o040:
            try:
                os.chown(tmp, -1, gid)
            except OSError:
                pass
        os.chmod(tmp, mode)
        os.replace(tmp, name)


BG = {"threads": {}, "said": {}}


def _bg_say(name, words):
    """A part of the background that went wrong, written to the journal - once until it says something else."""
    if BG["said"].get(name) != words:
        BG["said"][name] = words
        sys.stderr.write("api: %s in the background: %s\n" % (name, words))


def _bg_one(name, fn):
    try:
        fn()
        BG["said"].pop(name, None)
    except SystemExit as e:                             # the command line's readers end the program: not here
        _bg_say(name, "a file it reads could not be read (%s)" % (e.code or "permission"))
    except Exception as e:                              # noqa: BLE001 - one part does not stop the rest
        _bg_say(name, "%s: %s" % (type(e).__name__, e))


def background():
    """Once a minute: old sign-ins away; once a day: a look at upgrade_url; each pane's background().
    Each part on its own (1.7.5): one that raises does not skip the others, and a pane whose background
    still runs from the minute before (a server that does not answer) is not started again beside itself,
    nor does it hold up the rest - every pane's runs in a thread of its own."""
    while True:
        _bg_one("sign-ins", lambda: STORE[0].tidy_sessions(60 * int(CFG.get("session_idle_minutes") or 120)))
        _bg_one("settings", load_cfg)

        def look():
            if CFG.get("upgrade_check"):
                last = STORE[0].meta_json("upgrade:online") or {}
                url = CFG.get("upgrade_url") or ON.DEFAULT_URL
                if last.get("url") != url or time.time() - float(last.get("at") or 0) > ON.EVERY_S:
                    look_now("")
        _bg_one("upgrade look", look)
        for mod in PN.MODULES:
            if not hasattr(mod, "background"):
                continue
            name = getattr(mod, "NAME", "?")
            was = BG["threads"].get(name)
            if was is not None and was.is_alive():
                _bg_say(name, "still busy with the minute before - not started again")
                continue

            def run(mod=mod, name=name):
                _bg_one(name, lambda: mod.background(PN.Ctx(None, "BG", "", {}, None, STORE[0], CFG, mod,
                                                            STORE[0].add_event)))
            t = threading.Thread(target=run, name="bg-%s" % name, daemon=True)
            BG["threads"][name] = t
            t.start()
        time.sleep(60)


def main():
    global CFG_PATH
    ap = argparse.ArgumentParser(description="fake-igd - the API of the web pages (127.0.0.1)")
    ap.add_argument("--config", default=U.DEFAULT_CONFIG)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--version", action="version", version="fake-igd-api " + VERSION)
    args = ap.parse_args()
    CFG_PATH = args.config
    cfg = load_cfg(force=True)
    U.NO_DNS = bool(os.environ.get("FAKE_IGD_NO_DNS"))
    db = os.environ.get("FAKE_IGD_DB") or os.path.join(cfg["state_dir"], "fake-igd.db")
    STORE[0] = ST.Store(db)
    TOKEN[0] = secrets.token_urlsafe(32)
    CLI_TOKEN[0] = secrets.token_urlsafe(32)
    port = args.port or int(cfg.get("api_port") or 9862)
    try:
        ThreadingHTTPServer.request_queue_size = 128     # a burst of the pages' requests is queued, not reset
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        sys.stderr.write("api: 127.0.0.1:%d cannot be opened: %s\n" % (port, e))
        return 1
    httpd.daemon_threads = True
    write_run_files(port)
    PN.load(log=lambda w: sys.stderr.write(w + "\n"))
    threading.Thread(target=background, daemon=True).start()
    threading.Thread(target=php_state, daemon=True).start()     # rpm -q --changelog is slow: asked ahead
    STORE[0].add_event("service", "the pages' API %s started on 127.0.0.1:%d" % (VERSION, port), "info")
    sys.stderr.write("api: fake-igd %s - the pages' API on 127.0.0.1:%d, database %s\n" % (VERSION, port, db))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
