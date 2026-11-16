"""api_about.py - Settings → About and Settings → The service (1.6.1; otp's pane-about, its
/api/software and /api/load, and otp's nodes / maintenance card for the units).

About, as otp's drawAbout: the version and how long fake-igd.service has run, what it answers
on and what it was asked, the console at login (root's line of /etc/upnp-console-login - the
normal users' line is the same file, shown here and in Local users), what it runs on (the
program, its Python and the libraries under it, the pages' nginx and PHP - php-fpm's own, the
system), the README and the CHANGELOG of what runs, and its settings: the performance meter in
the header (perf_meter, otp's /api/load - readings of /proc and /sys only while a page looks)
and the debug log (what the API does, into its journal).

The service, fake-igd's own (otp has the nodes instead): each unit fake-igd lives on -
fake-igd.service, fake-igd-api.service, nginx, php-fpm, avahi-daemon and the two path units
root's part hangs on - its state, since when, its restarts and memory, the last lines of its
journal; Restart / Stop / Start of the units that may be, asked of root through the queue
(deploy/root_service.py - those units and nothing else), what root did as otp's bands.

  GET  /api/about                    the state, the facts, the console at login
  GET  /api/about/software           what it runs on (otp's /api/software, one node)
  GET  /api/about/doc?name=readme|changelog
  POST /api/about/console {on, users}           root's line and the normal users (root asked)
  GET  /api/load[?since=&detail=1&keep=]        the performance meter (otp's)
  GET  /api/service                  the units, root's last answers, what was done lately
  GET  /api/service/journal?unit=&lines=
  POST /api/service {action: restart|stop|start|reload, unit} | {action: done|clear, id}
"""
import glob
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

import igd_panes as PN

NAME = "about"
HERE = os.path.dirname(os.path.abspath(__file__))
CONSOLE_FLAG = os.environ.get("UPNP_CONSOLE_FLAG", "/etc/upnp-console-login")
CONSOLE_PROFILE = os.environ.get("UPNP_CONSOLE_PROFILE", "/etc/profile.d/zz-upnp-console.sh")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")

SETTINGS = [
    {"key": "perf_meter", "name": "The performance meter in the header", "kind": "bool", "default": False,
     "pane": "about",
     "says": "How busy the server is - the processor, the memory, the disks and the network - beside the "
             "state at the top of every page, for full administrators; pointed at, each part shows its "
             "details. Off, nothing is read or written for it."},
    {"key": "debug", "name": "Debug log", "kind": "bool", "default": False, "pane": "about",
     "says": "Write more into the journal of fake-igd-api (<code>journalctl -u fake-igd-api</code>): what "
             "the panes ask root and what root answered. Loud: for finding something out, not for leaving "
             "on. What fake-igd.service writes is its log level (Settings → Logs and state)."},
    {"key": "debug_api", "name": "...every API call", "kind": "bool", "default": True, "pane": "about",
     "only_when": ("debug", "true"),
     "says": "Every API call the web pages make: the road, who asked and how long it took. Never a "
             "password, a token or what was sent."},
]


# ==== the debug log (otp's debug, debug_api) ==================================================
DEBUG = {"on": False, "api": False}


def _debug_read(store):
    try:
        DEBUG["on"] = bool(PN.value(store, "debug"))
        DEBUG["api"] = DEBUG["on"] and bool(PN.value(store, "debug_api"))
    except Exception:                                   # noqa: BLE001 - never in the way
        pass


def _say(words):
    try:
        sys.stderr.write("debug: %s\n" % words)
        sys.stderr.flush()
    except Exception:                                   # noqa: BLE001
        pass


def _wrap_route():
    """Every road asked of the API, while debug_api is on - igd_panes.route is asked first for each."""
    if getattr(PN.route, "_about", False):
        return
    plain_route, plain_ask = PN.route, PN.ask_root

    def route(method, path):
        hit = plain_route(method, path)
        if not DEBUG["api"]:
            return hit
        if hit is None:
            _say("api: %s %s" % (method, path))
            return None
        mod, fn = hit

        def timed(ctx):
            t0 = time.monotonic()
            ok = "answered"
            try:
                return fn(ctx)
            except Exception as e:                      # noqa: BLE001 - said, then on as it was
                ok = "refused: %s" % str(e)[:120]
                raise
            finally:
                _say("api: %s %s by %s from %s - %s in %d ms" % (
                    method, path, (ctx.me or {}).get("name", "-"), ctx.addr or "-", ok,
                    (time.monotonic() - t0) * 1000))
        timed.PUBLIC = getattr(fn, "PUBLIC", False)
        return mod, timed

    def ask_root(state_dir, kind, payload, by=""):
        ident = plain_ask(state_dir, kind, payload, by)
        if DEBUG["on"]:
            what = payload.get("do") or payload.get("action") if isinstance(payload, dict) else None
            _say("root asked: %s%s by %s (%s)" % (kind, " " + str(what)[:40] if what else "", by or "-", ident))
        return ident

    route._about = True
    PN.route, PN.ask_root = route, ask_root


_wrap_route()


def on_saved(ctx, changed):
    _debug_read(ctx.store)
    for k, v in changed.items():
        if k in ("debug", "debug_api", "perf_meter"):
            ctx.event("%s: %s" % ({"debug": "the debug log", "debug_api": "the debug log of every API call",
                                   "perf_meter": "the performance meter"}[k], "on" if v else "off"),
                      "warn" if k == "debug" and v else "info")


def background(ctx):
    _debug_read(ctx.store)
    lately_settle(ctx)


# ==== small things =============================================================================
def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                           timeout=timeout)
        return r.returncode, r.stdout or ""
    except (OSError, subprocess.SubprocessError) as e:
        return -1, str(e)


def first_line(cmd, timeout=5):
    rc, out = run(cmd, timeout)
    return (out.strip().splitlines() or [""])[0].strip()[:200] if rc != -1 else ""


def which(name):
    return shutil.which(name) or next((p for p in ("/usr/sbin/" + name, "/sbin/" + name, "/usr/bin/" + name)
                                       if os.path.exists(p)), None)


def mono_to_epoch(us):
    """systemd's ...TimestampMonotonic (µs of CLOCK_MONOTONIC) as seconds since 1970; None for 0."""
    try:
        us = int(us)
    except (TypeError, ValueError):
        return None
    if us <= 0:
        return None
    return time.time() - (time.monotonic() - us / 1e6)


def cached(store, key, ttl, make):
    hit = CACHE.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    v = make()
    CACHE[key] = (time.time(), v)
    return v


CACHE = {}


def _upnp():
    import upnp as U
    return U


# ==== the units ================================================================================
# unit -> (what it is, what may be done to it). Root's module has the same list (root_service.py).
UNITS = [
    ("fake-igd.service", "fake-igd itself: SSDP and the description and SOAP - what the PS5 asks",
     ("restart", "stop", "start")),
    ("fake-igd-api.service", "the API of these pages, on 127.0.0.1 - its own account, sandboxed",
     ("restart",)),
    ("nginx.service", "the web server in front of these pages: TLS, who may reach them",
     ("reload", "restart")),
    ("php-fpm.service", "PHP for these pages - it only relays them to the API", ("restart",)),
    ("avahi-daemon.service", "mDNS, and its reflector between the networks (Settings → mDNS)",
     ("restart", "stop", "start")),
    ("fake-igd-web.path", "starts fake-igd-web.service, root's part of what the pages ask", ()),
    ("fake-igd-upgrade.path", "starts fake-igd-upgrade.service, an upgrade sent from the pages", ()),
]
UNIT_NAMES = [u[0] for u in UNITS]
TRIGGERS = {"fake-igd-web.path": "fake-igd-web.service", "fake-igd-upgrade.path": "fake-igd-upgrade.service"}
PROPS = ("Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "NRestarts",
         "MemoryCurrent", "TasksCurrent", "CPUUsageNSec", "ActiveEnterTimestampMonotonic",
         "InactiveEnterTimestampMonotonic", "ExecMainStartTimestampMonotonic",
         "ExecMainExitTimestampMonotonic", "ExecMainStatus", "Result", "FragmentPath")
NOT_SET = ("", "[not set]", "18446744073709551615")


def sd_show(units):
    """{unit: {prop: value}} - one systemctl for all of them (it answers a user as well as root)."""
    rc, out = run(["systemctl", "show", "--no-pager", "-p", ",".join(PROPS)] + list(units), 15)
    got, cur, i = {}, {}, 0
    blocks = re.split(r"\n\s*\n", out.strip()) if out.strip() else []
    for b in blocks:
        cur = {}
        for ln in b.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                cur[k] = v
        name = cur.get("Id") or (units[i] if i < len(units) else "")
        if i < len(units):
            got[units[i]] = cur
        else:
            got[name] = cur
        i += 1
    return got, (out.strip() if rc != 0 and not got else "")


def _int(v):
    if v in NOT_SET or v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def unit_row(name, what, can, p, trig=None):
    state = p.get("ActiveState") or "unknown"
    load = p.get("LoadState") or "?"
    since = mono_to_epoch(p.get("ActiveEnterTimestampMonotonic") if state in ("active", "reloading")
                          else p.get("InactiveEnterTimestampMonotonic"))
    row = {"unit": name, "what": what, "description": p.get("Description") or "", "load": load,
           "state": state if load != "not-found" else "not installed", "sub": p.get("SubState") or "",
           "boot": p.get("UnitFileState") or "", "pid": _int(p.get("MainPID")) or None,
           "restarts": _int(p.get("NRestarts")), "memory": _int(p.get("MemoryCurrent")),
           "tasks": _int(p.get("TasksCurrent")), "cpu_s": (_int(p.get("CPUUsageNSec")) or 0) / 1e9 or None,
           "since": since, "result": p.get("Result") or "", "file": p.get("FragmentPath") or "",
           "can": [a for a in can if load != "not-found"]}
    if trig is not None:
        ran = mono_to_epoch(trig.get("InactiveEnterTimestampMonotonic"))
        row["triggers"] = {"unit": TRIGGERS.get(name), "state": trig.get("ActiveState") or "",
                           "result": trig.get("Result") or "", "ran": ran,
                           "status": _int(trig.get("ExecMainStatus"))}
    return row


def units_view():
    want = UNIT_NAMES + list(TRIGGERS.values())
    got, err = sd_show(want)
    rows = []
    for name, what, can in UNITS:
        rows.append(unit_row(name, what, can, got.get(name) or {}, got.get(TRIGGERS[name]) if name in TRIGGERS
                             else None))
    return rows, err


def journal(units, n):
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "-n", str(n)]
    for u in units:
        cmd += ["-u", u]
    rc, out = run(cmd, 20)
    lines = out.splitlines()
    if rc == -1:
        lines = ["journalctl could not be asked: %s" % out.strip()]
    return lines


# ==== what root did (the bands and Done lately) ===============================================
LATELY_KEY = "service:lately"
LATELY_MOST = 40
DONE_WORDS = {"restart": "restarted", "stop": "stopped", "start": "started", "reload": "reloaded",
              "console": "the console at login set"}


def lately_load(store):
    try:
        got = json.loads(store.get_meta(LATELY_KEY) or "[]")
    except (ValueError, TypeError):
        got = []
    return [x for x in got if isinstance(x, dict)] if isinstance(got, list) else []


def lately_save(store, rows):
    store.set_meta(LATELY_KEY, json.dumps(rows[-LATELY_MOST:]))


def lately_settle(ctx):
    """Root's last answer put to the ask it answers; an ask older than an answered one and never
    answered is said to be so."""
    rows = lately_load(ctx.store)
    if not rows:
        return rows
    r = ctx.root_result("service")
    changed = False
    rid = str(r.get("id") or "")
    for x in rows:
        if x.get("state") != "asked":
            continue
        if rid and x.get("id") == rid:
            x.update({"state": "done" if r.get("ok") else "failed", "ok": bool(r.get("ok")),
                      "said": [str(s)[:400] for s in (r.get("said") or [])][:12],
                      "now": r.get("now") or "", "done_at": r.get("at")})
            ctx.event("root: %s %s - %s" % (x.get("unit") or x.get("do"), "done" if r.get("ok") else "FAILED",
                                            "; ".join(x["said"])[:600]),
                      "info" if r.get("ok") else "warn", kind="service")
            changed = True
        elif rid and x.get("id", "") < rid and r.get("at") and float(r.get("at") or 0) > float(x.get("at") or 0) + 1:
            x.update({"state": "unknown", "said": ["root's answer to this was not seen (another came after it)"]})
            changed = True
        elif time.time() - float(x.get("at") or 0) > 600:
            x.update({"state": "unknown", "said": ["root did not answer in ten minutes - is fake-igd-web.path running?"]})
            changed = True
    if changed:
        lately_save(ctx.store, rows)
    return rows


def lately_add(ctx, ident, do, unit, extra=None):
    rows = lately_load(ctx.store)
    one = {"id": ident, "do": do, "unit": unit, "by": (ctx.me or {}).get("name", ""), "at": time.time(),
           "state": "asked", "seen": False}
    if extra:
        one.update(extra)
    rows.append(one)
    lately_save(ctx.store, rows)
    return one


def what_words(x):
    if x.get("do") == "console":
        return "The console at login"
    return "%s %s" % (x.get("unit") or "?", {"restart": "restart", "stop": "stop", "start": "start",
                                             "reload": "reload"}.get(x.get("do"), x.get("do") or ""))


def lately_view(rows):
    bands, done = [], []
    for x in reversed(rows):
        st = x.get("state")
        how = {"asked": "waiting for root", "done": DONE_WORDS.get(x.get("do"), "done"), "failed": "failed",
               "unknown": "not known"}.get(st, st or "")
        one = {"id": x.get("id"), "title": what_words(x), "how": how, "who": x.get("by") or "", "at": x.get("at"),
               "done_at": x.get("done_at"), "said": x.get("said") or [], "unit": x.get("unit") or "",
               "do": x.get("do"), "state": st, "now": x.get("now") or ""}
        if not x.get("seen"):
            bands.append(one)
        done.append(one)
    return bands[:6], done


# ==== the routes: The service =================================================================
def service_get(ctx):
    ctx.need("readonly")
    rows, err = units_view()
    lately = lately_settle(ctx)
    bands, done = lately_view(lately)
    folder = PN.ask_folder(ctx.cfg.get("state_dir"))
    waiting = len(glob.glob(os.path.join(folder, "service-*.json")))
    return {"units": rows, "error": err, "bands": bands, "lately": done, "waiting": waiting,
            "node": socket.gethostname().split(".")[0], "now": time.time(),
            "api": {"since": _api_since(), "pid": os.getpid()}}


def _api_since():
    main = sys.modules.get("__main__")
    return getattr(main, "STARTED", None)


def service_journal(ctx):
    ctx.need("readonly")
    unit = ctx.arg("unit")
    if unit not in UNIT_NAMES:
        raise ValueError("no such unit here")
    try:
        n = max(20, min(2000, int(ctx.arg("lines", "200"))))
    except ValueError:
        n = 200
    units = [unit] + ([TRIGGERS[unit]] if unit in TRIGGERS else [])
    return {"unit": unit, "units": units, "lines": journal(units, n)}


def service_post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    if act in ("done", "clear"):
        rows = lately_load(ctx.store)
        if act == "done":
            ident = str(b.get("id") or "")
            for x in rows:
                if x.get("id") == ident or ident == "*":
                    x["seen"] = True
            lately_save(ctx.store, rows)
            return dict(service_get(ctx), message="taken off")
        keep = [x for x in rows if x.get("state") == "asked"]
        lately_save(ctx.store, keep)
        ctx.event("%s cleared the list of what root did with the units" % ctx.me.get("name", ""), kind="service")
        return dict(service_get(ctx), message="cleared")
    unit = str(b.get("unit") or "")
    can = {u[0]: u[2] for u in UNITS}
    if unit not in can:
        raise ValueError("no such unit here")
    if act not in can[unit]:
        raise ValueError("%s is not %s from these pages" % (unit, {"stop": "stopped", "start": "started",
                                                                  "restart": "restarted",
                                                                  "reload": "reloaded"}.get(act, "changed so")))
    ident = ctx.ask_root({"do": act, "unit": unit}, kind="service")
    lately_add(ctx, ident, act, unit)
    ctx.event("%s asked root to %s %s" % (ctx.me.get("name", ""), act, unit),
              "warn" if act in ("stop", "restart") else "info", kind="service")
    return {"id": ident, "message": "asked root - within a few seconds"}


# ==== the routes: About ========================================================================
def counts(cfg):
    U = _upnp()
    try:
        ev = U.read_events(cfg)
    except Exception:                                   # noqa: BLE001
        ev = []
    by = {}
    clients, ports = set(), set()
    for e in ev:
        a = e.get("action") or "?"
        by[a] = by.get(a, 0) + 1
        clients.add(e.get("client"))
        if a == "AddPortMapping":
            ports.add((e.get("client"), str(e.get("protocol") or "").lower(), e.get("external_port")))
    try:
        with open(os.path.join(cfg.get("state_dir") or "/var/lib/fake-igd", "mappings.json"), encoding="utf-8") as f:
            nmap = len(json.load(f))
    except (OSError, ValueError, TypeError):
        nmap = 0
    return {"actions": by, "requests": len(ev), "clients": len([c for c in clients if c]), "ports": len(ports),
            "mappings": nmap}


def console_read():
    try:
        fd = os.open(CONSOLE_FLAG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False, [], False
    try:
        import stat
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False, [], False
        text = os.read(fd, 8192).decode("utf-8", "replace")
    finally:
        os.close(fd)
    lines = text.split("\n")
    users = []
    for ln in lines[1:]:
        if ln.startswith("users:"):
            words = ln[6:].split()
            users = "*" if words == ["*"] else [w for w in words if USER_RE.match(w)][:200]
    return lines[0].strip() == "on", users, True


def console_view(ctx):
    on, users, there = console_read()
    pend = [x for x in lately_load(ctx.store) if x.get("do") == "console" and x.get("state") == "asked"]
    r = ctx.root_result("service")
    err = ""
    last = [x for x in lately_load(ctx.store) if x.get("do") == "console"]
    if last and last[-1].get("state") == "failed":
        err = "; ".join(last[-1].get("said") or [])
    # the normal users who may sign in, as Local users read them (root_osusers' last list)
    names = [u.get("name") for u in (ctx.root_result("osusers").get("users") or [])
             if isinstance(u, dict) and u.get("login") and not u.get("root") and u.get("name")]
    return {"name": socket.gethostname().split(".")[0], "me": True, "on": on, "users": users, "there": there,
            "pending": bool(pend), "error": err, "file": CONSOLE_FLAG,
            "profile": os.path.exists(CONSOLE_PROFILE), "accounts": names, "at": r.get("at")}


def about_get(ctx):
    ctx.need("readonly")
    _debug_read(ctx.store)
    U = _upnp()
    cfg = ctx.cfg
    sv = (sd_show(["fake-igd.service"])[0] or {}).get("fake-igd.service") or {}
    since = mono_to_epoch(sv.get("ActiveEnterTimestampMonotonic")) if sv.get("ActiveState") == "active" else None
    c = cached(ctx.store, "counts", 10, lambda: counts(cfg))
    listening = []
    if sv.get("ActiveState") == "active":
        listening = ["1900/udp (SSDP)", "%s/tcp (description, SOAP)" % cfg.get("http_port", 5000)]
    out = {"version": getattr(U, "VERSION", ""), "node": socket.gethostname().split(".")[0],
           "state": sv.get("ActiveState") or "unknown", "since": since,
           "uptime": (time.time() - since) if since else 0, "listening": listening,
           "mode": cfg.get("mode"), "answer": cfg.get("mapping_response"), "counts": c,
           "database": "SQLite", "program": os.path.join(HERE, "fake-igd.py"),
           "docs": {k: bool(doc_path(k)) for k in DOCS}, "api_since": _api_since()}
    if ctx.me and ctx.me.get("role") == "fulladmin":
        out["console"] = console_view(ctx)
    return out


def console_post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    on = b.get("on")
    if not isinstance(on, bool):
        raise ValueError("on: true or false")
    users = b.get("users")
    if users != "*":
        if not isinstance(users, list) or len(users) > 200:
            raise ValueError("the users: \"*\" or a list of names, 200 at most")
        for u in users:
            if not isinstance(u, str) or not USER_RE.match(u) or u == "root":
                raise ValueError("%r is not the name of a normal user" % str(u)[:40])
    ident = ctx.ask_root({"do": "console", "on": on, "users": users}, kind="service")
    lately_add(ctx, ident, "console", "", {"on": on})
    who = "every normal user" if users == "*" else (", ".join(users) if users else "no normal user")
    ctx.event("%s set the upnp console at login: root %s; %s" % (ctx.me.get("name", ""), "on" if on else "off", who),
              "warn")
    return {"id": ident, "message": "asked root - within a few seconds"}


DOCS = {"readme": "README.md", "changelog": "CHANGELOG.md"}


def doc_path(name):
    f = DOCS.get(name)
    if not f:
        return None
    for d in (HERE, os.path.dirname(HERE)):
        p = os.path.join(d, f)
        if os.path.isfile(p):
            return p
    return None


def doc_get(ctx):
    ctx.need("readonly")
    name = ctx.arg("name")
    p = doc_path(name)
    if not p:
        raise ValueError("%s is not here" % DOCS.get(name, "that"))
    with open(p, encoding="utf-8", errors="replace") as f:
        text = f.read(2 * 1024 * 1024)
    return {"name": name, "file": p, "text": text, "size": os.path.getsize(p), "at": os.path.getmtime(p)}


# ---- what it runs on (otp's software_info, one node) ------------------------------------------
SOFTWARE = {"at": 0.0, "state": None}


def software_now():
    if time.time() - SOFTWARE["at"] < 3600 and SOFTWARE["state"] is not None:
        return dict(SOFTWARE["state"])
    import sqlite3
    U = _upnp()
    out = {"fake_igd": getattr(U, "VERSION", ""),
           "python": "%s %s" % (platform.python_implementation(), platform.python_version()),
           "python_path": os.path.realpath(sys.executable), "openssl": ssl.OPENSSL_VERSION,
           "sqlite": sqlite3.sqlite_version, "kernel": "%s %s" % (platform.system(), platform.release()),
           "arch": platform.machine(), "modules": {}, "programs": {}}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            rel = dict(ln.strip().split("=", 1) for ln in f if "=" in ln)
        out["os"] = rel.get("PRETTY_NAME", "").strip('"')
    except OSError:
        out["os"] = ""
    for mod in ("colorama",):
        try:
            m = __import__(mod)
            out["modules"][mod] = str(getattr(m, "__version__", "") or "").split(" ")[0]
        except Exception:                               # noqa: BLE001
            out["modules"][mod] = ""
    progs = (("nginx", ["nginx", "-v"]), ("php-fpm", None), ("php", ["php", "-v"]),
             ("avahi-daemon", ["avahi-daemon", "--version"]), ("openssl", ["openssl", "version"]),
             ("systemd", ["systemctl", "--version"]), ("iptables", ["iptables", "--version"]),
             ("firewalld", ["firewall-cmd", "--version"]))
    for name, cmd in progs:
        if name == "php-fpm":
            exe = php_fpm()
            line = first_line([exe, "-v"]) if exe else ""
        else:
            exe = which(cmd[0])
            line = first_line([exe] + cmd[1:]) if exe else ""
        m = re.search(r"(\d+\.\d+(?:\.\d+)?[^\s,()]*)", line or "")
        if m and not re.search(r"(?i)denied|not found|error", line):
            out["programs"][name] = m.group(1)
        elif name == "systemd":
            m = re.search(r"^systemd\s+(\d+)", line or "")
            if m:
                out["programs"][name] = m.group(1)
    out["php_cli"] = out["programs"].pop("php", "")
    SOFTWARE.update(at=time.time(), state=dict(out))
    return out


def php_fpm():
    fpm = sorted(glob.glob("/usr/sbin/php-fpm*") + glob.glob("/usr/sbin/php*-fpm*"))
    return fpm[-1] if fpm else which("php-fpm")


PAGES = {"at": 0.0, "state": None}


def pages_php():
    """The pages' PHP as php-fpm runs it, asked of php-fpm itself (-v, -m, -i) - the relay
    (index.php) can say it better, from inside: when it adds "pages", this is not used."""
    if time.time() - PAGES["at"] < 3600 and PAGES["state"] is not None:
        return PAGES["state"]
    exe = php_fpm()
    out = {}
    if exe:
        v = re.search(r"PHP (\d+\.\d+\.\d+\S*)", first_line([exe, "-v"]) or "")
        rc, mods = run([exe, "-m"], 10)
        ext = {}
        if rc == 0:
            for ln in mods.splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("["):
                    ext[ln] = ""
        rc, info = run([exe, "-i"], 10)
        opc = re.search(r"^opcache\.enable => (\w+)", info, re.M) if rc == 0 else None
        if v:
            out = {"php": v.group(1), "sapi": "fpm-fcgi", "extensions": dict(sorted(ext.items(),
                                                                                 key=lambda x: x[0].lower())),
                   "opcache": bool(opc and opc.group(1).lower() in ("on", "1")),
                   "server": ("nginx/" + (software_now().get("programs") or {}).get("nginx", "")).rstrip("/"),
                   "from": "php-fpm -m"}
    PAGES.update(at=time.time(), state=out)
    return out


def software_get(ctx):
    ctx.need("readonly")
    me = socket.gethostname().split(".")[0]
    sw = software_now()
    sw["database"] = "SQLite %s" % sw.get("sqlite", "")
    return {"nodes": [{"name": me, "me": True, "alive": True, "software": sw}], "pages": pages_php()}


# ==== the performance meter (otp's /api/load, 1.0.253 - this node alone) ======================
LOAD_LOCK = threading.Lock()
LOAD_HIST = []
LOAD_STEP = 1.0
LOAD_HIST_KEEP = 150
LOAD_LOOK_S = 10
LOAD_KEEP_MAX = 75
LOAD_BACK_S = 5
LOAD_FS_KINDS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "ntfs3", "jfs", "reiserfs", "nilfs2",
                 "bcachefs")
LOAD_LAST = {"at": 0.0, "raw": None, "out": None}
LOAD_DETAIL = {"at": 0.0, "raw": None, "out": None}
LOAD_SYS = os.environ.get("FAKE_IGD_LOAD_SYS") or "/sys"
LOAD_WAKE = threading.Event()
LOAD_LOOK = {"until": 0.0, "on": False, "thread": None}


def load_nic_counted(name):
    if name == "lo" or name.startswith(("veth", "docker", "br-", "virbr", "podman", "cni", "flannel", "tun", "tap",
                                        "vnet", "ifb", "dummy", "lxc", "kube", "cali", "vxlan", "genev")):
        return False
    master = os.path.join(LOAD_SYS, "class/net", name, "master")
    if os.path.islink(master) and os.path.isdir(os.path.join(os.path.realpath(master), "bonding")):
        return False
    return True


def _rd(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _load_raw():
    raw = {"at": time.time()}
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        v = [int(x) for x in parts[:8]] + [0] * (8 - len(parts[:8]))
        raw["cpu_idle"] = v[3] + v[4]
        raw["cpu_all"] = sum(v)
    except (OSError, ValueError):
        pass
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _s, rest = line.partition(":")
                mem[k] = int(rest.split()[0]) * 1024
        raw["mem_total"] = mem.get("MemTotal", 0)
        raw["mem_used"] = mem.get("MemTotal", 0) - mem.get("MemAvailable", mem.get("MemFree", 0))
        raw["swap_used"] = mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)
    except (OSError, ValueError, IndexError):
        pass
    try:
        rd = wr = 0
        whole = set(os.listdir(os.path.join(LOAD_SYS, "block")))
        with open("/proc/diskstats") as f:
            for line in f:
                x = line.split()
                if len(x) < 10 or x[2] not in whole or x[2].startswith(("loop", "ram", "dm-", "zram", "sr")):
                    continue
                rd += int(x[5]) * 512
                wr += int(x[9]) * 512
        raw["disk_rd"], raw["disk_wr"] = rd, wr
    except (OSError, ValueError):
        pass
    try:
        rx = tx = 0
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _s, rest = line.partition(":")
                if not load_nic_counted(name.strip()):
                    continue
                x = rest.split()
                rx += int(x[0])
                tx += int(x[8])
        raw["net_rx"], raw["net_tx"] = rx, tx
    except (OSError, ValueError, IndexError):
        pass
    return raw


def load_temps():
    out = {"cpu": [], "cores": {}, "pkg_cores": {}, "disks": {}, "other": []}
    base = os.path.join(LOAD_SYS, "class/hwmon")
    try:
        mons = sorted(os.listdir(base))
    except OSError:
        mons = []
    for m in mons:
        d = os.path.join(base, m)
        chip = _rd(os.path.join(d, "name"))
        try:
            files = sorted(f for f in os.listdir(d) if re.match(r"^temp\d+_input$", f))
        except OSError:
            continue
        for f in files:
            n = f.split("_")[0]
            try:
                t = int(_rd(os.path.join(d, f), "x")) / 1000.0
            except ValueError:
                continue
            if t <= -40 or t > 150:
                continue
            label = _rd(os.path.join(d, n + "_label")) or chip
            core = re.match(r"^Core (\d+)$", label)
            if chip in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "soc_thermal", "k8temp", "via_cputemp"):
                if core:
                    out["cores"][int(core.group(1))] = round(t, 1)
                    pkg = re.search(r"\.(\d+)$", os.path.realpath(os.path.join(d, "device")))
                    out["pkg_cores"]["%s:%s" % (pkg.group(1) if pkg else "0", core.group(1))] = round(t, 1)
                else:
                    out["cpu"].append([label, round(t, 1)])
            elif chip in ("nvme", "drivetemp"):
                dev = ""
                try:
                    dev = os.path.basename(os.path.realpath(os.path.join(d, "device")))
                    if chip == "nvme":
                        nv = [x for x in os.listdir(os.path.join(d, "device")) if re.match(r"^nvme\d+n\d+$", x)]
                        dev = nv[0] if nv else dev
                    else:
                        blk = os.listdir(os.path.join(d, "device", "block"))
                        dev = blk[0] if blk else dev
                except OSError:
                    pass
                if label.lower() in ("composite", chip, "") or dev not in out["disks"]:
                    out["disks"][dev or chip] = round(t, 1)
            else:
                out["other"].append([chip + (" " + label if label != chip else ""), round(t, 1)])
    if not out["cpu"] and not out["cores"]:
        tz = os.path.join(LOAD_SYS, "class/thermal")
        try:
            zones = sorted(z for z in os.listdir(tz) if z.startswith("thermal_zone"))
        except OSError:
            zones = []
        for z in zones:
            kind = _rd(os.path.join(tz, z, "type"))
            try:
                t = int(_rd(os.path.join(tz, z, "temp"), "x")) / 1000.0
            except ValueError:
                continue
            if -40 < t < 150:
                (out["cpu"] if re.search(r"cpu|x86_pkg|soc|core", kind, re.I) else out["other"]).append(
                    [kind, round(t, 1)])
    out["cores"] = {str(k): v for k, v in out["cores"].items()}
    return out


def _load_detail_raw():
    raw = {"at": time.time(), "cores": {}, "disks": {}, "nics": {}, "procs": {}}
    try:
        with open("/proc/stat") as f:
            for line in f:
                m = re.match(r"^cpu(\d+)\s+(.*)$", line)
                if m:
                    v = [int(x) for x in m.group(2).split()[:8]]
                    raw["cores"][int(m.group(1))] = (v[3] + v[4], sum(v))
    except (OSError, ValueError):
        pass
    try:
        whole = set(os.listdir(os.path.join(LOAD_SYS, "block")))
        with open("/proc/diskstats") as f:
            for line in f:
                x = line.split()
                if len(x) < 13 or x[2] not in whole or x[2].startswith(("loop", "ram", "zram", "sr")):
                    continue
                raw["disks"][x[2]] = (int(x[5]) * 512, int(x[9]) * 512, int(x[12]))
    except (OSError, ValueError):
        pass
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _s, rest = line.partition(":")
                name = name.strip()
                if load_nic_counted(name):
                    x = rest.split()
                    raw["nics"][name] = (int(x[0]), int(x[8]))
    except (OSError, ValueError, IndexError):
        pass
    tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        try:
            with open("/proc/%s/stat" % pid) as f:
                st = f.read()
            name = st[st.index("(") + 1:st.rindex(")")]
            rest = st[st.rindex(")") + 2:].split()
            raw["procs"][int(pid)] = (name[:40], (int(rest[11]) + int(rest[12])) / float(tick), int(rest[21]) * page)
        except (OSError, ValueError, IndexError):
            continue
    return raw


def load_detail():
    """What the header's panels show when opened - only while a panel is open (otp's load_detail)."""
    with LOAD_LOCK:
        now = time.time()
        if LOAD_DETAIL["out"] and now - LOAD_DETAIL["at"] < 1.0:
            return LOAD_DETAIL["out"]
        raw = _load_detail_raw()
        was = LOAD_DETAIL["raw"] or {}
        if not was or now - was.get("at", 0) > 30:
            was = raw
            time.sleep(0.3)
            raw = _load_detail_raw()
        dt = max(0.2, raw["at"] - was.get("at", raw["at"] - 1)) if was else None
        temps = load_temps()
        cores = []
        for n in sorted(raw["cores"]):
            idle, allc = raw["cores"][n]
            busy = None
            if dt and n in was.get("cores", {}):
                pi, pa = was["cores"][n]
                if allc > pa:
                    busy = round(max(0.0, min(1.0, 1 - (idle - pi) / float(allc - pa))) * 100, 1)
            mhz = _rd(os.path.join(LOAD_SYS, "devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq" % n))
            topo = os.path.join(LOAD_SYS, "devices/system/cpu/cpu%d/topology" % n)
            cid = _rd(os.path.join(topo, "core_id"))
            pkg = _rd(os.path.join(topo, "physical_package_id"), "0")
            if cid.isdigit():
                temp = temps["pkg_cores"].get("%s:%s" % (pkg if pkg.isdigit() else "0", cid))
                if temp is None:
                    temp = temps["cores"].get(cid)
            else:
                temp = temps["cores"].get(str(n))
            cores.append({"n": n, "busy": busy, "mhz": round(int(mhz) / 1000) if mhz.isdigit() else None,
                          "temp": temp})
        if cores and not any(c["mhz"] for c in cores):
            try:
                with open("/proc/cpuinfo") as f:
                    mh = [float(x.split(":")[1]) for x in f if x.startswith("cpu MHz")]
                for c, m in zip(cores, mh):
                    c["mhz"] = round(m)
            except (OSError, ValueError, IndexError):
                pass
        model = ""
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith(("model name", "Hardware", "Model")):
                        model = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
        disks = []
        for name, (rd, wr, ms) in sorted(raw["disks"].items()):
            one = {"name": name, "temp": temps["disks"].get(name),
                   "size": int(_rd(os.path.join(LOAD_SYS, "block", name, "size"), "0") or 0) * 512,
                   "model": _rd(os.path.join(LOAD_SYS, "block", name, "device/model"))}
            if dt and name in was.get("disks", {}):
                prd, pwr, pms = was["disks"][name]
                one["rd"] = max(0, round((rd - prd) / dt))
                one["wr"] = max(0, round((wr - pwr) / dt))
                one["util"] = round(max(0.0, min(100.0, (ms - pms) / (dt * 10.0))), 1)
            disks.append(one)
        fss, seen = [], set()
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    dev, mnt, kind = line.split()[:3]
                    if kind not in LOAD_FS_KINDS or dev in seen:
                        continue
                    if not dev.startswith("/") and kind not in ("zfs", "btrfs"):
                        continue
                    seen.add(dev)
                    try:
                        sv = os.statvfs(mnt)
                    except OSError:
                        continue
                    total = sv.f_blocks * sv.f_frsize
                    if not total:
                        continue
                    fss.append({"mount": mnt, "dev": dev, "kind": kind, "total": total,
                                "used": total - sv.f_bfree * sv.f_frsize, "free": sv.f_bavail * sv.f_frsize})
        except OSError:
            pass
        nics = []
        for name, (rx, tx) in sorted(raw["nics"].items()):
            sp = _rd(os.path.join(LOAD_SYS, "class/net", name, "speed"))
            one = {"name": name, "state": _rd(os.path.join(LOAD_SYS, "class/net", name, "operstate")),
                   "speed": int(sp) if sp.lstrip("-").isdigit() and int(sp) > 0 else None, "rx_all": rx, "tx_all": tx}
            if dt and name in was.get("nics", {}):
                one["rx"] = max(0, round((rx - was["nics"][name][0]) / dt))
                one["tx"] = max(0, round((tx - was["nics"][name][1]) / dt))
            nics.append(one)
        procs = []
        for pid, (name, cpu_s, rss) in raw["procs"].items():
            p = {"pid": pid, "name": name, "rss": rss}
            if dt and pid in was.get("procs", {}):
                p["cpu"] = round(max(0.0, (cpu_s - was["procs"][pid][1]) / dt) * 100, 1)
            procs.append(p)
        mem = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    k, _s, rest = line.partition(":")
                    mem[k] = int(rest.split()[0]) * 1024
        except (OSError, ValueError, IndexError):
            pass
        try:
            up = float(_rd("/proc/uptime", "0").split()[0])
        except (ValueError, IndexError):
            up = 0.0
        out = {"cores": cores, "model": model, "temps": temps, "disks": disks, "filesystems": fss, "nics": nics,
               "top_cpu": sorted([p for p in procs if p.get("cpu")], key=lambda p: -p["cpu"])[:6],
               "top_mem": sorted(procs, key=lambda p: -p["rss"])[:6], "uptime": up,
               "mem": {k: mem.get(v) for k, v in (("total", "MemTotal"), ("available", "MemAvailable"),
                                                  ("cached", "Cached"), ("buffers", "Buffers"),
                                                  ("swap_total", "SwapTotal"), ("swap_free", "SwapFree"),
                                                  ("shared", "Shmem"))},
               "procs": len(procs)}
        LOAD_DETAIL.update(at=now, raw=raw, out=out)
        return out


def server_load(fresh=False):
    with LOAD_LOCK:
        now = time.time()
        if not fresh and LOAD_LAST["out"] and now - LOAD_LAST["at"] < 1.0:
            return LOAD_LAST["out"]
        raw = _load_raw()
        was = LOAD_LAST["raw"]
        out = {"at": now, "cores": os.cpu_count() or 1, "mem_total": raw.get("mem_total"),
               "mem_used": raw.get("mem_used"), "swap_used": raw.get("swap_used")}
        try:
            out["load"] = [round(x, 2) for x in os.getloadavg()]
        except OSError:
            out["load"] = None
        if was:
            dt = max(0.2, raw["at"] - was["at"])

            def rate(k):
                if k in raw and k in was and raw[k] >= was[k]:
                    return round((raw[k] - was[k]) / dt)
                return None
            if raw.get("cpu_all") and was.get("cpu_all") and raw["cpu_all"] > was["cpu_all"]:
                busy = 1 - (raw["cpu_idle"] - was["cpu_idle"]) / float(raw["cpu_all"] - was["cpu_all"])
                out["cpu"] = round(max(0.0, min(1.0, busy)) * 100, 1)
            for k in ("disk_rd", "disk_wr", "net_rx", "net_tx"):
                out[k] = rate(k)
            out["over_s"] = round(dt, 1)
        LOAD_LAST.update(at=now, raw=raw, out=out)
        return out


def load_history(since=None, span=150):
    now = time.time()
    if since is not None and since > now + 1:
        since = None
    with LOAD_LOCK:
        return [dict(x) for x in LOAD_HIST if now - x["at"] <= span and (since is None or x["at"] > since)]


def load_looked():
    return time.monotonic() < LOAD_LOOK["until"] and LOAD_LOOK["on"]


def load_sample():
    out = server_load(fresh=True)
    if out.get("cpu") is None:
        return
    mp = 100.0 * out["mem_used"] / out["mem_total"] if out.get("mem_total") else None
    one = {"at": round(out["at"], 2), "cpu": out.get("cpu"), "mem": round(mp, 1) if mp is not None else None}
    for k in ("disk_rd", "disk_wr", "net_rx", "net_tx"):
        one[k] = out.get(k) or 0
    with LOAD_LOCK:
        if LOAD_HIST and one["at"] < LOAD_HIST[-1]["at"] - LOAD_BACK_S:
            del LOAD_HIST[:]
        LOAD_HIST.append(one)
        del LOAD_HIST[:-LOAD_HIST_KEEP]


def load_sampler():
    """One reading a second while a page looks; nobody looking: it waits and reads nothing."""
    while True:
        if not load_looked():
            LOAD_WAKE.clear()
            if not load_looked():
                LOAD_WAKE.wait(30)
            if not load_looked():
                continue
            with LOAD_LOCK:
                LOAD_LAST.update(at=0.0, raw=None, out=None)
        began = time.monotonic()
        try:
            load_sample()
        except Exception as e:                          # noqa: BLE001
            _say("the performance meter: %s" % e)
        time.sleep(max(0.05, LOAD_STEP - (time.monotonic() - began)))


def load_ask(keep=None):
    try:
        look = max(LOAD_LOOK_S, min(LOAD_KEEP_MAX, float(keep or 0)))
    except (TypeError, ValueError):
        look = LOAD_LOOK_S
    LOAD_LOOK["until"] = max(LOAD_LOOK["until"], time.monotonic() + look)
    LOAD_LOOK["on"] = True
    t = LOAD_LOOK.get("thread")
    if t is None or not t.is_alive():
        t = threading.Thread(target=load_sampler, name="about-load", daemon=True)
        LOAD_LOOK["thread"] = t
        t.start()
    LOAD_WAKE.set()


def load_since(text):
    out = {}
    for part in str(text or "").split(",")[:8]:
        name, _, t = part.rpartition(":")
        try:
            out[name] = float(t)
        except ValueError:
            continue
    return out


def load_now():
    with LOAD_LOCK:
        last = LOAD_LAST["out"] if load_looked() and LOAD_LAST["out"] and \
            time.time() - LOAD_LAST["at"] < 3 * LOAD_STEP else None
    d = dict(last or server_load())
    return {k: d.get(k) for k in ("at", "cpu", "cores", "mem_total", "mem_used", "swap_used", "load",
                                  "disk_rd", "disk_wr", "net_rx", "net_tx", "over_s")}


def load_get(ctx):
    ctx.need("fulladmin")
    if not PN.value(ctx.store, "perf_meter"):
        LOAD_LOOK["on"] = False
        raise LookupError("the performance meter is switched off (Settings - About)")
    load_ask(ctx.arg("keep") or None)
    me = socket.gethostname().split(".")[0]
    since = load_since(ctx.arg("since"))
    out = {"node": me, "now": load_now(), "step": LOAD_STEP, "hist": load_history(since.get(me, since.get("")))}
    if ctx.arg("detail"):
        out["detail"] = load_detail()
    return out


def load_route(ctx):
    try:
        return load_get(ctx)
    except LookupError as e:
        # otp answers 404; the API's own errors are 400 - the page's meter switches itself off on "switched off"
        raise ValueError(str(e))


ROUTES = {
    ("GET", "/api/about"): about_get,
    ("GET", "/api/about/software"): software_get,
    ("GET", "/api/about/doc"): doc_get,
    ("POST", "/api/about/console"): console_post,
    ("GET", "/api/load"): load_route,
    ("GET", "/api/service"): service_get,
    ("GET", "/api/service/journal"): service_journal,
    ("POST", "/api/service"): service_post,
}
