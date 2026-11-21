"""api_time.py - Settings → Time (1.6.0), otp's Settings → Time for one server.

The clock as chrony has it - read here with chronyc -n tracking / sources / sourcestats and
timedatectl show (the fake-igd account may ask chronyd over its UDP port, 127.0.0.1:323) - and the
time servers, set in /etc/chrony.conf by root (deploy/root_time.py) as otp sets them, with the
time zone. A step to the right time now (chronyc makestep) is root's too.

  GET  /api/time                       the clock, its sources, the zone, what root did last
  POST /api/time {action: read | sync}
"""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time

NAME = "time"
CHRONYC = os.environ.get("FAKE_IGD_CHRONYC", "chronyc")
TIMEDATECTL = os.environ.get("FAKE_IGD_TIMEDATECTL", "timedatectl")
ZONEINFO = os.environ.get("FAKE_IGD_ZONEINFO", "/usr/share/zoneinfo")
CHRONY_CONF = os.environ.get("FAKE_IGD_CHRONY_CONF") or next(
    (p for p in ("/etc/chrony.conf", "/etc/chrony/chrony.conf") if os.path.isfile(p)), "/etc/chrony.conf")
BEGIN = "# ---- fake-igd: the time servers, set on its pages (Settings - Time) ----"
ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z")
NAME_RE = re.compile(r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
UNITS = {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1.0}
SPAN = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "y": 31536000}


def run(cmd, timeout=6):
    try:
        got = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError("%s: %s" % (cmd[0], e))
    if got.returncode != 0:
        raise ValueError("%s: %s" % (" ".join(cmd[:3]), (got.stderr or got.stdout).strip()[-300:]))
    return got.stdout


def zones():
    """Every time zone: timedatectl list-timezones, or the zoneinfo's own list."""
    try:
        got = [z for z in run([TIMEDATECTL, "list-timezones"], 10).split() if z]
        if got:
            return got[:800]
    except ValueError:
        pass
    got = set(["UTC"])
    for tab in ("tzdata.zi", "zone1970.tab", "zone.tab"):
        try:
            with open(os.path.join(ZONEINFO, tab)) as f:
                for line in f:
                    p = line.split()
                    if tab == "tzdata.zi":
                        if p[:1] == ["Z"] and len(p) > 1:
                            got.add(p[1])
                        elif p[:1] == ["L"] and len(p) > 2:
                            got.add(p[2])
                    elif len(p) >= 3 and not p[0].startswith("#"):
                        got.add(p[2])
        except OSError:
            continue
        if len(got) > 1:
            break
    return sorted(got)


# ---- the settings: the time servers, as otp's ntp form ----------------------------------
def check_server(line):
    """One time server: "server|pool HOST [iburst] [prefer] [nts]"."""
    p = line.split()
    if len(p) < 2 or p[0] not in ("server", "pool"):
        return "%r: \"server HOST\" or \"pool HOST\", then iburst, prefer, nts" % line[:60]
    host = p[1].lower().rstrip(".")
    if not (ADDR_RE.match(host) and _ip(host)) and not NAME_RE.match(host):
        return "%r is not a host name or an address" % host[:60]
    for o in p[2:]:
        if o not in ("iburst", "prefer", "nts"):
            return "%r: only iburst, prefer and nts" % o[:20]
    return ""


def _ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def check_servers(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if len(lines) > 12:
        return "12 servers at most"
    for l in lines:
        bad = check_server(l)
        if bad:
            return bad
    return ""


def check_net(x):
    try:
        if "%" in x or not ADDR_RE.match(x):
            raise ValueError
        ipaddress.ip_network(x, strict=False)
    except ValueError:
        return "%r is not a network (192.0.2.0/24)" % x[:60]
    return ""


def check_step(x):
    try:
        v = float(x)
    except ValueError:
        return "a number of seconds (1, 0.5)"
    return "" if 0.001 <= v <= 3600 else "0.001 - 3600 s"


SETTINGS = [
    {"key": "time_manage", "name": "fake-igd sets the time servers", "kind": "bool", "default": False, "root": True,
     "says": "Off: this machine keeps its own /etc/chrony.conf (AlmaLinux's pool, or what you set by hand) - "
             "shown and checked here, not changed. On: the servers below; the file's own server and pool lines "
             "are commented out, and put back when switched off again."},
    {"key": "time_servers", "name": "Servers", "kind": "textarea", "default": "pool pool.ntp.org iburst",
     "check": check_servers, "only_when": ("time_manage", True), "root": True,
     "says": "A host name or address each; one server or a pool (several addresses behind one name); iburst "
             "(synchronised in seconds after a start), preferred, NTS (Network Time Security - the server proves "
             "who it is; needs TCP 4460 out)."},
    {"key": "time_step_s", "name": "Step when off by more than (s)", "kind": "text", "default": "1",
     "check": check_step, "only_when": ("time_manage", True), "root": True,
     "says": "Further off than this, the clock jumps to the right time instead of being slowed or sped up gently."},
    {"key": "time_step_n", "name": "…in the first updates", "kind": "int", "default": 3, "min": -1, "max": 1000,
     "only_when": ("time_manage", True), "root": True,
     "says": "How many updates after chronyd starts may step it: 3 is after a boot; -1 any time."},
    {"key": "time_minsources", "name": "Sources that have to agree", "kind": "int", "default": 1, "min": 1, "max": 10,
     "only_when": ("time_manage", True), "root": True,
     "says": "The clock is set only when at least this many sources agree. 1 with one server; 2 or 3 with several."},
    {"key": "time_allow", "name": "Serve the time to", "kind": "list", "default": [], "check": check_net,
     "only_when": ("time_manage", True), "root": True,
     "says": "Networks that may ask this machine for the time (UDP 123) - the PS5 and the rest of the home "
             "network, say. Empty: nobody. Open UDP 123 in the firewall for them too."},
    {"key": "time_zone", "name": "Time zone", "kind": "choice", "default": "", "root": True,
     "choices": [("", "- as the machine has it -")] + [(z, z) for z in zones()],
     "says": "Of the machine: the logs and the times on these pages. Set with timedatectl set-timezone."},
]


def conf_of(ctx):
    servers = []
    for line in str(ctx.setting("time_servers") or "").splitlines():
        p = line.split()
        if len(p) >= 2:
            servers.append({"host": p[1].lower().rstrip("."), "pool": p[0] == "pool", "iburst": "iburst" in p[2:],
                            "prefer": "prefer" in p[2:], "nts": "nts" in p[2:]})
    try:
        step = float(ctx.setting("time_step_s") or 1)
    except ValueError:
        step = 1.0
    return {"do": "apply", "manage": bool(ctx.setting("time_manage")), "servers": servers,
            "makestep": [step, int(ctx.setting("time_step_n"))], "minsources": int(ctx.setting("time_minsources") or 1),
            "allow": list(ctx.setting("time_allow") or []), "timezone": str(ctx.setting("time_zone") or "")}


def on_saved(ctx, changed):
    c = conf_of(ctx)
    if c["manage"] and not c["servers"]:
        ctx.event("the time servers were not put in: fake-igd sets them, and none is given", "warn")
        return
    ident = ctx.ask_root(c)
    ctx.store.set_meta("time:apply", json.dumps({"ask": ident, "at": time.time()}))


# ---- reading chrony: chronyc -n tracking / sources / sourcestats --------------------------
def _num(v, unit):
    return float(v) * UNITS.get(unit, 1.0)


def _span(v):
    m = re.match(r"^(\d+)([smhdy]?)$", v or "")
    return int(m.group(1)) * SPAN[m.group(2)] if m else None


def parse_tracking(text):
    t = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        try:
            if k == "Reference ID":
                m = re.match(r"^([0-9A-Fa-f]+)\s*(?:\((.*)\))?", v)
                if m:
                    t["ref_id"], t["ref"] = m.group(1), (m.group(2) or "")
            elif k == "Stratum":
                t["stratum"] = int(v)
            elif k == "Ref time (UTC)":
                t["ref_time"] = v
            elif k == "System time":
                m = re.match(r"^([\d.]+) seconds (fast|slow)", v)
                if m:
                    t["offset"] = float(m.group(1)) * (1 if m.group(2) == "fast" else -1)
            elif k in ("Last offset", "RMS offset", "Root delay", "Root dispersion", "Update interval"):
                key = {"Last offset": "last_offset", "RMS offset": "rms", "Root delay": "root_delay",
                       "Root dispersion": "root_disp", "Update interval": "interval"}[k]
                t[key] = float(v.split()[0])
            elif k == "Frequency":
                m = re.match(r"^([\d.]+) ppm (fast|slow)", v)
                if m:
                    t["freq"] = float(m.group(1)) * (1 if m.group(2) == "fast" else -1)
            elif k == "Residual freq":
                t["resid_freq"] = float(v.split()[0])
            elif k == "Skew":
                t["skew"] = float(v.split()[0])
            elif k == "Leap status":
                t["leap"] = v
        except ValueError:
            continue
    return t


SRC_RE = re.compile(r"^([\^=#])([*+\-?x~])\s+(\S+)\s+(\d+)\s+(-?\d+)\s+([0-7]+)\s+(\S+)\s+"
                    r"([+-]?[\d.]+)(ns|us|ms|s)\[\s*([+-]?[\d.]+)(ns|us|ms|s)\]\s+\+/-\s+([\d.]+)(ns|us|ms|s)")


def parse_sources(text):
    out = []
    for line in text.splitlines():
        m = SRC_RE.match(line.strip())
        if not m:
            continue
        out.append({"mode": m.group(1), "state": m.group(2), "name": m.group(3)[:120],
                    "stratum": int(m.group(4)), "poll": int(m.group(5)), "reach": int(m.group(6), 8),
                    "last_rx": _span(m.group(7)), "offset": _num(m.group(8), m.group(9)),
                    "measured": _num(m.group(10), m.group(11)), "error": _num(m.group(12), m.group(13))})
    return out


STAT_RE = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+[smhdy]?)\s+([+-]?[\d.]+)\s+([\d.]+)\s+"
                     r"([+-]?[\d.]+)(ns|us|ms|s)\s+([\d.]+)(ns|us|ms|s)\s*$")


def parse_sourcestats(text):
    out = {}
    for line in text.splitlines():
        m = STAT_RE.match(line.strip())
        if not m:
            continue
        out[m.group(1)] = {"np": int(m.group(2)), "nr": int(m.group(3)), "span": _span(m.group(4)),
                           "freq": float(m.group(5)), "freq_skew": float(m.group(6)),
                           "offset": _num(m.group(7), m.group(8)), "std_dev": _num(m.group(9), m.group(10))}
    return out


def read():
    out = {"chrony": bool(shutil.which(CHRONYC)), "tracking": {}, "sources": [], "stats": {}, "time": time.time()}
    try:
        for line in run([TIMEDATECTL, "show"]).splitlines():
            k, sep, v = line.partition("=")
            if sep and k in ("Timezone", "NTP", "NTPSynchronized", "LocalRTC", "CanNTP"):
                out[k.lower()] = v
    except ValueError:
        pass
    if out["chrony"]:
        try:
            out["tracking"] = parse_tracking(run([CHRONYC, "-n", "tracking"]))
        except ValueError as e:
            out["said"] = str(e)[:200]
        try:
            out["sources"] = parse_sources(run([CHRONYC, "-n", "sources"]))
            out["stats"] = parse_sourcestats(run([CHRONYC, "-n", "sourcestats"]))
        except ValueError as e:
            out.setdefault("said", str(e)[:200])
    try:
        with open(CHRONY_CONF) as f:
            text = f.read()
        out["managed"] = BEGIN in text
        out["own"] = [l.strip() for l in text.splitlines() if (l.split() or [""])[0] in ("server", "pool", "peer")][:20]
        out["conf_file"] = CHRONY_CONF
    except OSError:
        out["managed"] = False
    return out


def applied(ctx):
    """How root's last apply went: {at, ok, said}."""
    a = ctx.store.meta_json("time:apply") or {}
    if a.get("ask") and not a.get("done"):
        r = ctx.root_result()
        if r.get("id") == a["ask"]:
            a.update({"done": True, "ok": bool(r.get("ok")), "said": "; ".join(str(x) for x in r.get("said") or []),
                      "at": r.get("at") or time.time()})
            ctx.store.set_meta("time:apply", json.dumps(a))
            ctx.event("the time servers %s: %s" % ("put in" if a["ok"] else "were NOT put in", a["said"][:900]),
                      "info" if a["ok"] else "warn")
    return a


def view(ctx):
    sync = ctx.store.meta_json("time:sync") or {}
    if sync.get("ask") and not sync.get("done"):
        r = ctx.root_result()
        if r.get("id") == sync["ask"]:
            sync.update({"done": True, "ok": bool(r.get("ok")), "said": "; ".join(str(x) for x in r.get("said") or [])})
            ctx.store.set_meta("time:sync", json.dumps(sync))
        elif time.time() - float(sync.get("at") or 0) > 300:
            # root never answered: failed, not "asked of root" for ever (1.9.11)
            sync.update({"done": True, "ok": False, "said": "root did not answer in 5 minutes (is fake-igd-web.path running?)"})
            ctx.store.set_meta("time:sync", json.dumps(sync))
    return {"now": read(), "applied": applied(ctx), "sync": sync, "server_now": time.time()}


def get_time(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post_time(ctx):
    me = ctx.need("fulladmin")
    act = ctx.body().get("action")
    if act == "read":
        return view(ctx)
    if act == "sync":
        ident = ctx.ask_root({"do": "sync"})
        ctx.store.set_meta("time:sync", json.dumps({"ask": ident, "at": time.time(), "by": me["name"]}))
        ctx.event("%s asked to step the clock to the time servers now" % me["name"], "warn")
        return {"message": "asked: root steps the clock within seconds", "id": ident}
    raise ValueError("no such thing to do")


def background(ctx):
    applied(ctx)


ROUTES = {("GET", "/api/time"): get_time, ("POST", "/api/time"): post_time}
