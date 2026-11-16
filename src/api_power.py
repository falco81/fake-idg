"""api_power.py - Settings → Restart and power off (1.6.0), otp's for one server.

This machine restarted or switched off from the pages - now, or in so many minutes (shutdown
+N, which can be cancelled: shutdown -c) - by root (deploy/root_power.py); and a restart on a
schedule (otp's power_auto), asked of root by this API's own minute.

  GET  /api/power                        this machine, what is set for later, the last ask
  POST /api/power {how: reboot | poweroff, in: MINUTES} | {action: cancel | hide}
"""
import json
import os
import re
import socket
import time

NAME = "power"
SHUTDOWN_FILE = os.environ.get("FAKE_IGD_SHUTDOWN_FILE", "/run/systemd/shutdown/scheduled")
LIVE_S = 1800
AT_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]\Z")


def _at(v):
    return "" if AT_RE.match(v) else "as HH:MM (05:40)"


SETTINGS = [
    {"key": "power_auto", "name": "A restart on a schedule", "kind": "bool", "default": False,
     "says": "This machine restarted in the window below. Off until switched on."},
    {"key": "power_auto_every", "name": "How often", "kind": "choice", "default": "weekly",
     "choices": [("weekly", "every week, on the day below"), ("monthly", "on the first of every month")],
     "only_when": ("power_auto", True), "says": "A week or a month."},
    {"key": "power_auto_day", "name": "On the day", "kind": "choice", "default": "7",
     "choices": [("1", "Monday"), ("2", "Tuesday"), ("3", "Wednesday"), ("4", "Thursday"), ("5", "Friday"),
                 ("6", "Saturday"), ("7", "Sunday")],
     "only_when": ("power_auto_every", "weekly"), "says": "The day a weekly restart goes."},
    {"key": "power_auto_at", "name": "At", "kind": "text", "default": "05:40", "check": _at,
     "only_when": ("power_auto", True), "says": "When, as HH:MM on this machine's clock."},
    {"key": "power_auto_needed", "name": "Only when an update needs one", "kind": "bool", "default": True,
     "only_when": ("power_auto", True),
     "says": "Only when an update left the machine waiting for a restart (needs-restarting -r); off: every time."},
]


def booted():
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def scheduled():
    """What systemd has set for later (shutdown +N): {mode, at} or {}."""
    try:
        with open(SHUTDOWN_FILE) as f:
            kv = dict(l.strip().split("=", 1) for l in f if "=" in l)
        usec = int(kv.get("USEC") or 0)
    except (OSError, ValueError):
        return {}
    if not usec or usec / 1e6 < time.time() - 60:
        return {}
    return {"mode": kv.get("MODE") or "", "at": usec / 1e6}


def plan(ctx):
    p = ctx.store.meta_json("power:plan") or {}
    if p.get("state") == "asked":
        r = ctx.root_result()
        if r.get("id") == p.get("ask"):
            p["state"] = "going" if r.get("ok") else "failed"
            if r.get("ok") and any("none made" in str(x) for x in r.get("said") or []):
                p["state"] = "skipped"
            if r.get("ok") and p.get("how") == "cancel":
                p["state"] = "cancelled"
            p["said"] = [str(x) for x in r.get("said") or []][:6]
            p["answered"] = time.time()
            ctx.store.set_meta("power:plan", json.dumps(p))
            if not r.get("ok"):
                ctx.event("%s was not done: %s" % (p.get("words"), "; ".join(p["said"])), "warn")
    return p


def view(ctx):
    p = plan(ctx)
    up = booted()
    seen = ctx.store.get_meta("power:seen") == str(p.get("ask") or "")
    if seen or time.time() - float(p.get("at") or 0) > LIVE_S + 60 * int(p.get("in") or 0):
        p = {}
    if p and p.get("how") != "cancel" and p.get("state") == "going" and up and up > float(p.get("at") or 0):
        p["state"] = "back"
    elif p and p.get("state") == "going" and not p.get("in") and p.get("how") == "reboot" and \
            time.time() - float(p.get("answered") or p.get("at") or 0) > 900:
        p["state"] = "failed"            # as otp's: a node not back in 15 minutes is marked failed
        p["said"] = (p.get("said") or []) + ["it has not restarted in 15 minutes"]
    try:
        import upnp as U
        version = U.VERSION
    except Exception:                                   # noqa: BLE001
        version = ""
    addrs = []
    try:
        import upnp as U
        addrs = ["%s %s" % (k, v) for k, v in sorted(U.local_interfaces().items())]
    except Exception:                                   # noqa: BLE001
        pass
    return {"node": {"name": socket.gethostname(), "alive": True, "started": up, "version": version,
                     "address": ", ".join(addrs)},
            "scheduled": scheduled(), "plan": p, "now": time.time(),
            "auto": {"on": bool(ctx.setting("power_auto")), "next": next_auto(ctx)}}


def get_power(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post_power(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    if act == "hide":
        p = ctx.store.meta_json("power:plan") or {}
        if p.get("ask"):
            ctx.store.set_meta("power:seen", str(p["ask"]))
        return view(ctx)
    p = plan(ctx)
    if p.get("state") == "asked" and time.time() - float(p.get("at") or 0) < 120:
        raise ValueError("root has not answered the last ask yet")
    if act == "cancel":
        if not scheduled() and not (p.get("state") == "going" and int(p.get("in") or 0) > 0):
            raise ValueError("nothing is set for later")
        ident = ctx.ask_root({"do": "cancel"})
        ctx.store.set_meta("power:plan", json.dumps({"ask": ident, "how": "cancel", "in": 0, "at": time.time(),
                                                     "by": me["name"], "state": "asked",
                                                     "words": "cancelling what was set"}))
        ctx.event("%s cancelled the restart or power-off set for later" % me["name"], "warn")
        return {"message": "asked: what was set is cancelled within seconds", "id": ident}
    how = b.get("how")
    if how not in ("reboot", "poweroff"):
        raise ValueError("restart (reboot) or power off (poweroff)?")
    m = b.get("in", 0)
    if isinstance(m, bool) or not isinstance(m, int) or not 0 <= m <= 1440:
        raise ValueError("in: whole minutes, 0 to 1440")
    words = ("a restart" if how == "reboot" else "a power-off") + (" in %d min" % m if m else " now")
    ident = ctx.ask_root({"do": how, "in": m})
    ctx.store.set_meta("power:plan", json.dumps({"ask": ident, "how": how, "in": m, "at": time.time(),
                                                 "by": me["name"], "state": "asked", "words": words,
                                                 "boot": booted()}))
    ctx.event("%s asked for %s of this machine" % (me["name"], words), "warn")
    return {"message": "asked: %s" % words, "id": ident}


# ---- the restart on a schedule (otp's power_auto) ---------------------------------------
def _due_today(ctx, lt):
    every = ctx.setting("power_auto_every") or "weekly"
    if every == "monthly":
        return lt.tm_mday == 1
    return str(lt.tm_wday + 1) == str(ctx.setting("power_auto_day") or "7")


def next_auto(ctx):
    if not ctx.setting("power_auto"):
        return None
    at = str(ctx.setting("power_auto_at") or "05:40")
    if not AT_RE.match(at):
        return None
    hh, mm = int(at[:2]), int(at[3:])
    now = time.time()
    for days in range(0, 33):
        lt = time.localtime(now + days * 86400)
        t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hh, mm, 0, 0, 0, -1))
        if t > now and _due_today(ctx, time.localtime(t)):
            return t
    return None


def background(ctx):
    plan(ctx)
    if not ctx.setting("power_auto"):
        return
    at = str(ctx.setting("power_auto_at") or "")
    if not AT_RE.match(at):
        return
    now = time.time()
    lt = time.localtime(now)
    if not _due_today(ctx, lt):
        return
    t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, int(at[:2]), int(at[3:]), 0, 0, 0, -1))
    if not t <= now < t + 3600:           # a window of an hour: the API down a while does not lose it
        return
    day = time.strftime("%Y-%m-%d", lt)
    if ctx.store.get_meta("power:auto:last") == day:
        return
    b = booted()
    if b and b >= t:                      # it restarted in the window already
        ctx.store.set_meta("power:auto:last", day)
        return
    ctx.store.set_meta("power:auto:last", day)
    need = bool(ctx.setting("power_auto_needed"))
    ident = ctx.ask_root({"do": "auto", "needed": need})
    ctx.store.set_meta("power:plan", json.dumps({"ask": ident, "how": "reboot", "in": 0, "at": now, "by": "the schedule",
                                                 "state": "asked", "words": "the restart on a schedule",
                                                 "boot": b}))
    ctx.event("the restart on a schedule: root is asked%s" % (" (only if an update needs one)" if need else ""), "info")


ROUTES = {("GET", "/api/power"): get_power, ("POST", "/api/power"): post_power}
