"""api_osup.py - Settings → System updates (1.6.0), as otp's.

The operating system's packages: what dnf has waiting (dnf check-update, the security ones
by dnf updateinfo), the update itself (dnf -y upgrade, every package or only the security
ones) as a background job of root's with its output followed on the page, and whether a
restart is needed (dnf needs-restarting -r) - offered when it is, or made by itself where
that was chosen. Root's side is deploy/root_osup.py; its job writes web/osup.json.

On a schedule (the pane's settings): a look every day, and the update itself every day,
week or month - with a restart where it needs one, or only offered.
"""
import json
import os
import re
import time
from datetime import datetime

NAME = "osup"
PLAN_KEY = "osup:plan"
CHECK_KEY = "osup:check"


def _hhmm(v):
    try:
        hh, mm = v.split(":")
        if 0 <= int(hh) <= 23 and 0 <= int(mm) <= 59 and len(mm) == 2:
            return ""
    except ValueError:
        pass
    return "HH:MM, e.g. 04:45"


SETTINGS = [
    {"key": "osup_check", "name": "Look for updates every day", "kind": "bool", "default": False,
     "says": "This machine looks what dnf has waiting, every day at the time below - for the card here, the alerts "
             "and the report. Nothing is put in."},
    {"key": "osup_check_at", "name": "At", "kind": "text", "default": "06:15", "check": _hhmm,
     "only_when": ("osup_check", True), "says": "When, as <code>HH:MM</code> on this machine’s clock."},
    {"key": "osup_auto", "name": "Updates on a schedule", "kind": "bool", "default": False,
     "says": "dnf updates the packages by itself, as often as below. fake-igd.service goes on answering meanwhile."},
    {"key": "osup_auto_what", "name": "Which", "kind": "choice", "default": "security",
     "only_when": ("osup_auto", True),
     "choices": [("security", "only the security updates"), ("all", "every update")],
     "says": "Every package, or only those of a security advisory (dnf upgrade --security)."},
    {"key": "osup_auto_every", "name": "How often", "kind": "choice", "default": "weekly",
     "only_when": ("osup_auto", True),
     "choices": [("daily", "every day"), ("weekly", "every week, on the day below"),
                 ("monthly", "every month, on the first")],
     "says": "When the update is made."},
    {"key": "osup_auto_day", "name": "On the day", "kind": "choice", "default": "7",
     "only_when": ("osup_auto_every", "weekly"),
     "choices": [("1", "Monday"), ("2", "Tuesday"), ("3", "Wednesday"), ("4", "Thursday"), ("5", "Friday"),
                 ("6", "Saturday"), ("7", "Sunday")],
     "says": "The day a weekly update is made."},
    {"key": "osup_auto_at", "name": "At", "kind": "text", "default": "04:45", "check": _hhmm,
     "only_when": ("osup_auto", True), "says": "When, as <code>HH:MM</code> on this machine’s clock."},
    {"key": "osup_auto_reboot", "name": "After the update", "kind": "choice", "default": "auto",
     "only_when": ("osup_auto", True),
     "choices": [("auto", "restarted by itself where an update needs it"),
                 ("ask", "a restart only offered here")],
     "says": "A new kernel or libraries are brought into use only by a restart - for a minute the PS5 gets no "
             "answer."},
]


def _cfg(store):
    import igd_panes as PN
    return {s["key"]: PN.value(store, s["key"]) for s in SETTINGS}


def web_dir(ctx):
    return os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web")


def job_state(ctx):
    try:
        with open(os.path.join(web_dir(ctx), "osup.json"), encoding="utf-8") as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def helper_there():
    lib = os.environ.get("FAKE_IGD_LIB", "/opt/fake-igd")
    return os.path.exists(os.path.join(lib, "root_osup.py"))


def ask(ctx, do, security=False, by=""):
    import igd_proxy as P
    payload = {"do": do}
    if do in ("check", "upgrade"):
        payload["proxy"] = P.url_for(ctx.store, "os") or ""
        payload["proxy_no"] = ",".join(P.no_list(P.settings(ctx.store))) if payload["proxy"] else ""
    if do == "upgrade":
        payload["security"] = bool(security)
    return ctx.ask_root(payload)


def follow(ctx):
    """A job that ended, taken in: the look kept for the alerts and the cards; the plan ended,
    and the restart made where it was asked to be."""
    st = job_state(ctx)
    plan = ctx.store.meta_json(PLAN_KEY) or {}
    res = ctx.root_result()
    if plan.get("state") == "running" and res.get("id") == plan.get("id") and res.get("ok") is False:
        plan.update(state="failed", ended=res.get("at"), said="; ".join(res.get("said") or []) or "root said no")
        ctx.store.set_meta(PLAN_KEY, json.dumps(plan))
        ctx.event("the system update did not start: %s" % plan["said"], "warn", kind="osup")
    if st.get("state") == "running" and time.time() - float(st.get("at") or 0) > 1800:
        # A job that has said nothing for half an hour (the machine restarted under it): ended.
        st = dict(st, state="failed", said="dnf never said that it ended")
    if not st or st.get("state") == "running":
        return st, plan
    done_id = st.get("id")
    if st.get("kind") == "check":
        chk = ctx.store.meta_json(CHECK_KEY) or {}
        if chk.get("id") != done_id:
            chk = {"id": done_id, "at": st.get("at"), "state": st.get("state"), "count": st.get("count"),
                   "security": st.get("security"), "packages": (st.get("packages") or [])[:300],
                   "reboot_now": st.get("reboot_now"), "reboot_after": st.get("reboot_after"),
                   "reboot_why": st.get("reboot_why") or [], "error": st.get("said") if st.get("state") == "failed"
                   else ""}
            ctx.store.set_meta(CHECK_KEY, json.dumps(chk))
            ctx.event("system updates: %s" % (("%d waiting, %d of them security%s" % (
                chk["count"] or 0, chk["security"] or 0, ", a restart is needed" if chk["reboot_now"] else ""))
                if st.get("state") == "done" else "the look failed: %s" % chk["error"]),
                "info" if st.get("state") == "done" else "warn")
    if st.get("kind") == "upgrade" and done_id == plan.get("id") and plan.get("state") == "running":
        plan.update(state=st.get("state"), ended=st.get("at"), job_done=done_id, reboot_needed=bool(st.get("reboot")),
                    said=st.get("said") or "")
        ctx.store.set_meta(PLAN_KEY, json.dumps(plan))
        chk = ctx.store.meta_json(CHECK_KEY) or {}
        chk.update(reboot_now=bool(st.get("reboot")), count=0 if st.get("state") == "done" and not plan.get("security")
                   else chk.get("count"), security=0 if st.get("state") == "done" else chk.get("security"),
                   packages=[] if st.get("state") == "done" and not plan.get("security") else chk.get("packages"),
                   at=st.get("at"))
        ctx.store.set_meta(CHECK_KEY, json.dumps(chk))
        ctx.event("the system update %s%s" % ("is done" if st.get("state") == "done" else
                                              "failed: %s" % (st.get("said") or "?"),
                                              " - a restart is needed" if st.get("reboot") else ""),
                  "info" if st.get("state") == "done" else "warn", kind="osup")
        if st.get("reboot") and plan.get("reboot") == "auto":
            ask(ctx, "reboot")
            plan["rebooting"] = time.time()
            ctx.store.set_meta(PLAN_KEY, json.dumps(plan))
            ctx.event("the machine is restarted after the system update, as it was asked to be", "warn", kind="osup")
    return st, plan


def osup_get(ctx):
    st, plan = follow(ctx)
    chk = ctx.store.meta_json(CHECK_KEY) or {}
    res = ctx.root_result()
    hidden = ctx.store.meta_json("osup:hidden") or {}
    lines = st.get("lines") or []
    if hidden.get("id") == st.get("id"):
        lines = lines[int(hidden.get("from") or 0):]
    reboot = bool(chk.get("reboot_now")) or bool(plan.get("reboot_needed") and plan.get("state") == "done"
                                                 and not plan.get("rebooting"))
    return {"job": {k: st.get(k) for k in ("id", "kind", "state", "pct", "phase", "began", "at", "said",
                                           "security_only", "reboot")},
            "lines": lines, "check": chk, "plan": plan if not plan.get("hidden") else {},
            "reboot": reboot, "root": res, "helper": helper_there(), "now": time.time(),
            "node": os.uname()[1].split(".")[0]}


def osup_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    st = job_state(ctx)
    busy = st.get("state") == "running" and time.time() - float(st.get("at") or 0) < 1800
    if act == "check":
        if busy:
            raise ValueError("dnf is busy already - wait until it has ended")
        ident = ask(ctx, "check", by=me["name"])
        ctx.event("%s asked root to look for system updates" % me["name"])
        return {"id": ident, "message": "asked root - dnf looks for updates"}
    if act == "start":
        if busy:
            raise ValueError("dnf is busy already - wait until it has ended")
        security = b.get("security") is True
        rb = "auto" if b.get("reboot") == "auto" else "ask"
        ident = ask(ctx, "upgrade", security, me["name"])
        plan = {"id": ident, "at": time.time(), "by": me["name"], "state": "running", "reboot": rb,
                "security": security}
        ctx.store.set_meta(PLAN_KEY, json.dumps(plan))
        ctx.event("%s started the system update (%s; %s)" % (
            me["name"], "security updates only" if security else "every update",
            "restarted by itself where needed" if rb == "auto" else "a restart offered"), "warn")
        return {"id": ident, "message": "asked root - dnf updates the packages"}
    if act == "reboot":
        if busy:
            raise ValueError("an update is going on - restart once it has ended")
        ident = ask(ctx, "reboot", by=me["name"])
        plan = ctx.store.meta_json(PLAN_KEY) or {}
        plan["rebooting"] = time.time()
        ctx.store.set_meta(PLAN_KEY, json.dumps(plan))
        chk = ctx.store.meta_json(CHECK_KEY) or {}
        chk["reboot_now"] = False
        ctx.store.set_meta(CHECK_KEY, json.dumps(chk))
        ctx.event("%s restarted the machine after the system update" % me["name"], "warn")
        return {"id": ident, "message": "asked root - the machine restarts in a few seconds; these pages are "
                                        "away for a minute or two"}
    if act == "clear":
        ctx.store.set_meta("osup:hidden", json.dumps({"id": st.get("id"), "from": len(st.get("lines") or [])}))
        return osup_get(ctx)
    if act == "hide":
        plan = ctx.store.meta_json(PLAN_KEY) or {}
        if plan.get("state") == "running":
            raise ValueError("it is still going on")
        plan["hidden"] = True
        ctx.store.set_meta(PLAN_KEY, json.dumps(plan))
        return osup_get(ctx)
    raise ValueError("no such action")


ROUTES = {
    ("GET", "/api/osup"): osup_get,
    ("POST", "/api/osup"): osup_post,
}


def _at_minute(hhmm, now):
    m = re.match(r"^(\d{1,2}):(\d{2})\Z", str(hhmm or ""))
    return bool(m) and (now.hour, now.minute) == (int(m.group(1)), int(m.group(2)))


def background(ctx):
    follow(ctx)
    c = _cfg(ctx.store)
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    st = job_state(ctx)
    busy = st.get("state") == "running" and time.time() - float(st.get("at") or 0) < 1800
    if busy:
        return
    if c.get("osup_check") and _at_minute(c.get("osup_check_at"), now) and ctx.store.get_meta("osup:checked") != today:
        ctx.store.set_meta("osup:checked", today)
        ask(ctx, "check")
        ctx.event("the daily look for system updates", kind="osup")
        return
    if c.get("osup_auto") and _at_minute(c.get("osup_auto_at"), now) and ctx.store.get_meta("osup:auto") != today:
        every = c.get("osup_auto_every") or "weekly"
        if every == "weekly" and now.isoweekday() != int(c.get("osup_auto_day") or 7):
            return
        if every == "monthly" and now.day != 1:
            return
        ctx.store.set_meta("osup:auto", today)
        security = (c.get("osup_auto_what") or "security") == "security"
        ident = ask(ctx, "upgrade", security)
        ctx.store.set_meta(PLAN_KEY, json.dumps({"id": ident, "at": time.time(), "by": "the schedule",
                                                 "state": "running", "reboot": c.get("osup_auto_reboot") or "auto",
                                                 "security": security}))
        ctx.event("the system update on a schedule started (%s)" % ("security updates only" if security
                                                                  else "every update"), "warn", kind="osup")
