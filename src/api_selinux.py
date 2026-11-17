"""api_selinux.py - Settings → SELinux (1.7.7): otp's SELinux card (Settings → High security, 1.0.233 -
1.0.270), for one server.

The mode now and after a restart, what fake-igd needs of it (its module fake_igd_server, the labels of its
files, the boolean httpd_can_network_connect, the SSH server's port) and what SELinux refused since the
machine started - read by root (deploy/root_selinux.py) every half hour, the first two minutes after the
API starts, and whenever asked. The three steps - made ready and permissive, enforcing, permissive again -
and the report for whoever writes fake-igd's module are asked of root the same way; nothing happens by
itself, and a machine with SELinux disabled stays so.

  GET  /api/selinux        {nodes: [{name, me, state, at, error, said, action, pending}], reports: {...}}
  POST /api/selinux        {action: check | prepare | enforce | permissive | report | download}

Kept in the database: meta "selinux:want" (the step asked: id, do, by, at) and "selinux:now" (what root
said last: data, at, error, said, action, done, seen, report).
"""
import base64
import json
import os
import socket
import time

NAME = "selinux"
SETTINGS = []

ACTIONS = ("check", "prepare", "enforce", "permissive", "report")
EVERY = 1800                    # looked at every half hour
FIRST_AFTER = 120               # the first look two minutes after the start (otp 1.0.234)
STEP_STALE_S = 3600             # a step asked and not answered for an hour is said, and left (otp 1.0.270)
REPORT_KEEP_S = 3600            # the report handed out for an hour (otp 1.0.236)
REPORT_FILE = "selinux-report.tar.gz"
STARTED = time.time()
WORDS = {"check": "asked: %s looks within seconds",
         "prepare": "asked: %s makes SELinux ready and permissive within seconds",
         "enforce": "asked: %s switches SELinux to enforcing within seconds",
         "permissive": "asked: %s switches SELinux to permissive within seconds",
         "report": "asked: %s makes its report within a minute"}


def node_name():
    return socket.gethostname().split(".")[0]


def _meta(store, k):
    try:
        got = json.loads(store.get_meta(k) or "{}")
    except ValueError:
        got = {}
    return got if isinstance(got, dict) else {}


def _put(store, k, v):
    store.set_meta(k, json.dumps(v))


def report_path(ctx):
    return os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web", REPORT_FILE)


def take_answer(ctx):
    """Root's newest answer of the kind selinux taken into "selinux:now" - once. Returns now."""
    S = ctx.store
    now = _meta(S, "selinux:now")
    want = _meta(S, "selinux:want")
    got = ctx.root_result()
    if not got or not got.get("id") or got.get("id") == now.get("seen"):
        # A step asked an hour ago and not answered (root's helper away): said, and left (otp 1.0.270).
        if want.get("id") and want.get("id") != now.get("done") and want.get("do") in ("prepare", "enforce",
                                                                                        "permissive") \
                and time.time() - float(want.get("at") or 0) > STEP_STALE_S:
            now.update(done=want["id"], action=want.get("do"), at=time.time(), said=[],
                       error='the step "%s" was asked more than an hour ago and root did not do it - is '
                             'fake-igd-web.path active? Ask for it again' % want.get("do"))
            _put(S, "selinux:now", now)
            ctx.event('SELinux: the step "%s" asked more than an hour ago was not done' % want.get("do"), "warn",
                      kind="settings")
        return now
    do = str(got.get("do") or "check")
    ok = got.get("ok") is not False
    err = "" if ok else "; ".join(str(x) for x in (got.get("said") or []))[:400] or "root could not do it"
    said = [str(x)[:300] for x in (got.get("said") or [])] if ok else []
    now.update(seen=got["id"], at=float(got.get("at") or time.time()), error=err, said=said, action=do)
    if isinstance(got.get("data"), dict):
        now["data"] = got["data"]          # what was known kept when a look fails (otp 1.0.270)
    if want.get("id") and want.get("id") == got.get("ask_id", got.get("id")):
        now["done"] = want["id"]
    if do == "report":
        rep = got.get("report") if isinstance(got.get("report"), dict) else {}
        now["report"] = {"id": got["id"], "at": time.time(), "bytes": int(rep.get("bytes") or 0), "error": err}
    _put(S, "selinux:now", now)
    if do not in ("check", "report"):
        ctx.event("SELinux on %s: %s" % (node_name(), err or "; ".join(said) or "done"),
                  "bad" if err else "warn", kind="settings")
    return now


def ask(ctx, action, by):
    S = ctx.store
    was = _meta(S, "selinux:want")
    now = _meta(S, "selinux:now")
    # A step asked and not done yet is not put aside by a look or a report (otp 1.0.248).
    if action in ("check", "report") and was.get("do") in ("prepare", "enforce", "permissive") and \
            was.get("id") != now.get("done") and time.time() - float(was.get("at") or 0) < STEP_STALE_S:
        if action == "check":
            return was.get("id")
        raise ValueError("%s has not done the step asked of it yet (%s) - ask for the report after it"
                         % (node_name(), was.get("do")))
    ident = ctx.ask_root({"do": action})
    _put(S, "selinux:want", {"id": ident, "do": action, "by": by, "at": time.time()})
    if action == "report":
        ctx.event("%s asked for the SELinux report of %s" % (by, node_name()), "info", kind="settings")
    elif action != "check":
        ctx.event("%s asked SELinux on %s: %s" % (by, node_name(), {
            "prepare": "made ready, permissive", "enforce": "enforcing", "permissive": "permissive again"}[action]),
            "warn", kind="settings")
    return ident


def pending(ctx, now=None):
    want = _meta(ctx.store, "selinux:want")
    now = now if now is not None else _meta(ctx.store, "selinux:now")
    if not want.get("id") or want.get("id") == now.get("done"):
        return ""
    # Answered by root (the answer's id is the ask's): no longer waited for.
    if ctx.root_result(ident=want["id"]):
        return ""
    if time.time() - float(want.get("at") or 0) > STEP_STALE_S:
        return ""
    return want.get("do") or ""


def view(ctx):
    now = take_answer(ctx)
    rep = now.get("report") or {}
    reports = {}
    if rep and time.time() - float(rep.get("at") or 0) <= REPORT_KEEP_S:
        reports[node_name()] = {k: rep.get(k) for k in ("at", "bytes", "error", "id")}
    return {"nodes": [{"name": node_name(), "me": True, "state": now.get("data") or {}, "at": now.get("at"),
                       "error": now.get("error") or "", "said": now.get("said") or [],
                       "action": now.get("action") or "", "pending": pending(ctx, now)}],
            "reports": reports}


def problems(store, data=None):
    """For the alerts and To be done by hand: what keeps SELinux from protecting this server as it should -
    nothing at all where it is disabled or not on the machine (otp's selinux_problems)."""
    d = data if data is not None else (_meta(store, "selinux:now").get("data") or {})
    if d.get("mode") not in ("Enforcing", "Permissive"):
        return []
    out = list(d.get("problems") or [])
    if d.get("mode") == "Permissive" and not out:
        out.append("SELinux is permissive: nothing is refused - fake-igd is ready for enforcing")
    return out


def get(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    action = str(b.get("action") or "")
    node = str(b.get("node") or node_name())
    if action == "download":
        p = report_path(ctx)
        try:
            st = os.stat(p)
            if time.time() - st.st_mtime > REPORT_KEEP_S:
                raise OSError("old")
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as f:
                raw = f.read(8 << 20)
        except OSError:
            raw = b""
        missing = [] if raw else ["%s: %s" % (node_name(), (_meta(ctx.store, "selinux:now").get("report") or {}).get(
            "error") or "no report (ask for it first)")]
        if not raw:
            raise ValueError("there is no report of %s yet - Download the report asks for one" % node_name())
        ctx.event("%s took the SELinux report" % me["name"], "info", kind="settings")
        return {"name": "fake-igd-selinux-report-%s-%s.tar.gz" % (node_name(), time.strftime("%Y%m%d-%H%M")),
                "file": base64.b64encode(raw).decode("ascii"), "mime": "application/gzip", "missing": missing}
    if action not in ACTIONS:
        raise ValueError("check, prepare, enforce, permissive or report")
    if node not in ("*", node_name()):
        raise ValueError("there is no node %s" % node[:60])
    ask(ctx, action, me["name"])
    if action == "report" and node == "*":
        return {"message": "asked: every node makes its report within a minute", "busy": []}
    return {"message": WORDS[action] % node_name()}


ROUTES = {
    ("GET", "/api/selinux"): get,
    ("POST", "/api/selinux"): post,
}


def background(ctx):
    """Once a minute: root's answer taken in; a look every half hour (the first two minutes after the start)."""
    now = take_answer(ctx)
    if pending(ctx, now):
        return
    last = float(now.get("asked_at") or 0)
    if time.time() - STARTED < FIRST_AFTER or time.time() - last < EVERY:
        return
    now["asked_at"] = time.time()
    _put(ctx.store, "selinux:now", now)
    try:
        ident = ctx.ask_root({"do": "check"})
        _put(ctx.store, "selinux:want", {"id": ident, "do": "check", "by": "", "at": time.time()})
    except (OSError, ValueError):
        pass
