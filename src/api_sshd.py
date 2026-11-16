"""api_sshd.py - Settings -> SSH server and notices (1.6.0; otp's sshd_view, sshd_save, sshd_tick).

One wish (the settings below, saved with the bar), put in by root (deploy/root_sshd.py) as a
drop-in of fake-igd's own, checked by `sshd -t`, and ON TRIAL: unless "Keep it" comes in time,
root puts back what was there by itself (a timer of systemd's own). The notice before signing in
over SSH (Banner, /etc/issue.net), at the console (/etc/issue) and after signing in (motd).

  GET  /api/sshd                    the wish, what sshd has, the state: done | trial | waiting |
                                    failed | back
  POST /api/sshd {action: keep}     the change on trial kept
  POST /api/sshd {action: back}     put back now
  POST /api/sshd {action: refresh}  read again
"""
import glob
import hashlib
import json
import os
import re
import socket
import time

import igd_panes as PN

NAME = "sshd"
USER_RE = re.compile(r"^[A-Za-z0-9._@*?-]{1,64}\Z")


def _user(v):
    return "" if USER_RE.match(v) else "a user name: letters, digits and . _ @ - (and * ? as sshd takes them)"


SETTINGS = [
    {"key": "sshd_manage", "name": "fake-igd sets the SSH server", "kind": "bool", "default": False, "root": True,
     "says": "Off: sshd is as the system has it, and fake-igd's file (sshd_config.d/00-fake-igd.conf) is taken "
             "away. On: the values below, put in by root, checked by sshd -t, and on trial."},
    {"key": "sshd_permit_root", "name": "Root signs in", "kind": "choice", "default": "prohibit-password",
     "root": True, "only_when": ("sshd_manage", True),
     "choices": [("prohibit-password", "With a key only"), ("yes", "With a key or a password"),
                 ("no", "Not at all")],
     "says": "PermitRootLogin. With a key only: root needs a key in /root/.ssh/authorized_keys (SSH keys) - "
             "without one, this is refused."},
    {"key": "sshd_password", "name": "Passwords", "kind": "bool", "default": True, "root": True,
     "only_when": ("sshd_manage", True),
     "says": "Off: only keys sign in, for everybody (PasswordAuthentication, KbdInteractiveAuthentication)."},
    {"key": "sshd_port", "name": "Port", "kind": "int", "default": 22, "min": 1, "max": 65535, "root": True,
     "only_when": ("sshd_manage", True),
     "says": "Another than 22: SELinux and firewalld let it in by themselves, the old one too while it is on "
             "trial."},
    {"key": "sshd_tries", "name": "Tries a connection", "kind": "int", "default": 4, "min": 1, "max": 10,
     "root": True, "only_when": ("sshd_manage", True),
     "says": "Wrong passwords or keys before sshd closes it (MaxAuthTries)."},
    {"key": "sshd_allow_users", "name": "Who may sign in", "kind": "list", "default": [], "root": True,
     "only_when": ("sshd_manage", True), "check": _user,
     "says": "The accounts that may sign in over SSH (AllowUsers) - empty: everybody. Root left out of the list "
             "signs in only at the console."},
    {"key": "sshd_trial_min", "name": "On trial for (min)", "kind": "int", "default": 5, "min": 0, "max": 60,
     "only_when": ("sshd_manage", True),
     "says": "Unless kept within this, root puts back what was there. 0: no trial - not advised."},
    {"key": "sshd_notice", "name": "The notice", "kind": "textarea", "default": "", "root": True, "most": 4000,
     "says": "Plain text, as many lines as needed - often what the security policy wants said. Shown where it "
             "is switched on below."},
    {"key": "sshd_notice_ssh", "name": "Before signing in over SSH", "kind": "bool", "default": False,
     "root": True, "only_when": ("sshd_manage", True),
     "says": "sshd's Banner (/etc/issue.net) - needs fake-igd to set the SSH server."},
    {"key": "sshd_notice_console", "name": "At the console", "kind": "bool", "default": False, "root": True,
     "says": "/etc/issue (a file of fake-igd's own in /etc/issue.d where the system has it)."},
    {"key": "sshd_notice_motd", "name": "After signing in", "kind": "bool", "default": False, "root": True,
     "says": "The message of the day (/etc/motd.d or /etc/motd)."},
]
CONF_KEYS = ("manage", "permit_root", "password", "port", "tries", "allow_users", "notice", "notice_ssh",
             "notice_console", "notice_motd", "trial_min")
STATE_WORDS = {"done": "as wished", "trial": "on trial", "waiting": "being put in", "failed": "refused",
               "back": "went back"}
READ = {"asked": 0.0}


def conf(ctx):
    c = {k: ctx.setting("sshd_" + k) for k in CONF_KEYS}
    c["allow_users"] = [u for u in (c.get("allow_users") or []) if isinstance(u, str)]
    c["notice"] = str(c.get("notice") or "").replace("\r\n", "\n")
    return c


def wish(ctx):
    try:
        got = json.loads(ctx.store.get_meta("sshd:wish") or "{}")
    except ValueError:
        got = {}
    return got if isinstance(got, dict) else {}


def asks_waiting(ctx, kind=NAME):
    """The asks of this kind not yet taken by root: (how many, the age of the oldest)."""
    folder = PN.ask_folder(ctx.cfg.get("state_dir"))
    ages = []
    for p in glob.glob(os.path.join(folder, "%s-*.json" % kind)):
        try:
            ages.append(time.time() - os.stat(p).st_mtime)
        except OSError:
            pass
    return len(ages), max(ages) if ages else 0


def ask(ctx, payload):
    READ["asked"] = time.time()
    return ctx.ask_root(payload)


def apply(ctx, by):
    c = conf(ctx)
    at = time.time()
    h = hashlib.sha256((json.dumps(c, sort_keys=True) + repr(at)).encode()).hexdigest()[:24]
    ctx.store.set_meta("sshd:wish", json.dumps({"hash": h, "at": at, "by": by}))
    ask(ctx, {"do": "apply", "conf": {k: c[k] for k in CONF_KEYS if k != "trial_min"},
              "trial_min": int(c.get("trial_min") or 0) if c["manage"] else 0, "hash": h})
    what = ("root %s, passwords %s, port %d, tries %d%s" % (
        c["permit_root"], "on" if c["password"] else "off", int(c["port"]), int(c["tries"]),
        ", AllowUsers " + " ".join(c["allow_users"]) if c["allow_users"] else "")
        if c["manage"] else "the SSH server as the system has it")
    notes = [w for k, w in (("notice_ssh", "SSH"), ("notice_console", "console"), ("notice_motd", "after sign-in"))
             if c[k] and c["notice"].strip() and (k != "notice_ssh" or c["manage"])]
    ctx.event("%s set the SSH server: %s%s%s" % (
        by, what, "; the notice %s" % ", ".join(notes) if notes else "",
        "; on trial for %d min" % int(c["trial_min"]) if c["manage"] and c["trial_min"] else ""), "warn")
    return h


def on_saved(ctx, changed):
    apply(ctx, (ctx.me or {}).get("name", ""))


def view(ctx):
    c = conf(ctx)
    w = wish(ctx)
    r = ctx.root_result()
    n, oldest = asks_waiting(ctx)
    if not r and not n and time.time() - READ["asked"] > 30:
        ask(ctx, {"do": "read"})
        n = 1
    h = w.get("hash") or ""
    trial = r.get("trial") if isinstance(r.get("trial"), dict) else {}
    if n:
        state = "waiting" if h and r.get("hash") != h else ("trial" if trial.get("until") else "done")
    elif h and r.get("asked_hash") == h and r.get("ok") is False:
        state = "failed"
    elif h and r.get("back_hash") == h:
        state = "back"
    elif trial.get("until"):
        state = "trial"
    elif not h or r.get("hash") == h:
        state = "done"
    else:
        state = "waiting"
    helper = os.path.exists("/opt/fake-igd/fake_igd_web.py") or bool(os.environ.get("FAKE_IGD_STATE"))
    return {"conf": c, "wish": w, "now": {k: v for k, v in r.items() if k not in ("payload",)},
            "state": state, "state_words": STATE_WORDS[state], "pending": n,
            "late": "%d ask(s) of root are waiting for more than five minutes - is fake-igd-web.path "
                    "running?" % n if n and oldest > 300 else "",
            "helper": helper, "now_at": time.time(), "node": socket.gethostname().split(".")[0]}


def get(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    by = ctx.me.get("name", "")
    if act == "keep":
        ask(ctx, {"do": "keep"})
        ctx.event("%s kept the change of the SSH server" % by, "warn")
        return dict(view(ctx), message="kept - the timer that would put it back is stopped")
    if act == "back":
        ask(ctx, {"do": "back", "why": "asked on the pages by %s" % by[:40]})
        ctx.event("%s put the SSH server back as it was before the change on trial" % by, "warn")
        return dict(view(ctx), message="put back within a few seconds")
    if act == "apply":
        apply(ctx, by)
        return dict(view(ctx), message="put in again within a few seconds")
    if act == "refresh":
        ask(ctx, {"do": "read"})
        return dict(view(ctx), message="asked again")
    raise ValueError("keep, back, apply or refresh")


def background(ctx):
    """A trial whose time is up read again (root puts it back if its timer did not), and what sshd
    has read now and then."""
    r = ctx.root_result()
    trial = r.get("trial") if isinstance(r.get("trial"), dict) else {}
    try:
        until = float(trial.get("until") or 0)
    except (TypeError, ValueError):
        until = 0
    n, _ = asks_waiting(ctx)
    if n:
        return
    if (until and time.time() > until + 45 and time.time() - READ["asked"] > 60) or \
            (time.time() - float(r.get("at") or 0) > 1800 and time.time() - READ["asked"] > 600):
        ask(ctx, {"do": "read"})


ROUTES = {("GET", "/api/sshd"): get, ("POST", "/api/sshd"): post}
