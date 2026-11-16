"""api_osusers.py - Settings -> Local users (1.6.0; otp's osu_view, osu_ask, osu_hash, the policy).

The users of this machine's own system - who may sign in to it, over SSH or at its console; not
the accounts of these pages. root is shown and never changed here; the others (UID 1000 and up)
are made, given a password or sudo, locked or taken away by root (deploy/root_osusers.py). A
password typed here goes to root as its hash only (SHA-512 crypt, `openssl passwd -6` from its
standard input) and is kept nowhere. The password policy, each user's password aging (chage),
and whether the upnp console opens when they sign in (/etc/upnp-console-login, through sudo).

  GET  /api/osusers
  POST /api/osusers {action: refresh | add | password | lock | unlock | sudo | set | aging | drop |
                     policy | console, name, ...}
"""
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time

import igd_panes as PN

NAME = "osusers"
NEW_NAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\Z")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
KEEP = ("root", "fake-igd", "fake-igd-www", "fake-igd-web", "nginx", "apache", "nobody", "sshd", "polkitd",
        "dbus", "chrony", "avahi", "tss", "systemd-network", "systemd-resolve", "systemd-oom",
        "systemd-coredump", "php-fpm", "postfix", "unbound", "rpc")
DOS = ("list", "add", "password", "lock", "unlock", "sudo", "set", "aging", "drop")
PW_MIN = 8
PWP_DEFAULT = {"managed": False, "minlen": 12, "minclass": 3, "maxrepeat": 3, "dictcheck": 1, "usercheck": 1,
               "difok": 5, "remember": 5, "max_days": 99999, "min_days": 0, "warn_days": 7, "deny": 0,
               "unlock_time": 900, "fail_interval": 900, "existing": False}
PWP_RANGES = {"minlen": (6, 128), "minclass": (0, 4), "maxrepeat": (0, 20), "difok": (0, 20), "remember": (0, 50),
              "max_days": (1, 99999), "min_days": (0, 365), "warn_days": (0, 365), "deny": (0, 100),
              "unlock_time": (0, 86400), "fail_interval": (60, 86400)}
PWP_WORDS = {"minlen": "the shortest password", "max_days": "days a password is good",
             "min_days": "the least days between two changes", "warn_days": "days warned before",
             "remember": "the last passwords not taken again", "deny": "wrong passwords before the lock",
             "unlock_time": "how long locked", "fail_interval": "counted within", "minclass": "kinds of characters",
             "maxrepeat": "the same character in a row", "difok": "characters not in the old one"}
CONSOLE_FLAG = os.environ.get("UPNP_CONSOLE_FLAG", "/etc/upnp-console-login")
READ = {"asked": 0.0}


def asks_waiting(ctx):
    folder = PN.ask_folder(ctx.cfg.get("state_dir"))
    ages = []
    for p in glob.glob(os.path.join(folder, "%s-*.json" % NAME)):
        try:
            ages.append(time.time() - os.stat(p).st_mtime)
        except OSError:
            pass
    return len(ages), max(ages) if ages else 0


def ask(ctx, payload):
    READ["asked"] = time.time()
    return ctx.ask_root(payload)


# ---- the password policy ------------------------------------------------------------------------
def pwp_conf(ctx):
    try:
        got = json.loads(ctx.store.get_meta("osusers:policy") or "{}")
    except ValueError:
        got = {}
    c = dict(PWP_DEFAULT)
    if isinstance(got, dict):
        c.update({k: v for k, v in got.items() if k in PWP_DEFAULT})
    return c


def pwp_hash(c):
    return hashlib.sha256(json.dumps({k: c[k] for k in PWP_DEFAULT}, sort_keys=True).encode()).hexdigest()[:16]


def pwp_checked(b):
    c = dict(PWP_DEFAULT)
    for k in PWP_DEFAULT:
        if k not in b:
            continue
        if k in PWP_RANGES:
            if isinstance(b[k], bool):
                raise ValueError("%s is a number" % PWP_WORDS.get(k, k))
            try:
                v = int(b[k])
            except (TypeError, ValueError):
                raise ValueError("%s is a number" % PWP_WORDS.get(k, k))
            lo, hi = PWP_RANGES[k]
            if not lo <= v <= hi:
                raise ValueError("%s is %d to %d" % (PWP_WORDS.get(k, k), lo, hi))
            c[k] = v
        else:
            v = b[k]
            on = v.strip().lower() in ("1", "yes", "on", "true") if isinstance(v, str) else bool(v)
            c[k] = on if k in ("managed", "existing") else (1 if on else 0)
    if c["min_days"] and c["max_days"] < 99999 and c["min_days"] > c["max_days"]:
        raise ValueError("the least days between two changes is more than the days a password is good")
    return c


def pwp_password_check(ctx, password, name):
    """A password set from these pages kept to the policy: by pwscore (the system's own rules and its
    dictionary) where it is there, by the rules set here where it is not."""
    c = pwp_conf(ctx)
    if not c["managed"]:
        return
    exe = shutil.which("pwscore")
    if exe:
        got = subprocess.run([exe, name], input=password + "\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=30)
        if got.returncode != 0:
            why = ((got.stderr or got.stdout or "").strip().splitlines() or ["refused"])[-1]
            why = re.sub(r"^Password quality check failed:\s*", "", why)
            raise ValueError("the password policy does not take it: %s" % why[:200])
        return
    if len(password) < c["minlen"]:
        raise ValueError("the password policy wants %d characters at least" % c["minlen"])
    kinds = sum(1 for rx in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]") if re.search(rx, password))
    if kinds < c["minclass"]:
        raise ValueError("the password policy wants %d kinds of characters at least (small letters, capitals, "
                         "digits, others) - it has %d" % (c["minclass"], kinds))
    if c["maxrepeat"] and re.search(r"(.)\1{%d,}" % c["maxrepeat"], password):
        raise ValueError("the password policy takes no character more than %d times in a row" % c["maxrepeat"])
    if c["usercheck"] and name and len(name) >= 3 and name.lower() in password.lower():
        raise ValueError("the password policy takes no password with the user's name in it")


def pw_hash(ctx, password, name):
    """The SHA-512 crypt hash of a password, by openssl from its standard input."""
    pw = str(password or "")
    if pw:
        pwp_password_check(ctx, pw, name)
    if len(pw) < PW_MIN:
        raise ValueError("the password is %d characters at least" % PW_MIN)
    if len(pw) > 256 or re.search(r"[\x00-\x1f\x7f]", pw):
        raise ValueError("the password is 256 characters at most, with no line breaks")
    exe = shutil.which("openssl")
    if not exe:
        raise ValueError("openssl is not on this machine - it makes the password's hash")
    got = subprocess.run([exe, "passwd", "-6", "-stdin"], input=pw + "\n", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
    h = (got.stdout or "").strip()
    if got.returncode != 0 or not h.startswith("$6$"):
        raise ValueError("openssl did not make the password's hash: %s" % ((got.stderr or "").strip()[:200] or
                                                                            "no answer"))
    return h


# ---- the console at login ----------------------------------------------------------------------
def console_read():
    try:
        fd = os.open(CONSOLE_FLAG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False, [], False
    try:
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


# ---- the view -----------------------------------------------------------------------------------
def view(ctx):
    r = ctx.root_result()
    n, oldest = asks_waiting(ctx)
    if not r.get("users") and not n and time.time() - READ["asked"] > 30:
        ask(ctx, {"do": "list"})
        n = 1
    pol = pwp_conf(ctx)
    con_root, con_users, con_there = console_read()
    return {"users": r.get("users") or [], "admin_group": r.get("admin_group") or "", "shells": r.get("shells") or [],
            "uid_min": r.get("uid_min"), "uid_max": r.get("uid_max"), "today": r.get("today"),
            "at": r.get("at"), "done": r.get("done") or [],
            "last": {"ok": r.get("ok"), "said": "; ".join(r.get("said") or []), "do": r.get("do"),
                     "name": r.get("name"), "at": r.get("at")},
            "policy": pol, "policy_now": r.get("policy") or {},
            "policy_applied": r.get("policy_hash") == pwp_hash(pol) or (not pol["managed"] and
                                                                        not (r.get("policy") or {}).get("managed")),
            "console": {"root": con_root, "users": con_users, "there": con_there, "file": CONSOLE_FLAG},
            "pending": n,
            "late": "%d ask(s) of root are waiting for more than five minutes - is fake-igd-web.path running?" % n
            if n and oldest > 300 else "",
            "node": socket.gethostname().split(".")[0], "pw_min": max(PW_MIN, pol["minlen"] if pol["managed"] else 0), "openssl": bool(shutil.which("openssl"))}


def known(ctx, name):
    r = ctx.root_result()
    return [u for u in (r.get("users") or []) if u.get("name") == name]


def get(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    by = ctx.me.get("name", "")
    act = str(b.get("action") or "")
    if act == "policy":
        p = b.get("policy")
        c = pwp_checked(p if isinstance(p, dict) else {})
        ctx.store.set_meta("osusers:policy", json.dumps(dict(c, at=time.time(), by=by)))
        ask(ctx, {"do": "policy", "conf": c, "hash": pwp_hash(c)})
        ctx.event("%s %s the password policy of the local users%s" % (
            by, "set" if c["managed"] else "gave back to the system",
            (": at least %d characters, %d kinds, %s, history %d, %s" % (
                c["minlen"], c["minclass"], "good for %d days" % c["max_days"] if c["max_days"] < 99999
                else "no end", c["remember"], "locked after %d wrong" % c["deny"] if c["deny"] else "no lockout"))
            if c["managed"] else ""), "warn")
        return dict(view(ctx), message="root puts it in within a few seconds")
    if act == "refresh":
        ask(ctx, {"do": "list"})
        return dict(view(ctx), message="asked again")
    name = str(b.get("name") or "")
    if name == "root":
        raise PermissionError("root is shown here, never changed - on the machine itself only")
    if not USER_RE.match(name) or name in KEEP or name.lower() != name:
        raise ValueError("a user's name is small letters, digits, _ . and -, 32 at most, starting with a letter - "
                         "and not one of the system's")
    if act == "console":
        on = b.get("on") is True
        _, cur, _ = console_read()
        if cur == "*":
            every = [u["name"] for u in (ctx.root_result().get("users") or []) if u.get("login") and not u.get("root")]
            users = "*" if on else [u for u in every if u != name]
        else:
            users = [u for u in cur if u != name] + ([name] if on else [])
        ask(ctx, {"do": "console", "users": users})
        ctx.event("%s %s the upnp console at login for %s" % (by, "opened" if on else "closed", name), "warn")
        return dict(view(ctx), message="within a few seconds")
    if act not in DOS:
        raise ValueError("no such thing to do with a user")
    if act != "add" and ctx.root_result().get("users") and not known(ctx, name) and act != "drop":
        raise ValueError("there is no user %s here" % name)
    a = {"do": act, "name": name}
    if act in ("add", "set"):
        if "gecos" in b:
            g = str(b.get("gecos") or "").strip()
            if len(g) > 120 or re.search(r"[:\x00-\x1f\x7f]", g):
                raise ValueError("the full name is 120 characters at most, without a colon")
            a["gecos"] = g
        if "shell" in b:
            s = str(b.get("shell") or "")
            if not re.match(r"^/[A-Za-z0-9_./-]{1,80}\Z", s):
                raise ValueError("that is not a shell")
            a["shell"] = s
    if act == "add":
        if not NEW_NAME_RE.match(name):
            raise ValueError("a name is small letters, digits, _ . and -, starting with a letter")
        if known(ctx, name):
            raise ValueError("%s is there already" % name)
        a["sudo"] = b.get("sudo") is True
        if a["sudo"] and not b.get("password"):
            raise ValueError("sudo asks for the user's own password - give them one, or they cannot use sudo")
        a["must_change"] = b.get("must_change") is True and bool(b.get("password"))
        if b.get("password"):
            a["hash"] = pw_hash(ctx, b["password"], name)
    elif act == "password":
        a["hash"] = pw_hash(ctx, b.get("password"), name)
        a["must_change"] = b.get("must_change") is True
        pol = pwp_conf(ctx)
        if pol["managed"]:
            a["policy_aging"] = {k: pol[k] for k in ("max_days", "min_days", "warn_days")}
    elif act == "sudo":
        a["on"] = b.get("on") is True
    elif act == "drop":
        a["home"] = b.get("home") is True
    elif act == "aging":
        for k in ("max_days", "min_days", "warn_days"):
            if k in b and b[k] not in (None, ""):
                try:
                    v = int(b[k])
                except (TypeError, ValueError):
                    raise ValueError("%s is a number" % PWP_WORDS.get(k, k))
                lo, hi = PWP_RANGES[k]
                if k == "max_days":
                    lo = 0
                if not lo <= v <= hi:
                    raise ValueError("%s is %d to %d" % (PWP_WORDS.get(k, k), lo, hi))
                a[k] = v
    ask(ctx, a)
    words = {"add": "made the local user %s" % name,
             "password": "set a new password for the local user %s" % name,
             "lock": "locked the local user %s" % name,
             "unlock": "unlocked the local user %s" % name,
             "sudo": "%s the local user %s sudo" % ("gave" if a.get("on") else "took from", name),
             "set": "changed the local user %s" % name,
             "drop": "took away the local user %s%s" % (name, " and the home folder" if a.get("home") else ""),
             "aging": "set the password aging of the local user %s (%s)" % (name, ", ".join(
                 "%s %s" % (k, a[k]) for k in ("max_days", "min_days", "warn_days") if k in a))}[act]
    if act == "add":
        words += " (%s%s)" % ("sudo, " if a["sudo"] else "", "a password set" if a.get("hash") else "no password")
    ctx.event("%s %s" % (by, words), "warn")
    return dict(view(ctx), message="done within a few seconds")


def background(ctx):
    """The policy put in again where root has another (a change asked and lost, a file edited)."""
    r = ctx.root_result()
    pol = pwp_conf(ctx)
    n, _ = asks_waiting(ctx)
    if n or not r:
        return
    if pol["managed"] and r.get("policy_hash") != pwp_hash(pol) and time.time() - READ["asked"] > 600:
        ask(ctx, {"do": "policy", "conf": pol, "hash": pwp_hash(pol)})


ROUTES = {("GET", "/api/osusers"): get, ("POST", "/api/osusers"): post}
