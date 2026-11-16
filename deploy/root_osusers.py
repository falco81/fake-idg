#!/usr/bin/python3 -I
"""root_osusers.py - Settings -> Local users, root's part (1.6.0; otp's lu_do and pwp_apply).

The users of this machine's own system - who may sign in to it, over SSH or at its console; not
the accounts of the pages. Done with the system's own tools, as an administrator would at the
console: useradd, usermod, chpasswd -e, chage, gpasswd, userdel.

  * root is read, never changed; accounts of the system (outside UID_MIN..UID_MAX of
    /etc/login.defs) and the services' own (fake-igd, nginx, sshd ...) are neither shown nor
    changed - every name is checked here again;
  * a password comes as its hash only (SHA-512 crypt, made by the API with `openssl passwd -6`
    from its standard input) and is handed to `chpasswd -e` on ITS standard input - never on a
    command line, never in a log, never in the answer;
  * locked: the password put out of use (usermod -L) AND the account expired (chage -E 0) - no
    SSH key lets them in either; unlocked: both undone;
  * the password policy (otp's 1.0.245): one for every local user, put into the system's own
    files so that it holds however a password is changed - pwquality.conf.d/50-fake-igd.conf,
    fake-igd's lines between marks in pwhistory.conf and faillock.conf, the aging lines of
    login.defs (the values before kept to be put back), with authselect the features that put
    the modules into PAM (only those fake-igd switched on are switched off again). Not managed:
    what fake-igd wrote is taken out again;
  * the upnp console at login for normal users (/etc/upnp-console-login, its "users:" line -
    `upnp --console-users`); root's own line is left as it is.

Asked as {"do": "list" | "add" | "password" | "lock" | "unlock" | "sudo" | "set" | "aging" |
"drop" | "policy" | "console", "name": ..., ...}. Each answer: the list, the policy in effect,
and what was done last (kept by root, the last 20).

Paths and tools for a test: FAKE_IGD_PASSWD, FAKE_IGD_GROUP, FAKE_IGD_SHADOW, FAKE_IGD_SHELLS,
FAKE_IGD_LOGIN_DEFS, FAKE_IGD_SECURITY_DIR, FAKE_IGD_PAM_DIR, FAKE_IGD_AUTHSELECT,
FAKE_IGD_ROOT_STATE, FAKE_IGD_CONSOLE_FLAG, FAKE_IGD_LU_BIN (a folder the tools are taken from).
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time

PASSWD = os.environ.get("FAKE_IGD_PASSWD", "/etc/passwd")
GROUP = os.environ.get("FAKE_IGD_GROUP", "/etc/group")
SHADOW = os.environ.get("FAKE_IGD_SHADOW", "/etc/shadow")
SHELLS_FILE = os.environ.get("FAKE_IGD_SHELLS", "/etc/shells")
LOGIN_DEFS = os.environ.get("FAKE_IGD_LOGIN_DEFS", "/etc/login.defs")
SEC_DIR = os.environ.get("FAKE_IGD_SECURITY_DIR", "/etc/security")
PAM_DIR = os.environ.get("FAKE_IGD_PAM_DIR", "/etc/pam.d")
LU_BIN = os.environ.get("FAKE_IGD_LU_BIN", "")
AUTHSELECT = os.environ.get("FAKE_IGD_AUTHSELECT", shutil.which("authselect") or "")
ROOT_STATE = os.environ.get("FAKE_IGD_ROOT_STATE", "/var/lib/fake-igd-root")
CONSOLE_FLAG = os.environ.get("FAKE_IGD_CONSOLE_FLAG") or os.environ.get("UPNP_CONSOLE_FLAG") or \
    "/etc/upnp-console-login"
NO_SERVICES = os.environ.get("FAKE_IGD_NO_SERVICES") == "1"
USER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
NEW_NAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\Z")
PW_HASH_RE = re.compile(r"^\$(?:6|5|y|gy|2b|2y)\$[./A-Za-z0-9$=]{16,300}\Z")
GECOS_RE = re.compile(r"^[^:\n\x00-\x1f\x7f]{0,120}\Z")
NO_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
KEEP_NAMES = ("root", "fake-igd", "fake-igd-www", "fake-igd-web", "nginx", "apache", "nobody", "sshd",
              "polkitd", "dbus", "chrony", "avahi", "tss", "systemd-network", "systemd-resolve",
              "systemd-oom", "systemd-coredump", "php-fpm", "postfix", "unbound", "rpc")
PWP_MARK_A = "# ---- fake-igd: Settings -> Local users -> Password policy (from here) ----\n"
PWP_MARK_B = "# ---- fake-igd: (to here) ----\n"
PWQ_DROPIN = "pwquality.conf.d/50-fake-igd.conf"
PWP_FEATURES = ("with-pwhistory", "with-faillock")
PWQ_KEYS = ("minlen", "minclass", "maxrepeat", "dictcheck", "usercheck", "enforce_for_root", "difok", "retry")
PWQ_DEFAULT = {"minlen": 8, "minclass": 0, "maxrepeat": 0, "dictcheck": 1, "usercheck": 1,
               "enforce_for_root": 0, "difok": 1, "retry": 1}
DEFS_KEYS = ("PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE")
DOS = ("list", "add", "password", "lock", "unlock", "sudo", "set", "aging", "drop", "policy", "console")


class Refused(Exception):
    pass


# ---- files ------------------------------------------------------------------------------------
def read_text(path, most=4 << 20):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
        with os.fdopen(fd, "rb") as f:
            return f.read(most).decode("utf-8", "replace")
    except OSError:
        return None


def put_file(path, text, mode=0o644):
    folder = os.path.dirname(path)
    if os.path.islink(path) or os.path.islink(folder):
        raise Refused("%s is a link - not written" % path)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".fake-igd-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if shutil.which("restorecon") and not NO_SERVICES:
        subprocess.run(["restorecon", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tool(name):
    if LU_BIN:
        return os.path.join(LU_BIN, name)
    return shutil.which(name) or "/usr/sbin/" + name


def run(argv, data=None):
    """A tool of shadow-utils, its error said back - never with a secret among the words."""
    argv = [tool(argv[0])] + list(argv[1:])
    try:
        got = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=120)
    except OSError as e:
        raise Refused("%s: %s" % (os.path.basename(argv[0]), e.strerror or e))
    if got.returncode != 0:
        msg = ((got.stderr or got.stdout or "").strip().splitlines() or ["exit %d" % got.returncode])[-1]
        raise Refused("%s: %s" % (os.path.basename(argv[0]), msg[:300]))
    return got.stdout


# ---- who is there --------------------------------------------------------------------------
class Pw(object):
    def __init__(self, p):
        self.pw_name, self.pw_uid, self.pw_gid = p[0], int(p[2]), int(p[3])
        self.pw_gecos, self.pw_dir, self.pw_shell = p[4], p[5], p[6]


def passwd():
    out = []
    for ln in (read_text(PASSWD) or "").split("\n"):
        p = ln.split(":")
        if len(p) >= 7 and p[2].isdigit() and p[3].isdigit():
            out.append(Pw(p))
    return out


def groups():
    """[(name, gid, [members])]."""
    out = []
    for ln in (read_text(GROUP) or "").split("\n"):
        p = ln.split(":")
        if len(p) >= 4 and p[2].isdigit():
            out.append((p[0], int(p[2]), [m for m in p[3].split(",") if m]))
    return out


def shadow():
    """{name: (hash field, last change, max days, expire day, min days, warn days)} - read as root."""
    out = {}
    for ln in (read_text(SHADOW) or "").split("\n"):
        p = ln.split(":")
        if len(p) >= 8:
            out[p[0]] = (p[1], p[2], p[4], p[7], p[3], p[5])
    return out


def uid_range():
    lo, hi = 1000, 60000
    for ln in (read_text(LOGIN_DEFS) or "").split("\n"):
        w = ln.split()
        if len(w) >= 2 and w[0] in ("UID_MIN", "UID_MAX") and w[1].isdigit():
            if w[0] == "UID_MIN":
                lo = int(w[1])
            else:
                hi = int(w[1])
    return lo, hi


def admin_group():
    names = [g[0] for g in groups()]
    for g in ("wheel", "sudo"):
        if g in names:
            return g
    return ""


def shells():
    out = []
    for ln in (read_text(SHELLS_FILE) or "").split("\n"):
        ln = ln.strip()
        if ln.startswith("/") and " " not in ln and ln not in out and os.path.basename(ln) not in NO_SHELLS:
            out.append(ln)
    if not out:
        out.append("/bin/bash")
    nl = "/usr/sbin/nologin" if os.path.exists("/usr/sbin/nologin") or not os.path.exists("/sbin/nologin") \
        else "/sbin/nologin"
    return out[:20] + [nl]


def console_read():
    """(root on, the normal users it opens for: '*', a list, or [])."""
    text = read_text(CONSOLE_FLAG, 8192)
    if text is None:
        return False, []
    lines = text.split("\n")
    users = []
    for ln in lines[1:]:
        if ln.startswith("users:"):
            words = ln[6:].split()
            users = "*" if words == ["*"] else [w for w in words if USER_NAME_RE.match(w)][:200]
    return lines[0].strip() == "on", users


def one(p, sh, admin, today, grs):
    h, last, mx, exp, mn, wn = sh.get(p.pw_name, ("", "", "", "", "", ""))
    gnames = {g[0] for g in grs if p.pw_name in g[2]} | {g[0] for g in grs if g[1] == p.pw_gid}
    plain = h.lstrip("!")
    locked = (h.startswith("!") and plain.startswith("$")) or (exp.isdigit() and int(exp) <= today)
    return {"name": p.pw_name, "uid": p.pw_uid, "gecos": p.pw_gecos.split(",")[0][:120],
            "home": p.pw_dir, "shell": p.pw_shell,
            "login": bool(p.pw_shell) and os.path.basename(p.pw_shell) not in NO_SHELLS,
            "groups": sorted(gnames)[:40], "sudo": bool(admin) and admin in gnames,
            "password": bool(plain) and plain.startswith("$"),
            "locked": bool(locked), "must_change": last == "0",
            "changed": int(last) if last.isdigit() and last != "0" else None,
            "expires": int(exp) if exp.isdigit() and int(exp) > 0 else None,
            "max_days": int(mx) if mx.isdigit() and int(mx) < 99999 else None,
            "min_days": int(mn) if mn.isdigit() else 0, "warn_days": int(wn) if wn.isdigit() else None,
            "pw_ends": (int(last) + int(mx)) if last.isdigit() and last != "0" and mx.isdigit()
            and int(mx) < 99999 else None,
            "home_there": os.path.isdir(p.pw_dir)}


def listing():
    lo, hi = uid_range()
    sh, admin, today, grs = shadow(), admin_group(), int(time.time() // 86400), groups()
    users = []
    for p in passwd():
        if p.pw_name == "root" or (lo <= p.pw_uid <= hi and p.pw_uid != 65534 and
                                   USER_NAME_RE.match(p.pw_name) and p.pw_name not in KEEP_NAMES):
            if any(u["name"] == p.pw_name for u in users):
                continue
            u = one(p, sh, admin, today, grs)
            u["root"] = p.pw_name == "root"
            users.append(u)
    users.sort(key=lambda u: (not u["root"], u["name"]))
    try:
        policy = pwp_read()
    except Exception as e:                              # noqa: BLE001
        policy = {"error": str(e)[:200]}
    con_root, con_users = console_read()
    return {"users": users[:500], "uid_min": lo, "uid_max": hi, "admin_group": admin, "shells": shells(),
            "today": today, "policy": policy, "policy_hash": state_read().get("policy_hash") or "",
            "console": {"root": con_root, "users": con_users, "file": CONSOLE_FLAG,
                        "there": read_text(CONSOLE_FLAG, 8192) is not None}}


def target(name):
    """The passwd entry of a user this may change - refused for root, the system and services."""
    name = str(name or "")
    if not USER_NAME_RE.match(name) or name in KEEP_NAMES:
        raise Refused("%s is not a local user this may change" % name[:40])
    p = next((x for x in passwd() if x.pw_name == name), None)
    if p is None:
        return None
    lo, hi = uid_range()
    if not lo <= p.pw_uid <= hi or p.pw_uid == 65534:
        raise Refused("%s is an account of the system (UID %d) - not changed here" % (name, p.pw_uid))
    return p


def hash_checked(h):
    h = str(h or "")
    if not PW_HASH_RE.match(h):
        raise Refused("the password does not come as a hash this takes")
    return h


def sudo_set(name, on):
    g = admin_group()
    if not g:
        raise Refused("this machine has no wheel or sudo group")
    member = any(x[0] == g and name in x[2] for x in groups())
    if on and not member:
        run(["gpasswd", "-a", name, g])
    elif not on and member:
        run(["gpasswd", "-d", name, g])


def int_or(v, default=None):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


# ---- what root keeps: what was done, the policy put in -----------------------------------------
def state_path():
    return os.path.join(ROOT_STATE, "osusers.json")


def state_read():
    try:
        got = json.loads(read_text(state_path()) or "{}")
    except ValueError:
        return {}
    return got if isinstance(got, dict) else {}


def state_write(s):
    os.makedirs(ROOT_STATE, mode=0o700, exist_ok=True)
    try:
        os.chmod(ROOT_STATE, 0o700)
    except OSError:
        pass
    put_file(state_path(), json.dumps(s), 0o600)


# ---- the console at login ----------------------------------------------------------------------
def console_set(users):
    if users != "*":
        if not isinstance(users, list) or len(users) > 200:
            raise Refused("the users: \"*\" or a list of names, 200 at most")
        out = []
        for u in users:
            if not isinstance(u, str) or not USER_NAME_RE.match(u) or u == "root":
                raise Refused("%r is not the name of a normal user" % str(u)[:40])
            if u not in out:
                out.append(u)
        users = out
    on = console_read()[0]
    text = "on\n" if on else "off\n"
    if users:
        text += "users: %s\n" % ("*" if users == "*" else " ".join(users))
    folder = os.path.dirname(CONSOLE_FLAG)
    tmp = os.path.join(folder, ".%s.%d.tmp" % (os.path.basename(CONSOLE_FLAG), os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, text.encode())
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, CONSOLE_FLAG)
    return "the upnp console at login: %s" % ("every normal user" if users == "*" else
                                              ", ".join(users) if users else "no normal user")


# ---- the password policy (otp's pwp_*) ----------------------------------------------------------
def pwp_conf_read(path, flags=("enforce_for_root", "even_deny_root")):
    out = {}
    for ln in (read_text(path) or "").split("\n"):
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        if "=" in ln:
            k, v = [x.strip() for x in ln.split("=", 1)]
            out[k] = v
        elif ln in flags:
            out[ln] = "1"
    return out


def pwp_pam():
    text = ""
    for f in ("system-auth", "password-auth", "common-password", "common-auth", "common-account"):
        text += (read_text(os.path.join(PAM_DIR, f)) or "") + "\n"
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]

    def has(m):
        return any(m in ln for ln in lines)
    return {"pwquality": has("pam_pwquality"), "pwhistory": has("pam_pwhistory"),
            "faillock": has("pam_faillock"), "read": bool(text.strip())}


def pwp_authselect():
    if not AUTHSELECT or not os.path.exists(AUTHSELECT):
        return None
    try:
        got = subprocess.run([AUTHSELECT, "current", "--raw"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if got.returncode != 0 or not got.stdout.strip():
        return None
    words = got.stdout.split()
    return {"profile": words[0], "features": words[1:]}


def pwp_read():
    """The policy as in effect here, read from its files."""
    pwq = dict(PWQ_DEFAULT)
    raw = pwp_conf_read(os.path.join(SEC_DIR, "pwquality.conf"))
    d = os.path.join(SEC_DIR, "pwquality.conf.d")
    try:
        for name in sorted(os.listdir(d)):
            if name.endswith(".conf"):
                raw.update(pwp_conf_read(os.path.join(d, name)))
    except OSError:
        pass
    for k in PWQ_KEYS:
        if k in raw:
            pwq[k] = int_or(raw[k], raw[k])
    hist = pwp_conf_read(os.path.join(SEC_DIR, "pwhistory.conf"))
    fl = pwp_conf_read(os.path.join(SEC_DIR, "faillock.conf"), flags=("even_deny_root", "silent", "audit"))
    defs = {}
    for ln in (read_text(LOGIN_DEFS) or "").split("\n"):
        w = ln.split()
        if len(w) >= 2 and w[0] in DEFS_KEYS:
            defs[w[0]] = int_or(w[1], w[1])
    pam = pwp_pam()
    return {"pwquality": pwq, "remember": int_or(hist.get("remember"), 10 if pam["pwhistory"] else 0),
            "faillock": {"deny": int_or(fl.get("deny"), 3), "unlock_time": int_or(fl.get("unlock_time"), 600),
                         "fail_interval": int_or(fl.get("fail_interval"), 900)},
            "aging": {"max_days": defs.get("PASS_MAX_DAYS", 99999), "min_days": defs.get("PASS_MIN_DAYS", 0),
                      "warn_days": defs.get("PASS_WARN_AGE", 7)},
            "pam": pam, "authselect": pwp_authselect(),
            "managed": os.path.exists(os.path.join(SEC_DIR, PWQ_DROPIN)),
            "pwscore": bool(shutil.which("pwscore"))}


def pwp_block_put(path, lines):
    """fake-igd's lines between the marks: put in, replaced, or (None) taken out; the rest as it is."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("%s is not a plain file - not written" % path)
        text = read_text(path) or ""
        mode = stat.S_IMODE(st.st_mode)
    except FileNotFoundError:
        if lines is None:
            return
        text, mode = "", 0o644
    a, b = text.find(PWP_MARK_A), text.find(PWP_MARK_B)
    if lines is None and not (a >= 0 and b > a):
        return
    was = text
    if a >= 0 and b > a:
        text = text[:a] + text[b + len(PWP_MARK_B):]
    if lines is not None:
        if text and not text.endswith("\n"):
            text += "\n"
        text += PWP_MARK_A + "".join("%s\n" % ln for ln in lines) + PWP_MARK_B
    if text != was:
        put_file(path, text, mode)


def pwp_defs_put(values):
    """login.defs' aging lines set (values) or put back as they were (None). The lines as they were
    are kept in login.defs itself, commented between fake-igd's marks."""
    text = read_text(LOGIN_DEFS)
    if text is None:
        raise Refused("%s cannot be read" % LOGIN_DEFS)
    a, b = text.find(PWP_MARK_A), text.find(PWP_MARK_B)
    was = {}
    if a >= 0 and b > a:
        for ln in text[a + len(PWP_MARK_A):b].split("\n"):
            if ln.startswith("# fake-igd-was: "):
                k, _, line = ln[len("# fake-igd-was: "):].partition(" ")
                if k in DEFS_KEYS:
                    was[k] = line
        text = text[:a] + text[b + len(PWP_MARK_B):]
    lines = text.split("\n")
    if values is not None and not was:
        for k in DEFS_KEYS:
            was[k] = next((ln for ln in lines if ln.split()[:1] == [k]), "")
    out, seen = [], set()
    for ln in lines:
        w = ln.split()
        if w and w[0] in DEFS_KEYS:
            if values is not None:
                if w[0] not in seen:
                    out.append("%s\t%s" % (w[0], values[w[0]]))
                seen.add(w[0])
                continue
            if w[0] in was:
                if w[0] not in seen and was[w[0]]:
                    out.append(was[w[0]])
                seen.add(w[0])
                continue
        out.append(ln)
    if values is not None:
        for k in DEFS_KEYS:
            if k not in seen:
                out.append("%s\t%s" % (k, values[k]))
        text = "\n".join(out)
        if not text.endswith("\n"):
            text += "\n"
        text += PWP_MARK_A + "".join("# fake-igd-was: %s %s\n" % (k, was.get(k, "")) for k in DEFS_KEYS) + PWP_MARK_B
    else:
        for k in DEFS_KEYS:
            if k in was and was[k] and k not in seen:
                out.append(was[k])
        text = "\n".join(out)
    put_file(LOGIN_DEFS, text, stat.S_IMODE(os.stat(LOGIN_DEFS).st_mode))


def pwp_checked(c):
    if not isinstance(c, dict):
        raise Refused("the policy is not an object")

    def num(k, lo, hi, default):
        v = c.get(k, default)
        if isinstance(v, bool):
            raise Refused("%s is a number" % k)
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise Refused("%s is a number" % k)
        if not lo <= v <= hi:
            raise Refused("%s is %d to %d" % (k, lo, hi))
        return v
    return {"managed": c.get("managed") is True,
            "minlen": num("minlen", 6, 128, 12), "minclass": num("minclass", 0, 4, 3),
            "maxrepeat": num("maxrepeat", 0, 20, 3), "dictcheck": 1 if c.get("dictcheck", 1) else 0,
            "usercheck": 1 if c.get("usercheck", 1) else 0, "difok": num("difok", 0, 20, 5),
            "remember": num("remember", 0, 50, 5),
            "max_days": num("max_days", 0, 99999, 99999), "min_days": num("min_days", 0, 365, 0),
            "warn_days": num("warn_days", 0, 365, 7),
            "deny": num("deny", 0, 100, 0), "unlock_time": num("unlock_time", 0, 86400, 900),
            "fail_interval": num("fail_interval", 60, 86400, 900),
            "existing": c.get("existing") is True}


def pwp_hash(c):
    return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()[:16]


def pwp_apply(c):
    c = pwp_checked(c)
    said = []
    st = state_read()
    sel = pwp_authselect()
    added = [f for f in (st.get("features") or []) if f in PWP_FEATURES]
    dropin = os.path.join(SEC_DIR, PWQ_DROPIN)

    def note(features):
        s = state_read()
        s["features"] = features
        state_write(s)
    if not c["managed"]:
        if os.path.exists(dropin) and not os.path.islink(dropin):
            os.unlink(dropin)
            said.append("pwquality: fake-igd's drop-in taken out")
        for f in ("pwhistory.conf", "faillock.conf"):
            pwp_block_put(os.path.join(SEC_DIR, f), None)
        if PWP_MARK_A in (read_text(LOGIN_DEFS) or ""):
            pwp_defs_put(None)
            said.append("login.defs: the aging as it was")
        if sel:
            for feat in added:
                if feat in sel["features"]:
                    run([AUTHSELECT, "disable-feature", feat])
                    said.append("authselect: %s taken out again" % feat)
        note([])
        return said or ["nothing of fake-igd's was there"], c
    os.makedirs(os.path.dirname(dropin), exist_ok=True)
    put_file(dropin, "# written by fake-igd - Settings -> Local users -> Password policy\n"
             "minlen = %(minlen)d\nminclass = %(minclass)d\nmaxrepeat = %(maxrepeat)d\n"
             "dictcheck = %(dictcheck)d\nusercheck = %(usercheck)d\ndifok = %(difok)d\n"
             "retry = 3\n" % c, 0o644)
    said.append("pwquality: at least %d characters, %d kinds" % (c["minlen"], c["minclass"]))
    pwp_block_put(os.path.join(SEC_DIR, "pwhistory.conf"),
                  ["remember = %d" % c["remember"]] if c["remember"] else None)
    pwp_block_put(os.path.join(SEC_DIR, "faillock.conf"),
                  ["deny = %d" % c["deny"], "unlock_time = %d" % c["unlock_time"],
                   "fail_interval = %d" % c["fail_interval"]] if c["deny"] else None)
    pwp_defs_put({"PASS_MAX_DAYS": c["max_days"], "PASS_MIN_DAYS": c["min_days"], "PASS_WARN_AGE": c["warn_days"]})
    said.append("login.defs: a password good for %s days" % (c["max_days"] if c["max_days"] < 99999 else "all"))
    if sel:
        want = (["with-pwhistory"] if c["remember"] else []) + (["with-faillock"] if c["deny"] else [])
        for feat in want:
            if feat not in sel["features"]:
                added.append(feat)
                note(added)
                run([AUTHSELECT, "enable-feature", feat])
                said.append("authselect: %s put in" % feat)
        for feat in [f for f in added if f not in want]:
            if feat in sel["features"]:
                run([AUTHSELECT, "disable-feature", feat])
                said.append("authselect: %s taken out again" % feat)
            added = [f for f in added if f != feat]
        note(added)
    if c["existing"]:
        lo, hi = uid_range()
        n = skipped = 0
        sh = shadow()
        for p in passwd():
            if lo <= p.pw_uid <= hi and p.pw_uid != 65534 and p.pw_name not in KEEP_NAMES and \
                    USER_NAME_RE.match(p.pw_name):
                if not sh.get(p.pw_name, ("",))[0].lstrip("!").startswith("$"):
                    skipped += 1        # no password: a key only - never asked for a new one
                    continue
                run(["chage", "-M", str(c["max_days"]), "-m", str(c["min_days"]), "-W", str(c["warn_days"]), p.pw_name])
                n += 1
        said.append("the aging put on %d user(s) too%s" % (
            n, " (%d with no password - a key only - left without)" % skipped if skipped else ""))
    return said, c


# ---- one change ------------------------------------------------------------------------------
def do_one(r):
    do = str(r.get("do") or "list")
    if do not in DOS:
        raise Refused("list, add, password, lock, unlock, sudo, set, aging, drop, policy or console")
    name = str(r.get("name") or "")
    if do == "list":
        return ""
    if do == "policy":
        said, c = pwp_apply(r.get("conf") or {})
        s = state_read()
        s["policy_hash"] = str(r.get("hash") or pwp_hash(c))[:32]
        state_write(s)
        return "; ".join(said)
    if do == "console":
        return console_set(r.get("users"))
    p = target(name)
    if do == "add":
        if not NEW_NAME_RE.match(name):
            raise Refused("a new user's name is small letters, digits, _ . and -, starting with a letter")
        gecos = str(r.get("gecos") or "")
        shell = str(r.get("shell") or "/bin/bash")
        if not GECOS_RE.match(gecos):
            raise Refused("the full name has letters that cannot be in it (a colon, a line break)")
        if shell not in shells():
            raise Refused("%s is not a shell of /etc/shells here" % shell[:60])
        h = hash_checked(r["hash"]) if r.get("hash") else ""
        if p is not None:
            return "%s was here already" % name
        run(["useradd", "-m", "-s", shell, "-c", gecos, "-U", "--", name])
        if h:
            run(["chpasswd", "-e"], "%s:%s\n" % (name, h))
        else:
            # No password - a key only: no password aging for it, or once its days ran out sshd
            # would ask, at every sign-in by a key too, for a new password the user never had.
            run(["chage", "-M", "-1", "-I", "-1", name])
        if r.get("must_change") is True and h:
            run(["chage", "-d", "0", name])
        if r.get("sudo") is True:
            sudo_set(name, True)
        return "%s made%s" % (name, ", with sudo" if r.get("sudo") is True else "")
    if p is None:
        if do == "drop":
            return "%s was not here" % name
        raise Refused("there is no user %s here" % name)
    if do == "password":
        h = hash_checked(r.get("hash"))
        run(["chpasswd", "-e"], "%s:%s\n" % (name, h))
        ag = r.get("policy_aging")
        if isinstance(ag, dict):
            mx, mn, wn = int_or(ag.get("max_days"), 99999), int_or(ag.get("min_days"), 0), int_or(ag.get("warn_days"), 7)
            if 0 <= mx <= 99999 and 0 <= mn <= 365 and 0 <= wn <= 365:
                run(["chage", "-M", str(mx), "-m", str(mn), "-W", str(wn), name])
        run(["chage", "-d", "0" if r.get("must_change") is True else str(int(time.time() // 86400)), name])
        return "the password of %s set%s" % (name, ", to be changed at the next sign-in"
                                              if r.get("must_change") is True else "")
    if do == "lock":
        h = shadow().get(name, ("",))[0]
        if h and not h.startswith("!"):
            run(["usermod", "-L", "--", name])
        run(["chage", "-E", "0", name])
        return "%s locked" % name
    if do == "unlock":
        h = shadow().get(name, ("",))[0]
        for _ in range(4):
            if not (h.startswith("!") and re.match(r"^\$[0-9a-z]{1,3}\$", h.lstrip("!"))):
                break
            run(["usermod", "-U", "--", name])
            h = shadow().get(name, ("",))[0]
        run(["chage", "-E", "-1", name])
        return "%s unlocked" % name
    if do == "sudo":
        sudo_set(name, r.get("on") is True)
        return "%s %s" % (name, "may use sudo" if r.get("on") is True else "no longer uses sudo")
    if do == "set":
        argv = ["usermod"]
        if "gecos" in r:
            g = str(r.get("gecos") or "")
            if not GECOS_RE.match(g):
                raise Refused("the full name has letters that cannot be in it (a colon, a line break)")
            if g != p.pw_gecos.split(",")[0]:
                rest = p.pw_gecos.split(",", 1)[1:]
                argv += ["-c", ",".join([g] + rest) if rest and "," not in g else g]
        if "shell" in r:
            s = str(r.get("shell") or "")
            if s != p.pw_shell:
                if s not in shells():
                    raise Refused("%s is not a shell of /etc/shells here" % s[:60])
                argv += ["-s", s]
        if len(argv) > 1:
            run(argv + ["--", name])
            return "%s changed" % name
        return "%s as it was" % name
    if do == "aging":
        argv = ["chage"]
        for k, opt, lo, hi in (("max_days", "-M", 0, 99999), ("min_days", "-m", 0, 365), ("warn_days", "-W", 0, 365)):
            if k in r:
                v = r.get(k)
                v = None if isinstance(v, bool) else int_or(v)
                if v is None or not lo <= v <= hi:
                    raise Refused("%s is %d to %d" % (k, lo, hi))
                argv += [opt, str(v)]
        if len(argv) > 1:
            run(argv + [name])
        return "the password aging of %s set" % name
    if do == "drop":
        busy = subprocess.run([tool("pgrep"), "-u", str(p.pw_uid)], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, universal_newlines=True)
        if busy.stdout.strip():
            raise Refused("%s is signed in or runs something here - sign them out first" % name)
        run(["userdel"] + (["-r"] if r.get("home") is True else []) + ["--", name])
        # Out of the console's list too.
        con = console_read()[1]
        if isinstance(con, list) and name in con:
            console_set([u for u in con if u != name])
        return "%s taken away%s" % (name, " with the home folder" if r.get("home") is True else "")
    raise Refused("no such thing to do")


def serve(payload, ask=None):
    r = payload or {}
    do = str(r.get("do") or "list")
    ok, said = True, ""
    try:
        said = do_one(r)
    except Refused as e:
        ok, said = False, str(e)[:400]
    except (OSError, subprocess.SubprocessError) as e:
        ok, said = False, "it went wrong: %s" % str(e)[:300]
    if do != "list":
        try:
            s = state_read()
            hist = [x for x in (s.get("said") or []) if isinstance(x, dict)]
            hist.append({"at": time.time(), "do": do[:12], "name": str(r.get("name") or "")[:32]
                         if USER_NAME_RE.match(str(r.get("name") or "")) else "",
                         "by": str((ask or {}).get("by") or "")[:80], "ok": ok, "said": said[:400]})
            s["said"] = hist[-20:]
            state_write(s)
        except (OSError, Refused):
            pass
    out = listing()
    out.update(ok=ok, said=[said] if said else [], do=do, name=str(r.get("name") or "")[:32],
               done=state_read().get("said") or [], read_at=time.time())
    return out
