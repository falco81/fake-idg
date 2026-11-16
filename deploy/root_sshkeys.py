#!/usr/bin/python3 -I
"""root_sshkeys.py - Settings -> SSH keys, root's part (1.6.0; otp's sshkeys_do).

The keys that may sign in over SSH: root's (/root/.ssh/authorized_keys) - ONLY READ here, as otp
1.0.280 has it: a way in as root is put on or taken away by root on the machine itself, never
from the pages - and those of every user who may sign in (UID_MIN..UID_MAX of /etc/login.defs, a
login shell), their own ~/.ssh/authorized_keys: listed, a key added, a key taken away.

A user's file is read and written AS THAT USER - by a child that has their UID, GID and groups:
~/.ssh made 0700 and the file 0600, theirs; a link put there (to /etc/shadow, to /root/.ssh) is
refused and never followed, so nothing in a user's own home can make root write anywhere else.
A name that is not such a user (a system account, one with nologin, "../root") is refused.

Asked as {"do": "list" | "add" | "drop", "user": "root" | NAME, "line": "...", "fp": "SHA256:..."}.
The answer: the keys of the user asked (type, bits, comment, fingerprint, the public line), the
users who may sign in, and what sshd makes of root and of keys.

A key's facts are read from the key itself (its blob, SHA-256 of it for the fingerprint - what
`ssh-keygen -l -E sha256` says), so nothing is run for a line of a user's file.

Paths for a test: FAKE_IGD_ROOT_AUTHKEYS, FAKE_IGD_PASSWD, FAKE_IGD_LOGIN_DEFS, FAKE_IGD_SSHD,
FAKE_IGD_NO_SERVICES=1 (no restorecon).
"""
import base64
import errno
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time

ROOT_AUTH = os.environ.get("FAKE_IGD_ROOT_AUTHKEYS", "/root/.ssh/authorized_keys")
PASSWD = os.environ.get("FAKE_IGD_PASSWD", "/etc/passwd")
LOGIN_DEFS = os.environ.get("FAKE_IGD_LOGIN_DEFS", "/etc/login.defs")
SSHD_BIN = os.environ.get("FAKE_IGD_SSHD") or shutil.which("sshd") or "/usr/sbin/sshd"
NO_SERVICES = os.environ.get("FAKE_IGD_NO_SERVICES") == "1"
USER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
NO_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "ssh-rsa", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
KEY_LINE_RE = re.compile(r"^(?P<type>[a-z0-9@.-]+) (?P<blob>[A-Za-z0-9+/]{40,16000}={0,3})"
                         r"(?: (?P<comment>[^\x00-\x1f\x7f]{0,200}))?\Z")
KEY_IN_LINE_RE = re.compile(r"(?:^|\s)(?P<type>(?:ssh|ecdsa|sk)-[a-z0-9@.-]+) (?P<blob>[A-Za-z0-9+/]{40,16000}={0,3})"
                            r"(?:\s+(?P<comment>[^\x00-\x1f\x7f]{0,200}))?\s*\Z")
AUTH_KEYS_MAX = 1000
AUTH_READ_MAX = 1 << 20


class Refused(Exception):
    pass


# ---- a key, read from itself --------------------------------------------------------------
def _strings(blob):
    out, i = [], 0
    while i + 4 <= len(blob):
        n = struct.unpack(">I", blob[i:i + 4])[0]
        if n > len(blob) - i - 4:
            raise ValueError("short")
        out.append(blob[i + 4:i + 4 + n])
        i += 4 + n
    if i != len(blob):
        raise ValueError("left over")
    return out


def key_facts(typ, b64):
    """(bits, 'SHA256:...', 'ED25519') of a key, or None when the blob is not that key."""
    try:
        blob = base64.b64decode(b64, validate=True)
        parts = _strings(blob)
    except (ValueError, struct.error):
        return None
    if not parts or parts[0].decode("ascii", "replace") != typ:
        return None
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    if typ == "ssh-ed25519" and len(parts) == 2 and len(parts[1]) == 32:
        return 256, fp, "ED25519"
    if typ == "sk-ssh-ed25519@openssh.com" and len(parts) == 3:
        return 256, fp, "ED25519-SK"
    if typ == "ssh-rsa" and len(parts) == 3:
        return int.from_bytes(parts[2], "big").bit_length(), fp, "RSA"
    if typ == "ssh-dss" and len(parts) == 5:
        return int.from_bytes(parts[1], "big").bit_length(), fp, "DSA"
    m = re.match(r"^ecdsa-sha2-nistp(256|384|521)\Z", typ)
    if m and len(parts) == 3:
        return int(m.group(1)), fp, "ECDSA"
    if typ == "sk-ecdsa-sha2-nistp256@openssh.com" and len(parts) == 4:
        return 256, fp, "ECDSA-SK"
    return None


def auth_keys(lines):
    out = []
    for i, ln in enumerate(lines):
        t = ln.strip()
        if not t or t.startswith("#"):
            continue
        if len(out) >= AUTH_KEYS_MAX:
            break
        m = KEY_LINE_RE.match(t)
        k = m or KEY_IN_LINE_RE.search(t)
        facts = key_facts(k.group("type"), k.group("blob")) if k and len(t) <= 16500 else None
        out.append({"line": i, "fp": facts[1] if facts else "", "bits": facts[0] if facts else 0,
                    "type": facts[2] if facts else "?",
                    "comment": ((k.group("comment") or "") if k else "").strip()[:200],
                    "options": not bool(m), "readable": bool(facts),
                    # The public line itself, for the page's export: public halves only.
                    "text": t[:16500]})
    return out


def key_line_checked(line):
    m = KEY_LINE_RE.match(line)
    if not m or m.group("type") not in KEY_TYPES:
        raise Refused("that is not one public key line (ssh-ed25519 AAAA... comment) - "
                      "options before the key are not taken here")
    facts = key_facts(m.group("type"), m.group("blob"))
    if not facts:
        raise Refused("that key does not read as the key it says it is")
    bits, fp, kind = facts
    if kind == "RSA" and bits < 3072:
        raise Refused("an RSA key of %d bits is too weak: 3072 at least, or ed25519" % bits)
    return fp


# ---- root's ---------------------------------------------------------------------------------
def root_lines():
    try:
        fd = os.open(ROOT_AUTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise Refused("%s cannot be read: %s" % (ROOT_AUTH, e))
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused("%s is not a plain file" % ROOT_AUTH)
        return f.read(AUTH_READ_MAX).split("\n")


# ---- the users who may sign in --------------------------------------------------------------
class Pw(object):
    def __init__(self, name, uid, gid, gecos, home, shell):
        self.pw_name, self.pw_uid, self.pw_gid = name, uid, gid
        self.pw_gecos, self.pw_dir, self.pw_shell = gecos, home, shell


def passwd():
    """The local users, as /etc/passwd lists them."""
    out = []
    try:
        with open(PASSWD, encoding="utf-8", errors="replace") as f:
            for ln in f:
                p = ln.rstrip("\n").split(":")
                if len(p) >= 7 and p[2].isdigit() and p[3].isdigit():
                    out.append(Pw(p[0], int(p[2]), int(p[3]), p[4], p[5], p[6]))
    except OSError:
        pass
    return out


def uid_range():
    lo, hi = 1000, 60000
    try:
        with open(LOGIN_DEFS, encoding="utf-8", errors="replace") as f:
            for ln in f:
                w = ln.split()
                if len(w) >= 2 and w[0] in ("UID_MIN", "UID_MAX") and w[1].isdigit():
                    if w[0] == "UID_MIN":
                        lo = int(w[1])
                    else:
                        hi = int(w[1])
    except OSError:
        pass
    return lo, hi


def normal_users():
    """[{name, uid, home, shell}] of the users who may sign in here, by name - 500 at most."""
    lo, hi = uid_range()
    out = []
    for p in passwd():
        if not lo <= p.pw_uid <= hi or p.pw_uid == 65534 or not USER_NAME_RE.match(p.pw_name):
            continue
        if not p.pw_shell or os.path.basename(p.pw_shell) in NO_SHELLS:
            continue
        if not p.pw_dir.startswith("/") or p.pw_dir == "/":
            continue
        if any(u["name"] == p.pw_name for u in out):
            continue
        out.append({"name": p.pw_name, "uid": p.pw_uid, "home": p.pw_dir, "shell": p.pw_shell})
    out.sort(key=lambda x: x["name"])
    return out[:500]


def ssh_user(name):
    name = str(name or "")
    if not USER_NAME_RE.match(name) or not any(u["name"] == name for u in normal_users()):
        raise Refused("%s is not a user who may sign in on this machine" % name[:40])
    return [p for p in passwd() if p.pw_name == name][0]


def as_user(pw, fn):
    """fn() run by a child that is the user - its answer (JSON) back through a pipe."""
    rd, wr = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            os.close(rd)
            try:
                groups = os.getgrouplist(pw.pw_name, pw.pw_gid)
            except (KeyError, OSError):
                groups = [pw.pw_gid]
            os.setgroups(groups)
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            if os.getuid() != pw.pw_uid or os.geteuid() != pw.pw_uid or pw.pw_uid == 0:
                raise OSError("could not become %s" % pw.pw_name)
            os.umask(0o077)
            try:
                got = {"ok": True, "data": fn()}
            except Refused as e:
                got = {"ok": False, "said": str(e)}
            except OSError as e:
                got = {"ok": False, "said": "%s: %s" % (e.filename or pw.pw_name, e.strerror or e)}
            data = json.dumps(got).encode()[:4 << 20]
            while data:
                data = data[os.write(wr, data):]
        except BaseException as e:                      # noqa: BLE001
            try:
                os.write(wr, json.dumps({"ok": False, "said": str(e)[:300]}).encode())
            except BaseException:                       # noqa: BLE001
                pass
            code = 1
        finally:
            os._exit(code)
    os.close(wr)
    chunks = []
    # A deadline: the child is the user's, who may stop it (SIGSTOP).
    end = time.time() + 30
    late = False
    with os.fdopen(rd, "rb") as f:
        while True:
            left = end - time.time()
            ready = select.select([f], [], [], max(0.0, left))[0] if left > 0 else []
            if not ready:
                late = True
                break
            b = os.read(f.fileno(), 65536)
            if not b:
                break
            chunks.append(b)
    if late:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    os.waitpid(pid, 0)
    if late:
        raise Refused("the child working as %s did not answer in 30 s" % pw.pw_name)
    try:
        got = json.loads(b"".join(chunks).decode("utf-8", "replace") or "{}")
    except ValueError:
        got = {}
    if not got.get("ok"):
        raise Refused(got.get("said") or "it went wrong as %s" % pw.pw_name)
    return got.get("data")


def user_paths(pw):
    return os.path.join(pw.pw_dir, ".ssh"), os.path.join(pw.pw_dir, ".ssh", "authorized_keys")


def user_read(pw):
    folder, path = user_paths(pw)

    def go():
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return ""
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise Refused("%s is a link - put the file itself there" % path)
            raise
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise Refused("%s is not a plain file" % path)
            return f.read(AUTH_READ_MAX)
    return (as_user(pw, go) or "").split("\n")


def user_write(pw, lines):
    """~/.ssh/authorized_keys of the user, written by the user: ~/.ssh made 0700 when it is not
    there, refused when it or the file is a link; a new file, 0600, renamed in."""
    folder, path = user_paths(pw)
    text = "\n".join(lines).rstrip("\n") + "\n"

    def go():
        hs = os.lstat(pw.pw_dir)
        if stat.S_ISLNK(hs.st_mode) or not stat.S_ISDIR(hs.st_mode) or hs.st_uid != pw.pw_uid:
            raise Refused("%s is not a home folder of %s's own" % (pw.pw_dir, pw.pw_name))
        try:
            st = os.lstat(folder)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise Refused("%s is not a plain folder" % folder)
        except FileNotFoundError:
            os.mkdir(folder, 0o700)
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                raise Refused("%s is a link - put the file itself there" % path)
            if st.st_size > AUTH_READ_MAX:
                raise Refused("%s is longer than 1 MiB - shorten it by hand first" % path)
        except FileNotFoundError:
            pass
        fd, tmp = tempfile.mkstemp(prefix=".authorized_keys.", dir=folder)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                fd = None
                f.write(text)
            os.replace(tmp, path)
        except BaseException:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    as_user(pw, go)
    if shutil.which("restorecon") and not NO_SERVICES:
        subprocess.run(["restorecon", "-R", folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---- what sshd makes of it -----------------------------------------------------------------
def sshd_says():
    if not os.path.exists(SSHD_BIN):
        return {"there": False}
    try:
        got = subprocess.run([SSHD_BIN, "-T"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return {"there": True}
    said = {}
    for ln in got.stdout.splitlines():
        k, _, v = ln.partition(" ")
        if k in ("permitrootlogin", "pubkeyauthentication", "passwordauthentication", "port"):
            said[k] = v.strip() if k not in said else said[k] + " " + v.strip()
    return {"there": True, "permit_root": said.get("permitrootlogin", ""),
            "pubkey": said.get("pubkeyauthentication", ""),
            "password": said.get("passwordauthentication", ""), "port": said.get("port", "")}


def shown(keys):
    return [dict((k, v) for k, v in x.items() if k != "line") for x in keys]


def serve(payload, ask=None):
    r = payload or {}
    user = str(r.get("user") or "root")
    do = str(r.get("do") or "list")
    said, ok = "", True
    out = {"user": user, "do": do}
    try:
        if do not in ("list", "add", "drop"):
            raise Refused("list, add or drop")
        if user == "root":
            if do != "list":
                raise Refused("root's SSH keys are only shown on these pages - put on and taken away by root "
                              "on the machine itself (%s)" % ROOT_AUTH)
            out.update(keys=shown(auth_keys(root_lines())), file=ROOT_AUTH)
        else:
            pw = ssh_user(user)
            lines = user_read(pw)
            if do == "add":
                line = str(r.get("line") or "").strip()
                if len(line) > 16500 or "\n" in line:
                    raise Refused("one public key line")
                fp = key_line_checked(line)
                if any(k["fp"] == fp for k in auth_keys(lines)):
                    said = "that key was there already"
                else:
                    user_write(pw, [ln for ln in lines if ln.strip()] + [line])
                    said = "the key %s added for %s" % (fp, user)
            elif do == "drop":
                fp = str(r.get("fp") or "")
                hit = [k for k in auth_keys(lines) if k["fp"] and k["fp"] == fp]
                if not hit:
                    raise Refused("no key %s is there" % fp[:80])
                gone = {k["line"] for k in hit}
                user_write(pw, [ln for i, ln in enumerate(lines) if i not in gone])
                said = "the key %s taken away from %s" % (fp, user)
            lines = user_read(pw)
            out.update(keys=shown(auth_keys(lines)), file=user_paths(pw)[1])
    except Refused as e:
        ok, said = False, str(e)[:400]
    except OSError as e:
        ok, said = False, "it went wrong: %s" % str(e)[:300]
    # Root's keys with every answer: what sshd makes of root needs them on the pages.
    try:
        out["root_keys"] = shown(auth_keys(root_lines())) if user != "root" else out.get("keys", [])
    except Refused as e:
        out["root_keys"] = []
        out["root_error"] = str(e)[:200]
    out.update(ok=ok, said=[said] if said else [], users=normal_users(), sshd=sshd_says(),
               read_at=time.time())
    return out
