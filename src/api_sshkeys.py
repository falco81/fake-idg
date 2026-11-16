"""api_sshkeys.py - Settings -> SSH keys (1.6.0; otp's sshkeys_view, sshkeys_ask, sshkey_pair).

The keys that may sign in over SSH - as root (/root/.ssh/authorized_keys, only shown: put on and
taken away by root on the machine itself, as otp 1.0.280) or as any user who may sign in (their
own ~/.ssh/authorized_keys, written as they are by root's child that is that user -
deploy/root_sshkeys.py). A key made here for a user is shown once, to be kept by you, and kept
nowhere on the server; one of your own is put on by its public half (or a private key, of which
only the public half is worked out and used).

  GET  /api/sshkeys                                      what root read last, every user's
  POST /api/sshkeys {action: refresh, user}              read again
  POST /api/sshkeys {action: add, user, line[, passphrase]}
  POST /api/sshkeys {action: drop, user, fp}
  POST /api/sshkeys {action: uk_make, user, kind: ed25519|rsa4096}  -> {private, pub, fp, file}
"""
import base64
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time

import igd_panes as PN

NAME = "sshkeys"
SSH_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "ssh-rsa", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
KEY_LINE_RE = re.compile(r"^(?P<type>[a-z0-9@.-]+) (?P<blob>[A-Za-z0-9+/]{40,16000}={0,3})"
                         r"(?: (?P<comment>[^\x00-\x1f\x7f]{0,200}))?\Z")
SSH_KEY_KINDS = {"ed25519": ["-t", "ed25519"], "rsa4096": ["-t", "rsa", "-b", "4096"]}
READ = {"asked": 0.0}


def keygen():
    return os.environ.get("FAKE_IGD_SSH_KEYGEN") or shutil.which("ssh-keygen") or ""


# ---- a key, read from itself (as root_sshkeys) ------------------------------------------------
def key_facts(typ, b64):
    try:
        blob = base64.b64decode(b64, validate=True)
        parts, i = [], 0
        while i + 4 <= len(blob):
            n = struct.unpack(">I", blob[i:i + 4])[0]
            if n > len(blob) - i - 4:
                return None
            parts.append(blob[i + 4:i + 4 + n])
            i += 4 + n
        if i != len(blob):
            return None
    except (ValueError, struct.error):
        return None
    if not parts or parts[0].decode("ascii", "replace") != typ:
        return None
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    if typ in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        return 256, fp, "ED25519" if typ == "ssh-ed25519" else "ED25519-SK"
    if typ == "ssh-rsa" and len(parts) == 3:
        return int.from_bytes(parts[2], "big").bit_length(), fp, "RSA"
    m = re.match(r"^ecdsa-sha2-nistp(256|384|521)\Z", typ)
    if m:
        return int(m.group(1)), fp, "ECDSA"
    if typ == "sk-ecdsa-sha2-nistp256@openssh.com":
        return 256, fp, "ECDSA-SK"
    return None


def public_checked(line):
    """(the line, its fingerprint) of one public key line - refused otherwise."""
    line = str(line or "").strip()
    if len(line) > 16500 or "\n" in line:
        raise ValueError("one public key line")
    m = KEY_LINE_RE.match(line)
    if not m or m.group("type") not in KEY_TYPES:
        if line.startswith("ssh-dss "):
            raise ValueError("DSA keys are not taken")
        raise ValueError("that is not one public key line (ssh-ed25519 AAAA... comment) - options before the "
                         "key are not taken here")
    facts = key_facts(m.group("type"), m.group("blob"))
    if not facts:
        raise ValueError("that key does not read as the key it says it is")
    if facts[2] == "RSA" and facts[0] < 3072:
        raise ValueError("an RSA key of %d bits is too weak: 3072 at least, or ed25519" % facts[0])
    return line, facts[1]


def public_of(text, passphrase=""):
    """A public line - or a private key, of which only the public half is worked out (ssh-keygen -y)
    and nothing else kept. (line, was_private)."""
    text = str(text or "").strip().replace("\r\n", "\n")
    if "PRIVATE KEY" not in text:
        return public_checked(text.split("\n")[0].strip())[0], False
    if len(text) > 65536:
        raise ValueError("that is far bigger than a key")
    exe = keygen()
    if not exe:
        raise ValueError("ssh-keygen is not on this machine (dnf install openssh-clients) - give the public line")
    with tempfile.TemporaryDirectory(prefix=".fake-igd-key-") as work:
        path = os.path.join(work, "k")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text + "\n")
        got = subprocess.run([exe, "-y", "-P", str(passphrase or ""), "-f", path], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
    if got.returncode != 0 or not got.stdout.strip():
        raise ValueError("ssh-keygen does not read that private key%s" % (
            " - is the passphrase right?" if "passphrase" in (got.stderr or "").lower() or passphrase else ""))
    return public_checked(got.stdout.strip().split("\n")[0])[0], True


def key_pair(kind, comment):
    """A new pair made by ssh-keygen in a folder of its own, taken away after: (private, public, fp)."""
    if kind not in SSH_KEY_KINDS:
        raise ValueError("ed25519 or rsa4096")
    exe = keygen()
    if not exe:
        raise ValueError("ssh-keygen is not on this machine (dnf install openssh-clients)")
    comment = re.sub(r"[^A-Za-z0-9@._ -]", "", str(comment or ""))[:80].strip() or "key"
    with tempfile.TemporaryDirectory(prefix=".fake-igd-key-") as work:
        path = os.path.join(work, "k")
        got = subprocess.run([exe, "-q"] + SSH_KEY_KINDS[kind] + ["-a", "100", "-N", "", "-C", comment, "-f", path],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        if got.returncode != 0:
            raise ValueError("ssh-keygen: %s" % (got.stderr or got.stdout).strip()[:200])
        with open(path) as f:
            private = f.read()
        with open(path + ".pub") as f:
            public = f.read().strip()
    line, fp = public_checked(public)
    return private, line, fp


# ---- what root read, kept per user --------------------------------------------------------------
def asks_waiting(ctx):
    folder = PN.ask_folder(ctx.cfg.get("state_dir"))
    ages = []
    for p in glob.glob(os.path.join(folder, "%s-*.json" % NAME)):
        try:
            ages.append(time.time() - os.stat(p).st_mtime)
        except OSError:
            pass
    return len(ages), max(ages) if ages else 0


def now(ctx):
    """root's answers, each kept: root's keys, and each user's that was read (the last 30)."""
    try:
        row = json.loads(ctx.store.get_meta("sshkeys:now") or "{}")
    except ValueError:
        row = {}
    if not isinstance(row, dict):
        row = {}
    r = ctx.root_result()
    if r.get("id") and r.get("id") != row.get("seen"):
        row["seen"] = r["id"]
        of = row.get("keys_of") if isinstance(row.get("keys_of"), dict) else {}
        user = str(r.get("user") or "root")
        if SSH_USER_RE.match(user):
            mine = dict(of.get(user) or {})
            mine.update(at=r.get("at"), error="" if r.get("ok") else "; ".join(r.get("said") or []))
            if "keys" in r:
                mine.update(keys=r.get("keys") or [], file=r.get("file") or "")
            of[user] = mine
        if isinstance(r.get("root_keys"), list) and user != "root":
            root = dict(of.get("root") or {})
            root.update(keys=r["root_keys"], at=r.get("at"), file=root.get("file") or "/root/.ssh/authorized_keys")
            of["root"] = root
        if len(of) > 31:
            for k in sorted((k for k in of if k != "root"), key=lambda k: float(of[k].get("at") or 0))[:len(of) - 31]:
                of.pop(k, None)
        row.update(keys_of=of, users=r.get("users") if isinstance(r.get("users"), list) else row.get("users") or [],
                   sshd=r.get("sshd") if isinstance(r.get("sshd"), dict) else row.get("sshd") or {},
                   at=r.get("at"))
        if r.get("do") in ("add", "drop"):
            row["last"] = {"ok": bool(r.get("ok")), "said": "; ".join(r.get("said") or []), "user": user,
                           "at": r.get("at"), "by": r.get("by") or ""}
        ctx.store.set_meta("sshkeys:now", json.dumps(row))
    return row


def ask(ctx, do, user, **kw):
    READ["asked"] = time.time()
    d = {"do": do, "user": user}
    d.update(kw)
    return ctx.ask_root(d)


def user_checked(ctx, user, row):
    user = str(user or "root")
    if not SSH_USER_RE.match(user):
        raise ValueError("that is not the name of a user")
    if user != "root" and row.get("users") and not any(u.get("name") == user for u in row["users"]):
        raise ValueError("%s is not a user who may sign in on this machine" % user)
    return user


def view(ctx):
    row = now(ctx)
    n, oldest = asks_waiting(ctx)
    if not row.get("at") and not n and time.time() - READ["asked"] > 30:
        ask(ctx, "list", "root")
        n = 1
    return {"keys_of": row.get("keys_of") or {}, "users": row.get("users") or [], "sshd": row.get("sshd") or {},
            "at": row.get("at"), "last": row.get("last") or {}, "pending": n,
            "late": "%d ask(s) of root are waiting for more than five minutes - is fake-igd-web.path running?" % n
            if n and oldest > 300 else "",
            "keygen": bool(keygen()), "node": socket.gethostname().split(".")[0]}


def get(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    by = ctx.me.get("name", "")
    act = str(b.get("action") or "")
    row = now(ctx)
    user = user_checked(ctx, b.get("user"), row)
    if act in ("add", "drop", "uk_make") and user == "root":
        raise PermissionError("root's SSH keys are only shown on these pages - put on and taken away by root on "
                              "the machine itself (/root/.ssh/authorized_keys)")
    if act == "refresh":
        ask(ctx, "list", user)
        return dict(view(ctx), message="asked again")
    if act == "add":
        line, was_private = public_of(b.get("line"), str(b.get("passphrase") or ""))
        _, fp = public_checked(line)
        ask(ctx, "add", user, line=line)
        comment = line.split(" ", 2)[2] if line.count(" ") >= 2 else ""
        ctx.event("%s added the SSH key %s%s for %s" % (by, fp, " (%s)" % comment if comment else "", user), "warn")
        return dict(view(ctx), message="the key goes on within a few seconds%s" % (
            " - the private half was not kept" if was_private else ""))
    if act == "drop":
        fp = str(b.get("fp") or "")
        if not re.match(r"^SHA256:[A-Za-z0-9+/]{43}\Z", fp):
            raise ValueError("which key? (its SHA256 fingerprint)")
        ask(ctx, "drop", user, fp=fp)
        ctx.event("%s took away the SSH key %s of %s" % (by, fp, user), "warn")
        return dict(view(ctx), message="the key is taken away within a few seconds")
    if act == "uk_make":
        kind = str(b.get("kind") or "ed25519")
        node = socket.gethostname().split(".")[0]
        private, public, fp = key_pair(kind, "%s@%s %s" % (user, node, time.strftime("%Y-%m-%d")))
        ask(ctx, "add", user, line=public)
        ctx.event("%s made a new SSH key for %s (%s) - its private half handed to the page once, kept nowhere"
                  % (by, user, fp), "warn")
        return {"private": private, "pub": public, "fp": fp, "user": user,
                "file": "fake-igd-%s-%s" % (re.sub(r"[^A-Za-z0-9-]", "", user), time.strftime("%Y%m%d")),
                "message": "made - keep the private half now, it is not shown again"}
    raise ValueError("refresh, add, drop or uk_make")


def background(ctx):
    now(ctx)


ROUTES = {("GET", "/api/sshkeys"): get, ("POST", "/api/sshkeys"): post}
