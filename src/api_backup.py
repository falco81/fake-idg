"""api_backup.py - Settings → Backups (otp's remote backups, `rbackup`, for fake-igd).

A backup is everything that makes this installation what it is, in one file
fake-igd-backup-SITE-NODE-YYYYMMDD-HHMMSS.tar.gz.enc:

  fake-igd.db       the whole database (SQLite's backup API: whole while it is written to)
  secrets.key       the key its secrets are sealed with (igd_seal)
  config.json       /etc/fake-igd/config.json
  mappings.json     what the service has handed out (to read)
  system/...        what only root may read, collected by root (deploy/root_backup.py):
                    avahi-daemon.conf, nginx's fake-igd.conf, the certificate and key of the
                    pages, the journal's drop-in, logrotate's file, and fake-igd's lines of
                    /etc/sysconfig/iptables
  manifest.json     what it is, where and when it was made, the SHA-256 of every file
  RESTORE.md        the exact steps to put it back

locked with the password of the backups, as otp locks them:
`openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -salt` - opened by these pages or
by openssl alone. Without a password nothing is sent (otp 1.0.136). Beside it, not locked,
go .sha256 and -RESTORE.md.

Sent to every destination switched on: a folder on this machine (written by root - the API's
sandbox writes only /var/lib/fake-igd), FTP and FTPS (Python's ftplib, as otp), SFTP and SCP
(OpenSSH's sftp, scp and ssh - the server's host key trusted once, a key made here or your
own, or a password through SSH_ASKPASS), SMB (smbclient, an authentication file of its own,
SMB2 at least, SMB3 encryption when asked). Of this machine's backups each destination keeps
rbackup_keep (and none older than rbackup_keep_days). On a schedule (rbackup, rbackup_at,
rbackup_every, rbackup_day), or now; the newest fetched back and tried (rbackup_verify); and
one put back - from a destination or a file sent from the browser: the database (a copy of
what is here made first), config.json (this machine's paths and port kept) and root's files,
then nginx, the firewall and the service as the config says.
"""
import base64
import ftplib
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

import igd_seal as SEAL
from datetime import datetime, timezone

NAME = "backup"
KINDS = ("folder", "ftp", "ftps", "sftp", "scp", "smb")
KIND_WORDS = {"folder": "a folder", "ftp": "FTP", "ftps": "FTPS", "sftp": "SFTP", "scp": "SCP (ssh)",
              "smb": "SMB (Windows share, Samba)"}
PORTS = {"ftp": 21, "ftps": 21, "sftp": 22, "scp": 22, "smb": 445}
SECRET_FIELDS = ("password", "key", "key_pass")
ITER = 600000
TIMEOUT = 60
ROOT_WAIT_S = 150
NAME_RE = re.compile(r"^fake-igd-backup-(?P<site>[A-Za-z0-9_.-]+?)-(?P<node>[A-Za-z0-9_.-]+)-"
                     r"(?P<stamp>\d{8}-\d{6})\.tar\.gz(?P<enc>\.enc)?\Z")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\Z")
UPLOAD_RE = re.compile(r"^upload-[0-9a-f]{16}\Z")
OPEN_MOST_FILES = 200               # a backup opened: its files (and folders) at most (1.9.9)
OPEN_MOST_OTHER = 16 * 1024 * 1024  # ... and each but the database at most (config.json, the system's files)
HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d\Z")
RUNS_KEEP = 60
VERIFY_KEEP = 30
TARGETS_MOST = 20
JOB_LOCK = threading.Lock()
JOB = {"running": False, "what": "", "says": "", "done": 0, "whole": 0, "error": "", "began": 0, "ended": 0,
       "result": None, "by": ""}
MACHINE_KEYS = ("state_dir", "log_file", "request_log", "api_port")


class RbError(Exception):
    pass


def _hhmm(v):
    return "" if HHMM_RE.match(v) else "a time as HH:MM (04:15)"


SETTINGS = [
    {"key": "rbackup", "name": "Backups to the destinations on a schedule", "kind": "bool", "default": False,
     "says": "This machine makes its backup and sends it to every destination switched on, at the time below. "
             "Without it, only Back up now sends one."},
    {"key": "rbackup_at", "name": "At", "kind": "text", "default": "04:15", "check": _hhmm,
     "says": "When, as <code>HH:MM</code> on this machine’s clock.", "only_when": ("rbackup", True)},
    {"key": "rbackup_every", "name": "How often", "kind": "choice", "default": "daily",
     "choices": [("daily", "daily"), ("weekly", "weekly")], "says": "daily, or weekly on the day below.",
     "only_when": ("rbackup", True)},
    {"key": "rbackup_day", "name": "On (1 Monday - 7 Sunday)", "kind": "int", "default": 7, "min": 1, "max": 7,
     "says": "The day of a weekly backup: 1 is Monday, 7 Sunday.", "only_when": ("rbackup_every", "weekly")},
    {"key": "rbackup_keep", "name": "Backups kept at each destination", "kind": "int", "default": 30,
     "min": 1, "max": 1000,
     "says": "How many of this machine’s backups each destination keeps; the oldest go first, the newest never."},
    {"key": "rbackup_keep_days", "name": "And none older than (days)", "kind": "int", "default": 0,
     "min": 0, "max": 3650, "says": "Older ones are taken away too - 0: only the count above decides."},
    {"key": "rbackup_password", "name": "The password of the backups", "kind": "secret", "default": "",
     "says": "Every backup is locked with it (AES-256, opened with fake-igd or with openssl alone). Keep it apart "
             "from the backups as well - in a password vault: without it nobody, you included, opens them. Empty: "
             "nothing is sent - an unlocked backup would hand every account's hash to whoever reads it."},
    {"key": "rbackup_verify", "name": "Try the backups", "kind": "choice", "default": "off",
     "choices": [("off", "only by hand"), ("after", "after every backup, the one just sent"),
                 ("weekly", "once a week, the newest one")],
     "says": "The newest backup fetched back, opened with the password, every file checked, the database read "
             "through and the secrets tried against the key in it - nothing is put back. After every backup, or "
             "once a week."},
]


# ---- small things ---------------------------------------------------------------------------
def node_name():
    return socket.gethostname().split(".")[0] or "fake-igd"


def slug(text):
    """otp's rb_slug: no - in it, so that SITE-NODE-STAMP reads back as it was put."""
    s = re.sub(r"[^A-Za-z0-9_.]+", "_", str(text or "")).strip("_.")
    return s[:40] or "fake_igd"


def site(ctx):
    return slug(ctx.cfg.get("site_name") or "fake_igd")


def base_dir(ctx):
    return os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "backup")


def sub(ctx, name):
    p = os.path.join(base_dir(ctx), name)
    os.makedirs(p, mode=0o770, exist_ok=True)
    return p


def cfg_path():
    main = sys.modules.get("__main__")
    return getattr(main, "CFG_PATH", None) or os.environ.get("FAKE_IGD_CONFIG", "/etc/fake-igd/config.json")


def safe_name(name):
    name = str(name or "")
    if not SAFE_NAME.match(name):
        raise RbError("not a file name of a backup: %r" % name[:80])
    return name


def password(ctx):
    return str(SEAL.unseal_or(ctx.store, ctx.setting("rbackup_password") or ""))


def tools():
    return {t: bool(shutil.which(t)) for t in ("openssl", "ssh", "sftp", "scp", "smbclient", "ssh-keygen",
                                               "ssh-keyscan")}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def said(e):
    if isinstance(e, EOFError):
        return "the server closed the connection"
    if isinstance(e, socket.timeout):
        return "the server did not answer in time"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "the server's certificate is not trusted: %s - pin it, or check it against nothing" % e.verify_message
    if isinstance(e, ftplib.Error):
        return "the FTP server said: %s" % str(e)[:300]
    return (str(e) or e.__class__.__name__)[:400]


# ---- root, asked and waited for -----------------------------------------------------------------
def root_wait(ctx, payload, wait=ROOT_WAIT_S):
    """An ask of root (kind backup), and its answer read from backup/work/JOB.json."""
    job = secrets.token_hex(8)
    payload = dict(payload, job=job)
    sub(ctx, "work")
    ctx.ask_root(payload, kind="backup")
    path = os.path.join(base_dir(ctx), "work", "%s.json" % job)
    end = time.time() + wait
    while time.time() < end:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    got = json.load(f)
            except (OSError, ValueError):
                time.sleep(0.3)
                continue
            try:
                os.unlink(path)
            except OSError:
                pass
            if not got.get("ok"):
                raise RbError("root: %s" % "; ".join(got.get("said") or ["it failed"]))
            got["job"] = job
            return got
        time.sleep(0.4)
    raise RbError("root did not answer in %d s - is fake-igd-web.path running (systemctl status fake-igd-web.path)?"
                  % wait)


# ---- destinations ----------------------------------------------------------------------------------
def targets(ctx):
    """The destinations, their secrets opened (they are kept sealed in the database - igd_seal)."""
    got = ctx.store.meta_json("backup:targets") or {}
    out = []
    for t in list(got.get("list") or []):
        t = dict(t)
        for k in SECRET_FIELDS:
            if t.get(k):
                t[k] = SEAL.unseal_or(ctx.store, t[k])
        out.append(t)
    return out


def put_targets(ctx, ts):
    """The destinations kept, each password and key sealed with the key beside the database."""
    kept = []
    for t in ts:
        t = dict(t)
        for k in SECRET_FIELDS:
            if t.get(k):
                t[k] = SEAL.seal(ctx.store, t[k])
        kept.append(t)
    ctx.store.set_meta("backup:targets", json.dumps({"list": kept}))


def target(ctx, tid):
    for t in targets(ctx):
        if t["id"] == tid:
            return t
    raise ValueError("no such destination")


def fingerprints(hostkey):
    if not hostkey or not shutil.which("ssh-keygen"):
        return []
    with tempfile.NamedTemporaryFile("w", prefix="fake-igd-kh-", delete=False) as f:
        f.write(hostkey)
        kh = f.name
    try:
        r = subprocess.run(["ssh-keygen", "-lf", kh], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=20)
        return [x.strip() for x in r.stdout.splitlines() if x.strip()]
    finally:
        os.unlink(kh)


def view_target(t, last=None):
    v = {k: t.get(k) for k in ("id", "kind", "name", "enabled", "host", "port", "path", "user", "share", "domain",
                               "smb_encrypt", "passive", "implicit", "tls_check", "pin", "pub", "ssh_cert")
         if k in t}
    v.update({"kind_words": KIND_WORDS.get(t["kind"], t["kind"]), "has_password": bool(t.get("password")),
              "has_key": bool(t.get("key")), "hostkey": bool(t.get("hostkey")),
              "hostkey_fp": fingerprints(t.get("hostkey")) if t.get("hostkey") else [],
              "password": "•" * 8 if t.get("password") else "", "last": last})
    return v


def clean(text, what, most=200, pattern=None, empty=True):
    v = str(text if text is not None else "").strip()
    if len(v) > most or "\n" in v or "\x00" in v:
        raise ValueError("%s: one line, at most %d characters" % (what, most))
    if not v and not empty:
        raise ValueError("%s: needed" % what)
    if v and pattern and not re.match(pattern, v):
        raise ValueError("%s: not a value it takes" % what)
    return v


def masked(v):
    return isinstance(v, str) and v.startswith("•")


def checked(data, old=None):
    """otp's rb_checked: a destination as typed on the pages; secrets left out or as dots keep
    what was there - unless the server changed, then they are typed again."""
    old = dict(old or {})
    if not isinstance(data, dict):
        raise ValueError("a destination is an object")
    kind = str(data.get("kind") or old.get("kind") or "")
    if kind not in KINDS:
        raise ValueError("the kind is one of %s" % ", ".join(KINDS))
    t = {"id": old.get("id") or secrets.token_hex(6), "kind": kind}
    t["name"] = clean(data.get("name"), "the name", 60) or \
        ("%s %s" % (KIND_WORDS[kind], data.get("host") or data.get("path") or "")).strip()
    t["enabled"] = 1 if data.get("enabled", old.get("enabled", 1)) else 0
    t["path"] = clean(data.get("path"), "the folder", 400)
    if kind == "folder":
        if not t["path"].startswith("/"):
            raise ValueError("the folder is a whole path on this machine (/mnt/backup/fake-igd)")
        if re.search(r"(^|/)\.\.?(/|$)", t["path"]):
            raise ValueError("the folder has no . or .. in it")
    else:
        t["host"] = clean(data.get("host"), "the server", 253, r"^[A-Za-z0-9\[][A-Za-z0-9.:_\[\]-]*\Z", empty=False)
        try:
            port = int(data.get("port") or PORTS.get(kind) or 0)
        except (TypeError, ValueError):
            raise ValueError("the port is a number")
        if kind == "ftps" and data.get("implicit") and not data.get("port"):
            port = 990
        if not 1 <= port <= 65535:
            raise ValueError("the port is 1 to 65535")
        t["port"] = port
        t["user"] = clean(data.get("user"), "the account", 128, r"^[^\s:@/\\]+\Z")
        if t["user"].startswith("-"):
            raise ValueError("the account does not begin with -")
        if re.search(r'[;"]', t["path"]) or t["path"].lstrip().startswith("-"):
            raise ValueError('the folder has no ; or " in it, and does not begin with -')
        if kind != "smb" and re.search(r"(^|/)\.\.(/|$)", t["path"]):
            raise ValueError("the folder has no .. in it")
        if kind == "scp" and re.search(r"[^A-Za-z0-9._/~+@%=,-]", t["path"]):
            raise ValueError("the folder (SCP) is letters, digits and . _ / ~ + @ % = , - only - use SFTP for any other")
    pw = data.get("password")
    moved = bool(old) and (old.get("kind") != kind or str(old.get("host") or "").lower() != str(t.get("host") or "").lower()
                           or int(old.get("port") or 0) != int(t.get("port") or 0))
    if (pw is None or masked(pw)) and moved and old.get("password"):
        raise ValueError("the server changed: type the password again")
    if pw is None or masked(pw):
        t["password"] = old.get("password") or ""
    else:
        pw = str(pw)
        if len(pw) > 512 or "\n" in pw or "\x00" in pw:
            raise ValueError("the password is one line, at most 512 characters")
        t["password"] = pw
    if kind in ("sftp", "scp"):
        for k in ("key", "pub", "ssh_cert", "hostkey", "key_pass"):
            if k in old and not moved:
                t[k] = old[k]
        if moved and old.get("key"):
            t["key"], t["pub"] = old["key"], old.get("pub")          # the key is ours; the host key is the server's
        if data.get("ssh_cert") is not None:
            c = str(data.get("ssh_cert") or "").strip()
            if c and not re.match(r"^[a-z0-9@.-]+-cert-v01@openssh\.com AAAA[A-Za-z0-9+/=]+( .*)?\Z", c):
                raise ValueError("the SSH certificate is the one line of a ...-cert.pub file")
            t["ssh_cert"] = c
    if kind in ("ftp", "ftps"):
        t["passive"] = 0 if data.get("passive", old.get("passive", 1)) in (0, "0", False) else 1
    if kind == "ftps":
        t["implicit"] = 1 if data.get("implicit", old.get("implicit")) else 0
        check = str(data.get("tls_check") or old.get("tls_check") or "system")
        if check not in ("system", "pin", "none"):
            raise ValueError("the server certificate is checked against system, pin or none")
        t["tls_check"] = check
        pin = data.get("pin", old.get("pin"))
        pin = re.sub(r"[^0-9A-Fa-f]", "", str(pin or "")).lower()
        if pin and len(pin) != 64:
            raise ValueError("the pinned fingerprint is SHA-256: 64 hex digits")
        t["pin"] = pin
        if check == "pin" and not pin:
            raise ValueError("pinned: the fingerprint is needed - Try it shows the server's")
        if old and old.get("password") and (pw is None or masked(pw)) and (
                (old.get("tls_check") or "system") != check or (old.get("pin") or "") != pin
                or int(old.get("implicit") or 0) != t["implicit"]):
            raise ValueError("how the server is checked changed: type the password again")
    if kind == "smb":
        t["share"] = clean(data.get("share"), "the share", 80, r'^[^\\/:*?"<>|;-][^\\/:*?"<>|;]*\Z', empty=False)
        t["domain"] = clean(data.get("domain"), "the domain", 64, r"^[A-Za-z0-9._-]+\Z")
        t["smb_encrypt"] = 1 if data.get("smb_encrypt", old.get("smb_encrypt", 1)) else 0
        if re.search(r"(^|[\\/])\.\.([\\/]|$)", t["path"]):
            raise ValueError("the folder has no .. in it")
    return t


# ---- the ways there (otp's RbFtp, RbSsh, RbSmb; a folder through root) --------------------------
class Folder(object):
    def __init__(self, t, ctx):
        self.t, self.ctx = t, ctx

    def _ask(self, do, **kw):
        return root_wait(self.ctx, dict(kw, do=do, path=self.t["path"]))

    def open(self):
        self._ask("folder_check")

    def put(self, local, name):
        out = sub(self.ctx, "out")
        here = os.path.join(out, name)
        if os.path.abspath(local) != here:
            shutil.copyfile(local, here)
        try:
            self._ask("folder_put", name=name)
        finally:
            if os.path.abspath(local) != here:
                os.unlink(here)

    def get(self, name, local):
        got = self._ask("folder_get", name=safe_name(name))
        src = os.path.join(base_dir(self.ctx), "work", got["file"])
        shutil.copyfile(src, local)
        try:
            os.unlink(src)
        except OSError:
            pass

    def list(self):
        return self._ask("folder_list").get("files") or []

    def delete(self, name):
        self._ask("folder_delete", name=safe_name(name))

    def close(self):
        pass


class FtpTlsImplicit(ftplib.FTP_TLS):
    """FTPS on its own port (990): TLS from the first byte."""
    def connect(self, host="", port=0, timeout=-999, source_address=None):
        if host:
            self.host = host
        if port > 0:
            self.port = port
        if timeout != -999:
            self.timeout = timeout
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.af = self.sock.family
        self.sock = self.context.wrap_socket(self.sock, server_hostname=self.host)
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome


class _Reuse(object):
    """The data connection resumes the control connection's TLS session (vsftpd, ProFTPD)."""
    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
        return conn, size


class FtpTls(_Reuse, ftplib.FTP_TLS):
    pass


class FtpTlsImpl(_Reuse, FtpTlsImplicit):
    pass


class Ftp(object):
    def __init__(self, t, ctx=None):
        self.t = t
        self.ftp = None
        self.seen = {}

    def _context(self):
        if (self.t.get("tls_check") or "system") == "system":
            return ssl.create_default_context()
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c

    def open(self):
        t = self.t
        try:
            if t["kind"] == "ftps":
                cls = FtpTlsImpl if t.get("implicit") else FtpTls
                self.ftp = cls(context=self._context(), timeout=TIMEOUT)
                self.ftp.connect(t["host"], int(t["port"]))
                if not t.get("implicit"):
                    self.ftp.auth()
                der = self.ftp.sock.getpeercert(True)
                fp = hashlib.sha256(der).hexdigest() if der else ""
                self.seen = {"fingerprint": fp}
                if t.get("tls_check") == "pin" and fp != (t.get("pin") or ""):
                    raise RbError("the server answers with another certificate than the one pinned (SHA-256 %s)" % fp)
            else:
                self.ftp = ftplib.FTP(timeout=TIMEOUT)
                self.ftp.connect(t["host"], int(t["port"]))
            self.ftp.login(t.get("user") or "anonymous", t.get("password") or "")
            if t["kind"] == "ftps":
                self.ftp.prot_p()
            self.ftp.set_pasv(bool(t.get("passive", 1)))
            self._cd(t.get("path") or "")
        except ssl.SSLCertVerificationError as e:
            raise RbError("the server's certificate is not trusted: %s - pin it" % e.verify_message)
        except ftplib.error_perm as e:
            raise RbError("the FTP server said: %s" % str(e)[:200])
        except (OSError, EOFError, ftplib.Error) as e:
            raise RbError(str(e)[:200] or e.__class__.__name__)

    def _cd(self, path):
        if not path:
            return
        if path.startswith("/"):
            self.ftp.cwd("/")
        for part in [p for p in path.split("/") if p]:
            try:
                self.ftp.cwd(part)
            except ftplib.error_perm:
                self.ftp.mkd(part)
                self.ftp.cwd(part)

    def put(self, local, name):
        with open(local, "rb") as f:
            self.ftp.storbinary("STOR .%s.part" % name, f, blocksize=262144)
        try:
            self.ftp.delete(name)
        except ftplib.error_perm:
            pass
        self.ftp.rename(".%s.part" % name, name)

    def get(self, name, local):
        with open(local, "wb") as f:
            self.ftp.retrbinary("RETR %s" % safe_name(name), f.write, blocksize=262144)

    def list(self):
        out = []
        try:
            for name, facts in self.ftp.mlsd(facts=["type", "size", "modify"]):
                if facts.get("type") == "file":
                    m = facts.get("modify") or ""
                    try:
                        mt = datetime.strptime(m[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()
                    except ValueError:
                        mt = 0
                    out.append({"name": name, "size": int(facts.get("size") or 0), "mtime": mt})
            return out
        except ftplib.error_perm:
            pass
        for name in self.ftp.nlst():
            name = name.rsplit("/", 1)[-1]
            if name in (".", ".."):
                continue
            try:
                size = self.ftp.size(name) or 0
            except ftplib.error_perm:
                continue
            out.append({"name": name, "size": size, "mtime": 0})
        return out

    def delete(self, name):
        self.ftp.delete(safe_name(name))

    def close(self):
        try:
            if self.ftp:
                self.ftp.quit()
        except Exception:                                   # noqa: BLE001
            try:
                self.ftp.close()
            except Exception:                               # noqa: BLE001
                pass


class Ssh(object):
    """SFTP (sftp) or SCP (scp, and ssh to list and take away) - OpenSSH itself, the server's host
    key checked against the one trusted on the pages, a key or a password through SSH_ASKPASS."""
    def __init__(self, t, ctx=None):
        self.t = t
        self.d = None

    def open(self):
        t = self.t
        for tool in ["ssh"] + (["sftp"] if t["kind"] == "sftp" else ["scp"]):
            if not shutil.which(tool):
                raise RbError("%s is not on this machine (dnf install openssh-clients)" % tool)
        if not t.get("hostkey"):
            raise RbError("the server's host key is not trusted yet: Try it, then trust the fingerprint it shows")
        self.d = tempfile.mkdtemp(prefix="fake-igd-ssh-")
        kh = os.path.join(self.d, "known_hosts")
        with open(kh, "w") as f:
            f.write(t["hostkey"])
        self.opts = ["-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + kh,
                     "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=20",
                     "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
                     "-o", "LogLevel=ERROR", "-o", "IdentitiesOnly=yes", "-F", "/dev/null"]
        key = t.get("key") or ""
        if key:
            kf = os.path.join(self.d, "id")
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(key if key.endswith("\n") else key + "\n")
            self.opts += ["-i", kf]
            if t.get("ssh_cert"):
                cf = os.path.join(self.d, "id-cert.pub")
                with open(cf, "w") as f:
                    f.write(t["ssh_cert"] + "\n")
                self.opts += ["-o", "CertificateFile=" + cf]
        else:
            self.opts += ["-o", "IdentityFile=/dev/null"]
        self.env = dict(os.environ, DISPLAY=":0", SSH_ASKPASS_REQUIRE="force")
        pw = t.get("password") or t.get("key_pass") or ""
        kp = t.get("key_pass") or t.get("password") or ""
        ask = os.path.join(self.d, "ask")
        with open(ask, "w") as f:
            f.write('#!/bin/sh\ncase "$1" in\n  *assphrase*) printf "%s\\n" "$FAKE_IGD_RB_KEYPASS";;\n'
                    '  *) printf "%s\\n" "$FAKE_IGD_RB_SECRET";;\nesac\n')
        os.chmod(ask, 0o700)
        self.env.update(SSH_ASKPASS=ask, FAKE_IGD_RB_SECRET=pw, FAKE_IGD_RB_KEYPASS=kp)
        auths = ["publickey"] if key else []
        if t.get("password"):
            auths += ["password", "keyboard-interactive"]
        if not auths:
            raise RbError("neither a key nor a password is set")
        self.opts += ["-o", "PreferredAuthentications=" + ",".join(auths), "-o", "NumberOfPasswordPrompts=1"]
        if t.get("password") or t.get("key_pass"):
            self.opts += ["-o", "BatchMode=no"]
        host = str(t["host"]).strip("[]")
        self.dest = "%s@%s" % (t.get("user") or "root", host)
        self.rdest = "%s@[%s]" % (t.get("user") or "root", host) if ":" in host else self.dest
        self.dir = re.sub(r"^~(/+|$)", "", (t.get("path") or "")).rstrip("/") or "."
        if t["kind"] == "sftp":
            parts = [p for p in self.dir.split("/") if p and p != "."]
            cmds, acc = [], "/" if self.dir.startswith("/") else ""
            for p in parts:
                acc = (acc + "/" + p) if acc not in ("", "/") else (acc + p)
                cmds.append('-mkdir "%s"' % acc)
            cmds.append('cd "%s"' % self.dir)
            self._sftp(cmds)
        else:
            self._ssh("mkdir -p -- %s && test -w %s" % (shlex.quote(self.dir), shlex.quote(self.dir)))

    def _run(self, args, what, timeout=3600):
        got = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                             timeout=timeout, env=self.env, start_new_session=True, stdin=subprocess.DEVNULL)
        if got.returncode != 0:
            lines = [x for x in (got.stderr or got.stdout or "").strip().splitlines()
                     if x.strip() and not x.startswith("Warning: Permanently")]
            tail = " / ".join(lines[-3:])[:300] or "it said nothing (exit %d)" % got.returncode
            if "Host key verification failed" in tail or "REMOTE HOST IDENTIFICATION" in tail:
                tail = ("the server shows another host key than the one trusted - if it was reinstalled on "
                        "purpose, Try it and trust the new one")
            elif "Permission denied" in tail:
                tail = "the server did not let the account in (%s)" % tail
            raise RbError("%s: %s" % (what, tail))
        return got.stdout

    def _ssh(self, command):
        return self._run(["ssh"] + self.opts + ["-p", str(int(self.t["port"])), self.dest, command], "ssh")

    def _sftp(self, cmds, timeout=3600):
        batch = os.path.join(self.d, "batch")
        with open(batch, "w") as f:
            f.write("\n".join(cmds) + "\n")
        return self._run(["sftp"] + self.opts + ["-P", str(int(self.t["port"])), "-b", batch, self.rdest],
                         "sftp", timeout=timeout)

    def put(self, local, name):
        name = safe_name(name)
        if self.t["kind"] == "sftp":
            self._sftp(['cd "%s"' % self.dir, 'put "%s" ".%s.part"' % (local, name), '-rm "%s"' % name,
                        'rename ".%s.part" "%s"' % (name, name)])
        else:
            self._run(["scp"] + self.opts + ["-P", str(int(self.t["port"])), "-q", local,
                                             "%s:%s/.%s.part" % (self.rdest, self.dir, name)], "scp")
            self._ssh("mv -f -- %s %s" % (shlex.quote("%s/.%s.part" % (self.dir, name)),
                                          shlex.quote("%s/%s" % (self.dir, name))))

    def get(self, name, local):
        name = safe_name(name)
        if self.t["kind"] == "sftp":
            self._sftp(['cd "%s"' % self.dir, 'get "%s" "%s"' % (name, local)])
        else:
            self._run(["scp"] + self.opts + ["-P", str(int(self.t["port"])), "-q",
                                             "%s:%s/%s" % (self.rdest, self.dir, name), local], "scp")

    def list(self):
        if self.t["kind"] == "sftp":
            text = self._sftp(['cd "%s"' % self.dir, "ls -ln"])
        else:
            text = self._ssh("LC_ALL=C ls -ln -- %s" % shlex.quote(self.dir))
        return parse_ls(text)

    def delete(self, name):
        name = safe_name(name)
        if self.t["kind"] == "sftp":
            self._sftp(['cd "%s"' % self.dir, 'rm "%s"' % name])
        else:
            self._ssh("rm -f -- %s" % shlex.quote("%s/%s" % (self.dir, name)))

    def close(self):
        if self.d:
            shutil.rmtree(self.d, ignore_errors=True)


def parse_ls(text):
    out = []
    for line in (text or "").splitlines():
        f = line.split(None, 8)
        if len(f) == 9 and f[0].startswith("-"):
            try:
                out.append({"name": f[8].rsplit("/", 1)[-1], "size": int(f[4]), "mtime": 0})
            except ValueError:
                pass
    return out


SMB_LS = re.compile(r"^\s\s(.+?)\s+([ADHNRS]*)\s+(\d+)\s+(\w{3} \w{3}\s+\d+ [\d:]+ \d{4})\s*$")


def parse_smb_ls(text):
    out = []
    for line in (text or "").splitlines():
        m = SMB_LS.match(line)
        if m and "D" not in m.group(2) and m.group(1) not in (".", ".."):
            try:
                mt = datetime.strptime(re.sub(r"\s+", " ", m.group(4)), "%a %b %d %H:%M:%S %Y").timestamp()
            except ValueError:
                mt = 0
            out.append({"name": m.group(1), "size": int(m.group(3)), "mtime": mt})
    return out


class Smb(object):
    """SMB through smbclient: an authentication file of its own (never the password on a command
    line), SMB2 at least, SMB3 encryption when asked."""
    def __init__(self, t, ctx=None):
        self.t = t
        self.d = None

    def open(self):
        t = self.t
        if not shutil.which("smbclient"):
            raise RbError("smbclient is not on this machine (dnf install samba-client)")
        self.d = tempfile.mkdtemp(prefix="fake-igd-smb-")
        auth = os.path.join(self.d, "auth")
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("username = %s\npassword = %s\n" % (t.get("user") or "guest", t.get("password") or ""))
            if t.get("domain"):
                f.write("domain = %s\n" % t["domain"])
        self.args = ["smbclient", "//%s/%s" % (t["host"], t["share"]), "-A", auth, "-p", str(int(t["port"])),
                     "--option=client min protocol=SMB2", "-t", str(TIMEOUT)]
        if t.get("smb_encrypt"):
            self.args += ["--client-protection=encrypt"]
        self.dir = (t.get("path") or "").replace("/", "\\").strip("\\")
        cmds, acc = [], ""
        for p in [x for x in self.dir.split("\\") if x]:
            acc = (acc + "\\" + p) if acc else p
            cmds.append('mkdir "%s"' % acc)
        self._run(cmds + ['cd "\\%s"' % self.dir, "ls"], ignore=("NT_STATUS_OBJECT_NAME_COLLISION",))

    def _run(self, cmds, ignore=(), timeout=3600):
        got = subprocess.run(self.args + ["-c", "; ".join(cmds)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=timeout, cwd=self.d, start_new_session=True,
                             stdin=subprocess.DEVNULL)
        text = (got.stdout or "") + (got.stderr or "")
        if "Could not determine network interfaces" in text and \
                not any(a.startswith("--option=interfaces=") for a in self.args):
            self.args.append("--option=interfaces=127.0.0.1/8")
            return self._run(cmds, ignore, timeout)
        bad = [x for x in text.splitlines() if "NT_STATUS_" in x and not any(i in x for i in ignore)]
        if got.returncode != 0 or bad:
            s = " / ".join((bad or text.strip().splitlines() or ["no answer"])[-2:])[:300]
            if "NT_STATUS_LOGON_FAILURE" in s:
                s = "the server did not take the account and password (%s)" % s
            elif "NT_STATUS_BAD_NETWORK_NAME" in s:
                s = "there is no share %s on %s" % (self.t["share"], self.t["host"])
            raise RbError("smbclient: %s" % s)
        return got.stdout or ""

    def _cd(self):
        return 'cd "\\%s"' % self.dir

    def put(self, local, name):
        name = safe_name(name)
        self._run([self._cd(), 'put "%s" ".%s.part"' % (local, name), 'del "%s"' % name,
                   'rename ".%s.part" "%s"' % (name, name)],
                  ignore=("NT_STATUS_NO_SUCH_FILE", "NT_STATUS_OBJECT_NAME_NOT_FOUND"))

    def get(self, name, local):
        self._run([self._cd(), 'get "%s" "%s"' % (safe_name(name), local)])

    def list(self):
        return parse_smb_ls(self._run([self._cd(), "ls"]))

    def delete(self, name):
        self._run([self._cd(), 'del "%s"' % safe_name(name)])

    def close(self):
        if self.d:
            shutil.rmtree(self.d, ignore_errors=True)


def transport(t, ctx):
    return {"folder": Folder, "ftp": Ftp, "ftps": Ftp, "sftp": Ssh, "scp": Ssh, "smb": Smb}[t["kind"]](t, ctx)


def try_target(t, ctx):
    """Signed in, a small file written, seen in the list, taken away again."""
    out = {"ok": False, "steps": []}
    began = time.time()
    tr = transport(t, ctx)
    try:
        tr.open()
        out["steps"].append("signed in, the folder is there")
        name = "fake-igd-backup-try-%s-%s.txt" % (slug(node_name()), secrets.token_hex(4))
        local = os.path.join(sub(ctx, "out"), name)
        with open(local, "w") as f:
            f.write("fake-igd on %s tried this destination at %s - this file is taken away again\n"
                    % (node_name(), datetime.now().isoformat(timespec="seconds")))
        try:
            tr.put(local, name)
        finally:
            if os.path.exists(local):
                os.unlink(local)
        out["steps"].append("a file written")
        names = [x["name"] for x in tr.list()]
        if name not in names:
            raise RbError("the file written is not in the list the server gives")
        out["steps"].append("it is in the list (%d file(s) there)" % len(names))
        tr.delete(name)
        out["steps"].append("taken away again")
        out["ok"] = True
    except Exception as e:                                  # noqa: BLE001
        out["error"] = said(e)
    finally:
        if getattr(tr, "seen", None):
            out["server_cert"] = tr.seen
        tr.close()
    out["secs"] = round(time.time() - began, 1)
    return out


# ---- the backup itself ------------------------------------------------------------------------------
def openssl(args, secret, what):
    if not shutil.which("openssl"):
        raise RbError("openssl is not on this machine (dnf install openssl)")
    got = subprocess.run(["openssl"] + args, input=secret + "\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         universal_newlines=True, timeout=1800)
    if got.returncode != 0:
        err = (got.stderr or "").strip().splitlines()
        if what == "opening it" and any("bad decrypt" in x for x in err):
            raise RbError("the password is not the one it was locked with")
        raise RbError("%s: %s" % (what, " / ".join(err[-2:])[:300] or "openssl failed"))


def lock(src, dst, pw):
    openssl(["enc", "-aes-256-cbc", "-pbkdf2", "-iter", str(ITER), "-md", "sha256", "-salt", "-in", src,
             "-out", dst, "-pass", "stdin"], pw, "locking it")


def unlock(src, dst, pw):
    openssl(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", str(ITER), "-md", "sha256", "-in", src,
             "-out", dst, "-pass", "stdin"], pw, "opening it")


def restore_md(m):
    f = m["file"]
    plain = f[:-4] if f.endswith(".enc") else f
    base = plain[:-len(".tar.gz")]
    return """# Putting back {file}

Made by fake-igd {version} on **{node}** ({host}), site *{site}*, {when}.
{locked}

## With the pages (fake-igd installed and running)

Settings → Backups → *Put one back…* and choose this file - or *Backups there* on the
destination it went to. The database is put back (a copy of what was there is made first),
config.json (this machine's own paths and port are kept), and root puts back avahi-daemon.conf,
nginx's fake-igd.conf, the certificate and key of the pages, the journal's drop-in and
logrotate's file; then nginx's allow list, the firewall and fake-igd.service as config.json says.
You sign in again afterwards, with an account the backup has.

## By hand, on a machine installed from nothing

```bash
sudo ./install.sh --yes                         # fake-igd {version}, the same version
{unlock}tar xzf {plain}
cd {base}
sha256sum -c <(python3 -c 'import json;[print(v["sha256"]+"  "+k) for k,v in json.load(open("manifest.json"))["files"].items()]')
sudo systemctl stop fake-igd fake-igd-api
sudo install -o fake-igd -g fake-igd -m 0640 fake-igd.db /var/lib/fake-igd/fake-igd.db
sudo install -o fake-igd -g fake-igd -m 0600 secrets.key /var/lib/fake-igd/secrets.key
sudo rm -f /var/lib/fake-igd/fake-igd.db-wal /var/lib/fake-igd/fake-igd.db-shm
sudo install -o root -g fake-igd -m 0664 config.json /etc/fake-igd/config.json
sudo cp system/etc/avahi/avahi-daemon.conf /etc/avahi/avahi-daemon.conf
sudo cp system/etc/nginx/conf.d/fake-igd.conf /etc/nginx/conf.d/fake-igd.conf
sudo install -m 0644 system/etc/nginx/certs/fake-igd.pem /etc/nginx/certs/fake-igd.pem
sudo install -m 0600 system/etc/nginx/certs/fake-igd.key /etc/nginx/certs/fake-igd.key
sudo restorecon -R /etc/nginx /etc/avahi /var/lib/fake-igd /etc/fake-igd 2>/dev/null
sudo nginx -t && sudo systemctl reload nginx && sudo systemctl restart avahi-daemon
sudo /opt/fake-igd/fake_igd_web.py --apply --restart   # the allow list and the firewall
sudo systemctl start fake-igd fake-igd-api
upnp status
```

`system/etc/sysconfig/iptables.fake-igd` holds the lines fake-igd had in /etc/sysconfig/iptables -
to read: the chain FAKE-IGD-IN is made again from config.json by the step above.

## What is in it

| File | |
|---|---|
| fake-igd.db | the database: accounts, events, the settings saved on the pages, the destinations of the backups |
| secrets.key | the key the secrets in the database are sealed with (the destinations' passwords, the mail server's, the proxy's, the ACME account key) |
| config.json | /etc/fake-igd/config.json |
| mappings.json | what the service had handed out |
| system/ | the system's files, collected by root |
| manifest.json | what it is, and the SHA-256 of every file |
""".format(file=f, version=m["version"], node=m["node"], host=m["host"], site=m["site"], when=m["made_words"],
           locked=("Locked with the password of the backups (AES-256-CBC, PBKDF2 %d rounds, SHA-256)." % ITER
                   if m["encrypted"] else "**Not locked.**"),
           unlock=("openssl enc -d -aes-256-cbc -pbkdf2 -iter %d -md sha256 -in %s -out %s\n" % (ITER, f, plain)
                   if m["encrypted"] else ""), plain=plain, base=base)


def manifest(ctx, base, pw):
    v = getattr(sys.modules.get("__main__"), "VERSION", "") or ""
    if not v:
        try:
            import upnp as U
            v = U.VERSION
        except Exception:                                  # noqa: BLE001
            v = "?"
    return {"fake_igd": v, "version": v, "made": time.time(),
            "made_words": datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip(),
            "site": ctx.cfg.get("site_name") or "fake-igd", "node": node_name(), "host": socket.getfqdn(),
            "encrypted": bool(pw), "iter": ITER if pw else 0,
            "file": base + (".tar.gz.enc" if pw else ".tar.gz"), "files": {}}


def db_module():
    mod = sys.modules.get("api_db")
    if mod is None:
        import api_db as mod                                # noqa: F811
    return mod


def build(ctx, work, collected, progress, unlocked=False):
    """The backup, built in `work`: (path of the file, manifest, RESTORE.md), the file and its two
    companions in backup/out/. unlocked: only for a download asked for in so many words while no
    password is set (otp's "Download a backup that is not locked?") - never one that is sent."""
    pw = password(ctx)
    if not pw and not unlocked:
        raise RbError("the backups have no password - set it (Settings → Backups → The password of the backups); "
                      "an unlocked backup would hand every account's hash to whoever reads the destination")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = "fake-igd-backup-%s-%s-%s" % (site(ctx), slug(node_name()), stamp)
    inner = os.path.join(work, "in")
    os.makedirs(inner, mode=0o700)
    progress(2, "the database is copied")
    db_module().snapshot(ctx.store, os.path.join(inner, "fake-igd.db"))
    try:
        shutil.copyfile(cfg_path(), os.path.join(inner, "config.json"))
    except OSError as e:
        raise RbError("%s cannot be read: %s" % (cfg_path(), e))
    kp = SEAL.key_path(ctx.store)
    if os.path.isfile(kp):                                  # the key that opens the secrets in the database
        shutil.copyfile(kp, os.path.join(inner, "secrets.key"))
        os.chmod(os.path.join(inner, "secrets.key"), 0o600)
    mp = os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "mappings.json")
    if os.path.isfile(mp):
        shutil.copyfile(mp, os.path.join(inner, "mappings.json"))
    if collected:
        with tarfile.open(collected, "r:") as tf:
            for m in tf.getmembers():
                if not m.isreg() or m.name.startswith("/") or ".." in m.name.split("/"):
                    continue
                dst = os.path.join(inner, "system", m.name)
                os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
                with tf.extractfile(m) as a, open(dst, "wb") as b:
                    shutil.copyfileobj(a, b)
    progress(3, "packed")
    m = manifest(ctx, base, pw)
    m["system"] = bool(collected)
    for top, _dirs, files in os.walk(inner):
        for n in sorted(files):
            p = os.path.join(top, n)
            m["files"][os.path.relpath(p, inner)] = {"sha256": sha256_of(p), "bytes": os.path.getsize(p)}
    md = restore_md(m)
    with open(os.path.join(inner, "RESTORE.md"), "w") as f:
        f.write(md)
    with open(os.path.join(inner, "manifest.json"), "w") as f:
        json.dump(m, f, indent=2, default=str)
    tar = os.path.join(work, base + ".tar.gz")
    with tarfile.open(tar, "w:gz", compresslevel=6) as tf:
        for n in sorted(os.listdir(inner)):
            tf.add(os.path.join(inner, n), arcname="%s/%s" % (base, n))
    shutil.rmtree(inner, ignore_errors=True)
    out_dir = sub(ctx, "out")
    final = os.path.join(out_dir, m["file"])
    if pw:
        progress(4, "locked with the password of the backups")
        lock(tar, final, pw)
        os.unlink(tar)
    else:
        progress(4, "not locked - no password of the backups is set")
        os.replace(tar, final)
    os.chmod(final, 0o640)
    m["sha256"] = sha256_of(final)
    m["bytes"] = os.path.getsize(final)
    with open(os.path.join(out_dir, m["file"] + ".sha256"), "w") as f:
        f.write("%s  %s\n" % (m["sha256"], m["file"]))
    with open(os.path.join(out_dir, base + "-RESTORE.md"), "w") as f:
        f.write(md)
    return final, m, md


def companions(name):
    if not NAME_RE.match(name):
        return []
    return [name + ".sha256", name.split(".tar.gz")[0] + "-RESTORE.md"]


def mine(ctx, m):
    return bool(m) and m.group("node") == slug(node_name()) and m.group("site") == site(ctx)


def retain(ctx, tr, keep, days, just=""):
    """otp's rb_retain: this machine's backups past what is kept, taken away - never the newest,
    never the one just sent, none stamped ahead of the clock."""
    now = time.time()
    files = tr.list()
    names = set(x["name"] for x in files)
    ours = []
    for x in files:
        m = NAME_RE.match(x["name"])
        if mine(ctx, m):
            try:
                when = datetime.strptime(m.group("stamp"), "%Y%m%d-%H%M%S").timestamp()
            except ValueError:
                continue
            if when > now + 86400:
                continue
            ours.append((when, x["name"]))
    ours.sort(reverse=True)
    gone, kept = [], []
    for i, (when, name) in enumerate(ours):
        if i == 0 or name == just:
            continue
        if (keep and i >= keep) or (days and now - when > days * 86400):
            failed = None
            for n in [name] + [c for c in companions(name) if c in names]:
                try:
                    tr.delete(n)
                except Exception as e:                      # noqa: BLE001
                    if n == name:
                        failed = e
            if failed is None:
                gone.append(name)
            else:
                kept.append("%s (%s)" % (name, str(failed)[:80]))
    if kept:
        raise RbError("not taken away: " + "; ".join(kept[:5]))
    return gone


def room(ctx):
    try:
        free = shutil.disk_usage(base_dir(ctx)).free
    except OSError:
        return
    size = os.path.getsize(ctx.store.path) if os.path.exists(ctx.store.path) else 0
    need = 3 * size + 64 * 1024 * 1024
    if free < need:
        raise RbError("there is no room for it in %s: %d MB free, %d MB needed" % (base_dir(ctx), free >> 20,
                                                                                  need >> 20))


def collect(ctx, progress, only=None):
    """Root's part (the system's files) as a tar in backup/work - or None, said, when root does not answer."""
    progress(1, "what only root may read is collected")
    payload = {"do": "collect"}
    if only:
        payload["only"] = only
    try:
        got = root_wait(ctx, payload)
    except RbError as e:
        return None, str(e)
    return os.path.join(base_dir(ctx), "work", got["tar"]), "; ".join(got.get("said") or [])


def runs(ctx):
    return list((ctx.store.meta_json("backup:runs") or {}).get("list") or [])


def runs_put(ctx, rows):
    ctx.store.set_meta("backup:runs", json.dumps({"list": rows[:RUNS_KEEP]}))


def run(ctx, by, only=None, progress=None):
    """Made once, sent to every destination switched on (or the ones asked)."""
    progress = progress or (lambda n, w: None)
    ts = [t for t in targets(ctx) if (only and t["id"] in only) or (not only and t.get("enabled"))]
    try:
        if not ts:
            raise RbError("no destination is switched on")
        if not password(ctx):
            raise RbError("the backups have no password - nothing is sent (set The password of the backups)")
        room(ctx)
    except RbError as e:
        if by in ("", AGAIN_BY):
            # The schedule's backup that stopped before it began is a failed run with its reason (1.9.11): it left
            # no row, and the alert said only "No backup went in time", a day and a half later.
            runs_put(ctx, [{"at": time.time(), "node": node_name(), "by": by, "targets": [], "ok": False,
                            "error": said(e)}] + runs(ctx))
            ctx.event("the schedule: no backup - %s" % said(e), "warn")
        raise
    work = tempfile.mkdtemp(prefix="run-", dir=sub(ctx, "work"))
    collected, root_said = collect(ctx, progress)
    row = {"at": time.time(), "node": node_name(), "by": by, "targets": [], "ok": False}
    try:
        final, m, _md = build(ctx, work, collected, progress)
        row.update({"file": m["file"], "bytes": m["bytes"], "encrypted": m["encrypted"], "system": bool(collected)})
        if not collected:
            row["warning"] = "without the system's files - %s" % root_said
        n = 0
        for t in ts:
            n += 1
            progress(5, "sent to %s (%d of %d)" % (t["name"], n, len(ts)))
            began = time.time()
            one = {"id": t["id"], "name": t["name"], "ok": False}
            tr = transport(t, ctx)
            try:
                tr.open()
                tr.put(final, m["file"])
                for c in companions(m["file"]):
                    p = os.path.join(sub(ctx, "out"), c)
                    if os.path.exists(p):
                        tr.put(p, c)
                one["ok"] = True
                try:
                    one["taken_away"] = retain(ctx, tr, int(ctx.setting("rbackup_keep") or 30),
                                               int(ctx.setting("rbackup_keep_days") or 0), m["file"])
                except Exception as e:                      # noqa: BLE001 - sent all the same
                    one["warning"] = said(e)
            except Exception as e:                          # noqa: BLE001
                one["error"] = said(e)
            finally:
                tr.close()
            one["secs"] = round(time.time() - began, 1)
            row["targets"].append(one)
            last = {"at": time.time(), "ok": one["ok"], "error": one.get("error", ""), "bytes": m["bytes"],
                    "file": m["file"]}
            ctx.store.set_meta("backup:last:" + t["id"], json.dumps(last))
        row["ok"] = all(x["ok"] for x in row["targets"])
    except Exception as e:                                  # noqa: BLE001
        row["error"] = said(e)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if collected:
            try:
                os.unlink(collected)
            except OSError:
                pass
        for n in [row.get("file")] + companions(row.get("file") or ""):
            if n:
                try:
                    os.unlink(os.path.join(sub(ctx, "out"), n))
                except OSError:
                    pass
    runs_put(ctx, [row] + runs(ctx))
    ok_names = [x["name"] for x in row["targets"] if x["ok"]]
    bad = ["%s: %s" % (x["name"], x.get("error")) for x in row["targets"] if not x["ok"]]
    ctx.event("%s: a backup %s%s%s" % (by or "the schedule", row.get("file") or "",
                                        (" went to " + ", ".join(ok_names)) if ok_names else "",
                                        (" - not to " + "; ".join(bad)) if bad else
                                        (" - " + row["error"] if row.get("error") else "")),
              "info" if row["ok"] else "warn")
    if row["ok"] and ctx.setting("rbackup_verify") == "after":
        try:
            verify(ctx, by, ts[0]["id"], row["file"], progress)
        except Exception:                                   # noqa: BLE001 - said in its own list
            pass
    return row


# ---- opening one, trying it, putting it back --------------------------------------------------------
def fetch(ctx, tid, name, dst):
    t = target(ctx, tid)
    safe_name(name)
    tr = transport(t, ctx)
    try:
        tr.open()
        tr.get(name, dst)
    finally:
        tr.close()


def remote_list(ctx, tid):
    t = target(ctx, tid)
    tr = transport(t, ctx)
    try:
        tr.open()
        files = tr.list()
    finally:
        tr.close()
    out = []
    for x in files:
        m = NAME_RE.match(x["name"])
        if not m:
            continue
        try:
            when = datetime.strptime(m.group("stamp"), "%Y%m%d-%H%M%S").timestamp()
        except ValueError:
            when = x.get("mtime") or 0
        out.append({"name": x["name"], "bytes": x["size"], "when": when, "node": m.group("node"),
                    "site": m.group("site"), "encrypted": bool(m.group("enc")), "mine": mine(ctx, m)})
    out.sort(key=lambda r: r["when"], reverse=True)
    return out


def open_file(ctx, path, pw, work):
    """A backup file opened into work/x: its manifest, every file checked. (manifest, folder)"""
    plain = path
    with open(path, "rb") as f:
        head = f.read(8)
    if head.startswith(b"Salted__"):
        pw = pw or password(ctx)
        if not pw:
            raise RbError("it is locked, and no password was given or set")
        plain = os.path.join(work, "plain.tar.gz")
        unlock(path, plain, pw)
    elif head[:2] != b"\x1f\x8b":
        raise RbError("that is not a backup of fake-igd (neither locked nor a .tar.gz)")
    x = os.path.join(work, "x")
    os.makedirs(x, mode=0o700)
    top = None
    count, total = 0, 0
    try:
        with tarfile.open(plain, "r:gz") as tf:
            for mem in tf:                  # one by one: refused at the first that is too much, not after all
                parts = mem.name.split("/")
                if mem.name.startswith("/") or ".." in parts or len(parts) < 2:
                    raise RbError("a name in it that does not belong there: %s" % mem.name[:80])
                if top is None:
                    top = parts[0]
                if parts[0] != top or not top.startswith("fake-igd-backup-"):
                    raise RbError("that is not a backup of fake-igd")
                count += 1
                if count > OPEN_MOST_FILES:
                    raise RbError("more than %d files in it - a backup of fake-igd has a dozen" % OPEN_MOST_FILES)
                if mem.isdir():
                    continue
                if not mem.isreg() or mem.size > 512 * 1024 * 1024:
                    raise RbError("something in it that is not a plain file: %s" % mem.name[:80])
                # Bounded unpacked (1.9.9): a backup is the database (DB_MOST) and files of a few kB - a crafted
                # one of a few MB filled the disk of the state folder as it was opened.
                most = db_module().DB_MOST if parts[1:] == ["fake-igd.db"] else OPEN_MOST_OTHER
                total += mem.size
                if mem.size > most or total > db_module().DB_MOST + OPEN_MOST_OTHER * 4:
                    raise RbError("%s is larger than a backup of fake-igd holds (%d MB) - refused"
                                  % (mem.name[:80], max(1, most >> 20)))
                dst = os.path.join(x, *parts[1:])
                os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
                with tf.extractfile(mem) as a, open(dst, "wb") as b:
                    shutil.copyfileobj(a, b, 1 << 20)
    except (tarfile.TarError, EOFError, OSError) as e:
        raise RbError("it does not open: %s" % e)
    try:
        with open(os.path.join(x, "manifest.json"), encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError):
        raise RbError("there is no manifest.json in it - not a backup of fake-igd")
    files = m.get("files") if isinstance(m, dict) else None
    if not isinstance(files, dict):
        raise RbError("its manifest.json lists no files - not a backup of fake-igd")
    real = os.path.realpath(x)
    for rel, info in files.items():
        # A name of the manifest as the names in the file are checked (1.9.9): never a path of this machine.
        parts = str(rel).split("/")
        p = os.path.join(x, *parts) if parts else x
        if not rel or str(rel).startswith("/") or "\x00" in str(rel) or any(q in ("", ".", "..") for q in parts) \
                or not os.path.realpath(p).startswith(real + os.sep) or not isinstance(info, dict):
            raise RbError("its manifest names a file that does not belong there: %s" % str(rel)[:80])
        if not os.path.isfile(p):
            raise RbError("%s is missing from it" % rel)
        if sha256_of(p) != info.get("sha256"):
            raise RbError("%s is not what was put in it (its SHA-256 differs)" % rel)
    return m, x


def verified(ctx):
    return list((ctx.store.meta_json("backup:verified") or {}).get("list") or [])


def verify(ctx, by, tid=None, name=None, progress=None):
    progress = progress or (lambda n, w: None)
    ts = [t for t in targets(ctx) if t.get("enabled")]
    if tid:
        ts = [target(ctx, tid)]
    if not ts:
        raise RbError("no destination is switched on")
    t = ts[0]
    row = {"at": time.time(), "node": node_name(), "target_name": t["name"], "by": by, "checks": [], "ok": False}
    work = tempfile.mkdtemp(prefix="verify-", dir=sub(ctx, "work"))

    def check(what, ok, words=""):
        row["checks"].append({"what": what, "ok": bool(ok), "said": words})
        if not ok:
            raise RbError("%s: %s" % (what, words))
    try:
        progress(1, "the list at %s" % t["name"])
        if not name:
            mine_ = [f for f in remote_list(ctx, t["id"]) if f["mine"]]
            check("a backup of this machine is there", bool(mine_),
                  "%d there, the newest taken" % len(mine_) if mine_ else "none at %s" % t["name"])
            name = mine_[0]["name"]
        row["file"] = name
        progress(2, "fetched back")
        local = os.path.join(work, "file")
        fetch(ctx, t["id"], name, local)
        check("fetched back", True, "%d bytes" % os.path.getsize(local))
        progress(3, "opened and every file checked")
        m, x = open_file(ctx, local, "", work)
        check("opened with the password, every file as its SHA-256 says", True, "%d file(s)" % len(m.get("files") or {}))
        progress(4, "the database read through")
        says = db_module().read_db(os.path.join(x, "fake-igd.db"))
        check("the database is whole, with a full admin", True, "%s account(s), %s event(s)"
              % (says["counts"].get("users"), says["counts"].get("events")))
        sealed_ok, sealed_said = secrets_open(os.path.join(x, "fake-igd.db"), os.path.join(x, "secrets.key"))
        check("its secrets open with the key in it", sealed_ok, sealed_said)
        check("config.json reads", _json_ok(os.path.join(x, "config.json")))
        check("the system's files are in it", bool(m.get("system")), "" if m.get("system") else
              "made without them (root did not answer)")
        row["ok"] = True
    except Exception as e:                                  # noqa: BLE001
        if not row["checks"] or row["checks"][-1]["ok"]:
            row["checks"].append({"what": "tried", "ok": False, "said": said(e)})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ctx.store.set_meta("backup:verified", json.dumps({"list": ([row] + verified(ctx))[:VERIFY_KEEP]}))
    ctx.store.set_meta("backup:verified:at", str(time.time()))
    ctx.event("%s: the backup %s was tried - %s" % (by or "the schedule", row.get("file") or "?",
                                                    "it can be put back" if row["ok"] else "NOT GOOD: " +
                                                    row["checks"][-1]["said"]), "info" if row["ok"] else "warn")
    return row


def secrets_open(dbfile, keyfile):
    """(ok, words): every sealed secret in a backup's database tried against the key beside it - as otp
    tries the tokens against the key in a backup."""
    import sqlite3 as _sq
    try:
        conn = _sq.connect("file:%s?mode=ro" % dbfile, uri=True)
        try:
            rows = conn.execute("SELECT k, v FROM meta").fetchall()
        finally:
            conn.close()
    except _sq.Error as e:
        return False, str(e)
    sealed = []
    for _k, v in rows:
        sealed += re.findall(r"sealed:[12]:[A-Za-z0-9_=-]+", str(v or ""))
    if not sealed:
        return True, "no secret sealed in it"
    try:
        with open(keyfile, encoding="ascii") as f:
            k = bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return False, "%d secret(s) sealed, and no secrets.key in it" % len(sealed)
    bad = sum(1 for v in sealed if v.startswith("sealed:1:") and SEAL.unseal_with(k, v) is None)
    return not bad, ("%d secret(s), every one opens" % len(sealed)) if not bad else \
        "%d of %d secret(s) do not open with its key" % (bad, len(sealed))


def _json_ok(p):
    try:
        with open(p, encoding="utf-8") as f:
            return isinstance(json.load(f), dict)
    except (OSError, ValueError):
        return False


def write_config(new):
    """config.json put back in place (the folder is root's): this machine's paths and port kept."""
    path = cfg_path()
    import fcntl
    with open(path, "r+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            here = json.load(f)
        except ValueError:
            here = {}
        for k in MACHINE_KEYS:
            if k in here:
                new[k] = here[k]
            else:
                new.pop(k, None)
        f.seek(0)
        f.write(json.dumps(new, ensure_ascii=False, indent=2) + "\n")
        f.truncate()
        f.flush()
        os.fsync(f.fileno())
    main = sys.modules.get("__main__")
    if main is not None and hasattr(main, "load_cfg"):
        main.load_cfg(force=True)


def system_tar(ctx, folder, job_dir):
    """The system/ part of an opened backup as a tar for root, in backup/work/restore-JOB.tar."""
    sysdir = os.path.join(folder, "system")
    job = secrets.token_hex(8)
    path = os.path.join(job_dir, "restore-%s.tar" % job)
    with tarfile.open(path, "w") as tf:
        for top, _d, files in os.walk(sysdir):          # none: an empty one - root then only applies
            for n in files:
                p = os.path.join(top, n)
                tf.add(p, arcname=os.path.relpath(p, sysdir))
    os.chmod(path, 0o640)
    return job


def root_restore(ctx, job, apply=True):
    """root puts back the files of work/restore-JOB.tar (and, apply, nginx/firewall/service)."""
    path = os.path.join(base_dir(ctx), "work", "%s.json" % job)
    ctx.ask_root({"do": "restore", "job": job, "apply": bool(apply)}, kind="backup")
    end = time.time() + ROOT_WAIT_S
    while time.time() < end:
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    got = json.load(f)
            except (OSError, ValueError):
                time.sleep(0.3)
                continue
            try:
                os.unlink(path)
            except OSError:
                pass
            return got
        time.sleep(0.4)
    return {"ok": False, "said": ["root did not answer in %d s - the system's files are not put back; "
                                  "they are in work/restore-%s.tar" % (ROOT_WAIT_S, job)]}


def restore(ctx, by, src, pw, progress=None):
    """A backup put back: the database, config.json, the system's files through root."""
    progress = progress or (lambda n, w: None)
    work = tempfile.mkdtemp(prefix="restore-", dir=sub(ctx, "work"))
    out = {"said": []}
    try:
        progress(1, "fetched")
        if src.get("upload"):
            if not UPLOAD_RE.match(src["upload"]):
                raise RbError("no such file sent")
            local = os.path.join(sub(ctx, "in"), src["upload"])
            if not os.path.isfile(local):
                raise RbError("the file sent is gone - send it again")
            what = str(src.get("file") or "a file sent")[:120]
        else:
            local = os.path.join(work, "file")
            fetch(ctx, src["id"], src["name"], local)
            what = src["name"]
        progress(2, "opened and every file checked")
        m, x = open_file(ctx, local, pw, work)
        dbm = db_module()
        progress(3, "the database put back")
        says = dbm.read_db(os.path.join(x, "fake-igd.db"))
        key_hex = None
        if os.path.isfile(os.path.join(x, "secrets.key")):
            with open(os.path.join(x, "secrets.key"), encoding="ascii") as f:
                key_hex = f.read().strip()
        got = dbm.restore_from(ctx, os.path.join(x, "fake-igd.db"), what, key_hex)
        out["safety"] = got["safety"]
        out["said"].append("the database: %s account(s), %s event(s)" % (says["counts"].get("users"),
                                                                       says["counts"].get("events")))
        progress(4, "config.json put back")
        try:
            with open(os.path.join(x, "config.json"), encoding="utf-8") as f:
                conf = json.load(f)
            if not isinstance(conf, dict):
                raise ValueError("not an object")
            write_config(conf)
            out["said"].append("config.json (this machine's %s kept)" % ", ".join(MACHINE_KEYS))
        except (OSError, ValueError) as e:
            out["said"].append("config.json was not put back: %s" % e)
        progress(5, "root puts the system's files back")
        if not os.path.isdir(os.path.join(x, "system")):
            out["said"].append("no system files in it (made while root did not answer)")
        job = system_tar(ctx, x, sub(ctx, "work"))
        r = root_restore(ctx, job, apply=True)
        out["said"].extend(r.get("said") or [])
        out["root_ok"] = bool(r.get("ok"))
        out["manifest"] = {k: m.get(k) for k in ("node", "host", "site", "made", "made_words", "version")}
        ctx.event("%s put a backup back: %s (made on %s, %s)" % (by, what, m.get("node"), m.get("made_words")), "warn")
        return out
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if src.get("upload"):
            try:
                os.unlink(os.path.join(sub(ctx, "in"), src["upload"]))
            except OSError:
                pass


# ---- the job going on (one at a time) -----------------------------------------------------------
def job_view():
    with JOB_LOCK:
        return dict(JOB)


def start_job(ctx, what, by, fn):
    with JOB_LOCK:
        if JOB["running"]:
            raise ValueError("%s is going on - wait for it" % JOB["what"])
        JOB.update({"running": True, "what": what, "says": "", "done": 0, "whole": 5, "error": "",
                    "began": time.time(), "ended": 0, "result": None, "by": by})

    def progress(n, words):
        with JOB_LOCK:
            JOB.update({"done": n, "says": words})

    def go():
        try:
            r = fn(progress)
            with JOB_LOCK:
                JOB.update({"result": r, "done": JOB["whole"]})
        except Exception as e:                              # noqa: BLE001
            with JOB_LOCK:
                JOB["error"] = said(e)
        finally:
            with JOB_LOCK:
                JOB.update({"running": False, "ended": time.time()})
    threading.Thread(target=go, name="fake-igd-backup", daemon=True).start()
    return job_view()


# ---- the view --------------------------------------------------------------------------------------
def next_run(ctx, now=None):
    if not ctx.setting("rbackup"):
        return None
    at = str(ctx.setting("rbackup_at") or "04:15")
    if not HHMM_RE.match(at):
        return None
    now = now or time.time()
    lt = time.localtime(now)
    h, mi = int(at[:2]), int(at[3:])
    for d in range(0, 9):
        t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + d, h, mi, 0, 0, 0, -1))
        if t <= now:
            continue
        if ctx.setting("rbackup_every") == "weekly" and time.localtime(t).tm_wday + 1 != int(ctx.setting("rbackup_day") or 7):
            continue
        return t
    return None


def view(ctx):
    ts = targets(ctx)
    lasts = {t["id"]: ctx.store.meta_json("backup:last:" + t["id"]) for t in ts}
    n = next_run(ctx)
    return {"targets": [view_target(t, lasts.get(t["id"])) for t in ts], "runs": runs(ctx), "verified": verified(ctx),
            "job": job_view(), "node": node_name(), "site": site(ctx), "next": n * 1000 if n else None,
            "locked": bool(password(ctx)), "tools": tools(),
            "kinds": [{"kind": k, "words": KIND_WORDS[k], "port": PORTS.get(k)} for k in KINDS]}


def keygen(ctx, t):
    if not shutil.which("ssh-keygen"):
        raise ValueError("ssh-keygen is not on this machine (dnf install openssh-clients)")
    d = tempfile.mkdtemp(prefix="fake-igd-kg-")
    try:
        k = os.path.join(d, "id")
        r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                            "fake-igd-backup@%s" % node_name(), "-f", k], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        if r.returncode != 0:
            raise ValueError("ssh-keygen: %s" % r.stderr.strip()[:200])
        with open(k) as f:
            key = f.read()
        with open(k + ".pub") as f:
            pub = f.read().strip()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return key, pub


def key_public(key, passphrase):
    if not shutil.which("ssh-keygen"):
        raise ValueError("ssh-keygen is not on this machine (dnf install openssh-clients)")
    if "PRIVATE KEY-----" not in key or len(key) > 20000:
        raise ValueError("that is not a private key (-----BEGIN ... PRIVATE KEY-----)")
    d = tempfile.mkdtemp(prefix="fake-igd-kp-")
    try:
        k = os.path.join(d, "id")
        fd = os.open(k, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.strip() + "\n")
        r = subprocess.run(["ssh-keygen", "-y", "-P", passphrase or "", "-f", k], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        if r.returncode != 0:
            raise ValueError("ssh-keygen does not read it%s: %s" % (" with that passphrase" if passphrase else "",
                                                                    r.stderr.strip()[:200]))
        return r.stdout.strip()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def keyscan(host, port):
    if not shutil.which("ssh-keyscan"):
        raise RbError("ssh-keyscan is not on this machine (dnf install openssh-clients)")
    got = subprocess.run(["ssh-keyscan", "-T", "10", "-p", str(int(port)), str(host).strip("[]")],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
    lines = [x for x in got.stdout.splitlines() if x.strip() and not x.startswith("#")]
    if not lines:
        raise RbError("%s:%s did not show a host key" % (host, port))
    text = "\n".join(lines) + "\n"
    return text, fingerprints(text)


# ---- the routes -------------------------------------------------------------------------------------
def get_backup(ctx):
    ctx.need("fulladmin")                       # the destinations' accounts are a full admin's to see
    return view(ctx)


def get_job(ctx):
    ctx.need("fulladmin")
    return {"job": job_view()}


def disk_words(e):
    """No room / no right to write, said - not "the API broke" (1.7.6)."""
    import errno
    if getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
        return "no room left on the disk of %s: %s" % (getattr(e, "filename", None) or "the state folder",
                                                       e.strerror or e)
    return "%s: %s" % (getattr(e, "filename", None) or "a file", e.strerror or e)


def post_backup(ctx):
    try:
        return _post_backup(ctx)
    except RbError as e:            # a name or a destination refused before any job: said, not "the API broke"
        raise ValueError(str(e))
    except OSError as e:
        if isinstance(e, PermissionError) and e.errno is None:
            raise                       # the role check (read only): a 403, as before
        raise ValueError(disk_words(e))


def _post_backup(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    who = ctx.me["name"]
    if act == "job":
        return {"job": job_view()}
    if act == "save":
        ts = targets(ctx)
        tid = str(b.get("id") or "")
        old = next((t for t in ts if t["id"] == tid), None) if tid else None
        if tid and old is None:
            raise ValueError("no such destination")
        if old is None and len(ts) >= TARGETS_MOST:
            raise ValueError("%d destinations at most" % TARGETS_MOST)
        t = checked(b.get("target") or {}, old)
        if old is None:
            ts.append(t)
        else:
            ts = [t if x["id"] == tid else x for x in ts]
        put_targets(ctx, ts)
        ctx.event("%s %s the destination of the backups %s (%s)" % (who, "changed" if old else "added", t["name"],
                                                                     KIND_WORDS[t["kind"]]))
        return {"target": view_target(t, ctx.store.meta_json("backup:last:" + t["id"])), "message": "saved"}
    if act == "delete":
        t = target(ctx, str(b.get("id") or ""))
        put_targets(ctx, [x for x in targets(ctx) if x["id"] != t["id"]])
        ctx.store.set_meta("backup:last:" + t["id"], "")
        ctx.event("%s took the destination of the backups %s away" % (who, t["name"]), "warn")
        return {"message": "%s is taken away - nothing was deleted there" % t["name"]}
    if act == "try":
        tid = str(b.get("id") or "")
        old = target(ctx, tid) if tid else None
        t = checked(b["target"], old) if isinstance(b.get("target"), dict) else old
        if t is None:
            raise ValueError("nothing to try")
        if t["kind"] in ("sftp", "scp") and not t.get("hostkey"):
            try:
                text, fps = keyscan(t["host"], t["port"])
            except RbError as e:
                return {"works": False, "steps": [], "error": str(e), "secs": 0}
            return {"hostkey_needed": True, "hostkey": text, "fingerprints": fps}
        r = try_target(t, ctx)
        ctx.event("%s tried the destination %s: %s" % (who, t["name"], "it works" if r["ok"] else r.get("error")),
                  "info" if r["ok"] else "warn")
        r["works"] = r.pop("ok")              # "ok" is the answer's own: false would read as a refusal
        return r
    if act == "hostkey_trust":
        ts = targets(ctx)
        t = target(ctx, str(b.get("id") or ""))
        hk = str(b.get("hostkey") or "")
        if not hk or len(hk) > 20000 or not all(re.match(r"^\S+ (ssh-|ecdsa-|sk-)\S+ [A-Za-z0-9+/=]+\s*$", x)
                                                  for x in hk.strip().splitlines()):
            raise ValueError("that is not a host key as ssh-keyscan shows it")
        msg = "trusted"
        if t.get("hostkey") and t["hostkey"] != hk and t.get("password"):
            t["password"] = ""
            msg = "trusted - another key than before, so the saved password was forgotten: type it again"
        t["hostkey"] = hk
        put_targets(ctx, [t if x["id"] == t["id"] else x for x in ts])
        ctx.event("%s trusted the host key of %s (%s)" % (who, t["name"], ", ".join(fingerprints(hk))[:300]))
        return {"message": msg, "fingerprints": fingerprints(hk)}
    if act in ("hostkey_forget", "keygen", "key_paste", "key_forget", "key_download"):
        ts = targets(ctx)
        t = target(ctx, str(b.get("id") or ""))
        if t["kind"] not in ("sftp", "scp"):
            raise ValueError("only SFTP and SCP have keys")
        out = {}
        if act == "hostkey_forget":
            t.pop("hostkey", None)
            t["password"] = ""
            out["message"] = "the host key is forgotten, and the password with it"
        elif act == "keygen":
            t["key"], t["pub"] = keygen(ctx, t)
            t.pop("key_pass", None)
            out["pub"] = t["pub"]
        elif act == "key_paste":
            key = str(b.get("key") or "")
            pp = str(b.get("passphrase") or "")
            t["pub"] = key_public(key, pp)
            t["key"] = key.strip() + "\n"
            t["key_pass"] = pp
            out["pub"] = t["pub"]
        elif act == "key_forget":
            for k in ("key", "pub", "key_pass"):
                t.pop(k, None)
        else:
            if not t.get("key"):
                raise ValueError("there is no key")
            ctx.event("%s downloaded the private SSH key of the destination %s" % (who, t["name"]), "warn")
            return {"pem": t["key"], "file": "fake-igd-backup-%s.key" % slug(t["name"])}
        put_targets(ctx, [t if x["id"] == t["id"] else x for x in ts])
        ctx.event("%s: %s of the destination %s" % (who, {"hostkey_forget": "the host key forgotten",
                                                           "keygen": "a new SSH key made",
                                                           "key_paste": "an SSH key of their own put in",
                                                           "key_forget": "the SSH key forgotten"}[act], t["name"]))
        return out
    if act == "run":
        only = [str(x) for x in b["only"]] if isinstance(b.get("only"), list) else None
        only = only or None
        j = start_job(ctx, "the backup", who, lambda p: run(ctx, who, only, p))
        return {"job": j, "message": "the backup is being made"}
    if act == "verify":
        tid = str(b.get("id") or "") or None
        j = start_job(ctx, "trying the newest backup", who, lambda p: verify(ctx, who, tid, None, p))
        return {"job": j, "message": "the newest backup is being fetched and tried"}
    if act == "download":
        tid, name = str(b.get("id") or ""), str(b.get("name") or "")

        def make(p):
            out = sub(ctx, "out")
            if tid:
                safe_name(name)
                dst = os.path.join(out, "download-" + name)
                fetch(ctx, tid, name, dst)
                return {"ready": "download-" + name, "name": name}
            unlocked = not password(ctx)
            if unlocked and b.get("unlocked") is not True:
                raise RbError("the backups have no password - set it first, or download it not locked")
            work = tempfile.mkdtemp(prefix="dl-", dir=sub(ctx, "work"))
            collected, _w = collect(ctx, p)
            try:
                final, m, _md = build(ctx, work, collected, p, unlocked=unlocked)
            finally:
                shutil.rmtree(work, ignore_errors=True)
                if collected:
                    os.unlink(collected)
            os.replace(final, os.path.join(out, "download-" + m["file"]))
            for c in companions(m["file"]):
                try:
                    os.unlink(os.path.join(out, c))
                except OSError:
                    pass
            return {"ready": "download-" + m["file"], "name": m["file"], "system": bool(collected)}
        if not tid and not password(ctx) and b.get("unlocked") is True:
            ctx.event("%s downloaded a backup that is NOT locked (no password of the backups is set)" % who, "warn")
        j = start_job(ctx, "a backup to download", who, make)
        return {"job": j, "message": "it is being made - the download starts when it is ready"}
    if act == "download_get":
        r = (job_view().get("result") or {})
        ready = str(b.get("ready") or "")
        if not ready or ready != r.get("ready"):
            raise ValueError("no backup is waiting to be downloaded")
        p = os.path.join(sub(ctx, "out"), ready)
        with open(p, "rb") as f:
            data = f.read()
        os.unlink(p)
        ctx.event("%s downloaded the backup %s" % (who, r.get("name")), "warn")
        return {"name": r.get("name"), "bytes": len(data), "data": base64.b64encode(data).decode("ascii")}
    if act == "list":
        try:
            return {"files": remote_list(ctx, str(b.get("id") or ""))}
        except RbError as e:
            raise ValueError(str(e))
    if act == "delete_file":
        t = target(ctx, str(b.get("id") or ""))
        name = safe_name(b.get("name"))
        if not NAME_RE.match(name):
            raise ValueError("not a backup of fake-igd")
        tr = transport(t, ctx)
        try:
            tr.open()
            tr.delete(name)
            names = set(x["name"] for x in tr.list())
            for c in companions(name):
                if c in names:
                    tr.delete(c)
        except RbError as e:
            raise ValueError(str(e))
        finally:
            tr.close()
        ctx.event("%s deleted the backup %s at %s" % (who, name, t["name"]), "warn")
        return {"message": "deleted"}
    if act == "restore":
        src = {"upload": str(b.get("upload") or ""), "file": b.get("file")} if b.get("upload") else \
            {"id": str(b.get("id") or ""), "name": safe_name(b.get("name"))}
        if not src.get("upload"):
            target(ctx, src["id"])
        pw = str(b.get("password") or "")
        j = start_job(ctx, "putting a backup back", who, lambda p: restore(ctx, who, src, pw, p))
        return {"job": j, "message": "the backup is being put back"}
    if act == "runs_forget":
        rows = runs(ctx)
        if b.get("all"):
            rows = []
        else:
            rows = [r for r in rows if not (abs(float(r.get("at") or 0) - float(b.get("at") or -1)) < 0.001
                                            and (r.get("file") or "") == (b.get("file") or ""))]
        runs_put(ctx, rows)
        ctx.event("%s cleared %s of the backups sent" % (who, "the list" if b.get("all") else "a line"))
        return {"runs": rows, "message": "cleared"}
    if act == "verified_forget":
        rows = [] if b.get("all") else [r for r in verified(ctx) if abs(float(r.get("at") or 0) -
                                                                         float(b.get("at") or -1)) >= 0.001]
        ctx.store.set_meta("backup:verified", json.dumps({"list": rows}))
        ctx.event("%s cleared %s of the backups tried" % (who, "the list" if b.get("all") else "a line"))
        return {"verified": rows, "message": "cleared"}
    if act == "restore_md":
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = "fake-igd-backup-%s-%s-%s" % (site(ctx), slug(node_name()), stamp)
        m = manifest(ctx, base, password(ctx))
        return {"md": restore_md(m), "name": "RESTORE-%s-%s.md" % (site(ctx), slug(node_name())), "file": m["file"]}
    raise ValueError("no such action")


def post_restore(ctx):
    try:
        return _post_restore(ctx)
    except OSError as e:
        if isinstance(e, PermissionError) and e.errno is None:
            raise                       # the role check (read only): a 403, as before
        raise ValueError(disk_words(e))


def _post_restore(ctx):
    """A backup file sent from the browser (base64 in JSON) - kept for an hour; what it is said if the
    password opens it. Nothing is put back until action restore."""
    ctx.need("fulladmin")
    b = ctx.body(most=96 * 1024 * 1024)
    try:
        data = base64.b64decode(str(b.get("data") or ""), validate=True)
    except ValueError:
        raise ValueError("the file did not come whole")
    if not data:
        raise ValueError("the file is empty")
    folder = sub(ctx, "in")
    for n in os.listdir(folder):
        p = os.path.join(folder, n)
        if UPLOAD_RE.match(n) and time.time() - os.path.getmtime(p) > 3600:
            os.unlink(p)
    up = "upload-%s" % secrets.token_hex(8)
    p = os.path.join(folder, up)
    with open(p, "wb") as f:
        f.write(data)
    locked = data[:8] == b"Salted__"
    out = {"upload": up, "locked": locked, "name": str(b.get("name") or "")[:120]}
    if not locked and data[:2] != b"\x1f\x8b":
        os.unlink(p)
        raise ValueError("that is not a backup of fake-igd (neither locked nor a .tar.gz)")
    work = tempfile.mkdtemp(prefix="peek-", dir=sub(ctx, "work"))
    try:
        m, _x = open_file(ctx, p, str(b.get("password") or ""), work)
        out["manifest"] = {k: m.get(k) for k in ("node", "host", "site", "made", "made_words", "version", "system")}
    except RbError as e:
        out["said"] = str(e)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


ROUTES = {("GET", "/api/backup"): get_backup, ("POST", "/api/backup"): post_backup,
          ("GET", "/api/backup/job"): get_job, ("POST", "/api/backup/restore"): post_restore}


def on_saved(ctx, changed):
    SEAL.seal_settings(ctx.store, ["rbackup_password"])     # kept sealed in the database (igd_seal)


def seal_old(ctx):
    """What 1.6.0 kept as it was typed, sealed now (once: then nothing is left to seal)."""
    SEAL.seal_settings(ctx.store, ["rbackup_password"])
    got = ctx.store.meta_json("backup:targets") or {}
    if any(t.get(k) and not SEAL.is_sealed(t.get(k)) for t in got.get("list") or [] for k in SECRET_FIELDS):
        put_targets(ctx, targets(ctx))


AGAIN_BY = "the schedule, again"


def weekly_slot(at, day, now=None):
    """The date (YYYY-MM-DD) of the last time a weekly job on `day` (1 Monday - 7 Sunday) at `at` (HH:MM) was due,
    at `now` or before (1.9.11)."""
    try:
        h, mi = int(at[:2]), int(at[3:5])
    except ValueError:
        return None
    now = now or time.time()
    lt = time.localtime(now)
    for d in range(0, 8):
        t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday - d, h, mi, 0, 0, 0, -1))
        if t <= now and time.localtime(t).tm_wday + 1 == day:
            return time.strftime("%Y-%m-%d", time.localtime(t))
    return None


def again_due(ctx, today):
    """otp's rb_tick_again (1.0.278): today's scheduled backup failed - tried again an hour later, three
    times at most the same day. One failure (the destination down at 04:15) left a weekly schedule a week
    more without a backup."""
    if ctx.store.get_meta("backup:day") != today or not any(t.get("enabled") for t in targets(ctx)):
        return False
    mine = [r for r in runs(ctx) if str(r.get("by") or "") in ("", AGAIN_BY)
            and time.strftime("%Y-%m-%d", time.localtime(float(r.get("at") or 0))) == today]
    if not mine or mine[0].get("ok") or len(mine) >= 4:
        return False
    if time.time() - float(mine[0].get("at") or 0) < 3600:
        return False
    return time.time() - float(ctx.store.get_meta("backup:again:at") or 0) >= 3600


def background(ctx):
    """The scheduled backup (tried again when it failed), and the weekly try."""
    seal_old(ctx)
    if not ctx.setting("rbackup"):
        return
    at = str(ctx.setting("rbackup_at") or "04:15")
    if not HHMM_RE.match(at):
        return
    today = time.strftime("%Y-%m-%d")
    lt = time.localtime()
    last_day = ctx.store.get_meta("backup:day")
    due = time.strftime("%H:%M") >= at and last_day != today
    if ctx.setting("rbackup_every") == "weekly" and lt.tm_wday + 1 != int(ctx.setting("rbackup_day") or 7):
        # Its day gone by while the API was away: made once now, not a week later (1.9.11) - when the last
        # scheduled one is older than the day it should have been made on.
        slot = weekly_slot(at, int(ctx.setting("rbackup_day") or 7))
        due = bool(last_day) and slot is not None and last_day < slot
    if due and not job_view()["running"]:
        ctx.store.set_meta("backup:day", today)
        try:
            start_job(ctx, "the backup", "the schedule", lambda p: run(ctx, "", None, p))
        except ValueError:
            pass
        return
    if again_due(ctx, today) and not job_view()["running"]:
        ctx.store.set_meta("backup:again:at", str(time.time()))
        try:
            start_job(ctx, "the backup", "the schedule", lambda p: run(ctx, AGAIN_BY, None, p))
        except ValueError:
            pass
        return
    if ctx.setting("rbackup_verify") == "weekly" and not job_view()["running"]:
        last = float(ctx.store.get_meta("backup:verified:at") or 0)
        if time.time() - last > 7 * 86400 and any(t.get("enabled") for t in targets(ctx)) and runs(ctx):
            ctx.store.set_meta("backup:verified:at", str(time.time()))
            try:
                start_job(ctx, "trying the newest backup", "the schedule", lambda p: verify(ctx, "", None, None, p))
            except ValueError:
                pass
