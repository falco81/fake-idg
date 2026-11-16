"""root_backup.py - root's part of Settings → Backups and Export and import.

The API (the fake-igd account) makes the backup, locks it and sends it; what only root
may read or write is done here, asked through the queue (kind "backup"):

  do=collect   the system's files that make this installation what it is, into
               /var/lib/fake-igd/backup/work/collect-JOB.tar (root:fake-igd 0640) - the
               avahi-daemon.conf, nginx's fake-igd.conf, the certificate and key of the
               pages, the journal's drop-in, logrotate's file, and fake-igd's lines of
               /etc/sysconfig/iptables (to read - the firewall is made again from config.json).
               `only` narrows it to some of them.
  do=restore   the files of work/restore-JOB.tar put back where they belong: each name
               must be one of those above (nothing else is ever written), a regular file
               of a sane size and shape; the one there is kept beside it (.before-restore)
               and put back when the service does not take the new one (nginx -t, avahi-daemon
               restarted and up). Then nginx's allow list, the firewall and fake-igd.service as
               the (restored) config.json says - fake_igd_web.apply(restart=True).
  do=folder_*  a destination that is a folder on this machine (an NFS or CIFS mount): the
               API's sandbox may not write outside /var/lib/fake-igd, so root does -
               folder_check (made, writable), folder_put (from backup/out/, under a temporary
               name, renamed when whole), folder_list, folder_get (into backup/work/,
               root:fake-igd 0640) and folder_delete. The folder is an absolute path, no ..,
               never under the system's own folders.

Every answer is also written to backup/work/JOB.json (root:fake-igd 0640), which the API
waits for: the queue keeps one result a kind, and two asks may be in it at once.

Paths for tests: FAKE_IGD_STATE, FAKE_IGD_AVAHI_CONF, FAKE_IGD_NGINX, FAKE_IGD_CERT,
FAKE_IGD_CERT_KEY, FAKE_IGD_JOURNALD_DROPIN, FAKE_IGD_LOGROTATE, FAKE_IGD_IPTABLES_FILE;
FAKE_IGD_NO_SERVICES=1 checks and restarts nothing; FAKE_IGD_FOLDER_ANYWHERE=1 lets a test
use a folder under /tmp.
"""
import grp
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time


class _Refused(Exception):
    pass


Refused = getattr(sys.modules.get("__main__"), "Refused", None) or _Refused

STATE_DIR = os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd")
BACKUP_DIR = os.path.join(STATE_DIR, "backup")
WORK = os.path.join(BACKUP_DIR, "work")
OUT = os.path.join(BACKUP_DIR, "out")
NO_SERVICES = bool(os.environ.get("FAKE_IGD_NO_SERVICES"))
IPT_FILE = os.environ.get("FAKE_IGD_IPTABLES_FILE", "/etc/sysconfig/iptables")
MARK = "# fake-igd:"
# The name a file has in a backup -> where it lives here, and what it must look like.
FILES = {
    "etc/avahi/avahi-daemon.conf": (os.environ.get("FAKE_IGD_AVAHI_CONF", "/etc/avahi/avahi-daemon.conf"),
                                    "avahi", 0o644),
    "etc/nginx/conf.d/fake-igd.conf": (os.environ.get("FAKE_IGD_NGINX", "/etc/nginx/conf.d/fake-igd.conf"),
                                       "nginx", 0o644),
    "etc/nginx/certs/fake-igd.pem": (os.environ.get("FAKE_IGD_CERT", "/etc/nginx/certs/fake-igd.pem"), "cert", 0o644),
    "etc/nginx/certs/fake-igd.key": (os.environ.get("FAKE_IGD_CERT_KEY", "/etc/nginx/certs/fake-igd.key"), "key", 0o600),
    "etc/systemd/journald.conf.d/00-fake-igd.conf": (
        os.environ.get("FAKE_IGD_JOURNALD_DROPIN", "/etc/systemd/journald.conf.d/00-fake-igd.conf"), "text", 0o644),
    "etc/logrotate.d/fake-igd": (os.environ.get("FAKE_IGD_LOGROTATE", "/etc/logrotate.d/fake-igd"), "text", 0o644),
}
IPT_NAME = "etc/sysconfig/iptables.fake-igd"
GROUPS = {"tls": ("etc/nginx/certs/fake-igd.pem", "etc/nginx/certs/fake-igd.key"),
          "avahi": ("etc/avahi/avahi-daemon.conf",), "nginx": ("etc/nginx/conf.d/fake-igd.conf",),
          "logs": ("etc/systemd/journald.conf.d/00-fake-igd.conf", "etc/logrotate.d/fake-igd"),
          "iptables": (IPT_NAME,)}
MOST = 1024 * 1024
JOB_RE = re.compile(r"^[0-9a-f]{16}\Z")
NAME_RE = re.compile(r"^fake-igd-backup-[A-Za-z0-9_.-]{1,200}\Z")
NOT_UNDER = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev", "/run",
             "/root", "/var/lib", "/var/log", "/var/cache", "/var/spool", "/opt", "/tmp", "/var/tmp")


def _run(argv, timeout=120):
    try:
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)
    return r.returncode, r.stdout, r.stderr


def _gid():
    try:
        return grp.getgrnam("fake-igd").gr_gid
    except KeyError:
        return -1


def _subdir(dfd, name):
    """name inside the folder open as dfd - made root:fake-igd 0770 when it is not there; one that is
    there must be a folder itself, never a link. Returns its fd."""
    try:
        os.mkdir(name, 0o770, dir_fd=dfd)
        made = True
    except FileExistsError:
        made = False
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
    if made:
        try:
            os.fchown(fd, 0, _gid())
        except OSError:
            pass
        os.fchmod(fd, 0o770)
    return fd


def _work_fd():
    """backup/work, reached one folder at a time without following a link: the fake-igd account
    owns /var/lib/fake-igd and could lay one there."""
    top = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        b = _subdir(top, "backup")
    finally:
        os.close(top)
    try:
        return _subdir(b, "work")
    finally:
        os.close(b)


def _new_file(dfd, name):
    """A file made fresh in the folder open as dfd: a name there is taken away first and the new one
    made with O_EXCL and O_NOFOLLOW; root:fake-igd 0640 on the open file itself."""
    try:
        os.unlink(name, dir_fd=dfd)
    except FileNotFoundError:
        pass
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
    try:
        os.fchown(fd, 0, _gid())
    except OSError:
        pass
    os.fchmod(fd, 0o640)
    return os.fdopen(fd, "wb")


def _rename(dfd, a, b):
    os.replace(a, b, src_dir_fd=dfd, dst_dir_fd=dfd)


def _read(path, most=MOST, dfd=None):
    """A regular file, not through a link, at most `most` bytes - or None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        data = f.read(most + 1)
    return data if len(data) <= most else None


def _put(path, data, mode):
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    tmp = os.path.join(folder, ".%s.fake-igd-new" % os.path.basename(path))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _job(payload):
    j = payload.get("job")
    if not isinstance(j, str) or not JOB_RE.match(j):
        raise Refused("job: 16 hex digits")
    return j


def iptables_lines():
    text = (_read(IPT_FILE, 4 * MOST) or b"").decode("utf-8", "replace")
    lines, inside = [], False
    for ln in text.splitlines():
        if ln.startswith(MARK + " begin"):
            inside = True
        if inside or ln.startswith(MARK) or CHAIN_RE.search(ln) or ln.startswith("*") or ln == "COMMIT":
            lines.append(ln)
        if ln.startswith(MARK + " end"):
            inside = False
    return ("\n".join(lines) + "\n") if lines else ""


CHAIN_RE = re.compile(r"FAKE-IGD-IN")


# ---- collect ----------------------------------------------------------------------------
def collect(payload, said):
    job = _job(payload)
    only = payload.get("only")
    names = list(FILES) + [IPT_NAME]
    if only is not None:
        if not isinstance(only, list) or not all(isinstance(x, str) and x in GROUPS for x in only):
            raise Refused("only: some of %s" % ", ".join(sorted(GROUPS)))
        names = [n for g in only for n in GROUPS[g]]
    wfd = _work_fd()
    got, missing = [], []
    with _new_file(wfd, ".collect-%s.tar" % job) as raw, tarfile.open(fileobj=raw, mode="w") as tf:
        for name in names:
            if name == IPT_NAME:
                data = iptables_lines().encode("utf-8")
                if not data:
                    missing.append(IPT_FILE + " (no lines of fake-igd)")
                    continue
            else:
                data = _read(FILES[name][0])
                if data is None:
                    missing.append(FILES[name][0])
                    continue
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = int(time.time())
            ti.mode = 0o600
            tf.addfile(ti, io.BytesIO(data))
            got.append(name)
    _rename(wfd, ".collect-%s.tar" % job, "collect-%s.tar" % job)
    os.close(wfd)
    said.append("%d file(s) of the system collected%s" % (len(got), "; not there: " + ", ".join(missing)
                                                           if missing else ""))
    return {"files": got, "missing": missing, "tar": "collect-%s.tar" % job}


# ---- restore ------------------------------------------------------------------------------
def check_shape(kind, data):
    if b"\x00" in data:
        return "it is not text"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "it is not UTF-8 text"
    if kind == "cert" and "-----BEGIN CERTIFICATE-----" not in text:
        return "it holds no certificate"
    if kind == "key" and not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text):
        return "it holds no private key"
    if kind == "avahi" and not re.search(r"(?m)^\s*\[server\]\s*$", text):
        return "it has no [server] section - not an avahi-daemon.conf"
    if kind == "nginx" and "server" not in text:
        return "it has no server block"
    return ""


def nginx_ok():
    if NO_SERVICES or not shutil.which("nginx"):
        return True, ""
    rc, out, err = _run(["nginx", "-t"], 60)
    return rc == 0, (err or out).strip()[-300:]


def restore(payload, said):
    job = _job(payload)
    wfd = _work_fd()
    try:
        data = _read("restore-%s.tar" % job, 32 * MOST, wfd)
        if data is None:
            raise Refused("nothing to put back: work/restore-%s.tar is not there (or not a file)" % job)
        try:
            os.unlink("restore-%s.tar" % job, dir_fd=wfd)
        except OSError:
            pass
    finally:
        os.close(wfd)
    wanted = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        for m in tf.getmembers():
            if m.name == IPT_NAME:
                continue                           # only to read: the firewall is made from config.json
            if m.name not in FILES:
                said.append("%s left out - not a file fake-igd puts back" % m.name[:120])
                continue
            if not m.isreg() or m.size > MOST:
                said.append("%s left out - not a plain file of a sane size" % m.name)
                continue
            body = tf.extractfile(m).read()
            bad = check_shape(FILES[m.name][1], body)
            if bad:
                said.append("%s left out - %s" % (m.name, bad))
                continue
            wanted[m.name] = body
    changed = {}
    for name, body in wanted.items():
        path, _kind, mode = FILES[name]
        old = _read(path)
        if old == body:
            continue
        if old is not None:
            _put(path + ".before-restore", old, 0o600)
        _put(path, body, mode)
        changed[name] = old
    if not changed:
        said.append("the system's files were already as in it")
    web = [n for n in changed if n.startswith("etc/nginx/")]
    if web:
        ok, words = nginx_ok()
        if not ok:
            for n in web:
                _back(n, changed[n])
            said.append("nginx did not take them (%s) - %s put back as they were" % (words, ", ".join(web)))
            web = []
        elif not NO_SERVICES and shutil.which("systemctl"):
            _run(["systemctl", "reload", "nginx"], 60)
    if "etc/avahi/avahi-daemon.conf" in changed and not NO_SERVICES and shutil.which("systemctl"):
        rc, _o, err = _run(["systemctl", "restart", "avahi-daemon"], 60)
        rc2, out2, _e = _run(["systemctl", "is-active", "avahi-daemon"], 20)
        if rc != 0 or out2.strip() != "active":
            _back("etc/avahi/avahi-daemon.conf", changed["etc/avahi/avahi-daemon.conf"])
            _run(["systemctl", "restart", "avahi-daemon"], 60)
            said.append("avahi-daemon did not come up with it (%s) - avahi-daemon.conf put back as it was"
                        % err.strip()[-200:])
            changed.pop("etc/avahi/avahi-daemon.conf")
    if "etc/systemd/journald.conf.d/00-fake-igd.conf" in changed and not NO_SERVICES and shutil.which("systemctl"):
        _run(["systemctl", "restart", "systemd-journald"], 60)
    for n in changed:
        said.append("%s put back (the one before is beside it, .before-restore)" % FILES[n][0])
    main = sys.modules.get("__main__")
    if payload.get("apply") is True and main is not None and hasattr(main, "apply"):
        try:
            said.extend(main.apply(restart=True))
        except Exception as e:                      # noqa: BLE001 - said, the files stay put back
            said.append("nginx's allow list, the firewall and the service as config.json says: %s" % e)
    return {"put_back": sorted(changed)}


def _back(name, old):
    path, _kind, mode = FILES[name]
    if old is None:
        try:
            os.unlink(path)
        except OSError:
            pass
    else:
        _put(path, old, mode)


# ---- a folder on this machine as a destination -----------------------------------------------
def folder_path(payload):
    p = payload.get("path")
    if not isinstance(p, str) or not p.startswith("/") or len(p) > 400 or "\x00" in p or "\n" in p:
        raise Refused("the folder is a whole path on this machine (/mnt/backup/fake-igd)")
    if re.search(r"(^|/)\.\.?(/|$)", p):
        raise Refused("the folder has no . or .. in it")
    p = os.path.normpath(p)
    if not os.environ.get("FAKE_IGD_FOLDER_ANYWHERE"):
        if p == "/" or any(p == x or p.startswith(x + "/") for x in NOT_UNDER):
            raise Refused("not under %s - a folder of its own (/mnt, /srv, /backup …)" % ", ".join(NOT_UNDER[:6]))
    real = os.path.realpath(p)
    if real != p and os.path.exists(p):
        raise Refused("the folder is reached through a link - give its real path (%s)" % real)
    return p


def file_name(payload, key="name"):
    n = payload.get(key)
    if not isinstance(n, str) or not NAME_RE.match(n):
        raise Refused("not a file name of a backup")
    return n


def folder(payload, said):
    do = payload["do"]
    p = folder_path(payload)
    if do == "folder_check":
        os.makedirs(p, mode=0o700, exist_ok=True)
        probe = os.path.join(p, ".fake-igd-try")
        with open(probe, "w") as f:
            f.write("fake-igd tried this folder\n")
        os.unlink(probe)
        said.append("%s is there and root writes into it" % p)
        return {}
    if not os.path.isdir(p):
        raise Refused("%s is not there" % p)
    if do == "folder_list":
        out = []
        for n in os.listdir(p):
            if not NAME_RE.match(n):
                continue
            st = os.lstat(os.path.join(p, n))
            if stat.S_ISREG(st.st_mode):
                out.append({"name": n, "size": st.st_size, "mtime": st.st_mtime})
        return {"files": out}
    name = file_name(payload)
    if do == "folder_put":
        src = os.path.join(OUT, name)
        top = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            b = os.open("backup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=top)
        finally:
            os.close(top)
        try:
            o = os.open("out", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=b)
        finally:
            os.close(b)
        try:
            sfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=o)
        finally:
            os.close(o)
        part = os.path.join(p, ".%s.part" % name)
        with os.fdopen(sfd, "rb") as a:
            if not stat.S_ISREG(os.fstat(a.fileno()).st_mode):
                raise Refused("%s is not a file" % src)
            fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as b:
                shutil.copyfileobj(a, b, 1 << 20)
                b.flush()
                os.fsync(b.fileno())
        os.replace(part, os.path.join(p, name))
        return {}
    if do == "folder_get":
        src = os.path.join(p, name)
        sfd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        job = _job(payload)
        wfd = _work_fd()
        try:
            with os.fdopen(sfd, "rb") as a:
                if not stat.S_ISREG(os.fstat(a.fileno()).st_mode):
                    raise Refused("%s is not a file" % src)
                with _new_file(wfd, ".fetched-%s.part" % job) as b:
                    shutil.copyfileobj(a, b, 1 << 20)
            _rename(wfd, ".fetched-%s.part" % job, "fetched-%s" % job)
        finally:
            os.close(wfd)
        return {"file": "fetched-%s" % job}
    if do == "folder_delete":
        try:
            os.unlink(os.path.join(p, name))
        except FileNotFoundError:
            pass
        return {}
    raise Refused("no such folder step")


def _serve(payload, ask):
    do = payload.get("do")
    said = []
    if do == "collect":
        out = collect(payload, said)
    elif do == "restore":
        out = restore(payload, said)
    elif do in ("folder_check", "folder_list", "folder_put", "folder_get", "folder_delete"):
        try:
            out = folder(payload, said)
        except OSError as e:
            raise Refused("%s: %s" % (payload.get("path"), e.strerror or e))
    else:
        raise Refused("collect, restore or a folder step only")
    out.update({"ok": True, "do": do, "said": said})
    answer(payload, out)
    return out


def answer(payload, out):
    """The answer beside the work too, where the API waits for it by the job's name."""
    job = payload.get("job")
    if not isinstance(job, str) or not JOB_RE.match(job):
        return
    wfd = _work_fd()
    try:
        with _new_file(wfd, ".%s.json.part" % job) as f:
            f.write(json.dumps(dict(out, at=time.time()), default=str).encode("utf-8"))
        _rename(wfd, ".%s.json.part" % job, "%s.json" % job)
    finally:
        os.close(wfd)


def serve(payload, ask):
    try:
        return _serve(payload, ask)
    except Exception as e:                          # noqa: BLE001 - the API waits for an answer either way
        answer(payload, {"ok": False, "do": payload.get("do"), "said": [str(e)]})
        raise
