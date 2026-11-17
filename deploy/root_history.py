"""root_history.py - Settings → The database → Erase the collected data: what is kept outside the database,
erased by root (1.7.12). Asked through the queue (web/ask/history-*.json), run as root by fake_igd_web.py.

  {"what": ["requests", "log", "mappings"]}

  requests   the request log (requests.jsonl, and its rotated copies): every SSDP/SOAP request - what the
             Ports, Requests and Clients tabs, the Overview's chart and the reports are made of
  log        the service's own log (fake-igd.log, and its rotated copies): the searches of the devices, the
             steps of each client, what the service said
  mappings   the mappings the devices believe are open (mappings.json) - fake-igd.service is stopped, the
             file emptied and the service started again: for a few seconds nothing is answered

Nothing of the request is trusted but which of these three. The files are never taken from config.json
(which the API's group may write): only fake-igd's own log folder and state folder, regular files that are
not links, opened without following one, truncated on the open file. Every path can be pointed elsewhere
for a test: FAKE_IGD_LOG_DIR, FAKE_IGD_STATE, FAKE_IGD_SYSTEMCTL.
"""
import json
import os
import re
import stat
import subprocess

LOG_DIR = os.environ.get("FAKE_IGD_LOG_DIR", "/var/log/fake-igd")
STATE_DIR = os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd")
SYSTEMCTL = os.environ.get("FAKE_IGD_SYSTEMCTL") or "systemctl"
UNIT = "fake-igd.service"
WHAT = ("requests", "log", "mappings")
# The files of each, in LOG_DIR: the file itself and what logrotate made of it (name.1, name.2.gz,
# name-20261117, name-20261117.gz).
FILES = {"requests": "requests.jsonl", "log": "fake-igd.log"}
ROTATED = r"^%s(\.\d+|-\d{8})(\.gz|\.xz|\.bz2|\.zst)?\Z"


class Refused(Exception):
    pass


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                           timeout=timeout)
        return r.returncode, (r.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return 124, "did not finish in %d s" % timeout
    except OSError as e:
        return 127, str(e)


def _folder(path):
    """A folder of fake-igd's, opened without following a link: its descriptor."""
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _erase_files(base, said):
    """LOG_DIR/base emptied in place (the service goes on writing into it), its rotated copies taken away.
    Returns (bytes before, files)."""
    try:
        dfd = _folder(LOG_DIR)
    except OSError as e:
        said.append("%s cannot be opened: %s" % (LOG_DIR, e))
        return 0, 0
    total, n = 0, 0
    try:
        rot = re.compile(ROTATED % re.escape(base))
        for name in sorted(os.listdir(dfd)):
            if name != base and not rot.match(name):
                continue
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                said.append("%s/%s is not a plain file - left alone" % (LOG_DIR, name))
                continue
            total += st.st_size
            if name == base:
                fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                try:
                    if stat.S_ISREG(os.fstat(fd).st_mode):
                        os.ftruncate(fd, 0)
                finally:
                    os.close(fd)
            else:
                os.unlink(name, dir_fd=dfd)
            n += 1
    finally:
        os.close(dfd)
    return total, n


def _empty_mappings(said):
    dfd = _folder(STATE_DIR)
    try:
        tmp = ".mappings.json.%d" % os.getpid()
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
        with os.fdopen(fd, "w") as f:
            f.write("[]\n")
            try:   # the service's own, as it writes it - on the open file, never by name
                import pwd
                pw = pwd.getpwnam("fake-igd")
                os.fchown(f.fileno(), pw.pw_uid, pw.pw_gid)
            except (KeyError, OSError):
                pass
        os.replace(tmp, "mappings.json", src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


def _state():
    _rc, out = _run([SYSTEMCTL, "is-active", UNIT], 20)
    return (out.splitlines() or ["unknown"])[-1].strip()


def serve(payload, ask=None):
    what = payload.get("what") if isinstance(payload, dict) else None
    if not isinstance(what, list) or not what or any(w not in WHAT for w in what):
        return {"ok": False, "said": ["requests, log and/or mappings - nothing else is erased here"]}
    what = [w for w in WHAT if w in what]
    said, done = [], []
    was = None
    try:
        if "mappings" in what:
            was = _state()
            if was == "active":
                rc, out = _run([SYSTEMCTL, "stop", UNIT])
                if rc != 0:
                    raise Refused("%s could not be stopped, nothing was erased: %s" % (UNIT, out[-300:]))
                said.append("%s stopped" % UNIT)
        for w in ("requests", "log"):
            if w in what:
                b, n = _erase_files(FILES[w], said)
                done.append(w)
                said.append("%s erased - %d file(s), %d bytes" % (
                    {"requests": "the request log", "log": "the service's log"}[w], n, b))
        if "mappings" in what:
            try:
                with open(os.path.join(STATE_DIR, "mappings.json"), encoding="utf-8") as f:
                    had = len(json.load(f) or [])
            except (OSError, ValueError, TypeError):
                had = 0
            _empty_mappings(said)
            done.append("mappings")
            said.append("the mappings forgotten (%d)" % had)
    except Refused as e:
        return {"ok": False, "said": said + [str(e)], "done": done}
    except OSError as e:
        said.append("it stopped half way: %s" % e)
        return {"ok": False, "said": said, "done": done}
    finally:
        if was == "active":
            rc, out = _run([SYSTEMCTL, "start", UNIT])
            said.append("%s started again" % UNIT if rc == 0 else
                        "%s could not be started again: %s - Settings → The service" % (UNIT, out[-300:]))
    return {"ok": True, "said": said, "done": done}
