"""root_service.py - what root does for Settings → The service and Settings → About (1.6.1).

Asked through the queue (web/ask/service-*.json, fake-igd-web.path); run as root by
fake_igd_web.py, which hands it the payload and writes what it returns to
web/result-service.json. Nothing in the payload is trusted:

  {"do": "restart" | "stop" | "start" | "reload", "unit": UNIT}
      UNIT and what may be done to it come from the list below and nothing else: fake-igd,
      its API, nginx, php-fpm, avahi-daemon. nginx is asked (nginx -t) and php-fpm too
      (php-fpm -t) before either is reloaded or restarted - a configuration that does not
      read is said, and the running one is left as it is. The path units root's part hangs
      on are never stopped from the pages (nothing could start them again from there).

  {"do": "console", "on": true|false, "users": "*" | ["alice", ...]}
      /etc/upnp-console-login, as `upnp --console-at-login on|off --console-users ...`
      writes it: written beside it and put in its place, a link or a pipe found there
      replaced, never followed.

Python 3.9, the standard library. Every path can be pointed elsewhere for a test:
FAKE_IGD_SYSTEMCTL, FAKE_IGD_NGINX_BIN, FAKE_IGD_PHP_FPM, UPNP_CONSOLE_FLAG, UPNP_CONSOLE_PROFILE.
"""
import glob
import json
import os
import re
import shutil
import stat
import subprocess

SYSTEMCTL = os.environ.get("FAKE_IGD_SYSTEMCTL") or "systemctl"
NGINX = os.environ.get("FAKE_IGD_NGINX_BIN") or "nginx"
PHP_FPM = os.environ.get("FAKE_IGD_PHP_FPM") or ""
CONSOLE_FLAG = os.environ.get("UPNP_CONSOLE_FLAG", "/etc/upnp-console-login")
CONSOLE_PROFILE = os.environ.get("UPNP_CONSOLE_PROFILE", "/etc/profile.d/zz-upnp-console.sh")
WEB_DIR = os.path.join(os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd"), "web")
ANSWERS_KEPT = 20
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")

# The units and what may be done to each - the same list as the API's (api_about.UNITS).
ALLOWED = {
    "fake-igd.service": ("restart", "stop", "start"),
    "fake-igd-api.service": ("restart",),
    "nginx.service": ("reload", "restart"),
    "php-fpm.service": ("restart",),
    "avahi-daemon.service": ("restart", "stop", "start"),
}
DONE = {"restart": "restarted", "stop": "stopped", "start": "started", "reload": "reloaded"}


class Refused(Exception):
    pass


def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "%s did not finish in %d s" % (os.path.basename(cmd[0]), timeout)
    except OSError as e:
        return 127, str(e)
    return r.returncode, (r.stdout or "").strip()


def php_fpm():
    if PHP_FPM:
        return PHP_FPM
    found = sorted(glob.glob("/usr/sbin/php-fpm*") + glob.glob("/usr/sbin/php*-fpm*"))
    return found[-1] if found else shutil.which("php-fpm")


def state(unit):
    _rc, out = run([SYSTEMCTL, "show", "--no-pager", "-p", "ActiveState,SubState,MainPID", unit], 20)
    d = dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)
    return d.get("ActiveState") or "unknown", d.get("SubState") or "", d.get("MainPID") or ""


def check_first(unit):
    """nginx -t, php-fpm -t: (ok, words)."""
    if unit == "nginx.service":
        rc, out = run([NGINX, "-t"], 30)
        if rc != 0:
            return False, "nginx -t refused its configuration, nginx is left as it runs: %s" % out[-400:]
        return True, "nginx -t: the configuration reads"
    if unit == "php-fpm.service":
        exe = php_fpm()
        if not exe:
            return True, ""
        rc, out = run([exe, "-t"], 30)
        if rc != 0:
            return False, "php-fpm -t refused its configuration, php-fpm is left as it runs: %s" % out[-400:]
        return True, "php-fpm -t: the configuration reads"
    return True, ""


def unit_do(do, unit):
    if not isinstance(unit, str) or unit not in ALLOWED:
        raise Refused("%s is not one of the units these pages may touch" % str(unit)[:60])
    if do not in ALLOWED[unit]:
        raise Refused("%s is not %s from the pages" % (unit, DONE.get(do, "changed so") if do in DONE else "changed so"))
    said = []
    if do in ("restart", "reload", "start"):
        ok, words = check_first(unit)
        if words:
            said.append(words)
        if not ok:
            st = state(unit)
            return {"ok": False, "said": said, "unit": unit, "do": do, "now": "%s (%s)" % st[:2]}
    was = state(unit)
    rc, out = run([SYSTEMCTL, do, unit], 120)
    now = state(unit)
    if rc != 0:
        said.append("systemctl %s %s failed: %s" % (do, unit, out[-400:] or "exit %d" % rc))
        return {"ok": False, "said": said, "unit": unit, "do": do, "now": "%s (%s)" % now[:2]}
    want_up = do != "stop"
    good = (now[0] == "active") if want_up else (now[0] in ("inactive", "failed"))
    if good:
        said.append("%s %s - now %s (%s)%s" % (unit, DONE[do], now[0], now[1],
                                              ", PID %s" % now[2] if want_up and now[2] not in ("", "0") else ""))
    else:
        said.append("%s was %s, but it is %s (%s) now - see its journal" % (unit, DONE[do], now[0], now[1]))
    if was[0] != "active" and do == "reload":
        said.append("it was not running: nothing to reload")
    return {"ok": good, "said": said, "unit": unit, "do": do, "now": "%s (%s)" % now[:2]}


def console_users(users):
    if users == "*":
        return "*"
    if not isinstance(users, list) or len(users) > 200:
        raise Refused("the users: \"*\" or a list of names, 200 at most")
    out = []
    for u in users:
        if not isinstance(u, str) or not USER_RE.match(u) or u == "root":
            raise Refused("%r is not the name of a normal user" % str(u)[:40])
        if u not in out:
            out.append(u)
    return out


def console_read():
    try:
        fd = os.open(CONSOLE_FLAG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False, []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False, []
        text = os.read(fd, 8192).decode("utf-8", "replace")
    finally:
        os.close(fd)
    lines = text.split("\n")
    users = []
    for ln in lines[1:]:
        if ln.startswith("users:"):
            words = ln[6:].split()
            users = "*" if words == ["*"] else [w for w in words if USER_RE.match(w)][:200]
    return lines[0].strip() == "on", users


def console_set(on, users):
    if not isinstance(on, bool):
        raise Refused("on: true or false")
    users = console_users(users)
    text = "on\n" if on else "off\n"
    if users:
        text += "users: %s\n" % ("*" if users == "*" else " ".join(users))
    folder = os.path.dirname(CONSOLE_FLAG) or "."
    tmp = os.path.join(folder, ".%s.%d.tmp" % (os.path.basename(CONSOLE_FLAG), os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, text.encode())
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, CONSOLE_FLAG)
    got_on, got_users = console_read()
    said = ["the upnp console at login: %s for root; %s" % (
        "on" if got_on else "off",
        "every normal user, through sudo" if got_users == "*" else
        ("%s, through sudo" % ", ".join(got_users) if got_users else "no normal user"))]
    if not os.path.exists(CONSOLE_PROFILE):
        said.append("NOTE: %s is missing - run the installer again, or nothing opens it" % CONSOLE_PROFILE)
    return {"ok": got_on == on, "said": said, "do": "console", "console": {"on": got_on, "users": got_users}}


def answers_before():
    """The answers root gave before this one: the last result (written by fake_igd_web.py after each
    ask) and the ones it carried. Several asks served in one go each overwrite result-service.json,
    so each result carries the ones before it, and the API finds the answer to every ask. Read as
    data only - never followed through a link, never more than 256 kB - and checked shape by shape."""
    try:
        fd = os.open(os.path.join(WEB_DIR, "result-service.json"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return []
        raw = os.read(fd, 256 * 1024)
    finally:
        os.close(fd)
    try:
        last = json.loads(raw.decode("utf-8"))
    except ValueError:
        return []
    if not isinstance(last, dict):
        return []
    out = []
    for x in (last.get("answers") if isinstance(last.get("answers"), list) else []) + [last]:
        if not isinstance(x, dict) or not re.match(r"^[0-9]{10,16}-[0-9a-f]{8}\Z", str(x.get("id") or "")):
            continue
        said = x.get("said") if isinstance(x.get("said"), list) else []
        try:
            at = float(x.get("at") or 0)
        except (TypeError, ValueError):
            at = 0.0
        out.append({"id": str(x["id"]), "ok": x.get("ok") is True, "said": [str(w)[:400] for w in said[:12]],
                    "now": str(x.get("now") or "")[:80], "at": at})
    seen, keep = set(), []
    for x in reversed(out):
        if x["id"] not in seen:
            seen.add(x["id"])
            keep.append(x)
    return list(reversed(keep))[-ANSWERS_KEPT:]


def serve(payload, ask=None):
    before = answers_before()
    try:
        if not isinstance(payload, dict):
            raise Refused("the ask is not an object")
        do = payload.get("do")
        if do == "console":
            got = console_set(payload.get("on"), payload.get("users"))
        elif do in DONE:
            got = unit_do(do, payload.get("unit"))
        else:
            raise Refused("restart, stop, start, reload or console")
    except (Refused, OSError) as e:
        got = {"ok": False, "said": ["refused: %s" % e]}
    got["answers"] = before
    return got
