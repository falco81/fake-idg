#!/usr/bin/python3 -I
"""root_osup.py - Settings → System updates, root's side (1.6.0), as otp's osup part.

Asked through the queue of root's asks (fake_igd_web.py: serve(payload, ask)):

  {"do": "check"}                          dnf check-update, dnf updateinfo --security, needs-restarting -r
  {"do": "upgrade", "security": bool}      dnf -y upgrade [--security], then needs-restarting -r
  {"do": "reboot"}                         the machine restarted, in a few seconds
  {"proxy": "http://…", "proxy_no": "…"}   with check/upgrade: dnf goes through the proxy (Settings → Proxy)

The work itself - minutes of dnf - runs as a unit of its own (systemd-run), so the queue
is free meanwhile; this same file is that unit (--job ID KIND [security]). Its progress
and its last 400 lines go into /var/lib/fake-igd/web/osup.json (root's, group fake-igd,
0640) about every second; the API reads it and the page follows it. One at a time: a lock
in /run. The proxy is handed over in a file of root's alone (0600), never on a command line.
Nothing of the payload is trusted: every value is checked against the one shape it may have.

Overridable for tests: FAKE_IGD_STATE, FAKE_IGD_DNF (a fake dnf), FAKE_IGD_OSUP_LOCK,
FAKE_IGD_OSUP_PROXY, FAKE_IGD_NO_SYSTEMD=1 (a process of its own instead of systemd-run),
FAKE_IGD_NO_REBOOT=1 (the restart only said).
Python 3.9, the standard library only.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

STATE_DIR = os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd")
WEB_DIR = os.path.join(STATE_DIR, "web")
OSUP_FILE = "osup.json"
LOCK = os.environ.get("FAKE_IGD_OSUP_LOCK", "/run/fake-igd-osup.lock")
PROXY_FILE = os.environ.get("FAKE_IGD_OSUP_PROXY", "/run/fake-igd-osup-proxy.json")
DNF = os.environ.get("FAKE_IGD_DNF", "dnf")
NO_SYSTEMD = bool(os.environ.get("FAKE_IGD_NO_SYSTEMD"))
NO_REBOOT = bool(os.environ.get("FAKE_IGD_NO_REBOOT"))
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# The packages a restart is needed for once they are updated (as otp's REBOOT_PKGS, dnf's
# needs-restarting -r list).
REBOOT_PKGS = {"kernel", "kernel-core", "kernel-rt", "kernel-rt-core", "kernel-modules", "kernel-modules-core",
               "kernel-uek", "glibc", "linux-firmware", "systemd", "dbus", "dbus-broker", "dbus-daemon",
               "microcode_ctl", "zlib", "zlib-ng-compat", "openssl-libs", "gnutls"}
ARCH_RE = re.compile(r"\.(x86_64|aarch64|noarch|i686|ppc64le|s390x|src)$")


class Refused(Exception):
    pass


# ---- writing beside the API without following its links -------------------------------------
def write_here(name, text):
    """WEB_DIR/name, written as a new file and renamed - never through a link the API could lay."""
    dfd = os.open(WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        tmp = ".%s.%d" % (name, os.getpid())
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            try:   # on the open file, never by name in a folder the API owns
                import grp
                os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
            except (KeyError, OSError):
                pass
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


def dnf_there():
    if os.sep in DNF:
        return os.path.isfile(DNF) and os.access(DNF, os.X_OK)
    return bool(shutil.which(DNF, path=PATH))


def running():
    import fcntl
    try:
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def proxy_keep(payload):
    url = str(payload.get("proxy") or "").strip()
    if url and not re.match(r"^http://[^\s@/]*@?[A-Za-z0-9.\-\[\]:]+(?::\d{1,5})?/?\Z", url):
        raise Refused("the proxy is not an http:// address")
    no = ",".join(w for w in re.split(r"[\s,;]+", re.sub(r"[^A-Za-z0-9.*:/\[\],;\s_-]", "",
                                                          str(payload.get("proxy_no") or ""))) if w)
    if not url:
        try:
            os.unlink(PROXY_FILE)
        except OSError:
            pass
        return
    fd = os.open(PROXY_FILE + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps({"url": url, "no": no}))
    os.replace(PROXY_FILE + ".new", PROXY_FILE)


def proxy_env(env):
    try:
        with open(PROXY_FILE, encoding="utf-8") as f:
            got = json.load(f)
    except (OSError, ValueError):
        got = {}
    if isinstance(got, dict) and got.get("url"):
        for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            env[k] = got["url"]
        if got.get("no"):
            env["no_proxy"] = env["NO_PROXY"] = got["no"]
    return env


def launch(ident, kind, security):
    if running():
        raise Refused("an update or a look for updates is going on already")
    if not dnf_there():
        raise Refused("dnf is not on this machine")
    me = os.path.abspath(__file__)
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
    argv = [py, "-I", me, "--job", ident, kind] + (["security"] if security else [])
    if not NO_SYSTEMD and shutil.which("systemd-run", path=PATH) and os.path.isdir("/run/systemd/system"):
        got = subprocess.run(["systemd-run", "--unit", "fake-igd-os-%s-%s" % (kind, ident[:12]), "--collect",
                              "--quiet", "--property", "TimeoutStopSec=30min"] + argv,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        if got.returncode != 0:
            raise Refused("systemd-run: %s" % (got.stderr or got.stdout).strip()[-200:])
        return
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True, close_fds=True)


def reboot():
    if NO_REBOOT:
        return "the restart is only said (FAKE_IGD_NO_REBOOT)"
    if shutil.which("systemd-run", path=PATH) and os.path.isdir("/run/systemd/system"):
        got = subprocess.run(["systemd-run", "--unit", "fake-igd-reboot", "--collect", "--quiet",
                              "--on-active=5", "/usr/bin/systemctl", "reboot"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        if got.returncode != 0:
            raise Refused("systemd-run: %s" % (got.stderr or got.stdout).strip()[-200:])
        return "the machine restarts in 5 seconds"
    got = subprocess.run(["shutdown", "-r", "+1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         universal_newlines=True, timeout=30)
    if got.returncode != 0:
        raise Refused("shutdown: %s" % (got.stderr or got.stdout).strip()[-200:])
    return "the machine restarts in a minute"


def serve(payload, ask):
    """One ask of the pages, answered at once - the work itself runs on by itself."""
    if not isinstance(payload, dict):
        return {"ok": False, "said": ["the request is not an object"]}
    do = payload.get("do")
    if do not in ("check", "upgrade", "reboot", "stop"):
        return {"ok": False, "said": ["check, upgrade, reboot or stop - not %r" % str(do)[:40]]}
    if do == "stop":
        try:
            return {"ok": True, "do": do, "said": [stop(str((ask or {}).get("by") or ""))]}
        except Refused as e:
            return {"ok": False, "do": do, "said": [str(e)[:400]]}
    ident = re.sub(r"[^A-Za-z0-9-]", "", str((ask or {}).get("id") or ""))[:40] or "%d" % int(time.time())
    try:
        if do == "reboot":
            if running():
                raise Refused("an update is going on - the restart waits until it has ended")
            said = reboot()
            return {"ok": True, "said": [said], "do": do}
        proxy_keep(payload)
        security = payload.get("security") is True and do == "upgrade"
        launch(ident, do, security)
        return {"ok": True, "do": do, "job": ident, "security": security,
                "said": ["dnf %s started%s%s" % ("check-update" if do == "check" else "upgrade",
                                                 " (security updates only)" if security else "",
                                                 " through the proxy" if payload.get("proxy") else "")]}
    except Refused as e:
        return {"ok": False, "do": do, "said": [str(e)[:400]]}


def stop(by=""):
    """Stop it (otp's): the job asked to end - dnf stopped while it asks and downloads; once it puts the
    packages in, it finishes (stopped there the system would be left half updated - otp lets the node
    being updated finish too)."""
    try:
        with open(os.path.join(WEB_DIR, OSUP_FILE), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    if st.get("state") != "running" or not running():
        raise Refused("nothing is going on")
    if st.get("phase") == "whether a restart is needed":
        raise Refused("the packages are in already - it only asks whether a restart is needed")
    if st.get("phase") == "putting the packages in":
        raise Refused("dnf is putting the packages in - stopped now, the system would be left half updated; "
                      "it ends by itself in a few minutes")
    pid = int(st.get("pid") or 0)
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            cmd = f.read().split(b"\0")
    except OSError:
        raise Refused("the job is not found")
    if b"--job" not in cmd or not any(c.endswith(b"root_osup.py") for c in cmd):
        raise Refused("the job is not found")
    with open(os.path.join(WEB_DIR, "osup.stop"), "w") as f:
        f.write(json.dumps({"by": by[:80], "at": time.time()}))
    os.kill(pid, signal.SIGTERM)
    return "dnf is asked to stop - nothing more is put in"


# ---- what dnf says, read -----------------------------------------------------------------
def parse_check_update(lines):
    """`dnf -q check-update` → ['name.arch version', …] (the obsoleting section's indented lines left out)."""
    out = []
    for ln in lines:
        parts = ln.split()
        if ln.startswith((" ", "\t")) or len(parts) < 3 or "." not in parts[0]:
            continue
        if parts[0].lower().startswith(("last", "obsoleting", "security:")):
            continue
        out.append("%s %s" % (parts[0], parts[1]))
    return out


def reboot_for(packages):
    out = []
    for p in packages:
        name = str(p).split()[0] if str(p).split() else ""
        name = ARCH_RE.sub("", name)
        if name in REBOOT_PKGS or name.startswith("kernel-core-"):
            out.append(name)
    return sorted(set(out))


def job(ident, kind, security=False):
    """The work itself, as root, in a process of its own."""
    import fcntl
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 1
    state = {"id": ident, "kind": kind, "state": "running", "pct": 1, "lines": [], "began": time.time(), "pid": os.getpid(),
             "at": time.time(), "packages": [], "reboot": False, "pm": "dnf", "phase": "starting",
             "security_only": bool(security)}
    last = [0.0]

    def put(force=False):
        state["at"] = time.time()
        if force or time.time() - last[0] > 0.8:
            last[0] = time.time()
            state["lines"] = state["lines"][-400:]
            try:
                write_here(OSUP_FILE, json.dumps(state))
            except OSError:
                pass

    def say(line):
        line = line.rstrip()
        if line:
            state["lines"].append(line[:300])
        put()

    env = proxy_env({"PATH": PATH, "LANG": "C", "LC_ALL": "C", "HOME": "/root"})

    child = {"p": None, "stopped": False}

    def on_term(signum, frame):
        """Stop it: dnf ended as Ctrl-C ends it (it leaves nothing half done before the transaction)."""
        child["stopped"] = True
        if child["p"] is not None and child["p"].poll() is None:
            try:
                child["p"].send_signal(signal.SIGINT)
            except OSError:
                pass
    signal.signal(signal.SIGTERM, on_term)
    try:
        os.unlink(os.path.join(WEB_DIR, "osup.stop"))
    except OSError:
        pass

    def stream(cmd, on_line=None, ok=(0,)):
        if child["stopped"]:
            raise Refused("stopped")
        say("$ " + " ".join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                             stdin=subprocess.DEVNULL, universal_newlines=True, bufsize=1)
        child["p"] = p
        try:
            for ln in p.stdout:
                say(ln)
                if on_line:
                    on_line(ln)
        finally:
            try:
                for _ in p.stdout:
                    pass
            except Exception:                           # noqa: BLE001
                pass
            rc = p.wait()
        child["p"] = None
        if child["stopped"]:
            raise Refused("stopped")
        if rc not in ok:
            raise Refused("%s ended with %d" % (os.path.basename(cmd[0]), rc))
        return rc

    def needs_restart():
        nr = subprocess.run([DNF, "needs-restarting", "-r"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            universal_newlines=True, env=env, timeout=300)
        lines = [x.strip() for x in nr.stdout.splitlines() if x.strip()]
        if nr.returncode == 1:
            why = [x.lstrip("* ").strip() for x in lines if x.startswith("*")]
            say("needs-restarting -r: a restart is needed" + (" (%s)" % ", ".join(why) if why else ""))
            state["reboot_why_now"] = why
            return True
        say("needs-restarting -r: " + (lines[0] if lines else "no restart is needed"))
        return False

    try:
        put(True)
        if kind == "check":
            state["phase"] = "asking for what is new"
            got = []
            stream([DNF, "-q", "--refresh", "check-update"], got.append, ok=(0, 100))
            pk = parse_check_update(got)
            state["packages"] = pk[:1000]
            state["count"] = len(pk)
            state["phase"] = "the security updates"
            sec = subprocess.run([DNF, "-q", "updateinfo", "list", "--security"], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, universal_newlines=True, env=env, timeout=300)
            state["security"] = len([x for x in sec.stdout.splitlines() if x.strip()])
            say("%d update(s) waiting, %d of them security" % (len(pk), state["security"]))
            state["phase"] = "whether a restart is needed"
            state["reboot_why"] = reboot_for(pk)
            state["reboot_after"] = bool(state["reboot_why"])
            try:
                state["reboot_now"] = needs_restart()
            except (OSError, subprocess.SubprocessError):
                state["reboot_now"] = False
            if state["reboot_why"]:
                say("a restart will be needed after the update: %s" % ", ".join(state["reboot_why"]))
            state["pct"] = 100
        else:
            seen = {"total": 0, "done": 0}

            def count(ln):
                m = re.search(r"\b(\d+)/(\d+)\s*$", ln)
                if m and re.search(r"(Upgrading|Installing|Cleanup|Verifying|Running scriptlet|Erasing|Reinstalling|"
                                   r"Downgrading|Obsoleting)\s*:", ln):
                    seen["total"] = max(seen["total"], int(m.group(2)) * 2)
                    seen["done"] = min(seen["total"], seen["done"] + 1)
                    state["phase"] = "putting the packages in"
                if ln.startswith("Running transaction") or ln.startswith("Transaction test"):
                    state["phase"] = "putting the packages in"
                if ln.startswith("Downloading Packages"):
                    state["phase"] = "downloading"
                    state["pct"] = max(state["pct"], 8)
                if seen["total"]:
                    state["pct"] = max(state["pct"], min(97, 10 + int(87 * seen["done"] / seen["total"])))
            state["phase"] = "asking for what is new"
            stream([DNF, "-y", "--refresh", "upgrade"] + (["--security"] if security else []), count)
            state["phase"] = "whether a restart is needed"
            state["reboot"] = needs_restart()
            state["pct"] = 100
        state["state"] = "done"
        state["phase"] = "done"
    except Refused as e:
        if child["stopped"]:
            who = ""
            try:
                with open(os.path.join(WEB_DIR, "osup.stop"), encoding="utf-8") as f:
                    who = str(json.load(f).get("by") or "")
            except (OSError, ValueError):
                pass
            state.update(state="stopped", said="stopped" + (" by " + who if who else "") + " - nothing more was put in")
            say(state["said"])
        else:
            state.update(state="failed", said=str(e)[:300])
    except Exception as e:                              # noqa: BLE001
        state.update(state="failed", said="it broke: %s" % str(e)[:300])
    finally:
        put(True)
        os.close(fd)
    return 0


def main(argv):
    if len(argv) >= 4 and argv[1] == "--job":
        if os.geteuid() != 0 and not os.environ.get("FAKE_IGD_STATE"):
            sys.stderr.write("root only\n")
            return 1
        kind = argv[3]
        if kind not in ("check", "upgrade"):
            return 2
        return job(re.sub(r"[^A-Za-z0-9-]", "", argv[2])[:40], kind, len(argv) > 4 and argv[4] == "security")
    sys.stderr.write("root_osup.py is asked through fake_igd_web.py (the queue of root's asks)\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
