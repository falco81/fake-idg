#!/usr/bin/python3 -I
"""root_sshd.py - Settings -> SSH server and notices, root's part (1.6.0; otp's sshd_do).

How the SSH server lets people in - root with a key or a password, passwords at all, the port,
the tries of a connection, who may sign in - and the notice shown before signing in over SSH
(sshd's Banner, /etc/issue.net), at the console (/etc/issue.d or /etc/issue) and after signing
in (/etc/motd.d or /etc/motd). As otp does it:

  * fake-igd's own drop-in, read before every other: /etc/ssh/sshd_config.d/00-fake-igd.conf
    (the first value sshd reads of a setting is the one it keeps), written whole each time,
    checked by `sshd -t` before it is used - put back as it was when sshd says no;
  * ON TRIAL: before the change, a timer of systemd's own (systemd-run --on-active) is armed
    that puts back what was there unless "Keep it" comes in time - also with the API down; a
    trial whose time is up and that nobody kept (the timer does not outlive a restart of the
    machine) is put back by the next ask of this module, and the API asks one each minute;
  * a port other than 22 let through SELinux (semanage) and firewalld (at once, and for good
    once kept); fake-igd's own chain FAKE-IGD-IN takes ssh_ports() (see below);
  * the notices: a file of fake-igd's own in issue.d / motd.d where agetty and pam_motd read
    those, else the one file, kept as it was beside it (.fake-igd-before) and put back when the
    notice is switched off. /etc/issue.net is always the one file.

Nothing in the payload is trusted: every value is checked again here against the one shape it
may have. Asked as {"do": "read" | "apply" | "keep" | "back", ...}:

  apply: {"conf": {manage, permit_root, password, port, tries, allow_users, notice, notice_ssh,
          notice_console, notice_motd}, "trial_min": 0..60, "hash": "..."}

Run by itself (the timer): root_sshd.py --back [why]  - puts back what a change on trial had,
and writes result-sshd.json as fake_igd_web.py would.

Every path can be pointed elsewhere for a test: FAKE_IGD_SSH_DIR, FAKE_IGD_ETC, FAKE_IGD_SSHD,
FAKE_IGD_ROOT_AUTHKEYS, FAKE_IGD_CONFIG; FAKE_IGD_NO_SERVICES=1 runs no systemctl,
systemd-run, semanage or firewall-cmd.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

SSH_DIR = os.environ.get("FAKE_IGD_SSH_DIR", "/etc/ssh")
ETC_DIR = os.environ.get("FAKE_IGD_ETC", "/etc")
SSHD_BIN = os.environ.get("FAKE_IGD_SSHD") or shutil.which("sshd") or "/usr/sbin/sshd"
ROOT_AUTH = os.environ.get("FAKE_IGD_ROOT_AUTHKEYS", "/root/.ssh/authorized_keys")
CONFIG = os.environ.get("FAKE_IGD_CONFIG", "/etc/fake-igd/config.json")
NO_SERVICES = os.environ.get("FAKE_IGD_NO_SERVICES") == "1"
DROPIN = os.path.join(SSH_DIR, "sshd_config.d", "00-fake-igd.conf")
TRIAL = os.path.join(SSH_DIR, ".fake-igd-sshd-trial.json")
STATE = os.path.join(SSH_DIR, ".fake-igd-sshd.json")
PERMIT = ("yes", "prohibit-password", "no")
NOTICE_MARK = "# written by fake-igd - Settings -> SSH server and notices\n"
USER_RE = re.compile(r"^[A-Za-z0-9._@*?-]{1,64}\Z")
HASH_RE = re.compile(r"^[0-9a-f]{8,64}\Z")
# Ports of this machine's other services: sshd could not listen there (and SELinux would have
# the port labelled for ssh, away from its own service).
TAKEN = {80: "the web server", 443: "the web server", 1900: "SSDP (fake-igd)", 9862: "fake-igd's API",
         25: "mail", 53: "DNS", 123: "the time", 161: "SNMP", 162: "SNMP", 514: "syslog",
         5353: "mDNS (avahi)", 631: "printing"}


class Refused(Exception):
    pass


# ---- files ------------------------------------------------------------------------------
def read_or(path, most=65536):
    """A plain file's text, or None - never through a link, never waiting on a FIFO."""
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
    """Written whole, beside and renamed in; never through a link."""
    folder = os.path.dirname(path)
    if os.path.islink(path) or os.path.islink(folder):
        raise Refused("%s is a link - put the file itself there" % path)
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


def drop(path):
    try:
        if not os.path.islink(path):
            os.unlink(path)
    except FileNotFoundError:
        pass


def read_json(path):
    try:
        got = json.loads(read_or(path) or "{}")
    except ValueError:
        return {}
    return got if isinstance(got, dict) else {}


def config_port(key, default):
    try:
        with open(CONFIG, encoding="utf-8") as f:
            v = int(json.load(f).get(key) or default)
        return v if 0 < v < 65536 else default
    except (OSError, ValueError, TypeError, AttributeError):
        return default


# ---- what sshd makes of it -------------------------------------------------------------
def conf_path():
    return os.path.join(SSH_DIR, "sshd_config")


def reads_dropins():
    """Whether sshd_config takes sshd_config.d (OpenSSH 8.2 on; EL9's does)."""
    text = read_or(conf_path()) or ""
    return bool(re.search(r"(?im)^\s*Include\s+\S*sshd_config\.d/\*\.conf", text))


def values():
    if not os.path.exists(SSHD_BIN):
        return {}
    try:
        got = subprocess.run([SSHD_BIN, "-T", "-f", conf_path(), "-C", "user=root,host=localhost,addr=127.0.0.1"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_values(got.stdout)


def parse_values(text):
    said = {}
    for ln in text.splitlines():
        k, _, v = ln.partition(" ")
        if k in ("port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "allowusers",
                 "banner", "kbdinteractiveauthentication", "maxauthtries", "listenaddress"):
            said[k] = v.strip() if k not in said else said[k] + " " + v.strip()
    return said


def key_blob_ok(line):
    """A public key line whose blob is what it says it is (no ssh-keygen needed)."""
    m = re.match(r"^(?:.*? )?((?:ssh|ecdsa|sk)-[a-z0-9@.-]+) ([A-Za-z0-9+/]{40,16000}={0,3})(?: .*)?$", line)
    if not m:
        return False
    try:
        blob = base64.b64decode(m.group(2), validate=True)
        n = struct.unpack(">I", blob[:4])[0]
        return blob[4:4 + n].decode("ascii", "replace") == m.group(1)
    except (ValueError, struct.error):
        return False


def root_keys():
    text = read_or(ROOT_AUTH, 1 << 20) or ""
    return len([ln for ln in text.split("\n") if ln.strip() and not ln.strip().startswith("#")
                and key_blob_ok(ln.strip())])


def selinux():
    if not shutil.which("getenforce"):
        return ""
    try:
        return subprocess.run(["getenforce"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              universal_newlines=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---- the wish, checked again --------------------------------------------------------------
def checked(c):
    if not isinstance(c, dict):
        raise Refused("the request is not an object")
    out = {"manage": c.get("manage") is True}
    permit = str(c.get("permit_root") or "prohibit-password")
    if permit not in PERMIT:
        raise Refused("root signs in with: yes, prohibit-password or no")
    out["permit_root"] = permit
    out["password"] = c.get("password") is True
    try:
        port = int(c.get("port") or 22)
    except (TypeError, ValueError):
        raise Refused("the port is a number")
    if not 1 <= port <= 65535:
        raise Refused("the port is 1 to 65535")
    taken = dict(TAKEN)
    taken[config_port("http_port", 5000)] = "fake-igd's description and SOAP"
    taken[config_port("api_port", 9862)] = "fake-igd's API"
    if port in taken and port != 22:
        raise Refused("port %d is %s's - choose another for SSH" % (port, taken[port]))
    out["port"] = port
    raw = c.get("allow_users") or []
    users = [str(u) for u in raw if u] if isinstance(raw, list) else [u for u in re.split(r"[\s,]+", str(raw)) if u]
    for u in users:
        if not USER_RE.match(u):
            raise Refused("%r is not a user name" % u[:40])
    out["allow_users"] = users[:50]
    try:
        out["tries"] = max(1, min(10, int(c.get("tries") or 4)))
    except (TypeError, ValueError):
        out["tries"] = 4
    text = str(c.get("notice") or "").replace("\r\n", "\n")
    if len(text) > 4000:
        raise Refused("the notice is 4000 characters at most")
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", text):
        raise Refused("no control characters in the notice")
    out["notice"] = text
    for k in ("notice_ssh", "notice_console", "notice_motd"):
        out[k] = c.get(k) is True and bool(text.strip())
    out["notice_ssh"] = out["notice_ssh"] and out["manage"]
    return out


def dropin_text(c):
    lines = ["# fake-igd - Settings -> SSH server and notices. Changed there, not here: this",
             "# file is written whole each time.",
             "Port %d" % c["port"],
             "PermitRootLogin %s" % c["permit_root"],
             "PasswordAuthentication %s" % ("yes" if c["password"] else "no"),
             "KbdInteractiveAuthentication %s" % ("yes" if c["password"] else "no"),
             "PubkeyAuthentication yes",
             "MaxAuthTries %d" % c["tries"]]
    if c["allow_users"]:
        lines.append("AllowUsers %s" % " ".join(c["allow_users"]))
    lines.append("Banner %s" % (notice_paths()["banner"] if c["notice_ssh"] else "none"))
    return "\n".join(lines) + "\n"


# ---- the notices --------------------------------------------------------------------------
def notice_paths():
    issue_d = os.path.join(ETC_DIR, "issue.d")
    motd_d = os.path.join(ETC_DIR, "motd.d")
    return {"issue": os.path.join(issue_d, "fake-igd.issue") if os.path.isdir(issue_d)
            else os.path.join(ETC_DIR, "issue"),
            "motd": os.path.join(motd_d, "fake-igd") if os.path.isdir(motd_d) else os.path.join(ETC_DIR, "motd"),
            "banner": os.path.join(ETC_DIR, "issue.net")}


def whole(path):
    return os.path.basename(path) in ("issue", "motd", "issue.net")


def notice_set(where, text):
    """The notice put in at `where` (issue, motd, banner), or taken out (text None). A whole file
    of the system's is kept beside it as it was (.fake-igd-before), or a mark that there was none
    (.fake-igd-none), and put back when the notice goes."""
    path = notice_paths()[where]
    keep, none = path + ".fake-igd-before", path + ".fake-igd-none"
    if text is None:
        if not whole(path):
            drop(path)
            return
        had = read_or(keep)
        cur = read_or(path)
        ours = where == "banner" or (cur or "").startswith(NOTICE_MARK.strip())
        if had is not None:
            if ours:
                put_file(path, had)
            drop(keep)
        elif os.path.exists(none):
            if ours:
                drop(path)
            drop(none)
        return
    if whole(path) and read_or(keep) is None and not os.path.exists(none):
        cur = read_or(path)
        if cur is None:
            put_file(none, "", 0o600)
        elif not cur.startswith(NOTICE_MARK.strip()):
            put_file(keep, cur)
    body = text.rstrip() + "\n"
    if where == "issue":
        body = body.replace("\\", "\\\\") + "\n"       # agetty reads \ escapes
    # The banner is shown as it is, before every sign-in: no mark of ours in it - it is known as
    # ours by what is kept beside it.
    put_file(path, body if where == "banner" else (NOTICE_MARK if whole(path) else "") + body)


def notice_now(where):
    """The words of fake-igd's notice there now, or None."""
    path = notice_paths()[where]
    cur = read_or(path)
    if cur is None:
        return None
    if where == "banner":
        return cur if read_or(path + ".fake-igd-before") is not None or os.path.exists(path + ".fake-igd-none") \
            else None
    if whole(path):
        return cur.split("\n", 1)[1] if cur.startswith(NOTICE_MARK.strip()) else None
    return cur


# ---- services -------------------------------------------------------------------------------
def reload_sshd():
    if NO_SERVICES:
        return
    err = ""
    for unit in ("sshd", "ssh"):
        got = subprocess.run(["systemctl", "reload-or-restart", unit], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, universal_newlines=True)
        if got.returncode == 0:
            return
        err = (got.stderr or "").strip()
    raise Refused("sshd could not be reloaded: %s" % err[-200:])


def selinux_port(port):
    """A port other than 22 let through by SELinux, where it is enforcing."""
    if port == 22 or NO_SERVICES or selinux() != "Enforcing":
        return ""
    if not shutil.which("semanage"):
        raise Refused("SELinux keeps sshd to port 22 and semanage is not on this machine "
                      "(dnf install policycoreutils-python-utils)")
    got = subprocess.run(["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", str(port)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if got.returncode != 0:
        got = subprocess.run(["semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", str(port)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if got.returncode != 0:
            raise Refused("semanage: %s" % (got.stderr or got.stdout).strip()[-200:])
    return "SELinux lets sshd use port %d" % port


def firewalld_port(port, permanent=False):
    """firewalld, where it runs: the port let in (at once; for good once kept)."""
    if port == 22 or NO_SERVICES or not shutil.which("firewall-cmd"):
        return ""
    if subprocess.run(["firewall-cmd", "--state"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        return ""
    argv = ["firewall-cmd"] + (["--permanent"] if permanent else []) + ["--add-port=%d/tcp" % port]
    got = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if got.returncode != 0:
        return "firewalld did not let port %d in: %s" % (port, got.stdout.strip()[-150:])
    return "firewalld lets port %d in%s" % (port, " for good" if permanent else "")


def ssh_ports():
    """The SSH ports a firewall should let in now: the one sshd has, and while a change is on
    trial the one before it too. For fake_igd_web.chain_rules (FAKE-IGD-IN)."""
    ports = set()
    v = values()
    for one in str(v.get("port") or "").replace(",", " ").split():
        if one.isdigit() and 0 < int(one) < 65536:
            ports.add(int(one))
    m = re.search(r"(?m)^Port\s+(\d+)", read_or(DROPIN) or "")
    if m:
        ports.add(int(m.group(1)))
    t = read_json(TRIAL)
    try:
        if t.get("before_port"):
            ports.add(int(t["before_port"]))
    except (TypeError, ValueError):
        pass
    return sorted(p for p in ports if 0 < p < 65536) or [22]


def firewall_again():
    """FAKE-IGD-IN put in again with the ports of now - where fake_igd_web takes them."""
    if NO_SERVICES:
        return ""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        import fake_igd_web as W
        if not getattr(W, "SSH_PORTS_FROM_SSHD", False):
            return ""
        cfg = W.read_config()
        if not cfg.get("firewall"):
            return ""
        W.firewall(cfg)
        return "firewall: FAKE-IGD-IN lets SSH in on %s" % ", ".join(str(p) for p in ssh_ports())
    except Exception as e:                              # noqa: BLE001 - said, the change stays
        return "firewall: not put in again (%s)" % str(e)[:120]


# ---- on trial ---------------------------------------------------------------------------
def arm(seconds, ident):
    """The timer that puts it back: systemd's own, not this helper's."""
    if NO_SERVICES or not seconds:
        return ""
    unit = "fake-igd-sshd-back-%s" % ident
    me = os.path.abspath(__file__)
    got = subprocess.run(["systemd-run", "--on-active=%ds" % int(seconds), "--unit", unit,
                          "/usr/bin/python3", "-I", me, "--back"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if got.returncode != 0:
        raise Refused("systemd-run could not arm the timer that puts it back: %s" % got.stdout.strip()[-200:])
    return unit


def disarm(t):
    unit = str((t or {}).get("unit") or "")
    if unit and re.match(r"^fake-igd-sshd-back-[A-Za-z0-9]{1,16}\Z", unit) and not NO_SERVICES:
        subprocess.run(["systemctl", "stop", unit + ".timer"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def state_set(**kw):
    s = read_json(STATE)
    s.update(kw)
    put_file(STATE, json.dumps(s), 0o600)


def put_back(why="not kept in time"):
    """What was there before the change on trial, back."""
    t = read_json(TRIAL)
    if not t:
        return False
    if t.get("dropin") is None:
        drop(DROPIN)
    else:
        put_file(DROPIN, t["dropin"], 0o600)
    for where in ("issue", "motd", "banner"):
        notice_set(where, None)
        if t.get(where) is not None:
            text = t[where]
            if where == "issue":
                text = text.rstrip("\n").replace("\\\\", "\\")
            notice_set(where, text)
    try:
        reload_sshd()
    except Refused:
        pass
    drop(TRIAL)
    state_set(hash="", back_hash=str(t.get("hash") or "")[:64], back_at=time.time(), back_why=why[:200])
    firewall_again()
    return True


def overdue():
    """A change on trial whose time is up and that nobody kept: put back (its timer does not
    outlive a restart of the machine - and one locked out by the change restarts it)."""
    t = read_json(TRIAL)
    try:
        until = float(t.get("until") or 0)
    except (TypeError, ValueError):
        until = 0
    if until and time.time() > until + 30:
        return put_back("not kept in time (its timer did not outlive a restart)")
    return False


def apply_files(c, now_dropin):
    said = []
    if c["manage"]:
        if c["notice_ssh"]:
            notice_set("banner", c["notice"])
        put_file(DROPIN, dropin_text(c), 0o600)
        if os.path.exists(SSHD_BIN):
            got = subprocess.run([SSHD_BIN, "-t", "-f", conf_path()], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, universal_newlines=True)
            if got.returncode != 0:
                if now_dropin is None:
                    drop(DROPIN)
                else:
                    put_file(DROPIN, now_dropin, 0o600)
                raise Refused("sshd does not take it, so it is as it was: %s"
                              % (got.stderr or got.stdout).strip()[-300:])
            said.append("sshd -t: the file is good")
        else:
            raise Refused("sshd is not on this machine (%s)" % SSHD_BIN)
        s = selinux_port(c["port"])
        if s:
            said.append(s)
        s = firewalld_port(c["port"])
        if s:
            said.append(s)
    else:
        if os.path.exists(DROPIN):
            drop(DROPIN)
            said.append("fake-igd's drop-in taken away: sshd as the system has it")
    if not (c["manage"] and c["notice_ssh"]):
        notice_set("banner", None)
    notice_set("issue", c["notice"] if c["notice_console"] else None)
    notice_set("motd", c["notice"] if c["notice_motd"] else None)
    reload_sshd()
    said.append("sshd reloaded")
    return said


def apply(r):
    c = checked(r.get("conf"))
    try:
        trial = max(0, min(60, int(r.get("trial_min") or 0)))
    except (TypeError, ValueError):
        trial = 0
    h = str(r.get("hash") or "")
    if h and not HASH_RE.match(h):
        raise Refused("that is not the mark of a change")
    keys = root_keys()
    if c["manage"]:
        if not reads_dropins():
            raise Refused("this sshd does not read sshd_config.d (an Include taken out of %s) - set it there "
                          "by hand" % conf_path())
        if c["permit_root"] != "no" and not c["password"] and not keys:
            raise Refused("root has no SSH key here, and passwords would be off: nobody would reach this "
                          "machine as root over SSH - add a key first")
        if c["permit_root"] == "prohibit-password" and not keys:
            raise Refused("root may sign in only with a key and has none here - add a key first")
    old = read_json(TRIAL)
    now_dropin = read_or(DROPIN)
    paths = notice_paths()
    before = old or {"dropin": now_dropin, "issue": notice_now("issue"), "motd": notice_now("motd"),
                     "banner": notice_now("banner"),
                     "before_port": next((int(p) for p in str(values().get("port") or "22").split()
                                          if p.isdigit()), 22)}
    # Every file as it is now, put back on any failure.
    entry = {p + x: read_or(p + x) for p in (paths["banner"], paths["issue"], paths["motd"])
             for x in ("", ".fake-igd-before", ".fake-igd-none")}
    entry[DROPIN] = now_dropin
    ident = (re.sub(r"[^A-Za-z0-9]", "", h)[:6] or "x") + "%x" % int(time.time())
    new_unit = ""
    on_trial = bool(trial and c["manage"])
    try:
        # The timer that puts it back armed first: armed after the change, a timer that could
        # not be made would leave the change in with nothing to undo it.
        if on_trial:
            new_unit = arm(trial * 60, ident)
            put_file(TRIAL, json.dumps(dict(before, hash=h, until=time.time() + trial * 60,
                                            unit=new_unit)), 0o600)
        said = apply_files(c, now_dropin)
    except BaseException:
        for p, was in entry.items():
            try:
                if was is None:
                    drop(p)
                else:
                    put_file(p, was, 0o600 if p == DROPIN else 0o644)
            except Exception:                           # noqa: BLE001
                pass
        try:
            reload_sshd()
        except Exception:                               # noqa: BLE001
            pass
        if new_unit:
            disarm({"unit": new_unit})
        try:
            if old:
                put_file(TRIAL, json.dumps(old), 0o600)
            else:
                drop(TRIAL)
        except Exception:                               # noqa: BLE001
            pass
        raise
    if not on_trial:
        if old:
            disarm(old)
        drop(TRIAL)
    elif old and old.get("unit") and old.get("unit") != new_unit:
        disarm(old)
    state_set(hash=h, applied_at=time.time(), failed="", error="")
    if on_trial:
        said.append("on trial for %d min: unless kept, put back by itself" % trial)
    fw = firewall_again()
    if fw:
        said.append(fw)
    return said


def keep():
    t = read_json(TRIAL)
    if not t:
        return ["nothing was on trial"]
    disarm(t)
    drop(TRIAL)
    state_set(kept_at=time.time())
    said = ["kept"]
    m = re.search(r"(?m)^Port\s+(\d+)", read_or(DROPIN) or "")
    if m:
        s = firewalld_port(int(m.group(1)), permanent=True)
        if s:
            said.append(s)
    fw = firewall_again()
    if fw:
        said.append(fw)
    return said


def facts():
    t = read_json(TRIAL)
    s = read_json(STATE)
    return {"values": values(), "there": os.path.exists(SSHD_BIN), "dropins": reads_dropins(),
            "dropin": read_or(DROPIN), "keys": root_keys(), "paths": notice_paths(),
            "trial": {"hash": t.get("hash"), "until": t.get("until"), "before_port": t.get("before_port")} if t else {},
            "hash": s.get("hash") or "", "back_hash": s.get("back_hash") or "", "back_at": s.get("back_at"),
            "back_why": s.get("back_why") or "", "failed": s.get("failed") or "", "error": s.get("error") or "",
            "selinux": selinux(), "ports": ssh_ports(), "read_at": time.time()}


def serve(payload, ask=None):
    try:
        overdue()
    except Exception:                                   # noqa: BLE001 - said by the read below
        pass
    do = str((payload or {}).get("do") or "read")
    said, ok = [], True
    try:
        if do == "apply":
            said = apply(payload)
        elif do == "keep":
            said = keep()
        elif do == "back":
            said = ["put back" if put_back(str(payload.get("why") or "asked to go back")[:120])
                    else "nothing was on trial"]
        elif do != "read":
            raise Refused("read, apply, keep or back")
    except Refused as e:
        ok, said = False, [str(e)[:400]]
    except (OSError, subprocess.SubprocessError) as e:
        ok, said = False, ["it went wrong: %s" % str(e)[:300]]
    if not ok and do == "apply":
        h = str(payload.get("hash") or "")
        state_set(failed=h if HASH_RE.match(h) else "", error=said[0])
    out = facts()
    out.update(ok=ok, said=said, do=do, asked_hash=str(payload.get("hash") or "")[:64] if do == "apply" else "")
    return out


def main(argv):
    if argv[:1] == ["--back"]:
        if os.geteuid() != 0 and not os.environ.get("FAKE_IGD_SSH_DIR"):
            print("root_sshd.py: run as root")
            return 1
        why = " ".join(argv[1:])[:120] or "not kept in time"
        got = serve({"do": "back", "why": why})
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            if here not in sys.path:
                sys.path.insert(0, here)
            import fake_igd_web as W
            got["by"] = "the timer"
            W.write_kind_result("sshd", got)
        except Exception as e:                          # noqa: BLE001
            print("root_sshd.py: the result not written: %s" % e)
        print(json.dumps(got, indent=1, default=str))
        return 0
    if argv[:1] == ["--ports"]:
        print(" ".join(str(p) for p in ssh_ports()))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
