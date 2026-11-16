#!/usr/bin/python3 -I
"""root_time.py - what root does for Settings → Time (1.6.0), otp's ntp_* of otp_web.py.

  {"do": "apply", "manage", "servers": [{host, pool, iburst, prefer, nts}], "makestep": [s, n],
   "minsources", "allow": [...], "timezone"}
        chrony's time servers: in /etc/chrony.conf the file's own server, pool, peer, sourcedir,
        makestep, allow and minsources lines are commented out (#fake-igd# …) and fake-igd's lines
        go between two marks at its end; the file as it was is kept as chrony.conf.fake-igd-before.
        Checked by chronyd -p before chronyd is restarted; a chronyd that does not start on it
        gets the file as it was back. manage false: the marked lines go, the file's own come
        back. The time zone with timedatectl set-timezone.
  {"do": "sync"}   the clock stepped to the time servers now (chronyc makestep), then a burst.

Nothing in the payload is trusted: each value checked against the one shape it may have.
Paths and commands overridable for tests (FAKE_IGD_CHRONY_CONF, FAKE_IGD_CHRONYC, …).
"""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

CHRONYC = os.environ.get("FAKE_IGD_CHRONYC", "chronyc")
CHRONYD = os.environ.get("FAKE_IGD_CHRONYD", "chronyd")
TIMEDATECTL = os.environ.get("FAKE_IGD_TIMEDATECTL", "timedatectl")
SYSTEMCTL = os.environ.get("FAKE_IGD_SYSTEMCTL", "systemctl")
CHRONY_CONF = os.environ.get("FAKE_IGD_CHRONY_CONF") or next(
    (p for p in ("/etc/chrony.conf", "/etc/chrony/chrony.conf") if os.path.isfile(p)), "/etc/chrony.conf")
NO_SERVICES = bool(os.environ.get("FAKE_IGD_NO_SERVICES"))
BEGIN = "# ---- fake-igd: the time servers, set on its pages (Settings - Time) ----"
END = "# ---- fake-igd: end ----"
OFF = "#fake-igd# "
KEYS = ("server", "pool", "peer", "makestep", "allow", "minsources", "maxdistance", "sourcedir")
ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z")
NAME_RE = re.compile(r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
TZ_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]{0,39}(/[A-Za-z0-9_+-]{1,40}){0,3}\Z")


class Refused(Exception):
    pass


def run(cmd, what, ok=(0,), timeout=60):
    try:
        got = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=timeout)
    except FileNotFoundError:
        raise Refused("%s: %s is not on this machine" % (what, cmd[0]))
    except subprocess.TimeoutExpired:
        raise Refused("%s: no answer in %d s" % (what, timeout))
    if got.returncode not in ok:
        raise Refused("%s: %s" % (what, (got.stderr or got.stdout).strip()[-300:] or
                                  "ended with %d" % got.returncode))
    return got.stdout


def plain(text, how):
    text = str(text or "").strip()
    if not ADDR_RE.match(text):
        raise ValueError("not a plain address")
    got = {"address": ipaddress.ip_address,
           "network": lambda t: ipaddress.ip_network(t, strict=False)}[how](text)
    if "%" in str(got):
        raise ValueError("a scope id is not taken")
    return got


def write_root(path, text, mode):
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fake-igd-", dir=folder)
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


def checked(r):
    """otp's ntp_checked, without the other node."""
    out = {"manage": r.get("manage") is True, "servers": [], "allow": [],
           "makestep": [1.0, 3], "minsources": 1, "timezone": ""}
    servers = r.get("servers") if isinstance(r.get("servers"), list) else []
    for x in servers[:12]:
        if not isinstance(x, dict):
            raise Refused("a server is an object")
        host = str(x.get("host") or "").strip().lower().rstrip(".")
        try:
            host = str(plain(host, "address"))
        except ValueError:
            if not NAME_RE.match(host):
                raise Refused("%r is not a host name or an address" % host[:80])
        out["servers"].append({"host": host, "pool": x.get("pool") is True,
                               "iburst": x.get("iburst") is not False,
                               "prefer": x.get("prefer") is True, "nts": x.get("nts") is True})
    allow = r.get("allow") if isinstance(r.get("allow"), list) else []
    for a in allow[:20]:
        try:
            out["allow"].append(str(plain(a, "network")))
        except ValueError:
            raise Refused("%r is not a network (192.0.2.0/24)" % str(a)[:60])
    ms = r.get("makestep") if isinstance(r.get("makestep"), list) else [1.0, 3]
    try:
        th, lim = float(ms[0]), int(ms[1])
    except (TypeError, ValueError, IndexError):
        raise Refused("makestep is a threshold in seconds and a number of updates")
    if not (0.001 <= th <= 3600) or not (-1 <= lim <= 1000):
        raise Refused("makestep: 0.001 - 3600 s, and -1 (always) to 1000 updates")
    out["makestep"] = [th, lim]
    try:
        out["minsources"] = max(1, min(10, int(r.get("minsources") or 1)))
    except (TypeError, ValueError):
        out["minsources"] = 1
    tz = str(r.get("timezone") or "").strip()
    if tz and not TZ_RE.match(tz):
        raise Refused("%r is not a time zone" % tz[:60])
    out["timezone"] = tz
    if out["manage"] and not out["servers"]:
        raise Refused("at least one time server")
    return out


def conf_text(text, n):
    """chrony.conf with fake-igd's block (or without it, put back as it was)."""
    out, inside = [], False
    for l in text.splitlines():
        if l.strip() == BEGIN:
            inside = True
            continue
        if l.strip() == END:
            inside = False
            continue
        if inside:
            continue
        if l.startswith(OFF):
            l = l[len(OFF):]                # the file's own line, put back first
        out.append(l)
    if not n["manage"]:
        return "\n".join(out).rstrip("\n") + "\n"
    kept = []
    for l in out:
        kept.append(OFF + l if (l.split() or [""])[0] in KEYS else l)
    block = [BEGIN]
    for x in n["servers"]:
        opts = [o for o, on in (("iburst", x["iburst"]), ("prefer", x["prefer"]), ("nts", x["nts"])) if on]
        block.append(("%s %s %s" % ("pool" if x["pool"] else "server", x["host"], " ".join(opts))).rstrip())
    for a in n["allow"]:
        block.append("allow %s" % a)
    block.append("makestep %s %d" % ("%g" % n["makestep"][0], n["makestep"][1]))
    if n["minsources"] > 1:
        block.append("minsources %d" % n["minsources"])
    block.append(END)
    return "\n".join(l.rstrip() for l in kept).rstrip("\n") + "\n\n" + "\n".join(block) + "\n"


def restart_chronyd():
    run([SYSTEMCTL, "enable", "--now", "chronyd"], "systemctl enable chronyd")
    run([SYSTEMCTL, "restart", "chronyd"], "systemctl restart chronyd")
    run([SYSTEMCTL, "is-active", "--quiet", "chronyd"], "chronyd is not running")


def apply(n):
    said = []
    if not shutil.which(CHRONYC) and not NO_SERVICES:
        if shutil.which("dnf"):
            run(["dnf", "-y", "install", "chrony"], "dnf install chrony", timeout=600)
            said.append("chrony installed")
        else:
            raise Refused("chrony is not on this machine")
    try:
        with open(CHRONY_CONF) as f:
            had = f.read()
    except FileNotFoundError:
        had = "driftfile /var/lib/chrony/drift\nrtcsync\nlogdir /var/log/chrony\n"
    new = conf_text(had, n)
    if new != had:
        if BEGIN not in had:
            try:
                write_root(CHRONY_CONF + ".fake-igd-before", had, 0o644)
            except OSError:
                pass
        write_root(CHRONY_CONF, new, 0o644)
        said.append("%s: %s" % (CHRONY_CONF, ", ".join(x["host"] for x in n["servers"])
                                if n["manage"] else "its own servers again"))
        try:
            if shutil.which(CHRONYD) and not NO_SERVICES:
                # chronyd -p reads the file and says what it makes of it - a line it does not
                # know (an older chrony and "nts", say) stops here, before chronyd is restarted.
                run([CHRONYD, "-p", "-f", CHRONY_CONF], "chronyd -p")
            if not NO_SERVICES:
                restart_chronyd()
                said.append("chronyd restarted")
        except Refused as e:
            write_root(CHRONY_CONF, had, 0o644)
            if not NO_SERVICES:
                try:
                    run([SYSTEMCTL, "restart", "chronyd"], "systemctl restart chronyd")
                except Refused:
                    pass
            raise Refused("%s - chrony.conf put back as it was" % e)
    else:
        said.append("%s: as it is already" % CHRONY_CONF)
    if n["timezone"]:
        try:
            cur = run([TIMEDATECTL, "show", "-p", "Timezone", "--value"], "timedatectl").strip()
        except Refused:
            cur = ""
        if cur != n["timezone"]:
            run([TIMEDATECTL, "set-timezone", n["timezone"]], "timedatectl set-timezone")
            said.append("time zone: %s" % n["timezone"])
    if not NO_SERVICES and shutil.which(TIMEDATECTL):
        run([TIMEDATECTL, "set-ntp", "true"], "timedatectl set-ntp", ok=(0, 1))
    return said


def serve(payload, ask):
    r = payload if isinstance(payload, dict) else {}
    what = r.get("do")
    try:
        if what == "apply":
            return {"ok": True, "do": "apply", "said": apply(checked(r))}
        if what == "sync":
            said = run([CHRONYC, "makestep"], "chronyc makestep").strip()
            run([CHRONYC, "burst", "4/4"], "chronyc burst", ok=(0, 1))
            return {"ok": True, "do": "sync", "said": [said or "stepped"]}
        raise Refused("apply or sync")
    except Refused as e:
        return {"ok": False, "do": str(what)[:10], "said": [str(e)[:600]]}


if __name__ == "__main__":
    print(json.dumps(serve(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}, {}), indent=1))
