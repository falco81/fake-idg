#!/usr/bin/python3 -I
"""root_power.py - what root does for Settings → Restart and power off (1.6.0), otp's
power_after of otp_web.py, for one server.

  {"do": "reboot" | "poweroff", "in": MINUTES}
        in 0: a few seconds from now, by a timer (systemd-run … systemctl reboot) - after this
        helper has written its answer and the page has had it; in 1 - 1440: shutdown -r/-P +MINUTES,
        which systemd keeps in /run/systemd/shutdown/scheduled (the page shows it, and warns
        whoever is signed in).
  {"do": "cancel"}                 shutdown -c - what was set for later does not happen
  {"do": "auto", "needed": bool}   the restart on a schedule: with needed, only when an update
                                   asks for one (needs-restarting -r says so)

Tests: FAKE_IGD_POWER_CMD names a file the asks are written to instead of being done, and
FAKE_IGD_SHUTDOWN_FILE the file that stands for systemd's own list of what is set.
"""
import json
import os
import shutil
import subprocess
import sys
import time

SYSTEMD_RUN = os.environ.get("FAKE_IGD_SYSTEMD_RUN", "systemd-run")
SYSTEMCTL = os.environ.get("FAKE_IGD_SYSTEMCTL", "/usr/bin/systemctl")
SHUTDOWN = os.environ.get("FAKE_IGD_SHUTDOWN", "shutdown")
NEEDS_RESTARTING = os.environ.get("FAKE_IGD_NEEDS_RESTARTING", "needs-restarting")
POWER_CMD = os.environ.get("FAKE_IGD_POWER_CMD", "")
SHUTDOWN_FILE = os.environ.get("FAKE_IGD_SHUTDOWN_FILE", "/run/systemd/shutdown/scheduled")
WALL = "fake-igd: %s asked on its pages (Settings - Restart and power off)"


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
    return got


def test_write(line, mode=None, usec=None):
    with open(POWER_CMD, "a") as f:
        f.write("%s %s\n" % (time.time(), line))
    if mode is None:
        try:
            os.unlink(SHUTDOWN_FILE)
        except OSError:
            pass
    elif usec:
        with open(SHUTDOWN_FILE, "w") as f:
            f.write("USEC=%d\nWARN_WALL=1\nMODE=%s\n" % (usec, mode))


def go(how, minutes):
    words = "a restart" if how == "reboot" else "a power-off"
    if minutes == 0:
        if POWER_CMD:
            test_write("%s in 5 s" % how)
            return "%s in 5 s (written to %s)" % (how, POWER_CMD)
        run([SYSTEMD_RUN, "--on-active=5s", "--unit", "fake-igd-%s-%d" % (how, int(time.time())),
             "--description", "fake-igd: " + words + " asked on its pages", SYSTEMCTL, how], "systemd-run %s" % how)
        return "%s in 5 s" % how
    flag = "-r" if how == "reboot" else "-P"
    if POWER_CMD:
        test_write("shutdown %s +%d" % (flag, minutes), "reboot" if how == "reboot" else "poweroff",
                   int((time.time() + minutes * 60) * 1e6))
        return "%s in %d min (written to %s)" % (how, minutes, POWER_CMD)
    run([SHUTDOWN, flag, "+%d" % minutes, WALL % words], "shutdown %s" % flag)
    return "%s in %d min - %s" % (how, minutes, time.strftime("at %H:%M", time.localtime(time.time() + minutes * 60)))


def cancel():
    if POWER_CMD:
        test_write("shutdown -c")
        return "what was set is cancelled (written to %s)" % POWER_CMD
    run([SHUTDOWN, "-c", "fake-igd: cancelled on its pages"], "shutdown -c")
    return "what was set is cancelled"


def needed():
    """Does an update wait for a restart? needs-restarting -r: 1 yes, 0 no."""
    if not shutil.which(NEEDS_RESTARTING):
        if shutil.which("dnf"):
            got = run(["dnf", "-q", "needs-restarting", "-r"], "dnf needs-restarting", ok=(0, 1))
        else:
            raise Refused("needs-restarting is not here (dnf install dnf-utils)")
    else:
        got = run([NEEDS_RESTARTING, "-r"], "needs-restarting", ok=(0, 1))
    return got.returncode == 1, (got.stdout or "").strip().splitlines()[:3]


def serve(payload, ask):
    r = payload if isinstance(payload, dict) else {}
    what = r.get("do")
    try:
        if what in ("reboot", "poweroff"):
            m = r.get("in", 0)
            if isinstance(m, bool) or not isinstance(m, int) or not 0 <= m <= 1440:
                raise Refused("in: whole minutes, 0 to 1440")
            return {"ok": True, "do": what, "in": m, "said": [go(what, m)]}
        if what == "cancel":
            return {"ok": True, "do": "cancel", "said": [cancel()]}
        if what == "auto":
            if r.get("needed") is True:
                need, words = needed()
                if not need:
                    return {"ok": True, "do": "auto", "said": ["no update waits for a restart - none made"]}
                return {"ok": True, "do": "auto", "said": words + [go("reboot", 0)]}
            return {"ok": True, "do": "auto", "said": [go("reboot", 0)]}
        raise Refused("reboot, poweroff, cancel or auto")
    except Refused as e:
        return {"ok": False, "do": str(what)[:10], "said": [str(e)[:600]]}


if __name__ == "__main__":
    print(json.dumps(serve(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}, {}), indent=1))
