"""root_disks.py - root's part of Settings → Disks and logs (otp_web.py's logs_do, for fake-igd).

Asked by the API (kind "disks"), run by fake_igd_web.py as root:

  do=apply   how much systemd's journal may take and for how long - the drop-in
             /etc/systemd/journald.conf.d/00-fake-igd.conf (SystemMaxUse=, MaxRetentionSec=;
             both 0 takes the file away), systemd-journald restarted only when the file
             changed - and how logrotate turns /var/log/fake-igd: the `rotate N`, the
             daily/weekly/monthly line and `maxsize` of /etc/logrotate.d/fake-igd, nothing else
             in it changed; the file checked with `logrotate -d` and put back when it says no.
  do=rotate  logrotate -f /etc/logrotate.d/fake-igd - the logs put aside now.
  do=vacuum  journalctl --vacuum-size / --vacuum-time - the journal shrunk to the limits now.

Every answer says what the journal takes now (journalctl --disk-usage) and the lines in
force. Nothing in the payload is trusted: each number is checked against its range, the
period against its three words.

Paths for tests: FAKE_IGD_JOURNALD_DROPIN, FAKE_IGD_LOGROTATE; FAKE_IGD_NO_SERVICES=1 leaves
systemd-journald alone; FAKE_IGD_JOURNALCTL / FAKE_IGD_LOGROTATE_BIN name the programs.
"""
import os
import re
import shutil
import subprocess
import sys

DROPIN = os.environ.get("FAKE_IGD_JOURNALD_DROPIN", "/etc/systemd/journald.conf.d/00-fake-igd.conf")
LOGROTATE = os.environ.get("FAKE_IGD_LOGROTATE", "/etc/logrotate.d/fake-igd")
NO_SERVICES = bool(os.environ.get("FAKE_IGD_NO_SERVICES"))
JOURNALCTL = os.environ.get("FAKE_IGD_JOURNALCTL", "journalctl")
LOGROTATE_BIN = os.environ.get("FAKE_IGD_LOGROTATE_BIN", "logrotate")
PERIODS = ("daily", "weekly", "monthly")
HASH_RE = re.compile(r"^[0-9a-f]{16}\Z")


class _Refused(Exception):
    pass


# fake_igd_web.py's own, when it runs this: its refusals are said as they are, not as "broke".
Refused = getattr(sys.modules.get("__main__"), "Refused", None) or _Refused


def _int_in(r, key, lo, hi):
    v = r.get(key, 0)
    if isinstance(v, bool) or not isinstance(v, int):
        raise Refused("%s: a whole number" % key)
    if not lo <= v <= hi:
        raise Refused("%s: %d to %d" % (key, lo, hi))
    return v


def _read_or(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _put_file(path, text, mode=0o644):
    """Written beside the file and renamed over it; the folder made when it is not there."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    tmp = os.path.join(folder, ".%s.fake-igd-new" % os.path.basename(path))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _run(argv, timeout=120):
    try:
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, "", str(e)
    return r.returncode, r.stdout, r.stderr


def parse_usage(text):
    """'Archived and active journals take up 1.2G in the file system.' -> bytes."""
    m = re.search(r"take up ([0-9.]+)\s*([BKMGT])", text or "")
    if not m:
        return None
    return int(float(m.group(1)) * {"B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)])


def journal_use():
    if not shutil.which(JOURNALCTL):
        return None
    _rc, out, err = _run([JOURNALCTL, "--disk-usage"], 30)
    return parse_usage(out + err)


def journal_text(mb, days):
    return ("# Written by fake-igd (Settings - Disks and logs); changed there, not here.\n[Journal]\n"
            + ("SystemMaxUse=%dM\n" % mb if mb else "") + ("MaxRetentionSec=%dday\n" % days if days else ""))


def rotate_text(text, keep, every, max_mb):
    """The three lines of logrotate's file, nothing else: rotate, the period, maxsize (added after
    rotate when it is not there; taken out with 0)."""
    new = re.sub(r"(?m)^(\s*)rotate\s+\d+\s*$", r"\g<1>rotate %d" % keep, text)
    new = re.sub(r"(?m)^(\s*)(daily|weekly|monthly|yearly)\s*$", r"\g<1>%s" % every, new)
    if max_mb:
        if re.search(r"(?m)^\s*maxsize\s+\S+\s*$", new):
            new = re.sub(r"(?m)^(\s*)maxsize\s+\S+\s*$", r"\g<1>maxsize %dM" % max_mb, new)
        else:
            new = re.sub(r"(?m)^(\s*)(rotate\s+\d+)\s*$", r"\g<1>\g<2>\n\g<1>maxsize %dM" % max_mb, new, count=1)
    else:
        new = re.sub(r"(?m)^\s*maxsize\s+\S+\s*\n", "", new)
    return new


def rotate_lines(text):
    return "\n".join(x.strip() for x in (text or "").splitlines()
                     if re.match(r"\s*(rotate|maxsize|daily|weekly|monthly|yearly)\b", x))


def apply(r, said):
    mb = _int_in(r, "journal_mb", 0, 100000)
    days = _int_in(r, "journal_days", 0, 3650)
    keep = _int_in(r, "keep", 1, 3650)
    max_mb = _int_in(r, "max_mb", 0, 100000)
    every = r.get("every")
    if every not in PERIODS:
        raise Refused("every: daily, weekly or monthly")
    ok = True
    before = _read_or(DROPIN)
    if mb or days:
        text = journal_text(mb, days)
        if before != text:
            _put_file(DROPIN, text)
            said.append("the journal: %s" % ", ".join(([("at most %d MB" % mb)] if mb else [])
                                                      + ([("%d days" % days)] if days else [])))
    elif before is not None:
        os.unlink(DROPIN)
        said.append("the journal: as the system has it (%s taken away)" % DROPIN)
    if _read_or(DROPIN) != before and not NO_SERVICES and shutil.which("systemctl"):
        rc, _o, err = _run(["systemctl", "restart", "systemd-journald"], 60)
        if rc != 0:
            said.append("systemd-journald did not restart: %s" % err.strip()[-200:])
            ok = False
    text = _read_or(LOGROTATE)
    if text is None:
        said.append("%s is not there - fake-igd's logs are not rotated" % LOGROTATE)
        return ok
    new = rotate_text(text, keep, every, max_mb)
    if new == text:
        return ok
    _put_file(LOGROTATE, new)
    if shutil.which(LOGROTATE_BIN):
        rc, out, err = _run([LOGROTATE_BIN, "-d", LOGROTATE], 60)
        if rc != 0:
            _put_file(LOGROTATE, text)
            # Said as the line itself, not as a list - and not ok: the limits asked are not in place, so
            # the pages do not show them "as set" (1.9.11).
            said.append("logrotate did not take the change, %s is as it was: %s"
                        % (LOGROTATE, ((err or out).strip().splitlines() or ["?"])[-1]))
            return False
    said.append("fake-igd's logs: %d kept, %s%s" % (keep, every, ", %d MB each at most" % max_mb if max_mb else ""))
    return ok


def rotate(said):
    if not os.path.isfile(LOGROTATE):
        raise Refused("%s is not there" % LOGROTATE)
    if not shutil.which(LOGROTATE_BIN):
        raise Refused("logrotate is not on this machine (dnf install logrotate)")
    rc, out, err = _run([LOGROTATE_BIN, "-f", LOGROTATE], 300)
    if rc != 0:
        raise Refused("logrotate said: %s" % ((err or out).strip()[-300:] or "exit %d" % rc))
    said.append("fake-igd's logs were put aside now")


def vacuum(r, said):
    mb = _int_in(r, "journal_mb", 0, 100000)
    days = _int_in(r, "journal_days", 0, 3650)
    if not (mb or days):
        raise Refused("the journal has no limit set - nothing to shrink it to")
    if not shutil.which(JOURNALCTL):
        raise Refused("journalctl is not on this machine")
    before = journal_use()
    argv = [JOURNALCTL] + (["--vacuum-size=%dM" % mb] if mb else []) + (["--vacuum-time=%dd" % days] if days else [])
    rc, out, err = _run(argv, 300)
    if rc != 0:
        raise Refused("journalctl said: %s" % ((err or out).strip()[-300:] or "exit %d" % rc))
    after = journal_use()
    said.append("the journal shrunk%s" % (" from %d MB to %d MB" % (before >> 20, after >> 20)
                                         if before is not None and after is not None else ""))


def serve(payload, ask):
    do = payload.get("do")
    if do not in ("apply", "rotate", "vacuum", "look"):
        raise Refused("apply, rotate, vacuum or look only")
    said = []
    ok = True
    if do == "apply":
        ok = apply(payload, said) is not False
    elif do == "rotate":
        rotate(said)
    elif do == "vacuum":
        vacuum(payload, said)
    h = payload.get("hash")
    out = {"ok": ok, "do": do, "said": said, "journal_use": journal_use(),
           "journal_conf": _read_or(DROPIN) or "", "rotate_conf": rotate_lines(_read_or(LOGROTATE)),
           "dropin": DROPIN, "logrotate": LOGROTATE}
    # The settings it was asked with (their hash) - only once they are in place.
    if do == "apply" and ok and isinstance(h, str) and HASH_RE.match(h):
        out["hash"] = h
    elif do != "apply":
        out["hash"] = h if isinstance(h, str) and HASH_RE.match(h) and _in_force(payload) else ""
    return out


def _in_force(r):
    """Whether what is in the files is what r says (after a rotate or a vacuum, which change neither)."""
    try:
        mb, days = int(r.get("journal_mb") or 0), int(r.get("journal_days") or 0)
        keep, every, max_mb = int(r.get("keep") or 0), r.get("every"), int(r.get("max_mb") or 0)
    except (TypeError, ValueError):
        return False
    j = _read_or(DROPIN)
    if (mb or days) and j != journal_text(mb, days):
        return False
    if not (mb or days) and j is not None:
        return False
    t = _read_or(LOGROTATE)
    return t is None or rotate_text(t, keep, every, max_mb) == t if every in PERIODS else False
