"""api_disks.py - Settings → Disks and logs (otp's pane `logs`).

How full each file system is (statvfs - what df says), how much the system journal and
fake-igd's own logs (/var/log/fake-igd) take, and the limits of both:

  logs_journal_mb, logs_journal_days   SystemMaxUse= and MaxRetentionSec= in
                                       /etc/systemd/journald.conf.d/00-fake-igd.conf
  logs_keep, logs_every, logs_max_mb   rotate, daily/weekly/monthly and maxsize in
                                       /etc/logrotate.d/fake-igd

Root puts them in (deploy/root_disks.py) when they are saved, and every 6 hours it is
asked again - which also reads how much the journal takes (journalctl --disk-usage is
root's: the fake-igd account sees only its own journal). *Put in and look again*
asks now; *Rotate the logs now* and *Shrink the journal now* clear what is over the
limits at once.
"""
import hashlib
import json
import os
import re
import time

NAME = "disks"
EVERY_S = 6 * 3600
RETRY_S = 600
PSEUDO = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "securityfs", "cgroup", "cgroup2", "pstore", "bpf",
          "debugfs", "tracefs", "mqueue", "hugetlbfs", "configfs", "fusectl", "autofs", "rpc_pipefs", "nsfs",
          "binfmt_misc", "selinuxfs", "efivarfs", "ramfs", "squashfs", "nfsd", "fuse.gvfsd-fuse", "fuse.portal",
          "iso9660"}
MOUNTS = os.environ.get("FAKE_IGD_MOUNTS", "/proc/self/mounts")

SETTINGS = [
    {"key": "logs_journal_mb", "name": "The system journal at most (MB)", "kind": "int", "default": 0,
     "min": 0, "max": 100000, "root": True,
     "says": "How much room systemd's journal may take; the oldest goes first. 0: as the system has it."},
    {"key": "logs_journal_days", "name": "The system journal kept for (days)", "kind": "int", "default": 0,
     "min": 0, "max": 3650, "root": True,
     "says": "Nothing older is kept. 0: as the system has it."},
    {"key": "logs_keep", "name": "fake-igd's own logs kept (files)", "kind": "int", "default": 12,
     "min": 1, "max": 3650, "root": True,
     "says": "How many old files of /var/log/fake-igd logrotate keeps, one each time it turns them."},
    {"key": "logs_every", "name": "Turned", "kind": "choice", "default": "weekly", "root": True,
     "choices": [("daily", "daily"), ("weekly", "weekly"), ("monthly", "monthly")],
     "says": "How often logrotate puts the logs aside and starts new ones."},
    {"key": "logs_max_mb", "name": "A log file at most (MB)", "kind": "int", "default": 0,
     "min": 0, "max": 100000, "root": True,
     "says": "A file bigger than this is put aside sooner than its turn. 0: only when its turn comes."},
]


def desired(ctx):
    return {"journal_mb": int(ctx.setting("logs_journal_mb") or 0),
            "journal_days": int(ctx.setting("logs_journal_days") or 0),
            "keep": int(ctx.setting("logs_keep") or 12),
            "every": str(ctx.setting("logs_every") or "weekly"),
            "max_mb": int(ctx.setting("logs_max_mb") or 0)}


def want_hash(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()[:16]


# ---- what is here ---------------------------------------------------------------------
def unescape(path):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def filesystems():
    """Each real file system once, as df shows it: size, used, free (for anybody but root)."""
    out, seen = [], set()
    try:
        with open(MOUNTS, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = ["/ / - rw 0 0"]
    for ln in lines:
        parts = ln.split()
        if len(parts) < 3:
            continue
        dev, where, kind = parts[0], unescape(parts[1]), parts[2]
        if kind in PSEUDO or where.startswith(("/proc", "/sys", "/dev", "/run/user")):
            continue
        try:
            st = os.statvfs(where)
            ident = os.stat(where).st_dev
        except OSError:
            continue
        if not st.f_blocks or ident in seen:
            continue
        seen.add(ident)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        out.append({"path": where, "device": dev, "kind": kind, "total": total, "used": used, "free": free,
                    "pct": round(100.0 * used / (used + free), 1) if used + free else 0.0,
                    "inodes": round(100.0 * (st.f_files - st.f_ffree) / st.f_files, 1) if st.f_files else None})
    out.sort(key=lambda d: d["path"])
    return out


def dir_size(path, most=200000):
    total, n = 0, 0
    for top, _dirs, files in os.walk(path):
        for f in files:
            n += 1
            if n > most:
                return total
            try:
                total += os.lstat(os.path.join(top, f)).st_size
            except OSError:
                pass
    return total


def log_files(folder):
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for n in names:
        p = os.path.join(folder, n)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if os.path.isfile(p):
            out.append({"name": n, "bytes": st.st_size, "at": st.st_mtime})
    out.sort(key=lambda x: (-x["at"], x["name"]))
    return out


def log_dir(ctx):
    return os.path.dirname(ctx.cfg.get("log_file") or "/var/log/fake-igd/fake-igd.log") or "/var/log/fake-igd"


def ask(ctx, do):
    payload = dict(desired(ctx), do=do)
    payload["hash"] = want_hash(desired(ctx))
    ident = ctx.ask_root(payload)
    ctx.store.set_meta("disks:asked", json.dumps({"at": time.time(), "id": ident, "do": do}))
    return ident


def view(ctx):
    want = desired(ctx)
    r = ctx.root_result()
    asked = ctx.store.meta_json("disks:asked") or {}
    folder = log_dir(ctx)
    state = ctx.cfg.get("state_dir") or "/var/lib/fake-igd"
    return {"disks": filesystems(), "want": want, "hash": want_hash(want), "result": r,
            "current": r.get("hash") == want_hash(want) and bool(r.get("ok")),
            "waiting": bool(asked.get("id")) and asked.get("id") != r.get("id"),
            "asked": asked, "logdir": folder, "logs": log_files(folder), "logdir_bytes": dir_size(folder),
            "state": state, "state_bytes": dir_size(state), "now": time.time()}


def get_disks(ctx):
    return view(ctx)


def post_disks(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    words = {"refresh": "put the limits of the journal and the logs in and look again",
             "rotate": "rotate fake-igd's logs now", "vacuum": "shrink the system journal to its limits now"}
    if act not in words:
        raise ValueError("no such action")
    if act == "vacuum" and not (int(ctx.setting("logs_journal_mb") or 0) or int(ctx.setting("logs_journal_days") or 0)):
        raise ValueError("the journal has no limit set here - set one above (MB or days) and save it first")
    ident = ask(ctx, {"refresh": "apply"}.get(act, act))
    ctx.event("%s asked root to %s" % (ctx.me["name"], words[act]))
    d = view(ctx)
    d.update({"id": ident, "message": "asked root - a moment"})
    return d


ROUTES = {("GET", "/api/disks"): get_disks, ("POST", "/api/disks"): post_disks}


def on_saved(ctx, changed):
    ask(ctx, "apply")


def background(ctx):
    """Asked again every 6 hours (10 minutes after a failure), and whenever what was put in
    is not what the settings say - but never again while an ask is waiting."""
    r = ctx.root_result()
    asked = ctx.store.meta_json("disks:asked") or {}
    now = time.time()
    if asked.get("id") and asked.get("id") != r.get("id") and now - float(asked.get("at") or 0) < RETRY_S:
        return
    age = now - float(r.get("at") or 0)
    stale = r.get("hash") != want_hash(desired(ctx))
    if (stale and now - float(asked.get("at") or 0) >= RETRY_S) or age >= (EVERY_S if r.get("ok") else RETRY_S):
        ask(ctx, "apply")
