"""api_db.py - Settings → The database (otp's pane `db`, for fake-igd's one SQLite file).

Everything the pages keep is in /var/lib/fake-igd/fake-igd.db: the accounts, who is
signed in, the wrong passwords, the events and the settings saved on the pages. This
pane shows how big it is and what is in it, keeps copies of it (SQLite's own backup
API - a consistent copy while it is being written to - gzip'd, one a night and on
demand, the last N kept in /var/lib/fake-igd/backups), trims the events older than
the days set here (once an hour, in the background), checks it, gives the disk back
(VACUUM), downloads a copy and puts one back - a kept one, or a file sent from the
browser. otp has MariaDB and PostgreSQL besides; fake-igd has the file only.

All of it is the API's own work (the fake-igd account owns the file); nothing is
asked of root.
"""
import base64
import gzip
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time

NAME = "db"

HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d\Z")
COPY_RE = re.compile(r"^fake-igd-(?:(before-restore|upload)-)?(\d{8}-\d{6})\.db\.gz\Z")
UPLOAD_RE = re.compile(r"^upload-[0-9a-f]{16}\.db\Z")
TIDY_EVERY_S = 3600
UPLOAD_KEEP_S = 3600
TABLE_SAID = {"users": "The accounts of the pages", "sessions": "Who is signed in",
              "fails": "Wrong passwords counted", "events": "Events",
              "meta": "Settings and small values", "sqlite_sequence": "SQLite's own counters"}


def _hhmm(v):
    return "" if HHMM_RE.match(v) else "a time as HH:MM (03:30)"


SETTINGS = [
    {"key": "db_copy_daily", "name": "A copy of the database every day", "kind": "bool", "default": True,
     "says": "A copy of the database once a day, into <code>/var/lib/fake-igd/backups</code> - made by "
             "SQLite's own backup, so it is whole even while the API writes to it."},
    {"key": "db_copy_at", "name": "At", "kind": "text", "default": "03:30", "check": _hhmm,
     "says": "When, as <code>HH:MM</code> on this machine's clock.", "only_when": ("db_copy_daily", True)},
    {"key": "db_copy_keep", "name": "Copies kept", "kind": "int", "default": 14, "min": 1, "max": 365,
     "says": "How many of those copies are kept; the oldest goes first. A copy made by hand counts too."},
    {"key": "events_keep_days", "name": "Keep the events (days)", "kind": "int", "default": 365,
     "min": 0, "max": 36500,
     "says": "How long the events are kept. 0 keeps them for ever (fake-igd still keeps no more than the "
             "newest 20 000). Trimmed once an hour; <b>Apply what is kept, now</b> does it at once."},
]


# ---- where things are ---------------------------------------------------------------
def state_dir(ctx):
    return ctx.cfg.get("state_dir") or "/var/lib/fake-igd"


def copies_dir(ctx):
    return os.path.join(state_dir(ctx), "backups")


def db_path(ctx):
    return ctx.store.path


def file_size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


def db_bytes(ctx):
    p = db_path(ctx)
    return sum(file_size(p + x) for x in ("", "-wal", "-shm"))


# ---- what is in it ------------------------------------------------------------------
def tables(conn):
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    sizes = {}
    try:
        for name, b in conn.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name"):
            sizes[name] = int(b or 0)
    except sqlite3.Error:
        sizes = None                                     # no dbstat in this SQLite
    out = []
    for n in names:
        try:
            rows = conn.execute('SELECT COUNT(*) FROM "%s"' % n.replace('"', '""')).fetchone()[0]
        except sqlite3.Error:
            rows = None
        out.append({"table": n, "rows": rows, "bytes": None if sizes is None else sizes.get(n, 0)})
    return out


def free_bytes(conn):
    try:
        n = conn.execute("PRAGMA freelist_count").fetchone()[0]
        size = conn.execute("PRAGMA page_size").fetchone()[0]
        return int(n) * int(size)
    except sqlite3.Error:
        return 0


def disk_of(path):
    try:
        st = os.statvfs(path)
    except OSError:
        return {}
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    return {"where": path, "total": total, "free": free,
            "share": round(100.0 * (total - free) / total, 1) if total else 0}


# ---- copies -------------------------------------------------------------------------
def copies(ctx):
    folder = copies_dir(ctx)
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for n in names:
        m = COPY_RE.match(n)
        if not m:
            continue
        p = os.path.join(folder, n)
        try:
            st = os.stat(p)
        except OSError:
            continue
        out.append({"name": n, "bytes": st.st_size, "at": st.st_mtime,
                    "kind": m.group(1) or "copy"})
    out.sort(key=lambda c: c["at"], reverse=True)
    return out


def snapshot(store, dst):
    """The live database into the file dst - SQLite's backup API, under the store's lock."""
    out = sqlite3.connect(dst)
    try:
        with store.lock:
            store.db.backup(out)
    finally:
        out.close()


def make_copy(ctx, kind=""):
    """A copy kept in backups/: its name."""
    folder = copies_dir(ctx)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = "fake-igd-%s%s.db.gz" % (kind + "-" if kind else "", stamp)
    while os.path.exists(os.path.join(folder, name)):          # two in one second: the next second's name
        time.sleep(1)
        name = "fake-igd-%s%s.db.gz" % (kind + "-" if kind else "", time.strftime("%Y%m%d-%H%M%S"))
    fd, raw = tempfile.mkstemp(prefix=".copy-", dir=folder)
    os.close(fd)
    try:
        snapshot(ctx.store, raw)
        tmp = os.path.join(folder, "." + name + ".part")
        with open(raw, "rb") as src, gzip.open(tmp, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(folder, name))
    finally:
        for p in (raw, os.path.join(folder, "." + name + ".part")):
            try:
                os.unlink(p)
            except OSError:
                pass
    prune(ctx)
    return name


def prune(ctx):
    """The copies past db_copy_keep, oldest first (the ones made before a restore count too)."""
    keep = int(ctx.setting("db_copy_keep") or 14)
    gone = []
    for c in copies(ctx)[keep:]:
        try:
            os.unlink(os.path.join(copies_dir(ctx), c["name"]))
            gone.append(c["name"])
        except OSError:
            pass
    return gone


def copy_path(ctx, name):
    name = str(name or "")
    if not COPY_RE.match(name):
        raise ValueError("no such copy")
    p = os.path.join(copies_dir(ctx), name)
    if not os.path.isfile(p):
        raise ValueError("no such copy: %s" % name)
    return p


# ---- a database from somewhere else, read before anything is done ---------------------
def unpack(src, dst):
    """A copy (gzip'd or not) as a plain SQLite file in dst."""
    with open(src, "rb") as f:
        head = f.read(2)
    if head == b"\x1f\x8b":
        with gzip.open(src, "rb") as a, open(dst, "wb") as b:
            shutil.copyfileobj(a, b, 1 << 20)
    else:
        shutil.copyfile(src, dst)
    with open(dst, "rb") as f:
        if f.read(16) != b"SQLite format 3\x00":
            raise ValueError("that is not a SQLite database (nor a gzip'd one)")


def read_db(path):
    """What a database file holds - refused unless it is fake-igd's with a full admin in it."""
    conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise ValueError("the file is damaged: %s" % ok)
        t = tables(conn)
        names = {x["table"] for x in t}
        if not {"users", "events", "meta"} <= names:
            raise ValueError("that is not fake-igd's database: it has no users, events and meta tables")
        admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'fulladmin'").fetchone()[0]
        if not admins:
            raise ValueError("there is no full admin in it - nobody could sign in to put it right")
        last = conn.execute("SELECT MAX(at) FROM events").fetchone()[0]
        counts = {x["table"]: x["rows"] for x in t}
    finally:
        conn.close()
    return {"bytes": file_size(path), "tables": len(t), "counts": counts, "admins": admins, "last_event": last}


def restore_from(ctx, path, what):
    """Everything in the live database replaced by the file at path (plain SQLite)."""
    says = read_db(path)
    safety = make_copy(ctx, "before-restore")
    src = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        with ctx.store.lock:
            src.backup(ctx.store.db)
    finally:
        src.close()
    who = (ctx.me or {}).get("name", "")
    ctx.event("%s put the database back from %s (%s account(s), %s event(s)); what it replaced is in %s"
              % (who, what, says["counts"].get("users"), says["counts"].get("events"), safety), "warn")
    return {"ok": True, "safety": safety, "says": says,
            "message": "the database is back from %s - what it replaced is kept as %s" % (what, safety)}


def tidy_uploads(ctx):
    folder = copies_dir(ctx)
    try:
        for n in os.listdir(folder):
            if UPLOAD_RE.match(n) and time.time() - os.path.getmtime(os.path.join(folder, n)) > UPLOAD_KEEP_S:
                os.unlink(os.path.join(folder, n))
    except OSError:
        pass


# ---- keeping it trim ------------------------------------------------------------------
def tidy(ctx):
    days = int(ctx.setting("events_keep_days") or 0)
    n = 0
    if days:
        n = ctx.store.run("DELETE FROM events WHERE at < ?", (time.time() - days * 86400,)).rowcount
    f = ctx.store.run("DELETE FROM fails WHERE at < ?", (time.time() - 86400,)).rowcount
    ctx.store.set_meta("db:tidy:at", str(time.time()))
    return n, f


def view(ctx):
    conn = ctx.store.db
    with ctx.store.lock:
        t = tables(conn)
        free = free_bytes(conn)
        try:
            version = "SQLite " + conn.execute("SELECT sqlite_version()").fetchone()[0]
        except sqlite3.Error:
            version = "SQLite"
    folder = copies_dir(ctx)
    tidied = ctx.store.get_meta("db:tidy:at")
    last_copy = ctx.store.get_meta("db:copy:at")
    p = db_path(ctx)
    return {"where": p, "size": db_bytes(ctx), "version": version, "tables": t, "free": free,
            "copies": copies(ctx), "keep": int(ctx.setting("db_copy_keep") or 14), "backup_dir": folder,
            "daily": bool(ctx.setting("db_copy_daily")), "at": ctx.setting("db_copy_at"),
            "last_copy": float(last_copy) if last_copy else None,
            "events_keep_days": int(ctx.setting("events_keep_days") or 0),
            "tidied": float(tidied) if tidied else None, "disk": disk_of(os.path.dirname(p) or "."),
            "parts": [{"name": os.path.basename(p) + x, "what": w, "bytes": file_size(p + x)}
                      for x, w in (("", "the database"), ("-wal", "what is written, not yet in the file (WAL)"),
                                   ("-shm", "the WAL's index")) if os.path.exists(p + x)]}


# ---- the routes ------------------------------------------------------------------------
def get_db(ctx):
    return view(ctx)


def post_db(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    who = ctx.me["name"]
    if act == "copy":
        name = make_copy(ctx)
        ctx.store.set_meta("db:copy:at", str(time.time()))
        ctx.event("%s made a copy of the database: %s" % (who, name))
        return {"message": "a copy was made: %s" % name, "name": name}
    if act == "check":
        with ctx.store.lock:
            rows = [r[0] for r in ctx.store.db.execute("PRAGMA integrity_check").fetchall()]
        good = rows == ["ok"]
        ctx.event("%s had the database checked: %s" % (who, "whole" if good else "; ".join(rows[:5])),
                  "info" if good else "warn")
        return {"good": good, "said": rows[:50],
                "message": "the database is whole" if good else "the database is damaged: " + "; ".join(rows[:3])}
    if act == "tidy":
        n, f = tidy(ctx)
        ctx.event("%s applied what is kept: %d event(s) and %d wrong password(s) forgotten" % (who, n, f))
        return {"message": "%d event(s) older than %s day(s) forgotten" % (n, ctx.setting("events_keep_days"))
                if ctx.setting("events_keep_days") else "events are kept for ever - nothing was forgotten"}
    if act == "prune":
        try:
            days = int(b.get("days"))
        except (TypeError, ValueError):
            raise ValueError("days: a whole number")
        if not 1 <= days <= 36500:
            raise ValueError("days: 1 to 36500")
        n = ctx.store.run("DELETE FROM events WHERE at < ?", (time.time() - days * 86400,)).rowcount
        ctx.event("%s forgot the events older than %d day(s): %d" % (who, days, n), "warn")
        return {"message": "%d event(s) older than %d day(s) forgotten" % (n, days)}
    if act == "vacuum":
        before = db_bytes(ctx)
        with ctx.store.lock:
            ctx.store.db.execute("VACUUM")
            try:
                ctx.store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
        after = db_bytes(ctx)
        ctx.event("%s gave the disk back: %d → %d bytes" % (who, before, after))
        return {"before": before, "after": after, "message": "the disk is given back"}
    if act == "delete":
        p = copy_path(ctx, b.get("name"))
        os.unlink(p)
        ctx.event("%s deleted the copy %s" % (who, os.path.basename(p)), "warn")
        return {"message": "%s is deleted" % os.path.basename(p)}
    if act == "download":
        name = str(b.get("name") or "")
        if name:
            p = copy_path(ctx, name)
            with open(p, "rb") as f:
                data = f.read()
        else:
            fd, raw = tempfile.mkstemp(prefix=".dl-", dir=state_dir(ctx))
            os.close(fd)
            try:
                snapshot(ctx.store, raw)
                with open(raw, "rb") as f:
                    data = gzip.compress(f.read(), 6)
            finally:
                os.unlink(raw)
            name = "fake-igd-%s.db.gz" % time.strftime("%Y%m%d-%H%M%S")
        ctx.event("%s downloaded the database (%s)" % (who, name), "warn")
        return {"name": name, "bytes": len(data), "data": base64.b64encode(data).decode("ascii")}
    if act == "restore_kept":
        p = copy_path(ctx, b.get("name"))
        work = tempfile.mkdtemp(prefix=".restore-", dir=state_dir(ctx))
        try:
            plain = os.path.join(work, "db")
            unpack(p, plain)
            if b.get("check"):
                return {"says": read_db(plain)}
            return restore_from(ctx, plain, os.path.basename(p))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if act == "restore_upload":
        up = str(b.get("upload") or "")
        if not UPLOAD_RE.match(up):
            raise ValueError("no such file sent")
        p = os.path.join(copies_dir(ctx), up)
        if not os.path.isfile(p):
            raise ValueError("the file sent is gone (an hour passed?) - send it again")
        try:
            return restore_from(ctx, p, str(b.get("file") or "a file sent")[:120])
        finally:
            try:
                os.unlink(p)
            except OSError:
                pass
    raise ValueError("no such action")


def post_upload(ctx):
    """A database sent from the browser (base64 in JSON): kept for an hour, read and said - nothing
    else happens until restore_upload."""
    ctx.need("fulladmin")
    b = ctx.body(most=96 * 1024 * 1024)
    try:
        data = base64.b64decode(str(b.get("data") or ""), validate=True)
    except ValueError:
        raise ValueError("the file did not come whole")
    if not data:
        raise ValueError("the file is empty")
    folder = copies_dir(ctx)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    tidy_uploads(ctx)
    up = "upload-%s.db" % secrets.token_hex(8)
    raw = os.path.join(folder, "." + up + ".raw")
    with open(raw, "wb") as f:
        f.write(data)
    try:
        unpack(raw, os.path.join(folder, up))
        says = read_db(os.path.join(folder, up))
    except Exception:
        try:
            os.unlink(os.path.join(folder, up))
        except OSError:
            pass
        raise
    finally:
        os.unlink(raw)
    return {"upload": up, "says": says}


ROUTES = {("GET", "/api/db"): get_db, ("POST", "/api/db"): post_db, ("POST", "/api/db/upload"): post_upload}


def on_saved(ctx, changed):
    if "db_copy_keep" in changed:
        prune(ctx)


def background(ctx):
    """A copy once a day at db_copy_at; the events trimmed once an hour."""
    now = time.time()
    if ctx.setting("db_copy_daily"):
        at = str(ctx.setting("db_copy_at") or "03:30")
        today = time.strftime("%Y-%m-%d")
        if HHMM_RE.match(at) and time.strftime("%H:%M") >= at and ctx.store.get_meta("db:copy:day") != today:
            ctx.store.set_meta("db:copy:day", today)
            try:
                name = make_copy(ctx)
                ctx.store.set_meta("db:copy:at", str(now))
                ctx.event("the nightly copy of the database was made: %s" % name)
            except (OSError, sqlite3.Error) as e:
                ctx.event("the nightly copy of the database could not be made: %s" % e, "warn")
    last = float(ctx.store.get_meta("db:tidy:at") or 0)
    if now - last >= TIDY_EVERY_S:
        tidy(ctx)
    tidy_uploads(ctx)
