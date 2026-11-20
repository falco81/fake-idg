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
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import tarfile
import tempfile
import time

import igd_seal as SEAL

NAME = "db"

HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d\Z")
COPY_RE = re.compile(r"^fake-igd-(?:(before-restore|upload)-)?(\d{8}-\d{6})\.db\.gz\Z")
DUMP_RE = re.compile(r"^fake-igd-sqlite-(\d{8}-\d{6})-(daily|now|before-restore)\.db\Z")
UPLOAD_RE = re.compile(r"^upload-[0-9a-f]{16}\.(db|tar)\Z")
LOCKED_KIND = "fake-igd-key-locked"
SIZES_KEEP = 30
TIDY_EVERY_S = 3600
UPLOAD_KEEP_S = 3600
TABLE_SAID = {"users": "The accounts of the pages", "sessions": "Who is signed in",
              "fails": "Wrong passwords counted", "events": "Events",
              "meta": "Settings and small values", "sqlite_sequence": "SQLite's own counters"}


def _hhmm(v):
    return "" if HHMM_RE.match(v) else "a time as HH:MM (03:30)"


SETTINGS = [
    {"key": "db_copy_daily", "name": "A copy of the database every day", "kind": "bool", "default": True,
     "says": "A copy of the database once a day, into <code>/var/lib/fake-igd/backups</code>, with the key "
             "that opens its secrets beside it."},
    {"key": "db_copy_keep", "name": "Copies kept", "kind": "int", "default": 14, "min": 1, "max": 365,
     "says": "How many of those copies are kept; the oldest goes first."},
    {"key": "db_copy_at", "name": "At", "kind": "text", "default": "03:30", "check": _hhmm,
     "says": "When, as <code>HH:MM</code> on this machine's clock."},
    {"key": "events_keep_days", "name": "Keep the events (days)", "kind": "int", "default": 365,
     "min": 0, "max": 36500,
     "says": "How long the events are kept. 0 keeps them for ever (the newest 20 000 at most)."},
]


# ---- where things are ---------------------------------------------------------------
def state_dir(ctx):
    return ctx.cfg.get("state_dir") or "/var/lib/fake-igd"


def copies_dir(ctx):
    return os.path.join(state_dir(ctx), "backups")


def dumps_dir(ctx):
    return os.path.join(state_dir(ctx), "dumps")


def key_beside(ctx, path):
    """secrets.key beside a copy or a dump (NAME.key, 0600): without it the secrets in it open nowhere."""
    src = SEAL.key_path(ctx.store)
    if not os.path.isfile(src):
        return False
    tmp = path + ".key.part"
    shutil.copyfile(src, tmp)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path + ".key")
    return True


def drop_with_key(path):
    for p in (path, path + ".key"):
        try:
            os.unlink(p)
        except OSError:
            pass


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
                    "kind": m.group(1) or "copy", "key": os.path.isfile(p + ".key")})
    out.sort(key=lambda c: c["at"], reverse=True)
    return out


def dumps(ctx):
    folder = dumps_dir(ctx)
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for n in names:
        m = DUMP_RE.match(n)
        if not m:
            continue
        p = os.path.join(folder, n)
        try:
            st = os.stat(p)
        except OSError:
            continue
        out.append({"name": n, "bytes": st.st_size, "at": st.st_mtime, "kind": "sqlite", "made": m.group(2),
                    "key": os.path.isfile(p + ".key"), "mine": True})
    out.sort(key=lambda c: c["at"], reverse=True)
    return out


def make_dump(ctx, why="now"):
    """A dump: on the file, SQLite's own backup, which is the file (otp's dump of SQLite) - kept in dumps/,
    the key beside it."""
    folder = dumps_dir(ctx)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    name = "fake-igd-sqlite-%s-%s.db" % (time.strftime("%Y%m%d-%H%M%S"), why)
    while os.path.exists(os.path.join(folder, name)):
        time.sleep(1)
        name = "fake-igd-sqlite-%s-%s.db" % (time.strftime("%Y%m%d-%H%M%S"), why)
    tmp = os.path.join(folder, "." + name + ".part")
    try:
        snapshot(ctx.store, tmp)
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(folder, name))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    key_beside(ctx, os.path.join(folder, name))
    keep = int(ctx.setting("db_copy_keep") or 14)
    for d in dumps(ctx)[keep:]:
        drop_with_key(os.path.join(folder, d["name"]))
    return name


def dump_path(ctx, name):
    name = str(name or "")
    if not DUMP_RE.match(name):
        raise ValueError("no such dump")
    p = os.path.join(dumps_dir(ctx), name)
    if not os.path.isfile(p):
        raise ValueError("no such dump: %s" % name)
    return p


def kept_path(ctx, name, kind):
    return dump_path(ctx, name) if kind == "dump" else copy_path(ctx, name)


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
    key_beside(ctx, os.path.join(folder, name))
    prune(ctx)
    return name


def prune(ctx):
    """The copies past db_copy_keep, oldest first (the ones made before a restore count too)."""
    keep = int(ctx.setting("db_copy_keep") or 14)
    gone = []
    for c in copies(ctx)[keep:]:
        drop_with_key(os.path.join(copies_dir(ctx), c["name"]))
        gone.append(c["name"])
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
# A database put back is at most this big, unpacked (1.9.9): fake-igd's is a few MB (20 000 events at most) - a
# gzip'd file of a few kB that unpacks to the whole disk is refused when it passes this, not when the disk is full.
DB_MOST = 1 << 30


def copy_most(a, b, most, what):
    """a (an open file) into b, refused past `most` bytes."""
    n = 0
    while True:
        chunk = a.read(1 << 20)
        if not chunk:
            return n
        n += len(chunk)
        if n > most:
            raise ValueError("%s unpacks to more than %d MB - not a database of fake-igd; refused" % (
                what, max(1, most >> 20)))
        b.write(chunk)


def unpack(src, dst):
    """A copy (gzip'd or not) as a plain SQLite file in dst - DB_MOST at most."""
    with open(src, "rb") as f:
        head = f.read(2)
    try:
        with (gzip.open(src, "rb") if head == b"\x1f\x8b" else open(src, "rb")) as a, open(dst, "wb") as b:
            copy_most(a, b, DB_MOST, "that file")
    except (OSError, EOFError) as e:
        if isinstance(e, OSError) and e.errno is not None:
            raise
        os.unlink(dst)
        raise ValueError("that file does not unpack: %s" % e)
    except ValueError:
        os.unlink(dst)
        raise
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


def strip_extras(conn):
    """Every trigger and view of a database dropped - fake-igd's own schema has none (1.9.9). What was dropped."""
    gone = []
    for kind, name in conn.execute("SELECT type, name FROM sqlite_master WHERE type IN ('trigger', 'view') "
                                   "AND name NOT LIKE 'sqlite_%'").fetchall():
        conn.execute('DROP %s IF EXISTS "%s"' % ("TRIGGER" if kind == "trigger" else "VIEW", name.replace('"', '""')))
        gone.append("%s %s" % (kind, name[:60]))
    return gone


def put_key(ctx, key_hex):
    """The key that came with a database put in place of this one - the one there kept beside it
    (secrets.key.before-restore-STAMP). Words saying what was done."""
    try:
        new = bytes.fromhex(str(key_hex or "").strip())
    except ValueError:
        new = b""
    if len(new) != 32:
        return "the key in use stays (none came with it)"
    path = SEAL.key_path(ctx.store)
    old = SEAL.key(ctx.store)
    if old == new:
        return "the key in use is the same"
    if os.path.isfile(path):
        shutil.copyfile(path, path + ".before-restore-" + time.strftime("%Y%m%d-%H%M%S"))
    tmp = path + ".new"
    with open(tmp, "w", encoding="ascii") as f:
        f.write(new.hex() + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    SEAL.forget()
    return "the key that came with it is in use; the one before is kept beside it"


def restore_from(ctx, path, what, key_hex=None):
    """Everything in the live database replaced by the file at path (plain SQLite); the key that seals
    its secrets put in place too, where one came with it."""
    says = read_db(path)
    safety = make_copy(ctx, "before-restore")
    src = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        with ctx.store.lock:
            # Who is signed in NOW stays so, and only they (1.9.9): the file's own sessions came back to
            # life with it - a sign-in ended since (by its password changed, by Accounts → End, by signing
            # out) opened the pages again for whoever still had its cookie, within its idle time.
            live = [dict(r) for r in ctx.store.db.execute("SELECT * FROM sessions").fetchall()]
            src.backup(ctx.store.db)
            # Nothing but tables comes with it (1.9.9): fake-igd makes no trigger and no view, and one in the file
            # (a trigger on sessions making an account a full admin, say) stayed in the database and ran on.
            stripped = strip_extras(ctx.store.db)
            # A database of an older version gets this version's columns at once (1.9.9).
            ctx.store.migrate()
            ctx.store.db.execute("DELETE FROM sessions")
            ctx.store.db.execute("DELETE FROM challenges")
            for r in live:
                ctx.store.db.execute("INSERT OR REPLACE INTO sessions (%s) VALUES (%s)" % (
                    ", ".join(r), ", ".join("?" * len(r))), tuple(r.values()))
    finally:
        src.close()
    key_said = put_key(ctx, key_hex) if key_hex else "the key in use stays (none came with it)"
    if stripped:
        key_said += "; left out of it, not fake-igd's: %s" % ", ".join(stripped[:20])
    who = (ctx.me or {}).get("name", "")
    ctx.event("%s put the database back from %s (%s account(s), %s event(s)); what it replaced is in %s; %s"
              % (who, what, says["counts"].get("users"), says["counts"].get("events"), safety, key_said), "warn")
    return {"ok": True, "safety": safety, "says": says, "key": key_said,
            "message": "the database is back from %s - what it replaced is kept as %s" % (what, safety)}


def key_of(path):
    """The key beside a kept file (hex), or None."""
    try:
        with open(path + ".key", encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


# ---- a copy with its key, locked with a passphrase (otp 1.0.123) ---------------------------
def _pkey(passphrase, salt):
    return hashlib.scrypt(str(passphrase).encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def lock_key(key_hex, passphrase):
    salt = secrets.token_bytes(16)
    k = _pkey(passphrase, salt)
    sealed = SEAL.seal_with(k, key_hex, bind=LOCKED_KIND)
    return {"kind": LOCKED_KIND, "salt": base64.b64encode(salt).decode("ascii"), "sealed": sealed}


def open_key(locked, passphrase):
    if not isinstance(locked, dict) or locked.get("kind") != LOCKED_KIND:
        raise ValueError("the key in the file is not one of ours")
    try:
        salt = base64.b64decode(locked.get("salt") or "")
    except (ValueError, TypeError):
        raise ValueError("the key in the file is damaged")
    got = SEAL.unseal_with(_pkey(passphrase, salt), locked.get("sealed"), bind=LOCKED_KIND)
    if not got:
        raise ValueError("the passphrase is not the one the file was locked with")
    return got


def bundle(name, data, key_hex, passphrase):
    """One .tar: the copy (or the dump) and secrets.key.locked."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for n, raw in ((name, data), ("secrets.key.locked",
                                      json.dumps(lock_key(key_hex, passphrase)).encode("utf-8"))):
            ti = tarfile.TarInfo(n)
            ti.size = len(raw)
            ti.mtime = int(time.time())
            ti.mode = 0o600
            tf.addfile(ti, io.BytesIO(raw))
    return buf.getvalue()


def unbundle(path, work):
    """(the database file, the locked key) out of a .tar made by bundle()."""
    dbf, locked = None, None
    with tarfile.open(path, "r:") as tf:
        for m in tf.getmembers():
            if not m.isreg() or "/" in m.name or m.size > DB_MOST:
                continue
            if m.name == "secrets.key.locked" and m.size < 65536:
                locked = json.loads(tf.extractfile(m).read().decode("utf-8"))
            elif COPY_RE.match(m.name) or DUMP_RE.match(m.name) or m.name.endswith((".db", ".db.gz")):
                dbf = os.path.join(work, "packed")
                with tf.extractfile(m) as a, open(dbf, "wb") as b:
                    shutil.copyfileobj(a, b, 1 << 20)
    if not dbf or not locked:
        raise ValueError("that is not a copy with its key from these pages")
    plain = os.path.join(work, "db")
    unpack(dbf, plain)
    return plain, locked


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


def dir_bytes(folder):
    total = 0
    try:
        for n in os.listdir(folder):
            total += file_size(os.path.join(folder, n))
    except OSError:
        pass
    return total


def note_size(ctx):
    """The size of the database, noted once a day (the last SIZES_KEEP days): how fast it grows."""
    try:
        got = json.loads(ctx.store.get_meta("db:sizes") or "[]")
    except ValueError:
        got = []
    today = time.strftime("%Y-%m-%d")
    if got and got[-1][0] == today:
        return got
    got = (got + [[today, db_bytes(ctx), time.time()]])[-SIZES_KEEP:]
    ctx.store.set_meta("db:sizes", json.dumps(got))
    return got


def growth(ctx):
    """otp's: the slope of the last fortnight, a day."""
    try:
        got = json.loads(ctx.store.get_meta("db:sizes") or "[]")
    except ValueError:
        got = []
    got = [g for g in got if len(g) == 3 and time.time() - g[2] <= 15 * 86400]
    if len(got) < 2:
        return {}
    days = (got[-1][2] - got[0][2]) / 86400.0
    if days < 0.5:
        return {}
    a_day = (got[-1][1] - got[0][1]) / days
    return {"a_day": max(0, int(a_day)), "over_days": int(round(days))}


ERASE = [("events", "the event log", "events",
          "what fake-igd noted about itself and about what was done on these pages: sign-ins, changes, copies, "
          "starts and stops."),
         ("mailq", "the outgoing mail", "mailq",
          "every mail sent and what became of it - the alerts, the reports, the tests. What still waits to be "
          "sent goes with it.")]


# Kept outside the database (1.7.12): erased by root (deploy/root_history.py) - the API may read them, not
# write them. (key, name, file in the log folder or the state folder, says)
ERASE_ROOT = [("requests", "the requests - Ports, Requests, Clients", "requests.jsonl",
               "every SSDP and SOAP request of every device (the request log and its rotated copies): what the "
               "Ports, Requests and Clients tabs, the Overview's chart and the reports are made of."),
              ("log", "the service's log - searches and steps", "fake-igd.log",
               "what fake-igd.service wrote down (and its rotated copies): the devices' searches, how far each "
               "client got, what the service said. The Log tab starts empty."),
              ("mappings", "the mappings", "mappings.json",
               "what the devices believe is open now. fake-igd.service is stopped and started again for it: "
               "for a few seconds the PS5 gets no answer.")]


def _count_lines(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def _root_groups(ctx):
    out = []
    logdir = os.path.dirname(ctx.cfg.get("request_log") or "/var/log/fake-igd/requests.jsonl")
    for key, name, fname, says in ERASE_ROOT:
        if key == "mappings":
            p = os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", fname)
            try:
                with open(p, encoding="utf-8") as f:
                    n = len(json.load(f) or [])
            except (OSError, ValueError, TypeError):
                n = 0
            unit = "mapping(s)"
        else:
            p = ctx.cfg.get("request_log") if key == "requests" else ctx.cfg.get("log_file")
            p = p or os.path.join(logdir, fname)
            n = _count_lines(p)
            unit = "line(s)"
        out.append({"key": key, "name": name, "rows": n or 0, "unit": unit, "says": says, "root": True,
                    "unknown": n is None})
    return out


def erasable(ctx):
    groups = []
    for key, name, table, says in ERASE:
        try:
            n = ctx.store.rows('SELECT COUNT(*) AS n FROM "%s"' % table)[0]["n"]
        except (sqlite3.Error, IndexError, KeyError):
            continue
        groups.append({"key": key, "name": name, "rows": n, "says": says})
    groups += _root_groups(ctx)
    return {"groups": groups, "bytes": db_bytes(ctx), "root": ctx.root_result("history")}


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
    note_size(ctx)
    disk = disk_of(os.path.dirname(p) or ".")
    grew = growth(ctx)
    if disk.get("free") and grew.get("a_day"):
        disk["days_left"] = int(disk["free"] / grew["a_day"])
    disk["holds"] = "the database itself, its copies and its dumps"
    parts = [{"name": os.path.basename(p) + x, "what": w, "bytes": file_size(p + x)}
             for x, w in (("", "the database"), ("-wal", "what is written, not yet folded in"),
                          ("-shm", "the index of that")) if os.path.exists(p + x)]
    parts += [{"name": d, "what": w, "bytes": dir_bytes(d)}
              for d, w in ((folder, "the copies"), (dumps_dir(ctx), "the dumps")) if os.path.isdir(d)]
    counts = {x["table"]: x["rows"] for x in t}
    kp = SEAL.key_path(ctx.store)
    return {"where": p, "size": db_bytes(ctx), "version": version, "tables": t, "free": free, "engine": "sqlite",
            "counts": counts, "copies": copies(ctx), "dumps": dumps(ctx), "dump_dir": dumps_dir(ctx),
            "dump": {"ready": True, "words": "a copy of the file", "suffix": ".db"},
            "keep": int(ctx.setting("db_copy_keep") or 14), "backup_dir": folder,
            "daily": bool(ctx.setting("db_copy_daily")), "at": ctx.setting("db_copy_at"),
            "last_copy": float(last_copy) if last_copy else None,
            "events_keep_days": int(ctx.setting("events_keep_days") or 0),
            "tidied": float(tidied) if tidied else None, "disk": disk, "growth": grew, "parts": parts,
            "key": kp, "key_there": os.path.isfile(kp), "erasable": erasable(ctx),
            "config_file": getattr(__import__("sys").modules.get("__main__"), "CFG_PATH", None)
            or os.environ.get("FAKE_IGD_CONFIG", "/etc/fake-igd/config.json")}


# ---- the routes ------------------------------------------------------------------------
def get_db(ctx):
    return view(ctx)


def _disk_words(e):
    import errno
    if getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
        return "no room left on the disk of the database's folder: %s" % (e.strerror or e)
    return "%s: %s" % (getattr(e, "filename", None) or "a file", e.strerror or e)


def post_db(ctx):
    try:
        return _post_db(ctx)
    except OSError as e:                # no room for a copy, a dump or a download: said (1.7.6)
        if isinstance(e, PermissionError) and e.errno is None:
            raise                       # the role check (read only): a 403, as before
        raise ValueError(_disk_words(e))
    except sqlite3.Error as e:          # "database or disk is full" while a dump is written
        raise ValueError("SQLite could not do it: %s%s" % (e, " - make room on the disk of the database's folder"
                                                         if "full" in str(e) else ""))


def post_upload(ctx):
    try:
        return _post_upload(ctx)
    except OSError as e:
        if isinstance(e, PermissionError) and e.errno is None:
            raise
        raise ValueError(_disk_words(e))


def _post_db(ctx):
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
    if act == "dump":
        name = make_dump(ctx, "now")
        ctx.event("%s made a dump of the database: %s" % (who, name))
        return {"message": "a dump was made: %s" % name, "name": name}
    if act == "delete":
        kind = "dump" if b.get("kind") == "dump" else "copy"
        p = kept_path(ctx, b.get("name"), kind)
        drop_with_key(p)
        ctx.event("%s deleted the %s %s" % (who, kind, os.path.basename(p)), "warn")
        return {"message": "%s is deleted" % os.path.basename(p)}
    if act == "download":
        name = str(b.get("name") or "")
        kind = "dump" if b.get("kind") == "dump" else "copy"
        key_hex = None
        if name:
            p = kept_path(ctx, name, kind)
            with open(p, "rb") as f:
                data = f.read()
            key_hex = key_of(p)
        else:
            fd, raw = tempfile.mkstemp(prefix=".dl-", dir=state_dir(ctx))
            os.close(fd)
            try:
                snapshot(ctx.store, raw)
                with open(raw, "rb") as f:
                    data = f.read() if kind == "dump" else gzip.compress(f.read(), 6)
            finally:
                os.unlink(raw)
            name = ("fake-igd-sqlite-%s-now.db" if kind == "dump" else "fake-igd-%s.db.gz") % time.strftime("%Y%m%d-%H%M%S")
            k = SEAL.key(ctx.store)
            key_hex = k.hex() if k else None
        phrase = b.get("passphrase")
        if phrase is not None:
            phrase = str(phrase)
            if len(phrase) < 10:
                raise ValueError("a passphrase of 10 characters at least")
            if not key_hex:
                raise ValueError("there is no key beside it to put in")
            data = bundle(name, data, key_hex, phrase)
            name = name.replace(".db.gz", "").replace(".db", "") + "-with-key.tar"
        ctx.event("%s downloaded the database (%s)%s" % (who, name, " with its key, locked with a passphrase"
                                                          if phrase is not None else ""), "warn")
        return {"name": name, "bytes": len(data), "data": base64.b64encode(data).decode("ascii")}
    if act == "restore_kept":
        kind = "dump" if b.get("kind") == "dump" else "copy"
        p = kept_path(ctx, b.get("name"), kind)
        work = tempfile.mkdtemp(prefix=".restore-", dir=state_dir(ctx))
        try:
            plain = os.path.join(work, "db")
            unpack(p, plain)
            if b.get("check"):
                return {"says": dict(read_db(plain), kind=kind)}
            return restore_from(ctx, plain, os.path.basename(p), key_of(p))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if act == "restore_upload":
        up = str(b.get("upload") or "")
        if not UPLOAD_RE.match(up):
            raise ValueError("no such file sent")
        p = os.path.join(copies_dir(ctx), up)
        if not os.path.isfile(p):
            raise ValueError("the file sent is gone (an hour passed?) - send it again")
        key_hex = None
        work = None
        try:
            if up.endswith(".tar"):
                work = tempfile.mkdtemp(prefix=".restore-", dir=state_dir(ctx))
                plain, locked = unbundle(p, work)
                key_hex = open_key(locked, str(b.get("passphrase") or ""))
            else:
                plain = p
            if b.get("check"):
                return {"says": read_db(plain)}
            out = restore_from(ctx, plain, str(b.get("file") or "a file sent")[:120], key_hex)
        finally:
            if work:
                shutil.rmtree(work, ignore_errors=True)
        try:
            os.unlink(p)
        except OSError:
            pass
        return out
    if act == "erase":
        picked = [g for g in (b.get("groups") or []) if isinstance(g, str)]
        known = {k: (n, t) for k, n, t, _s in ERASE}
        rooted = {k: n for k, n, _f, _s in ERASE_ROOT}
        if not picked or any(g not in known and g not in rooted for g in picked):
            raise ValueError("nothing known to erase")
        to_root = [g for g in picked if g in rooted]
        picked = [g for g in picked if g in known]
        ident = None
        if to_root:
            ident = ctx.ask_root({"what": to_root}, kind="history")
            ctx.event("%s asked root to erase %s" % (who, ", ".join(rooted[g] for g in to_root)), "warn")
        if not picked:
            return {"erased": [], "root": ident, "message": "asked root to erase %s - done within seconds"
                    % ", ".join(rooted[g] for g in to_root)}
        safety = make_copy(ctx, "before-restore")
        done = []
        for g in picked:
            n = ctx.store.run('DELETE FROM "%s"' % known[g][1]).rowcount
            done.append("%s (%d)" % (known[g][0], n))
        before = db_bytes(ctx)
        after = before
        if b.get("tidy"):
            with ctx.store.lock:
                ctx.store.db.execute("VACUUM")
                try:
                    ctx.store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
            after = db_bytes(ctx)
        ctx.event("%s erased the collected data: %s; a copy was made first: %s" % (who, ", ".join(done), safety),
                  "warn")
        return {"erased": done, "copy": safety, "before": before, "after": after, "root": ident,
                "message": "erased; a copy was made first: %s%s" % (
                    safety, "; root erases %s within seconds" % ", ".join(rooted[g] for g in to_root) if to_root else "")}
    raise ValueError("no such action")


def _post_upload(ctx):
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
    if len(data) > 262 and data[257:262] == b"ustar":            # a copy with its key: the passphrase opens it
        up = "upload-%s.tar" % secrets.token_hex(8)
        with open(os.path.join(folder, up), "wb") as f:
            f.write(data)
        return {"upload": up, "locked": True}
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
    try:
        SEAL.key(ctx.store, make=True)                  # the key beside the database, as otp makes it at its start
    except OSError as e:
        ctx.event("the key that seals the secrets: %s" % e, "warn")
    if ctx.setting("db_copy_daily"):
        at = str(ctx.setting("db_copy_at") or "03:30")
        today = time.strftime("%Y-%m-%d")
        if HHMM_RE.match(at) and time.strftime("%H:%M") >= at and ctx.store.get_meta("db:copy:day") != today:
            ctx.store.set_meta("db:copy:day", today)
            try:
                name = make_copy(ctx)
                ctx.store.set_meta("db:copy:at", str(now))
                ctx.event("the nightly copy of the database was made: %s" % name)
                name = make_dump(ctx, "daily")
                ctx.event("the nightly dump of the database was made: %s" % name)
            except (OSError, sqlite3.Error) as e:
                ctx.event("the nightly copy of the database could not be made: %s" % e, "warn")
    last = float(ctx.store.get_meta("db:tidy:at") or 0)
    if now - last >= TIDY_EVERY_S:
        tidy(ctx)
    tidy_uploads(ctx)
    note_size(ctx)
