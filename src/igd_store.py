"""igd_store.py - what fake-igd keeps in its database (1.4.0).

One SQLite file, /var/lib/fake-igd/fake-igd.db, owned by the fake-igd account:

  users      the local accounts of the web pages - a name, a role, a password
             hash (scrypt), when it was made and last signed in
  sessions   who is signed in now - only the SHA-256 of each session's token
             is kept, the token itself lives in the browser's cookie alone
  fails      wrong passwords, by address and by name: too many in a while and
             signing in from there is refused until the while is over
  events     what was done - an account made, a setting changed, an upgrade
             asked for, a sign-in - by whom and from where
  meta       small values: the last look for a new version, and the like

Used by the API (fake_igd_api.py, as the fake-igd account) and by the
command line (`upnp user ...`, which root runs as the fake-igd account too, so
the file never becomes root's). Only the standard library.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time

DB_FILE = os.environ.get("FAKE_IGD_DB", "/var/lib/fake-igd/fake-igd.db")
ROLES = ("fulladmin", "readonly")
ROLE_WORDS = {"fulladmin": "full admin", "readonly": "read only"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")
SCRYPT_N, SCRYPT_R, SCRYPT_P = 16384, 8, 1
MIN_PASSWORD = 8
SESSION_MOST_S = 24 * 3600            # a sign-in lasts a day at most
FAIL_WINDOW_S = 600                   # wrong passwords counted over ten minutes
FAIL_MOST_ADDR = 10                   # ... from one address
FAIL_MOST_NAME = 6                    # ... for one name
EVENTS_KEPT = 20000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    name TEXT PRIMARY KEY COLLATE NOCASE,
    role TEXT NOT NULL,
    hash TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    must_change INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL,
    changed REAL NOT NULL,
    last_login REAL,
    last_from TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL COLLATE NOCASE,
    created REAL NOT NULL,
    seen REAL NOT NULL,
    addr TEXT NOT NULL DEFAULT '',
    agent TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS fails (
    at REAL NOT NULL,
    addr TEXT NOT NULL,
    name TEXT NOT NULL COLLATE NOCASE
);
CREATE INDEX IF NOT EXISTS fails_at ON fails(at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    kind TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    who TEXT NOT NULL DEFAULT '',
    addr TEXT NOT NULL DEFAULT '',
    words TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events(at);
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""


class StoreError(ValueError):
    """Something asked of the store that it says no to - the words are for the person."""


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=64 * 1024 * 1024, dklen=32)
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P,
                                      base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(password, stored):
    try:
        kind, n, r, p, salt, want = str(stored).split("$")
        if kind != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r),
                            p=int(p), maxmem=64 * 1024 * 1024, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, base64.b64decode(want))


# A hash to check a name nobody has against: the same time spent as for a real one, so the
# answer's speed does not say which names exist.
_DUMMY = []


def _dummy_hash():
    if not _DUMMY:
        _DUMMY.append(hash_password(secrets.token_hex(8)))
    return _DUMMY[0]


def password_problem(pw):
    if len(pw) < MIN_PASSWORD:
        return "a password needs at least %d characters" % MIN_PASSWORD
    if len(pw) > 256:
        return "that password is longer than 256 characters"
    return ""


def _sid(token):
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


class Store(object):
    def __init__(self, path=None):
        self.path = path or DB_FILE
        self.lock = threading.RLock()
        folder = os.path.dirname(self.path) or "."
        if not os.path.isdir(folder):
            raise StoreError("the folder of the database is not there: %s" % folder)
        old_umask = os.umask(0o027)
        try:
            self.db = sqlite3.connect(self.path, timeout=15, check_same_thread=False, isolation_level=None)
        finally:
            os.umask(old_umask)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        with self.lock:
            self.db.executescript(SCHEMA)

    # ---- the bare minimum ------------------------------------------------------------
    def rows(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        got = self.rows(sql, args)
        return got[0] if got else None

    def run(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args)

    def close(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass

    def ok(self):
        try:
            self.one("SELECT 1 AS x")
            return True
        except sqlite3.Error:
            return False

    # ---- meta ------------------------------------------------------------------------
    def get_meta(self, k, default=None):
        r = self.one("SELECT v FROM meta WHERE k = ?", (k,))
        return r["v"] if r else default

    def set_meta(self, k, v):
        self.run("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, v))

    def meta_json(self, k):
        try:
            got = json.loads(self.get_meta(k) or "null")
        except ValueError:
            return None
        return got if isinstance(got, dict) else None

    # ---- events ----------------------------------------------------------------------
    def add_event(self, kind, words, level="info", who="", addr=""):
        self.run("INSERT INTO events (at, kind, level, who, addr, words) VALUES (?, ?, ?, ?, ?, ?)",
                 (time.time(), str(kind)[:40], str(level)[:8], str(who or "")[:80], str(addr or "")[:64],
                  str(words)[:2000]))
        if secrets.randbelow(200) == 0:
            self.run("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (EVENTS_KEPT,))

    def events(self, q="", kind="", since=0.0, limit=100, offset=0, until=0.0):
        where, args = ["at >= ?"], [float(since or 0)]
        if until:
            where.append("at <= ?")
            args.append(float(until))
        if kind:
            where.append("kind = ?")
            args.append(kind)
        if q:
            where.append("(words LIKE ? OR who LIKE ? OR addr LIKE ? OR kind LIKE ?)")
            args += ["%" + q + "%"] * 4
        sql = " WHERE " + " AND ".join(where)
        total = self.one("SELECT COUNT(*) AS n FROM events" + sql, args)["n"]
        rows = self.rows("SELECT * FROM events" + sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
                         args + [int(limit), int(offset)])
        kinds = [r["kind"] for r in self.rows("SELECT DISTINCT kind FROM events ORDER BY kind")]
        return {"events": rows, "total": total, "kinds": kinds}

    # ---- accounts --------------------------------------------------------------------
    def users(self):
        rows = self.rows("SELECT name, role, note, must_change, created, changed, last_login, last_from "
                         "FROM users ORDER BY name COLLATE NOCASE")
        now = time.time()
        live = {}
        for s in self.rows("SELECT name, COUNT(*) AS n FROM sessions WHERE seen > ? GROUP BY name COLLATE NOCASE",
                           (now - SESSION_MOST_S,)):
            live[s["name"].lower()] = s["n"]
        for r in rows:
            r["role_words"] = ROLE_WORDS.get(r["role"], r["role"])
            r["sessions"] = live.get(r["name"].lower(), 0)
            r["must_change"] = bool(r["must_change"])
        return rows

    def user(self, name):
        return self.one("SELECT * FROM users WHERE name = ?", (str(name),))

    def count_users(self):
        return self.one("SELECT COUNT(*) AS n FROM users")["n"]

    def count_admins(self):
        return self.one("SELECT COUNT(*) AS n FROM users WHERE role = 'fulladmin'")["n"]

    def add_user(self, name, password, role="fulladmin", note="", must_change=False):
        name = str(name or "").strip()
        if not NAME_RE.match(name):
            raise StoreError("a name of letters, digits and . _ @ - (64 at most), starting with a letter or digit")
        if role not in ROLES:
            raise StoreError("the role is one of: %s" % ", ".join(ROLES))
        bad = password_problem(password)
        if bad:
            raise StoreError(bad)
        if self.user(name):
            raise StoreError("%s is there already" % name)
        now = time.time()
        self.run("INSERT INTO users (name, role, hash, note, must_change, created, changed) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (name, role, hash_password(password), str(note or "")[:200], 1 if must_change else 0, now, now))
        return self.user(name)

    def set_password(self, name, password, must_change=False):
        if not self.user(name):
            raise StoreError("there is no account %s" % name)
        bad = password_problem(password)
        if bad:
            raise StoreError(bad)
        self.run("UPDATE users SET hash = ?, must_change = ?, changed = ? WHERE name = ?",
                 (hash_password(password), 1 if must_change else 0, time.time(), name))

    def set_role(self, name, role):
        u = self.user(name)
        if not u:
            raise StoreError("there is no account %s" % name)
        if role not in ROLES:
            raise StoreError("the role is one of: %s" % ", ".join(ROLES))
        if u["role"] == "fulladmin" and role != "fulladmin" and self.count_admins() <= 1:
            raise StoreError("%s is the last full admin - make another one first" % name)
        self.run("UPDATE users SET role = ?, changed = ? WHERE name = ?", (role, time.time(), name))

    def set_note(self, name, note):
        if not self.user(name):
            raise StoreError("there is no account %s" % name)
        self.run("UPDATE users SET note = ?, changed = ? WHERE name = ?", (str(note or "")[:200], time.time(), name))

    def delete_user(self, name):
        u = self.user(name)
        if not u:
            raise StoreError("there is no account %s" % name)
        if u["role"] == "fulladmin" and self.count_admins() <= 1:
            raise StoreError("%s is the last full admin - make another one first" % name)
        self.run("DELETE FROM sessions WHERE name = ?", (name,))
        self.run("DELETE FROM users WHERE name = ?", (name,))

    # ---- signing in ------------------------------------------------------------------
    def too_many(self, addr, name):
        since = time.time() - FAIL_WINDOW_S
        a = self.one("SELECT COUNT(*) AS n FROM fails WHERE at > ? AND addr = ?", (since, addr))["n"]
        n = self.one("SELECT COUNT(*) AS n FROM fails WHERE at > ? AND name = ?", (since, name))["n"]
        return a >= FAIL_MOST_ADDR or n >= FAIL_MOST_NAME

    def login(self, name, password, addr="", agent="", idle_s=7200):
        """(token, user) - or StoreError with the words for the sign-in page."""
        name = str(name or "").strip()[:64]
        addr = str(addr or "")[:64]
        self.run("DELETE FROM fails WHERE at < ?", (time.time() - FAIL_WINDOW_S,))
        if self.too_many(addr, name):
            check_password(password, _dummy_hash())
            raise StoreError("too many wrong passwords - wait ten minutes and try again")
        u = self.user(name) if name else None
        if not u or not check_password(password, u["hash"]):
            if not u:
                check_password(password, _dummy_hash())
            self.run("INSERT INTO fails (at, addr, name) VALUES (?, ?, ?)", (time.time(), addr, name))
            raise StoreError("wrong name or password")
        self.run("DELETE FROM fails WHERE name = ?", (u["name"],))
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.run("INSERT INTO sessions (id, name, created, seen, addr, agent) VALUES (?, ?, ?, ?, ?, ?)",
                 (_sid(token), u["name"], now, now, addr, str(agent or "")[:200]))
        self.run("UPDATE users SET last_login = ?, last_from = ? WHERE name = ?", (now, addr, u["name"]))
        self.tidy_sessions(idle_s)
        return token, u

    def session(self, token, idle_s=7200, touch=True):
        """The account of a session that is still good, or None."""
        if not token:
            return None
        sid = _sid(token)
        s = self.one("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not s:
            return None
        now = time.time()
        if now - s["seen"] > idle_s or now - s["created"] > SESSION_MOST_S:
            self.run("DELETE FROM sessions WHERE id = ?", (sid,))
            return None
        u = self.user(s["name"])
        if not u:
            self.run("DELETE FROM sessions WHERE id = ?", (sid,))
            return None
        if touch and now - s["seen"] > 15:
            self.run("UPDATE sessions SET seen = ? WHERE id = ?", (now, sid))
        u = dict(u)
        u.pop("hash", None)
        u["session"] = sid[:12]
        u["session_started"] = s["created"]
        return u

    def logout(self, token):
        self.run("DELETE FROM sessions WHERE id = ?", (_sid(token),))

    def sessions(self):
        return self.rows("SELECT substr(id, 1, 12) AS id, name, created, seen, addr, agent FROM sessions "
                         "ORDER BY seen DESC")

    def end_session(self, short_id):
        if not re.match(r"^[0-9a-f]{6,64}\Z", str(short_id or "")):
            raise StoreError("no such sign-in")
        n = self.run("DELETE FROM sessions WHERE substr(id, 1, ?) = ?", (len(short_id), short_id)).rowcount
        if not n:
            raise StoreError("no such sign-in")

    def tidy_sessions(self, idle_s=7200):
        now = time.time()
        self.run("DELETE FROM sessions WHERE seen < ? OR created < ?", (now - idle_s, now - SESSION_MOST_S))
