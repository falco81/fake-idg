"""igd_store.py - what fake-igd keeps in its database (1.4.0; accounts as otp's, 1.6.1).

One SQLite file, /var/lib/fake-igd/fake-igd.db, owned by the fake-igd account:

  users      the local accounts of the web pages - a name, a role, a password
             hash (scrypt), when it was made and last signed in, switched off
             or not, its second step of signing in (an authenticator app), and the
             passkeys of its devices that sign it in by themselves (their public
             halves only, users.passkeys, 1.9.7)
  sessions   who is signed in now - only the SHA-256 of each session's token
             is kept, the token itself lives in the browser's cookie alone; a
             sign-in still to give its second step is kept too, and is good
             for nothing else
  fails      wrong passwords and codes, by address and by name: too many in a
             while and signing in from there is refused until the while is over
  challenges the questions asked of a passkey before anybody is signed in (1.9.7): each
             taken by one answer, from the address that asked, within five minutes
  events     what was done - an account made, a setting changed, an upgrade
             asked for, a sign-in - by whom and from where
  meta       small values: the last look for a new version, and the like

Used by the API (fake_igd_api.py, as the fake-igd account) and by the
command line (`upnp user ...`, which root runs as the fake-igd account too, so
the file never becomes root's). Only the standard library.

How long a sign-in lasts, how many wrong attempts lock out and for how long,
how long a password must be and whether a second step is asked are the
settings of the Accounts pane (api_people.py), kept in meta "settings" with
every module's - read here (policy()) so the API and the command line agree.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import struct
import threading
import time

DB_FILE = os.environ.get("FAKE_IGD_DB", "/var/lib/fake-igd/fake-igd.db")
ROLES = ("fulladmin", "readonly")
ROLE_WORDS = {"fulladmin": "full admin", "readonly": "read only"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")
SCRYPT_N, SCRYPT_R, SCRYPT_P = 16384, 8, 1
MIN_PASSWORD = 8
SESSION_MOST_S = 24 * 3600            # a sign-in lasts a day at most (as it came before 1.6.1)
OWN_SPAN_S = 300                      # one's own password typed wrong where it is changed: counted 5 min (otp)
FAIL_WINDOW_S = 600                   # wrong passwords counted over ten minutes (as it came before 1.6.1)
FAIL_MOST_ADDR = 10                   # ... from one address
FAIL_MOST_NAME = 6                    # ... for one name
EVENTS_KEPT = 20000
PENDING_MOST_S = 900                  # a sign-in waiting for its second step: a quarter of an hour
MFA_WINDOW = 1                        # an app's code taken one period either side (clocks a little apart)

# The settings of the Accounts pane (api_people.py), as they come - otp's.
POLICY = {
    "session_hours": 12,              # a sign-in lasts, however busy
    "session_idle_min": 120,          # ... and may sit untouched
    "login_tries": 5,                 # wrong passwords for one name before a pause (an address: 10x, 50 at least)
    "login_wait_min": 15,             # ... and the pause
    "password_min": MIN_PASSWORD,     # a password of these accounts at least this long
    "admin_2fa": False,               # a second step (an authenticator app) after the password
    "passkey_signin": False,          # signing in with a passkey alone: Face ID, Touch ID, Windows Hello (1.9.7)
}
PASSKEY_MOST = 10                     # passkeys of one account (otp 1.0.257)
CHALLENGE_S = 300                     # a passkey's question is good this long (igd_webauthn.WA_CHALLENGE_S)
CHALLENGE_MOST_ADDR = 20              # questions waiting from one address - asked by nobody signed in
CHALLENGE_MOST = 2000                 # ... and from all of them

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
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    at REAL NOT NULL,
    addr TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""
# Columns added since 1.4.0, put into an older database when it opens.
COLUMNS = (
    ("users", "disabled", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "mfa", "TEXT NOT NULL DEFAULT ''"),
    ("sessions", "mfa", "TEXT NOT NULL DEFAULT ''"),
    ("sessions", "data", "TEXT NOT NULL DEFAULT ''"),
    ("fails", "what", "TEXT NOT NULL DEFAULT ''"),
    ("users", "passkeys", "TEXT NOT NULL DEFAULT ''"),
)


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


def password_problem(pw, least=None):
    least = int(least or MIN_PASSWORD)
    if len(pw) < least:
        return "a password needs at least %d characters" % least
    if len(pw) > 256:
        return "that password is longer than 256 characters"
    return ""


# ---- the second step: an authenticator app (RFC 4226 / RFC 6238, as otp's) -----------------
def b32_clean(text):
    """A base32 key as somebody may have written it - small letters, spaces, no padding."""
    said = re.sub(r"[\s\-]", "", str(text or "")).upper().rstrip("=")
    if not said or not re.match(r"^[A-Z2-7]+\Z", said):
        raise ValueError("that is not a base32 key (A-Z and 2-7)")
    return base64.b32decode(said + "=" * ((8 - len(said) % 8) % 8))


def b32_new(size=20):
    """A fresh key: 160 bits, the size RFC 4226 recommends, as base32."""
    return base64.b32encode(secrets.token_bytes(size)).decode("ascii").rstrip("=")


def hotp(key, counter, digits=6):
    if isinstance(key, str):
        key = b32_clean(key)
    mac = hmac.new(key, struct.pack(">Q", int(counter)), hashlib.sha1).digest()
    at = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[at:at + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** int(digits))).zfill(int(digits))


def totp_step(when=None, period=30):
    return int((time.time() if when is None else float(when)) // int(period))


def totp(key, when=None, digits=6, period=30):
    return hotp(key, totp_step(when, period), digits)


def code_typed(code):
    """A code as somebody typed it: "123 456", "123-456" - the digits meant."""
    import unicodedata
    return "".join(c for c in str(code or "")
                   if not (c.isspace() or c in "\u2212\u00ad\u200b" or unicodedata.category(c) == "Pd"))


def totp_match(key, code, when=None, digits=6, period=30, window=MFA_WINDOW):
    """The period (step) the code belongs to, the nearest first - or None. Constant time each."""
    code = code_typed(code)
    if not re.match(r"^[0-9]+\Z", code) or len(code) != int(digits):
        return None
    if isinstance(key, str):
        key = b32_clean(key)
    here = totp_step(when, period)
    found = None
    for off in [0] + [d for i in range(1, int(window) + 1) for d in (-i, i)]:
        if hmac.compare_digest(hotp(key, here + off, digits), code) and found is None:
            found = here + off
    return found


def otpauth_uri(secret, label, issuer):
    """What the QR code holds: otpauth://totp/Issuer:label?secret=...&issuer=..."""
    from urllib.parse import quote
    issuer = str(issuer or "").strip()
    who = (quote(issuer, safe="") + ":" if issuer else "") + quote(str(label), safe="@.")
    args = ["secret=" + str(secret).upper().replace("=", "")]
    if issuer:
        args.append("issuer=" + quote(issuer, safe=""))
    return "otpauth://totp/%s?%s" % (who, "&".join(args))


def _jload(text):
    try:
        got = json.loads(text or "{}")
    except ValueError:
        return {}
    return got if isinstance(got, dict) else {}


def _jlist(text):
    try:
        got = json.loads(text or "[]")
    except ValueError:
        return []
    return [k for k in got if isinstance(k, dict)] if isinstance(got, list) else []


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
        self._policy = (0.0, None)
        self.migrate()

    def migrate(self):
        """The tables and columns of this version put into the database, and what an older version kept
        moved - when it opens, and again after a database is put back in its place (1.9.9: one of an older
        version, put back by Settings → Database or Backups, lacked the newer columns until the API was
        restarted - signing in broke on "no such column"). Does nothing to a database that has them."""
        with self.lock:
            self.db.executescript(SCHEMA)
            for table, col, kind in COLUMNS:
                have = [r[1] for r in self.db.execute("PRAGMA table_info(%s)" % table).fetchall()]
                if col not in have:
                    try:
                        self.db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, kind))
                    except sqlite3.OperationalError as e:
                        # Added a moment ago by the other one opening it (the API and `upnp user` at once).
                        if "duplicate column" not in str(e):
                            raise
        self._policy = (0.0, None)
        self._passkeys_moved()

    def _passkeys_moved(self):
        """1.9.2-1.9.6 kept passkeys as the second step (users.mfa {"kind": "passkey", "keys"}) under
        the setting admin_2fa_passkey. From 1.9.7 a passkey signs in by itself: the keys move to the
        account's own users.passkeys (never lost - merged with what is there), the second step is
        cleared (with admin_2fa on, the app is set up at the next sign-in with the password), and
        the setting becomes passkey_signin. Once; nothing to do after."""
        with self.lock:
            moved = []
            for r in self.db.execute("SELECT name, mfa, passkeys FROM users WHERE mfa LIKE '%passkey%'").fetchall():
                m = _jload(r["mfa"])
                if m.get("kind") != "passkey":
                    continue
                have = _jlist(r["passkeys"])
                ids = set(k.get("id") for k in have)
                for k in m.get("keys") or []:
                    if isinstance(k, dict) and k.get("id") and k["id"] not in ids:
                        have.append(k)
                        ids.add(k["id"])
                self.db.execute("UPDATE users SET passkeys = ?, mfa = '' WHERE name = ?",
                                (json.dumps(have), r["name"]))
                moved.append((r["name"], len(have)))
            raw = self.db.execute("SELECT v FROM meta WHERE k = 'settings'").fetchone()
            saved = _jload(raw["v"]) if raw else {}
            if "admin_2fa_passkey" in saved:
                if "passkey_signin" not in saved:
                    saved["passkey_signin"] = bool(saved["admin_2fa_passkey"])
                del saved["admin_2fa_passkey"]
                self.db.execute("UPDATE meta SET v = ? WHERE k = 'settings'", (json.dumps(saved),))
        for name, n in moved:
            self.add_event("account", "the passkeys of %s (%d) sign in by themselves now - no longer the second "
                           "step; the second step of %s is set up again (the app)" % (name, n, name), "warn", name)

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
        if k == "settings":
            self._policy = (0.0, None)
        self.run("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, v))

    def meta_json(self, k):
        try:
            got = json.loads(self.get_meta(k) or "null")
        except ValueError:
            return None
        return got if isinstance(got, dict) else None

    # ---- the settings of the Accounts pane ------------------------------------------------
    def policy(self, fresh=False):
        """POLICY as saved on the pages (meta "settings"), with "idle_saved": whether the idle
        time was saved there - until it is, the API's own (config.json's) holds."""
        at, got = self._policy
        if got is not None and not fresh and time.time() - at < 2:
            return got
        saved = _jload(self.get_meta("settings"))
        got = dict(POLICY)
        for k, v in POLICY.items():
            if k in saved:
                try:
                    got[k] = bool(saved[k]) if isinstance(v, bool) else int(saved[k])
                except (TypeError, ValueError):
                    pass
        got["idle_saved"] = "session_idle_min" in saved
        self._policy = (time.time(), got)
        return got

    def _idle(self, idle_s):
        p = self.policy()
        if p["idle_saved"] or not idle_s:
            return 60 * max(1, int(p["session_idle_min"]))
        return int(idle_s)

    def _most(self):
        return 3600 * max(1, int(self.policy()["session_hours"]))

    def password_problem(self, pw):
        return password_problem(pw, self.policy()["password_min"])

    def fail_limits(self, own=False):
        """(span s, tries for a name, tries for an address) - otp's throttle: a name may make four
        times "Wrong passwords before a pause", an address ten times as many (50 at least), so an
        office behind one address is not locked out by one person's typos. `own`: one's own
        password typed wrong where it is changed (otp's kind "password") - a count of its own, never
        the sign-in's: five minutes, the setting's tries for an address and four times it for a name."""
        p = self.policy()
        tries = max(1, int(p["login_tries"]))
        if own:
            return OWN_SPAN_S, tries * 4, tries
        return 60 * max(1, int(p["login_wait_min"])), tries * 4, max(50, tries * 10)

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
            kinds = [kind] if isinstance(kind, str) else [str(k) for k in kind]
            where.append("kind IN (%s)" % ",".join("?" * len(kinds)))
            args += kinds
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
        rows = self.rows("SELECT name, role, note, must_change, created, changed, last_login, last_from, "
                         "disabled, mfa, passkeys FROM users ORDER BY name COLLATE NOCASE")
        now = time.time()
        live = {}
        for s in self.rows("SELECT name, COUNT(*) AS n FROM sessions WHERE seen > ? AND mfa = '' "
                           "GROUP BY name COLLATE NOCASE", (now - self._idle(0),)):
            live[s["name"].lower()] = s["n"]
        for r in rows:
            r["role_words"] = ROLE_WORDS.get(r["role"], r["role"])
            r["sessions"] = live.get(r["name"].lower(), 0)
            r["must_change"] = bool(r["must_change"])
            r["disabled"] = bool(r["disabled"])
            m = _jload(r["mfa"])
            r["mfa"] = {"kind": m.get("kind"), "at": m.get("at")} if m.get("kind") else None
            # The passkeys that sign it in (1.9.7): how many, and which device for which name.
            keys = _jlist(r.pop("passkeys"))
            r["passkeys"] = len(keys)
            r["passkeys_said"] = ", ".join("%s \u00b7 %s" % (k.get("name") or "a device", k.get("host") or "?")
                                           for k in keys)
        return rows

    def user(self, name):
        return self.one("SELECT * FROM users WHERE name = ?", (str(name),))

    def count_users(self):
        return self.one("SELECT COUNT(*) AS n FROM users")["n"]

    def count_admins(self):
        """Full admins who can sign in (not switched off)."""
        return self.one("SELECT COUNT(*) AS n FROM users WHERE role = 'fulladmin' AND disabled = 0")["n"]

    def _last_admin(self, u):
        """Is `u` a full admin with no other full admin left who can sign in?"""
        if u["role"] != "fulladmin":
            return False
        n = self.one("SELECT COUNT(*) AS n FROM users WHERE role = 'fulladmin' AND disabled = 0 AND name <> ?",
                     (u["name"],))["n"]
        return n == 0

    def add_user(self, name, password, role="fulladmin", note="", must_change=False):
        name = str(name or "").strip()
        if not NAME_RE.match(name):
            raise StoreError("a name of letters, digits and . _ @ - (64 at most), starting with a letter or digit")
        if role not in ROLES:
            raise StoreError("the role is one of: %s" % ", ".join(ROLES))
        bad = self.password_problem(password)
        if bad:
            raise StoreError(bad)
        hashed = hash_password(password)
        with self.lock:                     # two pages making the same name at once: one is told so
            if self.user(name):
                raise StoreError("%s is there already" % name)
            now = time.time()
            self.run("INSERT INTO users (name, role, hash, note, must_change, created, changed) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (name, role, hashed, str(note or "")[:200], 1 if must_change else 0, now, now))
            return self.user(name)

    def set_password(self, name, password, must_change=False):
        if not self.user(name):
            raise StoreError("there is no account %s" % name)
        bad = self.password_problem(password)
        if bad:
            raise StoreError(bad)
        self.run("UPDATE users SET hash = ?, must_change = ?, changed = ? WHERE name = ?",
                 (hash_password(password), 1 if must_change else 0, time.time(), name))

    def set_must_change(self, name, on=True):
        if not self.user(name):
            raise StoreError("there is no account %s" % name)
        self.run("UPDATE users SET must_change = ?, changed = ? WHERE name = ?", (1 if on else 0, time.time(), name))

    def set_role(self, name, role):
        with self.lock:
            u = self.user(name)
            if not u:
                raise StoreError("there is no account %s" % name)
            if role not in ROLES:
                raise StoreError("the role is one of: %s" % ", ".join(ROLES))
            if role != "fulladmin" and self._last_admin(u):
                raise StoreError("%s is the last full admin who can sign in - make another one first" % name)
            self.run("UPDATE users SET role = ?, changed = ? WHERE name = ?", (role, time.time(), name))

    def set_note(self, name, note):
        if not self.user(name):
            raise StoreError("there is no account %s" % name)
        self.run("UPDATE users SET note = ?, changed = ? WHERE name = ?", (str(note or "")[:200], time.time(), name))

    def set_disabled(self, name, off=True):
        """Switched off: it cannot sign in, and its sign-ins now are ended."""
        with self.lock:
            u = self.user(name)
            if not u:
                raise StoreError("there is no account %s" % name)
            if off and not u["disabled"] and self._last_admin(u):
                raise StoreError("%s is the last full admin who can sign in - make another one first" % name)
            self.run("UPDATE users SET disabled = ?, changed = ? WHERE name = ?", (1 if off else 0, time.time(), name))
            if off:
                self.end_sessions_of(name)

    def delete_user(self, name):
        with self.lock:
            u = self.user(name)
            if not u:
                raise StoreError("there is no account %s" % name)
            if self._last_admin(u) and not u["disabled"]:
                raise StoreError("%s is the last full admin who can sign in - make another one first" % name)
            self.run("DELETE FROM sessions WHERE name = ?", (name,))
            self.run("DELETE FROM users WHERE name = ?", (name,))

    def sign_ins(self, name, limit=50):
        """The sign-ins of one account, and the refused ones, as the events wrote them."""
        return self.rows("SELECT at, level, addr, words FROM events WHERE kind = 'sign-in' AND who = ? "
                         "COLLATE NOCASE ORDER BY id DESC LIMIT ?", (str(name), int(limit)))

    # ---- passkeys: a sign-in by themselves (1.9.7) -----------------------------------------
    # The account's own, in its row (users.passkeys, a JSON list) - so a backup of the database has
    # them; never touched by a reset of the second step:
    #   [{"id", "alg", "pub", "count", "host", "name", "at", "used", "backed_up"}]
    def passkeys(self, name):
        u = self.user(name)
        return _jlist(u["passkeys"]) if u else []

    def passkeys_put(self, name, keys):
        self.run("UPDATE users SET passkeys = ? WHERE name = ?", (json.dumps(list(keys)), name))

    def passkey_find(self, cred_id):
        """(account, its key) of a passkey's credential ID among every account - or (None, None)."""
        cid = str(cred_id or "")
        if not cid:
            return None, None
        for u in self.rows("SELECT * FROM users WHERE passkeys <> ''"):
            for k in _jlist(u["passkeys"]):
                if hmac.compare_digest(str(k.get("id") or "").encode(), cid.encode()):
                    return u, k
        return None, None

    def passkeys_remove(self, name):
        """Every passkey of an account taken away (Accounts, upnp user passkeys NAME --remove-all): how many.
        The sign-ins they opened end with them (1.9.9): taken away for a lost phone, the phone stayed
        signed in for the rest of the sign-in's hours."""
        u = self.user(name)
        if not u:
            raise StoreError("there is no account %s" % name)
        n = len(_jlist(u["passkeys"]))
        self.run("UPDATE users SET passkeys = '', changed = ? WHERE name = ?", (time.time(), name))
        self.end_passkey_sessions(u["name"])
        return n

    def end_passkey_sessions(self, name, key_id=None, but_token=None):
        """The sign-ins of an account opened by a passkey - by that one (key_id), or by any - ended, but
        but_token's (1.9.9). How many."""
        but = _sid(but_token) if but_token else ""
        gone = 0
        with self.lock:
            for s in self.rows("SELECT id, data FROM sessions WHERE name = ? AND mfa = ''", (str(name),)):
                d = _jload(s["data"])
                if d.get("by") != "passkey" or s["id"] == but:
                    continue
                # A sign-in of 1.9.7-1.9.8 does not say which key opened it: ended with any of them.
                if key_id is not None and d.get("key") not in (None, key_id):
                    continue
                gone += self.run("DELETE FROM sessions WHERE id = ?", (s["id"],)).rowcount
        return gone

    def challenge_put(self, addr, data):
        """A passkey's question asked before anybody is signed in (1.9.7), kept for its one answer:
        bound to the address, five minutes. Bounded: 20 waiting from an address, 2000 in all."""
        now = time.time()
        addr = str(addr or "")[:64]
        with self.lock:
            self.run("DELETE FROM challenges WHERE at < ?", (now - CHALLENGE_S,))
            if self.one("SELECT COUNT(*) AS n FROM challenges WHERE addr = ?", (addr,))["n"] >= CHALLENGE_MOST_ADDR:
                self.run("DELETE FROM challenges WHERE id IN (SELECT id FROM challenges WHERE addr = ? ORDER BY at "
                         "LIMIT 1)", (addr,))
            if self.one("SELECT COUNT(*) AS n FROM challenges")["n"] >= CHALLENGE_MOST:
                raise StoreError("too many sign-ins with a passkey at once - try again in a moment")
            self.run("INSERT INTO challenges (id, at, addr, data) VALUES (?, ?, ?, ?)",
                     (str(data["challenge"]), now, addr, json.dumps(data)))

    def challenge_take(self, ident, addr):
        """The question, taken away by its answer - from the address that asked it, in its time. None
        otherwise (an old question, another address, or answered already)."""
        ident = str(ident or "")[:100]
        with self.lock:
            r = self.one("SELECT at, addr, data FROM challenges WHERE id = ?", (ident,))
            if not r:
                return None
            if r["addr"] != str(addr or "")[:64]:
                return None                 # left where it is: its own address may still answer it
            self.run("DELETE FROM challenges WHERE id = ?", (ident,))
        if time.time() - r["at"] > CHALLENGE_S:
            return None
        return _jload(r["data"])

    def passkey_login(self, name, key, addr="", agent="", idle_s=7200):
        """A sign-in opened by a passkey (checked by igd_webauthn - the face, a finger or the PIN
        verified): whole by itself, never a second step asked (1.9.7). The key, its counter moved on,
        kept; the token of a new sign-in returned."""
        with self.lock:
            u = self.user(name)
            if not u or u["disabled"]:
                raise StoreError("that passkey signs nobody in here")
            keys = _jlist(u["passkeys"])
            if not any(k.get("id") == key["id"] for k in keys):
                raise StoreError("that passkey signs nobody in here")
            self.passkeys_put(u["name"], [key if k.get("id") == key["id"] else k for k in keys])
            token = secrets.token_urlsafe(32)
            now = time.time()
            self.run("INSERT INTO sessions (id, name, created, seen, addr, agent, mfa, data) "
                     "VALUES (?, ?, ?, ?, ?, ?, '', ?)",
                     (_sid(token), u["name"], now, now, str(addr or "")[:64], str(agent or "")[:200],
                      json.dumps({"by": "passkey", "key": str(key["id"])})))
            self.run("UPDATE users SET last_login = ?, last_from = ? WHERE name = ?", (now, addr, u["name"]))
        self.tidy_sessions(idle_s)
        u = dict(u)
        u.pop("hash", None)
        return token, u

    # ---- the second step (an authenticator app) ------------------------------------------
    # The account's own, in its row (users.mfa, JSON) - so a backup of the database has it, and
    # a reset (Accounts, upnp user reset-2fa NAME) takes it away (never the passkeys, 1.9.7):
    #   {"kind": "app", "secret", "step": the last code's step, used once, "at", "by"}
    def mfa_get(self, name):
        u = self.user(name)
        return _jload(u["mfa"]) if u else {}

    def mfa_stage(self, name):
        """'' (none asked), 'check' (give the code) or 'enrol' (set the app up first)."""
        if not self.policy()["admin_2fa"]:
            return ""
        return "check" if self.mfa_get(name).get("kind") else "enrol"

    def mfa_reset(self, name):
        """Its app taken away (set up again at the next sign-in); its sign-ins ended. Had it one?"""
        u = self.user(name)
        if not u:
            raise StoreError("there is no account %s" % name)
        had = bool(_jload(u["mfa"]).get("kind"))
        self.run("UPDATE users SET mfa = '', changed = ? WHERE name = ?", (time.time(), name))
        self.end_sessions_of(name)
        return had

    def mfa_check(self, name, code):
        """The code of the account's app: True, or StoreError with the words. A code is good once."""
        with self.lock:
            rec = self.mfa_get(name)
            if rec.get("kind") != "app" or not rec.get("secret"):
                raise StoreError("this account has no second step set up")
            try:
                step = totp_match(rec["secret"], code)
            except ValueError:
                step = None
            if step is None:
                raise StoreError("that code is not right")
            if step <= int(rec.get("step") or 0):
                raise StoreError("that code was used already - wait for the next one")
            rec["step"] = step
            self.run("UPDATE users SET mfa = ? WHERE name = ?", (json.dumps(rec), name))
        return True

    # ---- signing in ------------------------------------------------------------------
    def fail(self, addr, name, what="password"):
        self.run("INSERT INTO fails (at, addr, name, what) VALUES (?, ?, ?, ?)",
                 (time.time(), str(addr or "")[:64], str(name or "")[:64], what))

    def too_many(self, addr, name, own=False):
        span, most_name, most_addr = self.fail_limits(own)
        since = time.time() - span
        which = "what = 'own'" if own else "what <> 'own'"
        a = self.one("SELECT COUNT(*) AS n FROM fails WHERE at > ? AND addr = ? AND " + which, (since, addr))["n"]
        if name is None:                # the address alone (a passkey before its key told the name, 1.9.7)
            return a >= most_addr
        n = self.one("SELECT COUNT(*) AS n FROM fails WHERE at > ? AND name = ? AND " + which, (since, name))["n"]
        return a >= most_addr or n >= most_name

    def _locked_words(self, own=False):
        span = self.fail_limits(own)[0]
        if own:
            return "too many wrong passwords - try again in %d min" % max(1, span // 60)
        return "too many wrong attempts - try again in %d min" % max(1, span // 60)

    def login(self, name, password, addr="", agent="", idle_s=7200):
        """(token, user) - or StoreError with the words for the sign-in page. user["mfa_stage"]:
        '' signed in; 'check' / 'enrol' - the sign-in is made, and may do nothing but give its
        second step (session() does not know it until then)."""
        name = str(name or "").strip()[:64]
        addr = str(addr or "")[:64]
        span = self.fail_limits()[0]
        self.run("DELETE FROM fails WHERE at < ?", (time.time() - max(span, FAIL_WINDOW_S),))
        # The attempt holds its place before the slow check (otp 1.0.33): counted only after it,
        # many at once all slipped past the count. Given back when the password was right.
        with self.lock:
            locked = self.too_many(addr, name)
            if not locked:
                place = self.run("INSERT INTO fails (at, addr, name, what) VALUES (?, ?, ?, 'password')",
                                 (time.time(), addr, name)).lastrowid
        if locked:
            check_password(password, _dummy_hash())
            raise StoreError(self._locked_words())
        u = self.user(name) if name else None
        if not u or not check_password(password, u["hash"]):
            if not u:
                check_password(password, _dummy_hash())
            raise StoreError("wrong name or password")
        if u["disabled"]:
            # Said as a wrong password is, and counted as one (otp 1.0.57): the difference
            # told that the password was right.
            raise StoreError("wrong name or password")
        self.run("DELETE FROM fails WHERE rowid = ?", (place,))
        # The wrong attempts before a right password stay counted until their time runs out (otp's
        # throttle gives back only the place of the attempt that went well): forgotten here, four
        # wrong and one right were a fresh start each time, for the name's guessing too.
        stage = self.mfa_stage(u["name"])
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.run("INSERT INTO sessions (id, name, created, seen, addr, agent, mfa) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (_sid(token), u["name"], now, now, addr, str(agent or "")[:200], stage))
        if not stage:
            self.run("UPDATE users SET last_login = ?, last_from = ? WHERE name = ?", (now, addr, u["name"]))
        self.tidy_sessions(idle_s)
        u = dict(u)
        u.pop("hash", None)
        u["mfa_stage"] = stage
        return token, u

    def _good(self, s, idle_s):
        now = time.time()
        if s["mfa"]:
            return now - s["created"] <= PENDING_MOST_S
        return now - s["seen"] <= self._idle(idle_s) and now - s["created"] <= self._most()

    def session(self, token, idle_s=7200, touch=True):
        """The account of a session that is still good, or None. A sign-in still to give its
        second step is None here: nothing but that step (pending()) takes it."""
        if not token:
            return None
        sid = _sid(token)
        s = self.one("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not s:
            return None
        if not self._good(s, idle_s):
            self.run("DELETE FROM sessions WHERE id = ?", (sid,))
            return None
        if s["mfa"]:
            return None
        u = self.user(s["name"])
        if not u or u["disabled"]:
            self.run("DELETE FROM sessions WHERE id = ?", (sid,))
            return None
        now = time.time()
        if touch and now - s["seen"] > 15:
            self.run("UPDATE sessions SET seen = ? WHERE id = ?", (now, sid))
        u = dict(u)
        u.pop("hash", None)
        u.pop("mfa", None)
        u["session"] = sid[:12]
        u["session_started"] = s["created"]
        u["mfa_at"] = _jload(s.get("data")).get("mfa_at") or 0
        return u

    def pending(self, token):
        """(session, account) of a sign-in that is waiting for its second step - or (None, None)."""
        if not token:
            return None, None
        sid = _sid(token)
        s = self.one("SELECT * FROM sessions WHERE id = ?", (sid,))
        if not s or not s["mfa"]:
            return None, None
        if not self._good(s, 0):
            self.run("DELETE FROM sessions WHERE id = ?", (sid,))
            return None, None
        u = self.user(s["name"])
        if not u or u["disabled"]:
            self.run("DELETE FROM sessions WHERE id = ?", (sid,))
            return None, None
        s = dict(s)
        s["data"] = _jload(s.get("data"))
        return s, dict(u)

    def session_take(self, token, key):
        """A value kept with a sign-in (waiting or not), taken away by the one who reads it - a
        passkey's question is answered once (otp's session_take). None: not there (any more)."""
        if not token:
            return None
        sid = _sid(token)
        with self.lock:
            s = self.one("SELECT data FROM sessions WHERE id = ?", (sid,))
            if not s:
                return None
            d = _jload(s["data"])
            if key not in d:
                return None
            got = d.pop(key)
            self.run("UPDATE sessions SET data = ? WHERE id = ?", (json.dumps(d), sid))
        return got

    def session_merge(self, token, data):
        """Values kept with a sign-in that is good (Your account's passkey question, 1.9.2)."""
        sid = _sid(token or "")
        with self.lock:
            s = self.one("SELECT data FROM sessions WHERE id = ?", (sid,))
            if not s:
                raise StoreError("this sign-in has ended - sign in again")
            d = _jload(s["data"])
            d.update(data)
            self.run("UPDATE sessions SET data = ? WHERE id = ?", (json.dumps(d), sid))

    def pending_merge(self, token, data):
        with self.lock:
            s, _u = self.pending(token)
            if not s:
                raise StoreError("this sign-in has ended - sign in again")
            d = s["data"]
            d.update(data)
            self.run("UPDATE sessions SET data = ? WHERE id = ?", (json.dumps(d), s["id"]))

    def mfa_enrol(self, token, code):
        """The app set up in this sign-in, proven by its first code: kept, and the sign-in opened -
        the new token returned (mfa_passed)."""
        with self.lock:
            s, u = self.pending(token)
            if not s:
                raise StoreError("this sign-in has ended - sign in again")
            if self.mfa_get(u["name"]).get("kind"):
                raise StoreError("this account has its second step set up already - sign in again")
            secret = s["data"].get("mfa_new") or ""
            if not secret or not isinstance(secret, str):
                raise StoreError("make the QR code first")
            step = totp_match(secret, code)
            if step is None:
                raise StoreError("that code is not right - the one the app shows now")
            rec = {"kind": "app", "secret": secret, "step": step, "at": time.time(), "by": u["name"]}
            self.run("UPDATE users SET mfa = ? WHERE name = ?", (json.dumps(rec), u["name"]))
        return self.mfa_passed(token)

    def mfa_put(self, name, rec):
        self.run("UPDATE users SET mfa = ? WHERE name = ?", (json.dumps(rec), name))

    def mfa_passed(self, token):
        """The second step given: a sign-in of its own from here on, with a NEW token, returned
        (otp 1.0.149, 1.9.2) - the one the password alone opened is ended, not made whole: whoever had
        seen its cookie had the pages once the code was given. When it was given is kept with the new
        one (otp 1.0.262)."""
        sid = _sid(token)
        new = secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            s = self.one("SELECT name, addr, agent, mfa FROM sessions WHERE id = ?", (sid,))
            if not s or not s["mfa"]:
                raise StoreError("this sign-in has ended - sign in again")
            # Taken by one request only: two answers at once open one sign-in, not two.
            if not self.run("DELETE FROM sessions WHERE id = ? AND mfa <> ''", (sid,)).rowcount:
                raise StoreError("this sign-in has ended - sign in again")
            self.run("INSERT INTO sessions (id, name, created, seen, addr, agent, mfa, data) "
                     "VALUES (?, ?, ?, ?, ?, ?, '', ?)",
                     (_sid(new), s["name"], now, now, s["addr"], s["agent"], json.dumps({"mfa_at": int(now)})))
        self.run("UPDATE users SET last_login = ?, last_from = ? WHERE name = ?", (now, s["addr"], s["name"]))
        return new

    def logout(self, token):
        self.run("DELETE FROM sessions WHERE id = ?", (_sid(token),))

    def sessions(self):
        return self.rows("SELECT substr(id, 1, 12) AS id, name, created, seen, addr, agent, mfa FROM sessions "
                         "ORDER BY seen DESC")

    def end_session(self, short_id):
        if not re.match(r"^[0-9a-f]{12,64}\Z", str(short_id or "")):
            raise StoreError("no such sign-in")
        n = self.run("DELETE FROM sessions WHERE substr(id, 1, ?) = ?", (len(short_id), short_id)).rowcount
        if not n:
            raise StoreError("that sign-in has ended already")

    def session_of(self, short_id):
        if not re.match(r"^[0-9a-f]{12,64}\Z", str(short_id or "")):
            return None
        return self.one("SELECT name, addr FROM sessions WHERE substr(id, 1, ?) = ?", (len(short_id), short_id))

    def end_sessions_of(self, name, but_token=None):
        if but_token:
            return self.run("DELETE FROM sessions WHERE name = ? AND id <> ?", (name, _sid(but_token))).rowcount
        return self.run("DELETE FROM sessions WHERE name = ?", (name,)).rowcount

    def tidy_sessions(self, idle_s=7200):
        now = time.time()
        self.run("DELETE FROM sessions WHERE mfa = '' AND (seen < ? OR created < ?)",
                 (now - self._idle(idle_s), now - self._most()))
        self.run("DELETE FROM sessions WHERE mfa <> '' AND created < ?", (now - PENDING_MOST_S,))

    # ---- locked out: the wrong attempts still counted ------------------------------------
    def lockouts(self):
        """One row per address and per name with a wrong attempt still counted, locked or not yet
        (the shape of otp's lockouts_view)."""
        now = time.time()
        rows = []
        for own in (False, True):
            rows += self._lockouts(own, now)
        rows.sort(key=lambda r: (not r["locked"], -r["last"]))
        return rows

    def _lockouts(self, own, now):
        span, most_name, most_addr = self.fail_limits(own)
        rows = []
        got = self.rows("SELECT at, addr, name, what FROM fails WHERE at > ? AND %s ORDER BY at"
                        % ("what = 'own'" if own else "what <> 'own'"), (now - span,))
        kinds = ("password", "password-name") if own else ("admin", "admin-name")
        for by, col, other, limit in (("address", "addr", "name", most_addr), ("name", "name", "addr", most_name)):
            seen = {}
            for f in got:
                if not f[col]:
                    continue                    # cleared for this count, still counted for the other
                seen.setdefault(f[col].lower() if by == "name" else f[col], []).append(f)
            for who, fs in seen.items():
                times = [f["at"] for f in fs]
                locked = len(times) >= limit
                others = []
                for f in fs:
                    if f[other] and f[other] not in others:
                        others.append(f[other])
                whats = set(f["what"] or "password" for f in fs)
                rows.append({
                    "kind": kinds[0] if by == "address" else kinds[1], "who": fs[-1][col], "by": by,
                    "what": "changing a password" if own else "signing in to these pages",
                    "words": "wrong codes" if whats == {"code"} else ("wrong passwords and codes" if "code" in whats
                                                                     else "wrong passwords"),
                    "fails": len(times), "limit": limit, "locked": locked,
                    "until": (times[len(times) - limit] + span) if locked else None,
                    "forgets": times[-1] + span, "first": times[0], "last": times[-1], "others": others[-10:]})
        return rows

    def clear_fails(self, by, who, own=None):
        """How many wrong attempts of that address or name were forgotten. Only that count (otp's
        counters are one per address and one per name): clearing an address forgets its attempts
        for the address, while the names tried from it keep theirs - and the other way round. The
        wrong attempts counted for neither any more are gone. `own`: True the count of one's own password
        typed wrong (kinds password, password-name), False the sign-in's, None both."""
        col = "addr" if by in ("address", "admin", "password") else "name"
        which = "" if own is None else (" AND what = 'own'" if own else " AND what <> 'own'")
        with self.lock:
            n = self.run("UPDATE fails SET %s = '' WHERE %s = ?%s%s" % (col, col, " COLLATE NOCASE" if col == "name"
                                                                      else "", which), (str(who),)).rowcount
            self.run("DELETE FROM fails WHERE addr = '' AND name = ''")
        return n

    def clear_all_fails(self):
        return self.run("DELETE FROM fails").rowcount
