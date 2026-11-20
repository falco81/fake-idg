#!/usr/bin/env python3
"""test_auth.py - the sign-ins, the accounts and root's boundary (1.9.9): what was found wrong and put right.

  python3 test/auth/test_auth.py         (from the source tree; nothing of the machine is touched - every
                                         path is a folder of its own under /tmp)

What it proves:

  - a database put back (Settings → Database, Backups) leaves who is signed in now as they are: the file's
    own sign-ins do not come back to life (one ended since - signed out, its password changed - opened the
    pages again for whoever still had its cookie)
  - a database of an older version put back gets this version's columns at once (signing in broke on "no
    such column" until the API was restarted), and a 1.9.2-1.9.6 one has its passkeys moved as on opening
  - the columns are added once however many open the database at the same moment (the API and upnp user)
  - Export and import: an account's password written over by the file ends its sign-ins; the last full
    admin who can sign in stays one, also for an import from the command line
  - root's helpers never write or read through a link the fake-igd account laid in its own folder: the
    stop of a system update (osup.stop), the network's trial (net-trial.json), the queue of asks (web/ask)
"""
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(ROOT, "src")
DEPLOY = os.path.join(ROOT, "deploy")
sys.path[:0] = [SRC]
TMP = tempfile.mkdtemp(prefix="fake-igd-auth-test-")
os.environ["FAKE_IGD_SEAL_KEY"] = os.path.join(TMP, "secrets.key")

import igd_store as ST      # noqa: E402
import igd_panes as PN      # noqa: E402

PN.load()
DB = sys.modules["api_db"]
CARRY = sys.modules["api_carry"]

# The tables of 1.4.0, before any column was added (igd_store.COLUMNS) and before passkeys' questions.
OLD_SCHEMA = """
CREATE TABLE users (name TEXT PRIMARY KEY COLLATE NOCASE, role TEXT NOT NULL, hash TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '', must_change INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL,
    changed REAL NOT NULL, last_login REAL, last_from TEXT);
CREATE TABLE sessions (id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE, created REAL NOT NULL,
    seen REAL NOT NULL, addr TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL DEFAULT '');
CREATE TABLE fails (at REAL NOT NULL, addr TEXT NOT NULL, name TEXT NOT NULL COLLATE NOCASE);
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, kind TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info', who TEXT NOT NULL DEFAULT '', addr TEXT NOT NULL DEFAULT '',
    words TEXT NOT NULL);
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
"""


def module(name, path, env):
    """A file of deploy/ loaded afresh with its paths pointed into the test's folder."""
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location(name + "_t%d" % time.monotonic_ns(), path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.S = ST.Store(os.path.join(self.dir, "fake-igd.db"))
        self.S.add_user("admin", "secret123", "fulladmin")
        self.S.add_user("viewer", "secret123", "readonly")

    def tearDown(self):
        self.S.close()

    def ctx(self, me="admin"):
        u = {"name": me, "role": "fulladmin"}
        return PN.Ctx(None, "POST", "/api/x", {}, u, self.S, {"state_dir": self.dir}, DB, self.S.add_event)


class Restore(Base):
    def copy_now(self):
        p = os.path.join(self.dir, "copy.db")
        DB.snapshot(self.S, p)
        return p

    def test_ended_sign_ins_stay_ended(self):
        old, _u = self.S.login("viewer", "secret123", "192.0.2.9")
        copy = self.copy_now()
        self.S.logout(old)                                   # ended after the copy was made
        mine, _u = self.S.login("admin", "secret123", "192.0.2.1")
        self.assertIsNone(self.S.session(old))
        DB.restore_from(self.ctx(), copy, "a copy")
        self.assertIsNone(self.S.session(old), "a sign-in ended before the restore came back with the file")
        self.assertEqual(self.S.session(mine)["name"], "admin", "the one who put it back was signed out")

    def test_old_version_gets_its_columns(self):
        p = os.path.join(self.dir, "old.db")
        db = sqlite3.connect(p)
        db.executescript(OLD_SCHEMA)
        now = time.time()
        db.execute("INSERT INTO users VALUES ('old', 'fulladmin', ?, '', 0, ?, ?, NULL, NULL)",
                   (ST.hash_password("secret456"), now, now))
        db.execute("INSERT INTO events (at, kind, words) VALUES (?, 'x', 'y')", (now,))
        db.commit()
        db.close()
        DB.restore_from(self.ctx(), p, "an old copy")
        tok, u = self.S.login("old", "secret456", "192.0.2.1")
        self.assertEqual(self.S.session(tok)["name"], "old")
        self.assertEqual(self.S.users()[0]["passkeys"], 0)
        self.S.challenge_put("192.0.2.1", {"challenge": "c" * 43})

    def test_passkeys_of_1_9_6_moved(self):
        key = {"id": "k1", "alg": -7, "pub": "x", "host": "h"}
        self.S.run("UPDATE users SET mfa = ? WHERE name = 'admin'", (json.dumps({"kind": "passkey", "keys": [key]}),))
        copy = self.copy_now()
        self.S.run("UPDATE users SET mfa = '' WHERE name = 'admin'")
        DB.restore_from(self.ctx(), copy, "a copy of 1.9.6")
        self.assertEqual(self.S.mfa_get("admin"), {})
        self.assertEqual([k["id"] for k in self.S.passkeys("admin")], ["k1"])


class Migrate(unittest.TestCase):
    def test_twice_and_at_the_same_moment(self):
        d = tempfile.mkdtemp(dir=TMP)
        p = os.path.join(d, "old.db")
        db = sqlite3.connect(p)
        db.executescript(OLD_SCHEMA)
        db.close()
        a = ST.Store(p)
        a.migrate()
        a.migrate()

        class Late(object):
            """The connection of one that read the columns before the other added them."""
            def __init__(self, db):
                self._db = db

            def execute(self, sql, *args):
                if sql.startswith("PRAGMA table_info"):
                    return self._db.execute("SELECT 1 WHERE 0")
                return self._db.execute(sql, *args)

            def __getattr__(self, k):
                return getattr(self._db, k)
        b = ST.Store(p)
        b.db = Late(b.db)
        b.migrate()                                      # "duplicate column name" is no error here
        cols = [r[1] for r in a.db.execute("PRAGMA table_info(users)").fetchall()]
        self.assertEqual(cols.count("passkeys"), 1)


class Import(Base):
    def test_new_hash_ends_sign_ins(self):
        tok, _u = self.S.login("viewer", "secret123", "192.0.2.9")
        rows = [{"name": "viewer", "role": "readonly", "hash": ST.hash_password("another99")}]
        CARRY.import_users(self.ctx(), rows, False, "admin")
        self.assertIsNone(self.S.session(tok), "a sign-in with the password written over stayed open")
        tok, _u = self.S.login("viewer", "another99", "192.0.2.9")
        rows = [{"name": "viewer", "role": "readonly", "note": "same password", "hash": self.S.user("viewer")["hash"]}]
        CARRY.import_users(self.ctx(), rows, False, "admin")
        self.assertIsNotNone(self.S.session(tok), "the same password ended the sign-in")

    def test_last_full_admin_stays(self):
        rows = [{"name": "admin", "role": "readonly", "hash": self.S.user("admin")["hash"]},
                {"name": "viewer", "role": "readonly"}]
        said, _made, _gone = CARRY.import_users(self.ctx("root (command line)"), rows, True, "root (command line)")
        self.assertEqual(self.S.user("admin")["role"], "fulladmin")
        self.assertTrue(any("stays a full admin" in s for s in said))
        self.S.add_user("second", "secret123", "fulladmin")
        rows = [{"name": "admin", "role": "readonly"}, {"name": "second", "role": "readonly"}]
        CARRY.import_users(self.ctx("root (command line)"), rows, False, "root (command line)")
        self.assertEqual(self.S.count_admins(), 1)


class RootLinks(unittest.TestCase):
    """What the fake-igd account owns (/var/lib/fake-igd, its web/) may hold its links: root never follows one."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.state = os.path.join(self.dir, "state")
        os.makedirs(os.path.join(self.state, "web", "ask"))
        self.victim = os.path.join(self.dir, "victim")
        with open(self.victim, "w") as f:
            f.write("root's own\n")

    def test_osup_stop(self):
        lock = os.path.join(self.dir, "osup.lock")
        R = module("root_osup", os.path.join(DEPLOY, "root_osup.py"),
                   {"FAKE_IGD_STATE": self.state, "FAKE_IGD_OSUP_LOCK": lock})
        job = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "--job", "root_osup.py"])
        import fcntl
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            web = os.path.join(self.state, "web")
            with open(os.path.join(web, "osup.json"), "w") as f:
                json.dump({"state": "running", "phase": "asking for what is new", "pid": job.pid}, f)
            os.symlink(self.victim, os.path.join(web, "osup.stop"))
            R.stop("admin")
            job.wait(10)
        finally:
            os.close(fd)
            if job.poll() is None:
                job.kill()
        with open(self.victim) as f:
            self.assertEqual(f.read(), "root's own\n", "root wrote through the link")
        self.assertFalse(os.path.islink(os.path.join(self.state, "web", "osup.stop")))
        # osup.json as a link: not read through it either
        os.unlink(os.path.join(self.state, "web", "osup.json"))
        os.symlink(self.victim, os.path.join(self.state, "web", "osup.json"))
        with self.assertRaises(OSError):
            R.read_here("osup.json")

    def test_net_trial(self):
        other = os.path.join(self.dir, "elsewhere")
        os.makedirs(other)
        shutil.rmtree(os.path.join(self.state, "web"))
        os.symlink(other, os.path.join(self.state, "web"))
        R = module("root_net", os.path.join(DEPLOY, "root_net.py"), {"FAKE_IGD_STATE": self.state})
        R.trial_write({"state": "trial"})
        self.assertEqual(os.listdir(other), [], "root wrote into the folder the link pointed to")
        os.unlink(os.path.join(self.state, "web"))
        os.makedirs(os.path.join(self.state, "web"))
        R.trial_write({"state": "trial", "snapshot": "abcdef12"})
        self.assertEqual(R.trial_read()["snapshot"], "abcdef12")
        os.unlink(R.TRIAL_FILE)
        os.symlink(self.victim, R.TRIAL_FILE)
        self.assertEqual(R.trial_read(), {})

    def test_queue_through_a_link(self):
        other = os.path.join(self.dir, "elsewhere")
        os.makedirs(os.path.join(other, "ask"))
        with open(os.path.join(other, "ask", "keep-me"), "w") as f:
            f.write("x")
        shutil.rmtree(os.path.join(self.state, "web"))
        os.symlink(other, os.path.join(self.state, "web"))
        W = module("fake_igd_web", os.path.join(DEPLOY, "fake_igd_web.py"), {"FAKE_IGD_STATE": self.state})
        W.serve_queue()
        self.assertEqual(os.listdir(os.path.join(other, "ask")), ["keep-me"], "root took another folder's files")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
