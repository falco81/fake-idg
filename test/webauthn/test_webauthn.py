#!/usr/bin/env python3
"""test_webauthn.py - signing in to the pages with a passkey (1.9.7; the second step 1.9.2-1.9.6), against a
device made here.

  python3 test/webauthn/test_webauthn.py         (from the source tree; `cryptography` is used when the
                                                 system has it for RS256 and EdDSA, ES256 is signed here)

A device (an authenticator) is played by this file: it makes a discoverable key, answers
navigator.credentials.create() and .get() as a browser would hand them to the pages - the clientDataJSON, the
CBOR of the attestation, the authenticator's data, the signature, the user handle - and these are given to
the API's own functions (api_people.pk_signin, pk_do, mfa_post ...) with a real igd_store on a database of its
own. What it proves:

  - Your account adds a passkey (resident key and user verification required), names it, takes it away -
    the last one too; ES256 (signed by the P-256 lines below, no package), RS256 and EdDSA
  - a sign-in by the passkey alone, no name typed: the key found among every account's, a new sign-in
    (token) of the same lifetime as a password's - and no second step after it, even with admin_2fa on
  - every refusal: a bad signature, another origin (http://, another name, another port), another RP ID,
    another question, the answer given twice, an answer from another address, the user not present, not
    verified, the counter going back, a key nobody has, a key taken away, another account's user handle, an
    account switched off, a name or an address locked out - each counted as a wrong password is
  - offered only by a name and only while switched on
  - the second step is the app alone now: no passkey offered, set up or taken there; a sign-in that gives it
    gets a NEW token, the password-only one refused at once
  - from 1.9.2-1.9.6: a passkey kept as the second step becomes a passkey that signs in (never lost), the
    second step cleared; the setting admin_2fa_passkey becomes passkey_signin
  - Accounts and upnp user take an account's passkeys away; a reset of the second step leaves them
  - the bounds of otp 1.0.254 / 1.0.262: CBOR too deep, a huge RSA key or exponent, a short RSA key
"""
import base64
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(os.path.dirname(HERE)), "src")
sys.path[:0] = [SRC]
import igd_store as ST      # noqa: E402
import igd_webauthn as WA   # noqa: E402
import api_people as AP     # noqa: E402

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    HAVE_CRYPTO = True
except ImportError:                                    # pragma: no cover
    HAVE_CRYPTO = False

TMP = tempfile.mkdtemp(prefix="fake-igd-wa-test-")
HOST = "fakeigd.test"
ORIGIN = "https://fakeigd.test"


# ---- CBOR, as a device writes it ------------------------------------------------------------------
def cbor(v):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return head(3, len(raw)) + raw
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ---- ECDSA P-256 signed by hand (RFC 6979 is not needed: a fresh k each time) --------------------
def p256_sign(d, msg):
    n = WA._P256_N
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    while True:
        k = secrets.randbelow(n - 1) + 1
        r = WA._p256_mul(k, WA._P256_G)[0] % n
        s = pow(k, n - 2, n) * (e + r * d) % n
        if r and s:
            break

    def der_int(x):
        raw = x.to_bytes((x.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(raw)]) + raw
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


class Device(object):
    """One passkey of a device: its key, its ID, its counter."""

    def __init__(self, alg=-7, counter=True):
        self.alg = alg
        self.cid = secrets.token_bytes(32)
        self.count = 0 if not counter else 1
        self.counter = counter
        if alg == -7:
            self.d = secrets.randbelow(WA._P256_N - 1) + 1
            x, y = WA._p256_mul(self.d, WA._P256_G)
            self.cose = {1: 2, 3: -7, -1: 1, -2: x.to_bytes(32, "big"), -3: y.to_bytes(32, "big")}
        elif alg == -257:
            self.k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pn = self.k.public_key().public_numbers()
            self.cose = {1: 3, 3: -257, -1: pn.n.to_bytes(256, "big"), -2: pn.e.to_bytes(3, "big")}
        elif alg == -8:
            self.k = ed25519.Ed25519PrivateKey.generate()
            raw = self.k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.cose = {1: 1, 3: -8, -1: 6, -2: raw}
        else:
            raise ValueError(alg)

    def sign(self, msg):
        if self.alg == -7:
            return p256_sign(self.d, msg)
        if self.alg == -257:
            return self.k.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return self.k.sign(msg)

    def _ad(self, rp_id, flags, with_key=False):
        if self.counter:
            self.count += 1
        ad = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + self.count.to_bytes(4, "big")
        if with_key:
            ad += b"\x00" * 16 + len(self.cid).to_bytes(2, "big") + self.cid + cbor(self.cose)
        return ad

    def create(self, opts, origin=ORIGIN, rp_id=None, flags=0x45, kind="webauthn.create", challenge=None):
        o = opts["publicKey"]
        self.user = o["user"]["id"]          # kept by a discoverable key, said back at each sign-in
        cd = json.dumps({"type": kind, "challenge": challenge or o["challenge"], "origin": origin,
                         "crossOrigin": False}).encode()
        ad = self._ad(rp_id or o["rp"]["id"], flags, with_key=True)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"device": "Test device", "clientDataJSON": b64(cd), "attestationObject": b64(att)}

    def get(self, opts, origin=ORIGIN, rp_id=None, flags=0x05, kind="webauthn.get", challenge=None,
            bad_sig=False, count=None, user=None):
        o = opts["publicKey"]
        cd = json.dumps({"type": kind, "challenge": challenge or o["challenge"], "origin": origin}).encode()
        ad = self._ad(rp_id or o["rpId"], flags)
        if count is not None:
            ad = ad[:33] + count.to_bytes(4, "big")
        sig = self.sign(ad + hashlib.sha256(cd).digest())
        if bad_sig:
            sig = self.sign(ad + hashlib.sha256(cd + b" ").digest())
        return {"id": b64(self.cid), "clientDataJSON": b64(cd), "authenticatorData": b64(ad),
                "signature": b64(sig), "userHandle": user if user is not None else getattr(self, "user", ""),
                "challenge": o["challenge"]}


# ---- the API's functions, as fake_igd_api.py calls them ---------------------------------------------
class Handler(object):
    def __init__(self, host, token, body, addr="192.0.2.7"):
        self.headers = {"X-IGD-Host": host, "X-IGD-Session": token or "", "User-Agent": "test"}
        self._b, self._addr = body, addr

    def addr(self):
        return self._addr

    def body(self, most=0):
        return dict(self._b or {})


class Pages(object):
    """One browser: its cookie (the token), the name it opened the pages by, its address."""

    def __init__(self, store, host=HOST, addr="192.0.2.7"):
        self.S, self.host, self.addr, self.token, self.old = store, host, addr, "", ""

    def call(self, fn, body=None, signed_in=False):
        import igd_panes as PN
        h = Handler(self.host, self.token, body, self.addr)
        me = self.S.session(self.token) if signed_in else None
        if signed_in and not me:
            raise PermissionError("not signed in")
        ctx = PN.Ctx(h, "POST" if body is not None else "GET", "/api/x", {}, me, self.S,
                     {"site_name": "lab"}, AP, self.S.add_event)
        return fn(ctx)

    def _cookie(self, got):
        # As index.php does (?api=login, ?api=mfa, ?api=passkey-login): the token into the cookie,
        # never to the page.
        if isinstance(got, dict) and got.get("token"):
            self.old, self.token = self.token, got.pop("token")
        return got

    def login(self, name="admin", pw="secret123"):
        return self._cookie(self.call(AP.login, {"name": name, "password": pw}))

    def mfa(self, body=None):
        return self._cookie(self.call(AP.mfa_post if body is not None else AP.mfa_get, body))

    def pk(self, body=None):
        return self.call(AP.pk_do if body is not None else AP.pk_list, body, signed_in=True)

    def offered(self):
        return self.call(AP.pk_signin_get)

    def begin(self):
        return self.call(AP.pk_signin, {"action": "begin"})

    def finish(self, answer):
        return self._cookie(self.call(AP.pk_signin, dict(answer, action="finish")))

    def pk_sign_in(self, dev, **kw):
        return self.finish(dev.get(self.begin(), **kw))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.S = ST.Store(os.path.join(self.dir, "t.db"))
        self.S.add_user("admin", "secret123", "fulladmin")
        self.S.add_user("viewer", "secret123", "readonly")
        self.on(False, True)

    def tearDown(self):
        self.S.close()

    def on(self, two, pk):
        self.S.set_meta("settings", json.dumps({"admin_2fa": two, "passkey_signin": pk}))

    def add(self, dev, name="admin", p=None):
        """The device's passkey added under Your account of a sign-in with the password."""
        if p is None:
            p = Pages(self.S)
            self.assertEqual(p.login(name)["mfa"], "")
        opts = p.pk({"action": "add_begin"})
        got = p.pk(dict(dev.create(opts), action="add_finish"))
        self.assertIn(dev_id(dev), [k["id"] for k in got["keys"]])
        return p

    def wrongs(self, what="password"):
        return self.S.one("SELECT COUNT(*) AS n FROM fails WHERE what = ?", (what,))["n"]

    def events(self, n=30):
        return " ".join(e["words"] for e in self.S.events(limit=n)["events"])


def dev_id(dev):
    return b64(dev.cid)


class Add(Base):
    def test_options_ask_a_discoverable_verified_key(self):
        p = Pages(self.S)
        p.login()
        o = p.pk({"action": "add_begin"})["publicKey"]
        self.assertEqual(o["authenticatorSelection"], {"userVerification": "required", "residentKey": "required",
                                                       "requireResidentKey": True})
        self.assertEqual(o["rp"]["id"], HOST)
        self.assertEqual(o["user"]["id"], WA.wa_user_id("admin"))

    def test_es256_add_and_sign_in(self):
        dev = Device(-7)
        self.add(dev)
        keys = self.S.passkeys("admin")
        self.assertEqual(len(keys), 1)
        self.assertEqual(sorted(keys[0]), ["alg", "at", "backed_up", "count", "host", "id", "name", "pub", "used"])
        self.assertNotIn(b64(dev.d.to_bytes(32, "big")), json.dumps(keys))      # only the public half
        self.assertEqual(self.S.mfa_get("admin"), {})                           # not the second step
        u = [x for x in self.S.users() if x["name"] == "admin"][0]
        self.assertEqual((u["passkeys"], u["passkeys_said"]), (1, "Test device · fakeigd.test"))
        p = Pages(self.S)
        got = p.pk_sign_in(dev)
        self.assertEqual((got["who"]["name"], got["mfa"]), ("admin", ""))
        me = self.S.session(p.token)
        self.assertEqual(me["name"], "admin")
        self.assertTrue(self.S.passkeys("admin")[0]["used"])
        self.assertIn("admin signed in with a passkey (Test device) from 192.0.2.7", self.events())
        self.assertIn("added a passkey (Test device, for https://fakeigd.test/)", self.events())

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography is not here")
    def test_rs256_and_eddsa(self):
        for alg in (-257, -8):
            dev = Device(alg)
            self.add(dev)
            p = Pages(self.S)
            self.assertEqual(p.pk_sign_in(dev)["who"]["name"], "admin")
            with self.assertRaises(ValueError) as e:
                Pages(self.S).pk_sign_in(dev, bad_sig=True)
            self.assertIn("signature is not right", str(e.exception))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography is not here")
    def test_es256_by_cryptography(self):
        """A key made and signed by the `cryptography` package, checked by the lines of igd_webauthn."""
        k = ec.generate_private_key(ec.SECP256R1())
        pn = k.public_key().public_numbers()
        sig = k.sign(b"the pages", ec.ECDSA(hashes.SHA256()))
        self.assertTrue(WA.wa_es256_ok(pn.x.to_bytes(32, "big"), pn.y.to_bytes(32, "big"), b"the pages", sig))
        self.assertFalse(WA.wa_es256_ok(pn.x.to_bytes(32, "big"), pn.y.to_bytes(32, "big"), b"the pages!", sig))

    def test_eddsa_without_the_package(self):
        if not HAVE_CRYPTO:
            self.skipTest("cryptography is not here to sign")
        k = ed25519.Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = k.sign(b"m")
        was = WA._ed_crypto
        WA._ed_crypto = lambda: None
        try:
            self.assertTrue(WA.ed25519_verify(pub, b"m", sig))
            self.assertFalse(WA.ed25519_verify(pub, b"n", sig))
        finally:
            WA._ed_crypto = was

    def test_add_refusals(self):
        p = Pages(self.S)
        p.login()
        for words, kw in (("not from these pages", dict(origin="https://evil.test")),
                          ("not from these pages", dict(origin="http://fakeigd.test")),
                          ("for another name", dict(rp_id="evil.test")),
                          ("another question", dict(challenge=b64(b"x" * 32))),
                          ("did not check who it was", dict(flags=0x41)),
                          ("nobody was there", dict(flags=0x44))):
            opts = p.pk({"action": "add_begin"})
            with self.assertRaises(ValueError) as e:
                p.pk(dict(Device(-7).create(opts, **kw), action="add_finish"))
            self.assertIn(words, str(e.exception))
        self.assertEqual(self.S.passkeys("admin"), [])
        # the answer once
        dev = Device(-7)
        opts = p.pk({"action": "add_begin"})
        ans = dict(dev.create(opts), action="add_finish")
        p.pk(ans)
        with self.assertRaises(ValueError) as e:
            p.pk(ans)
        self.assertIn("old question", str(e.exception))
        # the same device twice, and another account's key
        opts = p.pk({"action": "add_begin"})
        self.assertEqual([c["id"] for c in opts["publicKey"]["excludeCredentials"]], [dev_id(dev)])
        with self.assertRaises(ValueError) as e:
            p.pk(dict(dev.create(opts), action="add_finish"))
        self.assertIn("has a passkey for this account already", str(e.exception))
        v = Pages(self.S)
        v.login("viewer")
        with self.assertRaises(ValueError) as e:
            v.pk(dict(dev.create(v.pk({"action": "add_begin"})), action="add_finish"))
        self.assertIn("another account's already", str(e.exception))

    def test_rename_delete_the_last_too(self):
        dev = Device(-7)
        p = self.add(dev)
        kid = dev_id(dev)
        self.assertEqual(p.pk({"action": "rename", "id": kid, "name": "  my   iPhone "})["keys"][0]["name"], "my iPhone")
        with self.assertRaises(ValueError):
            p.pk({"action": "rename", "id": kid, "name": "  "})
        self.assertEqual(p.pk({"action": "delete", "id": kid})["keys"], [])    # the last one: the password stays
        with self.assertRaises(ValueError) as e:
            Pages(self.S).pk_sign_in(dev)
        self.assertIn("signs nobody in", str(e.exception))
        self.assertEqual(Pages(self.S).login()["who"]["name"], "admin")
        self.assertIn("took a passkey away (my iPhone", self.events())

    def test_only_soon_after_signing_in(self):
        p = Pages(self.S)
        p.login()
        self.S.run("UPDATE sessions SET created = created - ?", (AP.PK_ADD_FRESH + 5,))
        d = p.pk()
        self.assertFalse(d["can_add"])
        self.assertIn("within 15 minutes", d["why"])
        with self.assertRaises(ValueError):
            p.pk({"action": "add_begin"})

    def test_ten_at_most_and_not_by_an_address(self):
        p = Pages(self.S)
        p.login()
        for _ in range(AP.PK_MAX):
            self.add(Device(-7), p=p)
        d = p.pk()
        self.assertEqual((len(d["keys"]), d["can_add"]), (10, False))
        with self.assertRaises(ValueError):
            p.pk({"action": "add_begin"})
        p.host = "127.0.0.1"
        self.assertIn("not by an address", p.pk()["why"])

    def test_switched_off(self):
        self.on(False, False)
        p = Pages(self.S)
        p.login()
        self.assertEqual((p.pk()["on"], p.pk()["can_add"]), (False, False))
        with self.assertRaises(ValueError):
            p.pk({"action": "add_begin"})
        self.assertEqual(p.offered(), {"on": False, "here": False})
        with self.assertRaises(ValueError):
            p.begin()


class SignIn(Base):
    def setUp(self):
        Base.setUp(self)
        self.dev = Device(-7)
        self.add(self.dev)

    def refused(self, words, p=None, **kw):
        p = p or Pages(self.S)
        with self.assertRaises(ValueError) as e:
            p.pk_sign_in(self.dev, **kw)
        self.assertIn(words, str(e.exception))
        self.assertEqual(p.token, "")
        return p

    def test_offered_only_by_a_name(self):
        for host, here in ((HOST, True), ("fakeigd.test:8443", True), ("127.0.0.1", False), ("[::1]", False),
                           ("", False)):
            p = Pages(self.S, host=host)
            self.assertEqual(p.offered(), {"on": True, "here": here}, host)
            if not here:
                with self.assertRaises(ValueError):
                    p.begin()

    def test_no_name_asked_and_a_whole_sign_in(self):
        opts = Pages(self.S).begin()["publicKey"]
        self.assertEqual((opts["allowCredentials"], opts["userVerification"], opts["rpId"]), ([], "required", HOST))
        # with the second step on: still whole, no code asked
        self.on(True, True)
        p = Pages(self.S)
        got = p.pk_sign_in(self.dev)
        self.assertEqual(got["mfa"], "")
        me = self.S.session(p.token)
        self.assertTrue(me and me["name"] == "admin")
        self.assertEqual(self.S.pending(p.token), (None, None))
        # the same lifetime as a password's: idle and most
        self.S.run("UPDATE sessions SET seen = seen - ? WHERE name = 'admin'", (121 * 60,))
        self.assertIsNone(self.S.session(p.token))
        # the password still signs in, and with admin_2fa on it asks the app as before
        self.assertEqual(Pages(self.S).login()["mfa"], "enrol")

    def test_refusals_counted(self):
        self.refused("signature is not right", bad_sig=True)
        self.refused("not from these pages", origin="http://fakeigd.test")
        self.refused("not from these pages", origin="https://fakeigd.test:8443")
        self.refused("for another name", rp_id="evil.test")
        self.refused("another question", challenge=b64(secrets.token_bytes(32)))
        self.refused("not of this step", kind="webauthn.create")
        self.refused("nobody was there", flags=0x04)
        self.refused("did not check who it was", flags=0x01)
        self.refused("made for another account", user=WA.wa_user_id("viewer"))
        self.assertEqual(self.wrongs(), 9)
        self.assertEqual(self.S.one("SELECT COUNT(*) AS n FROM fails WHERE name = 'admin'")["n"], 9)
        self.assertIn("admin could not sign in with a passkey from 192.0.2.7: the passkey's signature is not right",
                      self.events())

    def test_counter_back(self):
        self.refused("counter went back", count=1)
        bad = [e for e in self.S.events(limit=5)["events"] if "counter went back" in e["words"]]
        self.assertEqual(bad[0]["level"], "bad")

    def test_question_once_and_bound(self):
        p = Pages(self.S)
        ans = self.dev.get(p.begin())
        # from another address: refused there, and the question is still its own address's
        q = Pages(self.S, addr="198.51.100.9")
        with self.assertRaises(ValueError) as e:
            q.finish(ans)
        self.assertIn("old question", str(e.exception))
        self.assertTrue(p.finish(ans)["who"])
        # the same answer again (a replay): the question was taken
        with self.assertRaises(ValueError) as e:
            Pages(self.S).finish(ans)
        self.assertIn("old question", str(e.exception))
        # a wrong answer takes its question too
        r = Pages(self.S)
        opts = r.begin()
        with self.assertRaises(ValueError):
            r.finish(self.dev.get(opts, bad_sig=True))
        with self.assertRaises(ValueError) as e:
            r.finish(self.dev.get(opts))
        self.assertIn("old question", str(e.exception))
        # an old one
        opts = r.begin()
        self.S.run("UPDATE challenges SET at = at - ?", (ST.CHALLENGE_S + 1,))
        with self.assertRaises(ValueError):
            r.finish(self.dev.get(opts))

    def test_questions_bounded(self):
        p = Pages(self.S)
        for _ in range(ST.CHALLENGE_MOST_ADDR + 5):
            p.begin()
        self.assertEqual(self.S.one("SELECT COUNT(*) AS n FROM challenges")["n"], ST.CHALLENGE_MOST_ADDR)

    def test_unknown_and_deleted_key(self):
        stranger = Device(-7)
        stranger.user = WA.wa_user_id("admin")
        p = Pages(self.S)
        with self.assertRaises(ValueError) as e:
            p.pk_sign_in(stranger)
        self.assertIn("signs nobody in", str(e.exception))
        self.assertEqual(self.S.one("SELECT COUNT(*) AS n FROM fails WHERE name = '' AND addr = '192.0.2.7'")["n"], 1)
        self.S.passkeys_remove("admin")
        self.refused("signs nobody in")

    def test_switched_off_account(self):
        self.S.add_user("third", "secret123", "fulladmin")
        self.S.set_disabled("admin", True)
        self.refused("signs nobody in")
        self.assertIsNone(self.S.one("SELECT * FROM sessions WHERE name = 'admin'"))

    def test_locked_out(self):
        # the name: as many wrong passwords as lock it out
        tries = self.S.fail_limits()[1]
        for _ in range(tries):
            self.S.fail("203.0.113.1", "admin")
        self.refused("too many wrong attempts")
        self.S.clear_all_fails()
        # the address: before the key is even looked at
        for _ in range(self.S.fail_limits()[2]):
            self.S.fail("192.0.2.7", "someone")
        with self.assertRaises(ValueError) as e:
            Pages(self.S).begin()
        self.assertIn("too many wrong attempts", str(e.exception))
        # another address is not held by it
        self.assertTrue(Pages(self.S, addr="192.0.2.8").pk_sign_in(self.dev)["who"])

    def test_wrong_keys_lock_the_address(self):
        stranger = Device(-7)
        for _ in range(self.S.fail_limits()[2]):
            with self.assertRaises(ValueError):
                Pages(self.S).pk_sign_in(stranger)
        with self.assertRaises(ValueError) as e:
            Pages(self.S).pk_sign_in(self.dev)
        self.assertIn("too many wrong attempts", str(e.exception))

    def test_no_counter_device(self):
        """A device that keeps no counter (iCloud Keychain: always 0) is taken."""
        dev = Device(-7, counter=False)
        self.add(dev, name="viewer")
        for _ in range(2):
            self.assertEqual(Pages(self.S).pk_sign_in(dev)["who"]["name"], "viewer")

    def test_second_step_switched_on_leaves_it(self):
        p = Pages(self.S)
        p.pk_sign_in(self.dev)
        a = Pages(self.S)
        a.login("viewer")
        import igd_panes as PN
        ctx = PN.Ctx(Handler(HOST, a.token, {}), "POST", "/api/settings", {}, self.S.session(a.token), self.S, {},
                     AP, self.S.add_event)
        AP.on_saved(ctx, {"admin_2fa": True})
        self.assertTrue(self.S.session(p.token))


class SecondStep(Base):
    """The app alone (1.9.7)."""

    def test_no_passkey_offered(self):
        self.on(True, True)
        p = Pages(self.S)
        self.assertEqual(p.login()["mfa"], "enrol")
        self.assertEqual(p.mfa()["methods"], ["app"])
        with self.assertRaises(ValueError):
            p.mfa({"action": "enrol_start", "kind": "passkey"})
        with self.assertRaises(ValueError):
            p.mfa({"action": "pk_begin"})

    def check_swapped(self, p, before):
        self.assertNotEqual(p.token, before)
        self.assertIsNone(self.S.session(before))
        self.assertEqual(self.S.pending(before), (None, None))
        self.assertTrue(self.S.session(p.token))
        old = Pages(self.S)
        old.token = before
        with self.assertRaises(ValueError):
            old.mfa()
        with self.assertRaises(PermissionError):
            old.pk()

    def test_new_token_app(self):
        self.on(True, True)
        p = Pages(self.S)
        p.login()
        before = p.token
        p.mfa({"action": "enrol_start", "kind": "app"})
        s, _a = self.S.pending(p.token)
        secret = s["data"]["mfa_new"]
        p.mfa({"action": "enrol_confirm", "code": ST.totp(secret)})
        self.check_swapped(p, before)
        rec = self.S.mfa_get("admin")
        rec["step"] = 0
        self.S.mfa_put("admin", rec)
        p2 = Pages(self.S)
        p2.login()
        before = p2.token
        p2.mfa({"action": "check", "code": ST.totp(secret)})
        self.check_swapped(p2, before)

    def test_once(self):
        self.on(True, True)
        p = Pages(self.S)
        p.login()
        new = self.S.mfa_passed(p.token)
        with self.assertRaises(ST.StoreError):
            self.S.mfa_passed(p.token)
        with self.assertRaises(ST.StoreError):
            self.S.mfa_passed(new)

    def test_reset_leaves_the_passkeys(self):
        dev = Device(-7)
        self.add(dev)
        import igd_panes as PN
        a = Pages(self.S)
        a.login("viewer")
        self.S.set_role("viewer", "fulladmin")
        self.on(True, True)
        self.S.mfa_put("admin", {"kind": "app", "secret": ST.b32_new(), "step": 0, "at": time.time()})
        me = self.S.session(a.token)
        ctx = PN.Ctx(Handler(HOST, a.token, {"action": "mfa_reset", "name": "admin"}), "POST", "/api/users", {}, me,
                     self.S, {}, AP, self.S.add_event)
        AP.users_post(ctx)
        self.assertEqual(self.S.mfa_get("admin"), {})
        self.assertEqual(len(self.S.passkeys("admin")), 1)
        self.assertTrue(Pages(self.S).pk_sign_in(dev)["who"])
        # Accounts → the key button: every passkey taken away
        ctx = PN.Ctx(Handler(HOST, a.token, {"action": "passkeys_remove", "name": "admin"}), "POST", "/api/users",
                     {}, me, self.S, {}, AP, self.S.add_event)
        self.assertIn("taken away (1)", AP.users_post(ctx)["message"])
        self.assertEqual(self.S.passkeys("admin"), [])
        with self.assertRaises(ValueError):
            Pages(self.S).pk_sign_in(dev)


class Migration(unittest.TestCase):
    """A database of 1.9.2-1.9.6: passkeys as the second step, the setting admin_2fa_passkey."""

    def test_moved_never_lost(self):
        d = tempfile.mkdtemp(dir=TMP)
        path = os.path.join(d, "old.db")
        S = ST.Store(path)
        S.add_user("admin", "secret123", "fulladmin")
        S.add_user("bob", "secret123", "readonly")
        dev = Device(-7)
        cose = WA.wa_cose(dev.cose)
        key = {"id": b64(dev.cid), "alg": cose[0], "pub": cose[1], "count": 0, "host": HOST, "name": "iPad",
               "at": time.time(), "used": 0, "backed_up": False}
        # as 1.9.6 wrote them: the key in users.mfa, no passkeys column filled, the old setting
        S.run("UPDATE users SET mfa = ? WHERE name = 'admin'",
              (json.dumps({"kind": "passkey", "keys": [key], "at": time.time(), "by": "admin"}),))
        S.run("UPDATE users SET mfa = ? WHERE name = 'bob'",
              (json.dumps({"kind": "app", "secret": ST.b32_new(), "step": 0, "at": time.time()}),))
        S.set_meta("settings", json.dumps({"admin_2fa": True, "admin_2fa_passkey": True}))
        S.close()
        S = ST.Store(path)                                     # opened by 1.9.7
        self.assertEqual(S.passkeys("admin"), [key])
        self.assertEqual(S.mfa_get("admin"), {})
        self.assertEqual(S.mfa_get("bob")["kind"], "app")      # the app stays
        saved = json.loads(S.get_meta("settings"))
        self.assertNotIn("admin_2fa_passkey", saved)
        self.assertTrue(saved["passkey_signin"] and S.policy()["passkey_signin"])
        self.assertIn("the passkeys of admin (1) sign in by themselves now",
                      " ".join(e["words"] for e in S.events(limit=5)["events"]))
        S.close()
        S = ST.Store(path)                                     # and again: nothing more
        self.assertEqual(len(S.passkeys("admin")), 1)
        # the old key signs in by itself now, no second step asked (admin_2fa on)
        dev.user = WA.wa_user_id("admin")
        got = Pages(S).pk_sign_in(dev)
        self.assertEqual((got["who"]["name"], got["mfa"]), ("admin", ""))
        # the password asks the app's set-up (the passkey is no second step any more)
        self.assertEqual(Pages(S).login()["mfa"], "enrol")
        S.close()

    def test_off_stays_off(self):
        d = tempfile.mkdtemp(dir=TMP)
        S = ST.Store(os.path.join(d, "o.db"))
        S.set_meta("settings", json.dumps({"admin_2fa": True, "admin_2fa_passkey": False}))
        S.close()
        S = ST.Store(os.path.join(d, "o.db"))
        self.assertFalse(S.policy()["passkey_signin"])
        S.close()


class Bounds(unittest.TestCase):
    def test_cbor(self):
        deep = b"\x81" * 12 + b"\x00"
        with self.assertRaises(ValueError):
            WA.wa_cbor(deep)
        with self.assertRaises(ValueError):
            WA.wa_cbor(b"\x9f\x00\xff")             # indefinite
        with self.assertRaises(ValueError):
            WA.wa_cbor(b"\x5a\xff\xff\xff\xff")     # longer than it is
        with self.assertRaises(ValueError):
            WA.wa_cbor(bytes([0x98, 65]) + b"\x00" * 65)
        self.assertEqual(WA.wa_cbor(cbor({1: [b"a", "b", -7, True]}))[0], {1: [b"a", "b", -7, True]})

    def test_rsa_bounds(self):
        n = (1 << 9000) | 1
        self.assertFalse(WA.wa_rs256_ok(n, 65537, b"m", b"\x00" * ((n.bit_length() + 7) // 8)))
        self.assertFalse(WA.wa_rs256_ok((1 << 2047) | 1, (1 << 40) | 1, b"m", b"\x00" * 256))
        with self.assertRaises(ValueError):
            WA.wa_cose({1: 3, 3: -257, -1: b"\xff" * 128, -2: b"\x01\x00\x01"})
        with self.assertRaises(ValueError):
            WA.wa_cose({1: 3, 3: -257, -1: b"\xff" * 256, -2: b"\x01\x00\x00\x00\x01"})
        with self.assertRaises(ValueError):
            WA.wa_cose({1: 3, 3: -257, -1: b"\xff" * 256, -2: b"\x02"})
        with self.assertRaises(ValueError):
            WA.wa_cose({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})   # not on the curve
        with self.assertRaises(ValueError):
            WA.wa_cose({1: 2, 3: -35, -1: 2})

    def test_base64(self):
        with self.assertRaises(ValueError):
            WA.wa_unb64("a+b/")
        with self.assertRaises(ValueError):
            WA.wa_unb64("A" * (1 << 18))

    def test_es256_edges(self):
        d = 12345
        q = WA._p256_mul(d, WA._P256_G)
        x, y = q[0].to_bytes(32, "big"), q[1].to_bytes(32, "big")
        sig = p256_sign(d, b"m")
        self.assertTrue(WA.wa_es256_ok(x, y, b"m", sig))
        self.assertFalse(WA.wa_es256_ok(x, y, b"m", sig + b"\x00"))
        self.assertFalse(WA.wa_es256_ok(x, y, b"m", b"\x30\x06\x02\x01\x00\x02\x01\x00"))   # r = s = 0


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
