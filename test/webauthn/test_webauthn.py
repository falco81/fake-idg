#!/usr/bin/env python3
"""test_webauthn.py - a passkey as the second step of the pages (1.9.1), against a device made here.

  python3 test/webauthn/test_webauthn.py         (from the source tree; `cryptography` is used when the
                                                 system has it for RS256 and EdDSA, ES256 is signed here)

A device (an authenticator) is played by this file: it makes a key, answers navigator.credentials
.create() and .get() as a browser would hand them to the pages - the clientDataJSON, the CBOR of the
attestation, the authenticator's data, the signature - and these are given to the API's own functions
(api_people.mfa_post, pk_do ...) with a real igd_store on a database of its own. What it proves:

  - register and sign in with ES256 (signed by the P-256 lines below, no package), RS256 and EdDSA
  - every refusal: a bad signature, another origin (http://, another name, another port), another RP ID,
    another question, the answer given twice, the answer after the question was taken by a wrong one,
    the user not present, the user not verified, the counter going back (a copied passkey), a key of
    another account, a passkey of another name
  - wrong answers counted as wrong codes: the fifth ends the sign-in, the address and the name counted
  - offered only by a name: not on an address, not with nothing, not switched off; never without the app
  - Your account: the list, Add (only soon after the second step), the name, taken away, never the last,
    10 at most, the same device twice refused
  - the reset (Accounts, as upnp user reset-2fa) takes the passkeys too
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
        cd = json.dumps({"type": kind, "challenge": challenge or o["challenge"], "origin": origin,
                         "crossOrigin": False}).encode()
        ad = self._ad(rp_id or o["rp"]["id"], flags, with_key=True)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"device": "Test device", "clientDataJSON": b64(cd), "attestationObject": b64(att)}

    def get(self, opts, origin=ORIGIN, rp_id=None, flags=0x05, kind="webauthn.get", challenge=None,
            bad_sig=False, count=None):
        o = opts["publicKey"]
        cd = json.dumps({"type": kind, "challenge": challenge or o["challenge"], "origin": origin}).encode()
        ad = self._ad(rp_id or o["rpId"], flags)
        if count is not None:
            ad = ad[:33] + count.to_bytes(4, "big")
        sig = self.sign(ad + hashlib.sha256(cd).digest())
        if bad_sig:
            sig = self.sign(ad + hashlib.sha256(cd + b" ").digest())
        return {"id": b64(self.cid), "clientDataJSON": b64(cd), "authenticatorData": b64(ad),
                "signature": b64(sig)}


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
    """One browser: its cookie (the token) and the name it opened the pages by."""

    def __init__(self, store, host=HOST, addr="192.0.2.7"):
        self.S, self.host, self.addr, self.token = store, host, addr, ""

    def call(self, fn, body=None, signed_in=False):
        import igd_panes as PN
        h = Handler(self.host, self.token, body, self.addr)
        me = self.S.session(self.token) if signed_in else None
        if signed_in and not me:
            raise PermissionError("not signed in")
        ctx = PN.Ctx(h, "POST" if body is not None else "GET", "/api/x", {}, me, self.S,
                     {"site_name": "lab"}, AP, self.S.add_event)
        return fn(ctx)

    def login(self, name="admin", pw="secret123"):
        got = self.call(AP.login, {"name": name, "password": pw})
        self.token = got["token"]
        return got

    def mfa(self, body=None):
        return self.call(AP.mfa_post if body is not None else AP.mfa_get, body)

    def pk(self, body=None):
        return self.call(AP.pk_do if body is not None else AP.pk_list, body, signed_in=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.S = ST.Store(os.path.join(self.dir, "t.db"))
        self.S.add_user("admin", "secret123", "fulladmin")
        self.S.add_user("viewer", "secret123", "readonly")
        self.on(True, True)

    def tearDown(self):
        self.S.close()

    def on(self, two, pk):
        self.S.set_meta("settings", json.dumps({"admin_2fa": two, "admin_2fa_passkey": pk}))

    def enrol(self, dev, p=None, name="admin"):
        p = p or Pages(self.S)
        self.assertEqual(p.login(name)["mfa"], "enrol")
        opts = p.mfa({"action": "enrol_start", "kind": "passkey"})
        got = p.mfa(dict(dev.create(opts), action="enrol_confirm"))
        self.assertTrue(got["done"])
        self.assertTrue(self.S.session(p.token))
        return p

    def sign_in(self, dev, p=None, **kw):
        p = p or Pages(self.S)
        self.assertEqual(p.login()["mfa"], "check")
        opts = p.mfa({"action": "pk_begin"})
        return p, opts, p.mfa(dict(dev.get(opts, **kw), action="check"))

    def refused(self, p, words, body):
        with self.assertRaises(ValueError) as e:
            p.mfa(body)
        self.assertIn(words, str(e.exception))
        self.assertIsNone(self.S.session(p.token))
        return str(e.exception)

    def wrongs(self):
        return self.S.one("SELECT COUNT(*) AS n FROM fails WHERE what = 'code'")["n"]


class Register(Base):
    def test_es256_whole_way(self):
        dev = Device(-7)
        p = self.enrol(dev)
        rec = self.S.mfa_get("admin")
        self.assertEqual(rec["kind"], "passkey")
        self.assertEqual(rec["keys"][0]["host"], HOST)
        self.assertEqual(rec["keys"][0]["alg"], -7)
        # only the public half: what is kept, and nothing of the private key
        self.assertEqual(sorted(rec["keys"][0]), ["alg", "at", "backed_up", "count", "host", "id", "name", "pub",
                                                  "used"])
        self.assertNotIn(b64(dev.d.to_bytes(32, "big")), json.dumps(rec))
        self.assertTrue(self.S.session(p.token)["mfa_at"])
        u = [x for x in self.S.users() if x["name"] == "admin"][0]
        self.assertEqual(u["mfa"]["kind"], "passkey")
        self.assertIn("Test device · fakeigd.test", u["mfa"]["dest"])
        ev = [e["words"] for e in self.S.events(limit=20)["events"]]
        self.assertTrue(any("set up the second step of signing in: a passkey" in w and "https://fakeigd.test/" in w
                            for w in ev), ev)
        # and signs in with it
        p2, opts, got = self.sign_in(dev)
        self.assertTrue(got["done"])
        self.assertEqual(opts["publicKey"]["rpId"], HOST)
        self.assertEqual(opts["publicKey"]["userVerification"], "required")
        self.assertTrue(self.S.session(p2.token))
        self.assertTrue(self.S.mfa_get("admin")["keys"][0]["used"])
        self.assertEqual(self.S.mfa_get("admin")["keys"][0]["count"], dev.count)
        self.assertIn("gave the second step (a passkey (Test device))",
                      " ".join(e["words"] for e in self.S.events(limit=5)["events"]))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography is not here")
    def test_rs256_and_eddsa(self):
        for alg in (-257, -8):
            self.S.mfa_reset("admin")
            dev = Device(alg)
            self.enrol(dev)
            self.assertEqual(self.S.mfa_get("admin")["keys"][0]["alg"], alg)
            _p, _o, got = self.sign_in(dev)
            self.assertTrue(got["done"])
            p = Pages(self.S)
            p.login()
            opts = p.mfa({"action": "pk_begin"})
            self.refused(p, "signature is not right", dict(dev.get(opts, bad_sig=True), action="check"))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography is not here")
    def test_es256_by_cryptography(self):
        """A key made and signed by the `cryptography` package, checked by the lines of igd_webauthn."""
        k = ec.generate_private_key(ec.SECP256R1())
        pn = k.public_key().public_numbers()
        msg = b"the pages"
        sig = k.sign(msg, ec.ECDSA(hashes.SHA256()))
        self.assertTrue(WA.wa_es256_ok(pn.x.to_bytes(32, "big"), pn.y.to_bytes(32, "big"), msg, sig))
        self.assertFalse(WA.wa_es256_ok(pn.x.to_bytes(32, "big"), pn.y.to_bytes(32, "big"), msg + b"!", sig))

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

    def test_register_refusals(self):
        cases = [
            ("not from these pages", dict(origin="http://fakeigd.test")),
            ("not from these pages", dict(origin="https://evil.test")),
            ("not from these pages", dict(origin="https://fakeigd.test:8443")),
            ("for another name", dict(rp_id="evil.test")),
            ("another question", dict(challenge=b64(b"x" * 32))),
            ("not of this step", dict(kind="webauthn.get")),
            ("nobody was there", dict(flags=0x44)),
            ("did not check who it was", dict(flags=0x41)),
            ("gave no key", dict(flags=0x05)),
        ]
        for words, kw in cases:
            p = Pages(self.S)
            p.login()
            opts = p.mfa({"action": "enrol_start", "kind": "passkey"})
            with self.assertRaises(ValueError) as e:
                p.mfa(dict(Device(-7).create(opts, **kw), action="enrol_confirm"))
            self.assertIn(words, str(e.exception), kw)
            self.assertIn("the passkey was not taken", str(e.exception))
            self.assertEqual(self.S.mfa_get("admin"), {})
            self.assertIsNone(self.S.session(p.token))
        self.assertEqual(self.wrongs(), len(cases))

    def test_register_answer_once(self):
        p = Pages(self.S)
        p.login()
        opts = p.mfa({"action": "enrol_start", "kind": "passkey"})
        ans = dict(Device(-7).create(opts), action="enrol_confirm")
        self.assertTrue(p.mfa(ans)["done"])
        # the same answer again: the sign-in is open now, nothing to give
        with self.assertRaises(ValueError):
            p.mfa(ans)
        # an answer to an old question in a new sign-in of another account set up nothing
        p2 = Pages(self.S)
        p2.login("viewer")
        with self.assertRaises(ValueError) as e:
            p2.mfa(ans)
        self.assertIn("choose a way first", str(e.exception))
        self.assertEqual(self.S.mfa_get("viewer"), {})

    def test_register_late(self):
        p = Pages(self.S)
        p.login()
        opts = p.mfa({"action": "enrol_start", "kind": "passkey"})
        s, _a = self.S.pending(p.token)
        new = s["data"]["mfa_new"]
        new["t"] -= WA.WA_CHALLENGE_S + 1
        self.S.pending_merge(p.token, {"mfa_new": new})
        with self.assertRaises(ValueError) as e:
            p.mfa(dict(Device(-7).create(opts), action="enrol_confirm"))
        self.assertIn("took too long", str(e.exception))


class Offered(Base):
    def test_only_by_a_name(self):
        for host, offered in ((HOST, True), ("fakeigd.test:8443", True), ("localhost", True),
                              ("127.0.0.1", False), ("127.0.0.1:8099", False), ("[::1]:443", False),
                              ("", False), ("1.2.3", False), ("a..b", False), ("-a.test", False)):
            p = Pages(self.S, host=host)
            p.login()
            self.assertEqual("passkey" in p.mfa()["methods"], offered, host)
            self.assertIn("app", p.mfa()["methods"])
            if not offered:
                with self.assertRaises(ValueError) as e:
                    p.mfa({"action": "enrol_start", "kind": "passkey"})
                self.assertIn("not offered", str(e.exception))

    def test_origin_of_a_port(self):
        self.assertEqual(WA.wa_host("fakeigd.test:8443"), ("fakeigd.test", "https://fakeigd.test:8443"))
        self.assertEqual(WA.wa_host("FakeIGD.test:443"), ("fakeigd.test", "https://fakeigd.test"))

    def test_switched_off(self):
        self.on(True, False)
        p = Pages(self.S)
        p.login()
        self.assertEqual(p.mfa()["methods"], ["app"])
        with self.assertRaises(ValueError):
            p.mfa({"action": "enrol_start", "kind": "passkey"})
        self.on(False, True)
        self.assertEqual(Pages(self.S).login()["mfa"], "")

    def test_switched_off_later_stays_the_accounts(self):
        dev = Device(-7)
        self.enrol(dev)
        self.on(True, False)
        p, _o, got = self.sign_in(dev)
        self.assertTrue(got["done"])
        self.assertEqual(p.pk()["on"], False)


class SignIn(Base):
    def setUp(self):
        Base.setUp(self)
        self.dev = Device(-7)
        self.enrol(self.dev)

    def attempt(self, words, **kw):
        p = Pages(self.S)
        self.assertEqual(p.login()["mfa"], "check")
        d = p.mfa()
        self.assertEqual((d["kind"], d["hosts"]), ("passkey", [HOST]))
        opts = p.mfa({"action": "pk_begin"})
        with self.assertRaises(ValueError) as e:
            p.mfa(dict(self.dev.get(opts, **kw), action="check"))
        self.assertIn(words, str(e.exception))
        self.assertIsNone(self.S.session(p.token))
        return p, opts

    def test_refusals(self):
        self.attempt("signature is not right", bad_sig=True)
        self.attempt("not from these pages", origin="http://fakeigd.test")
        self.attempt("not from these pages", origin="https://fakeigd.test.evil.test")
        self.attempt("for another name", rp_id="evil.test")
        self.attempt("another question", challenge=b64(secrets.token_bytes(32)))
        self.attempt("not of this step", kind="webauthn.create")
        self.attempt("nobody was there", flags=0x04)
        self.attempt("did not check who it was", flags=0x01)
        self.assertEqual(self.wrongs(), 8)
        ev = " ".join(e["words"] for e in self.S.events(limit=40)["events"])
        self.assertIn("the passkey was refused - the passkey's signature is not right", ev)

    def test_counter_back(self):
        p, _o = self.attempt("counter went back", count=1)
        bad = [e for e in self.S.events(limit=5)["events"] if "counter went back" in e["words"]]
        self.assertEqual(bad[0]["level"], "bad")

    def test_answer_once(self):
        p = Pages(self.S)
        p.login()
        opts = p.mfa({"action": "pk_begin"})
        ans = dict(self.dev.get(opts), action="check")
        # a wrong answer first takes the question: the right one after it is to an old question
        with self.assertRaises(ValueError):
            p.mfa(dict(self.dev.get(opts, bad_sig=True), action="check"))
        with self.assertRaises(ValueError) as e:
            p.mfa(ans)
        self.assertIn("old question", str(e.exception))
        self.assertIsNone(self.S.session(p.token))
        # and the answer of one sign-in is no answer in the next
        p2 = Pages(self.S)
        p2.login()
        p2.mfa({"action": "pk_begin"})
        with self.assertRaises(ValueError) as e:
            p2.mfa(ans)
        self.assertIn("another question", str(e.exception))
        # replayed after a good one: the sign-in is open, the replay has nothing to answer
        p3, opts3, got = self.sign_in(self.dev)
        self.assertTrue(got["done"])
        p4 = Pages(self.S)
        p4.login()
        with self.assertRaises(ValueError) as e:
            p4.mfa(dict(self.dev.get(opts3), action="check"))
        self.assertIn("old question", str(e.exception))

    def test_another_accounts_key(self):
        other = Device(-7)
        self.enrol(other, name="viewer")
        p = Pages(self.S)
        p.login()
        opts = p.mfa({"action": "pk_begin"})
        with self.assertRaises(ValueError) as e:
            p.mfa(dict(other.get(opts), action="check"))
        self.assertIn("not this account's", str(e.exception))

    def test_another_name(self):
        p = Pages(self.S, host="other.test")
        p.login()
        with self.assertRaises(ValueError) as e:
            p.mfa({"action": "pk_begin"})
        self.assertIn("is for https://fakeigd.test/", str(e.exception))

    def test_five_wrong_end_it(self):
        p = Pages(self.S)
        p.login()
        for i in range(AP.MFA_WRONG_MOST):
            opts = p.mfa({"action": "pk_begin"})
            with self.assertRaises(ValueError) as e:
                p.mfa(dict(self.dev.get(opts, bad_sig=True), action="check"))
        self.assertIn("too many wrong codes - sign in again", str(e.exception))
        self.assertEqual(self.S.pending(p.token), (None, None))
        self.assertEqual(self.wrongs(), AP.MFA_WRONG_MOST)

    def test_no_counter_device(self):
        """A device that keeps no counter (iCloud Keychain: always 0) is taken."""
        self.S.mfa_reset("admin")
        dev = Device(-7, counter=False)
        self.enrol(dev)
        for _ in range(2):
            self.assertTrue(self.sign_in(dev)[2]["done"])

    def test_app_code_not_a_passkey(self):
        p = Pages(self.S)
        p.login()
        with self.assertRaises(ValueError):
            p.mfa({"action": "check", "code": "123456"})


class YourAccount(Base):
    def setUp(self):
        Base.setUp(self)
        self.dev = Device(-7)
        self.p = self.enrol(self.dev)

    def test_list_add_rename_delete(self):
        d = self.p.pk()
        self.assertEqual((d["on"], d["mine"], d["can_add"], d["max"], len(d["keys"])), (True, True, True, 10, 1))
        opts = self.p.pk({"action": "add_begin"})
        self.assertEqual([c["id"] for c in opts["publicKey"]["excludeCredentials"]], [d["keys"][0]["id"]])
        second = Device(-7)
        got = self.p.pk(dict(second.create(opts), action="add_finish"))
        self.assertEqual(len(got["keys"]), 2)
        # the answer once
        with self.assertRaises(ValueError) as e:
            self.p.pk(dict(second.create(opts), action="add_finish"))
        self.assertIn("old question", str(e.exception))
        # both sign in
        for dev in (self.dev, second):
            self.assertTrue(self.sign_in(dev)[2]["done"])
        kid = got["keys"][1]["id"]
        self.assertEqual(self.p.pk({"action": "rename", "id": kid, "name": "  my   iPhone "})["keys"][1]["name"],
                         "my iPhone")
        with self.assertRaises(ValueError):
            self.p.pk({"action": "rename", "id": kid, "name": "  "})
        with self.assertRaises(ValueError):
            self.p.pk({"action": "rename", "id": "nope", "name": "x"})
        self.assertEqual(len(self.p.pk({"action": "delete", "id": kid})["keys"]), 1)
        with self.assertRaises(ValueError) as e:
            self.p.pk({"action": "delete", "id": got["keys"][0]["id"]})
        self.assertIn("the last passkey", str(e.exception))
        # the one taken away signs in no more
        p = Pages(self.S)
        p.login()
        opts = p.mfa({"action": "pk_begin"})
        with self.assertRaises(ValueError):
            p.mfa(dict(second.get(opts), action="check"))
        ev = " ".join(e["words"] for e in self.S.events(limit=40)["events"])
        for w in ("added a passkey (Test device, for https://fakeigd.test/)", "named a passkey my iPhone",
                  "took a passkey away (my iPhone"):
            self.assertIn(w, ev)

    def test_add_refusals(self):
        opts = self.p.pk({"action": "add_begin"})
        for words, kw in (("not from these pages", dict(origin="https://evil.test")),
                          ("for another name", dict(rp_id="evil.test")),
                          ("did not check who it was", dict(flags=0x41))):
            with self.assertRaises(ValueError) as e:
                self.p.pk(dict(Device(-7).create(opts, **kw), action="add_finish"))
            self.assertIn(words, str(e.exception))
        # the same device twice
        self.dev.count += 1
        with self.assertRaises(ValueError) as e:
            self.p.pk(dict(self.dev.create(opts), action="add_finish"))
        self.assertIn("has a passkey for this account already", str(e.exception))

    def test_only_soon_after_the_second_step(self):
        self.S.session_merge(self.p.token, {"mfa_at": int(time.time()) - AP.PK_ADD_FRESH - 5})
        d = self.p.pk()
        self.assertFalse(d["can_add"])
        self.assertIn("within 15 minutes", d["why"])
        with self.assertRaises(ValueError):
            self.p.pk({"action": "add_begin"})

    def test_ten_at_most(self):
        for _ in range(AP.PK_MAX - 1):
            opts = self.p.pk({"action": "add_begin"})
            self.p.pk(dict(Device(-7).create(opts), action="add_finish"))
        d = self.p.pk()
        self.assertEqual((len(d["keys"]), d["can_add"]), (10, False))
        with self.assertRaises(ValueError):
            self.p.pk({"action": "add_begin"})

    def test_by_an_address(self):
        self.p.host = "127.0.0.1"
        d = self.p.pk()
        self.assertFalse(d["can_add"])
        self.assertIn("not by an address", d["why"])
        with self.assertRaises(ValueError):
            self.p.pk({"action": "add_begin"})

    def test_not_a_passkey_account(self):
        p = Pages(self.S)
        p.login("viewer")
        p.mfa({"action": "enrol_start", "kind": "app"})
        s, _a = self.S.pending(p.token)
        p.mfa({"action": "enrol_confirm", "code": ST.totp(s["data"]["mfa_new"])})
        self.assertEqual(p.pk()["mine"], False)
        with self.assertRaises(ValueError):
            p.pk({"action": "add_begin"})

    def test_a_waiting_sign_in_may_not(self):
        p = Pages(self.S)
        p.login()
        with self.assertRaises(PermissionError):
            p.pk()

    def test_reset_takes_them(self):
        import igd_panes as PN
        me = self.S.session(self.p.token)
        ctx = PN.Ctx(Handler(HOST, self.p.token, {"action": "mfa_reset", "name": "admin"}), "POST", "/api/users",
                     {}, me, self.S, {}, AP, self.S.add_event)
        self.assertIn("is reset", AP.users_post(ctx)["message"])
        self.assertEqual(self.S.mfa_get("admin"), {})
        self.assertIsNone(self.S.session(self.p.token))
        self.assertEqual(Pages(self.S).login()["mfa"], "enrol")
        self.assertIn("(it was a passkey (Face ID, Touch ID, Windows Hello))",
                      " ".join(e["words"] for e in self.S.events(limit=10)["events"]))


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
