"""api_acme.py - Settings → Automatic certificates (otp's ACME, for one server).

The certificate of these pages ordered from Let's Encrypt - or another ACME CA (RFC 8555),
its staging too - for the names given, and renewed by itself well before it runs out: the
CA's own renewal window (ARI, RFC 9773) where it has one, else when fewer days are left than
acme_days (a third of its life at most). As otp does it, in stdlib Python: the account key and
every JWS signature made with the openssl command (ES256/ES384, or RS256), nothing else.

How the CA checks the names:
  HTTP-01 - it asks http://NAME/.well-known/acme-challenge/TOKEN: nginx's server on port 80
            sends that to web/acme.php, which asks this API (GET /api/acme/challenge, a public
            route - the API token still) for the answer kept here while the order waits;
  DNS-01  - a TXT record _acme-challenge.NAME (or, with a zone of its own for them, a CNAME
            in your DNS to it): put in by nsupdate (RFC 2136, a TSIG key), Cloudflare's API,
            an acme-dns server, deSEC.io's API - or by hand, shown on the page.

The certificate that comes is put in nginx through Certificates and TLS (api_tls.put_pem →
root_tls.py); the one it had before is kept by root to go back to. Every order is written
down step by step (the log of orders), and an event says how it went.

One server: no cluster, no VIP address, no acme push - those parts of otp's are left out.
"""
import base64
import calendar
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = "acme"

ACME_CAS = {"letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
            "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory"}
EVERY = float(os.environ.get("FAKE_IGD_ACME_EVERY") or 3600)        # a look at what is due
RETRY = float(os.environ.get("FAKE_IGD_ACME_RETRY") or 6 * 3600)    # after a failed order
ARI_EVERY = float(os.environ.get("FAKE_IGD_ACME_ARI_EVERY") or 6 * 3600)
SETTLE = float(os.environ.get("FAKE_IGD_ACME_SETTLE") or 1)
MANUAL_WAIT = float(os.environ.get("FAKE_IGD_ACME_MANUAL_WAIT") or 3600)
NSUPDATE = os.environ.get("FAKE_IGD_NSUPDATE") or "nsupdate"
LOG_KEPT = 100
UA = "fake-igd (acme)"

KEY_WORDS = {"ec": "ECDSA P-256", "ec384": "ECDSA P-384", "rsa2048": "RSA 2048", "rsa3072": "RSA 3072",
             "rsa4096": "RSA 4096"}
CERT_KEYS = {"dual": ("rsa2048", "ec"), "dual-strong": ("rsa4096", "ec384"), "ec": ("ec",), "ec384": ("ec384",),
             "rsa2048": ("rsa2048",), "rsa3072": ("rsa3072",), "rsa4096": ("rsa4096",)}
FQDN_RE = re.compile(r"^(?=.{1,253}\Z)(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                     r"(?:[A-Za-z]{2,63}|[Xx][Nn]--[A-Za-z0-9-]{1,59})\Z")


def _name_bad(v):
    return "" if FQDN_RE.match(v) else "%s is not a full DNS name (like igd.example.cz)" % v[:80]


def _https_bad(v):
    return "" if re.match(r"^https://[^\s/]+(/\S*)?\Z", v) else "an https:// address"


def _mail_bad(v):
    return "" if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+\Z", v) else "a mail address"


def _host_bad(v):
    return "" if re.match(r"^(\[[0-9A-Fa-f:.]+\](:\d{1,5})?|[0-9A-Fa-f:]+|[A-Za-z0-9.-]{1,253}(:\d{1,5})?)\Z", v) \
        else "a host name or address, with :port where it is not 53"


def _resolvers_bad(v):
    for w in re.split(r"[\s,;]+", v.strip()):
        if w:
            try:
                ipaddress.ip_address(w)
            except ValueError:
                return "%s is not an address (1.1.1.1, 9.9.9.9)" % w[:60]
    return ""


ON = ("acme", "true")
DNS01 = ("acme_challenge", "dns-01")
SETTINGS = [
    {"key": "acme", "kind": "bool", "default": False, "name": "Certificates from an ACME CA",
     "says": "The certificate of these pages ordered from the CA and renewed by itself - by HTTP-01 port 80 of "
             "each name must reach this server; by DNS-01 nothing has to be open. Off until switched on."},
    {"key": "acme_names", "kind": "list", "default": [], "name": "The names of the certificate", "only_when": ON,
     "check": _name_bad, "most": 4000,
     "says": "The full DNS names it is for - the first is its name (CN), all of them in its alternative "
             "names. A wildcard (<code>*.example.cz</code>) only by DNS-01. Empty: the names in nginx's "
             "<code>server_name</code> that are full DNS names."},
    {"key": "acme_email", "kind": "text", "default": "", "name": "Mail of the account at the CA", "only_when": ON,
     "check": _mail_bad, "says": "Where the CA writes when a certificate runs out unrenewed. Empty: none."},
    {"key": "acme_ca", "kind": "choice", "default": "letsencrypt", "name": "The CA", "only_when": ON,
     "choices": [("letsencrypt", "Let\u2019s Encrypt"),
                 ("letsencrypt-staging", "Let\u2019s Encrypt - staging (to try it)"),
                 ("custom", "another ACME CA (step-ca, an internal CA...)")],
     "says": "Let\u2019s Encrypt, its staging (certificates browsers do not trust - to try it), or another."},
    {"key": "acme_url", "kind": "text", "default": "", "name": "Its ACME directory",
     "only_when": ("acme_ca", "custom"), "check": _https_bad,
     "says": "The directory of another ACME CA, <code>https://ca.example.cz/acme/acme/directory</code>."},
    {"key": "acme_ca_pem", "kind": "textarea", "default": "", "name": "The CA\u2019s own certificate",
     "only_when": ("acme_ca", "custom"), "most": 20000,
     "says": "The CA\u2019s root (PEM), where the system does not trust it already."},
    {"key": "acme_days", "kind": "int", "default": 30, "min": 7, "max": 60,
     "name": "Renewed when fewer days are left than", "only_when": ON,
     "says": "Let\u2019s Encrypt\u2019s certificates last 90 days; 30 is what it advises. The CA\u2019s own "
             "renewal window (ARI) comes first where it has one."},
    {"key": "acme_key", "kind": "choice", "default": "dual", "name": "The key of the certificate", "only_when": ON,
     "choices": [("dual", "Both: RSA 2048 + ECDSA P-256 (advised)"), ("dual-strong", "Both: RSA 4096 + ECDSA P-384"),
                 ("ec", "ECDSA P-256"), ("ec384", "ECDSA P-384"), ("rsa2048", "RSA 2048"), ("rsa3072", "RSA 3072"),
                 ("rsa4096", "RSA 4096")],
     "says": "Let\u2019s Encrypt takes RSA keys of 2048, 3072 or 4096 bits and ECDSA keys on P-256 or P-384. "
             "Both - what Let\u2019s Encrypt advises - orders two certificates for the names: RSA served by "
             "default, the much smaller ECDSA one to the clients that say they take it."},
    {"key": "acme_account_key", "kind": "choice", "default": "ec", "name": "The key of the ACME account",
     "only_when": ON,
     "choices": [("ec", "ECDSA P-256 (ES256)"), ("ec384", "ECDSA P-384 (ES384)"), ("rsa2048", "RSA 2048 (RS256)"),
                 ("rsa3072", "RSA 3072 (RS256)"), ("rsa4096", "RSA 4096 (RS256)")],
     "says": "The key the account with the CA signs with - never one of a certificate. A change makes a new "
             "account at the next order."},
    {"key": "acme_profile", "kind": "choice", "default": "", "name": "The profile of the certificate",
     "only_when": ON,
     "choices": [("", "the CA\u2019s own (classic at Let\u2019s Encrypt)"), ("classic", "classic - 90 days"),
                 ("tlsserver", "tlsserver - 90 days, for TLS servers only"), ("shortlived", "shortlived - 6 days")],
     "says": "What the CA makes the certificate as, where it offers profiles (Let\u2019s Encrypt does): "
             "shortlived lasts 6 days and is renewed every two or three. Another CA without profiles: its own."},
    {"key": "acme_challenge", "kind": "choice", "default": "http-01", "name": "How the CA checks the name",
     "only_when": ON,
     "choices": [("http-01", "HTTP-01 - the CA asks port 80 of the name"),
                 ("dns-01", "DNS-01 - a TXT record in DNS (no port open to the internet)")],
     "says": "HTTP-01 needs port 80 of the name reachable from the internet (or from the CA, for a CA of your "
             "own). DNS-01 needs nothing open: the CA reads a TXT record."},
    {"key": "acme_dns", "kind": "choice", "default": "manual", "name": "Who puts the TXT record in DNS",
     "only_when": DNS01,
     "choices": [("manual", "by hand - the record is shown here, you put it in"),
                 ("rfc2136", "RFC 2136 dynamic update with a TSIG key (BIND, PowerDNS, Knot...)"),
                 ("cloudflare", "Cloudflare, with an API token"), ("acmedns", "an acme-dns server"),
                 ("desec", "deSEC.io (free), with an API token - a CNAME in your DNS")],
     "says": "By hand the order waits up to an hour for you; the others renew by themselves."},
    {"key": "acme_dns_server", "kind": "text", "default": "", "name": "The DNS server taking the updates",
     "only_when": ("acme_dns", "rfc2136"), "check": _host_bad,
     "says": "The primary DNS server of the zone, <code>ns1.example.cz</code> or with a port "
             "<code>10.0.0.53:53</code>."},
    {"key": "acme_dns_zone", "kind": "text", "default": "", "name": "The zone", "only_when": ("acme_dns", "rfc2136"),
     "check": lambda v: "" if re.match(r"^[A-Za-z0-9.-]{1,253}\Z", v) else "a DNS zone, example.cz",
     "says": "Where the record goes, <code>example.cz</code>. Empty: as the server finds it."},
    {"key": "acme_dns_tsig_name", "kind": "text", "default": "", "name": "The name of the TSIG key",
     "only_when": ("acme_dns", "rfc2136"),
     "check": lambda v: "" if re.match(r"^[A-Za-z0-9._-]{1,253}\Z", v) else "a key name, fake-igd-acme.",
     "says": "As the DNS server knows it, <code>fake-igd-acme.</code>; allowed to update _acme-challenge "
             "records only."},
    {"key": "acme_dns_tsig_alg", "kind": "choice", "default": "hmac-sha256", "name": "Its algorithm",
     "only_when": ("acme_dns", "rfc2136"),
     "choices": [(a, a) for a in ("hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1", "hmac-md5")],
     "says": "As the key was made (tsig-keygen makes hmac-sha256)."},
    {"key": "acme_dns_tsig_secret", "kind": "secret", "default": "", "name": "The TSIG secret",
     "only_when": ("acme_dns", "rfc2136"),
     "check": lambda v: "" if re.match(r"^[A-Za-z0-9+/=]{4,512}\Z", v) else "base64, as tsig-keygen gives it",
     "says": "The key\u2019s secret (base64). Written to a file only fake-igd reads for the moment nsupdate runs."},
    {"key": "acme_dns_token", "kind": "secret", "default": "", "name": "The Cloudflare API token",
     "only_when": ("acme_dns", "cloudflare"), "says": "A token with Zone - DNS - Edit for the zone."},
    {"key": "acme_dns_url", "kind": "text", "default": "", "name": "The acme-dns server",
     "only_when": ("acme_dns", "acmedns"), "check": _https_bad,
     "says": "<code>https://auth.acme-dns.example.cz</code>; _acme-challenge.NAME is a CNAME to the subdomain below."},
    {"key": "acme_dns_user", "kind": "text", "default": "", "name": "acme-dns user",
     "only_when": ("acme_dns", "acmedns"), "says": "From the registration at acme-dns."},
    {"key": "acme_dns_key", "kind": "secret", "default": "", "name": "acme-dns key",
     "only_when": ("acme_dns", "acmedns"), "says": "From the registration at acme-dns."},
    {"key": "acme_dns_subdomain", "kind": "text", "default": "", "name": "acme-dns subdomain",
     "only_when": ("acme_dns", "acmedns"), "says": "From the registration at acme-dns."},
    {"key": "acme_desec_domain", "kind": "text", "default": "", "name": "The domain at deSEC",
     "only_when": ("acme_dns", "desec"), "check": _name_bad,
     "says": "Your domain at deSEC, <code>example.dedyn.io</code> (free) or one of your own whose DNS is there. "
             "The records go into it; your DNS has a CNAME to it for each name - <i>In your DNS</i> above says which."},
    {"key": "acme_desec_token", "kind": "secret", "default": "", "name": "The deSEC API token",
     "only_when": ("acme_dns", "desec"),
     "says": "A token from deSEC (Token management) - one that may change this domain\u2019s records."},
    {"key": "acme_dns_alias", "kind": "text", "default": "", "name": "The TXT records go into", "only_when": DNS01,
     "check": lambda v: "" if re.match(r"^[A-Za-z0-9.-]{1,253}\Z", v) else "a DNS zone, acme.example.net",
     "says": "A zone the records go into instead of the name\u2019s own (<code>acme.example.net</code>), each name "
             "with a CNAME to it in your DNS - <i>In your DNS</i> above says which. Empty: _acme-challenge.NAME "
             "itself. Not used with acme-dns."},
    {"key": "acme_dns_wait", "kind": "int", "default": 30, "min": 0, "max": 600,
     "name": "Wait for DNS to carry it (s)", "only_when": DNS01,
     "says": "How long the record is given to reach every DNS server before the CA is asked."},
    {"key": "acme_resolvers", "kind": "text", "default": "", "name": "DNS servers for ACME", "only_when": ON,
     "check": _resolvers_bad,
     "says": "The DNS servers asked on this page: <i>Check DNS</i>, and whether the TXT record can be seen "
             "before the CA is asked - <code>1.1.1.1, 9.9.9.9</code> to see what the internet sees. Empty: the "
             "machine\u2019s own (/etc/resolv.conf)."},
]

WORK = {"busy": False, "at": 0.0, "says": "", "began": 0.0}
LAST = {"look": 0.0, "ari": 0.0}
LOCK = threading.Lock()


class AcmeError(Exception):
    pass


def _tls():
    """Certificates and TLS, as the API loaded it (one copy of its module, never a second)."""
    import igd_panes
    mod = igd_panes.module("tls")
    if mod is None:
        raise AcmeError("Certificates and TLS (api_tls.py) is not loaded")
    return mod


def _b64u(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _meta(store, k):
    try:
        got = json.loads(store.get_meta(k) or "null")
    except ValueError:
        return None
    return got if isinstance(got, (dict, list)) else None


def _set(store, k, v):
    store.set_meta(k, json.dumps(v))


def _drop(store, k):
    store.run("DELETE FROM meta WHERE k = ?", (k,))


def conf(ctx):
    """The settings of an order, read once when it begins."""
    return {s["key"]: ctx.setting(s["key"]) for s in SETTINGS}


def directory_url(c):
    if c.get("acme_ca") == "custom":
        return str(c.get("acme_url") or "").strip()
    return ACME_CAS.get(c.get("acme_ca") or "letsencrypt", ACME_CAS["letsencrypt"])


def _rfc3339(text):
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)[Tt ](\d\d):(\d\d):(\d\d)(\.\d+)?(Z|z|[+-]\d\d:\d\d)$", str(text or "").strip())
    if not m:
        return 0.0
    t = calendar.timegm(tuple(int(m.group(i)) for i in range(1, 7)) + (0, 0, 0))
    if m.group(8) not in ("Z", "z"):
        sign = 1 if m.group(8)[0] == "+" else -1
        t -= sign * (int(m.group(8)[1:3]) * 3600 + int(m.group(8)[4:6]) * 60)
    return float(t) + (float(m.group(7)) if m.group(7) else 0.0)


def ari_cert_id(cert):
    """A certificate's ARI id (RFC 9773): base64url(AKI) "." base64url(serial's DER bytes)."""
    if not cert:
        return ""
    try:
        out = _tls().openssl(["x509", "-noout", "-serial", "-ext", "authorityKeyIdentifier"], cert,
                             what="the certificate").decode()
    except ValueError:
        return ""
    serial = re.search(r"serial=([0-9A-Fa-f]+)", out)
    aki = re.search(r"(?:keyid:)?((?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2})", out.split("Authority Key Identifier", 1)[-1])
    if not serial or not aki:
        return ""
    h = serial.group(1)
    sb = bytes.fromhex(h.rjust(len(h) + len(h) % 2, "0"))
    if sb and sb[0] & 0x80:
        sb = b"\x00" + sb
    return "%s.%s" % (_b64u(bytes.fromhex(aki.group(1).replace(":", ""))), _b64u(sb))


def _account_gone(kind, said):
    if kind.endswith(":accountDoesNotExist") or kind == "accountDoesNotExist":
        return True
    low = str(said or "").lower()
    return kind.endswith("unauthorized") and "account" in low and \
        any(w in low for w in ("deactivated", "not valid", "not found", "does not exist", "revoked"))


# ---- one conversation with the CA -------------------------------------------------------------
class Acme(object):
    """The account, its key, the nonces - as otp's class Acme."""

    def __init__(self, ctx, c):
        self.ctx, self.store, self.c = ctx, ctx.store, c
        self.dir_url = directory_url(c)
        if not re.match(r"^https://[^\s]+\Z", self.dir_url):
            raise AcmeError("the ACME directory is an https:// address")
        state = ctx.cfg.get("state_dir") or "/var/lib/fake-igd"
        self.work = tempfile.mkdtemp(prefix="acme-", dir=state if os.path.isdir(state) else None)
        os.chmod(self.work, 0o700)
        self.nonce = None
        self.kid = None
        self._jwk_done = None
        self.sslctx = ssl.create_default_context()
        pem = str(c.get("acme_ca_pem") or "").strip()
        if pem and c.get("acme_ca") == "custom":
            try:
                self.sslctx.load_verify_locations(cadata=pem)
            except (ssl.SSLError, ValueError) as e:
                self.close()
                raise AcmeError("the CA's own certificate does not read: %s" % e)
        try:
            self.dir = self._get(self.dir_url)[0]
            self._account()
        except BaseException:
            self.close()
            raise

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _req(self, url, data=None, method=None, accept="application/json"):
        if not str(url).startswith("https://"):
            raise AcmeError("the CA sent an address that is not https: %s" % url)
        req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"),
                                     headers={"User-Agent": UA, "Accept": accept})
        if data is not None:
            req.add_header("Content-Type", "application/jose+json")
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.sslctx) as r:
                body, headers, status = r.read(1 << 20), r.headers, r.status
        except urllib.error.HTTPError as e:
            body, headers, status = e.read(1 << 20), e.headers, e.code
        except (OSError, ssl.SSLError) as e:
            raise AcmeError("the CA did not answer (%s): %s" % (urllib.parse.urlsplit(url).hostname,
                                                               getattr(e, "reason", e)))
        if headers.get("Replay-Nonce"):
            self.nonce = headers["Replay-Nonce"]
        return body, headers, status

    def _get(self, url):
        body, headers, status = self._req(url)
        if status >= 400:
            raise AcmeError("the CA said %d: %s" % (status, body[:200].decode("utf-8", "replace")))
        try:
            return json.loads(body.decode("utf-8")), headers
        except ValueError:
            raise AcmeError("the CA's answer is not JSON (%s)" % url)

    def _key_file(self):
        p = os.path.join(self.work, "account.pem")
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(self.key_pem)
        return p

    def _alg(self):
        kind = getattr(self, "akind", "ec")
        if kind == "ec384":
            return "ES384", "-sha384", 48
        if kind.startswith("rsa"):
            return "RS256", "-sha256", 0
        return "ES256", "-sha256", 32

    def _jwk(self):
        if self._jwk_done:
            return self._jwk_done
        o = _tls().openssl
        alg, _d, size = self._alg()
        if alg == "RS256":
            txt = o(["pkey", "-in", self._key_file(), "-noout", "-text_pub"], what="the account key").decode()
            m = re.search(r"(?s)Modulus:\s*\n(.*?)\n\S", txt)
            e = re.search(r"Exponent:\s*(\d+)", txt)
            if not m or not e:
                raise AcmeError("the RSA account key does not read")
            n = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", m.group(1))).lstrip(b"\x00")
            ev = int(e.group(1))
            jwk = {"e": _b64u(ev.to_bytes((ev.bit_length() + 7) // 8, "big")), "kty": "RSA", "n": _b64u(n)}
        else:
            der = o(["pkey", "-in", self._key_file(), "-pubout", "-outform", "DER"], what="the account key")
            point = der[-2 * size:]
            jwk = {"crv": "P-384" if size == 48 else "P-256", "kty": "EC", "x": _b64u(point[:size]),
                   "y": _b64u(point[size:])}
        self._jwk_done = jwk
        return jwk

    def thumbprint(self):
        return _b64u(hashlib.sha256(json.dumps(self._jwk(), separators=(",", ":"), sort_keys=True).encode()).digest())

    def _sign(self, data):
        alg, digest, size = self._alg()
        der = _tls().openssl(["dgst", digest, "-sign", self._key_file()], data=data, what="signing for the CA")
        if alg == "RS256":
            return der
        i = 2 if der[1] < 0x80 else 3

        def integer(at):
            n = der[at + 1]
            v = der[at + 2:at + 2 + n].lstrip(b"\x00")
            return v.rjust(size, b"\x00"), at + 2 + n
        r, i = integer(i)
        s, _ = integer(i)
        return r + s

    def post(self, url, payload, use_jwk=False):
        anew = False
        for attempt in (1, 2, 3):
            if not self.nonce:
                self._req(self.dir["newNonce"], method="HEAD")
            protected = {"alg": self._alg()[0], "nonce": self.nonce, "url": url}
            if use_jwk or not self.kid:
                protected["jwk"] = self._jwk()
            else:
                protected["kid"] = self.kid
            p64 = _b64u(json.dumps(protected))
            b64 = "" if payload is None else _b64u(json.dumps(payload))
            sig = _b64u(self._sign(("%s.%s" % (p64, b64)).encode("ascii")))
            self.nonce = None
            body, headers, status = self._req(url, json.dumps({"protected": p64, "payload": b64, "signature": sig})
                                              .encode("utf-8"),
                                              accept="application/pem-certificate-chain" if "cert" in url
                                              else "application/json")
            if status == 400 and b"badNonce" in body and attempt == 1:
                continue
            if status >= 400:
                try:
                    err = json.loads(body.decode("utf-8"))
                    said, kind = err.get("detail") or err.get("type"), str(err.get("type") or "")
                except (ValueError, AttributeError):
                    said, kind = body[:200].decode("utf-8", "replace"), ""
                if self.kid and not use_jwk and not anew and url != self.dir.get("newAccount") and \
                        _account_gone(kind, said):
                    anew = True
                    self._account(fresh=True)
                    continue
                raise AcmeError("the CA refused it: %s" % said)
            return body, headers
        raise AcmeError("the CA kept refusing the nonce")

    def post_json(self, url, payload):
        body, headers = self.post(url, payload)
        try:
            return (json.loads(body.decode("utf-8")) if body else {}), headers
        except ValueError:
            raise AcmeError("the CA's answer is not JSON (%s)" % url)

    def _account(self, fresh=False):
        row = {} if fresh else (_meta(self.store, "acme:account") or {})
        pem = row.get("key") or ""
        self.akind = str(self.c.get("acme_account_key") or "ec")
        if self.akind not in KEY_WORDS:
            self.akind = "ec"
        if row.get("directory") != self.dir_url or (row.get("kind") or "ec") != self.akind:
            pem = ""
        self.kid = None
        self._jwk_done = None
        try:
            os.unlink(os.path.join(self.work, "account.pem"))
        except OSError:
            pass
        if not pem:
            pem = _tls().new_key(self.akind)
            row = {}
        self.key_pem = pem
        if row.get("kid"):
            self.kid = row["kid"]
            return
        mail = str(self.c.get("acme_email") or "").strip()
        payload = {"termsOfServiceAgreed": True}
        if mail:
            payload["contact"] = ["mailto:" + mail]
        _body, headers = self.post(self.dir["newAccount"], payload, use_jwk=True)
        self.kid = headers.get("Location")
        if not self.kid:
            raise AcmeError("the CA made no account")
        _set(self.store, "acme:account", {"key": pem, "kid": self.kid, "directory": self.dir_url, "email": mail,
                                          "at": time.time(), "kind": self.akind})

    def _poll(self, url, done, what, secs=90):
        end = time.time() + secs
        while True:
            got, hdr = self.post_json(url, None)
            st = got.get("status")
            if st in done:
                return got
            if st == "invalid":
                errs = [ch.get("error", {}).get("detail") for ch in got.get("challenges") or [] if ch.get("error")] \
                    or [(got.get("error") or {}).get("detail")]
                raise AcmeError("%s: %s" % (what, "; ".join(e for e in errs if e) or "invalid"))
            if time.time() > end:
                raise AcmeError("%s: the CA has not said in %d s (%s)" % (what, secs, st))
            try:
                wait = float(hdr.get("Retry-After") or 2)
            except (TypeError, ValueError):
                wait = 2.0
            time.sleep(max(1.0, min(30.0, wait, max(0.0, end - time.time()))))

    def renewal_info(self, cert_id):
        base = self.dir.get("renewalInfo")
        if not base or not cert_id:
            return None
        got, _h = self._get(base.rstrip("/") + "/" + cert_id)
        w = got.get("suggestedWindow") or {}
        start, end = _rfc3339(w.get("start")), _rfc3339(w.get("end"))
        if not start or not end or end < start:
            return None
        return {"start": start, "end": end, "url": got.get("explanationURL") or ""}

    def order(self, names, say, key_kind=None, replaces=""):
        c = self.c
        say("ordered from the CA" + (" (%s)" % KEY_WORDS.get(key_kind, key_kind) if key_kind else ""))
        ask = {"identifiers": [{"type": "dns", "value": n} for n in names]}
        prof = str(c.get("acme_profile") or "")
        offered = (self.dir.get("meta") or {}).get("profiles") or {}
        if prof and prof in offered:
            ask["profile"] = prof
        elif prof:
            say("this CA offers no profile %s - its own is used" % prof)
        if replaces and self.dir.get("renewalInfo"):
            ask["replaces"] = replaces
        try:
            got, headers = self.post_json(self.dir["newOrder"], ask)
        except AcmeError as e:
            # Only the account that ordered a certificate may say it replaces it (otp 1.0.199).
            if "replaces" not in ask or "replace" not in str(e).lower():
                raise
            say("the CA does not take it as the renewal of the one before (another account ordered that one) - "
                "ordered as a new certificate")
            ask.pop("replaces", None)
            got, headers = self.post_json(self.dir["newOrder"], ask)
        order_url = headers.get("Location")
        thumb = self.thumbprint()
        kind = "dns-01" if c.get("acme_challenge") == "dns-01" else "http-01"
        for az in got.get("authorizations") or []:
            a, _h = self.post_json(az, None)
            if a.get("status") == "valid":
                continue
            name = (a.get("identifier") or {}).get("value")
            ch = [x for x in a.get("challenges") or [] if x.get("type") == kind]
            if not ch:
                raise AcmeError("the CA offers no %s challenge for %s%s" % (
                    kind.upper(), name, " (a wildcard is given by DNS-01 only)" if a.get("wildcard") else ""))
            token = ch[0]["token"]
            if not re.match(r"^[A-Za-z0-9_-]{8,256}\Z", token):
                raise AcmeError("the CA sent a token that is not one")
            auth = token + "." + thumb
            if kind == "dns-01":
                txt = _b64u(hashlib.sha256(auth.encode()).digest())
                undo = dns_put(self.ctx, c, name, txt, say)
                try:
                    say("the CA looks up _acme-challenge.%s" % name)
                    self.post_json(ch[0]["url"], {})
                    self._poll(az, ("valid",), "the CA did not take %s" % name, 180)
                finally:
                    try:
                        undo()
                    except Exception as e:                  # noqa: BLE001 - said, the order goes on
                        say("the TXT record of %s was not taken away: %s" % (name, e))
                continue
            _set(self.store, "acme:chal:" + token, {"auth": auth, "at": time.time(), "name": name})
            time.sleep(SETTLE)
            say("the CA looks at http://%s/.well-known/acme-challenge/" % name)
            try:
                self.post_json(ch[0]["url"], {})
                self._poll(az, ("valid",), "the CA did not take %s" % name)
            finally:
                _drop(self.store, "acme:chal:" + token)
        T = _tls()
        key, csr = T.make_csr(names[0], names[1:], key_kind or "ec")
        der = T.openssl(["req", "-outform", "DER"], data=csr, what="the request")
        say("the certificate is made")
        if order_url:
            self._poll(order_url, ("ready", "processing", "valid"), "the order", 60)
        o, _h = self.post_json(got["finalize"], {"csr": _b64u(der)})
        if o.get("status") != "valid":
            o = self._poll(order_url, ("valid",), "the order", 120)
        body, _h = self.post(o["certificate"], None)
        return key, body.decode("utf-8")


# ---- what is ordered, and when -----------------------------------------------------------------
def names_from_nginx():
    try:
        return [n for n in _tls().nginx_now().get("names") or [] if FQDN_RE.match(n) and not n.startswith("*")]
    except Exception:                                   # noqa: BLE001
        return []


def names_of(ctx):
    given = ctx.setting("acme_names") or []
    if isinstance(given, str):
        given = [x.strip() for x in re.split(r"[,\s]+", given) if x.strip()]
    out = []
    for n in (given or names_from_nginx()):
        n = n.strip().lower().rstrip(".")
        if n and n not in out:
            out.append(n)
    return out[:100]


def state(store):
    return _meta(store, "acme:state") or {}


def care(store):
    return (_meta(store, "acme:care") or {}).get("on", True)


def care_set(ctx, on, by, why=""):
    was = care(ctx.store)
    _set(ctx.store, "acme:care", {"on": bool(on), "at": time.time(), "by": by, "why": why})
    if was != bool(on):
        ctx.event("%s: ACME %s the certificate of these pages%s" % (
            by or "fake-igd", "looks after" if on else "leaves alone", (" (%s)" % why) if why else ""))


def how_now(store):
    return ((_meta(store, "tls:how") or {}).get("how")) or ""


def due(ctx, names=None):
    """Why the certificate is to be ordered now, or ''."""
    names = names if names is not None else names_of(ctx)
    if not ctx.setting("acme") or not names or not care(ctx.store):
        return ""
    st = state(ctx.store)
    if st.get("failed_at") and time.time() - float(st["failed_at"]) < RETRY and st.get("names") == names:
        return ""
    if how_now(ctx.store) != "ACME" or st.get("names") != names:
        return "not ordered yet for %s" % ", ".join(names)
    cur = _tls().current() or {}
    info = cur.get("info") or {}
    ari = _meta(ctx.store, "acme:ari") or {}
    if ari.get("pick") and ari.get("cert") == (info.get("fingerprint") or "") and \
            time.time() - float(ari.get("at") or 0) < 2 * 86400 and time.time() >= float(ari["pick"]):
        return "the CA's renewal window (%s - %s)" % (
            time.strftime("%Y-%m-%d %H:%M", time.gmtime(ari["start"])), time.strftime("%Y-%m-%d %H:%M", time.gmtime(ari["end"])))
    na, nb = float(info.get("not_after") or st.get("not_after") or 0), float(info.get("not_before") or 0)
    left = (na - time.time()) / 86400
    days = float(ctx.setting("acme_days") or 30)
    if nb and na > nb:
        days = min(days, (na - nb) / 86400 / 3)
    if left < days:
        return "%d days left" % int(left)
    return ""


def http80(ctx, names, say=None, wait=60):
    """Port 80 made ready for HTTP-01 by root (root_tls.py acme_http): the location to acme.php
    where an older fake-igd.conf lacks it, the names in its server_name. Waited for when `wait`."""
    plain = [n for n in names if not n.startswith("*.")]
    done = _meta(ctx.store, "acme:http80") or {}
    if done.get("ok") and done.get("names") == plain:
        return True
    T = _tls()
    ident = ctx.ask_root({"action": "acme_http", "names": plain}, kind="tls")
    T.set_meta(ctx.store, "tls:asked", {"id": ident, "at": time.time(), "action": "acme_http",
                                        "by": (ctx.me or {}).get("name", "")})
    if say:
        say("asked root to make port 80 ready for the CA (%s)" % ", ".join(plain))
    end = time.time() + wait
    while time.time() < end:
        res = ctx.root_result("tls")
        if res.get("id") == ident:
            _set(ctx.store, "acme:http80", {"names": plain, "ok": bool(res.get("ok")), "at": time.time()})
            if not res.get("ok"):
                raise AcmeError("root could not make port 80 ready: %s" % ((res.get("said") or ["?"])[-1]))
            if say:
                say((res.get("said") or ["port 80 is ready"])[0])
            return True
        time.sleep(1)
    if say and wait:
        say("root has not answered in %d s (is fake-igd-web.path active?) - the CA is asked anyway" % wait)
    return False


def say_work(text):
    WORK["says"] = str(text)[:300]


def order(ctx, names, by):
    """One certificate ordered and put in; the state kept, the order written down, an event."""
    steps = []

    def say(t):
        steps.append([round(time.time(), 1), str(t)[:300]])
        say_work(t)
    c = conf(ctx)
    T = _tls()
    began = time.time()
    st = {"names": names, "at": began, "by": by, "ca": directory_url(c), "steps": steps}
    a = None
    try:
        for n in names:
            if not FQDN_RE.match(n):
                raise AcmeError("%s is not a name a CA gives a certificate for (a full DNS name)" % n)
            if n.startswith("*.") and c.get("acme_challenge") != "dns-01":
                raise AcmeError("%s: a wildcard is given by DNS-01 only" % n)
        if c.get("acme_challenge") != "dns-01":
            http80(ctx, names, say)
        a = Acme(ctx, c)
        kinds = CERT_KEYS.get(str(c.get("acme_key") or "dual")) or ("ec",)
        was = state(ctx.store)
        cur = T.current() or {}
        replaces = ari_cert_id(cur.get("pem")) if how_now(ctx.store) == "ACME" else ""
        if replaces and was.get("kid") and was["kid"] != a.kid:
            replaces = ""
        say("the key%s: %s" % ("s" if len(kinds) > 1 else "", " + ".join(KEY_WORDS[k] for k in kinds)))
        key, chain = a.order(names, say, kinds[0], replaces)
        certs = T.PEM_CERT.findall(chain)
        if not certs:
            raise AcmeError("the CA sent no certificate")
        info = T.cert_info(certs[0])
        alt = None
        made = [kinds[0]]
        if len(kinds) > 1:
            say("a second certificate, with a %s key" % KEY_WORDS[kinds[1]])
            try:
                k2, c2 = a.order(names, say, kinds[1])
                c2s = T.PEM_CERT.findall(c2)
                alt = {"cert": c2s[0] + "\n", "chain": "".join(x + "\n" for x in c2s[1:]), "key": k2}
                made.append(kinds[1])
            except (AcmeError, ValueError, IndexError) as e:
                say("the second certificate did not come (%s) - the %s one is put in alone"
                    % (str(e)[:200], KEY_WORDS[kinds[0]]))
                st["alt_said"] = str(e)[:300]
        if not care(ctx.store):
            raise AcmeError("ACME was told to leave this certificate alone while it was being ordered - the "
                            "new one is not put in")
        keep = how_now(ctx.store) != "ACME" and bool(cur.get("pem"))
        T.put_pem(ctx, certs[0] + "\n", "".join(x + "\n" for x in certs[1:]), key, "ACME", by or "fake-igd",
                  alt=alt, keep_before=keep, words="from the CA")
        say("asked root to put it in nginx" + (" (the one before is kept)" if keep else ""))
        st.update(ok=True, kid=a.kid or "", not_after=info.get("not_after"), not_before=info.get("not_before"),
                  issuer=info.get("issuer"), ordered_at=time.time(), cert=certs[0] + "\n",
                  keys=" + ".join(KEY_WORDS[k] for k in made))
        st["steps"] = steps[-40:]
        _set(ctx.store, "acme:state", st)
        _drop(ctx.store, "acme:ari")
        ctx.event("a certificate for %s came from the CA, good until %s" % (
            ", ".join(names), time.strftime("%Y-%m-%d", time.gmtime(info["not_after"])) if info.get("not_after") else "?"),
            kind="acme")
        return st
    except Exception as e:                              # noqa: BLE001 - every failure written down
        if not isinstance(e, (AcmeError, ValueError, OSError)):
            e = AcmeError("%s: %s" % (type(e).__name__, e))
        words = str(e)
        if "NXDOMAIN" in words and c.get("acme_challenge") == "dns-01":
            words += (" - the CA does not find the record: In your DNS → Check DNS, with DNS servers for ACME set "
                      "to public ones (1.1.1.1), shows where the way to it stops")
        say("it did not go: %s" % words[:280])
        st.update(ok=False, failed_at=time.time(), said=words[:600])
        old = state(ctx.store)
        for k in ("not_after", "not_before", "issuer", "ordered_at", "kid", "cert", "keys"):
            if old.get(k):
                st[k] = old[k]
        st["steps"] = steps[-40:]
        _set(ctx.store, "acme:state", st)
        ctx.event("no certificate for %s came from the CA: %s" % (", ".join(names), words[:400]), "bad", kind="acme")
        return st
    finally:
        if a:
            a.close()
        log = _meta(ctx.store, "acme:log") or []
        if not isinstance(log, list):
            log = []
        log.insert(0, {"at": began, "took": round(time.time() - began, 1), "by": by, "names": names,
                       "ok": bool(st.get("ok")), "said": st.get("said") or "", "ca": st.get("ca"),
                       "issuer": st.get("issuer") if st.get("ok") else "", "keys": st.get("keys") if st.get("ok") else "",
                       "not_after": st.get("not_after") if st.get("ok") else None,
                       "challenge": c.get("acme_challenge") or "http-01", "steps": steps[-40:]})
        _set(ctx.store, "acme:log", log[:LOG_KEPT])


def start(ctx, names, by):
    with LOCK:
        if WORK["busy"]:
            raise ValueError("a certificate is being ordered already")
        WORK.update(busy=True, says="starting", began=time.time())

    def go():
        try:
            order(ctx, names, by)
        except Exception as e:                          # noqa: BLE001
            ctx.event("the order for %s stopped: %s" % (", ".join(names), e), "bad", kind="acme")
        finally:
            with LOCK:
                WORK.update(busy=False, says="", began=0.0)
    threading.Thread(target=go, name="fake-igd-acme", daemon=True).start()


def ari_refresh(ctx):
    """The CA's window to renew the certificate in (ARI), a moment in it picked once."""
    st = state(ctx.store)
    if how_now(ctx.store) != "ACME" or not st.get("cert"):
        return
    cid = ari_cert_id(st["cert"])
    if not cid:
        return
    a = None
    try:
        a = Acme(ctx, conf(ctx))
        if not a.dir.get("renewalInfo"):
            return
        w = a.renewal_info(cid)
        if not w:
            return
        fp = ""
        try:
            fp = _tls().cert_info(st["cert"]).get("fingerprint") or ""
        except ValueError:
            pass
        was = _meta(ctx.store, "acme:ari") or {}
        pick = was.get("pick") if (was.get("start"), was.get("end"), was.get("cert")) == (w["start"], w["end"], fp) else None
        if not pick:
            pick = w["start"] + secrets.randbelow(max(1, int(w["end"] - w["start"])))
        _set(ctx.store, "acme:ari", dict(w, pick=pick, at=time.time(), cert=fp))
    except Exception as e:                              # noqa: BLE001 - asked again in six hours
        _set(ctx.store, "acme:ari_said", {"said": str(e)[:300], "at": time.time()})
    finally:
        if a:
            a.close()


def background(ctx):
    """Once a minute: old answers for the CA dropped; once an hour what is due ordered."""
    for r in ctx.store.rows("SELECT k, v FROM meta WHERE k LIKE 'acme:chal:%'"):
        try:
            at = float(json.loads(r["v"]).get("at") or 0)
        except (ValueError, AttributeError, TypeError):
            at = 0
        if time.time() - at > 3600:
            _drop(ctx.store, r["k"])
    if not ctx.setting("acme"):
        return
    if time.time() - LAST["ari"] >= ARI_EVERY and not WORK["busy"]:
        LAST["ari"] = time.time()
        threading.Thread(target=ari_refresh, args=(ctx,), name="fake-igd-acme-ari", daemon=True).start()
    if WORK["busy"] or time.time() - LAST["look"] < EVERY:
        return
    LAST["look"] = time.time()
    names = names_of(ctx)
    why = due(ctx, names)
    if why:
        try:
            start(ctx, names, "fake-igd (renewal: %s)" % why)
        except ValueError:
            pass


def challenge(ctx):
    """What acme.php gives the CA on port 80 - no account: the CA asks."""
    token = ctx.arg("token")
    if not re.match(r"^[A-Za-z0-9_-]{8,256}\Z", token or ""):
        return {"auth": None}
    probe = token.startswith("igd-probe-")
    if not ctx.setting("acme") and not probe:
        return {"auth": None}
    got = _meta(ctx.store, "acme:chal:" + token) or {}
    if not got.get("auth") or time.time() - float(got.get("at") or 0) > 3600 or (probe and not got.get("probe")):
        return {"auth": None}
    return {"auth": got["auth"]}


challenge.PUBLIC = True


# ---- DNS-01 ------------------------------------------------------------------------------------
def dns_where(c, name):
    """(where the TXT record goes, the CNAME your DNS needs or None) - otp's acme_dns_where."""
    name = str(name or "").rstrip(".").lower()
    if name.startswith("*."):
        name = name[2:]
    own = "_acme-challenge." + name
    how = c.get("acme_dns") or "manual"
    if how == "acmedns":
        host = urllib.parse.urlparse(str(c.get("acme_dns_url") or "").strip()).hostname or ""
        sub = str(c.get("acme_dns_subdomain") or "").strip()
        return own, ("%s.%s" % (sub, host) if sub and host else "")
    zone = str(c.get("acme_dns_alias") or "").strip().rstrip(".").lower()
    if how == "desec":
        dom = str(c.get("acme_desec_domain") or "").strip().rstrip(".").lower()
        if dom and (name == dom or name.endswith("." + dom)):
            return own, None
        if not zone or not (zone == dom or zone.endswith("." + dom)):
            zone = dom
    if not zone or name == zone or name.endswith("." + zone):
        return own, None
    there = "_acme-challenge.%s.%s" % (name.split(".")[0], zone)
    return there, there


def _dns_wait(c, say, least=0):
    w = max(int(c.get("acme_dns_wait") or 0), least)
    if w:
        say("waiting %d s for DNS to carry it" % w)
        time.sleep(w)


def dns_put(ctx, c, name, txt, say):
    """The TXT record put in; returns what takes it away again."""
    how = c.get("acme_dns") or "manual"
    rr, cname = dns_where(c, name)
    if cname and how != "acmedns":
        say("the TXT record %s put in DNS (%s; _acme-challenge.%s is a CNAME to it)" % (rr, how, name))
    else:
        say("the TXT record %s put in DNS (%s)" % (rr, how))
    if how == "rfc2136":
        undo = _dns_rfc2136(ctx, c, rr, txt)
    elif how == "cloudflare":
        undo = _dns_cloudflare(c, rr, txt)
    elif how == "acmedns":
        undo = _dns_acmedns(c, txt)
    elif how == "desec":
        undo = _dns_desec(c, rr, txt)
    else:
        undo = _dns_manual(ctx, rr, txt, say)
    if how == "desec":
        _desec_seen(c, rr, txt, say)
    else:
        _dns_wait(c, say)
        if how != "manual":
            txt_seen(c, "_acme-challenge." + name.lstrip("*.").rstrip("."), txt, say)
    return undo


def _dns_rfc2136(ctx, c, rr, txt):
    server = str(c.get("acme_dns_server") or "").strip()
    if not server:
        raise AcmeError("the DNS server for the updates is not set")
    keyname = str(c.get("acme_dns_tsig_name") or "").strip()
    secret = str(c.get("acme_dns_tsig_secret") or "")
    alg = c.get("acme_dns_tsig_alg") or "hmac-sha256"
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?\Z", server)
    if m:
        host, port = m.group(1), m.group(2) or ""
    elif server.count(":") > 1:
        host, port = server, ""
    else:
        host, _c, port = server.partition(":")
    zone = str(c.get("acme_dns_zone") or "").strip()
    state_dir = ctx.cfg.get("state_dir") or "/var/lib/fake-igd"

    def run(op):
        work = tempfile.mkdtemp(prefix="dns-", dir=state_dir if os.path.isdir(state_dir) else None)
        os.chmod(work, 0o700)
        try:
            args = [NSUPDATE]
            if keyname:
                kf = os.path.join(work, "tsig.key")
                fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write('key "%s" {\n  algorithm %s;\n  secret "%s";\n};\n' % (keyname, alg, secret))
                args += ["-k", kf]
            script = "server %s %s\n" % (host, port or "53")
            if zone:
                script += "zone %s\n" % zone
            script += ('update add %s 60 TXT "%s"\nsend\n' % (rr, txt)) if op == "add" else \
                ('update delete %s TXT "%s"\nsend\n' % (rr, txt))
            try:
                got = subprocess.run(args, input=script, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True, timeout=60)
            except FileNotFoundError:
                raise AcmeError("nsupdate is not on this machine (dnf install bind-utils)")
            if got.returncode != 0:
                raise AcmeError("the DNS server did not take the update: %s" % (got.stderr or got.stdout).strip()[-300:])
        finally:
            shutil.rmtree(work, ignore_errors=True)
    run("add")
    return lambda: run("delete")


def _http_json(url, method="GET", body=None, headers=None, what="the API"):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers=dict({"Content-Type": "application/json", "User-Agent": UA}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()
                                    if url.startswith("https") else None) as r:
            raw = r.read(1 << 20)
            return r.status, (json.loads(raw.decode()) if raw.strip() else None), r.headers
    except urllib.error.HTTPError as e:
        raw = e.read(1 << 16)
        try:
            got = json.loads(raw.decode())
        except ValueError:
            got = raw.decode("utf-8", "replace")
        return e.code, got, e.headers
    except OSError as e:
        raise AcmeError("%s did not answer: %s" % (what, getattr(e, "reason", e)))


def _cf(c, method, path, body=None):
    tok = str(c.get("acme_dns_token") or "")
    if not tok:
        raise AcmeError("the Cloudflare API token is not set")
    base = str(os.environ.get("FAKE_IGD_CF_API") or "https://api.cloudflare.com/client/v4").rstrip("/")
    status, got, _h = _http_json(base + path, method, body, {"Authorization": "Bearer " + tok}, "Cloudflare")
    got = got if isinstance(got, dict) else {}
    if status >= 400 or not got.get("success"):
        raise AcmeError("Cloudflare said %d: %s" % (status, "; ".join(x.get("message", "") for x in got.get("errors") or [])
                                                    or "no"))
    return got.get("result")


def _dns_cloudflare(c, rr, txt):
    labels = rr.split(".")
    zone_id = None
    for i in range(1, len(labels) - 1):
        got = _cf(c, "GET", "/zones?name=" + urllib.parse.quote(".".join(labels[i:])))
        if got:
            zone_id = got[0]["id"]
            break
    if not zone_id:
        raise AcmeError("Cloudflare has no zone for %s that the token may see" % rr)
    rec = _cf(c, "POST", "/zones/%s/dns_records" % zone_id, {"type": "TXT", "name": rr, "content": txt, "ttl": 60})
    return lambda: _cf(c, "DELETE", "/zones/%s/dns_records/%s" % (zone_id, rec["id"]))


def _dns_acmedns(c, txt):
    url = str(c.get("acme_dns_url") or "").strip().rstrip("/")
    if not url:
        raise AcmeError("the acme-dns server is not set")
    status, got, _h = _http_json(url + "/update", "POST", {"subdomain": str(c.get("acme_dns_subdomain") or ""), "txt": txt},
                                 {"X-Api-User": str(c.get("acme_dns_user") or ""),
                                  "X-Api-Key": str(c.get("acme_dns_key") or "")}, "acme-dns")
    if status >= 400:
        raise AcmeError("acme-dns said %d: %s" % (status, str(got)[:300]))
    return lambda: None             # acme-dns keeps the last two; nothing to take away


def _desec(c, method, path, body=None):
    tok = str(c.get("acme_desec_token") or "")
    if not tok:
        raise AcmeError("the deSEC API token is not set")
    base = str(os.environ.get("FAKE_IGD_DESEC_API") or "https://desec.io/api/v1").rstrip("/")
    for attempt in range(3):
        status, got, hdr = _http_json(base + path, method, body, {"Authorization": "Token " + tok}, "deSEC")
        if status < 400:
            return got
        if status == 404 and method == "GET":
            return None
        if status == 429 and attempt < 2:
            try:
                pause = float((hdr or {}).get("Retry-After") or 5)
            except ValueError:
                pause = 5
            time.sleep(min(max(pause, 1), 60))
            continue
        raise AcmeError("deSEC said %d: %s" % (status, str(got)[:400]))
    raise AcmeError("deSEC asked to wait too long (429)")


def _dns_desec(c, rr, txt):
    dom = str(c.get("acme_desec_domain") or "").strip().rstrip(".").lower()
    if not dom:
        raise AcmeError("the domain at deSEC is not set")
    if not rr.endswith("." + dom):
        raise AcmeError("%s is not in %s" % (rr, dom))
    sub = rr[:-len(dom) - 1]
    path = "/domains/%s/rrsets/" % urllib.parse.quote(dom)
    info = _desec(c, "GET", "/domains/%s/" % urllib.parse.quote(dom))
    if info is None:
        raise AcmeError("deSEC has no domain %s that the token may see" % dom)
    ttl = max(int((info or {}).get("minimum_ttl") or 3600), 60)
    one = '"%s"' % txt

    def have():
        got = _desec(c, "GET", "%s%s/TXT/" % (path, urllib.parse.quote(sub))) or {}
        return list(got.get("records") or [])
    recs = have()
    if one not in recs:
        recs.append(one)
    _desec(c, "PATCH", path, [{"subname": sub, "type": "TXT", "ttl": ttl, "records": recs}])

    def undo():
        left = [x for x in have() if x != one]
        _desec(c, "PATCH", path, [{"subname": sub, "type": "TXT", "ttl": ttl, "records": left}])
    return undo


DESEC_NS = ("ns1.desec.io", "ns2.desec.org")


def _desec_seen(c, rr, txt, say):
    """deSEC's own name servers asked until both have the record, then a while more (anycast)."""
    _dns_wait(c, say)
    addrs = []
    for ns in DESEC_NS:
        try:
            addrs += [(ns, a) for t, a in dns_ask(c, ns, 1) if t == "A"][:1]
        except OSError:
            pass
    if not addrs:
        say("deSEC's name servers not found - waited 120 s instead")
        time.sleep(120)
        return
    began = time.time()
    end = began + float(os.environ.get("FAKE_IGD_DESEC_PROPAGATION") or 300)
    seen = []
    while True:
        seen = []
        for ns, a in addrs:
            try:
                _rc, got = _dns_parse(_dns_query(a, rr, 16, 3.0))
                if txt in [v for t, v in got if t == "TXT"]:
                    seen.append(ns)
            except OSError:
                pass
        if len(seen) == len(addrs):
            break
        if time.time() > end:
            say("%s TXT not on every deSEC name server yet (%s) - the CA is asked anyway" % (rr, ", ".join(seen) or "none"))
            return
        say_work("waiting for deSEC's name servers to have the record - %s so far, %d s" % (
            ", ".join(seen) or "none", int(time.time() - began)))
        time.sleep(5)
    settle = float(os.environ.get("FAKE_IGD_DESEC_SETTLE") or 60)
    say("%s TXT is on %s after %d s; %d s more for deSEC's other places" % (rr, ", ".join(seen), int(time.time() - began), settle))
    time.sleep(settle)


def _dns_manual(ctx, rr, txt, say):
    """Shown on the page; waited for until somebody says it is in DNS."""
    ident = secrets.token_hex(6)
    end = time.time() + MANUAL_WAIT
    _set(ctx.store, "acme:manual", {"id": ident, "rr": rr, "txt": txt, "at": time.time()})
    say("waiting: put %s TXT \"%s\" in DNS, then say so on the page" % (rr, txt))
    try:
        while time.time() < end:
            got = _meta(ctx.store, "acme:manual") or {}
            if got.get("id") != ident:
                raise AcmeError("the manual DNS step was given up")
            if got.get("done"):
                say("said to be in DNS")
                return lambda: None
            time.sleep(2)
        raise AcmeError("nobody said the TXT record was in DNS within an hour")
    finally:
        got = _meta(ctx.store, "acme:manual") or {}
        if got.get("id") == ident:
            _drop(ctx.store, "acme:manual")


# ---- a small DNS client (otp's) -----------------------------------------------------------------
DNS_RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def resolvers(c):
    out = []
    for w in re.split(r"[\s,;]+", str(c.get("acme_resolvers") or "")):
        try:
            out.append(str(ipaddress.ip_address(w)))
        except ValueError:
            pass
    return out


def os_resolvers():
    out = []
    try:
        with open(os.environ.get("FAKE_IGD_RESOLV_CONF", "/etc/resolv.conf")) as f:
            for line in f:
                bits = line.split()
                if len(bits) >= 2 and bits[0] == "nameserver":
                    out.append(bits[1])
    except OSError:
        pass
    return out or ["127.0.0.1"]


def _dns_query(server, name, qtype, timeout=3.0):
    """One question, its answer as bytes (UDP; TCP when the answer was cut)."""
    qid = random.randint(0, 0xffff)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in str(name).rstrip(".").split("."):
        b = label.encode("idna") if label else b""
        if not b or len(b) > 63:
            raise OSError("%s is not a DNS name" % name)
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        end = time.time() + timeout
        while True:
            data, _a = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
            if time.time() > end:
                raise OSError("no answer")
    finally:
        s.close()
    if data[2] & 0x02:                                  # cut: asked again over TCP
        t = socket.socket(fam, socket.SOCK_STREAM)
        t.settimeout(timeout)
        try:
            t.connect((server, 53))
            t.sendall(struct.pack(">H", len(q)) + q)
            head = b""
            while len(head) < 2:
                got = t.recv(2 - len(head))
                if not got:
                    raise OSError("the DNS server closed the connection")
                head += got
            n = struct.unpack(">H", head)[0]
            data = b""
            while len(data) < n:
                got = t.recv(n - len(data))
                if not got:
                    break
                data += got
        finally:
            t.close()
    return data


def _dns_name(data, at):
    out, jumped, end, hops = [], False, at, 0
    while True:
        if at >= len(data):
            raise OSError("a broken DNS answer")
        n = data[at]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at = ((n & 0x3F) << 8) | data[at + 1]
            jumped = True
            hops += 1
            if hops > 30:
                raise OSError("a DNS answer that loops")
            continue
        if n == 0:
            if not jumped:
                end = at + 1
            break
        out.append(data[at + 1:at + 1 + n].decode("ascii", "replace"))
        at += 1 + n
    return ".".join(out), end


def _dns_parse(data):
    """(rcode, [(type, text)]) of one answer: CNAME, TXT, A, AAAA, NS."""
    if len(data) < 12:
        raise OSError("a broken DNS answer")
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x0F
    if rcode:
        return rcode, []
    at = 12
    for _i in range(qd):
        _n, at = _dns_name(data, at)
        at += 4
    out = []
    for _i in range(an):
        _n, at = _dns_name(data, at)
        rtype, _cls, _ttl, size = struct.unpack(">HHIH", data[at:at + 10])
        at += 10
        rd = data[at:at + size]
        if rtype == 5:
            out.append(("CNAME", _dns_name(data, at)[0].lower()))
        elif rtype == 16:
            j, parts = 0, []
            while j < len(rd):
                parts.append(rd[j + 1:j + 1 + rd[j]].decode("utf-8", "replace"))
                j += 1 + rd[j]
            out.append(("TXT", "".join(parts)))
        elif rtype == 1 and size == 4:
            out.append(("A", socket.inet_ntop(socket.AF_INET, rd)))
        elif rtype == 28 and size == 16:
            out.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rd)))
        elif rtype == 2:
            out.append(("NS", _dns_name(data, at)[0].lower()))
        at += size
    return 0, out


def dns_ask_rc(c, name, qtype):
    last = None
    for srv in (resolvers(c) or os_resolvers())[:3]:
        try:
            rcode, out = _dns_parse(_dns_query(srv, str(name).rstrip("."), qtype, 3.0))
        except OSError as e:
            last = e
            continue
        if rcode in (0, 3):
            return rcode, out
        last = OSError(DNS_RCODES.get(rcode, "rcode %d" % rcode))
    raise OSError("no DNS server answered (%s)" % (last or "none"))


def dns_ask(c, name, qtype):
    return dns_ask_rc(c, name, qtype)[1]


def txt_seen(c, rr, txt, say):
    end = time.time() + float(os.environ.get("FAKE_IGD_ACME_SEEN_WAIT") or 120)
    who = ", ".join(resolvers(c)) or "this machine's DNS"
    while True:
        try:
            got = [v for t, v in dns_ask(c, rr, 16) if t == "TXT"]
        except OSError as e:
            say("DNS could not be asked whether the record is there (%s): the CA is asked anyway" % str(e)[:80])
            return False
        if txt in got:
            say("%s TXT is seen by %s" % (rr, who))
            return True
        if time.time() > end:
            say("%s TXT is not seen yet by %s - the CA is asked anyway" % (rr, who))
            return False
        time.sleep(5)


def dns_guide(ctx, c=None):
    c = c or conf(ctx)
    rows = []
    http = c.get("acme_challenge") != "dns-01"
    how = c.get("acme_dns") or "manual"
    ips = _tls().host_ips()
    for name in names_of(ctx):
        if http:
            rows.append({"name": name, "type": "A", "record": name, "value": ", ".join(ips[:2]),
                         "why": "the name points at an address that reaches port 80 of this server", "check": "a"})
            continue
        rr, cname = dns_where(c, name)
        if how == "desec" and cname:
            dom = str(c.get("acme_desec_domain") or "").strip().rstrip(".").lower()
            if dom and not dom.endswith(".dedyn.io") and not any(x.get("type") == "NS" for x in rows):
                rows.append({"name": dom, "type": "NS", "record": dom, "value": "ns1.desec.io. ns2.desec.org.",
                             "why": "once, in the zone above it: %s at deSEC" % dom, "check": "ns", "zone": True})
        own = "_acme-challenge." + name.lstrip("*.")
        if how == "acmedns" or cname:
            rows.append({"name": name, "type": "CNAME", "record": own, "value": (cname or "?") + ".",
                         "why": "once, by hand, in your DNS", "check": "cname"})
        elif how == "manual":
            rows.append({"name": name, "type": "TXT", "record": rr, "value": "shown here at every order",
                         "why": "by hand, at every order"})
        else:
            rows.append({"name": name, "type": "TXT", "record": rr, "value": "",
                         "why": "nothing to do: fake-igd puts it in and takes it away"})
    return {"rows": rows, "challenge": "http-01" if http else "dns-01", "dns": how}


def dns_check(ctx):
    c = conf(ctx)
    g = dns_guide(ctx, c)
    for r in g["rows"]:
        if not r.get("check"):
            continue
        try:
            if r["check"] == "cname":
                _rc, recs = dns_ask_rc(c, r["record"], 5)
                got = [x[1] for x in recs if x[0] == "CNAME"]
                want = r["value"].rstrip(".").lower()
                r["found"] = got[0] + "." if got else ""
                r["ok"] = bool(got) and got[0].rstrip(".") == want
                r["said"] = "there" if r["ok"] else ("it points elsewhere: %s" % r["found"] if got else "not there yet")
            elif r["check"] == "ns":
                _rc, recs = dns_ask_rc(c, r["record"], 2)
                got = sorted(x[1] for x in recs if x[0] == "NS")
                r["found"] = " ".join(got)
                r["ok"] = any(x.rstrip(".").endswith(("desec.io", "desec.org")) for x in got)
                r["said"] = "there" if r["ok"] else (("it is served by %s, not deSEC" % r["found"]) if got else
                                                     "not delegated: the internet does not know %s" % r["record"])
            else:
                got = []
                for qt, kind in ((1, "A"), (28, "AAAA")):
                    try:
                        got += [a for t, a in dns_ask(c, r["record"], qt) if t == kind]
                    except OSError:
                        if kind == "A":
                            raise
                r["found"] = ", ".join(got)
                r["ok"] = bool(got)
                r["said"] = "it points at %s" % r["found"] if got else "not there"
        except OSError as e:
            r.update(ok=False, said="could not be looked up: %s" % str(e)[:120])
    g["at"] = time.time()
    g["resolvers"] = resolvers(c) or ["this machine's DNS"]
    g["own_resolvers"] = bool(resolvers(c))
    return g


def probe(ctx):
    """Whether http://NAME/.well-known/acme-challenge/ reaches this server and is answered - asked from
    here, straight, as the CA will (from outside a firewall in front may still stop it)."""
    names = names_of(ctx)
    if not names:
        raise ValueError("which name? none is given, and nginx's server_name has no full DNS name")
    name = next((n for n in names if not n.startswith("*.")), "")
    if not name:
        raise ValueError("a wildcard cannot be asked on port 80 - it is given by DNS-01 only")
    token = "igd-probe-" + secrets.token_urlsafe(16)
    want = token + "." + secrets.token_urlsafe(8)
    _set(ctx.store, "acme:chal:" + token, {"auth": want, "at": time.time(), "name": name, "probe": True})
    url = "http://%s/.well-known/acme-challenge/%s" % (name, token)
    began = time.time()
    out = {"name": name, "url": url, "ok": False}
    try:
        time.sleep(SETTLE)
        req = urllib.request.Request(url, headers={"User-Agent": UA + " probe"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=10) as r:
            body = r.read(4096).decode("utf-8", "replace").strip()
            status = r.status
        out.update(ok=body == want, status=status, said="answered as the CA wants it" if body == want else
                   "something answers on port 80, but not fake-igd's answer: %r" % body[:80])
    except urllib.error.HTTPError as e:
        out["said"] = "port 80 answers %d - nginx does not send /.well-known/acme-challenge/ to fake-igd" % e.code
    except (OSError, ValueError) as e:
        out["said"] = "port 80 of %s cannot be reached: %s" % (name, getattr(e, "reason", e))
    finally:
        _drop(ctx.store, "acme:chal:" + token)
    out["ms"] = int((time.time() - began) * 1000)
    out["at"] = time.time()
    return out


# ---- what the pages see ------------------------------------------------------------------------
def view(ctx):
    c = conf(ctx)
    T = _tls()
    cur = T.current() or {}
    info = cur.get("info") or {}
    keys = " + ".join(x for x in [info.get("key") or "", ((cur.get("alt") or {}).get("info") or {}).get("key") or ""] if x)
    acc = _meta(ctx.store, "acme:account") or {}
    with LOCK:
        work = dict(WORK)
    log = _meta(ctx.store, "acme:log") or []
    names = names_of(ctx)
    st = state(ctx.store)
    st.pop("cert", None)
    ari = _meta(ctx.store, "acme:ari") or {}
    return {"on": bool(c.get("acme")), "may": (ctx.me or {}).get("role") == "fulladmin", "days": c.get("acme_days"),
            "names": names, "names_given": bool(c.get("acme_names")), "names_nginx": names_from_nginx(),
            "card": {"name": ", ".join(names), "state": st, "how": how_now(ctx.store),
                     "subject": info.get("subject"), "issuer": info.get("issuer"), "not_after": info.get("not_after"),
                     "keys": keys, "care": care(ctx.store), "wanted": bool(names), "before": T.before_acme(),
                     "due": due(ctx, names) if c.get("acme") else "",
                     "ari": {k: ari.get(k) for k in ("start", "end", "pick", "url")} if ari else None},
            "directory": directory_url(c),
            "account": {"kid": acc.get("kid"), "email": acc.get("email"), "at": acc.get("at"),
                        "key": KEY_WORDS.get(acc.get("kind") or "ec", "") if acc.get("kid") else ""},
            "work": work, "challenge": c.get("acme_challenge") or "http-01", "dns_guide": dns_guide(ctx, c),
            "manual": {k: v for k, v in (_meta(ctx.store, "acme:manual") or {}).items()
                       if k in ("rr", "txt", "at", "done")} or None,
            "log": log if isinstance(log, list) else [], "tls_root": T.ask_state(ctx)}


def get_acme(ctx):
    return view(ctx)


def post_acme(ctx):
    me = ctx.need("fulladmin")
    who = me.get("name", "")
    b = ctx.body()
    act = str(b.get("action") or "")
    if act == "order":
        if not ctx.setting("acme"):
            raise ValueError("certificates by ACME are off - switch them on and save first")
        names = names_of(ctx)
        if not names:
            raise ValueError("no name to order it for - give them (Its names…), or a full DNS name in nginx's server_name")
        care_set(ctx, True, who, "ordered by hand")
        start(ctx, names, who)
        ctx.event("%s ordered a certificate for %s from %s" % (who, ", ".join(names), directory_url(conf(ctx))))
        return dict(view(ctx), message="the certificate of %s is being ordered" % ", ".join(names))
    if act == "care":
        on = b.get("on") is True
        care_set(ctx, on, who)
        return view(ctx)
    if act == "names":
        raw = b.get("names")
        if isinstance(raw, list):
            raw = ", ".join(str(x) for x in raw)
        import igd_panes as PN
        changed = PN.save(ctx.store, {"acme_names": str(raw or "")[:4000]})
        if changed:
            ctx.event("%s: the certificate of these pages is for %s" % (
                who, ", ".join(names_of(ctx)) or "the names in nginx's server_name"))
        return dict(view(ctx), message="kept")
    if act == "probe":
        return probe(ctx)
    if act == "dns_check":
        return dns_check(ctx)
    if act in ("manual_done", "manual_drop"):
        got = _meta(ctx.store, "acme:manual") or {}
        if not got:
            raise ValueError("no order waits for a TXT record")
        if act == "manual_done":
            got["done"] = True
            _set(ctx.store, "acme:manual", got)
            ctx.event("%s said the TXT record %s is in DNS" % (who, got.get("rr")))
        else:
            _drop(ctx.store, "acme:manual")
            ctx.event("%s gave the order waiting for %s up" % (who, got.get("rr")))
        return view(ctx)
    if act == "put_back":
        T = _tls()
        bef = T.before_acme()
        if not bef:
            raise ValueError("there is no certificate from before ACME here")
        care_set(ctx, False, who, "the one before put back")
        ident = ctx.ask_root({"action": "put_back"}, kind="tls")
        T.set_meta(ctx.store, "tls:asked", {"id": ident, "at": time.time(), "action": "put_back", "by": who})
        T.set_meta(ctx.store, "tls:how", {"how": bef.get("how") or "uploaded", "at": time.time(), "by": who})
        ctx.event("%s put the certificate from before ACME back (%s)" % (who, bef.get("issuer") or "?"))
        return dict(view(ctx), message="the certificate from before ACME is put back - root puts it in nginx within a few seconds")
    raise ValueError("no such action: %s" % act[:40])


ROUTES = {("GET", "/api/acme"): get_acme, ("POST", "/api/acme"): post_acme,
          ("GET", "/api/acme/challenge"): challenge}


def on_saved(ctx, changed):
    """Switched on, or the names or the CA changed: looked at within the minute."""
    # The firewall's port 80 from anywhere follows HTTP-01 (1.6.0): root puts FAKE-IGD-IN in place again.
    if any(k in changed for k in ("acme", "acme_challenge")):
        try:
            ctx.ask_root({"action": "apply"}, kind="fw")
        except (OSError, ValueError):
            pass
    if any(k in changed for k in ("acme", "acme_names", "acme_ca", "acme_url", "acme_key", "acme_challenge")):
        LAST["look"] = 0.0
    if ctx.setting("acme") and ctx.setting("acme_challenge") != "dns-01" and \
            any(k in changed for k in ("acme", "acme_names", "acme_challenge")):
        names = names_of(ctx)
        if names:
            try:
                http80(ctx, names, wait=0)
            except (AcmeError, ValueError):
                pass
    if changed.get("acme") is True and not care(ctx.store):
        # Switched on: ACME looks after the certificate again (as otp's "Look after it").
        care_set(ctx, True, (ctx.me or {}).get("name", ""), "switched on")
