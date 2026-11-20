"""igd_mikrotik.py - the MikroTik reader (1.8.2): READ-ONLY, as isemon's (1.10.211-1.10.217).

fake-igd answers a PS5's UPnP and opens nothing; the real router is a MikroTik. This reads it - its
firewall (filter, nat, mangle, raw, IPv4 and IPv6), its address lists, its interfaces and their lists,
its addresses, its neighbours and its own UPnP - so that fake-igd can tell, port by port, whether the
router carries what a device asked for (igd_mtcheck.py), and draw the whole firewall.

Three ways to reach it, as isemon reads one (RosApi / RosSsh) plus RouterOS 7's REST:
  rest   GET https://ROUTER/rest/<menu> (RouterOS 7, the www-ssl service), basic auth
  api    the RouterOS API (api-ssl 8729 over TLS, or api 8728), its sentences of words, /login
  ssh    the console over ssh - with a key made here or a password - each menu printed as-value
TLS (rest, api): the certificate pinned by its SHA-256 fingerprint ("Trust this certificate" after it is
shown), checked by an authority (the system's, or one pasted), or not checked; or plain (no TLS).
SSH: the router's host key pinned in a known_hosts file of fake-igd's own after "Trust this host key".

NOTHING THAT CHANGES THE ROUTER IS EVER SENT: every question goes through `menu()`, which knows only the
menus in READ; the REST client only GETs, the API client only `<menu>/print` (and /login), the ssh client
only the console lines built here from READ - anything else is refused before it leaves (test/mikrotik).
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

# ---- what is read, and nothing else ---------------------------------------------------------------
# name -> (the menu, one entry rather than a list, needed for the checks)
READ = {
    "identity": ("/system/identity", True, True),
    "resource": ("/system/resource", True, True),
    "routerboard": ("/system/routerboard", True, False),
    "interfaces": ("/interface", False, True),
    "iflists": ("/interface/list", False, True),
    "iflist_members": ("/interface/list/member", False, True),
    "addresses4": ("/ip/address", False, True),
    "addresses6": ("/ipv6/address", False, False),
    "routes4": ("/ip/route", False, False),
    "routes6": ("/ipv6/route", False, False),
    # 1.9.2: the way of each device out - VRFs and routing rules (RouterOS 7; missing on 6, said so)
    "vrfs": ("/ip/vrf", False, False),
    "routing_rules": ("/routing/rule", False, False),
    # 1.9.2: its log - the lines its firewall's rules logged (log=yes), to say what it dropped of a device's
    "log": ("/log", False, False),
    "arp": ("/ip/arp", False, False),
    "neigh6": ("/ipv6/neighbor", False, False),
    "filter4": ("/ip/firewall/filter", False, True),
    "nat4": ("/ip/firewall/nat", False, True),
    "mangle4": ("/ip/firewall/mangle", False, False),
    "raw4": ("/ip/firewall/raw", False, False),
    "lists4": ("/ip/firewall/address-list", False, False),
    "filter6": ("/ipv6/firewall/filter", False, False),
    "nat6": ("/ipv6/firewall/nat", False, False),
    "mangle6": ("/ipv6/firewall/mangle", False, False),
    "raw6": ("/ipv6/firewall/raw", False, False),
    "lists6": ("/ipv6/firewall/address-list", False, False),
    "upnp": ("/ip/upnp", True, False),
    "upnp_ifs": ("/ip/upnp/interfaces", False, False),
    "tracking": ("/ip/firewall/connection/tracking", True, False),
    # asked by "Try reaching it" only: whether the account could change anything (isemon's probe)
    "users": ("/user", False, False),
    "groups": ("/user/group", False, False),
}
MENUS = {v[0] for v in READ.values()}
SINGLE = {v[0] for v in READ.values() if v[1]}
# The words a console line is made of: a menu's words, and what a query compares with (never quoted).
MENU_RE = re.compile(r"^(?:/[a-z0-9-]+)+$")
VALUE_RE = re.compile(r"^[A-Za-z0-9_.@+:-]{0,64}$")
# What may never be in anything sent over ssh unless this module put it there itself.
SSH_FORBIDDEN = re.compile(r"[;\[\]{}$\n\r`\\\"]")
LIST_MOST = 5000                    # a table longer than this is cut (an address list of a country)
USUAL_PORT = {("rest", "plain"): 80, ("rest", ""): 443, ("api", "plain"): 8728, ("api", ""): 8729, ("ssh", ""): 22}
WRITE_POLICIES = {"write", "policy", "password", "sensitive", "reboot", "ftp", "test", "sniff", "romon"}


class MtError(RuntimeError):
    """The router refused, or could not be reached; said in words."""


class Refused(MtError):
    """Something that is not a read was asked - refused before it was sent."""


def menu(path):
    """A menu this reads, or Refused. The one gate every question passes."""
    p = str(path or "").rstrip("/")
    if p not in MENUS or not MENU_RE.match(p):
        raise Refused("%s is not something fake-igd reads from a router" % (p or "(nothing)")[:80])
    return p


def usual_port(mode, tls):
    return USUAL_PORT.get((mode, "plain" if tls == "plain" and mode != "ssh" else ""), 443)


def fp_words(fp):
    """A fingerprint as people compare them: pairs of hex, colons between (isemon's rosapi_fp_words)."""
    fp = re.sub(r"[^0-9a-fA-F]", "", str(fp or "")).upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def bare_host(host):
    """An IPv6 address written in brackets, without them (isemon's ssh_bare_host)."""
    h = str(host or "").strip()
    if len(h) > 2 and h[0] == "[" and h[-1] == "]":
        return h[1:-1]
    return h


HOST_LABEL = re.compile(r"[A-Za-z0-9-]{1,63}")


def host_ok(host):
    """An address or a host name, and nothing that could be read as an option (isemon's is_ssh_host)."""
    h = bare_host(host)
    if not h or len(h) > 253 or h.startswith("-"):
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    return h.isascii() and h[0].isalnum() and h[-1].isalnum() and all(HOST_LABEL.fullmatch(x) for x in h.split("."))


# ---- TLS: pinned, by an authority, not checked ------------------------------------------------------
def tls_context(tls, ca="", name=None):
    """An SSLContext for `tls`: pin (any certificate taken, its fingerprint compared afterwards), ca (an
    authority - the pasted one or the system's - and the router's name), none (encrypted, not checked)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls == "ca":
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            if ca:
                ctx.load_verify_locations(cadata=ca)
            else:
                ctx.load_default_certs()
        except (ssl.SSLError, ValueError) as e:
            raise MtError("the authority's certificate cannot be read: %s" % str(e)[:120])
        ctx.check_hostname = bool(name)
    # What RouterOS's api-ssl speaks over TLS 1.2: often only AES-CBC with SHA-1, which Python leaves out
    # by default (isemon 1.10.212) - the strong ones first, those after them.
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:ECDHE+AES:DHE+AES:RSA+AESGCM:RSA+AES:"
                        "!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


def check_pin(der, pin, host, port):
    """The certificate's SHA-256 fingerprint; MtError when one is pinned and this is another."""
    fp = hashlib.sha256(der).hexdigest() if der else ""
    if not fp:
        raise MtError("%s offered no certificate" % host)
    if pin and not hmac.compare_digest(str(pin).lower(), fp):
        raise MtError("%s:%s answered with another certificate than the one trusted (%s, trusted %s), so "
                      "nothing was asked of it - not even the password was sent. If its certificate was "
                      "replaced on purpose, forget the trusted one and trust the new one"
                      % (host, port, fp_words(fp), fp_words(pin)))
    return fp


def cert_words(der):
    """The subject and the end of a certificate - shown before it is trusted."""
    out = {"fingerprint": hashlib.sha256(der).hexdigest() if der else ""}
    try:
        import tempfile as _t
        with _t.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        try:
            d = ssl._ssl._test_decode_cert(path)              # noqa: SLF001 - stdlib's own decoder
        finally:
            os.unlink(path)
        flat = lambda seq: ", ".join("%s=%s" % kv for rdn in seq or () for kv in rdn)   # noqa: E731
        out.update(subject=flat(d.get("subject")), issuer=flat(d.get("issuer")),
                   until=d.get("notAfter") or "", since=d.get("notBefore") or "")
    except Exception:                                   # noqa: BLE001 - the fingerprint is what counts
        pass
    return out


def _tunnel(host, port, timeout, proxy):
    """A TCP connection to host:port - through the proxy's CONNECT when one is given (Settings → Proxy,
    switched on for the MikroTik)."""
    if not proxy:
        try:
            return socket.create_connection((bare_host(host), int(port)), timeout=timeout)
        except OSError as e:
            raise MtError("%s:%s could not be reached (%s)" % (host, port, getattr(e, "strerror", None) or e))
    u = urllib.parse.urlsplit(proxy)
    try:
        s = socket.create_connection((u.hostname, u.port or 3128), timeout=timeout)
    except OSError as e:
        raise MtError("the proxy %s:%s could not be reached (%s)" % (u.hostname, u.port or 3128, e))
    hdr = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (bare_host(host), int(port), bare_host(host), int(port))
    if u.username:
        cred = "%s:%s" % (urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or ""))
        hdr += "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(cred.encode()).decode()
    s.sendall((hdr + "\r\n").encode())
    got = b""
    while b"\r\n\r\n" not in got and len(got) < 8192:
        chunk = s.recv(1024)
        if not chunk:
            break
        got += chunk
    first = got.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if not re.match(r"^HTTP/1\.[01] 200", first):
        s.close()
        raise MtError("the proxy would not connect to %s:%s (%s)" % (host, port, first[:80] or "no answer"))
    return s


# ---- the RouterOS API (api-ssl / api), as isemon's RosApi -------------------------------------------
class RosApi(object):
    """One session to a RouterOS API: `/login`, then sentences of words - each word its length then its
    bytes, a sentence ended by an empty word; an answer is `!re` sentences with `=name=value` words and a
    `!done`, or a `!trap` with a message. Only `<menu>/print` of READ's menus is ever sent."""

    def __init__(self, host, port=8729, tls="pin", user="", password="", pin="", ca="", tls_name="",
                 timeout=20.0, proxy=None):
        self.host, self.port, self.tls = str(host or ""), int(port or 8729), tls
        self.user, self.password, self.pin, self.ca, self.tls_name = user, password, pin or "", ca, tls_name
        self.timeout, self.proxy = float(timeout), proxy
        self.sock = self.rfile = None
        self.fingerprint, self.cert = "", {}
        self.steps = []

    @staticmethod
    def encode_length(n):
        if n < 0x80:
            return bytes([n])
        if n < 0x4000:
            return (n | 0x8000).to_bytes(2, "big")
        if n < 0x200000:
            return (n | 0xC00000).to_bytes(3, "big")
        if n < 0x10000000:
            return (n | 0xE0000000).to_bytes(4, "big")
        return b"\xf0" + n.to_bytes(4, "big")

    def _read_exact(self, n):
        out = self.rfile.read(n)
        if out is None or len(out) < n:
            raise MtError("%s closed the connection" % self.host)
        return out

    def _read_length(self):
        first = self._read_exact(1)[0]
        if first < 0x80:
            return first
        if first < 0xC0:
            return ((first & 0x3F) << 8) | self._read_exact(1)[0]
        if first < 0xE0:
            return ((first & 0x1F) << 16) | int.from_bytes(self._read_exact(2), "big")
        if first < 0xF0:
            return ((first & 0x0F) << 24) | int.from_bytes(self._read_exact(3), "big")
        return int.from_bytes(self._read_exact(4), "big")

    def _send(self, words):
        self.sock.sendall(b"".join(self.encode_length(len(w)) + w for w in (x.encode("utf-8") for x in words))
                          + b"\x00")

    def _sentence(self):
        words = []
        while True:
            n = self._read_length()
            if n == 0:
                return words
            words.append(self._read_exact(n).decode("utf-8", "replace"))

    def connect(self):
        t0 = time.time()
        raw = _tunnel(self.host, self.port, self.timeout, self.proxy)
        raw.settimeout(self.timeout)
        self.steps.append({"what": "reached %s:%d%s" % (self.host, self.port, " through the proxy" if self.proxy else ""),
                           "ok": True, "said": "%d ms" % ((time.time() - t0) * 1000)})
        if self.tls != "plain":
            name = (self.tls_name or bare_host(self.host)) if self.tls == "ca" else None
            ctx = tls_context(self.tls, self.ca, name)
            if self.tls == "none":
                # api-ssl with no certificate assigned speaks only anonymous DH; one WITH a certificate the
                # usual suites - both offered (isemon 1.10.213)
                try:
                    ctx.set_ciphers("ADH-AES256-GCM-SHA384:ADH-AES256-SHA256:ADH-AES128-SHA256:ADH-AES256-SHA:"
                                    "ADH-AES128-SHA:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:ECDHE+AES:DHE+AES:"
                                    "RSA+AESGCM:RSA+AES:!eNULL:!MD5:!RC4:!3DES:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            try:
                self.sock = ctx.wrap_socket(raw, server_hostname=name)
            except ssl.SSLCertVerificationError as e:
                raw.close()
                raise MtError("the certificate of %s:%d is not one this trusts (%s) - give the authority that "
                              "signed it, or choose \"its certificate trusted by its fingerprint\""
                              % (self.host, self.port, str(getattr(e, "verify_message", "") or e)[:120]))
            except (ssl.SSLError, OSError) as e:
                raw.close()
                raise MtError("TLS with %s:%d failed (%s) - is api-ssl on, on this port, with a certificate that "
                              "has its private key on the router (flag K in /certificate print)?"
                              % (self.host, self.port, str(e)[:120]))
            der = self.sock.getpeercert(binary_form=True) or b""
            if der:
                self.cert = cert_words(der)
                self.fingerprint = self.cert["fingerprint"]
            if self.tls == "pin":
                try:
                    check_pin(der, self.pin, self.host, self.port)
                except MtError:
                    self.close()
                    raise
                if not self.pin:
                    self.close()
                    raise MtError("its certificate is not trusted yet: %s - trust it in Settings → MikroTik "
                                  "once you have compared it with the router's (/certificate print detail)"
                                  % fp_words(self.fingerprint))
            self.steps.append({"what": "TLS", "ok": True, "said": "%s, %s" % (self.sock.version(), {
                "pin": "its certificate the one trusted", "ca": "its certificate checked by an authority",
                "none": "its certificate not checked"}.get(self.tls, ""))})
        else:
            self.sock = raw
        self.rfile = self.sock.makefile("rb", buffering=65536)
        try:
            self.talk("/login", {"name": self.user, "password": self.password})
        except MtError as e:
            self.close()
            raise MtError("%s refused the sign-in of %s: %s" % (self.host, self.user, e))
        self.steps.append({"what": "signed in as %s" % self.user, "ok": True, "said": ""})
        return self

    def close(self):
        for f in (self.rfile, self.sock):
            try:
                if f is not None:
                    f.close()
            except OSError:
                pass
        self.sock = self.rfile = None

    def talk(self, command, args=None, query=None):
        if command == "/login":
            if args is None or set(args) != {"name", "password"}:
                raise Refused("/login takes a name and a password only")
        else:
            if not command.endswith("/print"):
                raise Refused("%s is not something fake-igd asks a router" % command[:80])
            menu(command[:-len("/print")])
            if args:
                raise Refused("a print is asked without arguments")
        if self.sock is None:
            raise MtError("not connected to %s" % self.host)
        words = [command] + ["=%s=%s" % kv for kv in (args or {}).items()]
        for q in query or ():
            k, _, v = str(q).partition("=")
            if not VALUE_RE.match(k) or not VALUE_RE.match(v):
                raise Refused("not something fake-igd asks a router: %s" % str(q)[:60])
            words.append("?%s=%s" % (k, v))
        try:
            self._send(words)
            out, trap = [], None
            while True:
                sentence = self._sentence()
                if not sentence:
                    continue
                kind, rest = sentence[0], sentence[1:]
                said = {}
                for w in rest:
                    if w.startswith("="):
                        k, _, v = w[1:].partition("=")
                        said[k] = v
                if kind == "!re":
                    if len(out) < LIST_MOST:
                        out.append(said)
                elif kind == "!trap":
                    trap = said.get("message") or "refused"
                elif kind == "!fatal":
                    self.close()
                    raise MtError(" ".join(rest)[:200] or "the router ended the session")
                elif kind == "!done":
                    if trap:
                        raise MtError(trap[:200])
                    return out
        except (OSError, ssl.SSLError) as e:
            self.close()
            raise MtError("%s: %s" % (self.host, getattr(e, "strerror", None) or e))

    def read(self, path, query=None):
        return self.talk(menu(path) + "/print", None, query)


# ---- RouterOS 7's REST API (GET only) ----------------------------------------------------------------
class RosRest(object):
    """GET https://ROUTER/rest/<menu> with the account's name and password (basic auth) - RouterOS 7's
    www-ssl. Each question its own connection, its certificate checked BEFORE the password is sent:
    pinned, by an authority (and the name), or not checked; through the proxy's CONNECT where it is on."""

    def __init__(self, host, port=443, tls="pin", user="", password="", pin="", ca="", tls_name="",
                 timeout=20.0, proxy=None):
        self.host, self.port, self.tls = str(host or ""), int(port or 443), tls
        self.user, self.password, self.pin, self.ca, self.tls_name = user, password, pin or "", ca, tls_name
        self.timeout, self.proxy = float(timeout), proxy
        self.fingerprint, self.cert, self.steps = "", {}, []
        self.ready = False

    def _open(self, first=False):
        t0 = time.time()
        raw = _tunnel(self.host, self.port, self.timeout, self.proxy)
        raw.settimeout(self.timeout)
        if first:
            self.steps.append({"what": "reached %s:%d%s" % (self.host, self.port,
                                                           " through the proxy" if self.proxy else ""),
                               "ok": True, "said": "%d ms" % ((time.time() - t0) * 1000)})
        if self.tls == "plain":
            return raw
        name = (self.tls_name or bare_host(self.host)) if self.tls == "ca" else None
        ctx = tls_context(self.tls, self.ca, name)
        try:
            sock = ctx.wrap_socket(raw, server_hostname=name)
        except ssl.SSLCertVerificationError as e:
            raw.close()
            raise MtError("the certificate of %s:%d is not one this trusts (%s) - give the authority that signed "
                          "it, or trust it by its fingerprint" % (self.host, self.port,
                                                                  str(getattr(e, "verify_message", "") or e)[:120]))
        except (ssl.SSLError, OSError) as e:
            raw.close()
            raise MtError("TLS with %s:%d failed (%s) - is www-ssl on, on this port, with a certificate "
                          "(/ip service print)?" % (self.host, self.port, str(e)[:120]))
        der = sock.getpeercert(binary_form=True) or b""
        if der and not self.fingerprint:
            self.cert = cert_words(der)
            self.fingerprint = self.cert["fingerprint"]
        if self.tls == "pin":
            try:
                check_pin(der, self.pin, self.host, self.port)
            except MtError:
                sock.close()
                raise
            if not self.pin:
                sock.close()
                raise MtError("its certificate is not trusted yet: %s - trust it in Settings → MikroTik once "
                              "you have compared it with the router's (/certificate print detail)"
                              % fp_words(hashlib.sha256(der).hexdigest()))
        if first:
            self.steps.append({"what": "TLS", "ok": True, "said": "%s, %s" % (sock.version(), {
                "pin": "its certificate the one trusted", "ca": "its certificate checked by an authority",
                "none": "its certificate not checked"}.get(self.tls, ""))})
        return sock

    def connect(self):
        """One TLS connection kept for the whole read (1.9.2: HTTP keep-alive - one handshake and one sign-in on
        the router, not one for every menu); opened again only where the router closes it."""
        self.ready = True
        self._sock = self._open(first=True)
        try:
            self._ask(self._sock, "/system/identity")
        except MtError:
            self._drop()
            raise
        if getattr(self, "_will_close", True):
            self._drop()
        self.steps.append({"what": "signed in as %s" % self.user, "ok": True, "said": "REST"})
        return self

    def _drop(self):
        s, self._sock = getattr(self, "_sock", None), None
        if s is not None:
            try:
                s.close()
            except OSError:
                pass

    def close(self):
        self.ready = False
        self._drop()

    def _ask(self, sock, p, q=()):
        url = "/rest" + p + ("?" + urllib.parse.urlencode(list(q)) if q else "")
        auth = base64.b64encode(("%s:%s" % (self.user, self.password)).encode("utf-8")).decode()
        host = bare_host(self.host)
        head = ("GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nAccept: application/json\r\n"
                "User-Agent: fake-igd\r\nConnection: keep-alive\r\n\r\n"
                % (url, ("[%s]" % host if ":" in host else host) + ("" if self.port in (80, 443) else ":%d" % self.port),
                   auth))
        try:
            sock.sendall(head.encode("utf-8"))
            r = http.client.HTTPResponse(sock, method="GET")
            r.begin()
            body = r.read(64 << 20)
            self._will_close, self._conn_err = r.will_close, False
        except (http.client.HTTPException, OSError) as e:
            self._will_close, self._conn_err = True, True
            raise MtError("%s: %s" % (self.host, getattr(e, "strerror", None) or e))
        if r.status == 401:
            raise MtError("%s refused the sign-in of %s (401) - the name or the password, or the account's group "
                          "lacks rest-api" % (self.host, self.user))
        if r.status >= 400:
            try:
                said = json.loads(body.decode("utf-8", "replace"))
                said = said.get("detail") or said.get("message") or ""
            except ValueError:
                said = body[:120].decode("utf-8", "replace")
            raise MtError("%s answered %d for %s%s" % (self.host, r.status, p, (": " + str(said)) if said else ""))
        try:
            got = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            raise MtError("%s did not answer JSON for %s - is it RouterOS 7, with www-ssl on?" % (self.host, p))
        if isinstance(got, dict):
            got = [got]
        return [x for x in got if isinstance(x, dict)][:LIST_MOST]

    def get(self, path, query=None):
        """GET /rest<path> - the only method this client has."""
        p = menu(path)
        q = []
        for one in query or ():
            k, _, v = str(one).partition("=")
            if not VALUE_RE.match(k) or not VALUE_RE.match(v):
                raise Refused("not something fake-igd asks a router: %s" % str(one)[:60])
            q.append((k, v))
        if not self.ready:
            raise MtError("not connected to %s" % self.host)
        reused = getattr(self, "_sock", None) is not None
        if not reused:
            self._sock = self._open()
        try:
            got = self._ask(self._sock, p, q)
        except MtError:
            conn = getattr(self, "_conn_err", False)
            if conn or getattr(self, "_will_close", True):
                self._drop()
            if not (reused and conn):           # an answer of the router (401, 404...) is not asked again
                raise
            self._sock = self._open()           # the router closed the kept one: once more, on a new one
            try:
                got = self._ask(self._sock, p, q)
            except MtError:
                self._drop()
                raise
        if getattr(self, "_will_close", True):
            self._drop()
        return got

    def read(self, path, query=None):
        return self.get(path, query)


# ---- over ssh, as isemon's RosSsh: each menu printed as-value ----------------------------------------
SSH_TIMEOUT = 45
TERSE_KEY = re.compile(r"^[\w.-]+=")


def ssh_command(path, query=None):
    """The console's words for one print of a READ menu (isemon's RosSsh.command): a list printed a line
    per entry as `key=value;key=value`; one entry `:put` whole. Built here, from READ alone."""
    p = menu(path)
    words = "/%s print as-value" % p.strip("/").replace("/", " ")
    where = []
    for one in query or ():
        k, _, v = str(one).partition("=")
        if not VALUE_RE.match(k) or not VALUE_RE.match(v):
            raise Refused("not something fake-igd asks a router: %s" % str(one)[:60])
        where.append('%s="%s"' % (k, v))
    if where:
        words += " where " + " and ".join(where)
    line = (":put [%s]" if p in SINGLE else ":foreach r in=[%s] do={:put $r}") % words
    ssh_check(line)
    return line


SSH_LINE = re.compile(r'^(?::put \[|:foreach r in=\[)(/[a-z0-9-]+(?: [a-z0-9-]+)*) print as-value'
                      r'(?: where [A-Za-z0-9_.@+:-]+="[A-Za-z0-9_.@+:-]*"(?: and [A-Za-z0-9_.@+:-]+="[A-Za-z0-9_.@+:-]*")*)?'
                      r'(?:\]|\] do=\{:put \$r\})$')


def ssh_check(line):
    """Refuse any console line that is not one ssh_command() makes from READ - nothing with ; [ ] { } $ or
    a newline but the frame of a print, and its menu one of READ's."""
    m = SSH_LINE.fullmatch(str(line or ""))        # 1.9.9: whole - `$` let a newline at its end through
    if not m:
        raise Refused("not a console line fake-igd sends: %s" % str(line)[:80])
    menu("/" + m.group(1).strip("/").replace(" ", "/"))
    frame = re.sub(r"^:put \[|^:foreach r in=\[|\]$|\] do=\{:put \$r\}$", "", line)
    if SSH_FORBIDDEN.search(frame.replace('"', "")):
        raise Refused("not a console line fake-igd sends: %s" % str(line)[:80])
    return line


BATCH_MARK = re.compile(r"^==fake-igd=([a-z0-9_]+)==$")
NONCE_RE = re.compile(r"^[0-9a-f]{8,32}\Z")


def ssh_batch(names, nonce=""):
    """One console line that prints every menu of `names` (READ's names) one after the other, each after a
    mark of its own (1.9.2): ONE ssh connection - one sign-in on the router - for a whole read, not one for
    each menu. Each print is one ssh_command() would make, checked as such; the marks are fixed words - and
    (1.9.9) a nonce of this read's own in them: a comment, a log line or a name on the router that holds a
    line "==fake-igd=filter4==" cannot pass for a mark (it would have put what follows it in that menu's place)."""
    if nonce and not NONCE_RE.match(nonce):
        raise Refused("not a mark fake-igd puts in a batch")
    parts = []
    for name in names:
        if name not in READ or not re.match(r"^[a-z0-9_]+$", name):
            raise Refused("not something fake-igd reads from a router: %s" % str(name)[:40])
        parts.append(':put "==fake-igd%s=%s=="' % (("-" + nonce) if nonce else "", name))
        parts.append(ssh_command(READ[name][0]))
    return "; ".join(parts)


def ssh_batch_check(line):
    """Refuse a batch line that is not ssh_batch()'s: marks and prints of READ, nothing else."""
    for part in str(line or "").split("; "):
        if re.fullmatch(r':put "==fake-igd(?:-[0-9a-f]{8,32})?=[a-z0-9_]+=="', part):
            continue
        ssh_check(part)
    return line


def ssh_split(text, nonce=""):
    """The answer of a batch: {name: its lines} by the marks - with a nonce, only the marks that carry it."""
    out, cur = {}, None
    mark = re.compile(r"^==fake-igd-%s=([a-z0-9_]+)==$" % re.escape(nonce)) if nonce else BATCH_MARK
    for line in str(text or "").replace("\r\n", "\n").split("\n"):
        m = mark.match(line.strip())
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def ssh_answers(text):
    """`key=value;key=value` a line (print as-value), as the API's dictionaries; a line the console broke
    put back on the end of the one before it (isemon's RosSsh.answers)."""
    lines = []
    for line in str(text or "").replace("\r\n", "\n").split("\n"):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if lines and not TERSE_KEY.match(line.lstrip()):
            lines[-1] += line.strip()
        else:
            lines.append(line.strip())
    out = []
    for line in lines:
        said = {}
        for part in re.split(r";(?=[\w.-]+=)", line):
            k, eq, v = part.partition("=")
            if eq:
                said[k] = v
        if said:
            out.append(said)
    return out


def terse_answers(text):
    """`print terse` (and `print detail`) as dictionaries - for a RouterOS whose console does not know
    as-value: ` 3 X  ;;; a comment` / ` 3 XD chain=forward action=accept comment="a b"` - the number, the
    flags (X disabled, D dynamic, I invalid), then key=value words; a value in quotes may hold spaces and
    \\" ; a ;;; line is the comment of its entry (print detail); a line that does not begin with a number
    is the rest of the one before."""
    entries = []
    for raw in str(text or "").replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip() or re.match(r"^\s*(Flags|Columns):", line):
            continue
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if m:
            rest, flags = m.group(2), ""
            f = re.match(r"^([XDIA*SLHE]{1,6})(?:\s+|$)(.*)$", rest)
            if f and "=" not in f.group(1):
                flags, rest = f.group(1), f.group(2)
            e = {"n": int(m.group(1)), "flags": flags, "text": "", "comment": None}
            rest = rest.strip()
            if rest.startswith(";;;"):
                e["comment"] = rest[3:].strip()
            else:
                e["text"] = rest
            entries.append(e)
            continue
        if not entries:
            continue
        e, stripped = entries[-1], line.strip()
        if stripped.startswith(";;;"):
            e["comment"] = ((e["comment"] + " ") if e["comment"] else "") + stripped[3:].strip()
        else:
            e["text"] += (" " if e["text"] else "") + stripped
    out = []
    for e in entries:
        said = _kv_words(e["text"])
        if e["comment"] is not None and "comment" not in said:
            said["comment"] = e["comment"]
        said["disabled"] = "true" if "X" in e["flags"] else said.get("disabled", "false")
        said["dynamic"] = "true" if "D" in e["flags"] else said.get("dynamic", "false")
        if "I" in e["flags"]:
            said["invalid"] = "true"
        said[".n"] = str(e["n"])
        out.append(said)
    return out


def _kv_words(text):
    """key=value words: a value in quotes may hold spaces and \\" \\\\; one not in quotes ends at a space -
    but a word without = after it is the rest of that value (a comment written without quotes)."""
    out, i, n, last = {}, 0, len(text), None
    while i < n:
        while i < n and text[i] == " ":
            i += 1
        m = re.match(r"([\w.-]+)=", text[i:])
        if not m:
            j = text.find(" ", i)
            j = n if j < 0 else j
            if last is not None:
                out[last] += " " + text[i:j]
            i = j
            continue
        key = m.group(1)
        i += m.end()
        if i < n and text[i] == '"':
            i += 1
            val = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 1
                val.append(text[i])
                i += 1
            i += 1
            out[key] = "".join(val)
        else:
            j = text.find(" ", i)
            j = n if j < 0 else j
            out[key] = text[i:j]
            i = j
        last = key
    return out


def keyvalue_answers(text):
    """`name: value` lines (/system resource print), as one dictionary - a value the console wrapped
    put back together (isemon's unwrap_router_print)."""
    said, last = {}, None
    for line in str(text or "").replace("\r\n", "\n").split("\n"):
        m = re.match(r"^\s*([\w.-]+): ?(.*)$", line)
        if m:
            last = m.group(1)
            said[last] = m.group(2).strip()
        elif last and line.strip():
            said[last] += line.strip()
    return [said] if said else []


def clean_terminal_text(text):
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]", "", text)
    out = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if "\r" in line:
            drawn = ""
            for piece in line.split("\r"):
                drawn = piece + drawn[len(piece):]
            line = drawn
        out.append("".join(c for c in line if c == "\t" or ord(c) >= 32).rstrip())
    return "\n".join(out)


class RosSsh(object):
    """The same questions over ssh - signed in with a key made here (its private half sealed in the
    database, written to a 0600 file only for the length of a connection) or a password (answered on a
    terminal of its own, as isemon does without sshpass). The router's host key pinned in a known_hosts
    file of fake-igd's own: StrictHostKeyChecking=yes, so one it does not know - or another than the one
    trusted - is refused before anything is sent. No agent, no X11, no forwarding, a strict timeout."""

    def __init__(self, host, port=22, user="", password="", key="", auth="key", known_hosts="",
                 timeout=float(SSH_TIMEOUT), ssh="ssh"):
        self.host, self.port, self.user = str(host or ""), int(port or 22), str(user or "")
        self.password, self.key, self.auth = str(password or ""), str(key or ""), auth
        self.known_hosts, self.timeout, self.ssh = known_hosts, float(timeout), ssh
        self.fingerprint, self.cert, self.steps = "", {}, []

    def argv(self, key_path=None):
        if not host_ok(self.host):
            raise MtError("%s is not an address or a host name" % self.host[:60])
        a = [self.ssh, "-p", str(self.port), "-F", "/dev/null",
             "-o", "ConnectTimeout=%d" % max(3, min(30, int(self.timeout))),
             "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=%s" % self.known_hosts,
             "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no", "-o", "LogLevel=ERROR",
             "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
             "-o", "PermitLocalCommand=no", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
             "-o", "NumberOfPasswordPrompts=1", "-T",
             "-o", "PreferredAuthentications=" + ("publickey" if key_path else "password,keyboard-interactive")]
        if key_path:
            a += ["-i", key_path, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        return a + ["-l", self.user, "--", bare_host(self.host)]

    def run(self, line, batch=False):
        """One console line (ssh_check'ed, or ssh_batch_check'ed) on the router: its words, or MtError."""
        if batch:
            ssh_batch_check(line)
        else:
            ssh_check(line)
        if not shutil.which(self.ssh) and not os.path.isfile(self.ssh):
            raise MtError("the ssh client is not installed (dnf install openssh-clients)")
        folder = None
        try:
            if self.auth == "key":
                if not self.key:
                    raise MtError("no ssh key is kept for it yet - make one in Settings → MikroTik")
                folder = tempfile.mkdtemp(prefix="fake-igd-mt-")
                path = os.path.join(folder, "id")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(self.key if self.key.endswith("\n") else self.key + "\n")
                try:
                    r = subprocess.run(self.argv(path) + [line], capture_output=True, timeout=self.timeout,
                                       stdin=subprocess.DEVNULL, env=_ssh_env())
                except subprocess.TimeoutExpired:
                    raise MtError("%s did not answer within %d s" % (self.host, self.timeout))
                out, err, code = r.stdout, r.stderr, r.returncode
            else:
                if not self.password:
                    raise MtError("no password is set for it")
                out, err, code = self._with_password(self.argv() + [line])
        finally:
            if folder:
                shutil.rmtree(folder, ignore_errors=True)
        text = clean_terminal_text(out.decode("utf-8", "replace"))
        if code != 0:
            said = clean_terminal_text(err.decode("utf-8", "replace")) or text
            if "IDENTIFICATION HAS CHANGED" in said or "Host key verification failed" in said \
                    or "No ED25519 host key is known" in said or "host key for" in said.lower():
                raise MtError("%s answered with an ssh host key other than the one trusted, or one not trusted "
                              "yet - so nothing was sent to it. Look at its host key in Settings → MikroTik and "
                              "trust it only if it is the router's (/ip ssh print on its console)" % self.host)
            why = [x for x in said.splitlines() if x.strip()]
            raise MtError(why[-1][:200] if why else "ssh exited %s" % code)
        low = text.strip().lower()
        if not batch and low.startswith(("expected ", "syntax error", "bad command", "no such command",
                                         "not enough permissions", "failure:", "input does not match")):
            raise MtError(text.strip().splitlines()[0][:200])
        return text

    def _with_password(self, argv):
        """ssh insists on a terminal for its password prompt: it is given one, and answered once."""
        import pty
        pw = (self.password + "\n").encode()
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execvpe(argv[0], argv, _ssh_env())
            finally:
                os._exit(127)
        pieces, tail, sent, status = [], b"", False, None
        deadline = time.time() + self.timeout
        try:
            while time.time() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.3)
                if ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    pieces.append(chunk)
                    tail = (tail + chunk)[-200:]
                    if not sent and b"assword" in tail:
                        os.write(fd, pw)
                        sent, pieces, tail = True, [], b""
                    elif sent and tail.rstrip().lower().endswith(b"password:"):
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        return b"", b"the router refused the name or the password", 255
                else:
                    done, st = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = st
                        break
            else:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise MtError("%s did not answer within %d s" % (self.host, self.timeout))
            if status is None:
                _, status = os.waitpid(pid, 0)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        code = os.waitstatus_to_exitcode(status) if status is not None else 255
        out = b"".join(pieces)
        return (out, b"", 0) if code == 0 else (b"", out, code)

    def connect(self):
        t0 = time.time()
        got = self.read("/system/identity")
        self.steps.append({"what": "reached %s:%d over ssh, its host key the one trusted" % (self.host, self.port),
                           "ok": True, "said": "%d ms" % ((time.time() - t0) * 1000)})
        self.steps.append({"what": "signed in as %s with %s" % (self.user, "a key" if self.auth == "key" else "a password"),
                           "ok": True, "said": (got[0].get("name") if got else "")})
        return self

    def close(self):
        pass

    def read(self, path, query=None):
        return self._answers(self.run(ssh_command(path, query)))

    @staticmethod
    def _answers(text):
        got = ssh_answers(text)
        if not got and text.strip() and "=" not in text:
            got = keyvalue_answers(text)
        return got[:LIST_MOST]

    def read_many(self, names):
        """Every menu of `names` in ONE ssh connection (1.9.2) - {name: entries} and {name: why not}. RouterOS
        reads the whole line before it runs any of it: a menu it does not know (an older RouterOS) fails the
        whole line - then the ones it knows are read in one line again, and only the one it does not know is
        said missing."""
        names = list(names)
        nonce = secrets.token_hex(8)
        text = self.run(ssh_batch(names, nonce), batch=True)
        parts = ssh_split(text, nonce)
        if not parts:
            low = text.strip().lower()
            bad = re.search(r"bad command name (\S+)", low)
            if bad and len(names) > 1:
                word = bad.group(1)
                gone = [n for n in names if word in READ[n][0].split("/")]
                if gone and len(gone) < len(names):
                    got, missing = self.read_many([n for n in names if n not in gone])
                    for n in gone:
                        missing[n] = "bad command name %s - not on this RouterOS" % word
                    return got, missing
            raise MtError(text.strip().splitlines()[0][:200] if text.strip() else "no answer to the read")
        got, missing = {}, {}
        for n in names:
            if n not in parts:
                missing[n] = "not answered"
                continue
            low = parts[n].strip().lower()
            if low.startswith(("bad command", "no such command", "not enough permissions", "failure:", "syntax error",
                               "expected ")):
                missing[n] = parts[n].strip().splitlines()[0][:200]
                continue
            got[n] = self._answers(parts[n])
        # 1.9.9: a print the router refuses while it runs the line (not enough permissions for /log or /user)
        # ends the whole line there - the menus after it are read again, in a line of their own
        rest = [n for n in names if missing.get(n) == "not answered"]
        if rest and len(rest) < len(names) and not any(n in parts for n in names[names.index(rest[0]):]):
            more, still = self.read_many(rest)
            got.update(more)
            for n in rest:
                missing.pop(n, None)
            missing.update(still)
        return got, missing


def _ssh_env():
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "HOME": tempfile.gettempdir()}
    for k in ("FAKE_SSH_LOG", "FAKE_SSH_HOSTKEY", "FAKE_ROUTER_WRITES", "FAKE_SSH_UNKNOWN",
              "FAKE_SSH_DENY"):    # the test's stand-in for ssh
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


# ---- the host key: shown, then trusted (TOFU, as otp's backup destinations) ----------------------------
def host_key_scan(host, port=22, timeout=10, keyscan="ssh-keyscan", keygen="ssh-keygen"):
    """The router's ssh host keys as it shows them now: [{line, type, fingerprint}] - not trusted yet."""
    if not host_ok(host):
        raise MtError("%s is not an address or a host name" % str(host)[:60])
    try:
        r = subprocess.run([keyscan, "-T", str(int(timeout)), "-p", str(int(port)), "-t", "ed25519,ecdsa,rsa", "--",
                            bare_host(host)], capture_output=True, timeout=timeout + 5, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise MtError("its host key could not be read (%s)" % e)
    out = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            blob = base64.b64decode(parts[2])
        except ValueError:
            continue
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        out.append({"line": "%s %s %s" % (_kh_name(host, port), parts[1], parts[2]), "type": parts[1],
                    "fingerprint": fp})
    if not out:
        said = r.stderr.decode("utf-8", "replace").strip().splitlines()
        raise MtError("%s:%s showed no ssh host key%s" % (host, port, (" (%s)" % said[-1][:120]) if said else
                                                          " - is its ssh service on, for this machine's address?"))
    return out


def _kh_name(host, port):
    h = bare_host(host)
    return h if int(port) == 22 else "[%s]:%d" % (h, int(port))


def host_keys_known(path, host, port=22):
    """The trusted host keys of host:port in our known_hosts file: [{type, fingerprint}]."""
    name = _kh_name(host, port)
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and name in parts[0].split(","):
                    blob = base64.b64decode(parts[2])
                    out.append({"type": parts[1], "fingerprint": "SHA256:" + base64.b64encode(
                        hashlib.sha256(blob).digest()).decode().rstrip("=")})
    except (OSError, ValueError):
        pass
    return out


def host_key_trust(path, host, port, keys, fingerprint):
    """The key shown with this fingerprint written to our known_hosts - and every other line of that router
    taken out. Only a key that was shown (keys from host_key_scan) and chosen by its fingerprint."""
    chosen = [k for k in keys if k.get("fingerprint") == fingerprint]
    if not chosen:
        raise MtError("that host key is not the one the router shows now - look again")
    name = _kh_name(host, port)
    kept = []
    try:
        with open(path, encoding="utf-8") as f:
            kept = [ln for ln in f if ln.split() and name not in ln.split()[0].split(",")]
    except OSError:
        pass
    kept.append(chosen[0]["line"].strip() + "\n")
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("".join(kept))
    os.replace(tmp, path)
    return chosen[0]


def host_key_forget(path, host, port=22):
    name = _kh_name(host, port)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return False
    kept = [ln for ln in lines if not (ln.split() and name in ln.split()[0].split(","))]
    if len(kept) == len(lines):
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(kept))
    return True


def make_key(comment="fake-igd-read", keygen="ssh-keygen"):
    """A fresh ed25519 pair (isemon's generate_ssh_key): (private, public)."""
    if not shutil.which(keygen):
        raise MtError("ssh-keygen is not installed (dnf install openssh-clients)")
    folder = tempfile.mkdtemp(prefix="fake-igd-key-")
    path = os.path.join(folder, "id")
    try:
        r = subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path],
                           capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
        if r.returncode != 0:
            raise MtError("ssh-keygen failed: %s" % r.stderr.decode("utf-8", "replace")[:200])
        with open(path, encoding="utf-8") as f:
            private = f.read()
        with open(path + ".pub", encoding="utf-8") as f:
            public = f.read().strip()
        return private, public
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def public_of(private, keygen="ssh-keygen"):
    if not private or not shutil.which(keygen):
        return ""
    folder = tempfile.mkdtemp(prefix="fake-igd-key-")
    path = os.path.join(folder, "id")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(private if private.endswith("\n") else private + "\n")
        r = subprocess.run([keygen, "-y", "-P", "", "-f", path], capture_output=True, timeout=20,
                           stdin=subprocess.DEVNULL)
        return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---- one session, as the settings say -----------------------------------------------------------------
def session(c, password="", pin="", key="", known_hosts="", proxy=None):
    """The way the router is read: c = {mode, tls, host, port, user, auth, ca, tls_name, timeout}."""
    mode, tls = c.get("mode") or "rest", c.get("tls") or "pin"
    port = int(c.get("port") or 0) or usual_port(mode, tls)
    timeout = float(c.get("timeout") or 20)
    if not host_ok(c.get("host")):
        raise MtError("the router's address is not set (Settings → MikroTik)" if not c.get("host")
                      else "%s is not an address or a host name" % str(c.get("host"))[:60])
    if mode == "ssh":
        return RosSsh(c["host"], port, c.get("user"), password, key, c.get("auth") or "key", known_hosts,
                      timeout=max(timeout, 20.0), ssh=os.environ.get("FAKE_IGD_SSH", "ssh"))
    cls = RosApi if mode == "api" else RosRest
    return cls(c["host"], port, tls, c.get("user"), password, pin, c.get("ca") or "", c.get("tls_name") or "",
               timeout=timeout, proxy=proxy)


def _bool(v):
    return str(v).lower() in ("true", "yes", "1")


def read_all(sess, log=None):
    """Everything READ says is needed, plus what else it can read: {name: [entries]} and what could not be
    read, with why ({name: words}). The checks need filter4, nat4, interfaces and their lists."""
    out, missing = {}, {}
    if hasattr(sess, "read_many"):              # ssh: one connection for the whole read (1.9.2)
        names = [n for n in READ if n not in ("users", "groups")]
        got, missing = sess.read_many(names)
        if "identity" in missing:
            raise MtError("its identity could not be read: %s" % missing["identity"])
        return got, missing
    for name, (path, _single, needed) in READ.items():
        if name in ("users", "groups"):
            continue
        try:
            out[name] = sess.read(path)
        except Refused:
            raise
        except MtError as e:
            low = str(e).lower()
            missing[name] = str(e)[:200]
            if needed and not ("no such command" in low or "404" in low or "bad command" in low):
                if name in ("identity",):
                    raise
            # 1.9.9: and a router that stopped answering (REST: each menu would wait the timeout twice, the
            # read busy for many minutes)
            if "closed the connection" in low or "not connected" in low or "could not be reached" in low \
                    or "timed out" in low:
                break
    return out, missing


# 1.9.9: "in:(unknown 0)" (what the router sends itself, output / srcnat) and an IPv6 address without a port
# (ICMPv6: no brackets) are lines of its firewall too
_FW_ADDR = r"\[[0-9a-fA-F:.]+\]|[0-9.]+|[0-9a-fA-F]*:[0-9a-fA-F:.]+"
FW_LINE = re.compile(
    r"^(?P<prefix>.*?)\s*(?P<chain>[A-Za-z][\w-]*): in:(?P<inif>\(unknown \d+\)|\S+) out:(?P<outif>[^,]+),.*?"
    r"proto (?P<proto>[A-Za-z0-9-]+)(?: \([^)]*\))?, "
    r"(?P<src>" + _FW_ADDR + r")(?::(?P<sport>\d+))?->(?P<dst>" + _FW_ADDR + r")(?::(?P<dport>\d+))?(?=[,\s]|$)")
CHAINS = ("input", "forward", "output", "prerouting", "postrouting", "dstnat", "srcnat")


def fw_log(entries, most=2000, chains=()):
    """The lines of the router's log its firewall wrote (a rule with log=yes, 1.9.2): who to whom, which
    protocol and ports, in and out of which interface, under which prefix. Nothing else of the log is kept.
    `chains` (1.9.9): the chains its rules have - RouterOS writes a log-prefix right before the chain, without a
    space ("DROPforward: in:..."): the prefix is told from the chain by them."""
    known = sorted(set(CHAINS) | {str(c) for c in chains or () if c}, key=len, reverse=True)
    out = []
    for e in entries[-most:]:
        if "firewall" not in str(e.get("topics") or ""):
            continue
        msg = str(e.get("message") or "")
        m = FW_LINE.match(msg)
        if not m:
            continue
        g = m.groupdict()
        prefix, chain = g["prefix"].strip(), g["chain"]
        if chain not in known:
            c = next((c for c in known if chain.endswith(c) and len(chain) > len(c)), None)
            if c:
                prefix, chain = (msg[:m.start("chain")] + chain[:-len(c)]).strip(), c
        out.append({"time": str(e.get("time") or ""), "prefix": prefix, "chain": chain,
                    "in": g["inif"], "out": g["outif"].strip(), "proto": g["proto"].lower(),
                    "src": g["src"].strip("[]"), "sport": int(g["sport"]) if g["sport"] else None,
                    "dst": g["dst"].strip("[]"), "dport": int(g["dport"]) if g["dport"] else None,
                    "family": "ipv6" if ":" in g["dst"] else "ip"})
    return out


def snapshot(raw, missing, via):
    """What was read, as the pages and the checks take it: each rule with its number in its table (as
    `print` numbers them), its flags as booleans, its counters as numbers."""
    one = lambda k: (raw.get(k) or [{}])[0] if raw.get(k) else {}   # noqa: E731
    res, ident, rb = one("resource"), one("identity"), one("routerboard")

    def rules(name):
        out = []
        for i, r in enumerate(raw.get(name) or []):
            x = {k: str(v) for k, v in r.items() if not k.startswith(".") or k == ".id"}
            x["n"] = int(r[".n"]) if str(r.get(".n", "")).isdigit() else i
            for f in ("disabled", "dynamic", "invalid", "log"):
                if f in x:
                    x[f] = _bool(x[f])
            for f in ("bytes", "packets"):
                try:
                    x[f] = int(x.get(f) or 0)
                except ValueError:
                    x[f] = 0
            out.append(x)
        return out

    def lists(name):
        got = {}
        for r in raw.get(name) or []:
            got.setdefault(str(r.get("list") or "?"), []).append(
                {"address": str(r.get("address") or ""), "comment": str(r.get("comment") or ""),
                 "disabled": _bool(r.get("disabled")), "dynamic": _bool(r.get("dynamic")),
                 "timeout": str(r.get("timeout") or "")})
        return got
    members = {}
    for m in raw.get("iflist_members") or []:
        if not _bool(m.get("disabled")):
            members.setdefault(str(m.get("list") or ""), []).append(str(m.get("interface") or ""))
    # the built-in lists, as RouterOS has them
    names = [str(r.get("name") or "") for r in raw.get("interfaces") or []]
    members.setdefault("all", names)
    members.setdefault("none", [])
    # 1.9.9: "dynamic" is what /interface flags D (a PPP/VPN server's <pppoe-user>), not a name's beginning - a
    # pppoe-client is pppoe-out1 and an OpenVPN server ovpn-server1, both static
    dyn = [str(r.get("name") or "") for r in raw.get("interfaces") or []
           if _bool(r.get("dynamic")) or str(r.get("name") or "").startswith("<")]
    members.setdefault("dynamic", dyn)
    members.setdefault("static", [n for n in names if n not in dyn])
    # 1.9.9: a list of /interface list may include other lists and exclude some (include=LAN,VPN exclude=...) -
    # its members are its own, those of the lists it includes, less those of the lists it excludes
    defs = {str(r.get("name") or ""): r for r in raw.get("iflists") or [] if r.get("name")}
    for _round in range(4):                             # a list including a list that includes another
        before = {k: list(v) for k, v in members.items()}
        for name, r in defs.items():
            inc = [x.strip() for x in str(r.get("include") or "").split(",") if x.strip()]
            exc = [x.strip() for x in str(r.get("exclude") or "").split(",") if x.strip()]
            if not inc and not exc:
                continue
            got = list(before.get(name) or [])
            for x in inc:
                got += [i for i in before.get(x) or [] if i not in got]
            out_ = {i for x in exc for i in before.get(x) or []}
            members[name] = [i for i in got if i not in out_]
        if members == before:
            break
    return {
        "at": time.time(), "via": via, "missing": missing,
        "identity": ident.get("name") or "", "version": res.get("version") or "",
        "board": res.get("board-name") or rb.get("model") or "", "uptime": res.get("uptime") or "",
        "cpu": res.get("cpu-load") or "", "memory": [res.get("free-memory") or "", res.get("total-memory") or ""],
        "serial": rb.get("serial-number") or "",
        "interfaces": [{k: (_bool(v) if k in ("running", "disabled", "dynamic") else str(v))
                        for k, v in r.items() if k in ("name", "type", "running", "disabled", "mac-address", "comment",
                                                       "dynamic")} for r in raw.get("interfaces") or []],
        "iflists": members,
        "addresses4": [{"address": str(r.get("address") or ""), "interface": str(r.get("interface") or ""),
                        "disabled": _bool(r.get("disabled"))} for r in raw.get("addresses4") or []],
        "addresses6": [{"address": str(r.get("address") or ""), "interface": str(r.get("interface") or ""),
                        "disabled": _bool(r.get("disabled"))} for r in raw.get("addresses6") or []],
        # RouterOS 7 says immediate-gw, 6 immediate-gateway (1.9.2); the routing table kept - main is the one
        "routes4": [{"dst": str(r.get("dst-address") or ""), "gateway": str(r.get("gateway") or ""),
                     "immediate": str(r.get("immediate-gw") or r.get("immediate-gateway") or ""),
                     "active": _bool(r.get("active", "true")), "disabled": _bool(r.get("disabled")),
                     "table": str(r.get("routing-table") or r.get("routing-mark") or "main"),
                     "distance": str(r.get("distance") or ""), "pref-src": str(r.get("pref-src") or ""),
                     "comment": str(r.get("comment") or ""), ".id": str(r.get(".id") or "")}
                    for r in (raw.get("routes4") or [])[:LIST_MOST]
                    if ":" not in str(r.get("dst-address") or "")],
        "routes6": [{"dst": str(r.get("dst-address") or ""), "gateway": str(r.get("gateway") or ""),
                     "immediate": str(r.get("immediate-gw") or r.get("immediate-gateway") or ""),
                     "active": _bool(r.get("active", "true")), "disabled": _bool(r.get("disabled")),
                     "table": str(r.get("routing-table") or "main")}
                    for r in (raw.get("routes6") or [])[:LIST_MOST] if str(r.get("dst-address") or "") == "::/0"],
        "vrfs": [{"name": str(r.get("name") or ""), "interfaces": str(r.get("interfaces") or ""),
                  "disabled": _bool(r.get("disabled"))} for r in raw.get("vrfs") or []],
        "routing_rules": [{k: str(v) for k, v in r.items() if k in (
            "src-address", "dst-address", "routing-mark", "interface", "action", "table", "comment", ".id")}
            | {"disabled": _bool(r.get("disabled")), "inactive": _bool(r.get("inactive"))}
            for r in raw.get("routing_rules") or []],
        "arp": [{"address": str(r.get("address") or ""), "mac": str(r.get("mac-address") or "").upper(),
                 "interface": str(r.get("interface") or "")} for r in raw.get("arp") or []],
        "neigh6": [{"address": str(r.get("address") or ""), "mac": str(r.get("mac-address") or "").upper(),
                    "interface": str(r.get("interface") or "")} for r in raw.get("neigh6") or []],
        "rules": {"ip": {t: rules(t + "4") for t in ("filter", "nat", "mangle", "raw")},
                  "ipv6": {t: rules(t + "6") for t in ("filter", "nat", "mangle", "raw")}},
        "lists": {"ip": lists("lists4"), "ipv6": lists("lists6")},
        "fwlog": fw_log(raw.get("log") or [], chains={r.get("chain") for t in ("filter", "raw", "nat", "mangle")
                                                       for f in ("4", "6") for r in raw.get(t + f) or []}),
        "upnp": {k: str(v) for k, v in one("upnp").items()},
        "upnp_ifs": [{k: str(v) for k, v in r.items() if not k.startswith(".")} for r in raw.get("upnp_ifs") or []],
        "tracking": {k: str(v) for k, v in one("tracking").items() if k in ("enabled", "total-entries", "max-entries")},
    }


def probe(sess, user=""):
    """Try reaching it (isemon's rosapi_probe): sign in, its name, version, board - and whether the account
    could change anything. {ok, steps, identity, version, board, fingerprint, policy, can_write, trouble}."""
    out = {"ok": False}
    try:
        sess.connect()
        seen = {}
        if hasattr(sess, "read_many"):          # ssh: the questions below in one connection (1.9.2)
            got, _miss = sess.read_many(["identity", "resource", "routerboard", "users", "groups"])
            seen = {READ[k][0]: v for k, v in got.items()}

        def rd(path):
            return seen[path] if path in seen else sess.read(path)
        ident = rd("/system/identity")
        res = rd("/system/resource")
        try:
            rb = rd("/system/routerboard")
        except MtError:
            rb = []
        r0, b0 = (res[0] if res else {}), (rb[0] if rb else {})
        out.update(ok=True, identity=(ident[0].get("name") if ident else "") or "", version=r0.get("version") or "",
                   board=r0.get("board-name") or b0.get("model") or "", uptime=r0.get("uptime") or "",
                   serial=b0.get("serial-number") or "")
        sess.steps.append({"what": "its identity", "ok": True, "said": out["identity"]})
        sess.steps.append({"what": "its version", "ok": True, "said": "RouterOS %s" % out["version"]})
        sess.steps.append({"what": "the routerboard", "ok": True, "said": " ".join(x for x in (
            out["board"], out["serial"]) if x) or "-"})
        try:
            me = [u for u in rd("/user") if u.get("name") == user]
            group = me[0].get("group") if me else ""
            groups = [g for g in rd("/user/group") if g.get("name") == group] if group else []
            policy = [p for p in str((groups[0] if groups else {}).get("policy") or "").split(",")
                      if p and not p.startswith("!")]
            out.update(group=group, policy=policy, can_write=bool(set(policy) & WRITE_POLICIES))
            sess.steps.append({"what": "its account's group", "ok": not out["can_write"],
                               "said": "%s: %s%s" % (group or "?", ",".join(policy) or "?",
                                                     " - it may CHANGE things: give it a group that may only read"
                                                     if out["can_write"] else "")})
        except MtError:
            out["policy"] = None
    except MtError as e:
        out["trouble"] = str(e)
        sess.steps.append({"what": "reaching it", "ok": False, "said": str(e)[:300]})
    finally:
        out["fingerprint"] = getattr(sess, "fingerprint", "")
        out["cert"] = getattr(sess, "cert", {})
        out["steps"] = list(sess.steps)
        try:
            sess.close()
        except Exception:                               # noqa: BLE001
            pass
    return out


def commands(user="fake-igd-read", mode="rest", allow_from="", public_key=""):
    """What to type on the router (isemon's rosapi_commands): a group that may only read and use the one
    way chosen, an account in it - and for ssh with a key, the key."""
    user = re.sub(r"[^A-Za-z0-9_.@-]", "", str(user or "")) or "fake-igd-read"
    where = (" address=%s" % allow_from) if allow_from and host_ok(allow_from) else ""
    allowed = {"rest": "rest-api", "api": "api", "ssh": "ssh"}.get(mode, "rest-api")
    deny = [p for p in ("local", "telnet", "ssh", "ftp", "reboot", "write", "policy", "test", "winbox", "password",
                        "web", "sniff", "sensitive", "romon", "api", "rest-api") if p != allowed]
    lines = ["/user group add name=fake-igd-read policy=read,%s,%s" % (allowed, ",".join("!" + p for p in deny)),
             '/user add name=%s group=fake-igd-read%s password="choose-a-long-one"' % (user, where)]
    if mode == "ssh" and public_key:
        lines.append('/user ssh-keys add user=%s key="%s"' % (user, public_key.strip().replace('"', "")))
    if mode == "rest":
        lines.append("/ip service set www-ssl disabled=no%s" % where)
    elif mode == "api":
        lines.append("/ip service set api-ssl disabled=no%s" % where)
    else:
        lines.append("/ip service set ssh disabled=no%s" % where)
    return "\n".join(lines)
