"""igd_proxy.py - the HTTP proxy fake-igd goes out through, for what is switched on (1.6.0).

As otp's: off by default, and switched on it is used only for what is switched on in
Settings → Proxy - the new versions of fake-igd (`upgrade`), the system updates (`os`),
ACME (`acme`) and the ntfy notifications (`ntfy`); all of them off, nowhere. Mail never
goes through it (SMTP is not HTTP), nor does syslog. `proxy_no` lists what is reached
straight: a name, `.example.cz` for every name under it, an address or a net.

For the others:

    import igd_proxy
    igd_proxy.url_for(store, "upgrade")       # "http://user:pw@proxy:3128" or None
    igd_proxy.open_url(store, "upgrade", req, timeout=30)   # urllib, through it where it should
    igd_proxy.env(store, "os")                # {"https_proxy": ..., "no_proxy": ...} for a program

`store` may be None: the database is then opened by itself (FAKE_IGD_DB, read only), so
fake-igd.service can ask too. Only the standard library.
"""
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request

DEFAULTS = {
    "proxy": False,
    "proxy_url": "",
    "proxy_user": "",
    "proxy_password": "",
    "proxy_no": "localhost, 127.0.0.1, ::1",
    "proxy_update": False,
    "proxy_os": False,
    "proxy_acme": False,
    "proxy_ntfy": False,
}
PURPOSES = {"upgrade": "proxy_update", "os": "proxy_os", "acme": "proxy_acme", "ntfy": "proxy_ntfy"}
URL_RE = re.compile(r"^http://(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]{1,253})(?::\d{1,5})?/?\Z")
DB_FILE = os.environ.get("FAKE_IGD_DB", "/var/lib/fake-igd/fake-igd.db")


def settings(store=None):
    raw = None
    if store is not None:
        raw = store.get_meta("settings")
    else:
        try:
            import sqlite3
            db = sqlite3.connect("file:%s?mode=ro" % DB_FILE, uri=True, timeout=5)
            try:
                row = db.execute("SELECT v FROM meta WHERE k = 'settings'").fetchone()
                raw = row[0] if row else None
            finally:
                db.close()
        except Exception:                               # noqa: BLE001 - no database: no proxy
            raw = None
    try:
        got = json.loads(raw or "{}")
    except ValueError:
        got = {}
    out = dict(DEFAULTS)
    if isinstance(got, dict):
        out.update({k: got[k] for k in DEFAULTS if k in got})
    return out


def is_set(c):
    return bool(c.get("proxy")) and bool(str(c.get("proxy_url") or "").strip())


def full(c):
    """The proxy's address with its user and password in it - never logged, never shown."""
    url = str(c.get("proxy_url") or "").strip().rstrip("/")
    user = str(c.get("proxy_user") or "").strip()
    if not url or not user:
        return url
    scheme, _, rest = url.partition("://")
    return "%s://%s:%s@%s" % (scheme, urllib.parse.quote(user, safe=""),
                              urllib.parse.quote(str(c.get("proxy_password") or ""), safe=""), rest)


def url_for(store, purpose):
    """The proxy (user and password in it) for this purpose, or None where it goes straight."""
    c = settings(store)
    key = PURPOSES.get(purpose)
    if not key or not is_set(c) or not c.get(key):
        return None
    return full(c) or None


def no_list(c):
    return [w.strip().lower() for w in re.split(r"[\s,;]+", str(c.get("proxy_no") or "")) if w.strip()]


def skips(c, host):
    """Whether this host is reached straight, as proxy_no says."""
    host = str(host or "").strip("[]").lower()
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for one in no_list(c):
        if one == "*":
            return True
        if ip is not None and ("/" in one or re.match(r"^[0-9a-f.:]+\Z", one)):
            try:
                if ip in ipaddress.ip_network(one.strip("[]"), strict=False):
                    return True
            except ValueError:
                pass
            continue
        one = one.lstrip("*")
        if one.startswith("."):
            if host.endswith(one) or host == one[1:]:
                return True
        elif host == one:
            return True
    return False


class _ProxyOnly(urllib.request.ProxyHandler):
    """ProxyHandler that does not look at no_proxy of the environment: only proxy_no says."""

    def proxy_open(self, req, proxy, type):            # noqa: A002 - urllib's own name
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)   # noqa: SLF001
        if user and password:
            creds = base64.b64encode(("%s:%s" % (urllib.parse.unquote(user),
                                                 urllib.parse.unquote(password))).encode())
            req.add_header("Proxy-authorization", "Basic " + creds.decode("ascii"))
        req.set_proxy(urllib.parse.unquote(hostport), proxy_type or req.type)
        return None


def open_url(store, purpose, req, timeout=30, context=None):
    """urllib.request.urlopen - through the proxy when this purpose's switch is on and the host
    is not one reached straight; never through what the environment says."""
    if not isinstance(req, urllib.request.Request):
        req = urllib.request.Request(req)
    c = settings(store)
    proxy = url_for(store, purpose)
    host = urllib.parse.urlsplit(req.full_url).hostname or ""
    handlers = [_ProxyOnly({"http": proxy, "https": proxy} if proxy and not skips(c, host) else {})]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def env(store, purpose):
    """http_proxy, https_proxy and no_proxy for a program (dnf, curl) - {} where it goes straight."""
    proxy = url_for(store, purpose)
    if not proxy:
        return {}
    c = settings(store)
    out = {k: proxy for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")}
    no = ",".join(no_list(c))
    if no:
        out["no_proxy"] = out["NO_PROXY"] = no
    return out


def try_url(store, url, version=""):
    """Settings → Proxy → Try it (otp's proxy_try): an address asked through the proxy where one
    is set and the address is not one reached straight, else straight - one step at a time."""
    url = str(url or "").strip()
    if not re.match(r"^https?://[^\s/]+[^\s]*\Z", url):
        raise ValueError("an address starting https:// (or http://)")
    c = settings(store)
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    tls_on = u.scheme == "https"
    port = u.port or (443 if tls_on else 80)
    via, why = "", ""
    if not is_set(c):
        why = "no proxy is set" if not c.get("proxy") else "the proxy has no address"
    elif skips(c, host):
        why = "%s is in the list reached straight" % host
    else:
        via = full(c)
    px = urllib.parse.urlsplit(via) if via else None
    out = {"url": url, "host": host, "port": port, "mode": "proxy" if via else "direct", "why_direct": why,
           "node": socket.gethostname().split(".")[0], "steps": [], "ok": False,
           "proxy": "%s:%d" % (px.hostname, px.port or 3128) if px else "", "proxy_auth": bool(px and px.username)}
    began = time.time()
    sock = [None]

    def step(what, fn):
        t0 = time.time()
        try:
            said = fn() or ""
        except Exception as e:                          # noqa: BLE001
            out["steps"].append({"what": what, "ok": False, "ms": int((time.time() - t0) * 1000),
                                 "said": str(getattr(e, "reason", "") or e)[:300]})
            raise
        out["steps"].append({"what": what, "ok": True, "ms": int((time.time() - t0) * 1000), "said": said})

    def resolve(name, p):
        addrs = []
        for g in socket.getaddrinfo(name, p, 0, socket.SOCK_STREAM):
            if g[4][0] not in addrs:
                addrs.append(g[4][0])
        return ", ".join(addrs[:4])

    def connect(name, p):
        sock[0] = socket.create_connection((name, p), timeout=10)
        sock[0].settimeout(15)
        peer = sock[0].getpeername()
        return "%s port %d" % (peer[0], peer[1])

    def read_head():
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock[0].recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        m = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)$", line)
        if not m:
            raise ValueError("no HTTP answer: %r" % line[:80])
        return int(m.group(1)), m.group(2).strip()

    def auth_header():
        if not (px and px.username):
            return ""
        creds = "%s:%s" % (urllib.parse.unquote(px.username), urllib.parse.unquote(px.password or ""))
        return "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(creds.encode()).decode()

    agent = "fake-igd/%s (+proxy check)" % (version or "?")
    try:
        if via:
            step("the proxy looked up (%s)" % px.hostname, lambda: resolve(px.hostname, px.port or 3128))
            step("connected to the proxy", lambda: connect(px.hostname, px.port or 3128))
            if tls_on:
                def tunnel():
                    sock[0].sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%sUser-Agent: %s\r\n\r\n" % (
                        host, port, host, port, auth_header(), agent)).encode())
                    code, words = read_head()
                    if code == 407:
                        raise ValueError("the proxy asks for a user name and a password (407) - they are %s"
                                         % ("wrong" if px.username else "missing"))
                    if code != 200:
                        raise ValueError("the proxy said %d %s" % (code, words))
                    return "%d %s%s" % (code, words, " - with the user name and password" if px.username else "")
                step("a tunnel through the proxy to %s:%d" % (host, port), tunnel)
        else:
            step("%s looked up" % host, lambda: resolve(host, port))
            step("connected to %s" % host, lambda: connect(host, port))
        if tls_on:
            def handshake():
                ctx = ssl.create_default_context()
                sock[0] = ctx.wrap_socket(sock[0], server_hostname=host)
                cert = sock[0].getpeercert() or {}
                subj = dict(x[0] for x in cert.get("subject", ()) if x)
                iss = dict(x[0] for x in cert.get("issuer", ()) if x)
                out["tls"] = {"version": sock[0].version(), "cipher": (sock[0].cipher() or [""])[0],
                              "subject": subj.get("commonName", ""),
                              "issuer": iss.get("organizationName") or iss.get("commonName", ""),
                              "until": cert.get("notAfter", "")}
                return "%s, %s - %s, by %s" % (out["tls"]["version"], out["tls"]["cipher"], out["tls"]["subject"],
                                               out["tls"]["issuer"])
            step("TLS, the certificate of %s checked" % host, handshake)

        def ask():
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            target = url if (via and not tls_on) else path
            sock[0].sendall(("HEAD %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: %s\r\nConnection: close\r\n\r\n" % (
                target, u.netloc.split("@")[-1], auth_header() if (via and not tls_on) else "", agent)).encode())
            code, words = read_head()
            out["status"] = code
            if code == 407:
                raise ValueError("the proxy asks for a user name and a password (407)")
            return "%d %s" % (code, words)
        step("asked for %s" % (u.path or "/"), ask)
        out["ok"] = True
    except Exception:                                   # noqa: BLE001 - the step says what
        pass
    finally:
        try:
            if sock[0]:
                sock[0].close()
        except OSError:
            pass
    out["ms"] = int((time.time() - began) * 1000)
    return out
