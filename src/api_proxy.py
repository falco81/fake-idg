"""api_proxy.py - Settings → Proxy (1.6.0), as otp's: the settings and Try it.
The proxy itself is igd_proxy.py, which the others ask (url_for, open_url, env)."""
import re

import igd_proxy as P
import igd_seal as SEAL

NAME = "proxy"


def _url(v):
    return "" if P.URL_RE.match(v) else "http://host:port - an HTTP proxy (CONNECT for https)"


def _no(v):
    for w in re.split(r"[\s,;]+", v):
        if w and not re.match(r"^[A-Za-z0-9.*:\[\]/_-]{1,253}\Z", w):
            return "%s is not a name, an address or a net" % w
    return ""


SETTINGS = [
    {"key": "proxy", "name": "Go out through a proxy", "kind": "bool", "default": False,
     "says": "An HTTP proxy for what is switched on below, and for nothing else; all of them off, it is used "
             "nowhere. Mail, syslog, the backups, the PS5's UPnP and the pages themselves never use it."},
    {"key": "proxy_url", "name": "The proxy", "kind": "text", "default": "", "check": _url,
     "only_when": ("proxy", True), "says": "<code>http://proxy.example.cz:3128</code>"},
    {"key": "proxy_user", "name": "User name at the proxy", "kind": "text", "default": "", "most": 200,
     "only_when": ("proxy", True), "says": "Where the proxy asks for one. Empty: none."},
    {"key": "proxy_password", "name": "Password at the proxy", "kind": "secret", "default": "", "most": 500,
     "only_when": ("proxy", True), "says": "Kept sealed, like the other passwords."},
    {"key": "proxy_no", "name": "Straight, not through the proxy", "kind": "text",
     "default": "localhost, 127.0.0.1, ::1", "check": _no, "most": 2000, "only_when": ("proxy", True),
     "says": "Names and addresses reached without it, separated by commas: <code>.example.cz</code> is every "
             "name under it, <code>10.0.0.0/8</code> a net."},
    {"key": "proxy_update", "name": "The new versions of fake-igd", "kind": "bool", "default": False,
     "only_when": ("proxy", True), "says": "Looking for a new version of fake-igd and fetching it (Upgrades)."},
    {"key": "proxy_os", "name": "The system updates (dnf)", "kind": "bool", "default": False,
     "only_when": ("proxy", True),
     "says": "dnf fetches the updates of System updates through it - handed to root's job as https_proxy, "
             "never on a command line."},
    {"key": "proxy_acme", "name": "ACME: the CA (Let’s Encrypt)", "kind": "bool", "default": False,
     "only_when": ("proxy", True),
     "says": "Ordering and renewing the certificates, and the CA’s renewal window. A proxy down then stops the "
             "renewals - they are tried again, well before one runs out."},
    {"key": "proxy_acme_dns", "name": "ACME: the DNS APIs (deSEC, Cloudflare, acme-dns)", "kind": "bool",
     "default": False, "only_when": ("proxy", True),
     "says": "The TXT record put in and taken away again (DNS-01) through the API of deSEC, Cloudflare or "
             "acme-dns. RFC 2136 updates are DNS, never through it."},
    {"key": "proxy_ntfy", "name": "The notifications (ntfy)", "kind": "bool", "default": False,
     "only_when": ("proxy", True),
     "says": "fake-igd.service sends its notifications to the ntfy server through it. A proxy down then stops "
             "them - leave it off unless the ntfy server can be reached no other way."},
]


def proxy_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    if b.get("action") != "try":
        raise ValueError("no such action")
    import upnp as U
    url = str(b.get("url") or "").strip() or ctx.cfg.get("upgrade_url") or "https://github.com/"
    got = P.try_url(ctx.store, url, U.VERSION)
    ctx.event("%s tried %s %s: %s" % (me["name"], got["url"], "through the proxy" if got["mode"] == "proxy"
                                       else "straight", "reached" if got["ok"] else "not reached"),
              "info" if got["ok"] else "warn")
    return {"result": got}


def proxy_get(ctx):
    c = P.settings(ctx.store)
    return {"on": P.is_set(c), "for": {k: bool(c.get(v)) for k, v in P.PURPOSES.items()},
            "upgrade_url": ctx.cfg.get("upgrade_url") or ""}


ROUTES = {
    ("GET", "/api/proxy"): proxy_get,
    ("POST", "/api/proxy"): proxy_post,
}


def on_saved(ctx, changed):
    SEAL.seal_settings(ctx.store, ["proxy_password"])       # kept sealed in the database (igd_seal)


def background(ctx):
    SEAL.seal_settings(ctx.store, ["proxy_password"])
