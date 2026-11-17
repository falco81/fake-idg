"""igd_ntfy.py - notifications to ntfy, shared by fake-igd.service and the pages' API (1.8.2).

What is sent - each kind of event switched on or off, with a priority and tags of its own (config.json's
ntfy_events, {kind: {on, priority, tags}}) - quiet hours (ntfy_quiet_from / _to: only ntfy_quiet_priority
and above go out then; the rest are held and sent as one summary when they end, or dropped), and a rate
limit (ntfy_rate_per_hour for each kind; then one "N more" summary). The message itself goes out with
send(): ntfy.sh or a server of your own, a token or a user and password, a CA of your own, the proxy of
Settings → Proxy when it is on for ntfy.

The two older switches stay what they were: notify_on_renew is the kind port_renew's "on" and
notify_other_router other_router's, unless ntfy_events says otherwise.
"""
import base64
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# kind -> (group, what it is, when, on as it comes, from where)
EVENTS = [
    ("port_new", "upnp", "A new port asked for and accepted", "A device asks for a port with AddPortMapping and fake-igd confirms it.", True),
    ("port_renew", "upnp", "A port renewed", "A device asks again for a port it holds (its lease renewed).", False),
    ("port_refused", "upnp", "A port refused", "Refused: reject mode (501), a conflict with another device (718), no room (728) or invalid (402).", True),
    ("port_deleted", "upnp", "A port taken away", "A device takes a port away (DeletePortMapping, DeletePortMappingRange).", False),
    ("port_expired", "upnp", "A mapping ran out", "A port's lease ran out and fake-igd forgot it.", False),
    ("device_new", "upnp", "A new device searching for a router", "A device (its address and User-Agent) searches for a UPnP router for the first time.", False),
    ("device_stopped", "upnp", "A device that stopped after the answer", "Answered, it did not fetch the description within a minute - a PS5 asks only its default gateway (Settings → Gateway for devices).", False),
    ("other_router", "upnp", "Another UPnP router", "Another UPnP router announces itself on the network - the PS5 may ask it instead.", True),
    ("public_ip", "upnp", "The public IP changed", "The public IP fake-igd reports changed (external_ip auto, looked up every 30 minutes).", True),
    ("iface", "upnp", "An interface came or went", "An interface fake-igd answers on came up or went away.", False),
    ("service", "upnp", "The service started or stopped", "fake-igd.service started or stopped.", False),
    ("service_crash", "upnp", "An unclean start after a crash", "fake-igd.service started after it had not stopped cleanly.", False),
    ("gw_online", "gateway", "A device came online or went offline", "A device of Gateway for devices appeared in or left the neighbour table, or its traffic started or stopped.", False),
    ("gw_drops", "gateway", "Drops toward local networks", "A device of Gateway for devices tried networks it may not reach more often than the limit in an hour.", False),
    ("gw_forward", "gateway", "Forwarding turned off by something else", "The gateway for devices is on, but net.ipv4.ip_forward is off or FAKE-IGD-FWD is not first in FORWARD.", False),
    ("gw_rule_first", "gateway", "A device's own rule used for the first time", "A rule of a device's own firewall forwarded its first packet.", False),
    ("alerts", "system", "Every alert of Settings → Alerts and reports", "What the alerts find wrong, sent here as well (each kind below can be left out).", False),
    ("alerts_over", "system", "... and when it is over", "The alert's \"over\" message, as the mail says it.", False),
]
KINDS = [e[0] for e in EVENTS]
GROUP_WORDS = {"upnp": "UPnP - from fake-igd.service", "gateway": "Gateway for devices", "system": "System - the alerts"}
# The alerts' own kinds (api_alerts problems(): their keys before ":") - each can be left out of ntfy.
ALERT_KINDS = [("service", "fake-igd.service down"), ("avahi", "avahi-daemon down"), ("other", "another UPnP router"),
               ("newer", "a new version is out"), ("disk", "a disk getting full"), ("cert", "the certificate running out"),
               ("acme", "ACME failed"), ("backup", "a backup failed"), ("upgrade", "an upgrade failed"),
               ("selinux", "SELinux refusing"), ("gateway", "the gateway not forwarding"), ("mailq", "mails that do not go"),
               ("updates", "system updates waiting"), ("reboot", "a restart waiting"), ("siem", "the syslog servers"),
               ("snmp", "the SNMP agent"), ("dbcopy", "the copy of the database"), ("guard", "sign-in protection"),
               ("mikrotik", "the MikroTik (a port missing, not readable)")]
# How a kind looks as it comes: (priority, tags) - 0 and "" are those of Settings above.
LOOK = {"other_router": (4, "warning"), "service_crash": (4, "warning"), "gw_forward": (4, "warning"),
        "port_refused": (0, "no_entry")}
# Each kind's wording as fake-igd and the pages send it, with made-up values - "Send a sample".
SAMPLES = {
    "port_new": ("UPnP: UDP 3074", "192.168.40.50 asks for UDP 3074 -> 192.168.40.50:3074 'PS5 3074 UDP' (lease 3600s)"),
    "port_renew": ("UPnP: UDP 3074 renewed", "192.168.40.50 asks for UDP 3074 -> 192.168.40.50:3074 'PS5 3074 UDP' "
                   "(lease 3600s) - renewed"),
    "port_refused": ("UPnP: UDP 3074 refused", "192.168.40.50 asks for UDP 3074 -> 192.168.40.50:3074 'PS5 3074 UDP' "
                     "- refused: it belongs to 192.168.40.61 (conflict, 718)"),
    "port_deleted": ("UPnP: UDP 3074 taken away", "192.168.40.50 took UDP 3074 -> 192.168.40.50 away (DeletePortMapping)"),
    "port_expired": ("UPnP: UDP 3074 ran out", "the mapping UDP 3074 -> 192.168.40.50:3074 ran out (its lease was "
                     "not renewed)"),
    "device_new": ("UPnP: a new device searching", "192.168.40.50 (PS5/8.20 UPnP/1.1) searches for a UPnP router for "
                   "the first time (ST=urn:schemas-upnp-org:device:InternetGatewayDevice:1)"),
    "device_stopped": ("UPnP: 192.168.40.50 stopped after the answer", "192.168.40.50 was answered but did not fetch the "
                       "description within a minute. A PS5 asks only its default gateway: make this server its "
                       "gateway (Settings → Gateway for devices)."),
    "other_router": ("UPnP: another router", "192.168.40.1 announces itself as a UPnP router "
                     "(urn:schemas-upnp-org:device:InternetGatewayDevice:1) - the PS5 may use it instead of fake-igd"),
    "public_ip": ("fake-igd: the public IP changed", "The public IP is 203.0.113.7 now (it was 203.0.113.5)."),
    "iface": ("fake-igd: ens224 is gone", "ens224 (172.16.16.254) is gone - fake-igd no longer answers there."),
    "service": ("fake-igd: started", "fake-igd 1.8.2 started on igd (mode active)."),
    "service_crash": ("fake-igd: started after a crash", "fake-igd 1.8.2 started on igd, and it had not stopped "
                      "cleanly before (a crash, a kill or a power cut)."),
    "gw_online": ("Gateway: PS5 is online", "PS5 (192.168.40.50, 00:11:22:33:44:55) is online - in the neighbour "
                  "table again."),
    "gw_drops": ("Gateway: PS5 tried local networks", "PS5 (192.168.40.50) tried 240 times in the last hour to reach "
                 "networks it may not (the limit is 100)."),
    "gw_forward": ("Gateway: forwarding is off", "The gateway for devices is on, but net.ipv4.ip_forward was turned "
                   "off by something else."),
    "gw_rule_first": ("Gateway: PS5's rule used", "The rule 'allow TCP 443 to 10.0.0.5' of PS5 forwarded its first "
                      "packet."),
    "alerts": ("fake-igd: a disk is getting full", "/var is 93% full."),
    "alerts_over": ("fake-igd: over - a disk is getting full", "It is all right again: /var is 93% full."),
}
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d\Z")


def _hdr(value):
    """A header value: plain ASCII as it is, anything else as an RFC 2047 encoded word (ntfy reads it)."""
    v = str(value)
    try:
        v.encode("ascii")
        return v
    except UnicodeEncodeError:
        return "=?UTF-8?B?%s?=" % base64.b64encode(v.encode("utf-8")).decode()


def post(cfg, title, message, priority=None, tags=None, timeout=10):
    """One message to ntfy (ntfy.sh or a private server). Returns (ok, words)."""
    url = str(cfg.get("ntfy_url") or "").strip()
    if not url:
        return False, "ntfy_url is not set"
    if not re.match(r"^https?://[^/\s]+/[^\s]+$", url):
        return False, "ntfy_url must be http(s)://server/topic"
    headers = {"Title": _hdr(title), "Priority": str(priority or cfg.get("ntfy_priority") or 3)}
    t = tags if tags is not None else cfg.get("ntfy_tags")
    if t:
        headers["Tags"] = _hdr(t)
    if cfg.get("ntfy_token"):
        headers["Authorization"] = "Bearer %s" % str(cfg["ntfy_token"]).strip()
    elif cfg.get("ntfy_user"):
        pair = "%s:%s" % (cfg.get("ntfy_user"), cfg.get("ntfy_password") or "")
        headers["Authorization"] = "Basic %s" % base64.b64encode(pair.encode("utf-8")).decode()
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context(cafile=cfg.get("ntfy_ca_file") or None)
    req = urllib.request.Request(url, data=str(message).encode("utf-8"), headers=headers, method="POST")
    try:
        proxy = ""
        try:                                   # Settings → Proxy, switched on for ntfy (1.6.0)
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import igd_proxy
            proxy = igd_proxy.url_for(None, "ntfy")
        except Exception:                      # noqa: BLE001 - straight
            proxy = ""
        opener = (lambda: igd_proxy.open_url(None, "ntfy", req, timeout=timeout, context=ctx)) if proxy else \
            (lambda: urllib.request.urlopen(req, timeout=timeout, context=ctx))
        with opener() as r:
            r.read()
            return True, "HTTP %d" % r.status
    except urllib.error.HTTPError as e:
        why = {401: "unauthorized - check ntfy_token / ntfy_user / ntfy_password",
               403: "forbidden - the token/user may not write to this topic",
               429: "too many messages (rate limited)"}.get(e.code, e.reason)
        return False, "HTTP %d %s" % (e.code, why)
    except ssl.SSLError as e:
        return False, "TLS: %s (a private CA? set ntfy_ca_file)" % e
    except Exception as e:  # noqa: BLE001
        why = getattr(e, "reason", e)
        if isinstance(why, ssl.SSLError):
            vm = getattr(why, "verify_message", "")
            return False, "TLS: %s (a private CA? set ntfy_ca_file)" % (("certificate verify failed: " + vm) if vm
                                                                         else why)
        return False, str(why)


# ---- what is sent ---------------------------------------------------------------------------------
def events_checked(raw):
    """ntfy_events as it may be kept: {kind: {on, priority 0-5 (0: as set above), tags}} and {"alert:K": {on}}."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except ValueError:
            raise ValueError("ntfy_events: not a JSON object")
    if not isinstance(raw, dict):
        raise ValueError("ntfy_events: not a JSON object")
    out = {}
    known_alerts = {k for k, _w in ALERT_KINDS}
    for k, v in raw.items():
        k = str(k)
        if k not in KINDS and not (k.startswith("alert:") and k[6:] in known_alerts):
            raise ValueError("ntfy_events: %s is not a kind of event" % k[:40])
        if not isinstance(v, dict):
            raise ValueError("ntfy_events: %s is not an object" % k)
        one = {"on": v.get("on") is True}
        if not k.startswith("alert:") and "priority" in v:
            try:
                p = int(v.get("priority") or 0)
            except (TypeError, ValueError):
                raise ValueError("ntfy_events: %s - a priority of 0 to 5" % k)
            if not 0 <= p <= 5:
                raise ValueError("ntfy_events: %s - a priority of 0 to 5" % k)
            one["priority"] = p
        if not k.startswith("alert:") and "tags" in v:
            tags = str(v.get("tags") or "").strip()
            if len(tags) > 120 or re.search(r"[\x00-\x1f\x7f]", tags):
                raise ValueError("ntfy_events: %s - tags: one line, 120 characters at most" % k)
            one["tags"] = tags
        out[k] = one
    return out


def conf(cfg, kind):
    """{on, priority, tags} of a kind as it is in force: ntfy_events, else the older switches, else as it comes."""
    try:
        ev = events_checked(cfg.get("ntfy_events") or {})
    except ValueError:
        ev = {}
    base = next((e for e in EVENTS if e[0] == kind), None)
    on = base[4] if base else (kind.startswith("alert:"))
    if kind == "port_renew" and "notify_on_renew" in cfg:
        on = bool(cfg.get("notify_on_renew"))
    if kind == "other_router" and "notify_other_router" in cfg:
        on = bool(cfg.get("notify_other_router"))
    p, t = LOOK.get(kind, (0, ""))
    got = {"on": on, "priority": p, "tags": t}
    got.update(ev.get(kind) or {})
    return got


def _quiet(cfg, now=None):
    """Whether it is quiet hours now (the machine's clock)."""
    a, b = str(cfg.get("ntfy_quiet_from") or ""), str(cfg.get("ntfy_quiet_to") or "")
    if not (TIME_RE.match(a) and TIME_RE.match(b)) or a == b:
        return False
    t = time.strftime("%H:%M", time.localtime(now or time.time()))
    return (a <= t < b) if a < b else (t >= a or t < b)


class Notifier:
    """What decides whether a message goes - its kind on, quiet hours, the rate limit - and sends it in a
    thread of its own. record(kind, title, ok, words, why) is told every send (the pages' "What was sent")."""

    def __init__(self, cfg_of, record=None):
        self.cfg_of = cfg_of
        self.record = record or (lambda *a, **k: None)
        self.lock = threading.Lock()
        self.sent = {}            # kind -> [times in the last hour]
        self.over = {}            # kind -> held back by the rate limit: count, first title
        self.held = []            # quiet hours: [(kind, title, message, priority)]

    def _go(self, cfg, kind, title, message, priority, tags, why=""):
        def run():
            ok, words = post(cfg, title, message, priority, tags)
            self.record(kind, title, ok, words, why)
        threading.Thread(target=run, daemon=True).start()

    def send(self, kind, title, message, sample=False, wait=False):
        """Send it as its kind says. sample: the kind's wording as a test - off or quiet, it goes all the same.
        wait: sent before it returns (the service stopping).
        Returns what became of it: "sent", "off", "quiet", "held", "limited", "no url"."""
        cfg = self.cfg_of()
        if not cfg.get("ntfy_url"):
            return "no url"
        c = conf(cfg, kind)
        if not c["on"] and not sample:
            return "off"
        prio = int(c.get("priority") or 0) or int(cfg.get("ntfy_priority") or 3)
        tags = c.get("tags") or cfg.get("ntfy_tags") or ""
        if sample:
            title = "[a sample] " + title
            if wait:
                ok, words = post(cfg, title, message, prio, tags)
                self.record(kind, title, ok, words, "a sample")
                return ("sent: " if ok else "failed: ") + words
            self._go(cfg, kind, title, message, prio, tags, "a sample")
            return "sent"
        now = time.time()
        with self.lock:
            if _quiet(cfg, now) and prio < int(cfg.get("ntfy_quiet_priority") or 4):
                if cfg.get("ntfy_quiet_summary", True):
                    self.held.append((kind, title, message, prio))
                    self.held = self.held[-500:]
                    return "held"
                return "quiet"
            most = int(cfg.get("ntfy_rate_per_hour") or 0)
            times = [t for t in self.sent.get(kind, []) if now - t < 3600]
            if most and len(times) >= most:
                o = self.over.setdefault(kind, {"n": 0, "first": title, "since": now})
                o["n"] += 1
                self.sent[kind] = times
                return "limited"
            times.append(now)
            self.sent[kind] = times
        if wait:                               # the service stopping: before the process is gone
            ok, words = post(cfg, title, message, prio, tags, timeout=5)
            self.record(kind, title, ok, words, "")
            return "sent" if ok else "failed"
        self._go(cfg, kind, title, message, prio, tags)
        return "sent"

    def tick(self):
        """Once a minute: the summary of quiet hours when they are over, and of what the rate limit held back
        once its hour has passed."""
        cfg = self.cfg_of()
        if not cfg.get("ntfy_url"):
            return
        now = time.time()
        with self.lock:
            held = []
            if self.held and not _quiet(cfg, now):
                held, self.held = self.held, []
            over = {}
            for kind, o in list(self.over.items()):
                times = [t for t in self.sent.get(kind, []) if now - t < 3600]
                if len(times) < int(cfg.get("ntfy_rate_per_hour") or 0) or not cfg.get("ntfy_rate_per_hour") \
                        or now - o["since"] >= 3600:
                    over[kind] = self.over.pop(kind)
        if held:
            lines = ["%s - %s" % (h[1], h[2]) for h in held[:40]]
            more = len(held) - len(lines)
            self._go(cfg, "summary", "fake-igd: %d held in the quiet hours" % len(held),
                     "\n".join(lines) + ("\n... and %d more" % more if more else ""),
                     int(cfg.get("ntfy_priority") or 3), cfg.get("ntfy_tags") or "", "quiet hours over")
        for kind, o in over.items():
            words = next((e[2] for e in EVENTS if e[0] == kind), kind)
            self._go(cfg, "summary", "fake-igd: %d more - %s" % (o["n"], words),
                     "%d more of \"%s\" were not sent in the last hour (at most %s an hour) - the first: %s"
                     % (o["n"], words, cfg.get("ntfy_rate_per_hour"), o["first"]),
                     int(cfg.get("ntfy_priority") or 3), cfg.get("ntfy_tags") or "", "rate limit")
