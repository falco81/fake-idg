#!/usr/bin/env python3
"""upnp - command line interface for fake-igd (a fake UPnP IGD that logs port mapping requests)."""
import argparse
import collections
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from xml.etree import ElementTree as ET

VERSION = "1.9.2"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
APP = "fake-igd"
DEFAULT_CONFIG = "/etc/fake-igd/config.json"
SERVICE = "fake-igd"

DEFAULTS = {
    "mode": "active",
    "mapping_response": "accept",
    "igd_version": 1,
    "http_port": 5000,
    "external_ip": "auto",
    "interfaces": [],
    "exclude_interfaces": ["lo"],
    "allowed_clients": [],
    "ntfy_url": "",
    "ntfy_token": "",
    "ntfy_user": "",
    "ntfy_password": "",
    "ntfy_priority": 3,
    "ntfy_tags": "video_game",
    "ntfy_ca_file": "",
    "notify_on_renew": False,
    "notify_other_router": True,
    "ntfy_events": {},
    "ntfy_quiet_from": "",
    "ntfy_quiet_to": "",
    "ntfy_quiet_priority": 4,
    "ntfy_quiet_summary": True,
    "ntfy_rate_per_hour": 30,
    "log_level": "INFO",
    "log_file": "/var/log/fake-igd/fake-igd.log",
    "request_log": "/var/log/fake-igd/requests.jsonl",
    "state_dir": "/var/lib/fake-igd",
    "interface_rescan_seconds": 60,
    "notify_interval_seconds": 300,
    "site_name": "",
    "api_port": 9862,
    "session_idle_minutes": 120,
    "web_allow": ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"],
    "firewall": False,
    "firewall_ssh": True,
    "firewall_icmp": True,
    "upgrade_url": "https://github.com/falco81/fake-idg/tree/main/release",
    "upgrade_check": True,
}
KEY_HELP = {
    "mode": "active = answer like a UPnP router, passive = only listen and log",
    "mapping_response": "accept = confirm AddPortMapping (nothing is opened), reject = refuse with error 501",
    "igd_version": "1: InternetGatewayDevice:1 (what fake-igd always was); 2: InternetGatewayDevice:2 with WANIPConnection:2, as miniupnpd built with IGD2 - a device that searches only for :2 is answered only then (the Clients tab shows what it searched for)",
    "http_port": "TCP port for the device description and SOAP",
    "external_ip": "public IP reported to clients, 'auto' = detect automatically",
    "interfaces": "interfaces to listen on, empty = all",
    "exclude_interfaces": "excluded interfaces (e.g. WAN)",
    "allowed_clients": "who to answer (IPs or subnets), empty = everyone",
    "ntfy_url": "ntfy topic URL: https://ntfy.sh/topic or your private server https://ntfy.example.com/topic; empty = no notifications",
    "ntfy_token": "access token of a private ntfy server (tk_...), sent as Authorization: Bearer; kept hidden",
    "ntfy_user": "user of a private ntfy server (Basic auth) - instead of a token",
    "ntfy_password": "password of ntfy_user; kept hidden",
    "ntfy_priority": "priority of the notifications: 1 min, 2 low, 3 default, 4 high, 5 max",
    "ntfy_tags": "comma-separated tags / emoji names shown with the notification (e.g. video_game)",
    "ntfy_ca_file": "CA certificate (PEM) of a private ntfy server with its own certificate authority",
    "notify_on_renew": "notify on mapping renewals too",
    "notify_other_router": "notify when another UPnP router announces itself on the network",
    "ntfy_events": "what is sent: each kind of event on or off, with a priority (0: as ntfy_priority) and tags of its own - JSON {kind: {on, priority, tags}} (upnp notify list|on|off KIND; Settings → Notifications (ntfy) → What is sent)",
    "ntfy_quiet_from": "quiet hours from HH:MM (this machine's clock); empty = none",
    "ntfy_quiet_to": "quiet hours until HH:MM",
    "ntfy_quiet_priority": "in the quiet hours only this priority and above is sent (1-5)",
    "ntfy_quiet_summary": "what the quiet hours held back is sent as one summary when they end (off: dropped)",
    "ntfy_rate_per_hour": "at most this many of one kind an hour, then one \"N more\" summary (0 = no limit)",
    "log_level": "INFO or DEBUG",
    "log_file": "main log",
    "request_log": "request log (JSON lines)",
    "state_dir": "state directory (mappings.json)",
    "interface_rescan_seconds": "how often to check for interface changes",
    "notify_interval_seconds": "SSDP announcement interval in active mode",
    "site_name": "what the web pages call this installation (empty = the host name)",
    "api_port": "TCP port of the API the web pages ask, on 127.0.0.1 only (fake-igd-api.service)",
    "session_idle_minutes": "a sign-in to the web pages ends after this many minutes without a request",
    "web_allow": "who may reach the web pages: addresses or networks (nginx allow, and the firewall's 80/443); empty = everybody",
    "firewall": "iptables: fake-igd's own chain FAKE-IGD-IN, jumped to first from INPUT, lets in what fake-igd needs (as otp's OTP-IN)",
    "firewall_ssh": "the chain lets SSH (tcp 22) in from anywhere - keep a rule of your own if you switch it off",
    "firewall_icmp": "the chain lets ping (ICMP) in",
    "upgrade_url": "Where new versions are looked for: a GitHub folder, a web page with links, or one package's address (https)",
    "upgrade_check": "Look for a new version every day - a newer one is offered under Settings → Upgrades, never put in by itself (upnp upgrade check asks at any time)",
}
ALLOWED_VALUES = {"mode": ("active", "passive"), "mapping_response": ("accept", "reject"),
                  "log_level": ("DEBUG", "INFO", "WARNING", "ERROR")}
NUMBER_RANGES = {"ntfy_quiet_priority": (1, 5), "ntfy_rate_per_hour": (0, 1000), "igd_version": (1, 2), "api_port": (1024, 65535), "session_idle_minutes": (5, 1440), "http_port": (1, 65535), "ntfy_priority": (1, 5), "interface_rescan_seconds": (10, 3600),
                 "notify_interval_seconds": (30, 86400)}
SECRET_KEYS = ("ntfy_token", "ntfy_password")
SETTING_GROUPS = [
    ("How it answers", ["mode", "mapping_response", "igd_version", "allowed_clients", "external_ip"]),
    ("Network", ["http_port", "interfaces", "exclude_interfaces", "interface_rescan_seconds",
                 "notify_interval_seconds"]),
    ("Notifications (ntfy)", ["ntfy_url", "ntfy_token", "ntfy_user", "ntfy_password", "ntfy_priority",
                              "ntfy_tags", "ntfy_ca_file", "ntfy_quiet_from", "ntfy_quiet_to", "ntfy_quiet_priority",
                              "ntfy_quiet_summary", "ntfy_rate_per_hour"]),
    ("Logs and state", ["log_level", "log_file", "request_log", "state_dir"]),
    ("About", ["site_name", "api_port"]),
    ("Web pages and firewall", ["web_allow",
                                "firewall", "firewall_ssh", "firewall_icmp"]),
    ("Upgrades", ["upgrade_url", "upgrade_check"]),
]
# What the fake-igd service itself uses: a change of anything else does not restart it (1.4.0).
SERVICE_KEYS = ("mode", "mapping_response", "igd_version", "http_port", "external_ip", "interfaces", "exclude_interfaces",
                "allowed_clients", "ntfy_url", "ntfy_token", "ntfy_user", "ntfy_password", "ntfy_priority",
                "ntfy_tags", "ntfy_ca_file", "notify_on_renew", "notify_other_router", "ntfy_events",
                "ntfy_quiet_from", "ntfy_quiet_to", "ntfy_quiet_priority", "ntfy_quiet_summary", "ntfy_rate_per_hour",
                "log_level", "log_file",
                "request_log", "state_dir", "interface_rescan_seconds", "notify_interval_seconds")
# What root has to put in place again when it changes: nginx's allow list, the firewall's chain.
ROOT_KEYS = ("web_allow", "firewall", "firewall_ssh", "firewall_icmp", "http_port", "interfaces",
             "exclude_interfaces", "api_port")


def shown_value(key, v):
    """A value for the screen; a secret never."""
    if key in SECRET_KEYS:
        return "(set, hidden)" if v else ""
    if isinstance(v, bool):
        return "on" if v else "off"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)
    return "" if v is None else str(v)


CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def check_value(key, raw):
    """(value, None) or (None, error) - the same checks `config set` makes, without leaving."""
    default = DEFAULTS[key]
    if isinstance(default, dict):           # ntfy_events (1.8.2): a JSON object, every kind checked
        import igd_ntfy
        try:
            return igd_ntfy.events_checked(raw if isinstance(raw, dict) else str(raw or "{}")), None
        except ValueError as e:
            return None, str(e)
    raw = str(raw)
    if isinstance(default, bool):
        if raw.lower() in ("1", "true", "yes", "on"):
            return True, None
        if raw.lower() in ("0", "false", "no", "off"):
            return False, None
        return None, "%s expects on/off" % key
    if isinstance(default, int):
        try:
            v = int(raw)
        except ValueError:
            return None, "%s expects a whole number" % key
        lo, hi = NUMBER_RANGES.get(key, (None, None))
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            return None, "%s - a whole number from %s to %s" % (key, lo, hi)
        return v, None
    if isinstance(default, list):
        if raw.strip().startswith("["):
            try:
                v = json.loads(raw)
            except ValueError:
                v = None
            if not isinstance(v, list):
                return None, "%s: invalid JSON list" % key
            v = [str(x).strip() for x in v if str(x).strip()]       # and checked as the comma-separated form
        else:
            v = [x.strip() for x in raw.split(",") if x.strip()]
        if any(CONTROL_RE.search(x) for x in v):
            return None, "%s: no control characters" % key
        if key in ("interfaces", "exclude_interfaces"):
            bad = [x for x in v if not re.match(r"^[A-Za-z0-9_.:@-]{1,15}\Z", x)]
            if bad:
                return None, "%s: %r is not the name of an interface" % (key, bad[0])
        if key in ("allowed_clients", "web_allow"):
            import ipaddress
            for x in v:
                try:
                    ipaddress.ip_network(x, strict=False)
                except ValueError:
                    return None, "%s: %r is not an IP address or subnet" % (key, x)
        return v, None
    v = raw.strip()
    # Nothing that would break a line of the log, a header or a page (1.7.5): "a\x00b" was taken.
    if CONTROL_RE.search(v):
        return None, "%s: no control characters (a new line, a tab, NUL ...)" % key
    if key in ALLOWED_VALUES:
        v2 = v.upper() if key == "log_level" else v.lower()
        if v2 not in ALLOWED_VALUES[key]:
            return None, "%s must be one of: %s" % (key, ", ".join(ALLOWED_VALUES[key]))
        return v2, None
    if key == "ntfy_url" and v and not re.match(r"^https?://[^/\s]+/[^\s/][^\s]*$", v):
        return None, "ntfy_url must be http(s)://server/topic, e.g. https://ntfy.example.com/ps5"
    if key in ("ntfy_quiet_from", "ntfy_quiet_to") and v and not re.match(r"^([01]\d|2[0-3]):[0-5]\d\Z", v):
        return None, "%s: HH:MM (22:00), or empty" % key
    if key == "ntfy_ca_file" and v and not os.path.isfile(v):
        return None, "ntfy_ca_file: %s is not a file" % v
    if key == "upgrade_url" and v and not v.startswith("https://"):
        return None, "upgrade_url: an address starting https://"
    if key == "site_name" and len(v) > 60:
        return None, "site_name: 60 characters at most"
    if key == "external_ip" and v and v != "auto":
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            return None, "external_ip must be 'auto' or an IP address"
    return v, None

# ================================================================ colours (colorama)
class Palette(object):
    """The console's colours - as otp's Palette: colorama when it is there, the same
    escape sequences by hand when it is not, nothing when colour is off."""

    def __init__(self, on):
        self.on = bool(on)
        try:
            from colorama import Fore, Style
        except ImportError:
            class Fore(object):
                RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; MAGENTA = "\033[35m"
                CYAN = "\033[36m"; WHITE = "\033[37m"

            class Style(object):
                BRIGHT = "\033[1m"; DIM = "\033[2m"; RESET_ALL = "\033[0m"

        def code(*parts):
            return "".join(parts) if self.on else ""
        self.c_ok = code(Fore.GREEN)
        self.c_warn = code(Fore.YELLOW)
        self.c_bad = code(Style.BRIGHT, Fore.RED)
        self.c_info = code(Fore.CYAN)
        self.c_head = code(Style.BRIGHT, Fore.CYAN)
        self.c_addr = code(Fore.MAGENTA)
        self.c_hi = code(Style.BRIGHT)
        self.c_dim = code(Style.DIM)
        self.off = code(Style.RESET_ALL)

    def paint(self, text, colour):
        if not self.on or not colour:
            return str(text)
        return "%s%s%s" % (colour, text, self.off)

    def good(self, t):
        return self.paint(t, self.c_ok)

    def bad(self, t):
        return self.paint(t, self.c_bad)

    def warn(self, t):
        return self.paint(t, self.c_warn)

    def info(self, t):
        return self.paint(t, self.c_info)

    def dim(self, t):
        return self.paint(t, self.c_dim)

    def head(self, t):
        return self.paint(t, self.c_head)

    def bold(self, t):
        return self.paint(t, self.c_hi)

    def addr(self, t):
        return self.paint(t, self.c_addr)

    def bad_line(self, t):
        return (self.bad("✘ ") if self.on else "[fail] ") + str(t)


PAL = Palette(False)
LOG_TONES = {"error": "bad", "crit": "bad", "warn": "warn", "info": "", "debug": "dim",
             "ERROR": "bad", "CRITICAL": "bad", "WARNING": "warn", "INFO": "", "DEBUG": "dim"}


def log_text(ln, p=None):
    """One line of the log coloured as otp colours its own: the time dim, the level by how
    bad, what it is about in cyan, addresses in magenta, accepted green and rejected red,
    a whole warning yellow and a whole error red."""
    p = p or PAL
    ln = ln.rstrip("\n")
    m = re.match(r"^(\S+ \S+) (\w+)(\s+)(.*)$", ln)
    if not m or not p.on:
        return ln
    lvl, rest = m.group(2), m.group(4)
    tone = LOG_TONES.get(lvl, "")
    paint = {"bad": p.bad, "warn": p.warn, "dim": p.dim}.get(tone)
    what = re.match(r"^([a-z][a-z -]{1,30}): (.*)$", rest)
    head, body = (what.group(1) + ":", what.group(2)) if what else ("", rest)

    def words(t):
        t = re.sub(r"(\[?[0-9a-fA-F:]*\d{1,3}(?:\.\d{1,3}){3}\]?(?::\d+)?|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b)",
                   lambda x: p.addr(x.group(1)) + (p.c_warn if tone == "warn" else p.c_bad if tone == "bad" else ""), t)
        t = re.sub(r"\b(accept(?:ed)?|signed in|in place|done|ok)\b",
                   lambda x: p.good(x.group(1)) + (p.c_warn if tone == "warn" else ""), t)
        t = re.sub(r"\b(reject(?:ed)?|refused|failed|wrong|locked out|not answering)\b",
                   lambda x: p.bad(x.group(1)) + (p.c_warn if tone == "warn" else ""), t)
        return t
    body = words(body)
    if paint is not None and tone != "dim":
        body = paint(body)
    elif tone == "dim":
        body = p.dim(body)
    lv = (paint or p.info)(lvl.ljust(5))
    return "%s %s %s%s" % (p.dim(m.group(1)), lv, p.info(head) + (" " if head else ""), body)


class C:
    red = green = yellow = blue = magenta = cyan = white = dim = bold = reset = ""


def setup_colors(mode):
    enabled = mode == "always" or (mode == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    if not enabled:
        return False
    try:
        from colorama import Fore, Style
        if os.name == "nt":
            import colorama
            colorama.just_fix_windows_console()
        vals = dict(red=Fore.RED, green=Fore.GREEN, yellow=Fore.YELLOW, blue=Fore.BLUE, magenta=Fore.MAGENTA,
                    cyan=Fore.CYAN, white=Fore.WHITE, dim=Style.DIM, bold=Style.BRIGHT, reset=Style.RESET_ALL)
    except ImportError:  # without colorama, fall back to raw ANSI sequences
        vals = dict(red="\x1b[31m", green="\x1b[32m", yellow="\x1b[33m", blue="\x1b[34m", magenta="\x1b[35m",
                    cyan="\x1b[36m", white="\x1b[37m", dim="\x1b[2m", bold="\x1b[1m", reset="\x1b[0m")
    for k, v in vals.items():
        setattr(C, k, v)
    return True


def col(text, *styles):
    s = "".join(styles)
    return "%s%s%s" % (s, text, C.reset) if s else str(text)


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def vlen(s):
    return len(ANSI_RE.sub("", str(s)))


def table(headers, rows, empty="(nothing to show)"):
    if not rows:
        print(col(empty, C.dim))
        return
    widths = [vlen(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], vlen(c))
    widths[-1] = 0  # last column is not padded

    def fmt(cells):
        return "  ".join(str(c) + " " * (widths[i] - vlen(c)) if i < len(cells) - 1 else str(c)
                         for i, c in enumerate(cells)).rstrip()

    print(col(fmt(headers), C.bold))
    for r in rows:
        print(fmt(r))


def info(msg):
    print(col("•", C.cyan), msg, flush=True)


def ok(msg):
    print(col("✔", C.green, C.bold), msg, flush=True)


def warn(msg):
    sys.stdout.flush()
    print(col("!", C.yellow, C.bold), col(msg, C.yellow), file=sys.stderr, flush=True)


def fail(msg, code=1):
    print(col("✘ " + msg, C.red, C.bold), file=sys.stderr)
    sys.exit(code)


def hint_perm(path):
    fail("Permission denied reading/writing %s.\n  Use sudo, or add yourself to the %s group:\n"
         "    sudo usermod -aG %s $USER   (then log out and back in)" % (path, APP, APP))


# ================================================================ konfigurace a data
def load_config(path, strict=False):
    cfg = dict(DEFAULTS)
    try:
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        if strict:
            fail("Config %s does not exist." % path)
    except PermissionError:
        hint_perm(path)
    except json.JSONDecodeError as e:
        fail("JSON error in %s: %s" % (path, e))
    return cfg


def parse_time(s):
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    return dt.astimezone() if dt.tzinfo is None else dt


def parse_since(s):
    if not s:
        return None
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", s)
    if m:
        n, u = int(m.group(1)), m.group(2)
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[u]
        return datetime.now().astimezone() - timedelta(**{unit: n})
    dt = parse_time(s.replace(" ", "T", 1) if re.match(r"\d{4}-\d\d-\d\d \d", s) else s)
    if not dt:
        fail("Invalid --since time: %r (examples: 30m, 2h, 7d, 2026-11-16, '2026-11-16 18:00')" % s)
    return dt


def read_events(cfg, since=None, client=None, action=None):
    path = cfg["request_log"]
    try:
        f = open(path, encoding="utf-8")
    except FileNotFoundError:
        return []
    except PermissionError:
        hint_perm(path)
    out = []
    with f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            e["_t"] = parse_time(e.get("time"))
            if since and (not e["_t"] or e["_t"] < since):
                continue
            if client and e.get("client") != client and e.get("internal_client") != client:
                continue
            if action and e.get("action", "").lower() != action.lower():
                continue
            out.append(e)
    return out


def aggregate_ports(events, proto=None, min_count=1, port=None):
    ports = {}
    for e in events:
        if port and int(e.get("external_port") or 0) != int(port):
            continue
        if e.get("action") != "AddPortMapping" or e.get("description") == "upnp-cli-test":
            continue
        if proto and e.get("protocol", "").upper() != proto.upper():
            continue
        k = (e.get("internal_client", e.get("client", "")), e["protocol"], int(e["external_port"]))
        p = ports.setdefault(k, {"count": 0, "first": e.get("time", ""), "last": e.get("time", ""),
                                 "desc": set(), "results": collections.Counter(), "internal_port": set(),
                                 "requested_by": set()})
        p["count"] += 1
        p["last"] = e.get("time", p["last"])
        p["results"][e.get("result", "ok")] += 1
        p["internal_port"].add(e.get("internal_port"))
        p["requested_by"].add(e.get("client"))
        if e.get("description"):
            p["desc"].add(e["description"])
    return {k: v for k, v in ports.items() if v["count"] >= min_count}


LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:,\d+)?\s+(\w+)\s+(.*)$")


def read_log_lines(cfg, n=None):
    path = cfg["log_file"]
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            if n:
                return list(collections.deque(f, maxlen=n))
            return f.readlines()
    except FileNotFoundError:
        return []
    except PermissionError:
        hint_perm(path)


# ---- PTR names (reverse DNS) of the addresses shown ---------------------------------
NO_DNS = False
_PTR = {}


def ptr_names(ips, timeout=1.5):
    """{ip: PTR name or ''} - looked up side by side, never longer than `timeout` in all;
    an address that does not answer in time is shown without a name."""
    import threading
    ips = [ip for ip in dict.fromkeys(ips) if ip]
    todo = [ip for ip in ips if ip not in _PTR]
    if todo and not NO_DNS:
        got = {}

        def one(ip):
            try:
                got[ip] = socket.gethostbyaddr(ip)[0].rstrip(".")
            except (OSError, UnicodeError):
                got[ip] = ""
        threads = [threading.Thread(target=one, args=(ip,), daemon=True) for ip in todo[:256]]
        for t in threads:
            t.start()
        end = time.time() + timeout
        for t in threads:
            t.join(max(0, end - time.time()))
        for ip in todo:
            _PTR[ip] = got.get(ip, "")
    return {ip: _PTR.get(ip, "") for ip in ips}


def ptr(ip):
    return ptr_names([ip]).get(ip, "") if ip else ""


def fmt_time(s):
    t = parse_time(s) if isinstance(s, str) else s
    return t.strftime("%Y-%m-%d %H:%M:%S") if t else (s or "-")


def ago(t):
    if not t:
        return "-"
    sec = int((datetime.now().astimezone() - t).total_seconds())
    if sec < 60:
        return "%ds ago" % sec
    if sec < 3600:
        return "%dm ago" % (sec // 60)
    if sec < 86400:
        return "%dh %dm ago" % (sec // 3600, sec % 3600 // 60)
    return "%dd ago" % (sec // 86400)


def require_root(what):
    if os.geteuid() != 0:
        fail("%s requires root. Run: sudo upnp %s" % (what, " ".join(sys.argv[1:])))


def systemctl(*args, quiet=False):
    cmd = ["systemctl"] + list(args)
    if os.geteuid() != 0 and args and args[0] not in ("show", "status", "is-active", "is-enabled"):
        if shutil.which("sudo"):
            cmd = ["sudo"] + cmd
    try:
        return subprocess.run(cmd, check=False, text=True,
                              stdout=subprocess.PIPE if quiet else None, stderr=subprocess.PIPE if quiet else None)
    except FileNotFoundError:
        fail("systemctl is not available.")


def service_info():
    r = systemctl("show", SERVICE, "-p", "ActiveState,SubState,MainPID,ActiveEnterTimestamp,UnitFileState,NRestarts",
                  quiet=True)
    d = {}
    for line in (r.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v
    return d


def write_config(path, cfg):
    data = {k: cfg[k] for k in DEFAULTS if k in cfg}
    for k, v in cfg.items():
        if k not in data and not k.startswith("_"):
            data[k] = v
    st = os.stat(path) if os.path.exists(path) else None
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        if st:
            os.chmod(tmp, st.st_mode & 0o777)
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    except PermissionError:
        os.unlink(tmp)
        hint_perm(path)


def coerce_value(key, raw):
    if raw == "@env":                              # a secret passed by the environment, not argv
        raw = os.environ.get("UPNP_VALUE", "")
    elif raw == "-" and key in SECRET_KEYS:        # asked for, not echoed
        import getpass
        raw = getpass.getpass("%s: " % key)
    v, err = check_value(key, raw)
    if err:
        fail(err)
    return v


def restart_service(no_restart):
    if no_restart:
        info("Service was not restarted (--no-restart). Apply the change with: sudo systemctl restart %s" % SERVICE)
        return
    r = systemctl("restart", SERVICE)
    if r.returncode == 0:
        time.sleep(1)
        st = service_info().get("ActiveState", "?")
        (ok if st == "active" else warn)("Service restarted, state: %s" % st)
    else:
        warn("Restart failed, try: sudo systemctl restart %s" % SERVICE)


# ================================================================ log colouring
EVENT_STYLES = [
    ("OTHER UPnP ROUTER", lambda: C.red + C.bold),
    ("NEW PORT", lambda: C.green + C.bold),
    ("RENEW", lambda: C.cyan),
    ("REJECTED", lambda: C.yellow + C.bold),
    ("CONFLICT", lambda: C.red + C.bold),
    ("DELETE", lambda: C.magenta),
    ("EXPIRED", lambda: C.dim),
    ("SEARCH", lambda: C.blue),
    ("DESC", lambda: C.blue),
    ("ANNOUNCE", lambda: C.cyan),
    ("SOAP", lambda: C.white),
    ("=====", lambda: C.bold),
    ("Listening on", lambda: C.green),
]
EVENT_WORDS = ("NEW PORT", "RENEW", "REJECTED", "CONFLICT", "DELETE", "EXPIRED", "SEARCH", "DESC", "ANNOUNCE",
               "OTHER UPnP ROUTER", "=====")
LEVEL_STYLE = {"DEBUG": lambda: C.dim, "INFO": lambda: C.green, "WARNING": lambda: C.yellow + C.bold,
               "ERROR": lambda: C.red + C.bold, "CRITICAL": lambda: C.red + C.bold}
LEVEL_NUM = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50,
             "debug": 10, "info": 20, "warn": 30, "error": 40, "crit": 50}


def color_log_line(line):
    return log_text(line.rstrip("\n"), PAL)


EVENT_TOPICS = ("port:", "ssdp:", "http:", "net:", "service:", "notify:", "config:")


def is_event(lvl, msg):
    """What `log --events` keeps: everything but the SOAP details and debug lines."""
    if lvl.lower() in ("warn", "warning", "error", "crit", "critical"):
        return True
    if lvl.lower() == "debug":
        return False
    return msg.startswith(EVENT_TOPICS) or any(w in msg for w in EVENT_WORDS)


def log_line_match(line, args, since):
    m = LOG_RE.match(line.rstrip("\n"))
    if not m:
        return not (args.events or args.level or since)
    ts, lvl, msg = m.groups()
    if since:
        t = parse_time(ts.replace(" ", "T"))
        if t and t < since:
            return False
    if args.level and LEVEL_NUM.get(lvl, 0) < LEVEL_NUM[args.level]:
        return False
    if args.events and not is_event(lvl, msg):
        return False
    if args.grep and not re.search(args.grep, line, re.I):
        return False
    return True


# ================================================================ commands
def status_data(cfg):
    """Everything `upnp status` shows, as data (also for the console's bar)."""
    s = service_info()
    lines = read_log_lines(cfg)
    start_idx = max((i for i, l in enumerate(lines)
                     if ("service: fake-igd" in l or "===== fake-igd" in l) and "starting" in l), default=0)
    ifaces = collections.OrderedDict()
    ext_ip = None
    for l in lines[start_idx:]:
        m = re.search(r"(?:net: listening on|Listening on interface) (\S+) \(([\d.]+)\)", l)
        if m:
            ifaces[m.group(1)] = m.group(2)
        m = re.search(r"(?:net: (\S+) \(([\d.]+)\) is gone|Interface (\S+) \(([\d.]+)\) removed)", l)
        if m:
            ifaces.pop(m.group(1) or m.group(3), None)
        m = re.search(r"(?:net: the public IP is|Detected public IP:) (\S+)", l)
        if m:
            ext_ip = m.group(1)
    other_igd = []
    for l in lines:
        m = re.search(r"OTHER UPnP ROUTER on the network: (\S+)", l) or \
            (re.search(r"ANNOUNCE\s+(\S+)", l) if "OTHER UPnP ROUTER" in l else None)
        if m and m.group(1) not in other_igd:
            other_igd.append(m.group(1))
    ev = read_events(cfg)
    ports = aggregate_ports(ev)
    try:
        with open(os.path.join(cfg["state_dir"], "mappings.json"), encoding="utf-8") as f:
            nmap = len(json.load(f))
    except (OSError, ValueError):
        nmap = 0
    last = max((e["_t"] for e in ev if e.get("_t")), default=None)
    ntfy = "off"
    if cfg.get("ntfy_url"):
        ntfy = "%s (%s)" % (cfg["ntfy_url"], "token" if cfg.get("ntfy_token") else
                            ("user " + cfg["ntfy_user"]) if cfg.get("ntfy_user") else "no auth")
    mdns = None
    try:
        import upnp_mdns
        if os.path.exists(upnp_mdns.CONF):
            vals, _l = upnp_mdns.read_conf()
            sd = upnp_mdns.systemd_state()
            mdns = {"state": sd.get("ActiveState", "unknown"),
                    "reflector": upnp_mdns.effective(vals).get("enable-reflector") == "yes"}
    except Exception:  # noqa: BLE001
        mdns = None
    return {
        "version": VERSION,
        "mdns": mdns,
        "service": {"state": s.get("ActiveState", "unknown"), "sub": s.get("SubState", "?"),
                    "pid": s.get("MainPID", "0"), "since": s.get("ActiveEnterTimestamp", ""),
                    "boot": s.get("UnitFileState", "-"), "restarts": s.get("NRestarts", "-")},
        "mode": cfg["mode"], "mapping_response": cfg["mapping_response"], "http_port": cfg["http_port"],
        "external_ip": cfg["external_ip"], "public_ip": ext_ip, "allowed_clients": cfg["allowed_clients"],
        "notifications": ntfy, "interfaces": ifaces, "other_igd": other_igd,
        "stats": {"requests": len(ev), "add": len([e for e in ev if e.get("action") == "AddPortMapping"]),
                  "ports": len(ports), "clients": len({e.get("client") for e in ev}), "mappings": nmap,
                  "last": last.isoformat() if last else None,
                  "refused_24h": len([e for e in ev if e.get("action") == "AddPortMapping" and e.get("_t")
                                      and e["_t"].timestamp() > time.time() - 86400
                                      and str(e.get("result") or "ok") != "ok"])},
    }


def cmd_status(args, cfg):
    d = status_data(cfg)
    if getattr(args, "json", False):
        print(json.dumps(d, ensure_ascii=False, indent=2))
        return
    sv = d["service"]
    state = sv["state"]
    st_col = C.green if state == "active" else (C.yellow if state in ("activating", "reloading") else C.red)
    print(col("fake-igd", C.bold), col("v" + VERSION, C.dim))
    print()
    rows = [
        ["Service", col("%s (%s)" % (state, sv["sub"]), st_col, C.bold)],
        ["PID", sv["pid"] if sv["pid"] != "0" else "-"],
        ["Running since", sv["since"] or "-"],
        ["Start on boot", sv["boot"]],
        ["Restarts", sv["restarts"]],
        ["Mode", col(d["mode"], C.green if d["mode"] == "active" else C.yellow, C.bold)],
        ["AddPortMapping", col(d["mapping_response"], C.green if d["mapping_response"] == "accept" else C.yellow, C.bold)],
        ["HTTP port", d["http_port"]],
        ["Public IP", d["external_ip"]],
        ["Allowed clients", ", ".join(d["allowed_clients"]) or col("everyone", C.yellow)],
        ["Notifications", col(d["notifications"], C.green) if d["notifications"] != "off" else col("off", C.dim)],
    ]
    for k, v in rows:
        print("  %-18s %s" % (k, v))
    print()
    print(col("Interfaces", C.bold))
    if d["interfaces"]:
        for n, ip in d["interfaces"].items():
            print("  %s %-12s %s  %s" % (col("●", C.green), n, ip, col("http://%s:%s/rootDesc.xml" % (ip, d["http_port"]), C.dim)))
    else:
        print(col("  (no interfaces in the log since the last start)", C.dim))
    if d["public_ip"]:
        print("  detected public IP: %s" % col(d["public_ip"], C.cyan))
    st = d["stats"]
    last = parse_time(st["last"]) if st["last"] else None
    print()
    print(col("Statistics", C.bold))
    print("  %-18s %s" % ("Requests total", st["requests"]))
    print("  %-18s %s" % ("AddPortMapping", st["add"]))
    print("  %-18s %s" % ("Unique ports", col(st["ports"], C.green, C.bold)))
    print("  %-18s %s" % ("Clients", st["clients"]))
    print("  %-18s %s" % ("Active mappings", st["mappings"]))
    print("  %-18s %s" % ("Last event", "%s (%s)" % (fmt_time(last), ago(last)) if last else "-"))
    if d["other_igd"]:
        print()
        warn("Another UPnP router is on the network: %s - disable UPnP on it!" % ", ".join(d["other_igd"]))
    if state != "active":
        print()
        warn("Service is not running. Start it: sudo upnp start   (log: upnp log -n 30)")


def cmd_ports(args, cfg):
    ev = read_events(cfg, parse_since(args.since), args.client)
    ports = aggregate_ports(ev, args.proto, args.min_count, getattr(args, "port", None))
    names = ptr_names([k[0] for k in ports])
    if args.json:
        out = [{"client": k[0], "name": names.get(k[0], ""), "protocol": k[1], "port": k[2], "count": v["count"], "first": v["first"],
                "last": v["last"], "descriptions": sorted(v["desc"]), "results": dict(v["results"]),
                "internal_ports": sorted(p for p in v["internal_port"] if p)} for k, v in sorted(ports.items())]
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return
    rows = []
    for (cl, proto, port), v in sorted(ports.items()):
        res = ", ".join("%s×%d" % (r, n) for r, n in v["results"].items())
        res_c = C.green if set(v["results"]) == {"ok"} else C.yellow
        iports = sorted(p for p in v["internal_port"] if p and p != port)
        rows.append([col(proto, C.cyan if proto == "UDP" else C.magenta), col(port, C.bold), cl,
                     col(names.get(cl, ""), C.cyan),
                     ("→ %s" % ",".join(map(str, iports))) if iports else "", v["count"],
                     fmt_time(v["first"]), fmt_time(v["last"]), col(res, res_c), ", ".join(sorted(v["desc"]))])
    table(["PROTO", "PORT", "CLIENT", "NAME", "INT.PORT", "COUNT", "FIRST", "LAST", "RESULT", "DESCRIPTION"], rows,
          "No port requests yet. Run a connection test / game / party chat on the PS5.")
    if rows:
        print()
        info("%d port(s). Router rules: %s" % (len(rows), col("upnp dnat", C.bold)))


def cmd_requests(args, cfg):
    ev = read_events(cfg, parse_since(args.since), args.client, args.action)
    ev = ev[-args.n:] if args.n else ev
    names = ptr_names([e.get("client") for e in ev])
    if args.json:
        for e in ev:
            e.pop("_t", None)
            e["name"] = names.get(e.get("client"), "")
            print(json.dumps(e, ensure_ascii=False))
        return
    rows = []
    for e in ev:
        a = e.get("action", "")
        res = e.get("result", "")
        if e.get("renew"):
            res = "renew"
        rc = {"ok": C.green, "renew": C.cyan, "rejected": C.yellow, "conflict": C.red}.get(res, "")
        ac = {"AddPortMapping": C.green, "DeletePortMapping": C.magenta, "Expired": C.dim}.get(a, "")
        target = ""
        if e.get("internal_client"):
            target = "%s:%s" % (e["internal_client"], e.get("internal_port", "")) if e.get("internal_port") else e["internal_client"]
        lease = e.get("lease")
        rows.append([fmt_time(e.get("time")), e.get("client", "-"), col(names.get(e.get("client"), ""), C.cyan),
                     col(a, ac), e.get("protocol", ""),
                     col(e.get("external_port", ""), C.bold), target,
                     ("%ss" % lease) if lease else ("∞" if lease == 0 else ""), col(res, rc), e.get("description", "")])
    table(["TIME", "CLIENT", "NAME", "ACTION", "PROTO", "PORT", "TARGET", "LEASE", "RESULT", "DESCRIPTION"], rows,
          "No requests (for the selected filter).")


def cmd_mappings(args, cfg):
    path = os.path.join(cfg["state_dir"], "mappings.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = []
    except PermissionError:
        hint_perm(path)
    except ValueError:
        fail("Corrupted %s" % path)
    names = ptr_names([m.get("internal_client") for m in data])
    if args.json:
        for m in data:
            m["name"] = names.get(m.get("internal_client"), "")
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    rows = []
    now = time.time()
    for m in sorted(data, key=lambda x: (x.get("internal_client", ""), x.get("protocol", ""), x.get("external_port", 0))):
        exp = m.get("expires_at")
        left = ("%ds" % max(0, int(exp - now))) if exp else "∞"
        if exp and exp < now:
            left = col("expired", C.dim)
        rows.append([col(m.get("protocol"), C.cyan), col(m.get("external_port"), C.bold),
                     "%s:%s" % (m.get("internal_client"), m.get("internal_port")),
                     col(names.get(m.get("internal_client"), ""), C.cyan), left,
                     fmt_time(m.get("added_at")), m.get("requested_by", ""), m.get("description", "")])
    table(["PROTO", "PORT", "TARGET", "NAME", "REMAINING", "ADDED", "REQUESTER", "DESCRIPTION"], rows,
          "No active mappings (they are not stored in reject/passive mode).")
    if rows:
        print()
        info("Note: this is only what clients *believe*. Nothing is open on the router.")


def clients_data(cfg, since=None):
    cl = {}
    for e in read_events(cfg, since):
        if not e.get("client"):
            continue                  # the daemon's own rows (a lease run out) - nobody asked
        c = cl.setdefault(e.get("client", "?"), {"req": 0, "ports": set(), "last": None, "ua": "", "search": 0})
        c["req"] += 1
        if e.get("action") == "AddPortMapping" and e.get("description") != "upnp-cli-test":
            c["ports"].add("%s/%s" % (e.get("external_port"), e.get("protocol", "").lower()))
        if e.get("_t") and (not c["last"] or e["_t"] > c["last"]):
            c["last"] = e["_t"]
    for l in read_log_lines(cfg):
        m = LOG_RE.match(l.rstrip("\n"))
        if not m:
            continue
        hm = re.search(r"(?:ssdp: |SEARCH\s+)(\S+) is looking for a UPnP device \(ST=.*?, UA=(.*)\)", m.group(3))
        if not hm:
            continue
        t = parse_time(m.group(1).replace(" ", "T"))
        if since and t and t < since:
            continue
        c = cl.setdefault(hm.group(1), {"req": 0, "ports": set(), "last": None, "ua": "", "search": 0})
        c["search"] += 1
        if hm.group(2) and hm.group(2) != "-":
            c["ua"] = hm.group(2)
        if t and (not c["last"] or t > c["last"]):
            c["last"] = t
    out = []
    names = ptr_names(list(cl))
    for ip, c in sorted(cl.items(), key=lambda x: x[1]["last"] or datetime.min.astimezone(), reverse=True):
        out.append({"client": ip, "name": names.get(ip, ""), "searches": c["search"], "requests": c["req"],
                    "ports": sorted(c["ports"], key=lambda p: int(p.split("/")[0])),
                    "last": c["last"].isoformat() if c["last"] else None, "user_agent": c["ua"]})
    return out


def cmd_clients(args, cfg):
    data = clients_data(cfg, parse_since(args.since))
    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return
    rows = []
    for c in data:
        last = parse_time(c["last"]) if c["last"] else None
        ports = c["ports"]
        rows.append([col(c["client"], C.bold), col(c["name"], C.cyan), c["searches"], c["requests"],
                     col(len(ports), C.green, C.bold) if ports else "0",
                     "%s (%s)" % (fmt_time(last), ago(last)), ", ".join(ports[:12]) + (" …" if len(ports) > 12 else ""),
                     col(c["user_agent"][:60], C.dim)])
    table(["CLIENT", "NAME", "SEARCHES", "REQUESTS", "PORTS", "LAST SEEN", "PORT LIST", "USER-AGENT"], rows,
          "No clients yet.")


def cmd_log(args, cfg):
    since = parse_since(args.since)
    path = cfg["log_file"]
    lines = read_log_lines(cfg)
    shown = [l for l in lines if log_line_match(l, args, since)]
    if args.n:
        shown = shown[-args.n:]
    for l in shown:
        print(color_log_line(l) if not args.raw else l.rstrip("\n"))
    if not args.follow:
        return
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError as e:
        fail("Cannot open %s: %s" % (path, e))
    f.seek(0, os.SEEK_END)
    ino = os.fstat(f.fileno()).st_ino
    try:
        while True:
            line = f.readline()
            if line:
                if log_line_match(line, args, None):
                    print(color_log_line(line) if not args.raw else line.rstrip("\n"), flush=True)
                continue
            time.sleep(0.5)
            try:
                st = os.stat(path)
                if st.st_ino != ino or st.st_size < f.tell():
                    f.close()
                    f = open(path, encoding="utf-8", errors="replace")
                    ino = os.fstat(f.fileno()).st_ino
                    print(col("--- log was rotated ---", C.dim))
            except FileNotFoundError:
                pass
    except KeyboardInterrupt:
        print()


def compress_ranges(ports):
    ports = sorted(set(ports))
    out = []
    for p in ports:
        if out and p == out[-1][1] + 1:
            out[-1][1] = p
        else:
            out.append([p, p])
    return out


def chunk_ranges(ranges, limit=15):
    chunk, used = [], 0
    for a, b in ranges:
        w = 1 if a == b else 2
        if used + w > limit:
            yield chunk
            chunk, used = [], 0
        chunk.append((a, b))
        used += w
    if chunk:
        yield chunk


def cmd_dnat(args, cfg):
    ev = read_events(cfg, parse_since(args.since), args.client)
    ports = aggregate_ports(ev, args.proto, args.min_count, getattr(args, "port", None))
    if not ports:
        fail("No ports to generate rules for (try without filters or wait for requests).", 0 if args.quiet else 1)
    groups = {}
    for (cl, proto, port) in ports:
        groups.setdefault((cl, proto.lower()), []).append(port)
    fmt = args.format
    wan = args.wan or {"iptables": "eth0", "nft": "eth0", "mikrotik": "WAN", "firewalld": "external"}[fmt]
    lines = []
    if not args.quiet:
        lines.append("# fake-igd %s - DNAT rules (%s), generated %s" % (VERSION, fmt, datetime.now().strftime("%Y-%m-%d %H:%M")))
        lines.append("# %d port(s), %d client(s); check the WAN interface/zone: %s" % (len(ports), len({g[0] for g in groups}), wan))
    for (cl, proto), pl in sorted(groups.items()):
        ranges = compress_ranges(pl)
        if not args.quiet:
            lines.append("")
            lines.append("# %s %s: %s" % (cl, proto.upper(), ", ".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in ranges)))
        if fmt == "iptables":
            for ch in chunk_ranges(ranges):
                spec = ",".join(str(a) if a == b else "%d:%d" % (a, b) for a, b in ch)
                lines.append("iptables -t nat -A PREROUTING -i %s -p %s -m multiport --dports %s -j DNAT --to-destination %s"
                             % (wan, proto, spec, cl))
                if not args.no_forward:
                    lines.append("iptables -A FORWARD -d %s -p %s -m multiport --dports %s -m conntrack --ctstate DNAT -j ACCEPT"
                                 % (cl, proto, spec))
        elif fmt == "nft":
            spec = ", ".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in ranges)
            lines.append('nft add rule ip nat prerouting iifname "%s" %s dport { %s } dnat to %s' % (wan, proto, spec, cl))
            if not args.no_forward:
                lines.append('nft add rule inet filter forward ip daddr %s %s dport { %s } ct status dnat accept' % (cl, proto, spec))
        elif fmt == "mikrotik":
            for ch in chunk_ranges(ranges):
                spec = ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in ch)
                lines.append('/ip firewall nat add chain=dstnat in-interface=%s protocol=%s dst-port=%s action=dst-nat '
                             'to-addresses=%s comment="fake-igd %s"' % (wan, proto, spec, cl, cl))
        elif fmt == "firewalld":
            for a, b in ranges:
                spec = str(a) if a == b else "%d-%d" % (a, b)
                lines.append("firewall-cmd --permanent --zone=%s --add-forward-port=port=%s:proto=%s:toaddr=%s"
                             % (wan, spec, proto, cl))
    if fmt == "firewalld" and not args.quiet:
        lines += ["", "firewall-cmd --permanent --zone=%s --add-masquerade" % wan, "firewall-cmd --reload"]
    if fmt == "nft" and not args.quiet:
        lines.insert(2, "# assumes existing tables 'ip nat' (chain prerouting) and 'inet filter' (chain forward)")
    for l in lines:
        print(col(l, C.dim) if l.startswith("#") else l)


def cmd_config(args, cfg):
    path = args.config
    sub = args.config_cmd or "show"
    if sub == "path":
        print(path)
        return
    if sub == "show":
        if args.json:
            print(json.dumps({k: ("(hidden)" if k in SECRET_KEYS and cfg[k] else cfg[k]) for k in cfg},
                             ensure_ascii=False, indent=2))
            return
        print(col(path, C.bold))
        print()
        for k in DEFAULTS:
            v = cfg.get(k)
            changed = v != DEFAULTS[k]
            vs = '"(hidden)"' if (k in SECRET_KEYS and v) else json.dumps(v, ensure_ascii=False)
            print("  %s %s" % (col("%-26s" % k, C.cyan), col(vs, C.bold if changed else "", C.green if changed else "")))
            print("  %-26s %s" % ("", col(KEY_HELP.get(k, ""), C.dim)))
        extra = [k for k in cfg if k not in DEFAULTS]
        if extra:
            warn("Unknown keys: %s" % ", ".join(extra))
        return
    if sub == "get":
        if args.key not in DEFAULTS:
            fail("Unknown key %s. Valid keys: %s" % (args.key, ", ".join(DEFAULTS)))
        v = cfg.get(args.key)
        if args.key in SECRET_KEYS and v:
            v = "(hidden)"
        print(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
        return
    if sub == "validate":
        raw = load_config(path, strict=True)
        errs = []
        for k, v in raw.items():
            if k == "health_allow":
                # Who may ask /healthz - a key of the pages' (Settings → Firewall and access) with no
                # default on purpose: never set, it is web_allow's.
                if not isinstance(v, list):
                    errs.append("health_allow is a list of addresses and networks")
                else:
                    import ipaddress
                    for x in v:
                        try:
                            ipaddress.ip_network(str(x), strict=False)
                        except ValueError:
                            errs.append("health_allow: %r is not an address or a network" % x)
            elif k not in DEFAULTS:
                errs.append("unknown key %s" % k)
            elif k in ALLOWED_VALUES and str(v).lower() not in [x.lower() for x in ALLOWED_VALUES[k]]:
                errs.append("%s=%r (allowed: %s)" % (k, v, ", ".join(ALLOWED_VALUES[k])))
            elif type(DEFAULTS[k]) is not type(v) and not (isinstance(DEFAULTS[k], int) and isinstance(v, int)):
                errs.append("%s has type %s, expected %s" % (k, type(v).__name__, type(DEFAULTS[k]).__name__))
            elif k not in ("ntfy_ca_file",):
                # The same checks as config set and the pages (ranges, addresses, no control characters).
                _v, bad = check_value(k, json.dumps(v) if isinstance(v, list) else
                                      ("on" if v is True else "off" if v is False else v))
                if bad:
                    errs.append(bad)
        if errs:
            for e in errs:
                warn(e)
            sys.exit(1)
        ok("Config %s is valid." % path)
        return
    if sub == "set":
        require_root("Changing the config")
        if args.key not in DEFAULTS:
            fail("Unknown key %s. Valid keys: %s" % (args.key, ", ".join(DEFAULTS)))
        raw = load_config(path, strict=True)
        old = raw.get(args.key)
        raw[args.key] = coerce_value(args.key, args.value)
        write_config(path, raw)
        if args.key in SECRET_KEYS:
            ok("%s: %s" % (args.key, "set (hidden)" if raw[args.key] else "cleared"))
        else:
            ok("%s: %s → %s" % (args.key, json.dumps(old, ensure_ascii=False), json.dumps(raw[args.key], ensure_ascii=False)))
        if args.key == "http_port":
            warn("Don't forget to update the firewall (new port %s/tcp)." % raw[args.key])
        restart_service(args.no_restart)
        return
    if sub == "edit":
        require_root("Editing the config")
        editor = os.environ.get("EDITOR") or shutil.which("nano") or shutil.which("vi") or "vi"
        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        shutil.copyfile(path, tmp)
        while True:
            subprocess.call([editor, tmp])
            try:
                with open(tmp, encoding="utf-8") as f:
                    new = json.load(f)
                break
            except ValueError as e:
                warn("Invalid JSON: %s" % e)
                if input("Edit again? [Y/n] ").strip().lower() in ("n", "no"):
                    os.unlink(tmp)
                    fail("Changes discarded.")
        os.unlink(tmp)
        write_config(path, new)
        ok("Config saved.")
        restart_service(args.no_restart)


def cmd_setting(key):
    def run(args, cfg):
        if not args.value:
            print(cfg[key])
            return
        args.config_cmd, args.key = "set", key
        cmd_config(args, cfg)
    return run


def cmd_service(action):
    def run(args, cfg):
        r = systemctl(action, SERVICE)
        if r.returncode != 0:
            fail("systemctl %s %s failed." % (action, SERVICE))
        if action in ("start", "restart"):
            time.sleep(1.5)
        st = service_info().get("ActiveState", "?")
        ok("%s: %s" % (action, st))
    return run


def ssdp_search(st, timeout, target=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.3)
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: %s\r\nUSER-AGENT: upnp-cli/%s\r\n\r\n" % (st, VERSION)).encode()
    s.sendto(msg, (target or "239.255.255.250", 1900))
    found = {}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, (src, _) = s.recvfrom(4096)
        except socket.timeout:
            continue
        hdr = {}
        for ln in data.decode("utf-8", "ignore").split("\r\n")[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdr[k.strip().upper()] = v.strip()
        found.setdefault((src, hdr.get("LOCATION", "")), hdr)
    s.close()
    return found


def soap_call(url, service, action, args=None, timeout=5):
    body = "".join("<%s>%s</%s>" % (k, v, k) for k, v in (args or {}).items())
    env = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
           's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="%s">%s</u:%s>'
           "</s:Body></s:Envelope>" % (action, service, body, action))
    req = urllib.request.Request(url, data=env.encode(), method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (service, action)})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def xml_find(text, name):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] == name:
            return (el.text or "").strip()
    return None


def local_interfaces():
    """{name: ip} of active IPv4 interfaces (except loopback), read directly from the kernel."""
    import fcntl
    import struct
    out = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _, name in socket.if_nameindex():
            try:
                req = struct.pack("256s", name[:15].encode())
                flags = struct.unpack("H", fcntl.ioctl(s.fileno(), 0x8913, req)[16:18])[0]   # SIOCGIFFLAGS
                if not flags & 0x1 or flags & 0x8:                                          # !IFF_UP or IFF_LOOPBACK
                    continue
                out[name] = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])  # SIOCGIFADDR
            except OSError:
                continue
    finally:
        s.close()
    return out


def detect_firewall():
    """Return the name of the active host firewall service, or None."""
    for svc in ("firewalld", "nftables", "iptables"):
        r = systemctl("is-active", svc, quiet=True)
        if (r.stdout or "").strip() == "active":
            return svc
    if os.geteuid() == 0 and shutil.which("iptables"):   # rules loaded without a service
        r = subprocess.run(["iptables", "-S", "INPUT"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if any(l.startswith("-A INPUT") for l in r.stdout.splitlines()):
            return "iptables"
    return None


def cmd_test(args, cfg):
    print(col("1) SSDP discovery", C.bold), col("(ST=%s, %ss)" % (args.st, args.timeout), C.dim))
    found = ssdp_search(args.st, args.timeout, args.target)
    ours = []
    mcast_blocked = False
    if not found:
        warn("Nobody answered the %s." % ("unicast M-SEARCH" if args.target else "multicast M-SEARCH"))
    for (src, loc), hdr in found.items():
        server = hdr.get("SERVER", "")
        mine = "fake-igd" in server
        tag = col("fake-igd", C.green, C.bold) if mine else col("OTHER DEVICE", C.red, C.bold)
        print("   %s %-15s %s  %s" % (tag, src, loc, col(server, C.dim)))
        if mine:
            ours.append(loc)
        elif "InternetGatewayDevice" in hdr.get("ST", "") or "WANIPConnection" in hdr.get("ST", ""):
            warn("%s is a UPnP router! The PS5 may use it instead of fake-igd. Disable UPnP on it." % src)

    if not ours and not args.target:
        # Multicast got no answer: probe the service directly over unicast to tell
        # "service broken" apart from "multicast blocked by the firewall".
        ifaces = local_interfaces()
        if ifaces:
            print()
            print(col("   unicast probe of the local interfaces:", C.dim))
        uni_ok = []
        for name, ip in sorted(ifaces.items()):
            res = ssdp_search(args.st, 1.5, ip)
            hit = [loc for (src, loc), h in res.items() if "fake-igd" in h.get("SERVER", "")]
            print("   %s %-10s %-15s %s" % (col("✔", C.green) if hit else col("✘", C.red), name, ip,
                                         "answers" if hit else "no answer"))
            if hit:
                uni_ok.append(name)
                ours.extend(hit)
        if uni_ok:
            mcast_blocked = True
            print()
            warn("fake-igd is running and answers unicast, but MULTICAST SSDP (239.255.255.250:1900) did not reach it.")
            warn("Most likely the host firewall drops incoming UDP 1900 on the physical interfaces "
                 "(this test's multicast loops back through the interface, not through 'lo').")
            fw = detect_firewall()
            info("Active firewall service: %s" % (col(fw, C.bold) if fw else "none detected"))
            info("Rules to add: %s" % col("upnp firewall%s" % ((" --format " + ("nft" if fw == "nftables" else fw))
                                                              if fw in ("nftables", "firewalld") else ""), C.bold))
            info("The PS5 discovers the router via multicast, so it will NOT find fake-igd until this is fixed.")
            print()

    if not ours:
        print()
        if cfg["mode"] == "passive":
            warn("Mode is 'passive' - fake-igd intentionally does not answer. Switch: sudo upnp mode active")
        elif cfg["allowed_clients"]:
            warn("allowed_clients is restricted (%s) - this server is probably not in the list, so it gets no answer. "
                 "Test from an allowed device or temporarily: sudo upnp config set allowed_clients ''"
                 % ", ".join(cfg["allowed_clients"]))
        else:
            st = service_info().get("ActiveState", "?")
            if st != "active":
                warn("The service is not running (state: %s). Start it: sudo upnp start; log: upnp log -n 30" % st)
            else:
                warn("fake-igd did not answer even over unicast. Check: upnp log -n 30, upnp firewall")
        sys.exit(1)

    loc = sorted(set(ours))[0]
    print()
    print(col("2) Device description", C.bold), col(loc, C.dim))
    try:
        with urllib.request.urlopen(loc, timeout=5) as r:
            desc = r.read().decode("utf-8", "replace")
        ok("HTTP %d, %d B" % (r.status, len(desc)))
    except Exception as e:  # noqa: BLE001
        fail("Downloading the description failed: %s (firewall %s/tcp? see: upnp firewall)" % (e, cfg["http_port"]))
    ctl = None
    try:
        root = ET.fromstring(desc)
        base = loc.rsplit("/", 1)[0]
        for svc in root.iter():
            if svc.tag.endswith("service"):
                kids = {c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in svc}
                if "WANIPConnection" in kids.get("serviceType", ""):
                    ctl = kids.get("controlURL", "")
                    ctl = ctl if ctl.startswith("http") else base + ctl
    except ET.ParseError as e:
        fail("Invalid XML: %s" % e)
    if not ctl:
        fail("The description has no WANIPConnection service.")
    ok("controlURL %s" % ctl)

    svc = "urn:schemas-upnp-org:service:WANIPConnection:1"
    print()
    print(col("3) SOAP queries", C.bold))
    for action, field in (("GetStatusInfo", "NewConnectionStatus"), ("GetExternalIPAddress", "NewExternalIPAddress")):
        code, text = soap_call(ctl, svc, action)
        val = xml_find(text, field)
        (ok if code == 200 else warn)("%s → HTTP %d, %s = %s" % (action, code, field, col(val, C.cyan, C.bold)))
        if action == "GetExternalIPAddress" and not val:
            warn("The public IP is empty - set external_ip in the config.")

    if args.add:
        m = re.fullmatch(r"(\d+)(?:/(tcp|udp))?", args.add.lower())
        if not m:
            fail("--add expects PORT or PORT/udp|tcp")
        port, proto = int(m.group(1)), (m.group(2) or "udp").upper()
        lan = urllib.parse.urlparse(ctl).hostname
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((lan, 1))
            me = s.getsockname()[0]
            s.close()
        except OSError:
            me = "127.0.0.1"
        print()
        print(col("4) Test AddPortMapping %d/%s" % (port, proto), C.bold))
        code, text = soap_call(ctl, svc, "AddPortMapping", {
            "NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": proto, "NewInternalPort": port,
            "NewInternalClient": me, "NewEnabled": 1, "NewPortMappingDescription": "upnp-cli-test", "NewLeaseDuration": 60})
        if code == 200:
            ok("accepted (accept mode)")
            code2, _ = soap_call(ctl, svc, "DeletePortMapping", {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": proto})
            ok("DeletePortMapping → HTTP %d" % code2)
        else:
            info("rejected, HTTP %d, error %s (%s)" % (code, xml_find(text, "errorCode"), xml_find(text, "errorDescription")))
        info("See the log: upnp log --events -n 5")
    print()
    if mcast_blocked:
        warn("The service itself works, but the PS5 will not find it until multicast SSDP is allowed (upnp firewall).")
        sys.exit(2)
    ok("fake-igd answers correctly.")


def cmd_firewall(args, cfg):
    if getattr(args, "apply", False) or getattr(args, "off", False) or getattr(args, "status", False):
        import upnp_admin
        sys.exit(upnp_admin.firewall_do(sys.modules[__name__], args, cfg))
    port = cfg["http_port"]
    ifaces = local_interfaces()
    excl = set(cfg.get("exclude_interfaces") or [])
    want = set(cfg.get("interfaces") or [])
    names = args.interface or sorted(n for n in ifaces if n not in excl and (not want or n in want))
    sources = args.source or []
    fmt = args.format
    if fmt == "auto":
        fw = detect_firewall()
        fmt = {"firewalld": "firewalld", "nftables": "nft"}.get(fw, "iptables")
    lines = ["# fake-igd %s - host firewall rules (INPUT) for format: %s" % (VERSION, fmt),
             "# allow: SSDP 1900/udp (multicast discovery), %d/tcp (description + SOAP)" % port,
             "# interfaces: %s%s" % (", ".join(names) or "all", ("; sources: " + ", ".join(sources)) if sources else ""),
             "# fake-igd is IPv4 only - nothing is needed for ip6tables."]
    if fmt == "iptables":
        lines.append("")
        targets = names or [None]
        srcs = sources or [None]
        for ifn in targets:
            for src in srcs:
                base = "iptables -I INPUT"
                if ifn:
                    base += " -i %s" % ifn
                if src:
                    base += " -s %s" % src
                lines.append("%s -p udp --dport 1900 -m comment --comment fake-igd -j ACCEPT" % base)
                lines.append("%s -p tcp --dport %d -m comment --comment fake-igd -j ACCEPT" % (base, port))
        lines.append("# optional - only if 'upnp test' on this server still gets no answer and loopback traffic is not accepted:")
        lines.append("iptables -I INPUT -p udp --sport 1900 -m addrtype --dst-type LOCAL -m comment --comment fake-igd -j ACCEPT")
        lines += ["", "# make persistent (AlmaLinux, iptables-services):",
                  "service iptables save        # writes /etc/sysconfig/iptables",
                  "# remove later: iptables -S INPUT | grep fake-igd | sed 's/^-A/-D/' | xargs -L1 iptables"]
    elif fmt == "nft":
        cond = []
        if names:
            cond.append("iifname { %s }" % ", ".join('"%s"' % n for n in names))
        if sources:
            cond.append("ip saddr { %s }" % ", ".join(sources))
        c = (" ".join(cond) + " ") if cond else ""
        lines += ["",
                  "nft insert rule inet filter input %sudp dport 1900 accept comment \"fake-igd\"" % c,
                  "nft insert rule inet filter input %stcp dport %d accept comment \"fake-igd\"" % (c, port),
                  "# optional - only if 'upnp test' on this server still gets no answer:",
                  "nft insert rule inet filter input udp sport 1900 fib daddr type local accept comment \"fake-igd\"",
                  "", "# adjust table/chain names to your ruleset (nft list ruleset); persist in /etc/sysconfig/nftables.conf"]
    else:
        zones = args.zone or ["<zone>"]
        lines.append("")
        for z in zones:
            lines.append("firewall-cmd --permanent --zone=%s --add-port=1900/udp" % z)
            lines.append("firewall-cmd --permanent --zone=%s --add-port=%d/tcp" % (z, port))
        lines += ["firewall-cmd --reload", "# zones of interfaces: firewall-cmd --get-active-zones"]
    for l in lines:
        print(col(l, C.dim) if l.startswith("#") else l)


def cmd_clear(args, cfg):
    require_root("Clearing logs")
    targets = []
    if args.requests or args.all:
        targets.append(cfg["request_log"])
    if args.log or args.all:
        targets.append(cfg["log_file"])
    if not targets:
        fail("Choose what to clear: --requests, --log or --all")
    if not args.yes:
        ans = input("Truncate %s? [y/N] " % ", ".join(targets)).strip().lower()
        if ans not in ("y", "yes"):
            fail("Cancelled.", 0)
    for t in targets:
        if os.path.exists(t):
            with open(t, "w"):
                pass
            ok("truncated: %s" % t)
    if args.all:
        info("Active mappings held in the service's memory disappear only after: sudo upnp restart")


def cmd_notify_test(args, cfg):
    daemon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake-igd.py")
    if not cfg.get("ntfy_url"):
        fail("ntfy_url is not set. Set it: sudo upnp config set ntfy_url https://ntfy.example.com/topic")
    r = subprocess.run([sys.executable, "-I", daemon, "--config", args.config, "--notify-test"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = (r.stdout or "").strip()
    if r.returncode == 0:
        ok(out)
    else:
        fail(out or "the test failed (exit %d)" % r.returncode, r.returncode or 1)


def cmd_notify(args, cfg):
    """upnp notify list | on KIND | off KIND | test KIND (1.8.2): what is sent to ntfy."""
    import igd_ntfy as N
    sub = args.notify_cmd or "list"
    kinds = N.KINDS + ["alert:%s" % k for k, _w in N.ALERT_KINDS]
    if sub == "list":
        rows = []
        for kind, group, words, _says, dflt in N.EVENTS:
            c = N.conf(cfg, kind)
            rows.append({"kind": kind, "group": group, "on": bool(c["on"]), "default": dflt,
                         "priority": c.get("priority") or 0, "tags": c.get("tags") or "", "words": words})
        for k, w in N.ALERT_KINDS:
            rows.append({"kind": "alert:" + k, "group": "alerts", "on": bool(N.conf(cfg, "alert:" + k)["on"]),
                         "default": True, "priority": "", "tags": "", "words": w})
        if args.json:
            print(json.dumps({"events": rows, "url": bool(cfg.get("ntfy_url")),
                              "quiet": [cfg.get("ntfy_quiet_from"), cfg.get("ntfy_quiet_to"),
                                        cfg.get("ntfy_quiet_priority"), cfg.get("ntfy_quiet_summary")],
                              "rate_per_hour": cfg.get("ntfy_rate_per_hour")}, ensure_ascii=False, indent=2))
            return
        print(col("What is sent to ntfy", C.bold) + "  " + col(str(cfg.get("ntfy_url") or "ntfy_url not set - "
                                                                     "nothing goes out"), C.dim))
        group = None
        for r in rows:
            if r["group"] != group:
                group = r["group"]
                print()
                print(col(N.GROUP_WORDS.get(group, "The alerts' kinds (with alerts on)"), C.bold))
            mark = col("on ", C.green + C.bold) if r["on"] else col("off", C.dim)
            look = []
            if r["priority"]:
                look.append("priority %s" % r["priority"])
            if r["tags"]:
                look.append("tags %s" % r["tags"])
            print("  %s  %-16s %s%s" % (mark, r["kind"], r["words"], col(("  (" + ", ".join(look) + ")") if look
                                                                         else "", C.dim)))
        q = (cfg.get("ntfy_quiet_from"), cfg.get("ntfy_quiet_to"))
        print()
        print("  quiet hours: %s · rate limit: %s" % (
            ("%s-%s, priority %s and above pass, the rest %s" % (q[0], q[1], cfg.get("ntfy_quiet_priority"),
             "held for one summary" if cfg.get("ntfy_quiet_summary", True) else "dropped")) if q[0] and q[1]
            else "none", ("%s of a kind an hour" % cfg.get("ntfy_rate_per_hour")) if cfg.get("ntfy_rate_per_hour")
            else "none"))
        return
    kind = args.kind
    if kind not in kinds:
        fail("Unknown kind %s. Kinds: %s" % (kind, ", ".join(kinds)))
    if sub == "test":
        if kind.startswith("alert:"):
            kind = "alerts"
        if not cfg.get("ntfy_url"):
            fail("ntfy_url is not set. Set it: sudo upnp config set ntfy_url https://ntfy.example.com/topic")
        title, words = N.SAMPLES[kind]
        got = {}
        said = N.Notifier(lambda: cfg, lambda *a: got.update(a=a)).send(kind, title, words, sample=True, wait=True)
        (ok if said.startswith("sent") else fail)("a sample of %s: %s" % (kind, said))
        return
    require_root("Changing the config")
    raw = load_config(args.config, strict=True)
    ev = N.events_checked(raw.get("ntfy_events") or {})
    one = dict(N.conf(dict(raw, ntfy_events=ev), kind))
    one["on"] = sub == "on"
    if kind.startswith("alert:"):
        one = {"on": one["on"]}
    ev[kind] = one
    raw["ntfy_events"] = N.events_checked(ev)
    if kind == "port_renew":
        raw["notify_on_renew"] = one["on"]
    if kind == "other_router":
        raw["notify_other_router"] = one["on"]
    write_config(args.config, raw)
    ok("%s: %s" % (kind, "on" if one["on"] else "off"))
    if kind.split(":")[0] in ("alert", "alerts", "alerts_over") or kind.startswith("gw_"):
        info("Sent by the pages' API (fake-igd-api) - it reads config.json again within a minute.")
    else:
        restart_service(args.no_restart)


# ================================================================ mDNS / Avahi
def cmd_mdns(args, cfg):
    import upnp_mdns as M
    sub = args.mdns_cmd or "status"
    try:
        if sub == "status":
            d = M.status()
            if args.json:
                print(M.to_json(d))
                return
            sv = d["service"]
            stc = C.green if sv["state"] == "active" else C.red
            print(col("mDNS reflector (avahi-daemon)", C.bold), col(d["version"] or "", C.dim))
            print()
            rows = [
                ("Service", col("%s (%s)" % (sv["state"], sv["sub"]), stc, C.bold)),
                ("Running since", sv["since"] or "-"),
                ("Start on boot", sv["boot"]),
                ("Reflector", col("on", C.green, C.bold) if d["reflector"] else col("off", C.yellow, C.bold)),
                ("Reflect IPv4<->IPv6", "on" if d["reflect_ipv"] else "off"),
                ("Reflect only", ", ".join(d["reflect_filters"]) or col("every service type", C.dim)),
                ("IPv4 / IPv6", "%s / %s" % ("on" if d["ipv4"] else "off", "on" if d["ipv6"] else "off")),
                ("Allowed interfaces", ", ".join(d["allow_interfaces"]) or col("all", C.dim)),
                ("Denied interfaces", ", ".join(d["deny_interfaces"]) or col("-", C.dim)),
                ("Cache entries max", d["cache_entries_max"]),
                ("Rate limit", "%s packets / %s us" % (d["ratelimit"]["burst"] or "-", d["ratelimit"]["interval_usec"] or "-")),
                ("Config", d["config"]),
            ]
            for k, v in rows:
                print("  %-20s %s" % (k, v))
            print()
            print(col("Interfaces it uses", C.bold))
            names = ptr_names([ip for i in d["interfaces"] for ip in i["ipv4"]])
            for i in d["interfaces"]:
                ip = ", ".join(i["ipv4"]) or "-"
                nm = ", ".join(names.get(x, "") for x in i["ipv4"] if names.get(x))
                print("  %s %-12s %-16s %s" % (col("●", C.green if i["exists"] else C.red), i["name"], ip, col(nm, C.cyan)))
            if d["missing_interfaces"]:
                print()
                warn("allow-interfaces names interfaces that do not exist: %s" % ", ".join(d["missing_interfaces"]))
            if not d["browse_tool"]:
                print()
                info("avahi-browse is not installed (dnf install avahi-tools) - 'upnp mdns services' needs it.")
            if sv["state"] != "active":
                print()
                warn("avahi-daemon is not running: sudo upnp mdns start")
            elif d["reflector"] and len(d["interfaces"]) < 2:
                print()
                warn("The reflector is on but avahi uses fewer than two interfaces - nothing to reflect between.")
            return
        if sub == "services":
            got = M.services(resolve=not args.no_resolve, timeout=args.timeout)
            if args.type:
                got = [x for x in got if args.type.lower() in x["type"].lower()]
            if args.iface:
                got = [x for x in got if x["iface"] == args.iface]
            if args.json:
                print(M.to_json(got))
                return
            rows = [[col(x["type"], C.cyan), col(x["name"], C.bold), x["iface"], x["proto"],
                     x.get("host", ""), col(x.get("address", ""), C.magenta), x.get("port", ""),
                     col((x.get("txt") or "")[:60], C.dim)] for x in got]
            table(["TYPE", "NAME", "IFACE", "PROTO", "HOST", "ADDRESS", "PORT", "TXT"], rows,
                  "No mDNS services seen (is avahi-daemon running? are the interfaces right?)")
            if rows:
                print()
                info("%d service(s) on %d interface(s)." % (len(rows), len({x["iface"] for x in got})))
            return
        if sub == "browse":
            if not shutil.which("avahi-browse"):
                fail("avahi-browse is missing - dnf install avahi-tools")
            pr = subprocess.Popen(["avahi-browse", "-a", "-p", "-r"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, errors="replace")
            try:
                for ln in pr.stdout:
                    d = M.parse_browse(ln.rstrip("\n"))
                    print(mdns_line(d) if d else ln.rstrip("\n"), flush=True)
            except KeyboardInterrupt:
                print()
            finally:
                pr.terminate()
            return
        if sub == "config":
            vals, _lines = M.read_conf()
            if args.json:
                print(M.to_json(vals))
                return
            print(col(M.CONF, C.bold) + col("  (the lines set - everything else as avahi has it)", C.dim))
            for k, v in vals.items():
                print("  %s %s" % (col("%-26s" % k, C.cyan), v))
            return
        if sub in ("start", "stop", "restart", "enable", "disable"):
            if sub == "stop":
                warn("Stopping avahi-daemon stops the mDNS reflector: devices in other networks stop seeing each other.")
            r = systemctl(sub, M.SERVICE)
            if r.returncode != 0:
                fail("systemctl %s %s failed." % (sub, M.SERVICE))
            time.sleep(1)
            ok("%s: %s" % (sub, M.systemd_state().get("ActiveState", "?")))
            return
        if sub == "log":
            argv = ["journalctl", "-u", M.SERVICE, "--no-pager", "-n", str(args.n)] + (["-f"] if args.follow else [])
            try:
                sys.exit(subprocess.call(argv))
            except KeyboardInterrupt:
                return
        changes = {}
        if sub == "reflector":
            changes["enable-reflector"] = args.value
        elif sub == "reflect-ipv":
            changes["reflect-ipv"] = args.value
        elif sub == "ipv6":
            changes["use-ipv6"] = args.value
        elif sub == "ipv4":
            changes["use-ipv4"] = args.value
        elif sub == "interfaces":
            changes["allow-interfaces"] = ",".join(args.value)
        elif sub == "filters":
            changes["reflect-filters"] = ",".join(args.value)
        elif sub == "set":
            changes[args.key] = args.value
        print(ok_words(M.apply(changes, restart=not args.no_restart)))
    except M.MdnsError as e:
        fail(str(e))


def ok_words(t):
    return col("✔", C.green, C.bold) + " " + t


def mdns_line(d):
    """One event of avahi-browse, coloured as the live views colour."""
    p = PAL
    ev = {"new": p.good("new     "), "gone": p.bad("gone    "), "resolved": p.info("resolved")}[d["event"]]
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    bits = [p.dim(t), ev, "%-8s" % d["iface"], "%-4s" % d["proto"], p.info(d["type"]), p.bold(d["name"])]
    if d.get("address"):
        bits.append("%s %s:%s" % (d.get("host", ""), p.addr(d["address"]), d.get("port", "")))
    if d.get("txt"):
        bits.append(p.dim(d["txt"][:80]))
    return " ".join(bits)


def cmd_version(args, cfg):
    print("upnp CLI %s (fake-igd), Python %s" % (VERSION, sys.version.split()[0]))
    try:
        import colorama
        print("colorama %s" % colorama.__version__)
    except ImportError:
        print("colorama: not installed (using raw ANSI colours)")


# ================================================================ argparse
MAIN_DESC = """\
upnp - control and reporting tool for fake-igd.

fake-igd is a fake UPnP router (IGD). Devices on the LAN (e.g. a PS5) send it
port mapping requests (AddPortMapping). It only logs them - nothing is opened
on the real router. From the log you learn which ports to forward with DNAT.
"""
MAIN_EPILOG = """\
commands by purpose:
  overview        status, clients
  ports           ports, requests, mappings, dnat
  log             log
  settings        config, mode, response
  service         start, stop, restart, enable, disable, test
  firewall        firewall
  notifications   notify (list, on, off, test), notify-test
  mDNS reflector  mdns (status, services, browse, reflector, interfaces, filters, log)
  maintenance     check, events, db, backup, export-config, import-config, clear, version
  upgrades        upgrade (check, online, file, status, follow, log, after), updates (the system's)
  security        selinux (check, prepare, enforce, permissive, report), firewall
  web pages       web, tls, acme, user (list, add, passwd, role, del, sessions, lockouts)
  the machine     net, gateway, time, updates, power
  tests           test, notify-test, mail-test, siem-test, proxy-test, snmp-trap
  what the pages do, here too   api GET|POST /api/... (any pane's question, as JSON)
  console         --console (menus, live log), --console-at-login on|off|status

typical workflow:
  upnp --console                       # everything by its menus, opens on the live log
  upnp status                          # is the service running? on which interfaces?
  upnp test                            # does fake-igd answer? is another UPnP router on the network?
  upnp firewall                        # host firewall rules if the test reports blocked multicast
  upnp log -f --events                 # watch live while running a test / game / party chat on the PS5
  upnp ports                           # list of requested ports
  upnp dnat --format mikrotik --wan ether1   # ready-made rules for the router

help for a command:  upnp <command> --help   (or  upnp help <command>)

files:
  /etc/fake-igd/config.json            configuration
  /var/log/fake-igd/fake-igd.log       main log
  /var/log/fake-igd/requests.jsonl     requests (JSON lines)
  /var/lib/fake-igd/mappings.json      current "mappings"
  /var/lib/fake-igd/fake-igd.db        the web pages' accounts, sign-ins and events (SQLite)
  https://SERVER/admin/                the web pages (nginx, php-fpm, fake-igd-api)

colours: colorama (or raw ANSI); disable with --no-color or the NO_COLOR variable.
read logs without sudo: sudo usermod -aG fake-igd $USER  (then log in again)
"""

SINCE_HELP = "only entries newer than: 30m, 2h, 7d, 2w or a date '2026-11-16', '2026-11-16 18:00'"


def build_parser():
    fmt = argparse.RawDescriptionHelpFormatter
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS, metavar="FILE",
                        help="config file (default %s)" % DEFAULT_CONFIG)
    common.add_argument("--color", choices=("auto", "always", "never"), default=argparse.SUPPRESS,
                        help="coloured output: auto (terminal only), always, never (default auto)")
    common.add_argument("--no-color", dest="color", action="store_const", const="never", default=argparse.SUPPRESS,
                        help="disable colours")
    common.add_argument("--no-dns", action="store_true", default=argparse.SUPPRESS,
                        help="do not look up PTR names (reverse DNS) of the addresses shown")

    kw = {}
    if sys.version_info >= (3, 14):
        kw = {"color": True, "suggest_on_error": True}
    p = argparse.ArgumentParser(prog="upnp", description=MAIN_DESC, epilog=MAIN_EPILOG, formatter_class=fmt,
                                parents=[common], **kw)
    g = p.add_argument_group("console")
    g.add_argument("--console", action="store_true",
                   help="the console: everything by its menus, opens on the live log (q leaves)")
    g.add_argument("--console-at-login", choices=("on", "off", "status"), metavar="on|off|status",
                   help="open the console when root signs in (at the console or over SSH)")
    g.add_argument("--console-users", metavar="USERS",
                   help="open it at login for normal users too: 'alice bob', '*' (every one) or none - through sudo")
    sp = p.add_subparsers(dest="cmd", metavar="<command>", title="commands")

    def add(name, help_, desc, epilog="", aliases=()):
        kwargs = dict(help=help_, description=desc, epilog=epilog, formatter_class=fmt, parents=[common], aliases=list(aliases))
        kwargs.update(kw)
        return sp.add_parser(name, **kwargs)

    s = add("status", "service state, configuration, interfaces and statistics",
            "Shows the systemd service state, the main settings, the interfaces fake-igd\n"
            "listens on (from the log since the last start) and request statistics.\n"
            "Also warns about another UPnP router on the network if fake-igd has seen one.",
            "example:\n  upnp status\n  upnp status --json", aliases=("st",))
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=cmd_status)

    s = add("ports", "requested ports (summary per client/protocol/port)",
            "Summary of all ports clients asked for via AddPortMapping.\n"
            "One row = client + protocol + port, with the number of requests, time of the\n"
            "first and last request, the result (ok / rejected / conflict) and the\n"
            "description sent by the application (often the game's name).",
            "examples:\n"
            "  upnp ports                         # everything\n"
            "  upnp ports --client 192.168.1.50   # PS5 only\n"
            "  upnp ports --proto udp --since 2h  # UDP in the last 2 hours\n"
            "  upnp ports --min-count 2           # only ports requested repeatedly (no one-offs)\n"
            "  upnp ports --json | jq .           # machine-readable output", aliases=("p",))
    s.add_argument("--client", metavar="IP", help="only ports for this IP (requester or target)")
    s.add_argument("--proto", choices=("tcp", "udp"), type=str.lower, help="only TCP or UDP")
    s.add_argument("--since", metavar="TIME", help=SINCE_HELP)
    s.add_argument("--min-count", type=int, default=1, metavar="N", help="only ports requested at least N times (default 1)")
    s.add_argument("--port", type=int, metavar="PORT", help="only this external port")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=cmd_ports)

    s = add("requests", "individual requests over time (requests.jsonl)",
            "Chronological list of individual requests: AddPortMapping, DeletePortMapping\n"
            "and expirations (Expired). Shows time, client, port, target, lease duration,\n"
            "result and description. Defaults to the last 30 entries.",
            "examples:\n"
            "  upnp requests                          # last 30\n"
            "  upnp requests -n 0                     # all\n"
            "  upnp requests --action AddPortMapping --since 1d\n"
            "  upnp requests --json > export.jsonl", aliases=("req", "r"))
    s.add_argument("-n", type=int, default=30, metavar="N", help="last N entries, 0 = all (default 30)")
    s.add_argument("--client", metavar="IP", help="filter by client")
    s.add_argument("--action", metavar="ACTION", help="filter by action: AddPortMapping, DeletePortMapping, Expired")
    s.add_argument("--since", metavar="TIME", help=SINCE_HELP)
    s.add_argument("--json", action="store_true", help="JSON lines output")
    s.set_defaults(func=cmd_requests)

    s = add("mappings", "ports clients currently believe are open",
            "Current mappings stored by the service (/var/lib/fake-igd/mappings.json)\n"
            "including the remaining lease time. Stored only with mapping_response=accept.\n"
            "NOTE: nothing is open on the router - this is only what clients believe.",
            "example:\n  upnp mappings", aliases=("m",))
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=cmd_mappings)

    s = add("clients", "devices that searched for a UPnP router or requested ports",
            "Overview of devices: how many times they searched for a UPnP router\n"
            "(SSDP M-SEARCH), how many requests they sent, how many different ports they\n"
            "wanted, when they were last seen and their User-Agent.",
            "examples:\n  upnp clients\n  upnp clients --since 1d\n  upnp clients --no-dns", aliases=("c",))
    s.add_argument("--since", metavar="TIME", help=SINCE_HELP)
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=cmd_clients)

    s = add("log", "main log with colours, filters and follow mode (-f)",
            "Shows /var/log/fake-igd/fake-igd.log coloured by event type:\n"
            "  NEW PORT (green), RENEW (cyan), REJECTED (yellow), CONFLICT (red),\n"
            "  DELETED (magenta), SEARCH/DESC (blue), warnings and errors (yellow/red),\n"
            "  OTHER UPnP ROUTER (bold red).\n"
            "With -f it follows new lines live (handles log rotation). Stop with Ctrl+C.",
            "examples:\n"
            "  upnp log                     # last 50 lines\n"
            "  upnp log -f --events         # live, important events only\n"
            "  upnp log --level WARNING     # warnings and errors only\n"
            "  upnp log --grep 3478 -n 0    # everything containing 3478\n"
            "  upnp log --since 30m", aliases=("l",))
    s.add_argument("-n", type=int, default=50, metavar="N", help="last N lines, 0 = all (default 50)")
    s.add_argument("-f", "--follow", action="store_true", help="follow new lines (like tail -f)")
    s.add_argument("-e", "--events", action="store_true", help="events only (ports, searches, warnings) without SOAP details")
    s.add_argument("--level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), type=str.upper, help="minimum level")
    s.add_argument("--grep", metavar="REGEX", help="only lines matching the regular expression (case-insensitive)")
    s.add_argument("--since", metavar="TIME", help=SINCE_HELP)
    s.add_argument("--raw", action="store_true", help="no colouring or formatting")
    s.set_defaults(func=cmd_log)

    s = add("dnat", "generate DNAT rules from the requested ports",
            "Generates port forwarding rules for the router from the requested ports.\n"
            "Consecutive ports are merged into ranges, long lists are split (multiport max 15).\n"
            "Formats:\n"
            "  iptables   PREROUTING DNAT + FORWARD accept (WAN default eth0)\n"
            "  nft        nftables, assumes tables ip nat / inet filter\n"
            "  mikrotik   /ip firewall nat (WAN default 'WAN' = in-interface)\n"
            "  firewalld  forward-port in a zone (default 'external') + masquerade",
            "examples:\n"
            "  upnp dnat\n"
            "  upnp dnat --format mikrotik --wan ether1\n"
            "  upnp dnat --format nft --client 192.168.1.50 --min-count 2\n"
            "  upnp dnat --quiet > /root/ps5-dnat.sh", aliases=("d",))
    s.add_argument("--format", "-F", choices=("iptables", "nft", "mikrotik", "firewalld"), default="iptables",
                   help="rule format (default iptables)")
    s.add_argument("--wan", metavar="IFACE", help="WAN interface / interface list / zone (depends on the format)")
    s.add_argument("--client", metavar="IP", help="only for this IP")
    s.add_argument("--proto", choices=("tcp", "udp"), type=str.lower, help="only TCP or UDP")
    s.add_argument("--since", metavar="TIME", help=SINCE_HELP)
    s.add_argument("--min-count", type=int, default=1, metavar="N", help="only ports requested at least N times")
    s.add_argument("--port", type=int, metavar="PORT", help="only this external port")
    s.add_argument("--no-forward", action="store_true", help="do not generate FORWARD/accept rules")
    s.add_argument("--quiet", "-q", action="store_true", help="commands only, no comments")
    s.set_defaults(func=cmd_dnat)

    s = add("firewall", "host firewall rules (INPUT) that fake-igd needs on THIS server",
            "Prints the rules that let SSDP discovery (1900/udp multicast) and the\n"
            "description/SOAP port (http_port/tcp) reach fake-igd on this server.\n"
            "Without them the PS5's multicast M-SEARCH is dropped and it never finds fake-igd.\n"
            "By default the rules are limited to the interfaces fake-igd listens on.\n"
            "The format is detected from the active service (firewalld / nftables / iptables).\n"
            "fake-igd is IPv4 only - nothing is needed for ip6tables.",
            "examples:\n"
            "  upnp firewall\n"
            "  upnp firewall --interface ens161 --interface ens224\n"
            "  upnp firewall --source 172.16.16.0/24\n"
            "  upnp firewall --format firewalld --zone internal\n"
            "  upnp firewall -q | grep -v '^#' | sudo sh      # apply (iptables) by hand\n"
            "\n"
            "fake-igd's own chain, as otp's OTP-IN (1.4.0) - FAKE-IGD-IN, jumped to first from INPUT,\n"
            "ACCEPT rules only (loopback, answers, SSH, ping, 1900/udp, http_port/tcp, 80/443 from web_allow),\n"
            "put in at once and kept in /etc/sysconfig/iptables between '# fake-igd:' lines:\n"
            "  sudo upnp firewall --apply          # switch it on (firewall=on) and put it in place\n"
            "  sudo upnp firewall --status         # what is in place\n"
            "  sudo upnp firewall --off            # the chain and its jump taken away", aliases=("fw",))
    s.add_argument("--format", "-F", choices=("auto", "iptables", "nft", "firewalld"), default="auto",
                   help="rule format (default auto = by the active firewall service)")
    s.add_argument("--interface", "-i", action="append", metavar="IFACE",
                   help="limit to an interface (repeatable; default = interfaces fake-igd uses)")
    s.add_argument("--source", "-s", action="append", metavar="CIDR", help="limit to a source subnet (repeatable)")
    s.add_argument("--zone", action="append", metavar="ZONE", help="firewalld zone (repeatable)")
    s.add_argument("--quiet", "-q", action="store_true", help=argparse.SUPPRESS)
    fx = s.add_mutually_exclusive_group()
    fx.add_argument("--apply", action="store_true", help="put fake-igd's chain FAKE-IGD-IN in place (iptables, root)")
    fx.add_argument("--off", action="store_true", help="take FAKE-IGD-IN and its jump away (root)")
    fx.add_argument("--status", action="store_true", help="what of FAKE-IGD-IN is in place (root)")
    s.set_defaults(func=cmd_firewall)

    s = add("config", "show and change the configuration",
            "Works with /etc/fake-igd/config.json.\n"
            "  show       all keys with descriptions (changed values highlighted)\n"
            "  get KEY    value of one key\n"
            "  set KEY VALUE   change a value (type-checked) and restart the service\n"
            "  edit       open the config in $EDITOR, validate the JSON, restart the service\n"
            "  validate   check the configuration\n"
            "  path       path to the config file\n"
            "Lists (interfaces, exclude_interfaces, allowed_clients) take comma-separated\n"
            "values or JSON; empty list = ''.",
            "examples:\n"
            "  upnp config\n"
            "  sudo upnp config set allowed_clients 192.168.1.50\n"
            "  sudo upnp config set exclude_interfaces lo,ens19\n"
            "  sudo upnp config set ntfy_url https://ntfy.sh/my-secret-topic\n"
            "  sudo upnp config set log_level DEBUG\n"
            "  sudo upnp config edit", aliases=("cfg",))
    csp = s.add_subparsers(dest="config_cmd", metavar="<action>")
    for name, h in (("show", "show the configuration"), ("path", "path to the config file"),
                    ("validate", "validate the configuration"), ("edit", "edit in $EDITOR")):
        c = csp.add_parser(name, help=h, parents=[common])
        c.add_argument("--json", action="store_true", help=argparse.SUPPRESS if name != "show" else "JSON output")
        c.add_argument("--no-restart", action="store_true", help=argparse.SUPPRESS if name != "edit" else "do not restart the service")
    c = csp.add_parser("get", help="value of a key", parents=[common])
    c.add_argument("key", metavar="KEY", choices=list(DEFAULTS))
    c = csp.add_parser("set", help="set a key and restart the service", parents=[common])
    c.add_argument("key", metavar="KEY", choices=list(DEFAULTS))
    c.add_argument("value", metavar="VALUE")
    c.add_argument("--no-restart", action="store_true", help="do not restart the service")
    s.set_defaults(func=cmd_config, json=False, no_restart=False)

    s = add("mode", "show / switch the mode active <-> passive",
            "active   fake-igd answers like a UPnP router -> captures port requests\n"
            "passive  never answers, only logs who is looking for a UPnP router\n"
            "         (does not affect the PS5, but you will not learn the ports)\n"
            "Without an argument prints the current mode. A change restarts the service.",
            "examples:\n  upnp mode\n  sudo upnp mode passive")
    s.add_argument("value", nargs="?", choices=("active", "passive"), metavar="active|passive")
    s.add_argument("--no-restart", action="store_true", help="do not restart the service")
    s.set_defaults(func=cmd_setting("mode"))

    s = add("response", "show / switch the AddPortMapping response (accept <-> reject)",
            "accept  confirm the request (nothing is opened on the router); the client keeps\n"
            "        sending further requests -> you capture the most ports\n"
            "reject  refuse with error 501 ActionFailed; the client behaves as without UPnP,\n"
            "        the request is still logged\n"
            "Without an argument prints the current setting. A change restarts the service.",
            "examples:\n  upnp response\n  sudo upnp response reject")
    s.add_argument("value", nargs="?", choices=("accept", "reject"), metavar="accept|reject")
    s.add_argument("--no-restart", action="store_true", help="do not restart the service")
    s.set_defaults(func=cmd_setting("mapping_response"))

    s = add("test", "test fake-igd as a UPnP client (SSDP + HTTP + SOAP)",
            "Behaves like the PS5: sends an SSDP M-SEARCH, lists ALL devices that answered\n"
            "(also reveals another UPnP router on the network), downloads the fake-igd\n"
            "description and calls GetStatusInfo and GetExternalIPAddress.\n"
            "If multicast gets no answer it probes every local interface over unicast and\n"
            "tells you whether the service is down or the firewall blocks multicast.\n"
            "With --add it also sends a test AddPortMapping (logged with the description\n"
            "'upnp-cli-test', excluded from reports) and deletes it again.\n"
            "If allowed_clients does not include this server's IP, fake-igd ignores it on purpose.",
            "examples:\n"
            "  upnp test\n"
            "  upnp test --add 40000/udp\n"
            "  upnp test --target 192.168.1.10      # unicast instead of multicast\n"
            "  upnp test --st ssdp:all --timeout 5  # list every UPnP device on the network", aliases=("t",))
    s.add_argument("--st", default="urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                   help="search target (default IGD:1; ssdp:all = all devices)")
    s.add_argument("--timeout", type=float, default=3.0, help="how long to wait for answers in seconds (default 3)")
    s.add_argument("--target", metavar="IP", help="send the M-SEARCH as unicast to this IP")
    s.add_argument("--add", metavar="PORT[/udp|tcp]", help="also send a test AddPortMapping")
    s.set_defaults(func=cmd_test)

    s = add("mdns", "the mDNS reflector (avahi-daemon): status, services, control",
            "Shows and controls avahi-daemon - the mDNS reflector that repeats mDNS (Bonjour,\n"
            "AirPlay, Chromecast, printers...) between the server's networks.\n"
            "  status                 the daemon, the reflector, IPv4/IPv6, filters, interfaces\n"
            "  services               what mDNS shows now on every interface (avahi-browse)\n"
            "  browse                 mDNS events live (new / gone / resolved), Ctrl+C stops\n"
            "  reflector on|off       repeat mDNS between the interfaces or not\n"
            "  interfaces IF...|all   allow-interfaces - the interfaces it uses and reflects between\n"
            "  filters TYPE...|none   reflect only these service types (reflect-filters)\n"
            "  ipv6 on|off, ipv4 on|off, reflect-ipv on|off\n"
            "  set KEY VALUE          any known key of avahi-daemon.conf\n"
            "  config                 the lines set in avahi-daemon.conf\n"
            "  start|stop|restart|enable|disable, log [-f]\n"
            "Changes keep every comment of the file, leave a copy beside it\n"
            "(avahi-daemon.conf.bak-DATE), check the value first and restart avahi-daemon;\n"
            "when it does not come up with the change the copy is put back.",
            "examples:\n"
            "  upnp mdns\n"
            "  upnp mdns services --type _airplay\n"
            "  upnp mdns browse\n"
            "  sudo upnp mdns reflector on\n"
            "  sudo upnp mdns interfaces ens192 ens224\n"
            "  sudo upnp mdns filters _airplay._tcp _raop._tcp\n"
            "  sudo upnp mdns set cache-entries-max 0\n"
            "  upnp mdns log -f", aliases=("avahi",))
    msp = s.add_subparsers(dest="mdns_cmd", metavar="<action>")
    c = msp.add_parser("status", help="the daemon and the reflector", parents=[common])
    c.add_argument("--json", action="store_true", help="JSON output")
    c = msp.add_parser("services", help="what mDNS shows now (avahi-browse)", parents=[common])
    c.add_argument("--json", action="store_true", help="JSON output")
    c.add_argument("--type", metavar="TYPE", help="only service types containing this (e.g. _airplay)")
    c.add_argument("--iface", metavar="IFACE", help="only this interface")
    c.add_argument("--no-resolve", action="store_true", help="names only, faster (no host / address / port)")
    c.add_argument("--timeout", type=int, default=15, metavar="S", help="stop looking after S seconds (default 15)")
    msp.add_parser("browse", help="mDNS events live", parents=[common])
    c = msp.add_parser("config", help="the lines set in avahi-daemon.conf", parents=[common])
    c.add_argument("--json", action="store_true", help="JSON output")
    for name, h in (("reflector", "the reflector on or off"), ("reflect-ipv", "reflect between IPv4 and IPv6"),
                    ("ipv6", "mDNS over IPv6"), ("ipv4", "mDNS over IPv4")):
        c = msp.add_parser(name, help=h, parents=[common])
        c.add_argument("value", choices=("on", "off", "yes", "no"), metavar="on|off")
        c.add_argument("--no-restart", action="store_true", help="do not restart avahi-daemon")
    c = msp.add_parser("interfaces", help="allow-interfaces (all = every interface)", parents=[common])
    c.add_argument("value", nargs="+", metavar="IFACE")
    c.add_argument("--no-restart", action="store_true", help="do not restart avahi-daemon")
    c = msp.add_parser("filters", help="reflect-filters (none = every type)", parents=[common])
    c.add_argument("value", nargs="+", metavar="TYPE")
    c.add_argument("--no-restart", action="store_true", help="do not restart avahi-daemon")
    c = msp.add_parser("set", help="any known key", parents=[common])
    c.add_argument("key", metavar="KEY")
    c.add_argument("value", metavar="VALUE")
    c.add_argument("--no-restart", action="store_true", help="do not restart avahi-daemon")
    for name in ("start", "stop", "restart", "enable", "disable"):
        msp.add_parser(name, help="%s avahi-daemon" % name, parents=[common])
    c = msp.add_parser("log", help="journalctl -u avahi-daemon", parents=[common])
    c.add_argument("-n", type=int, default=50, metavar="N", help="last N lines (default 50)")
    c.add_argument("-f", "--follow", action="store_true", help="follow")
    s.set_defaults(func=cmd_mdns, mdns_cmd=None, json=False)

    s = add("notify-test", "send a test notification with the configured ntfy",
            "Sends one test message the way fake-igd sends its notifications - to ntfy.sh or\n"
            "your private ntfy server (ntfy_url), with its token or user/password, priority,\n"
            "tags and own CA certificate (ntfy_ca_file). Prints what the server answered.",
            "examples:\n"
            "  upnp notify-test\n"
            "  sudo upnp config set ntfy_url https://ntfy.example.com/ps5\n"
            "  sudo upnp config set ntfy_token -          # asked for, not shown\n"
            "  sudo upnp config set ntfy_ca_file /etc/pki/tls/certs/my-ca.pem", aliases=("nt",))
    s.set_defaults(func=cmd_notify_test)

    s = add("notify", "what is sent to ntfy: list, on KIND, off KIND, test KIND",
            "Each kind of event sent to ntfy switched on or off (config.json's ntfy_events, the\n"
            "card \"What is sent\" of Settings → Notifications (ntfy)). The UPnP events are sent by\n"
            "fake-igd.service (restarted after a change), the gateway's and the alerts' by the pages'\n"
            "API. test sends that kind's own wording now, marked as a sample.",
            "examples:\n"
            "  upnp notify list\n"
            "  sudo upnp notify on port_renew\n"
            "  sudo upnp notify off other_router\n"
            "  sudo upnp notify off alert:updates    # the alerts sent, but not this kind\n"
            "  upnp notify test port_refused\n"
            "  sudo upnp config set ntfy_quiet_from 22:00; sudo upnp config set ntfy_quiet_to 07:00")
    nsp = s.add_subparsers(dest="notify_cmd", metavar="list|on|off|test")
    c = nsp.add_parser("list", help="every kind: on or off, its priority and tags", parents=[common])
    c.add_argument("--json", action="store_true", help="as JSON")
    for name, h in (("on", "send this kind"), ("off", "do not send this kind"), ("test", "send a sample of it now")):
        c = nsp.add_parser(name, help=h, parents=[common])
        c.add_argument("kind", metavar="KIND", help="port_new, port_renew, ... gw_online, alerts, alert:disk ...")
        if name != "test":
            c.add_argument("--no-restart", action="store_true", help="do not restart the service")
    s.set_defaults(func=cmd_notify, notify_cmd=None, json=False, no_restart=False)

    for name, h in (("start", "start the service"), ("stop", "stop the service"), ("restart", "restart the service"),
                    ("enable", "enable start on boot"), ("disable", "disable start on boot")):
        s = add(name, h, "%s fake-igd (systemctl %s fake-igd). Uses sudo when not run as root." % (h.capitalize(), name))
        s.set_defaults(func=cmd_service(name))

    s = add("clear", "truncate the request log and/or the main log",
            "Truncates log files (requires root). Useful before a new measurement,\n"
            "e.g. when you want the ports of one particular game only.",
            "examples:\n  sudo upnp clear --requests\n  sudo upnp clear --all -y")
    s.add_argument("--requests", action="store_true", help="truncate requests.jsonl")
    s.add_argument("--log", action="store_true", help="truncate fake-igd.log")
    s.add_argument("--all", action="store_true", help="both")
    s.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    s.set_defaults(func=cmd_clear)

    s = add("version", "versions of the CLI, Python and colorama", "Prints versions.")
    s.set_defaults(func=cmd_version)

    def admin(fn_name):
        def go(a, c):
            import upnp_admin
            sys.exit(getattr(upnp_admin, fn_name)(sys.modules[__name__], a, c) or 0)
        return go

    s = add("upgrade", "a new version from the web (or a package file), checked and put in by root",
            "New versions of fake-igd, as otp's --upgrade-check / --upgrade-online:\n"
            "  check              look at upgrade_url now: which versions are there, is one newer\n"
            "  online [VERSION]   fetch the newest (or VERSION), check its signature and every file,\n"
            "                     and have root put it in (fake-igd-upgrade.path) - followed here\n"
            "  file PATH          the same with a fake-igd-X.Y.Z.tar.gz you have\n"
            "  status             how the last upgrade went\n"
            "  follow             follow one going on, with its progress bar\n"
            "  log                what install.sh said the last time\n"
            "  after [ID]         what is to be done by hand after an update (ID: mark it done)\n"
            "  check --downgrade / online VERSION --downgrade   going back to an older version\n"
            "A package must be signed by a release key this machine trusts (/opt/fake-igd/release-keys),\n"
            "every file must be the one signed, and it must not be older than what is installed -\n"
            "going back is only by hand: sudo upnp upgrade file OLDER.tar.gz --downgrade.\n"
            "Nothing is ever put in by itself; upgrade_check only looks once a day (for the pages).",
            "examples:\n"
            "  upnp upgrade check\n"
            "  sudo upnp upgrade online\n"
            "  sudo upnp upgrade online 1.4.2 --yes\n"
            "  sudo upnp upgrade file /root/fake-igd-1.4.2.tar.gz\n"
            "  upnp upgrade follow\n"
            "the web: https://SERVER/admin/ → Settings → Upgrades", aliases=("up",))
    s.add_argument("what", nargs="?", choices=("check", "online", "file", "status", "follow", "log", "after"),
                   metavar="check|online|file|status|follow|log|after")
    s.add_argument("version", nargs="?", metavar="VERSION|PATH", help="the version (online) or the package (file)")
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.add_argument("--no-follow", action="store_true", help="ask root and leave - upnp upgrade follow later")
    s.add_argument("--downgrade", action="store_true", help="file/online: put an older version in; check: list the older ones")
    s.add_argument("--quiet", "-q", action="store_true", help="do not print what is new")
    s.add_argument("--json", action="store_true", help="JSON output (check, status)")
    s.add_argument("-n", "--lines", type=int, default=400, help="log: how many lines (default 400)")
    s.set_defaults(func=admin("cmd_upgrade"))

    s = add("user", "the local accounts of the web pages (SQLite)",
            "Who may sign in to the web pages (https://SERVER/admin/):\n"
            "  list                      every account, its role, when it last signed in\n"
            "  add NAME [--role R]       a new account (full admin unless --role readonly)\n"
            "  passwd NAME               a new password (its sign-ins end)\n"
            "  role NAME --role R        fulladmin (may change everything) or readonly (may look)\n"
            "  note NAME --note TEXT     a note\n"
            "  del NAME                  take an account away (never the last full admin)\n"
            "  sessions                  who is signed in now\n"
            "  end ID                    end one sign-in\n"
            "  must-change NAME          a new password asked for at its next sign-in\n"
            "  off NAME / on NAME        switch an account off (it may not sign in) and on again\n"
            "  reset-2fa NAME            the second step (the app, or the passkeys) taken away - set up again at\n"
            "                            sign-in\n"
            "  lockouts                  the names and addresses held back by wrong passwords\n"
            "  clear [NAME|ADDRESS]      let them try again at once (all of them without one)\n"
            "The password: --password - asks for it twice, --password @env takes UPNP_PASSWORD;\n"
            "without it one is made and printed once.",
            "examples:\n"
            "  sudo upnp user add alice\n"
            "  sudo upnp user add bob --role readonly --password -\n"
            "  sudo upnp user passwd admin\n"
            "  sudo upnp user list", aliases=("users",))
    s.add_argument("what", nargs="?", choices=("list", "add", "passwd", "role", "note", "must-change", "off", "on",
                                               "disable", "enable", "reset-2fa", "del", "sessions", "end",
                                               "lockouts", "clear", "lockouts-clear", "unlock"),
                   metavar="list|add|passwd|role|note|must-change|off|on|reset-2fa|del|sessions|end|lockouts|clear")
    s.add_argument("name", nargs="?", metavar="NAME|ID")
    s.add_argument("--role", choices=("fulladmin", "readonly"))
    s.add_argument("--password", metavar="-|@env", help="'-' asks for it, '@env' reads UPNP_PASSWORD")
    s.add_argument("--note", default=None)
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.add_argument("--json", action="store_true", help="JSON output (list, sessions)")
    s.set_defaults(func=admin("cmd_user"))

    s = add("web", "the web pages: their address, nginx, php-fpm, the API",
            "  status            the address of the pages and whether what serves them runs\n"
            "  apply             root puts nginx's allow list (web_allow) and the firewall in place\n"
            "  apply --restart   ... and restarts fake-igd.service",
            "examples:\n  upnp web\n  sudo upnp web apply")
    s.add_argument("what", nargs="?", choices=("status", "apply"), metavar="status|apply")
    s.add_argument("--restart", action="store_true", help="apply: restart fake-igd.service too")
    s.set_defaults(func=admin("cmd_web"))

    # What the pages do, here too (otp 1.0.187's section, 1.7.4): asked of fake-igd-api as root.
    pages_note = ("\nAsked of fake-igd-api as a full administrator - as root (sudo), with the key only root\n"
                  "may read (/run/fake-igd-api/cli-token); written down in the events as \"root (command line)\".")
    s = add("api", "any question of the web pages, answered as JSON (otp --api)",
            "Asks fake-igd-api what a page asks it, as a full administrator, and prints the answer.\n"
            "BODY is a JSON object; - reads it from stdin (a body holding a secret is only taken so)." + pages_note,
            "examples:\n"
            "  sudo upnp api GET /api/db\n"
            "  sudo upnp api GET '/api/events?q=kind:sign-in'\n"
            "  sudo upnp api POST /api/osup '{\"action\": \"check\"}'\n"
            "  sudo upnp api POST /api/settings - < changes.json")
    s.add_argument("method", metavar="GET|POST")
    s.add_argument("path", metavar="PATH")
    s.add_argument("body", nargs="?", metavar="BODY|-")
    s.set_defaults(func=admin("cmd_api"))

    s = add("events", "fake-igd's own events: sign-ins, settings, root's work (otp --events)",
            "The events the pages show under Events - newest last." + pages_note,
            "examples:\n  sudo upnp events\n  sudo upnp events --kind sign-in --hours 48\n"
            "  sudo upnp events --search 'level:warn'", aliases=("ev",))
    s.add_argument("--search", "-s", metavar="TEXT", help="only rows holding this (the pages' search language)")
    s.add_argument("--kind", metavar="KIND", help="only this kind (sign-in, setting, account, upgrade ...)")
    s.add_argument("--hours", type=float, metavar="N", help="the last N hours")
    s.add_argument("-n", "--limit", type=int, default=40, metavar="N", help="how many rows (default 40)")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_events"))

    s = add("check", "a health check of every part, as the pages' alerts (otp --check)",
            "The API, the database, the service and every problem the pages' alerts see\n"
            "(disks, mail, the certificate, the syslog servers ...). Exit status 1 on a problem." + pages_note,
            "example:\n  sudo upnp check")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_check"))

    s = add("backup", "the backups: their destinations, one now, the newest one tried (otp --rbackup-*)",
            "  status   the destinations and the last backups (default)\n"
            "  now      a backup to every destination switched on, now - followed with its progress\n"
            "  verify   the newest backup fetched back and tried" + pages_note,
            "examples:\n  sudo upnp backup\n  sudo upnp backup now")
    s.add_argument("what", nargs="?", choices=("status", "now", "verify"), metavar="status|now|verify")
    s.add_argument("--json", action="store_true", help="JSON output (status)")
    s.set_defaults(func=admin("cmd_backup"))

    s = add("db", "the database: its tables and copies, checked, tidied, given back to the disk",
            "  status   the file, its tables, its copies, the key of its secrets (default)\n"
            "  check    PRAGMA integrity_check\n"
            "  copy     a copy now, beside the others\n"
            "  tidy     forget the events older than they are kept\n"
            "  vacuum   give the disk back" + pages_note,
            "examples:\n  sudo upnp db\n  sudo upnp db check")
    s.add_argument("what", nargs="?", choices=("status", "check", "copy", "tidy", "vacuum"),
                   metavar="status|check|copy|tidy|vacuum")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_db"))

    s = add("updates", "the operating system's updates (dnf): look, put them in, restart (otp --updates)",
            "  status   what is waiting, and the last run (default)\n"
            "  check    look for updates now\n"
            "  start    put them in (--security: security updates only; --reboot auto|ask)\n"
            "  stop     stop it while dnf still asks and downloads\n"
            "  reboot   restart the machine an update asked for" + pages_note,
            "examples:\n  sudo upnp updates check\n  sudo upnp updates start --security --yes")
    s.add_argument("what", nargs="?", choices=("status", "check", "start", "stop", "reboot"),
                   metavar="status|check|start|stop|reboot")
    s.add_argument("--security", action="store_true", help="start: security updates only")
    s.add_argument("--reboot", choices=("ask", "auto"), help="start: restart by itself where needed (auto) or not")
    s.add_argument("--no-follow", action="store_true", help="ask root and leave")
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.add_argument("--json", action="store_true", help="JSON output (status)")
    s.set_defaults(func=admin("cmd_updates"))

    s = add("time", "the clock and its time servers (otp --ntp, --ntp-sync)",
            "  status   the time, chrony and its servers (default)\n"
            "  sync     step the clock to the servers now" + pages_note,
            "examples:\n  sudo upnp time\n  sudo upnp time sync")
    s.add_argument("what", nargs="?", choices=("status", "sync"), metavar="status|sync")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_time"))

    s = add("tls", "the certificate of the pages and their TLS settings (otp --web-status)",
            "The certificate nginx shows, its names and end, the protocols, DH, HSTS and ACME." + pages_note,
            "example:\n  sudo upnp tls")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_tls"))

    s = add("acme", "the certificate by ACME: how it stands, an order now (otp --acme, --acme-order)",
            "  status   the CA, the names, the certificate now, the last order (default)\n"
            "  order    order it now - followed here" + pages_note,
            "examples:\n  sudo upnp acme\n  sudo upnp acme order")
    s.add_argument("what", nargs="?", choices=("status", "order"), metavar="status|order")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_acme"))

    s = add("net", "the network of this machine as the pages read it (otp --net)",
            "Its devices, addresses, gateway and DNS servers." + pages_note, "example:\n  sudo upnp net")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_net"))

    for name, h, d, ex in (
            ("mail-test", "send a test mail now, every step said (otp --mail-test)",
             "A test mail to ADDRESS, as Settings → Mail → Send a test.", "sudo upnp mail-test ops@example.com"),
            ("siem-test", "a test line to the syslog servers (otp --siem-test)",
             "One line to every syslog server set (Settings → SIEM), and what each said.", "sudo upnp siem-test"),
            ("proxy-test", "the way out through the proxy tried (otp --proxy-test)",
             "URL (or upgrade_url) reached as fake-igd reaches it: through the proxy where it is set.",
             "sudo upnp proxy-test https://github.com/"),
            ("snmp-trap", "a test trap to the SNMP receivers (otp --snmp-trap)",
             "One trap to every receiver set (Settings → Monitoring).", "sudo upnp snmp-trap")):
        s = add(name, h, d + pages_note, "example:\n  " + ex)
        if name in ("mail-test", "proxy-test"):
            s.add_argument("target", nargs="?", metavar="ADDRESS" if name == "mail-test" else "URL")
        if name == "mail-test":
            s.add_argument("--kind", choices=("short", "alert", "report"), help="what is sent (default short)")
            s.add_argument("--straight", action="store_true", help="straight to the server, not by the queue")
        s.add_argument("--json", action="store_true", help="JSON output")
        s.set_defaults(func=admin("cmd_pane_test"))

    s = add("export-config", "everything of this installation into one file (otp --export-config)",
            "The settings, the panes' settings, the accounts, the backups' destinations, the firewall's rules\n"
            "and avahi's - as Settings → Export and import → Export. Without --with-secrets the secrets are\n"
            "left out; with it they are in, the file locked with a passphrase printed once." + pages_note,
            "examples:\n  sudo upnp export-config /root/fake-igd-config.json\n"
            "  sudo upnp export-config /root/fake-igd-all.json --with-secrets")
    s.add_argument("file", metavar="FILE", help="a new file (never written over)")
    s.add_argument("--with-secrets", action="store_true", help="with the secrets, locked with a passphrase")
    s.set_defaults(func=admin("cmd_carry"))

    s = add("import-config", "a file of export-config (or of the pages) put in (otp --import-config)",
            "What the file holds is shown first, then put in after a yes. A locked file asks for its\n"
            "passphrase (or UPNP_PASSPHRASE). --replace: what is not in the file is taken away." + pages_note,
            "examples:\n  sudo upnp import-config /root/fake-igd-config.json\n"
            "  sudo upnp import-config /root/fake-igd-all.json --replace --yes")
    s.add_argument("file", metavar="FILE")
    s.add_argument("--replace", action="store_true", help="exactly the file: what is not in it goes")
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.set_defaults(func=admin("cmd_carry"))

    s = add("power", "restart or power off this machine, now or later (otp --restart-nodes, --restarts)",
            "  status            what is set for later, the last ask, the restart on a schedule (default)\n"
            "  reboot [--in N]   restart it now or in N minutes\n"
            "  poweroff [--in N] power it off\n"
            "  cancel            what was set for later does not happen" + pages_note,
            "examples:\n  sudo upnp power\n  sudo upnp power reboot --in 10")
    s.add_argument("what", nargs="?", choices=("status", "reboot", "poweroff", "cancel"),
                   metavar="status|reboot|poweroff|cancel")
    s.add_argument("--in", dest="minutes", type=int, default=0, metavar="MIN", help="in so many minutes (0-1440)")
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.add_argument("--json", action="store_true", help="JSON output (status)")
    s.set_defaults(func=admin("cmd_power"))

    s = add("mikrotik", "the real router - a MikroTik - read only: does it carry the ports asked for? its firewall",
            "  status                  how it is read, and the ports it does not carry (default)\n"
            "  check                   every port asked for: open / no dst-nat / shadowed / disabled / dropped -\n"
            "                          and the RouterOS commands that would add what is missing (shown, never sent)\n"
            "  rules [ipv4|ipv6]       its firewall as read: filter, nat, mangle, raw (--table one of them)\n"
            "  read                    read it now\n"
            "  try                     sign in and say each step (Try reaching it)\n"
            "  Read-only: fake-igd only ever asks it to print. Set it up in Settings → MikroTik." + pages_note,
            "examples:\n  sudo upnp mikrotik\n  sudo upnp mikrotik check\n  sudo upnp mikrotik rules ipv4 --table nat")
    s.add_argument("what", nargs="?", choices=("status", "check", "rules", "read", "try"), metavar="status|check|rules|read|try")
    s.add_argument("family", nargs="?", choices=("ipv4", "ipv6"), help="rules: IPv4 (default) or IPv6")
    s.add_argument("--table", choices=("filter", "nat", "mangle", "raw"), help="rules: one table only")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.set_defaults(func=admin("cmd_mikrotik"))

    s = add("gateway", "this server as the default gateway of chosen devices (a PS5 asks UPnP only of its gateway)",
            "  status                  forwarding, fake-igd's chain, the devices and their packets (default)\n"
            "  on | off                switch the gateway for devices on (fake-igd's firewall must be on) or off\n"
            "  add IP --name NAME      a device: forwarded only for it, only toward the router\n"
            "      [--mac MAC | --mac-seen]   its MAC too (--mac-seen: as this server's neighbour table has it)\n"
            "  del IP                  the device taken away (the last one: the forwarding goes off with it)\n"
            "  keep | back             a change on trial kept, or put back now\n"
            "  dns IP add|del DNS [--dot]      the DNS servers the device may ask (udp+tcp 53, --dot: 853 too)\n"
            "  rule IP list | add --to NET [--proto tcp|udp|icmp|any] [--ports P] [--comment C] | del N\n"
            "                          its own rules: one destination each (another network of this server too)\n"
            "  try IP DEST PROTO [PORT]        a packet from the device through the rules: which one decides\n"
            "  top                     the devices: traffic, DNS, rules, drops (the Gateway tab)\n"
            "  conns IP                its live connections (conntrack)\n"
            "  Only in and out the interface of the default route, toward the router - never between this\n"
            "  server's networks; fake-igd's FORWARD chain ends in a DROP. IPv6 is never forwarded." + pages_note,
            "examples:\n  sudo upnp gateway\n  sudo upnp gateway add 192.168.40.95 --name \"PS5 Pro\" --mac-seen\n"
            "  sudo upnp gateway on\n  sudo upnp gateway keep\n  sudo upnp gateway dns 192.168.40.95 add 172.16.16.53\n"
            "  sudo upnp gateway rule 192.168.40.95 add --to 172.16.17.10 --proto tcp --ports 8080 --comment media\n"
            "  sudo upnp gateway try 192.168.40.95 172.16.17.10 tcp 8080")
    s.add_argument("what", nargs="?", choices=("status", "on", "off", "add", "del", "keep", "back", "dns", "rule",
                                                "try", "top", "conns"),
                   metavar="status|on|off|add|del|keep|back|dns|rule|try|top|conns")
    s.add_argument("ip", nargs="?", help="the device's IPv4 address (add, del, dns, rule, try, conns)")
    s.add_argument("rest", nargs="*", help="dns: add|del DNS · rule: list|add|del N · try: DEST PROTO [PORT]")
    s.add_argument("--to", default="", help="rule add: the destination (address or network)")
    s.add_argument("--proto", default="tcp", choices=("tcp", "udp", "icmp", "any"), help="rule add: the protocol")
    s.add_argument("--ports", default="", help="rule add: 8080, 8000-8100, 80,443")
    s.add_argument("--comment", default="", help="rule add: what it is for")
    s.add_argument("--dot", action="store_true", help="dns add: DNS over TLS (tcp 853) as well")
    s.add_argument("--name", default="", help="what it is (add)")
    s.add_argument("--mac", default="", help="its MAC address (add)")
    s.add_argument("--mac-seen", action="store_true", help="its MAC from this server's neighbour table (add)")
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.add_argument("--json", action="store_true", help="JSON output (status)")
    s.set_defaults(func=admin("cmd_gateway"))

    s = add("selinux", "SELinux on this server: how it stands, a step, the report (otp --selinux-check, --selinux)",
            "  check             the mode now and after a restart, fake-igd's module, the labels of its files,\n"
            "                    the boolean and ports it needs, what SELinux refused since the machine started\n"
            "                    (nothing is changed; exit 1 when something is not as fake-igd needs it)\n"
            "  prepare           disabled: permissive at the next start, every file labelled then, the module in\n"
            "                    (the machine is not restarted now); permissive: what fake-igd needs put in\n"
            "  apply             the same as prepare while permissive: module, labels, boolean, ports\n"
            "  enforce           permissive -> enforcing, now and after a restart - only when nothing is missing\n"
            "                    and nothing was refused\n"
            "  permissive        enforcing -> permissive, now and after a restart\n"
            "  look              everything SELinux refused, found out and sorted by what puts it right: a boolean,\n"
            "                    a label, a port, a rule of fake-igd's own local module - or why not from here\n"
            "  fix ID ... | --all  put right what look found (root finds it again first): setsebool, restorecon,\n"
            "                    semanage port, or a rule into fake-igd's local module fake_igd_local\n"
            "  rules [--take-away ID]  fake-igd's local rules - and one taken away again\n"
            "  report [FILE]     what SELinux says here, for whoever writes fake-igd's module, as one file\n"
            "                    (/root/fake-igd-selinux-report-NODE-DATE.tar.gz unless named); nothing changed\n"
            "As root; root's helper does it, the same as Settings → SELinux on the pages.",
            "examples:\n  sudo upnp selinux\n  sudo upnp selinux look\n  sudo upnp selinux fix --all\n"
            "  sudo upnp selinux fix 73f2d405a5f5\n  sudo upnp selinux rules --take-away 73f2d405a5f5\n"
            "  sudo upnp selinux prepare --yes\n  sudo upnp selinux enforce\n  sudo upnp selinux report")
    s.add_argument("what", nargs="?", choices=("check", "look", "fix", "rules", "prepare", "apply", "enforce",
                                               "permissive", "report"),
                   metavar="check|look|fix|rules|prepare|apply|enforce|permissive|report")
    s.add_argument("args", nargs="*", metavar="ID|FILE", help="fix: the findings' ids (look shows them); report: the file")
    s.add_argument("--all", action="store_true", help="fix: everything that can be put right here")
    s.add_argument("--take-away", metavar="ID", help="rules: take this rule out of fake-igd's local module")
    s.add_argument("--yes", "-y", action="store_true", help="do not ask")
    s.add_argument("--json", action="store_true", help="JSON output (check and the steps)")
    s.set_defaults(func=admin("cmd_selinux"))

    s = add("help", "help for a command", "upnp help <command> = upnp <command> --help")
    s.add_argument("topic", nargs="?", metavar="COMMAND")
    s.set_defaults(func=None)
    return p, sp


def main():
    # set up colours as early as possible (also for argparse error messages)
    mode = "auto"
    for i, a in enumerate(sys.argv):
        if a == "--no-color":
            mode = "never"
        elif a.startswith("--color="):
            mode = a.split("=", 1)[1]
        elif a == "--color" and i + 1 < len(sys.argv):
            mode = sys.argv[i + 1]
    colored = setup_colors(mode)
    if sys.version_info >= (3, 14):
        if colored and mode == "always":
            os.environ.setdefault("FORCE_COLOR", "1")
        elif not colored:
            os.environ["NO_COLOR"] = "1"

    parser, sp = build_parser()
    args = parser.parse_args()
    global NO_DNS, PAL
    NO_DNS = bool(getattr(args, "no_dns", False))
    PAL = Palette(colored)
    if args.console or args.console_at_login or args.console_users is not None:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import upnp_console
        args.config = getattr(args, "config", DEFAULT_CONFIG)
        if args.console_at_login or args.console_users is not None:
            sys.exit(upnp_console.at_login_cli(args.console_at_login, args.console_users, PAL))
        sys.exit(upnp_console.console_main(sys.modules[__name__], PAL, args.config))
    if not args.cmd:
        parser.print_help()
        return
    if args.cmd == "help":
        if args.topic and args.topic in sp.choices:
            sp.choices[args.topic].print_help()
        else:
            parser.print_help()
        return
    args.config = getattr(args, "config", DEFAULT_CONFIG)
    cfg = load_config(args.config)
    try:
        args.func(args, cfg)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:  # noqa: BLE001
            pass
    except KeyboardInterrupt:
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
