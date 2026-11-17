#!/usr/bin/env python3
"""
fake-igd - fake UPnP Internet Gateway Device (IGD v1).

Pretends to be a router with UPnP enabled on the LAN, but opens NOTHING. It only logs
which ports devices (e.g. a PS5) ask for, and can optionally send notifications.
Listens on all (or selected) network interfaces of the server.

Usage:
  fake-igd.py [--config /etc/fake-igd/config.json]            run the service
  fake-igd.py [--config ...] --summary                         print requested ports

Python 3.9+ standard library only (Linux).
"""
import argparse
import fcntl
import ipaddress
import json
import logging
import logging.handlers
import os
import random
import re
import signal
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

__version__ = '1.7.14'
VERSION = __version__
DEFAULT_CONFIG = "/etc/fake-igd/config.json"
DEFAULTS = {
    "mode": "active",              # active = answer like a UPnP router; passive = only log SSDP, never answer
    "mapping_response": "accept",  # accept = confirm AddPortMapping (nothing is opened); reject = refuse with error 501
    "igd_version": 1,              # 1 = InternetGatewayDevice:1 (WANIPConnection:1); 2 = IGD:2 as miniupnpd built with IGD2
    "http_port": 5000,
    "external_ip": "auto",
    "interfaces": [],
    "exclude_interfaces": ["lo"],
    "allowed_clients": [],
    "ntfy_url": "",                # https://ntfy.sh/topic or https://ntfy.example.com/topic (private server)
    "ntfy_token": "",              # access token (tk_...) for a private server - Authorization: Bearer
    "ntfy_user": "",               # or user + password (Basic auth)
    "ntfy_password": "",
    "ntfy_priority": 3,            # 1 min .. 5 max
    "ntfy_tags": "video_game",     # comma-separated tags / emoji names
    "ntfy_ca_file": "",            # CA bundle for a private server with its own certificate authority
    "notify_on_renew": False,
    "notify_other_router": True,   # notify when another UPnP router announces itself
    "log_level": "INFO",
    "log_file": "/var/log/fake-igd/fake-igd.log",
    "request_log": "/var/log/fake-igd/requests.jsonl",
    "state_dir": "/var/lib/fake-igd",
    "interface_rescan_seconds": 60,
    "notify_interval_seconds": 300,
    # Not this daemon's - the web pages', the firewall's and the upgrades' (1.4.0):
    "site_name": "",               # what the pages call this installation (empty = the host name)
    "api_port": 9862,              # the API the pages ask, on 127.0.0.1 (fake-igd-api.service)
    "session_idle_minutes": 120,   # a sign-in to the pages ends after this long without a request
    "web_allow": ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"],   # who may reach the pages (nginx allow)
    "firewall": False,             # iptables: fake-igd's own chain FAKE-IGD-IN, jumped to first from INPUT
    "firewall_ssh": True,          # ... with SSH (tcp 22) let in
    "firewall_icmp": True,         # ... and ping
    "upgrade_url": "https://github.com/falco81/fake-idg/tree/main/release",
    "upgrade_check": True,         # look at upgrade_url once a day
}

SOAP_MOST = 64 * 1024            # a SOAP request larger than this is refused (413) - real ones are < 2 KB
MAPPINGS_MOST = 1024             # port mappings held at most; more is answered 728 NoPortMapsAvailable
DESC_MOST = 256                  # a description longer than this is cut (it goes to the log and the pages)
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900
SERVER_HDR = "Linux/5 UPnP/1.0 fake-igd/" + VERSION
START_TIME = time.time()

IGD_V = 1                        # igd_version: what the device says it is (set in main)
T_IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
T_WAN = "urn:schemas-upnp-org:device:WANDevice:1"
T_CONN = "urn:schemas-upnp-org:device:WANConnectionDevice:1"
S_IPC = "urn:schemas-upnp-org:service:WANIPConnection:1"
S_CIC = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"     # :1 in IGD:2 too (as miniupnpd)
LEASE_V2 = 604800                # IGD:2 - a lease of 0 (or longer) is a week (WANIPConnection:2, 2.3.16)
TYPE_RE = re.compile(r"^(urn:[^:\s]+:(?:device|service):[^:\s]+):(\d{1,3})$")


def set_version(v):
    """The device types and the control of WANIPConnection as igd_version says."""
    global IGD_V, T_IGD, T_WAN, T_CONN, S_IPC
    IGD_V = 2 if int(v or 1) == 2 else 1
    T_IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:%d" % IGD_V
    T_WAN = "urn:schemas-upnp-org:device:WANDevice:%d" % IGD_V
    T_CONN = "urn:schemas-upnp-org:device:WANConnectionDevice:%d" % IGD_V
    S_IPC = "urn:schemas-upnp-org:service:WANIPConnection:%d" % IGD_V
    CONTROL["/ctl/IPConn"] = (S_IPC, handle_ipc)


# What is said in the log at info level only once in a while for the same client and thing (1.7.4): a
# device that asks again and again is seen, without a line every second.
_SAID = {}
_SAID_LOCK = threading.Lock()


SEARCH_EVERY = 30


def once(key, every=600):
    t = time.time()
    with _SAID_LOCK:
        if t - _SAID.get(key, 0) < every:
            return False
        if len(_SAID) > 8192:
            for k in [k for k, v in _SAID.items() if t - v > 3600]:
                del _SAID[k]
            if len(_SAID) > 8192:
                _SAID.clear()
        _SAID[key] = t
        return True


def ua_words(ua):
    ua = re.sub(r"[\x00-\x1f\x7f]", " ", str(ua or "")).strip()[:160]
    return ua or "-"

log = logging.getLogger("fake-igd")
CFG = {}
ALLOWED_NETS = []
EXTERNAL_IP = ""
UUID_ROOT = UUID_WAN = UUID_CONN = ""
ADVERTS = []
BOOTID = 1                       # BOOTID.UPNP.ORG: the start of the service (seconds), as miniupnpd - it grows


# ================================================================ konfigurace
def load_config(path):
    cfg = dict(DEFAULTS)
    try:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
    except FileNotFoundError:
        print("Config %s does not exist, using defaults." % path, file=sys.stderr)
        user = {}
    except json.JSONDecodeError as e:
        print("JSON error in config %s: %s" % (path, e), file=sys.stderr)
        sys.exit(2)
    # Keys of the pages' that have no default on purpose (1.7.0): health_allow - never set, the health
    # check follows web_allow.
    unknown = set(user) - set(DEFAULTS) - {"health_allow"}
    cfg.update(user)
    cfg["_unknown_keys"] = sorted(k for k in unknown if not k.startswith("_"))
    cfg["mode"] = str(cfg["mode"]).lower()
    cfg["mapping_response"] = str(cfg["mapping_response"]).lower()
    if cfg["mode"] not in ("active", "passive"):
        print("Invalid mode: %r (active/passive)" % cfg["mode"], file=sys.stderr)
        sys.exit(2)
    if cfg["mapping_response"] not in ("accept", "reject"):
        print("Invalid mapping_response: %r (accept/reject)" % cfg["mapping_response"], file=sys.stderr)
        sys.exit(2)
    try:
        cfg["igd_version"] = int(cfg["igd_version"])
        assert cfg["igd_version"] in (1, 2)
    except (TypeError, ValueError, AssertionError):
        print("Invalid igd_version: %r (1/2)" % cfg["igd_version"], file=sys.stderr)
        sys.exit(2)
    try:
        cfg["http_port"] = int(cfg["http_port"])
        assert 0 < cfg["http_port"] < 65536
    except (ValueError, AssertionError):
        print("Invalid http_port: %r" % cfg["http_port"], file=sys.stderr)
        sys.exit(2)
    return cfg


def parse_allowed(items):
    nets = []
    for it in items:
        try:
            nets.append(ipaddress.ip_network(str(it).strip(), strict=False))
        except ValueError:
            print("Invalid entry in allowed_clients: %r" % it, file=sys.stderr)
            sys.exit(2)
    return nets


class OtpFormatter(logging.Formatter):
    """Lines as otp writes them: 'YYYY-MM-DD HH:MM:SS level what: words', the level lower case
    (info, warn, error, debug, crit); control characters shown, a newline continued indented."""
    LEVELS = {"DEBUG": "debug", "INFO": "info", "WARNING": "warn", "ERROR": "error", "CRITICAL": "crit"}

    def __init__(self, with_time=True):
        super().__init__()
        self.with_time = with_time

    def format(self, record):
        words = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", lambda m: "\\x%02x" % ord(m.group(0)),
                       record.getMessage()).replace("\n", "\n    ")
        lvl = self.LEVELS.get(record.levelname, "info")
        if not self.with_time:
            return "%-5s %s" % (lvl, words)
        return "%s %-5s %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created)), lvl, words)


def setup_logging(cfg):
    level = getattr(logging, str(cfg["log_level"]).upper(), logging.INFO)
    fmt = OtpFormatter()
    log.setLevel(level)
    log.handlers.clear()
    try:
        os.makedirs(os.path.dirname(cfg["log_file"]), exist_ok=True)
        fh = logging.handlers.WatchedFileHandler(cfg["log_file"], encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError as e:
        print("Cannot open log %s: %s" % (cfg["log_file"], e), file=sys.stderr)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(OtpFormatter(with_time=False))
    log.addHandler(sh)


def client_allowed(ip):
    if not ALLOWED_NETS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in ALLOWED_NETS)


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ================================================================ interfaces
SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
IFF_UP = 0x1
IFF_LOOPBACK = 0x8
IFF_MULTICAST = 0x1000


def _ioctl(sock, req, name):
    return fcntl.ioctl(sock.fileno(), req, struct.pack("256s", name[:15].encode()))


def list_interfaces():
    """Return {name: ipv4} of active interfaces with IPv4, according to the config."""
    want = set(CFG["interfaces"])
    skip = set(CFG["exclude_interfaces"])
    result = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _, name in socket.if_nameindex():
            if want and name not in want:
                continue
            if name in skip:
                continue
            try:
                flags = struct.unpack("H", _ioctl(s, SIOCGIFFLAGS, name)[16:18])[0]
                if not flags & IFF_UP:
                    continue
                if flags & IFF_LOOPBACK and not want:
                    continue
                if not flags & IFF_MULTICAST:
                    log.debug("net: %s does not support multicast - skipped", name)
                    continue
                ip = socket.inet_ntoa(_ioctl(s, SIOCGIFADDR, name)[20:24])
            except OSError:
                continue  # bez IPv4
            result[name] = ip
    finally:
        s.close()
    return result


def local_ip_for(client_ip):
    """Local IP through which the server reaches the client (used for LOCATION)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((client_ip, SSDP_PORT))
        return s.getsockname()[0]
    finally:
        s.close()


def location_url(local_ip):
    return "http://%s:%d/rootDesc.xml" % (local_ip, CFG["http_port"])


# ================================================================ external IP
def resolve_external_ip():
    global EXTERNAL_IP
    val = str(CFG["external_ip"]).strip()
    if val and val.lower() != "auto":
        EXTERNAL_IP = val
        return
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                EXTERNAL_IP = r.read().decode().strip()
            log.info("net: the public IP is %s (from %s)", EXTERNAL_IP, url)
            return
        except Exception as e:  # noqa: BLE001
            log.warning("net: looking up the public IP at %s failed: %s", url, e)
    EXTERNAL_IP = ""
    log.warning("net: the public IP could not be found - set external_ip in the config")


# ================================================================ state and request log
_lock = threading.Lock()
mappings = {}  # (remote_host, external_port, protocol) -> dict


def record(event):
    event = dict(event, time=now_iso())
    try:
        with open(CFG["request_log"], "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("service: %s cannot be written: %s", CFG["request_log"], e)


def map_file():
    return os.path.join(CFG["state_dir"], "mappings.json")


def save_mappings():
    data = [dict(m, remote_host=k[0], external_port=k[1], protocol=k[2]) for k, m in mappings.items()]
    try:
        tmp = map_file() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, map_file())
    except OSError as e:
        log.warning("service: %s cannot be written: %s", map_file(), e)


def load_mappings():
    """The mappings held before a restart (mappings.json) - kept, as a router keeps its leases: the
    Mappings tab shows that file, and a device that asks GetSpecificPortMappingEntry after a restart
    of the service finds its own. What ran out meanwhile, or is not a mapping, is left out."""
    try:
        with open(map_file(), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as e:
        log.warning("service: %s cannot be read, the mappings start empty: %s", map_file(), e)
        return
    t = time.time()
    for m in data if isinstance(data, list) else []:
        try:
            key = (str(m.get("remote_host") or "")[:64], int(m["external_port"]), str(m["protocol"]).upper())
            if key[2] not in ("TCP", "UDP") or not 0 < key[1] < 65536:
                continue
            if m.get("expires_at") and float(m["expires_at"]) < t:
                continue
            if not 0 <= int(m.get("lease") or 0) <= 0xFFFFFFFF:
                continue
            mappings[key] = {"internal_client": str(m["internal_client"]), "internal_port": int(m["internal_port"]),
                             "description": str(m.get("description") or "")[:DESC_MOST],
                             "enabled": bool(m.get("enabled", True)), "lease": int(m.get("lease") or 0),
                             "expires_at": float(m["expires_at"]) if m.get("expires_at") else None,
                             "requested_by": str(m.get("requested_by") or ""), "added_at": str(m.get("added_at") or "")}
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if len(mappings) >= MAPPINGS_MOST:
            break
    if mappings:
        log.info("service: %d mapping(s) held before the restart kept (%s)", len(mappings), map_file())


def purge_expired():
    t = time.time()
    dead = [k for k, m in mappings.items() if m.get("expires_at") and m["expires_at"] < t]
    for k in dead:
        log.info("port: %s %d of %s expired", k[2], k[1], mappings[k]["internal_client"])
        record({"action": "Expired", "protocol": k[2], "external_port": k[1],
                "internal_client": mappings[k]["internal_client"]})
        del mappings[k]
    if dead:
        save_mappings()


def _hdr(value):
    """A header value: plain ASCII as it is, anything else as an RFC 2047 encoded word (ntfy reads it)."""
    v = str(value)
    try:
        v.encode("ascii")
        return v
    except UnicodeEncodeError:
        import base64
        return "=?UTF-8?B?%s?=" % base64.b64encode(v.encode("utf-8")).decode()


def ntfy_send(cfg, title, message, priority=None, tags=None, timeout=10):
    """One message to ntfy (ntfy.sh or a private server). Returns (ok, words)."""
    import base64
    import ssl
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
        return False, str(getattr(e, "reason", e))


def ntfy_words(cfg):
    """How notifications go, for the log - never the secret itself."""
    url = str(cfg.get("ntfy_url") or "")
    if not url:
        return "off"
    auth = "token" if cfg.get("ntfy_token") else ("user %s" % cfg["ntfy_user"] if cfg.get("ntfy_user") else "no auth")
    return "ntfy %s (%s%s)" % (url, auth, ", own CA" if cfg.get("ntfy_ca_file") else "")


def notify(title, message, priority=None, tags=None):
    if not CFG.get("ntfy_url"):
        return

    def _send():
        ok, words = ntfy_send(CFG, title, message, priority, tags)
        host = urllib.parse.urlparse(CFG["ntfy_url"]).netloc
        if ok:
            log.info("notify: sent '%s' to %s (%s)", title, host, words)
        else:
            log.warning("notify: sending '%s' to %s failed: %s", title, host, words)

    threading.Thread(target=_send, daemon=True).start()


# ================================================================ XML descriptions
def device_xml(local_ip):
    base = "http://%s:%d" % (local_ip, CFG["http_port"])

    def svc(stype, sid, scpd, ctl, evt):
        return ("<service><serviceType>%s</serviceType><serviceId>%s</serviceId><SCPDURL>%s</SCPDURL>"
                "<controlURL>%s</controlURL><eventSubURL>%s</eventSubURL></service>") % (stype, sid, scpd, ctl, evt)

    return (
        '<?xml version="1.0"?>\n<root xmlns="urn:schemas-upnp-org:device-1-0">'
        "<specVersion><major>1</major><minor>0</minor></specVersion><URLBase>%(base)s/</URLBase>"
        "<device><deviceType>%(igd)s</deviceType><friendlyName>fake-igd</friendlyName>"
        "<manufacturer>fake-igd</manufacturer><modelName>fake-igd</modelName><modelNumber>%(ver)s</modelNumber>"
        "<UDN>uuid:%(u1)s</UDN><serviceList></serviceList>"
        "<deviceList><device><deviceType>%(wan)s</deviceType><friendlyName>WAN Device</friendlyName>"
        "<manufacturer>fake-igd</manufacturer><modelName>WAN Device</modelName><UDN>uuid:%(u2)s</UDN>"
        "<serviceList>%(cic)s</serviceList>"
        "<deviceList><device><deviceType>%(conn)s</deviceType><friendlyName>WAN Connection Device</friendlyName>"
        "<manufacturer>fake-igd</manufacturer><modelName>WAN Connection Device</modelName><UDN>uuid:%(u3)s</UDN>"
        "<serviceList>%(ipc)s</serviceList></device></deviceList></device></deviceList>"
        "<presentationURL>https://%(ip)s/admin/</presentationURL></device></root>"
    ) % {
        "base": base, "ip": local_ip, "igd": T_IGD, "wan": T_WAN, "conn": T_CONN, "ver": VERSION,
        "u1": UUID_ROOT, "u2": UUID_WAN, "u3": UUID_CONN,
        "cic": svc(S_CIC, "urn:upnp-org:serviceId:WANCommonIFC1", "/WANCfg.xml", "/ctl/CmnIfCfg", "/evt/CmnIfCfg"),
        "ipc": svc(S_IPC, "urn:upnp-org:serviceId:WANIPConn1", "/WANIPCn.xml", "/ctl/IPConn", "/evt/IPConn"),
    }


PM_KEY = [("NewRemoteHost", "RemoteHost"), ("NewExternalPort", "ExternalPort"), ("NewProtocol", "PortMappingProtocol")]
PM_OUT = [("NewInternalPort", "InternalPort"), ("NewInternalClient", "InternalClient"),
          ("NewEnabled", "PortMappingEnabled"), ("NewPortMappingDescription", "PortMappingDescription"),
          ("NewLeaseDuration", "PortMappingLeaseDuration")]
IPC_ACTIONS = {
    "GetConnectionTypeInfo": ([], [("NewConnectionType", "ConnectionType"), ("NewPossibleConnectionTypes", "PossibleConnectionTypes")]),
    "GetStatusInfo": ([], [("NewConnectionStatus", "ConnectionStatus"), ("NewLastConnectionError", "LastConnectionError"), ("NewUptime", "Uptime")]),
    "GetNATRSIPStatus": ([], [("NewRSIPAvailable", "RSIPAvailable"), ("NewNATEnabled", "NATEnabled")]),
    "GetExternalIPAddress": ([], [("NewExternalIPAddress", "ExternalIPAddress")]),
    "AddPortMapping": (PM_KEY + PM_OUT, []),
    "DeletePortMapping": (PM_KEY, []),
    "GetSpecificPortMappingEntry": (PM_KEY, PM_OUT),
    "GetGenericPortMappingEntry": ([("NewPortMappingIndex", "PortMappingNumberOfEntries")], PM_KEY + PM_OUT),
}
IPC_VARS = [
    ("ConnectionType", "string", "no"), ("PossibleConnectionTypes", "string", "yes"),
    ("ConnectionStatus", "string", "yes"), ("Uptime", "ui4", "no"), ("LastConnectionError", "string", "no"),
    ("RSIPAvailable", "boolean", "no"), ("NATEnabled", "boolean", "no"), ("ExternalIPAddress", "string", "yes"),
    ("PortMappingNumberOfEntries", "ui2", "yes"), ("PortMappingEnabled", "boolean", "no"),
    ("PortMappingLeaseDuration", "ui4", "no"), ("RemoteHost", "string", "no"), ("ExternalPort", "ui2", "no"),
    ("InternalPort", "ui2", "no"), ("PortMappingProtocol", "string", "no"), ("InternalClient", "string", "no"),
    ("PortMappingDescription", "string", "no"),
]
IPC_ACTIONS_2 = dict(IPC_ACTIONS, **{
    "AddAnyPortMapping": (PM_KEY + PM_OUT, [("NewReservedPort", "ExternalPort")]),
    "DeletePortMappingRange": ([("NewStartPort", "ExternalPort"), ("NewEndPort", "ExternalPort"),
                                ("NewProtocol", "PortMappingProtocol"), ("NewManage", "A_ARG_TYPE_Manage")], []),
    "GetListOfPortMappings": ([("NewStartPort", "ExternalPort"), ("NewEndPort", "ExternalPort"),
                               ("NewProtocol", "PortMappingProtocol"), ("NewManage", "A_ARG_TYPE_Manage"),
                               ("NewNumberOfPorts", "PortMappingNumberOfEntries")],
                              [("NewPortListing", "A_ARG_TYPE_PortListing")]),
})
IPC_VARS_2 = IPC_VARS + [("SystemUpdateID", "ui4", "yes"), ("A_ARG_TYPE_Manage", "boolean", "no"),
                         ("A_ARG_TYPE_PortListing", "string", "no")]
CIC_ACTIONS = {
    "GetCommonLinkProperties": ([], [
        ("NewWANAccessType", "WANAccessType"), ("NewLayer1UpstreamMaxBitRate", "Layer1UpstreamMaxBitRate"),
        ("NewLayer1DownstreamMaxBitRate", "Layer1DownstreamMaxBitRate"), ("NewPhysicalLinkStatus", "PhysicalLinkStatus")]),
    "GetTotalBytesSent": ([], [("NewTotalBytesSent", "TotalBytesSent")]),
    "GetTotalBytesReceived": ([], [("NewTotalBytesReceived", "TotalBytesReceived")]),
    "GetTotalPacketsSent": ([], [("NewTotalPacketsSent", "TotalPacketsSent")]),
    "GetTotalPacketsReceived": ([], [("NewTotalPacketsReceived", "TotalPacketsReceived")]),
}
CIC_VARS = [
    ("WANAccessType", "string", "no"), ("Layer1UpstreamMaxBitRate", "ui4", "no"),
    ("Layer1DownstreamMaxBitRate", "ui4", "no"), ("PhysicalLinkStatus", "string", "yes"),
    ("TotalBytesSent", "ui4", "no"), ("TotalBytesReceived", "ui4", "no"),
    ("TotalPacketsSent", "ui4", "no"), ("TotalPacketsReceived", "ui4", "no"),
]


def scpd_xml(actions, variables):
    p = ['<?xml version="1.0"?>\n<scpd xmlns="urn:schemas-upnp-org:service-1-0">'
         "<specVersion><major>1</major><minor>0</minor></specVersion><actionList>"]
    for name, (ins, outs) in actions.items():
        p.append("<action><name>%s</name><argumentList>" % name)
        for d, args in (("in", ins), ("out", outs)):
            for arg, rel in args:
                p.append("<argument><name>%s</name><direction>%s</direction>"
                         "<relatedStateVariable>%s</relatedStateVariable></argument>" % (arg, d, rel))
        p.append("</argumentList></action>")
    p.append("</actionList><serviceStateTable>")
    for name, dtype, ev in variables:
        p.append('<stateVariable sendEvents="%s"><name>%s</name><dataType>%s</dataType></stateVariable>' % (ev, name, dtype))
    p.append("</serviceStateTable></scpd>")
    return "".join(p)


# ================================================================ SOAP
class UPnPError(Exception):
    def __init__(self, code, desc):
        super().__init__(desc)
        self.code, self.desc = code, desc


ENV_OPEN = ('<?xml version="1.0"?>\n<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>')
ENV_CLOSE = "</s:Body></s:Envelope>"


class CData(str):
    """A value sent as it is, in CDATA - the port listing of GetListOfPortMappings, as miniupnpd sends it
    (miniupnpc reads it so, not escaped)."""


def soap_response(service, action, args):
    body = "".join("<%s>%s</%s>" % (k, ("<![CDATA[%s]]>" % v.replace("]]>", "]]&gt;")) if isinstance(v, CData)
                                    else escape(str(v)), k) for k, v in args)
    return ENV_OPEN + '<u:%sResponse xmlns:u="%s">%s</u:%sResponse>' % (action, service, body, action) + ENV_CLOSE


def soap_fault(code, desc):
    return (ENV_OPEN + "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"
            '<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode>'
            "<errorDescription>%s</errorDescription></UPnPError></detail></s:Fault>" % (code, escape(desc)) + ENV_CLOSE)


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_soap(body):
    root = ET.fromstring(body)
    for el in root:
        if local_name(el.tag) == "Body":
            for act in el:
                return local_name(act.tag), {local_name(c.tag): (c.text or "").strip() for c in act}
    raise ValueError("SOAP Body not found")


def entry_args(key, m, with_key):
    out = [("NewRemoteHost", key[0]), ("NewExternalPort", key[1]), ("NewProtocol", key[2])] if with_key else []
    lease = max(0, int(m["expires_at"] - time.time())) if m.get("expires_at") else m["lease"]
    return out + [("NewInternalPort", m["internal_port"]), ("NewInternalClient", m["internal_client"]),
                  ("NewEnabled", 1 if m["enabled"] else 0), ("NewPortMappingDescription", m["description"]),
                  ("NewLeaseDuration", lease)]


def _key(a, strict=True):
    """(remote host, external port, protocol) of a request - with strict, only TCP or UDP and a port
    1-65535 (anything else is 402 Invalid Args, as miniupnpd answers)."""
    try:
        key = (a.get("NewRemoteHost", "")[:64], int(a.get("NewExternalPort", "0")), a.get("NewProtocol", "").upper())
    except ValueError:
        raise UPnPError(402, "Invalid Args")
    if strict and (key[2] not in ("TCP", "UDP") or not 0 < key[1] < 65536):
        raise UPnPError(402, "Invalid Args")
    return key


def _free_port(key, ic):
    """AddAnyPortMapping: the port asked for when it is free (or already this client's), else the next
    free one above it (wrapping round past 1024), as miniupnpd picks one."""
    if key not in mappings or mappings[key]["internal_client"] == ic:
        return key
    port = key[1]
    for _ in range(65535):
        port = port + 1 if port < 65535 else 1024
        k = (key[0], port, key[2])
        if k not in mappings:
            return k
    raise UPnPError(728, "NoPortMapsAvailable")


def _add(action, a, client):
    key = _key(a)
    try:
        iport = int(a.get("NewInternalPort", "0"))
        lease = int(a.get("NewLeaseDuration", "0") or 0)
        ic = str(ipaddress.IPv4Address(a.get("NewInternalClient", "") or client))
    except ValueError:
        raise UPnPError(402, "Invalid Args")
    # the lease is a ui4; the internal client an IPv4 address (a name, or rubbish, is refused)
    if not (0 < iport < 65536) or not (0 <= lease <= 0xFFFFFFFF):
        raise UPnPError(402, "Invalid Args")
    if IGD_V == 2 and (lease == 0 or lease > LEASE_V2):
        lease = LEASE_V2
    desc = a.get("NewPortMappingDescription", "")[:DESC_MOST]
    asked = key
    if action == "AddAnyPortMapping":
        key = _free_port(key, ic)
    # written as AddPortMapping (the Ports tab, the report, SNMP count those), with how it was asked
    ev = {"action": "AddPortMapping", "client": client, "protocol": key[2], "external_port": key[1],
          "internal_client": ic, "internal_port": iport, "lease": lease, "description": desc,
          "remote_host": key[0]}
    if action != "AddPortMapping":
        ev["asked_as"] = action
    if key != asked:
        ev["asked_port"] = asked[1]
    if CFG["mapping_response"] == "reject":
        log.info("port: %s %d -> %s:%d asked by %s (lease %s, '%s') - rejected (mapping_response reject)",
                 key[2], key[1], ic, iport, client, ("%ds" % lease) if lease else "unlimited", desc)
        record(dict(ev, result="rejected"))
        notify("UPnP: %s %d" % (key[2], key[1]), "%s asks for %s %d -> %s:%d '%s' (rejected)" % (
            client, key[2], key[1], ic, iport, desc))
        raise UPnPError(501, "ActionFailed")
    old = mappings.get(key)
    if old and old["internal_client"] != ic:
        log.warning("port: %s %d already belongs to %s, asked for %s by %s - refused (conflict)",
                    key[2], key[1], old["internal_client"], ic, client)
        record(dict(ev, result="conflict"))
        raise UPnPError(718, "ConflictInMappingEntry")
    renew = old is not None
    if not renew and len(mappings) >= MAPPINGS_MOST:
        log.warning("port: %s %d asked by %s - refused, %d mappings are held already", key[2], key[1],
                    client, len(mappings))
        record(dict(ev, result="full"))
        raise UPnPError(728, "NoPortMapsAvailable")
    mappings[key] = {"internal_client": ic, "internal_port": iport, "description": desc,
                     "enabled": a.get("NewEnabled", "1") in ("1", "true", "yes"), "lease": lease,
                     "expires_at": (time.time() + lease) if lease else None, "requested_by": client,
                     "added_at": old["added_at"] if old else now_iso()}
    save_mappings()
    record(dict(ev, result="ok", renew=renew))
    lw = ("%ds" % lease) if lease else "unlimited"
    log.info("port: %s %d -> %s:%d asked by %s (lease %s, '%s') - accepted, %s%s",
             key[2], key[1], ic, iport, client, lw, desc, "renewed" if renew else "new",
             (" (port %d was taken)" % asked[1]) if key != asked else "")
    if not renew or CFG.get("notify_on_renew"):
        notify("UPnP: %s %d" % (key[2], key[1]), "%s asks for %s %d -> %s:%d '%s' (lease %s)%s" % (
            client, key[2], key[1], ic, iport, desc, lw, " - renewed" if renew else ""))
    if ic != client:
        log.warning("port: %s asks for a mapping to another IP (%s)", client, ic)
    return [("NewReservedPort", key[1])] if action == "AddAnyPortMapping" else []


def _range(a):
    """(start, end, protocol, manage) of DeletePortMappingRange / GetListOfPortMappings."""
    try:
        lo, hi = int(a.get("NewStartPort", "")), int(a.get("NewEndPort", ""))
    except ValueError:
        raise UPnPError(402, "Invalid Args")
    proto = a.get("NewProtocol", "").upper()
    if proto not in ("TCP", "UDP") or not (0 <= lo <= 65535 and 0 <= hi <= 65535):
        raise UPnPError(402, "Invalid Args")
    if lo > hi:
        raise UPnPError(733, "InconsistentParameters")
    return lo, hi, proto, a.get("NewManage", "0").lower() in ("1", "true", "yes")


def port_listing(items):
    """WANIPConnection:2's A_ARG_TYPE_PortListing (an XML document, sent escaped in the answer)."""
    rows = []
    for k, m in items:
        lease = max(0, int(m["expires_at"] - time.time())) if m.get("expires_at") else m["lease"]
        rows.append("<p:PortMappingEntry><p:NewRemoteHost>%s</p:NewRemoteHost><p:NewExternalPort>%d"
                    "</p:NewExternalPort><p:NewProtocol>%s</p:NewProtocol><p:NewInternalPort>%d</p:NewInternalPort>"
                    "<p:NewInternalClient>%s</p:NewInternalClient><p:NewEnabled>%d</p:NewEnabled>"
                    "<p:NewDescription>%s</p:NewDescription><p:NewLeaseTime>%d</p:NewLeaseTime></p:PortMappingEntry>"
                    % (escape(k[0]), k[1], k[2], m["internal_port"], escape(m["internal_client"]),
                       1 if m["enabled"] else 0, escape(m["description"]), lease))
    return ('<?xml version="1.0" encoding="UTF-8"?><p:PortMappingList '
            'xmlns:p="urn:schemas-upnp-org:gw:WANIPConnection" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xsi:schemaLocation="urn:schemas-upnp-org:gw:WANIPConnection '
            'http://www.upnp.org/schemas/gw/WANIPConnection-v2.xsd">%s</p:PortMappingList>' % "".join(rows))


def handle_ipc(action, a, client):
    if action == "GetExternalIPAddress":
        return [("NewExternalIPAddress", EXTERNAL_IP)]
    if action == "GetStatusInfo":
        return [("NewConnectionStatus", "Connected"), ("NewLastConnectionError", "ERROR_NONE"),
                ("NewUptime", int(time.time() - START_TIME))]
    if action == "GetConnectionTypeInfo":
        return [("NewConnectionType", "IP_Routed"), ("NewPossibleConnectionTypes", "IP_Routed")]
    if action == "GetNATRSIPStatus":
        return [("NewRSIPAvailable", 0), ("NewNATEnabled", 1)]
    v2 = ("AddAnyPortMapping", "DeletePortMappingRange", "GetListOfPortMappings")
    if action in v2 and IGD_V != 2:
        raise UPnPError(401, "Invalid Action")

    with _lock:
        purge_expired()
        if action in ("AddPortMapping", "AddAnyPortMapping"):
            return _add(action, a, client)

        if action == "DeletePortMapping":
            key = _key(a)
            record({"action": action, "client": client, "protocol": key[2], "external_port": key[1]})
            if key not in mappings:
                log.info("port: %s %d deleted by %s - there was none", key[2], key[1], client)
                raise UPnPError(714, "NoSuchEntryInArray")
            del mappings[key]
            save_mappings()
            log.info("port: %s %d deleted by %s", key[2], key[1], client)
            return []

        if action == "DeletePortMappingRange":
            lo, hi, proto, manage = _range(a)
            gone = [k for k, m in mappings.items() if k[2] == proto and lo <= k[1] <= hi
                    and (manage or m["internal_client"] == client)]
            record({"action": action, "client": client, "protocol": proto, "external_port": lo, "end_port": hi,
                    "result": "ok" if gone else "none"})
            if not gone:
                log.info("port: %s %d-%d deleted by %s - there was none", proto, lo, hi, client)
                raise UPnPError(730, "PortMappingNotFound")
            for k in gone:
                del mappings[k]
            save_mappings()
            log.info("port: %s %d-%d deleted by %s (%d mapping(s))", proto, lo, hi, client, len(gone))
            return []

        if action == "GetListOfPortMappings":
            lo, hi, proto, manage = _range(a)
            try:
                most = int(a.get("NewNumberOfPorts", "0") or 0)
            except ValueError:
                raise UPnPError(402, "Invalid Args")
            items = sorted(((k, m) for k, m in mappings.items() if k[2] == proto and lo <= k[1] <= hi
                            and (manage or m["internal_client"] == client)), key=lambda x: x[0][1])
            if most > 0:
                items = items[:most]
            if not items:
                raise UPnPError(730, "PortMappingNotFound")
            return [("NewPortListing", CData(port_listing(items)))]

        if action == "GetSpecificPortMappingEntry":
            key = _key(a)
            if key not in mappings:
                raise UPnPError(714, "NoSuchEntryInArray")
            return entry_args(key, mappings[key], False)

        if action == "GetGenericPortMappingEntry":
            try:
                idx = int(a.get("NewPortMappingIndex", "-1"))
            except ValueError:
                raise UPnPError(402, "Invalid Args")
            items = list(mappings.items())
            if not 0 <= idx < len(items):
                raise UPnPError(713, "SpecifiedArrayIndexInvalid")
            return entry_args(items[idx][0], items[idx][1], True)

    raise UPnPError(401, "Invalid Action")


def handle_cic(action, a, client):
    if action == "GetCommonLinkProperties":
        return [("NewWANAccessType", "Ethernet"), ("NewLayer1UpstreamMaxBitRate", 1000000000),
                ("NewLayer1DownstreamMaxBitRate", 1000000000), ("NewPhysicalLinkStatus", "Up")]
    if action in ("GetTotalBytesSent", "GetTotalBytesReceived", "GetTotalPacketsSent", "GetTotalPacketsReceived"):
        return [("New" + action[3:], 0)]
    raise UPnPError(401, "Invalid Action")


CONTROL = {"/ctl/IPConn": (S_IPC, handle_ipc), "/ctl/CmnIfCfg": (S_CIC, handle_cic)}
MUTATING = ("AddPortMapping", "AddAnyPortMapping", "DeletePortMapping", "DeletePortMappingRange")


def _int_or(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_HDR
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 15                       # a request that does not come whole in time is let go (no thread held)

    def version_string(self):
        return SERVER_HDR

    def log_message(self, fmt, *args):
        log.debug("http: %s %s", self.client_address[0], fmt % args)

    def _send(self, code, body, ctype='text/xml; charset="utf-8"', extra=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("EXT", "")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.close_connection = True

    def _allowed(self):
        if client_allowed(self.client_address[0]):
            return True
        log.debug("http: %s %s from %s refused (not in allowed_clients)", self.command, self.path, self.client_address[0])
        self._send(403, "forbidden", "text/plain")
        return False

    def do_GET(self):
        if not self._allowed():
            return
        path = self.path.split("?", 1)[0]
        local_ip = self.connection.getsockname()[0]
        client, ua = self.client_address[0], ua_words(self.headers.get("User-Agent"))
        if path in ("/rootDesc.xml", "/WANIPCn.xml", "/WANCfg.xml"):
            # Each step of a device on its way to a port, at info (1.7.4) - once in 10 minutes for the
            # same client and file: where a console stopped is seen in the log and on the Clients tab.
            (log.info if once(("get", client, path), SEARCH_EVERY) else log.debug)(
                "http: %s fetched %s (%s, via %s, UA=%s)", client, path,
                {"/rootDesc.xml": "the device description", "/WANIPCn.xml": "the description of WANIPConnection:%d"
                 % IGD_V, "/WANCfg.xml": "the description of WANCommonInterfaceConfig:1"}[path], local_ip, ua)
        if path == "/rootDesc.xml":
            self._send(200, device_xml(local_ip))
        elif path == "/WANIPCn.xml":
            self._send(200, scpd_xml(IPC_ACTIONS_2, IPC_VARS_2) if IGD_V == 2 else scpd_xml(IPC_ACTIONS, IPC_VARS))
        elif path == "/WANCfg.xml":
            self._send(200, scpd_xml(CIC_ACTIONS, CIC_VARS))
        else:
            (log.info if once(("404", client, path[:80])) else log.debug)(
                "http: %s asked for %s - not here, 404 (UA=%s)", client, path[:200], ua)
            self._send(404, "not found", "text/plain")

    do_HEAD = do_GET

    def do_POST(self):
        if not self._allowed():
            return
        client = self.client_address[0]
        path = self.path.split("?", 1)[0]
        if path not in CONTROL:
            self._send(404, "not found", "text/plain")
            return
        service, handler = CONTROL[path]
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length < 0:
                raise ValueError(length)
        except ValueError:
            log.warning("soap: invalid request from %s: Content-Length %r", client,
                        str(self.headers.get("Content-Length"))[:40])
            self._send(400, "bad Content-Length", "text/plain")
            return
        if length > SOAP_MOST:
            log.warning("soap: invalid request from %s: %d bytes (%d at most)", client, length, SOAP_MOST)
            self._send(413, "too large", "text/plain")
            return
        try:
            body = self.rfile.read(length) if length else b""
        except OSError as e:
            log.debug("http: the request of %s did not come whole: %s", client, e)
            self.close_connection = True
            return
        if len(body) < length:
            log.debug("http: the request of %s was cut short (%d of %d bytes)", client, len(body), length)
            self.close_connection = True
            return
        try:
            action, args = parse_soap(body)
        except Exception as e:  # noqa: BLE001
            log.warning("soap: invalid request from %s: %s", client, e)
            self._send(500, soap_fault(402, "Invalid Args"))
            return
        sa = (self.headers.get("SOAPAction") or "").strip('"')
        if "#" in sa and sa.split("#", 1)[1]:
            action = sa.split("#", 1)[1]
        action = re.sub(r"[^A-Za-z0-9_]", "", action)[:64] or "?"
        ua = ua_words(self.headers.get("User-Agent"))
        # What changes the mappings is said every time; a question (GetExternalIPAddress, GetStatusInfo,
        # GetSpecificPortMappingEntry...) once in 10 minutes for the same client - and written to the
        # request log once a minute, so the Requests and Clients tabs see it.
        changes = action in MUTATING
        loud = changes or once(("soap", client, action))
        (log.info if loud else log.debug)("soap: %s -> %s %s(UA=%s)", client, action,
                                          (json.dumps(args, ensure_ascii=False) + " ") if args else "", ua)
        try:
            out = handler(action, args, client)
            self._send(200, soap_response(service, action, out))
            said = "ok"
        except UPnPError as e:
            (log.info if loud else log.debug)("soap: %s <- %s error %d %s", client, action, e.code, e.desc)
            self._send(500, soap_fault(e.code, e.desc))
            said = "error %d %s" % (e.code, e.desc)
        if not changes and once(("rec", client, action, args.get("NewExternalPort", ""),
                                 args.get("NewProtocol", "")), 60):
            ev = {"action": action, "client": client, "result": said}
            if action == "GetSpecificPortMappingEntry":
                ev.update(protocol=str(args.get("NewProtocol", ""))[:8].upper(),
                          external_port=_int_or(args.get("NewExternalPort")))
            record(ev)

    def do_SUBSCRIBE(self):
        if not self._allowed():
            return
        log.debug("http: SUBSCRIBE %s %s", self.client_address[0], self.path)
        self._send(200, "", "text/plain", {"SID": "uuid:" + str(uuid.uuid4()), "TIMEOUT": "Second-1800"})

    def do_UNSUBSCRIBE(self):
        if not self._allowed():
            return
        self._send(200, "", "text/plain")


class Server(ThreadingHTTPServer):
    # socketserver's listen backlog is 5: many devices at once (a flood, a LAN starting up) were reset
    request_queue_size = 128
    daemon_threads = True

    def handle_error(self, request, client_address):
        # a device that went away mid-answer is not a traceback on stderr (the journal); anything else is
        # said once, in the log
        e = sys.exc_info()[1]
        if isinstance(e, (ConnectionError, TimeoutError, socket.timeout)):
            log.debug("http: %s went away: %s", client_address[0], e)
        else:
            log.warning("http: a request of %s failed: %s: %s", client_address[0], type(e).__name__, e)


# ================================================================ SSDP
def ssdp_message(first_line, headers):
    return (first_line + "\r\n" + "".join("%s: %s\r\n" % (k, v) for k, v in headers) + "\r\n").encode()


class SSDP:
    def __init__(self):
        self.rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.rx.bind(("", SSDP_PORT))
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        self.joined = {}  # interface name -> ip
        self.seen = {}
        self.lock = threading.Lock()

    # ---- multicast group membership on all interfaces
    def sync_interfaces(self):
        current = list_interfaces()
        with self.lock:
            for name, ip in list(self.joined.items()):
                if current.get(name) != ip:
                    try:
                        self.rx.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                           struct.pack("4s4s", socket.inet_aton(SSDP_GROUP), socket.inet_aton(ip)))
                    except OSError:
                        pass
                    del self.joined[name]
                    log.info("net: %s (%s) is gone", name, ip)
            for name, ip in current.items():
                if name in self.joined:
                    continue
                try:
                    self.rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                       struct.pack("4s4s", socket.inet_aton(SSDP_GROUP), socket.inet_aton(ip)))
                    self.joined[name] = ip
                    log.info("net: listening on %s (%s) - %s", name, ip, location_url(ip))
                    if CFG["mode"] == "active":
                        self.send_notify(name, ip)
                except OSError as e:
                    log.warning("net: the SSDP group cannot be joined on %s (%s): %s", name, ip, e)
            if not self.joined:
                log.warning("net: no usable interface with IPv4 (check interfaces / exclude_interfaces)")

    def rescan_loop(self):
        while True:
            time.sleep(max(10, int(CFG["interface_rescan_seconds"])))
            try:
                self.sync_interfaces()
            except Exception as e:  # noqa: BLE001
                log.warning("net: checking the interfaces failed: %s", e)

    # ---- NOTIFY ssdp:alive / ssdp:byebye (UDA 1.1: BOOTID.UPNP.ORG grows with each start, CONFIGID with
    # each change of the descriptions - here the IGD version)
    def send_notify(self, name, ip, nts="ssdp:alive"):
        try:
            self.tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
        except OSError as e:
            log.debug("ssdp: IP_MULTICAST_IF %s failed: %s", ip, e)
            return
        for nt, usn in ADVERTS:
            head = [("HOST", "%s:%d" % (SSDP_GROUP, SSDP_PORT))]
            if nts == "ssdp:alive":
                head += [("CACHE-CONTROL", "max-age=1800"), ("LOCATION", location_url(ip)), ("SERVER", SERVER_HDR)]
            head += [("NT", nt), ("NTS", nts), ("USN", usn), ("BOOTID.UPNP.ORG", str(BOOTID)),
                     ("CONFIGID.UPNP.ORG", str(IGD_V))]
            try:
                self.tx.sendto(ssdp_message("NOTIFY * HTTP/1.1", head), (SSDP_GROUP, SSDP_PORT))
            except OSError as e:
                log.debug("ssdp: NOTIFY on %s failed: %s", name, e)
                return
        log.debug("ssdp: NOTIFY %s sent on %s (%s)", nts, name, ip)

    def byebye(self):
        """ssdp:byebye on every interface - the service stops: the devices forget it at once, not after
        CACHE-CONTROL's half an hour."""
        if CFG.get("mode") != "active":
            return
        with self.lock:
            for name, ip in list(self.joined.items()):
                self.send_notify(name, ip, "ssdp:byebye")
        log.info("ssdp: NOTIFY ssdp:byebye sent on %s", ", ".join(sorted(self.joined)) or "no interface")

    def notify_loop(self):
        while True:
            time.sleep(max(30, int(CFG["notify_interval_seconds"])))
            if CFG["mode"] != "active":
                continue
            with self.lock:
                for name, ip in list(self.joined.items()):
                    self.send_notify(name, ip)

    # ---- M-SEARCH
    def listen(self):
        pkt = getattr(socket, "IP_PKTINFO", None)
        if pkt:
            try:
                self.rx.setsockopt(socket.IPPROTO_IP, pkt, 1)
            except OSError:
                pkt = None
        while True:
            arrived = None
            try:
                if pkt:
                    data, anc, _flags, (src, sport) = self.rx.recvmsg(4096, socket.CMSG_SPACE(12))
                    for level, kind, raw in anc:
                        if level == socket.IPPROTO_IP and kind == pkt and len(raw) >= 4:
                            try:
                                arrived = socket.if_indextoname(struct.unpack("i", raw[:4])[0])
                            except OSError:
                                arrived = None
                else:
                    data, (src, sport) = self.rx.recvfrom(4096)
            except OSError as e:
                log.warning("ssdp: receiving failed: %s", e)
                time.sleep(1)
                continue
            try:
                self.handle(data, src, sport, arrived)
            except Exception as e:  # noqa: BLE001
                # once in 10 min for the same address: made-up packets are no flood in the log
                (log.warning if once(("pkt", src)) else log.debug)("ssdp: a packet from %s failed: %s", src, e)

    def handle(self, data, src, sport, arrived=None):
        lines = data.decode("utf-8", "ignore").split("\r\n")
        if not lines or not lines[0].upper().startswith("M-SEARCH"):
            if lines and lines[0].upper().startswith("NOTIFY") and src not in self.joined.values():
                nt = next((ln.split(":", 1)[1].strip() for ln in lines if ln.upper().startswith("NT:")), "")
                nt = nt[:200]
                router = "InternetGatewayDevice" in nt or "WANIPConnection" in nt
                # a router announces several types (IGD, WANDevice, WANIPConnection...): one warning and one
                # notification an hour for it, not one for each type
                k = (src, "NOTIFY", "router" if router else nt)
                self._prune()
                if time.time() - self.seen.get(k, 0) > 3600:
                    self.seen[k] = time.time()
                    if router:
                        log.warning("ssdp: OTHER UPnP ROUTER on the network: %s announces NT=%s", src, nt)
                        if CFG.get("notify_other_router", True):
                            notify("UPnP: another router", "%s announces itself as a UPnP router (%s) - "
                                   "the PS5 may use it instead of fake-igd" % (src, nt), priority=4, tags="warning")
                    else:
                        log.info("ssdp: %s announces NT=%s", src, nt)
            return
        hdr = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdr[k.strip().upper()] = v.strip()
        if hdr.get("MAN", "").strip('"') != "ssdp:discover":
            return
        st = re.sub(r"[\x00-\x1f\x7f]", "", hdr.get("ST", ""))[:200]
        if not client_allowed(src):
            log.debug("ssdp: M-SEARCH from %s (ST=%s) ignored - not in allowed_clients", src, st)
            return
        k = (src, st)
        self._prune()
        # Each search written down (1.7.14) - once in 30 s per device and what it searched for (a device
        # sends the same search two or three times at once): the Clients tab counts every look, a test of
        # the PS5's connection shows at once. It was once in 10 minutes.
        loud = time.time() - self.seen.get(k, 0) > SEARCH_EVERY
        if loud:
            log.info("ssdp: %s is looking for a UPnP device (ST=%s, MX=%s, UA=%s)", src, st,
                     ua_words(hdr.get("MX", "-"))[:8], ua_words(hdr.get("USER-AGENT")))
            self.seen[k] = time.time()
        else:
            log.debug("ssdp: M-SEARCH %s ST=%s", src, st)
        with self.lock:
            joined = dict(self.joined)
        own = src in joined.values()
        if arrived and arrived not in joined and not own:
            # a search that came in on an interface fake-igd does not use (interfaces / exclude_interfaces):
            # not answered, as miniupnpd answers only on its listening interfaces
            if loud:
                log.info("ssdp: %s not answered - its search came in on %s, which fake-igd does not use "
                         "(interfaces, exclude_interfaces)", src, arrived)
            return
        if CFG["mode"] == "passive":
            if loud:
                log.info("ssdp: %s not answered - the mode is passive (ST=%s)", src, st)
            return
        answers = search_answers(st)
        if not answers:
            if loud:
                log.info("ssdp: %s not answered - nothing here is %s (this is InternetGatewayDevice:%d%s)", src, st,
                         IGD_V, "; igd_version 2 answers :2" if IGD_V == 1 and TYPE_RE.match(st) else "")
            return
        local_ip = local_ip_for(src)
        if local_ip not in joined.values() and not own and arrived in joined:
            # the way back to it goes out by another address (another subnet, a route): LOCATION is the
            # address of the interface its search came in on, which it reached
            local_ip = joined[arrived]
        try:
            mx = max(0, min(int(hdr.get("MX", "1")), 5))
        except ValueError:
            mx = 1
        # UDA 1.1 spreads the answers of many devices over up to MX seconds. fake-igd is one device, and a
        # PS5 searching with MX=1 was answered after up to a second - and never came for the description
        # (1.7.13): a client may stop listening before MX is over. Answered within 50 ms now (still not all
        # at the same instant); a search sent to this address (unicast) at once.
        delay = random.uniform(0.005, 0.05) if mx and hdr.get("HOST", "").startswith(SSDP_GROUP) else 0
        threading.Timer(delay, self._reply, args=(src, sport, local_ip, answers, loud)).start()

    def _prune(self):
        """What was seen, kept for an hour - not for ever (a flood of made-up sources or STs grew it)."""
        if len(self.seen) > 4096:
            t = time.time() - 3600
            for k in [k for k, v in self.seen.items() if v < t]:
                del self.seen[k]
            if len(self.seen) > 4096:
                self.seen.clear()

    def _reply(self, src, sport, local_ip, answers, loud=False):
        # Replies go out from the SSDP socket itself (source port 1900), like real routers do,
        # so they pass stateful firewalls / conntrack on the client side.
        s = self.rx
        try:
            for st, usn in answers:
                s.sendto(ssdp_message("HTTP/1.1 200 OK", [
                    ("CACHE-CONTROL", "max-age=1800"), ("DATE", formatdate(usegmt=True)), ("EXT", ""),
                    ("LOCATION", location_url(local_ip)), ("SERVER", SERVER_HDR), ("ST", st), ("USN", usn),
                    ("BOOTID.UPNP.ORG", str(BOOTID)), ("CONFIGID.UPNP.ORG", str(IGD_V))]), (src, sport))
            (log.info if loud else log.debug)(
                "ssdp: answered %s:%d - ST=%s USN=%s LOCATION=%s%s", src, sport, answers[0][0], answers[0][1],
                location_url(local_ip), (" (and %d more)" % (len(answers) - 1)) if len(answers) > 1 else "")
        except OSError as e:
            log.warning("ssdp: the reply to %s failed: %s", src, e)


def search_answers(st):
    """What an M-SEARCH for st is answered with, [(ST, USN)] - as UDA 1.1 and miniupnpd: ssdp:all every
    advertisement; upnp:rootdevice and uuid: as they are; a device or service type answered when this
    device has it in the version asked or a later one, with the ST as asked (and the USN of it); a later
    version than this device has is not answered."""
    if st == "ssdp:all":
        return list(ADVERTS)
    m = TYPE_RE.match(st)
    if m:
        for t, usn in ADVERTS:
            have = TYPE_RE.match(t)
            if have and have.group(1) == m.group(1) and 1 <= int(m.group(2)) <= int(have.group(2)):
                return [(st, usn.rsplit("::", 1)[0] + "::" + st)]
        return []
    return [(t, u) for t, u in ADVERTS if t == st]


def expiry_loop():
    while True:
        time.sleep(30)
        with _lock:
            purge_expired()


# ================================================================ --summary
def summary():
    path = CFG["request_log"]
    ports = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("action") != "AddPortMapping":
                    continue
                k = (e["protocol"], e["external_port"], e.get("internal_client", ""))
                p = ports.setdefault(k, {"count": 0, "first": e["time"], "last": e["time"], "desc": set()})
                p["count"] += 1
                p["last"] = e["time"]
                if e.get("description"):
                    p["desc"].add(e["description"])
    except FileNotFoundError:
        print("Request log %s does not exist yet." % path)
        return
    if not ports:
        print("No port requests yet.")
        return
    print("%-5s %-6s %-16s %-6s %-25s %s" % ("PROTO", "PORT", "CLIENT", "COUNT", "LAST", "DESCRIPTION"))
    for (proto, port, ic), p in sorted(ports.items(), key=lambda x: (x[0][2], x[0][0], x[0][1])):
        print("%-5s %-6d %-16s %-6d %-25s %s" % (proto, port, ic, p["count"], p["last"], ", ".join(sorted(p["desc"]))))
    by = {}
    for proto, port, ic in ports:
        by.setdefault((ic, proto), set()).add(port)
    print("\nSuggested iptables DNAT (adjust the WAN interface):")
    for (ic, proto), pl in sorted(by.items()):
        pl = sorted(pl)
        for i in range(0, len(pl), 15):  # multiport supports max 15 ports
            print("iptables -t nat -A PREROUTING -i eth0 -p %s -m multiport --dports %s -j DNAT --to-destination %s"
                  % (proto.lower(), ",".join(map(str, pl[i:i + 15])), ic))


# ================================================================ main
def main():
    global CFG, ALLOWED_NETS, UUID_ROOT, UUID_WAN, UUID_CONN, ADVERTS, BOOTID
    ap = argparse.ArgumentParser(description="fake-igd - fake UPnP IGD that only logs port mapping requests")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--summary", action="store_true", help="print requested ports from the request log and exit")
    ap.add_argument("--notify-test", action="store_true", help="send a test notification with the configured ntfy and exit")
    ap.add_argument("--version", action="version", version="fake-igd " + VERSION)
    args = ap.parse_args()

    CFG = load_config(args.config)
    if args.summary:
        summary()
        return
    if args.notify_test:
        if not CFG.get("ntfy_url"):
            print("ntfy_url is not set - nothing to send to")
            sys.exit(2)
        ok, words = ntfy_send(CFG, "fake-igd test", "A test notification from fake-igd %s on %s."
                              % (VERSION, socket.gethostname()), tags="white_check_mark")
        print("%s: %s - %s" % ("sent" if ok else "FAILED", ntfy_words(CFG), words))
        sys.exit(0 if ok else 1)
    ALLOWED_NETS = parse_allowed(CFG["allowed_clients"])
    setup_logging(CFG)
    os.makedirs(CFG["state_dir"], exist_ok=True)
    with _lock:
        load_mappings()
        save_mappings()

    set_version(CFG.get("igd_version"))
    BOOTID = max(1, int(time.time()) & 0x7FFFFFFF)
    host = socket.gethostname()
    UUID_ROOT = str(uuid.uuid5(uuid.NAMESPACE_DNS, "fake-igd-root-" + host))
    UUID_WAN = str(uuid.uuid5(uuid.NAMESPACE_DNS, "fake-igd-wan-" + host))
    UUID_CONN = str(uuid.uuid5(uuid.NAMESPACE_DNS, "fake-igd-conn-" + host))
    ADVERTS = [
        ("upnp:rootdevice", "uuid:%s::upnp:rootdevice" % UUID_ROOT),
        ("uuid:" + UUID_ROOT, "uuid:" + UUID_ROOT), (T_IGD, "uuid:%s::%s" % (UUID_ROOT, T_IGD)),
        ("uuid:" + UUID_WAN, "uuid:" + UUID_WAN), (T_WAN, "uuid:%s::%s" % (UUID_WAN, T_WAN)),
        (S_CIC, "uuid:%s::%s" % (UUID_WAN, S_CIC)),
        ("uuid:" + UUID_CONN, "uuid:" + UUID_CONN), (T_CONN, "uuid:%s::%s" % (UUID_CONN, T_CONN)),
        (S_IPC, "uuid:%s::%s" % (UUID_CONN, S_IPC)),
    ]

    log.info("service: fake-igd %s starting (config %s)", VERSION, args.config)
    if CFG["_unknown_keys"]:
        log.warning("config: unknown keys ignored: %s", ", ".join(CFG["_unknown_keys"]))
    resolve_external_ip()
    log.info("service: mode %s, AddPortMapping answered: %s, InternetGatewayDevice:%d", CFG["mode"],
             CFG["mapping_response"], IGD_V)
    log.info("service: HTTP port %d, public IP '%s', interfaces: %s, excluded: %s",
             CFG["http_port"], EXTERNAL_IP, ", ".join(CFG["interfaces"]) or "all",
             ", ".join(CFG["exclude_interfaces"]) or "-")
    log.info("service: allowed clients: %s, notifications: %s", ", ".join(map(str, ALLOWED_NETS)) or "all",
             ntfy_words(CFG))
    log.info("service: log %s, requests %s, state %s", CFG["log_file"], CFG["request_log"], map_file())

    try:
        httpd = Server(("0.0.0.0", CFG["http_port"]), Handler)
    except OSError as e:
        log.error("service: HTTP port %d cannot be opened: %s", CFG["http_port"], e)
        sys.exit(1)
    httpd.daemon_threads = True
    try:
        ssdp = SSDP()
    except OSError as e:
        log.error("service: SSDP port %d/udp cannot be opened: %s", SSDP_PORT, e)
        sys.exit(1)
    ssdp.sync_interfaces()

    for target in (ssdp.listen, ssdp.rescan_loop, ssdp.notify_loop, expiry_loop):
        threading.Thread(target=target, daemon=True).start()

    def stop(signum, _frame):
        log.info("service: stopping (signal %d)", signum)
        try:
            ssdp.byebye()
        except Exception as e:  # noqa: BLE001
            log.debug("ssdp: byebye failed: %s", e)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("service: running - HTTP on 0.0.0.0:%d, SSDP on %d/udp", CFG["http_port"], SSDP_PORT)
    httpd.serve_forever()
    log.info("service: stopped")


if __name__ == "__main__":
    main()
