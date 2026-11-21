"""api_monitor.py - Settings → Monitoring (1.6.0): Prometheus metrics at /metrics, and SNMPv3 (1.7.2), as otp's.

nginx sends `location = /metrics` to web/metrics.php, which hands the scraper's bearer
token to POST /api/metrics/scrape (a PUBLIC route: no sign-in, the API token still); the
token and where the request comes from are checked here before anything is said. A wrong
or missing token is a 401, a network not let in a 403, metrics switched off a 404.

What it says: this machine (load, memory, uptime, disks) and fake-igd (the requests and
the ports asked for, the clients, the mappings, the mDNS services, the services' states,
the outgoing mail, the alerts open, syslog, the certificate, a new version).

SNMPv3 (1.7.2, otp's "SNMPv3 (1.0.182)"): this API answers it itself - igd_snmp.Agent, a thread
started by background(), on snmp_port/udp (161: CAP_NET_BIND_SERVICE in fake-igd-api.service, as
otp.service has it; the firewall's "what fake-igd needs" opens it, deploy/root_fw.py). authPriv
only, one user, its passphrases sealed. What it answers: the system group and FAKE-IGD-MIB
(deploy/FAKE-IGD-MIB.txt) - the same things /metrics says, typed, and every sample of /metrics
as a table. Traps (authPriv) when something goes wrong, as the alerts see it, and when it is right
again.

  GET  /api/snmp                    the agent's state and the settings' (the pane's card)
  POST /api/snmp {action: test | trap}   asked as the monitoring would / a test trap
  GET  /api/snmpfile?what=mib|zabbix   FAKE-IGD-MIB or the Zabbix 7.0 template, as the package has them
"""
import collections
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import sys
import time
import zlib

NAME = "monitor"
CERT_FILE = os.environ.get("FAKE_IGD_NGINX_CERT", "/etc/nginx/certs/fake-igd.pem")
MDNS_EVERY_S = 300


def _net(v):
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        return "%s is not an address or a net" % v
    if "%" in str(v):
        return "%s: no scope id" % v               # root's helper refuses one (otp 1.0.287)
    return ""


def _addr(v):
    try:
        ipaddress.ip_address(str(v).strip())
    except ValueError:
        return "one address of this machine, or empty for every one"
    return ""


def _user(v):
    return "" if re.match(r"^[A-Za-z0-9._-]{1,32}\Z", v) else "1 to 32 letters, digits and . _ -"


def _phrase(v):
    return "" if 12 <= len(v) <= 128 else "12 to 128 characters"


def _token(v):
    # What web/metrics.php hands on (RFC 6750's b64token, 24 to 200 characters): a token typed shorter or with
    # a space in it was saved, and Prometheus got a 401 with it for ever (1.9.11).
    return "" if re.match(r"^[A-Za-z0-9_.~+/=-]{24,200}\Z", v) else \
        "24 to 200 letters, digits and - . _ ~ + / = (Make a token below makes one)"


def _traps_to(v):
    import igd_snmp as SN
    try:
        SN.trap_targets(v, strict=True)
    except ValueError as e:
        return str(e)
    return ""


SNMP_ON = ("snmp", True)
SETTINGS = [
    # --- SNMPv3 (1.7.2): otp's settings, the same names and words (Settings → Monitoring) ---
    {"key": "snmp", "name": "SNMPv3", "kind": "bool", "default": False,
     "says": "This machine answers SNMPv3 itself - an agent of fake-igd, no snmpd: the system group and "
             "fake-igd\u2019s own objects (FAKE-IGD-MIB, <code>deploy/FAKE-IGD-MIB.txt</code>), read only. "
             "authPriv only: a user with a passphrase for each."},
    {"key": "snmp_port", "name": "Port (UDP)", "kind": "int", "default": 161, "min": 1, "max": 65535,
     "only_when": SNMP_ON,
     "says": "161 is SNMP\u2019s. Another where snmpd of the system has it already (not 1900: SSDP\u2019s)."},
    {"key": "snmp_bind", "name": "Listen on", "kind": "text", "default": "", "check": _addr, "most": 64,
     "only_when": SNMP_ON, "says": "Empty: every address of this machine. Or one of its addresses."},
    {"key": "snmp_from", "name": "SNMP only from", "kind": "list", "default": [], "check": _net,
     "only_when": SNMP_ON,
     "says": "The addresses or networks the monitoring asks from, <code>10.0.5.0/24, 192.0.2.7</code>. Empty: "
             "anybody with the user and its passphrases. The firewall lets in these only."},
    {"key": "snmp_user", "name": "User", "kind": "text", "default": "", "check": _user, "most": 32,
     "only_when": SNMP_ON, "says": "The SNMPv3 user (securityName) the monitoring asks as."},
    {"key": "snmp_auth", "name": "Authentication", "kind": "choice", "default": "SHA-256", "only_when": SNMP_ON,
     "choices": [("SHA-256", "SHA-256"), ("SHA-512", "SHA-512"), ("SHA-1", "SHA-1")],
     "says": "HMAC of every message. SHA-256 or SHA-512; SHA-1 only for old monitoring."},
    {"key": "snmp_auth_pass", "name": "Its passphrase (authentication)", "kind": "secret", "default": "",
     "check": _phrase, "most": 128, "only_when": SNMP_ON, "says": "12 characters at least. Kept sealed."},
    {"key": "snmp_priv", "name": "Encryption", "kind": "choice", "default": "AES-128", "only_when": SNMP_ON,
     "choices": [("AES-128", "AES-128"), ("AES-256", "AES-256")],
     "says": "Every message encrypted. AES-256 is net-snmp\u2019s and Zabbix\u2019s (\u201cAES256\u201d, not "
             "Cisco\u2019s \u201cAES256C\u201d)."},
    {"key": "snmp_priv_pass", "name": "Its passphrase (encryption)", "kind": "secret", "default": "",
     "check": _phrase, "most": 128, "only_when": SNMP_ON,
     "says": "12 characters at least - best not the same as the other. Kept sealed."},
    {"key": "snmp_contact", "name": "Contact (sysContact)", "kind": "text", "default": "", "most": 255,
     "only_when": SNMP_ON, "says": "Who looks after it - as sysContact.0 says."},
    {"key": "snmp_location", "name": "Location (sysLocation)", "kind": "text", "default": "", "most": 255,
     "only_when": SNMP_ON, "says": "Where it is - as sysLocation.0 says."},
    {"key": "snmp_traps", "name": "Traps when something is wrong", "kind": "bool", "default": False,
     "only_when": SNMP_ON,
     "says": "An SNMPv2 trap (authPriv) when something goes wrong - what the alerts see - and when it is "
             "right again."},
    {"key": "snmp_trap_to", "name": "Where traps go", "kind": "text", "default": "", "check": _traps_to,
     "most": 1000, "only_when": ("snmp_traps", True),
     "says": "host or host:port (162 by default), separated by commas. The receiver knows the user with this "
             "machine\u2019s engine ID (shown below)."},

    {"key": "metrics", "name": "Prometheus metrics (/metrics)", "kind": "bool", "default": False,
     "says": "This machine answers <code>https://SERVER/metrics</code> in Prometheus’ format - the requests and "
             "the ports asked for, the clients, the mappings, the mDNS services, the services, the disks, the "
             "mail, the alerts. Asked with the token below."},
    {"key": "metrics_token", "name": "Its token (Bearer)", "kind": "secret", "default": "", "most": 200, "check": _token,
     "only_when": ("metrics", True),
     "says": "What Prometheus sends as <code>Authorization: Bearer ...</code>. Kept sealed; <i>Make a "
             "token</i> below makes one and shows it once."},
    {"key": "metrics_from", "name": "Only from", "kind": "list", "default": [], "check": _net,
     "only_when": ("metrics", True),
     "says": "The addresses or networks Prometheus asks from, <code>10.0.5.0/24, 2001:db8::/64</code>. Empty: from "
             "anywhere that reaches the pages, with the token."},
]


def _setting(store, key):
    import igd_panes as PN
    import igd_seal as SEAL
    v = PN.value(store, key)
    return SEAL.unseal_or(store, v) if key in SEALED else v


SEALED = ("metrics_token", "snmp_auth_pass", "snmp_priv_pass")


def on_saved(ctx, changed):
    import igd_seal as SEAL
    SEAL.seal_settings(ctx.store, list(SEALED))             # kept sealed in the database (igd_seal)
    if any(k.startswith("snmp") for k in changed):
        snmp_start(ctx)
        if AGENT["a"] is not None:
            AGENT["a"].looked = 0.0                         # looked at again within the second
            AGENT["a"].mib_at = 0.0
    # The firewall's SNMP port follows the settings (as ACME's HTTP-01 does): root puts FAKE-IGD-IN in again.
    if any(k in changed for k in ("snmp", "snmp_port", "snmp_from")):
        try:
            ctx.ask_root({"action": "apply"}, kind="fw")
        except (OSError, ValueError):
            pass


# ---- this machine ----------------------------------------------------------------------------
def disks(cfg):
    """[{path, total, free, used, pct}] of the file systems fake-igd lives on (each once)."""
    seen, out = set(), []
    for p in ("/", cfg.get("state_dir") or "/var/lib/fake-igd",
              os.path.dirname(cfg.get("log_file") or "/var/log/fake-igd/fake-igd.log")):
        try:
            dev = os.stat(p).st_dev
            if dev in seen:
                continue
            seen.add(dev)
            u = shutil.disk_usage(p)
        except OSError:
            continue
        pct = round(100.0 * (u.total - u.free) / u.total, 1) if u.total else 0.0
        out.append({"path": p, "total": u.total, "free": u.free, "used": u.total - u.free, "pct": pct})
    return out


def certificate(path=None):
    """{file, subject, until (epoch), days} of the pages' certificate, or {file, error}."""
    path = path or CERT_FILE
    try:
        d = ssl._ssl._test_decode_cert(path)           # noqa: SLF001 - the stdlib's own reader of X.509
        until = ssl.cert_time_to_seconds(d["notAfter"])
        subj = ", ".join("%s=%s" % kv for rdn in d.get("subject", ()) for kv in rdn)
        return {"file": path, "subject": subj, "until": until, "days": (until - time.time()) / 86400.0}
    except Exception as e:                              # noqa: BLE001
        return {"file": path, "error": str(e)[:200]}


def machine():
    out = {}
    try:
        out["load"] = os.getloadavg()
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as f:
            mem = {ln.split(":")[0]: int(ln.split()[1]) * 1024 for ln in f if len(ln.split()) >= 2}
        out["mem_total"], out["mem_available"] = mem.get("MemTotal"), mem.get("MemAvailable")
    except (OSError, ValueError):
        pass
    try:
        with open("/proc/uptime") as f:
            out["uptime"] = float(f.read().split()[0])
    except (OSError, ValueError):
        pass
    out["cpus"] = os.cpu_count() or 1
    return out


def unit_states():
    """{unit: ActiveState} - fake-igd.service, fake-igd-api (this) and avahi-daemon."""
    import upnp as U
    out = {"fake-igd-api.service": "active"}
    try:
        out["fake-igd.service"] = U.service_info().get("ActiveState") or "unknown"
    except Exception:                                   # noqa: BLE001
        out["fake-igd.service"] = "unknown"
    try:
        import upnp_mdns as MD
        if os.path.exists(MD.CONF) or shutil.which("avahi-daemon"):
            out["avahi-daemon.service"] = MD.systemd_state("avahi-daemon").get("ActiveState") or "unknown"
    except Exception:                                   # noqa: BLE001
        pass
    return out


def mdns_count(store):
    got = store.meta_json("monitor:mdns") or {}
    return got.get("n"), got.get("at")


# ---- the metrics -----------------------------------------------------------------------------
def _esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class Out(object):
    """The samples of each metric together, in the order first said (as the text format wants)."""

    def __init__(self):
        self.families = collections.OrderedDict()

    def add(self, name, kind, helptext, value, labels=None):
        if value is None:
            return
        fam = self.families.setdefault(name, ["# HELP %s %s" % (name, helptext), "# TYPE %s %s" % (name, kind)])
        lab = ""
        if labels:
            lab = "{%s}" % ",".join('%s="%s"' % (k, _esc(v)) for k, v in labels.items())
        if isinstance(value, bool):
            value = int(value)
        fam.append("%s%s %s" % (name, lab, repr(float(value)) if isinstance(value, float) else value))

    @property
    def lines(self):
        return [ln for fam in self.families.values() for ln in fam]


def metrics_text(ctx):
    import upnp as U
    began = time.time()
    cfg = ctx.cfg
    S = ctx.store
    o = Out()
    node = socket.gethostname().split(".")[0]
    o.add("fake_igd_info", "gauge", "fake-igd's version and this machine", 1,
          {"version": U.VERSION, "node": node, "site": cfg.get("site_name") or ""})
    main = sys.modules.get("__main__")
    o.add("fake_igd_api_start_time_seconds", "gauge", "when the pages' API started",
          getattr(main, "STARTED", None))
    for unit, st in unit_states().items():
        o.add("fake_igd_service_up", "gauge", "a service is active (1) or not (0)", st == "active", {"unit": unit})
    try:
        ev = U.read_events(cfg)
    except SystemExit:
        ev = []
    by_action, by_result, clients, ports = collections.Counter(), collections.Counter(), set(), set()
    last = 0.0
    for e in ev:
        by_action[e.get("action") or "?"] += 1
        clients.add(e.get("client"))
        if e.get("action") == "AddPortMapping":
            by_result[str(e.get("result") or "?")] += 1
            ports.add((e.get("client"), str(e.get("protocol") or "").upper(), e.get("external_port")))
        if e.get("_t"):
            last = max(last, e["_t"].timestamp())
    for a, n in sorted(by_action.items()):
        o.add("fake_igd_requests_total", "counter", "SOAP requests in the request log, by action", n, {"action": a})
    for r, n in sorted(by_result.items()):
        o.add("fake_igd_port_requests_total", "counter", "AddPortMapping asked for, by what it was answered", n,
              {"result": r})
    o.add("fake_igd_ports", "gauge", "ports asked for (client, protocol, port), each once", len(ports))
    o.add("fake_igd_clients", "gauge", "devices that asked anything", len([c for c in clients if c]))
    o.add("fake_igd_last_request_timestamp_seconds", "gauge", "when the last request came", last or None)
    try:
        with open(os.path.join(cfg.get("state_dir") or "/var/lib/fake-igd", "mappings.json"), encoding="utf-8") as f:
            nmap = len(json.load(f))
    except (OSError, ValueError):
        nmap = 0
    o.add("fake_igd_mappings", "gauge", "port mappings held now (none is opened)", nmap)
    n, _at = mdns_count(S)
    o.add("fake_igd_mdns_services", "gauge", "services avahi-browse sees on the network (looked every 5 min)", n)
    try:
        st = U.status_data(cfg)
        o.add("fake_igd_other_igd", "gauge", "other UPnP routers seen on the network", len(st.get("other_igd") or []))
    except (SystemExit, Exception):                    # noqa: BLE001
        pass
    for d in disks(cfg):
        o.add("fake_igd_disk_bytes", "gauge", "the file systems fake-igd lives on", d["total"],
              {"path": d["path"], "kind": "total"})
        o.add("fake_igd_disk_bytes", "gauge", "the file systems fake-igd lives on", d["free"],
              {"path": d["path"], "kind": "free"})
    m = machine()
    for i, per in enumerate(("1m", "5m", "15m")):
        if m.get("load"):
            o.add("fake_igd_load", "gauge", "the load average of this machine", float(m["load"][i]), {"period": per})
    o.add("fake_igd_memory_bytes", "gauge", "this machine's memory", m.get("mem_total"), {"kind": "total"})
    o.add("fake_igd_memory_bytes", "gauge", "this machine's memory", m.get("mem_available"), {"kind": "available"})
    o.add("fake_igd_uptime_seconds", "gauge", "how long this machine has been up", m.get("uptime"))
    o.add("fake_igd_cpus", "gauge", "processors of this machine", m.get("cpus"))
    c = certificate()
    if c.get("until"):
        o.add("fake_igd_certificate_expiry_timestamp_seconds", "gauge", "when the pages' certificate runs out",
              int(c["until"]), {"file": c["file"]})
    try:
        import igd_mail
        for k, v in igd_mail.counts(S).items():
            o.add("fake_igd_mail_queue", "gauge", "the outgoing mail, by state", v, {"state": k})
    except Exception:                                   # noqa: BLE001
        pass
    al = S.meta_json("alerts:state") or {}
    open_ = collections.Counter(p.get("level") or "warn" for p in (al.get("problems") or {}).values())
    for lv in ("bad", "warn"):
        o.add("fake_igd_alerts_open", "gauge", "what the alerts see wrong now", open_.get(lv, 0), {"level": lv})
    si = S.meta_json("siem:state") or {}
    for k, v in sorted((si.get("sent") or {}).items()):
        o.add("fake_igd_siem_sent_total", "counter", "lines sent to a syslog server", v, {"target": k})
        o.add("fake_igd_siem_trouble", "gauge", "a syslog server not reached last time",
              k in (si.get("trouble") or {}), {"target": k})
    try:
        import igd_online as ON
        row = ON.view(S.meta_json("upgrade:online") or {}, U.VERSION)
        o.add("fake_igd_upgrade_available", "gauge", "a newer version of fake-igd is out", bool(row.get("newer")))
    except Exception:                                   # noqa: BLE001
        pass
    o.add("fake_igd_scrape_seconds", "gauge", "how long this answer took", round(time.time() - began, 4))
    return "\n".join(o.lines) + "\n"


# ---- the routes ------------------------------------------------------------------------------
def allowed(store, addr):
    nets = _setting(store, "metrics_from") or []
    if not nets:
        return True
    try:
        ip = ipaddress.ip_address(str(addr or "").strip("[]"))
    except ValueError:
        return False
    for n in nets:
        try:
            if ip in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def scrape(ctx):
    """POST /api/metrics/scrape {token} from metrics.php: {status, text} - the status is what
    metrics.php answers Prometheus with."""
    S = ctx.store
    if not _setting(S, "metrics"):
        return {"status": 404, "error": "metrics are switched off (Settings → Monitoring)"}
    want = str(_setting(S, "metrics_token") or "")
    got = str(ctx.body(4096).get("token") or "")
    if not want or not hmac.compare_digest(want.encode(), got.encode()):
        return {"status": 401, "error": "that token does not open /metrics"}
    if not allowed(S, ctx.addr):
        return {"status": 403, "error": "not from this address"}
    return {"status": 200, "text": metrics_text(ctx)}


scrape.PUBLIC = True


def monitor_get(ctx):
    n, at = mdns_count(ctx.store)
    return {"on": bool(_setting(ctx.store, "metrics")), "token_set": bool(_setting(ctx.store, "metrics_token")),
            "from": _setting(ctx.store, "metrics_from") or [], "mdns": {"n": n, "at": at},
            "snmp": snmp_view(ctx)}


def monitor_post(ctx):
    me = ctx.need("fulladmin")
    act = ctx.body().get("action")
    if act == "token":
        import igd_panes as PN
        tok = secrets.token_urlsafe(32)
        PN.save(ctx.store, {"metrics_token": tok})
        on_saved(ctx, {"metrics_token": tok})
        ctx.event("%s made a new token for Prometheus (the one before no longer opens /metrics)" % me["name"], "warn")
        return {"token": tok, "message": "a new token - the one before no longer opens /metrics"}
    if act == "preview":
        return {"text": metrics_text(ctx)}
    raise ValueError("no such action")

# ---- SNMPv3 (1.7.2): otp's agent, fake-igd's objects ------------------------------------------
# netSnmpPlaypen.8 - fake-igd has no enterprise number of its own; otp is netSnmpPlaypen.7.
SNMP_BASE = (1, 3, 6, 1, 4, 1, 8072, 9999, 9999, 8)
SNMP_GAUGE_MAX = 4294967295
SNMP_MIB_FILE = "FAKE-IGD-MIB.txt"
AGENT = {"a": None, "ctx": None, "lock": __import__("threading").Lock(), "problems": None, "problems_at": 0.0}


def _node():
    return socket.gethostname().split(".")[0]


def _g(v):
    """A Gauge32 never past its end (more is said as the most)."""
    try:
        v = int(v)
    except (TypeError, ValueError):
        return 0
    return max(0, min(v, SNMP_GAUGE_MAX))


def snmp_c(store):
    """The user, its protocols and its keys' passphrases - or None while not set (otp's snmp_conf)."""
    import igd_snmp as SN
    user = str(_setting(store, "snmp_user") or "").strip()
    auth = str(_setting(store, "snmp_auth") or "SHA-256")
    priv = str(_setting(store, "snmp_priv") or "AES-128")
    ap = str(_setting(store, "snmp_auth_pass") or "")
    pp = str(_setting(store, "snmp_priv_pass") or "")
    if not (user and ap and pp) or auth not in SN.SNMP_AUTH or priv not in SN.SNMP_PRIV:
        return None
    return {"user": user, "auth": auth, "priv": priv, "ap": ap, "pp": pp}


def snmp_conf(store):
    """What the agent reads every 5 seconds."""
    if not _setting(store, "snmp"):
        return {"on": False}
    return {"on": True, "port": int(_setting(store, "snmp_port") or 161),
            "bind": str(_setting(store, "snmp_bind") or "").strip(),
            "from": list(_setting(store, "snmp_from") or []), "c": snmp_c(store),
            "trap_to": str(_setting(store, "snmp_trap_to") or "") if _setting(store, "snmp_traps") else ""}


def snmp_start(ctx):
    """The agent, once in this process - made the first time SNMPv3 is on (its engine's starts counted)."""
    if AGENT["ctx"] is None or ctx.method == "BG":
        AGENT["ctx"] = ctx                              # the background's: no request's behind it
    with AGENT["lock"]:
        if AGENT["a"] is not None or not _setting(ctx.store, "snmp"):
            return AGENT["a"]
        import igd_snmp as SN
        state_dir = ctx.cfg.get("state_dir") or "/var/lib/fake-igd"
        store = ctx.store
        AGENT["a"] = SN.Agent(state_dir, lambda: snmp_conf(store), snmp_mib,
                              log=lambda w: sys.stderr.write("api: %s\n" % w))
        return AGENT["a"]


def _problems(ctx):
    """What the alerts see wrong now (computed the minute before) - {key: {level, title, said}}."""
    if AGENT["problems"] is not None and time.time() - AGENT["problems_at"] < 180:
        return AGENT["problems"]
    al = (ctx.store.meta_json("alerts:state") or {}).get("problems") or {}
    return al if isinstance(al, dict) else {}


def snmp_mib(agent):
    """Every object of the system group and of FAKE-IGD-MIB answered now: [(oid, kind, value)]
    (the engine's and usmStats igd_snmp adds). Each part by itself: one that fails leaves the rest."""
    import upnp as U
    import igd_snmp as SN
    ctx = AGENT["ctx"]
    S, cfg, B = ctx.store, ctx.cfg, SNMP_BASE
    up = int((time.monotonic() - agent.started) * 100)
    rows = [(SN.SNMP_SYS + (1, 0), "str", "fake-igd %s - a fake UPnP router (IGD) that opens no port, %s"
             % (U.VERSION, _node())),
            (SN.SNMP_SYS + (2, 0), "oid", B),
            (SN.SNMP_SYS + (3, 0), "ticks", up),
            (SN.SNMP_SYS + (4, 0), "str", str(_setting(S, "snmp_contact") or "")),
            (SN.SNMP_SYS + (5, 0), "str", socket.gethostname()),
            (SN.SNMP_SYS + (6, 0), "str", str(_setting(S, "snmp_location") or "")),
            (SN.SNMP_SYS + (7, 0), "int", 72)]
    main = sys.modules.get("__main__")
    api_up = int((time.time() - float(getattr(main, "STARTED", 0) or time.time())) * 100)
    rows += [(B + (1, 1, 0), "str", U.VERSION), (B + (1, 2, 0), "str", _node()),
             (B + (1, 3, 0), "str", str(cfg.get("site_name") or "")), (B + (1, 4, 0), "ticks", api_up)]
    for part in (_mib_services, _mib_requests, _mib_mdns, _mib_alerts, _mib_cert, _mib_host, _mib_mail,
                 _mib_logs, _mib_upgrade, _mib_metrics):
        try:
            rows += part(ctx, B)
        except Exception as e:                          # noqa: BLE001
            sys.stderr.write("api: SNMP, %s: %s\n" % (part.__name__[5:], e))
    return rows


def _mib_services(ctx, B):
    """.2: the services' table - fake-igd.service, fake-igd-api.service, avahi-daemon.service."""
    rows = []
    for i, (unit, st) in enumerate(sorted(unit_states().items()), 1):
        rows += [(B + (2, 1, 1, 1, i), "int", i), (B + (2, 1, 1, 2, i), "str", unit),
                 (B + (2, 1, 1, 3, i), "str", str(st)), (B + (2, 1, 1, 4, i), "int", 1 if st == "active" else 0)]
    return rows


def _mib_requests(ctx, B):
    """.3: the request log - by action, AddPortMapping by its answer, the ports, the devices, the mappings."""
    import upnp as U
    try:
        ev = U.read_events(ctx.cfg)
    except SystemExit:
        ev = []
    by_action, by_result, clients, ports = collections.Counter(), collections.Counter(), set(), set()
    day, last = time.time() - 86400, 0.0
    asked_day = refused_day = 0
    for e in ev:
        by_action[e.get("action") or "?"] += 1
        clients.add(e.get("client"))
        t = e["_t"].timestamp() if e.get("_t") else 0.0
        last = max(last, t)
        if e.get("action") == "AddPortMapping":
            r = str(e.get("result") or "?")
            by_result[r] += 1
            ports.add((e.get("client"), str(e.get("protocol") or "").upper(), e.get("external_port")))
            if t >= day:
                asked_day += 1
                refused_day += r != "ok"
    try:
        with open(os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "mappings.json"), encoding="utf-8") as f:
            nmap = len(json.load(f))
    except (OSError, ValueError, TypeError):
        nmap = 0
    rows = [(B + (3, 1, 0), "counter64", sum(by_action.values())),
            (B + (3, 2, 0), "counter64", sum(by_result.values())),
            (B + (3, 3, 0), "counter64", by_result.get("ok", 0)),
            (B + (3, 4, 0), "counter64", sum(n for r, n in by_result.items() if r != "ok")),
            (B + (3, 5, 0), "gauge", _g(len(ports))),
            (B + (3, 6, 0), "gauge", _g(len([c for c in clients if c]))),
            (B + (3, 7, 0), "int", int(last)),
            (B + (3, 8, 0), "gauge", _g(nmap)),
            (B + (3, 9, 0), "gauge", _g(asked_day)),
            (B + (3, 10, 0), "gauge", _g(refused_day))]
    for i, (a, n) in enumerate(sorted(by_action.items()), 1):
        rows += [(B + (3, 20, 1, 1, i), "int", i), (B + (3, 20, 1, 2, i), "str", str(a)[:64]),
                 (B + (3, 20, 1, 3, i), "counter64", n)]
    for i, (r, n) in enumerate(sorted(by_result.items()), 1):
        rows += [(B + (3, 21, 1, 1, i), "int", i), (B + (3, 21, 1, 2, i), "str", r[:64]),
                 (B + (3, 21, 1, 3, i), "counter64", n)]
    return rows


def _mib_mdns(ctx, B):
    """.4: the mDNS reflector (avahi-daemon), the services it sees, other UPnP routers."""
    import upnp as U
    av = unit_states().get("avahi-daemon.service")
    n, at = mdns_count(ctx.store)
    rows = [(B + (4, 1, 0), "int", 1 if av == "active" else 0), (B + (4, 2, 0), "str", av or "not installed"),
            (B + (4, 3, 0), "gauge", _g(n or 0)), (B + (4, 4, 0), "int", int(float(at or 0)))]
    try:
        rows.append((B + (4, 5, 0), "gauge", _g(len(U.status_data(ctx.cfg).get("other_igd") or []))))
    except (SystemExit, Exception):                    # noqa: BLE001
        pass
    return rows


def alert_index(key):
    """The row of an alert in fakeIgdAlertTable, from its key: the same while it lasts (1.9.11) - the row's number
    in the sorted list moved when another came or went, and the monitoring's items read their neighbour's."""
    return zlib.crc32(str(key).encode("utf-8")) % 2147483646 + 1


def alert_indexes(probs):
    """[(index, (key, problem))] - each key its own index (the next free one, were two to meet)."""
    out, taken = [], set()
    for k, p in sorted(probs.items()):
        i = alert_index(k)
        while i in taken:
            i = i % 2147483646 + 1
        taken.add(i)
        out.append((i, (k, p)))
    return out


def _mib_alerts(ctx, B):
    """.5: what the alerts see wrong now (as otp's otpAlerts)."""
    probs = _problems(ctx)
    rows = [(B + (5, 1, 0), "gauge", sum(1 for p in probs.values() if p.get("level") == "bad")),
            (B + (5, 2, 0), "gauge", sum(1 for p in probs.values() if p.get("level") != "bad"))]
    for i, (k, p) in alert_indexes(probs):
        rows += [(B + (5, 3, 1, 1, i), "int", i), (B + (5, 3, 1, 2, i), "str", k[:255]),
                 (B + (5, 3, 1, 3, i), "str", p.get("level") or ""),
                 (B + (5, 3, 1, 4, i), "str", str(p.get("title") or "")[:255]),
                 (B + (5, 3, 1, 5, i), "str", str(p.get("said") or "")[:255])]
    return rows


def _mib_cert(ctx, B):
    """.6: the pages' certificate."""
    c = certificate()
    if not c.get("until"):
        return [(B + (6, 1, 0), "str", c.get("file") or "")]
    return [(B + (6, 1, 0), "str", c["file"]), (B + (6, 2, 0), "str", (c.get("subject") or "")[:255]),
            (B + (6, 3, 0), "int", int(c["days"] // 1)), (B + (6, 4, 0), "int", int(c["until"]))]


def _mib_host(ctx, B):
    """.10: this machine, as otp's otpHost - CPU, memory, disks, network as counters (a rate is the
    monitor's to make), the load, the file systems fake-igd lives on."""
    B = B + (10,)
    ab = sys.modules.get("api_about")
    raw = ab._load_raw() if ab is not None and hasattr(ab, "_load_raw") else {}
    m = machine()
    l1, l5, l15 = m.get("load") or (0.0, 0.0, 0.0)
    rows = [(B + (1, 0), "counter64", int(raw.get("cpu_idle") or 0)),
            (B + (2, 0), "counter64", int(raw.get("cpu_all") or 0)),
            (B + (3, 0), "int", m.get("cpus") or 1),
            (B + (4, 0), "gauge", _g(round(l1 * 100))), (B + (5, 0), "gauge", _g(round(l5 * 100))),
            (B + (6, 0), "gauge", _g(round(l15 * 100))),
            (B + (7, 0), "gauge", _g(int(raw.get("mem_total") or m.get("mem_total") or 0) // 1024)),
            (B + (8, 0), "gauge", _g(int(raw.get("mem_used") or 0) // 1024 or
                                     (int(m.get("mem_total") or 0) - int(m.get("mem_available") or 0)) // 1024)),
            (B + (9, 0), "gauge", _g(int(raw.get("swap_used") or 0) // 1024)),
            (B + (10, 0), "counter64", int(raw.get("disk_rd") or 0)),
            (B + (11, 0), "counter64", int(raw.get("disk_wr") or 0)),
            (B + (12, 0), "counter64", int(raw.get("net_rx") or 0)),
            (B + (13, 0), "counter64", int(raw.get("net_tx") or 0)),
            (B + (14, 0), "gauge", _g(m.get("uptime") or 0))]
    for i, d in enumerate(disks(ctx.cfg), 1):
        try:
            st = os.statvfs(d["path"])
            ipct = round(100.0 * (st.f_files - st.f_ffree) / st.f_files) if st.f_files else 0
        except OSError:
            ipct = 0
        rows += [(B + (20, 1, 1, i), "int", i), (B + (20, 1, 2, i), "str", d["path"]),
                 (B + (20, 1, 3, i), "gauge", _g(d["total"] // 1024)),
                 (B + (20, 1, 4, i), "gauge", _g(d["used"] // 1024)),
                 (B + (20, 1, 5, i), "gauge", _g(d["free"] // 1024)),
                 (B + (20, 1, 6, i), "gauge", _g(round(d["pct"]))),
                 (B + (20, 1, 7, i), "gauge", _g(ipct))]
    return rows


def _mib_mail(ctx, B):
    """.14: the outgoing mail, by state (otp's otpMail)."""
    import igd_mail
    q = igd_mail.counts(ctx.store)
    return [(B + (14, i, 0), "gauge", _g(q.get(k, 0))) for i, k in enumerate(igd_mail.STATES, 1)]


def _mib_logs(ctx, B):
    """.17: the logs sent to syslog servers (SIEM): on, in trouble, lines sent."""
    si = ctx.store.meta_json("siem:state") or {}
    try:
        on = bool(sys.modules["api_siem"]._settings(ctx).get("siem"))
    except Exception:                                   # noqa: BLE001
        on = bool(_pn_value(ctx.store, "siem"))
    return [(B + (17, 1, 0), "int", 1 if on else 0), (B + (17, 2, 0), "int", 1 if si.get("trouble") else 0),
            (B + (17, 3, 0), "counter64", sum(int(v or 0) for v in (si.get("sent") or {}).values()))]


def _pn_value(store, key):
    import igd_panes as PN
    try:
        return PN.value(store, key)
    except KeyError:
        return None


def _mib_upgrade(ctx, B):
    """.18: a newer fake-igd out (as Upgrades last found it)."""
    import upnp as U
    import igd_online as ON
    row = ON.view(ctx.store.meta_json("upgrade:online") or {}, U.VERSION)
    return [(B + (18, 1, 0), "int", 1 if row.get("newer") else 0),
            (B + (18, 2, 0), "str", str((row.get("newest") or {}).get("version") or ""))]


def _mib_metrics(ctx, B):
    """.9: every sample /metrics gives, as a table (name, labels, value) - nothing it has is missing here."""
    rows = []
    i = 0
    for line in metrics_text(ctx).split("\n"):
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([a-zA-Z_:][\w:]*)(\{.*\})? (\S+)$", line)
        if m:
            i += 1
            rows += [(B + (9, 1, 1, 1, i), "int", i), (B + (9, 1, 1, 2, i), "str", m.group(1)),
                     (B + (9, 1, 1, 3, i), "str", (m.group(2) or "")[1:-1][:255]),
                     (B + (9, 1, 1, 4, i), "str", m.group(3))]
    return rows


def snmp_tick(ctx):
    """Once a minute: the agent started, what the alerts see, and a trap for each thing that went wrong
    and for each that is right again (otp's snmp_traps_tick)."""
    AGENT["ctx"] = ctx
    if not _setting(ctx.store, "snmp"):
        return
    ag = snmp_start(ctx)
    try:
        al = sys.modules.get("api_alerts") or __import__("api_alerts")
        cur = al.problems(ctx, al.cfg_of(ctx.store))
        AGENT["problems"], AGENT["problems_at"] = cur, time.time()
    except Exception as e:                              # noqa: BLE001
        sys.stderr.write("api: SNMP, what the alerts see: %s\n" % e)
        return
    import igd_snmp as SN
    if not ag or not _setting(ctx.store, "snmp_traps") or not SN.trap_targets(_setting(ctx.store, "snmp_trap_to")):
        return
    if not snmp_c(ctx.store):
        return
    S = ctx.store
    known = {k: v for k, v in (S.meta_json("snmp:trapped") or {}).items() if isinstance(v, dict)}
    for k in [k for k in known if re.match(r"^(newer:|backup:\d+\Z)", k)]:      # the keys before 1.9.11
        known.setdefault("newer" if k.startswith("newer:") else "backup:failed", known[k])
        known.pop(k)
    delay = 60 * int(_pn_value(S, "alerts_delay_min") or 0)
    now = time.time()
    changed = False
    for k, p in cur.items():
        was = known.get(k)
        if was and was.pop("missing_since", None) is not None:
            changed = True                              # back before it was over (otp 1.0.271)
        if not was:
            known[k] = was = {"since": now, "sent": False, "level": p.get("level")}
            changed = True
        since = float(was.get("since") or now)
        if (not was.get("sent") and now - since >= delay) or \
                (was.get("sent") and was.get("level") == "warn" and p.get("level") == "bad"):
            got = ag.trap(SNMP_BASE, 1, [("str", k), ("str", p.get("level") or ""),
                                         ("str", str(p.get("title") or "")[:255]),
                                         ("str", str(p.get("said") or "")[:255]), ("str", _node())])
            was.update(sent=any(v == "sent" for v in got.values()), level=p.get("level"))
            changed = True
    for k in [k for k in known if k not in cur]:
        if known[k].get("sent") and delay:
            # Over only once away as long as it had to be there (otp 1.0.271): no flapping traps.
            if not known[k].get("missing_since"):
                known[k]["missing_since"] = now
                changed = True
            if now - float(known[k].get("missing_since") or now) < delay:
                continue
        p = known.pop(k)
        changed = True
        if p.get("sent"):
            ag.trap(SNMP_BASE, 2, [("str", k), ("str", "ok"), ("str", "right again"), ("str", ""),
                                   ("str", _node())])
    if changed:
        S.set_meta("snmp:trapped", json.dumps(known))


def snmp_view(ctx):
    """The agent's state and the settings' - the pane's card (otp's snmp_view, one machine)."""
    import igd_snmp as SN
    S = ctx.store
    c = snmp_c(S)
    st = dict(SN.SNMP_STATE) if AGENT["a"] is not None else {}
    if not st:
        # Never started in this process (off since it started): the engine ID as it will be (made now,
        # once, as otp's is - the receiver of traps can be set before SNMPv3 is switched on) and the
        # starts counted so far.
        sd = ctx.cfg.get("state_dir") or "/var/lib/fake-igd"
        st = {}
        try:
            st["engine"] = SN.snmp_engine_id(sd).hex() if os.path.isdir(sd) else ""
        except (OSError, ValueError):
            pass
        try:
            with open(os.path.join(sd, "snmp-boots")) as f:
                st["boots"] = int(f.read().strip() or 0)
        except (OSError, ValueError):
            pass
    traps = bool(_setting(S, "snmp_traps"))
    return {"on": bool(_setting(S, "snmp")), "ready": bool(c), "node": _node(), "at": time.time(),
            "agent": st, "user": c["user"] if c else str(_setting(S, "snmp_user") or ""),
            "auth": str(_setting(S, "snmp_auth") or "SHA-256"), "priv": str(_setting(S, "snmp_priv") or "AES-128"),
            "port": int(_setting(S, "snmp_port") or 161), "bind": str(_setting(S, "snmp_bind") or ""),
            "from": list(_setting(S, "snmp_from") or []),
            "base": ".".join(str(x) for x in SNMP_BASE), "traps": traps,
            "trap_to": ["%s:%d" % t for t in SN.trap_targets(_setting(S, "snmp_trap_to"))] if traps else [],
            "mib": SNMP_MIB_FILE, "mib_here": bool(_mib_path()), "zabbix_here": bool(_mib_path("zabbix"))}


def snmp_get_route(ctx):
    if not ctx.me:
        raise PermissionError("not signed in")
    return snmp_view(ctx)


def snmp_post_route(ctx):
    """{action: test} - this machine asks its own agent as the monitoring would (discovery, then an authPriv
    GET); {action: trap} - a test trap to every receiver set."""
    import igd_snmp as SN
    me = ctx.need("fulladmin")
    act = str(ctx.body().get("action") or "")
    if act not in ("test", "trap"):
        raise ValueError("no such thing to do")
    if not _setting(ctx.store, "snmp"):
        raise ValueError("SNMPv3 is off")
    c = snmp_c(ctx.store)
    if not c:
        raise ValueError("the SNMPv3 user and its two passphrases are not set")
    ag = snmp_start(ctx)
    t0 = time.time()
    out = {"at": time.time(), "engine": ag.engine.hex() if ag else ""}
    if act == "trap":
        if not SN.trap_targets(_setting(ctx.store, "snmp_trap_to")) or not _setting(ctx.store, "snmp_traps"):
            raise ValueError("no receiver of traps is set")
        try:
            got = ag.trap(SNMP_BASE, 3, [("str", "test"), ("str", "info"),
                                         ("str", "a test trap from fake-igd, sent by %s" % me["name"]),
                                         ("str", ""), ("str", _node())])
        except (OSError, ValueError) as e:
            return dict(out, ok=False, error=str(e))
        ctx.event("%s sent a test SNMP trap to %s" % (me["name"], ", ".join(sorted(got)) or "nobody"))
        return dict(out, ok=bool(got) and all(v == "sent" for v in got.values()), sent=got)
    ag.looked = 0.0
    for _ in range(30):                                 # just switched on: listening within the second
        if SN.SNMP_STATE.get("listening") or SN.SNMP_STATE.get("error"):
            break
        time.sleep(0.1)
    if not SN.SNMP_STATE.get("listening"):
        return dict(out, ok=False, error=SN.SNMP_STATE.get("error") or "not listening")
    bound = str(_setting(ctx.store, "snmp_bind") or "").strip()
    at = bound if bound and bound not in ("0.0.0.0", "::") else "127.0.0.1"
    SN.SNMP_SELF["until"] = time.time() + 5
    try:
        got = SN.snmp_get(at, int(SN.SNMP_STATE.get("port") or 161), c,
                          [SN.SNMP_SYS + (1, 0), SN.SNMP_SYS + (3, 0), SNMP_BASE + (1, 1, 0)])
    except socket.timeout:
        return dict(out, ok=False, error="no answer in 3 s from %s:%s" % (at, SN.SNMP_STATE.get("port")))
    except (OSError, ValueError, IndexError) as e:
        return dict(out, ok=False, error=str(e) or e.__class__.__name__)
    return dict(out, ok=True, said=got, ms=int((time.time() - t0) * 1000))


SNMP_FILES = {"mib": (SNMP_MIB_FILE, SNMP_MIB_FILE),
              "zabbix": (os.path.join("zabbix", "fake_igd_by_snmp_zabbix7.yaml"), "fake_igd_by_snmp_zabbix7.yaml")}


def _mib_path(what="mib"):
    """Where the package's file is: beside this file (installed: /opt/fake-igd), or in deploy/ (the source)."""
    rel = SNMP_FILES[what][0]
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, rel), os.path.join(os.path.dirname(here), "deploy", rel),
              os.path.join(here, "deploy", rel)):
        if os.path.isfile(p):
            return p
    return ""


def snmp_file(ctx):
    """FAKE-IGD-MIB or the Zabbix 7.0 template, as the package has them (otp's snmpfile) - nothing of this
    server's own is in them: the user and its passphrases are set on the host in Zabbix."""
    if not ctx.me:
        raise PermissionError("not signed in")
    what = str(ctx.arg("what") or "")
    if what not in SNMP_FILES:
        raise ValueError("no such file")
    p = _mib_path(what)
    if not p:
        raise ValueError("%s is not in this installation" % SNMP_FILES[what][1])
    with open(p, encoding="utf-8") as f:
        return {"name": SNMP_FILES[what][1], "text": f.read(4 << 20)}


ROUTES = {
    ("GET", "/api/monitor"): monitor_get,
    ("POST", "/api/monitor"): monitor_post,
    ("POST", "/api/metrics/scrape"): scrape,
    ("GET", "/api/snmp"): snmp_get_route,
    ("POST", "/api/snmp"): snmp_post_route,
    ("GET", "/api/snmpfile"): snmp_file,
}


def background(ctx):
    """The SNMP agent started and its traps (1.7.2); every 5 minutes, while metrics or SNMP are on: how
    many services avahi-browse sees (it takes seconds)."""
    import igd_seal as SEAL
    SEAL.seal_settings(ctx.store, list(SEALED))
    try:
        snmp_tick(ctx)
    except Exception as e:                              # noqa: BLE001 - the metrics go on
        sys.stderr.write("api: SNMPv3: %s\n" % e)
    if not (_setting(ctx.store, "metrics") or _setting(ctx.store, "snmp")):
        return
    _n, at = mdns_count(ctx.store)
    if at and time.time() - float(at) < MDNS_EVERY_S:
        return
    n = None
    try:
        import upnp_mdns as MD
        n = len(MD.services(resolve=False, timeout=8))
    except Exception:                                   # noqa: BLE001 - not there, not running: no number
        n = None
    ctx.store.set_meta("monitor:mdns", json.dumps({"n": n, "at": time.time()}))
