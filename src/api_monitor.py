"""api_monitor.py - Settings → Monitoring (1.6.0): Prometheus metrics at /metrics, as otp's.

nginx sends `location = /metrics` to web/metrics.php, which hands the scraper's bearer
token to POST /api/metrics/scrape (a PUBLIC route: no sign-in, the API token still); the
token and where the request comes from are checked here before anything is said. A wrong
or missing token is a 401, a network not let in a 403, metrics switched off a 404.

What it says: this machine (load, memory, uptime, disks) and fake-igd (the requests and
the ports asked for, the clients, the mappings, the mDNS services, the services' states,
the outgoing mail, the alerts open, syslog, the certificate, a new version).

SNMPv3 is not here - see the pane: an agent needs UDP port 161 (CAP_NET_BIND_SERVICE for the
API, a firewall rule), BER, USM with HMAC and AES-CFB, which the standard library has not
(otp carries its own AES in Python for it) - Prometheus says the same and more.
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

NAME = "monitor"
CERT_FILE = os.environ.get("FAKE_IGD_NGINX_CERT", "/etc/nginx/certs/fake-igd.pem")
MDNS_EVERY_S = 300


def _net(v):
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        return "%s is not an address or a net" % v
    return ""


SETTINGS = [
    {"key": "metrics", "name": "Prometheus metrics (/metrics)", "kind": "bool", "default": False,
     "says": "This machine answers <code>https://SERVER/metrics</code> in Prometheus’ format - the requests and "
             "the ports asked for, the clients, the mappings, the mDNS services, the services, the disks, the "
             "mail, the alerts. Asked with the token below."},
    {"key": "metrics_token", "name": "Its token (Bearer)", "kind": "secret", "default": "", "most": 200,
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
    return SEAL.unseal_or(store, v) if key == "metrics_token" else v


def on_saved(ctx, changed):
    import igd_seal as SEAL
    SEAL.seal_settings(ctx.store, ["metrics_token"])        # kept sealed in the database (igd_seal)


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
            "snmp": {"supported": False}}


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


ROUTES = {
    ("GET", "/api/monitor"): monitor_get,
    ("POST", "/api/monitor"): monitor_post,
    ("POST", "/api/metrics/scrape"): scrape,
}


def background(ctx):
    """Every 5 minutes, while metrics are on: how many services avahi-browse sees (it takes seconds)."""
    import igd_seal as SEAL
    SEAL.seal_settings(ctx.store, ["metrics_token"])
    if not _setting(ctx.store, "metrics"):
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
