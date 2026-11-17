"""api_upnp.py - fake-igd's own panes of Settings, beside their settings (1.6.1).

How it answers, UPnP network, Notifications (ntfy), Logs and state: their settings are
config.json's (the generic settings code draws them); this module gives the cards otp shows
beside its own settings:

  GET  /api/upnp/here    what listens where now: the service, every interface of the machine and
                         whether fake-igd uses it (and why not), the sockets (SSDP 1900/udp, the
                         description and SOAP port), the description's URLs, the public IP and where
                         it came from, other UPnP routers heard, what was answered in the last 24 h
  POST /api/upnp/try     {add: "", "udp", "tcp"} - fake-igd asked as the PS5 asks it, every step shown
                         (as otp's mail test): SSDP M-SEARCH, the description, controlURL, SOAP
                         GetStatusInfo / GetExternalIPAddress, and - asked - a test AddPortMapping
                         and its DeletePortMapping
  GET  /api/upnp/ntfy    how notifications go, what is sent when, the last sends (from the main log),
                         the tests, the certificate authority of a private server
  POST /api/upnp/ntfy    {action: "test", title?} - one test, every step shown (looked up, connected,
                         TLS, sent); {action: "ca", mode: "add", ca: PEM} / {mode: "drop"} - the CA of a
                         private ntfy server kept beside config.json and set as ntfy_ca_file
  GET  /api/upnp/logs    the files: the main log, the request log, the rotated ones, the state
                         folder, the database - their sizes, and the disk they are on
"""
import collections
import fcntl
import glob
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timedelta

import upnp as U

NAME = "upnp"
IGD_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
WAN_SVC = "urn:schemas-upnp-org:service:WANIPConnection:1"
TESTS_KEPT = 20


def _api():
    """The API's own module (run as a script: __main__) - for config.json's settings."""
    for name in ("fake_igd_api", "__main__"):
        m = sys.modules.get(name)
        if m is not None and hasattr(m, "settings_save"):
            return m
    return None


def _node():
    return socket.gethostname().split(".")[0]


# ---- the interfaces of the machine ---------------------------------------------------------
def kernel_ifaces():
    """Every interface: its IPv4 address and mask, up, loopback, multicast, MAC (no tools needed)."""
    out = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _i, name in socket.if_nameindex():
            req = struct.pack("256s", name[:15].encode())
            row = {"name": name, "ipv4": "", "prefix": None, "up": False, "loopback": False, "multicast": False,
                   "mac": "", "state": ""}
            try:
                flags = struct.unpack("H", fcntl.ioctl(s.fileno(), 0x8913, req)[16:18])[0]
                row.update(up=bool(flags & 0x1), loopback=bool(flags & 0x8), multicast=bool(flags & 0x1000))
            except OSError:
                pass
            try:
                row["ipv4"] = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, req)[20:24])
                row["prefix"] = sum(bin(int(x)).count("1") for x in mask.split("."))
            except OSError:
                pass
            for f, k in (("address", "mac"), ("operstate", "state")):
                try:
                    with open("/sys/class/net/%s/%s" % (name, f)) as fh:
                        row[k] = fh.read().strip()
                except OSError:
                    pass
            out.append(row)
    finally:
        s.close()
    return out


def uses(cfg, row):
    """(used, why not) - the service's own rule (fake-igd.py list_interfaces)."""
    want = set(cfg.get("interfaces") or [])
    skip = set(cfg.get("exclude_interfaces") or [])
    if want and row["name"] not in want:
        return False, "not one of the interfaces chosen"
    if row["name"] in skip:
        return False, "left out"
    if not row["up"]:
        return False, "down"
    if row["loopback"] and not want:
        return False, "loopback"
    if not row["multicast"]:
        return False, "no multicast"
    if not row["ipv4"]:
        return False, "no IPv4 address"
    return True, ""


# ---- what the main log says since the service last started ---------------------------------
LOG_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:,\d+)?\s+(\w+)\s+(.*)$")


def _when(stamp):
    try:
        return time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def log_tail(cfg, most=4 * 1024 * 1024):
    path = cfg.get("log_file") or ""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - most))
            data = f.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > most else lines


def since_start(lines):
    start = 0
    for i, ln in enumerate(lines):
        if re.search(r"service: fake-igd \S+ starting|===== fake-igd .*starting", ln):
            start = i
    d = {"started": None, "listening": collections.OrderedDict(), "public": None, "public_from": "",
         "public_said": "", "other": [], "said": []}
    m = LOG_RE.match(lines[start]) if lines else None
    if m and "starting" in m.group(3):
        d["started"] = _when(m.group(1))
    for ln in lines[start:]:
        m = LOG_RE.match(ln)
        if not m:
            continue
        t, lvl, msg = _when(m.group(1)), m.group(2), m.group(3)
        x = re.search(r"net: listening on (\S+) \(([\d.]+)\)(?: - (\S+))?", msg)
        if x:
            d["listening"][x.group(1)] = {"name": x.group(1), "ipv4": x.group(2), "url": x.group(3) or "", "at": t}
            continue
        x = re.search(r"net: (\S+) \(([\d.]+)\) is gone", msg)
        if x:
            d["listening"].pop(x.group(1), None)
            continue
        x = re.search(r"net: the public IP is (\S+) \(from (\S+)\)", msg)
        if x:
            d["public"], d["public_from"], d["public_said"] = x.group(1), x.group(2), ""
            continue
        x = re.search(r"net: (looking up the public IP at \S+ failed: .*|the public IP could not be found.*)", msg)
        if x:
            d["public_said"] = x.group(1)
        if lvl.lower() in ("warning", "error", "critical") and "OTHER UPnP ROUTER" not in msg:
            d["said"].append({"at": t, "level": lvl.lower(), "words": msg})
    for ln in lines:
        x = re.search(r"OTHER UPnP ROUTER on the network: (\S+) announces NT=(\S+)", ln)
        m = LOG_RE.match(ln)
        if x:
            row = {"addr": x.group(1), "nt": x.group(2), "at": _when(m.group(1)) if m else None}
            d["other"] = [o for o in d["other"] if o["addr"] != row["addr"]] + [row]
    d["listening"] = list(d["listening"].values())
    d["said"] = d["said"][-6:]
    return d


# ---- the sockets (/proc/net) -------------------------------------------------------------------
def _hex_addr(h):
    ip, port = h.split(":")
    if len(ip) == 8:
        addr = socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(ip, 16)))
    else:
        raw = bytes.fromhex(ip)
        addr = socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return addr, int(port, 16)


def sockets(ports):
    """Who listens on these ports: [{proto, addr, port}] - TCP in LISTEN, UDP bound."""
    out = []
    for proto, f, want_state in (("tcp", "/proc/net/tcp", "0A"), ("tcp", "/proc/net/tcp6", "0A"),
                                 ("udp", "/proc/net/udp", None), ("udp", "/proc/net/udp6", None)):
        try:
            with open(f) as fh:
                next(fh)
                for ln in fh:
                    parts = ln.split()
                    if len(parts) < 4 or (want_state and parts[3] != want_state):
                        continue
                    addr, port = _hex_addr(parts[1])
                    if (proto, port) in ports:
                        row = {"proto": proto, "addr": addr, "port": port}
                        if row not in out:
                            out.append(row)
        except (OSError, ValueError, StopIteration):
            continue
    return out


_ANSWERED = {}


def answered_24h(cfg):
    """(requests, {result: AddPortMappings}) of the last 24 hours - read again only when the request
    log changed or a minute went by (the pane asks every 5 s)."""
    path = cfg.get("request_log") or ""
    try:
        st = os.stat(path)
        sig = (path, st.st_size, st.st_mtime, int(time.time() // 60))
    except OSError:
        return 0, {}
    if _ANSWERED.get("sig") == sig:
        return _ANSWERED["got"]
    try:
        ev = U.read_events(cfg, since=datetime.now().astimezone() - timedelta(hours=24))
    except (SystemExit, Exception):                      # noqa: BLE001 - an unreadable log says nothing
        ev = []
    counts = collections.Counter()
    for e in ev:
        if e.get("action") == "AddPortMapping" and e.get("description") != "upnp-cli-test":
            counts[e.get("result") or "ok"] += 1
    _ANSWERED.update(sig=sig, got=(len(ev), dict(counts)))
    return _ANSWERED["got"]


# ---- GET /api/upnp/here ---------------------------------------------------------------------------
def here(ctx):
    cfg = ctx.cfg
    try:
        svc = U.service_info()
    except Exception:                                    # noqa: BLE001 - no systemd here
        svc = {}
    ifs = kernel_ifaces()
    for r in ifs:
        r["used"], r["why"] = uses(cfg, r)
    lg = since_start(log_tail(cfg))
    port = int(cfg.get("http_port") or 5000)
    socks = sockets({("tcp", port), ("udp", 1900)})
    asked, answered = answered_24h(cfg)
    ext = str(cfg.get("external_ip") or "auto")
    public = {"set": ext, "now": ext if ext != "auto" else lg["public"],
              "from": "set by hand (external_ip)" if ext != "auto" else (lg["public_from"] or ""),
              "said": "" if ext != "auto" else lg["public_said"]}
    listening = lg["listening"]
    if not listening and svc.get("ActiveState") == "active":
        listening = [{"name": r["name"], "ipv4": r["ipv4"], "url": "", "at": None} for r in ifs if r["used"]]
    for x in listening:
        x["url"] = x.get("url") or "http://%s:%d/rootDesc.xml" % (x["ipv4"], port)
    return {
        "node": _node(), "at": time.time(),
        "service": {"state": svc.get("ActiveState", "unknown"), "sub": svc.get("SubState", "?"),
                    "pid": svc.get("MainPID", "0"), "since": svc.get("ActiveEnterTimestamp", ""),
                    "restarts": svc.get("NRestarts", "")},
        "started": lg["started"], "mode": cfg.get("mode"), "mapping_response": cfg.get("mapping_response"),
        "allowed_clients": cfg.get("allowed_clients") or [], "http_port": port,
        "interfaces_set": cfg.get("interfaces") or [], "exclude_set": cfg.get("exclude_interfaces") or [],
        "kernel": ifs, "listening": listening, "sockets": socks, "public": public, "other": lg["other"],
        "said": lg["said"], "answered": answered, "asked_24h": asked,
        "rescan_s": cfg.get("interface_rescan_seconds"), "announce_s": cfg.get("notify_interval_seconds"),
    }


# ---- POST /api/upnp/try: asked as the PS5 asks --------------------------------------------------
def _step(steps, what, fn):
    t0 = time.time()
    try:
        ok, said, val = fn()
    except Exception as e:                               # noqa: BLE001 - a step that broke is a failed step
        vm = getattr(e, "verify_message", "")
        said = ("the certificate is not trusted: %s - a server of your own authority? Add it below" % vm) if vm \
            else (str(getattr(e, "reason", "") or e) or e.__class__.__name__)
        ok, val = False, None
    steps.append({"what": what, "ok": bool(ok), "said": said, "ms": int((time.time() - t0) * 1000)})
    return ok, val


def try_it(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    add = str(b.get("add") or "")
    if add not in ("", "udp", "tcp"):
        raise ValueError("add: udp, tcp or nothing")
    cfg = ctx.cfg
    steps, t0 = [], time.time()
    found = {}

    def search():
        got = U.ssdp_search(IGD_ST, 2.5)
        found.update(got)
        mine = [(s, l) for (s, l), h in got.items() if "fake-igd" in h.get("SERVER", "")]
        others = sorted({s for (s, l), h in got.items() if "fake-igd" not in h.get("SERVER", "")})
        words = "%d answer(s)" % len(got)
        if mine:
            words += " - fake-igd from %s" % ", ".join(sorted({s for s, _l in mine}))
        if others:
            words += " - ANOTHER UPnP router: %s (the PS5 may ask it instead)" % ", ".join(others)
        if not got:
            words = "nobody answered the multicast M-SEARCH (239.255.255.250:1900)"
        return bool(mine), words, mine

    ok, mine = _step(steps, "SSDP: M-SEARCH for an InternetGatewayDevice, as the PS5 sends it", search)
    if not ok:
        used = [r for r in kernel_ifaces() if uses(cfg, r)[0]]
        for r in used:
            def uni(r=r):
                got = U.ssdp_search(IGD_ST, 1.5, r["ipv4"])
                hit = [(s, l) for (s, l), h in got.items() if "fake-igd" in h.get("SERVER", "")]
                return bool(hit), ("answers over unicast - multicast did not reach it: the firewall drops "
                                   "udp 1900 (Settings - Firewall and access)" if hit else "no answer"), hit
            okk, hit = _step(steps, "SSDP: unicast M-SEARCH to %s (%s)" % (r["ipv4"], r["name"]), uni)
            if okk:
                mine = hit
                break
    if not mine:
        why = ("mode is passive - fake-igd only listens" if cfg.get("mode") == "passive" else
               "allowed_clients does not let this server in" if cfg.get("allowed_clients") else
               "fake-igd.service does not answer - is it running? (the log: Settings - About)")
        return _tried(ctx, me, steps, t0, False, "fake-igd did not answer: %s" % why)
    loc = sorted({l for _s, l in mine})[0]
    holder = {}

    def desc():
        import urllib.request
        with urllib.request.urlopen(loc, timeout=5) as r:
            text = r.read().decode("utf-8", "replace")
        holder["desc"] = text
        return r.status == 200, "HTTP %d, %d bytes - %s" % (r.status, len(text), loc), text

    ok, _t = _step(steps, "The device description (LOCATION)", desc)
    if not ok:
        return _tried(ctx, me, steps, t0, False, "the description could not be read - tcp %s let in?"
                      % cfg.get("http_port"))

    def control():
        import xml.etree.ElementTree as ET
        root = ET.fromstring(holder["desc"])
        base = loc.rsplit("/", 1)[0]
        for svc in root.iter():
            if svc.tag.endswith("service"):
                kids = {c.tag.rsplit("}", 1)[-1]: (c.text or "") for c in svc}
                if "WANIPConnection" in kids.get("serviceType", ""):
                    ctl = kids.get("controlURL", "")
                    ctl = ctl if ctl.startswith("http") else base + ctl
                    return True, ctl, ctl
        return False, "no WANIPConnection service in the description", None

    ok, ctl = _step(steps, "The WANIPConnection service (controlURL)", control)
    if not ok:
        return _tried(ctx, me, steps, t0, False, "the description has no WANIPConnection service")
    for action, field in (("GetStatusInfo", "NewConnectionStatus"), ("GetExternalIPAddress", "NewExternalIPAddress")):
        def soap(action=action, field=field):
            code, text = U.soap_call(ctl, WAN_SVC, action)
            val = U.xml_find(text, field)
            good = code == 200 and (action != "GetExternalIPAddress" or bool(val))
            return good, "HTTP %d, %s = %s%s" % (code, field, val or "(empty)", "" if good or code != 200 else
                                                 " - set the public IP (How it answers)"), val
        _step(steps, "SOAP %s" % action, soap)
    if add:
        def mapping():
            lan = urllib.parse.urlparse(ctl).hostname
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((lan, 1))
                mine_ip = s.getsockname()[0]
            finally:
                s.close()
            code, text = U.soap_call(ctl, WAN_SVC, "AddPortMapping", {
                "NewRemoteHost": "", "NewExternalPort": 9, "NewProtocol": add.upper(), "NewInternalPort": 9,
                "NewInternalClient": mine_ip, "NewEnabled": 1, "NewPortMappingDescription": "upnp-cli-test",
                "NewLeaseDuration": 60})
            if code == 200:
                code2, _x = U.soap_call(ctl, WAN_SVC, "DeletePortMapping", {
                    "NewRemoteHost": "", "NewExternalPort": 9, "NewProtocol": add.upper()})
                return True, "accepted (nothing is opened) - DeletePortMapping: HTTP %d" % code2, None
            return cfg.get("mapping_response") == "reject", "refused: HTTP %d, error %s (%s)" % (
                code, U.xml_find(text, "errorCode"), U.xml_find(text, "errorDescription")), None
        _step(steps, "SOAP AddPortMapping %s 9 (upnp-cli-test, left out of the ports)" % add.upper(), mapping)
    good = all(s["ok"] for s in steps if not s["what"].startswith("SSDP: unicast"))
    return _tried(ctx, me, steps, t0, good, "fake-igd answers as a UPnP router should" if good
                  else "fake-igd answers, but not everything as it should - see the steps")


def _tried(ctx, me, steps, t0, ok, said):
    ctx.event("%s tried fake-igd as the PS5 asks it: %s" % (me["name"], said), "info" if ok else "warn")
    return {"sent": ok, "said": said, "steps": steps, "took_ms": int((time.time() - t0) * 1000)}


# ---- notifications (ntfy) ------------------------------------------------------------------------
def _daemon():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "fake_igd_daemon", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake-igd.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ca_path():
    a = _api()
    folder = os.path.dirname(getattr(a, "CFG_PATH", "") or U.DEFAULT_CONFIG)
    return os.environ.get("FAKE_IGD_NTFY_CA") or os.path.join(folder, "ntfy-ca.pem")


PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def certs_of(text):
    """[{subject, issuer, from, until, fingerprint, self_signed}] of every certificate in PEM text."""
    out = []
    for pem in PEM_RE.findall(text or ""):
        try:
            der = ssl.PEM_cert_to_DER_cert(pem)
        except ValueError:
            continue
        info = {}
        fd, tmp = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(pem + "\n")
            info = ssl._ssl._test_decode_cert(tmp)          # noqa: SLF001 - stdlib's own reader of a certificate
        except Exception:                                  # noqa: BLE001
            info = {}
        finally:
            os.unlink(tmp)

        def name(seq):
            parts = dict(x[0] for x in seq or () if x)
            return parts.get("commonName") or ", ".join("%s=%s" % kv for kv in parts.items())
        subj, iss = name(info.get("subject")), name(info.get("issuer"))
        out.append({"subject": subj, "issuer": iss, "self_signed": bool(subj) and subj == iss,
                    "from": info.get("notBefore", ""), "until": info.get("notAfter", ""),
                    "fingerprint": hashlib.sha256(der).hexdigest(), "pem": pem})
    return out


def _until_iso(s):
    try:
        return datetime.utcfromtimestamp(ssl.cert_time_to_seconds(s)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return s


SEND_RE = re.compile(r"notify: (sent|sending) (?:\[([a-z_:]+)\] )?'(.*)' to (\S*?)(?: \((.*)\))?(?: failed: (.*))?$")


def _old_kind(title):
    """A send written before kinds were (1.8.2): its kind from its title."""
    t = title.lower()
    return "other_router" if "another router" in t else "test" if "test" in t else \
        "port_renew" if "renewed" in t else "port_refused" if "rejected" in t or "refused" in t else "port_new"


def sends(cfg, most=60, raw=False):
    """fake-igd.service's sends, from its log: {at, kind, title, host, ok, said, by}."""
    out = []
    for ln in log_tail(cfg, 8 * 1024 * 1024):
        m = LOG_RE.match(ln)
        if not m or "notify:" not in m.group(3):
            continue
        x = SEND_RE.search(m.group(3))
        if not x:
            continue
        title = x.group(3)
        out.append({"at": _when(m.group(1)), "title": title, "host": x.group(4), "ok": x.group(1) == "sent",
                    "said": x.group(5) if x.group(1) == "sent" else (x.group(6) or ""),
                    "kind": x.group(2) or _old_kind(title), "by": "fake-igd.service"})
    return out[-most:]


def ntfy_view(ctx):
    cfg = ctx.cfg
    try:
        tests = json.loads(ctx.store.get_meta("ntfy:tests") or "[]")
    except ValueError:
        tests = []
    mine = sys.modules.get("api_ntfy")
    rows = sends(cfg, 200) + [dict(t, kind="test", by=t.get("by") or "") for t in tests if isinstance(t, dict)] + \
        (mine.sent_rows(ctx.store) if mine is not None else [])
    rows.sort(key=lambda r: r.get("at") or 0, reverse=True)
    kinds = sorted({r.get("kind") or "" for r in rows} - {""})
    want = (ctx.q.get("kind") or [""])[0]
    if want:
        rows = [r for r in rows if r.get("kind") == want]
    url = str(cfg.get("ntfy_url") or "")
    ca_file = str(cfg.get("ntfy_ca_file") or "")
    ca = []
    ca_said = ""
    if ca_file:
        try:
            with open(ca_file, encoding="utf-8", errors="replace") as f:
                ca = certs_of(f.read())
        except OSError as e:
            ca_said = "%s cannot be read: %s" % (ca_file, e.strerror or e)
    for c in ca:
        c.pop("pem", None)
        c["from"], c["until"] = _until_iso(c["from"]), _until_iso(c["until"])
    p = urllib.parse.urlparse(url) if url else None
    auth = "a token" if cfg.get("ntfy_token") else ("user %s" % cfg.get("ntfy_user") if cfg.get("ntfy_user")
                                                    else "none")
    return {"on": bool(url), "url": url, "server": p.netloc if p else "", "topic": p.path.lstrip("/") if p else "",
            "auth": auth, "priority": cfg.get("ntfy_priority"), "tags": cfg.get("ntfy_tags") or "",
            "on_port": bool(url), "on_renew": bool(cfg.get("notify_on_renew")),
            "on_other": bool(cfg.get("notify_other_router")), "ca_file": ca_file,
            "ca_ours": bool(ca_file) and os.path.abspath(ca_file) == os.path.abspath(_ca_path()),
            "ca_list": ca, "ca_said": ca_said, "sends": rows[:120], "send_kinds": kinds, "kind": want,
            "at": time.time()}


def ntfy_test(ctx, me, b):
    cfg = dict(ctx.cfg)
    if any(k.startswith(("ntfy_", "notify_")) for k in (b.get("dirty") or [])):
        raise ValueError("save the notification settings first")
    url = str(cfg.get("ntfy_url") or "").strip()
    if not url:
        raise ValueError("no ntfy topic URL yet - fill it in and save it first")
    steps, t0 = [], time.time()
    p = urllib.parse.urlparse(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    proxy = ""
    try:
        import igd_proxy
        proxy = igd_proxy.url_for(None, "ntfy") or ""
    except Exception:                                    # noqa: BLE001
        proxy = ""
    if proxy:
        steps.append({"what": "Through the proxy", "ok": True, "said": re.sub(r"//[^@/]*@", "//", proxy), "ms": 0})
    else:
        addrs = []

        def look():
            got = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
            addrs[:] = sorted({g[4][0] for g in got})
            return True, "%s - %s" % (host, ", ".join(addrs)), None
        ok, _v = _step(steps, "Looked up", look)
        if ok:
            holder = {}

            def conn():
                s = socket.create_connection((host, port), timeout=8)
                holder["s"] = s
                return True, "%s:%d (%s)" % (host, port, s.getpeername()[0]), None
            ok, _v = _step(steps, "Connected to", conn)
            if ok and p.scheme == "https":
                def tls():
                    c = ssl.create_default_context(cafile=cfg.get("ntfy_ca_file") or None)
                    t = c.wrap_socket(holder["s"], server_hostname=host)
                    holder["s"] = t
                    cert = t.getpeercert() or {}
                    who = dict(x[0] for x in cert.get("subject", ()) if x).get("commonName", "?")
                    by = dict(x[0] for x in cert.get("issuer", ()) if x).get("commonName", "?")
                    return True, "%s, %s - %s, signed by %s, until %s%s" % (
                        t.version(), (t.cipher() or ["?"])[0], who, by, cert.get("notAfter", "?"),
                        " (the CA of your own)" if cfg.get("ntfy_ca_file") else ""), None
                ok, _v = _step(steps, "TLS", tls)
            try:
                holder.get("s") and holder["s"].close()
            except OSError:
                pass
        if not ok:
            return _ntfy_done(ctx, me, steps, t0, False, steps[-1]["said"] if steps else "not sent")
    title = "fake-igd test"
    words = "A test notification from the fake-igd pages on %s, asked by %s." % (socket.gethostname(), me["name"])

    def send():
        good, said = _daemon().ntfy_send(cfg, title, words, tags="white_check_mark", timeout=15)
        return good, "%s as %s - %s" % (url, "a token" if cfg.get("ntfy_token") else (
            "user " + str(cfg.get("ntfy_user")) if cfg.get("ntfy_user") else "nobody (no sign-in)"), said), None
    ok, _v = _step(steps, "Sent to the topic", send)
    return _ntfy_done(ctx, me, steps, t0, ok, steps[-1]["said"])


def _ntfy_done(ctx, me, steps, t0, ok, said):
    took = int((time.time() - t0) * 1000)
    try:
        tests = json.loads(ctx.store.get_meta("ntfy:tests") or "[]")
    except ValueError:
        tests = []
    host = urllib.parse.urlparse(str(ctx.cfg.get("ntfy_url") or "")).netloc
    tests = ([t for t in tests if isinstance(t, dict)] + [{"at": time.time(), "title": "fake-igd test", "host": host,
                                                          "ok": ok, "said": said, "by": me["name"]}])[-TESTS_KEPT:]
    ctx.store.set_meta("ntfy:tests", json.dumps(tests))
    ctx.event("%s sent a test notification: %s" % (me["name"], said), "info" if ok else "warn", kind="notify")
    return {"sent": ok, "said": said, "steps": steps, "took_ms": took}


def _write_ca(path, certs):
    folder = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".ntfy-ca-", dir=folder)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(c["pem"] for c in certs) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ntfy_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    action = b.get("action")
    if action == "test":
        return ntfy_test(ctx, me, b)
    if action != "ca":
        raise ValueError("no such action")
    a = _api()
    if a is None:
        raise ValueError("the API cannot save config.json from here")
    path = _ca_path()
    if b.get("mode") == "drop" and b.get("fingerprint"):
        fp = str(b.get("fingerprint") or "").lower()
        cur = str(ctx.cfg.get("ntfy_ca_file") or "")
        if not cur or os.path.abspath(cur) != os.path.abspath(path):
            raise ValueError("the CA file was set by hand (%s) - it is changed on the server" % cur)
        with open(path, encoding="utf-8") as f:
            have = certs_of(f.read())
        keep = [c for c in have if c["fingerprint"] != fp]
        if len(keep) == len(have):
            raise ValueError("no such certificate here")
        if keep:
            _write_ca(path, keep)
            gone = [c for c in have if c["fingerprint"] == fp][0]
            ctx.event("%s took a certificate of the ntfy server's authority out (%s)" % (me["name"], gone["subject"]),
                      kind="notify")
            return {"message": "taken out - %d kept" % len(keep)}
        b = {"mode": "drop"}
    if b.get("mode") == "drop":
        was = str(ctx.cfg.get("ntfy_ca_file") or "")
        a.settings_save({"ntfy_ca_file": ""}, me["name"], ctx.addr)
        if was and os.path.abspath(was) == os.path.abspath(path):
            try:
                os.unlink(path)
            except OSError:
                pass
        ctx.event("%s took the certificate authority of the ntfy server away" % me["name"], kind="notify")
        return {"message": "taken away - the ntfy server is checked against the system's authorities again"}
    if b.get("mode") != "add":
        raise ValueError("add or drop")
    text = str(b.get("ca") or "")
    if len(text) > 256 * 1024:
        raise ValueError("that is more than a chain of certificates")
    new = certs_of(text)
    if not new:
        raise ValueError("no certificate in that (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)")
    have = []
    cur = str(ctx.cfg.get("ntfy_ca_file") or "")
    if cur and os.path.abspath(cur) == os.path.abspath(path):
        try:
            with open(path, encoding="utf-8") as f:
                have = certs_of(f.read())
        except OSError:
            have = []
    seen = {c["fingerprint"] for c in have}
    keep = have + [c for c in new if c["fingerprint"] not in seen]
    _write_ca(path, keep)
    if cur != path:
        a.settings_save({"ntfy_ca_file": path}, me["name"], ctx.addr)
    added = len(keep) - len(have)
    ctx.event("%s added %d certificate(s) of the ntfy server's authority (%s)" % (
        me["name"], added, ", ".join(c["subject"] for c in new)), kind="notify")
    return {"message": "%d added - %d kept in %s" % (added, len(keep), path)}


# ---- GET /api/upnp/logs ------------------------------------------------------------------------
def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def _lines(path, most=64 * 1024 * 1024):
    n = 0
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                n += b.count(b"\n")
                most -= len(b)
                if most <= 0:
                    return None
    except OSError:
        return None
    return n


def _dir_size(path):
    total, files = 0, 0
    for root, _dirs, names in os.walk(path):
        for n in names:
            try:
                total += os.lstat(os.path.join(root, n)).st_size
                files += 1
            except OSError:
                pass
    return total, files


def _disk(path):
    p = path
    while p and not os.path.exists(p):
        p = os.path.dirname(p)
    try:
        st = os.statvfs(p or "/")
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    mount = os.path.abspath(p or "/")
    while not os.path.ismount(mount):
        mount = os.path.dirname(mount)
    return {"path": mount, "total": total, "free": free,
            "pct": round(100.0 * (total - free) / total, 1) if total else 0}


def logs(ctx):
    cfg = ctx.cfg
    lf, rl, sd = cfg.get("log_file") or "", cfg.get("request_log") or "", cfg.get("state_dir") or ""
    db = os.environ.get("FAKE_IGD_DB") or os.path.join(sd, "fake-igd.db")
    files = []

    def add(what, path, lines=False, says=""):
        files.append({"what": what, "path": path, "size": _size(path), "at": _mtime(path),
                      "lines": _lines(path) if lines else None, "there": os.path.exists(path), "says": says})
    add("The main log", lf, True, "what fake-igd.service does: SSDP, ports, interfaces, notifications")
    add("The request log", rl, True, "every SOAP request, one JSON line each - the ports, requests and clients tabs")
    old = []
    for base in {lf, rl}:
        if not base:
            continue
        for p in glob.glob(base + ".*") + glob.glob(os.path.join(os.path.dirname(base), "old-*")):
            if p not in old and os.path.isfile(p):
                old.append(p)
    old_size = sum(_size(p) or 0 for p in old)
    st_size, st_files = _dir_size(sd) if sd and os.path.isdir(sd) else (None, 0)
    add("The mappings", os.path.join(sd, "mappings.json"), False, "the mappings a client holds now")
    add("The database", db, False, "accounts, sessions, events and the settings of the panes")
    disks = []
    for p in (lf, rl, sd):
        d = _disk(p) if p else None
        if d and d["path"] not in [x["path"] for x in disks]:
            disks.append(d)
    return {"node": _node(), "at": time.time(), "level": cfg.get("log_level"), "files": files,
            "rotated": {"count": len(old), "size": old_size,
                        "newest": max((_mtime(p) or 0 for p in old), default=None)},
            "state": {"path": sd, "size": st_size, "files": st_files}, "disks": disks,
            "logrotate": os.path.isfile("/etc/logrotate.d/fake-igd")}


# ---- the steps of each client (1.7.4) ----------------------------------------------------------------
# How far a device got on its way to a port, read from fake-igd's log and its request log: it searched
# (SSDP M-SEARCH, with what ST and User-Agent), fake-igd answered it (or why not), it fetched the device
# description and the service's, it asked SOAP questions, it asked for ports. A console that stops after
# the search is seen at a glance on the Clients tab.
STEP_RES = [
    ("searched", re.compile(r"ssdp: (\S+) is looking for a UPnP device \(ST=(.*?)(?:, MX=(.*?))?, UA=(.*)\)$")),
    ("answered", re.compile(r"ssdp: answered (\S+?):\d+ - ST=(\S+) USN=(\S+) LOCATION=(\S+)")),
    ("unanswered", re.compile(r"ssdp: (\S+) not answered - (.*)$")),
    ("fetched", re.compile(r"http: (\S+) fetched (/\S+) \((.*?), via \S+, UA=(.*)\)$")),
    ("fetched", re.compile(r"http: (\S+) fetched the device description")),
    ("missing", re.compile(r"http: (\S+) asked for (\S+) - not here")),
    ("soap", re.compile(r"soap: (\S+) -> (\w+)")),
    ("soap_error", re.compile(r"soap: (\S+) <- (\w+) error (\d+) (\S+)")),
]
STEP_ORDER = ["searched", "answered", "described", "service", "asked", "ports"]


def _steps_of(cfg, since=None, until=None, client=None):
    out = {}

    def one(ip):
        return out.setdefault(ip, {"client": ip, "searched": None, "answered": None, "unanswered": None,
                                   "described": None, "service": None, "missing": None, "actions": {},
                                   "ports": 0, "ports_ok": 0, "last_port": None, "timeline": []})

    def put(c, at, what, said=""):
        c["timeline"].append({"at": at, "what": what, "said": said})

    lo = since.timestamp() if since else 0
    hi = until.timestamp() if until else 1e12
    for ln in log_tail(cfg):
        m = U.LOG_RE.match(ln)
        if not m:
            continue
        at = _when(m.group(1))
        if at is None or at < lo or at > hi:
            continue
        words = m.group(3)
        for kind, rx in STEP_RES:
            x = rx.search(words)
            if not x or (client and x.group(1) != client):
                continue
            c = one(x.group(1))
            if kind == "searched":
                c["searched"] = {"at": at, "st": x.group(2), "mx": x.group(3) or "", "ua": x.group(4),
                                 "n": (c["searched"] or {}).get("n", 0) + 1}
                put(c, at, "searched", "ST=%s%s · %s" % (x.group(2), (", MX=" + x.group(3)) if x.group(3) else "",
                                                        x.group(4)))
            elif kind == "answered":
                c["answered"] = {"at": at, "st": x.group(2), "usn": x.group(3), "location": x.group(4)}
                put(c, at, "answered", "ST=%s · %s" % (x.group(2), x.group(4)))
            elif kind == "unanswered":
                c["unanswered"] = {"at": at, "why": x.group(2)}
                put(c, at, "not answered", x.group(2))
            elif kind == "fetched":
                path = x.group(2) if x.re.groups >= 2 else "/rootDesc.xml"
                key = "described" if path == "/rootDesc.xml" else "service"
                c[key] = {"at": at, "path": path, "ua": x.group(4) if x.re.groups >= 4 else ""}
                put(c, at, "fetched", path)
            elif kind == "missing":
                c["missing"] = {"at": at, "path": x.group(2)}
                put(c, at, "asked for what is not here", x.group(2))
            elif kind == "soap":
                a = c["actions"].setdefault(x.group(2), {"n": 0, "at": at, "errors": 0})
                a["n"] += 1
                a["at"] = at
                put(c, at, "asked " + x.group(2))
            elif kind == "soap_error":
                a = c["actions"].setdefault(x.group(2), {"n": 0, "at": at, "errors": 0})
                a["errors"] += 1
                a["said"] = "%s %s" % (x.group(3), x.group(4))
                put(c, at, "answered %s with error %s %s" % (x.group(2), x.group(3), x.group(4)))
            break
    try:
        ev = U.read_events(cfg, since)
    except SystemExit:
        ev = []
    for e in ev:
        t = e["_t"].timestamp() if e.get("_t") else None
        if t is None or t > hi or not e.get("client") or (client and e.get("client") != client):
            continue
        c = one(e.get("client") or "?")
        act = e.get("action") or "?"
        a = c["actions"].setdefault(act, {"n": 0, "at": t, "errors": 0})
        a["at"] = max(a["at"], t)
        if act in ("AddPortMapping", "AddAnyPortMapping"):
            c["ports"] += 1
            c["ports_ok"] += str(e.get("result") or "ok") == "ok"
            c["last_port"] = {"at": t, "port": e.get("external_port"), "proto": e.get("protocol"),
                              "result": e.get("result") or "ok"}
            put(c, t, "asked for a port", "%s %s → %s" % (e.get("protocol"), e.get("external_port"),
                                                        e.get("result") or "ok"))
    for c in out.values():
        # SOAP questions seen only in the request log (the log says them once in 10 minutes)
        for act, a in c["actions"].items():
            a["n"] = max(a["n"], 1)
        reached = [k for k, ok in (("searched", c["searched"]), ("answered", c["answered"]),
                                   ("described", c["described"]), ("service", c["service"]),
                                   ("asked", c["actions"]), ("ports", c["ports"])) if ok]
        c["reached"] = reached
        c["furthest"] = max((STEP_ORDER.index(k) for k in reached), default=-1)
        c["stopped"] = stopped_words(c)
        c["timeline"] = sorted(c["timeline"], key=lambda x: x["at"])[-80:]
    return out


def stopped_words(c):
    """Where it stopped, in words - empty when it asked for a port."""
    if c["ports"]:
        return ""
    if c["searched"] and c["unanswered"] and not c["answered"]:
        return "it searched and was not answered: " + c["unanswered"]["why"]
    if c["searched"] and not (c["answered"] or c["described"] or c["actions"]):
        return "it searched (ST=%s) and went no further" % c["searched"]["st"]
    if c["answered"] and not (c["described"] or c["actions"]):
        return "it was answered and never fetched the device description - the answer was not what it wanted, " \
               "or it cannot reach %s" % c["answered"]["location"]
    if c["described"] and not (c["service"] or c["actions"]):
        return "it fetched the device description and asked nothing - it found nothing there it wanted"
    if c["actions"]:
        return "it asked %s, but for no port" % ", ".join(sorted(c["actions"]))
    return ""


def steps(ctx):
    """GET /api/upnp/steps[?since=&until=&client=] - each client's steps (the Clients tab)."""
    ctx.need("readonly")

    def when(name):
        try:
            v = float(ctx.arg(name) or 0)
        except ValueError:
            v = 0
        return datetime.fromtimestamp(v).astimezone() if v > 0 else None
    client = str(ctx.arg("client") or "")[:64] or None
    got = _steps_of(ctx.cfg, when("since"), when("until"), client)
    _gateway_of(ctx, got)
    return {"clients": got, "at": time.time()}


def _gateway_of(ctx, clients):
    """Each client: whether it uses this server as its gateway (Settings → Gateway for devices, 1.7.15) -
    "uses" (on, put in, packets forwarded), "defined" (one of its devices, not forwarding), or "" - and the
    hint where it stopped at "answered": a PS5 asks UPnP only of its default gateway."""
    try:
        gw = __import__("api_gateway")
        meta = gw._meta(ctx.store)
        st = gw.state()
    except Exception:                                   # noqa: BLE001 - the steps all the same
        return
    applied = {d.get("ip") for d in st.get("devices") or [] if d.get("on")} if st.get("on") else set()
    seen = st.get("seen") or {}
    defined = {d.get("ip") for d in meta.get("devices") or []}
    for ip, c in clients.items():
        c["gateway"] = "uses" if ip in applied and (seen.get(ip) or {}).get("changed") else \
            ("defined" if ip in defined or ip in applied else "")
        c["gateway_hint"] = bool(c.get("answered") and not (c.get("described") or c.get("actions") or c.get("ports"))
                                 and c["gateway"] != "uses")


ROUTES = {
    ("GET", "/api/upnp/steps"): steps,
    ("GET", "/api/upnp/here"): here,
    ("POST", "/api/upnp/try"): try_it,
    ("GET", "/api/upnp/ntfy"): ntfy_view,
    ("POST", "/api/upnp/ntfy"): ntfy_post,
    ("GET", "/api/upnp/logs"): logs,
}
