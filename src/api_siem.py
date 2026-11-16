"""api_siem.py - Settings → Syslog and SIEM (1.6.0), as otp's.

Every event, every sign-in to these pages and every port asked for (AddPortMapping) to a
syslog server or a SIEM (Graylog, Splunk, Elastic, Wazuh, QRadar, Sentinel): RFC 5424
syslog over UDP, TCP or TLS (octet counting, RFC 5425 / 6587), the message JSON, CEF or
RFC 5424 structured data. Sent as it happens by a thread of its own in the API (it looks
every 3 s), never on the way of anything else; what was sent last is remembered for each
server (meta "siem:state"), so a server that was away gets what it missed.
"""
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone

NAME = "siem"
PEN = 32473                     # the example enterprise number of RFC 5612 (as otp's)
SEVERITY = {"bad": 3, "crit": 3, "error": 3, "warn": 4, "info": 6}
CTRL = re.compile(r"[\x00-\x1f\x7f]")
MOST_A_RUN = 2000
STATE_KEY = "siem:state"


def targets(text, strict=False):
    """`udp://host:514`, `tcp://host:514`, `tls://host:6514` - or host[:port][/udp|/tcp|/tls] -
    comma separated, as [(host, port, proto)]."""
    out = []
    for one in re.split(r"[,;\s]+", str(text or "")):
        one = one.strip()
        if not one:
            continue
        m = re.match(r"^(?:(udp|tcp|tls)://)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+)(?::(\d+))?(?:/(udp|tcp|tls))?/?\Z",
                     one, re.I)
        if not m:
            if strict:
                raise ValueError("%s is not tls://host:6514, tcp://host:514 or udp://host:514" % one)
            continue
        proto = (m.group(1) or m.group(4) or "udp").lower()
        port = int(m.group(3) or (6514 if proto == "tls" else 514))
        if strict and not 0 < port < 65536:
            raise ValueError("%d is not a port" % port)
        out.append((m.group(2).strip("[]"), port, proto))
    if strict and len(out) > 8:
        raise ValueError("8 servers at most")
    return out


def _targets_check(v):
    try:
        targets(v, strict=True)
    except ValueError as e:
        return str(e)
    return ""


def _ca_check(v):
    if "-----BEGIN CERTIFICATE-----" not in v:
        return "a PEM certificate (-----BEGIN CERTIFICATE----- …)"
    try:
        ssl.create_default_context().load_verify_locations(cadata=v)
    except (ssl.SSLError, ValueError) as e:
        return "it does not load: %s" % e
    return ""


SETTINGS = [
    {"key": "siem", "name": "Send to a syslog server or a SIEM", "kind": "bool", "default": False,
     "says": "Every event, every sign-in and every port asked for, as syslog (RFC 5424), to the servers below - "
             "as it happens. Sent by a thread of its own: a sign-in never waits for it, and a server that was "
             "away gets what it missed. Off until switched on."},
    {"key": "siem_targets", "name": "Where to send them", "kind": "text", "default": "", "check": _targets_check,
     "most": 2000, "only_when": ("siem", True),
     "says": "<code>tls://siem.example.cz:6514</code>, <code>tcp://host:514</code> or <code>udp://host:514</code>, "
             "separated by commas."},
    {"key": "siem_format", "name": "In the shape of", "kind": "choice", "default": "json", "only_when": ("siem", True),
     "choices": [("json", "JSON - one object to a line (Graylog, Splunk, Elastic, Wazuh)"),
                 ("cef", "CEF - ArcSight, QRadar, Sentinel"),
                 ("rfc5424", "RFC 5424 with structured data, key=\"value\"")],
     "says": "What the message is, after the syslog header."},
    {"key": "siem_events", "name": "Every event", "kind": "bool", "default": True, "only_when": ("siem", True),
     "says": "All that the Events page lists: a setting changed, an account made, an upgrade, a mail that did "
             "not go."},
    {"key": "siem_signins", "name": "Every sign-in, let in or refused", "kind": "bool", "default": True,
     "only_when": ("siem", True),
     "says": "Each sign-in to these pages and each signing out: who, from where, let in or refused and why. The "
             "password typed is never sent."},
    {"key": "siem_ports", "name": "Every port asked for", "kind": "bool", "default": True,
     "only_when": ("siem", True),
     "says": "Each AddPortMapping a device sent: the device, the port, the protocol, the description and what it "
             "was answered."},
    {"key": "siem_facility", "name": "Syslog facility", "kind": "int", "default": 13, "min": 0, "max": 23,
     "only_when": ("siem", True), "says": "13 (log audit) is the usual; 16-23 are local0-local7, 10 authpriv."},
    {"key": "siem_hostname", "name": "The name this machine is written under", "kind": "text", "default": "",
     "most": 120, "only_when": ("siem", True), "says": "The host name on every line. Empty: this machine's name."},
    {"key": "siem_verify", "name": "Check the server’s certificate (TLS)", "kind": "bool", "default": True,
     "only_when": ("siem", True), "says": "Off only for a test: anyone between could read and change the lines."},
    {"key": "siem_ca", "name": "The certificate authority of the server (TLS)", "kind": "textarea", "default": "",
     "check": _ca_check, "most": 64000, "only_when": ("siem", True),
     "says": "The CA certificate (PEM) the server’s certificate is signed by, where it is not one the system "
             "trusts already."},
]


def _cef_head(text):
    return str(text).replace("\\", "\\\\").replace("|", "\\|")


def _cef_val(text):
    return str(text).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", " ")


def _sd_val(text):
    return str(text).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _version():
    try:
        import upnp as U
        return U.VERSION
    except Exception:                                   # noqa: BLE001
        return "?"


def frame(c, kind, severity, fields, words, at=None):
    """One syslog line, in the shape siem_format says (as otp's Siem.frame)."""
    fmt = c.get("siem_format") or "json"
    node = socket.gethostname().split(".")[0]
    fields = dict(fields, node=node)
    if fmt == "json":
        body = json.dumps(dict(fields, type=kind, message=words), ensure_ascii=False, sort_keys=True, default=str)
        sd = "-"
    elif fmt == "cef":
        ext = " ".join("%s=%s" % (k, _cef_val(v)) for k, v in fields.items() if v not in (None, ""))
        body = "CEF:0|fake-igd|fake-igd|%s|%s|%s|%d|%s msg=%s" % (
            _cef_head(_version()), _cef_head(fields.get("event") or kind), _cef_head(words[:120]),
            {3: 7, 4: 5, 6: 2}.get(severity, 3), ext, _cef_val(words))
        sd = "-"
    else:
        sd = "[fake-igd@%d %s]" % (PEN, " ".join('%s="%s"' % (re.sub(r"[^A-Za-z0-9_.-]", "_", k)[:32], _sd_val(v))
                                                for k, v in fields.items() if v not in (None, "")))
        body = words
    when = datetime.fromtimestamp(at or time.time(), timezone.utc).astimezone().isoformat(timespec="milliseconds")
    fac = c.get("siem_facility")
    pri = (int(fac) if fac not in (None, "") else 13) * 8 + severity
    host = str(c.get("siem_hostname") or "").strip() or node
    host = re.sub(r"\s", "_", host)[:255] or "-"
    return CTRL.sub(" ", "<%d>1 %s %s fake-igd %d %s %s \ufeff%s" % (pri, when, host, os.getpid(), kind, sd, body))


def _tls(c):
    ctx = ssl.create_default_context()
    ca = str(c.get("siem_ca") or "").strip()
    if ca:
        ctx.load_verify_locations(cadata=ca)
    if not c.get("siem_verify", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_lines(c, target, lines):
    """How many went ('' when every one did, else what stopped it): (n, words)."""
    host, port, proto = target
    n = 0
    try:
        if proto == "udp":
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_DGRAM)
            try:
                for ln in lines:
                    s.sendto(ln.encode("utf-8", "replace")[:8000], (host, port))
                    n += 1
            finally:
                s.close()
            return n, ""
        s = socket.create_connection((host, port), timeout=8)
        try:
            if proto == "tls":
                s = _tls(c).wrap_socket(s, server_hostname=host)
            s.settimeout(8)
            for ln in lines:
                raw = ln.encode("utf-8", "replace")
                s.sendall(b"%d " % len(raw) + raw)
                n += 1
            if proto == "tls":
                try:
                    s.unwrap()          # close_notify: the server reads all before the connection goes
                except (OSError, ssl.SSLError, ValueError):
                    pass
        finally:
            try:
                s.close()
            except OSError:
                pass
        return n, ""
    except (OSError, ssl.SSLError, ValueError) as e:
        return n, (str(e)[:200] or e.__class__.__name__)


def key_of(t):
    return "%s:%d/%s" % t


def state(store):
    st = store.meta_json(STATE_KEY) or {}
    for k in ("cursors", "sent", "trouble"):
        if not isinstance(st.get(k), dict):
            st[k] = {}
    return st


def _settings(ctx):
    import igd_panes as PN
    return {s["key"]: PN.value(ctx.store, s["key"]) for s in SETTINGS}


def _port_rows(ctx, since_ts):
    import upnp as U
    try:
        since = datetime.fromtimestamp(since_ts).astimezone() if since_ts else None
        ev = U.read_events(ctx.cfg, since)
    except SystemExit:
        return []
    out = []
    for e in ev:
        if e.get("action") != "AddPortMapping" or not e.get("_t"):
            continue
        t = e["_t"].timestamp()
        if t > since_ts:
            out.append((t, e))
    out.sort(key=lambda x: x[0])
    return out


def lines_since(ctx, c, cur):
    """[(line, new cursor)] beyond the cursor {event, port} - oldest first."""
    out = []
    if c.get("siem_events", True) or c.get("siem_signins", True):
        for r in ctx.store.rows("SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?",
                                (int(cur.get("event") or 0), MOST_A_RUN)):
            signin = r["kind"] == "sign-in"
            if signin and not c.get("siem_signins", True) or (not signin and not c.get("siem_events", True)):
                out.append((None, {"event": r["id"]}, r["at"]))
                continue
            lv = r["level"] or "info"
            if signin:
                refused = "could not" in r["words"] or lv != "info"
                fields = {"event": "signin-" + ("reject" if refused else ("logout" if "signed out" in r["words"]
                                                                          else "accept")),
                          "user": r["who"], "src": r["addr"], "result": "refused" if refused else "ok"}
                line = frame(c, "signin", 4 if refused else 6, fields, r["words"], r["at"])
            else:
                fields = {"event": "event", "kind": r["kind"], "level": lv, "who": r["who"], "src": r["addr"]}
                line = frame(c, "event", SEVERITY.get(lv, 6), fields, "%s: %s" % (r["kind"], r["words"]), r["at"])
            out.append((line, {"event": r["id"]}, r["at"]))
    if c.get("siem_ports", True):
        for t, e in _port_rows(ctx, float(cur.get("port") or 0))[:MOST_A_RUN]:
            res = str(e.get("result") or "")
            fields = {"event": "port-request", "client": e.get("client"), "proto": e.get("protocol"),
                      "port": e.get("external_port"), "internal_client": e.get("internal_client"),
                      "internal_port": e.get("internal_port"), "lease": e.get("lease"),
                      "description": e.get("description"), "result": res}
            words = "%s asked for %s/%s (%s): %s" % (e.get("client"), e.get("external_port"),
                                                     str(e.get("protocol") or "").lower(),
                                                     e.get("description") or "-", res or "?")
            out.append((frame(c, "port", 6 if res in ("ok", "accepted", "") else 4, fields, words, t),
                        {"port": t}, t))
    out.sort(key=lambda x: x[2])
    return [(ln, cu) for ln, cu, _t in out[:MOST_A_RUN]]


def start_cursor(ctx):
    got = ctx.store.one("SELECT MAX(id) AS n FROM events") or {}
    return {"event": int(got.get("n") or 0), "port": time.time()}


def run(ctx, c=None):
    c = c or _settings(ctx)
    st = state(ctx.store)
    if not c.get("siem"):
        return st
    ts = targets(c.get("siem_targets"))
    keep = {key_of(t) for t in ts}
    for d in (st["cursors"], st["trouble"]):
        for k in list(d):
            if k not in keep:
                d.pop(k, None)
    for t in ts:
        k = key_of(t)
        cur = st["cursors"].get(k) or start_cursor(ctx)
        todo = lines_since(ctx, c, cur)
        lines = [ln for ln, _cu in todo if ln]
        n, err = send_lines(c, t, lines) if lines else (0, "")
        # The cursor moves past what went (and past what is not sent at all).
        went = 0
        for ln, cu in todo:
            if ln:
                if went >= n:
                    break
                went += 1
            cur = dict(cur, **cu)
        st["cursors"][k] = cur
        st["sent"][k] = int(st["sent"].get(k) or 0) + n
        SENT_RUN[k] = SENT_RUN.get(k, 0) + n
        if n:
            st["last_sent"] = time.time()
        if err:
            st["trouble"][k] = err
        else:
            st["trouble"].pop(k, None)
    st["at"] = time.time()
    ctx.store.set_meta(STATE_KEY, json.dumps(st))
    return st


def siem_get(ctx):
    c = _settings(ctx)
    st = state(ctx.store)
    ts = [key_of(t) for t in targets(c.get("siem_targets"))]
    waiting = {}
    if c.get("siem"):
        for k in ts:
            cur = st["cursors"].get(k)
            if cur:
                waiting[k] = ctx.store.one("SELECT COUNT(*) AS n FROM events WHERE id > ?", (int(cur.get("event") or 0),))["n"]
    return {"on": bool(c.get("siem")), "targets": ts, "format": c.get("siem_format"),
            "host": str(c.get("siem_hostname") or "").strip() or socket.gethostname().split(".")[0],
            "sent": st["sent"], "sent_run": SENT_RUN, "dropped": 0, "trouble": st["trouble"],
            "last_sent": st.get("last_sent"), "at": st.get("at"),
            "waiting": waiting, "test": st.get("test")}


def siem_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    c = _settings(ctx)
    if act == "test":
        ts = targets(c.get("siem_targets"))
        if not ts:
            raise ValueError("no syslog server is set")
        line = frame(c, "test", 6, {"event": "test", "who": me["name"]},
                     "a test from fake-igd %s, sent by %s" % (_version(), me["name"]))
        said = {}
        for t in ts:
            n, err = send_lines(c, t, [line])
            said[key_of(t)] = err or "sent"
        ok = all(v == "sent" for v in said.values())
        st = state(ctx.store)
        st["test"] = {"at": time.time(), "ok": ok, "said": said}
        ctx.store.set_meta(STATE_KEY, json.dumps(st))
        ctx.event("%s sent a test line to %s" % (me["name"], ", ".join("%s (%s)" % kv for kv in said.items())),
                  "info" if ok else "warn")
        return {"ok": True, "test": st["test"], "message": "the test line went to every server" if ok
                else "not to every server - see the card"}
    if act == "now":
        run(ctx, c)
        return {"ok": True, "message": "sent what was waiting"}
    raise ValueError("no such action")


ROUTES = {
    ("GET", "/api/siem"): siem_get,
    ("POST", "/api/siem"): siem_post,
}


def on_saved(ctx, changed):
    if "siem" in changed and changed["siem"]:
        st = state(ctx.store)
        st["cursors"] = {}                  # begins from now, not from the start of the events
        ctx.store.set_meta(STATE_KEY, json.dumps(st))


# ---- sent as it happens, from a thread of its own (otp's siem thread) ------------------------
SENT_RUN = {}                       # lines sent since the API started, by server
SENDER = {"thread": None, "seen": None}
TICK_S = 3.0


def _mark(ctx):
    """What would make another run worth it: the newest event, the request log's size and time."""
    got = ctx.store.one("SELECT MAX(id) AS n FROM events") or {}
    try:
        st = os.stat(ctx.cfg.get("request_log") or "/var/log/fake-igd/requests.jsonl")
        log = (st.st_size, st.st_mtime)
    except OSError:
        log = None
    return (got.get("n"), log)


def _loop(ctx):
    while True:
        time.sleep(TICK_S)
        try:
            c = _settings(ctx)
            if not c.get("siem"):
                continue
            mark = _mark(ctx)
            st = state(ctx.store)
            if mark == SENDER["seen"] and not st.get("trouble") and time.time() - float(st.get("at") or 0) < 60:
                continue                                    # nothing new, nothing to try again yet
            SENDER["seen"] = mark
            run(ctx, c)
        except Exception:                                   # noqa: BLE001 - the thread goes on
            time.sleep(10)


def background(ctx):
    """The thread that sends as it happens - started once (and again, were it to die)."""
    import threading
    th = SENDER["thread"]
    if th is None or not th.is_alive():
        th = threading.Thread(target=_loop, args=(ctx,), name="siem", daemon=True)
        SENDER["thread"] = th
        th.start()
