"""api_mikrotik.py - Settings → MikroTik (1.8.2): the real router read, READ-ONLY, as isemon reads one.

fake-igd answers a PS5's UPnP and opens nothing; the real router is a MikroTik. Read through its REST API
(RouterOS 7), its API (api-ssl / api) or over ssh (a key made here, or a password), it is asked for its
firewall - filter, nat, mangle, raw, IPv4 and IPv6 - its address lists, interfaces, addresses, neighbours
and its own UPnP; then every port a device asked fake-igd for (the request log, the mappings, the devices
of Gateway for devices) is checked against it (igd_mtcheck): open, no dst-nat, no accept, shadowed by a
rule, disabled, forwarded elsewhere, or cannot tell - with the RouterOS commands that would add what is
missing, shown and NEVER sent. Nothing that changes the router ever leaves this machine (igd_mikrotik).

  GET  /api/mikrotik          the settings' state, the last read, the checks with each device's way out
                              (Settings → MikroTik, Gateway → MikroTik, Overview, Ports) - read-only accounts too
  GET  /api/mikrotik/rules    the whole firewall as read, for Gateway → MikroTik - read-only accounts too
  POST /api/mikrotik {do: read | test | trust {fingerprint} | trust-forget | hostkey-scan |
                      hostkey-trust {fingerprint} | hostkey-forget | keygen | key {key} | key-forget}

Kept: meta "mikrotik:snap" (what was read), "mikrotik:state" ({at, ok, trouble, via, took}),
"mikrotik:pin" (the certificate trusted, its SHA-256), "mikrotik:key" (the ssh key's private half, sealed)
and "mikrotik:pub"; the router's ssh host key in mikrotik_known_hosts beside the database (0600).
"""
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import igd_mikrotik as M    # noqa: E402
import igd_mtcheck as C     # noqa: E402

NAME = "mikrotik"
LOCK = threading.Lock()
READING = {"busy": False, "since": 0.0}
WANTS_DAYS = 30


def _host_check(v):
    return "" if M.host_ok(v) else "an address or a host name"


def _user_check(v):
    return "" if re.match(r"^[A-Za-z0-9_.@-]{1,64}\Z", v) else "letters, digits and _ . @ - only"


def _ca_check(v):
    if not v.strip():
        return ""
    if "-----BEGIN CERTIFICATE-----" not in v:
        return "the authority's certificate as PEM, with its BEGIN CERTIFICATE and END CERTIFICATE lines"
    import ssl
    try:
        ssl.create_default_context(cadata=v)
    except (ssl.SSLError, ValueError) as e:
        return "that certificate cannot be used as an authority: %s" % str(e)[:100]
    return ""


ON = ("mikrotik", True)
_SETTINGS = [
    {"key": "mikrotik", "name": "Read the MikroTik", "kind": "bool", "default": False,
     "says": "Read the real router - a MikroTik - and say for every port a device asked for whether it carries "
             "what it takes: a dst-nat to the device, nothing that drops it, IPv6 let through. READ-ONLY: fake-igd "
             "only ever asks it to print; nothing is ever written to it. Off, nothing reaches the router."},
    {"key": "mikrotik_host", "name": "The router's address", "kind": "text", "default": "", "check": _host_check,
     "most": 255, "only_when": ON,
     "says": "Where this machine reaches the MikroTik - its address on the LAN (192.168.40.1) or its name."},
    {"key": "mikrotik_mode", "name": "How it is reached", "kind": "choice", "default": "rest", "only_when": ON,
     "choices": [("rest", "REST API over HTTPS (RouterOS 7, www-ssl 443)"),
                 ("api", "The RouterOS API (api-ssl 8729, or api 8728)"),
                 ("ssh", "Over ssh, with a key or a password (22)")],
     "says": "REST: RouterOS 7's own HTTPS API, GET only. The API: RouterOS's API, also on RouterOS 6 - over TLS "
             "(api-ssl) or plain. Over ssh: the same questions asked on its console, signed in with a key made "
             "here or a password. Whichever: the account may only read, and fake-igd only prints."},
    {"key": "mikrotik_tls", "hide_asleep": True, "name": "Its certificate", "kind": "choice", "default": "pin",
     "only_when": ("mikrotik_mode", "ssh-not"),
     "choices": [("pin", "trusted by its fingerprint (shown, then trusted here)"),
                 ("ca", "checked by an authority, and its name"),
                 ("none", "not checked - encrypted, but anybody in between could answer"),
                 ("plain", "no TLS at all (www 80, api 8728) - the password in the clear")],
     "says": "Trusted by its fingerprint: Try reaching it shows the router's certificate; Trust this certificate "
             "remembers it, and a router answering with another one is refused before the password is sent. "
             "Checked by an authority: as a browser checks a site - signed by one this machine trusts, or by the "
             "one given below, and for the router's name. Not checked / no TLS: only on a network that is yours "
             "alone."},
    {"key": "mikrotik_ca", "hide_asleep": True, "name": "The authority (PEM)", "kind": "textarea", "default": "", "check": _ca_check,
     "most": 20000, "only_when": ("mikrotik_tls", "ca"),
     "says": "The certificate of the authority that signed the router's - empty: the authorities this machine "
             "trusts."},
    {"key": "mikrotik_tls_name", "hide_asleep": True, "name": "The name on its certificate", "kind": "text", "default": "",
     "check": _host_check, "most": 255, "only_when": ("mikrotik_tls", "ca"),
     "says": "The name the router's certificate is checked for. Empty: its address above - write the name here "
             "when it is reached by its address and the certificate carries a name (gw.example.com)."},
    {"key": "mikrotik_port", "name": "Its port", "kind": "int", "default": 0, "min": 0, "max": 65535,
     "only_when": ON,
     "says": "0: the usual one - 443 for REST (80 without TLS), 8729 for api-ssl (8728 for api), 22 for ssh - "
             "or what /ip service print says."},
    {"key": "mikrotik_user", "name": "Sign in to it as", "kind": "text", "default": "fake-igd-read",
     "check": _user_check, "most": 64, "only_when": ON,
     "says": "An account on the router in a group that may only read - \"How to set it up on the router\" says "
             "how. Never the administrator's."},
    {"key": "mikrotik_auth", "hide_asleep": True, "name": "Sign in with", "kind": "choice", "default": "key",
     "only_when": ("mikrotik_mode", "ssh"),
     "choices": [("key", "a key made here (ed25519)"), ("password", "a password")],
     "says": "With a key fake-igd holds - its private half never leaves this machine, the router holds only the "
             "public half - or with the account's password."},
    {"key": "mikrotik_password", "name": "Its password", "kind": "secret", "default": "", "only_when": ON,
     "says": "The account's password (REST, the API, or ssh with a password). Kept sealed here and shown back by "
             "its last two letters only."},
    {"key": "mikrotik_every", "name": "Read it every (min)", "kind": "int", "default": 5, "min": 1, "max": 60,
     "only_when": ON,
     "says": "How often the firewall is read. A few cheap prints - the router hardly notices. Read it now reads "
             "it at once."},
    {"key": "mikrotik_timeout", "name": "Wait for it (s)", "kind": "int", "default": 20, "min": 3, "max": 120,
     "only_when": ON, "says": "How long a question may take before the router is taken to be away."},
]


# ---- the settings, the secrets, the files ----------------------------------------------------------------
_ORDER = ("mikrotik", "mikrotik_host", "mikrotik_mode", "mikrotik_port", "mikrotik_user", "mikrotik_auth",
          "mikrotik_password", "mikrotik_tls", "mikrotik_tls_name", "mikrotik_every", "mikrotik_timeout", "mikrotik_ca")
SETTINGS = sorted(_SETTINGS, key=lambda x: _ORDER.index(x["key"]))


def conf(ctx):
    v = ctx.setting
    return {"on": bool(v("mikrotik")), "host": str(v("mikrotik_host") or "").strip(), "mode": v("mikrotik_mode") or "rest",
            "tls": v("mikrotik_tls") or "pin", "port": int(v("mikrotik_port") or 0), "user": v("mikrotik_user") or "",
            "auth": v("mikrotik_auth") or "key", "ca": v("mikrotik_ca") or "", "tls_name": v("mikrotik_tls_name") or "",
            "every": int(v("mikrotik_every") or 5), "timeout": int(v("mikrotik_timeout") or 20)}


def state_dir(ctx):
    return ctx.cfg.get("state_dir") or "/var/lib/fake-igd"


def known_hosts(ctx):
    return os.path.join(state_dir(ctx), "mikrotik_known_hosts")


def _meta_json(store, key):
    try:
        got = json.loads(store.get_meta(key) or "null")
    except ValueError:
        got = None
    return got


def _key_private(ctx):
    import igd_seal as SEAL
    v = ctx.store.get_meta("mikrotik:key") or ""
    return SEAL.unseal_or(ctx.store, v, "mikrotik:key", "") if v else ""


def _proxy(ctx, c):
    """Settings → Proxy, only where it is on for the MikroTik and the router is not one reached straight."""
    try:
        import igd_proxy as P
        url = P.url_for(ctx.store, "mikrotik")
        if url and not P.skips(P.settings(ctx.store), M.bare_host(c["host"])):
            return url
    except Exception:                                   # noqa: BLE001 - no proxy
        pass
    return None


def session_of(ctx, c=None):
    c = c or conf(ctx)
    return M.session(c, password=ctx.setting("mikrotik_password") or "", pin=ctx.store.get_meta("mikrotik:pin") or "",
                     key=_key_private(ctx) if c["mode"] == "ssh" and c["auth"] == "key" else "",
                     known_hosts=known_hosts(ctx), proxy=None if c["mode"] == "ssh" else _proxy(ctx, c))


# ---- reading it ------------------------------------------------------------------------------------------------
def read_now(ctx, by=""):
    """Read the router whole; the snapshot and its state kept. One read at a time."""
    with LOCK:
        if READING["busy"]:
            return _meta_json(ctx.store, "mikrotik:state") or {}
        READING.update(busy=True, since=time.time())
    t0 = time.time()
    c = conf(ctx)
    was = _meta_json(ctx.store, "mikrotik:state") or {}
    st = {"at": t0, "via": c["mode"], "host": c["host"]}
    try:
        sess = session_of(ctx, c)
        sess.connect()
        try:
            raw, missing = M.read_all(sess)
        finally:
            sess.close()
        snap = M.snapshot(raw, missing, c["mode"])
        # the counters of the read before: what each rule counted since then (hits since the last read)
        old = _meta_json(ctx.store, "mikrotik:snap") or {}
        before = {}
        for fam, tabs in (old.get("rules") or {}).items():
            for t, rows in tabs.items():
                for r in rows:
                    if r.get(".id"):
                        before["%s:%s:%s" % (fam, t, r[".id"])] = [r.get("packets") or 0, r.get("bytes") or 0]
        for fam, tabs in snap["rules"].items():
            for t, rows in tabs.items():
                for r in rows:
                    was_ = before.get("%s:%s:%s" % (fam, t, r.get(".id")))
                    if was_ is not None and (r.get("packets") or 0) >= was_[0]:
                        r["hits"] = (r.get("packets") or 0) - was_[0]
        snap["prev_at"] = old.get("at") if old.get("host") == c["host"] else None
        snap["host"] = c["host"]
        ctx.store.set_meta("mikrotik:snap", json.dumps(snap))
        st.update(ok=True, took=round(time.time() - t0, 2), identity=snap["identity"], version=snap["version"],
                  board=snap["board"], missing=missing, rules=sum(len(v) for f in snap["rules"].values() for v in f.values()))
        if not was.get("ok"):
            ctx.event("the MikroTik %s (%s) is read again%s" % (snap["identity"] or c["host"], c["host"],
                                                               (" - asked by %s" % by) if by else ""), "info")
    except M.MtError as e:
        st.update(ok=False, trouble=str(e)[:400], took=round(time.time() - t0, 2))
        if was.get("ok") is not False or was.get("trouble") != st["trouble"]:
            ctx.event("the MikroTik %s could not be read: %s" % (c["host"] or "?", str(e)[:300]), "warn")
    except Exception as e:                              # noqa: BLE001 - said, not a traceback in the log
        st.update(ok=False, trouble="%s: %s" % (type(e).__name__, str(e)[:300]), took=round(time.time() - t0, 2))
    finally:
        READING["busy"] = False
    ctx.store.set_meta("mikrotik:state", json.dumps(st))
    return st


# ---- what was asked of fake-igd: the ports, each with its device -----------------------------------------------
def wants(ctx):
    """Every (device, protocol, port) a device asked for in the last 30 days - the request log's AddPortMapping
    (accepted or not), the mappings held now - and the devices of Gateway for devices with their names."""
    import upnp as U
    from datetime import datetime, timedelta
    since = datetime.now().astimezone() - timedelta(days=WANTS_DAYS)
    try:
        ev = U.read_events(ctx.cfg, since)
    except SystemExit:
        ev = []
    names = {}
    try:
        for d in (json.loads(ctx.store.get_meta("gateway") or "{}").get("devices") or []):
            if isinstance(d, dict) and d.get("ip"):
                names[d["ip"]] = {"name": d.get("name") or "", "mac": d.get("mac") or "",
                                  "ip6": [x for x in d.get("ip6") or [] if isinstance(x, str)]}
    except ValueError:
        pass
    got = {}
    for e in ev:
        if e.get("action") != "AddPortMapping" or e.get("description") == "upnp-cli-test":
            continue
        dev = str(e.get("internal_client") or e.get("client") or "")
        try:
            ipaddress.IPv4Address(dev)
            k = (dev, str(e.get("protocol") or "").lower(), int(e.get("external_port")))
            ip_ = int(e.get("internal_port") or k[2])
        except (ValueError, TypeError):
            continue
        if k[1] not in ("tcp", "udp"):
            continue
        w = got.setdefault(k, {"device": dev, "proto": k[1], "port": k[2], "to_port": ip_, "asked": 0, "last": "",
                               "description": ""})
        w["asked"] += 1
        w["last"] = e.get("time") or w["last"]
        w["to_port"] = ip_
        if e.get("description"):
            w["description"] = str(e["description"])[:80]
    try:
        with open(os.path.join(state_dir(ctx), "mappings.json"), encoding="utf-8") as f:
            maps = json.load(f)
        for m in maps if isinstance(maps, list) else []:
            try:
                dev = str(m.get("internal_client") or "")
                ipaddress.IPv4Address(dev)
                k = (dev, str(m.get("protocol") or "").lower(), int(m.get("external_port")))
            except (ValueError, TypeError, AttributeError):
                continue
            w = got.setdefault(k, {"device": dev, "proto": k[1], "port": k[2], "asked": 0, "last": "",
                                   "description": str(m.get("description") or "")[:80]})
            w["to_port"] = int(m.get("internal_port") or k[2])
            w["held"] = True
    except (OSError, ValueError):
        pass
    out = []
    for w in got.values():
        n = names.get(w["device"]) or {}
        w["name"] = n.get("name") or ""
        w["mac"] = n.get("mac") or ""
        if n.get("ip6"):                        # 1.9.2: its IPv6 as set in Gateway for devices (DHCPv6)
            w["v6"], w["v6_set"] = list(n["ip6"]), True
        w["gateway"] = w["device"] in names
        out.append(w)
    out.sort(key=lambda w: (w["device"], w["proto"], w["port"]))
    return out[:400]


def _public_ip(ctx):
    """The public address fake-igd knows (set by hand, or the last one it looked up) - the MikroTik's WAN
    is the interface that carries it when nothing else tells (1.9.2)."""
    try:
        cfg = ctx.cfg or {}
        ext = str(cfg.get("external_ip") or "auto")
        if ext != "auto":
            return ext
        import api_upnp as AU
        return AU.since_start(AU.log_tail(cfg)).get("public") or ""
    except Exception:                                    # noqa: BLE001 - only a hint
        return ""


def checks(ctx, snap=None):
    snap = snap or _meta_json(ctx.store, "mikrotik:snap")
    if not snap:
        return None
    ws = wants(ctx)
    snap = dict(snap, public_ip=_public_ip(ctx))
    res = C.check_all(snap, ws)
    for row, w in zip(res["rows"], ws):
        row.update(asked=w.get("asked", 0), last=w.get("last") or "", description=w.get("description") or "",
                   held=bool(w.get("held")), gateway=bool(w.get("gateway")))
    # 1.9.4: when a port turns open between two reads (a rule put right), the drops the router's log still holds
    # from before are history - counted only from that read on, and said as such
    seen = _meta_json(ctx.store, "mikrotik:opened") or {}
    at = float(snap.get("at") or time.time())
    was = json.dumps(seen, sort_keys=True)
    for row in res["rows"]:
        for fam, ok, key in (("4", row.get("state") == "ok", "drops4"), ("6", row.get("v6") == "open", "drops6")):
            k = "%s/%s/%s/%s" % (row["device"], row["proto"], row["port"], fam)
            old = seen.get(k)
            if not ok:
                seen[k] = {"ok": False, "since": 0}
                continue
            if old is None:
                seen[k] = {"ok": True, "since": 0}          # open when first seen: its drops are not history
            elif not old.get("ok"):
                seen[k] = {"ok": True, "since": at}         # opened now: what the log held before is history
            since = seen[k]["since"]
            if since:
                addrs = ([row["device"]] + ([row["way"]["public"]] if (row.get("way") or {}).get("public") else [])) \
                    if fam == "4" else (row.get("v6_addrs") or [])
                row[key] = C.drops_of(snap, addrs, row["proto"], {row["port"], row["to_port"]}, since=since)
                row[key]["opened_at"] = since
    if json.dumps(seen, sort_keys=True) != was:
        if len(seen) > 2000:
            seen = dict(list(seen.items())[-2000:])
        ctx.store.set_meta("mikrotik:opened", json.dumps(seen))
    res["merged"] = C.merged_commands(res["rows"])
    return res


def view(ctx, full=True):
    c = conf(ctx)
    st = _meta_json(ctx.store, "mikrotik:state") or {}
    snap = _meta_json(ctx.store, "mikrotik:snap")
    pin = ctx.store.get_meta("mikrotik:pin") or ""
    out = {"on": c["on"], "conf": {k: c[k] for k in ("host", "mode", "tls", "port", "user", "auth", "every", "timeout",
                                                    "tls_name")},
           "port_used": c["port"] or M.usual_port(c["mode"], c["tls"]), "state": st, "reading": READING["busy"],
           "pin": pin, "pin_words": M.fp_words(pin), "password_set": bool(ctx.setting("mikrotik_password")),
           "key": {"public": ctx.store.get_meta("mikrotik:pub") or "", "set": bool(ctx.store.get_meta("mikrotik:key"))},
           "hostkeys": M.host_keys_known(known_hosts(ctx), c["host"], c["port"] or 22) if c["mode"] == "ssh" and c["host"] else [],
           "can_keygen": bool(__import__("shutil").which("ssh-keygen")), "this": _this_address(c["host"]),
           "guide": {m: M.commands(c["user"], m, _this_address(c["host"]), ctx.store.get_meta("mikrotik:pub") or "")
                     for m in ("rest", "api", "ssh")},
           "node": socket.gethostname().split(".")[0], "at": time.time()}
    if snap:
        out["snap"] = {k: snap.get(k) for k in ("at", "via", "identity", "version", "board", "uptime", "cpu", "memory",
                                               "missing", "upnp", "tracking", "serial")}
        out["snap"]["counts"] = {fam: {t: len(v) for t, v in tabs.items()} for fam, tabs in (snap.get("rules") or {}).items()}
        out["checks"] = checks(ctx, snap)
    return out


def _this_address(host):
    """This machine's address toward the router - what its /ip service address= may let in."""
    try:
        h = M.bare_host(host)
        if not h:
            return ""
        fam = socket.AF_INET6 if ":" in h else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.connect((h, 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return ""


def rules_view(ctx):
    snap = _meta_json(ctx.store, "mikrotik:snap")
    if not snap:
        return {"snap": None}
    res = checks(ctx, snap) or {"rows": []}
    concern = {}
    for r in res["rows"]:
        for x in r.get("rules", []) + r.get("v6_rules", []):
            if x.get("id"):
                concern.setdefault("%s:%s" % (x["family"], x["id"]), []).append(
                    "%s %s/%s" % (r.get("name") or r["device"], r["port"], r["proto"]))
    wan = res.get("wan") or C.wan_of(snap)
    return {"snap": {k: snap.get(k) for k in ("at", "prev_at", "via", "identity", "version", "board", "rules", "lists",
                                             "interfaces", "iflists", "addresses4", "addresses6", "upnp", "upnp_ifs",
                                             "missing", "arp", "neigh6")},
            "concern": concern, "devices": sorted({r["device"] for r in res["rows"]}),
            "ports": sorted({"%s/%s" % (r["port"], r["proto"]) for r in res["rows"]}), "wan": wan}


# ---- the routes ------------------------------------------------------------------------------------------------
def get(ctx):
    me = ctx.need("readonly")
    return view(ctx, full=me.get("role") == "fulladmin")


def get_rules(ctx):
    ctx.need("readonly")
    return rules_view(ctx)


def post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    do = str(b.get("do") or "")
    c = conf(ctx)
    if do == "read":
        if not c["on"]:
            raise ValueError("reading the MikroTik is off - switch it on and save first")
        st = read_now(ctx, me["name"])
        d = view(ctx)
        d["message"] = ("read: %s rule(s) in %s s" % (st.get("rules"), st.get("took"))) if st.get("ok") else \
            "it could not be read: %s" % st.get("trouble")
        return d
    if do == "test":
        if not c["host"]:
            raise ValueError("the router's address is not set - Settings → MikroTik, above, and save")
        try:
            sess = session_of(ctx, c)
        except M.MtError as e:
            return {"ok": False, "trouble": str(e), "steps": [{"what": "the settings", "ok": False, "said": str(e)}]}
        got = M.probe(sess, c["user"])
        got["fingerprint_words"] = M.fp_words(got.get("fingerprint"))
        got["pinned"] = bool(got.get("fingerprint")) and got.get("fingerprint") == (ctx.store.get_meta("mikrotik:pin") or "")
        got["via"], got["tls"] = c["mode"], c["tls"]
        ctx.event("%s tried reaching the MikroTik %s (%s): %s" % (me["name"], c["host"], c["mode"],
                                                                "it answered" if got.get("ok") else got.get("trouble", "")[:200]),
                  "info" if got.get("ok") else "warn")
        return got
    if do == "trust":
        fp = re.sub(r"[^0-9a-f]", "", str(b.get("fingerprint") or "").lower())
        if len(fp) != 64:
            raise ValueError("which certificate? its SHA-256 fingerprint, as Try reaching it showed it")
        ctx.store.set_meta("mikrotik:pin", fp)
        ctx.event("%s trusted the MikroTik %s's certificate %s" % (me["name"], c["host"], M.fp_words(fp)), "warn")
        d = view(ctx)
        d["message"] = "its certificate is trusted - Try reaching it again"
        return d
    if do == "trust-forget":
        ctx.store.set_meta("mikrotik:pin", "")
        ctx.event("%s forgot the MikroTik's trusted certificate" % me["name"], "warn")
        d = view(ctx)
        d["message"] = "forgotten - the next Try reaching it shows the certificate the router answers with"
        return d
    if do == "hostkey-scan":
        keys = M.host_key_scan(c["host"], c["port"] or 22, timeout=min(15, c["timeout"]),
                               keyscan=os.environ.get("FAKE_IGD_SSH_KEYSCAN", "ssh-keyscan"))
        ctx.store.set_meta("mikrotik:hostkeys-seen", json.dumps({"host": c["host"], "port": c["port"] or 22,
                                                                 "keys": keys, "at": time.time()}))
        return {"keys": [{"type": k["type"], "fingerprint": k["fingerprint"]} for k in keys],
                "known": M.host_keys_known(known_hosts(ctx), c["host"], c["port"] or 22)}
    if do == "hostkey-trust":
        seen = _meta_json(ctx.store, "mikrotik:hostkeys-seen") or {}
        if seen.get("host") != c["host"] or seen.get("port") != (c["port"] or 22) or time.time() - float(seen.get("at") or 0) > 900:
            raise ValueError("look at its host key first (it is shown for 15 minutes)")
        k = M.host_key_trust(known_hosts(ctx), c["host"], c["port"] or 22, seen.get("keys") or [],
                             str(b.get("fingerprint") or ""))
        ctx.event("%s trusted the MikroTik %s's ssh host key %s %s" % (me["name"], c["host"], k["type"], k["fingerprint"]),
                  "warn")
        d = view(ctx)
        d["message"] = "its host key is trusted - Try reaching it"
        return d
    if do == "hostkey-forget":
        M.host_key_forget(known_hosts(ctx), c["host"], c["port"] or 22)
        ctx.event("%s forgot the MikroTik %s's ssh host key" % (me["name"], c["host"]), "warn")
        d = view(ctx)
        d["message"] = "forgotten - look at its host key again and trust it"
        return d
    if do in ("keygen", "key"):
        import igd_seal as SEAL
        if do == "keygen":
            private, public = M.make_key("fake-igd@%s" % socket.gethostname().split(".")[0])
        else:
            private = str(b.get("key") or "").strip() + "\n"
            if "PRIVATE KEY-----" not in private:
                raise ValueError("an OpenSSH private key, whole, with its BEGIN and END lines")
            public = M.public_of(private)
            if not public:
                raise ValueError("that key cannot be read (one with a passphrase cannot be used)")
        ctx.store.set_meta("mikrotik:key", SEAL.seal(ctx.store, private, "mikrotik:key"))
        ctx.store.set_meta("mikrotik:pub", public)
        ctx.event("%s %s the ssh key for the MikroTik" % (me["name"], "made" if do == "keygen" else "gave"), "warn")
        d = view(ctx)
        d["message"] = "a new key - put its public half on the router" if do == "keygen" else "the key is kept"
        return d
    if do == "key-forget":
        ctx.store.set_meta("mikrotik:key", "")
        ctx.store.set_meta("mikrotik:pub", "")
        ctx.event("%s forgot the ssh key for the MikroTik" % me["name"], "warn")
        d = view(ctx)
        d["message"] = "the key is gone"
        return d
    raise ValueError("no such thing to do")


def on_saved(ctx, changed):
    if any(k in changed for k in ("mikrotik_host", "mikrotik_mode", "mikrotik_port")):
        ctx.store.set_meta("mikrotik:pin", "")          # another router, or another service: trusted afresh
    if conf(ctx)["on"]:
        threading.Thread(target=read_now, args=(ctx, (ctx.me or {}).get("name", "")), daemon=True).start()


ROUTES = {
    ("GET", "/api/mikrotik"): get,
    ("GET", "/api/mikrotik/rules"): get_rules,
    ("POST", "/api/mikrotik"): post,
}


def background(ctx):
    c = conf(ctx)
    if not c["on"] or not c["host"] or READING["busy"]:
        return
    st = _meta_json(ctx.store, "mikrotik:state") or {}
    if time.time() - float(st.get("at") or 0) >= 60 * c["every"] - 5:
        threading.Thread(target=read_now, args=(ctx,), daemon=True).start()


def problems(ctx):
    """For the alerts: each port asked for that is not open on the MikroTik, and its own UPnP on."""
    c = conf(ctx)
    if not c["on"]:
        return {}
    out = {}
    st = _meta_json(ctx.store, "mikrotik:state") or {}
    if st.get("ok") is False:
        out["mikrotik"] = {"level": "warn", "title": "The MikroTik cannot be read", "pane": "mikrotik",
                           "said": str(st.get("trouble") or "")[:300]}
        return out
    res = checks(ctx)
    if not res:
        return out
    for r in res["rows"]:
        if r["state"] in ("ok", "unsure"):
            continue
        out["mikrotik:%s:%s:%s" % (r["device"], r["proto"], r["port"])] = {
            "level": "warn", "pane": "mikrotik", "link": "#gateway/mikrotik/%s/%s/%s" % (r["device"], r["proto"], r["port"]),
            "title": "%s %s/%s is not open on the MikroTik" % (r.get("name") or r["device"], r["port"], r["proto"]),
            "said": str(r.get("nat_why") or r.get("forward_why") or "")[:300]}
    for w in res["warnings"]:
        if "UPnP is ON" in w:
            out["mikrotik:upnp"] = {"level": "warn", "pane": "mikrotik", "link": "#gateway/mikrotik", "title": "The MikroTik's own UPnP is on",
                                    "said": w[:300]}
    return out
