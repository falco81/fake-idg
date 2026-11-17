"""api_gateway.py - Settings → Gateway for devices (1.7.15).

A PS5 asks UPnP only of its DEFAULT GATEWAY: with the real router as its gateway it searches, gets
fake-igd's answer and never fetches the description. Made the gateway of such a device, this server
forwards the device's traffic to the real router - and nothing else: forwarding only for the devices
defined here (each by its IPv4 address, a name and best its MAC), only in and out the interface of
this server's default route, only toward the router, never to another network of this server; a DROP
of fake-igd's own at the end of its FORWARD chain; turned on only with fake-igd's firewall on. Put in
by root (deploy/root_gateway.py) ON TRIAL as every change of the firewall.

  GET  /api/gateway          the devices, the interface and the router, how it stands (root's last
                             reading), the neighbours, the trial
  POST /api/gateway {action: on | off | device_save {device} | device_remove {id} |
                     device_on {id, on} | read | keep | back | mac_seen {ip}}
  GET  /api/gateway/trial    what waits to be kept (the banner on every page)

Kept in the database: meta "gateway" ({on, devices: [{id, name, ip, mac, on}], by, at}) - what is
wanted; root reads it (read only) and writes what it put in to web/gateway.json.
"""
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in (HERE, os.path.join(os.path.dirname(HERE), "deploy")):
    if os.path.isfile(os.path.join(_d, "root_gateway.py")) and _d not in sys.path:
        sys.path.append(_d)
import root_gateway as R     # noqa: E402 - the same checks as root's (it reads only, here)

NAME = "gateway"
SETTINGS = []
LOCK = threading.Lock()
READ_EVERY = 300
ASK_STALE_S = 120
RESOLV = os.environ.get("FAKE_IGD_RESOLV", "/etc/resolv.conf")


def _meta(store):
    try:
        got = json.loads(store.get_meta("gateway") or "{}")
    except ValueError:
        got = {}
    if not isinstance(got, dict):
        got = {}
    got["devices"] = [d for d in got.get("devices") or [] if isinstance(d, dict)][:R.MOST_DEVICES]
    got["on"] = got.get("on") is True
    return got


def _put(ctx, meta, words):
    meta["by"] = (ctx.me or {}).get("name") or "?"
    meta["at"] = time.time()
    ctx.store.set_meta("gateway", json.dumps(meta))
    ident = ctx.ask_root({"do": "apply"})
    ctx.store.set_meta("gateway:asked", json.dumps({"id": ident, "at": time.time(), "do": "apply"}))
    ctx.event("%s: %s" % (meta["by"], words), "warn")
    return ident


def state():
    return R.state_read()


def dns_now():
    out = []
    try:
        with open(RESOLV) as f:
            for ln in f:
                p = ln.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    try:
                        if ipaddress.ip_address(p[1]).version == 4:
                            out.append(p[1])
                    except ValueError:
                        pass
    except OSError:
        pass
    return out[:3]


def net_view():
    """The interface of the default route, the router, this server's address and mask there."""
    net = R.net_now()
    addrs = (net.get("ifaces") or {}).get(net.get("defif") or "", [])
    first = ipaddress.ip_interface(addrs[0]) if addrs else None
    return {"defif": net.get("defif") or "", "router": net.get("router") or "",
            "address": str(first.ip) if first else "", "prefix": first.network.prefixlen if first else 0,
            "mask": str(first.network.netmask) if first else "", "network": str(first.network) if first else "",
            "others": {k: [str(ipaddress.ip_interface(a).network) for a in v]
                       for k, v in (net.get("ifaces") or {}).items() if k != net.get("defif")},
            "dns": dns_now(), "_net": net}


def neighbours():
    return R.neighbours()


def asked(ctx):
    """The last ask of root and its answer: {id, at, do, state: waiting | done | failed, said}."""
    try:
        a = json.loads(ctx.store.get_meta("gateway:asked") or "{}")
    except ValueError:
        a = {}
    if not isinstance(a, dict) or not a.get("id"):
        return {}
    r = ctx.root_result(ident=a["id"])
    if r and r.get("id") == a["id"]:
        a.update(state="done" if r.get("ok", True) else "failed", said=[str(x) for x in r.get("said") or []][:12])
    elif time.time() - float(a.get("at") or 0) > ASK_STALE_S:
        a.update(state="failed", said=["root did not answer in %d s - is fake-igd-web.path running?" % ASK_STALE_S])
    else:
        a["state"] = "waiting"
    return a


def _trial_ack(ctx, st):
    """A trial put back by root: what is wanted goes back with it (once for each trial)."""
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    if t.get("done") != "back" or not t.get("id") or ctx.store.get_meta("gateway:back") == t["id"]:
        return
    was = t.get("was") if isinstance(t.get("was"), dict) else {}
    meta = _meta(ctx.store)
    meta.update(on=was.get("on") is True, devices=[d for d in was.get("devices") or [] if isinstance(d, dict)],
                by=str(t.get("done_by") or "the trial"), at=time.time())
    with LOCK:
        ctx.store.set_meta("gateway", json.dumps(meta))
        ctx.store.set_meta("gateway:back", t["id"])
    ctx.event("the gateway for devices went back to what it was: %s" % (t.get("done_by") or "not kept"), "warn")


def view(ctx):
    st = state()
    _trial_ack(ctx, st)
    meta = _meta(ctx.store)
    nv = net_view()
    net = nv.pop("_net")
    live = st.get("live") or {}
    fv = live.get("forward") or {}
    counters = fv.get("counters") or {}
    seen = st.get("seen") or {}
    applied = {d.get("ip"): d for d in st.get("devices") or [] if isinstance(d, dict)} if st.get("on") else {}
    by_comment = fv.get("by_comment") or {}
    devices = []
    for d in meta["devices"]:
        ok, bad = R.device_checked(d, net)
        ip = str(d.get("ip") or "")
        a = applied.get(ip)
        devices.append(dict(d, why=bad, applied=bool(a and a.get("on")),
                            mac_applied=(a or {}).get("mac") or "", counters=counters.get(ip) or {},
                            seen=(seen.get(ip) or {}).get("changed") or 0,
                            **(designer_of(ok, net, by_comment) if ok else {})))
    fwd_now = R.proc_read("net/ipv4/ip_forward")
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    return {"on": meta["on"], "devices": devices, "by": meta.get("by") or "", "at": meta.get("at") or 0,
            "net": nv, "applied": {"on": st.get("on") is True, "why_off": st.get("why_off") or "",
                                   "at": st.get("at") or 0, "defif": st.get("defif") or "",
                                   "router": st.get("router") or ""},
            "live": {"ip_forward": fwd_now, "ip6_forward": R.proc_read("net/ipv6/conf/all/forwarding"),
                     "redirects": R.proc_read("net/ipv4/conf/all/send_redirects"),
                     "chain": bool(fv.get("chain")), "first": bool(fv.get("ours_first")),
                     "ends_drop": bool(fv.get("ends_drop")), "dropped": int(fv.get("dropped") or 0),
                     "policy": fv.get("policy") or "", "file": bool(live.get("file")),
                     "firewall": bool(ctx.cfg.get("firewall")), "ready": live.get("ready"),
                     "read_at": live.get("read_at") or 0},
            "neigh": neighbours(), "asked": asked(ctx),
            "trial": {k: t.get(k) for k in ("id", "until", "min", "by", "at", "done", "done_by", "done_at")}
            if R.pending(t) else {}, "confirm_min": ctx.setting("fw_confirm_min"), "now": time.time()}


def _hits(by_comment, prefix):
    """Packets and bytes of the lines whose comment starts so (a rule: its way out; "back" counted apart)."""
    out = {"pkts": 0, "bytes": 0, "back_pkts": 0, "back_bytes": 0}
    for c, n in by_comment.items():
        if c == prefix or c.startswith(prefix + " ") or c.startswith(prefix + ":"):
            k = "back_" if c.endswith(" back") else ""
            out[k + "pkts"] += int(n.get("pkts") or 0)
            out[k + "bytes"] += int(n.get("bytes") or 0)
    return out


def designer_of(dev, net, by_comment):
    """What the FW designer of a device shows: its DNS servers and rules as root reads them (where each is
    reached, "direct" ones need no rule), what is left out and why, the lines root puts in for it, and the
    packets of each from iptables -vnx."""
    who = "fake-igd: %s (%s)" % (dev["name"], dev["ip"])
    dns = [dict(x, hits=_hits(by_comment, "%s dns %s" % (who, x["ip"]))) for x in dev["dns"]]
    rules = [dict(r, hits=_hits(by_comment, "%s rule %s" % (who, r["id"]))) for r in dev["rules"]]
    lines = R.allow_lines(dev, net) + [x for x in R.lines_for([dev], net) if "gateway for %s" % dev["name"] in x]
    return {"dns": dns, "rules": rules, "left_out": dev.get("left_out") or [], "lines": lines,
            "internet": _hits(by_comment, "fake-igd: gateway for %s (%s)" % (dev["name"], dev["ip"]))}


def _plain(dev):
    """A device as it is kept in the database: what was typed, nothing worked out."""
    return {"id": dev["id"], "name": dev["name"], "ip": dev["ip"], "mac": dev.get("mac") or "",
            "on": dev.get("on") is not False,
            "dns": [{"ip": x["ip"], "dot": bool(x.get("dot"))} for x in dev.get("dns") or []],
            "rules": [{k: r.get(k) for k in ("id", "to", "proto", "ports", "comment", "on")} for r in dev.get("rules") or []]}


def designed(raw, old, net):
    """A device's DNS servers and rules as the designer sends them - checked as root checks them; refused
    whole with every reason when anything does not pass (on the pages nothing is left out silently)."""
    dns = raw.get("dns") if isinstance(raw.get("dns"), list) else []
    rules = raw.get("rules") if isinstance(raw.get("rules"), list) else []
    if len(rules) > R.MOST_RULES:
        raise ValueError("%d rules at most for a device" % R.MOST_RULES)
    if len(dns) > R.MOST_DNS:
        raise ValueError("%d DNS servers at most for a device" % R.MOST_DNS)
    for r in rules:
        if isinstance(r, dict) and not R.RULE_ID_RE.match(str(r.get("id") or "")):
            r["id"] = secrets.token_hex(4)
    got, bad = R.device_checked(dict(old, dns=dns, rules=rules), net)
    if bad:
        raise ValueError(bad)
    if got["left_out"]:
        raise ValueError("; ".join(got["left_out"]))
    seen = set()
    for x in got["dns"]:
        if x["ip"] in seen:
            raise ValueError("%s twice among the DNS servers" % x["ip"])
        seen.add(x["ip"])
    return got


def get_gateway(ctx):
    ctx.need("readonly")
    return view(ctx)


def device_in(ctx, raw, meta, net):
    """A device as typed on the pages, checked as root checks it, and against the others."""
    if not isinstance(raw, dict):
        raise ValueError("which device?")
    got, bad = R.device_checked(dict(raw, on=raw.get("on") is not False), net)
    if bad:
        raise ValueError(bad)
    if raw.get("name") and R.NAME_BAD.search(str(raw["name"])):
        raise ValueError("the name: letters, digits, spaces and . _ ( ) + , : / - only")
    for d in meta["devices"]:
        if d.get("id") != raw.get("id") and d.get("ip") == got["ip"]:
            raise ValueError("%s is %s already" % (got["ip"], d.get("name")))
    if not raw.get("id"):
        got["id"] = secrets.token_hex(6)
    if len(meta["devices"]) >= R.MOST_DEVICES and not any(d.get("id") == raw.get("id") for d in meta["devices"]):
        raise ValueError("%d devices at most" % R.MOST_DEVICES)
    return got


def post_gateway(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    if act == "mac_seen":
        ip = str(b.get("ip") or "").strip()
        mac = neighbours().get(ip, "")
        return {"ip": ip, "mac": mac, "message": ("seen just now: %s" % mac) if mac else
                "%s is not in this server's neighbour table - is it on and on the same network?" % ip}
    if act in ("read", "keep", "back"):
        st = state()
        if act != "read" and not R.pending(st.get("trial")):
            raise ValueError("no change of the gateway for devices waits to be kept")
        ident = ctx.ask_root({"do": act})
        if act != "read":
            ctx.event("%s asked to %s the gateway for devices" % (me["name"], "keep" if act == "keep" else
                                                                  "put back the old instead of"),
                      "info" if act == "keep" else "warn")
        return {"id": ident, "message": {"read": "asked: root reads it within seconds",
                                         "keep": "kept - within seconds",
                                         "back": "what was there comes back within seconds"}[act]}
    nv = net_view()
    net = nv["_net"]
    with LOCK:
        meta = _meta(ctx.store)
        if act in ("on", "off"):
            want = act == "on"
            if want:
                if not any(d.get("on") is not False for d in meta["devices"]):
                    raise ValueError("define a device first (Add a device): forwarding is turned on only for the "
                                     "devices defined here")
                if not ctx.cfg.get("firewall"):
                    raise ValueError("fake-igd's firewall is off: switch it on first (Settings → Firewall and "
                                     "access) - forwarding is turned on only behind fake-igd's own FORWARD chain, "
                                     "which ends in a DROP")
                if not nv["defif"]:
                    raise ValueError("this server has no default route - there is no router to forward toward")
            meta["on"] = want
            ident = _put(ctx, meta, "the gateway for devices switched %s" % act)
            return {"id": ident, "message": "asked: root %s within seconds" %
                    ("turns the forwarding on for %s" % ", ".join(d.get("name") for d in meta["devices"]
                                                                if d.get("on") is not False)
                     if want else "turns the forwarding off")}
        if act in ("designer_save", "try"):
            did = str(b.get("id") or "")
            old = next((d for d in meta["devices"] if d.get("id") == did), None)
            if old is None:
                raise ValueError("no such device")
            got = designed(b, old, net)
            if act == "try":
                return try_it(meta, got, b, net)
            meta["devices"] = [_plain(got) if d.get("id") == did else d for d in meta["devices"]]
            ident = _put(ctx, meta, "the firewall of the device %s (%s): %d DNS server(s), %d rule(s) of its own" % (
                got["name"], got["ip"], len(got["dns"]), len(got["rules"])))
            return {"id": ident, "message": "saved - root puts it in within seconds" + (
                ", on trial" if meta["on"] and ctx.setting("fw_confirm_min") else "") if meta["on"]
                else "saved - put in when the gateway is switched on"}
        if act == "device_save":
            got = device_in(ctx, b.get("device"), meta, net)
            old = next((d for d in meta["devices"] if d.get("id") == got["id"]), None)
            if old:                             # its DNS servers and rules stay (the designer's)
                got["dns"] = old.get("dns") or []
                got["rules"] = old.get("rules") or []
            got = _plain(got)
            if old is None and b.get("device", {}).get("id"):
                raise ValueError("no such device")
            meta["devices"] = [got if d.get("id") == got["id"] else d for d in meta["devices"]] if old else \
                meta["devices"] + [got]
            ident = _put(ctx, meta, "%s the device %s (%s%s) of the gateway" % (
                "changed" if old else "added", got["name"], got["ip"], ", MAC %s" % got["mac"] if got["mac"] else ""))
            return {"id": ident, "device": got, "message": "saved - root puts it in within seconds" if meta["on"]
                    else "saved - switch the gateway on to forward for it"}
        if act in ("device_remove", "device_on"):
            did = str(b.get("id") or "")
            d = next((x for x in meta["devices"] if x.get("id") == did), None)
            if d is None:
                raise ValueError("no such device")
            if act == "device_remove":
                meta["devices"] = [x for x in meta["devices"] if x.get("id") != did]
                if not meta["devices"]:
                    meta["on"] = False              # the last one gone: the forwarding goes with it
                words = "took the device %s (%s) away from the gateway" % (d.get("name"), d.get("ip"))
            else:
                d["on"] = b.get("on") is True
                words = "switched the device %s (%s) %s" % (d.get("name"), d.get("ip"), "on" if d["on"] else "off")
            ident = _put(ctx, meta, words)
            return {"id": ident, "message": "asked: root puts it in within seconds"}
    raise ValueError("no such action")


def try_it(meta, dev, b, net):
    """"Try a packet": from the device (or a box that takes its address, mac_other) to dst - through the lines
    as they would be with what the designer holds now (the other devices as they are kept)."""
    dst = str(b.get("dst") or "").strip()
    preview = {"lines": R.allow_lines(dev, net) + [x for x in R.lines_for([dev], net) if "gateway for %s" % dev["name"] in x],
               "dns": dev["dns"], "rules": dev["rules"]}
    if not dst:
        return preview                          # what root would put in for it - nothing tried
    try:
        a = ipaddress.ip_address(dst)
    except ValueError:
        raise ValueError("the destination: one IPv4 address")
    if a.version != 4:
        raise ValueError("the destination: IPv4")
    proto = str(b.get("proto") or "tcp")
    if proto not in ("tcp", "udp", "icmp"):
        raise ValueError("tcp, udp or icmp")
    try:
        port = int(b.get("port") or 0)
    except (TypeError, ValueError):
        raise ValueError("the port: a number")
    if proto in ("tcp", "udp") and not 1 <= port <= 65535:
        raise ValueError("the port: 1 to 65535")
    others = []
    for d in meta["devices"]:
        if d.get("id") == dev["id"]:
            others.append(dict(dev, on=True))
            continue
        ok, _bad = R.device_checked(d, net)
        if ok:
            others.append(ok)
    got = R.try_packet(others, dev, str(a), proto, port, net, mac="aa:bb:cc:00:00:01" if b.get("mac_other") else None)
    words = {"ACCEPT": "forwarded", "DROP": "dropped", "FALLTHROUGH": "not decided by fake-igd"}.get(got["verdict"], got["verdict"])
    if got["direct"]:
        words = "reached directly on its own network - this server is not asked (no rule needed)"
    return dict(got, words=words, **preview)


def get_trial(ctx):
    """For the banner on every page: anybody signed in sees it; Keep it and Put it back are a full admin's."""
    ctx.need("readonly")
    st = state()
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    out = []
    if R.pending(t):
        out.append({"kind": "gateway", "id": t.get("id"), "until": float(t.get("until") or 0),
                    "devices": [d.get("name") for d in st.get("devices") or [] if d.get("on")]})
    return {"trials": out, "now": time.time()}


ROUTES = {("GET", "/api/gateway"): get_gateway, ("POST", "/api/gateway"): post_gateway,
          ("GET", "/api/gateway/trial"): get_trial}


def background(ctx):
    """The trial put back - what is wanted with it; a trial whose timer was lost - root asked; how it stands
    read every five minutes while it is on (the packets, and whether forwarding is still on)."""
    st = state()
    _trial_ack(ctx, st)
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    a = asked(ctx)
    waiting = a.get("state") == "waiting"
    if R.pending(t) and time.time() > float(t.get("until") or 0) + 120 and not waiting:
        ident = ctx.ask_root({"do": "expire", "id": t.get("id")})
        ctx.store.set_meta("gateway:asked", json.dumps({"id": ident, "at": time.time(), "do": "expire"}))
        return
    if st.get("on") is True and not waiting:
        live = st.get("live") or {}
        if time.time() - float(live.get("read_at") or 0) >= READ_EVERY:
            ident = ctx.ask_root({"do": "read"})
            ctx.store.set_meta("gateway:asked", json.dumps({"id": ident, "at": time.time(), "do": "read"}))


def problem(ctx):
    """For the alerts: switched on and put in, but the kernel's forwarding is off (turned off by something
    else) - or the chain is no longer first in FORWARD. "" when all is well."""
    st = state()
    if st.get("on") is not True:
        return ""
    if R.proc_read("net/ipv4/ip_forward") == "0":
        return "net.ipv4.ip_forward was turned off by something else - the devices that use this server as " \
               "their gateway reach nothing (Settings → Gateway for devices: switch it off and on)"
    fv = (st.get("live") or {}).get("forward") or {}
    if (st.get("live") or {}).get("read_at") and not (fv.get("chain") and fv.get("ours_first")):
        return "%s is no longer first in FORWARD - the devices' traffic is not forwarded (Settings → Gateway " \
               "for devices)" % R.CHAIN
    return ""
