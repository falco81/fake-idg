"""api_ntfy.py - what is sent to ntfy, and what the pages themselves send (1.8.2).

fake-igd.service sends the UPnP events itself (igd_ntfy, the same client); this module gives the
pane "Notifications (ntfy)" its card "What is sent" and sends what only the pages' API sees:

  the gateway for devices   a device came online or went offline (the neighbour table, its traffic),
                            its drops toward networks it may not reach over ntfy_gw_drops_per_hour,
                            forwarding turned off by something else, a device's own rule used first
  the alerts                every alert of Settings → Alerts and reports (each kind can be left out),
                            and - switched on - when it is over

  GET  /api/ntfy   every kind of event: on, priority, tags, as it comes; the alerts' kinds; quiet hours
                   and the rate limit as they are now; what the pages sent
  POST /api/ntfy   {action: "events", events: {kind: {on, priority, tags}, "alert:K": {on}}} - saved into
                   config.json's ntfy_events (fake-igd.service restarts with it; notify_on_renew and
                   notify_other_router follow port_renew and other_router)
                   {action: "sample", kind} - that kind's own wording sent now, marked as a sample

What the pages sent is kept in the database (meta "ntfy:sent"); a send that failed - the pages' or
fake-igd.service's (its log) - is written to Events as well.
"""
import json
import os
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import igd_ntfy as N                                       # noqa: E402

NAME = "ntfy"
SETTINGS = [
    {"key": "ntfy_gw_drops_per_hour", "name": "Drops toward local networks: more than (an hour)", "kind": "int",
     "default": 100, "min": 1, "max": 1000000, "pane": "ntfy",
     "says": "The event \"Drops toward local networks\" (What is sent → Gateway for devices): a device of Gateway "
             "for devices tried more often than this in an hour to reach networks it may not - counted by the "
             "drop lines of its own in fake-igd's FORWARD chain. Once an hour at most for each device."},
]
SENT_KEPT = 200
OFFLINE_S = int(os.environ.get("FAKE_IGD_NTFY_OFFLINE_S") or 180)     # gone this long: offline
TRAFFIC_S = 300                                                       # its traffic this recent: online
LOCK = threading.Lock()
CUR = {"cfg": {}, "store": None}


def _record(kind, title, ok, words, why=""):
    """Every send of the pages: kept for "What was sent"; a failed one in Events too."""
    store = CUR["store"]
    if store is None:
        return
    host = urllib.parse.urlparse(str(CUR["cfg"].get("ntfy_url") or "")).netloc
    with LOCK:
        try:
            rows = json.loads(store.get_meta("ntfy:sent") or "[]")
        except ValueError:
            rows = []
        rows = [r for r in rows if isinstance(r, dict)][-(SENT_KEPT - 1):]
        rows.append({"at": time.time(), "kind": kind, "title": str(title)[:200], "ok": bool(ok),
                     "said": str(words)[:300], "host": host, "why": why})
        store.set_meta("ntfy:sent", json.dumps(rows))
    if not ok:
        store.add_event("notify", "notify: sending [%s] '%s' to %s failed: %s" % (kind, title, host, words), "warn")


NOTE = N.Notifier(lambda: CUR["cfg"], _record)


def _use(ctx):
    CUR["cfg"], CUR["store"] = ctx.cfg, ctx.store


def _meta(store, key, empty):
    try:
        got = json.loads(store.get_meta(key) or "null")
    except ValueError:
        got = None
    return got if isinstance(got, type(empty)) else empty


def on(cfg, kind):
    return bool(N.conf(cfg, kind)["on"])


# ---- the view ----------------------------------------------------------------------------------------
def view(ctx):
    _use(ctx)
    cfg = ctx.cfg
    events = []
    for kind, group, words, says, dflt in N.EVENTS:
        c = N.conf(cfg, kind)
        look = N.LOOK.get(kind, (0, ""))
        events.append({"kind": kind, "group": group, "words": words, "says": says, "default": dflt,
                       "on": bool(c["on"]), "priority": int(c.get("priority") or 0), "tags": c.get("tags") or "",
                       "look_priority": look[0], "look_tags": look[1], "by": "fake-igd.service"
                       if group == "upnp" else "fake-igd-api"})
    alerts = [{"kind": k, "words": w, "on": on(cfg, "alert:" + k)} for k, w in N.ALERT_KINDS]
    with NOTE.lock:
        held = len(NOTE.held)
        limited = {k: o["n"] for k, o in NOTE.over.items()}
    return {"events": events, "groups": N.GROUP_WORDS, "alert_kinds": alerts,
            "quiet": {"from": cfg.get("ntfy_quiet_from") or "", "to": cfg.get("ntfy_quiet_to") or "",
                      "priority": int(cfg.get("ntfy_quiet_priority") or 4),
                      "summary": bool(cfg.get("ntfy_quiet_summary", True)), "now": N._quiet(cfg), "held": held},
            "rate": int(cfg.get("ntfy_rate_per_hour") or 0), "limited": limited,
            "drops_per_hour": int(ctx.setting("ntfy_gw_drops_per_hour") or 100),
            "url": bool(cfg.get("ntfy_url")), "kinds": N.KINDS + ["summary", "test"], "at": time.time()}


def sent_rows(store):
    """What the pages sent, for "What was sent" (api_upnp)."""
    return [dict(r, by="fake-igd-api") for r in _meta(store, "ntfy:sent", []) if isinstance(r, dict)]


def _api():
    for name in ("fake_igd_api", "__main__"):
        m = sys.modules.get(name)
        if m is not None and hasattr(m, "settings_save"):
            return m
    return None


def post(ctx):
    me = ctx.need("fulladmin")
    _use(ctx)
    b = ctx.body()
    action = b.get("action")
    if action == "sample":
        kind = str(b.get("kind") or "")
        if kind not in N.SAMPLES:
            raise ValueError("no such kind of event")
        if not ctx.cfg.get("ntfy_url"):
            raise ValueError("no ntfy topic URL yet - fill it in and save it first")
        title, words = N.SAMPLES[kind]
        said = NOTE.send(kind, title, words, sample=True, wait=True)
        ok = said.startswith("sent")
        ctx.event("%s sent a sample of \"%s\" to ntfy - %s" % (me["name"], kind, said), "info" if ok else "warn",
                  kind="notify")
        return {"ok": ok, "message": said}
    if action == "events":
        ev = N.events_checked(b.get("events") or {})
        a = _api()
        if a is None:
            raise ValueError("the API cannot save config.json from here")
        changes = {"ntfy_events": ev}
        if "port_renew" in ev:
            changes["notify_on_renew"] = ev["port_renew"]["on"]
        if "other_router" in ev:
            changes["notify_other_router"] = ev["other_router"]["on"]
        got = a.settings_save(changes, me["name"], ctx.addr)
        return dict(got, message="saved" + (" - fake-igd.service restarts with it" if got.get("restart") else ""))
    raise ValueError("no such action")


# ---- what only the pages see: the gateway, the alerts ---------------------------------------------------
def _gateway(ctx, now):
    G = sys.modules.get("api_gateway")
    if G is None:
        return
    st = G.state()
    m = _meta(ctx.store, "ntfy:gw", {})
    if st.get("on") is not True:
        if m:
            ctx.store.set_meta("ntfy:gw", "{}")
        return
    first = not m
    devices = [d for d in st.get("devices") or [] if isinstance(d, dict) and d.get("ip")]
    names = {d["ip"]: d.get("name") or d["ip"] for d in devices}
    # online / offline: in the neighbour table, or its traffic in the last minutes
    neigh = G.neighbours()
    seen = st.get("seen") if isinstance(st.get("seen"), dict) else {}
    was = m.get("online") if isinstance(m.get("online"), dict) else {}
    online = {}
    for ip, name in names.items():
        cur = ip in neigh or now - float((seen.get(ip) or {}).get("changed") or 0) < TRAFFIC_S
        o = was.get(ip) if isinstance(was.get(ip), dict) else None
        if o is None:
            online[ip] = {"on": cur, "flip": 0}
            continue
        if cur == o.get("on"):
            online[ip] = {"on": cur, "flip": 0}
            continue
        flip = float(o.get("flip") or 0) or now
        if cur or now - flip >= OFFLINE_S:
            if cur:
                NOTE.send("gw_online", "Gateway: %s is online" % name, "%s (%s%s) is online - in the neighbour table "
                          "again." % (name, ip, (", " + neigh[ip]) if ip in neigh else ""))
            else:
                NOTE.send("gw_online", "Gateway: %s is offline" % name, "%s (%s) went offline - not in the neighbour "
                          "table and no traffic for %d minutes." % (name, ip, max(1, int((now - flip) // 60))))
            online[ip] = {"on": cur, "flip": 0}
        else:
            online[ip] = {"on": o.get("on"), "flip": flip}
    m["online"] = online
    # drops toward local networks: more than the limit in the last hour (once an hour each)
    limit = int(ctx.setting("ntfy_gw_drops_per_hour") or 100)
    counters = G.counters_of(st) if (st.get("live") or {}).get("read_at") else {}
    drops = m.get("drops") if isinstance(m.get("drops"), dict) else {}
    for ip, ks in counters.items():
        pk = int((ks.get("dropped") or (0, 0))[0])
        d = drops.get(ip) if isinstance(drops.get(ip), dict) else {"hist": [], "told": 0}
        hist = [h for h in d.get("hist") or [] if now - h[0] <= 3600]
        if hist and pk < hist[-1][1]:
            hist = []                                      # counters zeroed (the chain made again)
        hist.append([now, pk])
        d["hist"] = hist[-90:]
        n = pk - hist[0][1]
        if n > limit and now - float(d.get("told") or 0) >= 3600:
            d["told"] = now
            NOTE.send("gw_drops", "Gateway: %s tried local networks" % names.get(ip, ip), "%s (%s) tried %d times in "
                      "the last hour to reach networks it may not (the limit is %d)." % (names.get(ip, ip), ip, n,
                                                                                       limit))
        drops[ip] = d
    m["drops"] = {k: v for k, v in drops.items() if k in names}
    # forwarding turned off by something else
    p = G.problem(ctx) or ""
    if p and p != m.get("fwd"):
        NOTE.send("gw_forward", "Gateway: forwarding is off" if "ip_forward" in p else "Gateway: not forwarding",
                  "The gateway for devices is on, but " + p + ".")
    m["fwd"] = p
    # a device's own rule used for the first time
    bc = (((st.get("live") or {}).get("forward")) or {}).get("by_comment") or {}
    hit = set(m.get("rules") or [])
    for d in devices:
        pre = "fake-igd: %s (%s) rule " % (d.get("name"), d["ip"])
        for c, n in bc.items():
            if not c.startswith(pre) or c.endswith(" back") or not int(n.get("pkts") or 0):
                continue
            rid = c[len(pre):].split(":")[0].split(" ")[0]
            key = "%s %s" % (d["ip"], rid)
            if key in hit:
                continue
            hit.add(key)
            if not first:
                rule = next((r for r in d.get("rules") or [] if isinstance(r, dict) and str(r.get("id")) == rid), {})
                what = rule.get("comment") or " ".join(str(x) for x in (rule.get("proto"), rule.get("ports"),
                                                                       "to", rule.get("to")) if x)
                NOTE.send("gw_rule_first", "Gateway: %s's rule used" % d.get("name"), "The rule %s '%s' of %s "
                          "forwarded its first packet." % (rid, what or "-", d.get("name")))
    m["rules"] = sorted(hit)[-500:]
    ctx.store.set_meta("ntfy:gw", json.dumps(m))


def _alerts(ctx, now):
    cfg = ctx.cfg
    if not on(cfg, "alerts"):
        if ctx.store.get_meta("ntfy:alerts") not in (None, "", "{}"):
            ctx.store.set_meta("ntfy:alerts", "{}")
        return
    A = sys.modules.get("api_alerts")
    if A is None:
        return
    c = A.cfg_of(ctx.store)
    cur = A.problems(ctx, c)
    known = _meta(ctx.store, "ntfy:alerts", {})
    delay = 60 * int(c.get("alerts_delay_min") or 0)
    for k, p in cur.items():
        kk = str(k).split(":")[0]
        was = known.get(k) if isinstance(known.get(k), dict) else {"since": now, "sent": False}
        was.update(title=str(p.get("title") or k)[:160], said=str(p.get("said") or "")[:600],
                   level=p.get("level") or "warn")
        if not was.get("sent") and now - float(was.get("since") or now) >= delay:
            if on(cfg, "alert:" + kk):
                NOTE.send("alerts", "fake-igd: " + was["title"], was["said"] or was["title"])
            was["sent"] = True                          # left out: not sent later either
        known[k] = was
    for k in [k for k in known if k not in cur]:
        p = known.pop(k)
        kk = str(k).split(":")[0]
        if isinstance(p, dict) and p.get("sent") and on(cfg, "alerts_over") and on(cfg, "alert:" + kk):
            NOTE.send("alerts_over", "fake-igd: over - " + str(p.get("title") or k),
                      "It is all right again: " + str(p.get("said") or p.get("title") or k))
    ctx.store.set_meta("ntfy:alerts", json.dumps(known))


def _daemon_failed(ctx):
    """fake-igd.service's sends that failed (its log): in Events as well."""
    U = sys.modules.get("api_upnp")
    if U is None:
        return
    rows = U.sends(ctx.cfg, 200, raw=True)
    last = ctx.store.get_meta("ntfy:daemon-seen")
    newest = max([r.get("at") or 0 for r in rows] + [float(last or 0)])
    if last is not None:
        for r in rows:
            if not r["ok"] and (r.get("at") or 0) > float(last):
                ctx.store.add_event("notify", "fake-igd.service: sending [%s] '%s' to %s failed: %s" % (
                    r.get("kind"), r.get("title"), r.get("host"), r.get("said")), "warn")
    ctx.store.set_meta("ntfy:daemon-seen", repr(newest))


def background(ctx):
    _use(ctx)
    now = time.time()
    for job in (lambda: NOTE.tick(), lambda: _daemon_failed(ctx), lambda: _gateway(ctx, now),
                lambda: _alerts(ctx, now)):
        try:
            job()
        except Exception as e:                         # noqa: BLE001 - one part never stops the others
            sys.stderr.write("api_ntfy: %s\n" % e)


ROUTES = {
    ("GET", "/api/ntfy"): view,
    ("POST", "/api/ntfy"): post,
}
