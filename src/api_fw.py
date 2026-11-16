"""api_fw.py - Settings → Firewall and access (1.6.0), otp's pane "fw" for one server.

Who may reach the pages (web_allow: nginx's allow list, and the firewall's 80/443) and the
machine's firewall - the chain FAKE-IGD-IN, for IPv4 and IPv6: what no rule may shut out, the
rules of your own in their order, then what fake-igd lets in by itself, each switchable.
Checked here, put in by root (deploy/root_fw.py) ON TRIAL as otp's: unless somebody presses
Keep it within fw_confirm_min minutes, what was there before comes back by itself.

  GET  /api/fw                     the firewall as set, what root found, the trial
  POST /api/fw {action: save | rule_check | read | apply}
  GET  /api/fw/trial               what waits to be kept (the banner on every page)
  POST /api/fw/trial {action: keep | back}
"""
import glob
import ipaddress
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in (HERE, os.path.join(os.path.dirname(HERE), "deploy")):
    if os.path.isfile(os.path.join(_d, "fake_igd_web.py")) and _d not in sys.path:
        sys.path.append(_d)
import fake_igd_web as W     # noqa: E402 - the same checks and the same rules as root's (pure functions)

NAME = "fw"
OPTIONAL = W.FW_OPTIONAL

SETTINGS = [
    {"key": "fw_confirm_min", "name": "A firewall change goes back unless kept within (min)", "kind": "int",
     "default": 5, "min": 0, "max": 120, "pane": "web",
     "says": "A change of the firewall or of who may reach the pages is put in - and what was there before "
             "comes back by itself unless somebody presses Keep it within these minutes: a rule that shuts SSH "
             "or the pages out does not stay. 0: kept at once."},
]
WEB_PROXY_ON = ("web_proxy", "true")


def _nets_bad(x):
    try:
        ipaddress.ip_network(str(x).strip(), strict=False)
    except ValueError:
        return "%r is not an address or a network" % str(x)[:60]
    return ""


def _header_bad(x):
    x = str(x or "").strip()
    if not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,63}\Z", x) or x.lower() in ("host", "cookie", "authorization"):
        return "a header's name: X-Forwarded-For, X-Real-IP, True-Client-IP…"
    return ""


# Behind a load balancer or WAF (otp's web_proxy*, its second section of this pane's settings).
SETTINGS += [
    {"key": "web_proxy", "name": "Behind a load balancer or WAF", "kind": "bool", "default": False, "pane": "web",
     "root": True,
     "says": "The pages published through a load balancer or a WAF (NetScaler, F5, HAProxy...): nginx takes the "
             "client's own address from the header below - only when the request comes from one of the addresses "
             "below, never from anybody else - so that the sign-in pause, who may reach the pages and every log "
             "see the client and not the balancer. Off: nginx as until now."},
    {"key": "web_proxy_from", "name": "The load balancers and WAFs", "kind": "list", "default": [], "pane": "web",
     "only_when": WEB_PROXY_ON, "check": _nets_bad, "root": True,
     "says": "Their addresses or networks, as nginx sees them come in - one or more, separated by spaces. Needed "
             "to switch it on: the header of anybody else is never believed."},
    {"key": "web_proxy_header", "name": "The header with the client's address", "kind": "text",
     "default": "X-Forwarded-For", "pane": "web", "only_when": WEB_PROXY_ON, "check": _header_bad, "root": True,
     "says": "Where the balancer puts the client's address: X-Forwarded-For (the usual), X-Real-IP, "
             "True-Client-IP, X-Client-IP, CF-Connecting-IP..."},
    {"key": "web_proxy_recursive", "name": "Through more than one of them", "kind": "bool", "default": True,
     "pane": "web", "only_when": WEB_PROXY_ON, "root": True,
     "says": "On: in a chain (a WAF in front of a balancer), the last address in the header that is not one of "
             "them is taken. Off: the last one, whoever put it there."},
]
LAST_EXPIRE = [0.0]


def cfg_path():
    main = sys.modules.get("__main__")
    return getattr(main, "CFG_PATH", None) or os.environ.get("FAKE_IGD_CONFIG") or "/etc/fake-igd/config.json"


def rules_path():
    return os.environ.get("FAKE_IGD_FW_RULES") or os.path.join(os.path.dirname(cfg_path()), "firewall-rules.json")


def trial_path():
    return os.environ.get("FAKE_IGD_FW_TRIAL") or os.path.join(os.path.dirname(cfg_path()), "firewall-trial.json")


def trial_read():
    try:
        with open(trial_path(), encoding="utf-8") as f:
            t = json.load(f)
        return t if isinstance(t, dict) else {}
    except (OSError, ValueError):
        return {}


def pending(t):
    return bool(t) and not t.get("done") and bool(re.match(r"^[0-9a-f]{12}\Z", str(t.get("id") or "")))


def checked(fn, *a):
    try:
        return fn(*a)
    except W.Refused as e:
        raise ValueError(str(e))


def queued(ctx):
    """The newest ask of this pane root has not taken yet (its payload), or None."""
    folder = os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web", "ask")
    for path in sorted(glob.glob(os.path.join(folder, "fw-*.json")), reverse=True):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return None


def legacy_result(ctx):
    try:
        with open(os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web", "result.json"),
                  encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def conf_now(cfg, conf):
    off = [k for k in conf.get("off") or []]
    if not W.flag(cfg.get("firewall_ssh"), True):
        off.append("ssh")
    if not W.flag(cfg.get("firewall_icmp"), True):
        off.append("icmp")
    return {"on": W.flag(cfg.get("firewall"), False), "off": [k for k in OPTIONAL if k in off],
            "rules": conf.get("rules") or [], "at": conf.get("at"), "by": conf.get("by")}


def fw_get(ctx):
    ctx.need("readonly")
    cfg = dict(ctx.cfg)
    conf = W.load_fw_conf(rules_path())
    c = conf_now(cfg, conf)
    allow = cfg.get("web_allow", W.DEFAULT_ALLOW)
    allow = allow if isinstance(allow, list) else []
    health = W.health_of(cfg)
    access = {"admin": {"any": not allow, "from": [str(x) for x in allow]},
              "health": {"any": not health, "from": [str(x) for x in health]},
              "health_set": isinstance(cfg.get("health_allow"), list)}
    # A save root has not taken yet is shown as what is being put in, not what was there.
    waiting = queued(ctx)
    pay = (waiting or {}).get("payload") or {}
    if pay.get("action") == "save":
        c.update(on=bool(pay.get("on")), off=[k for k in OPTIONAL if k in (pay.get("off") or [])],
                 rules=pay.get("rules") or [])
        conf = {"rules": c["rules"], "off": c["off"]}
        if isinstance(pay.get("access"), dict):
            for key, ck in (("admin", "web_allow"), ("health", "health_allow")):
                one = pay["access"].get(key)
                if isinstance(one, dict):
                    access[key] = {"any": bool(one.get("any")), "from": list(one.get("from") or [])}
                    cfg[ck] = [] if access[key]["any"] else access[key]["from"]
    cfg["firewall_ssh"] = "ssh" not in c["off"]
    cfg["firewall_icmp"] = "icmp" not in c["off"]
    pages_here = os.path.isfile(W.NGINX_CONF)
    auto = []
    for it in W.builtin(cfg, {"rules": [], "off": [k for k in c["off"] if k in W.FW_OFF_KEYS]}, pages_here):
        auto.append({k: it.get(k) for k in ("key", "title", "why", "fixed", "on", "rules", "skip")})
    res, old = ctx.root_result(), legacy_result(ctx)
    last = res if float(res.get("at") or 0) >= float(old.get("at") or 0) else old
    fw = {}
    for r in (old, res):                         # the newest that read the firewall
        if isinstance(r.get("firewall"), dict) and float(r.get("at") or 0) >= float(fw.get("_at") or 0):
            fw = dict(r["firewall"], _at=r.get("at"))
    may = (ctx.me or {}).get("role") == "fulladmin"
    t = trial_read()
    return {"may": may, "conf": c, "access": access, "auto": auto, "pages_here": pages_here,
            "fw": fw if may else {k: fw.get(k) for k in ("backend", "iptables", "ip6tables", "chain", "chain6")},
            "root": {k: last.get(k) for k in ("at", "ok", "said", "by", "kind")},
            "waiting": bool(waiting), "confirm_min": ctx.setting("fw_confirm_min"),
            "trial": trial_view(t), "allow_default": W.DEFAULT_ALLOW}


def fw_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    if act == "rule_check":
        return {"rule": checked(W.fw_rule_checked, b.get("rule"))}
    if act == "read":
        ident = ctx.ask_root({"action": "read"})
        return {"id": ident, "message": "root reads the firewall again - a moment"}
    if act == "apply":
        ident = ctx.ask_root({"action": "apply"})
        ctx.event("%s asked root to put the firewall and access in place again" % me["name"])
        return {"id": ident, "message": "asked root - a moment"}
    if act != "save":
        raise ValueError("no such action")
    if not isinstance(b.get("on"), bool):
        raise ValueError("the firewall is on or off")
    off = [k for k in OPTIONAL if k in [str(x) for x in (b.get("off") or [])]]
    rules = checked(W.fw_rules_checked, b.get("rules") if b.get("rules") is not None else [])
    pay = {"action": "save", "on": b["on"], "off": off, "rules": rules}
    words = ["the firewall %s" % ("on" if b["on"] else "off"), "%d rule(s) of your own" % len(rules)]
    if off:
        words.append("switched off: %s" % ", ".join(off))
    if b.get("access") is not None:
        acc = b["access"] if isinstance(b["access"], dict) else {}
        rows = {"admin": acc} if "any" in acc else acc
        pay["access"] = {}
        for key, what in (("admin", "the pages"), ("health", "the health check")):
            one = rows.get(key)
            if one is None:
                continue
            one = one if isinstance(one, dict) else {}
            nets = []
            raw = one.get("from") or []
            if isinstance(raw, str):
                raw = re.split(r"[\s,;]+", raw)
            for x in (raw if isinstance(raw, list) else [])[:200]:
                x = str(x).strip()
                if not x:
                    continue
                try:
                    nn = str(ipaddress.ip_network(x, strict=False))
                except ValueError:
                    raise ValueError("Who may reach %s: %s is not an address or a network" % (what, x[:60]))
                if nn not in nets:
                    nets.append(nn)
            if one.get("any") is not True and not nets:
                raise ValueError("%s would be for nobody: give a network, or let everybody in" % what)
            pay["access"][key] = {"any": one.get("any") is True, "from": [] if one.get("any") is True else nets}
            words.append("%s from %s" % (what, "everybody" if one.get("any") is True else ", ".join(nets)))
    n = int(ctx.setting("fw_confirm_min") or 0)
    pay["trial_min"] = n
    ident = ctx.ask_root(pay)
    ctx.event("%s changed the firewall and access: %s%s" % (me["name"], "; ".join(words),
                                                           " - on trial for %d min" % n if n else ""), "warn")
    return {"id": ident, "message": "saved - root puts it in place in a moment" +
            ("; it goes back by itself unless kept within %d min" % n if n else "")}


def _words(v):
    return ", ".join(str(x) for x in v) if isinstance(v, list) else str(v or "")


def on_saved(ctx, changed):
    """Behind a load balancer or WAF changed: root puts nginx's real_ip lines in (read from the database)."""
    if any(k.startswith("web_proxy") for k in changed):
        ctx.ask_root({"action": "realip"})
        on = ctx.setting("web_proxy")
        ctx.event("behind a load balancer or WAF: %s - root puts nginx's real_ip lines in" % (
            "on, the client's address from %s when it comes from %s" % (
                ctx.setting("web_proxy_header") or "X-Forwarded-For", _words(ctx.setting("web_proxy_from")) or "nobody yet")
            if on else "off"), "warn" if on else "info")


# ---- the trial (the banner on every page) --------------------------------------------
def trial_view(t):
    if not pending(t):
        return None
    return {"kind": "fw", "node": "", "id": t["id"], "until": float(t.get("until") or 0),
            "by": t.get("last_by") or t.get("by"), "at": t.get("at"), "min": t.get("min"),
            "words": "the change of the firewall and access"}


def trial_get(ctx):
    ctx.need("readonly")
    v = trial_view(trial_read())
    return {"trials": [v] if v else [], "now": time.time()}


def trial_post(ctx):
    me = ctx.need("fulladmin")
    act = str(ctx.body().get("action") or "")
    t = trial_read()
    if act not in ("keep", "back"):
        raise ValueError("keep or back")
    if not pending(t):
        raise ValueError("no change of the firewall waits to be kept")
    if act == "keep" and time.time() > float(t.get("until") or 0):
        raise ValueError("the time to keep it is over - it is being put back; make the change again if it is wanted")
    ident = ctx.ask_root({"action": act, "id": t["id"]})
    if act == "keep":
        ctx.event("%s kept the change of the firewall and access" % me["name"])
        return {"id": ident, "message": "kept"}
    ctx.event("%s put the firewall and access back to what they were before" % me["name"], "warn")
    return {"id": ident, "message": "what was there before comes back in a moment"}


def background(ctx):
    """The timer lost (a reboot, no systemd-run): the put-back asked for here, once a minute at most."""
    t = trial_read()
    if pending(t) and time.time() > float(t.get("until") or 0) + 20 and time.time() - LAST_EXPIRE[0] > 55:
        LAST_EXPIRE[0] = time.time()
        ctx.ask_root({"action": "expire", "id": t["id"]})
        ctx.event("the change of the firewall and access was not kept in time - root puts back what was there "
                  "before", "warn")


ROUTES = {
    ("GET", "/api/fw"): fw_get,
    ("POST", "/api/fw"): fw_post,
    ("GET", "/api/fw/trial"): trial_get,
    ("POST", "/api/fw/trial"): trial_post,
}
