"""api_shell.py - what the shell of the pages asks (1.6.1): otp's header, tabs and account popup.

Not a pane of Settings: the routes the header, the tabs and "Your account" need, as otp's
daemon answers them. Some of them take the place of the API's own (fake_igd_api.py) - a route
of a module is asked first - and give the same answer with what otp's pages read besides:

  GET  /api/auth/whoami         who is signed in (PUBLIC): + prefs, cols, cols_edit, source
  POST /api/auth/prefs          {hload, hpanel}: the looks of the load meter, kept with the account
  POST /api/auth/columns        {edit: bool} this sign-in edits the columns, or {cols, reset}
  GET  /api/auth/settings       one's own settings, for the file of Export my settings
  POST /api/auth/settings       {settings: {columns, prefs}} - Import settings
  GET  /api/status              the API's status + perf_meter, trials, uptime
  GET  /api/health              (PUBLIC) the API's health + whether fake-igd.service runs
  GET  /api/overview            the chart and the facets of Overview, each with when it was last
  GET  /api/requests            the requests: otp's search language (field:value), paged
  GET  /api/request?at=&client= one request: every field, the steps, what the log said then
  GET  /api/ports               the ports asked for: the search language, paged
  GET  /api/clients             the clients: the search language, paged
  GET  /api/events              the events: the search language, paged, the kinds
  GET  /api/suggest?list=&field=&typed=   what a search box offers (otp's qSuggest)
  GET  /api/settings            the API's settings, each with where it is kept and its command line

The search language (otp's ListQuery, worked out over rows here, not in SQL): words anywhere;
field:value (* a wildcard, a,b any of them), field~part (contains), field:>N / field:<N,
-field:value or !field:value (not), NOT, OR, AND, ( ).
"""
import collections
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime

import igd_panes as PN
import upnp as U

NAME = "shell"

SETTINGS = []          # perf_meter, the load meter's switch, is api_about.py's (with /api/load)


# ---- the API itself (fake_igd_api.py runs as __main__) ------------------------------------
def _api():
    for name in ("__main__", "fake_igd_api"):
        m = sys.modules.get(name)
        if m is not None and hasattr(m, "status_view") and hasattr(m, "load_cfg"):
            return m
    raise RuntimeError("the API's own module is not loaded")


def _cfg():
    return _api().load_cfg()


def _token_of(ctx):
    h = ctx.handler
    tok = (h.headers.get("X-IGD-Session") or "") if h is not None else ""
    return hashlib.sha256(tok.encode()).hexdigest() if tok else ""


def _refused(status, words, code=""):
    A = _api()
    return A.Refused(status, words, code)


# ---- an account's own: the looks of the meter and the columns of the tables -------------------
LOOKS = ("graphs", "pills", "line", "rings", "off")
PANELS = ("tiles", "table", "map", "wide", "off")
COLS_EDIT = {}                     # sha256 of a session's token -> True, for that sign-in only
COLS_MOST = 256 * 1024


def _mine_key(name):
    return "user:%s:own" % str(name).lower()


def _mine(store, name):
    try:
        got = json.loads(store.get_meta(_mine_key(name)) or "{}")
    except ValueError:
        got = {}
    if not isinstance(got, dict):
        got = {}
    got.setdefault("prefs", {})
    got.setdefault("cols", {})
    return got


def _mine_put(store, name, got):
    store.set_meta(_mine_key(name), json.dumps(got, separators=(",", ":")))


def cols_sane(all_):
    """A layout as the page can use it (otp's colsSane): whatever is not one is left out."""
    out = {}
    if not isinstance(all_, dict):
        return out
    for k, one in list(all_.items())[:400]:
        if not isinstance(k, str) or len(k) > 400 or not isinstance(one, dict):
            continue
        got = {}
        for f in ("o", "h", "s", "v"):
            if isinstance(one.get(f), list):
                seen, lst = set(), []
                for x in one[f][:100]:
                    if isinstance(x, str) and x and len(x) <= 80 and x not in seen:
                        seen.add(x)
                        lst.append(x)
                if lst:
                    got[f] = lst
        if isinstance(one.get("w"), dict):
            w = {}
            for ck, n in list(one["w"].items())[:100]:
                try:
                    n = float(n)
                except (TypeError, ValueError):
                    continue
                if isinstance(ck, str) and len(ck) <= 80 and n > 0:
                    w[ck] = int(min(5000, max(24, round(n))))
            if w:
                got["w"] = w
        try:
            got["t"] = float(one.get("t"))
        except (TypeError, ValueError):
            pass
        if got:
            out[k] = got
    return out


def prefs_sane(p):
    out = {}
    if not isinstance(p, dict):
        return out
    if p.get("hload") in LOOKS:
        out["hload"] = p["hload"]
    if p.get("hpanel") in PANELS:
        out["hpanel"] = p["hpanel"]
    return out


def _other_whoami(ctx):
    """Another module's whoami (Accounts may answer it): asked first, then added to."""
    for m in PN.MODULES:
        if m is sys.modules.get(__name__) or getattr(m, "NAME", "") == NAME:
            continue
        fn = (getattr(m, "ROUTES", {}) or {}).get(("GET", "/api/auth/whoami"))
        if fn:
            sub = PN.Ctx(ctx.handler, ctx.method, ctx.path, ctx.q, None, ctx.store, ctx.cfg, m, ctx.store.add_event)
            return fn(sub)
    return None


def whoami(ctx):
    got = _other_whoami(ctx)
    who = None
    if isinstance(got, dict):
        who = got.get("who")
    else:
        try:
            u = ctx.handler.who()
        except Exception:                               # noqa: BLE001 - not signed in
            u = None
        if u:
            import igd_store as ST
            who = {"name": u["name"], "role": u["role"], "role_words": ST.ROLE_WORDS.get(u["role"]),
                   "must_change": bool(u.get("must_change")), "note": u.get("note") or ""}
        got = {"ok": True, "who": who}
    if isinstance(who, dict) and who.get("name"):
        mine = _mine(ctx.store, who["name"])
        who.setdefault("source", "local")
        who["prefs"] = prefs_sane(mine.get("prefs"))
        who["cols"] = cols_sane(mine.get("cols"))
        who["cols_edit"] = bool(COLS_EDIT.get(_token_of(ctx)))
    return got


whoami.PUBLIC = True


def post_prefs(ctx):
    me = ctx.need("readonly")
    b = ctx.body()
    mine = _mine(ctx.store, me["name"])
    p = dict(mine.get("prefs") or {})
    for k, allowed in (("hload", LOOKS), ("hpanel", PANELS)):
        if k in b:
            if b[k] not in allowed:
                raise ValueError("%s: not one of %s" % (k, ", ".join(allowed)))
            p[k] = b[k]
    mine["prefs"] = prefs_sane(p)
    _mine_put(ctx.store, me["name"], mine)
    return {"prefs": mine["prefs"], "message": "kept"}


def post_columns(ctx):
    me = ctx.need("readonly")
    b = ctx.body(COLS_MOST + 4096)
    if "edit" in b:
        on = b.get("edit") is True
        tok = _token_of(ctx)
        if on:
            COLS_EDIT[tok] = True
        else:
            COLS_EDIT.pop(tok, None)
        return {"edit": on}
    if b.get("reset"):
        mine = _mine(ctx.store, me["name"])
        mine["cols"] = {}
        _mine_put(ctx.store, me["name"], mine)
        ctx.event("%s put the columns of every table back as they come" % me["name"], kind="account")
        return {"cols": {}, "message": "every table is back as it comes"}
    if not COLS_EDIT.get(_token_of(ctx)):
        raise ValueError("Edit the columns is off for this sign-in - switch it on under your name first")
    cols = cols_sane(b.get("cols"))
    if len(json.dumps(cols)) > COLS_MOST:
        raise ValueError("that is more columns than any page has")
    mine = _mine(ctx.store, me["name"])
    mine["cols"] = cols
    _mine_put(ctx.store, me["name"], mine)
    return {"cols": cols}


def get_my_settings(ctx):
    me = ctx.need("readonly")
    mine = _mine(ctx.store, me["name"])
    return {"name": me["name"], "version": U.VERSION,
            "settings": {"columns": cols_sane(mine.get("cols")), "prefs": prefs_sane(mine.get("prefs"))}}


def post_my_settings(ctx):
    me = ctx.need("readonly")
    b = ctx.body(2 * 1024 * 1024)
    s = b.get("settings")
    if not isinstance(s, dict):
        raise ValueError("that is not a settings file")
    mine = _mine(ctx.store, me["name"])
    took, ignored = {}, []
    for k, v in s.items():
        if k == "columns":
            mine["cols"] = cols_sane(v)
            took["columns"] = len(mine["cols"])
        elif k == "prefs":
            p = prefs_sane(v)
            mine["prefs"] = dict(mine.get("prefs") or {}, **p)
            took["prefs"] = len(p)
        else:
            ignored.append(str(k)[:40])
    _mine_put(ctx.store, me["name"], mine)
    ctx.event("%s read their own settings from a file: the columns of %d table(s)" % (
        me["name"], took.get("columns", 0)), kind="account")
    return {"took": took, "ignored": ignored[:20], "message": "imported"}


def node_name():
    import socket
    return socket.gethostname().split(".")[0]


# ---- the header: the status, with otp's additions ------------------------------------------
def _trials(cfg):
    """A change on trial that the header's banner shows (the network's; the firewall's banner is the
    Firewall pane's own)."""
    out = []
    try:
        with open(os.path.join(cfg.get("state_dir") or "/var/lib/fake-igd", "web", "net-trial.json")) as f:
            t = json.load(f)
        if isinstance(t, dict) and t.get("state") == "trial" and t.get("until"):
            out.append({"kind": "net", "node": str(t.get("con") or t.get("dev") or node_name())[:80],
                        "until": float(t["until"])})
    except (OSError, ValueError, TypeError):
        pass
    return out


def _read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _uptime():
    try:
        return float(_read("/proc/uptime", "0").split()[0])
    except ValueError:
        return 0.0


def get_status(ctx):
    A = _api()
    s = dict(A.status_view())
    cfg = A.load_cfg()
    try:
        s["perf_meter"] = bool(PN.value(ctx.store, "perf_meter"))     # api_about.py's setting
    except KeyError:
        s["perf_meter"] = False
    s["trials"] = _trials(cfg)
    s["started"] = A.STARTED
    s["api_uptime"] = time.time() - A.STARTED
    s["uptime"] = _uptime()
    s["host"] = node_name()
    s["now"] = time.time()
    # When fake-igd.service started, as a time (the Overview card says "up 1 h 35 min", as otp's).
    sv = s.get("service")
    if isinstance(sv, dict) and sv.get("since") and "since_at" not in sv:
        parts = str(sv["since"]).split()
        for take in (parts[1:3], parts[0:2]):
            try:
                sv["since_at"] = time.mktime(time.strptime(" ".join(take), "%Y-%m-%d %H:%M:%S"))
                break
            except (ValueError, OverflowError):
                continue
    return s


def get_health(ctx):
    S = ctx.store
    out = {"ok": True, "version": U.VERSION, "users": S.count_users(), "database": {"ok": S.ok()},
           "site": (ctx.cfg or {}).get("site_name") or "", "node": node_name()}
    if ctx.arg("check") == "service":
        try:
            out["service"] = U.service_info().get("ActiveState", "unknown")
        except Exception:                               # noqa: BLE001
            out["service"] = "unknown"
    return out


get_health.PUBLIC = True


# ---- the search language (otp's ListQuery, over rows) -----------------------------------
LIST_TOKEN = re.compile(r'\s*((?:[-!]?[A-Za-z_]+(?::|~)(?:"[^"]*"?|[^\s()]*))|"[^"]*"?|\(|\)|[^\s()]+)')
LIST_TERM = re.compile(r'^([-!]?)([A-Za-z_]+)(:|~)(.*)$', re.S)

LIST_FIELDS = {
    "requests": [("client", "the address that asked", "client:192.168.1.*"),
                 ("name", "its name (PTR)", "name:ps5*"),
                 ("action", "the SOAP action", "action:AddPortMapping"),
                 ("proto", "TCP or UDP", "proto:udp"),
                 ("port", "the external port", "port:3478,3479"),
                 ("to", "the address and port it wanted it sent to", "to:192.168.1.20*"),
                 ("result", "what fake-igd answered: ok, rejected, conflict…", "result:rejected"),
                 ("desc", "what it said it was for", "desc~party"),
                 ("lease", "the lease asked for, in seconds", "lease:>0")],
    "ports": [("client", "the address the port is for", "client:192.168.1.*"),
              ("name", "its name (PTR)", "name:ps5*"),
              ("proto", "TCP or UDP", "proto:udp"),
              ("port", "the port", "port:>49000"),
              ("asked", "how many times it was asked for", "asked:>5"),
              ("result", "what fake-igd answered", "result:rejected"),
              ("desc", "what it said it was for", "desc~remote")],
    "clients": [("client", "the address", "client:192.168.1.*"),
                ("name", "its name (PTR)", "name:ps5*"),
                ("agent", "what it says it is (SSDP's user agent)", "agent~PS5"),
                ("port", "a port it asked for", "port:3478"),
                ("searches", "how many SSDP searches", "searches:>10"),
                ("requests", "how many SOAP requests", "requests:0")],
    "events": [("kind", "the kind of event", "kind:sign-in"),
               ("who", "who did it", "who:admin"),
               ("what", "what it says", "what~password"),
               ("level", "info or warn", "level:warn"),
               ("from", "the address it was done from", "from:10.0.*")],
    # Outgoing mail (round 3): read by igd_mail.listing itself - only offered here, as otp's mailq box.
    "mailq": [("to", "the address it goes to", "to:*@example.cz"),
              ("state", "waiting, sending, sent, failed or expired", "state:waiting"),
              ("kind", "alert, report or test", "kind:alert")],
}


def _vals(row, fn):
    v = fn(row)
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if x is not None and str(x) != ""]
    v = str(v)
    return [v] if v != "" else []


class Query(object):
    """pred(row) -> bool, for one list; ValueError with words when it does not read."""

    def __init__(self, getters, text):
        self.get = getters
        self.text = str(text or "").strip()
        if len(self.text) > 2000:
            raise ValueError("that search is too long - 2000 characters at most")
        self.tokens = [m.group(1) for m in LIST_TOKEN.finditer(self.text) if m.group(1)]
        if len(self.tokens) > 300:
            raise ValueError("that search has too many parts")
        if sum(1 for t in self.tokens if t in ("NOT", "!", "(")) > 40:
            raise ValueError("that search has too many NOTs and brackets in it")
        self.at = 0
        self.pred = self._or() if self.tokens else (lambda r: True)
        if self.at < len(self.tokens):
            raise ValueError("a closing bracket with nothing open before it")

    def _peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def _or(self):
        parts = [self._and()]
        while self._peek() in ("OR", "|", "||"):
            self.at += 1
            if self._peek() in (None, ")"):
                raise ValueError("OR with nothing after it")
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda r, p=parts: any(f(r) for f in p))

    def _and(self):
        parts = [self._not()]
        while self._peek() not in (None, ")", "OR", "|", "||"):
            if self._peek() in ("AND", "&", "&&"):
                self.at += 1
                continue
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda r, p=parts: all(f(r) for f in p))

    def _not(self):
        t = self._peek()
        if t in ("NOT", "!"):
            self.at += 1
            if self._peek() is None:
                raise ValueError("NOT, ! or a bracket with nothing after it")
            inner = self._not()
            return lambda r: not inner(r)
        if t == "(":
            self.at += 1
            if self._peek() is None:
                raise ValueError("NOT, ! or a bracket with nothing after it")
            inner = self._or()
            if self._peek() != ")":
                raise ValueError("a bracket opened and never closed")
            self.at += 1
            return inner
        if t == ")":
            raise ValueError("a closing bracket with nothing open before it")
        self.at += 1
        return self._leaf(t)

    def _leaf(self, token):
        m = LIST_TERM.match(token)
        if m and m.group(2).lower() in self.get:
            lead, name, op, value = m.groups()
            fn = self.get[name.lower()]
            value = value.strip('"')
            neg = bool(lead)
            if value == "":
                return lambda r: True
            if op == "~":
                want = value.lower().replace("*", "")
                test = lambda r: any(want in v.lower() for v in _vals(r, fn))      # noqa: E731
            elif re.match(r"^(>=|<=|>|<)\s*-?\d+(\.\d+)?$", value):
                cmp, num = re.match(r"^(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)$", value).groups()
                num = float(num)

                def test(r, cmp=cmp, num=num):
                    for v in _vals(r, fn):
                        try:
                            x = float(v)
                        except ValueError:
                            continue
                        if (cmp == ">" and x > num) or (cmp == "<" and x < num) or \
                                (cmp == ">=" and x >= num) or (cmp == "<=" and x <= num):
                            return True
                    return False
            elif value == "*":
                test = lambda r: bool(_vals(r, fn))                                # noqa: E731
            else:
                pats = [p.strip().lower() for p in value.split(",") if p.strip()]
                test = lambda r: any(fnmatch.fnmatchcase(v.lower(), p) for v in _vals(r, fn) for p in pats)  # noqa
            return (lambda r: not test(r)) if neg else test
        lead = token[:1] if token[:1] in "-!" and len(token) > 1 else ""
        word = token[len(lead):].strip('"').lower()
        if not word:
            return lambda r: True
        test = lambda r: word in r.get("_text", "")                                # noqa: E731
        return (lambda r: not test(r)) if lead else test


def run_query(listname, rows, text):
    """(rows that match, error words)."""
    getters = {k: GETTERS[listname][k] for k, _s, _e in LIST_FIELDS[listname]}
    try:
        q = Query(getters, text)
    except ValueError as e:
        return [], str(e)
    for r in rows:
        if "_text" not in r:
            r["_text"] = json.dumps(r, ensure_ascii=False, default=str).lower()
    return [r for r in rows if q.pred(r)], ""


def _proto(r):
    return str(r.get("protocol") or r.get("proto") or "").upper()


GETTERS = {
    "requests": {"client": lambda r: r.get("client"), "name": lambda r: r.get("name"),
                 "action": lambda r: r.get("action"), "proto": _proto,
                 "port": lambda r: r.get("external_port"),
                 "to": lambda r: ("%s:%s" % (r.get("internal_client"), r.get("internal_port") or "")
                                  if r.get("internal_client") else None),
                 "result": lambda r: r.get("result"), "desc": lambda r: r.get("description"),
                 "lease": lambda r: r.get("lease")},
    "ports": {"client": lambda r: r.get("client"), "name": lambda r: r.get("name"), "proto": _proto,
              "port": lambda r: r.get("port"), "asked": lambda r: r.get("count"),
              "result": lambda r: list((r.get("results") or {}).keys()), "desc": lambda r: r.get("description")},
    "clients": {"client": lambda r: r.get("client"), "name": lambda r: r.get("name"),
                "agent": lambda r: r.get("user_agent"), "port": lambda r: [p.split("/")[0] for p in r.get("ports") or []],
                "searches": lambda r: r.get("searches"), "requests": lambda r: r.get("requests")},
    "events": {"kind": lambda r: r.get("kind"), "who": lambda r: r.get("who"), "what": lambda r: r.get("words"),
               "level": lambda r: r.get("level"), "from": lambda r: r.get("addr")},
    "mailq": {"to": lambda r: r.get("to"), "state": lambda r: r.get("state"), "kind": lambda r: r.get("kind")},
}


def _page(ctx, default_per=100):
    try:
        page = max(0, int(ctx.arg("page", "0") or 0))
        per = max(10, min(1000, int(ctx.arg("per", str(default_per)) or default_per)))
    except ValueError:
        page, per = 0, default_per
    return page, per


def _strip(rows):
    for r in rows:
        r.pop("_text", None)
    return rows


# ---- the lists of the tabs -------------------------------------------------------------------
def _events_window(ctx, default_s=None):
    A = _api()
    since, until = A.window(ctx.q, default_s)
    cfg = A.load_cfg()
    ev = A.before(A.guarded(U.read_events, cfg, since), until)
    return ev, since, until, cfg


def _names(ips):
    try:
        return U.ptr_names([x for x in ips if x]) if not U.NO_DNS else {}
    except Exception:                                   # noqa: BLE001
        return {}


def _epoch(dt):
    return dt.timestamp() if dt else None


def get_overview(ctx):
    A = _api()
    ev, since, until, cfg = _events_window(ctx, 86400)
    end = until.timestamp() if until else time.time()
    if since is None:
        first = min((e["_t"].timestamp() for e in ev if e.get("_t")), default=end - 86400)
        start = first
    else:
        start = since.timestamp()
    hours = max(1.0, (end - start) / 3600.0)
    step = 3600 if hours <= 72 else (6 * 3600 if hours <= 24 * 14 else 86400)
    buckets = collections.OrderedDict()
    t = start - (start % step)
    while t <= end:
        buckets[int(t)] = {"t": int(t), "at": int(t), "accepted": 0, "rejected": 0, "other": 0}
        t += step
    facets = {k: {} for k in ("ports", "clients", "actions", "results")}

    def count(kind, key, at, extra=None):
        one = facets[kind].get(key)
        if one is None:
            one = facets[kind][key] = {"said": key, "n": 0, "last": 0}
            one.update(extra or {})
        one["n"] += 1
        one["last"] = max(one["last"], at or 0)
    for e in ev:
        x = A.ts(e.get("_t"))
        if x is None:
            continue
        act = e.get("action") or "?"
        count("actions", act, x)
        count("clients", e.get("client") or "?", x, {"client": e.get("client") or ""})
        if act == "AddPortMapping":
            res = str(e.get("result") or "ok")
            proto = str(e.get("protocol") or "").upper()
            count("ports", "%s %s" % (e.get("external_port"), proto), x,
                  {"port": e.get("external_port"), "proto": proto})
            count("results", res, x)
            kind = "rejected" if res.startswith(("rej", "err", "fail", "conf")) else "accepted"
        else:
            kind = "other"
        b = buckets.get(int(x - (x % step)))
        if b:
            b[kind] += 1
    searches = 0
    for ln in A.guarded(U.read_log_lines, cfg, 20000) or []:
        if "is looking for a UPnP device" in ln:
            m = U.LOG_RE.match(ln.rstrip("\n"))
            if m:
                t2 = U.parse_time(m.group(1).replace(" ", "T"))
                if t2 and (since is None or t2 >= since) and (until is None or t2 <= until):
                    searches += 1
    top = {k: sorted(v.values(), key=lambda r: (-r["n"], -r["last"]))[:10] for k, v in facets.items()}
    names = _names([r["client"] for r in top["clients"]])
    for r in top["clients"]:
        r["name"] = names.get(r["client"], "")
    accepted = sum(b["accepted"] for b in buckets.values())
    rejected = sum(b["rejected"] for b in buckets.values())
    return {"hours": hours, "step": step, "series": list(buckets.values()), "chart": list(buckets.values()),
            "since": start, "until": end, "requests": len(ev), "add": accepted + rejected,
            "accepted": accepted, "rejected": rejected, "searches": searches,
            "top_ports": top["ports"], "top_clients": top["clients"], "top_actions": top["actions"],
            "top_results": top["results"],
            "ports": [{"port": r["said"], "n": r["n"]} for r in top["ports"]],
            "clients": [{"client": r["client"], "name": r.get("name", ""), "n": r["n"]} for r in top["clients"]],
            "actions": [{"action": r["said"], "n": r["n"]} for r in top["actions"]]}


def _request_rows(ev):
    rows = []
    for i, e in enumerate(ev):
        row = {k: v for k, v in e.items() if not k.startswith("_")}
        row["at"] = _epoch(e.get("_t"))
        rows.append(row)
    rows.sort(key=lambda r: r.get("at") or 0, reverse=True)
    return rows


def get_requests(ctx):
    ev, since, until, cfg = _events_window(ctx, 86400)
    rows = _request_rows(ev)
    actions = sorted({r.get("action") for r in rows if r.get("action")})
    results = sorted({str(r.get("result")) for r in rows if r.get("result")})
    clients = sorted({r.get("client") for r in rows if r.get("client")})
    act, res, cl = ctx.arg("action"), ctx.arg("result"), ctx.arg("client")
    if act:
        rows = [r for r in rows if r.get("action") == act]
    if res == "ports":
        rows = [r for r in rows if r.get("action") == "AddPortMapping"]
    elif res == "accepted":
        rows = [r for r in rows if r.get("action") == "AddPortMapping"
                and not str(r.get("result") or "ok").startswith(("rej", "err", "fail", "conf"))]
    elif res == "refused":
        rows = [r for r in rows if r.get("action") == "AddPortMapping"
                and str(r.get("result") or "ok").startswith(("rej", "err", "fail", "conf"))]
    elif res == "other":
        rows = [r for r in rows if r.get("action") != "AddPortMapping"]
    if cl:
        rows = [r for r in rows if r.get("client") == cl]
    if any(w in (ctx.arg("q") or "") for w in ("name:", "name~")):
        names = _names({r.get("client") for r in rows})
        for r in rows:
            r["name"] = names.get(r.get("client"), "")
    rows, bad = run_query("requests", rows, ctx.arg("q"))
    page, per = _page(ctx)
    out = rows[page * per:(page + 1) * per]
    names = _names({r.get("client") for r in out})
    for r in out:
        r["name"] = names.get(r.get("client"), r.get("name", ""))
    return {"requests": _strip(out), "total": len(rows), "page": page, "per": per,
            "actions": actions, "results": results, "clients": clients, "q_error": bad,
            "since": _epoch(since), "until": _epoch(until)}


def get_request(ctx):
    """One request: every field it carried, the steps of its answer, and what the log said then."""
    try:
        at = float(ctx.arg("at") or 0)
    except ValueError:
        raise ValueError("at: a time")
    client = ctx.arg("client")
    A = _api()
    cfg = A.load_cfg()
    ev = A.guarded(U.read_events, cfg, datetime.fromtimestamp(at - 2).astimezone())
    row = None
    for e in ev:
        t = _epoch(e.get("_t"))
        if t is not None and abs(t - at) < 0.002 and e.get("client") == client and \
                (not ctx.arg("action") or e.get("action") == ctx.arg("action")):
            row = {k: v for k, v in e.items() if not k.startswith("_")}
            row["at"] = t
            break
    if row is None:
        raise ValueError("that request is not in the log any more")
    row["name"] = _names([client]).get(client, "")
    near = []
    for ln in A.guarded(U.read_log_lines, cfg, 20000) or []:
        m = U.LOG_RE.match(ln.rstrip("\n"))
        if not m:
            continue
        t2 = U.parse_time(m.group(1).replace(" ", "T"))
        if t2 is None:
            continue
        if abs(t2.timestamp() - at) <= 2 and (client in m.group(3) or str(row.get("external_port") or "-") in m.group(3)):
            near.append({"at": t2.timestamp(), "level": m.group(2).lower(), "words": m.group(3)})
    before = []
    for ln in A.guarded(U.read_log_lines, cfg, 20000) or []:
        if client + " is looking for a UPnP device" in ln:
            m = U.LOG_RE.match(ln.rstrip("\n"))
            t2 = U.parse_time(m.group(1).replace(" ", "T")) if m else None
            if t2 and t2.timestamp() <= at + 1:
                before.append(t2.timestamp())
    steps = []
    if before:
        steps.append({"ok": True, "what": "It looked for a UPnP router (SSDP M-SEARCH)",
                      "said": "the last time %s before this request" % time.strftime(
                          "%Y-%m-%d %H:%M:%S", time.localtime(max(before)))})
    else:
        steps.append({"ok": True, "what": "It came straight to SOAP",
                      "said": "no SSDP search of this address in the log before it (it knew the address already)"})
    act = row.get("action") or "?"
    asked = act
    if row.get("protocol"):
        asked += " %s %s" % (row.get("protocol"), row.get("external_port"))
        if row.get("internal_client"):
            asked += " → %s:%s" % (row.get("internal_client"), row.get("internal_port") or "")
    steps.append({"ok": True, "what": "It asked: " + asked,
                  "said": ("lease %s s" % row.get("lease") if row.get("lease") not in (None, "") else "")
                  + (" · “%s”" % row.get("description") if row.get("description") else "")})
    res = str(row.get("result") or "")
    if act == "AddPortMapping":
        bad = res.startswith(("rej", "err", "fail", "conf"))
        steps.append({"ok": not bad, "what": "fake-igd answered: " + (res or "ok"),
                      "said": "refused - the client was told the port cannot be had" if bad
                      else "confirmed - the client believes the port is open (nothing is opened on the router)"})
        try:
            with open(os.path.join(cfg["state_dir"], "mappings.json"), encoding="utf-8") as f:
                maps = json.load(f)
            held = [m for m in maps if str(m.get("external_port")) == str(row.get("external_port"))
                    and str(m.get("protocol", "")).upper() == str(row.get("protocol", "")).upper()]
        except (OSError, ValueError, TypeError):
            held = []
        if not bad:
            steps.append({"ok": bool(held), "what": "Held as a mapping now" if held else "Not held now",
                          "said": "in the list of Mappings, with its lease" if held
                          else "its lease ran out, it was deleted, or the service started again"})
    elif res:
        steps.append({"ok": not res.startswith(("rej", "err", "fail", "conf")), "what": "fake-igd answered: " + res,
                      "said": ""})
    else:
        steps.append({"ok": True, "what": "fake-igd answered", "said": "a question, not a change"})
    for n in near:
        if "ntfy" in n["words"] or "notif" in n["words"]:
            steps.append({"ok": n["level"] not in ("error", "warning", "warn"), "what": "A notification",
                          "said": n["words"]})
    return {"row": row, "steps": steps, "log": near, "searches": len(before)}


def get_ports(ctx):
    A = _api()
    since, until = A.window(ctx.q)
    cfg = A.load_cfg()
    ev = A.before(A.guarded(U.read_events, cfg, since), until)
    agg = U.aggregate_ports(ev, ctx.arg("proto") or None)
    names = _names([k[0] for k in agg])
    rows = []
    for (client, proto, port), p in agg.items():
        rows.append({"client": client, "name": names.get(client, ""), "proto": proto, "port": port,
                     "count": p["count"], "first": A.ts(p["first"]), "last": A.ts(p["last"]),
                     "description": ", ".join(sorted(p["desc"])),
                     "internal_port": ", ".join(str(x) for x in sorted(p["internal_port"], key=str) if x),
                     "results": dict(p["results"]), "requested_by": sorted(x for x in p["requested_by"] if x)})
    sort = ctx.arg("sort") or "client"
    if sort == "last":
        rows.sort(key=lambda r: -(r["last"] or 0))
    elif sort == "count":
        rows.sort(key=lambda r: (-r["count"], r["client"]))
    else:
        rows.sort(key=lambda r: (r["client"], r["proto"], r["port"]))
    res = ctx.arg("result")
    if res == "refused":
        rows = [r for r in rows if any(str(k).startswith(("rej", "err", "fail", "conf")) for k in r["results"])]
    elif res == "accepted":
        rows = [r for r in rows if any(not str(k).startswith(("rej", "err", "fail", "conf")) for k in r["results"])]
    rows, bad = run_query("ports", rows, ctx.arg("q"))
    counts = {"ports": len(rows), "clients": len({r["client"] for r in rows}),
              "udp": len([r for r in rows if r["proto"].upper() == "UDP"]),
              "tcp": len([r for r in rows if r["proto"].upper() == "TCP"])}
    page, per = _page(ctx)
    return {"ports": _strip(rows[page * per:(page + 1) * per]), "total": len(rows), "page": page, "per": per,
            "counts": counts, "q_error": bad}


def get_clients(ctx):
    A = _api()
    since, until = A.window(ctx.q)
    rows = A.guarded(U.clients_data, A.load_cfg(), since)
    if until is not None:
        rows = [c for c in rows if not c.get("last") or datetime.fromisoformat(c["last"]) <= until]
    rows, bad = run_query("clients", rows, ctx.arg("q"))
    page, per = _page(ctx)
    return {"clients": _strip(rows[page * per:(page + 1) * per]), "total": len(rows), "page": page, "per": per,
            "q_error": bad}


def get_events(ctx):
    A = _api()
    page, per = _page(ctx)
    since, until = A.window(ctx.q)
    kind = ctx.arg("kind")
    S = ctx.store
    where, args = ["at >= ?"], [since.timestamp() if since else 0.0]
    if until is not None:
        where.append("at <= ?")
        args.append(until.timestamp())
    every = [r["kind"] for r in S.rows("SELECT DISTINCT kind FROM events ORDER BY kind")]
    if kind:
        # otp's group words (sign-ins, starting and stopping, ...): the raw kinds of the group; an old link
        # with a raw kind still filters.
        raw = [k for k in every if A.event_group(k) == kind] or [kind]
        where.append("kind IN (%s)" % ",".join("?" * len(raw)))
        args += raw
    rows = S.rows("SELECT * FROM events WHERE " + " AND ".join(where) + " ORDER BY id DESC LIMIT 20000", args)
    rows, bad = run_query("events", [dict(r) for r in rows], ctx.arg("q"))
    kinds = sorted({A.event_group(k) for k in every})
    out = _strip(rows[page * per:(page + 1) * per])
    for r in out:
        r["ts"] = r.get("at")
        r["kind_raw"], r["kind"] = r.get("kind"), A.event_group(r.get("kind"))
    return {"events": out, "total": len(rows), "kinds": kinds, "page": page, "per": per, "q_error": bad}


def get_suggest(ctx):
    name = ctx.arg("list")
    if name not in LIST_FIELDS:
        raise ValueError("no such list")
    field = ctx.arg("field").lower()
    if not field:
        return {"fields": [list(f) for f in LIST_FIELDS[name]]}
    fn = GETTERS[name].get(field)
    if not fn:
        return {"values": []}
    typed = ctx.arg("typed")[:120].strip("*").lower()
    A = _api()
    if name == "events":
        rows = [dict(r) for r in ctx.store.rows("SELECT * FROM events ORDER BY id DESC LIMIT 5000")]
    elif name == "requests":
        try:
            h = float(ctx.arg("hours") or 0)
        except ValueError:
            h = 0
        sub = dict(ctx.q)
        if h and "since" not in sub:
            sub["since"] = [str(time.time() - h * 3600)]
        since, until = A.window(sub, 90 * 86400)
        rows = _request_rows(A.before(A.guarded(U.read_events, A.load_cfg(), since), until))
        if field == "name":
            names = _names({r.get("client") for r in rows})
            for r in rows:
                r["name"] = names.get(r.get("client"), "")
    elif name == "ports":
        rows = get_ports(ctx)["ports"]
    elif name == "mailq":
        import igd_mail
        rows = igd_mail.listing(ctx.store, "", "", 1000, 0)["rows"]
    else:
        rows = A.guarded(U.clients_data, A.load_cfg(), None)
    got = collections.Counter()
    for r in rows:
        for v in _vals(r, fn):
            if not typed or typed in v.lower():
                got[v] += 1
    return {"values": [{"val": v, "n": n} for v, n in got.most_common(15)]}


def get_settings(ctx):
    """The API's settings, each with where it is kept and its command line (the (i) of each)."""
    me = ctx.need("readonly")
    A = _api()
    d = A.settings_view(full=me.get("role") == "fulladmin")
    d["root"] = A.root_result()
    for s in d.get("settings") or []:
        if s.get("key") in U.DEFAULTS:
            s["kept"] = "config"
            s["cli"] = "sudo upnp config set %s …" % s["key"]
        else:
            s["kept"] = "database"
            s["cli"] = ""
    d["node"] = node_name()
    return d


ROUTES = {
    ("GET", "/api/settings"): get_settings,
    ("GET", "/api/auth/whoami"): whoami,
    ("POST", "/api/auth/prefs"): post_prefs,
    ("POST", "/api/auth/columns"): post_columns,
    ("GET", "/api/auth/settings"): get_my_settings,
    ("POST", "/api/auth/settings"): post_my_settings,
    ("GET", "/api/status"): get_status,
    ("GET", "/api/health"): get_health,
    ("GET", "/api/overview"): get_overview,
    ("GET", "/api/requests"): get_requests,
    ("GET", "/api/request"): get_request,
    ("GET", "/api/ports"): get_ports,
    ("GET", "/api/clients"): get_clients,
    ("GET", "/api/events"): get_events,
    ("GET", "/api/suggest"): get_suggest,
}
