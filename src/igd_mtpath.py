"""igd_mtpath.py - which way does a device go out to the internet through the MikroTik, and as which
public address? (1.9.2)

Nothing of the router is assumed - no "WAN" by name, no address typed in: everything is read from what
the router said (igd_mikrotik.snapshot) and walked as RouterOS walks a new connection from the device to
somewhere on the internet:

  1. its interface        the router's interface whose network holds the device (/ip address), else the
                          one the router's ARP table has it on
  2. VRF                  that interface in an /ip vrf: its routing table
  3. mangle prerouting    first match wins for what ends (passthrough=no, accept, return), the marks set
                          on the way kept: mark-connection, then mark-routing by connection-mark, and so on;
                          a mark-routing gives the routing table (RouterOS 7: the mark IS the table)
  4. /routing rule        in order: src-address, dst-address, routing-mark, interface -> lookup (falls back
                          to main when the table has no route), lookup-only-in-table, drop, unreachable
  5. the route            in that table: the longest prefix holding the destination, then the lowest
                          distance; its gateway to an interface (immediate-gw, gateway%interface, an
                          interface named, the connected network that holds it, recursively)
  6. srcnat               first match wins on the way out (out-interface known now): masquerade (the out
                          interface's address - pref-src, the one on the gateway's network), src-nat
                          (to-addresses), netmap, accept/return (no translation)

The destination is "the internet in general": a public address that is in no list of the router's and in
no rule's address but /0 and the negated private ones. A rule that holds only for some of the traffic -
a protocol, a port, a time, some destinations, a mark this cannot know - is said ("for some of its
traffic only: rule #N ...") and passed, as it would be for most of it. Each step is kept with the rule
that decided it, so the pages can draw the way.
"""
import ipaddress
import re

PROBES = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "93.184.216.34", "151.101.1.69")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                               "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4",
                                               "240.0.0.0/4")]
# matchers that say nothing of a new connection to the internet in general
SOME_TRAFFIC = {"protocol", "dst-port", "src-port", "port", "time", "limit", "dst-limit", "nth", "random",
                "content", "layer7-protocol", "packet-size", "tcp-flags", "icmp-options", "tcp-mss", "dscp",
                "priority", "ttl", "hop-limit", "connection-bytes", "connection-rate", "per-connection-classifier",
                "src-mac-address", "hotspot", "ingress-priority", "psd", "fragment", "connection-limit",
                "connection-type", "p2p", "ipv4-options", "headers", "dst-address-type", "src-address-type",
                "tls-host", "in-bridge-port", "out-bridge-port", "in-bridge-port-list", "out-bridge-port-list"}
QUIET = {".id", "n", "chain", "action", "comment", "disabled", "dynamic", "invalid", "bytes", "packets", "log",
         "log-prefix", "to-addresses", "to-ports", "jump-target", "address-list", "address-list-timeout",
         "new-connection-mark", "new-packet-mark", "new-routing-mark", "passthrough", "new-dscp", "new-priority",
         "new-ttl", "new-mss", "route-dst", "time-left", "hits", "hw-offload", "randomise-ports", "new-hop-limit",
         "sniff-id", "sniff-target", "sniff-target-port", "reject-with"}


def _ip(text):
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None


def _iface_addr(a):
    try:
        return ipaddress.ip_interface(str(a.get("address") or ""))
    except ValueError:
        return None


def _nets(spec):
    """"a", "a/n", "a-b" -> [networks]; [] when it is a name."""
    s = str(spec or "").strip()
    try:
        if "-" in s and "/" not in s:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in s.split("-", 1))
            return list(ipaddress.summarize_address_range(lo, hi))
        return [ipaddress.ip_network(s, strict=False)]
    except ValueError:
        return []


def _is_public(net):
    return not any(net.subnet_of(p) for p in PRIVATE if p.version == net.version)


class Way(object):
    def __init__(self, snap, device):
        self.snap = snap
        self.device = _ip(device)
        self.lists = {}
        for name, entries in ((snap.get("lists") or {}).get("ip") or {}).items():
            nets = []
            for e in entries:
                if not e.get("disabled"):
                    nets.extend(_nets(e.get("address")))
            self.lists[name] = nets
        self.addrs = [(a.get("interface"), _iface_addr(a)) for a in snap.get("addresses4") or []
                      if not a.get("disabled") and _iface_addr(a)]
        self.steps, self.some = [], []
        self.marks = {"routing": "", "connection": "", "packet": ""}
        self.in_if, self.out_if, self.dst = "", "", None
        self.chain_name = ""

    # ---- the destination: a public address no rule or list of the router names (but /0) ----------------
    def pick_probe(self):
        named = []
        for nets in self.lists.values():
            named.extend(n for n in nets if n.prefixlen > 0)
        for t in ("mangle", "nat", "filter"):
            for r in ((self.snap.get("rules") or {}).get("ip") or {}).get(t) or []:
                for k in ("dst-address", "src-address"):
                    named.extend(n for n in _nets(str(r.get(k) or "").lstrip("!")) if n.prefixlen > 0)
        for r in self.snap.get("routes4") or []:
            named.extend(n for n in _nets(r.get("dst")) if n.prefixlen > 0)
        for p in PROBES:
            ip = ipaddress.ip_address(p)
            if not any(ip in n for n in named):
                return ip
        return ipaddress.ip_address(PROBES[0])

    # ---- one matcher, for the device's connection: True / False / "some" ---------------------------------
    def m_one(self, key, value):
        neg = str(value).startswith("!")
        v = str(value)[1:] if neg else str(value)

        def done(r):
            if r == "some":
                return "some"
            return (not r) if neg else r
        if key in SOME_TRAFFIC:
            return "some"
        if key in ("src-address", "dst-address"):
            ip = self.device if key == "src-address" else self.dst
            nets = _nets(v)
            if not nets:
                return "some"
            hit = any(ip in n for n in nets)
            if key == "dst-address" and not hit and not neg:
                return False
            if key == "dst-address" and hit and any(n.prefixlen > 0 and _is_public(n) for n in nets):
                return "some"                      # some public destinations, not the internet in general
            return done(hit)
        if key in ("src-address-list", "dst-address-list"):
            ip = self.device if key == "src-address-list" else self.dst
            nets = self.lists.get(v)
            if nets is None:
                return done(False)
            hit = any(ip in n for n in nets)
            if key == "dst-address-list" and any(n.prefixlen > 0 and _is_public(n) for n in nets):
                # a list of some public destinations: for the internet in general it does not hold - or, negated,
                # it does for most of it
                return "some" if hit else done(False)
            return done(hit)
        if key in ("in-interface", "out-interface"):
            have = self.in_if if key == "in-interface" else self.out_if
            if not have:
                return "some"
            return done(have == v or (v.endswith("*") and have.startswith(v[:-1])))
        if key in ("in-interface-list", "out-interface-list"):
            have = self.in_if if key == "in-interface-list" else self.out_if
            if not have:
                return "some"
            members = (self.snap.get("iflists") or {}).get(v)
            if members is None:
                return done(False)
            return done(have in members)
        if key in ("routing-mark", "connection-mark", "packet-mark"):
            have = self.marks[key.split("-")[0]]
            if v == "no-mark":
                return done(have == "")
            return done(have == v)
        if key == "routing-table":
            return done((self.marks["routing"] or "main") == v)
        if key == "connection-state":
            return done("new" in [x.strip() for x in v.split(",")])
        if key == "connection-nat-state":
            return done(False)
        if key == "ipsec-policy":
            return done(v.partition(",")[2] == "none")
        return "some"

    def m(self, rule):
        """True (it holds), False, or "some" (it holds for some of the traffic only)."""
        res = [self.m_one(k, v) for k, v in rule.items() if k not in QUIET and v not in ("", None)]
        if any(r is False for r in res):
            return False
        if any(r == "some" for r in res):
            return "some"
        return True

    def ref(self, table, r, words):
        return {"table": table, "n": r.get("n"), "id": r.get(".id"), "words": words,
                "comment": r.get("comment") or ""}

    # ---- a chain of mangle or nat walked with jumps; returns the deciding rule and its action -----------
    def walk(self, table, rules, chain, depth=0, seen=None):
        seen = (seen or set()) | {chain}
        if depth > 16:
            return None
        for r in rules:
            if r.get("chain") != chain or r.get("disabled") or r.get("invalid"):
                continue
            hit = self.m(r)
            if hit is False:
                continue
            act = r.get("action") or "accept"
            if hit == "some":
                if act not in ("log", "passthrough", "add-src-to-address-list", "add-dst-to-address-list"):
                    self.some.append(self.ref(table, r, "%s %s #%s holds for some of its traffic only (%s) - "
                                              "passed, as for most of it" % (table, chain, r.get("n"), act)))
                continue
            if act == "jump":
                tgt = r.get("jump-target") or ""
                if tgt in seen:
                    continue
                got = self.walk(table, rules, tgt, depth + 1, seen)
                if got is not None:
                    return got
                continue
            if act == "return":
                return None if depth else ("return", r)
            if act in ("mark-routing", "mark-connection", "mark-packet"):
                k = act.split("-")[1]
                self.marks[k] = str(r.get("new-%s-mark" % k) or "")
                self.steps.append({"stage": table, "rule": self.ref(table, r, "%s %s #%s: %s %s" % (
                    table, chain, r.get("n"), act, self.marks[k]))})
                if str(r.get("passthrough") or "yes").lower() in ("no", "false"):
                    return (act, r)
                continue
            if act in ("log", "passthrough", "add-src-to-address-list", "add-dst-to-address-list", "change-dscp",
                       "change-ttl", "change-mss", "set-priority", "sniff-tzsp", "sniff-pc", "strip-ipv4-options",
                       "clear-df", "change-hop-limit"):
                continue
            return (act, r)
        return None

    # ---- 1-2: its interface, its VRF ----------------------------------------------------------------------
    def interface(self):
        best = None
        for name, a in self.addrs:
            if self.device in a.network and a.ip != self.device:
                if best is None or a.network.prefixlen > best[1].network.prefixlen:
                    best = (name, a)
        if best:
            self.in_if = best[0]
            self.steps.append({"stage": "interface", "words": "on the router's %s (%s)" % (best[0], best[1].network)})
            return
        for a in self.snap.get("arp") or []:
            if a.get("address") == str(self.device) and a.get("interface"):
                self.in_if = a["interface"]
                self.steps.append({"stage": "interface", "words": "on the router's %s (its ARP table)" % self.in_if})
                return

    def vrf(self):
        for v in self.snap.get("vrfs") or []:
            if v.get("disabled"):
                continue
            ifs = [x.strip() for x in str(v.get("interfaces") or "").split(",") if x.strip()]
            if self.in_if and self.in_if in ifs:
                name = str(v.get("name") or "")
                self.marks["routing"] = name
                self.steps.append({"stage": "vrf", "words": "%s is in VRF %s - its routing table" % (self.in_if, name)})
                return name
        return ""

    # ---- 4: /routing rule ---------------------------------------------------------------------------------
    def routing_rules(self):
        for i, r in enumerate(self.snap.get("routing_rules") or []):
            if r.get("disabled") or r.get("inactive"):
                continue
            ok = True
            for key, have in (("src-address", self.device), ("dst-address", self.dst)):
                if r.get(key):
                    nets = _nets(r[key])
                    ok = ok and bool(nets) and any(have in n for n in nets)
            if r.get("routing-mark"):
                ok = ok and (self.marks["routing"] == r["routing-mark"])
            if r.get("interface"):
                ok = ok and (self.in_if == r["interface"])
            if not ok:
                continue
            act = str(r.get("action") or "lookup")
            words = "routing rule #%d: %s%s" % (i, act, (" table " + r["table"]) if r.get("table") else "")
            self.steps.append({"stage": "routing-rule", "rule": {"table": "routing-rule", "n": i, "id": r.get(".id"),
                                                                 "words": words, "comment": r.get("comment") or ""}})
            if act in ("drop", "unreachable"):
                return act, ""
            return act, str(r.get("table") or "main")
        return "", ""

    # ---- 5: the route --------------------------------------------------------------------------------------
    def route(self, table, dst, depth=0):
        cands = []
        for r in self.snap.get("routes4") or []:
            if r.get("disabled") or not r.get("active", True):
                continue
            if str(r.get("table") or "main") != table:
                continue
            nets = _nets(r.get("dst"))
            if nets and dst in nets[0]:
                try:
                    dist = int(r.get("distance") or 1)
                except ValueError:
                    dist = 1
                cands.append((-nets[0].prefixlen, dist, r))
        if not cands:
            return None
        cands.sort(key=lambda c: (c[0], c[1]))
        r = cands[0][2]
        gw, out_if = self.gateway_if(r, depth)
        return {"route": r, "gateway": gw, "out_if": out_if, "ecmp": "," in str(r.get("gateway") or "")}

    def gateway_if(self, r, depth=0):
        im = str(r.get("immediate") or "").split(",")[0]
        gw = str(r.get("gateway") or "").split(",")[0].strip()
        if "%" in im:
            return im.split("%", 1)
        if "%" in gw:
            return gw.split("%", 1)
        ip = _ip(gw)
        if gw and ip is None:
            return "", gw                           # an interface (pppoe-out1, a tunnel)
        if ip is None:
            return "", ""
        for name, a in self.addrs:
            if ip in a.network:
                return gw, name
        if depth < 3:                               # a recursive gateway: how is it reached
            sub = self.route("main", ip, depth + 1)
            if sub:
                return gw, sub["out_if"]
        return gw, ""

    # ---- 6: srcnat -----------------------------------------------------------------------------------------
    def masq_addr(self, route):
        pref = _ip((route or {}).get("route", {}).get("pref-src") or "")
        mine = [a for n, a in self.addrs if n == self.out_if]
        if pref and any(a.ip == pref for a in mine):
            return pref
        gw = _ip((route or {}).get("gateway") or "")
        for a in mine:
            if gw and gw in a.network:
                return a.ip
        return mine[0].ip if mine else None


def device_way(snap, device):
    """The way of a device out to the internet: {device, in_if, table, out_if, gateway, public, nat, steps,
    some, trouble, ok}. public: the address the internet sees (None when it cannot be told)."""
    w = Way(snap, device)
    out = {"device": str(device), "in_if": "", "table": "main", "out_if": "", "gateway": "", "public": "",
           "nat": "", "steps": [], "some": [], "trouble": "", "ok": False}
    if w.device is None or w.device.version != 4:
        out["trouble"] = "not an IPv4 address"
        return out
    w.dst = w.pick_probe()
    out["probe"] = str(w.dst)
    w.interface()
    w.vrf()
    mg = ((snap.get("rules") or {}).get("ip") or {}).get("mangle") or []
    got = w.walk("mangle", mg, "prerouting")
    if got and got[0] in ("drop",):
        out.update(trouble="mangle prerouting #%s drops it" % got[1].get("n"), steps=w.steps, some=w.some)
        return out
    act, table = w.routing_rules()
    if act in ("drop", "unreachable"):
        out.update(trouble="a routing rule says %s" % act, steps=w.steps, some=w.some)
        return out
    table = table or w.marks["routing"] or "main"
    rt = w.route(table, w.dst)
    if rt is None and table != "main" and act != "lookup-only-in-table":
        w.steps.append({"stage": "route", "words": "no route in table %s - main is looked up" % table})
        table = "main"
        rt = w.route(table, w.dst)
    out["table"] = table
    if rt is None:
        out.update(trouble="no route to the internet in table %s" % table, steps=w.steps, some=w.some,
                   in_if=w.in_if)
        return out
    w.out_if = rt["out_if"]
    r = rt["route"]
    w.steps.append({"stage": "route", "rule": {"table": "route", "n": None, "id": r.get(".id"), "comment":
                    r.get("comment") or "", "words": "table %s: %s via %s%s%s" % (
                        table, r.get("dst"), r.get("gateway") or "?", (" out " + rt["out_if"]) if rt["out_if"] else "",
                        " (ECMP: the first gateway taken)" if rt["ecmp"] else "")}})
    # mangle on the way out (postrouting) can still change nothing of the route; srcnat decides the address
    nat = ((snap.get("rules") or {}).get("ip") or {}).get("nat") or []
    w.chain_name = "srcnat"
    got = w.walk("nat", nat, "srcnat")
    public, how = None, ""
    if got is None or got[0] in ("accept", "return"):
        public = w.device
        how = ("srcnat #%s: %s - not translated" % (got[1].get("n"), got[0])) if got else "no srcnat rule - not translated"
        if got:
            w.steps.append({"stage": "srcnat", "rule": w.ref("nat", got[1], how)})
        else:
            w.steps.append({"stage": "srcnat", "words": how})
    else:
        act, rr = got
        if act == "masquerade":
            to = _nets(str(rr.get("to-addresses") or "").split(",")[0]) if rr.get("to-addresses") else []
            mine = [a.ip for n, a in w.addrs if n == w.out_if]
            if to and to[0].num_addresses == 1 and to[0][0] in mine:
                public = to[0][0]
            else:
                public = w.masq_addr(rt)
            how = "srcnat #%s: masquerade as %s's address" % (rr.get("n"), w.out_if or "?")
        elif act in ("src-nat", "same"):
            to = _nets(str(rr.get("to-addresses") or "").split(",")[0])
            public = to[0][0] if to else None
            how = "srcnat #%s: src-nat to %s" % (rr.get("n"), rr.get("to-addresses") or "?")
            if to and to[0].num_addresses > 1:
                w.some.append({"words": "src-nat to a range (%s): the first address is shown" % rr.get("to-addresses")})
        elif act == "netmap":
            to = _nets(rr.get("to-addresses"))
            src = _nets(rr.get("src-address")) if rr.get("src-address") else []
            if to and src and to[0].prefixlen == src[0].prefixlen:
                public = to[0][int(w.device) - int(src[0][0])]
            else:
                public = to[0][0] if to else None
            how = "srcnat #%s: netmap to %s" % (rr.get("n"), rr.get("to-addresses") or "?")
        else:
            how = "srcnat #%s: %s" % (rr.get("n"), act)
        w.steps.append({"stage": "srcnat", "rule": w.ref("nat", rr, how)})
        out["nat"] = act
    out.update(in_if=w.in_if, out_if=w.out_if, gateway=rt["gateway"], public=str(public) if public else "",
               steps=w.steps, some=w.some, how=how)
    pub_ok = public is not None and _is_public(ipaddress.ip_network(public))
    if public is not None and not pub_ok:
        out["trouble"] = "it goes out as %s - a private address: the internet cannot answer it there" % public
    out["ok"] = bool(pub_ok and w.out_if)
    return out


def default_out_ifs(snap):
    """The interfaces of the default routes of every table - where the internet comes in."""
    w = Way(snap, "0.0.0.0")
    ifs = set()
    for r in snap.get("routes4") or []:
        if r.get("disabled") or not r.get("active", True) or str(r.get("dst")) != "0.0.0.0/0":
            continue
        _gw, i = w.gateway_if(r)
        if i:
            ifs.add(i)
    return ifs


_ = re  # noqa: F841 - kept for the pages' patterns
