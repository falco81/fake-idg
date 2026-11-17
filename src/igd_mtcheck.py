"""igd_mtcheck.py - does the MikroTik carry what a device asked for? (1.8.2)

fake-igd answers AddPortMapping and opens nothing. For every port a device asked for, this reads the
MikroTik's firewall as RouterOS would walk it for the first packet of a connection from the internet -
first match wins, chain by chain - and says:

  IPv4  raw prerouting (dropped before anything?) -> nat dstnat (an enabled dst-nat to the device, its
        port; not shadowed by an earlier rule; a disabled one said as such) -> filter forward after the
        translation (connection-nat-state=dstnat: RouterOS's default "drop all from WAN not DSTNATed"
        lets it through; an accept, or nothing that drops it - a chain accepts by itself)
  IPv6  no NAT: raw prerouting -> filter forward to the device's own global addresses (from the router's
        neighbour table by its MAC), or "it has no IPv6 address the router knows"

Every matcher is answered yes / no / CANNOT TELL: what depends on things this does not know (who connects,
a rate limit, a time of day, a mark set by mangle) is "cannot tell" - said with the rule and the matcher -
rather than guessed. A packet from the internet: a source not private, any source port, connection-state
new, not IPsec, on the router's WAN (the members of the interface list WAN, else the interface of the
default route).

What is missing comes with the RouterOS commands that would add it - shown, never sent: fake-igd only reads.
"""
import ipaddress
import re

TERMINAL = {"accept", "drop", "reject", "tarpit", "fasttrack-connection", "dst-nat", "src-nat", "masquerade",
            "netmap", "redirect", "same", "endpoint-independent-nat", "return", "jump"}
NOT_MATCHERS = {".id", "n", "chain", "action", "comment", "disabled", "dynamic", "invalid", "bytes", "packets",
                "log", "log-prefix", "to-addresses", "to-ports", "jump-target", "address-list",
                "address-list-timeout", "reject-with", "new-connection-mark", "new-packet-mark", "new-routing-mark",
                "passthrough", "new-dscp", "new-priority", "new-ttl", "new-mss", "sniff-id", "sniff-target",
                "sniff-target-port", "route-dst", "place-before", ".nextid", ".about", "copy-from", "time-left", "hits",
                "hw-offload", "randomise-ports", "new-hop-limit"}
PRIVATE4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4",
                                                "240.0.0.0/4", "192.0.0.0/24", "198.18.0.0/15")]
PRIVATE6 = [ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128", "::/128", "ff00::/8")]
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "ipv6-icmp": 58, "gre": 47, "esp": 50, "ah": 51,
         "ipsec-esp": 50, "ipsec-ah": 51, "sctp": 132, "udp-lite": 136, "dccp": 33}


class Packet(object):
    """The first packet of a connection, as one chain sees it."""

    def __init__(self, family, proto, dport, dst, in_ifs, in_lists, out_ifs=None, out_lists=None,
                 nat_state="", chain="", lists=None):
        self.family, self.proto, self.dport = family, proto, int(dport)
        self.dst = dst                      # [ip_address] it may be (WAN addresses; the device), [] unknown
        self.in_ifs, self.in_lists = in_ifs, in_lists          # set or None (unknown)
        self.out_ifs, self.out_lists = out_ifs, out_lists      # set or None (unknown)
        self.nat_state = nat_state          # "" | "dstnat"
        self.chain = chain
        self.lists = lists or {}            # {list: [networks]} of this family's address lists
        self.action = "accept"              # the action of the rule being matched (match() sets it)


# ---- one matcher: True / False / None (cannot tell) ------------------------------------------------------
def _neg(v):
    v = str(v or "")
    return (True, v[1:]) if v.startswith("!") else (False, v)


def ports_in(spec, port):
    """`3478-3480,9308` holds port? (ValueError for what is not a list of ports)."""
    for one in str(spec).split(","):
        one = one.strip()
        if not one:
            continue
        if "-" in one:
            a, b = one.split("-", 1)
            if int(a) <= port <= int(b):
                return True
        elif int(one) == port:
            return True
    return False


def _nets(spec, family):
    """`1.2.3.4`, `1.2.3.0/24`, `1.2.3.4-1.2.3.9` (and lists of them) as (lo, hi) address pairs."""
    out = []
    for one in str(spec).split(","):
        one = one.strip()
        if not one:
            continue
        if "-" in one and "/" not in one:
            a, b = one.split("-", 1)
            out.append((ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())))
        else:
            n = ipaddress.ip_network(one, strict=False)
            out.append((n[0], n[-1]))
    return out


def addr_in(spec, ip, family="ip"):
    for lo, hi in _nets(spec, family):
        if lo.version == ip.version and lo <= ip <= hi:
            return True
    return False


def _private(lo, hi):
    pv = PRIVATE4 if lo.version == 4 else PRIVATE6
    return any(lo in n and hi in n for n in pv)


def _tri_all(results):
    if any(r is False for r in results):
        return False
    if any(r is None for r in results):
        return None
    return True


def match_one(key, value, pkt, why):
    """One matcher of a rule against the packet: True, False, or None (cannot tell - `why` gets the words)."""
    neg, v = _neg(value)

    def done(r):
        if r is None:
            why.append("%s=%s" % (key, value))
            return None
        return (not r) if neg else r
    try:
        if key == "protocol":
            want = PROTO.get(v.lower(), int(v) if v.isdigit() else None)
            return done(want == PROTO[pkt.proto] if want is not None else None)
        if key == "dst-port":
            return done(ports_in(v, pkt.dport))
        if key in ("src-port",):
            return done(None)                       # any port: who connects chooses it
        if key == "port":
            return done(True if ports_in(v, pkt.dport) else None)
        if key == "dst-address":
            if not pkt.dst:
                return done(None)
            hits = {addr_in(v, ip) for ip in pkt.dst}
            return done(hits.pop() if len(hits) == 1 else None)
        if key in ("src-address", "src-address-list"):
            # Who connects: anybody on the internet. Never a private address. A rule that names a share of
            # the internet that is not all of it: a block list's rule (drop) is taken not to hold the
            # sender (a port is open "for the internet" when the usual peer gets through); an accept or a
            # dst-nat for some sources only cannot be told for everybody.
            if key == "src-address":
                nets = [n for lo, hi in _nets(v, pkt.family) for n in ipaddress.summarize_address_range(lo, hi)]
            else:
                nets = pkt.lists.get(v)
                if nets is None:
                    return done(False)              # a list that does not exist holds nobody
            if not nets or all(_private(n[0], n[-1]) for n in nets):
                return done(False)
            whole = any(n.prefixlen == 0 for n in nets)
            if whole:
                return done(True)
            if pkt.action in ("drop", "reject", "tarpit"):
                return done(False)
            return done(None)
        if key == "dst-address-list":
            nets = pkt.lists.get(v)
            if nets is None:
                return done(False)
            if not pkt.dst:
                return done(None)
            hits = {any(ip in n for n in nets) for ip in pkt.dst}
            return done(hits.pop() if len(hits) == 1 else None)
        if key == "dst-address-type":
            types = set(v.split(","))
            if pkt.chain in ("dstnat", "prerouting") and pkt.nat_state == "":
                return done(bool(types & {"local", "unicast"}) if types <= {"local", "unicast", "broadcast", "multicast",
                                                                             "blackhole", "prohibit", "unreachable"}
                            else None)
            return done(bool(types & {"unicast"}) if types <= {"local", "unicast", "broadcast", "multicast"} else None)
        if key == "src-address-type":
            types = set(v.split(","))
            return done(bool(types & {"unicast"}) if types <= {"local", "unicast", "broadcast", "multicast"} else None)
        if key in ("in-interface", "out-interface"):
            ifs = pkt.in_ifs if key == "in-interface" else pkt.out_ifs
            if key == "out-interface" and pkt.chain in ("dstnat", "prerouting"):
                return done(None)
            if not ifs:
                return done(None)
            hits = {(i == v or (v.endswith("*") and i.startswith(v[:-1]))) for i in ifs}
            return done(hits.pop() if len(hits) == 1 else None)
        if key in ("in-interface-list", "out-interface-list"):
            lists = pkt.in_lists if key == "in-interface-list" else pkt.out_lists
            if key == "out-interface-list" and pkt.chain in ("dstnat", "prerouting"):
                return done(None)
            if lists is None:
                return done(None)
            return done(v in lists)
        if key == "connection-state":
            return done("new" in [x.strip() for x in v.split(",")])
        if key == "connection-nat-state":
            states = [x.strip() for x in v.split(",") if x.strip()]
            return done(pkt.nat_state in states if pkt.nat_state else False)
        if key == "connection-type":
            return done(False)                      # a game's connection is no helper's (ftp, sip...)
        if key == "ipsec-policy":
            d, _, pol = v.partition(",")
            return done(pol == "none")
        if key in ("hop-limit", "ttl"):
            op, _, n = v.partition(":")
            if op == "equal" and n in ("0", "1"):
                return done(False)
            return done(None)
        if key == "icmp-options":
            return done(False)
        if key == "tcp-flags":
            if pkt.proto != "tcp":
                return done(False)
            flags = [x.strip() for x in v.split(",")]
            have = {"syn"}
            ok = all((f[1:] not in have) if f.startswith("!") else (f in have) for f in flags)
            return done(ok)
        if key == "fragment":
            return done(v in ("no", "false"))
    except (ValueError, TypeError):
        return done(None)
    return done(None)                               # limit, time, marks, layer7, content...: cannot tell


def match(rule, pkt):
    """(True / False / None, [the matchers that cannot be told])."""
    why = []
    pkt.action = rule.get("action") or "accept"
    res = [match_one(k, v, pkt, why) for k, v in rule.items() if k not in NOT_MATCHERS and v not in ("", None)]
    return _tri_all(res), why


# ---- a chain walked, first match wins ---------------------------------------------------------------------
def walk(rules, chain, pkt, depth=0, seen=None):
    """{verdict, rule, unsure: [matchers]} - verdict: an action, "return", "end" (fell off the chain), or
    "unsure" (a rule that would decide it, and something of it cannot be told). Jumps followed."""
    seen = seen or set()
    if depth > 16 or chain in seen:
        return {"verdict": "unsure", "rule": None, "unsure": ["a loop of jumps"]}
    seen = seen | {chain}
    passed = []
    for r in rules:
        if r.get("chain") != chain or r.get("disabled") or r.get("invalid"):
            continue
        m, why = match(r, pkt)
        if m is False:
            continue
        action = r.get("action") or "accept"
        if action not in TERMINAL:
            continue                                # log, passthrough, marks, address lists: it goes on
        if m is None:
            return {"verdict": "unsure", "rule": r, "unsure": why, "passed": passed}
        if action == "jump":
            sub = walk(rules, r.get("jump-target") or "", pkt, depth + 1, seen)
            if sub["verdict"] in ("return", "end"):
                passed.append(r)
                continue
            return sub
        return {"verdict": action, "rule": r, "unsure": [], "passed": passed}
    return {"verdict": "end", "rule": None, "unsure": [], "passed": passed}


# ---- the router's WAN, as far as it can be told ----------------------------------------------------------
def wan_of(snap):
    """{ifs, addrs4, how}: the members of the interface list WAN; else the interface of the default route
    of the main table (its immediate-gw's interface, an interface named as the gateway, or the interface
    whose network holds the gateway's address); else the interface that carries the public address fake-igd
    knows (1.9.2); else the one interface with a public address. Its IPv4 addresses."""
    members = snap.get("iflists") or {}
    addrs = [a for a in snap.get("addresses4") or [] if not a.get("disabled")]

    def _ip(a):
        try:
            return ipaddress.ip_interface(a["address"])
        except (ValueError, KeyError):
            return None
    ifs, how = set(members.get("WAN") or []), "the interface list WAN"
    if not ifs:
        routes = [r for r in snap.get("routes4") or [] if r.get("active") and not r.get("disabled")]
        main = [r for r in routes if str(r.get("table") or "main") == "main"] or routes
        for r in main:
            im = str(r.get("immediate") or "")
            gw = str(r.get("gateway") or "").split("%")[0].split(",")[0]
            if "%" in im:
                ifs.add(im.split("%", 1)[1].split(",")[0])
            elif gw and not re.match(r"^[0-9.]+$", gw):
                ifs.add(gw)
            elif gw:
                for a in addrs:
                    x = _ip(a)
                    if x and ipaddress.ip_address(gw) in x.network:
                        ifs.add(a.get("interface"))
        how = "the interface of the default route"
    pub = str(snap.get("public_ip") or "")
    if not ifs and pub:
        for a in addrs:
            x = _ip(a)
            if x and str(x.ip) == pub:
                ifs.add(a.get("interface"))
        how = "the interface that carries %s (this network's public address)" % pub
    if not ifs:
        glob = {a.get("interface") for a in addrs if _ip(a) and _ip(a).ip.is_global}
        if len(glob) == 1:
            ifs, how = glob, "the only interface with a public address"
    out = []
    for a in addrs:
        x = _ip(a)
        if x and a.get("interface") in ifs:
            out.append(x.ip)
    return {"ifs": ifs, "addrs4": out, "how": how if ifs else ""}


def lists_of(snap, ifs):
    if not ifs:
        return None
    out = set()
    for name, members in (snap.get("iflists") or {}).items():
        if set(members) & set(ifs):
            out.add(name)
    return out


def address_lists(snap, family):
    got = {}
    for name, entries in ((snap.get("lists") or {}).get(family) or {}).items():
        nets = []
        for e in entries:
            if e.get("disabled"):
                continue
            a = str(e.get("address") or "")
            try:
                if "-" in a and "/" not in a:
                    lo, hi = (ipaddress.ip_address(x.strip()) for x in a.split("-", 1))
                    nets.extend(ipaddress.summarize_address_range(lo, hi))
                else:
                    nets.append(ipaddress.ip_network(a, strict=False))
            except ValueError:
                continue                            # a name (resolved by the router): not counted
        got[name] = nets
    return got


def _rule_words(r):
    if not r:
        return ""
    bits = ["#%s" % r.get("n")]
    if r.get("comment"):
        bits.append("“%s”" % r["comment"][:60])
    bits.append("(%s %s)" % (r.get("chain"), r.get("action")))
    return " ".join(bits)


def _to_device(r, device, port):
    """A dst-nat rule that sends it to the device on this port."""
    if (r.get("action") or "") not in ("dst-nat", "netmap"):
        return False
    to = r.get("to-addresses") or ""
    try:
        if not to or not addr_in(to, ipaddress.ip_address(device)):
            return False
    except ValueError:
        return False
    tp = r.get("to-ports") or ""
    if not tp:
        return True
    try:
        return ports_in(tp, int(port))
    except ValueError:
        return False


def _would_match_ignoring_order(rule, pkt):
    m, _why = match(dict(rule, disabled=False), pkt)
    return m is not False


def wan_spec(snap, wan):
    """How a rule here says "from the internet": the interface list WAN, the WAN interface, its address."""
    if "WAN" in (snap.get("iflists") or {}) and (snap.get("iflists") or {}).get("WAN"):
        return "in-interface-list=WAN"
    if len(wan["ifs"]) == 1:
        return "in-interface=%s" % next(iter(wan["ifs"]))
    if wan["addrs4"]:
        return "dst-address=%s" % wan["addrs4"][0]
    return "in-interface=ether1"


def comment_of(want):
    name = re.sub(r'["\\\\\[\]{};$]', "", str(want.get("name") or want.get("device") or ""))[:40]
    return "fake-igd: %s %s/%s" % (name, want["port"], want["proto"])


# ---- one port: is it open on the MikroTik? -----------------------------------------------------------------
def check_port(snap, want, wan=None):
    """want = {device, name, proto, port, to_port, mac, v6: [addresses]} -> its state, IPv4 and IPv6, the
    rules that decided it, and the commands that would add what is missing."""
    wan = wan or wan_of(snap)
    proto, port = want["proto"].lower(), int(want["port"])
    to_port = int(want.get("to_port") or port)
    device = want["device"]
    r4 = (snap.get("rules") or {}).get("ip") or {}
    lists4 = address_lists(snap, "ip")
    in_lists = lists_of(snap, wan["ifs"]) if wan["ifs"] else ({"WAN"} if "WAN" in (snap.get("iflists") or {}) else None)
    in_ifs = wan["ifs"] or None
    out = {"device": device, "name": want.get("name") or "", "proto": proto, "port": port, "to_port": to_port,
           "rules": [], "commands": [], "notes": []}
    nat = r4.get("nat") or []
    filt = r4.get("filter") or []
    raw = r4.get("raw") or []
    pkt = Packet("ip", proto, port, wan["addrs4"], in_ifs, in_lists, chain="dstnat", lists=lists4)
    # raw prerouting: dropped before anything
    rp = walk(raw, "prerouting", Packet("ip", proto, port, wan["addrs4"], in_ifs, in_lists, chain="prerouting",
                                        lists=lists4))
    # the dst-nat that would carry it, enabled or not, anywhere in dstnat
    cands = [r for r in nat if r.get("chain") == "dstnat" and _to_device(r, device, to_port)
             and _would_match_ignoring_order(r, pkt)]
    wanted_rule = next((r for r in cands if not r.get("disabled")), None)
    v = walk(nat, "dstnat", pkt)
    s4, why4, by = "missing", "", v.get("rule")
    if rp["verdict"] == "drop":
        s4, why4, by = "blocked", "dropped in raw prerouting by rule %s before any translation" % _rule_words(rp["rule"]), rp["rule"]
    elif rp["verdict"] == "unsure":
        s4, why4, by = "unsure", "raw prerouting rule %s may drop it (%s)" % (_rule_words(rp["rule"]), ", ".join(rp["unsure"])), rp["rule"]
    elif v["verdict"] == "unsure":
        s4, why4 = "unsure", "dstnat rule %s may take it first - cannot tell: %s" % (_rule_words(by), ", ".join(v["unsure"]))
    elif v["verdict"] in ("dst-nat", "netmap"):
        if _to_device(by, device, to_port):
            s4, why4 = "dnat", "translated by rule %s" % _rule_words(by)
        elif wanted_rule is not None:
            s4 = "shadowed"
            why4 = "rule %s sends it to %s first - rule %s comes after it" % (
                _rule_words(by), by.get("to-addresses") or "?", _rule_words(wanted_rule))
        else:
            s4 = "elsewhere"
            why4 = "rule %s sends it to %s%s, not to %s" % (_rule_words(by), by.get("to-addresses") or "?",
                                                          (":" + by["to-ports"]) if by.get("to-ports") else "", device)
    elif v["verdict"] == "redirect":
        s4, why4 = "elsewhere", "rule %s sends it to the router itself (redirect)" % _rule_words(by)
    elif v["verdict"] in ("accept", "return") and wanted_rule is not None:
        s4, why4 = "shadowed", "rule %s ends the translation before rule %s" % (_rule_words(by), _rule_words(wanted_rule))
    elif v["verdict"] in ("accept", "return", "end"):
        if wanted_rule is not None and v["verdict"] == "end":
            s4, why4 = "unsure", "rule %s should translate it but does not match it as it is read" % _rule_words(wanted_rule)
        elif cands:
            s4, by = "disabled", cands[0]
            why4 = "rule %s would translate it, but it is disabled" % _rule_words(by)
        else:
            s4 = "missing"
            why4 = "no dst-nat rule sends %s %d to %s" % (proto.upper(), port, device) + (
                " (rule %s ends the translation)" % _rule_words(by) if by is not None else "")
    if s4 == "dnat" and wanted_rule is not None and by is not wanted_rule and not _to_device(by, device, to_port):
        s4 = "shadowed"
    if by is not None:
        out["rules"].append({"table": "nat" if by in nat else "raw", "id": by.get(".id"), "n": by.get("n"), "family": "ip"})
    for r in cands:
        out["rules"].append({"table": "nat", "id": r.get(".id"), "n": r.get("n"), "family": "ip"})
    # the filter's forward chain, after the translation (walked also where there is none yet: what an added
    # dst-nat would meet)
    dev_ifs = {a.get("interface") for a in snap.get("arp") or [] if a.get("address") == device} - {None, ""}
    fp = Packet("ip", proto, to_port, [ipaddress.ip_address(device)], in_ifs, in_lists,
                out_ifs=dev_ifs or None, out_lists=lists_of(snap, dev_ifs) if dev_ifs else None,
                nat_state="dstnat", chain="forward", lists=lists4)
    fv = walk(filt, "forward", fp)
    fr = fv.get("rule")
    if fv["verdict"] in ("accept", "fasttrack-connection"):
        f4, whyf = "open", "let through by rule %s" % _rule_words(fr)
    elif fv["verdict"] in ("end", "return"):
        f4 = "open"
        notdst = next((r for r in filt if r.get("chain") == "forward" and r.get("action") == "drop"
                       and "!dstnat" in str(r.get("connection-nat-state") or "")), None)
        whyf = ("RouterOS's default rule %s drops only what came in untranslated: translated, it goes through"
                % _rule_words(notdst)
                if notdst else "nothing in forward drops it (a chain lets through what no rule stops)")
    elif fv["verdict"] == "unsure":
        f4, whyf = "unsure", "forward rule %s may stop it - cannot tell: %s" % (_rule_words(fr), ", ".join(fv["unsure"]))
    else:
        f4, whyf = "blocked", "forward rule %s %ss it" % (_rule_words(fr), fv["verdict"])
    if fr is not None:
        out["rules"].append({"table": "filter", "id": fr.get(".id"), "n": fr.get("n"), "family": "ip"})
    # the state of IPv4, in one word
    state = {"dnat": {"open": "ok", "blocked": "no_accept", "unsure": "unsure"}.get(f4, "unsure"),
             "missing": "no_dnat", "disabled": "disabled", "shadowed": "shadowed", "elsewhere": "elsewhere",
             "blocked": "no_accept", "unsure": "unsure"}[s4]
    out.update(state=state, nat=s4, nat_why=why4, forward=f4, forward_why=whyf)
    # what would put it right - shown, never sent
    spec = wan_spec(snap, wan)
    c = comment_of(want)
    if state in ("no_dnat", "shadowed", "elsewhere"):
        place = (" place-before=%s" % by[".id"]) if state == "shadowed" and by is not None and by.get(".id") else ""
        out["commands"].append("/ip firewall nat add chain=dstnat action=dst-nat protocol=%s dst-port=%d %s "
                               "to-addresses=%s to-ports=%d comment=\"%s\"%s" % (proto, port, spec, device, to_port, c, place))
        if state == "elsewhere":
            out["notes"].append("another rule already forwards this port elsewhere: one port can go to one device")
    if state == "disabled" and by is not None:
        out["commands"].append("/ip firewall nat enable %s" % (by.get(".id") or by.get("n")))
    if f4 == "blocked" and state in ("ok", "no_accept", "no_dnat", "shadowed", "disabled"):
        out["commands"].append("/ip firewall filter add chain=forward action=accept connection-nat-state=dstnat "
                               "protocol=%s dst-address=%s dst-port=%d %s comment=\"%s\"%s"
                               % (proto, device, to_port, spec, c, (" place-before=%s" % fr[".id"]) if fr and fr.get(".id") else ""))
    # IPv6
    out.update(_check_v6(snap, want, wan, proto, to_port, c))
    return out


def _forward_blocks(filt):
    """Whether forward drops what comes from the WAN untranslated - then an accept is needed only where the
    default "not DSTNATed" pattern is missing."""
    return any(r.get("chain") == "forward" and r.get("action") in ("drop", "reject") and not r.get("disabled")
               and not r.get("connection-state") and "!dstnat" not in str(r.get("connection-nat-state") or "")
               and (r.get("in-interface-list") or r.get("in-interface")) for r in filt)


def _check_v6(snap, want, wan, proto, port, c):
    mac = str(want.get("mac") or "").upper()
    if not mac:
        mac = next((a["mac"] for a in snap.get("arp") or [] if a.get("address") == want["device"] and a.get("mac")), "")
    v6 = list(want.get("v6") or [])
    if mac:
        v6 += [n["address"] for n in snap.get("neigh6") or [] if n.get("mac") == mac]
    glob = []
    for a in v6:
        try:
            ip = ipaddress.ip_address(str(a).split("/")[0].split("%")[0])
        except ValueError:
            continue
        if ip.version == 6 and ip in ipaddress.ip_network("2000::/3") and ip not in glob:
            glob.append(ip)
    if not glob:
        return {"v6": "none", "v6_why": "it has no global IPv6 address the router knows (its neighbour table%s)"
                % (", by its MAC %s" % mac if mac else "; its MAC is not known"), "v6_addrs": []}
    r6 = (snap.get("rules") or {}).get("ipv6") or {}
    filt, raw = r6.get("filter") or [], r6.get("raw") or []
    lists6 = address_lists(snap, "ipv6")
    wan6 = wan["ifs"] or None
    in_lists = lists_of(snap, wan["ifs"]) if wan["ifs"] else ({"WAN"} if "WAN" in (snap.get("iflists") or {}) else None)
    dev_ifs = {n.get("interface") for n in snap.get("neigh6") or [] if n.get("mac") == mac} - {None, ""}
    states, words, rules = [], [], []
    for ip in glob:
        rp = walk(raw, "prerouting", Packet("ipv6", proto, port, [ip], wan6, in_lists, chain="prerouting", lists=lists6))
        if rp["verdict"] == "drop":
            states.append("blocked")
            words.append("%s: raw rule %s drops it" % (ip, _rule_words(rp["rule"])))
            rules.append(rp["rule"])
            continue
        fv = walk(filt, "forward", Packet("ipv6", proto, port, [ip], wan6, in_lists, out_ifs=dev_ifs or None,
                                          out_lists=lists_of(snap, dev_ifs) if dev_ifs else None, chain="forward",
                                          lists=lists6))
        fr = fv.get("rule")
        if fr is not None:
            rules.append(fr)
        if fv["verdict"] in ("accept", "end", "return", "fasttrack-connection"):
            states.append("open")
            words.append("%s: %s" % (ip, ("let through by rule %s" % _rule_words(fr)) if fr else "nothing drops it"))
        elif fv["verdict"] == "unsure":
            states.append("unsure")
            words.append("%s: rule %s may stop it - cannot tell: %s" % (ip, _rule_words(fr), ", ".join(fv["unsure"])))
        else:
            states.append("blocked")
            words.append("%s: rule %s %ss it" % (ip, _rule_words(fr), fv["verdict"]))
    st = "open" if all(s == "open" for s in states) else ("blocked" if "blocked" in states else "unsure")
    cmds = []
    if st == "blocked":
        block = next((r for r in rules if r and r.get("action") in ("drop", "reject")), None)
        spec = "in-interface-list=WAN" if "WAN" in (snap.get("iflists") or {}) else (
            "in-interface=%s" % next(iter(wan["ifs"])) if len(wan["ifs"]) == 1 else "in-interface=ether1")
        for ip in glob:
            cmds.append("/ipv6 firewall filter add chain=forward action=accept protocol=%s dst-address=%s/128 "
                        "dst-port=%d %s comment=\"%s\"%s" % (proto, ip, port, spec, c,
                                                             (" place-before=%s" % block[".id"]) if block and block.get(".id") else ""))
    return {"v6": st, "v6_why": "; ".join(words), "v6_addrs": [str(x) for x in glob], "v6_commands": cmds,
            "v6_rules": [{"table": "filter", "id": r.get(".id"), "n": r.get("n"), "family": "ipv6"} for r in rules if r]}


def check_all(snap, wants):
    """Every port asked for, and what is wrong of the router as a whole (its own UPnP on)."""
    wan = wan_of(snap)
    rows = []
    for w in wants:
        try:
            rows.append(check_port(snap, w, wan))
        except Exception as e:                      # noqa: BLE001 - one port that cannot be told is said so
            rows.append({"device": w.get("device"), "name": w.get("name") or "", "proto": w.get("proto"),
                         "port": w.get("port"), "to_port": w.get("to_port"), "state": "unsure",
                         "nat_why": "cannot tell: %s" % e, "commands": [], "rules": [], "v6": "none", "v6_why": ""})
    warnings = []
    up = snap.get("upnp") or {}
    if str(up.get("enabled") or "").lower() in ("true", "yes"):
        warnings.append("The MikroTik's own UPnP is ON (/ip upnp): two UPnP routers on one network - a device may ask "
                        "the MikroTik instead of fake-igd, and the MikroTik opens what it is asked. "
                        "/ip upnp set enabled=no")
    if not wan["ifs"]:
        warnings.append("Which interface is the router's WAN cannot be told: no interface list WAN, no default "
                        "route read, no interface with the public address - the checks of the interfaces are "
                        "\"cannot tell\" (/interface list member add list=WAN interface=... tells it)")
    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    return {"rows": rows, "warnings": warnings, "wan": {"ifs": sorted(wan["ifs"]), "how": wan["how"],
                                                        "addrs4": [str(a) for a in wan["addrs4"]]},
            "counts": counts, "open": counts.get("ok", 0), "total": len(rows)}


def merged_commands(rows):
    """The missing ones of each device merged into one rule a protocol, the ports as ranges (isemon's
    "Rules to add", merged into ranges)."""
    by = {}
    for r in rows:
        if r.get("state") in ("no_dnat",) and r.get("port") == r.get("to_port"):
            by.setdefault((r["device"], r["proto"]), []).append(int(r["port"]))
    out = []
    for (dev, proto), ports in sorted(by.items()):
        ports = sorted(set(ports))
        spans, a = [], ports[0]
        for prev, cur in zip(ports, ports[1:] + [None]):
            if cur != prev + 1:
                spans.append(str(a) if a == prev else "%d-%d" % (a, prev))
                a = cur
        out.append({"device": dev, "proto": proto, "ports": ",".join(spans)})
    return out
