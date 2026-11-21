"""api_net.py - Settings → Network (1.6.0), otp's Settings → Network for one server.

Each interface as NetworkManager has it (nmcli -t, read here: the fake-igd account may ask
NetworkManager what it has), the host name, and a new network for one interface - checked
here (otp's net_check), then put in by root (deploy/root_net.py) ON TRIAL: unless somebody
presses Keep it within net_confirm_min minutes, root's own timer puts back exactly what the
machine had. No cluster, no VIP, no reboot: the connection is brought up again with it.

  GET  /api/net?host=NAME         the interfaces, the host name, the change under way, the trial
  POST /api/net {action: read | plan | apply | keep | back | hide, ...}
"""
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time

NAME = "net"
NMCLI = os.environ.get("FAKE_IGD_NMCLI", "nmcli")
IP = os.environ.get("FAKE_IGD_IP", "ip")
HOSTNAMECTL = os.environ.get("FAKE_IGD_HOSTNAMECTL", "hostnamectl")
RESOLV = os.environ.get("FAKE_IGD_RESOLV", "/etc/resolv.conf")
KINDS = ("ethernet", "bond", "vlan", "bridge", "team", "wifi", "infiniband", "macvlan")
DOMAIN_RE = re.compile(r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
                       r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]+\Z")
FIELDS = ["ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.dns-search",
          "ipv6.method", "ipv6.addresses", "ipv6.gateway", "ipv6.dns"]
JOB_KEEP_S = 6 * 3600
# NetworkManager's ipv6.method, every one, in otp's words where otp has them.
V6_METHODS = ("auto", "dhcp", "manual", "link-local", "ignore", "disabled")
V6_WORDS = {"auto": "automatic (SLAAC / DHCPv6)", "dhcp": "DHCPv6 only", "manual": "set by hand",
            "link-local": "link-local only", "ignore": "ignore (NetworkManager leaves IPv6 alone)", "disabled": "off",
            "shared": "shared to other machines"}

SETTINGS = [
    {"key": "net_confirm_min", "name": "A new network goes back unless kept within (min)", "kind": "int",
     "default": 10, "min": 0, "max": 120,
     "says": "A new network (Settings - Network) is put in - and the old one comes back by itself unless "
             "somebody presses Keep it within these minutes: a typo in the gateway or the prefix does not "
             "leave the machine unreachable. 0: kept at once."},
]


# ---- reading what the machine has --------------------------------------------------------
def run(cmd, timeout=8):
    try:
        got = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError("%s: %s" % (cmd[0], e))
    if got.returncode != 0:
        raise ValueError("%s: %s" % (" ".join(cmd[:3]), (got.stderr or got.stdout).strip()[-300:]))
    return got.stdout


def terse(line):
    """A line of nmcli -t: fields split at ':' that is not escaped (\\:)."""
    f = line.replace("\\\\", "\x01").replace("\\:", "\x00").split(":")
    return [x.replace("\x00", ":").replace("\x01", "\\") for x in f]


def nm_list(text):
    return [x.strip() for x in re.split(r"[,\s]+", text or "") if x.strip() and x.strip() != "--"]


def nm_fields(con):
    out = run([NMCLI, "-t", "-g", ",".join(FIELDS), "connection", "show", con])
    vals = out.rstrip("\n").split("\n")
    got = {}
    for k, v in zip(FIELDS, vals + [""] * (len(FIELDS) - len(vals))):
        got[k] = v.replace("\\:", ":").strip()
    return {"ipv4_method": got["ipv4.method"],
            "ipv4_addresses": nm_list(got["ipv4.addresses"]),
            "ipv4_gateway": got["ipv4.gateway"] if got["ipv4.gateway"] != "--" else "",
            "ipv4_dns": nm_list(got["ipv4.dns"]),
            "ipv4_search": nm_list(got["ipv4.dns-search"]),
            "ipv6_method": got["ipv6.method"],
            "ipv6_addresses": nm_list(got["ipv6.addresses"]),
            "ipv6_gateway": got["ipv6.gateway"] if got["ipv6.gateway"] != "--" else "",
            "ipv6_dns": nm_list(got["ipv6.dns"])}


def live():
    """What the kernel has: addresses (ip -o addr), default routes, resolv.conf."""
    out = {"addrs": {}, "gw4": "", "gw4_dev": "", "gw6": "", "gw6_dev": "", "dns": [], "links": []}
    try:
        for line in run([IP, "-o", "addr", "show"]).splitlines():
            f = line.split()
            if len(f) < 4 or f[2] not in ("inet", "inet6"):
                continue
            dev = f[1].split("@")[0].rstrip(":")
            try:
                ifc = ipaddress.ip_interface(f[3])
            except ValueError:
                continue
            if ifc.ip.is_loopback:
                continue
            a = out["addrs"].setdefault(dev, {"addrs4": [], "addrs6": [], "addrs6_ll": []})
            if ifc.version == 4:
                a["addrs4"].append(str(ifc))
            elif ifc.ip.is_link_local:
                # IPv6 link-local (fe80::/64, scope link) - every interface with IPv6 has one: listed, marked
                a["addrs6_ll"].append(str(ifc))
            else:
                a["addrs6"].append(str(ifc))
        for line in run([IP, "-o", "link", "show"]).splitlines():
            m = re.match(r"^\d+:\s+([^:@\s]+)[^<]*<([^>]*)>", line)
            mac = re.search(r"link/(?:ether|infiniband)\s+(\S+)", line)
            if m and m.group(1) != "lo":
                out["links"].append({"dev": m.group(1), "up": "UP" in m.group(2).split(","),
                                     "mac": mac.group(1) if mac else ""})
    except ValueError:
        pass
    for fam, key in (("-4", "gw4"), ("-6", "gw6")):
        try:
            m = re.search(r"default via (\S+) dev (\S+)", run([IP, fam, "route", "show", "default"]))
        except ValueError:
            m = None
        if m:
            out[key], out[key + "_dev"] = m.group(1), m.group(2)
    try:
        with open(RESOLV) as f:
            out["dns"] = [l.split()[1] for l in f if l.startswith("nameserver ") and len(l.split()) > 1][:6]
    except OSError:
        pass
    return out


def hostname():
    try:
        got = run([HOSTNAMECTL, "--static"]).strip()
    except ValueError:
        got = ""
    return got or socket.gethostname()


def answers_on(cfg, dev):
    """Does fake-igd (SSDP and SOAP) answer on this interface, as config.json says?"""
    want = set(cfg.get("interfaces") or [])
    skip = set(cfg.get("exclude_interfaces") or ["lo"])
    return (not want or dev in want) and dev not in skip


def page_dev(devs, host, client):
    """The interface these pages are reached by: the one holding the address the browser asked
    for (its host name looked up), else the one the client's address is reached through."""
    want = []
    host = (host or "").strip().strip("[]")
    if host:
        if ADDR_RE.match(host):
            want.append(host)
        elif DOMAIN_RE.match(host) and host not in ("localhost",) and not os.environ.get("FAKE_IGD_NO_DNS"):
            try:
                want += [x[4][0] for x in socket.getaddrinfo(host, None)]
            except (OSError, UnicodeError):
                pass
    for d in devs:
        for a in d["addrs4"] + d["addrs6"]:
            if a.split("/")[0] in want:
                return d["dev"]
    try:
        c = ipaddress.ip_address(client)
    except ValueError:
        return ""
    for d in devs:
        for a in d["addrs4"] + d["addrs6"]:
            try:
                if c in ipaddress.ip_interface(a).network:
                    return d["dev"]
            except ValueError:
                continue
    try:
        m = re.search(r"\bdev (\S+)", run([IP, "-o", "route", "get", str(c)]))
        return m.group(1) if m else ""
    except ValueError:
        return ""


def read(cfg, host="", client=""):
    lv = live()
    out = {"nm": bool(shutil.which(NMCLI)), "hostname": hostname(), "devices": [], "dns": lv["dns"],
           "gw4": lv["gw4"], "gw4_dev": lv["gw4_dev"], "gw6": lv["gw6"], "gw6_dev": lv["gw6_dev"],
           "read_at": time.time()}
    seen = {}
    if out["nm"]:
        try:
            for line in run([NMCLI, "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"]).splitlines():
                f = terse(line)
                if len(f) >= 4 and f[1] in KINDS:
                    seen[f[0]] = {"dev": f[0], "type": f[1], "state": f[2], "con": f[3] if f[3] != "--" else ""}
        except ValueError as e:
            out["nm_said"] = str(e)
    for l in lv["links"]:
        if l["dev"] not in seen and not out["nm"]:
            seen[l["dev"]] = {"dev": l["dev"], "type": "", "state": "connected" if l["up"] else "down", "con": ""}
    macs = {l["dev"]: l["mac"] for l in lv["links"]}
    for dev in sorted(seen):
        d = seen[dev]
        a = lv["addrs"].get(dev) or {"addrs4": [], "addrs6": [], "addrs6_ll": []}
        d.update(a)
        d["mac"] = macs.get(dev, "")
        d["conf"] = {}
        if d["con"]:
            try:
                d["conf"] = nm_fields(d["con"])
            except ValueError as e:
                d["said"] = str(e)
        d["answers"] = answers_on(cfg, dev)
        d["default"] = dev == lv["gw4_dev"]
        out["devices"].append(d)
    out["page_dev"] = page_dev(out["devices"], host, client)
    return out


# ---- what the page asks for, made whole and checked (otp's net_check) -------------------
def _list(v, most=4):
    if isinstance(v, str):
        v = re.split(r"[\s,;]+", v)
    return [str(x).strip() for x in (v or []) if str(x).strip()][:most]


def _plain(x):
    x = str(x or "").strip()
    if not ADDR_RE.match(x):
        return None
    try:
        return ipaddress.ip_address(x)
    except ValueError:
        return None


def check(ctx, now, want, trial_min):
    if not now["nm"]:
        raise ValueError("NetworkManager (nmcli) is not on this machine: its network is set by hand")
    if not isinstance(want, dict):
        raise ValueError("what is to be set?")
    devs = {d["dev"]: d for d in now["devices"]}
    dev = str(want.get("dev") or "")
    d = devs.get(dev)
    if not d or not d.get("con"):
        raise ValueError("which interface? It has: %s" % (", ".join(
            "%s (%s)" % (x["dev"], x["con"]) for x in now["devices"] if x.get("con")) or "none with a connection"))
    con = d["con"]
    v4 = want.get("ipv4") if isinstance(want.get("ipv4"), dict) else {}
    method = "auto" if v4.get("method") == "auto" else "manual"
    a4, gw = None, ""
    if method == "manual":
        try:
            a4 = ipaddress.ip_interface(str(v4.get("addr") or "").strip())
        except ValueError:
            raise ValueError("the IPv4 address is an address with its prefix: 192.0.2.10/24")
        if a4.version != 4 or "/" not in str(v4.get("addr")):
            raise ValueError("the IPv4 address is an address with its prefix: 192.0.2.10/24")
        if a4.ip.is_loopback or a4.ip.is_multicast or a4.ip.is_unspecified or \
                (a4.network.prefixlen < 31 and a4.ip in (a4.network.network_address, a4.network.broadcast_address)):
            raise ValueError("%s cannot be the address of a machine in %s" % (a4.ip, a4.network))
        gw = str(v4.get("gw") or "").strip()
        if gw:
            g = _plain(gw)
            if g is None or g.version != 4 or g == a4.ip or g not in a4.network:
                raise ValueError("the gateway %s is not another address in %s" % (gw, a4.network))
        for other in now["devices"]:
            if other["dev"] != dev and any(x.split("/")[0] == str(a4.ip) for x in other["addrs4"]):
                raise ValueError("%s is the address of %s already" % (a4.ip, other["dev"]))
    dns = _list(v4.get("dns"))
    for x in dns:
        p = _plain(x)
        if p is None:
            raise ValueError("%r is not the address of a DNS server" % x)
        if p.version != 4:
            raise ValueError("%s is an IPv6 address - put it with the IPv6 DNS servers" % x)
    search = _list(v4.get("search"), 6)
    for x in search:
        if not DOMAIN_RE.match(x):
            raise ValueError("%r is not a search domain: a DNS name such as example.com, with no dot at its end" % x)
    conf = d.get("conf") or {}
    v6 = want.get("ipv6") if isinstance(want.get("ipv6"), dict) else {}
    # Every ipv6.method NetworkManager has; the switch off is "disabled" (or "ignore", as found).
    mode6 = str(v6.get("method") or conf.get("ipv6_method") or "auto")
    # The method as found (shared, say - the form offers it "as it is") is taken when IPv6 is left as it
    # is (1.9.11): before, nothing of IPv4 could be changed on such an interface.
    if mode6 not in V6_METHODS and mode6 != (conf.get("ipv6_method") or ""):
        raise ValueError("IPv6 is one of: %s" % ", ".join(V6_METHODS))
    a6, g6 = None, ""
    if mode6 == "manual":
        try:
            a6 = ipaddress.ip_interface(str(v6.get("addr") or "").strip())
        except ValueError:
            raise ValueError("the IPv6 address is an address with its prefix: 2001:db8::10/64")
        if a6.version != 6 or a6.ip.is_link_local or "/" not in str(v6.get("addr")):
            raise ValueError("the IPv6 address is a global one with its prefix: 2001:db8::10/64")
        g6 = str(v6.get("gw") or "").strip()
        if g6:
            p = _plain(g6)
            if p is None or p.version != 6:
                raise ValueError("the IPv6 gateway is one IPv6 address")
    on6 = mode6 not in ("disabled", "ignore")
    dns6 = _list(v6.get("dns")) if on6 else []
    for x in dns6:
        p = _plain(x)
        if p is None or p.version != 6:
            raise ValueError("%r is not the IPv6 address of a DNS server" % x)
    # Nothing of IPv6 changed: ipv6.* left exactly as it is - root does not touch it at all.
    was_m = conf.get("ipv6_method") or ""
    keep6 = mode6 == was_m and (not on6 or dns6 == (conf.get("ipv6_dns") or [])) and (
        mode6 != "manual" or (str(a6) == ((conf.get("ipv6_addresses") or [""])[0]) and g6 == (conf.get("ipv6_gateway") or "")))
    if not keep6 and mode6 not in V6_METHODS:
        raise ValueError("IPv6 is one of: %s - or left as it is (%s)" % (", ".join(V6_METHODS), mode6))
    host = str(want.get("hostname") or "").strip().rstrip(".").lower()
    host_old = str(now.get("hostname") or "").strip().rstrip(".").lower()
    same = host == host_old
    if host and not re.match(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                             r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)%s$" % ("*" if same else "+"), host):
        raise ValueError("the host name is the whole name: igd.example.com")
    old_ip = ((conf.get("ipv4_addresses") or d["addrs4"] or [""])[0]).split("/")[0]
    new_ip = str(a4.ip) if a4 else ""
    plan = []
    if host and host != host_old:
        plan.append("the host name %s → %s (hostnamectl, and this machine's lines in /etc/hosts)" % (host_old or "?", host))
    if not keep6:
        plan.append("IPv6 on %s: %s → %s%s" % (dev, V6_WORDS.get(was_m, was_m or "?"), V6_WORDS[mode6],
                                               " %s via %s" % (a6, g6 or "no gateway") if a6 else ""))
    plan.append("NetworkManager (%s): %s, DNS %s%s" % (
        con if con == dev else "%s on %s" % (con, dev), ("%s via %s" % (a4, gw or "no gateway")) if a4 else "IPv4 by DHCP",
        ", ".join(dns) or ("none" if a4 else "from DHCP"),
        ", IPv6 left as it is (%s)" % V6_WORDS.get(was_m, was_m or "?") if keep6 else ""))
    plan.append("the connection %s is brought up again with it - %s is cut off for a moment" % (con, dev))
    changed_ip = (method == "auto" and conf.get("ipv4_method") != "auto") or (bool(new_ip) and new_ip != old_ip)
    if d["answers"] and changed_ip:
        plan.append("fake-igd answers on %s: it finds the new address by itself within %s s" % (
            dev, ctx.cfg.get("interface_rescan_seconds", 60)))
    page = dev == now.get("page_dev")
    if page and changed_ip:
        plan.append("these pages are reached through %s: %s" % (
            dev, "they answer at %s from now - this page goes there, and you sign in again" % new_ip
            if new_ip else "with DHCP its address is whatever the DHCP server gives - this page may not find it again"))
    if trial_min:
        plan.append("on trial: unless Keep it is pressed within %d min, %s gets back by itself what it has now" % (trial_min, dev))
    else:
        plan.append("kept at once: there is no going back by itself (net_confirm_min is 0)")
    return {"dev": dev, "con": con, "hostname": host,
            "ipv4": {"method": method, "addr": str(a4) if a4 else "", "gw": gw, "dns": dns, "search": search},
            "ipv6": {"mode": "keep" if keep6 else mode6, "addr": str(a6) if a6 else "", "gw": g6, "dns": dns6},
            "old_ip": old_ip, "new_ip": new_ip, "old_hostname": host_old, "page": page,
            "changed_ip": changed_ip, "plan": plan}


# ---- the change, and its trial --------------------------------------------------------------
def trial_file(ctx):
    return os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web", "net-trial.json")


def trial(ctx):
    try:
        with open(trial_file(ctx)) as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def job(ctx):
    """The last change asked of root, with root's answer when it came."""
    j = ctx.store.meta_json("net:job") or {}
    if not j:
        return {}
    if j.get("state") == "asked":
        r = ctx.root_result()
        t = trial(ctx)
        if r.get("id") != j.get("ask") and j.get("snapshot") and t.get("snapshot") == j.get("snapshot"):
            # root's answer was written over by a later ask (Keep it): the trial says how it went
            r = {"id": j.get("ask"), "ok": True, "said": t.get("apply_said") or []}
        if r.get("id") == j.get("ask"):
            j["state"] = "done" if r.get("ok") else "failed"
            j["said"] = [str(x) for x in (r.get("said") or [])][:20]
            j["moved"] = time.time()
            ctx.store.set_meta("net:job", json.dumps(j))
            ctx.event("the network of %s %s: %s" % (j.get("dev"), "is changed" if j["state"] == "done"
                                                   else "was not changed", "; ".join(j["said"])[:900]),
                      "info" if j["state"] == "done" else "warn")
        elif time.time() - float(j.get("at") or 0) > 300:
            j["state"] = "failed"
            j["said"] = ["root did not answer in 5 minutes (is fake-igd-web.path running?)"]
            j["moved"] = time.time()
            ctx.store.set_meta("net:job", json.dumps(j))
    if j.get("state") in ("done", "failed"):
        if ctx.store.get_meta("net:seen") == str(j.get("ask")) or \
                time.time() - float(j.get("moved") or j.get("at") or 0) > JOB_KEEP_S:
            return {}
    return j


def view(ctx):
    host = ctx.arg("host")[:255]
    now = read(ctx.cfg, host, ctx.addr)
    t = trial(ctx)
    if t.get("state") != "trial" and time.time() - float(t.get("at") or 0) > JOB_KEEP_S:
        t = {}
    return {"now": now, "job": job(ctx), "trial": t, "trial_min": int(ctx.setting("net_confirm_min") or 0),
            "at": time.time(), "server_now": time.time()}


def get_net(ctx):
    ctx.need("fulladmin")
    return view(ctx)


def post_net(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    if act == "read":
        return view(ctx)
    if act == "hide":
        j = ctx.store.meta_json("net:job") or {}
        if j.get("state") not in ("done", "failed"):
            raise ValueError("the change is not over yet")
        ctx.store.set_meta("net:seen", str(j.get("ask")))
        return view(ctx)
    t = trial(ctx)
    if act in ("keep", "back"):
        if t.get("state") != "trial":
            raise ValueError("nothing is on trial")
        ident = ctx.ask_root({"do": act, "snapshot": t.get("snapshot")})
        ctx.event("%s asked to %s the new network of %s" % (
            me["name"], "keep" if act == "keep" else "put back the old instead of", t.get("con")),
                  "info" if act == "keep" else "warn")
        return {"message": "kept - within seconds" if act == "keep" else "the old network comes back within seconds",
                "id": ident}
    trial_min = int(ctx.setting("net_confirm_min") or 0)
    now = read(ctx.cfg, str(b.get("host") or "")[:255], ctx.addr)
    got = check(ctx, now, b.get("want"), trial_min)
    if act == "plan":
        return {"plan": got["plan"], "want": got}
    if act == "apply":
        with APPLY_LOCK:                # two admins at once: one change asked of root, not two
            return _apply(ctx, me, got, trial_min)
    raise ValueError("no such thing to do")


APPLY_LOCK = threading.Lock()


def _apply(ctx, me, got, trial_min):
    if trial(ctx).get("state") == "trial":
        raise ValueError("a change is on trial: keep it or put it back first")
    j = job(ctx)
    if j.get("state") == "asked":
        raise ValueError("a change is under way already")
    snap = secrets.token_hex(8)
    ident = ctx.ask_root({"do": "apply", "con": got["con"], "hostname": got["hostname"],
                          "ipv4": got["ipv4"], "ipv6": got["ipv6"], "trial_min": trial_min,
                          "snapshot": snap})
    ctx.store.set_meta("net:job", json.dumps({
        "ask": ident, "state": "asked", "at": time.time(), "by": me["name"], "dev": got["dev"],
        "con": got["con"], "plan": got["plan"], "old_ip": got["old_ip"], "new_ip": got["new_ip"],
        "page": got["page"], "snapshot": snap}))
    ctx.event("%s asked for a new network of %s: %s" % (me["name"], got["dev"], "; ".join(got["plan"])[:900]),
              "warn")
    return {"message": "asked: root puts it in now", "id": ident, "plan": got["plan"]}


def background(ctx):
    """Belt and braces: a trial whose timer did not go back (two minutes past its time) is put
    back by asking root."""
    t = trial(ctx)
    if t.get("state") != "trial":
        return
    if time.time() < float(t.get("until") or 0) + 120:
        return
    last = float(ctx.store.get_meta("net:back-asked") or 0)
    if time.time() - last < 300:
        return
    ctx.store.set_meta("net:back-asked", repr(time.time()))
    ctx.ask_root({"do": "back", "snapshot": t.get("snapshot"), "why": "not kept in time"})
    ctx.event("the new network of %s was not kept in time and its timer did not put the old back: "
              "root is asked to" % t.get("con"), "warn")


def get_trial(ctx):
    """What waits to be kept - for the banner on every page (otp's trials in /api/status): anybody
    signed in sees it; Keep it and Put the old back are a full administrator's (POST /api/net)."""
    ctx.need("readonly")
    t = trial(ctx)
    out = []
    if t.get("state") == "trial":
        j = ctx.store.meta_json("net:job") or {}
        out.append({"kind": "net", "con": t.get("con"), "dev": j.get("dev") if j.get("con") == t.get("con") else t.get("con"),
                    "until": float(t.get("until") or 0), "failed": t.get("failed") or ""})
    return {"trials": out, "now": time.time()}


ROUTES = {("GET", "/api/net"): get_net, ("POST", "/api/net"): post_net, ("GET", "/api/net/trial"): get_trial}
