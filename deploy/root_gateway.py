"""root_gateway.py - root's part of Settings → Gateway for devices (1.7.15).

A PS5 asks UPnP only of its default gateway: answered by fake-igd, with the real router as its
gateway, it never fetched the description. Here chosen devices - each by its IPv4 address, a name and,
best, its MAC - may use this server as their default gateway, and this server forwards their traffic
to the real router. And nothing else, ever: this server is the mDNS reflector between networks that
must stay apart, so it forwards nothing by default and never between its networks.

What root does, asked through the queue (kind "gateway") - from what the pages saved (the database's
meta "gateway", read only), never from the ask:

  do=apply   on (switched on, and at least one device on):
               1. the chain FAKE-IGD-FWD first in FORWARD (fake_igd_web.fwd_live): drops toward every
                  network of this server's interfaces and the special ranges, then for each device
                  -i IF -o IF -s ITS-IP [-m mac --mac-source ITS-MAC] ACCEPT (IF: the interface of this
                  server's default route, where the router is - in and out the same one: toward the
                  internet, never to another network of this server), and at the end a DROP of its
                  own (the way back goes from the router to the device directly) - nothing else is forwarded, whatever FORWARD's policy says;
                  kept in /etc/sysconfig/iptables between fake-igd's marks;
               2. only then /etc/sysctl.d/90-fake-igd-gateway.conf: net.ipv4.ip_forward = 1 and
                  send_redirects = 0 for all, default and every interface (an ICMP redirect would send
                  the device to the router directly), with sysctl -p of that file. What ip_forward and
                  send_redirects were is remembered.
             It is refused with fake-igd's firewall off (or firewalld in charge): ip_forward is global,
             so it is turned on only behind fake-igd's own chain with its DROP.
             off (or no device on): forwarding back as it was, the file and the chain taken away.
             ON TRIAL as every change of the firewall (fw_confirm_min); turning off never is. Anything
             refused half way puts everything back as it was.
  do=keep | back | expire   the banner's buttons, and the timer
  do=read    how it stands: forwarding, the chain, the packets forwarded for each device, the neighbours

IPv6 forwarding is never turned on. fake-igd's firewall turned off later (fake_igd_web.firewall)
turns the forwarding off with it (sync()).
State: web/gateway.json (root's, the group fake-igd may read it). Paths for tests: FAKE_IGD_SYSCTL_GW,
FAKE_IGD_PROC_SYS, FAKE_IGD_SYSCTL, FAKE_IGD_SYSTEMD_RUN, FAKE_IGD_IP (and fake_igd_web.py's).
"""
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

_MAIN = sys.modules.get("__main__")
if getattr(_MAIN, "CHAIN", None) == "FAKE-IGD-IN" and hasattr(_MAIN, "fw_status"):
    W = _MAIN
else:
    import fake_igd_web as W

SYSCTL_FILE = os.environ.get("FAKE_IGD_SYSCTL_GW", "/etc/sysctl.d/90-fake-igd-gateway.conf")
PROC = os.environ.get("FAKE_IGD_PROC_SYS", "/proc/sys")
SYSCTL = os.environ.get("FAKE_IGD_SYSCTL", "sysctl")
SYSTEMD_RUN = os.environ.get("FAKE_IGD_SYSTEMD_RUN", "systemd-run")
IP = os.environ.get("FAKE_IGD_IP", "ip")
STATE = W.GW_STATE
CHAIN = W.FWD_CHAIN
ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
DEV_ID_RE = re.compile(r"^[0-9a-f]{8,16}\Z")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}\Z")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
NAME_BAD = re.compile(r"[^A-Za-z0-9 ._()+,:/-]")
MOST_DEVICES = 32
# Never forwarded to, whatever the routes say: this network ("0"), loopback, link-local, multicast, reserved -
# and every private network (RFC 1918, the carrier's 100.64/10): through this server a device reaches the
# internet only, never a network behind the router either (1.8.0). Its own LAN it reaches directly.
NEVER = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
         "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
HELPER = os.path.join(os.path.dirname(os.path.abspath(W.__file__)), "fake_igd_web.py")


# ---- this server's networks --------------------------------------------------------------------------
def net_now():
    """{ifaces: {name: [addr/prefix]}, defif, router} - from ip(8); empty where it cannot be read."""
    out = {"ifaces": {}, "defif": "", "router": ""}
    try:
        r = subprocess.run([IP, "-o", "-4", "addr", "show"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
        for ln in r.stdout.splitlines():
            f = ln.split()
            if len(f) >= 4 and f[2] == "inet":
                dev = f[1].split("@")[0].rstrip(":")
                if dev != "lo" and IFACE_RE.match(dev):
                    try:
                        out["ifaces"].setdefault(dev, []).append(str(ipaddress.ip_interface(f[3])))
                    except ValueError:
                        pass
        r = subprocess.run([IP, "-4", "route", "show", "default"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        m = re.search(r"default via (\S+) dev (\S+)", r.stdout)
        if m and IFACE_RE.match(m.group(2)):
            ipaddress.ip_address(m.group(1))
            out["router"], out["defif"] = m.group(1), m.group(2)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return out


def device_checked(d, net):
    """A device as the pages saved it - each value checked here again; (device, why not)."""
    if not isinstance(d, dict):
        return None, "not a device"
    name = NAME_BAD.sub("", str(d.get("name") or "")).strip()[:40]
    if not name:
        return None, "a device without a name"
    try:
        ip = ipaddress.ip_address(str(d.get("ip") or "").strip())
    except ValueError:
        return None, "%s: not an IPv4 address" % name
    if ip.version != 4:
        return None, "%s: IPv4 only" % name
    mac = str(d.get("mac") or "").strip().lower().replace("-", ":")
    if mac and not MAC_RE.match(mac):
        return None, "%s: %s is not a MAC address" % (name, mac[:20])
    defs = [ipaddress.ip_interface(x) for x in (net.get("ifaces") or {}).get(net.get("defif") or "", [])]
    if not defs:
        return None, "this server has no default route - nothing can be forwarded toward a router"
    home = [x for x in defs if ip in x.network]
    if not home:
        return None, "%s: %s is not in the network of %s (%s), where the router is" % (
            name, ip, net["defif"], ", ".join(str(x.network) for x in defs))
    n = home[0].network
    if ip in (n.network_address, n.broadcast_address) or any(ip == x.ip for x in defs) or str(ip) == net.get("router"):
        return None, "%s: %s is not the address of a device there" % (name, ip)
    did = str(d.get("id") or "")
    return {"id": did if DEV_ID_RE.match(did) else secrets.token_hex(6), "name": name, "ip": str(ip), "mac": mac,
            "on": d.get("on") is not False}, ""


def wanted(net):
    meta = W.module_meta("gateway")
    s = W.module_settings()
    try:
        trial_min = int(s.get("fw_confirm_min", 5))
    except (TypeError, ValueError):
        trial_min = 5
    devices, why = [], []
    seen = set()
    for d in (meta.get("devices") if isinstance(meta.get("devices"), list) else [])[:MOST_DEVICES]:
        got, bad = device_checked(d, net)
        if bad:
            why.append(bad)
        elif got["ip"] in seen:
            why.append("%s: %s twice" % (got["name"], got["ip"]))
        else:
            seen.add(got["ip"])
            devices.append(got)
    return {"on": meta.get("on") is True, "devices": devices, "why": why, "trial_min": max(0, min(120, trial_min))}


def lines_for(devices, net):
    """The chain FAKE-IGD-FWD: never toward any network of this server or the special ranges; each device in
    and out the default route's interface only; a DROP at the end."""
    defif = net["defif"]
    blocked = []
    for addrs in (net.get("ifaces") or {}).values():
        for a in addrs:
            n = str(ipaddress.ip_interface(a).network)
            if n not in blocked:
                blocked.append(n)
    out = []
    for n in blocked + [x for x in NEVER if x not in blocked]:
        out.append("-A %s -d %s -m comment --comment \"fake-igd: never forwarded to %s\" -j DROP" % (CHAIN, n, n))
    for d in devices:
        mac = " -m mac --mac-source %s" % d["mac"] if d.get("mac") else ""
        out.append("-A %s -s %s/32 -i %s -o %s%s -m comment --comment \"fake-igd: gateway for %s (%s)\" -j ACCEPT"
                   % (CHAIN, d["ip"], defif, defif, mac, d["name"], d["ip"]))
    out.append("-A %s -m comment --comment \"fake-igd: nothing else is forwarded\" -j DROP" % CHAIN)
    return out


# ---- the state file -------------------------------------------------------------------------------
def state_read():
    try:
        with open(STATE, encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def state_write(st):
    st["at"] = time.time()
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".gateway.", dir=os.path.dirname(STATE))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1)
        os.fchmod(f.fileno(), 0o640)
        try:                                    # on the open file, never by name
            import grp
            os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
        except (KeyError, OSError):
            pass
    os.replace(tmp, STATE)


# ---- the kernel's switches ------------------------------------------------------------------------
def proc_read(key):
    try:
        with open(os.path.join(PROC, key), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return ""


def conf_ifaces():
    try:
        names = os.listdir(os.path.join(PROC, "net/ipv4/conf"))
    except OSError:
        return []
    return sorted(n for n in names if n not in ("all", "default", "lo") and IFACE_RE.match(n))


def sysctl_text(names):
    lines = ["# Written by fake-igd (Settings → Gateway for devices) - there only while devices use this server",
             "# as their gateway; taken away when the last one is switched off. What may be forwarded is",
             "# fake-igd's chain FAKE-IGD-FWD (first in FORWARD, a DROP at its end): only those devices, only",
             "# toward the default router.",
             "net.ipv4.ip_forward = 1",
             "# no ICMP redirect: it would tell a device to go to the router directly",
             "net.ipv4.conf.all.send_redirects = 0", "net.ipv4.conf.default.send_redirects = 0"]
    lines += ["net.ipv4.conf.%s.send_redirects = 0" % n.replace(".", "/") for n in names]
    return "\n".join(lines) + "\n"


def sysctl_set(key, value):
    r = subprocess.run([SYSCTL, "-q", "-w", "%s=%s" % (key, value)], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0:
        raise W.Refused("sysctl -w %s=%s: %s" % (key, value, r.stdout.strip()[:200]))


def before_now():
    redir = {k: proc_read("net/ipv4/conf/%s/send_redirects" % k) for k in ["all", "default"] + conf_ifaces()}
    return {"ip_forward": proc_read("net/ipv4/ip_forward") or "0",
            "send_redirects": {k: v for k, v in redir.items() if v in ("0", "1")}}


def sysctl_on(said):
    os.makedirs(os.path.dirname(SYSCTL_FILE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fake-igd-gateway.", dir=os.path.dirname(SYSCTL_FILE))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(sysctl_text(conf_ifaces()))
        os.fchmod(f.fileno(), 0o644)
    os.replace(tmp, SYSCTL_FILE)
    r = subprocess.run([SYSCTL, "-q", "-p", SYSCTL_FILE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    if r.returncode != 0:
        raise W.Refused("sysctl -p %s: %s" % (SYSCTL_FILE, r.stdout.strip()[:300]))
    if proc_read("net/ipv4/ip_forward") != "1":
        raise W.Refused("net.ipv4.ip_forward is still 0 after sysctl -p - something keeps it off")
    said.append("forwarding on (net.ipv4.ip_forward = 1, no ICMP redirects) - %s, kept over a reboot" % SYSCTL_FILE)


def sysctl_off(before, said):
    had = os.path.exists(SYSCTL_FILE)
    if had:
        os.unlink(SYSCTL_FILE)
    fwd = str((before or {}).get("ip_forward") or "0")
    fwd = fwd if fwd in ("0", "1") else "0"
    if proc_read("net/ipv4/ip_forward") not in ("", fwd):
        sysctl_set("net.ipv4.ip_forward", fwd)
    for k, v in sorted(((before or {}).get("send_redirects") or {}).items()):
        if (k in ("all", "default") or IFACE_RE.match(k)) and v in ("0", "1") and \
                proc_read("net/ipv4/conf/%s/send_redirects" % k) not in ("", v):
            try:
                sysctl_set("net.ipv4.conf.%s.send_redirects" % k.replace(".", "/"), v)
            except W.Refused:
                pass                            # an interface gone since: nothing to put back on it
    if had:
        said.append("forwarding as it was before (net.ipv4.ip_forward = %s) - %s taken away" % (fwd, SYSCTL_FILE))


# ---- putting it in --------------------------------------------------------------------------------
def fw_ready(cfg):
    """Why the forwarding may not be turned on here - "" when fake-igd's chain with its DROP can carry it."""
    if not W.have_iptables():
        return "iptables is not on this machine"
    if W.fw_backend() == "firewalld":
        return "firewalld is in charge of this machine's firewall - fake-igd's chain with its DROP cannot be put in"
    if not W.flag(cfg.get("firewall"), False):
        return "fake-igd's firewall is off - switch it on (Settings → Firewall and access): forwarding is turned " \
               "on only behind fake-igd's own FORWARD chain, which ends in a DROP"
    return ""


def snapshot():
    try:
        with open(SYSCTL_FILE, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        text = None
    return {"sysctl": text, "proc": before_now(), "live": W.fw_saved_now(), "files": W.fw_file_snapshot()}


def restore(snap):
    try:
        if snap["sysctl"] is None:
            if os.path.exists(SYSCTL_FILE):
                os.unlink(SYSCTL_FILE)
        else:
            with open(SYSCTL_FILE, "w", encoding="utf-8") as f:
                f.write(snap["sysctl"])
        p = snap["proc"]
        sysctl_set("net.ipv4.ip_forward", p.get("ip_forward") or "0")
        for k, v in (p.get("send_redirects") or {}).items():
            try:
                sysctl_set("net.ipv4.conf.%s.send_redirects" % k.replace(".", "/"), v)
            except W.Refused:
                pass
    except (OSError, W.Refused):
        pass
    W.fw_put_live_back(snap["live"])
    W.fw_file_put_back(snap["files"])


def chain_off(said):
    if W.fwd_live_off():
        said.append("%s and its jump taken out of FORWARD" % CHAIN)
    f = W.fwd_file(None) if os.path.isfile(W.IPT_FILE) else ""
    if f:
        said.append(f)


def put(st, on, devices, net, said):
    """The gateway as asked, put in - all of it or nothing (everything put back on a refusal). Returns what
    was put in before."""
    snap = snapshot()
    was = {"on": st.get("on") is True, "devices": list(st.get("devices") or [])}
    active = [d for d in devices if d.get("on")]
    try:
        if on and active:
            why = fw_ready(W.read_config())
            if why:
                raise W.Refused("the gateway for devices cannot be switched on: %s" % why)
            W.fwd_live(lines_for(active, net))
            fv = W.forward_view()
            if not (fv.get("chain") and fv.get("ours_first") and fv.get("ends_drop")):
                raise W.Refused("%s is not first in FORWARD with its DROP at the end - forwarding not turned on" % CHAIN)
            said.append("%s first in FORWARD: %s, in and out %s toward %s only - nothing else is forwarded"
                        % (CHAIN, ", ".join("%s (%s%s)" % (d["name"], d["ip"], ", its MAC" if d["mac"] else "")
                                            for d in active), net["defif"], net["router"] or "the router"))
            f = W.fwd_file(lines_for(active, net))
            if f:
                said.append(f)
            if not was["on"] or not isinstance(st.get("before"), dict):
                st["before"] = before_now()
            sysctl_on(said)
            said.append("IPv6 forwarding is not turned on: the devices' IPv6 goes as it went")
            st.update(on=True, devices=devices, defif=net["defif"], router=net["router"])
            st.pop("why_off", None)
        else:
            sysctl_off(st.get("before"), said)      # forwarding off first, then the chain
            chain_off(said)
            st.pop("before", None)
            st.update(on=False, devices=devices)
            if on and not active:
                said.append("no device is switched on - nothing is forwarded")
        state_write(st)
    except BaseException as e:
        st["on"], st["devices"] = was["on"], was["devices"]
        try:
            state_write(st)
        except OSError:
            pass
        restore(snap)
        if isinstance(e, (W.Refused, OSError, subprocess.SubprocessError)):
            raise W.Refused("refused, everything put back as it was: %s" % e)
        raise
    return was


def sync(cfg):
    """After every change of fake-igd's firewall (fake_igd_web.firewall): the chain put in again with the
    networks as they are now - or, the firewall off, the forwarding turned off and the chain taken away."""
    st = state_read()
    said = []
    if st.get("on") is not True:
        if subprocess.run(["iptables", "-S", CHAIN], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0 if shutil.which("iptables") else False:
            chain_off(said)
        return said
    why = fw_ready(cfg)
    if why:
        sysctl_off(st.get("before"), said)
        chain_off(said)
        st.pop("before", None)
        st.update(on=False, why_off=why)
        state_write(st)
        return ["gateway for devices off: %s" % why] + said
    net = net_now()
    active = [d for d in st.get("devices") or [] if d.get("on")]
    if not net["defif"] or not active:
        return said
    W.fwd_live(lines_for(active, net))
    f = W.fwd_file(lines_for(active, net))
    return ["gateway for devices: %s first in FORWARD again" % CHAIN] + ([f] if f else [])


# ---- the trial (as every change of the firewall) -------------------------------------------------
def pending(t):
    return isinstance(t, dict) and bool(t) and not t.get("done") and bool(ID_RE.match(str(t.get("id") or "")))


def timer(t):
    if not shutil.which(SYSTEMD_RUN):
        return "no systemd-run here - the pages' API asks for the put-back when the time is over"
    secs = max(1, int(float(t["until"]) - time.time()) + 2)
    unit = "fake-igd-gw-back-%s-%d" % (t["id"], int(float(t["until"])))
    r = subprocess.run([SYSTEMD_RUN, "--quiet", "--unit", unit, "--on-active=%ds" % secs,
                        "--timer-property=AccuracySec=1s", "/usr/bin/python3", "-I", HELPER, "--kind", "gateway",
                        json.dumps({"do": "expire", "id": t["id"]})],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0:
        return "the timer could not be started (%s) - the pages' API asks for the put-back" % r.stdout.strip()[:200]
    return ""


def neighbours():
    """The neighbour table (ip neigh): {address: mac} - to offer a device's MAC."""
    out = {}
    try:
        r = subprocess.run([IP, "-4", "neigh", "show"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
        for ln in r.stdout.splitlines():
            m = re.match(r"^(\S+) dev (\S+) lladdr (\S+)", ln)
            if m and MAC_RE.match(m.group(3).lower()):
                out[m.group(1)] = m.group(3).lower()
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def read(st=None):
    """How it stands now - also written into the state file, with when each device last went through."""
    st = st if st is not None else state_read()
    fv = W.forward_view()
    seen = st.get("seen") if isinstance(st.get("seen"), dict) else {}
    now = time.time()
    for ip, n in (fv.get("counters") or {}).items():
        was = seen.get(ip) or {}
        if n["out_pkts"] > int(was.get("pkts") or 0):
            seen[ip] = {"pkts": n["out_pkts"], "changed": now}
        elif n["out_pkts"] < int(was.get("pkts") or 0):
            seen[ip] = {"pkts": n["out_pkts"], "changed": was.get("changed") or 0}   # counters zeroed
    ips = [d.get("ip") for d in st.get("devices") or []]
    st["seen"] = {k: v for k, v in seen.items() if k in ips}
    cfg = W.read_config()
    st["live"] = {"ip_forward": proc_read("net/ipv4/ip_forward"),
                  "ip6_forward": proc_read("net/ipv6/conf/all/forwarding"),
                  "redirects": proc_read("net/ipv4/conf/all/send_redirects"), "file": os.path.exists(SYSCTL_FILE),
                  "forward": fv, "firewall": W.flag(cfg.get("firewall"), False), "ready": fw_ready(cfg),
                  "net": net_now(), "neigh": neighbours(), "read_at": now}
    state_write(st)
    return st


def report(st, said, ok=True):
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    return {"ok": ok, "said": said, "on": st.get("on") is True, "devices": st.get("devices") or [],
            "live": st.get("live") or {}, "seen": st.get("seen") or {}, "why_off": st.get("why_off") or "",
            "trial": {k: t.get(k) for k in ("id", "until", "min", "by", "at", "done", "done_by", "done_at", "was")}}


def apply(by):
    net = net_now()
    w = wanted(net)
    st = state_read()
    said = ["left out: %s" % x for x in w["why"]]
    was = put(st, w["on"], w["devices"], net, said)
    now = (st.get("on") is True, [d for d in st.get("devices") or [] if d.get("on")])
    changed = now != (was["on"], [d for d in was["devices"] if d.get("on")] if was["on"] else [])
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    if changed and now[0] and w["trial_min"]:
        if not pending(t):
            t = {"id": secrets.token_hex(6), "at": time.time(), "by": by, "was": was}
        t.update(until=time.time() + w["trial_min"] * 60, min=w["trial_min"], last_by=by)
        st["trial"] = t
        said.append("on trial: it goes back by itself unless kept within %d min" % w["trial_min"])
        tw = timer(t)
        if tw:
            said.append(tw)
    elif changed and pending(t):
        # Off, or kept at once, while a trial waited: that one is over too.
        t.update(done="kept" if now[0] else "off", done_by=by, done_at=time.time())
        st["trial"] = t
    if not changed:
        said.append("as it was already - put in again")
    return report(read(st), said)


def put_back(st, why):
    t = st["trial"]
    was = t.get("was") if isinstance(t.get("was"), dict) else {}
    said = ["the gateway for devices goes back to what it was before %s: %s"
            % (time.strftime("%H:%M", time.localtime(float(t.get("at") or 0))), why)]
    net = net_now()
    devices = []
    for d in was.get("devices") or []:
        got, bad = device_checked(d, net)
        if got:
            devices.append(got)
    t.update(done="back", done_by=why, done_at=time.time())
    st["trial"] = t
    put(st, was.get("on") is True, devices, net, said)
    return report(read(st), said)


def trial_do(action, payload, by):
    st = state_read()
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    if not pending(t) or (payload.get("id") and str(payload.get("id")) != t.get("id")):
        return report(read(st), ["no change of the gateway for devices waits to be kept"])
    if action == "keep":
        if time.time() > float(t.get("until") or 0):
            raise W.Refused("the time to keep it is over - it is being put back")
        t.update(done="kept", done_by=by, done_at=time.time())
        st["trial"] = t
        return report(read(st), ["%s kept the gateway for devices" % (by or "somebody")])
    if action == "back":
        return put_back(st, "put back by %s" % (by or "somebody"))
    if time.time() + 2 >= float(t.get("until") or 0):
        return put_back(st, "not kept within %d min" % int(t.get("min") or 0))
    return report(read(st), ["not yet - it waits to be kept until %s"
                             % time.strftime("%H:%M:%S", time.localtime(float(t["until"])))])


def serve(payload, ask):
    r = payload if isinstance(payload, dict) else {}
    by = str((ask or {}).get("by") or "")[:80]
    what = str(r.get("do") or "")
    if what == "apply":
        return apply(by)
    if what == "read":
        return report(read(), ["read"])
    if what in ("keep", "back", "expire"):
        got = trial_do(what, r, by)
        if (ask or {}).get("by") == "the command line":
            # From the timer (fake_igd_web.py --kind gateway): the pages read it as any other answer.
            W.write_kind_result("gateway", dict(got, id="timer", by="the timer"))
        return got
    raise W.Refused("apply, read, keep, back or expire")
