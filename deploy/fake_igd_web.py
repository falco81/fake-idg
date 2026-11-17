#!/usr/bin/python3 -I
"""fake_igd_web.py - what the pages ask for that needs root (1.4.0).

The same shape as otp's otp_web.py. The API runs as `fake-igd` and may not
do any of this: it lays a request down in /var/lib/fake-igd/web/apply.ask and
systemd (fake-igd-web.path) starts this as root, which then:

  * puts the pages' allow list (web_allow) into nginx's fake-igd.conf, between
    `# ADMIN-ALLOW-BEGIN` and `# ADMIN-ALLOW-END`; nginx is asked (nginx -t)
    before it is reloaded and the file put back as it was when it says no;
  * puts fake-igd's own iptables chain in place - as otp's OTP-IN:

        INPUT ─► FAKE-IGD-IN: what fake-igd needs ─► the rest of INPUT

    FAKE-IGD-IN holds ACCEPT rules only: loopback, answers to connections this
    machine opened, SSH and ping (each can be switched off), SSDP 1900/udp and
    the description/SOAP port on the interfaces fake-igd answers on, and 80/443
    from web_allow. Anything it does not match goes back to INPUT and on to the
    rules that were there before - fake-igd never changes those. Put in at once
    (iptables-restore --noflush) and into /etc/sysconfig/iptables between lines
    that start `# fake-igd:`, checked with iptables-restore --test first;
  * restarts fake-igd.service when a setting it uses was changed;
  * changes avahi-daemon.conf (the mDNS reflector) and starts, stops or restarts
    avahi-daemon - through upnp_mdns.apply, the same as `upnp mdns`: every value
    checked, a copy kept beside the file, put back when the daemon does not come
    up with the change (1.5.0).

Nothing in the request is trusted: the values are read from config.json and
each is checked against the one shape it may have before it goes into a file.

  fake_igd_web.py                   serve apply.ask (as root, from systemd)
  fake_igd_web.py --apply           the same by hand: nginx's list and the firewall as config.json says
  fake_igd_web.py --firewall-off    the chain and its jump taken away (live and in the file)
  fake_igd_web.py --status          what is in place here (JSON)
"""
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

CONFIG = os.environ.get("FAKE_IGD_CONFIG", "/etc/fake-igd/config.json")
STATE_DIR = os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd")
WEB_DIR = os.path.join(STATE_DIR, "web")
NGINX_CONF = os.environ.get("FAKE_IGD_NGINX", "/etc/nginx/conf.d/fake-igd.conf")
IPT_FILE = os.environ.get("FAKE_IGD_IPTABLES_FILE", "/etc/sysconfig/iptables")
CHAIN = "FAKE-IGD-IN"
MARK = "# fake-igd:"
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}\Z")
# The rules `upnp firewall | sh` of 1.3 put straight into INPUT, by hand (1.4.1): with the
# chain in place they say nothing more, and they are taken out when it is put in place.
OLD_RE = re.compile(r'^-A INPUT (?:.* )?-m comment --comment "?fake-igd"? -j ACCEPT$')
# SSH's ports as the SSH pane set them (1.6.0): root_sshd says which; 22 when it cannot.
SSH_PORTS_FROM_SSHD = True


def ssh_ports():
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)          # -I keeps the script's folder out of the path
        import root_sshd
        got = [int(p) for p in root_sshd.ssh_ports() if 0 < int(p) < 65536]
        return got or [22]
    except Exception:                         # noqa: BLE001 - never without SSH
        return [22]


DEFAULT_ALLOW = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]


class Refused(Exception):
    pass


def run(cmd, data=None, ok=(0,)):
    r = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=120)
    if r.returncode not in ok:
        raise Refused("%s: %s" % (" ".join(cmd[:3]), (r.stderr or r.stdout).strip()[:400]))
    return r


def read_config():
    fd = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, encoding="utf-8") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused("%s is not a file" % CONFIG)
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise Refused("%s holds no settings" % CONFIG)
    return cfg


def nets(values):
    out = []
    for one in values if isinstance(values, list) else []:
        try:
            n = ipaddress.ip_network(str(one).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4:
            out.append(str(n))
    return out


def ifaces(values):
    return [str(x) for x in (values if isinstance(values, list) else []) if IFACE_RE.match(str(x))]


def port(v, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return v if 0 < v < 65536 else default


def flag(v, default):
    return v if isinstance(v, bool) else default


# ---- nginx: who may reach the pages ------------------------------------------------
HEALTH_BEGIN = "        # HEALTH-ALLOW-BEGIN - who may ask /healthz (Settings → Firewall and access)"
HEALTH_END = "        # HEALTH-ALLOW-END"
REALIP_BEGIN = "    # FAKE-IGD-REALIP-BEGIN - behind a load balancer or WAF, as set on the pages\n"
REALIP_END = "    # FAKE-IGD-REALIP-END\n"
HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}\Z")


def allow_nets(values):
    """Addresses and networks of a list, IPv4 and IPv6 alike, each once."""
    out = []
    for one in values if isinstance(values, list) else []:
        try:
            n = str(ipaddress.ip_network(str(one).strip(), strict=False))
        except ValueError:
            continue
        if n not in out:
            out.append(n)
    return out


def health_of(cfg):
    """Who may ask /healthz: config.json's health_allow ([] everybody), or - never set - the same
    networks as the pages (as before 1.6.1, when the firewall's 80/443 said it alone)."""
    if isinstance(cfg.get("health_allow"), list):
        return cfg["health_allow"]
    allow = cfg.get("web_allow", DEFAULT_ALLOW)
    return allow if isinstance(allow, list) else []


def realip_checked(s):
    """Behind a load balancer or WAF (otp's web_proxy*, the pages' settings): (nets, header, recursive) -
    nets empty when it is off or names nobody (the header of anybody else is never believed)."""
    if s.get("web_proxy") is not True:
        return [], "", False
    raw = s.get("web_proxy_from") or []
    if isinstance(raw, str):
        raw = re.split(r"[\s,;]+", raw)
    nets = allow_nets(raw)
    head = str(s.get("web_proxy_header") or "X-Forwarded-For").strip()
    if not HEADER_RE.match(head) or head.lower() in ("host", "cookie", "authorization"):
        head = "X-Forwarded-For"
    return nets, head, s.get("web_proxy_recursive") is not False


def nginx_text(text, cfg, realip=None):
    """fake-igd.conf with the allow lists and the real_ip lines as set - (new text, words)."""
    allow = cfg.get("web_allow", DEFAULT_ALLOW)
    # IPv4 and IPv6 alike (1.6.0): nginx takes both; only the firewall's chain is per family.
    both = allow_nets(allow)
    lines = ["        allow %s;" % n for n in both] if allow else ["        allow all;"]
    if allow and not both:
        lines = ["        # nothing in web_allow is an address or a network - only this machine"]
    new, n = re.subn(r"(# ADMIN-ALLOW-BEGIN[^\n]*\n)(.*?)(\n[ \t]*# ADMIN-ALLOW-END)",
                     lambda m: m.group(1) + "\n".join(lines) + m.group(3), text, flags=re.S)
    if not n:
        raise Refused("the allow list's marks are not in %s - left as it is" % NGINX_CONF)
    words = ["the pages may be reached from %s" % (", ".join(both) if allow else "everybody")]
    # The health check (otp's third row): everybody, or these - and this machine always.
    health = health_of(cfg)
    hn = allow_nets(health)
    new = re.sub(r"%s\n.*?%s\n" % (re.escape(HEALTH_BEGIN), re.escape(HEALTH_END)), "", new, flags=re.S)
    if hn:
        m = re.search(r"(?m)^[ \t]*location[ \t]*=[ \t]*/healthz[ \t]*\{[^\n]*\n", new)
        if m:
            block = HEALTH_BEGIN + "\n" + "".join("        allow %s;\n" % x for x in hn) + \
                "        allow 127.0.0.1;\n        allow ::1;\n        deny  all;\n" + HEALTH_END + "\n"
            new = new[:m.end()] + block + new[m.end():]
            words.append("/healthz from %s" % ", ".join(hn))
        else:
            words.append("no location = /healthz in %s - its list is not put in" % NGINX_CONF)
    # Behind a load balancer or WAF: nginx takes the client's address from the header - only when the
    # request comes from one of them.
    if realip is not None:
        nets, head, rec = realip
        new = re.sub(r"%s.*?%s" % (re.escape(REALIP_BEGIN), re.escape(REALIP_END)), "", new, flags=re.S)
        if nets:
            m = re.search(r"(?m)^[ \t]*listen[ \t]+(?:\S+:)?443\b[^\n]*\n", new)
            if not m:
                raise Refused("no server listening on 443 in %s - the balancer's lines are not put in" % NGINX_CONF)
            lines = REALIP_BEGIN + "".join("    set_real_ip_from %s;\n" % x for x in nets) + \
                "    real_ip_header %s;\n    real_ip_recursive %s;\n" % (head, "on" if rec else "off") + REALIP_END
            new = new[:m.end()] + lines + new[m.end():]
            words.append("the client's address from %s when it comes from %s" % (head, ", ".join(nets)))
    return new, words


def nginx_allow(cfg):
    if not os.path.isfile(NGINX_CONF) or os.path.islink(NGINX_CONF):
        return "no %s here" % NGINX_CONF
    with open(NGINX_CONF, encoding="utf-8") as f:
        text = f.read()
    try:
        new, words = nginx_text(text, cfg, realip_checked(module_settings()))
    except Refused as e:
        return str(e)
    if new == text:
        return "nginx: as it was"
    keep = NGINX_CONF + ".before-fake-igd"
    shutil.copy2(NGINX_CONF, keep)
    folder = os.path.dirname(NGINX_CONF)
    fd, tmp = tempfile.mkstemp(prefix=".fake-igd.", dir=folder)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(tmp, 0o644)
    os.replace(tmp, NGINX_CONF)
    try:
        t = subprocess.run([os.environ.get("FAKE_IGD_NGINX_BIN", "nginx"), "-t"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
    except OSError as e:
        os.replace(keep, NGINX_CONF)
        raise Refused("nginx could not be asked (%s), the file was put back" % e)
    if t.returncode != 0:
        os.replace(keep, NGINX_CONF)
        raise Refused("nginx -t refused the new allow list, the file was put back: %s" % t.stdout.strip()[-300:])
    os.unlink(keep)
    subprocess.run(["systemctl", "reload", "nginx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "nginx: %s" % "; ".join(words)


# ---- iptables / ip6tables: FAKE-IGD-IN ---------------------------------------------
# As otp's OTP-IN (1.6.0): the chain starts with what no rule may shut out (loopback, answers to
# what this machine asked, IPv6's neighbour discovery), then the rules of your own in their order
# (kept in firewall-rules.json beside config.json, written by root alone), then what fake-igd's
# functions need - each of those can be switched off. For IPv4 and, where ip6tables is there,
# IPv6 (UPnP is IPv4 only; SSH, ping and the pages are not).
IP6T_FILE = os.environ.get("FAKE_IGD_IP6TABLES_FILE", "/etc/sysconfig/ip6tables")
FW_RULES = os.environ.get("FAKE_IGD_FW_RULES", os.path.join(os.path.dirname(CONFIG), "firewall-rules.json"))
FW_FILES = {4: IPT_FILE, 6: IP6T_FILE}
FW_TOOLS = {4: ("iptables", "iptables-restore", "iptables-save"),
            6: ("ip6tables", "ip6tables-restore", "ip6tables-save")}
FW_PROTOS = ("tcp", "udp", "icmp", "vrrp", "any")
FW_ACTIONS = ("accept", "drop", "reject")
# What can be switched off: ssh and icmp are config.json's firewall_ssh / firewall_icmp (as before),
# the rest are kept in firewall-rules.json ("off").
FW_OPTIONAL = ("ssh", "icmp", "dhcpv6", "upnp", "pages", "snmp")
FW_OFF_KEYS = ("dhcpv6", "upnp", "pages", "snmp")
FW_MOST_RULES = 100
NOTE_RE = re.compile(r"[^A-Za-z0-9 ._:/@()+,-]")
RULE_ID_RE = re.compile(r"^[A-Za-z0-9]{1,24}\Z")
PORT_RE = re.compile(r"^([0-9]{1,5})(?:-([0-9]{1,5}))?\Z")


def nets_of(values, fam):
    """The addresses and networks of a list that are IPv`fam`, as iptables writes them."""
    out = []
    for one in values if isinstance(values, list) else []:
        try:
            n = ipaddress.ip_network(str(one).strip(), strict=False)
        except ValueError:
            continue
        if n.version == fam and str(n) not in out:
            out.append(str(n))
    return out


def fw_rule_checked(x):
    """A rule of somebody's, as it is kept - every value checked against the one shape it may have."""
    if not isinstance(x, dict):
        raise Refused("a firewall rule is not an object")
    try:
        fam = int(x.get("family") or 0)
    except (TypeError, ValueError):
        fam = -1
    if fam not in (0, 4, 6):
        raise Refused("a rule is for IPv4, IPv6 or both")
    proto = str(x.get("proto") or "any")
    if proto not in FW_PROTOS:
        raise Refused("the protocol is one of %s" % ", ".join(FW_PROTOS))
    port = re.sub(r"\s", "", str(x.get("port") or ""))
    if port:
        if proto not in ("tcp", "udp"):
            raise Refused("a port is for TCP or UDP")
        parts = port.split(",")
        for p in parts:
            m = PORT_RE.match(p)
            if not m or not 1 <= int(m.group(1)) <= 65535 or \
                    (m.group(2) and not int(m.group(1)) <= int(m.group(2)) <= 65535):
                raise Refused("%s is not a port or a range (80, 8000-8100, 80,443)" % p[:20])
        if sum(2 if "-" in p else 1 for p in parts) > 15:
            raise Refused("fifteen ports at most in one rule (a range counts as two)")
    raw = x.get("sources")
    if raw is None:
        raw = x.get("source") or ""
    if isinstance(raw, str):
        raw = [s for s in re.split(r"[\s,;]+", raw) if s]
    if not isinstance(raw, list):
        raise Refused("the sources are a list of addresses or networks")
    if len(raw) > 20:
        raise Refused("twenty addresses or networks at most in one rule")
    srcs = []
    for s in raw:
        try:
            n = ipaddress.ip_network(str(s).strip(), strict=False)
        except ValueError:
            raise Refused("%s is not an address or a network" % str(s)[:60])
        if fam and n.version != fam:
            raise Refused("%s is not an IPv%d address" % (n, fam))
        if str(n) not in srcs:
            srcs.append(str(n))
    if srcs and not fam and len({ipaddress.ip_network(s).version for s in srcs}) == 1:
        fam = ipaddress.ip_network(srcs[0]).version
    iface = str(x.get("iface") or "").strip()
    if iface and not IFACE_RE.match(iface):
        raise Refused("%s is not the name of an interface" % iface[:20])
    action = str(x.get("action") or "accept")
    if action not in FW_ACTIONS:
        raise Refused("a rule accepts, drops or rejects")
    note = NOTE_RE.sub("", str(x.get("note") or ""))[:80].strip()
    rid = str(x.get("id") or "")
    if not RULE_ID_RE.match(rid):
        rid = "r" + os.urandom(5).hex()
    return {"id": rid, "family": fam, "proto": proto, "port": port, "sources": srcs, "iface": iface,
            "action": action, "note": note, "disabled": x.get("disabled") is True}


def fw_rules_checked(rules):
    if not isinstance(rules, list):
        raise Refused("the rules are a list")
    if len(rules) > FW_MOST_RULES:
        raise Refused("%d rules at most" % FW_MOST_RULES)
    out, seen = [], set()
    for x in rules:
        r = fw_rule_checked(x)
        while r["id"] in seen:
            r["id"] = (r["id"] + "x")[-24:]
        seen.add(r["id"])
        out.append(r)
    return out


def load_fw_conf(path=None):
    """firewall-rules.json: {"rules": [...], "off": [...]} - each rule checked again as it is read."""
    conf = {"rules": [], "off": []}
    try:
        with open(path or FW_RULES, encoding="utf-8") as f:
            got = json.load(f)
    except (OSError, ValueError):
        return conf
    if not isinstance(got, dict):
        return conf
    for x in (got.get("rules") if isinstance(got.get("rules"), list) else [])[:FW_MOST_RULES]:
        try:
            conf["rules"].append(fw_rule_checked(x))
        except Refused:
            continue
    conf["off"] = [k for k in FW_OFF_KEYS if k in (got.get("off") if isinstance(got.get("off"), list) else [])]
    for k in ("at", "by"):
        if isinstance(got.get(k), (str, int, float)):
            conf[k] = got[k]
    return conf


def write_fw_conf(conf, path=None):
    """Root's alone, the API's group may read it (the pages show the rules)."""
    path = path or FW_RULES
    body = {"rules": fw_rules_checked(conf.get("rules") or []),
            "off": [k for k in FW_OFF_KEYS if k in (conf.get("off") or [])],
            "at": time.time(), "by": str(conf.get("by") or "")[:80]}
    fd, tmp = tempfile.mkstemp(prefix=".firewall-rules.", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=1)
        f.write("\n")
        os.fchmod(f.fileno(), 0o640)
        try:   # on the open file, never by name
            import grp
            os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
        except (KeyError, OSError):
            pass
    os.replace(tmp, path)
    return body


def fw_rule_lines(r, fam):
    """A rule of somebody's as the lines of the chain for IPv`fam` (none when it is not for it)."""
    if r.get("disabled") or (r["family"] and r["family"] != fam):
        return []
    srcs = [s for s in r["sources"] if ipaddress.ip_network(s).version == fam]
    if r["sources"] and not srcs:
        return []
    out = []
    for s in srcs or [None]:
        a = ["-A", CHAIN]
        if r["iface"]:
            a += ["-i", r["iface"]]
        if s:
            a += ["-s", s]
        if r["proto"] != "any":
            a += ["-p", "ipv6-icmp" if (r["proto"] == "icmp" and fam == 6) else r["proto"]]
        if r["port"]:
            if "," in r["port"]:
                a += ["-m", "multiport", "--dports", r["port"].replace("-", ":")]
            else:
                a += ["-m", r["proto"], "--dport", r["port"].replace("-", ":")]
        a += ["-m", "comment", "--comment", "\"fake-igd: %s\"" % (r["note"] or "a rule of yours")]
        a += ["-j", r["action"].upper()]
        out.append(" ".join(a))
    return out


def builtin(cfg, conf=None, pages_here=None):
    """What fake-igd lets in by itself: [{key, title, why, fixed, on, lines {4, 6}, rules}] - the
    first one (loopback and answers) always, ahead of the rules of your own; the rest after them."""
    conf = conf if conf is not None else load_fw_conf()
    off = conf.get("off") or []

    def show(fam, proto, port="", source="", iface=""):
        return {"family": fam, "proto": proto, "port": port, "source": source, "iface": iface}

    def c(words):
        return "-m comment --comment \"fake-igd: %s\"" % words

    items = []
    base6 = ["-A %s -i lo -j ACCEPT" % CHAIN,
             "-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" % CHAIN]
    base6 += ["-A %s -p ipv6-icmp -m icmp6 --icmpv6-type %d %s -j ACCEPT" % (CHAIN, t, c("neighbour discovery"))
              for t in (133, 134, 135, 136)]
    items.append({"key": "base", "title": "Loopback and answers", "fixed": True, "on": True,
                  "why": "the machine itself (lo), answers to connections it opened (DNS, ntfy, upgrades), and "
                         "IPv6's neighbour discovery - ahead of every rule, so none can shut them out",
                  "lines": {4: ["-A %s -i lo -j ACCEPT" % CHAIN,
                                "-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" % CHAIN],
                            6: base6},
                  "rules": [dict(show(0, "any", iface="lo"), words="everything on lo"),
                            dict(show(0, "any"), words="answers (ESTABLISHED, RELATED)"),
                            dict(show(6, "icmp"), words="ICMPv6 133-136 (neighbour discovery)")]})
    sshp = ssh_ports()
    items.append({"key": "ssh", "title": "SSH", "fixed": False, "on": flag(cfg.get("firewall_ssh"), True),
                  "why": "to manage the machine - turned off, take care to keep a rule of your own for it",
                  "lines": {f: ["-A %s -p tcp -m tcp --dport %d %s -j ACCEPT" % (CHAIN, p, c("ssh")) for p in sshp]
                            for f in (4, 6)},
                  "rules": [show(f, "tcp", str(p)) for f in (4, 6) for p in sshp]})
    items.append({"key": "icmp", "title": "ICMP / ICMPv6", "fixed": False, "on": flag(cfg.get("firewall_icmp"), True),
                  "why": "ping; IPv6 cannot work without ICMPv6 (neighbour discovery is let in above all the same)",
                  "lines": {4: ["-A %s -p icmp %s -j ACCEPT" % (CHAIN, c("ping"))],
                            6: ["-A %s -p ipv6-icmp %s -j ACCEPT" % (CHAIN, c("ping"))]},
                  "rules": [show(4, "icmp"), show(6, "icmp")]})
    items.append({"key": "dhcpv6", "title": "DHCPv6 client", "fixed": False, "on": "dhcpv6" not in off,
                  "why": "answers of a DHCPv6 server, for an address given that way",
                  "lines": {4: [], 6: ["-A %s -s fe80::/10 -p udp -m udp --dport 546 %s -j ACCEPT"
                                       % (CHAIN, c("dhcpv6 client"))]},
                  "rules": [show(6, "udp", "546", "fe80::/10")]})
    http = port(cfg.get("http_port"), 5000)
    want = ifaces(cfg.get("interfaces"))
    skip = [i for i in ifaces(cfg.get("exclude_interfaces", ["lo"])) if i != "lo"]
    up = []
    # Excluded interfaces first, back to INPUT: one "! -i" per rule only, so they are sent back.
    for i in skip:
        up.append("-A %s -i %s -p udp -m udp --dport 1900 -j RETURN" % (CHAIN, i))
        up.append("-A %s -i %s -p tcp -m tcp --dport %d -j RETURN" % (CHAIN, i, http))
    for i in (want or [None]):
        on = (" -i %s" % i) if i else ""
        up.append("-A %s%s -p udp -m udp --dport 1900 %s -j ACCEPT" % (CHAIN, on, c("ssdp")))
        up.append("-A %s%s -p tcp -m tcp --dport %d %s -j ACCEPT" % (CHAIN, on, http, c("description and soap")))
    # answers to `upnp test` from this machine (SSDP answers come from port 1900 of whoever answers)
    up.append("-A %s -p udp -m udp --sport 1900 -m addrtype --dst-type LOCAL %s -j ACCEPT"
              % (CHAIN, c("answers to upnp test")))
    items.append({"key": "upnp", "title": "UPnP (SSDP and SOAP)", "fixed": False, "on": "upnp" not in off,
                  "why": "what a PS5 asks fake-igd: SSDP 1900/udp and the description and SOAP port, on the "
                         "interfaces it answers on - turned off, fake-igd hears nothing (IPv4 only)",
                  "lines": {4: up, 6: []},
                  "rules": [show(4, "udp", "1900", iface=i or "") for i in (want or [None])] +
                           [show(4, "tcp", str(http), iface=i or "") for i in (want or [None])] +
                           [dict(show(4, "udp"), words="UDP from port 1900 (answers to upnp test)")],
                  "skip": skip})
    pages = {4: [], 6: []}
    shown = []
    if (os.path.isfile(NGINX_CONF) if pages_here is None else pages_here):
        allow = cfg.get("web_allow", DEFAULT_ALLOW)
        health = health_of(cfg)
        # 80 and 443 carry the administration and the health check: open to both lists (anybody's
        # when either is everybody's); nginx says page by page who sees which.
        if allow and health:
            allow = list(allow) + [x for x in health if x not in allow]
        elif not health:
            allow = []
        for f in (4, 6):
            srcs = nets_of(allow, f) if allow else [None]
            for s in srcs:
                pages[f].append("-A %s%s -p tcp -m multiport --dports 80,443 %s -j ACCEPT"
                                % (CHAIN, (" -s %s" % s) if s else "", c("the pages")))
                shown.append(show(f, "tcp", "80,443", s or ""))
        # ACME's HTTP-01 (1.6.0): the CA asks port 80 from the internet - from anywhere, only while
        # the pages order their certificate that way (Settings → Automatic certificates).
        if allow and acme_http01():
            for f in (4, 6):
                pages[f].append("-A %s -p tcp -m tcp --dport 80 %s -j ACCEPT" % (CHAIN, c("acme http-01")))
            shown.append(dict(show(4, "tcp", "80"), words="tcp 80 from anywhere - ACME's HTTP-01"))
    items.append({"key": "pages", "title": "HTTP / HTTPS", "fixed": False, "on": "pages" not in off,
                  "why": "these pages - from everybody, or from the networks of “Who may reach the pages”"
                         " (and port 80 from anywhere while ACME checks names by HTTP-01)",
                  "lines": pages, "rules": shown})
    # SNMPv3 (1.7.2): its UDP port while it is on - deploy/root_fw.py builds it from the settings.
    try:
        import root_fw
        snmp = root_fw.snmp_item(off)
    except Exception:                         # noqa: BLE001 - the rest of the chain all the same
        snmp = None
    if snmp:
        items.append(snmp)
    return items


def module_settings():
    """The settings saved on the pages for the panes (the database's meta "settings"), read only."""
    db = os.environ.get("FAKE_IGD_DB") or os.path.join(STATE_DIR, "fake-igd.db")
    try:
        import sqlite3
        con = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=5)
        try:
            row = con.execute("SELECT v FROM meta WHERE k = 'settings'").fetchone()
        finally:
            con.close()
        got = json.loads(row[0]) if row and row[0] else {}
        return got if isinstance(got, dict) else {}
    except Exception:                         # noqa: BLE001 - no database yet: nothing set
        return {}


def acme_http01():
    s = module_settings()
    return s.get("acme") is True and str(s.get("acme_challenge") or "http-01") == "http-01"


def chain_rules(cfg, fam=4, conf=None):
    """The lines of the chain for IPv`fam`, as iptables-save writes them (without the table's frame)."""
    conf = conf if conf is not None else load_fw_conf()
    items = builtin(cfg, conf)
    rules = list(items[0]["lines"][fam])
    for r in conf.get("rules") or []:
        rules += fw_rule_lines(r, fam)
    for it in items[1:]:
        if it["on"]:
            rules += it["lines"][fam]
    return rules


def have_iptables(fam=4):
    return bool(shutil.which(FW_TOOLS[fam][0])) and bool(shutil.which(FW_TOOLS[fam][1]))


def fw_families():
    return [f for f in (4, 6) if have_iptables(f)]


def fw_backend():
    if shutil.which("firewall-cmd") and subprocess.run(["firewall-cmd", "--state"], stdout=subprocess.DEVNULL,
                                                       stderr=subprocess.DEVNULL).returncode == 0:
        return "firewalld"
    return "iptables" if have_iptables() else ""


def fw_live_fam(cfg, fam, conf):
    tool, restore, _save = FW_TOOLS[fam]
    body = "*filter\n:%s - [0:0]\n%s\nCOMMIT\n" % (CHAIN, "\n".join(chain_rules(cfg, fam, conf)))
    run([restore, "--test", "--noflush"], body)
    run([restore, "--noflush"], body)
    if subprocess.run([tool, "-C", "INPUT", "-j", CHAIN], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        run([tool, "-I", "INPUT", "1", "-j", CHAIN])
    else:
        # First in INPUT, always: put back to the top when something was put before it.
        first = run([tool, "-S", "INPUT"]).stdout.splitlines()
        rules = [x for x in first if x.startswith("-A INPUT")]
        if rules and rules[0] != "-A INPUT -j %s" % CHAIN:
            while subprocess.run([tool, "-D", "INPUT", "-j", CHAIN], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL).returncode == 0:
                pass
            run([tool, "-I", "INPUT", "1", "-j", CHAIN])


def fw_live(cfg, conf=None):
    conf = conf if conf is not None else load_fw_conf()
    done = []
    for fam in fw_families():
        fw_live_fam(cfg, fam, conf)
        done.append(fam)
    return done


def old_live_off():
    """The rules of 1.3 in INPUT taken away; how many."""
    import shlex
    n = 0
    for ln in run(["iptables", "-S", "INPUT"]).stdout.splitlines():
        if OLD_RE.match(ln):
            args = shlex.split(ln)
            args[0] = "-D"
            if subprocess.run(["iptables"] + args, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                n += 1
    return n


def fw_live_off():
    for fam in (4, 6):
        tool = FW_TOOLS[fam][0]
        if not shutil.which(tool):
            continue
        while subprocess.run([tool, "-D", "INPUT", "-j", CHAIN], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL).returncode == 0:
            pass
        subprocess.run([tool, "-F", CHAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([tool, "-X", CHAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fw_saved_now():
    """The filter tables as they are live, to go back to when a change fails half way."""
    out = {}
    for fam in fw_families():
        save = FW_TOOLS[fam][2]
        if shutil.which(save):
            r = subprocess.run([save, "-t", "filter"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               universal_newlines=True)
            if r.returncode == 0:
                out[fam] = r.stdout
    return out


def fw_put_live_back(saved):
    for fam, text in saved.items():
        if text.strip():
            subprocess.run([FW_TOOLS[fam][1]], input=text, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           universal_newlines=True)


def file_strip(text):
    out = []
    inside = False
    for ln in text.splitlines():
        if ln.startswith(MARK + " begin"):
            inside = True
            continue
        if ln.startswith(MARK + " end"):
            inside = False
            continue
        if inside or CHAIN in ln:
            continue
        out.append(ln)
    return out


def file_with(text, cfg, fam=4, conf=None):
    """/etc/sysconfig/iptables (ip6tables) with the chain's lines in its filter table - or without them (cfg None)."""
    lines = file_strip(text)
    if cfg is not None and fam == 4:
        lines = [x for x in lines if not OLD_RE.match(x)]
    if cfg is None:
        return "\n".join(lines) + "\n"
    ours = ["%s begin - fake-igd keeps these lines (upnp firewall, the pages); do not change them" % MARK,
            ":%s - [0:0]" % CHAIN, "-A INPUT -j %s" % CHAIN] + chain_rules(cfg, fam, conf) + ["%s end" % MARK]
    try:
        top = lines.index("*filter")
    except ValueError:
        return "\n".join(lines + ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
                                  ":OUTPUT ACCEPT [0:0]"] + ours + ["COMMIT"]) + "\n"
    at = top + 1
    while at < len(lines) and (lines[at].startswith(":") or lines[at].startswith("#")):
        at += 1
    return "\n".join(lines[:at] + ours + lines[at:]) + "\n"


def fw_file_fam(cfg, fam, conf):
    path = FW_FILES[fam]
    if not os.path.exists(path):
        if cfg is None:
            return ""
        return "%s is not there (iptables-services not installed?) - the chain is live, not kept over a reboot" \
               % path
    if os.path.islink(path) or not os.path.isfile(path):
        return "%s is not a plain file - left as it is" % path
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new = file_with(text, cfg, fam, conf)
    if new == text:
        return "%s: as it was" % path
    done = "the chain's lines taken out" if cfg is None else "kept over a reboot"
    t = subprocess.run([FW_TOOLS[fam][1], "--test"], input=new, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    if t.returncode != 0:
        raise Refused("%s would not load with the chain in it (%s --test): %s - left as it was"
                      % (path, FW_TOOLS[fam][1], t.stdout.strip()[:300]))
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix=".iptables.", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    os.replace(tmp, path)
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "%s: %s" % (path, done)


def fw_file(cfg, conf=None):
    """Both files (iptables, and ip6tables where it is there); what was done, in one line."""
    conf = conf if conf is not None or cfg is None else load_fw_conf()
    said = [fw_file_fam(cfg, 4, conf)]
    if have_iptables(6) or os.path.isfile(IP6T_FILE):
        said.append(fw_file_fam(cfg, 6, conf))
    return "; ".join(s for s in said if s)


def fw_file_snapshot():
    out = {}
    for fam, path in FW_FILES.items():
        if os.path.isfile(path) and not os.path.islink(path):
            with open(path, encoding="utf-8") as f:
                out[path] = f.read()
    return out


def fw_file_put_back(snap):
    for path, text in snap.items():
        try:
            with open(path, encoding="utf-8") as f:
                if f.read() == text:
                    continue
            st = os.stat(path)
            fd, tmp = tempfile.mkstemp(prefix=".iptables.", dir=os.path.dirname(path))
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            os.replace(tmp, path)
        except OSError:
            pass


def firewall(cfg):
    if not have_iptables():
        return ["iptables is not installed - nothing done"]
    if not flag(cfg.get("firewall"), False):
        live = any(subprocess.run([FW_TOOLS[f][0], "-S", CHAIN], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode == 0 for f in fw_families())
        kept = False
        for path in FW_FILES.values():
            try:
                with open(path, encoding="utf-8") as f:
                    kept = kept or CHAIN in f.read()
            except OSError:
                pass
        gw = gateway_said(cfg)
        if not live and not kept:
            return ["firewall: off"] + gw
        fw_live_off()
        said = fw_file(None)
        return ["firewall: off - %s and its jump taken away" % CHAIN] + ([said] if said else []) + gw
    conf = load_fw_conf()
    # As it was, live and in the files, to go back to when anything fails half way (as otp's):
    # never a machine left half done.
    was_live, was_file = fw_saved_now(), fw_file_snapshot()
    try:
        fams = fw_live(cfg, conf)
        counts = ", ".join("IPv%d: %d rules" % (f, len(chain_rules(cfg, f, conf))) for f in fams)
        said = ["firewall: %s in place, first in INPUT (%s)" % (CHAIN, counts)]
        old = old_live_off()
        if old:
            said.append("firewall: %d rule(s) of fake-igd 1.3 taken out of INPUT (--comment fake-igd) - "
                        "%s does what they did" % (old, CHAIN))
        said.append(fw_file(cfg, conf))
        said += fwd_sync(cfg)
    except BaseException:
        fw_put_live_back(was_live)
        fw_file_put_back(was_file)
        raise
    return said


def gateway_said(cfg):
    """fake-igd's firewall off: the gateway for devices goes off with it (its forwarding and its chain)."""
    try:
        return fwd_sync(cfg)
    except (Refused, OSError, subprocess.SubprocessError) as e:
        return ["gateway: %s" % e]


# ---- the gateway for devices (1.7.15): FAKE-IGD-FWD, first in FORWARD ------------------------
# Settings → Gateway for devices: chosen devices (a PS5 asks UPnP only of its default gateway) use
# this server as their gateway. Root's part is deploy/root_gateway.py, which builds the chain's lines
# from what it put in (its state file - never from an ask); here the chain is put in live and kept in
# /etc/sysconfig/iptables between marks of its own. The chain ends in a DROP of its own: nothing else
# is ever forwarded, whatever the distribution's FORWARD says - this server stays no bridge between
# its networks. IPv4 only: IPv6 forwarding is never turned on.
FWD_CHAIN = "FAKE-IGD-FWD"
GW_BEGIN = "%s gateway begin - fake-igd's gateway for devices (Settings → Gateway for devices); do not change " \
           "these lines" % MARK
GW_END = "%s gateway end" % MARK
GW_STATE = os.path.join(WEB_DIR, "gateway.json")


def module_meta(key):
    """A row of the database's meta, read only (root never writes the API's database)."""
    db = os.environ.get("FAKE_IGD_DB") or os.path.join(STATE_DIR, "fake-igd.db")
    try:
        import sqlite3
        con = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=5)
        try:
            row = con.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
        finally:
            con.close()
        got = json.loads(row[0]) if row and row[0] else {}
        return got if isinstance(got, dict) else {}
    except Exception:                         # noqa: BLE001 - no database yet: nothing set
        return {}


def fwd_live(lines):
    """The chain as given (it ends in its own DROP), live, and its jump first in FORWARD."""
    body = "*filter\n:%s - [0:0]\n%s\nCOMMIT\n" % (FWD_CHAIN, "\n".join(lines))
    run(["iptables-restore", "--test", "--noflush"], body)
    run(["iptables-restore", "--noflush"], body)
    rules = [x for x in run(["iptables", "-S", "FORWARD"]).stdout.splitlines() if x.startswith("-A FORWARD")]
    if not rules or rules[0] != "-A FORWARD -j %s" % FWD_CHAIN:
        while subprocess.run(["iptables", "-D", "FORWARD", "-j", FWD_CHAIN], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL).returncode == 0:
            pass
        run(["iptables", "-I", "FORWARD", "1", "-j", FWD_CHAIN])


def fwd_live_off():
    """The jump and the chain taken away (live); whether there was anything to take."""
    if not shutil.which("iptables"):
        return False
    had = subprocess.run(["iptables", "-S", FWD_CHAIN], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL).returncode == 0
    while subprocess.run(["iptables", "-D", "FORWARD", "-j", FWD_CHAIN], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL).returncode == 0:
        pass
    subprocess.run(["iptables", "-F", FWD_CHAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-X", FWD_CHAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return had


def fwd_file_with(text, lines):
    """/etc/sysconfig/iptables with the gateway's lines (a list) - or without them (None)."""
    out, inside = [], False
    for ln in text.splitlines():
        if ln.startswith(MARK + " gateway begin"):
            inside = True
            continue
        if ln.startswith(GW_END):
            inside = False
            continue
        if inside or FWD_CHAIN in ln:
            continue
        out.append(ln)
    if lines is None:
        return "\n".join(out) + "\n"
    ours = [GW_BEGIN, ":%s - [0:0]" % FWD_CHAIN, "-A FORWARD -j %s" % FWD_CHAIN] + list(lines) + [GW_END]
    try:
        top = out.index("*filter")
    except ValueError:
        return "\n".join(out + ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
                                ":OUTPUT ACCEPT [0:0]"] + ours + ["COMMIT"]) + "\n"
    at = top + 1
    while at < len(out) and (out[at].startswith(":") or out[at].startswith("#")):
        at += 1
    return "\n".join(out[:at] + ours + out[at:]) + "\n"


def fwd_file(lines):
    """The gateway's lines into /etc/sysconfig/iptables (None: out of it) - checked with --test first."""
    path = IPT_FILE
    if not os.path.exists(path):
        return "" if lines is None else \
            "%s is not there (iptables-services not installed?) - the gateway's rules are live, not kept over a " \
            "reboot" % path
    if os.path.islink(path) or not os.path.isfile(path):
        return "%s is not a plain file - left as it is" % path
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new = fwd_file_with(text, lines)
    if new == text:
        return ""
    t = subprocess.run(["iptables-restore", "--test"], input=new, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    if t.returncode != 0:
        raise Refused("%s would not load with the gateway's lines (iptables-restore --test): %s - left as it was"
                      % (path, t.stdout.strip()[:300]))
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix=".iptables.", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    os.replace(tmp, path)
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "%s: the gateway's rules %s" % (path, "taken out" if lines is None else "kept over a reboot")


def fwd_sync(cfg):
    """The gateway for devices as root_gateway.py put it in, after a change of fake-igd's firewall: its
    chain put in again - or, the firewall turned off, the forwarding turned off with it (root_gateway)."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import root_gateway as GW
    except ImportError:
        return []
    return GW.sync(cfg)


def forward_view():
    """FORWARD as the kernel has it: its policy, the first rules, whether ours is first and ends in its own
    DROP, and the packets and bytes of each rule of FAKE-IGD-FWD by address (iptables -vnx: root's)."""
    out = {"iptables": have_iptables(), "backend": fw_backend(), "policy": "", "first": [], "ours_first": False,
           "chain": False, "ends_drop": False, "counters": {}, "dropped": 0}
    if not out["iptables"]:
        return out
    r = subprocess.run(["iptables", "-S", "FORWARD"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       universal_newlines=True)
    lines = r.stdout.splitlines()
    for ln in lines:
        if ln.startswith("-P FORWARD "):
            out["policy"] = ln.split()[2]
    rules = [x for x in lines if x.startswith("-A FORWARD")]
    out["first"] = rules[:8]
    out["ours_first"] = bool(rules) and rules[0] == "-A FORWARD -j %s" % FWD_CHAIN
    ch = subprocess.run(["iptables", "-S", FWD_CHAIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        universal_newlines=True)
    out["chain"] = ch.returncode == 0
    mine = [x for x in ch.stdout.splitlines() if x.startswith("-A ")]
    out["ends_drop"] = bool(mine) and mine[-1].endswith("-j DROP") and " -s " not in mine[-1] \
        and " -d " not in mine[-1] and " -i " not in mine[-1]
    v = subprocess.run(["iptables", "-v", "-x", "-n", "-L", FWD_CHAIN], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, universal_newlines=True)
    rows = [ln.split() for ln in v.stdout.splitlines()[2:]]
    rows = [f for f in rows if len(f) >= 9 and f[0].isdigit()]
    for f in rows:
        pk, by, target, src, dst = int(f[0]), int(f[1]), f[2], f[7], f[8]
        if target != "ACCEPT":
            continue
        ip, key = (src, "out") if src != "0.0.0.0/0" else (dst, "back")
        c = out["counters"].setdefault(ip.split("/")[0], {"out_pkts": 0, "out_bytes": 0, "back_pkts": 0,
                                                          "back_bytes": 0})
        c[key + "_pkts"] += pk
        c[key + "_bytes"] += by
    if rows and rows[-1][2] == "DROP":
        out["dropped"] = int(rows[-1][0])
    return out


def fw_full(fam):
    """The whole filter table as iptables-save shows it (as otp's): every chain, counters left out."""
    save = FW_TOOLS[fam][2]
    if not shutil.which(save):
        return []
    got = subprocess.run([save, "-t", "filter"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         universal_newlines=True)
    out = []
    for line in got.stdout.split("\n"):
        line = re.sub(r"^\[\d+:\d+\]\s+", "", line.strip())
        if not line or line.startswith("#") or line in ("*filter", "COMMIT"):
            continue
        out.append(re.sub(r" \[\d+:\d+\]$", "", line))
    return out[:1500]


def fw_status():
    out = {"iptables": have_iptables(), "chain": False, "first": False, "file": False, "rules": [],
           "ip6tables": have_iptables(6), "chain6": False, "first6": False, "file6": False, "rules6": [],
           "backend": fw_backend(), "full": {}, "full_at": time.time()}
    for fam, sfx in ((4, ""), (6, "6")):
        if not have_iptables(fam):
            continue
        tool = FW_TOOLS[fam][0]
        r = subprocess.run([tool, "-S", CHAIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True)
        out["chain" + sfx] = r.returncode == 0
        out["rules" + sfx] = [x for x in r.stdout.splitlines() if x.startswith("-A")]
        first = subprocess.run([tool, "-S", "INPUT"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               universal_newlines=True).stdout.splitlines()
        first = [x for x in first if x.startswith("-A INPUT")]
        out["first" + sfx] = bool(first) and first[0] == "-A INPUT -j %s" % CHAIN
        try:
            with open(FW_FILES[fam], encoding="utf-8") as f:
                out["file" + sfx] = CHAIN in f.read()
        except OSError:
            pass
        out["full"][str(fam)] = fw_full(fam)
    if not out["iptables"]:
        return out
    out["service"] = subprocess.run(["systemctl", "is-active", "--quiet", "iptables"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    return out


# ---- the request -----------------------------------------------------------------
def write_result(d):
    d["at"] = time.time()
    try:
        dfd = os.open(WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        name = ".result.%d" % os.getpid()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
            # By the open file, never by its name (1.7.4): the folder is the API account's, which could
            # put a link to a file of root's there between the write and a chown by name.
            try:
                import grp
                os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
            except (KeyError, OSError):
                pass
        os.replace(name, "result.json", src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


AVAHI_ACTIONS = ("restart", "start", "stop", "enable", "disable")


def avahi(changes, action):
    """The mDNS reflector: changes {key: value} of avahi-daemon.conf, and/or one action."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import upnp_mdns as M
    said = []
    if isinstance(changes, dict) and changes:
        clean = {}
        for k, v in list(changes.items())[:20]:
            if k not in M.KNOWN:
                raise Refused("avahi: %s is not a key fake-igd changes" % str(k)[:40])
            clean[k] = str(v)[:400]
        try:
            said.append("avahi: " + M.apply(clean, restart=action != "no-restart", log=lambda *_: None))
        except M.MdnsError as e:
            raise Refused("avahi: %s" % e)
    if action in AVAHI_ACTIONS:
        r = subprocess.run(["systemctl", action, M.SERVICE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
        said.append("avahi-daemon: %s %s" % (action, "done" if r.returncode == 0
                                               else "did not work: " + r.stdout.strip()[:200]))
    return said


def apply(restart=False):
    cfg = read_config()
    said = []
    try:
        said.append(nginx_allow(cfg))
    except (Refused, OSError) as e:
        said.append("nginx: %s" % e)
    try:
        said += firewall(cfg)
    except (Refused, OSError, subprocess.SubprocessError) as e:
        said.append("firewall: %s" % e)
    if restart:
        r = subprocess.run(["systemctl", "restart", "fake-igd"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
        said.append("fake-igd.service restarted" if r.returncode == 0
                    else "fake-igd.service did not restart: %s" % r.stdout.strip()[:200])
    return said


# ---- the panes' asks (1.6.0): a queue of files, one module of root's for each kind ----------
ASK_DIR = os.path.join(WEB_DIR, "ask")
KIND_RE = re.compile(r"^([a-z][a-z0-9]{0,30})-([0-9]{10,16}-[0-9a-f]{8})\.json\Z")


def root_module(kind):
    """deploy/root_KIND.py beside this file (installed beside it in /opt/fake-igd) - root's alone."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "root_%s.py" % kind)
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refused("%s is not root's alone - not run" % path)
    if here not in sys.path:
        sys.path.insert(0, here)
    import importlib.util
    spec = importlib.util.spec_from_file_location("root_%s" % kind, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RECENT_KEEP = 20


def write_kind_result(kind, d):
    """The answer of root's last ask of a kind - and, beside it, the short answers of the asks before it
    (1.7.1): one kind has asks of more than one sort (TLS: a certificate put, the trusted roots read), and
    the newest must not hide whether an older one was done."""
    d["at"] = time.time()
    d["kind"] = kind
    try:
        dfd = os.open(WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        recent = []
        try:
            fd = os.open("result-%s.json" % kind, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            with os.fdopen(fd, "rb") as f:
                was = json.loads(f.read(8 * 1024 * 1024).decode("utf-8") or "{}")
            if isinstance(was, dict):
                recent = [x for x in (was.get("recent") or []) if isinstance(x, dict)]
                if was.get("id"):
                    recent.append({k: was.get(k) for k in ("id", "ok", "action", "said", "at", "by") if k in was})
        except (OSError, ValueError):
            recent = []
        d["recent"] = [x for x in recent if x.get("id") != d.get("id")][-RECENT_KEEP:]
        name = ".result-%s.%d" % (kind, os.getpid())
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, default=str)
            try:                                # by the open file, never by its name (see write_result)
                import grp
                os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
            except (KeyError, OSError):
                pass
        os.replace(name, "result-%s.json" % kind, src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


def serve_queue():
    """Every ask in web/ask/, oldest first: taken out of the folder, then done by its module."""
    try:
        dfd = os.open(ASK_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return 0
    try:
        for _round in range(50):
            names = sorted(n for n in os.listdir(dfd) if KIND_RE.match(n))
            junk = [n for n in os.listdir(dfd) if not KIND_RE.match(n) and not n.startswith(".")]
            for n in junk:                       # nothing else stays there to start this again and again
                try:
                    os.unlink(n, dir_fd=dfd)
                except OSError:
                    pass
            if not names:
                break
            for n in names:
                kind, ident = KIND_RE.match(n).groups()
                try:
                    fd = os.open(n, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                    with os.fdopen(fd, "rb") as f:
                        raw = f.read(4 * 1024 * 1024) if stat.S_ISREG(os.fstat(f.fileno()).st_mode) else b""
                except OSError:
                    raw = b""
                try:
                    os.unlink(n, dir_fd=dfd)
                except OSError:
                    pass
                try:
                    ask = json.loads(raw.decode("utf-8") or "{}")
                except ValueError:
                    ask = {}
                payload = ask.get("payload") if isinstance(ask, dict) else None
                try:
                    mod = root_module(kind)
                    got = mod.serve(payload if isinstance(payload, dict) else {}, ask) or {}
                    if not isinstance(got, dict):
                        got = {"said": [str(got)]}
                    got.setdefault("ok", True)
                except Refused as e:
                    got = {"ok": False, "said": [str(e)]}
                except Exception as e:                      # noqa: BLE001 - said, never lost
                    got = {"ok": False, "said": ["%s broke: %s" % (kind, e)]}
                got["id"] = ident
                got["by"] = str((ask or {}).get("by") or "")[:80] if isinstance(ask, dict) else ""
                write_kind_result(kind, got)
    finally:
        os.close(dfd)
    return 0


def serve():
    serve_queue()
    try:
        dfd = os.open(WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return 0
    try:
        try:
            fd = os.open("apply.ask", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            return 0
        except OSError:
            try:
                os.unlink("apply.ask", dir_fd=dfd)
            except OSError:
                pass
            return 1
        with os.fdopen(fd, "rb") as f:
            raw = f.read(4096) if stat.S_ISREG(os.fstat(f.fileno()).st_mode) else b""
        os.unlink("apply.ask", dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        ask = json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        ask = {}
    ident = str(ask.get("id") or "")[:40] if isinstance(ask, dict) else ""
    try:
        if isinstance(ask, dict) and ("avahi" in ask or "avahi_action" in ask):
            said = avahi(ask.get("avahi") or {}, str(ask.get("avahi_action") or ""))
        else:
            said = apply(restart=isinstance(ask, dict) and ask.get("restart") is True)
        try:
            fw = fw_status()
        except Exception:                               # noqa: BLE001
            fw = {}
        write_result({"id": ident, "ok": not any(("refused" in s or "could not" in s or "did not" in s) for s in said),
                      "said": said, "firewall": fw})
    except Exception as e:                              # noqa: BLE001 - said, never lost
        write_result({"id": ident, "ok": False, "said": ["%s" % e]})
    return 0


def main(argv):
    if argv[:1] == ["--status"]:
        print(json.dumps({"firewall": fw_status(), "nginx": os.path.isfile(NGINX_CONF)}, indent=1))
        return 0
    if os.geteuid() != 0:
        print("fake_igd_web.py: run as root")
        return 1
    if argv[:1] in (["--selinux-check"], ["--selinux-do"], ["--selinux-report"], ["--selinux-fix"],
                    ["--selinux-rule-drop"]):
        # `sudo upnp selinux ...` (1.7.7, otp's otp_web.py --selinux-check / --selinux-do / --selinux-report):
        # this machine's SELinux, worked out and done here - what fake-igd needs is read by root itself.
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        import root_selinux as SE
        try:
            if argv[0] == "--selinux-report":
                if len(argv) < 2:
                    print("fake_igd_web.py --selinux-report FILE", file=sys.stderr)
                    return 2
                node = re.sub(r"[^A-Za-z0-9._-]", "", os.uname()[1].split(".")[0])[:60] or "server"
                SE.se_report_write(SE.se_report_bytes(node), argv[1])
                print(argv[1])
                return 0
            if argv[0] == "--selinux-fix":
                # `upnp selinux fix ID ... | --all` (1.7.10): root's own findings, found again here.
                ids = [a for a in argv[1:] if not a.startswith("--")]
                if "--all" in argv:
                    FIND = SE._here()
                    ids = [f["id"] for f in (SE.se_findings(SE.se_applied_at()) or []) if f["kind"] in FIND.FIXABLE]
                    if not ids:
                        print("nothing here can be put right - nothing fixable was refused")
                        return 0
                said, done = SE.se_fix(ids, os.environ.get("SUDO_USER") or "root (command line)")
                c = SE.se_check()
                print(json.dumps(dict(c, said=said, fixed=done)) if "--json" in argv else
                      "\n".join(["done: " + x for x in said] + [SE.se_text(c)]))
                return 0
            if argv[0] == "--selinux-rule-drop":
                said = SE.se_rule_drop(argv[1] if len(argv) > 1 else "")
                c = SE.se_check()
                print(json.dumps(dict(c, said=said)) if "--json" in argv else "\n".join(["done: " + x for x in said]))
                return 0
            if argv[0] == "--selinux-do":
                step = {"apply": "prepare"}.get(argv[1] if len(argv) > 1 else "", argv[1] if len(argv) > 1 else "")
                if step not in ("prepare", "enforce", "permissive"):
                    print("fake_igd_web.py --selinux-do prepare|apply|enforce|permissive", file=sys.stderr)
                    return 2
                c = SE.se_do(step)
                said = c.pop("said", [])
                print(json.dumps(c) if "--json" in argv else "\n".join(["done: " + x for x in said] + [SE.se_text(c)]))
                return 0
            c = SE.se_check()
        except (SE.Refused, OSError) as e:
            print("fake_igd_web.py: %s" % e, file=sys.stderr)
            return 2
        print(json.dumps(c) if "--json" in argv else SE.se_text(c))
        return 0 if (c["mode"] in ("absent", "Disabled") or not c["problems"]) else 1
    if argv[:1] == ["--kind"] and len(argv) >= 2:
        # A module's part by hand (install.sh, tests): --kind NAME [JSON]
        payload = json.loads(argv[2]) if len(argv) > 2 else {}
        got = root_module(argv[1]).serve(payload, {"by": "the command line"}) or {}
        print(json.dumps(got, indent=1, default=str))
        return 0 if got.get("ok", True) else 1
    if argv[:1] == ["--apply"]:
        for ln in apply(restart="--restart" in argv):
            print(ln)
        return 0
    if argv[:1] == ["--firewall-off"]:
        if have_iptables():
            fw_live_off()
            if os.path.isfile(IPT_FILE):
                print(fw_file(None))
        print("firewall: %s taken away" % CHAIN)
        return 0
    if not argv:
        return serve()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
