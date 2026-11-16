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
def nginx_allow(cfg):
    if not os.path.isfile(NGINX_CONF) or os.path.islink(NGINX_CONF):
        return "no %s here" % NGINX_CONF
    allow = cfg.get("web_allow", DEFAULT_ALLOW)
    lines = ["        allow %s;" % n for n in nets(allow)] if allow else ["        allow all;"]
    if allow and not lines:
        lines = ["        # nothing in web_allow is an IPv4 address or network - only this machine"]
    with open(NGINX_CONF, encoding="utf-8") as f:
        text = f.read()
    new, n = re.subn(r"(# ADMIN-ALLOW-BEGIN[^\n]*\n)(.*?)(\n[ \t]*# ADMIN-ALLOW-END)",
                     lambda m: m.group(1) + "\n".join(lines) + m.group(3), text, flags=re.S)
    if not n:
        return "the allow list's marks are not in %s - left as it is" % NGINX_CONF
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
        t = subprocess.run(["nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    except OSError as e:
        os.replace(keep, NGINX_CONF)
        raise Refused("nginx could not be asked (%s), the file was put back" % e)
    if t.returncode != 0:
        os.replace(keep, NGINX_CONF)
        raise Refused("nginx -t refused the new allow list, the file was put back: %s" % t.stdout.strip()[-300:])
    os.unlink(keep)
    subprocess.run(["systemctl", "reload", "nginx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "nginx: the pages may be reached from %s" % (", ".join(nets(allow)) if allow else "everybody")


# ---- iptables: FAKE-IGD-IN ---------------------------------------------------------
def chain_rules(cfg):
    """The lines of the chain, as iptables-save writes them (without the table's frame)."""
    rules = ["-A %s -i lo -j ACCEPT" % CHAIN,
             "-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" % CHAIN]
    if flag(cfg.get("firewall_ssh"), True):
        rules.append("-A %s -p tcp -m tcp --dport 22 -m comment --comment \"fake-igd: ssh\" -j ACCEPT" % CHAIN)
    if flag(cfg.get("firewall_icmp"), True):
        rules.append("-A %s -p icmp -m comment --comment \"fake-igd: ping\" -j ACCEPT" % CHAIN)
    http = port(cfg.get("http_port"), 5000)
    want = ifaces(cfg.get("interfaces"))
    skip = [i for i in ifaces(cfg.get("exclude_interfaces", ["lo"])) if i != "lo"]
    # Excluded interfaces first, back to INPUT: one "! -i" per rule only, so they are sent back.
    for i in skip:
        rules.append("-A %s -i %s -p udp -m udp --dport 1900 -j RETURN" % (CHAIN, i))
        rules.append("-A %s -i %s -p tcp -m tcp --dport %d -j RETURN" % (CHAIN, i, http))
    for i in (want or [None]):
        on = (" -i %s" % i) if i else ""
        rules.append("-A %s%s -p udp -m udp --dport 1900 -m comment --comment \"fake-igd: ssdp\" -j ACCEPT"
                     % (CHAIN, on))
        rules.append("-A %s%s -p tcp -m tcp --dport %d -m comment --comment \"fake-igd: description and soap\" "
                     "-j ACCEPT" % (CHAIN, on, http))
    # answers to `upnp test` from this machine (SSDP answers come from port 1900 of whoever answers)
    rules.append("-A %s -p udp -m udp --sport 1900 -m addrtype --dst-type LOCAL -m comment "
                 "--comment \"fake-igd: answers to upnp test\" -j ACCEPT" % CHAIN)
    allow = cfg.get("web_allow", DEFAULT_ALLOW)
    if os.path.isfile(NGINX_CONF):
        srcs = nets(allow) if allow else [None]
        for s in srcs:
            rules.append("-A %s%s -p tcp -m multiport --dports 80,443 -m comment --comment \"fake-igd: the pages\" "
                         "-j ACCEPT" % (CHAIN, (" -s %s" % s) if s else ""))
    return rules


def have_iptables():
    return bool(shutil.which("iptables")) and bool(shutil.which("iptables-restore"))


def fw_live(cfg):
    body = "*filter\n:%s - [0:0]\n%s\nCOMMIT\n" % (CHAIN, "\n".join(chain_rules(cfg)))
    run(["iptables-restore", "--test", "--noflush"], body)
    run(["iptables-restore", "--noflush"], body)
    if subprocess.run(["iptables", "-C", "INPUT", "-j", CHAIN], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        run(["iptables", "-I", "INPUT", "1", "-j", CHAIN])
    else:
        # First in INPUT, always: put back to the top when something was put before it.
        first = run(["iptables", "-S", "INPUT"]).stdout.splitlines()
        rules = [x for x in first if x.startswith("-A INPUT")]
        if rules and rules[0] != "-A INPUT -j %s" % CHAIN:
            while subprocess.run(["iptables", "-D", "INPUT", "-j", CHAIN], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL).returncode == 0:
                pass
            run(["iptables", "-I", "INPUT", "1", "-j", CHAIN])


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
    while subprocess.run(["iptables", "-D", "INPUT", "-j", CHAIN], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL).returncode == 0:
        pass
    subprocess.run(["iptables", "-F", CHAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-X", CHAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def file_with(text, cfg):
    """/etc/sysconfig/iptables with the chain's lines in its filter table - or without them (cfg None)."""
    lines = file_strip(text)
    if cfg is not None:
        lines = [x for x in lines if not OLD_RE.match(x)]
    if cfg is None:
        return "\n".join(lines) + "\n"
    ours = ["%s begin - fake-igd keeps these lines (upnp firewall, the pages); do not change them" % MARK,
            ":%s - [0:0]" % CHAIN, "-A INPUT -j %s" % CHAIN] + chain_rules(cfg) + ["%s end" % MARK]
    try:
        top = lines.index("*filter")
    except ValueError:
        return "\n".join(lines + ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]",
                                  ":OUTPUT ACCEPT [0:0]"] + ours + ["COMMIT"]) + "\n"
    at = top + 1
    while at < len(lines) and (lines[at].startswith(":") or lines[at].startswith("#")):
        at += 1
    return "\n".join(lines[:at] + ours + lines[at:]) + "\n"


def fw_file(cfg):
    if not os.path.exists(IPT_FILE):
        return "%s is not there (iptables-services not installed?) - the chain is live, not kept over a reboot" \
               % IPT_FILE
    if os.path.islink(IPT_FILE) or not os.path.isfile(IPT_FILE):
        return "%s is not a plain file - left as it is" % IPT_FILE
    with open(IPT_FILE, encoding="utf-8") as f:
        text = f.read()
    new = file_with(text, cfg)
    if new == text:
        return "%s: as it was" % IPT_FILE
    done = "the chain's lines taken out" if cfg is None else "kept over a reboot"
    t = subprocess.run(["iptables-restore", "--test"], input=new, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    if t.returncode != 0:
        raise Refused("%s would not load with the chain in it (iptables-restore --test): %s - left as it was"
                      % (IPT_FILE, t.stdout.strip()[:300]))
    st = os.stat(IPT_FILE)
    fd, tmp = tempfile.mkstemp(prefix=".iptables.", dir=os.path.dirname(IPT_FILE))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    os.replace(tmp, IPT_FILE)
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", IPT_FILE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "%s: %s" % (IPT_FILE, done)


def firewall(cfg):
    if not have_iptables():
        return ["iptables is not installed - nothing done"]
    if not flag(cfg.get("firewall"), False):
        live = subprocess.run(["iptables", "-S", CHAIN], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
        if not live and not (os.path.isfile(IPT_FILE) and CHAIN in open(IPT_FILE, encoding="utf-8").read()):
            return ["firewall: off"]
        fw_live_off()
        said = fw_file(None) if os.path.isfile(IPT_FILE) else ""
        return ["firewall: off - %s and its jump taken away" % CHAIN] + ([said] if said else [])
    fw_live(cfg)
    said = ["firewall: %s in place, first in INPUT (%d rules)" % (CHAIN, len(chain_rules(cfg)))]
    old = old_live_off()
    if old:
        said.append("firewall: %d rule(s) of fake-igd 1.3 taken out of INPUT (--comment fake-igd) - "
                    "%s does what they did" % (old, CHAIN))
    return said + [fw_file(cfg)]


def fw_status():
    out = {"iptables": have_iptables(), "chain": False, "first": False, "file": False, "rules": []}
    if not out["iptables"]:
        return out
    r = subprocess.run(["iptables", "-S", CHAIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       universal_newlines=True)
    out["chain"] = r.returncode == 0
    out["rules"] = [x for x in r.stdout.splitlines() if x.startswith("-A")]
    first = subprocess.run(["iptables", "-S", "INPUT"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True).stdout.splitlines()
    first = [x for x in first if x.startswith("-A INPUT")]
    out["first"] = bool(first) and first[0] == "-A INPUT -j %s" % CHAIN
    try:
        with open(IPT_FILE, encoding="utf-8") as f:
            out["file"] = CHAIN in f.read()
    except OSError:
        pass
    out["service"] = subprocess.run(["systemctl", "is-active", "--quiet", "iptables"]).returncode == 0
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
        try:
            import grp
            os.chown(name, 0, grp.getgrnam("fake-igd").gr_gid, dir_fd=dfd)
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


def write_kind_result(kind, d):
    d["at"] = time.time()
    d["kind"] = kind
    try:
        dfd = os.open(WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        name = ".result-%s.%d" % (kind, os.getpid())
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, default=str)
        try:
            import grp
            os.chown(name, 0, grp.getgrnam("fake-igd").gr_gid, dir_fd=dfd)
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
