#!/usr/bin/python3 -I
"""root_net.py - what root does for Settings → Network (1.6.0), otp's net_* of otp_web.py.

Asked by the API (kind "net") through the queue in web/ask/, or by its own timer:

  {"do": "apply", "con", "hostname", "ipv4": {...}, "ipv6": {...}, "trial_min", "snapshot"}
        the connection's settings changed in NetworkManager (nmcli connection modify), the host
        name (hostnamectl) and this machine's lines in /etc/hosts - and the connection brought up
        again with them. ON TRIAL (trial_min > 0): what the machine had is kept first (the
        connection's whole profile, its ipv4/ipv6 properties, the host name, /etc/hosts, the IPv6
        switch - in /var/lib/fake-igd-net, root's alone), and a timer (systemd-run) puts exactly
        that back after trial_min minutes unless somebody presses Keep it.
  {"do": "keep", "snapshot"}    the timer stopped, what was kept dropped: the new network stays
  {"do": "back", "snapshot"}    what was kept put back now (the timer's own ask, or Put it back)

How the trial stands is written to web/net-trial.json for the API (group fake-igd may read it).
Nothing in the payload is trusted: every value is checked against the one shape it may have,
the connection against the list NetworkManager gives. No shell; files written beside the target
and renamed. Every path and command may be pointed elsewhere for tests (FAKE_IGD_…).
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

STATE_DIR = os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd")
WEB_DIR = os.path.join(STATE_DIR, "web")
TRIAL_FILE = os.path.join(WEB_DIR, "net-trial.json")
NMCLI = os.environ.get("FAKE_IGD_NMCLI", "nmcli")
HOSTNAMECTL = os.environ.get("FAKE_IGD_HOSTNAMECTL", "hostnamectl")
SYSTEMD_RUN = os.environ.get("FAKE_IGD_SYSTEMD_RUN", "systemd-run")
SYSTEMCTL = os.environ.get("FAKE_IGD_SYSTEMCTL", "systemctl")
SYSCTL = os.environ.get("FAKE_IGD_SYSCTL", "sysctl")
HOSTS_FILE = os.environ.get("FAKE_IGD_HOSTS_FILE", "/etc/hosts")
SNAP_DIR = os.environ.get("FAKE_IGD_NET_SNAP_DIR", "/var/lib/fake-igd-net")
SNAP_FILE = "before.json"
PROFILE_DIRS = tuple(x for x in os.environ.get(
    "FAKE_IGD_NM_PROFILE_DIRS", "/etc/NetworkManager/system-connections/:"
    "/etc/sysconfig/network-scripts/:/run/NetworkManager/system-connections/").split(":") if x)
SYSCTL6 = os.environ.get("FAKE_IGD_SYSCTL6", "/etc/sysctl.d/90-fake-igd-ipv6.conf")
# Tests: the timer is written down here instead of being started by systemd.
TIMER_FILE = os.environ.get("FAKE_IGD_NET_TIMER_FILE", "")
UNIT_PREFIX = "fake-igd-net-back-"
MARK = "# fake-igd:"

ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z")
NAME_RE = re.compile(r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
SNAP_RE = re.compile(r"^[0-9a-f]{8,40}\Z")
PROP_RE = re.compile(r"^ipv[46]\.[a-z0-9-]+\Z")


class Refused(Exception):
    pass


def run(cmd, what, ok=(0,), timeout=120):
    try:
        got = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=timeout)
    except FileNotFoundError:
        raise Refused("%s: %s is not on this machine" % (what, cmd[0]))
    except subprocess.TimeoutExpired:
        raise Refused("%s: no answer in %d s" % (what, timeout))
    if got.returncode not in ok:
        raise Refused("%s: %s" % (what, (got.stderr or got.stdout).strip()[-300:] or
                                  "ended with %d" % got.returncode))
    return got.stdout


def plain(text, how):
    """An address, a network or an address with its prefix - and nothing else (no scope id)."""
    text = str(text or "").strip()
    if not ADDR_RE.match(text):
        raise ValueError("not a plain address")
    got = {"address": ipaddress.ip_address,
           "interface": ipaddress.ip_interface}[how](text)
    if "%" in str(got):
        raise ValueError("a scope id is not taken")
    return got


def write_root(path, text, mode):
    """A file of root's, replaced whole: written beside it, then renamed over."""
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fake-igd-", dir=folder)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_or_none(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def nm_fields(con, fields):
    out = run([NMCLI, "-t", "-g", ",".join(fields), "connection", "show", con],
              "nmcli connection show")
    vals = out.rstrip("\n").split("\n")
    got = {}
    for k, v in zip(fields, vals + [""] * (len(fields) - len(vals))):
        got[k] = v.replace("\\:", ":").strip()
    return got


def nm_list(text):
    return [x.strip() for x in re.split(r"[,\s]+", text or "") if x.strip() and x.strip() != "--"]


def nm_props(con):
    """Every ipv4.* and ipv6.* property of the connection, as nmcli shows it."""
    out = {}
    for line in run([NMCLI, "-t", "-f", "ipv4,ipv6", "connection", "show", con],
                    "nmcli connection show").splitlines():
        k, sep, v = line.partition(":")
        if sep and PROP_RE.match(k):
            out[k] = v.replace("\\:", ":")
    return out


def static_hostname():
    try:
        got = run([HOSTNAMECTL, "--static"], "hostnamectl").strip()
    except (Refused, OSError):
        got = ""
    if not got:
        got = os.uname().nodename
    return str(got or "").strip().rstrip(".").lower()


# ---- how the trial stands, for the API -----------------------------------------------
def trial_write(d):
    d["at"] = time.time()
    try:
        os.makedirs(WEB_DIR, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".net-trial-", dir=WEB_DIR)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
            os.fchmod(f.fileno(), 0o640)
            try:
                import grp
                os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
            except (KeyError, OSError):
                pass
        os.replace(tmp, TRIAL_FILE)
    except OSError:
        pass


def trial_read():
    try:
        with open(TRIAL_FILE) as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


# ---- the request, every value in its one shape (otp's net_checked) --------------------
def checked(r):
    out = {"con": str(r.get("con") or "")}
    if not out["con"] or len(out["con"]) > 120 or any(c in out["con"] for c in "\n\r\x00"):
        raise Refused("which connection?")
    v4 = r.get("ipv4") if isinstance(r.get("ipv4"), dict) else {}
    method = str(v4.get("method") or "manual")
    if method not in ("manual", "auto"):
        raise Refused("IPv4 is set by hand (manual) or by DHCP (auto)")
    out["method4"] = method
    out["addr4"], out["gw4"] = "", ""
    if method == "manual":
        try:
            a4 = plain(v4.get("addr"), "interface")
        except ValueError:
            raise Refused("the IPv4 address is an address with its prefix (192.0.2.10/24)")
        if a4.version != 4 or "/" not in str(v4.get("addr")):
            raise Refused("the IPv4 address is an address with its prefix (192.0.2.10/24)")
        out["addr4"] = str(a4)
        gw = str(v4.get("gw") or "").strip()
        if gw:
            try:
                g = plain(gw, "address")
            except ValueError:
                raise Refused("the gateway is one IPv4 address")
            if g.version != 4 or g not in a4.network:
                raise Refused("the gateway %s is not in %s" % (g, a4.network))
            out["gw4"] = str(g)
    v6 = r.get("ipv6") if isinstance(r.get("ipv6"), dict) else {}
    dns = []
    for d in list(v4.get("dns") or [])[:4] + list(v6.get("dns") or [])[:4]:
        try:
            dns.append(str(plain(d, "address")))
        except ValueError:
            raise Refused("%r is not the address of a DNS server" % str(d)[:60])
    out["dns4"] = [d for d in dns if ":" not in d]
    out["dns6"] = [d for d in dns if ":" in d]
    search = []
    for s_ in list(v4.get("search") or [])[:6]:
        if not NAME_RE.match(str(s_)):
            raise Refused("%r is not a domain" % str(s_)[:60])
        search.append(str(s_))
    out["search"] = search
    mode = str(v6.get("mode") or "off")
    if mode not in ("off", "auto", "manual"):
        raise Refused("IPv6 is off, auto or manual")
    out["mode6"] = mode
    out["addr6"], out["gw6"] = "", ""
    if mode == "manual":
        try:
            a6 = plain(v6.get("addr"), "interface")
        except ValueError:
            raise Refused("the IPv6 address is an address with its prefix (2001:db8::10/64)")
        if a6.version != 6 or a6.ip.is_link_local or "/" not in str(v6.get("addr")):
            raise Refused("the IPv6 address is a global one with its prefix (2001:db8::10/64)")
        out["addr6"] = str(a6)
        g6 = str(v6.get("gw") or "").strip()
        if g6:
            try:
                gg = plain(g6, "address")
            except ValueError:
                raise Refused("the IPv6 gateway is one IPv6 address")
            if gg.version != 6:
                raise Refused("the IPv6 gateway is one IPv6 address")
            out["gw6"] = str(gg)
    host = str(r.get("hostname") or "").strip().rstrip(".").lower()
    if host and not NAME_RE.match(host):
        raise Refused("%r is not a host name" % host[:80])
    if host and "." not in host and host != static_hostname():
        raise Refused("the host name is the whole name: igd.example.com")
    out["hostname"] = host
    snap = str(r.get("snapshot") or "")
    out["snapshot"] = snap if SNAP_RE.match(snap) else ""
    try:
        out["trial_min"] = max(0, min(120, int(r.get("trial_min") or 0)))
    except (TypeError, ValueError):
        out["trial_min"] = 0
    if out["trial_min"] and not out["snapshot"]:
        raise Refused("a change on trial needs the id of what is kept")
    return out


def hosts_lines(text, n, old_ips, old_host):
    """/etc/hosts after the change: a line of this connection's old address gets the new one (or
    goes, when the new one is not known - DHCP), the machine's old name becomes the new one where
    it stands; localhost lines are kept as they are. The machine's name gets a line of the new
    address when it has none (otp's hosts_lines, for a machine of several interfaces)."""
    name = n["hostname"] or old_host
    short = name.split(".")[0] if name else ""
    olds = set(x for x in (old_host, old_host.split(".")[0] if old_host else "") if x)
    new4 = n["addr4"].split("/")[0] if n["addr4"] else ""
    new6 = n["addr6"].split("/")[0] if n.get("addr6") else ""
    out, named = [], False
    for line in text.splitlines():
        body, sep, comment = line.partition("#")
        f = body.split()
        if not f or f[0].startswith(("127.", "::1")):
            out.append(line)
            continue
        ip, names = f[0], f[1:]
        if ip in old_ips:
            ip = (new6 if ":" in ip else new4)
            if not ip:
                continue
        if any(x.lower() in olds for x in names) and name:
            names = [name, short] + [x for x in names if x.lower() not in olds and x.lower() not in (name, short)]
        if any(x.lower() in (name, short) for x in names):
            named = True
        if [ip] + names != f:
            line = " ".join([ip] + names) + ("    #" + comment if sep else "")
        out.append(line)
    if name and not named and new4:
        out.append("%s %s %s    # this machine - written by fake-igd" % (new4, name, short))
    return "\n".join(out) + "\n"


def addrs_after(before, key, method_key, new):
    """The addresses the connection gets: the first replaced by the new one, the others set by
    hand before kept (otp's net_addrs4_after)."""
    out = [new]
    if str(before.get(method_key) or "") != "manual":
        return out
    ip = new.split("/")[0].lower()
    for a in nm_list(before.get(key))[1:8]:
        if a.split("/")[0].lower() != ip and a not in out:
            out.append(a)
    return out


FIELDS = ["ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.dns-search",
          "ipv6.method", "ipv6.addresses", "ipv6.gateway", "ipv6.dns"]


def connections():
    return [l.replace("\\:", ":") for l in run([NMCLI, "-t", "-g", "NAME", "connection", "show"],
                                                "nmcli connection show").splitlines() if l]


def snapshot(con, snap_id):
    """Everything of the machine's network a change touches, kept as it is now."""
    profile_path, profile = "", None
    try:
        got = run([NMCLI, "-t", "-g", "GENERAL.FILENAME", "connection", "show", con],
                  "nmcli connection show").strip()
        if got.startswith(PROFILE_DIRS) and "/../" not in got:
            profile_path, profile = got, read_or_none(got)
    except Refused:
        pass
    snap = {"id": snap_id, "at": time.time(), "con": con, "profile_path": profile_path,
            "profile": profile, "props": nm_props(con), "hostname": static_hostname(),
            "hosts": read_or_none(HOSTS_FILE), "sysctl6": read_or_none(SYSCTL6)}
    os.makedirs(SNAP_DIR, mode=0o700, exist_ok=True)
    os.chmod(SNAP_DIR, 0o700)
    write_root(os.path.join(SNAP_DIR, SNAP_FILE), json.dumps(snap), 0o600)
    return "what the machine has now kept, to go back to: %s" % (
        "the whole profile of %s" % con if profile is not None else "the IPv4 and IPv6 settings of %s" % con)


def con_up(con):
    """The connection brought up again with what it has now - the change put in at once."""
    run([NMCLI, "--wait", "40", "connection", "up", con], "nmcli connection up", timeout=60)


def unit_of(snap_id):
    return UNIT_PREFIX + snap_id[:12]


def timer_start(snap_id, minutes):
    """systemd-run: python3 -I fake_igd_web.py --kind net {"do": "back"} in `minutes`."""
    here = os.path.dirname(os.path.abspath(__file__))
    helper = os.path.join(here, "fake_igd_web.py")
    ask = json.dumps({"do": "back", "snapshot": snap_id, "why": "not kept in time"})
    if TIMER_FILE:
        with open(TIMER_FILE, "a") as f:
            f.write("%s %d %s\n" % (unit_of(snap_id), minutes * 60, ask))
        return "the old network comes back in %d min unless kept (written to %s)" % (minutes, TIMER_FILE)
    run([SYSTEMD_RUN, "--on-active=%ds" % (minutes * 60), "--unit", unit_of(snap_id),
         "--description", "fake-igd: the network on trial taken back unless kept",
         "/usr/bin/python3", "-I", helper, "--kind", "net", ask], "systemd-run")
    return "the old network comes back by itself in %d min unless kept (%s.timer)" % (minutes, unit_of(snap_id))


def timer_stop(snap_id):
    if TIMER_FILE:
        with open(TIMER_FILE, "a") as f:
            f.write("%s stopped\n" % unit_of(snap_id))
        return
    run([SYSTEMCTL, "stop", unit_of(snap_id) + ".timer"], "systemctl stop", ok=(0, 1, 5))


def snap_read(snap_id):
    try:
        with open(os.path.join(SNAP_DIR, SNAP_FILE)) as f:
            snap = json.load(f)
    except (OSError, ValueError):
        raise Refused("nothing kept to go back to on this machine")
    if not isinstance(snap, dict) or not snap_id or snap.get("id") != snap_id:
        raise Refused("what is kept here is of another change (%s)" % str(
            (snap or {}).get("id") if isinstance(snap, dict) else "?")[:20])
    return snap


def snap_drop():
    try:
        os.unlink(os.path.join(SNAP_DIR, SNAP_FILE))
    except OSError:
        pass


def apply(n):
    if not shutil.which(NMCLI):
        raise Refused("NetworkManager (nmcli) is not on this machine: set the network by hand")
    if n["con"] not in connections():
        raise Refused("there is no connection %r here" % n["con"])
    t = trial_read()
    if t.get("state") == "trial":
        raise Refused("a change is on trial already: keep it or put it back first")
    said = []
    before = nm_fields(n["con"], FIELDS)
    old_ips = [a.split("/")[0] for k in ("ipv4.addresses", "ipv6.addresses") for a in nm_list(before.get(k))]
    host_was = static_hostname()
    if n["trial_min"]:
        said.append(snapshot(n["con"], n["snapshot"]))
    args = [NMCLI, "connection", "modify", n["con"]]
    if n["method4"] == "manual":
        args += ["ipv4.method", "manual",
                 "ipv4.addresses", ",".join(addrs_after(before, "ipv4.addresses", "ipv4.method", n["addr4"])),
                 "ipv4.gateway", n["gw4"]]
    else:
        args += ["ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", ""]
    args += ["ipv4.dns", ",".join(n["dns4"]), "ipv4.dns-search", ",".join(n["search"]),
             "ipv4.ignore-auto-dns", "yes" if (n["dns4"] or n["method4"] == "manual") else "no"]
    if n["mode6"] == "off":
        args += ["ipv6.method", "disabled", "ipv6.addresses", "", "ipv6.gateway", "", "ipv6.dns", ""]
    elif n["mode6"] == "auto":
        args += ["ipv6.method", "auto", "ipv6.addresses", "", "ipv6.gateway", "", "ipv6.dns", ",".join(n["dns6"])]
    else:
        args += ["ipv6.method", "manual",
                 "ipv6.addresses", ",".join(addrs_after(before, "ipv6.addresses", "ipv6.method", n["addr6"])),
                 "ipv6.gateway", n["gw6"], "ipv6.dns", ",".join(n["dns6"])]
    try:
        run(args, "nmcli connection modify")
        said.append("NetworkManager: %s - %s, DNS %s%s" % (
            n["con"], ("%s via %s" % (n["addr4"], n["gw4"] or "no gateway")) if n["method4"] == "manual"
            else "IPv4 by DHCP", ", ".join(n["dns4"]) or ("none" if n["method4"] == "manual" else "from DHCP"),
            {"off": ", IPv6 off", "auto": ", IPv6 automatic", "manual": ", IPv6 %s" % n["addr6"]}[n["mode6"]]))
        if n["mode6"] in ("auto", "manual"):
            write_root(SYSCTL6, "%s IPv6 on (Settings - Network)\nnet.ipv6.conf.all.disable_ipv6 = 0\n"
                       "net.ipv6.conf.default.disable_ipv6 = 0\n" % MARK, 0o644)
            run([SYSCTL, "-q", "-p", SYSCTL6], "sysctl", ok=(0, 1, 255))
        if n["hostname"] and n["hostname"] != host_was:
            run([HOSTNAMECTL, "set-hostname", n["hostname"]], "hostnamectl set-hostname")
            said.append("host name: %s" % n["hostname"])
        had = read_or_none(HOSTS_FILE)
        if had is None:
            had = "127.0.0.1 localhost localhost.localdomain\n::1 localhost localhost.localdomain\n"
        if n["hostname"] or old_ips:
            new = hosts_lines(had, n, old_ips, host_was)
            if new != had:
                write_root(HOSTS_FILE + ".fake-igd-before", had, 0o644)
                write_root(HOSTS_FILE, new, 0o644)
                said.append("%s: this machine's lines" % HOSTS_FILE)
        con_up(n["con"])
        said.append("the connection %s is up with it" % n["con"])
    except Refused as e:
        # It did not go in: what was there comes back at once, when it was kept.
        if n["trial_min"]:
            try:
                back = restore({"snapshot": n["snapshot"]}, quiet=True)
                said += back["said"]
            except Refused as e2:
                said.append("could not put the old back: %s" % e2)
            snap_drop()
        raise Refused("%s%s" % (e, " - " + "; ".join(said) if said else ""))
    if n["trial_min"]:
        said.append(timer_start(n["snapshot"], n["trial_min"]))
        trial_write({"state": "trial", "snapshot": n["snapshot"], "con": n["con"],
                     "until": time.time() + n["trial_min"] * 60, "minutes": n["trial_min"], "said": said,
                     "apply_said": said})
    else:
        trial_write({"state": "kept", "snapshot": n["snapshot"], "con": n["con"], "said": said,
                     "apply_said": said})
    return {"said": said, "trial": trial_read()}


def restore(r, quiet=False):
    """The network as it was before the change on trial: the profile put back whole, the host
    name, /etc/hosts and the IPv6 switch - the connection brought up with it (otp's net_restore)."""
    snap_id = str(r.get("snapshot") or "")
    if not SNAP_RE.match(snap_id):
        raise Refused("which change?")
    snap = snap_read(snap_id)
    con = str(snap.get("con") or "")
    said = []
    path, profile = str(snap.get("profile_path") or ""), snap.get("profile")
    done = False
    if isinstance(profile, str) and path.startswith(PROFILE_DIRS) and "/../" not in path:
        st = None
        try:
            st = os.stat(path)
        except OSError:
            pass
        write_root(path, profile, stat.S_IMODE(st.st_mode) if st else 0o600)
        try:
            run([NMCLI, "connection", "load", path], "nmcli connection load")
            done = True
            said.append("NetworkManager: the profile of %s put back as it was" % con)
        except Refused as e:
            said.append("the profile could not be loaded (%s) - its settings put back one by one" % e)
    if not done:
        props = snap.get("props") if isinstance(snap.get("props"), dict) else {}
        args = [NMCLI, "connection", "modify", con]
        for k in sorted(props):
            if PROP_RE.match(k):
                v = props[k]
                args += [k, "" if v in ("--", None) else str(v)]
        try:
            run(args, "nmcli connection modify")
            said.append("NetworkManager: every IPv4 and IPv6 setting of %s put back" % con)
        except Refused:
            keys = ("ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.dns-search",
                    "ipv4.routes", "ipv4.ignore-auto-dns", "ipv6.method", "ipv6.addresses",
                    "ipv6.gateway", "ipv6.dns", "ipv6.routes")
            args = [NMCLI, "connection", "modify", con]
            for k in keys:
                if k in props:
                    args += [k, "" if props[k] in ("--", None) else str(props[k])]
            run(args, "nmcli connection modify")
            said.append("NetworkManager: the addresses, routes and DNS of %s put back" % con)
    host = str(snap.get("hostname") or "")
    if host and NAME_RE.match(host) and host != static_hostname():
        run([HOSTNAMECTL, "set-hostname", host], "hostnamectl set-hostname")
        said.append("host name: %s" % host)
    if isinstance(snap.get("hosts"), str) and snap["hosts"] != read_or_none(HOSTS_FILE):
        write_root(HOSTS_FILE, snap["hosts"], 0o644)
        said.append("%s as it was" % HOSTS_FILE)
    if snap.get("sysctl6") is None:
        if os.path.exists(SYSCTL6):
            os.unlink(SYSCTL6)
    elif isinstance(snap.get("sysctl6"), str):
        write_root(SYSCTL6, snap["sysctl6"], 0o644)
    con_up(con)
    said.append("the connection %s is up as it was" % con)
    return {"said": said}


def serve(payload, ask):
    r = payload if isinstance(payload, dict) else {}
    what = r.get("do")
    try:
        if what == "apply":
            return dict(apply(checked(r)), ok=True)
        if what == "keep":
            snap_id = str(r.get("snapshot") or "")
            t = trial_read()
            if t.get("state") != "trial" or t.get("snapshot") != snap_id or not SNAP_RE.match(snap_id):
                raise Refused("nothing of that change is on trial")
            timer_stop(snap_id)
            snap_drop()
            said = ["kept: the new network of %s stays" % t.get("con")]
            trial_write({"state": "kept", "snapshot": snap_id, "con": t.get("con"), "said": said,
                         "apply_said": t.get("apply_said") or []})
            return {"ok": True, "said": said, "trial": trial_read()}
        if what == "back":
            snap_id = str(r.get("snapshot") or "")
            t = trial_read()
            if t.get("state") != "trial" or t.get("snapshot") != snap_id:
                raise Refused("nothing of that change is on trial (it was kept or put back)")
            why = "not kept in time" if r.get("why") == "not kept in time" else "asked"
            timer_stop(snap_id)        # its own timer too: stopping the timer leaves its service running
            try:
                got = restore(r)
            except Refused as e:
                trial_write(dict(t, state="trial", failed="could not go back: %s" % e))
                raise
            snap_drop()
            trial_write({"state": "back", "snapshot": snap_id, "con": t.get("con"), "why": why,
                         "said": got["said"], "apply_said": t.get("apply_said") or []})
            return {"ok": True, "said": got["said"], "trial": trial_read()}
        raise Refused("apply, keep or back")
    except Refused as e:
        return {"ok": False, "said": [str(e)[:600]], "trial": trial_read()}


if __name__ == "__main__":
    print(json.dumps(serve(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}, {}), indent=1))
