"""mDNS / Avahi: the reflector (avahi-daemon with enable-reflector=yes) that repeats mDNS between
the server's networks - shown and controlled by `upnp mdns ...` and the console.

avahi-daemon.conf is changed line by line: comments and everything else stay as they are, a
copy is kept beside it before each change, the new value is checked first, and when the daemon
does not come back up with it the copy is put back and the daemon started again with it.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import time

CONF = os.environ.get("UPNP_AVAHI_CONF", "/etc/avahi/avahi-daemon.conf")
SERVICE = "avahi-daemon"
KNOWN = {
    # key: (section, kind, words)
    "use-ipv4": ("server", "bool", "mDNS over IPv4"),
    "use-ipv6": ("server", "bool", "mDNS over IPv6"),
    "allow-interfaces": ("server", "ifaces", "the interfaces avahi uses (and reflects between); empty = all"),
    "deny-interfaces": ("server", "ifaces", "interfaces avahi never uses"),
    "cache-entries-max": ("server", "int", "records kept in the cache (0 = none - every query asked again)"),
    "ratelimit-interval-usec": ("server", "int", "rate limit: the interval in microseconds"),
    "ratelimit-burst": ("server", "int", "rate limit: packets allowed in one interval"),
    "enable-wide-area": ("wide-area", "bool", "wide-area (unicast DNS-SD) browsing"),
    "publish-hinfo": ("publish", "bool", "publish the machine's HINFO record"),
    "publish-workstation": ("publish", "bool", "publish this machine as a workstation"),
    "disable-publishing": ("publish", "bool", "publish nothing of this machine"),
    "enable-reflector": ("reflector", "bool", "repeat mDNS between the interfaces (the reflector)"),
    "reflect-ipv": ("reflector", "bool", "reflect between IPv4 and IPv6 too"),
    "reflect-filters": ("reflector", "list", "reflect only these service types (e.g. _airplay._tcp.local); empty = all"),
}
DEFAULT = {"use-ipv4": "yes", "use-ipv6": "yes", "enable-reflector": "no", "reflect-ipv": "no",
           "enable-wide-area": "yes", "publish-hinfo": "no", "publish-workstation": "no",
           "disable-publishing": "no", "cache-entries-max": "4096", "allow-interfaces": "",
           "deny-interfaces": "", "reflect-filters": "", "ratelimit-interval-usec": "",
           "ratelimit-burst": ""}


class MdnsError(Exception):
    pass


# ---- reading ----------------------------------------------------------------------------
def read_conf(path=CONF):
    """{key: value} of the active (not commented) lines, and the raw lines."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().split("\n")
    except FileNotFoundError:
        raise MdnsError("%s does not exist - is avahi installed? (dnf install avahi)" % path)
    except PermissionError:
        raise MdnsError("%s cannot be read - run as root" % path)
    vals, sect = {}, ""
    for ln in lines:
        s = ln.strip()
        m = re.match(r"^\[([^\]]+)\]$", s)
        if m:
            sect = m.group(1).strip()
            continue
        if not s or s.startswith(("#", ";")) or "=" not in s:
            continue
        k, v = s.split("=", 1)
        vals[k.strip()] = v.strip()
    return vals, lines


def effective(vals):
    out = dict(DEFAULT)
    out.update(vals)
    return out


def systemd_state(unit=SERVICE):
    try:
        r = subprocess.run(["systemctl", "show", unit, "-p", "ActiveState,SubState,MainPID,ActiveEnterTimestamp,UnitFileState"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    d = {}
    for ln in r.stdout.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            d[k] = v
    return d


def version():
    for cmd in (["avahi-daemon", "--version"], ["/usr/sbin/avahi-daemon", "--version"]):
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", r.stdout)
            if m:
                return m.group(1)
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def system_ifaces():
    """{name: [ipv4...]} of the interfaces the kernel has (sysfs + ioctl, no tools needed)."""
    import fcntl
    import struct
    out = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _, name in socket.if_nameindex():
            ip = None
            try:
                ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))[20:24])
            except OSError:
                pass
            out[name] = [ip] if ip else []
    finally:
        s.close()
    return out


def status(path=CONF):
    vals, _lines = read_conf(path)
    eff = effective(vals)
    sd = systemd_state()
    allow = [x.strip() for x in eff.get("allow-interfaces", "").split(",") if x.strip()]
    deny = [x.strip() for x in eff.get("deny-interfaces", "").split(",") if x.strip()]
    sysif = system_ifaces()
    used = [i for i in (allow or [n for n in sysif if n != "lo"]) if i not in deny]
    return {
        "service": {"state": sd.get("ActiveState", "unknown"), "sub": sd.get("SubState", "?"),
                    "pid": sd.get("MainPID", "0"), "since": sd.get("ActiveEnterTimestamp", ""),
                    "boot": sd.get("UnitFileState", "-")},
        "version": version(),
        "config": path,
        "reflector": eff.get("enable-reflector", "no") == "yes",
        "reflect_ipv": eff.get("reflect-ipv", "no") == "yes",
        "reflect_filters": [x.strip() for x in eff.get("reflect-filters", "").split(",") if x.strip()],
        "ipv4": eff.get("use-ipv4", "yes") == "yes",
        "ipv6": eff.get("use-ipv6", "yes") == "yes",
        "allow_interfaces": allow, "deny_interfaces": deny,
        "interfaces": [{"name": n, "ipv4": sysif.get(n, []), "exists": n in sysif} for n in used],
        "missing_interfaces": [n for n in allow if n not in sysif],
        "cache_entries_max": eff.get("cache-entries-max"),
        "ratelimit": {"interval_usec": eff.get("ratelimit-interval-usec") or None,
                      "burst": eff.get("ratelimit-burst") or None},
        "wide_area": eff.get("enable-wide-area", "yes") == "yes",
        "browse_tool": bool(shutil.which("avahi-browse")),
        "set": vals,
    }


# ---- services on the network --------------------------------------------------------------
def _unescape(s):
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s).replace("\\.", ".").replace("\\\\", "\\")


def parse_browse(line):
    """One line of `avahi-browse -p`: + new, - gone, = resolved."""
    parts = line.split(";")
    if len(parts) < 6 or parts[0] not in ("+", "-", "="):
        return None
    d = {"event": {"+": "new", "-": "gone", "=": "resolved"}[parts[0]], "iface": parts[1],
         "proto": parts[2], "name": _unescape(parts[3]), "type": parts[4], "domain": parts[5]}
    if parts[0] == "=" and len(parts) >= 9:
        d.update(host=parts[6], address=parts[7], port=parts[8],
                 txt=_unescape(";".join(parts[9:])) if len(parts) > 9 else "")
    return d


def services(resolve=True, timeout=15):
    """What mDNS shows now on every interface (avahi-browse -a -t -p [-r])."""
    if not shutil.which("avahi-browse"):
        raise MdnsError("avahi-browse is missing - dnf install avahi-tools")
    argv = ["avahi-browse", "-a", "-t", "-p"] + (["-r"] if resolve else [])
    try:
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        r = e
        r.stdout = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
    if getattr(r, "returncode", 0) and "Daemon not running" in (getattr(r, "stderr", "") or ""):
        raise MdnsError("avahi-daemon is not running")
    seen = {}
    for ln in (r.stdout or "").splitlines():
        d = parse_browse(ln)
        if not d:
            continue
        k = (d["iface"], d["proto"], d["name"], d["type"])
        if d["event"] == "resolved" or k not in seen:
            seen[k] = d
    return sorted(seen.values(), key=lambda d: (d["type"], d["name"], d["iface"], d["proto"]))


# ---- changing ---------------------------------------------------------------------------
def check(key, value, sysif=None):
    """The value as avahi takes it, or MdnsError."""
    if key not in KNOWN:
        raise MdnsError("unknown key %s - known: %s" % (key, ", ".join(sorted(KNOWN))))
    _sect, kind, _w = KNOWN[key]
    v = str(value).strip()
    if kind == "bool":
        low = v.lower()
        if low in ("yes", "on", "true", "1"):
            return "yes"
        if low in ("no", "off", "false", "0"):
            return "no"
        raise MdnsError("%s takes yes or no" % key)
    if kind == "int":
        if v == "":
            return ""
        if not v.isdigit():
            raise MdnsError("%s takes a whole number" % key)
        return v
    items = [x.strip() for x in re.split(r"[,\s]+", v) if x.strip()]
    if v.lower() in ("", "none", "all", "-"):
        return ""
    if kind == "ifaces":
        known = sysif if sysif is not None else system_ifaces()
        bad = [i for i in items if i not in known]
        if bad:
            raise MdnsError("no such interface: %s (there are: %s)" % (", ".join(bad), ", ".join(sorted(known))))
    if kind == "list":
        bad = [i for i in items if not re.match(r"^_[A-Za-z0-9-]+\._(tcp|udp)(\.local)?$", i)]
        if bad:
            raise MdnsError("not a service type: %s (like _airplay._tcp.local)" % ", ".join(bad))
        items = [i if i.endswith(".local") else i + ".local" for i in items]
    return ",".join(items)


def edited(lines, changes):
    """`lines` with `changes` {key: value or ''} put in: an active line replaced, else a commented
    `#key=` uncommented under its section, else added at the end of its section (made if missing).
    '' comments the key out (as it comes)."""
    out = list(lines)
    for key, value in changes.items():
        sect = KNOWN[key][0]
        cur, idx_active, idx_comment, s_start, s_end = "", None, None, None, None
        for i, ln in enumerate(out):
            st = ln.strip()
            m = re.match(r"^\[([^\]]+)\]$", st)
            if m:
                if cur == sect and s_end is None:
                    s_end = i
                cur = m.group(1).strip()
                if cur == sect:
                    s_start = i
                continue
            if cur != sect:
                continue
            if re.match(r"^%s\s*=" % re.escape(key), st):
                idx_active = i
            elif idx_comment is None and re.match(r"^[#;]\s*%s\s*=" % re.escape(key), st):
                idx_comment = i
        if s_start is not None and s_end is None:
            s_end = len(out)
        if value == "":
            if idx_active is not None:
                out[idx_active] = "#" + out[idx_active].strip()
            continue
        new = "%s=%s" % (key, value)
        if idx_active is not None:
            out[idx_active] = new
        elif idx_comment is not None:
            out.insert(idx_comment + 1, new)
        elif s_start is not None:
            at = s_end
            while at > s_start + 1 and not out[at - 1].strip():
                at -= 1
            out.insert(at, new)
        else:
            if out and out[-1].strip():
                out.append("")
            out += ["[%s]" % sect, new]
    return out


def apply(changes, restart=True, path=CONF, log=print):
    """Change avahi-daemon.conf safely; returns words. Root only."""
    if os.geteuid() != 0:
        raise MdnsError("changing avahi needs root: sudo upnp mdns ...")
    sysif = system_ifaces()
    clean = {k: check(k, v, sysif) for k, v in changes.items()}
    vals, lines = read_conf(path)
    new_lines = edited(lines, clean)
    if new_lines == lines:
        return "nothing changed - %s already as asked" % ", ".join("%s=%s" % kv for kv in clean.items())
    st = os.stat(path)
    backup = "%s.bak-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    tmp = "%s.upnp-%d.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines))
    os.chmod(tmp, st.st_mode & 0o777)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, path)
    if shutil.which("restorecon"):
        subprocess.call(["restorecon", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    said = "%s changed: %s (copy kept: %s)" % (path, ", ".join(
        "%s=%s" % (k, v if v != "" else "(as it comes)") for k, v in clean.items()), backup)
    if not restart:
        return said + "; avahi-daemon not restarted"
    was_active = systemd_state().get("ActiveState") == "active"
    rc = subprocess.call(["systemctl", "restart", SERVICE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    if rc == 0 and systemd_state().get("ActiveState") == "active":
        return said + "; avahi-daemon restarted"
    # It did not come up with it: the copy put back, the daemon started again with it.
    shutil.copy2(backup, path)
    if was_active:
        subprocess.call(["systemctl", "restart", SERVICE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    raise MdnsError("avahi-daemon did not start with the change - the previous file was put back%s. "
                    "See: journalctl -u avahi-daemon -n 30" % (" and the daemon started again" if was_active else ""))


def to_json(x):
    return json.dumps(x, ensure_ascii=False, indent=2)
