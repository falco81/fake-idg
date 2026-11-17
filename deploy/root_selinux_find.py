"""root_selinux_find.py - what SELinux refused on this server, each refusal found out and sorted by what puts
it right (1.7.10). Used by root_selinux.py (Settings → SELinux: Look again, Put in what is selected) and by
`sudo upnp selinux look / fix / rules`. Root's alone; nothing here trusts a request: the pages name only which
of root's own findings to put right (their ids), and root finds them again before it does anything.

Every AVC / USER_AVC / SELINUX_ERR since the machine started (ausearch -ts boot) is read with the records of
its event (SYSCALL: the program; PATH: the whole path), grouped by what was refused - the source's and the
target's types, the class, the permissions, the program, the path or the port - and each group put to
audit2why. Then sorted into one of these kinds:

  allowed    the policy loaded now allows it (audit2why: "would be allowed by active policy") - not counted
  boolean    a boolean of the policy allows it (audit2why names it)        → setsebool -P NAME 1
  label      the file is not labelled as the policy says it should be      → restorecon -R PATH
  port       a confined program fake-igd runs may not bind / connect to a port of no type of its own
                                                                           → semanage port -a -t TYPE -p PROTO PORT
  rule       nothing else allows it, and it is safe to allow exactly that  → a rule of fake-igd's own local module
                                                                             fake_igd_local: (allow SRC TGT (CLASS (PERMS)))
  unsafe     fake-igd's, but what it would take is not for a button: the target is security-sensitive
             (shadow_t, the policy, the kernel, keys ...), or it executes, or it writes where everything lives
  foreign    not fake-igd's - another program on this machine; shown, never put right here

A finding's id is a hash of what was refused (12 hex characters): the same refusal has the same id at every
look. What was put right is noted with its time in root's own folder: a refusal of it from before that time
no longer counts; from after it, it comes back.
"""
import hashlib
import json
import os
import re
import time

# The domains fake-igd's units, root's helpers and the tools the API runs are in.
FAKE_DOMAINS = ("unconfined_service_t",)
TOOL_DOMAINS = ("chronyc_t", "ifconfig_t", "hostname_t", "ssh_t", "ssh_keygen_t", "ping_t", "traceroute_t",
                "dnsmasq_t", "avahi_t", "chronyd_t")
# Confined programs fake-igd works with - fixable only for what is fake-igd's (its paths, its ports).
SERVICE_DOMAINS = ("httpd_t", "sshd_t", "init_t", "logrotate_t", "NetworkManager_t", "iptables_t",
                   "firewalld_t", "syslogd_t", "rpm_t")
# Where fake-igd's files are (a path under one is fake-igd's).
FAKE_PATHS = ("/opt/fake-igd", "/var/lib/fake-igd", "/var/log/fake-igd", "/etc/fake-igd", "/var/www/fake-igd",
              "/run/fake-igd-api", "/var/run/fake-igd-api", "/etc/nginx/conf.d/fake-igd.conf",
              "/etc/nginx/certs/fake-igd", "/etc/php-fpm.d/fake-igd.conf", "/run/php-fpm/fake-igd.sock",
              "/etc/ssh/sshd_config.d/00-fake-igd.conf", "/etc/systemd/journald.conf.d/00-fake-igd.conf",
              "/etc/sysctl.d/90-fake-igd", "/var/lib/fake-igd-net", "/var/lib/fake-igd-root",
              "/etc/logrotate.d/fake-igd", "/etc/avahi/avahi-daemon.conf", "/etc/chrony.conf")
# A port a program binds, by its domain: the type it is given.
BIND_TYPES = {"httpd_t": "http_port_t", "sshd_t": "ssh_port_t", "chronyd_t": "ntp_port_t",
              "avahi_t": "howl_port_t"}
CONNECT_TYPES = {"ssh_t": "ssh_port_t"}
# Ports of no type of their own (any program's to take).
UNTYPED_PORTS = ("unreserved_port_t", "port_t", "hi_reserved_port_t", "reserved_port_t", "ephemeral_port_t")
# Never a rule with one of these as its target (and never a boolean of these words).
SENSITIVE_TARGET = re.compile(
    r"^(shadow_t|passwd_file_t|security_t|selinux_config_t|policy_config_t|policy_src_t|load_policy_t|"
    r"semanage_.*|setfiles_.*|kernel_t|sysadm_.*|unconfined_t|unconfined_exec_t|init_t|init_exec_t|"
    r"auditd_.*|audit_.*|sshd_key_t|ssh_home_t|.*_key_t|cert_t|home_cert_t|krb5.*|sudo_.*|devlog_t|"
    r"boot_t|bootloader_.*|fixed_disk_device_t|memory_device_t|kmsg_device_t|.*_secret_t|"
    r"systemd_passwd_.*|cloud_init_.*|admin_home_t|user_home_dir_t|user_home_t)\Z")
UNSAFE_PERMS = {"execute", "execute_no_trans", "entrypoint", "execmod", "execmem", "execstack", "execheap",
                "dyntransition", "setcurrent", "ptrace", "relabelfrom", "relabelto", "mounton", "load_policy",
                "setenforce", "setbool", "setsecparam", "module_load", "module_request", "sys_admin",
                "sys_module", "sys_rawio", "sys_ptrace", "dac_override", "dac_read_search", "setuid", "setgid",
                "fowner", "chown", "mac_admin", "mac_override", "setpcap", "net_admin", "sys_boot",
                "transition", "*"}
UNSAFE_CLASSES = {"security", "kernel_service", "capability2", "system", "key", "bpf", "perf_event"}
WRITE_PERMS = {"write", "append", "create", "unlink", "rename", "setattr", "add_name", "remove_name",
               "rmdir", "link", "reparent"}
GENERIC_TYPES = {"etc_t", "usr_t", "bin_t", "lib_t", "var_t", "root_t", "default_t", "tmp_t", "var_lib_t",
                 "var_log_t", "home_root_t", "device_t", "proc_t", "sysfs_t", "var_run_t", "file_t"}
UNSAFE_BOOLEAN = re.compile(r"(exec|unconfined|secure_mode|^deny_|selinuxuser|mmap_files|ptrace|"
                            r"_manage_all|_read_all|all_files|setrlimit|sys_admin)")
ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
HEX_KEYS = ("proctitle", "name", "path", "comm", "exe", "cwd")       # strings auditd writes in hex when they must
KIND_ORDER = ("boolean", "label", "port", "rule", "unsafe", "foreign")
FIXABLE = ("boolean", "label", "port", "rule")


def _type(ctx):
    parts = (str(ctx or "").split(":") + ["", "", ""])
    return parts[2]


def _val(rec, key):
    """key=value of an audit record: "quoted", hex (an untrusted string), or plain."""
    m = re.search(r"(?:^|\s)%s=(\"[^\"]*\"|\S+)" % re.escape(key), rec)
    if not m:
        return ""
    v = m.group(1)
    if v.startswith('"'):
        return v[1:-1]
    if key in HEX_KEYS and v != "(null)" and re.match(r"^[0-9A-F]+\Z", v) and len(v) % 2 == 0 and len(v) >= 2:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return "" if v == "(null)" else v


def parse(text):
    """ausearch's raw output → one dict for each AVC of each event: {id, at, source, target, class, perms,
    comm, exe, path, port, proto, permissive, line}."""
    events = {}
    order = []
    for line in (text or "").splitlines():
        m = re.search(r"msg=audit\((\d+)(?:\.(\d+))?:(\d+)\)", line)
        if not m:
            continue
        eid = "%s.%s:%s" % (m.group(1), m.group(2) or "000", m.group(3))
        ev = events.get(eid)
        if ev is None:
            ev = events[eid] = {"at": int(m.group(1)), "recs": []}
            order.append(eid)
        ev["recs"].append(line)
    out = []
    for eid in order:
        ev = events[eid]
        syscall = next((r for r in ev["recs"] if "type=SYSCALL" in r), "")
        paths = [r for r in ev["recs"] if "type=PATH" in r]
        cwd = next((_val(r, "cwd") for r in ev["recs"] if "type=CWD" in r), "")
        title = next((_val(r, "proctitle") for r in ev["recs"] if "type=PROCTITLE" in r), "")
        for rec in ev["recs"]:
            if not re.search(r"type=(USER_)?AVC\b|type=SELINUX_ERR\b", rec):
                continue
            if "avc:" in rec and "denied" not in rec:
                continue
            perms = re.search(r"denied\s+\{([^}]*)\}", rec)
            sc, tc, cl = _val(rec, "scontext"), _val(rec, "tcontext"), _val(rec, "tclass")
            if not (perms and sc and tc and cl):
                continue
            name = _val(rec, "name")
            path = _val(rec, "path")
            if not path:
                full = [_val(p, "name") for p in paths if _val(p, "name").startswith("/")]
                if full:
                    path = next((x for x in full if name and x.endswith("/" + name)), full[-1])
                elif name.startswith("/"):
                    path = name
                elif name and cwd.startswith("/") and "/" not in name:
                    path = ""            # a bare name: the folder is not known for sure
            port = _val(rec, "dest") if "name_connect" in perms.group(1) else (_val(rec, "src") or _val(rec, "dest"))
            out.append({"id": eid, "at": ev["at"], "source": _type(sc), "target": _type(tc), "class": cl,
                        "perms": sorted(set(perms.group(1).split())), "comm": _val(rec, "comm") or _val(syscall, "comm"),
                        "exe": _val(syscall, "exe") or _val(rec, "exe"), "path": path, "name": name,
                        "port": int(port) if port.isdigit() else None,
                        "proto": "udp" if cl.startswith("udp") else ("tcp" if cl.startswith("tcp") else ""),
                        "permissive": "permissive=1" in rec, "line": rec.strip(), "title": title[:200]})
    return out


def finding_id(d):
    key = "|".join([d["source"], d["target"], d["class"], " ".join(d["perms"]), d.get("comm") or "",
                    d.get("path") or "", str(d.get("port") or "")])
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:12]


def group(denials):
    """The denials grouped into findings (one for each id), with how many and when first and last."""
    out = {}
    for d in denials:
        fid = finding_id(d)
        f = out.get(fid)
        if f is None:
            f = out[fid] = dict({k: d[k] for k in ("source", "target", "class", "perms", "comm", "exe", "path",
                                                    "name", "port", "proto", "title")},
                                id=fid, count=0, first=d["at"], last=d["at"], line=d["line"],
                                audit_id=d["id"], permissive=d["permissive"])
        f["count"] += 1
        f["first"] = min(f["first"], d["at"])
        if d["at"] >= f["last"]:
            f["last"], f["line"], f["audit_id"], f["permissive"] = d["at"], d["line"], d["id"], d["permissive"]
    return out


def why_parse(text, by_audit_id):
    """audit2why's words → {finding id: {"allowed": bool, "boolean": NAME or "", "why": words}}."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = re.search(r"msg=audit\((\d+)(?:\.(\d+))?:(\d+)\)", line)
        if m and ("avc:" in line or "type=" in line):
            cur = by_audit_id.get("%s.%s:%s" % (m.group(1), m.group(2) or "000", m.group(3)))
            if cur is not None:
                out.setdefault(cur, {"allowed": False, "boolean": "", "why": ""})
            continue
        if cur is None:
            continue
        s = line.strip()
        if not s or s.startswith("Was caused by") or s.startswith("Description:") or \
                s.startswith("Allow access by executing"):
            continue
        w = out[cur]
        if "would be allowed by active policy" in s or "allowed by the current policy" in s:
            w["allowed"] = True
        b = re.search(r"setsebool\s+-P\s+([A-Za-z0-9_]+)\s+(?:1|on|true)", s)
        if b:
            w["boolean"] = w["boolean"] or b.group(1)
            continue
        if not s.startswith("#") and len(w["why"]) < 300:
            w["why"] = (w["why"] + " " + s).strip()[:300]
    return out


def fake_igds(f, api_port=9862):
    """Whether a finding is fake-igd's to put right: its own program, a tool it runs, or a confined service
    it works with - for its own paths and ports only."""
    src, path, port = f["source"], f.get("path") or "", f.get("port")
    ours_path = any(path == p or path.startswith(p.rstrip("/") + "/") or path.startswith(p) for p in FAKE_PATHS
                    if path)
    if src in FAKE_DOMAINS:
        exe, comm, title = f.get("exe") or "", f.get("comm") or "", f.get("title") or ""
        return (exe.startswith("/opt/fake-igd") or comm.startswith(("bg-", "fake-igd", "fake_igd")) or
                "fake-igd" in title or "fake_igd" in title or ours_path)
    if src in TOOL_DOMAINS:
        return True
    if src == "httpd_t":
        return ours_path or port == api_port or f["target"] in ("httpd_var_run_t", "httpd_runtime_t") and ours_path
    if src in ("sshd_t", "logrotate_t", "init_t", "syslogd_t", "NetworkManager_t", "iptables_t", "firewalld_t",
               "rpm_t"):
        return ours_path or (src == "sshd_t" and "name_bind" in f["perms"])
    return False


def classify(f, why, matchpathcon=None, port_types=None, api_port=9862):
    """One finding → kind, fix (what root does), says (for a person). why: audit2why's for it."""
    w = why or {}
    perms, cls, src, tgt = set(f["perms"]), f["class"], f["source"], f["target"]
    if w.get("allowed"):
        return "allowed", None, "the policy loaded now allows it (a module or a boolean put in since)"
    ours = fake_igds(f, api_port)
    known_src = src in FAKE_DOMAINS + TOOL_DOMAINS + SERVICE_DOMAINS
    # Never put right from here, whoever it is: a security-sensitive target, or running a program.
    if known_src and (SENSITIVE_TARGET.match(tgt) or perms & {"execute", "execute_no_trans", "entrypoint",
                                                              "execmod", "execmem"}):
        return "unsafe", None, rule_unsafe(f) or "never allowed from here"
    if not ours:
        return "foreign", None, ("not fake-igd's: %s (%s) is another program of this machine - look at it with "
                                 "whoever looks after it" % (f.get("comm") or "?", src))
    b = w.get("boolean") or ""
    if b:
        if UNSAFE_BOOLEAN.search(b):
            return "unsafe", None, ("the boolean %s would allow it - it allows far more than this: an admin's "
                                    "call, not a button's" % b)
        return "boolean", {"do": "boolean", "name": b, "cmd": "setsebool -P %s 1" % b}, \
            "the boolean %s allows it" % b
    path = f.get("path") or ""
    if path and matchpathcon is not None and cls in ("file", "dir", "lnk_file", "sock_file", "fifo_file"):
        want = matchpathcon(path)
        if want and want != tgt and not (want in ("httpd_var_run_t", "httpd_runtime_t") and
                                         tgt in ("httpd_var_run_t", "httpd_runtime_t")):
            target = path if cls == "dir" else os.path.dirname(path) if tgt in ("default_t", "var_t", "unlabeled_t") \
                and os.path.dirname(path) not in ("/", "") else path
            return "label", {"do": "label", "path": target, "want": want,
                             "cmd": "restorecon -R -v %s" % target}, \
                "%s is labelled %s - the policy says %s" % (path, tgt, want)
    if f.get("port") and perms & {"name_bind", "name_connect"} and cls in ("tcp_socket", "udp_socket"):
        want = (BIND_TYPES if "name_bind" in perms else CONNECT_TYPES).get(src)
        p = int(f["port"])
        if want and tgt in UNTYPED_PORTS:
            return "port", {"do": "port", "type": want, "proto": f["proto"] or "tcp", "port": p,
                            "cmd": "semanage port -a -t %s -p %s %d" % (want, f["proto"] or "tcp", p)}, \
                "port %d/%s has no type of its own - %s may %s it once it is %s" % (
                    p, f["proto"] or "tcp", src, "bind" if "name_bind" in perms else "connect to", want)
        if want and port_types is not None and tgt not in UNTYPED_PORTS:
            return "unsafe", None, ("port %d/%s is %s - another service's; it is not taken from it (choose "
                                    "another port)" % (p, f["proto"] or "tcp", tgt))
    bad = rule_unsafe(f)
    if bad:
        return "unsafe", None, bad
    if src in ("sshd_t", "avahi_t", "chronyd_t", "NetworkManager_t", "firewalld_t", "iptables_t", "rpm_t",
               "syslogd_t") and not tgt.startswith(src[:-2]):
        return "unsafe", None, ("a rule for %s, the system's own service: an admin's call, not a button's - the "
                                "report says what it is" % src)
    return "rule", {"do": "rule", "source": src, "target": tgt, "class": cls, "perms": sorted(perms),
                    "cmd": "(allow %s %s (%s (%s)))" % (src, tgt, cls, " ".join(sorted(perms)))}, \
        "nothing of the policy allows it: a rule of fake-igd's own local module allows exactly this"


def rule_unsafe(f):
    """Why a rule for this would not be safe to put in from a button - or ""."""
    perms, cls, tgt = set(f["perms"]), f["class"], f["target"]
    if SENSITIVE_TARGET.match(tgt):
        return "%s is security-sensitive (%s) - never allowed from here" % (tgt, cls)
    if cls in UNSAFE_CLASSES:
        return "the class %s is the kernel's or the policy's own - never allowed from here" % cls
    risky = sorted(perms & UNSAFE_PERMS)
    if risky:
        return "%s { %s } would let it run, change or reach far more than this - never allowed from here" % (
            cls, " ".join(risky))
    if perms & WRITE_PERMS and tgt in GENERIC_TYPES:
        return ("writing to %s (what most of the system is labelled) would allow far more than this - put the "
                "file's label right instead" % tgt)
    if not re.match(r"^[A-Za-z0-9_]+\Z", f["source"]) or not re.match(r"^[A-Za-z0-9_]+\Z", tgt) or \
            not re.match(r"^[a-z0-9_]+\Z", cls) or not all(re.match(r"^[a-z0-9_]+\Z", p) for p in perms):
        return "the refusal does not read as a plain rule"
    return ""


def findings(text, why_text_of, matchpathcon=None, port_types=None, fixed=None, since=0.0, api_port=9862,
             most=200):
    """Everything found out: [finding], sorted (kind, then how many). why_text_of(lines) → audit2why's words."""
    denials = [d for d in parse(text) if not since or d["at"] >= since]
    groups = group(denials)
    by_aid = {g["audit_id"]: fid for fid, g in groups.items()}
    whys = why_parse(why_text_of([g["line"] for g in groups.values()]) if groups else "", by_aid)
    out, fixed = [], fixed or {}
    for fid, g in groups.items():
        at_fix = float(fixed.get(fid) or 0)
        if at_fix and g["last"] <= at_fix:
            continue                                # put right, and not refused again since
        kind, fix, says = classify(g, whys.get(fid), matchpathcon, port_types, api_port)
        g.update(kind=kind, fix=fix, says=says, why=(whys.get(fid) or {}).get("why", ""))
        g.pop("line", None)
        out.append(g)
    out.sort(key=lambda g: (KIND_ORDER.index(g["kind"]) if g["kind"] in KIND_ORDER else 9, -g["count"]))
    return out[:most]


# ---- fake-igd's local module: the rules put in from the card ---------------------------------
def local_cil(rules):
    """The CIL of fake_igd_local: each rule in an optional block of its own, named after its id - a rule
    whose type the policy does not have is left out, never the module."""
    lines = ["; fake-igd's local rules (fake_igd_local) - put in from Settings → SELinux (Put in what is selected)",
             "; or `upnp selinux fix`, each exactly what SELinux refused here and nothing more. Taken away one by",
             "; one on the same card (or `upnp selinux rules --take-away ID`); the module goes with uninstall.sh.",
             "; Written by root; never edited by hand: the next change writes it again from its list.", ""]
    for r in rules:
        lines.append("; %s - %s (%s)" % (r["id"], str(r.get("why") or "")[:150].replace("\n", " "),
                                        time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("at") or 0))))
        lines.append("(optional fake_igd_local_%s" % r["id"])
        lines.append("    (allow %s %s (%s (%s))))" % (r["source"], r["target"], r["class"], " ".join(r["perms"])))
    return "\n".join(lines) + "\n"


def rule_checked(r):
    """A rule as kept in root's folder, checked again before it is written into the module."""
    if not isinstance(r, dict) or not ID_RE.match(str(r.get("id") or "")):
        return None
    f = {"source": str(r.get("source") or ""), "target": str(r.get("target") or ""),
         "class": str(r.get("class") or ""), "perms": [str(p) for p in (r.get("perms") or [])][:32]}
    if not f["perms"] or rule_unsafe(f):
        return None
    return dict(f, id=r["id"], why=str(r.get("why") or "")[:200], at=float(r.get("at") or 0),
                by=str(r.get("by") or "")[:80], comm=str(r.get("comm") or "")[:60])


def state_read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}
