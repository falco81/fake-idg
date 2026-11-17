#!/usr/bin/python3 -I
"""root_selinux.py - SELinux for fake-igd (1.7.7): otp's se_* of otp_web.py (1.0.233 - 1.0.270), for one
server. Asked by the API (Settings → SELinux) through web/ask/selinux-*.json, or by `sudo upnp selinux`
through fake_igd_web.py --selinux-check / --selinux-do STEP / --selinux-report FILE:

  {"do": "check"}        how it is - the mode now and after a restart, fake-igd's module, the labels of
                         its files, the booleans and ports it needs, what SELinux refused since the
                         machine started (or since fake-igd's needs were last put in). Nothing changed.
  {"do": "prepare"}      disabled: SELINUX=permissive in /etc/selinux/config, every file labelled at the
                         next start (/.autorelabel), selinux=0 taken off the kernel's command line, the
                         module put in. Permissive: what fake-igd needs put in (module, labels, booleans,
                         ports). The machine is never restarted here.
  {"do": "enforce"}      permissive → enforcing, now and after a restart - only when nothing is missing
                         and nothing was refused.
  {"do": "permissive"}   enforcing → permissive, now and after a restart.
  {"do": "report"}       what SELinux says here, for whoever writes fake-igd's module, into
                         web/selinux-report.tar.gz (nothing is changed).

Nothing of the request is trusted: what fake-igd needs (the booleans, the ports) is worked out here, from
config.json and the SSH server's own file - never taken from the ask. Nothing of it is done unless asked;
a machine with SELinux disabled stays so.

Tests: FAKE_IGD_SELINUX_CONFIG, _RELABEL, _CMDLINE, _CIL, _LABELS (a JSON file {path: label}), _AUDITD
(active|inactive) and FAKE_IGD_ROOT_STATE; the tools (getenforce, semodule, semanage, getsebool,
setsebool, setenforce, ausearch, audit2why, restorecon, grubby) are taken from PATH.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time

_MAIN = sys.modules.get("__main__")
if getattr(_MAIN, "CHAIN", None) == "FAKE-IGD-IN" and hasattr(_MAIN, "fw_status"):
    W = _MAIN
else:
    import fake_igd_web as W

SE_CONFIG = os.environ.get("FAKE_IGD_SELINUX_CONFIG", "/etc/selinux/config")
SE_RELABEL = os.environ.get("FAKE_IGD_SELINUX_RELABEL", "/.autorelabel")
SE_CMDLINE = os.environ.get("FAKE_IGD_SELINUX_CMDLINE", "/proc/cmdline")
SE_MODULE = "fake_igd_server"
SE_CIL = os.environ.get("FAKE_IGD_SELINUX_CIL", "/opt/fake-igd/fake_igd_server.cil")
ROOT_STATE = os.environ.get("FAKE_IGD_ROOT_STATE", "/var/lib/fake-igd-root")
RUN_DIR = os.environ.get("FAKE_IGD_RUN", "/run/fake-igd-api")
WEB_ROOT = os.environ.get("FAKE_IGD_WEB_ROOT", "/var/www/fake-igd")
# What fake-igd's files should be labelled; the label is the third field of the context.
SE_LABELS = ((RUN_DIR, "httpd_var_run_t", "the folder of the API token"),
             (os.path.join(RUN_DIR, "api-token"), "httpd_var_run_t", "the API token the pages read"),
             (WEB_ROOT, "httpd_sys_content_t", "the pages"))
# httpd_runtime_t is httpd_var_run_t's newer name (an alias of it in the policies that have both).
SE_SAME = {"httpd_var_run_t": ("httpd_var_run_t", "httpd_runtime_t")}
SE_BOOLEANS = ("httpd_can_network_connect",)
SE_PORT_TYPES = ("ssh_port_t",)
# The programs whose refusals are fake-igd's business.
SE_DOMAINS = ("httpd_t", "sshd_t", "chronyd_t", "avahi_t", "logrotate_t", "unconfined_service_t",
              "init_t", "NetworkManager_t", "syslogd_t", "rpm_t", "iptables_t", "firewalld_t")
SE_APPLIED = "selinux-applied"      # when fake-igd's needs were last put in (root's own folder)
SE_REPORT_FILE = "selinux-report.tar.gz"
SE_REPORT_MOST = 2 * 1024 * 1024        # each part at most, before it is packed
SE_REPORT_PATHS = (RUN_DIR, os.path.join(RUN_DIR, "api-token"), "/var/lib/fake-igd", "/var/lib/fake-igd/web",
                   "/etc/fake-igd", "/etc/fake-igd/config.json", WEB_ROOT, "/opt/fake-igd", "/var/log/fake-igd",
                   "/etc/nginx/certs", "/etc/nginx/conf.d", "/etc/chrony.conf", "/etc/ssh/sshd_config.d",
                   "/etc/avahi/avahi-daemon.conf", "/run/php-fpm", "/etc/php-fpm.d")
SE_REPORT_COMMS = ("python", "fake-igd", "nginx", "php-fpm", "sshd", "chronyd", "avahi", "auditd")
SE_REPORT_PORT_TYPES = ("ssh_port_t", "http_port_t", "http_cache_port_t", "snmp_port_t", "ntp_port_t",
                        "unreserved_port_t", "ssdp_port_t")


class Refused(Exception):
    pass


def _read_or(path, most=1 << 20):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(most)
    except OSError:
        return None


def _put_file(path, text):
    folder = os.path.dirname(path) or "."
    tmp = os.path.join(folder, ".%s.fake-igd-new" % os.path.basename(path))
    st = None
    try:
        st = os.stat(path)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
        if st is not None:
            os.fchmod(f.fileno(), st.st_mode & 0o7777)
    os.replace(tmp, path)
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _se_run(cmd, timeout=120, light=False, data=None):
    if not shutil.which(cmd[0]):
        return None
    if light:
        # The heavy ones (semanage loads the whole policy, ausearch reads the audit log since the start)
        # at the lowest priority (otp 1.0.234).
        if shutil.which("ionice"):
            cmd = ["ionice", "-c", "3"] + cmd
        if shutil.which("nice"):
            cmd = ["nice", "-n", "19"] + cmd
    try:
        # Never the helper's own stdin (otp 1.0.270): ausearch reads a pipe there for the audit log.
        if data is None:
            return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  universal_newlines=True, timeout=timeout)
        return subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def root_state_write(name, text):
    os.makedirs(ROOT_STATE, mode=0o700, exist_ok=True)
    os.chmod(ROOT_STATE, 0o700)
    path = os.path.join(ROOT_STATE, name)
    tmp = path + ".new"
    try:
        os.unlink(tmp)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def se_applied_at():
    # In root's own folder (otp 1.0.248): in the service's, a time ahead written there hid every refusal.
    try:
        fd = os.open(os.path.join(ROOT_STATE, SE_APPLIED), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            return float((json.load(f) or {}).get("at") or 0)
    except (OSError, TypeError, ValueError, AttributeError):
        return 0.0


def se_auditd():
    """Whether what SELinux refuses is written down at all: auditd running."""
    fake = os.environ.get("FAKE_IGD_SELINUX_AUDITD")            # tests
    if fake:
        return fake == "active"
    got = _se_run(["systemctl", "is-active", "auditd"], 20)
    return got is None or (got.stdout or "").strip() == "active"


def se_mode():
    got = _se_run(["getenforce"], 20)
    if got is None:
        return "absent"                 # no SELinux on this machine at all (Debian, Ubuntu)
    m = (got.stdout or "").strip()
    return m if m in ("Enforcing", "Permissive", "Disabled") else "Disabled"


def se_config():
    text = _read_or(SE_CONFIG) or ""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(SELINUX|SELINUXTYPE)\s*=\s*([A-Za-z0-9_-]+)\s*\Z", line)
        if m:
            out[m.group(1)] = m.group(2)
    return {"mode": out.get("SELINUX", ""), "type": out.get("SELINUXTYPE", ""), "there": bool(text)}


def se_config_set(mode):
    """SELINUX= in /etc/selinux/config, the rest of the file as it is."""
    if mode not in ("permissive", "enforcing"):
        raise Refused("permissive or enforcing")
    text = _read_or(SE_CONFIG)
    if text is None:
        raise Refused("%s is not there - is the SELinux policy installed? (dnf install selinux-policy-targeted)"
                      % SE_CONFIG)
    if re.search(r"(?m)^\s*SELINUX\s*=", text):
        new = re.sub(r"(?m)^(\s*)SELINUX\s*=.*$", r"\g<1>SELINUX=%s" % mode, text)
    else:
        new = text.rstrip("\n") + "\nSELINUX=%s\n" % mode
    if new != text:
        _put_file(SE_CONFIG, new)


def se_cmdline_off():
    """selinux=0 on the kernel's command line: the config alone does not switch it on."""
    return bool(re.search(r"(?:^|\s)selinux=0(?:\s|$)", _read_or(SE_CMDLINE) or ""))


def se_label(path):
    fake = os.environ.get("FAKE_IGD_SELINUX_LABELS")         # tests: {path: label}
    if fake:
        try:
            with open(fake) as f:
                return (json.load(f) or {}).get(path)
        except (OSError, ValueError):
            return None
    try:
        raw = os.getxattr(path, "security.selinux", follow_symlinks=False)
    except (OSError, AttributeError):
        return None
    parts = raw.decode("utf-8", "replace").rstrip("\0").split(":")
    return parts[2] if len(parts) >= 3 else None


def se_module_in():
    got = _se_run(["semodule", "-l"], 120, light=True)
    if got is None or got.returncode != 0:
        return None
    return any(line.split()[:1] == [SE_MODULE] for line in got.stdout.splitlines())


def se_bool(name):
    got = _se_run(["getsebool", name], 20)
    if got is None or got.returncode != 0:
        return None
    return bool(re.search(r"-->\s*on\s*$", got.stdout.strip()))


def se_ports():
    """semanage port -l: {(type, proto): [(lo, hi), ...]}; None without semanage."""
    got = _se_run(["semanage", "port", "-l"], 120, light=True)
    if got is None or got.returncode != 0:
        return None
    out = {}
    for line in got.stdout.splitlines():
        m = re.match(r"^(\S+_port_t)\s+(tcp|udp|sctp|dccp)\s+(.+)$", line.strip())
        if not m:
            continue
        spans = []
        for p in m.group(3).split(","):
            a, _, b = p.strip().partition("-")
            try:
                spans.append((int(a), int(b or a)))
            except ValueError:
                continue
        out.setdefault((m.group(1), m.group(2)), []).extend(spans)
    return out


def se_port_has(ports, kind, proto, port):
    return any(lo <= port <= hi for lo, hi in (ports or {}).get((kind, proto), []))


def se_want():
    """What fake-igd needs of SELinux here, and why - worked out by root, never taken from the ask."""
    try:
        cfg = W.read_config()
    except Exception:                                   # noqa: BLE001
        cfg = {}
    try:
        api_port = int(cfg.get("api_port") or 9862)
    except (TypeError, ValueError):
        api_port = 9862
    bools = [{"name": "httpd_can_network_connect",
              "why": "the pages ask fake-igd's API on 127.0.0.1:%d" % api_port}]
    ports = []
    try:
        for p in W.ssh_ports():
            if p != 22:
                ports.append({"port": int(p), "proto": "tcp", "type": "ssh_port_t",
                              "why": "the SSH server listens on it"})
    except Exception:                                   # noqa: BLE001
        pass
    return bools, ports[:8], cfg


def se_facts(cfg):
    """What fake-igd uses on this server, for the report: switches and ports only - nothing secret."""
    keys = ("mode", "mapping_response", "http_port", "api_port", "igd_version", "firewall", "firewall_ssh",
            "firewall_icmp", "upgrade_check")
    out = {k: cfg.get(k) for k in keys if k in cfg}
    out["fake_igd"] = _read_or("/opt/fake-igd/VERSION", 40) or ""
    out["fake_igd"] = out["fake_igd"].strip()
    return out


def se_denials(since=0.0):
    """What SELinux refused since the machine started - or since fake-igd's needs were last put in (what was
    refused before that is what they put right) - for the programs fake-igd works with."""
    got = _se_run(["ausearch", "-m", "AVC,USER_AVC", "-ts", "boot"], 120, light=True)
    if got is None:
        return {"tool": False, "total": 0, "groups": [], "since": since}
    groups, lines, total = {}, {}, 0
    for line in (got.stdout or "").splitlines():
        if "avc:" not in line or "denied" not in line:
            continue
        when = re.search(r"msg=audit\((\d+)(?:\.\d+)?:", line)
        if since and when and int(when.group(1)) < since:
            continue
        perms = re.search(r"denied\s+\{([^}]*)\}", line)
        sc = re.search(r"scontext=(\S+)", line)
        tc = re.search(r"tcontext=(\S+)", line)
        cl = re.search(r"tclass=(\S+)", line)
        comm = re.search(r"comm=(\S+)", line)
        name = re.search(r"\bname=(\S+)", line)
        if not (perms and sc and tc and cl):
            continue
        st = (sc.group(1).split(":") + ["", "", ""])[2]
        tt = (tc.group(1).split(":") + ["", "", ""])[2]
        what = " ".join(x for x in (comm.group(1) if comm else "", name.group(1) if name else "") if x)
        if st not in SE_DOMAINS and "fake-igd" not in line and "fake_igd" not in line:
            continue
        total += 1
        key = (st, tt, cl.group(1), perms.group(1).strip())
        lines[key] = line
        g = groups.setdefault(key, {"source": st, "target": tt, "class": cl.group(1),
                                    "perms": perms.group(1).strip(), "count": 0, "what": ""})
        g["count"] += 1
        g["what"] = what.replace('"', "")[:120] or g["what"]
        g["permissive"] = "permissive=1" in line
    # Refused once, allowed now (otp 1.0.238): a module or a boolean that came after it settles it.
    settled = 0
    for key in se_allowed_now(lines):
        settled += groups[key]["count"]
        total -= groups.pop(key)["count"]
    out = sorted(groups.values(), key=lambda g: -g["count"])[:30]
    return {"tool": True, "total": total, "groups": out, "since": since, "settled": settled}


def se_allowed_now(lines):
    """Which of the refusals (one line for each kind) the policy loaded now allows, as audit2why tells:
    "would be allowed by active policy". Nothing when audit2why is not there."""
    if not lines:
        return []
    by_id = {}
    for key, line in lines.items():
        m = re.search(r"msg=audit\(([0-9.]+:\d+)\)", line)
        if m:
            by_id[m.group(1)] = key
    if not by_id:
        return []
    got = _se_run(["audit2why"], 300, light=True, data="".join(lines[k] + "\n" for k in by_id.values()))
    if got is None or got.returncode != 0:
        return []
    now, cur = set(), None
    for line in (got.stdout or "").splitlines():
        m = re.search(r"msg=audit\(([0-9.]+:\d+)\)", line)
        if m and "avc:" in line:
            cur = by_id.get(m.group(1))
            continue
        if cur is not None and "would be allowed by active policy" in line:
            now.add(cur)
    return sorted(now)


def se_check():
    bools, ports, _cfg = se_want()
    mode = se_mode()
    conf = se_config()
    out = {"mode": mode, "config": conf["mode"], "policy": conf["type"],
           "relabel_pending": os.path.exists(SE_RELABEL), "cmdline_off": se_cmdline_off(),
           "tools": {"semanage": bool(shutil.which("semanage")), "ausearch": bool(shutil.which("ausearch")),
                     "semodule": bool(shutil.which("semodule"))},
           "module": None, "labels": [], "booleans": [], "ports": [],
           "denials": {"tool": False, "total": 0, "groups": []}, "problems": [], "left_out": [],
           "cil": os.path.exists(SE_CIL), "cil_in": (_read_or(SE_CIL + ".in-policy") or "") == (_read_or(SE_CIL) or "-")}
    if mode == "absent":
        out["ready"] = False
        return out
    on = mode in ("Enforcing", "Permissive")
    out["module"] = se_module_in()
    fake = os.environ.get("FAKE_IGD_SELINUX_LABELS")
    for path, want, why in SE_LABELS:
        if not fake and not os.path.exists(path):
            continue
        got = se_label(path) if on else None
        if fake and on and got is None:
            continue
        out["labels"].append({"path": path, "label": got, "want": want, "why": why,
                              "ok": (got in SE_SAME.get(want, (want,))) if on else None})
    for b in bools:
        out["booleans"].append(dict(b, on=se_bool(b["name"]) if on else None))
    known = se_ports() if on else None
    for p in ports:
        out["ports"].append(dict(p, labelled=(se_port_has(known, p["type"], p["proto"], p["port"])
                                              if known is not None else None)))
    if on:
        out["denials"] = se_denials(se_applied_at())
        out["auditd"] = se_auditd()
    probs = out["problems"]
    if on:
        if out["module"] is False:
            probs.append("fake-igd's module (%s) is not installed" % SE_MODULE)
        probs.extend("%s is labelled %s, not %s (%s)" % (x["path"], x["label"] or "?", x["want"], x["why"])
                     for x in out["labels"] if x["ok"] is False)
        probs.extend("the boolean %s is off (%s)" % (x["name"], x["why"]) for x in out["booleans"] if x["on"] is False)
        probs.extend("port %d/%s is not labelled %s (%s)" % (x["port"], x["proto"], x["type"], x["why"])
                     for x in out["ports"] if x["labelled"] is False)
        if known is None and ports:
            probs.append("semanage is not on this machine - the ports cannot be checked "
                         "(dnf install policycoreutils-python-utils)")
        if out["denials"]["total"]:
            probs.append(("SELinux refused %d thing(s) since fake-igd's needs were put in"
                          if out["denials"].get("since") else
                          "SELinux refused %d thing(s) since the machine started") % out["denials"]["total"])
        if not out.get("auditd", True):
            probs.append("auditd does not run - what SELinux refuses is not written down "
                         "(systemctl enable --now auditd)")
        if not out["denials"]["tool"]:
            probs.append("ausearch is not on this machine - what SELinux refused cannot be read (dnf install audit)")
    out["ready"] = mode == "Permissive" and not probs
    return out


def se_apply(bools, ports, said, mark=True):
    """fake-igd's module, labels, booleans and ports - on a machine where SELinux is on. `mark`: when
    anything was changed, what SELinux refused before no longer counts."""
    changed = False
    inpol = _read_or(SE_CIL + ".in-policy")
    if os.path.exists(SE_CIL) and shutil.which("semodule") and (
            se_module_in() is not True or inpol != _read_or(SE_CIL)):
        got = _se_run(["semodule", "-i", SE_CIL], 300)
        if got is None or got.returncode != 0:
            raise Refused("semodule -i %s: %s" % (SE_CIL, ((got.stderr or got.stdout) if got else "").strip()[-200:]))
        said.append("fake-igd's module installed")
        changed = True
        try:
            shutil.copyfile(SE_CIL, SE_CIL + ".in-policy")
        except OSError:
            pass
    for b in bools:
        if se_bool(b["name"]) is False:
            got = _se_run(["setsebool", "-P", b["name"], "on"], 300)
            if got is None or got.returncode != 0:
                raise Refused("setsebool -P %s on: %s" % (b["name"], ((got.stderr or "") if got else "").strip()[-200:]))
            said.append("%s on" % b["name"])
            changed = True
    known = se_ports() if ports else {}
    for p in ports:
        if known is None:
            raise Refused("semanage is not on this machine (dnf install policycoreutils-python-utils)")
        if se_port_has(known, p["type"], p["proto"], p["port"]):
            continue
        got = _se_run(["semanage", "port", "-a", "-t", p["type"], "-p", p["proto"], str(p["port"])], 300)
        if got is not None and got.returncode != 0 and "already defined" in (got.stderr or ""):
            # Never taken from the service it belongs to (otp 1.0.234).
            raise Refused("port %d/%s is another service's in the SELinux policy - choose another port for it (%s)"
                          % (p["port"], p["proto"], p["why"]))
        if got is None or got.returncode != 0:
            raise Refused("semanage port %d/%s: %s" % (p["port"], p["proto"],
                                                       ((got.stderr or "") if got else "").strip()[-200:]))
        said.append("port %d/%s labelled %s" % (p["port"], p["proto"], p["type"]))
        changed = True
    if shutil.which("restorecon"):
        got = _se_run(["restorecon", "-R", "-v"] + [x for x in (RUN_DIR, WEB_ROOT, "/opt/fake-igd", "/etc/fake-igd",
                                                              "/var/lib/fake-igd", "/var/log/fake-igd")
                                                  if os.path.exists(x)], 300)
        if got is not None and "elabel" in (got.stdout or "") + (got.stderr or ""):
            said.append("fake-igd's files labelled again")
            changed = True
    if mark and changed:
        root_state_write(SE_APPLIED, json.dumps({"at": time.time()}))


def se_do(do):
    bools, ports, _cfg = se_want()
    said = []
    if do == "check":
        return se_check()
    if do == "report":
        data = se_report_bytes(re.sub(r"[^A-Za-z0-9._-]", "", os.uname()[1].split(".")[0])[:60] or "server")
        se_report_write_web(data)
        return {"report": SE_REPORT_FILE, "bytes": len(data), "at": time.time()}
    mode = se_mode()
    if mode == "absent":
        raise Refused("there is no SELinux on this machine")
    if do == "prepare":
        if mode == "Enforcing":
            raise Refused("SELinux is enforcing already")
        se_config_set("permissive")
        said.append("%s: SELINUX=permissive" % SE_CONFIG)
        if mode == "Disabled":
            # Every file labelled at the next start, before anything runs (minutes); the booleans and ports
            # are put in by this step again once it is permissive ("Put in what fake-igd needs").
            open(SE_RELABEL, "a").close()
            said.append("the files are labelled at the next start of the machine")
            if se_cmdline_off() and shutil.which("grubby"):
                got = _se_run(["grubby", "--update-kernel", "ALL", "--remove-args", "selinux"], 120)
                if got is None or got.returncode != 0:
                    raise Refused("grubby: %s" % ((got.stderr or "") if got else "")[-200:])
                said.append("selinux=0 taken off the kernel's command line")
            elif se_cmdline_off():
                said.append("the kernel's command line has selinux=0: take it away "
                            "(grubby --update-kernel ALL --remove-args selinux)")
            if os.path.exists(SE_CIL) and shutil.which("semodule"):
                got = _se_run(["semodule", "-i", SE_CIL], 300)        # into the store; may not work while disabled
                if got is not None and got.returncode == 0:
                    said.append("fake-igd's module installed")
            said.append("restart the machine - it comes up permissive: nothing is refused yet, what would be "
                        "is written down")
        else:
            se_apply(bools, ports, said)
    elif do == "enforce":
        if mode != "Permissive":
            raise Refused("SELinux is %s - it goes to enforcing from permissive only" % mode.lower())
        se_apply(bools, ports, said, mark=False)
        c = se_check()
        if c["problems"]:
            raise Refused("not yet: " + "; ".join(c["problems"][:4]))
        got = _se_run(["setenforce", "1"], 60)
        if got is None or got.returncode != 0:
            raise Refused("setenforce 1: %s" % ((got.stderr or "") if got else "")[-200:])
        se_config_set("enforcing")
        said.append("SELinux is enforcing, and stays so after a restart")
    elif do == "permissive":
        if mode == "Disabled":
            raise Refused('SELinux is disabled - "prepare" makes it permissive')
        if mode == "Enforcing":
            got = _se_run(["setenforce", "0"], 60)
            if got is None or got.returncode != 0:
                raise Refused("setenforce 0: %s" % ((got.stderr or "") if got else "")[-200:])
        se_config_set("permissive")
        said.append("SELinux is permissive, and stays so after a restart")
    else:
        raise Refused("check, prepare, enforce, permissive or report")
    out = se_check()
    out["said"] = said
    return out


# ---- what SELinux needs, gathered for whoever writes fake-igd's module (otp 1.0.236) ----------
def _se_out(cmd, timeout=120, data=None, light=True):
    """A command's words for the report - what it said, or why it said nothing."""
    if not shutil.which(cmd[0]):
        return "(%s is not on this machine)\n" % cmd[0]
    got = _se_run(cmd, timeout, light, data)
    if got is None:
        return "(%s: did not answer)\n" % " ".join(cmd)
    text = (got.stdout or "") + (("\n--- stderr ---\n" + got.stderr) if (got.stderr or "").strip() else "")
    b = text.encode("utf-8", "replace")
    if len(b) <= SE_REPORT_MOST:
        return text
    # The newest lines kept: the end of the audit log is what came last.
    return "(the first %d bytes left out - too long)\n" % (len(b) - SE_REPORT_MOST) + \
        b[-SE_REPORT_MOST:].decode("utf-8", "replace")


def se_report_parts():
    """Every part of the report: {name: text}. Read only - nothing is changed."""
    bools, ports, cfg = se_want()
    parts = {"check.json": json.dumps(se_check(), indent=1, sort_keys=True),
             "fake-igd.json": json.dumps({"facts": se_facts(cfg), "want": {"booleans": bools, "ports": ports}},
                                         indent=1, sort_keys=True)}
    kinds = "AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR"
    raw = _se_out(["ausearch", "-m", kinds, "-ts", "boot"], 300)
    parts["avc-raw.txt"] = raw
    parts["avc.txt"] = _se_out(["ausearch", "-m", kinds, "-ts", "boot", "-i"], 300)
    if not shutil.which("ausearch") or (raw.startswith("(") and not raw.startswith("(the first ")):
        parts["audit2why.txt"] = parts["audit2allow.te"] = raw
    else:
        log_only = raw.split("\n", 1)[1] if raw.startswith("(the first ") else raw
        parts["audit2why.txt"] = _se_out(["audit2why"], 300, data=log_only)
        parts["audit2allow.te"] = _se_out(["audit2allow", "-m", "fake_igd_local"], 300, data=log_only)
    sysw = []
    for name, cmd in (("os-release", ["cat", "/etc/os-release"]), ("kernel", ["uname", "-a"]),
                      ("started", ["uptime", "-s"]), ("getenforce", ["getenforce"]),
                      ("sestatus", ["sestatus", "-v"]),
                      ("packages", ["rpm", "-q", "selinux-policy", "selinux-policy-targeted", "policycoreutils",
                                    "policycoreutils-python-utils", "libselinux-utils", "audit", "nginx",
                                    "php-fpm", "openssh-server", "chrony", "avahi"]),
                      ("kernel command line", ["cat", SE_CMDLINE]), ("selinux config", ["cat", SE_CONFIG]),
                      ("auditd", ["systemctl", "is-active", "auditd"])):
        sysw.append("==== %s\n%s" % (name, _se_out(cmd, 60, light=False)))
    parts["system.txt"] = "\n".join(sysw)
    lab = []
    for p in SE_REPORT_PATHS:
        if os.path.lexists(p):
            lab.append(_se_out(["ls", "-Zd", p], 20, light=False).rstrip())
            if os.path.isdir(p):
                lab.append(_se_out(["ls", "-Za", p], 20, light=False).rstrip())
            lab.append("  policy says: " + _se_out(["matchpathcon", p], 20, light=False).strip())
    parts["labels.txt"] = "\n".join(lab) + "\n"
    ps = _se_out(["ps", "-eo", "label,user,pid,comm,args"], 60, light=False)
    keep = [x for x in ps.splitlines() if x.startswith("LABEL") or any(c in x for c in SE_REPORT_COMMS)]
    if not any(x.startswith("LABEL") for x in keep):
        keep = ["(ps did not give the table of processes:)"] + ps.splitlines()[:40]
    parts["processes.txt"] = "\n".join(x[:200] for x in keep) + "\n"
    pl = _se_out(["semanage", "port", "-l"], 300)
    parts["ports.txt"] = "==== labelled\n" + "\n".join(
        x for x in pl.splitlines() if x.split()[:1] and x.split()[0] in SE_REPORT_PORT_TYPES) + \
        "\n\n==== listening\n" + _se_out(["ss", "-lntupZ"], 60, light=False)
    bl = _se_out(["getsebool", "-a"], 60, light=False)
    parts["booleans.txt"] = "\n".join(x for x in bl.splitlines() if re.match(
        r"^(httpd_|authlogin_|nis_enabled|daemons_|logging_|ssh|domain_can)", x)) + "\n"
    mods = _se_out(["semodule", "-l"], 300)
    parts["modules.txt"] = "==== fake-igd\n" + "\n".join(
        x for x in mods.splitlines() if "fake_igd" in x.lower()) + "\n\n==== %s\n%s\n==== in the policy\n%s\n" % (
        SE_CIL, _read_or(SE_CIL) or "(not there)", _read_or(SE_CIL + ".in-policy") or "(none put in yet)")
    parts["README.txt"] = (
        "fake-igd - what SELinux says on this server, for whoever writes fake-igd's module (fake_igd_server).\n"
        "Made %s. Nothing was changed to make it.\n\n"
        "check.json      the card: mode, module, labels, booleans, ports, refusals\n"
        "avc*.txt        what SELinux refused since the machine started (raw and readable)\n"
        "audit2why.txt   why; audit2allow.te: what would allow it - a hint, not to be loaded\n"
        "labels.txt      the labels of fake-igd's files and what the policy says they should be\n"
        "processes.txt   the domains the programs run in; ports.txt, booleans.txt, modules.txt\n"
        "system.txt      the system, the policy and the packages; fake-igd.json: what fake-igd uses here\n\n"
        "No password, key or token of fake-igd is in it. The audit log holds the command lines of the\n"
        "programs refused something: fake-igd never puts a secret on one - other programs on this\n"
        "machine may. Look through avc*.txt before sending it on.\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
    return parts


def se_report_bytes(top):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in se_report_parts().items():
            data = text.encode("utf-8", "replace")
            info = tarfile.TarInfo("%s/%s" % (top, name))
            info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def se_report_write_web(data):
    """Into the web folder, for the API to hand out: by the folder's descriptor, a new file renamed in -
    never through a link the API's account could lay there; the group fake-igd's to read."""
    dfd = os.open(W.WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        tmp = ".%s.%d" % (SE_REPORT_FILE, os.getpid())
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            try:
                import grp
                os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
            except (KeyError, OSError):
                pass
        os.replace(tmp, SE_REPORT_FILE, src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


def se_report_write(data, out):
    """`upnp selinux report FILE`: a new file of root's, 0600 - never written over, never through a link."""
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def se_text(c):
    """`upnp selinux check`: what se_check found, for a person (otp's se_report)."""
    lines = ["SELinux: %s (config: %s%s)" % (c["mode"], c.get("config") or "?",
                                            ", %s" % c["policy"] if c.get("policy") else "")]
    if c["mode"] == "absent":
        lines.append("  no SELinux on this machine - nothing to do")
        return "\n".join(lines)
    if c.get("relabel_pending"):
        lines.append("  the files are labelled at the next start of the machine")
    if c.get("cmdline_off"):
        lines.append("  the kernel's command line has selinux=0")
    if c["mode"] == "Disabled":
        lines.append('  disabled - fake-igd runs as always; "Make it ready (permissive)" on the pages '
                     "(Settings - SELinux) or sudo upnp selinux prepare makes it permissive at the next start")
        return "\n".join(lines)
    lines.append("  module %s: %s" % (SE_MODULE, {True: "installed", False: "NOT installed", None: "?"}[c["module"]]))
    for x in c["labels"]:
        lines.append("  %s %s: %s%s" % ("ok  " if x["ok"] else "FAIL", x["path"], x["label"] or "?",
                                        "" if x["ok"] else " (want %s)" % x["want"]))
    for x in c["booleans"]:
        lines.append("  %s boolean %s: %s - %s" % ("ok  " if x["on"] else "FAIL", x["name"],
                                                   "on" if x["on"] else "off", x["why"]))
    for x in c["ports"]:
        lines.append("  %s port %d/%s %s - %s" % ("ok  " if x["labelled"] else "FAIL", x["port"], x["proto"],
                                                 x["type"], x["why"]))
    d = c["denials"]
    lines.append("  refused since the start: %s" % (d["total"] if d["tool"] else "? (ausearch is not there)"))
    if d.get("settled"):
        lines.append("  refused before, allowed now (not counted): %d" % d["settled"])
    for g in d["groups"][:15]:
        lines.append("    %4dx %s -> %s %s { %s } %s" % (g["count"], g["source"], g["target"], g["class"],
                                                         g["perms"], g["what"]))
    lines.append("ready for enforcing" if c.get("ready") else
                 ("enforcing" if c["mode"] == "Enforcing" and not c["problems"] else
                  "not ready: " + "; ".join(c["problems"][:6]) if c["problems"] else ""))
    return "\n".join(x for x in lines if x)


ACTIONS = ("check", "prepare", "enforce", "permissive", "report")


def serve(payload, ask=None):
    """An ask of the pages: {"do": STEP} - the answer carries the card (data) and what was done (said)."""
    do = str((payload or {}).get("do") or "check")
    if do not in ACTIONS:
        return {"ok": False, "do": do[:20], "said": ["check, prepare, enforce, permissive or report"]}
    try:
        data = se_do(do)
    except Refused as e:
        return {"ok": False, "do": do, "said": [str(e)[:400]]}
    except OSError as e:
        return {"ok": False, "do": do, "said": ["it went wrong: %s" % str(e)[:300]]}
    said = data.pop("said", []) if isinstance(data, dict) and do != "report" else []
    if do == "report":
        return {"ok": True, "do": do, "report": data, "said": []}
    return {"ok": True, "do": do, "data": data, "said": said}
