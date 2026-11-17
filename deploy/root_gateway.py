"""root_gateway.py - root's part of Settings → Gateway mode (1.7.15).

A PS5 asks UPnP only of its default gateway: answered by fake-igd but with the real router as its
gateway, it never fetched the description. In the gateway mode the chosen devices (gateway_clients)
use this server as their default gateway, and this server forwards their traffic to the real router.
What root does for it, asked through the queue (kind "gateway"):

  do=apply   what the pages saved (gateway_mode, gateway_clients - read from the database, never from
             the ask) put in:
               on:  /etc/sysctl.d/90-fake-igd-gateway.conf - net.ipv4.ip_forward = 1 and
                    send_redirects = 0 for all, default and every interface (an ICMP redirect would
                    send the device to the router directly), applied with sysctl -p of that file;
                    what ip_forward and send_redirects were before is remembered. With fake-igd's
                    firewall on (iptables): the chain FAKE-IGD-FWD first in FORWARD, accepting from
                    and to the devices, kept in /etc/sysconfig/iptables (fake_igd_web.fwd_sync).
               off: the file taken away, ip_forward and send_redirects put back to what they were,
                    the chain taken away - never forwarding left on for nothing.
             ON TRIAL as every change of the firewall (fw_confirm_min): unless somebody presses Keep
             it, what was there comes back by itself (a systemd-run timer; the API's background asks
             should that be lost). Turning it off is never on trial. Anything refused half way puts
             everything back as it was.
  do=keep | back | expire   the banner's buttons, and the timer
  do=read    how it stands: forwarding on, the rules, the packets forwarded for each device

IPv6 forwarding is never turned on (the mode is IPv4's; a device's IPv6 goes as it went).
State: web/gateway.json (root's, the group fake-igd may read it): what is put in, what was before,
the trial, and the last reading. Paths for tests: FAKE_IGD_SYSCTL_GW, FAKE_IGD_PROC_SYS,
FAKE_IGD_SYSCTL, FAKE_IGD_SYSTEMD_RUN (and fake_igd_web.py's).
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
STATE = W.GW_STATE
ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}\Z")
MOST_CLIENTS = 32
HELPER = os.path.join(os.path.dirname(os.path.abspath(W.__file__)), "fake_igd_web.py")


# ---- what is asked: the settings, checked again here ----------------------------------------------
def clients_checked(raw, strict=True):
    """IPv4 addresses and networks: never everybody (0.0.0.0/0), nothing wider than a /16."""
    out = []
    for one in raw if isinstance(raw, list) else []:
        try:
            n = ipaddress.ip_network(str(one).strip(), strict=False)
        except ValueError:
            if strict:
                raise W.Refused("%s is not an IPv4 address or network" % str(one)[:60])
            continue
        bad = n.version != 4 and "IPv4 only - IPv6 forwarding is not turned on" or \
            n.prefixlen < 16 and "never everybody: a network of /16 at the widest" or \
            (n.is_loopback or n.is_multicast or n.is_unspecified) and "not an address of a device"
        if bad:
            if strict:
                raise W.Refused("%s: %s" % (n, bad))
            continue
        if str(n) not in out:
            out.append(str(n))
    if len(out) > MOST_CLIENTS:
        raise W.Refused("%d devices or networks at most" % MOST_CLIENTS)
    return out


def wanted():
    s = W.module_settings()
    try:
        trial_min = int(s.get("fw_confirm_min", 5))
    except (TypeError, ValueError):
        trial_min = 5
    return {"mode": s.get("gateway_mode") is True,
            "clients": clients_checked(s.get("gateway_clients") or [], strict=False),
            "trial_min": max(0, min(120, trial_min))}


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


def ifaces():
    """Every interface the kernel has an IPv4 configuration for (not lo, all, default)."""
    try:
        names = os.listdir(os.path.join(PROC, "net/ipv4/conf"))
    except OSError:
        return []
    return sorted(n for n in names if n not in ("all", "default", "lo") and IFACE_RE.match(n))


def sysctl_text(names):
    lines = ["# Written by fake-igd (Settings → Gateway mode) - taken away when the mode is switched off.",
             "# This server forwards the traffic of the devices that use it as their gateway.",
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
    """ip_forward and send_redirects as they are, to put back when the mode goes off."""
    redir = {k: proc_read("net/ipv4/conf/%s/send_redirects" % k) for k in ["all", "default"] + ifaces()}
    return {"ip_forward": proc_read("net/ipv4/ip_forward") or "0",
            "send_redirects": {k: v for k, v in redir.items() if v in ("0", "1")}}


def sysctl_on(said):
    text = sysctl_text(ifaces())
    os.makedirs(os.path.dirname(SYSCTL_FILE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fake-igd-gateway.", dir=os.path.dirname(SYSCTL_FILE))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        os.fchmod(f.fileno(), 0o644)
    os.replace(tmp, SYSCTL_FILE)
    r = subprocess.run([SYSCTL, "-q", "-p", SYSCTL_FILE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    if r.returncode != 0:
        raise W.Refused("sysctl -p %s: %s" % (SYSCTL_FILE, r.stdout.strip()[:300]))
    if proc_read("net/ipv4/ip_forward") != "1":
        raise W.Refused("net.ipv4.ip_forward is still 0 after sysctl -p - something keeps it off")
    said.append("forwarding on: net.ipv4.ip_forward = 1, no ICMP redirects (%s, kept over a reboot)" % SYSCTL_FILE)


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
    if had or fwd == "0":
        said.append("forwarding as it was before the gateway mode: net.ipv4.ip_forward = %s%s"
                    % (fwd, " (%s taken away)" % SYSCTL_FILE if had else ""))


# ---- putting it in --------------------------------------------------------------------------------
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


def put(st, mode, clients, said):
    """The mode as asked, put in - all of it or nothing (everything put back on a refusal)."""
    snap = snapshot()
    was = {"mode": st.get("mode") is True, "clients": list(st.get("clients") or [])}
    try:
        if mode and clients:
            if not was["mode"] or not isinstance(st.get("before"), dict):
                st["before"] = before_now()
            sysctl_on(said)
        else:
            sysctl_off(st.get("before"), said)
            st.pop("before", None)
        st["mode"], st["clients"] = bool(mode and clients), list(clients) if mode else []
        state_write(st)
        cfg = W.read_config()
        said += W.fwd_sync(cfg)
        if st["mode"]:
            fw_on = W.flag(cfg.get("firewall"), False)
            back = W.fw_backend()
            if back == "firewalld":
                said.append("firewalld manages this machine's firewall: fake-igd's chain is not used - let the "
                            "devices' forwarding through there (firewall-cmd --add-forward on their zone)")
            elif not fw_on:
                fv = W.forward_view()
                said.append("fake-igd's firewall is off: the system's own FORWARD rules decide%s"
                            % (" - and they reject (policy %s or a REJECT/DROP rule): switch fake-igd's firewall "
                               "on, or let the devices through yourself" % (fv.get("policy") or "?")
                               if fv.get("rejects") else ""))
            said.append("IPv6 forwarding is not turned on: the devices' IPv6 goes as it went")
    except BaseException as e:
        st["mode"], st["clients"] = was["mode"], was["clients"]
        try:
            state_write(st)
        except OSError:
            pass
        restore(snap)
        if isinstance(e, (W.Refused, OSError, subprocess.SubprocessError)):
            raise W.Refused("refused, everything put back as it was: %s" % e)
        raise
    return was


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


def read(st=None):
    """How it stands now - also written into the state file, with when each device last went through."""
    st = st if st is not None else state_read()
    fv = W.forward_view()
    seen = st.get("seen") if isinstance(st.get("seen"), dict) else {}
    now = time.time()
    for c, n in (fv.get("counters") or {}).items():
        was = seen.get(c) or {}
        if n["out_pkts"] > int(was.get("pkts") or 0):
            seen[c] = {"pkts": n["out_pkts"], "changed": now}
        elif n["out_pkts"] < int(was.get("pkts") or 0):
            seen[c] = {"pkts": n["out_pkts"], "changed": was.get("changed") or 0}   # counters zeroed
    st["seen"] = {k: v for k, v in seen.items() if k in (st.get("clients") or [])}
    st["live"] = {"ip_forward": proc_read("net/ipv4/ip_forward"), "ip6_forward": proc_read("net/ipv6/conf/all/forwarding"),
                  "redirects": proc_read("net/ipv4/conf/all/send_redirects"), "file": os.path.exists(SYSCTL_FILE),
                  "forward": fv, "firewall": W.flag(W.read_config().get("firewall"), False), "read_at": now}
    state_write(st)
    return st


def report(st, said, ok=True):
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    return {"ok": ok, "said": said, "mode": st.get("mode") is True, "clients": st.get("clients") or [],
            "live": st.get("live") or {}, "seen": st.get("seen") or {},
            "trial": {k: t.get(k) for k in ("id", "until", "min", "by", "at", "done", "done_by", "done_at", "was")}}


def apply(by):
    w = wanted()
    st = state_read()
    said = []
    was = put(st, w["mode"], w["clients"], said)
    now_on = st.get("mode") is True
    changed = (now_on, st.get("clients") or []) != (was["mode"], was["clients"] if was["mode"] else [])
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    if changed and now_on and w["trial_min"]:
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
        t.update(done="kept" if now_on else "off", done_by=by, done_at=time.time())
        st["trial"] = t
    if not changed:
        said.append("the gateway mode as it was already - put in again")
    return report(read(st), said)


def put_back(st, why):
    t = st["trial"]
    was = t.get("was") if isinstance(t.get("was"), dict) else {}
    said = ["the gateway mode goes back to what it was before %s: %s"
            % (time.strftime("%H:%M", time.localtime(float(t.get("at") or 0))), why)]
    put(st, was.get("mode") is True, clients_checked(was.get("clients") or [], strict=False), said)
    t.update(done="back", done_by=why, done_at=time.time())
    st["trial"] = t
    return report(read(st), said)


def trial_do(action, payload, by):
    st = state_read()
    t = st.get("trial") if isinstance(st.get("trial"), dict) else {}
    if not pending(t) or (payload.get("id") and str(payload.get("id")) != t.get("id")):
        return report(read(st), ["no change of the gateway mode waits to be kept"])
    if action == "keep":
        if time.time() > float(t.get("until") or 0):
            raise W.Refused("the time to keep it is over - it is being put back")
        t.update(done="kept", done_by=by, done_at=time.time())
        st["trial"] = t
        return report(read(st), ["%s kept the gateway mode" % (by or "somebody")])
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
