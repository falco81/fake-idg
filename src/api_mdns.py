"""api_mdns.py - the mDNS reflector (avahi-daemon): Settings → mDNS reflector (avahi), and the tab mDNS (1.6.1).

The routes of the built-in API of before (GET/POST /api/mdns, /api/mdns/services, /api/mdns/log)
are answered here now, the same paths - and more:

  GET  /api/mdns           the daemon, the file's keys (drawn as settings "avahi:KEY"), what the
                           daemon runs with now (its journal since it started: the interfaces it
                           joined), whether the file is newer than the daemon, the copies kept
  POST /api/mdns           {changes: {key: value}} | {action: restart|start|stop|enable|disable}
                           | {action: "restore", copy: NAME} - asked of root (deploy/root_mdns.py)
  GET  /api/mdns/result    root's answer to the last ask (avahiWait on the page follows it)
  GET  /api/mdns/services  what mDNS shows now (avahi-browse -a -t -r), as `upnp mdns services`
  GET  /api/mdns/browse    the live view: avahi-browse -a -r -p kept running while somebody
                           looks (stopped 90 s after the last look); ?after=SEQ the new and the
                           gone since, and every service as it is now
  GET  /api/mdns/log       avahi-daemon's journal

avahi is not put "on trial" as otp's network, firewall and sshd are: a change of it cannot shut
anybody out of this server. It is checked first, a copy is kept, and when the daemon does not come
up with it the copy is put back by itself (upnp_mdns.apply).
"""
import os
import subprocess
import threading
import time

import upnp_mdns as M

NAME = "mdns"

AVAHI = [
    # key, name, says (as otp's settings say it)
    ("enable-reflector", "The reflector",
     "On: every mDNS packet heard on one interface is repeated on the others - AirPlay, Chromecast, "
     "printers and the PS5's Remote Play are seen across networks. Off: avahi only answers for this machine."),
    ("allow-interfaces", "Interfaces it uses",
     "The interfaces avahi listens on and reflects between. None chosen: every interface the machine has "
     "(apart from the ones below)."),
    ("deny-interfaces", "Interfaces it never uses",
     "Never listened on, never reflected to - a WAN, a VPN, a management network."),
    ("reflect-filters", "Reflect only these service types",
     "Only these service types are reflected, e.g. _airplay._tcp.local, _googlecast._tcp.local. "
     "Empty: every type."),
    ("reflect-ipv", "Reflect between IPv4 and IPv6",
     "A packet heard over IPv4 is repeated over IPv6 too, and back. Rarely wanted."),
    ("use-ipv4", "mDNS over IPv4", "avahi speaks mDNS over IPv4 (224.0.0.251)."),
    ("use-ipv6", "mDNS over IPv6", "avahi speaks mDNS over IPv6 (ff02::fb)."),
    ("cache-entries-max", "Records in the cache",
     "How many records avahi keeps. 0: none - the reflector reflects all the same, but avahi-browse "
     "(the tab mDNS) is shown nothing. Empty: as avahi has it (4096)."),
    ("ratelimit-interval-usec", "Rate limit: the interval (µs)",
     "With the burst below: how many packets one interface may send in this many microseconds. Empty: no limit."),
    ("ratelimit-burst", "Rate limit: packets in it", "Packets allowed in one interval. Empty: no limit."),
    ("enable-wide-area", "Wide-area browsing (unicast DNS-SD)",
     "Services are looked up in the DNS of the machine's domain too, not only on the local network."),
    ("publish-hinfo", "Publish HINFO", "This machine's CPU and operating system told to whoever asks."),
    ("publish-workstation", "Publish as a workstation", "This machine announced as a workstation (_workstation._tcp)."),
    ("disable-publishing", "Publish nothing of this machine",
     "avahi announces nothing of this machine itself - it only browses and reflects."),
]
NAMES = {k: n for k, n, _s in AVAHI}
ACTIONS = ("restart", "start", "stop", "enable", "disable")
ACTION_WORDS = {"restart": "restart avahi-daemon", "start": "start avahi-daemon", "stop": "stop avahi-daemon",
                "enable": "start avahi-daemon at boot", "disable": "not start avahi-daemon at boot"}


def _since_epoch(stamp):
    """systemd's ActiveEnterTimestamp ('Mon 2026-11-16 20:01:02 CET') as epoch seconds, or None."""
    if not stamp or stamp == "n/a":
        return None
    parts = stamp.split()
    for take in (parts[1:3], parts[0:2]):
        try:
            return time.mktime(time.strptime(" ".join(take), "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            continue
    return None


def view(ctx):
    try:
        st = M.status()
    except M.MdnsError as e:
        return {"installed": False, "error": str(e), "root": ctx.root_result(), "node": _node()}
    vals, _l = M.read_conf()
    eff = M.effective(vals)
    keys = []
    for k, name, says in AVAHI:
        sect, kind, words = M.KNOWN[k]
        keys.append({"key": k, "name": name, "says": says, "section": sect, "kind": kind, "bool": kind == "bool",
                     "value": (eff.get(k) == "yes") if kind == "bool" else (eff.get(k) or ""),
                     "default": (M.DEFAULT.get(k, "") == "yes") if kind == "bool" else M.DEFAULT.get(k, ""),
                     "source": "config" if k in vals else "default",
                     "source_says": ("[%s] %s, set in %s" % (sect, k, M.CONF)) if k in vals
                     else "[%s] %s - not set in %s: as avahi has it" % (sect, k, M.CONF)})
    since = _since_epoch(st["service"].get("since"))
    try:
        changed = os.stat(M.CONF).st_mtime
    except OSError:
        changed = None
    lines = M.journal(400) if st["service"]["state"] in ("active", "activating", "reloading") else []
    now = M.running_with(lines)
    kernel = M.system_ifaces()
    st.update({
        "installed": True, "keys": keys, "node": _node(),
        "system_interfaces": sorted(kernel),
        "kernel": [{"name": n, "ipv4": kernel[n]} for n in sorted(kernel)],
        "since_at": since, "changed_at": changed,
        "file_newer": bool(since and changed and changed > since + 1),
        "now": now, "copies": M.copies(), "root": ctx.root_result(), "at": time.time(),
    })
    return st


def _node():
    import socket
    return socket.gethostname().split(".")[0]


def post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    changes = b.get("changes") or {}
    action = str(b.get("action") or "")
    if action == "restore":
        name = str(b.get("copy") or "")
        if name not in [c["name"] for c in M.copies()]:
            raise ValueError("no such copy of the file: %s" % name[:80])
        ident = ctx.ask_root({"do": "restore", "copy": name})
        ctx.event("%s asked root to put back avahi-daemon.conf as it was in %s" % (me["name"], name))
        return {"id": ident, "message": "asked root - the copy is put back in a moment"}
    if action in ACTIONS and not changes:
        ident = ctx.ask_root({"do": action})
        ctx.event("%s asked root to %s" % (me["name"], ACTION_WORDS[action]),
                  "warn" if action in ("stop", "disable") else "info")
        return {"id": ident, "message": "asked root to %s" % ACTION_WORDS[action]}
    if not isinstance(changes, dict) or not changes:
        raise ValueError("nothing to do")
    sysif = M.system_ifaces()
    clean = {}
    for k, v in changes.items():
        if k not in M.KNOWN:
            raise ValueError("%s is not a key of avahi-daemon.conf fake-igd changes" % str(k)[:40])
        if isinstance(v, bool):
            v = "yes" if v else "no"
        try:
            clean[k] = M.check(k, v, sysif)
        except M.MdnsError as e:
            raise ValueError("%s: %s" % (NAMES.get(k, k), e))
    ident = ctx.ask_root({"do": "set", "changes": clean})
    ctx.event("%s asked root to change avahi-daemon.conf: %s" % (me["name"], ", ".join(
        "%s=%s" % (k, v if v != "" else "(as it comes)") for k, v in clean.items())))
    return {"id": ident, "message": "asked root - avahi-daemon.conf is changed and the daemon restarted in a moment"}


def result(ctx):
    return {"result": ctx.root_result()}


def services(ctx):
    try:
        rows = M.services(resolve=ctx.arg("resolve", "1") != "0", timeout=12)
    except M.MdnsError as e:
        raise ValueError(str(e))
    return {"services": rows, "at": time.time(), "hint": "" if rows else _empty_hint()}


def _empty_hint():
    try:
        vals, _l = M.read_conf()
    except M.MdnsError:
        return ""
    if str(vals.get("cache-entries-max", "")).strip() == "0":
        return ("Nothing seen - cache-entries-max=0: avahi-daemon keeps no record, so avahi-browse is shown "
                "nothing (the reflector reflects all the same). Settings - mDNS reflector - Records in the "
                "cache, e.g. 4096, lets it be seen.")
    return ""


def log(ctx):
    try:
        n = max(20, min(5000, int(ctx.arg("lines", "300"))))
    except ValueError:
        n = 300
    return {"lines": M.journal(n)}


# ---- the live view: avahi-browse kept running while somebody looks ------------------------
class Browser(object):
    KEEP_S = 90          # stopped this long after the last look
    EVENTS = 2000        # the new and the gone kept
    FIRST_S = 3.0        # what comes in the first seconds was there before: not "new"

    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.started = 0.0
        self.asked = 0.0
        self.seq = 0
        self.events = []
        self.now = {}
        self.ended = ""
        self.ended_at = 0.0
        self.gen = 0

    def _key(self, d):
        return "%s|%s|%s|%s" % (d["iface"], d["proto"], d["type"], d["name"])

    def _run(self, gen):
        try:
            proc = subprocess.Popen(["avahi-browse", "-a", "-r", "-p"], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, universal_newlines=True, bufsize=1)
        except OSError as e:
            with self.lock:
                self.ended, self.ended_at = "avahi-browse could not be started: %s" % e, time.time()
            return
        with self.lock:
            if gen != self.gen:
                proc.kill()
                return
            self.proc = proc
        for ln in proc.stdout:
            d = M.parse_browse(ln.rstrip("\n"))
            if not d:
                continue
            t = time.time()
            with self.lock:
                if gen != self.gen:
                    break
                k = self._key(d)
                was = self.now.get(k)
                first = t - self.started < self.FIRST_S
                if d["event"] == "gone":
                    if was is None:
                        continue
                    self.now.pop(k, None)
                    ev = dict(was, event="gone")
                elif d["event"] == "new":
                    if was is not None:
                        continue
                    row = dict(d, key=k, first=t, last=t, before=first)
                    self.now[k] = row
                    ev = dict(row, event="new")
                else:
                    row = dict(was or {"first": t, "before": first}, **d)
                    row.update(key=k, last=t)
                    self.now[k] = row
                    if was is not None and was.get("address") == d.get("address") and was.get("port") == d.get("port") \
                            and was.get("txt") == d.get("txt"):
                        continue
                    if was is None or not was.get("address"):
                        # Its first resolution: the "new" it came with says it, no line of its own.
                        for e in reversed(self.events[-200:]):
                            if e.get("key") == k and e["event"] == "new":
                                e.update({x: d.get(x) for x in ("host", "address", "port", "txt")})
                                break
                        continue
                    ev = dict(row, event="resolved")
                self.seq += 1
                ev.update(seq=self.seq, at=t, before=first)
                self.events.append(ev)
                del self.events[:-self.EVENTS]
        try:
            proc.wait(timeout=5)
            err = (proc.stderr.read() or "").strip()
        except (subprocess.TimeoutExpired, OSError, ValueError):
            err = ""
        with self.lock:
            if gen == self.gen:
                self.proc = None
                self.ended = ("avahi-browse ended (%s)%s" % (proc.returncode, ": " + err.splitlines()[-1][:300]
                                                             if err else ""))
                self.ended_at = time.time()

    def _stop(self):
        p = self.proc
        self.proc = None
        self.gen += 1
        if p is not None:
            try:
                p.terminate()
            except OSError:
                pass

    def start(self, fresh=False):
        with self.lock:
            self.asked = time.time()
            if self.proc is not None and not fresh:
                return
            if self.proc is None and self.ended and not fresh and time.time() - self.ended_at < 15:
                return                                   # it ended a moment ago: not again and again
            self._stop()
            self.started = time.time()
            self.now, self.ended, self.ended_at = {}, "", 0.0
            self.events.append({"seq": self.seq + 1, "at": self.started, "event": "start"})
            self.seq += 1
            gen = self.gen
        threading.Thread(target=self._run, args=(gen,), daemon=True).start()

    def reap(self):
        with self.lock:
            if self.proc is not None and time.time() - self.asked > self.KEEP_S:
                self._stop()
                self.ended, self.ended_at = "stopped - nobody was looking", time.time()

    def view(self, after):
        with self.lock:
            evs = [e for e in self.events if e["seq"] > after]
            return {"running": self.proc is not None, "started": self.started, "ended": self.ended,
                    "ended_at": self.ended_at, "seq": self.seq, "events": evs[-500:],
                    "services": sorted(self.now.values(), key=lambda d: (d["type"], d["name"], d["iface"], d["proto"])),
                    "at": time.time()}


BROWSER = Browser()


def browse(ctx):
    import shutil
    if not shutil.which("avahi-browse"):
        raise ValueError("avahi-browse is missing - dnf install avahi-tools")
    BROWSER.start(fresh=ctx.arg("fresh", "") == "1")
    try:
        after = int(ctx.arg("after", "0"))
    except ValueError:
        after = 0
    d = BROWSER.view(after)
    d["hint"] = "" if d["services"] else _empty_hint()
    return d


def background(ctx):
    BROWSER.reap()


ROUTES = {
    ("GET", "/api/mdns"): view,
    ("POST", "/api/mdns"): post,
    ("GET", "/api/mdns/result"): result,
    ("GET", "/api/mdns/services"): services,
    ("GET", "/api/mdns/browse"): browse,
    ("GET", "/api/mdns/log"): log,
}
