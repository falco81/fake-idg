#!/usr/bin/python3 -I
"""root_mdns.py - what root does for Settings → mDNS reflector (avahi) (1.6.1).

  {"do": "set", "changes": {key: value, ...}}
        keys of avahi-daemon.conf fake-igd knows (upnp_mdns.KNOWN), changed line by line - the
        file's comments stay, a copy is kept beside it (the last 10), the value checked first;
        avahi-daemon restarted, and when it does not come up with the change the copy is put
        back and the daemon started again with it (upnp_mdns.apply - the same as `upnp mdns set`).
  {"do": "restart" | "start" | "stop" | "enable" | "disable"}
        avahi-daemon itself (systemctl).
  {"do": "restore", "copy": "avahi-daemon.conf.bak-YYYYmmdd-HHMMSS"}
        what fake-igd sets in the file put back as it was in a kept copy (the file as it is kept
        as a copy first), and the daemon restarted with it - put back again when it does not start.

Nothing in the payload is trusted: each value checked against the one shape it may have.
Paths and commands overridable for tests: UPNP_AVAHI_CONF (the file), FAKE_IGD_SYSTEMCTL.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Installed, upnp_mdns.py is beside this file (root's alone); in the source tree, in ../src (tests).
_SRC = HERE if os.path.isfile(os.path.join(HERE, "upnp_mdns.py")) else os.path.join(os.path.dirname(HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

ACTIONS = ("restart", "start", "stop", "enable", "disable")
VALUE_RE = re.compile(r"^[A-Za-z0-9_.,:@ -]{0,400}\Z")


class Refused(Exception):
    pass


def _mdns():
    try:
        import upnp_mdns
    except ImportError:
        raise Refused("upnp_mdns.py is not beside root's helper - install.sh --upgrade puts it in")
    return upnp_mdns


def _changes(M, raw):
    if not isinstance(raw, dict) or not raw:
        raise Refused("nothing to change")
    if len(raw) > len(M.KNOWN):
        raise Refused("more keys than avahi has")
    clean = {}
    for k, v in raw.items():
        if not isinstance(k, str) or k not in M.KNOWN:
            raise Refused("%s is not a key fake-igd changes" % str(k)[:40])
        if isinstance(v, bool):
            v = "yes" if v else "no"
        if not isinstance(v, (str, int)) or isinstance(v, bool):
            raise Refused("%s: not a value" % k)
        v = str(v)
        if not VALUE_RE.match(v):
            raise Refused("%s: not a value avahi takes" % k)
        clean[k] = v
    return clean


def serve(payload, ask):
    M = _mdns()
    payload = payload if isinstance(payload, dict) else {}
    do = payload.get("do")
    said = []
    try:
        if do == "set":
            clean = _changes(M, payload.get("changes"))
            said.append("avahi: " + M.apply(clean, restart=True, log=lambda *_: None))
        elif do == "restore":
            name = payload.get("copy")
            if not isinstance(name, str):
                raise Refused("which copy?")
            said.append("avahi: " + M.restore(name))
        elif do in ACTIONS:
            r = subprocess.run([M.SYSTEMCTL, do, M.SERVICE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, timeout=60)
            if r.returncode != 0:
                raise Refused("avahi-daemon: %s did not work: %s" % (do, r.stdout.strip()[-200:] or r.returncode))
            said.append("avahi-daemon: %s" % {"restart": "restarted", "start": "started", "stop": "stopped",
                                                    "enable": "starts at boot", "disable": "does not start at boot"}[do])
        else:
            raise Refused("no such ask: %s" % str(do)[:40])
    except M.MdnsError as e:
        return {"ok": False, "said": ["avahi: %s" % e]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "said": ["avahi-daemon: systemctl did not answer in 60 s"]}
    except Refused as e:
        return {"ok": False, "said": [str(e)]}
    st = M.systemd_state()
    return {"ok": True, "said": said, "state": st.get("ActiveState", "unknown")}


if __name__ == "__main__":
    import json
    if os.geteuid() != 0:
        print("root_mdns.py: run as root")
        sys.exit(1)
    print(json.dumps(serve(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}, {"by": "the command line"}),
                     indent=1))
