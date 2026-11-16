"""root_fw.py - Settings → Firewall and access: root's part (1.6.0).

As otp's firewall: who may reach the pages (web_allow, nginx's allow list) and the chain
FAKE-IGD-IN (fake_igd_web.py puts it in, for IPv4 and IPv6): the rules of your own, kept in
firewall-rules.json beside config.json, and what fake-igd lets in by itself, each switchable.

Every change is ON TRIAL (otp's fw_confirm_min): what was there before is kept, the change is put
in, and unless somebody presses "Keep it" within the minutes the pages said, it is put back by
itself - by a systemd-run timer started here, and should that be lost (a reboot), by the API's
background step asking for it. Further changes within a trial move its deadline on.

  serve({"action": "save", "on", "off", "rules", "access", "trial_min"})
  serve({"action": "keep" | "back", "id"})     - the banner's buttons
  serve({"action": "expire", "id"})            - the timer (or the API) when the time ran out
  serve({"action": "apply"})                   - put in again what is set (Try again)
  serve({"action": "read"})                    - the whole firewall read again
  serve({"action": "realip"})                  - nginx's real_ip lines as the pages' settings say

Nothing in the payload is trusted: every value is checked against the one shape it may have.
Paths: FAKE_IGD_CONFIG, FAKE_IGD_FW_RULES, FAKE_IGD_FW_TRIAL (fake_igd_web.py's for the rest).
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

# Root's helper itself when it runs this (fake_igd_web.py is __main__ then): its Refused is the one
# it catches and says as it is.
_MAIN = sys.modules.get("__main__")
if getattr(_MAIN, "CHAIN", None) == "FAKE-IGD-IN" and hasattr(_MAIN, "fw_status"):
    W = _MAIN
else:
    import fake_igd_web as W

TRIAL_FILE = os.environ.get("FAKE_IGD_FW_TRIAL", os.path.join(os.path.dirname(W.CONFIG), "firewall-trial.json"))
CFG_KEYS = ("firewall", "firewall_ssh", "firewall_icmp", "web_allow", "health_allow")
ID_RE = re.compile(r"^[0-9a-f]{12}\Z")
HELPER = os.path.join(os.path.dirname(os.path.abspath(W.__file__)), "fake_igd_web.py")


# ---- config.json's keys and firewall-rules.json ------------------------------------
def cfg_keys(cfg):
    return {"firewall": W.flag(cfg.get("firewall"), False), "firewall_ssh": W.flag(cfg.get("firewall_ssh"), True),
            "firewall_icmp": W.flag(cfg.get("firewall_icmp"), True),
            "web_allow": [str(x) for x in cfg.get("web_allow", W.DEFAULT_ALLOW)]
            if isinstance(cfg.get("web_allow", W.DEFAULT_ALLOW), list) else list(W.DEFAULT_ALLOW),
            "health_allow": [str(x) for x in W.health_of(cfg)]}


def write_cfg(changes):
    """The keys into config.json, in place and locked - as the API writes it (its owner and mode stay)."""
    import fcntl
    fd = os.open(W.CONFIG, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        data = json.load(f)
        if not isinstance(data, dict):
            raise W.Refused("%s holds no settings" % W.CONFIG)
        data.update(changes)
        f.seek(0)
        f.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        f.truncate()
        f.flush()
        os.fsync(f.fileno())


def nets_checked(raw):
    if isinstance(raw, str):
        raw = [x for x in re.split(r"[\s,;]+", raw) if x]
    if not isinstance(raw, list) or len(raw) > 200:
        raise W.Refused("who may reach the pages: a list of addresses or networks")
    out = []
    for x in raw:
        try:
            n = str(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            raise W.Refused("who may reach the pages: %s is not an address or a network" % str(x)[:60])
        if n not in out:
            out.append(n)
    return out


# ---- the trial ---------------------------------------------------------------------
def trial_read():
    try:
        with open(TRIAL_FILE, encoding="utf-8") as f:
            t = json.load(f)
        return t if isinstance(t, dict) else {}
    except (OSError, ValueError):
        return {}


def trial_write(t):
    fd, tmp = tempfile.mkstemp(prefix=".firewall-trial.", dir=os.path.dirname(TRIAL_FILE))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(t, f, indent=1)
    os.chmod(tmp, 0o640)
    try:
        import grp
        os.chown(tmp, 0, grp.getgrnam("fake-igd").gr_gid)
    except (KeyError, OSError):
        pass
    os.replace(tmp, TRIAL_FILE)


def pending(t):
    return bool(t) and not t.get("done") and ID_RE.match(str(t.get("id") or ""))


def timer(t):
    """A systemd-run timer that asks for the put-back when the time is over."""
    if not shutil.which("systemd-run"):
        return "no systemd-run here - the pages' API asks for the put-back when the time is over"
    secs = max(1, int(float(t["until"]) - time.time()) + 2)
    unit = "fake-igd-fw-back-%s-%d" % (t["id"], int(float(t["until"])))
    r = subprocess.run(["systemd-run", "--quiet", "--unit", unit, "--on-active=%ds" % secs,
                        "--timer-property=AccuracySec=1s", "/usr/bin/python3", "-I", HELPER, "--kind", "fw",
                        json.dumps({"action": "expire", "id": t["id"]})],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    if r.returncode != 0:
        return "the timer could not be started (%s) - the pages' API asks for the put-back" % r.stdout.strip()[:200]
    return ""


# ---- putting it in -----------------------------------------------------------------
def put_in(cfg_now, conf, by, said):
    """config.json's keys and the rules written, nginx's list and the chain put in. A refusal anywhere puts
    the files back as they were and the firewall with them, and says so."""
    before_cfg = cfg_keys(W.read_config())
    before_conf = W.load_fw_conf()
    write_cfg(cfg_now)
    W.write_fw_conf(dict(conf, by=by))
    cfg = W.read_config()
    try:
        said.append(W.nginx_allow(cfg))
        said.extend(W.firewall(cfg))
    except (W.Refused, OSError, subprocess.SubprocessError) as e:
        write_cfg(before_cfg)
        W.write_fw_conf(dict(before_conf, by=by))
        cfg = W.read_config()
        for step in (lambda: W.nginx_allow(cfg), lambda: W.firewall(cfg)):
            try:
                step()
            except (W.Refused, OSError, subprocess.SubprocessError):
                pass
        raise W.Refused("refused, everything put back as it was: %s" % e)


def report(said, ok=True):
    try:
        fw = W.fw_status()
    except Exception as e:                              # noqa: BLE001 - said, never lost
        fw = {"error": str(e)}
    t = trial_read()
    return {"ok": ok, "said": said, "firewall": fw,
            "trial": {k: t.get(k) for k in ("id", "until", "min", "by", "last_by", "at", "done", "done_by",
                                             "done_at")} if t else {}}


def save(p, by):
    if not isinstance(p.get("on"), bool):
        raise W.Refused("the firewall is on or off")
    off = p.get("off") if isinstance(p.get("off"), list) else []
    off = [k for k in W.FW_OPTIONAL if k in [str(x) for x in off]]
    rules = W.fw_rules_checked(p.get("rules") if p.get("rules") is not None else [])
    try:
        n = int(p.get("trial_min") or 0)
    except (TypeError, ValueError):
        n = -1
    if not 0 <= n <= 120:
        raise W.Refused("the minutes of a trial: 0 to 120")
    cfg = W.read_config()
    was_cfg, was_conf = cfg_keys(cfg), W.load_fw_conf()
    new_cfg = dict(was_cfg, firewall=p["on"], firewall_ssh="ssh" not in off, firewall_icmp="icmp" not in off)
    acc = p.get("access")
    if acc is not None:
        if not isinstance(acc, dict):
            raise W.Refused("who may reach the pages: everybody, or a list")
        # {admin: {any, from}, health: {any, from}} - or, as before, the administration's alone {any, from}
        rows = {"admin": acc} if "any" in acc else acc
        for key, cfg_key, words in (("admin", "web_allow", "the pages"), ("health", "health_allow", "the health check")):
            one = rows.get(key)
            if one is None:
                continue
            if not isinstance(one, dict):
                raise W.Refused("who may reach %s: everybody, or a list" % words)
            nets = nets_checked(one.get("from") or [])
            if one.get("any") is not True and not nets:
                raise W.Refused("%s would be for nobody: give a network, or let everybody in" % words)
            new_cfg[cfg_key] = [] if one.get("any") is True else nets
    new_conf = {"rules": rules, "off": [k for k in off if k in W.FW_OFF_KEYS]}
    if new_cfg == was_cfg and new_conf["rules"] == was_conf["rules"] and new_conf["off"] == was_conf["off"]:
        return report(["nothing was changed"])
    said = []
    t = trial_read()
    if n:
        now = time.time()
        if not pending(t):
            t = {"id": secrets.token_hex(6), "at": now, "by": by,
                 "was": {"cfg": was_cfg, "conf": {"rules": was_conf["rules"], "off": was_conf["off"]}}}
        t.update(until=now + n * 60, min=n, last_by=by)
    put_in(new_cfg, new_conf, by, said)
    if n:
        trial_write(t)
        said.append("on trial: it goes back by itself unless kept within %d min" % n)
        w = timer(t)
        if w:
            said.append(w)
    elif pending(t):
        # Kept at once (0 minutes) while a trial waited: that one is over too.
        t.update(done="kept", done_by=by, done_at=time.time())
        trial_write(t)
    return report(said)


def put_back(t, why):
    was = t.get("was") or {}
    said = ["the firewall and access go back to what they were before %s: %s"
            % (time.strftime("%H:%M", time.localtime(float(t.get("at") or 0))), why)]
    cfg_was = was.get("cfg") if isinstance(was.get("cfg"), dict) else {}
    clean = {}
    for k in ("firewall", "firewall_ssh", "firewall_icmp"):
        if isinstance(cfg_was.get(k), bool):
            clean[k] = cfg_was[k]
    for k in ("web_allow", "health_allow"):
        if isinstance(cfg_was.get(k), list):
            clean[k] = nets_checked(cfg_was[k]) if cfg_was[k] else []
    conf_was = was.get("conf") if isinstance(was.get("conf"), dict) else {}
    conf = {"rules": W.fw_rules_checked(conf_was.get("rules") or []),
            "off": [k for k in W.FW_OFF_KEYS if k in (conf_was.get("off") or [])]}
    t.update(done="back", done_by=why, done_at=time.time())
    trial_write(t)
    put_in(dict(cfg_keys(W.read_config()), **clean), conf, why, said)
    return report(said)


def serve(payload, ask):
    by = str((ask or {}).get("by") or "")[:80]
    action = str(payload.get("action") or "")
    if action == "save":
        return save(payload, by)
    if action == "read":
        return report(["the whole firewall read again"])
    if action == "realip":
        # Behind a load balancer or WAF - the settings are read from the database, not the payload.
        return report([W.nginx_allow(W.read_config())])
    if action == "apply":
        cfg = W.read_config()
        said = []
        try:
            said.append(W.nginx_allow(cfg))
        except (W.Refused, OSError) as e:
            said.append("nginx: %s" % e)
        said += W.firewall(cfg)
        return report(said)
    if action in ("keep", "back", "expire"):
        try:
            got = trial_do(action, payload, by)
        except W.Refused as e:
            if (ask or {}).get("by") != "the command line":
                raise
            got = report([str(e)], ok=False)
        if (ask or {}).get("by") == "the command line":
            # From the timer (fake_igd_web.py --kind fw): the pages read it as any other answer.
            W.write_kind_result("fw", dict(got, id="timer", by="the timer"))
        return got
    raise W.Refused("no such firewall action: %s" % action[:30])


def trial_do(action, payload, by):
    """Keep it, put it back now, or put it back because its time is over."""
    t = trial_read()
    if not pending(t) or (payload.get("id") and str(payload.get("id")) != t.get("id")):
        got = report(["no change of the firewall waits to be kept"])
    elif action == "keep":
        if time.time() > float(t.get("until") or 0):
            raise W.Refused("the time to keep it is over - it is being put back; make the change again "
                            "if it is wanted")
        t.update(done="kept", done_by=by, done_at=time.time())
        trial_write(t)
        got = report(["%s kept the change of the firewall and access" % (by or "somebody")])
    elif action == "back":
        got = put_back(t, "put back by %s" % (by or "somebody"))
    elif time.time() + 2 >= float(t.get("until") or 0):
        got = put_back(t, "not kept within %d min" % int(t.get("min") or 0))
    else:
        got = report(["not yet - it waits to be kept until %s"
                      % time.strftime("%H:%M:%S", time.localtime(float(t["until"])))])
    return got
