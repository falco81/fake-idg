"""api_upgrade.py - Settings → Upgrades (1.6.1), as otp's pane-upgrade.

What otp's _upgrade_view / _upgrade_do and the after-the-update list (otp 1.0.258) do, for the
one server fake-igd is:

  GET  /api/upgrade            this server, the package waiting, the upgrade asked for last (a
                               plan of one node: waiting → being put in → checking → done), what
                               upgrade_url had, whether going back is offered, root's last output
  POST /api/upgrade            action: online_look | online_get {version, start} |
                               online_changelog {version} | start | forget | hide | cancel |
                               downgrade_list | downgrade_changelog {version} |
                               downgrade_get {version, start}
  POST /api/upgrade-package    a package sent from the pages (base64 in "data"), checked
  GET  /api/after              To be done by hand: what an update cannot do itself (?brief=1: the
                               count beside Upgrades in the menu and on the Settings tab)
  POST /api/after              action: check (Look again) | done {id} | clear_done {items}

These replace the built-in routes of the same paths of fake_igd_api.py. Nothing here installs
anything: a package is laid down in /var/lib/fake-igd/upgrade/ and root's fake_igd_upgrade.py
(fake-igd-upgrade.path) checks it again and runs its install.sh --upgrade (igd_online.py).

What is to be done by hand is looked for here, as the fake-igd account: files only, nothing of
root's is run - root's helper and the path units, the version root's parts were installed with
(root-facts.json, which install.sh writes beside the program, or its VERSION), nginx's file,
SELinux's boolean and label (/sys/fs/selinux, the run folder's label), PHP's php2shell guard.
Each thing is an entry of AFTER: words, the commands with a Copy button, a check; one that can
be checked goes by itself, one that cannot waits for Done.
"""
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import igd_online as ON      # noqa: E402
import upnp as U             # noqa: E402

NAME = "upgrade"
VERSION = U.VERSION

SETTINGS = [
    {"key": "upgrade_downgrade", "name": "Offer going back to an older version", "kind": "bool", "default": False,
     "says": "Off: nothing on these pages offers going back to an older version. On: Settings → Upgrades shows "
             "<i>Going back to an older version</i> - only the versions it is safe to go back to, each with what "
             "changed in it. On the server, root can always: upnp upgrade file FILE --downgrade."},
]


def _node():
    return socket.gethostname().split(".")[0]


def _url(ctx):
    return str(ctx.cfg.get("upgrade_url") or ON.DEFAULT_URL)


def _down_on(ctx):
    try:
        return bool(ctx.setting("upgrade_downgrade"))
    except KeyError:
        return False


def _who(ctx):
    return (ctx.me or {}).get("name") or "the pages"


# ---- the package waiting ---------------------------------------------------------------
PKG_KEYS = ("version", "sha", "signed_by", "files", "bytes", "changelog", "installed", "newer", "older",
            "file", "from", "downgrade")


def _keep_package(ctx, info, by):
    meta = {k: info.get(k) for k in PKG_KEYS}
    meta.update({"by": by, "at": time.time(), "since": info.get("installed") or "",
                 "downgrade": bool(info.get("downgrade"))})
    ctx.store.set_meta("upgrade:pkg", json.dumps(meta))
    return meta


def _package(ctx):
    meta = ctx.store.meta_json("upgrade:pkg")
    if not meta or not isinstance(meta.get("version"), str):
        return None
    meta["there"] = bool(meta.get("file")) and os.path.isfile(str(meta["file"]))
    return meta


def _checks(ctx, meta, plan):
    """(ok, [why not]) - otp's upgrade_checks, for one server."""
    why = []
    if not meta:
        return False, ["no package has been sent yet"]
    if not re.match(r"^\d+\.\d+\.\d+\Z", str(meta.get("version") or "")):
        return False, ["the package's row is not as fake-igd writes it - send the package again"]
    if not meta.get("there"):
        why.append("the package is no longer in %s - send it again, or fetch it again" % ON.UPGRADE_DIR)
    if meta.get("downgrade"):
        why += ON.downgrade_why_not(meta["version"], VERSION)
        if not _down_on(ctx):
            why.append("going back to an older version is switched off (Settings → Upgrades)")
    elif ON.ver_tuple(meta["version"]) < ON.ver_tuple(VERSION):
        why.append("%s runs %s, newer than %s" % (_node(), VERSION, meta["version"]))
    if plan and plan.get("state") == "running":
        why.append("an upgrade is going on already")
    return not why, why


def _plan(ctx, hidden=True):
    p = ON.plan(VERSION, _node())
    _tell(ctx, p)
    if p and hidden and p.get("state") != "running" and ctx.store.get_meta("upgrade:seen") == str(p.get("id")):
        return None
    return p


def view(ctx):
    meta = _package(ctx)
    plan = _plan(ctx)
    ok, why = _checks(ctx, meta, plan)
    pk = None
    if meta:
        pk = {k: meta.get(k) for k in ("version", "signed_by", "files", "bytes", "changelog", "since", "by", "at",
                                       "from", "downgrade", "there")}
    online = ON.view(ctx.store.meta_json("upgrade:online") or {}, VERSION)
    return {"node": _node(), "version": VERSION, "package": pk, "plan": plan, "ready": ok, "not_ready": why,
            "downgrade_on": _down_on(ctx), "helper": os.path.exists(ON.HELPER),
            "path_unit": os.path.exists(ON.PATH_UNIT), "log": ON.log_lines(120),
            "log_file": os.path.join(ON.UPGRADE_DIR, "last.log"),
            "nodes": [{"name": _node(), "version": VERSION, "me": True, "alive": True, "at": time.time()}],
            "web": {"online": online, "url": _url(ctx), "check": bool(ctx.cfg.get("upgrade_check"))}}


def upgrade_get(ctx):
    return view(ctx)


def _start(ctx, meta):
    plan = _plan(ctx, hidden=False)
    ok, why = _checks(ctx, meta, plan)
    if not ok:
        raise ValueError("; ".join(why))
    info = dict(meta, installed=VERSION)
    ident = ON.ask_root(info, _who(ctx), downgrade=bool(meta.get("downgrade")))
    ctx.event("%s started %s fake-igd %s" % (_who(ctx), "going back to" if meta.get("downgrade") else
                                              "the upgrade to", meta["version"]), "warn")
    return ident


def upgrade_post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    act = {"look": "online_look", "fetch": "online_get", "online": "online_get"}.get(act, act)
    if b.get("action") == "online":
        b["start"] = True
    by = _who(ctx)
    try:
        if act == "online_look":
            row = ON.look(_url(ctx), VERSION, ctx.store, by)
            if row.get("error"):
                raise ValueError("%s: %s" % (row.get("url"), row["error"]))
            n = row.get("newest") or {}
            return dict(view(ctx), message=(
                "fake-igd %s is there - newer than %s" % (n["version"], VERSION) if row.get("newer")
                else ("nothing newer than %s" % VERSION if n else "no fake-igd package there")))
        if act == "online_changelog":
            return {"changelog": ON.changelog_of(_url(ctx), str(b.get("version") or ""), VERSION, ctx.store)}
        if act.startswith("downgrade") and not _down_on(ctx):
            raise ValueError("going back to an older version is not offered on these pages: switch it on in "
                             "Settings → Upgrades")
        if act == "downgrade_changelog":
            return {"changelog": ON.changelog_of(_url(ctx), str(b.get("version") or ""), VERSION, ctx.store)}
        if act == "downgrade_list":
            return {"downgrade": ON.downgrade_list(_url(ctx), VERSION)}
        if act in ("online_get", "downgrade_get"):
            down = act == "downgrade_get"
            plan = _plan(ctx, hidden=False)
            if plan and plan.get("state") == "running":
                raise ValueError("an upgrade is going on: wait for it, or stop it first")
            version = str(b.get("version") or "")
            if not version and not down:
                row = ON.look(_url(ctx), VERSION, ctx.store, by)
                version = (row.get("newest") or {}).get("version") or ""
            if not re.match(r"^\d+\.\d+\.\d+\Z", version):
                raise ValueError("which version?")
            try:
                info = ON.fetch(_url(ctx), version, VERSION, older=down)
            except ValueError as e:
                ctx.event("fake-igd %s from %s was refused: %s" % (version, _url(ctx), e), "warn")
                raise
            meta = _keep_package(ctx, info, by)
            ctx.event("%s fetched fake-igd %s from %s (signed by %s), ready %s" % (
                by, meta["version"], info.get("from"), meta.get("signed_by"),
                "to go back to" if down else "to be put in"), "warn")
            if b.get("start"):
                _start(ctx, _package(ctx))
                return dict(view(ctx), message="fake-igd %s fetched and checked; %s has begun" % (
                    meta["version"], "going back to it" if down else "the upgrade"))
            return dict(view(ctx), message="fake-igd %s is fetched, checked and ready%s" % (
                meta["version"], " to go back to" if down else ""))
        if act == "start":
            meta = _package(ctx)
            _start(ctx, meta)
            return dict(view(ctx), message="%s has begun - fake-igd.service and these pages restart once, and come "
                        "back by themselves" % ("going back to %s" % meta["version"] if meta.get("downgrade")
                                                else "the upgrade"))
        if act == "hide":
            plan = _plan(ctx, hidden=False)
            if plan and plan.get("state") == "running":
                raise ValueError("the upgrade is going on")
            if plan:
                ctx.store.set_meta("upgrade:seen", str(plan.get("id")))
            return view(ctx)
        if act == "cancel":
            p = ON.cancel(by)
            ctx.event("%s stopped the upgrade to %s before root took it: nothing was changed" % (
                by, p.get("version")), "warn")
            return dict(view(ctx), message="the upgrade is stopped")
        if act == "forget":
            plan = _plan(ctx, hidden=False)
            if plan and plan.get("state") == "running":
                raise ValueError("an upgrade is going on with it")
            meta = ctx.store.meta_json("upgrade:pkg") or {}
            if meta.get("file") and os.path.dirname(os.path.abspath(str(meta["file"]))) == \
                    os.path.abspath(ON.UPGRADE_DIR):
                try:
                    os.unlink(meta["file"])
                except OSError:
                    pass
            ctx.store.set_meta("upgrade:pkg", "")
            if meta.get("version"):
                ctx.event("%s threw the package of fake-igd %s away" % (by, meta.get("version")))
            return dict(view(ctx), message="the package is forgotten")
    except OSError as e:
        raise ValueError(_os_words(e))
    raise ValueError("no such thing to do")


def _os_words(e):
    """An OSError said for what it is: no room, no right to write, or the address not read."""
    import errno
    if getattr(e, "errno", None) in (errno.ENOSPC, errno.EDQUOT):
        return "no room left in %s for the package - make room on that disk (Settings → Disks and logs)" % ON.UPGRADE_DIR
    if getattr(e, "errno", None) in (errno.EACCES, errno.EPERM, errno.EROFS):
        return "%s cannot be written: %s - install.sh --upgrade puts its owner right" % (ON.UPGRADE_DIR, e.strerror or e)
    return "the address could not be read: %s" % (getattr(e, "reason", None) or e)


def upgrade_package(ctx):
    """A package sent from the pages: checked at once, kept ready (otp's /api/upgrade/package)."""
    import base64
    ctx.need("fulladmin")
    b = ctx.body(most=96 * 1024 * 1024)
    try:
        data = base64.b64decode(str(b.get("data") or ""), validate=True)
    except ValueError:
        raise ValueError("the package did not come whole")
    if not data:
        raise ValueError("no package was sent")
    plan = _plan(ctx, hidden=False)
    if plan and plan.get("state") == "running":
        raise ValueError("an upgrade is going on: wait for it, or stop it first")
    by = _who(ctx)
    try:
        try:
            info = ON.take_bytes(data, older=False)
        except OSError as e:
            raise ValueError(_os_words(e))
    except ValueError as e:
        ctx.event("%s sent a package that was refused: %s" % (by, e), "warn")
        raise
    if info.get("older"):
        try:
            os.unlink(info["file"])
        except OSError:
            pass
        raise ValueError("%s is older than %s, which runs here: going back is done from upgrade_url (Going back to "
                         "an older version, below) or on the command line" % (info["version"],
                                                                                info.get("installed") or VERSION))
    meta = _keep_package(ctx, info, by)
    ctx.event("%s sent fake-igd %s (signed by %s), ready to be put in" % (by, meta["version"],
                                                                         meta.get("signed_by")), "warn")
    return dict(view(ctx), package=view(ctx)["package"], message="fake-igd %s is checked and ready" % meta["version"])


# ==========================================================================================
# To be done by hand, after an update (otp 1.0.258)
# ==========================================================================================
AFTER = []
AFTER_EVERY = float(os.environ.get("FAKE_IGD_AFTER_EVERY") or 600)
AFTER_LEVELS = ("bad", "warn", "info")
AFTER_LOG_KEEP = 20
AFTER_LOCK = threading.Lock()
AFTER_WORK = {"at": 0.0}
LIB = ON.LIB_DIR
ROOT_FACTS = os.environ.get("FAKE_IGD_ROOT_FACTS") or os.path.join(LIB, "root-facts.json")
NGINX_CONF = os.environ.get("FAKE_IGD_NGINX_CONF") or "/etc/nginx/conf.d/fake-igd.conf"
SELINUX_FS = os.environ.get("FAKE_IGD_SELINUX_FS") or "/sys/fs/selinux"
PHP_D = os.environ.get("FAKE_IGD_PHP_D") or "/etc/php.d"
RUN_DIR = os.environ.get("FAKE_IGD_RUN") or "/run/fake-igd-api"


def after_test_file(ctx):
    return os.environ.get("FAKE_IGD_AFTER_TEST") or os.path.join(ctx.cfg.get("state_dir") or ON.STATE_DIR,
                                                                  "after-test.json")


def after_entry(**e):
    for k in ("id", "since", "level", "title", "why", "check", "ack"):
        if k not in e:
            raise ValueError("an entry of AFTER without %s" % k)
    e.setdefault("steps", [])
    e.setdefault("foot", "This band goes by itself once it is so." if e["ack"] == "auto"
                 else "Once it is done, press Done.")
    AFTER.append(e)
    return e


class _Args(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _words(text, args):
    try:
        return str(text or "").format_map(args)
    except (ValueError, IndexError, AttributeError):
        return str(text or "")


def _read_json_file(path, most=65536):
    try:
        st = os.lstat(path)
    except OSError:
        return None
    import stat as _stat
    if not _stat.S_ISREG(st.st_mode) or st.st_size > most:
        return {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def _read(path, most=1 << 20):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(most)
    except OSError:
        return None


def _units_active(names):
    """{unit: 'active' | 'inactive' | ...}, or {} where systemctl cannot be asked."""
    try:
        r = subprocess.run(["systemctl", "is-active"] + list(names), stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, universal_newlines=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return {}
    got = r.stdout.split()
    return dict(zip(names, got)) if len(got) == len(names) else {}


def after_facts(ctx):
    """What this server knows of its root side - files only, nothing of root's is run."""
    f = {"version": VERSION, "node": _node(), "root": _read_json_file(ROOT_FACTS),
         "http_port": int(ctx.cfg.get("http_port") or 5000)}
    f["installed"] = bool(os.path.exists(ON.HELPER) or os.path.exists(os.path.join(LIB, "fake-igd.py"))
                          or f["root"] is not None)
    installer = str((f["root"] or {}).get("installer") or "")
    if not installer:
        installer = (_read(os.path.join(LIB, "VERSION"), 64) or "").strip()
    f["installer"] = installer
    f["helper"] = os.path.exists(ON.HELPER)
    f["units"] = {u: os.path.exists(os.path.join(ON.UNIT_DIR, u))
                  for u in ("fake-igd-upgrade.path", "fake-igd-web.path")}
    f["active"] = _units_active(sorted(u for u, there in f["units"].items() if there)) if f["installed"] else {}
    f["nginx"] = _read(NGINX_CONF) if f["installed"] or os.environ.get("FAKE_IGD_NGINX_CONF") else None
    se = {}
    if os.path.isdir(SELINUX_FS):
        enf = (_read(os.path.join(SELINUX_FS, "enforce"), 8) or "").strip()
        se["mode"] = "Enforcing" if enf == "1" else ("Permissive" if enf == "0" else "")
        b = (_read(os.path.join(SELINUX_FS, "booleans", "httpd_can_network_connect"), 16) or "").split()
        se["network"] = b[0] if b else ""
        try:
            se["label"] = os.getxattr(RUN_DIR, "security.selinux").decode("ascii", "replace").strip("\0")
        except (OSError, AttributeError):
            se["label"] = ""
    f["selinux"] = se
    # The SELinux card's last look (1.7.7, root_selinux.py): mode, module, refusals - and the module beside the
    # program against the one last put into the policy (otp's cil / cil_in).
    try:
        f["se_now"] = (json.loads(ctx.store.get_meta("selinux:now") or "{}") or {}).get("data") or {}
    except (ValueError, AttributeError):
        f["se_now"] = {}

    def sha(p):
        raw = _read(p, 1 << 20)
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest() if raw is not None else ""
    f["cil"] = sha(os.path.join(LIB, "fake_igd_server.cil"))
    f["cil_in"] = sha(os.path.join(LIB, "fake_igd_server.cil.in-policy"))
    php = None
    if os.path.isdir(PHP_D):
        php = {"guard": _read(os.path.join(PHP_D, "99-php2shell.ini"), 8192)}
    f["php"] = php
    f["test"] = _read_json_file(after_test_file(ctx), 4096) or {}
    f["test_file"] = after_test_file(ctx)
    return f


# ---- the checks ------------------------------------------------------------------------
def _ck_root_parts(ctx, f):
    if not f.get("installed"):
        return "na"
    had = f.get("installer") or ""
    if re.match(r"^\d+\.\d+\.\d+\Z", had) and ON.ver_tuple(had) >= ON.ver_tuple(f["version"]):
        return "done"
    return ("needed", {"sig": had, "args": {"had": ("install.sh %s" % had) if had else "an older install.sh"}})


def _ck_helper(ctx, f):
    if not f.get("installed"):
        return "na"
    missing = ([] if f.get("helper") else [ON.HELPER]) + \
        [os.path.join(ON.UNIT_DIR, u) for u, there in sorted(f["units"].items()) if not there]
    if not missing:
        return "done"
    return ("needed", {"sig": ",".join(missing), "args": {"missing": ", ".join(missing)}})


def _ck_units_off(ctx, f):
    act = f.get("active") or {}
    if not act:
        return "na"
    off = sorted(u for u, s in act.items() if s != "active")
    if not off:
        return "done"
    return ("needed", {"sig": ",".join(off), "args": {"units": " ".join(off),
                                                       "units_words": ", ".join(off)}})


def _ck_nginx(ctx, f):
    t = f.get("nginx")
    rf = f.get("root") or {}
    if (rf.get("nginx") or {}).get("additions") == "failed":
        return ("needed", {"sig": str((rf.get("nginx") or {}).get("at") or ""),
                           "args": {"lacks": "what this version adds", "installer": rf.get("installer") or "?"}})
    if not t:
        return "na"
    lacks = []
    if "location = /metrics" not in t:
        lacks.append("GET /metrics for Prometheus")
    if "acme-challenge" not in t:
        lacks.append("ACME's HTTP-01 on port 80")
    if not lacks:
        return "done"
    return ("needed", {"sig": ",".join(lacks), "args": {"lacks": "; ".join(lacks),
                                                         "installer": f.get("installer") or "?"}})


def _ck_selinux(ctx, f):
    se = f.get("selinux") or {}
    if se.get("mode") not in ("Enforcing", "Permissive") or not f.get("installed"):
        return "na"
    what = []
    if se.get("network") == "0":
        what.append("httpd_can_network_connect is off (the pages may not ask the API on 127.0.0.1)")
    if os.path.isdir(RUN_DIR) and se.get("label") and "httpd_var_run_t" not in se["label"]:
        what.append("%s is labelled %s, not httpd_var_run_t (the pages may not read the API's token)"
                    % (RUN_DIR, se["label"].split(":")[2] if se["label"].count(":") >= 2 else se["label"]))
    if not what:
        return "done"
    return ("needed", {"sig": "|".join(what), "level": "bad" if se["mode"] == "Enforcing" else "warn",
                       "args": {"mode": se["mode"].lower(), "what": "; ".join(what)}})


def _ck_se_module(ctx, f):
    """fake-igd's module in the policy not the one beside this version (install.sh's semodule -i failed, or
    never ran while SELinux is on) - otp's selinux-module."""
    d = f.get("se_now") or {}
    mode = d.get("mode")
    if mode not in ("Enforcing", "Permissive"):
        return "na"
    off = d.get("module") is False
    old = bool(f.get("cil")) and f.get("cil_in") != f.get("cil")
    if not (off or old):
        return "done"
    return ("needed", {"sig": str(f.get("cil") or "")[:16], "level": "bad" if mode == "Enforcing" else "warn",
                       "args": {"mode": mode.lower(),
                                "how": "is not in its policy" if off else
                                "in its policy is older than the one of this version"}})


def _ck_se_refused(ctx, f):
    d = f.get("se_now") or ((f.get("root") or {}).get("selinux") or {})
    if d.get("mode") != "Enforcing":
        return "na"
    try:
        n = int((d.get("denials") or {}).get("total") or 0)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        return "done"
    fx = int((d.get("denials") or {}).get("fixable") or 0)
    return ("needed", {"sig": str(n), "grows": True, "args": {
        "n": n, "fixable": ("%d of them can be put right on Settings → SELinux at once (Put in what is selected) - a "
                            "boolean, a label, a port or a rule of fake-igd's own local module, exactly what was "
                            "refused" % fx) if fx else "none of them is for a button: Settings → SELinux says why, "
                                                    "each"}})


def _ck_php(ctx, f):
    p = f.get("php")
    if p is None or not f.get("installed"):
        return "na"
    g = p.get("guard") or ""
    if re.search(r"(?m)^\s*session\.upload_progress\.enabled\s*=\s*0", g):
        return "done"
    return ("needed", {"sig": "guard" if g else "none"})


def _ck_firewall(ctx, f):
    fw = (f.get("root") or {}).get("firewall") or {}
    if fw.get("state") != "none":
        return "na"
    return ("needed", {"sig": str(fw.get("at") or ""), "args": {"installer": (f.get("root") or {}).get("installer") or "?"}})


def _ck_test(which):
    def check(ctx, f):
        said = (f.get("test") or {}).get(which)
        if said not in ("needed", "done"):
            return "na"
        return said if said == "done" else ("needed", {"sig": "test"})
    return check


# ---- the entries -----------------------------------------------------------------------
after_entry(
    id="root-parts", since="1.6.1", level="bad", ack="auto", check=_ck_root_parts,
    title="fake-igd {version} is running, but the parts root installs are from before it",
    why="The program is new, and what install.sh puts in beside it as root is from {had}: root's helpers (the "
        "firewall, nginx's allow list, the certificates, what each pane asks of root), the upgrade helper, the "
        "path units and the additions to nginx. An upgrade from these pages does it all by itself; a package "
        "copied by hand, or an install.sh --upgrade that stopped half way, does not. Until it is done, what these "
        "pages ask of root may fail or be done as the older version did it.",
    steps=[{"where": "root", "lead": "As root, in the folder the fake-igd-{version} package was unpacked in:",
            "cmd": "./install.sh --upgrade"}],
    foot="This band goes by itself once install.sh of {version} has run to its end here.")

after_entry(
    id="upgrade-helper", since="1.6.1", level="warn", ack="auto", check=_ck_helper,
    title="A new version cannot be put in from these pages",
    why="What root uses to put in a package sent here, and to do what the panes ask of it, is not installed: "
        "{missing}. Upgrades from the pages and root's part of every pane wait until install.sh --upgrade has put "
        "them in once.",
    steps=[{"where": "root", "lead": "As root, in the folder the fake-igd-{version} package was unpacked in:",
            "cmd": "./install.sh --upgrade"}])

after_entry(
    id="path-units", since="1.6.1", level="warn", ack="auto", check=_ck_units_off,
    title="systemd does not watch for what the pages ask of root",
    why="{units_words} is installed but not running: a new version asked for on these pages, and what each pane "
        "asks of root (the firewall, nginx, the certificates, the network ...), lies in /var/lib/fake-igd and "
        "nobody takes it.",
    steps=[{"where": "root", "cmd": "systemctl enable --now {units}"},
           {"where": "root", "lead": "Then see that they run:", "cmd": "systemctl status {units}"}])

after_entry(
    id="nginx-additions", since="1.6.1", level="warn", ack="auto", check=_ck_nginx,
    title="nginx did not take the additions of the last upgrade",
    why="What this version needs of /etc/nginx/conf.d/fake-igd.conf is not in it: {lacks}. install.sh "
        "{installer} puts it in where it is missing, asks nginx -t, and puts the file back as it was when nginx "
        "refuses it - usually because of a change of your own in the file. The pages work as before; the copy "
        "from before the upgrade is the file's .before-VERSION beside it.",
    steps=[{"where": "root", "lead": "As root, on the server: what nginx says of the file now", "cmd": "nginx -t"},
           {"where": "root", "lead": "Then, once what it refused is put right, in the folder of the package:",
            "cmd": "./install.sh --upgrade"}],
    foot="This band goes by itself once nginx's file has what this version needs.")

after_entry(
    id="selinux", since="1.6.1", level="warn", ack="auto", check=_ck_selinux,
    title="SELinux: the pages may not reach fake-igd's API",
    why="SELinux is {mode} on this server, and {what}. install.sh sets both; a machine relabelled, or SELinux "
        "switched on after the install, loses them. Do not switch SELinux off for it - put back what the pages "
        "need, as install.sh does.",
    steps=[{"where": "root", "cmd": "setsebool -P httpd_can_network_connect 1"},
           {"where": "root", "lead": "And the label of the API's folder:",
            "cmd": "semanage fcontext -a -t httpd_var_run_t '/run/fake-igd-api(/.*)?' 2>/dev/null || "
                   "semanage fcontext -m -t httpd_var_run_t '/run/fake-igd-api(/.*)?'; restorecon -R /run/fake-igd-api"}],
    foot="This band goes by itself once it is so (looked at every ten minutes; Look again asks now).")

after_entry(
    id="selinux-module", since="1.7.7", level="warn", ack="auto", check=_ck_se_module,
    title="SELinux: fake-igd's module is not the one this version needs",
    why="SELinux is {mode} on this server, and fake-igd's module (fake_igd_server) {how}: the labels it gives "
        "fake-igd's files are missing, and the pages may not read what they need. Do not switch SELinux off for "
        "it - put the module in, as install.sh does.",
    steps=[{"where": "root", "lead": "As root, on the server:",
            "cmd": "semodule -i /opt/fake-igd/fake_igd_server.cil && install -m 0644 /opt/fake-igd/fake_igd_server.cil "
                   "/opt/fake-igd/fake_igd_server.cil.in-policy"},
           {"where": "root", "lead": "Then see that nothing else is missing:", "cmd": "upnp selinux check"},
           {"where": "pages", "pane": "selinux",
            "words": "Or on Settings → SELinux: Put in what fake-igd needs (while permissive)."}],
    foot="This band goes by itself once the module is in (SELinux is looked at every half hour; Look again asks "
         "sooner).")

after_entry(
    id="selinux-refused", since="1.6.1", level="bad", ack="auto", check=_ck_se_refused,
    title="SELinux refuses fake-igd something on this server",
    why="SELinux is enforcing and refused {n} thing(s) to fake-igd or to the programs it works with (since "
        "fake-igd's needs were last put in, or since the machine started): what was refused does not work - the "
        "pages, root's helper, the SSH server on its port. {fixable}. Do not switch SELinux off for it.",
    steps=[{"where": "pages", "pane": "selinux",
            "words": "Settings → SELinux: What SELinux refuses - select, then Put in what is selected."},
           {"where": "root", "lead": "Or as root, on the server - what is refused, and what puts it right:",
            "cmd": "upnp selinux look"},
           {"where": "root", "lead": "Everything that can be put right here:", "cmd": "upnp selinux fix --all"},
           {"where": "root", "lead": "The report, for whoever looks after fake-igd's module:",
            "cmd": "upnp selinux report"}],
    foot="This band goes by itself once nothing is refused any more (put right, or after the next start of the "
         "machine). Done takes it away until something more is refused.")

after_entry(
    id="php2shell", since="1.6.1", level="bad", ack="auto", check=_ck_php,
    title="PHP here does not have the php2shell guard",
    why="CVE-2026-109618 and CVE-2026-109619: remote code execution by anybody who can reach the web server. "
        "/etc/php.d/99-php2shell.ini (session upload progress off, sessions strict) is missing or changed. "
        "Update PHP to the fixed release of your distribution and restart php-fpm - install.sh --upgrade does "
        "both, and puts the guard back.",
    steps=[{"where": "root", "cmd": "dnf upgrade 'php*' && systemctl restart php-fpm"},
           {"where": "root", "lead": "Or, in the folder of the package:", "cmd": "./install.sh --upgrade"}],
    foot="This band goes by itself once the guard is in place.")

after_entry(
    id="firewall-by-hand", since="1.6.1", level="info", ack="manual", check=_ck_firewall,
    title="Nothing opened the firewall for fake-igd on this server",
    why="Neither firewalld nor iptables was there when install.sh {installer} ran, so it opened nothing. Whatever "
        "filters this machine must let through UDP 1900 and the SOAP port from the PS5's network, and TCP 443 "
        "(and 80) to these pages - or let fake-igd look after the machine's firewall on Settings → Firewall and "
        "access.",
    steps=[{"where": "root", "lead": "As root, with firewalld:",
            "cmd": "firewall-cmd --permanent --add-port=1900/udp --add-port={http_port}/tcp --add-service=https "
                   "--add-service=http && firewall-cmd --reload"},
           {"where": "pages", "pane": "web", "words": "Or on Settings → Firewall and access."}])

after_entry(
    id="test-auto", since="1.6.1", level="warn", ack="auto", check=_ck_test("auto"),
    title="A test: something that goes by itself",
    why="Made by the tests of the pages ({file}). It goes when the file says \"done\".",
    steps=[{"where": "root", "cmd": "rm {file}"}])
after_entry(
    id="test-manual", since="1.6.1", level="bad", ack="manual", check=_ck_test("manual"),
    title="A test: something done by hand",
    why="Made by the tests of the pages ({file}). Press Done.",
    steps=[{"where": "root", "cmd": "echo done"}])


def after_item(e, f, det):
    args = _Args({"version": f.get("version") or VERSION, "node": f.get("node") or _node(), "lib": LIB,
                  "file": f.get("test_file") or "", "lead": "As root, on the server:",
                  "http_port": f.get("http_port") or 5000})
    args.update({k: v for k, v in (det.get("args") or {}).items()})
    steps = []
    for st in e.get("steps") or []:
        one = {"where": st.get("where") or "root"}
        if st.get("cmd"):
            one["cmd"] = _words(st["cmd"], args)
            one["lead"] = _words(st.get("lead") or "{lead}", args)
        if st.get("pane"):
            one["pane"] = st["pane"]
            one["words"] = _words(st.get("words") or "", args)
        steps.append(one)
    level = det.get("level") if det.get("level") in AFTER_LEVELS else e["level"]
    return {"id": e["id"], "since_version": e["since"], "level": level, "ack": e["ack"],
            "title": _words(e["title"], args)[:300], "why": _words(e["why"], args)[:1500], "steps": steps,
            "foot": _words(e.get("foot"), args)[:400], "sig": str(det.get("sig") or "")[:200],
            "grows": bool(det.get("grows"))}


def _acks(store):
    got = store.meta_json("after:acks") or {}
    return {k: v for k, v in got.items() if isinstance(v, dict)}


def _acked(ack, it):
    if not ack:
        return False
    if str(ack.get("sig") or "") != str(it.get("sig") or ""):
        try:
            grown = it.get("grows") and float(it.get("sig") or 0) <= float(ack.get("sig") or 0)
        except ValueError:
            grown = False
        if not grown:
            return False
    if it.get("ack") == "auto" and float(ack.get("at") or 0) + 1 < float(it.get("since") or 0):
        return False
    return True


def after_evaluate(ctx):
    """Every entry's check, kept in meta 'after:row', with what went by itself and what came back."""
    with AFTER_LOCK:
        store = ctx.store
        was = store.meta_json("after:row") or {}
        # Not while an upgrade goes on (1.7.3): the new API starts before install.sh has put root's parts
        # in and written root-facts.json - every upgrade said "the parts root installs are from before it".
        try:
            busy = bool(ON.status().get("busy")) or ON.pages_running()
        except Exception:                               # noqa: BLE001
            busy = False
        if busy:
            return was
        old = was.get("items") or {}
        log = [x for x in (was.get("log") or []) if isinstance(x, dict)][:AFTER_LOG_KEEP]
        f = after_facts(ctx)
        acks = _acks(store)
        now = time.time()
        items = {}
        for e in AFTER:
            p = old.get(e["id"]) or {}
            try:
                got = e["check"](ctx, f)
                state, det = got if isinstance(got, tuple) else (got, {})
            except Exception as ex:                     # noqa: BLE001 - one check broken, the rest go on
                sys.stderr.write("api: after the update, %s: %s\n" % (e["id"], ex))
                if p:
                    items[e["id"]] = p
                continue
            if state != "needed":
                if p.get("state") == "needed":
                    log.insert(0, {"id": e["id"], "title": p.get("title") or e["id"], "how": "by itself", "at": now})
                continue
            it = after_item(e, f, det)
            it["since"] = float(p.get("since") or 0) or now
            it["state"] = "acked" if _acked(acks.get(e["id"]), it) else "needed"
            if p.get("state") == "acked" and it["state"] == "needed":
                log.insert(0, {"id": e["id"], "title": it["title"], "how": "taken back", "at": now})
            items[e["id"]] = it
        row = {"at": now, "node": f["node"], "version": VERSION, "items": items, "log": log[:AFTER_LOG_KEEP]}
        store.set_meta("after:row", json.dumps(row))
        AFTER_WORK["at"] = now
        return row


def _facts_newer(row, store=None):
    """root-facts.json written since the list was last looked at (install.sh ended), or SELinux looked at /
    changed by root since (a step of Settings → SELinux, 1.7.9): look again now - not ten minutes later."""
    seen = float((row or {}).get("at") or 0)
    try:
        if os.path.getmtime(ROOT_FACTS) > seen:
            return True
    except OSError:
        pass
    if store is not None:
        try:
            se = json.loads(store.get_meta("selinux:now") or "{}") or {}
            if float(se.get("at") or 0) > seen:
                return True
        except (ValueError, TypeError, AttributeError):
            pass
    return False


def _row(ctx):
    row = ctx.store.meta_json("after:row")
    if not row or row.get("version") != VERSION or time.time() - float(row.get("at") or 0) > AFTER_EVERY * 2 \
            or _facts_newer(row, ctx.store):
        row = after_evaluate(ctx)
    return row


def after_needed(ctx):
    row = _row(ctx)
    acks = _acks(ctx.store)
    out = []
    for i, it in (row.get("items") or {}).items():
        if not isinstance(it, dict) or it.get("level") not in AFTER_LEVELS:
            continue
        if _acked(acks.get(str(it.get("id") or i)), it):
            continue
        out.append(dict(it, id=str(it.get("id") or i), node=row.get("node") or _node(),
                        checked=float(row.get("at") or 0)))
    out.sort(key=lambda x: (AFTER_LEVELS.index(x["level"]), -float(x.get("since") or 0)))
    return out, row


def _line_key(x):
    return [str(x.get("id") or ""), str(x.get("node") or ""), int(float(x.get("at") or 0))]


def _lately_all(ctx, row):
    node = row.get("node") or _node()
    out = []
    for x in row.get("log") or []:
        if isinstance(x, dict):
            out.append({"id": x.get("id"), "node": node, "title": x.get("title") or x.get("id"),
                        "how": x.get("how") or "by itself", "who": "", "at": float(x.get("at") or 0)})
    for i, a in _acks(ctx.store).items():
        out.append({"id": i, "node": node, "title": a.get("title") or i, "how": "done",
                    "who": "the command line" if a.get("via") == "cli" else str(a.get("by") or ""),
                    "at": float(a.get("at") or 0)})
    return out


def after_view(ctx, full=True):
    items, row = after_needed(ctx)
    worst = items[0]["level"] if items else ""
    if not full:
        return {"count": len(items), "level": worst}
    gone = [list(x) for x in ((ctx.store.meta_json("after:cleared") or {}).get("lines") or []) if isinstance(x, list)]
    lately = [x for x in _lately_all(ctx, row) if _line_key(x) not in gone]
    lately.sort(key=lambda x: -x["at"])
    keys = ("id", "node", "level", "ack", "title", "why", "steps", "foot", "since", "checked", "since_version",
            "state")
    return {"items": [{k: x.get(k) for k in keys} for x in items], "count": len(items), "level": worst,
            "lately": lately[:AFTER_LOG_KEEP], "me": row.get("node") or _node(), "cluster": False,
            "nodes": [{"name": row.get("node") or _node(), "checked": float(row.get("at") or 0),
                       "version": VERSION}]}


def after_done(ctx, ident, by, via="pages"):
    row = _row(ctx)
    it = (row.get("items") or {}).get(ident)
    if not it:
        raise ValueError("%s has nothing called %s to be done" % (_node(), ident))
    acks = _acks(ctx.store)
    acks[ident] = {"by": by, "at": time.time(), "sig": it.get("sig") or "", "title": it.get("title") or ident,
                   "auto": it.get("ack") == "auto", "via": via}
    ctx.store.set_meta("after:acks", json.dumps(acks))
    ctx.event("%s marked as done: %s%s" % (by, it.get("title") or ident, " - although its check still finds it "
                                           "needed" if it.get("ack") == "auto" else ""),
              "warn" if it.get("ack") == "auto" else "info")
    return "marked as done"


def after_clear(ctx, items, by, via="pages"):
    _items, row = after_needed(ctx)
    every = [_line_key(x) for x in _lately_all(ctx, row)]
    had = [list(x) for x in ((ctx.store.meta_json("after:cleared") or {}).get("lines") or []) if isinstance(x, list)]
    if items is None:
        want = [k for k in every if k not in had]
    else:
        want = []
        for one in list(items)[:300]:
            try:
                k = [str(one[0])[:48], str(one[1])[:64], int(float(one[2]))]
            except (TypeError, ValueError, IndexError):
                continue
            if k in every and k not in had and k not in want:
                want.append(k)
    lines = [x for x in had if x in every] + want
    ctx.store.set_meta("after:cleared", json.dumps({"lines": lines[-400:], "at": time.time()}))
    ctx.event('"done lately" cleared by %s (%d)' % ("the command line" if via == "cli" else by, len(want)))
    return len(want)


def after_get(ctx):
    ctx.need("fulladmin")
    return after_view(ctx, full=ctx.arg("brief") not in ("1", "true"))


def after_post(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    by = _who(ctx)
    if act == "check":
        after_evaluate(ctx)
        return dict(after_view(ctx), message="looked again")
    if act == "done":
        words = after_done(ctx, str(b.get("id") or ""), by)
        return dict(after_view(ctx), message=words)
    if act == "clear_done":
        n = after_clear(ctx, b.get("items") if isinstance(b.get("items"), list) else [], by)
        return dict(after_view(ctx), message='"done lately" cleared (%d)' % n)
    raise ValueError("no such thing to do")


ROUTES = {
    ("GET", "/api/upgrade"): upgrade_get,
    ("POST", "/api/upgrade"): upgrade_post,
    ("POST", "/api/upgrade-package"): upgrade_package,
    ("GET", "/api/after"): after_get,
    ("POST", "/api/after"): after_post,
}


# ---- once a minute ---------------------------------------------------------------------
def background(ctx):
    """The list looked at every ten minutes; the end of an upgrade written in the events once."""
    if time.time() - AFTER_WORK["at"] >= AFTER_EVERY or _facts_newer(ctx.store.meta_json("after:row"), ctx.store):
        try:
            after_evaluate(ctx)
        except Exception as e:                          # noqa: BLE001
            sys.stderr.write("api: after the update: %s\n" % e)
    _plan(ctx, hidden=False)


def _tell(ctx, p):
    """How an upgrade ended, written in the events once (whichever asks first: the pages or the
    minute's background step)."""
    if not p or p.get("state") not in ("done", "failed"):
        return
    key = "%s:%s" % (p.get("id"), p["state"])
    if (ctx.store.get_meta("upgrade:told") or "") == key:
        return
    ctx.store.set_meta("upgrade:told", key)
    st = (p.get("steps") or [{}])[0]
    if p["state"] == "done":
        ctx.event("%s is %s fake-igd %s" % (_node(), "back on" if p.get("downgrade") else "upgraded to", VERSION),
                  "info", kind="upgrade")
    else:
        ctx.event("the %s of %s to fake-igd %s failed: %s" % ("going back" if p.get("downgrade") else "upgrade",
                                                              _node(), p.get("version"), st.get("said") or "?"),
                  "error", kind="upgrade")
