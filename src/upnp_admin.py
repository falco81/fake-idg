"""upnp_admin.py - `upnp upgrade`, `upnp user` and `upnp web` (1.4.0).

The command line's side of what otp has: new versions from the web
(otp --upgrade-check / --upgrade-online / --upgrade-follow), the local accounts
of the web pages (otp --users / --add-user / --passwd) and the pages themselves.
Every one is a function (M, args, cfg): M is the running upnp module, whose
colours, tables and words these use, so that everything looks the same.
"""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import igd_online as ON      # noqa: E402

APP_USER = "fake-igd"
LIB_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_HELPER = os.path.join(LIB_DIR, "fake_igd_web.py")


# ---- as the fake-igd account ----------------------------------------------------------
def as_app(fn):
    """fn() as the fake-igd account: root forks and drops to it, so that the database and the
    upgrade folder never get a file of root's. Anybody else runs it as they are. The exit code."""
    if os.geteuid() != 0:
        return fn() or 0
    import grp
    import pwd
    try:
        pw = pwd.getpwnam(APP_USER)
    except KeyError:
        return fn() or 0
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            groups = [g.gr_gid for g in grp.getgrall() if APP_USER in g.gr_mem] + [pw.pw_gid]
            os.setgroups(sorted(set(groups)))
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            os.environ["HOME"] = pw.pw_dir or "/"
            code = fn() or 0
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            if e.code and not isinstance(e.code, int):
                sys.stderr.write(str(e.code) + "\n")
        except BaseException as e:                       # noqa: BLE001 - said, never lost
            sys.stderr.write("upnp: %s\n" % e)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(code)
    _p, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else (status >> 8)


def store_of(M, cfg):
    import igd_store as ST
    path = os.environ.get("FAKE_IGD_DB") or os.path.join(cfg["state_dir"], "fake-igd.db")
    try:
        return ST.Store(path)
    except Exception as e:                                # noqa: BLE001
        M.fail("the database %s does not open: %s%s" % (path, e, "" if os.geteuid() == 0 else
                                                          " - try it with sudo"))


def who_runs():
    return "%s on the command line" % (os.environ.get("SUDO_USER") or os.environ.get("USER") or
                                       ("root" if os.geteuid() == 0 else str(os.geteuid())))


def bar(M, pc, width=30, bad=False, good=False):
    n = int(round(width * pc / 100.0))
    fill = "█" * n + "░" * (width - n)
    paint = M.PAL.bad if bad else (M.PAL.good if good else M.PAL.info)
    return paint(fill) + " %3d %%" % pc


# ---- upgrades -------------------------------------------------------------------------
def cmd_upgrade(M, args, cfg):
    what = args.what or "check"
    args.path = args.version if what == "file" else None
    url = cfg.get("upgrade_url") or ON.DEFAULT_URL
    here = M.VERSION
    pal = M.PAL
    if what == "check":
        row = ON.look(url, here)
        if os.geteuid() == 0:
            as_app(lambda: _keep_look(M, cfg, row))
        if args.json:
            print(json.dumps(ON.view(row, here), indent=2, default=str))
            return 0 if not row.get("error") else 1
        print(pal.head("looked at %s" % row.get("url")))
        if row.get("error"):
            M.fail(row["error"])
        for pk in row.get("packages") or []:
            mark = pal.good("newer    ") if ON.ver_tuple(pk["version"]) > ON.ver_tuple(here) else \
                (pal.info("this one ") if pk["version"] == here else pal.dim("not newer"))
            print("  %-26s %s  %s" % (pk["name"], mark, pal.dim(pk["url"])))
        n = row.get("newest")
        if not n:
            M.warn("no fake-igd package there")
        elif row.get("newer"):
            M.ok("fake-igd %s is there - this server runs %s: sudo upnp upgrade online" % (n["version"], here))
        else:
            M.ok("nothing newer than %s" % here)
        return 0
    if what == "status":
        st = ON.status()
        if args.json:
            st["log"] = ON.log_lines(200)
            print(json.dumps(st, indent=2, default=str))
            return 0
        _say_status(M, st)
        return 0
    if what == "log":
        lines = ON.log_lines(args.lines or 400)
        if not lines:
            print(pal.dim("nothing yet - %s is empty" % os.path.join(ON.UPGRADE_DIR, "last.log")))
        for ln in lines:
            print(_log_line(M, ln))
        return 0
    if what == "follow":
        return follow(M, None)
    # online and file put something in: root's
    M.require_root("An upgrade")
    if what == "online":
        st = ON.status()
        if st.get("busy"):
            M.fail("an upgrade is going on already - upnp upgrade follow")
        row = ON.look(url, here)
        if row.get("error"):
            M.fail("%s: %s" % (row.get("url"), row["error"]))
        want = args.version
        pk = row.get("newest") if not want else next(
            (x for x in row.get("packages") or [] if x["version"] == want), None)
        if not pk:
            M.fail("%s is not at %s" % (want or "no fake-igd package", row.get("url")))
        if ON.ver_tuple(pk["version"]) <= ON.ver_tuple(here):
            M.ok("nothing newer than %s at %s" % (here, row.get("url")))
            return 0
        print(pal.head("fake-igd %s → %s" % (here, pk["version"])) + pal.dim("  from %s" % pk["url"]))
        print("  this server - fake-igd.service and the pages restart once; the PS5 notices nothing")
        if not args.yes and not _ask("go on?"):
            print("  nothing done")
            return 1
        print(pal.dim("  fetching it and checking its signature…"))
        return as_app(lambda: _fetch_and_ask(M, cfg, url, pk["version"], here, args))
    if what == "file":
        if not args.path:
            M.fail("which file? upnp upgrade file fake-igd-X.Y.Z.tar.gz")
        if args.downgrade:
            return _downgrade(M, args)
        path = os.path.abspath(args.path)
        if not os.path.isfile(path):
            M.fail("%s is not a file" % path)
        st = ON.status()
        if st.get("busy"):
            M.fail("an upgrade is going on already - upnp upgrade follow")
        print(pal.dim("  checking %s…" % path))
        # Read by root (it may be root's alone), laid down by the fake-igd account.
        import tempfile
        tmpd = tempfile.mkdtemp(prefix="fake-igd-pkg-")
        try:
            copy = os.path.join(tmpd, "package.tar.gz")
            shutil.copyfile(path, copy)
            os.chmod(tmpd, 0o755)
            os.chmod(copy, 0o644)
            return as_app(lambda: _file_and_ask(M, copy, args, here))
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
    M.fail("upnp upgrade check | online [VERSION] | file PATH | status | follow | log")


def _ask(words):
    try:
        return input("  %s (y/N) " % words).strip().lower() in ("y", "yes", "a", "ano")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _keep_look(M, cfg, row):
    try:
        s = store_of(M, cfg)
        s.set_meta("upgrade:online", json.dumps(row, default=str))
    except BaseException:                                   # noqa: BLE001 - only kept for the pages
        pass
    return 0


def _event(M, cfg, kind, words, level="info"):
    try:
        store_of(M, cfg).add_event(kind, words, level, who_runs())
    except BaseException:                                   # noqa: BLE001
        pass


def _fetch_and_ask(M, cfg, url, version, here, args):
    try:
        info = ON.fetch(url, version, here)
    except ValueError as e:
        M.fail(str(e))
    M.ok("fake-igd %s fetched, signed by %s, %d files - checked" % (info["version"], info.get("signed_by"),
                                                                    info.get("files") or 0))
    if info.get("changelog") and not args.quiet:
        print(M.PAL.dim("  what is new:"))
        for ln in info["changelog"].splitlines()[:40]:
            print(M.PAL.dim("    " + ln))
    _event(M, cfg, "upgrade", "%s fetched fake-igd %s from %s" % (who_runs(), info["version"], info.get("from")),
           "warn")
    return _ask_root_and_follow(M, cfg, info, args)


def _file_and_ask(M, path, args, here):
    cfg = M.load_config(args.config)
    try:
        info = ON.take_file(path)
    except ValueError as e:
        M.fail(str(e))
    if info.get("older"):
        M.fail("%s is older than %s, which is installed - going back: sudo upnp upgrade file %s --downgrade"
               % (info["version"], info.get("installed"), args.path))
    M.ok("fake-igd %s, signed by %s, %d files - checked" % (info["version"], info.get("signed_by"),
                                                            info.get("files") or 0))
    if not info.get("newer"):
        M.info("the same version as installed (%s) - it is put in again" % here)
    if not args.yes and not _ask("put it in?"):
        print("  nothing done")
        return 1
    return _ask_root_and_follow(M, cfg, info, args)


def _ask_root_and_follow(M, cfg, info, args):
    try:
        ident = ON.ask_root(info, who_runs())
    except ValueError as e:
        M.fail(str(e))
    _event(M, cfg, "upgrade", "%s started the upgrade to fake-igd %s" % (who_runs(), info["version"]), "warn")
    M.info("asked root to put it in (fake-igd-upgrade.path) - followed here; Ctrl+C stops the following, "
           "not the upgrade")
    if args.no_follow:
        print(M.PAL.dim("  upnp upgrade follow  follows it, upnp upgrade status says how it ended"))
        return 0
    return follow(M, ident)


def _downgrade(M, args):
    """An older version, by hand, as root: root's helper straight, its output here."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
    helper = ON.HELPER
    if not os.path.exists(helper):
        M.fail("%s is not installed - upgrade once with install.sh --upgrade" % helper)
    M.warn("going back to an older version: its install.sh --upgrade runs here, now")
    if not args.yes and not _ask("go back?"):
        print("  nothing done")
        return 1
    p = subprocess.Popen([py, "-I", helper, "--run", os.path.abspath(args.path), "--downgrade"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for ln in p.stdout:
        print(_log_line(M, ln.rstrip("\n")))
    return p.wait()


def _log_line(M, ln):
    p = M.PAL
    low = ln.lower()
    if ln.startswith("==> "):
        return p.head(ln)
    if low.startswith("error") or low.startswith("refused") or low.startswith("broke") or " failed" in low:
        return p.bad(ln)
    if "warning" in low or low.lstrip().startswith("warn"):
        return p.warn(ln)
    if "checked" in low and "signed by" in low or low.startswith("install.sh ended with 0"):
        return p.good(ln)
    return ln


def _say_status(M, st):
    p = M.PAL
    state = st.get("state") or "none"
    if state == "none" or (not st.get("id") and not st.get("busy")):
        print(p.dim("no upgrade asked for yet on this machine"))
        return
    colour = {"done": p.good, "failed": p.bad, "running": p.info, "asked": p.warn}.get(state, p.dim)
    print("%s  fake-igd %s  %s" % (p.head("upgrade"), st.get("version") or "?", colour(state)))
    if st.get("at"):
        print(p.dim("  %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(st["at"])))))
    if st.get("said"):
        print("  " + p.bad(st["said"]))
    if st.get("busy"):
        pc, words = ON.progress(ON.log_lines())
        print("  " + bar(M, pc) + "  " + words)
    for ln in (st.get("tail") or [])[-12:]:
        print("  " + _log_line(M, ln))


def follow(M, ident):
    """An upgrade followed on the terminal: its lines as they come, a bar under them."""
    p = M.PAL
    tty = sys.stdout.isatty()
    shown = 0
    began = time.time()
    taken_said = False
    bar_drawn = False
    raw = sys.stdout
    try:
        while True:
            st = ON.status()
            lines = ON.log_lines(4000)
            mine = (not ident) or st.get("id") == ident
            if mine and st.get("state") in ("running", "done", "failed") and len(lines) > shown:
                if bar_drawn:
                    raw.write("\r\x1b[2K")
                    bar_drawn = False
                for ln in lines[shown:]:
                    raw.write("  " + _log_line(M, ln) + "\n")
                shown = len(lines)
            if mine and st.get("state") in ("done", "failed") and not st.get("busy"):
                if bar_drawn:
                    raw.write("\r\x1b[2K")
                raw.flush()
                if st["state"] == "done":
                    M.ok("the upgrade is done - fake-igd %s runs here" % st.get("version"))
                    return 0
                M.fail("the upgrade ended: %s" % (st.get("said") or "install.sh ended with %s" % st.get("rc")))
            if not ident and not st.get("busy"):
                print(p.dim("no upgrade going on") if not st.get("state") else "")
                _say_status(M, st)
                return 0
            if st.get("state") == "asked" and time.time() - began > 20 and not taken_said:
                taken_said = True
                if bar_drawn:
                    raw.write("\r\x1b[2K")
                    bar_drawn = False
                M.warn("root has not taken it yet - is fake-igd-upgrade.path running? "
                       "systemctl enable --now fake-igd-upgrade.path")
            if tty:
                pc, words = ON.progress(lines if mine else [])
                if st.get("state") == "asked":
                    words = "waiting for root to take it"
                raw.write("\r\x1b[2K  " + bar(M, pc) + "  " + p.dim(str(words)[:60]))
                raw.flush()
                bar_drawn = True
            time.sleep(1 if tty else 3)
    except KeyboardInterrupt:
        print("\n" + p.dim("no longer followed here - it goes on; upnp upgrade follow follows it again"))
        return 0


# ---- the accounts of the web pages ---------------------------------------------------
def _password_from(M, given, name):
    """`-`: asked twice on the terminal; @env: UPNP_PASSWORD; nothing: one is made and printed."""
    import igd_store as ST
    if given == "-":
        import getpass
        a = getpass.getpass("password for %s: " % name)
        b = getpass.getpass("again: ")
        if a != b:
            M.fail("those two are not the same")
        bad = ST.password_problem(a)
        if bad:
            M.fail(bad)
        return a, False
    if given == "@env":
        v = os.environ.get("UPNP_PASSWORD", "")
        bad = ST.password_problem(v)
        if bad:
            M.fail("UPNP_PASSWORD: %s" % bad)
        return v, False
    if given:
        M.warn("the password is on the command line (ps, the shell's history) - next time: --password -")
        return given, False
    import secrets
    return secrets.token_urlsafe(12), True


def cmd_user(M, args, cfg):
    import igd_store as ST
    what = args.what or "list"
    p = M.PAL
    if what in ("list", "sessions"):
        def go():
            s = store_of(M, cfg)
            if what == "sessions":
                rows = s.sessions()
                if args.json:
                    print(json.dumps(rows, indent=2, default=str))
                    return 0
                M.table(["ID", "ACCOUNT", "FROM", "SIGNED IN", "LAST SEEN", "BROWSER"],
                        [[M.col(r["id"], M.C.dim), M.col(r["name"], M.C.bold), M.col(r["addr"], M.C.magenta),
                          _when(r["created"]), _when(r["seen"]), (r["agent"] or "")[:50]] for r in rows],
                        "nobody is signed in to the pages")
                return 0
            rows = s.users()
            if args.json:
                print(json.dumps(rows, indent=2, default=str))
                return 0
            M.table(["NAME", "ROLE", "SIGNED IN NOW", "LAST SIGN-IN", "FROM", "NOTE"],
                    [[M.col(r["name"], M.C.bold),
                      M.col(r["role_words"], M.C.magenta if r["role"] == "fulladmin" else M.C.dim),
                      M.col(r["sessions"], M.C.green) if r["sessions"] else M.col("-", M.C.dim),
                      _when(r["last_login"]), r["last_from"] or "-", r["note"] or ""] for r in rows],
                    "no account yet - make one: sudo upnp user add NAME")
            return 0
        if os.geteuid() != 0 and not os.access(os.path.join(cfg["state_dir"], "fake-igd.db"), os.W_OK):
            M.require_root("The accounts of the web pages")
        return as_app(go)
    M.require_root("Changing the accounts of the web pages")
    name = args.name
    if what in ("add", "passwd", "role", "del", "note") and not name:
        M.fail("which account? upnp user %s NAME" % what)
    pw, made = ("", False)
    if what in ("add", "passwd"):
        pw, made = _password_from(M, args.password, name)
    if what == "del" and not args.yes and not _ask("take the account %s away?" % name):
        print("  nothing done")
        return 1

    def go():
        s = store_of(M, cfg)
        try:
            if what == "add":
                s.add_user(name, pw, args.role or "fulladmin", args.note or "")
                s.add_event("account", "%s made the account %s (%s)" % (who_runs(), name, args.role or "fulladmin"),
                            "info", who_runs())
                M.ok("%s may sign in to the pages, as %s" % (name, ST.ROLE_WORDS[args.role or "fulladmin"]))
            elif what == "passwd":
                s.set_password(name, pw)
                for x in s.sessions():
                    if x["name"].lower() == name.lower():
                        s.end_session(x["id"])
                s.add_event("account", "%s gave %s a new password" % (who_runs(), name), "info", who_runs())
                M.ok("%s has a new password (its sign-ins are ended)" % name)
            elif what == "role":
                if args.role not in ST.ROLES:
                    M.fail("--role fulladmin or readonly")
                s.set_role(name, args.role)
                s.add_event("account", "%s made %s %s" % (who_runs(), name, ST.ROLE_WORDS[args.role]), "info",
                            who_runs())
                M.ok("%s is %s" % (name, ST.ROLE_WORDS[args.role]))
            elif what == "note":
                s.set_note(name, args.note or "")
                M.ok("kept")
            elif what == "del":
                s.delete_user(name)
                s.add_event("account", "%s took the account %s away" % (who_runs(), name), "warn", who_runs())
                M.ok("%s is gone" % name)
            elif what == "end":
                s.end_session(name)
                M.ok("that sign-in is over")
            else:
                M.fail("upnp user list | add NAME | passwd NAME | role NAME --role R | note NAME | del NAME | "
                       "sessions | end ID")
        except ST.StoreError as e:
            M.fail(str(e))
        if made:
            print()
            print("    %s %s" % (p.good("name:    "), name))
            print("    %s %s" % (p.good("password:"), pw))
            print()
            M.warn("Write that down now - it is not shown again.")
        return 0
    return as_app(go)


def _when(t):
    if not t:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(t)))


# ---- the web pages ---------------------------------------------------------------------
def _active(unit):
    r = subprocess.run(["systemctl", "is-active", unit], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       universal_newlines=True)
    return (r.stdout or "").strip() or "unknown"


def cmd_web(M, args, cfg):
    what = args.what or "status"
    p = M.PAL
    if what == "apply":
        M.require_root("Putting nginx's allow list and the firewall in place")
        py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
        r = subprocess.run([py, "-I", WEB_HELPER, "--apply"] + (["--restart"] if args.restart else []),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        for ln in (r.stdout or "").splitlines():
            (M.ok if "refused" not in ln and "not" not in ln else M.warn)(ln)
        return r.returncode
    conf = "/etc/nginx/conf.d/fake-igd.conf"
    name = ""
    try:
        import re
        with open(conf, encoding="utf-8") as f:
            m = re.search(r"server_name\s+([^;\s]+)", f.read())
            name = m.group(1) if m else ""
    except OSError:
        pass
    print(M.col("The web pages", M.C.bold))
    rows = [
        ["Address", M.col("https://%s/" % (name or "<this server>"), M.C.cyan, M.C.bold) if name
         else M.col("not installed (install.sh without --no-web)", M.C.yellow)],
        ["nginx", _state(M, _active("nginx"))],
        ["php-fpm", _state(M, _active("php-fpm"))],
        ["fake-igd-api", _state(M, _active("fake-igd-api"))],
        ["API", "127.0.0.1:%s" % cfg.get("api_port", 9862)],
        ["Who may reach them", ", ".join(cfg.get("web_allow") or []) or M.col("everybody", M.C.yellow)],
        ["Sign-in ends after", "%s min idle" % cfg.get("session_idle_minutes", 120)],
        ["Firewall", M.col("FAKE-IGD-IN (iptables)", M.C.green) if cfg.get("firewall")
         else M.col("off - fake-igd does not touch iptables", M.C.dim)],
    ]
    for k, v in rows:
        print("  %-20s %s" % (k, v))
    print()
    print(p.dim("  accounts: upnp user list · upnp user add NAME · upnp user passwd NAME"))
    return 0


def _state(M, s):
    return M.col(s, M.C.green if s == "active" else M.C.red, M.C.bold)


# ---- the firewall (iptables, as otp's OTP-IN) ------------------------------------------
def firewall_do(M, args, cfg):
    """upnp firewall --apply | --off | --status: the chain FAKE-IGD-IN, by root's helper."""
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
    if args.status:
        M.require_root("Reading iptables")
        r = subprocess.run([py, "-I", WEB_HELPER, "--status"], stdout=subprocess.PIPE, universal_newlines=True)
        try:
            d = json.loads(r.stdout)["firewall"]
        except (ValueError, KeyError):
            M.fail("the helper said nothing readable: %s" % r.stdout[:200])
        print(M.col("Firewall - FAKE-IGD-IN (iptables)", M.C.bold))
        print("  %-22s %s" % ("in config.json", M.col("on", M.C.green) if cfg.get("firewall") else M.col("off", M.C.dim)))
        print("  %-22s %s" % ("the chain", M.col("in place", M.C.green) if d.get("chain") else M.col("not there", M.C.yellow)))
        print("  %-22s %s" % ("first in INPUT", M.col("yes", M.C.green) if d.get("first") else M.col("no", M.C.yellow)))
        print("  %-22s %s" % ("/etc/sysconfig/iptables", M.col("kept there", M.C.green) if d.get("file")
                                                           else M.col("not there", M.C.yellow)))
        print("  %-22s %s" % ("iptables.service", M.col("active", M.C.green) if d.get("service")
                                                    else M.col("not active", M.C.yellow)))
        for ln in d.get("rules") or []:
            print("    " + M.col(ln, M.C.dim))
        return 0
    M.require_root("Changing the firewall")
    if args.apply:
        if not cfg.get("firewall"):
            data = M.load_config(args.config)
            data["firewall"] = True
            M.write_config(args.config, data)
            M.info("firewall switched on in %s" % args.config)
        r = subprocess.run([py, "-I", WEB_HELPER, "--apply"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
    else:
        if cfg.get("firewall"):
            data = M.load_config(args.config)
            data["firewall"] = False
            M.write_config(args.config, data)
        r = subprocess.run([py, "-I", WEB_HELPER, "--firewall-off"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
    for ln in (r.stdout or "").splitlines():
        (M.warn if ("refused" in ln or "would not" in ln) else M.ok)(ln)
    return r.returncode
