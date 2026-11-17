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


def as_app_value(fn):
    """fn()'s value (JSON) worked out as the fake-igd account, as as_app does - None when it fails."""
    if os.geteuid() != 0:
        try:
            return fn()
        except BaseException:                            # noqa: BLE001
            return None
    r, w = os.pipe()

    def child():
        try:
            got = json.dumps(fn())
        except BaseException:                            # noqa: BLE001
            got = "null"
        os.write(w, got.encode()[:65536])
        return 0
    with open(os.devnull, "w") as quiet:
        old = os.dup(1)
        os.dup2(quiet.fileno(), 1)
        try:
            as_app(child)
        finally:
            os.dup2(old, 1)
            os.close(old)
    os.close(w)
    with os.fdopen(r, "rb") as f:
        raw = f.read()
    try:
        return json.loads(raw.decode() or "null")
    except ValueError:
        return None


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
    if what == "after":
        # To be done by hand (otp --after / --after-done): what an update cannot do itself.
        return as_app(lambda: after(M, args, cfg))
    if what == "check" and args.downgrade:
        return _downgrade_check(M, args, url, here)
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
        as_app(lambda: _after_short(M, cfg))
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
        if args.downgrade:
            return _downgrade_online(M, args, cfg, url, here, row)
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
    M.fail("upnp upgrade check [--downgrade] | online [VERSION] [--downgrade] | file PATH [--downgrade] | status | "
           "follow | log | after [ID]")


def _downgrade_check(M, args, url, here):
    """The older versions at upgrade_url, each with what stands in its way (otp --downgrade-check)."""
    pal = M.PAL
    try:
        g = ON.downgrade_list(url, here)
    except (ValueError, OSError) as e:
        M.fail("%s: %s" % (url, getattr(e, "reason", None) or e))
    if args.json:
        print(json.dumps(g, indent=2, default=str))
        return 0
    print(pal.head("older versions at %s" % g["url"]) + pal.dim("  this server runs %s; it may go back to %s or newer"
                                                           % (here, g["lowest"])))
    if not g["versions"]:
        M.ok("no version older than %s is there" % here)
        return 0
    for v in g["versions"]:
        if v["why"]:
            print("  %-10s %s  %s" % (v["version"], pal.warn("no "), pal.dim(v["short"])))
        else:
            print("  %-10s %s  %s" % (v["version"], pal.good("yes"), pal.dim("sudo upnp upgrade online %s --downgrade"
                                                                          % v["version"])))
    reasons = []
    for v in g["versions"]:
        for w in v["why"]:
            if w not in reasons:
                reasons.append(w)
    for w in reasons:
        print(pal.dim("  - " + w))
    return 0


def _downgrade_online(M, args, cfg, url, here, row):
    """Going back to an older version from upgrade_url (otp --downgrade VERSION): fetched, checked,
    and put in by root as an upgrade is - asked for as such."""
    pal = M.PAL
    want = args.version
    if not want:
        M.fail("which version? upnp upgrade check --downgrade lists them")
    pk = next((x for x in row.get("packages") or [] if x["version"] == want), None)
    if not pk:
        M.fail("%s is not at %s" % (want, row.get("url")))
    why = ON.downgrade_why_not(want, here)
    if why:
        M.fail("fake-igd %s cannot be gone back to here: %s" % (want, "; ".join(why)))
    print(pal.head("fake-igd %s → %s (going back)" % (here, want)) + pal.dim("  from %s" % pk["url"]))
    print("  the configuration, the database and the logs stay as they are; what came in the newer versions is gone "
          "until you upgrade again")
    if not args.yes and not _ask("go back?"):
        print("  nothing done")
        return 1
    print(pal.dim("  fetching it and checking its signature…"))

    def go():
        try:
            info = ON.fetch(url, want, here, older=True)
        except ValueError as e:
            M.fail(str(e))
        M.ok("fake-igd %s fetched, signed by %s, %d files - checked" % (info["version"], info.get("signed_by"),
                                                                        info.get("files") or 0))
        _event(M, cfg, "upgrade", "%s fetched fake-igd %s from %s to go back to" % (
            who_runs(), info["version"], info.get("from")), "warn")
        return _ask_root_and_follow(M, cfg, info, args, downgrade=True)
    return as_app(go)


def _upgrade_module(M, cfg, who):
    """Settings → Upgrades' own module (api_upgrade.py), with a context of the command line."""
    import igd_panes as PN
    PN.load()
    mod = PN.module("upgrade")
    if mod is None:
        M.fail("api_upgrade.py is not beside upnp.py")
    s = store_of(M, cfg)
    return mod, PN.Ctx(None, "CLI", "", {}, {"name": who, "role": "fulladmin"}, s, cfg, mod, s.add_event)


def after(M, args, cfg):
    """upnp upgrade after [ID]: what is to be done by hand, looked at now, with the commands - or ID
    marked as done (otp --after, --after-done)."""
    pal = M.PAL
    mod, ctx = _upgrade_module(M, cfg, who_runs())
    if args.version:
        try:
            print(pal.good("  " + mod.after_done(ctx, args.version, who_runs(), "cli")))
        except ValueError as e:
            M.fail(str(e))
        return 0
    try:
        mod.after_evaluate(ctx)
    except Exception as e:                                   # noqa: BLE001
        M.warn("this server could not look now: %s" % e)
    v = mod.after_view(ctx)
    if args.json:
        print(json.dumps(v, indent=2, default=str))
        return 0
    items = v["items"]
    if not items:
        M.ok("nothing is to be done by hand")
    else:
        print(pal.head("to be done by hand: %d" % len(items)))
    for it in items:
        mark = pal.bad if it["level"] == "bad" else pal.warn
        print("  " + mark(it["title"]))
        print(pal.dim("    " + it["why"]))
        for st in it.get("steps") or []:
            if st.get("cmd"):
                print("    " + st.get("lead", ""))
                print("      " + pal.bold(st["cmd"]) if hasattr(pal, "bold") else "      " + st["cmd"])
            elif st.get("words"):
                print("    " + st["words"])
        print(pal.dim("    %s  (upnp upgrade after %s marks it done)" % (it.get("foot") or "", it["id"])))
    return 0


def _after_short(M, cfg):
    """The count of what is to be done by hand, under upnp upgrade status."""
    try:
        mod, ctx = _upgrade_module(M, cfg, who_runs())
        items, _row = mod.after_needed(ctx)
    except BaseException:                                    # noqa: BLE001 - only said when it can be
        return 0
    if items:
        M.warn("%d to be done by hand - upnp upgrade after" % len(items))
        for it in items[:6]:
            print("    " + (M.PAL.bad if it["level"] == "bad" else M.PAL.warn)(it["title"]))
    return 0


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
        M.fail("%s is older than %s, which is installed - going back: sudo upnp upgrade file %s --downgrade, "
               "or from upgrade_url: sudo upnp upgrade online %s --downgrade"
               % (info["version"], info.get("installed"), args.path, info["version"]))
    M.ok("fake-igd %s, signed by %s, %d files - checked" % (info["version"], info.get("signed_by"),
                                                            info.get("files") or 0))
    if not info.get("newer"):
        M.info("the same version as installed (%s) - it is put in again" % here)
    if not args.yes and not _ask("put it in?"):
        print("  nothing done")
        return 1
    return _ask_root_and_follow(M, cfg, info, args)


def _ask_root_and_follow(M, cfg, info, args, downgrade=False):
    try:
        ident = ON.ask_root(info, who_runs(), downgrade=downgrade)
    except ValueError as e:
        M.fail(str(e))
    _event(M, cfg, "upgrade", "%s started %s fake-igd %s" % (
        who_runs(), "going back to" if downgrade else "the upgrade to", info["version"]), "warn")
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
    # Announced as one asked from the pages is (1.7.2): root's helper writes plan.json, status.json
    # and last.log for the API, and the pages' own file - the pages show it going on, and follow it
    # while the API restarts. Who asked, as `upnp upgrade online` says it.
    p = subprocess.Popen([py, "-I", helper, "--run", os.path.abspath(args.path), "--downgrade", "--by", who_runs()],
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
def _password_from(M, given, name, least=None):
    """`-`: asked twice on the terminal; @env: UPNP_PASSWORD; nothing: one is made and printed."""
    import igd_store as ST
    if given == "-":
        import getpass
        a = getpass.getpass("password for %s: " % name)
        b = getpass.getpass("again: ")
        if a != b:
            M.fail("those two are not the same")
        bad = ST.password_problem(a, least)
        if bad:
            M.fail(bad)
        return a, False
    if given == "@env":
        v = os.environ.get("UPNP_PASSWORD", "")
        bad = ST.password_problem(v, least)
        if bad:
            M.fail("UPNP_PASSWORD: %s" % bad)
        return v, False
    if given:
        M.warn("the password is on the command line (ps, the shell's history) - next time: --password -")
        return given, False
    import secrets
    n = max(16, int(least or ST.MIN_PASSWORD))
    return secrets.token_urlsafe(n)[:n], True


def _span(sec):
    sec = max(0, int(sec))
    return "%d min %02d s" % (sec // 60, sec % 60) if sec >= 60 else "%d s" % sec


def cmd_user(M, args, cfg):
    """upnp user - the accounts of the web pages, as Settings → Accounts has them (otp's --users,
    --add-user, --passwd, --set-role, --del-user, --disable-user, --enable-user, --reset-2fa,
    --lockouts, --lockouts-clear)."""
    import igd_store as ST
    what = args.what or "list"
    what = {"disable": "off", "enable": "on", "lockouts-clear": "clear", "unlock": "clear"}.get(what, what)
    p = M.PAL
    if what == "passkeys" and not getattr(args, "remove_all", False):
        # The passkeys of one account (1.9.7): read only, as list is.
        if not args.name:
            M.fail("which account? upnp user passkeys NAME [--remove-all]")

        def look():
            s = store_of(M, cfg)
            if not s.user(args.name):
                M.fail("there is no account %s" % args.name)
            keys = s.passkeys(args.name)
            if args.json:
                print(json.dumps([{k: v for k, v in x.items() if k != "pub"} for x in keys], indent=2, default=str))
                return 0
            M.table(["PASSKEY", "FOR", "ADDED", "LAST USED", "ID"],
                    [[M.col(k.get("name") or "a device", M.C.bold), "https://%s/" % (k.get("host") or "?"),
                      _when(k.get("at")), _when(k.get("used")) if k.get("used") else "-",
                      M.col(str(k.get("id") or "")[:16] + "…", M.C.dim)] for k in keys],
                    "%s has no passkey%s" % (args.name, "" if s.policy()["passkey_signin"] else
                                             " (and signing in with one is switched off)"))
            return 0
        if os.geteuid() != 0 and not os.access(os.path.join(cfg["state_dir"], "fake-igd.db"), os.R_OK):
            M.require_root("The accounts of the web pages")
        return as_app(look)
    if what in ("list", "sessions", "lockouts"):
        def go():
            s = store_of(M, cfg)
            if what == "sessions":
                rows = s.sessions()
                if args.json:
                    print(json.dumps(rows, indent=2, default=str))
                    return 0
                M.table(["ID", "ACCOUNT", "FROM", "SIGNED IN", "LAST SEEN", "BROWSER"],
                        [[M.col(r["id"], M.C.dim), M.col(r["name"], M.C.bold), M.col(r["addr"], M.C.magenta),
                          _when(r["created"]) + (" (second step)" if r.get("mfa") else ""), _when(r["seen"]),
                          (r["agent"] or "")[:50]] for r in rows],
                        "nobody is signed in to the pages")
                return 0
            if what == "lockouts":
                rows = s.lockouts()
                if args.json:
                    print(json.dumps(rows, indent=2, default=str))
                    return 0
                now = time.time()
                M.table(["STATE", "WHO", "BY", "HOW MANY", "TRIED", "LAST"],
                        [[M.col("locked out, %s left" % _span(r["until"] - now), M.C.red) if r["locked"]
                          else M.col("counting, forgotten in %s" % _span(r["forgets"] - now), M.C.yellow),
                          M.col(r["who"] or "(no name)", M.C.bold),
                          r["by"] + (" - changing a password" if str(r.get("kind", "")).startswith("password") else ""),
                          "%d / %d" % (r["fails"], r["limit"]),
                          ", ".join(r["others"][-4:]) or "-", _when(r["last"])] for r in rows],
                        "nobody is locked out, and no wrong attempt is being counted")
                return 0
            rows = s.users()
            if args.json:
                print(json.dumps(rows, indent=2, default=str))
                return 0
            on = s.policy()["admin_2fa"]
            M.table(["NAME", "ROLE", "STATE", "SECOND STEP", "PASSKEYS", "SIGNED IN NOW", "LAST SIGN-IN", "FROM", "NOTE"],
                    [[M.col(r["name"], M.C.bold),
                      M.col(r["role_words"], M.C.magenta if r["role"] == "fulladmin" else M.C.dim),
                      (M.col("off", M.C.red) if r["disabled"] else M.col("on", M.C.green))
                      + (" (to change its password)" if r["must_change"] else ""),
                      M.col({"app": "an app"}.get(r["mfa"]["kind"], r["mfa"]["kind"]), M.C.green) if r["mfa"]
                      else ("set up at the next sign-in" if on else "-"),
                      M.col("%d passkey%s" % (r["passkeys"], "" if r["passkeys"] == 1 else "s"), M.C.green)
                      if r["passkeys"] else "-",
                      M.col(r["sessions"], M.C.green) if r["sessions"] else M.col("-", M.C.dim),
                      _when(r["last_login"]), r["last_from"] or "-", r["note"] or ""] for r in rows],
                    "no account yet - make one: sudo upnp user add NAME")
            return 0
        if os.geteuid() != 0 and not os.access(os.path.join(cfg["state_dir"], "fake-igd.db"), os.W_OK):
            M.require_root("The accounts of the web pages")
        return as_app(go)
    M.require_root("Changing the accounts of the web pages")
    name = args.name
    if what in ("add", "passwd", "role", "del", "note", "off", "on", "reset-2fa", "must-change", "passkeys") and not name:
        M.fail("which account? upnp user %s NAME" % what)
    pw, made = ("", False)
    if what in ("add", "passwd"):
        # Read as the fake-igd account (as_app_value), never by root itself: root opening the database
        # makes its -wal/-shm root's when they are not there, and the API may not write it after.
        least = as_app_value(lambda: store_of(M, cfg).policy()["password_min"])
        pw, made = _password_from(M, args.password, name, least)
    if what == "del" and not args.yes and not _ask("take the account %s away?" % name):
        print("  nothing done")
        return 1
    if what == "passkeys" and not args.yes and not _ask(
            "every passkey of %s is taken away (the password still signs in). Go on?" % name):
        print("  nothing done")
        return 1
    if what == "reset-2fa" and not args.yes and not _ask(
            "%s sets the second step up again at the next sign-in - with the password alone. Go on?" % name):
        print("  nothing done")
        return 1

    def go():
        s = store_of(M, cfg)
        by = who_runs()
        try:
            if what == "add":
                s.add_user(name, pw, args.role or "fulladmin", args.note or "", must_change=made)
                s.add_event("account", "%s made the account %s (%s)" % (by, name, args.role or "fulladmin"),
                            "info", by)
                M.ok("%s may sign in to the pages, as %s" % (name, ST.ROLE_WORDS[args.role or "fulladmin"]))
            elif what == "passwd":
                s.set_password(name, pw, must_change=made)
                s.end_sessions_of(name)
                s.add_event("account", "%s set a new password for %s; their sign-ins are ended" % (by, name), "warn",
                            by)
                M.ok("%s has a new password (its sign-ins are ended)" % name)
            elif what == "role":
                if args.role not in ST.ROLES:
                    M.fail("--role fulladmin or readonly")
                s.set_role(name, args.role)
                s.add_event("account", "%s made %s %s" % (by, name, ST.ROLE_WORDS[args.role]), "info", by)
                M.ok("%s is %s" % (name, ST.ROLE_WORDS[args.role]))
            elif what == "note":
                s.set_note(name, args.note or "")
                M.ok("kept")
            elif what == "must-change":
                s.set_must_change(name, True)
                s.add_event("account", "%s asked %s to change the password at the next sign-in" % (by, name),
                            "info", by)
                M.ok("%s chooses a new password at the next sign-in" % name)
            elif what in ("off", "on"):
                s.set_disabled(name, what == "off")
                s.add_event("account", "%s switched %s %s" % (by, name, what), "warn" if what == "off" else "info",
                            by)
                M.ok("%s is switched %s%s" % (name, what, " - its sign-ins are ended" if what == "off" else ""))
            elif what == "reset-2fa":
                had = s.mfa_reset(name)
                s.add_event("account", "%s reset the second step of %s; their sign-ins are ended" % (by, name),
                            "warn", by)
                M.ok("the second step of %s is reset: set up again at the next sign-in" % name if had
                     else "%s had no second step set up" % name)
            elif what == "passkeys":
                n = s.passkeys_remove(name)
                if n:
                    s.add_event("account", "%s took every passkey of %s away (%d)" % (by, name, n), "warn", by)
                M.ok("the passkeys of %s are taken away (%d)" % (name, n) if n else "%s has no passkey" % name)
            elif what == "del":
                s.delete_user(name)
                try:                          # its own layout of the tables goes with it (as on the pages)
                    s.run("DELETE FROM meta WHERE k = ?", ("user:%s:own" % name.lower(),))
                except Exception:             # noqa: BLE001
                    pass
                s.add_event("account", "%s removed the account %s" % (by, name), "warn", by)
                M.ok("%s is gone" % name)
            elif what == "end":
                s.end_session(name)
                M.ok("that sign-in is over")
            elif what == "clear":
                if name:
                    n = s.clear_fails("name", name) + s.clear_fails("address", name)
                    if not n:
                        M.fail("nothing is counted for %s" % name)
                else:
                    n = s.clear_all_fails()
                s.add_event("sign-in", "%s cleared %s" % (by, ("the count of wrong attempts of %s" % name) if name
                                                          else "every count of wrong attempts (%d)" % n), "warn", by)
                M.ok("cleared - %s may try again at once" % (name or "every one"))
            else:
                M.fail("upnp user list | add NAME | passwd NAME | role NAME --role R | note NAME | must-change NAME | "
                       "off NAME | on NAME | reset-2fa NAME | del NAME | sessions | end ID | lockouts | "
                       "clear [NAME|ADDRESS]")
        except ST.StoreError as e:
            M.fail(str(e))
        if made:
            print()
            print("    %s %s" % (p.good("name:    "), name))
            print("    %s %s" % (p.good("password:"), pw))
            print()
            M.warn("Write that down now - it is not shown again. It is changed at the first sign-in.")
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


# ---- what the pages do, here too (otp's --api and its commands, 1.7.4) ----------------------
# A server whose pages are down, or reached only over SSH: the panes' questions asked of
# fake-igd-api as root on the command line - with the key only root and the API's account may
# read (/run/fake-igd-api/cli-token), so it is a full administrator, written down in the events
# as "root (command line)".
RUN_DIR = os.environ.get("FAKE_IGD_RUN", "/run/fake-igd-api")
SECRETISH = r"pass|secret|token|(^|_)key$|(^|_)pw$|pin$"


def _run_file(M, name):
    path = os.path.join(RUN_DIR, name)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except PermissionError:
        M.fail("this asks fake-igd-api as a full administrator, with a key only root may read: "
               "sudo upnp %s" % " ".join(sys.argv[1:]))
    except OSError:
        M.fail("fake-igd-api is not running (%s is not there): systemctl start fake-igd-api" % path)


def api(M, method, path, body=None, timeout=330.0, quiet=False):
    """One question of the pages asked of fake-igd-api: its answer (a dict), or M.fail with what it said
    (quiet: the answer with ok False instead)."""
    import http.client
    token, cli = _run_file(M, "api-token"), _run_file(M, "cli-token")
    try:
        port = int(_run_file(M, "api-port"))
    except ValueError:
        port = 9862
    who = os.environ.get("SUDO_USER") or ("root" if os.geteuid() == 0 else os.environ.get("USER") or "root")
    headers = {"X-IGD-Token": token, "X-IGD-Cli": cli, "X-IGD-Cli-Who": who, "X-IGD-Client": "127.0.0.1",
               "Accept": "application/json", "User-Agent": "upnp/%s" % M.VERSION}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        status = r.status
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        M.fail("fake-igd-api does not answer on 127.0.0.1:%d (%s): systemctl status fake-igd-api" % (port, e))
    try:
        got = json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        got = {"ok": False, "error": raw.decode("utf-8", "replace")[:300]}
    if not isinstance(got, dict):
        got = {"ok": True, "answer": got}
    if status != 200:
        got["ok"] = False
        got.setdefault("error", "HTTP %d" % status)
        if status in (401, 403) and got.get("code") in ("signed_out", ""):
            got["error"] = ("fake-igd-api did not take the command line's key (%s) - it was restarted just now, or "
                            "%s is not the one it wrote: try again" % (got["error"], os.path.join(RUN_DIR, "cli-token")))
        if not quiet:
            M.fail(str(got.get("error")))
    return got


def follow_root(M, cfg, kind, ident, timeout=120, words="root"):
    """Root's answer to one ask of a kind (web/result-KIND.json), waited for: the answer, or {}."""
    import igd_panes as PN
    end = time.time() + timeout
    spin = "|/-\\"
    n = 0
    tty = sys.stdout.isatty()
    while time.time() < end:
        got = PN.root_result(cfg.get("state_dir"), kind, ident)
        if got:
            if tty:
                sys.stdout.write("\r\033[K")
            return got
        if tty:
            sys.stdout.write("\r%s %s ..." % (spin[n % 4], words))
            sys.stdout.flush()
        n += 1
        time.sleep(0.5)
    if tty:
        sys.stdout.write("\r\033[K")
    M.warn("%s has not answered in %d s - is fake-igd-web.path active? (systemctl status fake-igd-web.path)"
           % (words, timeout))
    return {}


def _said_root(M, got):
    for ln in got.get("said") or []:
        (M.ok if got.get("ok", True) else M.warn)(str(ln))
    return 0 if got.get("ok", True) else 1


def _out(args, got):
    if getattr(args, "json", False):
        print(json.dumps(got, indent=1, ensure_ascii=False, default=str))
        return True
    return False


def cmd_api(M, args, cfg):
    """upnp api METHOD PATH [BODY|-] - any question of the pages (otp --api)."""
    import re
    method = (args.method or "").upper()
    if method not in ("GET", "POST") or not (args.path or "").startswith("/api/"):
        M.fail("upnp api GET|POST /api/... [BODY]   e.g. upnp api GET /api/db")
    body = None
    if args.body is not None:
        raw = sys.stdin.read() if args.body == "-" else args.body
        try:
            body = json.loads(raw or "{}")
        except ValueError:
            M.fail('the body is JSON: \'{"action": "..."}\'')
        if not isinstance(body, dict):
            M.fail("the body is a JSON object")

        def keys(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    yield str(k)
                    yield from keys(v)
            elif isinstance(o, list):
                for v in o:
                    yield from keys(v)
        secretish = sorted({k for k in keys(body) if re.search(SECRETISH, k, re.I)})
        if args.body != "-" and secretish:
            M.fail("%s - a secret is not taken written out on the command line, where ps and the shell's "
                   "history show it: give the body on stdin (upnp api POST PATH - < file)" % ", ".join(secretish))
    if method == "GET" and body:
        M.fail("a GET takes no body - its arguments go in the path: /api/events?q=word")
    got = api(M, method, args.path, body if method == "POST" else None)
    print(json.dumps(got, indent=1, ensure_ascii=False, default=str))
    return 0


def cmd_events(M, args, cfg):
    """upnp events - fake-igd's own events (otp --events): sign-ins, settings, root's work."""
    from urllib.parse import urlencode
    q = {"per": max(10, min(1000, args.limit or 40))}
    if args.search:
        q["q"] = args.search
    if args.kind:
        q["kind"] = args.kind
    if args.hours:
        q["since"] = int(time.time() - args.hours * 3600)
    got = api(M, "GET", "/api/events?" + urlencode(q))
    if _out(args, got):
        return 0
    rows = got.get("events") or []
    if args.limit and args.limit < 10:
        rows = rows[:args.limit]
    tone = {"warn": M.C.yellow, "error": M.C.red, "bad": M.C.red}
    out = []
    for e in reversed(rows):
        lvl = str(e.get("level") or "info")
        out.append([M.col(_when(e.get("at")), M.C.dim), e.get("kind") or "",
                    M.col(lvl, tone.get(lvl, "")) if lvl in tone else lvl,
                    e.get("who") or "", e.get("addr") or "", M.col(e.get("words") or e.get("text") or "",
                                                                   tone.get(lvl, ""))])
    M.table(["when", "kind", "level", "who", "from", "what"], out, empty="(no events)")
    if got.get("q_error"):
        M.warn("the search: %s" % got["q_error"])
    print(M.col("  %d of %d shown · kinds: %s" % (len(rows), got.get("total", len(rows)),
                                                 ", ".join(got.get("kinds") or [])), M.C.dim))
    return 0


def cmd_check(M, args, cfg):
    """upnp check - every part looked at, as the pages' alerts do it (otp --check). Exit 1 on a problem."""
    health = api(M, "GET", "/api/health?check=service", quiet=True)
    al = api(M, "GET", "/api/alerts", quiet=True)
    if _out(args, {"health": health, "alerts": al}):
        return 0 if not al.get("problems") else 1
    print(M.col("fake-igd %s on %s - every part" % (M.VERSION, health.get("node") or "?"), M.C.bold))
    rows = [["the API", M.col("answers", M.C.green) if health.get("ok") else M.col(health.get("error") or "no",
                                                                                M.C.red)],
            ["the database", M.col("opens", M.C.green) if (health.get("database") or {}).get("ok")
             else M.col("does not open", M.C.red)],
            ["accounts", str(health.get("users", "?"))],
            ["fake-igd.service", _state(M, str(health.get("service") or "?"))]]
    for k, v in rows:
        print("  %-20s %s" % (k, v))
    probs = al.get("problems") or []
    if not al.get("ok", True) and not probs:
        M.warn("the alerts could not be read: %s" % al.get("error"))
    print()
    if not probs:
        M.ok("nothing is wrong")
        return 0
    for p in probs:
        line = "%s - %s" % (p.get("title"), p.get("said") or "")
        if p.get("level") == "bad":
            print(M.col("✘ ", M.C.red, M.C.bold) + M.col(line, M.C.red))
        else:
            print(M.col("! ", M.C.yellow, M.C.bold) + M.col(line, M.C.yellow))
    print(M.col("  %d problem(s) - the same as the pages' alerts (Settings → Alerts)" % len(probs), M.C.dim))
    return 1


def cmd_backup(M, args, cfg):
    """upnp backup [status|now|verify] - the backups of Settings → Backups (otp --rbackup-*)."""
    what = args.what or "status"
    if what in ("now", "verify"):
        r = api(M, "POST", "/api/backup", {"action": "run" if what == "now" else "verify"})
        M.info(r.get("message") or "started")
        return _follow_job(M, "/api/backup/job")
    got = api(M, "GET", "/api/backup")
    if _out(args, got):
        return 0
    print(M.col("Backups of %s" % (got.get("node") or "?"), M.C.bold))
    ts = got.get("targets") or []
    M.table(["destination", "kind", "on", "where", "last"],
            [[t.get("name") or t.get("id"), t.get("kind") or "", M.col("on", M.C.green) if t.get("on")
              else M.col("off", M.C.dim), t.get("where") or t.get("host") or t.get("path") or "",
              _when(t.get("last_at") or (t.get("last") or {}).get("at") if isinstance(t.get("last"), dict)
                    else t.get("last_at"))] for t in ts], empty="(no destination - Settings → Backups)")
    runs = got.get("runs") or []
    if runs:
        print()
        M.table(["made", "by", "result"], [[_when(r.get("at") or r.get("began")), r.get("by") or "",
                                            M.col(r.get("said") or ("ok" if r.get("ok") else "failed"),
                                                  M.C.green if r.get("ok") else M.C.red)] for r in runs[-10:]])
    if got.get("next"):
        print(M.col("  next: %s" % _when(got["next"]), M.C.dim))
    j = got.get("job") or {}
    if j.get("running"):
        M.info("%s is going on: %s" % (j.get("what"), j.get("says")))
    return 0


def _follow_job(M, path):
    last = None
    while True:
        j = (api(M, "GET", path) or {}).get("job") or {}
        whole = max(1, int(j.get("whole") or 1))
        pc = int(100 * min(whole, int(j.get("done") or 0)) / whole)
        words = j.get("says") or j.get("what") or ""
        if sys.stdout.isatty():
            sys.stdout.write("\r\033[K%s %s" % (bar(M, pc), words[:60]))
            sys.stdout.flush()
        elif words != last:
            print("%3d %% %s" % (pc, words))
        last = words
        if not j.get("running"):
            break
        time.sleep(1)
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    if j.get("error"):
        M.fail(j["error"])
    r = j.get("result")
    M.ok(r.get("message") if isinstance(r, dict) and r.get("message") else "%s: done" % (j.get("what") or "it"))
    return 0


def cmd_db(M, args, cfg):
    """upnp db [status|check|copy|tidy|vacuum] - the database (Settings → Database)."""
    what = args.what or "status"
    if what != "status":
        r = api(M, "POST", "/api/db", {"action": what})
        if _out(args, r):
            return 0
        (M.ok if r.get("good", True) else M.warn)(r.get("message") or "done")
        return 0 if r.get("good", True) else 1
    d = api(M, "GET", "/api/db")
    if _out(args, d):
        return 0
    print(M.col("The database", M.C.bold))
    for k, v in (("file", d.get("where")), ("engine", d.get("version")),
                 ("size", "%.1f MB" % ((d.get("size") or 0) / 1048576.0)),
                 ("the key of its secrets", "%s%s" % (d.get("key"), "" if d.get("key_there")
                                                      else M.col("  - NOT THERE", M.C.red, M.C.bold))),
                 ("events kept", "%s day(s)" % d.get("events_keep_days") if d.get("events_keep_days") else "for ever"),
                 ("a copy every day", "at %s, %s kept in %s" % (d.get("at"), d.get("keep"), d.get("backup_dir"))
                  if d.get("daily") else "off"),
                 ("last copy", _when(d.get("last_copy")))):
        print("  %-24s %s" % (k, v))
    print()
    M.table(["table", "rows", "bytes"], [[t.get("table"), t.get("rows"), t.get("bytes")]
                                         for t in d.get("tables") or []])
    if d.get("copies"):
        print()
        M.table(["copy", "bytes", "made"], [[c.get("name"), c.get("bytes"), _when(c.get("at"))]
                                            for c in d["copies"][-10:]])
    return 0


def cmd_updates(M, args, cfg):
    """upnp updates [status|check|start|stop|reboot] - the operating system's updates (otp --updates)."""
    what = args.what or "status"
    if what in ("check", "start", "stop", "reboot"):
        body = {"action": what}
        if what == "start":
            body.update({"security": bool(args.security), "reboot": args.reboot or "ask"})
        if what in ("start", "reboot") and not args.yes:
            if not _ask("%s?" % ("Update the operating system now" if what == "start"
                                  else "Restart this machine now")):
                return 1
        r = api(M, "POST", "/api/osup", body)
        M.info(r.get("message") or "asked")
        if what in ("check", "start") and not args.no_follow:
            return _follow_osup(M)
        return 0
    d = api(M, "GET", "/api/osup")
    if _out(args, d):
        return 0
    c = d.get("check") or {}
    j = d.get("job") or {}
    print(M.col("The operating system's updates (dnf)", M.C.bold))
    print("  %-22s %s" % ("last looked", "%s - %s" % (_when(c.get("at")), c.get("state") or "never")))
    if c.get("error"):
        M.warn(c["error"])
    print("  %-22s %s" % ("waiting", M.col("%s update(s), %s for security" % (c.get("count", 0), c.get("security", 0)),
                                          M.C.yellow if c.get("count") else M.C.green)))
    if c.get("reboot_now") or d.get("reboot"):
        M.warn("a restart is needed: %s" % ", ".join(c.get("reboot_why") or []))
    if j:
        print("  %-22s %s" % ("the last run", "%s, %s %s%%" % (j.get("kind"), j.get("state"), j.get("pct"))))
    for p in (c.get("packages") or [])[:40]:
        print("    " + M.col(p if isinstance(p, str) else (p.get("name") or json.dumps(p)), M.C.dim))
    return 0


def _follow_osup(M):
    last = -1
    while True:
        d = api(M, "GET", "/api/osup")
        j = d.get("job") or {}
        pc = int(j.get("pct") or 0)
        lines = d.get("lines") or []
        for ln in lines[max(0, last):] if last >= 0 else lines[-5:]:
            print(M.col("  " + str(ln if isinstance(ln, str) else ln.get("text", ln)), M.C.dim))
        last = len(lines)
        if j.get("state") != "running":
            break
        if sys.stdout.isatty():
            print(bar(M, pc), j.get("phase") or "")
        time.sleep(2)
    (M.ok if j.get("state") == "done" else M.warn)("%s: %s" % (j.get("kind") or "dnf", j.get("state") or "?"))
    return 0 if j.get("state") == "done" else 1


def cmd_time(M, args, cfg):
    """upnp time [status|sync] - the clock and its time servers (otp --ntp, --ntp-sync)."""
    if args.what == "sync":
        r = api(M, "POST", "/api/time", {"action": "sync"})
        M.info(r.get("message") or "asked")
        got = follow_root(M, cfg, "time", r.get("id"), 60, "root steps the clock")
        return _said_root(M, got) if got else 1
    d = api(M, "GET", "/api/time")
    if _out(args, d):
        return 0
    n = d.get("now") or {}
    print(M.col("The time", M.C.bold))
    print("  %-22s %s" % ("this machine", time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(n.get("time") or
                                                                                          time.time()))))
    print("  %-22s %s" % ("chrony", M.col("running", M.C.green) if n.get("chrony") else M.col("not running",
                                                                                          M.C.yellow)))
    tr = n.get("tracking") or {}
    for k in ("ref", "reference", "stratum", "offset", "system_time", "leap"):
        if tr.get(k) not in (None, ""):
            print("  %-22s %s" % (k.replace("_", " "), tr[k]))
    srcs = n.get("sources") or []
    if srcs:
        M.table(["server", "state", "stratum", "offset"],
                [[s.get("name") or s.get("address"), s.get("state") or "", s.get("stratum") or "",
                  s.get("offset") or ""] for s in srcs])
    return 0


def _steps(M, steps):
    """The steps of a test as the pages list them: done or not, what, what was said, how long."""
    for st in steps or []:
        if isinstance(st, dict):
            good = st.get("ok")
            mark = M.col("✔", M.C.green) if good else (M.col("✘", M.C.red) if good is False else M.col("•", M.C.cyan))
            ms = st.get("ms")
            print("  %s %s%s%s" % (mark, st.get("what") or st.get("step") or "", M.col(" - %s" % st["said"], M.C.dim)
                                   if st.get("said") else "", M.col("  %s ms" % ms, M.C.dim) if ms else ""))
        elif isinstance(st, (list, tuple)):
            good = st[1] if len(st) > 1 and isinstance(st[1], bool) else None
            words = [str(x) for x in st if not isinstance(x, bool)]
            mark = M.col("✔", M.C.green) if good else (M.col("✘", M.C.red) if good is False else M.col("•", M.C.cyan))
            print("  %s %s" % (mark, " - ".join(w for w in words if w)))
        else:
            print(M.col("  " + str(st), M.C.dim))


def cmd_pane_test(M, args, cfg):
    """upnp mail-test ADDRESS · siem-test · proxy-test [URL] · snmp-trap - a test, as the pane's button."""
    what = args.cmd
    if what == "mail-test":
        if not args.target:
            M.fail("upnp mail-test ADDRESS")
        r = api(M, "POST", "/api/mail", {"action": "test", "to": args.target, "kind": args.kind or "short",
                                         "via": "straight" if args.straight else "queue"})
        if _out(args, r):
            return 0 if r.get("sent") else 1
        _steps(M, r.get("steps"))
        (M.ok if r.get("sent") else M.warn)("%s (%s ms)" % (r.get("said") or ("sent" if r.get("sent") else "not sent"),
                                                          r.get("took_ms", "?")))
        return 0 if r.get("sent") else 1
    if what == "siem-test":
        r = api(M, "POST", "/api/siem", {"action": "test"})
        if _out(args, r):
            return 0
        bad = 0
        for t, said in ((r.get("test") or {}).get("said") or {}).items():
            if said == "sent":
                M.ok("%s: sent" % t)
            else:
                bad += 1
                M.warn("%s: %s" % (t, said))
        return 1 if bad else 0
    if what == "proxy-test":
        r = api(M, "POST", "/api/proxy", {"action": "try", "url": args.target or ""})
        if _out(args, r):
            return 0
        g = r.get("result") or {}
        _steps(M, g.get("steps"))
        (M.ok if g.get("ok") else M.warn)("%s %s: %s" % (g.get("url"), "through the proxy" if g.get("mode") == "proxy"
                                                          else "straight", g.get("said") or
                                                          ("reached" if g.get("ok") else "not reached")))
        return 0 if g.get("ok") else 1
    if what == "snmp-trap":
        r = api(M, "POST", "/api/snmp", {"action": "trap"})
        if _out(args, r):
            return 0
        M.ok(r.get("message") or "sent")
        return 0
    return 2


def cmd_tls(M, args, cfg):
    """upnp tls - the pages' certificate and TLS settings (otp --web-status)."""
    d = api(M, "GET", "/api/tls")
    a = api(M, "GET", "/api/acme", quiet=True)
    if _out(args, {"tls": d, "acme": a}):
        return 0
    c = d.get("cert") or {}
    pol = d.get("policy") or {}
    print(M.col("The certificate of the pages", M.C.bold))
    rows = [["how", d.get("how") or "?"],
            ["subject", c.get("subject") or c.get("cn") or "-"],
            ["issued by", c.get("issuer") or "-"],
            ["names", ", ".join(c.get("names") or d.get("names") or []) or "-"],
            ["valid until", _when(c.get("not_after")) if isinstance(c.get("not_after"), (int, float))
             else (c.get("not_after") or "-")],
            ["key", c.get("key") or "-"],
            ["protocols", " ".join(pol.get("protocols") or []) + "  (%s)" % (pol.get("preset") or "?")],
            ["DH parameters", pol.get("dh") or "-"],
            ["HSTS", "%s s" % pol.get("hsts") if pol.get("hsts") else "off"],
            ["nginx", (d.get("nginx") or {}).get("file", "") + ("" if (d.get("nginx") or {}).get("there")
                                                                 else M.col("  - not there", M.C.yellow))],
            ["ACME", (M.col("on", M.C.green) if a.get("on") else M.col("off", M.C.dim)) +
             ("  %s" % a.get("directory") if a.get("on") else "")]]
    for k, v in rows:
        print("  %-16s %s" % (k, v))
    if d.get("pending"):
        M.warn("a certificate request waits for its certificate")
    return 0


def cmd_acme(M, args, cfg):
    """upnp acme [status|order] - the certificate by ACME (otp --acme, --acme-order)."""
    if args.what == "order":
        r = api(M, "POST", "/api/acme", {"action": "order"})
        M.info(r.get("message") or "ordered")
        seen = 0
        while True:
            d = api(M, "GET", "/api/acme")
            w = d.get("work") or {}
            log = d.get("log") or []
            for ln in log[seen:] if seen else []:
                print(M.col("  " + (ln if isinstance(ln, str) else (ln.get("said") or json.dumps(ln))), M.C.dim))
            seen = len(log) or seen
            if not w.get("busy"):
                break
            if w.get("says"):
                sys.stdout.write("\r\033[K… %s" % w["says"][:70] if sys.stdout.isatty() else "")
            time.sleep(2)
        st = (d.get("card") or {}).get("state") or {}
        (M.ok if st.get("ok") else M.warn)(st.get("said") or "the order has ended")
        return 0 if st.get("ok") else 1
    d = api(M, "GET", "/api/acme")
    if _out(args, d):
        return 0
    card = d.get("card") or {}
    print(M.col("The certificate by ACME", M.C.bold))
    for k, v in (("on", M.col("yes", M.C.green) if d.get("on") else M.col("no", M.C.dim)),
                 ("the CA", d.get("directory")), ("names", ", ".join(d.get("names") or []) or d.get("names_words")),
                 ("challenge", d.get("challenge")), ("the certificate now", card.get("how")),
                 ("valid until", _when(card.get("not_after")) if isinstance(card.get("not_after"), (int, float))
                  else (card.get("not_after") or "-")),
                 ("renewed", card.get("due") or "-"),
                 ("last order", (card.get("state") or {}).get("said") or "-")):
        print("  %-20s %s" % (k, v))
    return 0


def cmd_net(M, args, cfg):
    """upnp net - the network of this machine as the pages read it (otp --net)."""
    d = api(M, "GET", "/api/net")
    if _out(args, d):
        return 0
    n = d.get("now") or {}
    print(M.col("The network of %s" % (n.get("hostname") or "?"), M.C.bold))
    print("  %-16s %s" % ("NetworkManager", M.col("yes", M.C.green) if n.get("nm") else M.col("no", M.C.yellow)))
    print("  %-16s %s" % ("gateway", "%s %s" % (n.get("gw4") or "-", n.get("gw4_dev") or "")))
    if n.get("gw6"):
        print("  %-16s %s" % ("gateway (IPv6)", "%s %s" % (n.get("gw6"), n.get("gw6_dev") or "")))
    print("  %-16s %s" % ("DNS", ", ".join(n.get("dns") or []) or "-"))
    devs = n.get("devices") or []
    if devs:
        print()
        M.table(["device", "state", "connection", "addresses"],
                [[x.get("dev") or x.get("device") or x.get("name"), x.get("state") or "", x.get("con") or "",
                  ", ".join(x.get("ip4") or x.get("addresses") or [])] for x in devs])
    if d.get("trial"):
        M.warn("a change of the network is on trial - Settings → Network")
    return 0


def cmd_carry(M, args, cfg):
    """upnp export-config FILE [--with-secrets] · import-config FILE [--replace] [--yes] (otp --export-config,
    --import-config): everything that makes this installation what it is, as one file (Settings → Export and
    import)."""
    if args.cmd == "export-config":
        if args.with_secrets:
            M.info("root is asked for the pages' certificate and key too - a moment")
        r = api(M, "POST", "/api/carry", {"action": "export", "secrets": bool(args.with_secrets)})
        data = r.get("bundle") if args.with_secrets else r.get("config")
        if data is None:
            M.fail("the API gave nothing to write")
        path = args.file
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            M.fail("%s is there already - not written over" % path)
        except OSError as e:
            M.fail("%s: %s" % (path, e))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
            f.write("\n")
        M.ok("written to %s (0600)" % path)
        if args.with_secrets:
            print(M.col("  the passphrase that opens it (shown once - keep it apart from the file):", M.C.yellow))
            print("  " + M.col(r.get("passphrase") or "?", M.C.bold))
            if not r.get("tls"):
                M.warn("without the certificate of the pages: %s" % (r.get("tls_said") or "?"))
        return 0
    try:
        with open(args.file, encoding="utf-8") as f:
            conf = json.load(f)
    except (OSError, ValueError) as e:
        M.fail("%s: %s" % (args.file, e))
    phrase = ""
    if isinstance(conf, dict) and conf.get("kind") and "locked" in str(conf.get("kind")):
        phrase = os.environ.get("UPNP_PASSPHRASE") or ""
        if not phrase:
            import getpass
            phrase = getpass.getpass("the passphrase of %s: " % args.file)
    body = {"config": conf, "passphrase": phrase, "replace": bool(args.replace)}
    says = api(M, "POST", "/api/carry/import", dict(body, check=True)).get("says") or {}
    print(M.col("%s" % args.file, M.C.bold))
    for k in ("from", "version", "made", "secrets", "config", "settings", "users", "backup_targets", "avahi", "tls"):
        print("  %-16s %s" % (k.replace("_", " "), says.get(k)))
    if not args.yes and not _ask("put it in%s?" % (" - what is not in the file is taken away" if args.replace
                                                    else "")):
        print("  nothing done")
        return 1
    r = api(M, "POST", "/api/carry/import", body)
    for ln in r.get("said") or []:
        print(M.col("  " + str(ln), M.C.dim))
    for m in r.get("made") or []:
        print("  %s" % (m if isinstance(m, str) else json.dumps(m, ensure_ascii=False)))
    M.ok(r.get("message") or "imported")
    return 0


def cmd_power(M, args, cfg):
    """upnp power [status|reboot|poweroff|cancel] [--in MIN] - restart or power off this machine (otp
    --restart-nodes / --restarts), as Settings → Restart and power off."""
    what = args.what or "status"
    if what in ("reboot", "poweroff"):
        if not args.yes and not _ask("%s this machine%s?" % ("Restart" if what == "reboot" else "Power off",
                                                              " in %d min" % args.minutes if args.minutes else " now")):
            print("  nothing done")
            return 1
        r = api(M, "POST", "/api/power", {"how": what, "in": int(args.minutes or 0)})
        M.info(r.get("message") or "asked")
        got = follow_root(M, cfg, "power", r.get("id"), 60, "root")
        return _said_root(M, got) if got else 1
    if what == "cancel":
        r = api(M, "POST", "/api/power", {"action": "cancel"})
        M.info(r.get("message") or "asked")
        got = follow_root(M, cfg, "power", r.get("id"), 60, "root")
        return _said_root(M, got) if got else 1
    d = api(M, "GET", "/api/power")
    if _out(args, d):
        return 0
    print(M.col("Restart and power off", M.C.bold))
    n = d.get("node") or {}
    sc = d.get("scheduled") or {}
    pl = d.get("plan") or {}
    au = d.get("auto") or {}
    print("  %-20s %s" % ("this machine", "%s, up since %s, fake-igd %s" % (n.get("name"), _when(n.get("started")),
                                                                          n.get("version"))))
    print("  %-20s %s" % ("set for later", ("%s at %s" % (sc.get("mode") or sc.get("how") or "?", _when(sc.get("at"))))
                          if sc else "nothing"))
    if pl:
        print("  %-20s %s" % ("the last ask", "%s - %s, by %s at %s" % (pl.get("words"), pl.get("state"),
                                                                       pl.get("by"), _when(pl.get("at")))))
    print("  %-20s %s" % ("on a schedule", ("on, next %s" % _when(au.get("next"))) if au.get("on") else "off"))
    return 0


# ---- the gateway for devices (1.7.15) ----------------------------------------------------------------
def cmd_gateway(M, args, cfg):
    """upnp gateway [status|on|off|add IP --name N [--mac M|--mac-seen]|del IP|keep|back] - Settings → Gateway
    for devices: this server as the default gateway of chosen devices, forwarding only for them, only toward
    the router."""
    what = args.what or "status"
    d = api(M, "GET", "/api/gateway")
    if what in ("dns", "rule", "try"):
        return _gateway_fw(M, args, cfg, d, what)
    if what in ("top", "conns"):
        return _gateway_top(M, args, cfg, what)
    if what in ("on", "off", "keep", "back", "add", "del"):
        body = {"action": what}
        if what == "add":
            if not args.ip or not args.name:
                M.fail("upnp gateway add IP --name NAME [--mac MAC | --mac-seen]")
            mac = args.mac
            if args.mac_seen:
                seen = api(M, "POST", "/api/gateway", {"action": "mac_seen", "ip": args.ip})
                if not seen.get("mac"):
                    M.fail(seen.get("message") or "no MAC seen for %s" % args.ip)
                mac = seen["mac"]
                M.info("its MAC, as the neighbour table has it: %s" % mac)
            old = next((x for x in d.get("devices") or [] if x.get("ip") == args.ip), {})
            body = {"action": "device_save", "device": {"id": old.get("id") or "", "name": args.name, "ip": args.ip,
                                                        "mac": mac, "on": True}}
        elif what == "del":
            hit = next((x for x in d.get("devices") or [] if x.get("ip") == args.ip), None)
            if not hit:
                M.fail("%s is not one of the devices of the gateway" % (args.ip or "?"))
            body = {"action": "device_remove", "id": hit["id"]}
        elif what == "on" and not args.yes:
            names = ", ".join("%s (%s)" % (x["name"], x["ip"]) for x in d.get("devices") or [] if x.get("on") is not False)
            if not _ask("Forward the traffic of %s to the router %s?" % (names or "nobody", (d.get("net") or {}).get("router"))):
                print("  nothing done")
                return 1
        r = api(M, "POST", "/api/gateway", body)
        M.info(r.get("message") or "asked")
        if r.get("id"):
            got = follow_root(M, cfg, "gateway", r.get("id"), 60, "root")
            return _said_root(M, got) if got else 1
        return 0
    if _out(args, d):
        return 0
    nv, ap, lv = d.get("net") or {}, d.get("applied") or {}, d.get("live") or {}
    on = ap.get("on") and lv.get("ip_forward") == "1"
    print(M.col("Gateway for devices", M.C.bold) + "  " + (M.col("forwarding ON", M.C.green) if on else
                                                            M.col("off - nothing is forwarded", M.C.yellow)))
    print("  %-22s %s" % ("default route", "%s via %s (this server %s/%s)" % (nv.get("defif") or "-", nv.get("router") or "-",
                                                                         nv.get("address") or "-", nv.get("prefix") or "")))
    print("  %-22s %s" % ("net.ipv4.ip_forward", lv.get("ip_forward") or "?"))
    print("  %-22s %s" % ("FAKE-IGD-FWD", ("first in FORWARD" if lv.get("first") else "NOT first") + (", ends in DROP" if lv.get("ends_drop") else ", no DROP")
                          if lv.get("chain") else "not in place"))
    print("  %-22s %s" % ("fake-igd's firewall", "on" if lv.get("firewall") else "OFF - the gateway cannot be switched on"))
    if ap.get("why_off"):
        M.warn("turned off by itself: %s" % ap["why_off"])
    t = d.get("trial") or {}
    if t.get("id"):
        M.warn("a change waits to be kept until %s - sudo upnp gateway keep" % _when(t.get("until")))
    devs = d.get("devices") or []
    if devs:
        print()
        M.table(["device", "address", "MAC", "on", "forwarded", "last through"],
                [[x.get("name"), x.get("ip"), x.get("mac") or "-", "yes" if x.get("on") is not False else "no",
                  "%s pkts" % ((x.get("counters") or {}).get("out_pkts") or 0), _when(x.get("seen")) if x.get("seen") else "-"]
                 for x in devs])
    else:
        print("  no device yet - sudo upnp gateway add IP --name NAME --mac-seen")
    return 0


def _gateway_top(M, args, cfg, what):
    """upnp gateway top | conns IP - the Gateway tab's numbers: each device's traffic today, its DNS, rules and
    drops; or one device's live connections (conntrack, as root last read it)."""
    d = api(M, "GET", "/api/gateway/tab")
    if _out(args, d):
        return 0
    fmt = lambda n: "%.1f MB" % (n / 1e6) if n >= 1e6 else ("%.1f kB" % (n / 1e3) if n >= 1e3 else "%d B" % n)
    if what == "conns":
        dev = next((x for x in d.get("devices") or [] if x.get("ip") == args.ip), None)
        if not dev:
            M.fail("%s is not one of the devices of the gateway" % (args.ip or "?"))
        print(M.col("%s (%s) - %d connection(s) now" % (dev["name"], dev["ip"], dev.get("conns_n") or 0), M.C.bold)
              + "  (read by root %s; the way out only - the answers come from the router)" % _when(d.get("read_at")))
        M.table(["proto", "to", "port", "what", "state", "pkts", "sent", "expires"],
                [[c["proto"], c["dst"], c["dport"] or "-", "", c.get("state") or "-", c.get("pkts"), fmt(c.get("bytes") or 0),
                  "%ds" % c.get("timeout", 0)] for c in dev.get("conns") or []])
        return 0
    v = d.get("view") or {}
    on = (v.get("applied") or {}).get("on") and (v.get("live") or {}).get("ip_forward") == "1"
    print(M.col("Gateway for devices", M.C.bold) + "  " + (M.col("forwarding ON", M.C.green) if on else M.col("off", M.C.yellow))
          + "  sent today %s · final DROP %d pkts · read %s" % (fmt((d.get("today") or {}).get("bytes") or 0), d.get("dropped") or 0,
                                                                 _when(d.get("read_at"))))
    rows = []
    for x in d.get("devices") or []:
        hits = lambda lst: sum((y.get("hits") or {}).get("pkts") or 0 for y in lst)
        rows.append([x["name"], x["ip"], fmt(x["today"]["bytes"]), "%s/s" % fmt(x["today"]["rate"]), x.get("conns_n") or 0,
                     "%d (%d srv)" % (hits(x.get("dns") or []), len(x.get("dns") or [])),
                     "%d (%d)" % (hits(x.get("rules") or []), len(x.get("rules") or [])), (x.get("dropped") or {}).get("pkts") or 0,
                     ", ".join(t["dst"] for t in (x.get("top_dst") or [])[:3])])
    if rows:
        M.table(["device", "address", "sent today", "now", "conns", "dns pkts", "rule pkts", "dropped", "top destinations"], rows)
    else:
        print("  no device - sudo upnp gateway add IP --name NAME --mac-seen")
    return 0


def _gateway_fw(M, args, cfg, d, what):
    """upnp gateway dns|rule|try IP ... - a device's DNS servers and rules of its own (Settings → Gateway for
    devices → its firewall), and a packet tried through them."""
    dev = next((x for x in d.get("devices") or [] if x.get("ip") == args.ip), None)
    if not dev:
        M.fail("%s is not one of the devices of the gateway (upnp gateway add %s --name NAME)" % (args.ip or "?", args.ip or "IP"))
    dns = [{"ip": x["ip"], "dot": bool(x.get("dot"))} for x in dev.get("dns") or []]
    rules = [{k: r.get(k) for k in ("id", "to", "proto", "ports", "comment", "on")} for r in dev.get("rules") or []]
    rest = list(args.rest or [])
    if what == "try":
        if len(rest) < 2:
            M.fail("upnp gateway try IP DEST PROTO [PORT]")
        t = api(M, "POST", "/api/gateway", {"action": "try", "id": dev["id"], "dns": dns, "rules": rules, "dst": rest[0],
                                            "proto": rest[1], "port": rest[2] if len(rest) > 2 else 0})
        if _out(args, t):
            return 0
        (M.ok if t.get("verdict") == "ACCEPT" or t.get("direct") else M.warn)(
            "%s %s %s → %s: %s%s" % (dev["name"], rest[1], rest[2] if len(rest) > 2 else "", rest[0], t.get("words"),
                                    (" (out %s)" % t["out"]) if t.get("out") else ""))
        if t.get("rule"):
            print("  decided by: %s" % t["rule"])
        return 0
    if what == "rule" and (not rest or rest[0] == "list"):
        if _out(args, {"rules": dev.get("rules") or []}):
            return 0
        if not rules:
            print("  %s has no rule of its own - the internet only" % dev["name"])
        for n, r in enumerate(dev.get("rules") or [], 1):
            h = r.get("hits") or {}
            print("  %2d  %-3s %-5s %-16s → %-20s %-8s %s" % (n, "on" if r.get("on") else "off", r.get("proto"), r.get("ports") or "",
                                                          r.get("to"), r.get("via") or "", (r.get("comment") or "") +
                                                          ("  (%d pkts)" % h["pkts"] if h.get("pkts") else "")))
        print("  DNS: %s" % (", ".join(x["ip"] + (" +DoT" if x.get("dot") else "") for x in dev.get("dns") or []) or "as now"))
        return 0
    if what == "dns":
        if len(rest) < 2 or rest[0] not in ("add", "del"):
            M.fail("upnp gateway dns IP add|del DNS [--dot]")
        if rest[0] == "add":
            dns = [x for x in dns if x["ip"] != rest[1]] + [{"ip": rest[1], "dot": bool(args.dot)}]
        else:
            if not any(x["ip"] == rest[1] for x in dns):
                M.fail("%s is not a DNS server of %s" % (rest[1], dev["name"]))
            dns = [x for x in dns if x["ip"] != rest[1]]
    else:
        if rest[0] == "add":
            if not args.to:
                M.fail("upnp gateway rule IP add --to NET [--proto tcp] [--ports 8080] [--comment ...]")
            rules.append({"to": args.to, "proto": args.proto, "ports": args.ports, "comment": args.comment, "on": True})
        elif rest[0] == "del":
            try:
                n = int(rest[1]) if len(rest) > 1 else 0
            except ValueError:
                n = 0
            if not 1 <= n <= len(rules):
                M.fail("which rule? upnp gateway rule %s list - then del N" % args.ip)
            rules.pop(n - 1)
        else:
            M.fail("upnp gateway rule IP list | add --to NET ... | del N")
    r = api(M, "POST", "/api/gateway", {"action": "designer_save", "id": dev["id"], "dns": dns, "rules": rules})
    M.info(r.get("message") or "saved")
    if r.get("id"):
        got = follow_root(M, cfg, "gateway", r.get("id"), 60, "root")
        return _said_root(M, got) if got else 1
    return 0


# ---- MikroTik (1.8.2): the real router, read-only ----------------------------------------------------------
MT_WORDS = {"ok": "open", "no_dnat": "no dst-nat", "no_accept": "dropped by the filter", "shadowed": "shadowed",
            "disabled": "disabled", "elsewhere": "forwarded elsewhere", "unsure": "cannot tell"}


def cmd_mikrotik(M, args, cfg):
    """upnp mikrotik [status|check|rules [ipv4|ipv6] [--table T]|try|read] - Settings → MikroTik: the real router,
    read only - whether it carries every port a device asked for, and its firewall."""
    what = args.what or "status"
    if what == "try":
        d = api(M, "POST", "/api/mikrotik", {"do": "test"}, timeout=120)
        if _out(args, d):
            return 0 if d.get("ok") else 1
        for s in d.get("steps") or []:
            print("  %s %-40s %s" % (M.col("✓", M.C.green) if s.get("ok") else M.col("✗", M.C.red), s.get("what"),
                                     M.col(s.get("said") or "", M.C.dim)))
        if not d.get("ok") and d.get("fingerprint"):
            M.warn("its certificate %s is not trusted - compare it with /certificate print detail on the router, "
                   "then trust it in Settings → MikroTik" % d.get("fingerprint_words"))
        return 0 if d.get("ok") else 1
    if what == "read":
        d = api(M, "POST", "/api/mikrotik", {"do": "read"}, timeout=180)
        M.info(d.get("message") or "read")
        return 0 if (d.get("state") or {}).get("ok") else 1
    if what == "rules":
        d = api(M, "GET", "/api/mikrotik/rules")
        if _out(args, d):
            return 0
        snap = d.get("snap") or {}
        if not snap:
            M.fail("the MikroTik is not read yet - upnp mikrotik read")
        fam = "ipv6" if (args.family or "ipv4") in ("ipv6", "6") else "ip"
        tables = [args.table] if args.table else ["filter", "nat", "mangle", "raw"]
        for t in tables:
            rows = ((snap.get("rules") or {}).get(fam) or {}).get(t) or []
            print(M.col("%s firewall %s" % ("/ipv6" if fam == "ipv6" else "/ip", t), M.C.bold) + "  %d rule(s)" % len(rows))
            if rows:
                M.table(["#", "chain", "action", "what it matches", "packets", "comment"],
                        [[r.get("n"), r.get("chain"), ("X " if r.get("disabled") else "") + str(r.get("action") or "")
                          + ((" > " + r["to-addresses"] + (":" + r["to-ports"] if r.get("to-ports") else "")) if r.get("to-addresses") else ""),
                          " ".join("%s=%s" % (k, v) for k, v in r.items() if k in (
                              "protocol", "dst-port", "src-address", "dst-address", "in-interface", "in-interface-list",
                              "out-interface-list", "connection-state", "connection-nat-state", "src-address-list",
                              "dst-address-list")), r.get("packets") or 0, (r.get("comment") or "")[:40]] for r in rows])
            print()
        return 0
    d = api(M, "GET", "/api/mikrotik")
    if _out(args, d):
        return 0
    st, sn, c = d.get("state") or {}, d.get("snap") or {}, d.get("conf") or {}
    if not d.get("on"):
        print(M.col("MikroTik", M.C.bold) + "  " + M.col("off - nothing reaches the router (Settings → MikroTik)", M.C.yellow))
        return 0
    print(M.col("MikroTik", M.C.bold) + "  %s:%s over %s" % (c.get("host") or "-", d.get("port_used"), c.get("mode")))
    if st.get("ok") is False:
        M.warn("it cannot be read: %s" % st.get("trouble"))
    if sn:
        print("  %-16s %s, RouterOS %s on %s - read %s" % ("it is", sn.get("identity"), sn.get("version"), sn.get("board"),
                                                       _when(sn.get("at"))))
    ch = d.get("checks") or {}
    for w in ch.get("warnings") or []:
        M.warn(w)
    if not ch:
        return 0
    print("  %-16s %d of %d port(s) asked for are open on it" % ("the ports", ch.get("open", 0), ch.get("total", 0)))
    if True:                                            # the rows: all of them for check, the not open ones else
        rows = ch.get("rows") or []
        if what != "check":
            rows = [r for r in rows if r.get("state") != "ok"][:20]
        if rows:
            print()
            M.table(["device", "port", "IPv4 on the MikroTik", "why", "IPv6"],
                    [[r.get("device"), "%s/%s" % (r.get("port"), r.get("proto")),
                      M.col(MT_WORDS.get(r.get("state"), r.get("state")), M.C.green if r.get("state") == "ok" else M.C.red),
                      (r.get("nat_why") or "")[:70], r.get("v6")] for r in rows])
        if what == "check":
            cmds = [x for r in rows for x in (r.get("commands") or []) + (r.get("v6_commands") or [])]
            if cmds:
                print("\n" + M.col("What would put it right - type it on the MikroTik yourself (fake-igd only reads):", M.C.bold))
                for x in cmds:
                    print("  " + x)
    return 0


# ---- SELinux (1.7.7, otp's --selinux-check, --selinux STEP, --selinux-report) ------------------------
def _web_helper():
    for p in (WEB_HELPER, os.path.join(os.path.dirname(LIB_DIR), "deploy", "fake_igd_web.py")):
        if os.path.isfile(p):
            return p
    return ""


def cmd_selinux(M, args, cfg):
    """upnp selinux [check|prepare|apply|enforce|permissive|report [FILE]] - SELinux on this server, as
    Settings → SELinux: root's helper does it, and works out itself what fake-igd needs."""
    if os.geteuid() != 0:
        M.fail("SELinux is root's - sudo upnp selinux %s" % (args.what or "check"))
    helper = _web_helper()
    if not helper:
        M.fail("root's helper (fake_igd_web.py) is not installed - ./install.sh --upgrade")
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
    step = args.what or "check"
    args.file = (args.args or [None])[0]
    if step in ("look", "fix", "rules"):
        return _se_findings_cli(M, args, py, helper, step)
    if step == "report":
        node = (os.uname()[1].split(".")[0] or "server")
        out = args.file or "/root/fake-igd-selinux-report-%s-%s.tar.gz" % (node, time.strftime("%Y%m%d-%H%M"))
        print(M.col("gathering what SELinux says here - a minute or two (ausearch, semanage)...", M.C.dim))
        got = subprocess.run([py, "-I", helper, "--selinux-report", out], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, universal_newlines=True, timeout=1200)
        sys.stderr.write(got.stderr)
        if got.returncode != 0:
            return got.returncode
        M.ok("the report is in %s (%d kB)" % (out, os.path.getsize(out) >> 10))
        print("  look through avc*.txt in it before sending it on: the audit log holds the command lines of the "
              "programs SELinux refused something to")
        return 0
    if step == "check":
        argv = [py, "-I", helper, "--selinux-check"] + (["--json"] if args.json else [])
    else:
        words = {"prepare": "SELinux permissive at the next start of this machine, every file labelled then "
                            "(the machine is not restarted now)",
                 "apply": "fake-igd's module, the labels of its files, the boolean and ports it needs put in "
                          "(still permissive)",
                 "enforce": "SELinux ENFORCING on this machine, now and after a restart",
                 "permissive": "SELinux permissive on this machine, now and after a restart"}[step]
        if not args.yes:
            if not sys.stdin.isatty():
                M.fail("%s - add --yes to do it without a terminal" % words)
            if not _ask("%s. Go on?" % words):
                print("  nothing done")
                return 1
        argv = [py, "-I", helper, "--selinux-do", step] + (["--json"] if args.json else [])
    got = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                         timeout=1200)
    if args.json:
        sys.stdout.write(got.stdout)
    else:
        for ln in got.stdout.splitlines():
            low = ln.strip()
            if low.startswith("FAIL") or low.startswith("not ready"):
                print(M.col(ln, M.C.red if low.startswith("FAIL") else M.C.yellow))
            elif low.startswith("ok ") or low.startswith("done:") or low in ("ready for enforcing", "enforcing"):
                print(M.col(ln, M.C.green))
            elif ln.startswith("SELinux:"):
                print(M.col(ln, M.C.bold))
            else:
                print(ln)
    sys.stderr.write(got.stderr)
    if step != "check":
        # The card on the pages looks again now, not in half an hour (the API, where it runs).
        try:
            if os.path.exists(os.path.join(RUN_DIR, "cli-token")):
                api(M, "POST", "/api/selinux", {"action": "check"}, timeout=10, quiet=True)
        except SystemExit:
            pass
    return got.returncode


SE_KIND_WORDS = (("boolean", "A boolean", "a switch of the policy allows it"),
                 ("label", "A label", "the file is not labelled as the policy says"),
                 ("port", "A port", "a port with no type of its own"),
                 ("rule", "A rule of fake-igd's", "nothing of the policy allows it - exactly this, in fake_igd_local"),
                 ("unsafe", "Not for a button", "fake-igd's, but too much to allow from here"),
                 ("foreign", "Not fake-igd's", "other programs of this machine - never put right here"))


def _se_json(M, py, helper, argv):
    got = subprocess.run([py, "-I", helper] + argv + ["--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         universal_newlines=True, timeout=1200)
    if got.returncode not in (0, 1):
        M.fail((got.stderr or got.stdout).strip()[-400:] or "root's helper ended with %d" % got.returncode)
    try:
        return json.loads(got.stdout or "{}")
    except ValueError:
        M.fail("root's helper said nothing readable: %s" % (got.stdout or got.stderr)[:300])


def _se_findings_print(M, c):
    found = c.get("findings") or []
    d = c.get("denials") or {}
    print(M.col("What SELinux refuses on this server (%s) - %s" % (
        c.get("mode"), "since fake-igd's needs were put in" if d.get("since") else "since the machine started"),
        M.C.bold))
    if not d.get("tool", True) or c.get("mode") not in ("Enforcing", "Permissive"):
        print(M.col("  SELinux is %s - nothing it refuses is read" % (c.get("mode") or "?").lower(), M.C.dim)
              if c.get("mode") not in ("Enforcing", "Permissive") else
              M.col("  ausearch is not on this machine (dnf install audit)", M.C.yellow))
        return
    if not found:
        M.ok("SELinux refused nothing on this server")
        return
    tone = {"boolean": M.C.green, "label": M.C.green, "port": M.C.green, "rule": M.C.yellow, "unsafe": M.C.red,
            "foreign": M.C.dim}
    for kind, name, says in SE_KIND_WORDS:
        items = [f for f in found if f["kind"] == kind]
        if not items:
            continue
        print()
        print(M.col("%s (%d)" % (name, len(items)), tone[kind], M.C.bold) + M.col("  - " + says, M.C.dim))
        for f in items:
            what = f.get("path") or ("port %s/%s" % (f["port"], f.get("proto") or "tcp") if f.get("port") else "")
            print("  %s %s %s %s" % (M.col(f["id"], M.C.cyan), M.col("%3dx" % f["count"], M.C.dim),
                                     M.col(f.get("comm") or "?", M.C.bold),
                                     "%s -> %s %s { %s }" % (f["source"], f["target"], f["class"], " ".join(f["perms"]))))
            if what:
                print("                    " + M.col(what, M.C.magenta))
            fx = (f.get("fix") or {}).get("cmd")
            print("                    " + (M.col("-> " + fx, M.C.green) if fx else M.col(f.get("says") or "", tone[kind])))
    fixable = [f["id"] for f in found if f["kind"] in ("boolean", "label", "port", "rule")]
    print()
    if fixable:
        print(M.col("  %d can be put right here: sudo upnp selinux fix --all (or fix ID ...)" % len(fixable), M.C.cyan))


def _se_findings_cli(M, args, py, helper, step):
    if step == "look":
        c = _se_json(M, py, helper, ["--selinux-check"])
        if args.json:
            print(json.dumps({"findings": c.get("findings") or [], "local": c.get("local") or {},
                              "denials": c.get("denials") or {}}, indent=1))
            return 0
        _se_findings_print(M, c)
        return 0
    if step == "rules":
        if args.take_away:
            if not args.yes and not _ask("Take the rule %s out of fake-igd's local SELinux module?" % args.take_away):
                print("  nothing done")
                return 1
            c = _se_json(M, py, helper, ["--selinux-rule-drop", args.take_away])
            for x in c.get("said") or []:
                M.ok(x)
            return 0
        c = _se_json(M, py, helper, ["--selinux-check"])
        rules = (c.get("local") or {}).get("rules") or []
        if args.json:
            print(json.dumps(c.get("local") or {}, indent=1))
            return 0
        if not rules:
            print(M.col("fake-igd's local module (fake_igd_local) has no rule - nothing was put in from the card", M.C.dim))
            return 0
        print(M.col("fake-igd's local rules (fake_igd_local): %d%s" % (
            len(rules), "" if (c.get("local") or {}).get("in_policy") is not False else " - NOT in the policy"), M.C.bold))
        for r in rules:
            print("  %s (allow %s %s (%s (%s)))" % (M.col(r["id"], M.C.cyan), r["source"], r["target"], r["class"],
                                                   " ".join(r["perms"])))
            print(M.col("               %s%s" % (r.get("why") or "", (" - by %s" % r["by"]) if r.get("by") else ""), M.C.dim))
        print(M.col("  take one away: sudo upnp selinux rules --take-away ID", M.C.dim))
        return 0
    # fix
    c = _se_json(M, py, helper, ["--selinux-check"])
    found = {f["id"]: f for f in c.get("findings") or []}
    fixable = [i for i, f in found.items() if f["kind"] in ("boolean", "label", "port", "rule")]
    ids = fixable if args.all else list(args.args or [])
    if not ids:
        M.fail("which? sudo upnp selinux fix ID ... (upnp selinux look shows them) or --all")
    bad = [i for i in ids if i not in found]
    if bad:
        M.warn("not refused now (or not an id of look): %s" % ", ".join(bad))
    todo = [found[i] for i in ids if i in found and found[i]["kind"] in ("boolean", "label", "port", "rule")]
    for i in ids:
        if i in found and found[i] not in todo:
            M.warn("%s is not put right here: %s" % (i, found[i].get("says")))
    if not todo:
        M.fail("nothing of it can be put right here")
    print(M.col("Root does exactly this - nothing else:", M.C.bold))
    for f in todo:
        print("  %s %s" % (M.col(f["id"], M.C.cyan), f["fix"]["cmd"]))
    if not args.yes:
        if not sys.stdin.isatty():
            M.fail("add --yes to do it without a terminal")
        if not _ask("Put it in?"):
            print("  nothing done")
            return 1
    got = _se_json(M, py, helper, ["--selinux-fix"] + [f["id"] for f in todo])
    for x in got.get("said") or []:
        (M.warn if "not there" in x or "not put right" in x else M.ok)(x)
    try:
        if os.path.exists(os.path.join(RUN_DIR, "cli-token")):
            api(M, "POST", "/api/selinux", {"action": "check"}, timeout=10, quiet=True)
    except SystemExit:
        pass
    left = [f for f in got.get("findings") or [] if f["kind"] in ("boolean", "label", "port", "rule")]
    print(M.col("  %d left that can be put right here" % len(left), M.C.dim) if left else M.col("  nothing left that can be put right here", M.C.green))
    return 0
