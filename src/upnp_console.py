"""upnp --console - fake-igd run by its menus, on the server's own screen or over SSH.

The same console as `otp --console`: it opens on the live log (every line), Esc goes to the
main menu, q leaves it for the ordinary shell and ! opens a shell that comes back. The bar at
the top says how the service is, asked again every 20 s without holding anything up. Every
question is a window over the menu, every list scrolls with a scroll bar and / finds, long
output gets a screen of its own. Every action is the `upnp ...` command its window shows in
its title, run as it would be typed - the console can do nothing the command line cannot.
"""
import collections
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time

CONSOLE_FLAG = os.environ.get("UPNP_CONSOLE_FLAG", "/etc/upnp-console-login")
CONSOLE_PROFILE = "/etc/profile.d/zz-upnp-console.sh"
CONSOLE_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
ANSI = re.compile(r"\033\[[0-9;]*m")
TERM_CTL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def term_safe(text):
    """What came from outside, safe on a terminal: colours kept, any other control
    character shown as \\xNN."""
    t = str(text)
    out, at = [], 0
    for m in ANSI.finditer(t):
        out.append(TERM_CTL.sub(lambda c: "\\x%02x" % ord(c.group(0)), t[at:m.start()]))
        out.append(m.group(0))
        at = m.end()
    out.append(TERM_CTL.sub(lambda c: "\\x%02x" % ord(c.group(0)), t[at:]))
    return "".join(out)


class ConsoleBack(Exception):
    """Back to the menu."""


class Console(object):
    HELP = " Up/Down move   Enter choose   Esc back   ! shell   q leave "
    LIVE_KEEP = 20000
    RESULT_TONES = {"new": "good", "renewed": "info", "rejected": "bad", "conflict": "bad",
                    "deleted": "dim", "expired": "dim", "none": "dim"}

    def __init__(self, cli, pal, config):
        self.cli = cli
        self.pal = pal
        self.config = config
        self.me = os.path.abspath(cli.__file__)
        self.VERSION = cli.VERSION
        self.backdrop = None

    # ---- small things ---------------------------------------------------------------
    def argv(self, *args):
        a = [sys.executable, "-I", self.me] + [str(x) for x in args]
        if self.config != self.cli.DEFAULT_CONFIG:
            a += ["--config", self.config]
        return a

    def out(self, *args):
        """`upnp ARGS --json`, read."""
        try:
            got = subprocess.run(self.argv(*args) + ["--json", "--no-color"], capture_output=True, text=True,
                                 timeout=60, stdin=subprocess.DEVNULL)
            return json.loads(got.stdout or "null")
        except Exception:                               # noqa: BLE001
            return None

    @staticmethod
    def _quote(a):
        a = str(a)
        return a if re.match(r"^[A-Za-z0-9_@%+=:,./-]+\Z", a) else "'%s'" % a.replace("'", "'\\''")

    def cfg(self):
        return self.cli.load_config(self.config)

    # ---- keys on the ordinary terminal ----------------------------------------------
    def _raw(self):
        try:
            import termios
            return termios.tcgetattr(sys.stdin.fileno())
        except Exception:                               # noqa: BLE001
            return None

    def _restore(self, was):
        if was is None:
            return
        import termios
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, was)

    def key(self, wait=None):
        """One key, without Enter: 'esc', 'enter', 'bs', 'up'..., a character -
        or None when `wait` seconds went by without one."""
        import select
        import tty
        fd = sys.stdin.fileno()
        was = self._raw()
        try:
            if was is not None:
                import termios
                tty.setcbreak(fd, termios.TCSANOW)
            r, _w, _x = select.select([fd], [], [], wait)
            if not r:
                return None
            ch = os.read(fd, 1)
            if ch == b"\x1b":
                r, _w, _x = select.select([fd], [], [], 0.05)
                if not r:
                    return "esc"
                rest = os.read(fd, 8)
                full = {b"[5~": "pgup", b"[6~": "pgdn", b"[1~": "home", b"[4~": "end",
                        b"[7~": "home", b"[8~": "end", b"[H": "home", b"[F": "end",
                        b"OH": "home", b"OF": "end"}.get(rest)
                if full:
                    return full
                return {b"[A": "up", b"[B": "down", b"[C": "right", b"[D": "left", b"OA": "up",
                        b"OB": "down", b"OC": "right", b"OD": "left"}.get(rest[:2], "seq")
            if ch in (b"\r", b"\n"):
                return "enter"
            if ch in (b"\x7f", b"\x08"):
                return "bs"
            if ch == b"\x03":
                return "ctrl-c"
            if ch == b"\x04":
                return "ctrl-d"
            if ch == b"\x15":
                return "ctrl-u"
            try:
                return ch.decode("utf-8")
            except UnicodeDecodeError:
                more = ch
                while len(more) < 4:
                    more += os.read(fd, 1)
                    try:
                        return more.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                return ""
        finally:
            self._restore(was)

    def pause(self):
        sys.stdout.write(self.pal.dim("\n  Enter or Esc - back to the menu "))
        sys.stdout.flush()
        if self._raw() is None:
            try:
                input()
            except EOFError:
                pass
            return
        while self.key() not in ("enter", "esc", "ctrl-c", "ctrl-d", "q"):
            pass
        sys.stdout.write("\n")

    def clear_screen(self):
        if sys.stdout.isatty():
            sys.stdout.write("\033[H\033[2J")
            sys.stdout.flush()

    # ---- the bar at the top ---------------------------------------------------------
    def status_thread(self):
        """The line at the top, asked for again every 20 s off the screen's thread -
        the menu never waits for it. Nothing asked while nobody sees the bar."""
        def look():
            while not self.closing:
                if self.plain and not self.st_now:
                    time.sleep(0.5)
                    continue
                self.st_now = False
                self.st = self.out("status") or {}
                self.st_gen += 1
                for _ in range(40):
                    if self.closing or self.st_now:
                        break
                    time.sleep(0.5)
        threading.Thread(target=look, name="upnp-console-status", daemon=True).start()

    def _put(self, y, x, text, attr=0):
        try:
            h, w = self.scr.getmaxyx()
            if y < 0 or y >= h or x >= w:
                return
            self.scr.addnstr(y, x, str(text), max(0, w - x - (1 if y == h - 1 else 0)), attr)
        except Exception:                               # noqa: BLE001 - the edge
            pass

    def _colours(self):
        c = self.curses
        self.A = {"head": c.A_REVERSE, "sel": c.A_REVERSE | c.A_BOLD, "ok": c.A_BOLD,
                  "warn": c.A_BOLD, "bad": c.A_BOLD, "dim": c.A_DIM, "key": c.A_BOLD,
                  "title": c.A_BOLD}
        if not c.has_colors() or not self.pal.on:
            return
        try:
            c.start_color()
            try:
                c.use_default_colors()
                bg = -1
            except Exception:                           # noqa: BLE001
                bg = c.COLOR_BLACK
            c.init_pair(1, c.COLOR_BLACK, c.COLOR_CYAN)
            c.init_pair(2, c.COLOR_BLACK, c.COLOR_GREEN)
            c.init_pair(3, c.COLOR_GREEN, bg)
            c.init_pair(4, c.COLOR_YELLOW, bg)
            c.init_pair(5, c.COLOR_RED, bg)
            c.init_pair(6, c.COLOR_CYAN, bg)
            self.A.update(head=c.color_pair(1), sel=c.color_pair(2) | c.A_BOLD,
                          ok=c.color_pair(3) | c.A_BOLD, warn=c.color_pair(4) | c.A_BOLD,
                          bad=c.color_pair(5) | c.A_BOLD, key=c.color_pair(6) | c.A_BOLD)
        except Exception:                               # noqa: BLE001
            pass

    def draw(self, title, items, sel, top, path):
        scr, A = self.scr, self.A
        scr.erase()
        h, w = scr.getmaxyx()
        st = self.st or {}
        sv = st.get("service") or {}
        self._put(0, 0, " " * w, A["head"])
        left = " upnp %s  %s " % (self.VERSION, socket.gethostname())
        self._put(0, 0, left, A["head"] | self.curses.A_BOLD)
        active = sv.get("state") or "..."
        svc = " service %s " % active
        self._put(0, len(left) + 1, svc, A["sel"] if active == "active" else
                  (A["head"] if active == "..." else self.curses.A_REVERSE | A["bad"]))
        bits = []
        if st.get("mode"):
            bits.append("mode %s" % st["mode"])
        if st.get("mapping_response"):
            bits.append(st["mapping_response"])
        if st.get("interfaces") is not None:
            n = len(st.get("interfaces") or {})
            bits.append("%d interface%s" % (n, "" if n == 1 else "s"))
        stats = st.get("stats") or {}
        if stats:
            bits.append("%d clients" % stats.get("clients", 0))
            bits.append("%d ports" % stats.get("ports", 0))
        md = st.get("mdns")
        if md:
            bits.append("mDNS %s" % ("refl. on" if md.get("reflector") and md.get("state") == "active"
                                     else ("refl. off" if md.get("state") == "active" else md.get("state"))))
        pub = st.get("public_ip") or (st.get("external_ip") if st.get("external_ip") not in (None, "", "auto") else None)
        if pub:
            bits.append("public %s" % pub)
        short = [b.replace("interfaces", "if.").replace("interface", "if.").replace("mode ", "")
                 .replace("public ", "") for b in bits]
        tries = [bits, bits[:-1] if pub else bits, short[:-1] if pub else short]
        y = 1
        for b in tries:
            right = " " + " | ".join(b) + " "
            if len(left) + len(svc) + len(right) + 2 < w:
                self._put(0, w - len(right), right, A["head"])
                break
        else:
            self._put(1, 1, " | ".join(bits[:-1] if pub else bits), A["key"])
            y = 2
        for other in st.get("other_igd") or []:
            self._put(y, 1, "ANOTHER UPnP ROUTER ON THE NETWORK: %s - disable UPnP on it, the PS5 may use it"
                      % other, A["bad"])
            y += 1
        if st and active not in ("active", "..."):
            self._put(y, 1, "the service is not running (%s) - The service > Start it" % active, A["bad"])
            y += 1
        if md and md.get("state") not in ("active", None):
            self._put(y, 1, "the mDNS reflector (avahi-daemon) is not running (%s) - mDNS reflector > Start" % md.get("state"),
                      A["bad"])
            y += 1
        if st.get("mode") == "passive":
            self._put(y, 1, "MODE PASSIVE - fake-igd answers nobody, no ports are learned", A["warn"])
            y += 1
        if st.get("mapping_response") == "reject":
            self._put(y, 1, "AddPortMapping is rejected - requests are still logged", A["dim"])
            y += 1
        y += 1
        self._put(y, 2, path, A["dim"])
        self._put(y, 2 + len(path), title, A["title"])
        y += 2
        room = max(1, h - y - 2)
        if sel < top:
            top = sel
        if sel >= top + room:
            top = sel - room + 1
        width = max(20, min(w - 6, max(len(it[1]) for it in items) + 10))
        for n, it in enumerate(items[top:top + room]):
            i = top + n
            line = " %3s  %s" % (it[0], it[1])
            line = line + " " * max(0, width - len(line))
            if i == sel:
                self._put(y + n, 2, line, A["sel"])
            else:
                self._put(y + n, 2, " %3s" % it[0], A["key"])
                self._put(y + n, 8, it[1])
        if top > 0:
            self._put(y - 1, 4, "^ more", A["dim"])
        if top + room < len(items):
            self._put(y + room, 4, "v more", A["dim"])
        self._put(h - 1, 0, " " * (w - 1), A["head"])
        self._put(h - 1, 0, self.HELP[:w - 1], A["head"])
        scr.noutrefresh()
        return top

    # ---- the menus ------------------------------------------------------------------
    def menu(self, title, items, path=""):
        """items: [(key, words, function[, 'plain'])]; returns 'back' or 'quit'."""
        c = self.curses
        sel, top, typed, typed_at, seen = 0, 0, "", 0.0, -1
        while True:
            if self.plain:
                c.reset_prog_mode()
                self.scr.clear()
                self.plain = False
                self.st_now = True
            top = self.draw(title, items, sel, top, path)
            self.curses.doupdate()
            self.backdrop = (lambda _s=sel, _t=top: self.draw(title, items, _s, _t, path))
            seen = self.st_gen
            self.scr.timeout(500)
            while True:
                k = self.scr.getch()
                if k != -1 or self.st_gen != seen:
                    break
                try:
                    size = os.get_terminal_size(sys.__stdout__.fileno())
                    if (size.lines, size.columns) != self.scr.getmaxyx():
                        c.resizeterm(size.lines, size.columns)
                        k = c.KEY_RESIZE
                        break
                except (OSError, ValueError, c.error):
                    pass
            if k == -1:
                continue
            if k == 27:
                self.scr.nodelay(True)
                k2 = self.scr.getch()
                if k2 in (ord("["), ord("O")):
                    k3 = self.scr.getch()
                    k = {ord("A"): c.KEY_UP, ord("B"): c.KEY_DOWN, ord("C"): c.KEY_RIGHT,
                         ord("D"): c.KEY_LEFT, ord("H"): c.KEY_HOME,
                         ord("F"): c.KEY_END}.get(k3, -1)
                    if k3 in (ord("5"), ord("6")):
                        self.scr.getch()
                        k = c.KEY_PPAGE if k3 == ord("5") else c.KEY_NPAGE
                    if k == -1:
                        self.scr.nodelay(False)
                        continue
                elif k2 != -1:
                    c.ungetch(k2)
                self.scr.nodelay(False)
            if k == c.KEY_RESIZE:
                try:
                    c.update_lines_cols()
                except Exception:                       # noqa: BLE001
                    pass
                self.scr.clear()
                continue
            if k in (c.KEY_UP, ord("k")):
                sel = (sel - 1) % len(items)
            elif k in (c.KEY_DOWN, ord("j"), 9):
                sel = (sel + 1) % len(items)
            elif k in (c.KEY_HOME, c.KEY_PPAGE):
                sel = 0
            elif k in (c.KEY_END, c.KEY_NPAGE):
                sel = len(items) - 1
            elif k in (27, c.KEY_LEFT, c.KEY_BACKSPACE, 127, 8):
                if path:
                    return "back"
            elif k in (ord("q"), ord("Q")):
                return "quit"
            elif k == ord("!"):
                self.go_plain(self.shell)
            elif ord("0") <= k <= ord("9"):
                now = time.time()
                typed = (typed if now - typed_at < 1.0 else "") + chr(k)
                typed_at = now
                hit = [i for i, it in enumerate(items) if it[0] == typed]
                if hit:
                    sel = hit[0]
                    if not any(it[0].startswith(typed) and it[0] != typed for it in items):
                        k = 10
                        typed = ""
            if k in (10, 13, c.KEY_ENTER, c.KEY_RIGHT):
                it = items[sel]
                if len(it) > 3 and it[3] == "plain":
                    r = self.go_plain(it[2])
                else:
                    try:
                        r = it[2]()
                    except ConsoleBack:
                        r = None
                if r == "quit":
                    return "quit"

    def sub(self, title, items):
        r = self.menu(title, items, path="Main menu > ")
        return "quit" if r == "quit" else None

    def go_plain(self, fn):
        """`fn` on the ordinary terminal - a command's output, the live log - and back."""
        c = self.curses
        c.def_prog_mode()
        c.endwin()
        self.plain = True
        if sys.stdout.isatty():
            sys.stdout.write("\033[H\033[2J\033[3J")
            sys.stdout.flush()
        try:
            return fn()
        except ConsoleBack:
            return None
        except KeyboardInterrupt:
            print()
            return None

    def run(self):
        main = [
            ("1", "Status and checks", self.m_status),
            ("2", "Live log", self.m_live_log),
            ("3", "Live port requests", self.m_live_requests),
            ("4", "Requested ports", self.m_ports),
            ("5", "Clients", self.m_clients),
            ("6", "Current mappings", self.m_mappings),
            ("7", "Settings", self.m_settings),
            ("8", "Rules for the router (DNAT)", self.m_dnat),
            ("9", "Host firewall", self.m_firewall),
            ("10", "Notifications (ntfy)", self.m_notify),
            ("11", "The service", self.m_service),
            ("12", "Logs and maintenance", self.m_maint),
            ("13", "mDNS reflector (avahi)", self.m_mdns),
            ("14", "Upgrades", self.m_upgrade),
            ("15", "Web pages and accounts", self.m_web),
            ("16", "Backups and the database", self.m_backups),
            ("17", "Certificates, updates, time, tests", self.m_ops),
        ]
        os.environ.setdefault("ESCDELAY", "25")
        os.environ.setdefault("NCURSES_NO_UTF8_ACS", "1")
        try:
            import locale
            locale.setlocale(locale.LC_ALL, "")
        except Exception:                               # noqa: BLE001
            pass
        import curses
        self.curses = curses
        self.st, self.st_gen, self.st_now, self.closing, self.plain = {}, 0, False, False, False

        def body(scr):
            self.scr = scr
            try:
                curses.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass
            scr.keypad(True)
            self._colours()
            self.status_thread()
            if os.environ.get("UPNP_CONSOLE_START", "log") == "log":
                self.go_plain(lambda: self.live_log(""))
            self.menu("Main menu", main)
        try:
            curses.wrapper(body)
        finally:
            self.closing = True
        print(self.pal.dim("  The upnp console is closed - `upnp --console` opens it again."))
        return 0

    def shell(self):
        sh = os.environ.get("SHELL") or "/bin/bash"
        print(self.pal.dim("  A shell - exit (or Ctrl+D) comes back to the upnp console."))
        try:
            subprocess.call([sh], env=dict(os.environ, UPNP_CONSOLE="1"))
        except KeyboardInterrupt:
            pass

    # ---- long output: a screen of its own, scrolled -----------------------------------
    def capture(self, argv, env=None):
        """What a command writes, its colour kept: (text, exit code)."""
        e = dict(os.environ, **(env or {}))
        if self.pal.on:
            e.update(FORCE_COLOR="1", SYSTEMD_COLORS="1")
        e["COLUMNS"] = str(max(60, self._cols() - 2))
        try:
            got = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, env=e, timeout=1800)
            return term_safe(got.stdout.decode("utf-8", "replace")), got.returncode
        except subprocess.TimeoutExpired:
            return "it took more than 30 minutes and was stopped", 124
        except OSError as ex:
            return str(ex), 127

    @staticmethod
    def _cols():
        try:
            return os.get_terminal_size(sys.__stdout__.fileno()).columns
        except (OSError, ValueError):
            return 100

    @staticmethod
    def _fit(line, width):
        out, seen = [], 0
        for part in re.split(r"(\x1b\[[0-9;?]*[A-Za-z])", line):
            if not part:
                continue
            if part.startswith("\x1b["):
                out.append(part)
                continue
            if seen + len(part) > width:
                out.append(part[:max(0, width - seen)])
                out.append("\x1b[0m")
                return "".join(out)
            out.append(part)
            seen += len(part)
        return "".join(out) + ("\x1b[0m" if "\x1b[" in line else "")

    def page(self, title, text):
        p = self.pal
        lines = [term_safe(ln.expandtabs(8).replace("\r", "")) for ln in text.rstrip("\n").split("\n")] or [""]
        tty = self._raw() is not None and sys.stdout.isatty()
        if not tty:
            print(text)
            return
        out = sys.stdout
        out.write("\x1b[?1049h\x1b[?25l")
        top, size = 0, None
        try:
            while True:
                try:
                    sz = os.get_terminal_size(sys.__stdout__.fileno())
                    cols, rows = max(40, sz.columns), max(8, sz.lines)
                except OSError:
                    cols, rows = 100, 30
                avail = max(3, rows - 2)
                top = max(0, min(top, max(0, len(lines) - avail)))
                end = min(len(lines), top + avail)
                head = " %s " % title
                where = " %d-%d of %d " % (top + 1, end, len(lines)) if len(lines) > avail \
                    else " %d lines " % len(lines)
                bar = (head + " " * max(0, cols - len(head) - len(where)) + where)[:cols]
                foot = (" Up/Down PgUp/PgDn Home/End scroll   Esc, q or Enter back ")[:cols - 1]
                body = [self._fit(ln, cols - 2) for ln in lines[top:end]]
                body += [""] * (avail - len(body))
                frame = ["\x1b[7m" + bar + "\x1b[0m" if p.on else bar] + body + \
                    ["\x1b[7m" + foot + " " * max(0, cols - 1 - len(foot)) + "\x1b[0m"
                     if p.on else foot]
                out.write("\x1b[H" + "\n".join(ln + "\x1b[K" for ln in frame) + "\x1b[J")
                self._scrollbar(2, avail, len(lines), avail, top, cols)
                out.flush()
                size = (cols, rows)
                while True:
                    k = self.key(0.3)
                    if k is not None:
                        break
                    try:
                        sz = os.get_terminal_size(sys.__stdout__.fileno())
                        if (max(40, sz.columns), max(8, sz.lines)) != size:
                            break
                    except OSError:
                        pass
                if k in ("esc", "q", "enter", "ctrl-c", "ctrl-d"):
                    return
                if k in ("up", "k"):
                    top -= 1
                elif k in ("down", "j"):
                    top += 1
                elif k in ("pgup", "b"):
                    top -= avail - 1
                elif k in ("pgdn", " ", "f"):
                    top += avail - 1
                elif k in ("home", "g"):
                    top = 0
                elif k in ("end", "G"):
                    top = len(lines)
        finally:
            out.write("\x1b[?25h\x1b[?1049l")
            out.flush()

    def _scrollbar(self, base_row, nrows, total, visible, top, cols):
        if total <= visible or nrows <= 0:
            return
        thumb = max(1, min(nrows, round(nrows * visible / total)))
        span = nrows - thumb
        denom = max(1, total - visible)
        tstart = max(0, min(span, round(span * (top / denom))))
        on = self.pal.on
        parts = ["\x1b[?7l"]
        for r in range(nrows):
            hit = tstart <= r < tstart + thumb
            g = "█" if hit else "│"
            if on:
                g = ("\x1b[36m" if hit else "\x1b[2m") + g + "\x1b[0m"
            parts.append("\x1b[%d;%dH%s" % (base_row + r, cols, g))
        parts.append("\x1b[?7h")
        sys.stdout.write("".join(parts))

    # ---- live views: scrolled, and what is typed is a grep ----------------------------
    def _follow_file(self, path, convert=None):
        """first() and more() of a file followed as it grows (and is rotated)."""
        st = {"f": None, "ino": None}

        def opened():
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                import stat as _st
                if not _st.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("not a plain file")
            except OSError:
                os.close(fd)
                raise
            return os.fdopen(fd, "r", encoding="utf-8", errors="replace")

        def conv(lines):
            if not convert:
                return lines
            out = []
            for ln in lines:
                x = convert(ln)
                if x is not None:
                    out.append(x)
            return out

        def first():
            try:
                f = opened()
            except OSError as e:
                return [self.pal.bad_line("%s cannot be read: %s" % (path, e))]
            st["f"] = f
            st["ino"] = os.fstat(f.fileno()).st_ino
            f.seek(0, 2)
            start = max(0, f.tell() - 2 * 1024 * 1024)
            f.seek(start)
            got = f.read().splitlines()
            if start and len(got) > 1:
                got = got[1:]
            return conv(got[-self.LIVE_KEEP:])

        def more():
            f = st["f"]
            if f is None:
                try:
                    st["f"] = opened()
                    st["ino"] = os.fstat(st["f"].fileno()).st_ino
                    f = st["f"]
                except OSError:
                    return []
            out = []
            while len(out) < 5000:
                ln = f.readline()
                if not ln:
                    break
                out.append(ln.rstrip("\n"))
            if not out:
                try:
                    if os.stat(str(path)).st_ino != st["ino"]:
                        f.close()
                        st["f"] = opened()
                        st["ino"] = os.fstat(st["f"].fileno()).st_ino
                except OSError:
                    pass
            return conv(out)

        def close():
            if st["f"]:
                st["f"].close()
        return first, more, close

    def live_log(self, what=""):
        path = self.cfg()["log_file"]
        first, more, close = self._follow_file(path)
        try:
            self.live_view("Live log  %s" % path, first, more, self._log_text, what)
        finally:
            close()

    def _name(self, ip):
        """A PTR name from the cache; an unknown one looked up in the background."""
        cache = self.cli._PTR
        if not ip or self.cli.NO_DNS:
            return ""
        if ip not in cache:
            cache[ip] = ""

            def one():
                try:
                    cache[ip] = socket.gethostbyaddr(ip)[0].rstrip(".")
                except (OSError, UnicodeError):
                    pass
            threading.Thread(target=one, daemon=True).start()
        return cache.get(ip, "")

    def _request_line(self, raw):
        """One line of requests.jsonl as the live view shows it."""
        p = self.pal
        try:
            e = json.loads(raw)
        except ValueError:
            return None
        a = e.get("action")
        if a == "AddPortMapping":
            res = e.get("result", "ok")
            word = ("renewed" if e.get("renew") else "new") if res == "ok" else res
        elif a == "DeletePortMapping":
            word = "deleted"
        elif a == "Expired":
            word = "expired"
        else:
            word = (a or "?").lower()
        tone = self.RESULT_TONES.get(word, "")
        fn = {"good": p.good, "bad": p.bad, "info": p.info, "dim": p.dim}.get(tone, str)
        t = (e.get("time") or "").replace("T", " ")[:19]
        client = str(e.get("client") or e.get("internal_client") or "")
        name = self._name(client)
        target = ""
        if e.get("internal_client") and e.get("internal_port"):
            target = "-> %s:%s" % (e["internal_client"], e["internal_port"])
        lease = e.get("lease")
        bits = [p.dim(t), fn(word.ljust(9)), p.bold(client) + (" " + p.dim("(" + name + ")") if name else ""),
                p.info("%s %s" % (e.get("protocol", ""), e.get("external_port", ""))), p.addr(target) if target else "",
                p.dim(("lease %ss" % lease) if lease else ("lease unlimited" if lease == 0 and a == "AddPortMapping" else "")),
                str(e.get("description") or "")]
        return " ".join(b for b in bits if b)

    def live_requests(self, what=""):
        path = self.cfg()["request_log"]
        first, more, close = self._follow_file(path, self._request_line)
        try:
            self.live_view("Live port requests  %s" % path, first, more, None, what)
        finally:
            close()

    def journal(self):
        """journalctl -u fake-igd -f, in the live view."""
        try:
            pr = subprocess.Popen(["journalctl", "-u", "fake-igd", "-f", "-n", "400", "--no-pager"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                  errors="replace")
        except OSError as e:
            self.page("journalctl", self.pal.bad_line(str(e)))
            return
        q = collections.deque()

        def pump():
            for ln in pr.stdout:
                q.append(ln.rstrip("\n"))
        threading.Thread(target=pump, daemon=True).start()

        def more():
            out = []
            while q:
                out.append(q.popleft())
            return out

        def paint(ln):
            m = re.match(r"^(\S+ +\d+ \S+ \S+ \S+: )(\w+) +(.*)$", ln)
            if m:
                return self.pal.dim(m.group(1)) + self._log_text("0000-00-00 00:00:00 %s %s" % (m.group(2), m.group(3)))[20:]
            return ln
        try:
            self.live_view("journalctl -u fake-igd -f", lambda: [], more, paint, "")
        finally:
            pr.terminate()
            try:
                pr.wait(3)
            except Exception:                           # noqa: BLE001
                pr.kill()

    @staticmethod
    def _grep(find):
        """What is typed as `grep -i` takes it: a test of one line."""
        if not find:
            return lambda s: True
        try:
            rx = re.compile(find, re.I)
            return lambda s: rx.search(s) is not None
        except (re.error, OverflowError, RecursionError):
            low = find.lower()
            return lambda s: low in s.lower()

    def _mark(self, coloured, find):
        """The hits of `find` shown reversed - in the text between the colours."""
        if not find or not self.pal.on:
            return coloured
        try:
            rx = re.compile(find, re.I)
        except (re.error, OverflowError, RecursionError):
            rx = re.compile(re.escape(find), re.I)
        out = []
        for part in re.split(r"(\x1b\[[0-9;?]*[A-Za-z])", coloured):
            if part.startswith("\x1b["):
                out.append(part)
            elif part:
                out.append(rx.sub(lambda m: "\x1b[7m" + m.group(0) + "\x1b[27m" if m.group(0) else "", part))
        return "".join(out)

    @staticmethod
    def _slice(line, start, width):
        """Columns start..start+width of `line` on the screen, its colours kept."""
        out, seen = [], 0
        end = start + width
        for part in re.split(r"(\x1b\[[0-9;?]*[A-Za-z])", line):
            if not part:
                continue
            if part.startswith("\x1b["):
                out.append(part)
                continue
            a, b = seen, seen + len(part)
            if b > start and a < end:
                out.append(part[max(0, start - a):max(0, end - a)])
            seen = b
        return "".join(out) + ("\x1b[0m" if "\x1b[" in line else "")

    def live_view(self, title, first, more, paint, find=""):
        """The live screen: `first()` the lines there are, `more()` those come since
        (asked a few times a second), `paint(line)` its colours."""
        p = self.pal
        if self._raw() is None or not sys.stdout.isatty():
            for ln in first() + more():
                print(ln)
            return
        import termios
        import tty
        fd = sys.stdin.fileno()
        was = termios.tcgetattr(fd)
        out = sys.stdout
        lines = []                       # (plain, coloured)

        def add(raw):
            for ln in raw:
                ln = term_safe(ln.expandtabs(8).replace("\r", ""))
                col = (paint(ln) if paint else ln) if p.on else self._plain_text(ln)
                lines.append((self._plain_text(col), col))
        add(first())
        test = self._grep(find)
        hits = [i for i, x in enumerate(lines) if test(x[0])]
        top, follow, xoff, new, dirty, size = 0, True, 0, 0, True, None
        tty.setcbreak(fd, termios.TCSANOW)
        out.write("\x1b[?1049h\x1b[?25l")
        try:
            while True:
                came = more()
                if came:
                    n0 = len(lines)
                    add(came)
                    got = [i for i in range(n0, len(lines)) if test(lines[i][0])]
                    hits += got
                    if not follow:
                        new += len(got)
                    if len(lines) > self.LIVE_KEEP * 1.25:
                        cut = len(lines) - self.LIVE_KEEP
                        gone = sum(1 for i in hits if i < cut)
                        del lines[:cut]
                        hits = [i - cut for i in hits if i >= cut]
                        top = max(0, top - gone)
                    dirty = dirty or bool(got)
                try:
                    sz = os.get_terminal_size(sys.__stdout__.fileno())
                    cols, rows = max(40, sz.columns), max(8, sz.lines)
                except OSError:
                    cols, rows = 100, 30
                if (cols, rows) != size:
                    size, dirty = (cols, rows), True
                avail = max(3, rows - 2)
                last = max(0, len(hits) - avail)
                if follow:
                    top = last
                top = max(0, min(top, last))
                if dirty:
                    end = min(len(hits), top + avail)
                    where = (" %d-%d of %d " % (top + 1, end, len(hits))) if hits else " 0 "
                    state = " following " if follow else (" PAUSED%s " % (
                        ", %d new below" % new if new else ""))
                    head = " %s " % title
                    gp = "  grep -i: %s_ " % find if find else "  type to grep "
                    right = state + where
                    bar = (head + gp)[:max(0, cols - len(right))]
                    bar = bar + " " * max(0, cols - len(bar) - len(right)) + right
                    foot = (" type: grep (any case)  Bksp  Ctrl+U clear   Up/Down PgUp/PgDn "
                            "Home  End: follow   Left/Right  Esc back ")[:cols - 1]
                    body = [self._slice(self._mark(lines[i][1], find), xoff, cols - 2)
                            for i in hits[top:end]]
                    if not hits:
                        body = ["", "   " + (p.dim('nothing with "%s" yet' % find) if find
                                             else p.dim("nothing yet"))]
                    body += [""] * (avail - len(body))
                    inv = (lambda t: "\x1b[7m" + t + "\x1b[0m") if p.on else (lambda t: t)
                    tone = "\x1b[33m" if (not follow and p.on) else ""
                    frame = [tone + inv(bar[:cols])] + body[:avail] + \
                        [inv(foot + " " * max(0, cols - 1 - len(foot)))]
                    out.write("\x1b[H" + "\n".join(ln + "\x1b[K" for ln in frame) + "\x1b[J")
                    self._scrollbar(2, avail, len(hits), avail, top, cols)
                    out.flush()
                    dirty = False
                k = self.key(0.25)
                if k is None:
                    continue
                dirty = True
                if k in ("esc", "ctrl-c", "ctrl-d"):
                    if find and k == "esc":
                        find = ""
                    else:
                        return
                elif k == "up":
                    follow, top = False, top - 1
                elif k == "down":
                    top += 1
                    follow = top >= last
                elif k == "pgup":
                    follow, top = False, top - (avail - 1)
                elif k == "pgdn":
                    top += avail - 1
                    follow = top >= last
                elif k == "home":
                    follow, top = False, 0
                elif k in ("end", "enter"):
                    follow, new = True, 0
                elif k == "left":
                    xoff = max(0, xoff - 20)
                    continue
                elif k == "right":
                    xoff += 20
                    continue
                elif k == "bs":
                    find = find[:-1]
                elif k == "ctrl-u":
                    find = ""
                elif k and len(k) == 1 and k.isprintable():
                    find += k
                else:
                    continue
                if k in ("bs", "ctrl-u", "esc") or (k and len(k) == 1 and k.isprintable()):
                    test = self._grep(find)
                    hits = [i for i, x in enumerate(lines) if test(x[0])]
                    follow, new = True, 0
                if follow:
                    new = 0
        finally:
            out.write("\x1b[?25h\x1b[?1049l")
            out.flush()
            termios.tcsetattr(fd, termios.TCSADRAIN, was)

    def _log_text(self, ln):
        return self.cli.log_text(ln, self.pal)

    def live(self, fn):
        self.go_plain(fn)

    # ---- keys and lines on the text screen ------------------------------------------
    def _getkey(self, win=None):
        c = self.curses
        src = win or self.scr
        k = src.getch()
        if k == -1:
            try:
                size = os.get_terminal_size(sys.__stdout__.fileno())
                if (size.lines, size.columns) != self.scr.getmaxyx():
                    c.resizeterm(size.lines, size.columns)
                    self.scr.clear()
                    return "resize"
            except (OSError, ValueError, c.error):
                pass
            return None
        if k == 27:
            src.nodelay(True)
            k2 = src.getch()
            if k2 in (ord("["), ord("O")):
                seq = ""
                while True:
                    k3 = src.getch()
                    if k3 == -1:
                        break
                    seq += chr(k3)
                    if chr(k3).isalpha() or chr(k3) == "~":
                        break
                src.nodelay(False)
                return {"A": "up", "B": "down", "C": "right", "D": "left", "H": "home",
                        "F": "end", "5~": "pgup", "6~": "pgdn", "1~": "home", "4~": "end",
                        "7~": "home", "8~": "end", "3~": "del"}.get(seq, None)
            if k2 != -1:
                c.ungetch(k2)
            src.nodelay(False)
            return "esc"
        named = {c.KEY_UP: "up", c.KEY_DOWN: "down", c.KEY_LEFT: "left", c.KEY_RIGHT: "right",
                 c.KEY_PPAGE: "pgup", c.KEY_NPAGE: "pgdn", c.KEY_HOME: "home", c.KEY_END: "end",
                 c.KEY_ENTER: "enter", 10: "enter", 13: "enter", c.KEY_BACKSPACE: "bs",
                 127: "bs", 8: "bs", c.KEY_DC: "del", c.KEY_RESIZE: "resize", 21: "ctrl-u",
                 9: "tab"}
        if k in named:
            if k == c.KEY_RESIZE:
                try:
                    c.update_lines_cols()
                except Exception:                       # noqa: BLE001
                    pass
            return named[k]
        if 0xc0 <= k < 0xf8:
            raw = bytearray([k])
            src.nodelay(True)
            try:
                for _ in range(1 if k < 0xe0 else 2 if k < 0xf0 else 3):
                    k2 = src.getch()
                    if not 0x80 <= k2 < 0xc0:
                        break
                    raw.append(k2)
            finally:
                src.nodelay(False)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if 32 <= k < 0x110000:
            try:
                return chr(k)
            except ValueError:
                return None
        return None

    def _line_in(self, y, prompt, text, secret=False, win=None, x=1, width=None):
        c = self.curses
        scr = win or self.scr
        pos = len(text)
        try:
            c.curs_set(1)
        except Exception:                               # noqa: BLE001
            pass
        try:
            while True:
                h, w = scr.getmaxyx()
                room = (width or (w - x - len(prompt) - 2))
                shown = ("*" * len(text)) if secret else text
                start = max(0, pos - room + 1)
                try:
                    scr.addstr(y, x, prompt, self.A["key"])
                    scr.addstr(y, x + len(prompt), shown[start:start + room].ljust(room), self.curses.A_UNDERLINE)
                    scr.move(y, x + len(prompt) + pos - start)
                except c.error:
                    pass
                scr.refresh()
                scr.timeout(500)
                k = self._getkey(scr)
                if k == "enter":
                    return text
                if k == "esc":
                    return None
                if k == "bs" and pos > 0:
                    text = text[:pos - 1] + text[pos:]
                    pos -= 1
                elif k == "del":
                    text = text[:pos] + text[pos + 1:]
                elif k == "left":
                    pos = max(0, pos - 1)
                elif k == "right":
                    pos = min(len(text), pos + 1)
                elif k == "home":
                    pos = 0
                elif k == "end":
                    pos = len(text)
                elif k == "ctrl-u":
                    text, pos = "", 0
                elif k and len(k) == 1 and k.isprintable():
                    text = text[:pos] + k + text[pos:]
                    pos += 1
        finally:
            try:
                c.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass

    def _box(self, win, h, w):
        c, A = self.curses, self.A
        if "utf" in (sys.stdout.encoding or "").lower():
            hz, vt, tl, tr, bl, br = "─", "│", "┌", "┐", "└", "┘"
        else:
            hz, vt, tl, tr, bl, br = "-", "|", "+", "+", "+", "+"
        for y, line in ((0, tl + hz * (w - 2) + tr), (h - 1, bl + hz * (w - 2) + br)):
            try:
                win.addstr(y, 0, line, A["key"])
            except c.error:
                pass
        for y in range(1, h - 1):
            for x in (0, w - 1):
                try:
                    win.addstr(y, x, vt, A["key"])
                except c.error:
                    pass

    # ---- windows over the menu ------------------------------------------------------
    def _fresh(self):
        if self.plain:
            self.curses.reset_prog_mode()
            self.scr.clear()
            self.plain = False
            self.st_now = True

    def _under(self):
        self._fresh()
        fn = self.backdrop
        if fn:
            try:
                fn()
                return
            except Exception:                           # noqa: BLE001
                pass
        self.scr.noutrefresh()

    def _window(self, want_h, want_w):
        c = self.curses
        h, w = self.scr.getmaxyx()
        ww = max(20, min(want_w, w - 2))
        wh = max(5, min(want_h, h - 2))
        win = c.newwin(wh, ww, max(0, (h - wh) // 2), max(0, (w - ww) // 2))
        win.keypad(True)
        win.erase()
        self._box(win, wh, ww)
        return win, wh, ww

    def _wput(self, win, y, x, text, attr=0, width=None):
        try:
            wh, ww = win.getmaxyx()
            if 0 < y < wh - 1 and x < ww - 1:
                win.addnstr(y, x, str(text), max(0, (width or ww) - (x if width is None else 0)
                                                 - (1 if width is None else 0)), attr)
        except self.curses.error:
            pass

    def _wkey(self, win, wait=500):
        win.timeout(wait)
        return self._getkey(win)

    def _wrap(self, text, width):
        out = []
        for para in str(text or "").split("\n"):
            out += textwrap.wrap(para, max(10, width)) or [""]
        return out

    @staticmethod
    def _plain_text(text):
        return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", str(text or ""))

    def note(self, title, text, tone=""):
        """Words in a window; any of Enter, Esc, q or Space closes it."""
        A = self.A
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(30, min(100, w - 4))
            lines = self._wrap(text, ww - 4)[:max(1, h - 6)]
            win, wh, ww = self._window(len(lines) + 4, max(len(title) + 8, min(
                ww, max(len(x) for x in lines + [""]) + 6, ww)))
            try:
                win.addnstr(0, 2, " %s " % title, ww - 4, A["title"])
            except self.curses.error:
                pass
            for i, ln in enumerate(lines):
                self._wput(win, 1 + i, 2, ln, A.get(tone, 0) if tone else 0)
            self._wput(win, wh - 2, 2, "Enter or Esc - back", A["dim"])
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ("enter", "esc", "q", " "):
                return

    def working(self, words):
        self._under()
        win, wh, ww = self._window(3, min(100, len(words) + 6))
        self._wput(win, 1, 2, words, self.A["dim"])
        win.noutrefresh()
        self.curses.doupdate()

    def confirm(self, title, words, yes="Yes", no="No", danger=False):
        """Yes or no, chosen by the arrows (or y / n); No unless chosen."""
        A = self.A
        pick = 1
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(40, min(80, w - 4))
            lines = self._wrap(words, ww - 4)[:max(1, h - 8)]
            win, wh, ww = self._window(len(lines) + 5, ww)
            try:
                win.addnstr(0, 2, " %s " % title, ww - 4, A["bad"] if danger else A["title"])
            except self.curses.error:
                pass
            for i, ln in enumerate(lines):
                self._wput(win, 1 + i, 2, ln)
            x = 2
            y = wh - 2
            for i, lab in enumerate((yes, no)):
                lab = "  %s  " % lab
                self._wput(win, y, x, lab, (A["bad"] if danger and i == 0 else A["sel"]) if i == pick else A["key"])
                x += len(lab) + 2
            self._wput(win, y, x + 2, "Left/Right  Enter  Esc", A["dim"])
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ("esc", "n", "N"):
                return False
            if k in ("y", "Y"):
                return True
            if k in ("left", "right", "tab", "up", "down"):
                pick = 1 - pick
            elif k == "enter":
                return pick == 0

    def choose(self, title, options, words="", cur=0):
        """One of `options` ([(value, words)]), picked by the arrows; Esc None."""
        A = self.A
        if not options:
            return None
        sel = max(0, min(cur or 0, len(options) - 1))
        top = 0
        typed, typed_at = "", 0.0
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = min(90, w - 4, max(36, max(len(o[1]) for o in options) + 12,
                                    len(title) + 8, len(words) + 6 if words else 0))
            head = self._wrap(words, ww - 4) if words else []
            room = max(1, min(len(options), h - 6 - len(head)))
            win, wh, ww = self._window(room + len(head) + (4 if head else 3), ww)
            try:
                win.addnstr(0, 2, " %s " % title, ww - 4, A["title"])
            except self.curses.error:
                pass
            y = 1
            for ln in head:
                self._wput(win, y, 2, ln, A["dim"])
                y += 1
            if head:
                y += 1
            if sel < top:
                top = sel
            if sel >= top + room:
                top = sel - room + 1
            for n, (val, lab) in enumerate(options[top:top + room]):
                i = top + n
                line = " %2d  %s" % (i + 1, lab)
                if i == sel:
                    self._wput(win, y + n, 2, line.ljust(ww - 5), A["sel"])
                else:
                    self._wput(win, y + n, 2, " %2d" % (i + 1), A["key"])
                    self._wput(win, y + n, 7, lab)
            if len(options) > room:
                self._wbar(win, y, room, len(options), top, ww - 2)
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ("esc", "left", "q"):
                return None
            if k == "up":
                sel = (sel - 1) % len(options)
            elif k in ("down", "tab"):
                sel = (sel + 1) % len(options)
            elif k in ("home", "pgup"):
                sel = 0
            elif k in ("end", "pgdn"):
                sel = len(options) - 1
            elif k and k.isdigit():
                now = time.time()
                typed = (typed if now - typed_at < 1.0 else "") + k
                typed_at = now
                n = int(typed) - 1
                if 0 <= n < len(options):
                    sel = n
                    if not any(str(i + 1).startswith(typed) and str(i + 1) != typed for i in range(len(options))):
                        return options[sel][0]
                else:
                    typed = ""
            elif k in ("enter", "right"):
                return options[sel][0]

    def _wbar(self, win, y0, rows, total, top, x):
        A = self.A
        if total <= rows:
            return
        thumb = max(1, min(rows, round(rows * rows / total)))
        tstart = max(0, min(rows - thumb, round((rows - thumb) * top / max(1, total - rows))))
        utf = "utf" in (sys.stdout.encoding or "").lower()
        for r in range(rows):
            hit = tstart <= r < tstart + thumb
            try:
                win.addstr(y0 + r, x, ("█" if hit else "│") if utf else ("#" if hit else "|"),
                           A["key"] if hit else A["dim"])
            except self.curses.error:
                pass

    def form(self, title, fields, words="", check=None, ok="OK"):
        """Questions in one window. fields: [{'key', 'label', 'kind': 'text' | 'secret' |
        'choice' | 'number', 'value', 'options': [(value, words)], 'need', 'range',
        'help', 'check': fn(value, values), 'when': fn(values)}]. Up/Down (Tab) move,
        a choice is changed by Left/Right, Enter checks them all and gives {key: value};
        Esc gives None. A secret shows a star for each character."""
        c, A = self.curses, self.A
        vals, pos = {}, {}
        for f in fields:
            f.setdefault("kind", "text")
            if f["kind"] == "choice":
                opts = [o[0] for o in f["options"]]
                vals[f["key"]] = f.get("value") if f.get("value") in opts else opts[0]
            else:
                vals[f["key"]] = str(f.get("value") if f.get("value") is not None else "")
            pos[f["key"]] = len(vals[f["key"]]) if f["kind"] != "choice" else 0
        at, err, err_at = 0, "", None
        try:
            c.curs_set(1)
        except Exception:                               # noqa: BLE001
            pass
        try:
            while True:
                shown = [f for f in fields if not f.get("when") or f["when"](vals)]
                at = max(0, min(at, len(shown) - 1))
                f = shown[at]
                self._under()
                h, w = self.scr.getmaxyx()
                ww = max(50, min(100, w - 4))
                head = self._wrap(words, ww - 4) if words else []
                labw = min(30, max(len(x.get("label") or x["key"]) for x in shown) + 1)
                fieldw = max(8, ww - labw - 7)
                helps = self._wrap(f.get("help") or "", ww - 4) if f.get("help") else []
                helps = helps[:4]
                wh = len(head) + (1 if head else 0) + len(shown) + 2 + 4 + 1
                win, wh, ww = self._window(wh, ww)
                try:
                    win.addnstr(0, 2, " %s " % title, ww - 4, A["title"])
                except c.error:
                    pass
                y = 1
                for ln in head:
                    self._wput(win, y, 2, ln, A["dim"])
                    y += 1
                if head:
                    y += 1
                cursor = None
                for i, x in enumerate(shown):
                    lab = (x.get("label") or x["key"])[:labw - 1]
                    here = i == at
                    self._wput(win, y, 2, lab.rjust(labw), A["key"] if here else 0)
                    vx = 3 + labw + 1
                    v = vals[x["key"]]
                    if x["kind"] == "choice":
                        words_ = dict(x["options"]).get(v, v)
                        txt = ("< %s >" % words_) if here else ("  %s" % words_)
                        self._wput(win, y, vx, txt[:fieldw], A["sel"] if here else A["ok"])
                    else:
                        t = ("*" * len(v)) if x["kind"] == "secret" else v
                        p = pos[x["key"]] if here else len(t)
                        start = max(0, p - fieldw + 1)
                        self._wput(win, y, vx, t[start:start + fieldw].ljust(fieldw),
                                   c.A_UNDERLINE | (A["key"] if here else 0))
                        if here:
                            cursor = (y, vx + p - start)
                    if err and err_at == x["key"]:
                        self._wput(win, y, ww - 3, "!", A["bad"])
                    y += 1
                y += 1
                for ln in helps:
                    self._wput(win, y, 2, ln, A["dim"])
                    y += 1
                if err:
                    self._wput(win, wh - 2, 2, err[:ww - 4], A["bad"])
                else:
                    self._wput(win, wh - 2, 2, ("Up/Down field   " + ("Left/Right choose   "
                               if any(x["kind"] == "choice" for x in shown) else "") +
                               "Enter %s   Esc cancel" % ok)[:ww - 4], A["dim"])
                if cursor:
                    try:
                        c.curs_set(1)
                        win.move(*cursor)
                    except c.error:
                        pass
                else:
                    try:
                        c.curs_set(0)
                    except Exception:                   # noqa: BLE001
                        pass
                win.noutrefresh()
                c.doupdate()
                k = self._wkey(win)
                if k is None or k == "resize":
                    continue
                key, kind = f["key"], f["kind"]
                if k == "esc":
                    return None
                if k == "up":
                    at = (at - 1) % len(shown)
                elif k in ("down", "tab"):
                    at = (at + 1) % len(shown)
                elif k == "enter":
                    err, err_at = "", None
                    for i, x in enumerate(shown):
                        v = vals[x["key"]]
                        if x["kind"] != "choice":
                            v = v.strip() if x["kind"] != "secret" else v
                            vals[x["key"]] = v
                        bad = None
                        if x.get("need") and v == "":
                            bad = "%s - it is needed" % (x.get("label") or x["key"])
                        elif x["kind"] == "number" and v != "":
                            try:
                                n = int(v)
                                lo, hi = x.get("range") or (None, None)
                                if (lo is not None and n < lo) or (hi is not None and n > hi):
                                    bad = "%s - a whole number from %s to %s" % (x.get("label") or x["key"], lo, hi)
                            except ValueError:
                                bad = "%s - a whole number" % (x.get("label") or x["key"])
                        if not bad and x.get("check") and v != "":
                            try:
                                bad = x["check"](v, vals)
                            except Exception as e:              # noqa: BLE001
                                bad = str(e)
                        if bad:
                            err, err_at, at = bad, x["key"], i
                            break
                    if err:
                        continue
                    got = {x["key"]: vals[x["key"]] for x in shown}
                    if check:
                        bad = check(got)
                        if bad:
                            err, err_at = (bad if isinstance(bad, tuple) else (bad, None))
                            if err_at:
                                at = next((i for i, x in enumerate(shown) if x["key"] == err_at), at)
                            continue
                    return got
                elif kind == "choice":
                    opts = [o[0] for o in f["options"]]
                    i = opts.index(vals[key]) if vals[key] in opts else 0
                    if k == "left":
                        vals[key] = opts[(i - 1) % len(opts)]
                    elif k in ("right", " "):
                        vals[key] = opts[(i + 1) % len(opts)]
                    err = ""
                else:
                    t, p = vals[key], pos[key]
                    if k == "bs" and p > 0:
                        t, p = t[:p - 1] + t[p:], p - 1
                    elif k == "del":
                        t = t[:p] + t[p + 1:]
                    elif k == "left":
                        p = max(0, p - 1)
                    elif k == "right":
                        p = min(len(t), p + 1)
                    elif k == "home":
                        p = 0
                    elif k == "end":
                        p = len(t)
                    elif k == "ctrl-u":
                        t, p = "", 0
                    elif k and len(k) == 1 and k.isprintable():
                        if kind == "number" and not (k.isdigit() or (k == "-" and p == 0)):
                            continue
                        t, p = t[:p] + k + t[p:], p + 1
                    else:
                        continue
                    vals[key], pos[key] = t, p
                    if err_at == key:
                        err, err_at = "", None
        finally:
            try:
                c.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass

    def ask_one(self, title, label, value="", help_="", need=True, secret=False, check=None):
        got = self.form(title, [{"key": "v", "label": label, "value": value, "help": help_,
                                 "need": need, "kind": "secret" if secret else "text", "check": check}])
        return None if got is None else got["v"]

    def pick(self, title, load, cols, act=None, empty="nothing here", words=""):
        """A list to scroll with the arrows: `load()` gives its rows (asked again after
        something was done to one), `cols` [(heading, fn(row), width, tone fn(row) or None)].
        Enter calls `act(row)`; / finds. Esc back, q leaves the console."""
        c, A = self.curses, self.A
        rows = load() or []
        sel, top, find, said, said_bad = 0, 0, "", "", False
        while True:
            self._fresh()
            h, w = self.scr.getmaxyx()
            seen = [r for r in rows if not find or find.lower() in " ".join(
                str(fn(r)) for _h, fn, _w, _t in cols).lower()]
            sel = max(0, min(sel, len(seen) - 1))
            avail = max(3, h - 5 - (1 if words else 0))
            if sel < top:
                top = sel
            if sel >= top + avail:
                top = sel - avail + 1
            top = max(0, min(top, max(0, len(seen) - avail)))
            ws = [cw for _h, _f, cw, _t in cols]
            fixed = sum(x + 2 for x in ws[:-1])
            ws[-1] = max(8, min(ws[-1] or 200, w - 4 - fixed))

            def paint(_title=title, _seen=seen, _top=top, _sel=sel, _ws=ws, _avail=avail):
                self.scr.erase()
                self._put(0, 0, " " * w, A["head"])
                self._put(0, 0, " upnp %s  %s " % (self.VERSION, _title), A["head"] | c.A_BOLD)
                right = " %d%s " % (len(_seen), (' of %d, with "%s"' % (len(rows), find)) if find else "")
                self._put(0, max(0, w - len(right) - 1), right, A["head"])
                y = 1
                if words:
                    self._put(y, 1, words[:w - 2], A["dim"])
                    y += 1
                x = 2
                for (hd, _f, _w, _t), cw in zip(cols, _ws):
                    self._put(y + 1, x, hd[:cw], A["key"])
                    x += cw + 2
                y += 2
                if not _seen:
                    self._put(y + 1, 4, empty if not find else 'nothing with "%s"' % find, A["dim"])
                for n, r in enumerate(_seen[_top:_top + _avail]):
                    i = _top + n
                    x = 2
                    if i == _sel:
                        self._put(y + n, 1, " " * (w - 3), A["sel"])
                    for (hd, fn, _w, tone), cw in zip(cols, _ws):
                        try:
                            v = str(fn(r))
                        except Exception:               # noqa: BLE001
                            v = "?"
                        attr = A["sel"] if i == _sel else (A.get(tone(r) or "", 0) if tone else 0)
                        self._put(y + n, x, v[:cw], attr)
                        x += cw + 2
                if len(_seen) > _avail:
                    thumb = max(1, min(_avail, round(_avail * _avail / len(_seen))))
                    ts = max(0, min(_avail - thumb, round((_avail - thumb) * _top / max(1, len(_seen) - _avail))))
                    utf = "utf" in (sys.stdout.encoding or "").lower()
                    for r_ in range(_avail):
                        hit = ts <= r_ < ts + thumb
                        self._put(y + r_, w - 1, ("█" if hit else "│") if utf else ("#" if hit else "|"),
                                  A["key"] if hit else A["dim"])
                if said:
                    self._put(h - 2, 1, said[:w - 2], A["bad"] if said_bad else A["ok"])
                help_ = " Up/Down PgUp/PgDn Home/End move   Enter %s   / find   Esc back " % (
                    "what to do with it" if act else "look")
                self._put(h - 1, 0, " " * (w - 1), A["head"])
                self._put(h - 1, 0, help_[:w - 1], A["head"])
                self.scr.noutrefresh()
            self.backdrop = paint
            paint()
            c.doupdate()
            self.scr.timeout(500)
            k = self._getkey()
            if k is None:
                continue
            said = ""
            if k == "esc":
                if find:
                    find = ""
                    continue
                return None
            if k == "q":
                return "quit"
            if k in ("up", "down", "pgup", "pgdn", "home", "end"):
                sel = {"up": sel - 1, "down": sel + 1, "pgup": sel - (avail - 1),
                       "pgdn": sel + (avail - 1), "home": 0, "end": len(seen) - 1}[k]
            elif k == "/":
                got = self.ask_one("Find", "with the words", find, need=False,
                                   help_="Only the rows with these words in them stay; Esc in the list shows them all again.")
                if got is not None:
                    find, sel, top = got, 0, 0
            elif k in ("enter", "right") and seen and act:
                r = act(seen[sel])
                if r == "quit":
                    return "quit"
                if isinstance(r, tuple):
                    said, said_bad = r
                rows = load() or []

    def act(self, *args, env=None, title=None, quiet_ok=None):
        """`upnp ARGS` run: a short answer in a window, a long one on a screen of its own."""
        shown = "$ upnp " + " ".join(self._quote(a) for a in args)
        return self.act_argv(self.argv(*args), title or shown, env=env, quiet_ok=quiet_ok)

    def act_argv(self, argv, title, env=None, quiet_ok=None):
        self.working("working…  " + title)
        text, rc = self.capture(argv, env=env)
        plain = self._plain_text(text).rstrip()
        if rc == 0 and not plain and quiet_ok:
            plain = text = quiet_ok
        h, w = self.scr.getmaxyx()
        lines = self._wrap(plain, max(30, min(100, w - 4)) - 4)
        if len(lines) <= max(3, min(14, h - 8)):
            self.note(title if rc == 0 else "%s - it ended with %d" % (title, rc),
                      plain or "(it said nothing)", "" if rc == 0 else "bad")
        else:
            if rc not in (0, None):
                text += "\n" + self.pal.dim("(it ended with %d)" % rc)
            self.go_plain(lambda: self.page(title, text))
        self.st_now = True
        return rc

    @staticmethod
    def _when(ts):
        if not ts:
            return "-"
        return str(ts).replace("T", " ")[:16]

    def details(self, title, row, skip=()):
        lines = []
        for k, v in row.items():
            if k in skip or v in (None, "", [], {}):
                continue
            if isinstance(v, (list, dict)):
                v = json.dumps(v, default=str, ensure_ascii=False)
            elif k in ("expires_at",) and isinstance(v, (int, float)):
                v = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v))
            lines.append("%-16s %s" % (k, v))
        h, w = self.scr.getmaxyx()
        if len(lines) <= h - 8:
            self.note(title, "\n".join(lines))
        else:
            self.go_plain(lambda: self.page(title, "\n".join(lines)))

    # ---- 1 status and checks --------------------------------------------------------
    def m_status(self):
        def test_add():
            got = self.form("Test with a port request", [
                {"key": "port", "label": "port", "kind": "number", "value": "40000", "range": (1, 65535), "need": True},
                {"key": "proto", "label": "protocol", "kind": "choice", "options": [("udp", "UDP"), ("tcp", "TCP")]}],
                "Sends an AddPortMapping as the PS5 would and deletes it again. It is logged with the "
                "description 'upnp-cli-test' and left out of the reports.")
            if got:
                self.act("test", "--add", "%s/%s" % (got["port"], got["proto"]))
        return self.sub("Status and checks", [
            ("1", "Status", lambda: self.act("status")),
            ("2", "Test fake-igd as a UPnP client (as the PS5 does)", lambda: self.act("test")),
            ("3", "Test with a port request", test_add),
            ("4", "Every UPnP device on the network", lambda: self.act("test", "--st", "ssdp:all", "--timeout", "5")),
            ("5", "A test notification (ntfy)", lambda: self.act("notify-test")),
            ("6", "What the host firewall needs", lambda: self.act("firewall")),
        ])

    # ---- 2, 3 live views ------------------------------------------------------------
    def m_live_log(self):
        self.live(lambda: self.live_log(""))

    def m_live_requests(self):
        self.live(lambda: self.live_requests(""))

    # ---- 4 ports, 5 clients, 6 mappings -----------------------------------------------
    @staticmethod
    def _results(r):
        res = r.get("results") or {}
        return ", ".join("%s×%d" % (k, n) for k, n in res.items())

    def _rules_form(self, title, words, client="", port=None):
        got = self.form(title, [
            {"key": "format", "label": "format", "kind": "choice",
             "options": [("iptables", "iptables"), ("nft", "nftables"), ("mikrotik", "MikroTik"),
                         ("firewalld", "firewalld")]},
            {"key": "wan", "label": "WAN interface / zone", "help":
             "The router's internet side: eth0 (iptables, nft), the in-interface (MikroTik, e.g. "
             "ether1) or the zone (firewalld, e.g. external). Empty: eth0 / WAN / external."},
            {"key": "proto", "label": "protocol", "kind": "choice",
             "options": [("", "TCP and UDP"), ("udp", "UDP only"), ("tcp", "TCP only")]},
            {"key": "min", "label": "asked at least", "kind": "number", "value": "1", "range": (1, 100000),
             "need": True, "help": "Ports asked for fewer times are left out (2: no one-off ports)."},
        ], words)
        if not got:
            return
        args = ["dnat", "--format", got["format"], "--min-count", got["min"]]
        if got["wan"]:
            args += ["--wan", got["wan"]]
        if got["proto"]:
            args += ["--proto", got["proto"]]
        if client:
            args += ["--client", client]
        if port:
            args += ["--port", port]
        self.act(*args)

    def m_ports(self):
        def load():
            return self.out("ports") or []

        def act(r):
            what = self.choose("%s %s of %s" % (r.get("protocol"), r.get("port"), r.get("client")), [
                ("show", "Show it all"),
                ("rule", "The rule for the router for this port"),
                ("client", "Every port of %s" % r.get("client")),
                ("crules", "The rules for the router for %s" % r.get("client")),
            ])
            if what == "show":
                self.details("%s %s" % (r.get("protocol"), r.get("port")), r)
            elif what == "rule":
                self._rules_form("The rule for %s %s" % (r.get("protocol"), r.get("port")), "",
                                 r.get("client"), r.get("port"))
            elif what == "client":
                self.act("ports", "--client", r.get("client"))
            elif what == "crules":
                self._rules_form("The rules for %s" % r.get("client"), "", r.get("client"))
        return self.pick("Requested ports", load, [
            ("PROTO", lambda r: r.get("protocol"), 5, lambda r: "key"),
            ("PORT", lambda r: r.get("port"), 6, None),
            ("CLIENT", lambda r: r.get("client"), 15, None),
            ("NAME", lambda r: r.get("name") or "", 18, lambda r: "dim"),
            ("COUNT", lambda r: r.get("count"), 5, None),
            ("LAST", lambda r: self._when(r.get("last")), 16, lambda r: "dim"),
            ("RESULT", self._results, 10, lambda r: "ok" if set((r.get("results") or {})) == {"ok"} else "warn"),
            ("DESCRIPTION", lambda r: ", ".join(r.get("descriptions") or []), 0, None),
        ], act, empty="no port requests yet - run a connection test, a game or party chat on the PS5")

    def m_clients(self):
        def load():
            return self.out("clients") or []

        def act(r):
            ip = r.get("client")
            what = self.choose("%s%s" % (ip, (" (%s)" % r["name"]) if r.get("name") else ""), [
                ("show", "Show it all"),
                ("ports", "Its ports"),
                ("rules", "The rules for the router for it"),
                ("only", "Answer only this client (allowed_clients)"),
            ])
            if what == "show":
                self.details(ip, r)
            elif what == "ports":
                self.act("ports", "--client", ip)
            elif what == "rules":
                self._rules_form("The rules for %s" % ip, "", ip)
            elif what == "only":
                if self.confirm("Answer only %s" % ip, "fake-igd will ignore every other device "
                                "(allowed_clients = %s). The service is restarted." % ip, "Only this one"):
                    self.act("config", "set", "allowed_clients", ip)
        return self.pick("Clients", load, [
            ("CLIENT", lambda r: r.get("client"), 15, lambda r: "key"),
            ("NAME", lambda r: r.get("name") or "", 24, lambda r: "dim"),
            ("SEARCHES", lambda r: r.get("searches"), 8, None),
            ("REQUESTS", lambda r: r.get("requests"), 8, None),
            ("PORTS", lambda r: len(r.get("ports") or []), 5, lambda r: "ok" if r.get("ports") else "dim"),
            ("LAST SEEN", lambda r: self._when(r.get("last")), 16, lambda r: "dim"),
            ("PORT LIST", lambda r: ", ".join(r.get("ports") or []), 0, None),
        ], act, empty="no clients yet - nobody looked for a UPnP router")

    def m_mappings(self):
        def load():
            return self.out("mappings") or []

        def left(r):
            exp = r.get("expires_at")
            if not exp:
                return "unlimited"
            n = int(exp - time.time())
            return "expired" if n < 0 else "%ds" % n
        return self.pick("Current mappings", load, [
            ("PROTO", lambda r: r.get("protocol"), 5, lambda r: "key"),
            ("PORT", lambda r: r.get("external_port"), 6, None),
            ("TARGET", lambda r: "%s:%s" % (r.get("internal_client"), r.get("internal_port")), 21, None),
            ("NAME", lambda r: r.get("name") or "", 22, lambda r: "dim"),
            ("REMAINING", left, 9, None),
            ("ADDED", lambda r: self._when(r.get("added_at")), 16, lambda r: "dim"),
            ("DESCRIPTION", lambda r: r.get("description") or "", 0, None),
        ], lambda r: self.details("%s %s" % (r.get("protocol"), r.get("external_port")), r),
            empty="no mappings - they are kept only with mapping_response accept",
            words="What clients believe is open. Nothing is open on the router.")

    # ---- 7 settings -------------------------------------------------------------------
    def _settings_rows(self):
        cfg = self.cfg()
        out = []
        seen = set()
        for words, keys in self.cli.SETTING_GROUPS:
            out.append(("head", words))
            for k in keys:
                out.append(("set", self._setting(k, cfg)))
                seen.add(k)
        rest = [k for k in self.cli.DEFAULTS if k not in seen]
        if rest:
            out.append(("head", "Everything else"))
            out += [("set", self._setting(k, cfg)) for k in rest]
        return out

    def _setting(self, k, cfg):
        cli = self.cli
        return {"key": k, "name": k.replace("_", " "), "value": cfg.get(k), "default": cli.DEFAULTS[k],
                "source": "default" if cfg.get(k) == cli.DEFAULTS[k] else "config",
                "says": cli.KEY_HELP.get(k, ""), "secret": k in cli.SECRET_KEYS}

    def _kind(self, key):
        cli = self.cli
        d = cli.DEFAULTS.get(key)
        if isinstance(d, bool):
            return "switch", ["1", "0"]
        if key in cli.ALLOWED_VALUES:
            return "choice", list(cli.ALLOWED_VALUES[key])
        if isinstance(d, int):
            return "number", list(cli.NUMBER_RANGES.get(key, (0, 999999)))
        return "text", None

    def _shown(self, key, v):
        return self.cli.shown_value(key, v)

    def settings_tui(self):
        c, A = self.curses, self.A
        rows = self._settings_rows()
        sel = next(i for i, r in enumerate(rows) if r[0] == "set")
        top, said, said_bad, find = 0, "", False, ""
        while True:
            self._fresh()

            def paint():
                nonlocal top
                h, w = self.scr.getmaxyx()
                self.scr.erase()
                self._put(0, 0, " " * w, A["head"])
                self._put(0, 0, " upnp %s  Settings" % self.VERSION, A["head"] | c.A_BOLD)
                if find:
                    self._put(0, max(0, w - len(find) - 12), " find: %s " % find, A["head"])
                avail = max(3, h - 3)
                if sel < top:
                    top = sel
                if sel >= top + avail:
                    top = sel - avail + 1
                top = max(0, min(top, max(0, len(rows) - avail)))
                if top > 0 and rows[top - 1][0] == "head" and sel - top < avail - 1:
                    top -= 1
                namew = max(20, min(44, w // 3))
                valw = max(10, min(40, w - namew - 30))
                for n, r in enumerate(rows[top:top + avail]):
                    y = 1 + n
                    if r[0] == "head":
                        self._put(y, 1, r[1].upper(), A["key"])
                        continue
                    st = r[1]
                    val = self._shown(st["key"], st.get("value"))
                    line = "  %-*s %-*s %s" % (namew, st["name"][:namew], valw, val[:valw], st["key"])
                    if top + n == sel:
                        self._put(y, 0, line + " " * max(0, w - 2 - len(line)), A["sel"])
                    else:
                        self._put(y, 0, "  " + st["name"][:namew])
                        tone = A["dim"] if st.get("source") == "default" else A["ok"]
                        self._put(y, 3 + namew, val[:valw], tone)
                        self._put(y, 4 + namew + valw, st["key"], A["dim"])
                total = len(rows)
                if total > avail:
                    thumb = max(1, min(avail, round(avail * avail / total)))
                    tstart = max(0, min(avail - thumb, round((avail - thumb) * top / max(1, total - avail))))
                    utf = "utf" in (sys.stdout.encoding or "").lower()
                    for r in range(avail):
                        hit = tstart <= r < tstart + thumb
                        self._put(1 + r, w - 1, ("█" if hit else "│") if utf else ("#" if hit else "|"),
                                  A["key"] if hit else A["dim"])
                if said:
                    self._put(h - 2, 1, said[:w - 2], A["bad"] if said_bad else A["ok"])
                help_ = " Up/Down PgUp/PgDn Home/End move   Enter change   / find   Esc back "
                self._put(h - 1, 0, " " * (w - 1), A["head"])
                self._put(h - 1, 0, help_[:w - 1], A["head"])
                self.scr.noutrefresh()
                return h, avail
            self.backdrop = paint
            h, avail = paint()
            c.doupdate()
            self.scr.timeout(500)
            k = self._getkey()
            if k is None:
                continue
            said = ""
            sets = [i for i, r in enumerate(rows) if r[0] == "set"]
            if k == "esc":
                if find:
                    find = ""
                    continue
                return None
            if k == "q":
                return "quit"
            if k in ("up", "down", "pgup", "pgdn", "home", "end"):
                pos = sets.index(sel) if sel in sets else 0
                pos = {"up": pos - 1, "down": pos + 1, "pgup": pos - (avail - 2),
                       "pgdn": pos + (avail - 2), "home": 0, "end": len(sets) - 1}[k]
                sel = sets[max(0, min(len(sets) - 1, pos))]
            elif k == "/":
                find = self._line_in(h - 2, "Find (a word of its name or key): ", "") or ""
                if find:
                    hit = [i for i in sets if find.lower() in (rows[i][1]["name"] + " " + rows[i][1]["key"]).lower()]
                    if hit:
                        sel = hit[0]
                    else:
                        said, said_bad = 'nothing with "%s"' % find, True
            elif k == "n" and find:
                hit = [i for i in sets if i > sel and find.lower() in (
                    rows[i][1]["name"] + " " + rows[i][1]["key"]).lower()]
                if hit:
                    sel = hit[0]
            elif k == "enter":
                done = self._edit_one(rows[sel][1])
                if done:
                    said, said_bad = done
                    if not said_bad:
                        cur = rows[sel][1]["key"]
                        rows = self._settings_rows()
                        sel = next((i for i, r in enumerate(rows) if r[0] == "set" and r[1]["key"] == cur), sel)

    def _save(self, key, value, secret=False, restart=True):
        """`upnp config set KEY VALUE` - a secret by the environment, never on the command line.
        (words, bad)."""
        env = {"UPNP_VALUE": value} if secret else None
        args = ["config", "set", key, "@env" if secret else value]
        if not restart:
            args.append("--no-restart")
        out, rc = self.capture(self.argv(*args) + ["--no-color"], env=env)
        if rc != 0:
            return ((self._plain_text(out).strip().splitlines() or ["it was not saved"])[-1].lstrip("✘ "), True)
        self.st_now = True
        return ("%s = %s - saved%s" % (key, "(hidden)" if secret else (value or "(empty)"),
                                       "; the service was restarted" if restart else ""), False)

    def _edit_one(self, st):
        """The window to change one setting: what it is, what it may be, the value checked
        before it is saved. Returns (words, bad) or None when nothing was done."""
        c, A = self.curses, self.A
        key = st["key"]
        kind, shape = self._kind(key)
        secret = bool(st.get("secret"))
        v0 = st.get("value")
        cur = self._shown(key, v0)
        if kind == "switch":
            cur = "1" if v0 in (True, 1, "1", "on") else "0"
        if isinstance(v0, list):
            cur = ", ".join(v0)
        text = "" if secret else cur
        choice = shape.index(cur) if kind in ("switch", "choice") and cur in (shape or []) else 0
        err = ""
        helptext = str(st.get("says") or "")
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(40, min(96, w - 4))
            body = []
            for para in helptext.split("\n"):
                body += textwrap.wrap(para, ww - 4) or [""]
            facts = ["now: %s%s" % ("(hidden)" if (secret and v0) else (self._shown(key, v0) or "(empty)"),
                                    "" if st.get("source") == "default" else "   - in config.json"),
                     "as it comes: %s" % (self._shown(key, st.get("default")) or "(empty)")]
            if kind == "number":
                facts.append("a whole number from %s to %s" % (shape[0], shape[1]))
            elif kind == "choice":
                facts.append("one of: " + ", ".join(shape))
            if isinstance(st.get("default"), list):
                facts.append("several separated by commas; empty = none")
            if secret:
                facts.append("typed as stars; empty = it stays as it is; a single - clears it")
            facts.append("saved by upnp config set - the service is restarted")
            fixed = len(facts) + 9 + (len(shape) - 1 if kind == "choice" else 0)
            body = body[:max(1, h - 2 - fixed)]
            wh = min(h - 2, len(body) + fixed)
            win = c.newwin(wh, ww, max(0, (h - wh) // 2), max(0, (w - ww) // 2))
            win.keypad(True)
            win.erase()
            self._box(win, wh, ww)
            title = " %s " % st["name"]
            try:
                win.addnstr(0, 2, title, ww - 4, A["title"])
                win.addnstr(1, 2, key, ww - 4, A["dim"])
                y = 2
                for ln in body:
                    win.addnstr(y, 2, ln, ww - 4)
                    y += 1
                y += 1
                for f in facts:
                    win.addnstr(y, 2, f, ww - 4, A["dim"])
                    y += 1
                y += 1
                if err:
                    win.addnstr(wh - 2, 2, err[:ww - 4], ww - 4, A["bad"])
                else:
                    win.addnstr(wh - 2, 2, ("Left/Right choose" if kind in ("switch", "choice")
                                            else "type the new value") + "   Enter save   Esc cancel", ww - 4, A["dim"])
            except c.error:
                pass
            if kind in ("switch", "choice"):
                words = {"1": "on", "0": "off"} if kind == "switch" else {}
                x = 2
                for i, opt in enumerate(shape):
                    lab = " %s " % (words.get(opt) or opt)
                    if kind == "choice":
                        lab = (" > " if i == choice else "   ") + lab.strip() + " "
                        try:
                            win.addnstr(y, 2, lab, ww - 4, A["sel"] if i == choice else 0)
                        except c.error:
                            pass
                        y += 1
                        continue
                    try:
                        win.addnstr(y, x, lab, max(0, ww - x - 2), A["sel"] if i == choice else 0)
                    except c.error:
                        pass
                    x += len(lab) + 1
                win.noutrefresh()
                c.doupdate()
                win.timeout(500)
                k = self._getkey(win)
                if k == "esc":
                    return None
                if k in ("left", "up"):
                    choice = (choice - 1) % len(shape)
                elif k in ("right", "down", "tab", " "):
                    choice = (choice + 1) % len(shape)
                elif k == "enter":
                    value = shape[choice]
                else:
                    continue
                if k != "enter":
                    continue
                if kind == "switch":
                    value = "on" if value == "1" else "off"
            else:
                win.noutrefresh()
                c.doupdate()
                got = self._line_in(y, "value: ", text, secret=secret, win=win, x=2, width=ww - 14)
                if got is None:
                    return None
                text = got
                if secret and not got:
                    return ("nothing typed - %s stays as it was" % key, False)
                value = "" if (secret and got == "-") else got
            _v, bad = self.cli.check_value(key, value)
            if bad:
                err = bad
                continue
            self.working("working…  $ upnp config set %s %s" % (key, "(hidden)" if secret else self._quote(value)))
            return self._save(key, value, secret)

    def m_settings(self):
        def by_key():
            k = self.ask_one("Change one by its key", "key", help_="One of: " + ", ".join(self.cli.DEFAULTS),
                             check=lambda v, _: None if v in self.cli.DEFAULTS else "there is no setting %s" % v)
            if k:
                done = self._edit_one(self._setting(k, self.cfg()))
                if done:
                    self.note("Settings", done[0], "bad" if done[1] else "ok")
        return self.sub("Settings", [
            ("1", "Browse and change", self.settings_tui),
            ("2", "Change one by its key", by_key),
            ("3", "Show the configuration", lambda: self.act("config", "show")),
            ("4", "Check the configuration", lambda: self.act("config", "validate")),
        ])

    # ---- 8 router rules, 9 host firewall --------------------------------------------
    def m_dnat(self):
        self._rules_form("Rules for the router (DNAT)",
                         "Port forwarding for the real router, made from the ports the clients asked for. "
                         "They go on the router with the public IP - not on this server.")

    def m_firewall(self):
        got = self.form("Host firewall", [
            {"key": "format", "label": "format", "kind": "choice",
             "options": [("auto", "as the active service"), ("iptables", "iptables"), ("nft", "nftables"),
                         ("firewalld", "firewalld")]},
            {"key": "ifs", "label": "interfaces", "help":
             "Separated by spaces or commas. Empty: the interfaces fake-igd listens on."},
            {"key": "src", "label": "source subnets", "help": "e.g. 192.168.40.0/24. Empty: any source."},
        ], "What THIS server must let in: SSDP 1900/udp (multicast discovery) and the HTTP port "
           "(description + SOAP). fake-igd is IPv4 only - nothing for ip6tables.")
        if not got:
            return
        args = ["firewall", "--format", got["format"]]
        for i in re.split(r"[\s,]+", got["ifs"].strip()):
            if i:
                args += ["--interface", i]
        for s_ in re.split(r"[\s,]+", got["src"].strip()):
            if s_:
                args += ["--source", s_]
        self.act(*args)

    # ---- 10 notifications -----------------------------------------------------------
    def m_notify(self):
        def setup():
            cfg = self.cfg()
            auth = "token" if cfg.get("ntfy_token") else ("user" if cfg.get("ntfy_user") else "none")
            got = self.form("Notifications (ntfy)", [
                {"key": "url", "label": "topic URL", "value": cfg.get("ntfy_url") or "", "help":
                 "https://ntfy.sh/a-long-random-topic or your private server: https://ntfy.example.com/ps5. "
                 "Empty: no notifications.",
                 "check": lambda v, _: self.cli.check_value("ntfy_url", v)[1]},
                {"key": "auth", "label": "sign-in", "kind": "choice", "value": auth,
                 "options": [("none", "none (public topic)"), ("token", "access token"), ("user", "user and password")]},
                {"key": "token", "label": "access token", "kind": "secret", "when": lambda v: v["auth"] == "token",
                 "help": "tk_... made on your server (ntfy token add USER). Empty: the one kept stays."},
                {"key": "user", "label": "user", "value": cfg.get("ntfy_user") or "",
                 "when": lambda v: v["auth"] == "user", "need": True},
                {"key": "password", "label": "password", "kind": "secret", "when": lambda v: v["auth"] == "user",
                 "help": "Empty: the one kept stays."},
                {"key": "priority", "label": "priority", "kind": "choice", "value": str(cfg.get("ntfy_priority") or 3),
                 "options": [("1", "1 min"), ("2", "2 low"), ("3", "3 default"), ("4", "4 high"), ("5", "5 max")]},
                {"key": "tags", "label": "tags", "value": cfg.get("ntfy_tags") or "",
                 "help": "Comma-separated tags or emoji names, e.g. video_game."},
                {"key": "ca", "label": "CA certificate", "value": cfg.get("ntfy_ca_file") or "",
                 "help": "PEM file of a private server's own certificate authority. Empty: the system's CAs.",
                 "check": lambda v, _: self.cli.check_value("ntfy_ca_file", v)[1]},
            ], "Where notifications go. What is sent - each kind on or off - is item 5 of this menu. "
               "Each value is saved by upnp config set; the service is restarted once at the end.")
            if not got:
                return
            plan = [("ntfy_url", got["url"], False), ("ntfy_priority", got["priority"], False),
                    ("ntfy_tags", got["tags"], False), ("ntfy_ca_file", got["ca"], False)]
            if got["auth"] == "none":
                plan += [("ntfy_token", "", True), ("ntfy_user", "", False), ("ntfy_password", "", True)]
            elif got["auth"] == "token":
                plan += [("ntfy_user", "", False), ("ntfy_password", "", True)]
                if got.get("token"):
                    plan.append(("ntfy_token", got["token"], True))
            else:
                plan += [("ntfy_token", "", True), ("ntfy_user", got["user"], False)]
                if got.get("password"):
                    plan.append(("ntfy_password", got["password"], True))
            self.working("working…  $ upnp config set ntfy_… (%d values)" % len(plan))
            for k, v, sec in plan:
                words, bad = self._save(k, v, sec, restart=False)
                if bad:
                    self.note("Notifications (ntfy)", words, "bad")
                    return
            self.act_argv(["systemctl", "restart", "fake-igd"], "$ systemctl restart fake-igd",
                          quiet_ok="saved; the service was restarted")
            if got["url"] and self.confirm("Notifications (ntfy)", "Send a test notification now?", "Send"):
                self.act("notify-test")
        def kinds():
            import igd_ntfy as N
            cfg = self.cfg()
            out = [(k, "%-3s  %s" % ("on" if N.conf(cfg, k)["on"] else "off", w)) for k, _g, w, _s, _d in N.EVENTS]
            return out + [("alert:" + k, "%-3s  the alerts: %s" % ("on" if N.conf(cfg, "alert:" + k)["on"] else "off", w))
                          for k, w in N.ALERT_KINDS]

        def switch():
            import igd_ntfy as N
            k = self.choose("What is sent - on or off", kinds(), "Enter switches the kind picked. The UPnP events "
                            "restart fake-igd.service; the gateway's and the alerts' are the pages' API's.")
            if k:
                self.act("notify", "off" if N.conf(self.cfg(), k)["on"] else "on", k)

        def sample():
            k = self.choose("Send a sample", [x for x in kinds() if not x[0].startswith("alert:")],
                            "That kind's own wording sent now, marked as a sample.")
            if k:
                self.act("notify", "test", k)
        return self.sub("Notifications (ntfy)", [
            ("1", "Set up (ntfy.sh or a private server)", setup),
            ("2", "Send a test notification", lambda: self.act("notify-test")),
            ("3", "How it is set", lambda: self.act("status")),
            ("4", "What is sent (every kind, on or off)", lambda: self.act("notify", "list")),
            ("5", "Switch a kind on or off", switch),
            ("6", "Send a sample of a kind", sample),
        ])

    # ---- 11 the service ---------------------------------------------------------------
    def m_service(self):
        def restart():
            if self.confirm("Restart the service", "fake-igd does not answer for a second or two.", "Restart"):
                self.act_argv(["systemctl", "restart", "fake-igd"], "$ systemctl restart fake-igd",
                              quiet_ok="restarted")

        def start_stop():
            st = (self.st.get("service") or {}).get("state")
            if st == "active":
                if self.confirm("Stop the service", "fake-igd stops answering; the PS5 behaves as without "
                                "UPnP. It starts again at the next boot unless it is disabled.", "Stop", danger=True):
                    self.act_argv(["systemctl", "stop", "fake-igd"], "$ systemctl stop fake-igd", quiet_ok="stopped")
            else:
                self.act_argv(["systemctl", "start", "fake-igd"], "$ systemctl start fake-igd", quiet_ok="started")

        def mode():
            cur = self.cfg()["mode"]
            r = self.choose("Mode", [("active", "active - answer like a UPnP router, learn the ports"),
                                     ("passive", "passive - answer nobody, only log who looks for a router")],
                            "It is %s now." % cur, cur=0 if cur == "active" else 1)
            if r and r != cur:
                self.act("mode", r)

        def response():
            cur = self.cfg()["mapping_response"]
            r = self.choose("The answer to AddPortMapping", [
                ("accept", "accept - confirm it (nothing is opened); the most ports are learned"),
                ("reject", "reject - refuse with error 501; the PS5 behaves as without UPnP")],
                "It is %s now. Requests are logged either way." % cur, cur=0 if cur == "accept" else 1)
            if r and r != cur:
                self.act("response", r)

        def at_login():
            on = console_at_login()
            r = self.choose("The console at login", [
                ("on", "On - root sees this console first when signing in"),
                ("off", "Off - root gets the ordinary shell")],
                "It is %s now." % ("ON" if on else "off"), cur=0 if on else 1)
            if r and (r == "on") != on:
                try:
                    self.note("The console at login", console_at_login_set(r == "on"), "ok")
                except (SystemExit, OSError) as e:
                    self.note("The console at login", str(e), "bad")

        def at_login_users():
            users = console_users()
            r = self.choose("The console at login - normal users", [
                ("none", "Nobody - only root"),
                ("all", "Every normal user - through sudo, their own password"),
                ("these", "These users…")],
                "Now: %s. Without sudo rights a user gets a line saying so and the ordinary shell."
                % console_users_words(users), cur=1 if users == "*" else (2 if users else 0))
            if not r:
                return
            try:
                if r == "these":
                    typed = self.ask_one("The console at login", "The users, separated by spaces",
                                         " ".join(users) if isinstance(users, list) else "")
                    if typed is None:
                        return
                    got = console_users_parse(typed)
                else:
                    got = "*" if r == "all" else []
                self.note("The console at login", console_at_login_set(console_at_login(), got), "ok")
            except (SystemExit, ValueError, OSError) as e:
                self.note("The console at login", str(e), "bad")
        st = (self.st.get("service") or {}).get("state")
        return self.sub("The service", [
            ("1", "Its state", lambda: self.act_argv(
                ["systemctl", "status", "fake-igd", "--no-pager", "-n", "60", "-l"], "$ systemctl status fake-igd")),
            ("2", "Restart it", restart),
            ("3", "Stop it" if st == "active" else "Start it", start_stop),
            ("4", "Its journal, live", self.journal, "plain"),
            ("5", "Mode: active or passive", mode),
            ("6", "The answer to AddPortMapping: accept or reject", response),
            ("7", "The console at login: on or off", at_login),
            ("8", "The console at login: for normal users too", at_login_users),
        ])

    # ---- 13 mDNS reflector (avahi) ---------------------------------------------------------
    def live_mdns(self):
        """avahi-browse -a -p -r, in the live view: new / gone / resolved."""
        import upnp_mdns as M
        if not shutil.which("avahi-browse"):
            self.page("avahi-browse", self.pal.bad_line("avahi-browse is missing - dnf install avahi-tools"))
            return
        pr = subprocess.Popen(["avahi-browse", "-a", "-p", "-r"], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, errors="replace")
        q = collections.deque()

        def pump():
            for ln in pr.stdout:
                d = M.parse_browse(ln.rstrip("\n"))
                q.append(self.cli.mdns_line(d) if d else ln.rstrip("\n"))
        threading.Thread(target=pump, daemon=True).start()

        def more():
            out = []
            while q:
                out.append(q.popleft())
            return out
        try:
            self.live_view("Live mDNS  avahi-browse -a -r", lambda: [], more, None, "")
        finally:
            pr.terminate()
            try:
                pr.wait(3)
            except Exception:                           # noqa: BLE001
                pr.kill()

    def mdns_journal(self):
        try:
            pr = subprocess.Popen(["journalctl", "-u", "avahi-daemon", "-f", "-n", "400", "--no-pager"],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        except OSError as e:
            self.page("journalctl", self.pal.bad_line(str(e)))
            return
        q = collections.deque()

        def pump():
            for ln in pr.stdout:
                q.append(ln.rstrip("\n"))
        threading.Thread(target=pump, daemon=True).start()

        def more():
            out = []
            while q:
                out.append(q.popleft())
            return out

        def paint(ln):
            p = self.pal
            m = re.match(r"^(\S+ +\d+ \S+ \S+ \S+: )(.*)$", ln)
            if not m:
                return ln
            body = re.sub(r"(\d{1,3}(?:\.\d{1,3}){3})", lambda x: p.addr(x.group(1)), m.group(2))
            if re.search(r"(?i)fail|error|denied|conflict", body):
                body = p.bad(body)
            elif re.search(r"(?i)joining|established|server startup complete", body):
                body = p.good(body)
            return p.dim(m.group(1)) + body
        try:
            self.live_view("journalctl -u avahi-daemon -f", lambda: [], more, paint, "")
        finally:
            pr.terminate()
            try:
                pr.wait(3)
            except Exception:                           # noqa: BLE001
                pr.kill()

    def m_mdns(self):
        import upnp_mdns as M

        def st():
            try:
                return M.status()
            except M.MdnsError as e:
                self.note("mDNS reflector", str(e), "bad")
                return None

        def switch(title, key, words_on, words_off, args):
            d = st()
            if d is None:
                return
            cur = {"enable-reflector": d["reflector"], "reflect-ipv": d["reflect_ipv"],
                   "use-ipv6": d["ipv6"], "use-ipv4": d["ipv4"]}[key]
            r = self.choose(title, [("on", words_on), ("off", words_off)],
                            "It is %s now. avahi-daemon is restarted; when it does not come up with the change, "
                            "the previous file is put back." % ("ON" if cur else "off"), cur=0 if cur else 1)
            if r and (r == "on") != cur:
                self.act("mdns", args, r)

        def interfaces():
            d = st()
            if d is None:
                return
            have = sorted(n for n in M.system_ifaces() if n != "lo")
            got = self.form("Interfaces of the reflector", [
                {"key": "ifs", "label": "interfaces", "value": " ".join(d["allow_interfaces"]),
                 "help": "allow-interfaces: the interfaces avahi uses and reflects mDNS between, separated by "
                         "spaces. Empty: every interface. This machine has: " + ", ".join(have),
                 "check": lambda v, _: self._mdns_check(M, "allow-interfaces", v)}],
                "mDNS is repeated between these networks only.")
            if got is not None:
                self.act("mdns", "interfaces", *(got["ifs"].split() or ["all"]))

        def filters():
            d = st()
            if d is None:
                return
            got = self.form("Reflect only these service types", [
                {"key": "f", "label": "service types", "value": " ".join(d["reflect_filters"]),
                 "help": "reflect-filters: e.g. _airplay._tcp _raop._tcp _googlecast._tcp _ipp._tcp - separated by "
                         "spaces. Empty: every service type is reflected.",
                 "check": lambda v, _: self._mdns_check(M, "reflect-filters", v)}])
            if got is not None:
                self.act("mdns", "filters", *(got["f"].split() or ["none"]))

        def one_key():
            got = self.form("Change one key of avahi-daemon.conf", [
                {"key": "k", "label": "key", "kind": "choice", "options": [(k, k) for k in sorted(M.KNOWN)]},
                {"key": "v", "label": "value", "help": "yes/no, a number or a list - empty: as avahi has it "
                                                       "(the line is commented out)."}],
                check=lambda g: self._mdns_check(M, g["k"], g["v"]))
            if got is not None:
                self.act("mdns", "set", got["k"], got["v"] or "-")

        def services():
            def load():
                self.working("working…  $ upnp mdns services (avahi-browse, up to 15 s)")
                return self.out("mdns", "services") or []
            return self.pick("mDNS services", load, [
                ("TYPE", lambda r: r.get("type"), 22, lambda r: "key"),
                ("NAME", lambda r: r.get("name"), 28, None),
                ("IFACE", lambda r: r.get("iface"), 8, None),
                ("PROTO", lambda r: r.get("proto"), 5, lambda r: "dim"),
                ("ADDRESS", lambda r: r.get("address") or "", 15, None),
                ("PORT", lambda r: r.get("port") or "", 5, None),
                ("HOST", lambda r: r.get("host") or "", 0, lambda r: "dim"),
            ], lambda r: self.details(r.get("name"), r), empty="no mDNS services seen",
                words="What mDNS shows on each interface now - Enter shows one whole.")

        def restart():
            if self.confirm("Restart avahi-daemon", "mDNS is not reflected for a second or two.", "Restart"):
                self.act("mdns", "restart")

        def start_stop():
            d = st()
            if d is None:
                return
            if d["service"]["state"] == "active":
                if self.confirm("Stop avahi-daemon", "The reflector stops: devices in the other networks stop "
                                "seeing each other (AirPlay, Chromecast, printers...).", "Stop", danger=True):
                    self.act("mdns", "stop")
            else:
                self.act("mdns", "start")
        return self.sub("mDNS reflector (avahi)", [
            ("1", "Status", lambda: self.act("mdns", "status")),
            ("2", "Services on the network", services),
            ("3", "Live mDNS (new, gone, resolved)", self.live_mdns, "plain"),
            ("4", "The reflector: on or off", lambda: switch(
                "The mDNS reflector", "enable-reflector", "On - repeat mDNS between the interfaces",
                "Off - every network sees only its own devices", "reflector")),
            ("5", "Interfaces it reflects between", interfaces),
            ("6", "Reflect only some service types", filters),
            ("7", "IPv6: on or off", lambda: switch("mDNS over IPv6", "use-ipv6", "On", "Off", "ipv6")),
            ("8", "Reflect between IPv4 and IPv6", lambda: switch(
                "Reflect between IPv4 and IPv6", "reflect-ipv", "On", "Off", "reflect-ipv")),
            ("9", "Change one key of avahi-daemon.conf", one_key),
            ("10", "The lines set in avahi-daemon.conf", lambda: self.act("mdns", "config")),
            ("11", "Its journal, live", self.mdns_journal, "plain"),
            ("12", "Restart it", restart),
            ("13", "Start or stop it", start_stop),
        ])

    @staticmethod
    def _mdns_check(M, key, v):
        try:
            M.check(key, v)
            return None
        except M.MdnsError as e:
            return str(e)

    # ---- 12 logs and maintenance ------------------------------------------------------
    def m_maint(self):
        def clear_requests():
            if self.confirm("Clear the request log", "Every port request kept so far is deleted - the "
                            "reports (ports, clients, rules) start from nothing. It cannot be undone.",
                            "Clear", danger=True):
                self.act("clear", "--requests", "-y")

        def clear_all():
            if self.confirm("Clear every log", "The request log and the main log are emptied; the service "
                            "is not restarted. It cannot be undone.", "Clear", danger=True):
                self.act("clear", "--all", "-y")
        return self.sub("Logs and maintenance", [
            ("1", "Every request", lambda: self.act("requests", "-n", "0")),
            ("2", "The log, the last 500 lines", lambda: self.act("log", "-n", "500")),
            ("3", "Warnings and errors", lambda: self.act("log", "--level", "WARNING", "-n", "0")),
            ("4", "Clear the request log", clear_requests),
            ("5", "Clear every log", clear_all),
            ("6", "Versions", lambda: self.act("version")),
            ("7", "Every part looked at (upnp check)", lambda: self.act("check")),
            ("8", "fake-igd's own events", lambda: self.act("events", "-n", "300")),
        ])

    # ---- 1.7.5: as otp's console - Backups; Certificates, updates, tests (through `upnp api`) ----
    def m_backups(self):
        def db_do(what, title, words):
            if self.confirm(title, words, title):
                self.act("db", what)
        return self.sub("Backups and the database", [
            ("1", "The database: its tables and copies", lambda: self.act("db")),
            ("2", "A copy of the database now", lambda: self.act("db", "copy")),
            ("3", "Check the database (integrity_check)", lambda: self.act("db", "check")),
            ("4", "Forget the events kept long enough", lambda: db_do(
                "tidy", "Tidy the database", "The events older than they are kept are forgotten.")),
            ("5", "Give the disk back (VACUUM)", lambda: self.act("db", "vacuum")),
            ("6", "Backups to other machines: how they went", lambda: self.act("backup")),
            ("7", "Backups to other machines: one now", lambda: self.run_here("backup", "now")),
            ("8", "Try the newest backup (fetched back)", lambda: self.run_here("backup", "verify")),
            ("9", "Everything of this installation into a file", self.export_conf),
        ])

    def export_conf(self):
        got = self.form("Everything of this installation into a file", [
            {"key": "path", "label": "The file", "value": "/root/fake-igd-config-%s.json" % time.strftime("%Y%m%d"),
             "need": True, "help": "a new file, 0600 - never written over",
             "check": lambda v, _a: None if v.startswith("/") and not os.path.exists(v) else "a new file, a whole path"},
            {"key": "secrets", "label": "With the secrets", "kind": "choice",
             "options": [("no", "no - the secrets left out"), ("yes", "yes - locked with a passphrase shown once")]}])
        if got:
            self.run_here("export-config", got["path"], *(["--with-secrets"] if got["secrets"] == "yes" else []))

    def m_ops(self):
        def mail_test():
            got = self.form("A test mail", [
                {"key": "to", "label": "To", "need": True, "help": "an address - every step of the sending is said",
                 "check": lambda v, _a: None if "@" in v and " " not in v.strip() else "an e-mail address"},
                {"key": "kind", "label": "What", "kind": "choice",
                 "options": [("short", "a short test"), ("alert", "what an alert looks like"),
                             ("report", "the report of the period so far")]}])
            if got:
                self.act("mail-test", got["to"].strip(), "--kind", got["kind"])

        def proxy_test():
            got = self.form("The way out (proxy): try it", [
                {"key": "url", "label": "Address", "value": "https://github.com/",
                 "help": "reached as fake-igd reaches it: through the proxy where one is set"}])
            if got:
                self.act("proxy-test", got["url"].strip())

        def order():
            if self.confirm("Order the certificate now", "The CA is asked for a certificate of the names set "
                            "(Settings → Automatic certificates); nginx takes it when it comes.", "Order"):
                self.run_here("acme", "order")

        def updates_start():
            if self.confirm("Update the operating system", "dnf puts every waiting update in; a restart is "
                            "offered where one is needed.", "Update"):
                self.run_here("updates", "start", "--yes")
        return self.sub("Certificates, updates, time, tests", [
            ("1", "The certificate of the pages", lambda: self.act("tls")),
            ("2", "The certificate by ACME: how it stands", lambda: self.act("acme")),
            ("3", "The certificate by ACME: order it now", order),
            ("4", "The operating system's updates", lambda: self.act("updates")),
            ("5", "Look for system updates now", lambda: self.run_here("updates", "check")),
            ("6", "Put the system updates in", updates_start),
            ("7", "The time and its servers", lambda: self.act("time")),
            ("8", "Step the clock to the servers now", lambda: self.act("time", "sync")),
            ("9", "The network of this machine", lambda: self.act("net")),
            ("10", "A test mail", mail_test),
            ("11", "A test line to the syslog servers (SIEM)", lambda: self.act("siem-test")),
            ("12", "The way out (proxy): try it", proxy_test),
            ("13", "SNMPv3: a test trap", lambda: self.act("snmp-trap")),
            ("14", "Restart or power off: what is set", lambda: self.act("power")),
            ("15", "Restart this machine now", self.reboot_now),
            ("16", "Any question of the pages (upnp api)", self.api_ask),
            ("17", "SELinux: how it stands on this machine", lambda: self.act("selinux", "check")),
            ("18", "SELinux: a step on this machine", self.se_step),
            ("19", "SELinux: the report for fake-igd's module (a file)", lambda: self.run_here("selinux", "report")),
            ("20", "SELinux: what it refuses, and what puts it right", lambda: self.act("selinux", "look")),
            ("21", "SELinux: put right everything that can be", self.se_fix_all),
            ("22", "SELinux: fake-igd's local rules", lambda: self.act("selinux", "rules")),
            ("23", "Gateway for devices: how it stands", lambda: self.act("gateway")),
            ("24", "Gateway for devices: add a device", self.gw_add),
            ("25", "Gateway for devices: switch it on or off", self.gw_switch),
            ("26", "MikroTik: does it carry the ports asked for?", lambda: self.act("mikrotik", "check")),
            ("27", "MikroTik: read it now", lambda: self.act("mikrotik", "read")),
            ("28", "MikroTik: try reaching it", lambda: self.act("mikrotik", "try")),
            ("29", "MikroTik: its firewall (IPv4)", lambda: self.act("mikrotik", "rules", "ipv4")),
            ("30", "MikroTik: its firewall (IPv6)", lambda: self.act("mikrotik", "rules", "ipv6")),
        ])

    def gw_add(self):
        """A device that uses this server as its default gateway (a PS5 asks UPnP only of its gateway)."""
        got = self.form("Gateway for devices: add a device", [
            {"key": "name", "label": "Name", "value": "PS5", "need": True},
            {"key": "ip", "label": "Its IPv4 address", "need": True},
            {"key": "mac", "kind": "choice", "label": "Its MAC", "options": [
                ("seen", "as this server's neighbour table has it now"), ("none", "the address only")]}])
        if got:
            self.act("gateway", "add", got["ip"], "--name", got["name"], *(["--mac-seen"] if got.get("mac") == "seen" else []))

    def gw_switch(self):
        st = self.choose("Gateway for devices", [
            ("on", "on - forwarded for the devices defined, only toward the router"),
            ("off", "off - nothing is forwarded")])
        if st and self.confirm("Gateway for devices", {
                "on": "net.ipv4.ip_forward is turned on behind fake-igd's chain FAKE-IGD-FWD (first in FORWARD, a DROP "
                      "at its end): only the devices defined, in and out the interface of the default route. On trial "
                      "as every change of the firewall.",
                "off": "Forwarding goes back off and the chain is taken away: the devices that use this server as "
                       "their gateway reach nothing until they are given the router again."}[st],
                "Switch it %s" % st, danger=st == "off"):
            self.act("gateway", st, "--yes")

    def se_step(self):
        """otp's console se_step (1.0.236): one of the SELinux steps of Settings → SELinux, on this machine."""
        st = self.choose("SELinux: a step on this machine", [
            ("prepare", "make it ready - permissive at the next start (from disabled)"),
            ("apply", "put in what fake-igd needs (while permissive)"),
            ("enforce", "switch to enforcing"),
            ("permissive", "back to permissive")])
        if st and self.confirm("SELinux on this machine", {
                "prepare": "The configuration says permissive, and every file is labelled at the next start of "
                           "the machine. The machine is not restarted now.",
                "apply": "fake-igd's module, the labels of its files, the boolean and the ports it needs are put "
                         "in. Still permissive: nothing is refused.",
                "enforce": "From now on SELinux refuses what its policy does not allow - and stays enforcing after "
                           "a restart. Refused while anything is missing or was refused.",
                "permissive": "SELinux no longer refuses anything, now and after a restart."}[st],
                "Do it", danger=st in ("enforce", "prepare")):
            self.act("selinux", st, "--yes")

    def se_fix_all(self):
        if self.confirm("SELinux: put right what can be", "Every refusal of SELinux that can be put right here is: a "
                        "boolean, a label, a port, or a rule of fake-igd's own local module (fake_igd_local) - exactly "
                        "what was refused, nothing more. What is not for a button, or not fake-igd's, is left as it is. "
                        "upnp selinux look shows each first.", "Put it in"):
            self.act("selinux", "fix", "--all", "--yes")

    def reboot_now(self):
        if self.confirm("Restart this machine", "fake-igd, the pages and every other service on it are away "
                        "for a minute or two.", "Restart", danger=True):
            self.act("power", "reboot", "--yes")

    def api_ask(self):
        got = self.form("A question of the pages", [
            {"key": "method", "label": "Method", "kind": "choice", "options": [("GET", "GET - read"),
                                                                              ("POST", "POST - change")]},
            {"key": "path", "label": "Path", "value": "/api/", "need": True,
             "check": lambda v, _a: None if v.startswith("/api/") else "a path of the API: /api/..."},
            {"key": "body", "label": "Body (POST)", "value": "{}",
             "when": lambda v: v.get("method") == "POST", "help": 'JSON, e.g. {"action": "check"}'}])
        if got:
            self.act("api", got["method"], got["path"].strip(),
                     *([got["body"] or "{}"] if got["method"] == "POST" else []))


    # ---- 1.4.0: upgrades, the web pages and their accounts (otp's console: Upgrades, Accounts) ----
    def run_here(self, *args):
        """`upnp ARGS` on the ordinary terminal - its own colours and progress bar - then Enter."""
        def go():
            print(self.pal.head("$ upnp " + " ".join(self._quote(a) for a in args)))
            try:
                subprocess.run(self.argv(*args))
            except KeyboardInterrupt:
                pass
            try:
                input(self.pal.dim("\n  Enter goes back to the console "))
            except (EOFError, KeyboardInterrupt):
                pass
        return self.go_plain(go)

    def m_upgrade(self):
        def online():
            got = self.out("upgrade", "check") or {}
            if got.get("error"):
                self.note("Upgrades", "%s: %s" % (got.get("url"), got["error"]), "bad")
                return
            newer = got.get("newer_list") or []
            if not newer:
                self.note("Upgrades", "Nothing newer than %s at %s." % (got.get("here"), got.get("url")))
                return
            r = self.choose("Upgrade to", [(p["version"], "fake-igd %s" % p["version"]) for p in newer],
                            "This server runs %s. The package is fetched, its signature and every file checked, "
                            "and root runs its install.sh --upgrade - followed here." % got.get("here"))
            if r and self.confirm("Upgrade to %s" % r, "fake-igd.service and the pages restart once; the PS5 "
                                  "notices nothing.", "Upgrade"):
                self.run_here("upgrade", "online", r, "--yes")

        def from_file():
            got = self.form("Upgrade from a package file", [
                {"key": "path", "label": "The package", "value": "/root/", "need": True,
                 "help": "a fake-igd-X.Y.Z.tar.gz as released - signed by a release key this server trusts",
                 "check": lambda v, _a: None if os.path.isfile(v) else "%s is not a file" % v}])
            if got:
                self.run_here("upgrade", "file", got["path"], "--yes")
        return self.sub("Upgrades", [
            ("1", "What is there (upnp upgrade check)", lambda: self.act("upgrade", "check")),
            ("2", "Upgrade from the web", online),
            ("3", "Upgrade from a package file", from_file),
            ("4", "Follow one going on", lambda: self.run_here("upgrade", "follow")),
            ("5", "How the last one went", lambda: self.act("upgrade", "status")),
            ("6", "What install.sh said last", lambda: self.act("upgrade", "log")),
        ])

    def m_web(self):
        def add():
            got = self.form("Make an account of the pages", [
                {"key": "name", "label": "Name", "need": True, "help": "letters, digits and . _ @ -"},
                {"key": "role", "label": "Role", "kind": "choice",
                 "options": [("fulladmin", "full admin - may change everything"), ("readonly", "read only - may look")]},
                {"key": "pw", "label": "Password", "kind": "secret",
                 "help": "at least 8 characters; empty = one is made and shown once"}])
            if got:
                env = dict(os.environ, UPNP_PASSWORD=got["pw"])
                args = ["user", "add", got["name"], "--role", got["role"]] + (["--password", "@env"] if got["pw"] else [])
                self.act(*args, env=env)

        def passwd():
            users = self.out("user", "list") or []
            if not users:
                self.note("Accounts", "There is no account yet.")
                return
            name = self.choose("A new password for", [(u["name"], "%s (%s)" % (u["name"], u["role_words"])) for u in users])
            if not name:
                return
            got = self.form("A new password for %s" % name, [
                {"key": "pw", "label": "Password", "kind": "secret",
                 "help": "at least 8 characters; empty = one is made and shown once"}])
            if got is not None:
                env = dict(os.environ, UPNP_PASSWORD=got["pw"])
                self.act("user", "passwd", name, *(["--password", "@env"] if got["pw"] else []), env=env)

        def delete():
            users = self.out("user", "list") or []
            name = self.choose("Take away the account", [(u["name"], "%s (%s)" % (u["name"], u["role_words"])) for u in users])
            if name and self.confirm("Take %s away" % name, "Its sign-ins end and it cannot sign in again.",
                                     "Take it away", danger=True):
                self.act("user", "del", name, "--yes")

        def role():
            users = self.out("user", "list") or []
            name = self.choose("The role of", [(u["name"], "%s (%s)" % (u["name"], u["role_words"])) for u in users])
            if not name:
                return
            r = self.choose("%s is to be" % name, [("fulladmin", "full admin - may change everything"),
                                                    ("readonly", "read only - may look")])
            if r:
                self.act("user", "role", name, "--role", r)
        return self.sub("Web pages and accounts", [
            ("1", "The pages: address, nginx, php-fpm, the API", lambda: self.act("web")),
            ("2", "Accounts", lambda: self.act("user", "list")),
            ("3", "Make an account", add),
            ("4", "A new password", passwd),
            ("5", "Change a role", role),
            ("6", "Take an account away", delete),
            ("7", "Who is signed in now", lambda: self.act("user", "sessions")),
            ("8", "Firewall (FAKE-IGD-IN): what is in place", lambda: self.act("firewall", "--status")),
            ("9", "Put the allow list and the firewall in place again", lambda: self.act("web", "apply")),
        ])


# ---- the console at login -----------------------------------------------------------
def console_flag_lines():
    """(root on, the normal users it opens for: '*', a list or [])."""
    try:
        fd = os.open(CONSOLE_FLAG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False, []
    try:
        import stat as _stat
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            return False, []
        text = os.read(fd, 8192).decode("utf-8", "replace")
    finally:
        os.close(fd)
    lines = text.split("\n")
    users = []
    for ln in lines[1:]:
        if ln.startswith("users:"):
            words = ln[6:].split()
            users = "*" if words == ["*"] else [w for w in words if CONSOLE_USER_RE.match(w)][:200]
    return lines[0].strip() == "on", users


def console_at_login():
    return console_flag_lines()[0]


def console_users():
    return console_flag_lines()[1]


def console_users_parse(words):
    if isinstance(words, list):
        words = " ".join(str(w) for w in words)
    words = str(words or "").replace(",", " ").split()
    if words in (["*"], ["all"]):
        return "*"
    if words in ([], ["none"], ["-"]):
        return []
    out = []
    for w in words:
        if not CONSOLE_USER_RE.match(w) or w == "root":
            raise ValueError("%r is not the name of a normal user" % w[:40])
        if w not in out:
            out.append(w)
    if len(out) > 200:
        raise ValueError("200 users at most")
    return out


def console_users_words(users):
    return "every normal user" if users == "*" else (", ".join(users) if users else "nobody")


def console_at_login_set(on, users=None):
    if os.geteuid() != 0:
        raise SystemExit("upnp: only root sets that")
    if users is None:
        users = console_users()
    text = "on\n" if on else "off\n"
    if users:
        text += "users: %s\n" % ("*" if users == "*" else " ".join(users))
    tmp = "%s.%d.tmp" % (CONSOLE_FLAG, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, text.encode())
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, CONSOLE_FLAG)
    said = ("the upnp console opens when root signs in at the console or over SSH (q leaves it for "
            "the shell)" if on else "root signs in to the ordinary shell; `upnp --console` opens the console")
    if users:
        said += "; for %s too, through sudo (their own password)" % console_users_words(users)
    if not os.path.exists(CONSOLE_PROFILE):
        said += " - NOTE: %s is missing, run the installer again" % CONSOLE_PROFILE
    return said


def at_login_cli(what, users, pal):
    """upnp --console-at-login on|off|status, upnp --console-users USERS."""
    try:
        if what == "status" or (what is None and users is None):
            on, us = console_flag_lines()
            print("the upnp console at login: %s (root)%s" % (
                pal.good("on") if on else pal.dim("off"),
                "; normal users: %s (through sudo)" % console_users_words(us) if us else ""))
            return 0
        u = console_users_parse(users) if users is not None else None
        on = (what == "on") if what in ("on", "off") else console_at_login()
        print(pal.good("✔ ") + console_at_login_set(on, u))
        return 0
    except (SystemExit, ValueError, OSError) as e:
        print(pal.bad_line(str(e)), file=sys.stderr)
        return 1


def console_main(cli, pal, config):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit("upnp: the console needs a terminal")
    return Console(cli, pal, config).run()
