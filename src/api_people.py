"""api_people.py - Settings → Accounts, as otp's pane-people (1.6.1).

Who may open these pages: the local accounts in fake-igd's own database (igd_store.py), two
roles - full admin and read only. otp's third, token admin, looks after people's VPN tokens,
and fake-igd has none: there is nothing between looking and changing everything here.

  /api/users          the accounts: GET the list; POST add, role, password, note, must_change,
                      enable, disable, delete, mfa_reset (the second step set up again),
                      passkeys_remove (every passkey of the account taken away, 1.9.7),
                      reset_cols (somebody's own layout of the tables put back as it comes)
  /api/users/history  ?name= the sign-ins of one account (and the refused ones), from the events
  /api/sessions       who is signed in now - POST {id} ends one
  /api/lockouts       the wrong attempts still counted, by address and by name - POST clear / clear_all
  /api/auth/login     (replaces the API's own) - the password, counted; then, when it is on,
  /api/auth/mfa       the second step: the code of an authenticator app (RFC 6238), set up at the
  /api/mfa            first sign-in with a QR code. Until it is given the sign-in is good for
                      nothing but this (igd_store.Store.session says None for it). /api/mfa is the
                      same, for the pages' ?api=mfa.
  /api/auth/passkey-login  signing in with a passkey alone (1.9.7; Face ID, Touch ID, Windows Hello,
                      igd_webauthn.py): GET whether it is offered here; POST begin / finish - a
                      sign-in of its own, no password and no second step after it
  /api/auth/passkeys  Your account: the passkeys of the account signed in (otp 1.0.257) - GET the
  /api/passkeys       list; POST add_begin, add_finish, rename, delete.
  /api/auth/whoami    (replaces) - and, for a sign-in waiting for its second step, "mfa": the stage
  /api/auth/logout    (replaces) - a waiting sign-in ended too
  /api/auth/passwd    (replaces) - one's own password: the old one counted as a sign-in's, the
                      other sign-ins of the account ended

Its settings (pane "people") are otp's: how long a sign-in lasts and may sit idle, how many wrong
attempts before a pause and how long, the second step - and how long a password must be. They are
read by igd_store.Store.policy(), so the command line (upnp user) keeps to them too.

Left out, as they cannot be here: the directory (AD) accounts and its groups, Windows (Kerberos)
and certificate sign-in, codes by mail and SMS (otp's other second steps - the app needs nothing
more of this machine). The columns of the tables are the shell's
(api_shell.py); how many each account has laid out is shown, and put back, here.
"""
import base64
import os
import secrets
import socket
import time

import igd_store as ST
import igd_webauthn as WA

NAME = "people"
MFA_WRONG_MOST = 5          # wrong second-step codes of one sign-in, then the password again (otp 1.0.252)
PK_MAX = ST.PASSKEY_MOST    # passkeys of one account (otp 1.0.257)
# A passkey is added only within this long of signing in, not on the sign-in's cookie alone
# (otp 1.0.262): a passkey outlives the sign-in.
PK_ADD_FRESH = int(os.environ.get("FAKE_IGD_PK_ADD_FRESH") or 900)

SETTINGS = [
    {"key": "session_hours", "name": "A sign-in lasts (h)", "kind": "int", "default": 12, "min": 1, "max": 168,
     "says": "How long an administrator stays signed in, however busy."},
    {"key": "session_idle_min", "name": "...and may sit untouched (min)", "kind": "int", "default": 120,
     "min": 5, "max": 1440,
     "says": "How long a sign-in may sit without anything being asked before it has to be done again."},
    {"key": "login_tries", "name": "Wrong passwords before a pause", "kind": "int", "default": 5, "min": 1,
     "max": 100,
     "says": "Wrong passwords (and codes of the second step) before a pause, as otp counts them: one name "
             "may make four times as many, one address ten times as many (50 at least) - an office behind "
             "one address is not locked out by one person's typos. One's own password typed wrong where "
             "it is changed is counted apart: this many from an address, for five minutes."},
    {"key": "login_wait_min", "name": "...and the pause (min)", "kind": "int", "default": 15, "min": 1,
     "max": 1440, "says": "How long it waits. Locked out, above, shows who waits, and lets them try again at once."},
    {"key": "admin_2fa", "name": "A second step when signing in to these pages", "kind": "bool",
     "default": False,
     "says": "After the password, every account gives a code too - from an authenticator app (Google or "
             "Microsoft Authenticator…), its own. The first time, the account sets it up: it scans a QR "
             "code and writes the code the app shows. Accounts → Reset the second step, or upnp user "
             "reset-2fa NAME, makes it set it up again. Sign-ins already open stay open. A sign-in with a "
             "passkey (below) asks no code: it is whole by itself."},
    {"key": "passkey_signin", "name": "Sign in with Face ID, Touch ID or Windows Hello (a passkey)", "kind": "bool",
     "default": False,
     "says": "The sign-in page offers it beside the password: the face, a finger or the PIN of the device, "
             "and no name or password typed. The device keeps the key (an iPad and an iPhone in the iCloud "
             "Keychain, so on the person's other Apple devices too), this server only its public half. A "
             "sign-in with a passkey is whole by itself - the device that holds the key and the face, finger "
             "or PIN it checks - so no code of the second step is asked after it, even when the second step "
             "is on. The password still signs in as before. Each account adds its passkeys under Your account "
             "(within 15 minutes of signing in); Accounts takes them away. Only on these pages opened by a "
             "name with a certificate the browser trusts (https://name/), not by an address: a passkey works "
             "on the name it was added on."},
    {"key": "password_min", "name": "A password at least (characters)", "kind": "int", "default": 8, "min": 8,
     "max": 64,
     "says": "For a password set on these pages, by upnp user, and one's own. Passwords there already "
             "stay until they are changed."},
]

KIND_WORDS = {"app": "an app"}


# ---- the QR code the app scans: otp's, made here rather than by a package ----------------------
# The standard (ISO/IEC 18004) in byte mode, every version and level of error correction, the
# mask chosen as the standard says; drawn as SVG.
_QR_ECC_PER_BLOCK = {
    'L': (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    'M': (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    'Q': (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
          28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    'H': (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
          30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
}
_QR_BLOCKS = {
    'L': (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12,
          12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    'M': (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20,
          21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
    'Q': (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25,
          27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    'H': (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30,
          32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
}
_QR_FORMAT = {'L': 1, 'M': 0, 'Q': 3, 'H': 2}


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z & 0xFF


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(len(result)):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < len(result):
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _qr_raw_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        align = ver // 7 + 2
        result -= (25 * align - 10) * align - 55
        if ver >= 7:
            result -= 36
    return result


def _qr_data_codewords(ver, ecl):
    return (_qr_raw_modules(ver) // 8
            - _QR_ECC_PER_BLOCK[ecl][ver] * _QR_BLOCKS[ecl][ver])


class QrCode(object):
    """One QR code: `modules[y][x]` is True where the square is dark."""

    def __init__(self, text, ecl='M'):
        data = text.encode('utf-8') if isinstance(text, str) else bytes(text)
        self.ecl = ecl
        for ver in range(1, 41):
            count_bits = 8 if ver <= 9 else 16
            need = 4 + count_bits + 8 * len(data)
            if need <= _qr_data_codewords(ver, ecl) * 8:
                break
        else:
            raise ValueError('that is too long for a QR code')
        self.version = ver
        self.size = ver * 4 + 17
        bits = []

        def put(value, n):
            for i in reversed(range(n)):
                bits.append((value >> i) & 1)
        put(0x4, 4)
        put(len(data), count_bits)
        for b in data:
            put(b, 8)
        capacity = _qr_data_codewords(ver, ecl) * 8
        put(0, min(4, capacity - len(bits)))
        put(0, (8 - len(bits) % 8) % 8)
        pad = 0xEC
        while len(bits) < capacity:
            put(pad, 8)
            pad ^= 0xEC ^ 0x11
        words = [int(''.join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
        all_words = self._with_ecc(words)
        size = self.size
        self.modules = [[False] * size for _ in range(size)]
        self.function = [[False] * size for _ in range(size)]
        self._function_patterns()
        self._codewords(all_words)
        best, best_penalty = 0, None
        for mask in range(8):
            self._mask(mask)
            self._format(mask)
            penalty = self._penalty()
            if best_penalty is None or penalty < best_penalty:
                best, best_penalty = mask, penalty
            self._mask(mask)
        self._mask(best)
        self._format(best)
        self.mask = best

    # ---- the pieces ------------------------------------------------------
    def _set(self, x, y, dark):
        self.modules[y][x] = bool(dark)
        self.function[y][x] = True

    def _function_patterns(self):
        size = self.size
        for i in range(size):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for x, y in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    xx, yy = x + dx, y + dy
                    if 0 <= xx < size and 0 <= yy < size:
                        self._set(xx, yy, max(abs(dx), abs(dy)) not in (2, 4))
        places = self._alignment_places()
        last = len(places) - 1
        for i, a in enumerate(places):
            for j, b in enumerate(places):
                if (i == 0 and j == 0) or (i == 0 and j == last) or (i == last and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(a + dx, b + dy, max(abs(dx), abs(dy)) != 1)
        self._format(0)
        if self.version >= 7:
            rem = self.version
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            value = self.version << 12 | rem
            for i in range(18):
                bit = (value >> i) & 1
                a, b = size - 11 + i % 3, i // 3
                self._set(a, b, bit)
                self._set(b, a, bit)

    def _alignment_places(self):
        ver = self.version
        if ver == 1:
            return []
        count = ver // 7 + 2
        step = (ver * 8 + count * 3 + 5) // (count * 4 - 4) * 2
        result = [self.size - 7 - i * step for i in range(count - 1)] + [6]
        return list(reversed(result))

    def _format(self, mask):
        data = _QR_FORMAT[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1
        size = self.size
        for i in range(0, 6):
            self._set(8, i, bit(i))
        self._set(8, 7, bit(6))
        self._set(8, 8, bit(7))
        self._set(7, 8, bit(8))
        for i in range(9, 15):
            self._set(14 - i, 8, bit(i))
        for i in range(0, 8):
            self._set(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self._set(8, size - 15 + i, bit(i))
        self._set(8, size - 8, True)

    def _with_ecc(self, data):
        ver, ecl = self.version, self.ecl
        blocks_n = _QR_BLOCKS[ecl][ver]
        ecc_len = _QR_ECC_PER_BLOCK[ecl][ver]
        raw = _qr_raw_modules(ver) // 8
        short_n = blocks_n - raw % blocks_n
        short_len = raw // blocks_n
        divisor = _rs_divisor(ecc_len)
        blocks = []
        k = 0
        for i in range(blocks_n):
            take = short_len - ecc_len + (0 if i < short_n else 1)
            dat = data[k:k + take]
            k += take
            ecc = _rs_remainder(dat, divisor)
            if i < short_n:
                dat = dat + [0]
            blocks.append(dat + ecc)
        out = []
        for i in range(len(blocks[0])):
            for j, blk in enumerate(blocks):
                if i != short_len - ecc_len or j >= short_n:
                    out.append(blk[i])
        return out

    def _codewords(self, data):
        size = self.size
        i = 0
        right = size - 1
        total = len(data) * 8
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = size - 1 - vert if upward else vert
                    if not self.function[y][x] and i < total:
                        self.modules[y][x] = bool((data[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def _mask(self, mask):
        test = (lambda x, y: (x + y) % 2 == 0,
                lambda x, y: y % 2 == 0,
                lambda x, y: x % 3 == 0,
                lambda x, y: (x + y) % 3 == 0,
                lambda x, y: (x // 3 + y // 2) % 2 == 0,
                lambda x, y: x * y % 2 + x * y % 3 == 0,
                lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
                lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0)[mask]
        for y in range(self.size):
            row, fn = self.modules[y], self.function[y]
            for x in range(self.size):
                if not fn[x] and test(x, y):
                    row[x] = not row[x]

    def _penalty(self):
        size, m = self.size, self.modules
        score = 0
        lines = [m[y] for y in range(size)] + [[m[y][x] for y in range(size)]
                                                for x in range(size)]
        finder = ([True, False, True, True, True, False, True, False, False, False, False],
                  [False, False, False, False, True, False, True, True, True, False, True])
        for line in lines:
            run, last = 0, None
            for v in line:
                if v == last:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run, last = 1, v
            if run >= 5:
                score += 3 + run - 5
            for i in range(len(line) - 10):
                seg = line[i:i + 11]
                if seg == finder[0] or seg == finder[1]:
                    score += 40
        for y in range(size - 1):
            for x in range(size - 1):
                v = m[y][x]
                if v == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(sum(1 for v in row if v) for row in m)
        total = size * size
        k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        score += k * 10
        return score

    # ---- drawn -------------------------------------------------------------
    def svg(self, scale=6, border=4, dark='#000', light='#fff'):
        """The code as an SVG picture, light squares and all - a phone needs
        the quiet zone round it, so it is part of the picture."""
        size = self.size + border * 2
        path = []
        for y in range(self.size):
            x = 0
            while x < self.size:
                if self.modules[y][x]:
                    start = x
                    while x < self.size and self.modules[y][x]:
                        x += 1
                    path.append('M%d %dh%dv1h-%dz' % (start + border, y + border,
                                                      x - start, x - start))
                else:
                    x += 1
        return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" '
                'height="%d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" '
                'fill="%s"/><path d="%s" fill="%s"/></svg>'
                % (size, size, size * scale, size * scale, light, ''.join(path), dark))

    def terminal(self, border=2, invert=False):
        """The code as half-block characters, two rows of squares a line.
        Drawn for a dark terminal: a dark square is the terminal's own dark
        and a light one is a full block. `invert` for a light terminal."""
        size = self.size
        out = []
        def light(x, y):
            if x < 0 or y < 0 or x >= size or y >= size:
                return not invert
            return (not self.modules[y][x]) != invert
        for y in range(-border, size + border, 2):
            row = []
            for x in range(-border, size + border):
                top, bottom = light(x, y), light(x, y + 1)
                row.append('█' if top and bottom else
                           '▀' if top else '▄' if bottom else ' ')
            out.append(''.join(row))
        return '\n'.join(out)




def qr_data_uri(text, scale=6):
    return "data:image/svg+xml;base64," + base64.b64encode(
        QrCode(text, "M").svg(scale=scale).encode("ascii")).decode("ascii")


# ---- helpers ---------------------------------------------------------------------------------
def _token(ctx):
    return (ctx.handler.headers.get("X-IGD-Session") or "") if ctx.handler is not None else ""


def _host(ctx):
    """The Host the browser sent the pages (igd-api.php: X-IGD-Host) - checked by igd_webauthn."""
    return (ctx.handler.headers.get("X-IGD-Host") or "") if ctx.handler is not None else ""


def _agent(ctx):
    return (ctx.handler.headers.get("User-Agent") or "") if ctx.handler is not None else ""


def _idle_s(ctx):
    return 60 * int(ctx.cfg.get("session_idle_minutes") or 120)


def _say(ctx, kind, words, level="info", who=None):
    """An event of its own kind - "account" and "sign-in", as fake-igd wrote them before."""
    ctx.store.add_event(kind, words, level, who if who is not None else (ctx.me or {}).get("name", ""), ctx.addr)


def _made_password(S):
    """A password made here: 16 characters, or as many as "A password at least" asks when it is more
    (it was always 16, and refused by the policy it was made for)."""
    least = int(S.policy().get("password_min") or ST.MIN_PASSWORD)
    return secrets.token_urlsafe(max(16, least) * 3 // 4 + 1)[:max(16, least)]


def _is_me(ctx, name):
    return str(name or "").lower() == str((ctx.me or {}).get("name") or "").lower()


def _roles():
    return [{"role": r, "words": ST.ROLE_WORDS[r]} for r in ST.ROLES]


def _shell():
    import sys
    return sys.modules.get("api_shell")


def _own(store, name):
    """An account's own (api_shell's): the columns of its tables, the looks of the meter."""
    sh = _shell()
    if sh is None:
        return {}
    try:
        return sh._mine(store, name)
    except Exception:                                   # noqa: BLE001 - a list of accounts is drawn anyway
        return {}


def _site(ctx):
    return str(ctx.cfg.get("site_name") or socket.gethostname().split(".")[0])


# ---- the accounts ----------------------------------------------------------------------------
def users_get(ctx):
    me = ctx.need("readonly")
    S = ctx.store
    pol = S.policy()
    users = S.users()
    for u in users:
        # Every account here signs in with a password of its own (otp's "Signs in": no directory),
        # and how many tables it has laid out by hand (otp's "Columns").
        u["source"] = "local"
        u["cols_tables"] = len(_own(S, u["name"]).get("cols") or {})
    return {"users": users, "may_change": me["role"] == "fulladmin", "mfa_on": bool(pol["admin_2fa"]),
            "roles": _roles(), "me": me["name"], "password_min": pol["password_min"],
            "sessions": S.sessions() if me["role"] == "fulladmin" else []}


def users_post(ctx):
    me = ctx.need("fulladmin")
    S = ctx.store
    b = ctx.body()
    act = str(b.get("action") or "")
    name = str(b.get("name") or "").strip()
    who = me["name"]
    if act == "add":
        role = str(b.get("role") or "readonly")
        pw = str(b.get("password") or "")
        made = ""
        if not pw:
            pw = made = _made_password(S)
        must = bool(b.get("must_change", 1))
        S.add_user(name, pw, role, str(b.get("note") or ""), must_change=must)
        _say(ctx, "account", "%s made the account %s (%s)%s" % (who, name, ST.ROLE_WORDS.get(role, role),
                                                              ", to change its password at sign-in" if must else ""))
        return {"message": "the account %s is made" % name, "password": made}
    if act == "end-session":                    # as the API answered it before 1.6.1
        return _end_session(ctx, str(b.get("id") or ""))
    if not name:
        raise ValueError("which account?")
    acc = S.user(name)
    if not acc:
        raise ValueError("there is no account called %s" % name)
    name = acc["name"]
    if act == "delete":
        S.delete_user(name)
        # Its own layout goes with it: an account made later with the same name starts as it comes.
        sh = _shell()
        if sh is not None:
            S.run("DELETE FROM meta WHERE k = ?", (sh._mine_key(name),))
        _say(ctx, "account", "%s removed the account %s" % (who, name), "warn")
        return {"message": "the account %s is gone" % name}
    if act == "role":
        role = str(b.get("role") or "")
        S.set_role(name, role)
        _say(ctx, "account", "%s made %s %s" % (who, name, ST.ROLE_WORDS.get(role, role)))
        return {"message": "saved"}
    if act == "password":
        pw = str(b.get("password") or "")
        made = ""
        if not pw:
            pw = made = _made_password(S)
        must = bool(b.get("must_change", 1))
        S.set_password(name, pw, must_change=must)
        n = S.end_sessions_of(name, but_token=_token(ctx) if _is_me(ctx, name) else None)
        _say(ctx, "account", "%s set a new password for %s%s; their sign-ins are ended" % (
            who, name, " (to change at the next sign-in)" if must else ""), "warn")
        return {"message": "the password is set" + ("; %d sign-in(s) of %s ended" % (n, name) if n else ""),
                "password": made}
    if act == "must_change":
        on = bool(b.get("on", True))
        S.set_must_change(name, on)
        _say(ctx, "account", "%s %s" % (who, ("asked %s to change the password at the next sign-in" % name) if on
                                         else ("let %s keep the password" % name)))
        return {"message": "saved"}
    if act == "note":
        S.set_note(name, str(b.get("note") or ""))
        _say(ctx, "account", "%s wrote a note on %s" % (who, name))
        return {"message": "saved"}
    if act in ("disable", "enable"):
        S.set_disabled(name, act == "disable")
        _say(ctx, "account", "%s switched %s %s" % (who, name, "off" if act == "disable" else "on"),
             "warn" if act == "disable" else "info")
        return {"message": "saved"}
    if act == "reset_cols":
        # Somebody's own layout of the tables put back as it comes (otp's): nothing else of theirs.
        sh = _shell()
        if sh is None:
            raise ValueError("the columns of the tables are not kept here")
        mine = sh._mine(S, name)
        n = len(mine.get("cols") or {})
        if not n:
            return {"message": "%s has every table as it comes already" % name}
        mine["cols"] = {}
        sh._mine_put(S, name, mine)
        _say(ctx, "account", "%s put the columns of every table of %s back as they come (%d)" % (who, name, n))
        return {"message": "the columns of %s are back as they come" % name}
    if act == "passkeys_remove":
        # Every passkey of the account taken away (1.9.7): it signs in with its password, as before.
        n = S.passkeys_remove(name)
        if not n:
            return {"message": "%s has no passkey" % name}
        _say(ctx, "account", "%s took every passkey of %s away (%d)" % (who, name, n), "warn")
        return {"message": "the passkeys of %s are taken away (%d)" % (name, n)}
    if act == "mfa_reset":
        had = S.mfa_reset(name)
        # The app only (1.9.7): its passkeys stay - they sign in by themselves, not as the second step.
        _say(ctx, "account", "%s reset the second step of %s; their sign-ins are ended" % (who, name), "warn")
        return {"message": ("the second step of %s is reset: they set it up again at the next sign-in; their "
                            "sign-ins are ended" if had else "%s had no second step set up") % name}
    raise ValueError("no such thing to do to an account")


def history_get(ctx):
    ctx.need("readonly")
    name = ctx.arg("name").strip()
    acc = ctx.store.user(name)
    if not acc:
        raise ValueError("there is no account called %s" % name)
    try:
        most = max(1, min(500, int(ctx.arg("limit", "50"))))
    except ValueError:
        most = 50
    return {"name": acc["name"], "rows": ctx.store.sign_ins(acc["name"], most)}


# ---- who is signed in now --------------------------------------------------------------------
def sessions_get(ctx):
    ctx.need("fulladmin")
    S = ctx.store
    # The list is of who could still ask: the ones that sat too long are tidied first (otp 1.0.15).
    S.tidy_sessions(_idle_s(ctx))
    rows = S.sessions()
    mine = ""
    tok = _token(ctx)
    if tok:
        mine = ST._sid(tok)[:12]
    for r in rows:
        r["me"] = r["id"] == mine
    return {"sessions": rows}


def _end_session(ctx, ident):
    me = ctx.need("fulladmin")
    row = ctx.store.session_of(ident)
    if not row:
        # Gone already (otp 1.0.61): not written down as "ended the sign-in of ?".
        raise ValueError("that sign-in has ended already")
    ctx.store.end_session(ident)
    _say(ctx, "sign-in", "%s ended the sign-in of %s%s" % (me["name"], row["name"] or "?",
                                                          (" from %s" % row["addr"]) if row["addr"] else ""), "warn")
    return {"message": "ended"}


def sessions_post(ctx):
    return _end_session(ctx, str(ctx.body().get("id") or ""))


# ---- locked out ------------------------------------------------------------------------------
def lockouts_get(ctx):
    ctx.need("fulladmin")
    span, tries, addr_tries = ctx.store.fail_limits()
    return {"nodes": [{"node": socket.gethostname().split(".")[0], "me": True, "fresh": True,
                       "rows": ctx.store.lockouts()}],
            "now": time.time(), "cluster": False, "span": span, "tries": tries, "addr_tries": addr_tries}


def lockouts_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    if act == "clear_all":
        n = ctx.store.clear_all_fails()
        _say(ctx, "sign-in", "%s cleared every count of wrong attempts (%d)" % (me["name"], n), "warn")
        return {"message": "cleared", "told": []}
    if act == "clear":
        kind, who = str(b.get("kind") or ""), str(b.get("who") or "")
        if kind not in ("admin", "admin-name", "password", "password-name") or not who:
            raise ValueError("which lockout?")
        by = "address" if kind in ("admin", "password") else "name"
        n = ctx.store.clear_fails(by, who, own=kind.startswith("password"))
        if not n:
            raise ValueError("that is not counted any more")
        _say(ctx, "sign-in", "%s cleared the count of wrong attempts of %s %s" % (me["name"], "the address" if
                                                                                  by == "address" else "the name",
                                                                                  who), "warn")
        return {"message": "cleared", "told": []}
    raise ValueError("no such thing to do")


# ---- signing in ------------------------------------------------------------------------------
def login(ctx):
    S = ctx.store
    b = ctx.body()
    name = str(b.get("name") or "").strip()[:64]
    try:
        token, usr = S.login(name, str(b.get("password") or ""), ctx.addr, _agent(ctx), _idle_s(ctx))
    except ST.StoreError as e:
        # The name as typed, never a line of its own in the events (and the syslog after them).
        said = "".join(c if c.isprintable() else "?" for c in name)
        _say(ctx, "sign-in", "%s could not sign in from %s: %s" % (said or "(nobody)", ctx.addr, e), "warn", said)
        raise ValueError(str(e))
    stage = usr.get("mfa_stage") or ""
    _say(ctx, "sign-in", "%s signed in from %s%s" % (usr["name"], ctx.addr, {
        "check": " - the second step to give", "enrol": " - the second step to set up"}.get(stage, "")),
        "info", usr["name"])
    return {"token": token, "must_change": bool(usr["must_change"]), "mfa": stage,
            "who": {"name": usr["name"], "role": usr["role"] if not stage else ""}}


login.PUBLIC = True


def whoami(ctx):
    S = ctx.store
    tok = _token(ctx)
    u = S.session(tok, _idle_s(ctx)) if tok else None
    if u:
        pol = S.policy()
        return {"idle_min": pol["session_idle_min"] if pol["idle_saved"] else _idle_s(ctx) // 60,
                "who": {"name": u["name"], "role": u["role"], "role_words": ST.ROLE_WORDS.get(u["role"]),
                        "must_change": bool(u["must_change"]), "note": u["note"]}}
    s, acc = S.pending(tok)
    if s:
        # No role until the second step is given (otp): the pages that ask who it is refuse it.
        return {"who": None, "mfa": s["mfa"], "name": acc["name"]}
    return {"who": None}


whoami.PUBLIC = True


def logout(ctx):
    S = ctx.store
    tok = _token(ctx)
    if tok:
        u = S.session(tok, touch=False)
        s, acc = (None, None) if u else S.pending(tok)
        S.logout(tok)
        if u or acc:
            name = (u or acc)["name"]
            _say(ctx, "sign-in", "%s signed out" % name, "info", name)
    return {}


logout.PUBLIC = True


def passwd(ctx):
    me = ctx.need("readonly")
    S = ctx.store
    b = ctx.body()
    # Counted (otp 1.0.57): a session left open was a way to guess the password without end. On a
    # count of its own (otp's kind "password", 5 min) - a typo here never locks the account out of
    # signing in, as it did when it was counted as a wrong sign-in.
    if S.too_many(ctx.addr, me["name"], own=True):
        raise ValueError(S._locked_words(own=True))
    full = S.user(me["name"])
    if not ST.check_password(str(b.get("old") or ""), full["hash"]):
        S.fail(ctx.addr, me["name"], "own")
        raise ValueError("the password you have now is not right")
    new = str(b.get("new") or "")
    if new == str(b.get("old") or ""):
        raise ValueError("that is the password you have now - choose another")
    S.set_password(me["name"], new, must_change=False)
    # Every other sign-in with the old password ends (otp 1.0.33).
    S.end_sessions_of(me["name"], but_token=_token(ctx))
    _say(ctx, "account", "%s changed their own password" % me["name"])
    return {"message": "the password is changed"}


# ---- the second step: the app (since 1.9.7 the only one - a passkey signs in by itself) ----------
def _pending(ctx):
    s, acc = ctx.store.pending(_token(ctx))
    if not s:
        raise ValueError("this sign-in has no second step to give - sign in again")
    return s, acc


def mfa_get(ctx):
    s, acc = _pending(ctx)
    stage = s["mfa"]
    return {"name": acc["name"], "display": "", "stage": stage, "methods": ["app"],
            "kind": "app" if stage == "check" else "", "hosts": [], "dest": "", "started": None,
            "digits": 6, "blocked": "", "send": None}


mfa_get.PUBLIC = True


def _mfa_wrong(ctx, s, name, words):
    """A wrong code of the second step: counted on the address and the name as the passwords are,
    and on this sign-in (otp 1.0.252) - at the fifth its password is asked again. Raises."""
    S = ctx.store
    S.fail(ctx.addr, name, "code")
    _say(ctx, "sign-in", "%s: a wrong code of the second step from %s (%s)" % (name, ctx.addr, words), "warn", name)
    n = int(s["data"].get("mfa_wrong") or 0) + 1
    try:
        S.pending_merge(_token(ctx), {"mfa_wrong": n})
    except ST.StoreError:
        n = MFA_WRONG_MOST
    if n >= MFA_WRONG_MOST:
        S.logout(_token(ctx))
        _say(ctx, "account", "%s: %d wrong codes of the second step - the sign-in was ended, the password "
             "is asked again" % (name, MFA_WRONG_MOST), "warn", name)
        raise ST.StoreError("too many wrong codes - sign in again")
    raise ST.StoreError(words)


def mfa_post(ctx):
    S = ctx.store
    s, acc = _pending(ctx)
    stage = s["mfa"]
    name = acc["name"]
    b = ctx.body()
    act = b.get("action")
    # The account as it is now, not as it was at this sign-in (otp 1.0.139): a sign-in kept waiting
    # from before the second step was set up could set up its own, over the one in use.
    if act in ("enrol_start", "enrol_confirm") and (stage != "enrol" or S.mfa_get(name).get("kind")):
        raise ValueError("this account has its second step set up already - sign in again")
    if act == "enrol_start":
        if str(b.get("kind") or "app") != "app":
            raise ValueError("that way is not offered here")
        secret = ST.b32_new(20)
        S.pending_merge(_token(ctx), {"mfa_new": secret})
        uri = ST.otpauth_uri(secret, name, "%s (fake-igd)" % _site(ctx))
        return {"kind": "app", "qr": qr_data_uri(uri), "uri": uri,
                "secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))}
    if act not in ("enrol_confirm", "check"):
        raise ValueError("no such thing to do")
    if S.too_many(ctx.addr, name):
        raise ValueError(S._locked_words())
    try:
        if act == "enrol_confirm":
            if stage != "enrol":
                raise ST.StoreError("this account has its second step set up already")
            new_tok = S.mfa_enrol(_token(ctx), b.get("code") or "")
            _say(ctx, "account", "%s set up the second step of signing in: an app" % name, "info", name)
            _say(ctx, "sign-in", "%s gave the second step (set up now: an app) from %s" % (name, ctx.addr),
                 "info", name)
            return {"message": "the second step is set up", "done": True, "token": new_tok}
        if stage != "check":
            raise ST.StoreError("set the second step up first")
        S.mfa_check(name, b.get("code") or "")
    except ST.StoreError as e:
        if "sign in again" not in str(e):
            # Counted on this sign-in too (otp 1.0.252): at the fifth its password is asked again - a
            # sign-in with the password could go on guessing as long as the name's count let it.
            _mfa_wrong(ctx, s, name, str(e))
        raise
    # A sign-in of its own from here on (otp 1.0.149): the new token goes to the cookie (the pages,
    # ?api=mfa), never to the page; the one the password opened is ended.
    new_tok = S.mfa_passed(_token(ctx))
    _say(ctx, "sign-in", "%s gave the second step (an app) from %s" % (name, ctx.addr), "info", name)
    return {"message": "signed in", "done": True, "token": new_tok}


mfa_post.PUBLIC = True


# ---- signing in with a passkey (1.9.7): Face ID, Touch ID, Windows Hello - by itself -------------
# Instead of the password, never after it: the device that keeps the key, and the face, a finger or
# its PIN verified there (UV), are two factors of their own - so no second step is asked after it,
# even while admin_2fa is on. Discoverable keys: no name typed, the device offers the passkeys it
# has for this name of the pages, and the key found says which account it is.
def _pk_on(S):
    return bool(S.policy().get("passkey_signin"))


def pk_signin_get(ctx):
    """Whether the sign-in page offers it: switched on, and the pages opened by a name."""
    on = _pk_on(ctx.store)
    return {"on": on, "here": on and WA.wa_host_ok(_host(ctx))}


pk_signin_get.PUBLIC = True


def _pk_refused(ctx, name, words, level="warn", count=True):
    """A passkey that did not sign in: counted as a wrong password is (the address, and the name when
    the key told it), said in the events - the page is told only the words."""
    if count:
        ctx.store.fail(ctx.addr, name or "", "password")
    said = "".join(c if c.isprintable() else "?" for c in (name or ""))
    _say(ctx, "sign-in", "%s could not sign in with a passkey from %s: %s" % (said or "(no account)", ctx.addr, words),
         level, said)
    raise ValueError(words)


def pk_signin(ctx):
    """begin: a question for the device, kept here (bound to the address, once, five minutes).
    finish: the answer - the key found among every account's, checked as WebAuthn says; a new
    sign-in, whose token the pages put into the cookie (never shown to the page)."""
    S = ctx.store
    b = ctx.body()
    act = str(b.get("action") or "")
    if not _pk_on(S):
        raise ValueError("signing in with a passkey is switched off (Settings - Accounts)")
    # The address counted first: the name is told only by the key, once it is found.
    if S.too_many(ctx.addr, None):
        raise ValueError(S._locked_words())
    if act == "begin":
        saved, opts = WA.wa_signin_options(_host(ctx))
        S.challenge_put(ctx.addr, saved)
        return opts
    if act != "finish":
        raise ValueError("no such thing to do")
    saved = S.challenge_take(b.get("challenge"), ctx.addr)
    if not saved:
        _pk_refused(ctx, "", "that answer is to an old question - try again")
    acc, key = S.passkey_find(b.get("id"))
    if not acc:
        _pk_refused(ctx, "", "that passkey signs nobody in here (taken away, or of another server)")
    name = acc["name"]
    if S.too_many(ctx.addr, name):
        _pk_refused(ctx, name, S._locked_words(), count=False)
    # The device names the account the key was made for (userHandle): it must be this one.
    uh = str(b.get("userHandle") or "")
    if uh and uh != WA.wa_user_id(name):
        _pk_refused(ctx, name, "that passkey was made for another account")
    try:
        used = WA.wa_login_finish(saved, [key], b)
    except PermissionError as e:
        _pk_refused(ctx, name, str(e), "bad")
    except (ValueError, TypeError, KeyError) as e:
        _pk_refused(ctx, name, str(e))
    if acc["disabled"]:
        # Said as any passkey that signs nobody in, and counted (as a password of an account switched off).
        _pk_refused(ctx, name, "that passkey signs nobody in here (taken away, or of another server)")
    try:
        token, usr = S.passkey_login(name, used, ctx.addr, _agent(ctx), _idle_s(ctx))
    except ST.StoreError as e:
        _pk_refused(ctx, name, str(e))
    _say(ctx, "sign-in", "%s signed in with a passkey (%s) from %s" % (name, used.get("name") or "a device", ctx.addr),
         "info", name)
    return {"token": token, "must_change": bool(usr["must_change"]), "mfa": "",
            "who": {"name": usr["name"], "role": usr["role"]}}


pk_signin.PUBLIC = True


# ---- Your account: the passkeys of the account signed in (otp 1.0.257; 1.9.7 a sign-in) ----------
# Listed, one added from another device, named, taken away - the last one too: the password stays.
def _pk_row(k):
    def n(v):
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0.0
    return {"id": k.get("id"), "name": k.get("name") or "", "host": k.get("host") or "",
            "at": n(k.get("at")), "used": n(k.get("used")), "backed_up": bool(k.get("backed_up"))}


def _pk_stale(me):
    """Added only soon after signing in (otp 1.0.262): a passkey outlives the sign-in, so not on its
    cookie alone - within a quarter of an hour of the password (and its second step) or a passkey."""
    try:
        at = max(float(me.get("session_started") or 0), float(me.get("mfa_at") or 0))
    except (TypeError, ValueError):
        at = 0.0
    return time.time() - at > PK_ADD_FRESH


def pk_list(ctx):
    me = ctx.need("readonly")
    on = _pk_on(ctx.store)
    keys = ctx.store.passkeys(me["name"])
    why = ""
    if on and not WA.wa_host_ok(_host(ctx)):
        why = "A passkey is added on these pages opened by a name over HTTPS (https://name/), not by an address."
    elif on and len(keys) >= PK_MAX:
        why = "This account has %d passkeys, as many as it may." % PK_MAX
    elif on and _pk_stale(me):
        # Said before the button is pressed (otp 1.0.262), not only after.
        why = "A passkey is added within %d minutes of signing in - sign in again to add one." % (PK_ADD_FRESH // 60)
    return {"on": on, "mine": on, "keys": [_pk_row(k) for k in keys],
            "can_add": on and not why, "why": why, "max": PK_MAX}


def pk_do(ctx):
    me = ctx.need("readonly")
    S = ctx.store
    b = ctx.body()
    act = str(b.get("action") or "")
    name = me["name"]
    tok = _token(ctx)
    if act in ("add_begin", "add_finish") and not _pk_on(S):
        raise ValueError("signing in with a passkey is switched off (Settings - Accounts)")
    if act == "add_begin":
        keys = S.passkeys(name)
        if len(keys) >= PK_MAX:
            raise ValueError("this account has %d passkeys, as many as it may" % PK_MAX)
        if _pk_stale(me):
            raise ValueError("a passkey is added within %d minutes of signing in - sign in again and add it "
                             "then" % (PK_ADD_FRESH // 60))
        saved, opts = WA.wa_register_options(_host(ctx), name, "", _site(ctx),
                                             have=[k.get("id") for k in keys if k.get("id")])
        # Kept with this sign-in: the answer is taken by it alone.
        S.session_merge(tok, {"pk_add": saved})
        return opts
    if act == "add_finish":
        saved = _pk_saved(S, tok)
        if not saved:
            raise ValueError("that answer is to an old question - press the button again")
        try:
            pk = WA.wa_register_finish(saved, b)
        except (ValueError, TypeError, KeyError) as e:
            raise ValueError("the passkey was not taken: %s" % e)
        if not S.session_take(tok, "pk_add"):
            raise ValueError("that answer was taken already - press the button again")
        with S.lock:
            keys = S.passkeys(name)
            if any(k.get("id") == pk["id"] for k in keys):
                raise ValueError("this device has a passkey for this account already")
            # One credential signs in one account (1.9.7): found by its ID alone.
            other, _k = S.passkey_find(pk["id"])
            if other:
                raise ValueError("that passkey is another account's already")
            if len(keys) >= PK_MAX:
                raise ValueError("this account has %d passkeys, as many as it may" % PK_MAX)
            keys.append(pk)
            S.passkeys_put(name, keys)
        _say(ctx, "account", "%s added a passkey (%s, for https://%s/)" % (name, pk.get("name") or "a device",
                                                                         pk["host"]), "info", name)
        return {"message": "the passkey is added", "keys": [_pk_row(k) for k in keys]}
    ident = str(b.get("id") or "")
    if act == "rename":
        label = " ".join(str(b.get("name") or "").split())[:60]
        if not label:
            raise ValueError("a name for the passkey")
        with S.lock:
            keys = S.passkeys(name)
            hit = next((k for k in keys if k.get("id") == ident), None)
            if hit is None:
                raise ValueError("no such passkey of this account")
            was = hit.get("name") or "a device"
            hit["name"] = label
            S.passkeys_put(name, keys)
        _say(ctx, "account", "%s named a passkey %s (was %s)" % (name, label, was), "info", name)
        return {"message": "named", "keys": [_pk_row(k) for k in keys]}
    if act == "delete":
        with S.lock:
            keys = S.passkeys(name)
            hit = next((k for k in keys if k.get("id") == ident), None)
            if hit is None:
                raise ValueError("no such passkey of this account")
            keys = [k for k in keys if k.get("id") != ident]
            S.passkeys_put(name, keys)
        _say(ctx, "account", "%s took a passkey away (%s, for https://%s/)" % (
            name, hit.get("name") or "a device", hit.get("host") or "?"), "warn", name)
        return {"message": "taken away", "keys": [_pk_row(k) for k in keys]}
    raise ValueError("what should be done?")


def _pk_saved(S, tok):
    """The question of Your account's Add, as it is kept with the sign-in (not taken yet)."""
    s = S.one("SELECT data FROM sessions WHERE id = ?", (ST._sid(tok),))
    got = ST._jload(s["data"]).get("pk_add") if s else None
    return got if isinstance(got, dict) else None


def on_saved(ctx, changed):
    """The second step switched on: the sign-ins opened with the password alone end (otp 1.0.149) -
    they stayed whole for hours. The one saving it stays: it is how it was switched on (without the
    saving request at hand, every sign-in of the account that saved it stays)."""
    if not changed.get("admin_2fa"):
        return
    S = ctx.store
    tok = _token(ctx)
    who = (ctx.me or {}).get("name", "")
    # A sign-in with a passkey stays (1.9.7): it is whole by itself, no second step is asked after it.
    by_pk = "data NOT LIKE '%\"by\": \"passkey\"%'"
    if tok:
        gone = S.run("DELETE FROM sessions WHERE mfa = '' AND " + by_pk + " AND id <> ?", (ST._sid(tok),)).rowcount
    else:
        gone = S.run("DELETE FROM sessions WHERE mfa = '' AND " + by_pk + " AND name <> ?", (who,)).rowcount
    if gone:
        _say(ctx, "account", "the second step was switched on: %d other sign-in(s) to the pages ended" % gone,
             "warn", who)


def background(ctx):
    span = ctx.store.fail_limits()[0]
    ctx.store.run("DELETE FROM fails WHERE at < ?", (time.time() - max(span, ST.FAIL_WINDOW_S),))


ROUTES = {
    ("GET", "/api/users"): users_get, ("POST", "/api/users"): users_post,
    ("GET", "/api/users/history"): history_get,
    ("GET", "/api/sessions"): sessions_get, ("POST", "/api/sessions"): sessions_post,
    ("GET", "/api/lockouts"): lockouts_get, ("POST", "/api/lockouts"): lockouts_post,
    ("POST", "/api/auth/login"): login, ("GET", "/api/auth/whoami"): whoami,
    ("POST", "/api/auth/logout"): logout,
    ("POST", "/api/auth/passwd"): passwd, ("POST", "/api/auth/password"): passwd,
    ("GET", "/api/auth/mfa"): mfa_get, ("POST", "/api/auth/mfa"): mfa_post,
    ("GET", "/api/mfa"): mfa_get, ("POST", "/api/mfa"): mfa_post,
    ("GET", "/api/auth/passkey-login"): pk_signin_get, ("POST", "/api/auth/passkey-login"): pk_signin,
    ("GET", "/api/auth/passkeys"): pk_list, ("POST", "/api/auth/passkeys"): pk_do,
    ("GET", "/api/passkeys"): pk_list, ("POST", "/api/passkeys"): pk_do,
}
