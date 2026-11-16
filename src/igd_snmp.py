"""igd_snmp.py - fake-igd's own SNMPv3 agent (1.7.2), otp's (otp.py 1.0.288, "SNMPv3 (1.0.182)").

The pages' API answers SNMPv3 itself - an agent in a thread of its own, no snmpd: GET,
GETNEXT and GETBULK on the system group, the engine's own objects, usmStats and
fake-igd's subtree (FAKE-IGD-MIB, deploy/FAKE-IGD-MIB.txt), read only. One user, authPriv
only (USM, RFC 3414): HMAC-SHA-1/-256/-512 (RFC 3414, RFC 7860) and AES-128 or AES-256 in
CFB (RFC 3826; AES-256 with the key extended the way net-snmp and Zabbix do it,
"Blumenthal"), AES itself from igd_aes (otp's, in Python). The engine ID made once and kept
in the state folder (snmp-engine), the starts counted there (snmp-boots). Traps
(SNMPv2-Trap, authPriv, this engine's ID) when something goes wrong and when it is right
again - api_monitor.py decides when; this says how.

What is answered and the settings are api_monitor.py's: Agent(state_dir, conf, mib, log)
with conf() -> {on, port, bind, from [nets], c (user, auth, priv, ap, pp) or None, trap_to}
and mib(agent) -> [(oid, kind, value)], kind one of int str oid counter gauge ticks counter64.
"""
import bisect
import errno
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from collections import Counter

import igd_aes

SNMP_SYS = (1, 3, 6, 1, 2, 1, 1)
SNMP_ENGINE_OID = (1, 3, 6, 1, 6, 3, 10, 2, 1)
SNMP_USM_STATS = (1, 3, 6, 1, 6, 3, 15, 1, 1)
SNMP_TRAP_OID = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
SNMP_UPTIME_OID = SNMP_SYS + (3, 0)
SNMP_AUTH = {"SHA-1": ("sha1", 12), "SHA-256": ("sha256", 24), "SHA-512": ("sha512", 48)}
SNMP_PRIV = {"AES-128": 16, "AES-256": 32}
SNMP_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}\Z")
SNMP_WINDOW_S = 150
SNMP_CACHE_S = 10.0
SNMP_STATE = {"listening": False, "port": 0, "error": "", "since": 0.0, "asked": 0,
              "answered": 0, "last_from": "", "last_at": 0.0, "traps": 0, "trap_error": "",
              "engine": "", "boots": 0}
# usmStats: 1 unsupportedSecLevels, 2 notInTimeWindows, 3 unknownUserNames,
# 4 unknownEngineIDs, 5 wrongDigests, 6 decryptionErrors
SNMP_USM = Counter()
REPORT_WORDS = {1: "unsupported security level (authPriv only)", 2: "not in the time window",
                3: "unknown user name", 4: "unknown engine ID",
                5: "wrong digest - the authentication passphrase or protocol",
                6: "it could not decrypt - the encryption passphrase or protocol"}
SNMP_SELF = {"until": 0.0}        # the page's own test under way: this machine let in (otp 1.0.206)


# -- BER ------------------------------------------------------------------------------------
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def ber(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def ber_int(v, tag=2):
    v = int(v)
    if v == 0:
        return ber(tag, b"\x00")
    raw = v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
    while len(raw) > 1 and ((raw[0] == 0 and raw[1] < 0x80) or (raw[0] == 0xFF and raw[1] >= 0x80)):
        raw = raw[1:]
    return ber(tag, raw)


def ber_uint(v, tag):
    """An unsigned application type (Counter32, Gauge32, TimeTicks, Counter64): never negative."""
    v = int(v)
    raw = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80:
        raw = raw[1:]
    return ber(tag, raw)


def ber_str(v):
    return ber(4, v if isinstance(v, bytes) else str(v).encode("utf-8"))


def ber_oid(oid):
    oid = tuple(int(x) for x in oid)
    out = bytearray([40 * oid[0] + oid[1]])
    for n in oid[2:]:
        part = [n & 0x7F]
        n >>= 7
        while n:
            part.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(part))
    return ber(6, bytes(out))


def ber_read(data, at):
    """(tag, where its value starts, where it ends) - offsets into `data`."""
    if at + 2 > len(data):
        raise ValueError("cut short")
    tag, n = data[at], data[at + 1]
    at += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or at + k > len(data):
            raise ValueError("a length that is not one")
        n = int.from_bytes(data[at:at + k], "big")
        at += k
    if at + n > len(data):
        raise ValueError("cut short")
    return tag, at, at + n


def ber_items(data, start, end):
    out = []
    at = start
    while at < end:
        tag, s, e = ber_read(data, at)
        out.append((tag, s, e))
        at = e
    return out


def oid_decode(b):
    if not b:
        return ()
    out = [b[0] // 40, b[0] % 40] if b[0] < 80 else [2, b[0] - 80]
    n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            out.append(n)
            n = 0
    return tuple(out)


def snmp_value(kind, v):
    """One value, as its type wants it."""
    if kind == "int":
        return ber_int(max(-2 ** 31, min(int(v), 2 ** 31 - 1)))
    if kind == "str":
        return ber_str(v)
    if kind == "oid":
        return ber_oid(v)
    if kind == "counter":
        return ber_uint(int(v) & 0xFFFFFFFF, 0x41)
    if kind == "gauge":
        return ber_uint(max(0, min(int(v), 0xFFFFFFFF)), 0x42)
    if kind == "ticks":
        return ber_uint(int(v) & 0xFFFFFFFF, 0x43)
    if kind == "counter64":
        return ber_uint(int(v) & 0xFFFFFFFFFFFFFFFF, 0x46)
    return ber(0x05, b"")


# -- USM ------------------------------------------------------------------------------------
def snmp_key(passphrase, engine, hname):
    """RFC 3414 A.2 (RFC 7860 for SHA-2): the passphrase to a key, localized to the engine."""
    pw = str(passphrase).encode("utf-8")
    if not pw:
        raise ValueError("no passphrase")
    h = hashlib.new(hname)
    reps, rest = divmod(1048576, len(pw))
    h.update(pw * reps + pw[:rest])
    ku = h.digest()
    return hashlib.new(hname, ku + engine + ku).digest()


def snmp_priv_key(passphrase, engine, hname, size):
    k = snmp_key(passphrase, engine, hname)
    while len(k) < size:                    # AES-256 with SHA-1: net-snmp's extension
        k += hashlib.new(hname, k).digest()
    return k[:size]


def snmp_keys(c, engine):
    hname, _ = SNMP_AUTH[c["auth"]]
    return snmp_key(c["ap"], engine, hname), snmp_priv_key(c["pp"], engine, hname, SNMP_PRIV[c["priv"]])


def snmp_cfb(key, iv, data, decrypt):
    return igd_aes.cfb(key, iv, data, decrypt)


# -- the engine of this machine ------------------------------------------------------------
def _write_replacing(path, text):
    tmp = "%s.%s.tmp" % (path, secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def snmp_engine_id(state_dir):
    """0x80001F88 (net-snmp's number, RFC 3411's format 5) and 12 bytes of this machine's own,
    made once."""
    p = os.path.join(state_dir, "snmp-engine")
    try:
        with open(p) as f:
            raw = bytes.fromhex(f.read().strip())
        if 9 <= len(raw) <= 32:
            return raw
    except (OSError, ValueError):
        pass
    raw = bytes.fromhex("80001f8805") + secrets.token_bytes(12)
    try:
        _write_replacing(p, raw.hex() + "\n")
    except OSError:
        pass
    return raw


def snmp_boots_next(state_dir, log=None):
    p = os.path.join(state_dir, "snmp-boots")
    try:
        with open(p) as f:
            n = int(f.read().strip() or 0)
    except (OSError, ValueError):
        n = 0
    n = n + 1 if n < 2147483646 else 1
    try:
        # Written whole and put in its place (otp 1.0.234): cut short, it read as 0 - the count
        # went back, and answers seen before could be sent again.
        _write_replacing(p, "%d\n" % n)
    except OSError as e:
        if log:
            log("SNMPv3: the count of starts could not be written (%s): %s" % (p, e))
    return n


def trap_targets(text, strict=False):
    """[(host, port)] of "host, host:port, [v6]:port" - 162 by default. strict: ValueError at a bad one."""
    out = []
    for w in [x for x in re.split(r"[\s,;]+", str(text or "")) if x]:
        m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d+))?\Z", w) or \
            re.match(r"^([A-Za-z0-9.-]+)(?::(\d+))?\Z", w) or \
            re.match(r"^([0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)\Z", w)
        if not m:
            if strict:
                raise ValueError("%r is not host or host:port" % w)
            continue
        port = int(m.group(2)) if m.lastindex and m.lastindex >= 2 and m.group(2) else 162
        if not 0 < port < 65536:
            if strict:
                raise ValueError("%r - the port is 1 to 65535" % w)
            continue
        out.append((m.group(1), port))
    return out


def allowed(client, nets, bind=""):
    """The manager may ask: from one of the networks set, or from anywhere when none is."""
    nets = [w for w in (nets or []) if w]
    if not nets:
        return True
    try:
        a = ipaddress.ip_address(str(client or "").strip("[]"))
    except ValueError:
        return False
    if time.time() < SNMP_SELF["until"] and (a.is_loopback or str(a) == str(bind or "").strip().strip("[]")):
        # This machine itself, while the page's own test asks (otp 1.0.206).
        return True
    for n in nets:
        try:
            if a in ipaddress.ip_network(str(n), strict=False):
                return True
        except ValueError:
            continue
    return False


# -- the agent -------------------------------------------------------------------------------
class Agent(object):
    def __init__(self, state_dir, conf, mib, log=None, start=True):
        self.conf_fn, self.mib_fn = conf, mib
        self.log = log or (lambda w: None)
        self.sock = None
        self.bound = None
        self.engine = snmp_engine_id(state_dir)
        self.boots = snmp_boots_next(state_dir, self.log)
        # Monotonic (otp 1.0.206): RFC 3414's engine time never goes back.
        self.started = time.monotonic()
        self.keys = None
        self.keyed = None
        self.conf = {}
        self.mib = []
        self.mib_oids = []
        self.mib_at = 0.0
        self.lock = threading.Lock()
        self.looked = 0.0
        self.said = {}
        self.salt = int.from_bytes(secrets.token_bytes(8), "big")
        SNMP_STATE.update(engine=self.engine.hex(), boots=self.boots)
        self.thread = None
        if start:
            self.thread = threading.Thread(target=self.run, name="fake-igd-snmp", daemon=True)
            self.thread.start()

    def _sparing(self, key, words, every=600):
        if time.time() - self.said.get(key, 0) >= every:
            self.said[key] = time.time()
            self.log(words)

    def configure(self):
        conf = self.conf_fn() or {}
        self.conf = conf
        want = bool(conf.get("on"))
        try:
            port = int(conf.get("port") or 161)
        except (TypeError, ValueError):
            port = 161
        bind = str(conf.get("bind") or "").strip() or "::"
        key = (bind, port) if want else None
        if key != self.bound and self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock, self.bound = None, None
            SNMP_STATE.update(listening=False)
        if not want:
            SNMP_STATE.update(listening=False, error="")
        if want and not self.sock:
            try:
                try:
                    fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
                    s = socket.socket(fam, socket.SOCK_DGRAM)
                    try:
                        if fam == socket.AF_INET6:
                            try:
                                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                            except OSError:
                                pass
                        s.bind((bind, port))
                    except OSError:
                        s.close()
                        raise
                except OSError as e6:
                    # Every address, and no IPv6 on this machine: IPv4's every address instead.
                    # A port taken is said as it is.
                    if bind != "::" or getattr(e6, "errno", 0) in (errno.EADDRINUSE, errno.EACCES, errno.EPERM):
                        raise
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        s.bind(("0.0.0.0", port))
                    except OSError:
                        s.close()
                        raise
                s.settimeout(1.0)
                self.sock, self.bound = s, key
                SNMP_STATE.update(listening=True, port=port, error="", since=time.time())
                where = s.getsockname()[0]
                self.log("SNMPv3 listening on %s:%d/udp" % ("[%s]" % where if ":" in where else where, port))
            except OSError as e:
                why = str(e)
                if port < 1024 and getattr(e, "errno", 0) in (errno.EACCES, errno.EPERM):
                    why = ("port %d needs CAP_NET_BIND_SERVICE in fake-igd-api.service - install.sh --upgrade "
                           "puts it in; or a port above 1024" % port)
                SNMP_STATE.update(listening=False, port=port, error=why)
                self._sparing("bind", "SNMPv3 cannot listen on %s:%d: %s" % (bind, port, why))
        c = conf.get("c")
        sig = json.dumps(c, sort_keys=True) if c else None
        if sig != self.keyed:
            self.keys = snmp_keys(c, self.engine) if c else None
            self.keyed = sig

    def stop(self):
        """Stops listening (the tests)."""
        self.conf_fn = lambda: {}
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def run(self):
        while True:
            if time.time() - self.looked > 5:
                self.looked = time.time()
                try:
                    self.configure()
                except Exception as e:                  # noqa: BLE001
                    self._sparing("conf", "SNMPv3: %s" % e)
            s = self.sock
            if not s:
                time.sleep(1.0)
                continue
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.5)
                continue
            SNMP_STATE["asked"] += 1
            try:
                out = self.answer(data, addr)
                if out:
                    s.sendto(out, addr)
                    SNMP_STATE["answered"] += 1
            except Exception as e:                      # noqa: BLE001
                self._sparing("req", "SNMPv3: a request from %s: %s" % (addr[0], e), 300)

    def now_time(self):
        return int(time.monotonic() - self.started)

    # -- one message ------------------------------------------------------------------------
    def answer(self, data, addr):
        client = str(addr[0])
        if client.startswith("::ffff:"):
            client = client[7:]
        if not allowed(client, self.conf.get("from"), self.conf.get("bind")):
            return None
        tag, s, e = ber_read(data, 0)
        if tag != 0x30:
            return None
        items = ber_items(data, s, e)
        if len(items) != 4 or items[0][0] != 2:
            return None
        if int.from_bytes(data[items[0][1]:items[0][2]], "big", signed=True) != 3:
            return None                             # v1 and v2c: not answered at all
        g = ber_items(data, items[1][1], items[1][2])
        if len(g) != 4:
            return None
        msg_id = int.from_bytes(data[g[0][1]:g[0][2]], "big", signed=True)
        their_max = int.from_bytes(data[g[1][1]:g[1][2]], "big", signed=True)
        flags = data[g[2][1]] if g[2][2] > g[2][1] else 0
        if int.from_bytes(data[g[3][1]:g[3][2]], "big", signed=True) != 3:
            return None
        if items[2][0] != 4:
            return None
        sp = ber_read(data, items[2][1])
        sec = ber_items(data, sp[1], sp[2])
        if len(sec) != 6:
            return None
        engine = data[sec[0][1]:sec[0][2]]
        boots = int.from_bytes(data[sec[1][1]:sec[1][2]], "big", signed=True)
        etime = int.from_bytes(data[sec[2][1]:sec[2][2]], "big", signed=True)
        user = data[sec[3][1]:sec[3][2]].decode("utf-8", "replace")
        auth_at, auth_end = sec[4][1], sec[4][2]
        salt = data[sec[5][1]:sec[5][2]]
        reportable = bool(flags & 4)
        # A plain scoped PDU's request-id, for reports to a discovery.
        rid = 0
        if items[3][0] == 0x30:
            try:
                sc = ber_items(data, items[3][1], items[3][2])
                pdu = ber_items(data, sc[2][1], sc[2][2])
                rid = int.from_bytes(data[pdu[0][1]:pdu[0][2]], "big", signed=True)
            except (ValueError, IndexError):
                rid = 0
        c = self.conf.get("c")
        if engine != self.engine:
            SNMP_USM[4] += 1
            return self.report(msg_id, rid, 4, user, None, reportable)
        if not c or user != c["user"]:
            SNMP_USM[3] += 1
            return self.report(msg_id, rid, 3, user, None, reportable)
        if flags & 3 != 3:
            SNMP_USM[1] += 1
            return self.report(msg_id, rid, 1, user, None, reportable)
        hname, alen = SNMP_AUTH[c["auth"]]
        akey, pkey = self.keys or snmp_keys(c, self.engine)
        if auth_end - auth_at != alen:
            SNMP_USM[5] += 1
            return self.report(msg_id, rid, 5, user, None, reportable)
        zeroed = data[:auth_at] + b"\x00" * alen + data[auth_end:]
        want = hmac.new(akey, zeroed, hname).digest()[:alen]
        if not hmac.compare_digest(want, data[auth_at:auth_end]):
            SNMP_USM[5] += 1
            return self.report(msg_id, rid, 5, user, None, reportable)
        if boots != self.boots or abs(etime - self.now_time()) > SNMP_WINDOW_S:
            SNMP_USM[2] += 1
            return self.report(msg_id, rid, 2, user, c, reportable)
        if items[3][0] != 4 or len(salt) != 8:
            SNMP_USM[6] += 1
            return self.report(msg_id, rid, 6, user, c, reportable)
        iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + salt
        plain = snmp_cfb(pkey, iv, data[items[3][1]:items[3][2]], True)
        try:
            tag, s2, e2 = ber_read(plain, 0)
            sc = ber_items(plain, s2, e2)
            if tag != 0x30 or len(sc) != 3:
                raise ValueError("not a scoped PDU")
        except ValueError:
            SNMP_USM[6] += 1
            return self.report(msg_id, rid, 6, user, c, reportable)
        ctx_engine = plain[sc[0][1]:sc[0][2]]
        ctx_name = plain[sc[1][1]:sc[1][2]]
        pdu_tag = sc[2][0]
        pdu = ber_items(plain, sc[2][1], sc[2][2])
        rid = int.from_bytes(plain[pdu[0][1]:pdu[0][2]], "big", signed=True)
        a = int.from_bytes(plain[pdu[1][1]:pdu[1][2]], "big", signed=True)
        b = int.from_bytes(plain[pdu[2][1]:pdu[2][2]], "big", signed=True)
        oids = []
        for vb in ber_items(plain, pdu[3][1], pdu[3][2]):
            parts = ber_items(plain, vb[1], vb[2])
            oids.append(oid_decode(plain[parts[0][1]:parts[0][2]]))
        SNMP_STATE.update(last_from=client, last_at=time.time())
        most = max(484, min(their_max, 65507)) - 200
        if ctx_engine not in (self.engine, b"") or ctx_name:
            # One context only, the default one ("").
            vbs, err, idx = [(o, ber(0x80, b"")) for o in oids], 0, 0
        else:
            vbs, err, idx = self.vars(pdu_tag, oids, a, b, most)
        body = ber_int(rid) + ber_int(err) + ber_int(idx) + \
            ber(0x30, b"".join(ber(0x30, ber_oid(o) + v) for o, v in vbs))
        scoped = ber(0x30, ber_str(self.engine) + ber_str(ctx_name) + ber(0xA2, body))
        if len(scoped) > most and pdu_tag != 0xA5:
            body = ber_int(rid) + ber_int(1) + ber_int(0) + ber(0x30, b"")      # tooBig
            scoped = ber(0x30, ber_str(self.engine) + ber_str(ctx_name) + ber(0xA2, body))
        return self.wrap(msg_id, scoped, c, 3)

    def rows(self):
        """Every object answered now, sorted: what api_monitor says, and the engine's own."""
        rows = list(self.mib_fn(self) or [])
        rows += [(SNMP_ENGINE_OID + (1, 0), "str", self.engine),
                 (SNMP_ENGINE_OID + (2, 0), "int", self.boots),
                 (SNMP_ENGINE_OID + (3, 0), "int", self.now_time()),
                 (SNMP_ENGINE_OID + (4, 0), "int", 65507)]
        for i in range(1, 7):
            rows.append((SNMP_USM_STATS + (i, 0), "counter", SNMP_USM[i]))
        rows.sort(key=lambda x: x[0])
        return rows

    def vars(self, pdu_tag, oids, a, b, most):
        with self.lock:
            if time.time() - self.mib_at > SNMP_CACHE_S or not self.mib:
                self.mib = self.rows()
                self.mib_at = time.time()
                self.mib_oids = [x[0] for x in self.mib]
            mib, keys = self.mib, self.mib_oids
        exact = {x[0]: x for x in mib}

        def nxt(o):
            i = bisect.bisect_right(keys, tuple(o))
            return mib[i] if i < len(mib) else None
        out = []
        if pdu_tag == 0xA0:                         # GET
            for o in oids:
                x = exact.get(tuple(o))
                out.append((o, snmp_value(x[1], x[2])) if x else (o, ber(0x80, b"")))     # noSuchObject
            return out, 0, 0
        if pdu_tag == 0xA1:                         # GETNEXT
            for o in oids:
                x = nxt(o)
                out.append((x[0], snmp_value(x[1], x[2])) if x else (o, ber(0x82, b"")))
            return out, 0, 0
        if pdu_tag == 0xA5:                         # GETBULK: a non-repeaters, b repetitions
            n = max(0, min(a, len(oids)))
            reps = max(0, min(b, 200))
            size = 0
            for o in oids[:n]:
                x = nxt(o)
                out.append((x[0], snmp_value(x[1], x[2])) if x else (o, ber(0x82, b"")))
            cur = list(oids[n:])
            for _ in range(reps):
                if not cur:
                    break
                row, ended = [], True
                for j, o in enumerate(cur):
                    x = nxt(o)
                    if x:
                        row.append((x[0], snmp_value(x[1], x[2])))
                        cur[j] = x[0]
                        ended = False
                    else:
                        row.append((o, ber(0x82, b"")))
                size += sum(len(ber_oid(o)) + len(v) + 4 for o, v in row)
                if size > most and out:
                    break
                out += row
                if ended:
                    break
            return out, 0, 0
        if pdu_tag == 0xA3:                         # SET: nothing here is written
            return [(o, ber(0x05, b"")) for o in oids], 17, 1
        return [(o, ber(0x05, b"")) for o in oids], 5, 1       # genErr

    def report(self, msg_id, rid, which, user, c, reportable):
        """A Report of usmStats.<which> - authenticated (authNoPriv) when the time window was the
        trouble and the user is known."""
        if not reportable:
            return None
        body = ber_int(rid) + ber_int(0) + ber_int(0) + ber(0x30, ber(0x30, ber_oid(
            SNMP_USM_STATS + (which, 0)) + snmp_value("counter", SNMP_USM[which])))
        scoped = ber(0x30, ber_str(self.engine) + ber_str(b"") + ber(0xA8, body))
        return self.wrap(msg_id, scoped, c if which == 2 else None, 1 if which == 2 else 0, user=user)

    def wrap(self, msg_id, scoped, c, level, user=None, boots=None, etime=None):
        """The whole message around a scoped PDU: level 0 noAuthNoPriv, 1 authNoPriv, 3 authPriv
        (4 more: reportable)."""
        boots = self.boots if boots is None else boots
        etime = self.now_time() if etime is None else etime
        alen = SNMP_AUTH[c["auth"]][1] if c and level & 1 else 0
        priv = b""
        data = scoped
        if c and level & 2:
            self.salt = (self.salt + 1) & 0xFFFFFFFFFFFFFFFF
            priv = self.salt.to_bytes(8, "big")
            iv = boots.to_bytes(4, "big") + etime.to_bytes(4, "big") + priv
            data = ber_str(snmp_cfb((self.keys or snmp_keys(c, self.engine))[1], iv, scoped, False))
        name = (c["user"] if c else (user or "")).encode("utf-8")
        front = ber_str(self.engine) + ber_int(boots) + ber_int(etime) + ber_str(name)
        inner = ber(0x30, front + ber_str(b"\x00" * alen) + ber_str(priv))
        sec = ber_str(inner)
        glob = ber(0x30, ber_int(msg_id) + ber_int(65507) + ber_str(bytes([level])) + ber_int(3))
        body = ber_int(3) + glob + sec + data
        msg = ber(0x30, body)
        if alen:
            at = (len(msg) - len(body)) + len(ber_int(3)) + len(glob) + (len(sec) - len(inner)) + \
                (len(inner) - len(front) - len(ber_str(b"\x00" * alen)) - len(ber_str(priv))) + \
                len(front) + 2
            hname = SNMP_AUTH[c["auth"]][0]
            mac = hmac.new((self.keys or snmp_keys(c, self.engine))[0], msg, hname).digest()[:alen]
            msg = msg[:at] + mac + msg[at + alen:]
        return msg

    # -- traps ------------------------------------------------------------------------------
    def trap(self, base, what, binds):
        """An SNMPv2-Trap, authPriv, to every receiver set: what is 1 raised, 2 cleared, 3 a test;
        binds [(kind, value)] go as base.8.i.0. {target: 'sent' | why not}."""
        conf = self.conf_fn() or {}
        c = conf.get("c")
        if not c:
            raise ValueError("the SNMPv3 user and its two passphrases are not set")
        if not self.keys or self.keyed != json.dumps(c, sort_keys=True):
            self.keys, self.keyed = snmp_keys(c, self.engine), json.dumps(c, sort_keys=True)
        vbs = [(SNMP_UPTIME_OID, snmp_value("ticks", int((time.monotonic() - self.started) * 100))),
               (SNMP_TRAP_OID, ber_oid(tuple(base) + (0, what)))]
        for i, (kind, v) in enumerate(binds, 1):
            vbs.append((tuple(base) + (8, i, 0), snmp_value(kind, v)))
        rid = secrets.randbelow(2 ** 31)
        body = ber_int(rid) + ber_int(0) + ber_int(0) + \
            ber(0x30, b"".join(ber(0x30, ber_oid(o) + v) for o, v in vbs))
        scoped = ber(0x30, ber_str(self.engine) + ber_str(b"") + ber(0xA7, body))
        msg = self.wrap(secrets.randbelow(2 ** 31), scoped, c, 3)
        out = {}
        for host, port in trap_targets(conf.get("trap_to")):
            key = "%s:%d" % (host if ":" not in host else "[%s]" % host, port)
            try:
                for fam, _, _, _, sa in socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[:1]:
                    s = socket.socket(fam, socket.SOCK_DGRAM)
                    try:
                        s.sendto(msg, sa)
                    finally:
                        s.close()
                out[key] = "sent"
                SNMP_STATE["traps"] += 1
            except OSError as e:
                out[key] = str(e)
                SNMP_STATE["trap_error"] = "%s: %s" % (key, e)
        if out and all(v == "sent" for v in out.values()):
            SNMP_STATE["trap_error"] = ""       # every one went: the alert over (otp 1.0.249)
        return out


# -- a small manager: the page's own test ---------------------------------------------------
def snmp_get(host, port, c, oids, timeout=3.0):
    """Discovery, then one authPriv GET - as the monitoring asks. {oid: value as text}."""
    s = socket.socket(socket.AF_INET6 if ":" in str(host) else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        def ask(msg):
            s.sendto(msg, (host, port))
            return s.recv(65535)

        def pdu(rid):
            return ber(0xA0, ber_int(rid) + ber_int(0) + ber_int(0) + ber(0x30, b"".join(
                ber(0x30, ber_oid(o) + ber(0x05, b"")) for o in oids)))
        rid = secrets.randbelow(2 ** 31)
        disc = ber(0x30, ber_int(3) + ber(0x30, ber_int(rid) + ber_int(65507) + ber_str(b"\x04") + ber_int(3)) +
                   ber_str(ber(0x30, ber_str(b"") + ber_int(0) + ber_int(0) + ber_str(b"") +
                               ber_str(b"") + ber_str(b""))) +
                   ber(0x30, ber_str(b"") + ber_str(b"") + pdu(rid)))
        raw = ask(disc)
        _, s0, e0 = ber_read(raw, 0)
        it = ber_items(raw, s0, e0)
        sp = ber_read(raw, it[2][1])
        sec = ber_items(raw, sp[1], sp[2])
        engine = raw[sec[0][1]:sec[0][2]]
        boots = int.from_bytes(raw[sec[1][1]:sec[1][2]], "big")
        etime = int.from_bytes(raw[sec[2][1]:sec[2][2]], "big")
        fake = Agent.__new__(Agent)
        fake.engine, fake.boots, fake.started = engine, boots, time.monotonic() - etime
        fake.keys = snmp_keys(c, engine)
        fake.salt = int.from_bytes(secrets.token_bytes(8), "big")
        rid += 1
        scoped = ber(0x30, ber_str(engine) + ber_str(b"") + pdu(rid))
        msg = fake.wrap(rid, scoped, c, 7)
        raw = ask(msg)
        _, s0, e0 = ber_read(raw, 0)
        it = ber_items(raw, s0, e0)
        sp = ber_read(raw, it[2][1])
        sec = ber_items(raw, sp[1], sp[2])
        if it[3][0] != 4:
            # A Report in the clear (or authenticated only): which usmStats it counts says why.
            why = "?"
            try:
                sc = ber_items(raw, it[3][1], it[3][2])
                p = ber_items(raw, sc[2][1], sc[2][2])
                vb = ber_items(raw, p[3][1], p[3][2])[0]
                first = ber_items(raw, vb[1], vb[2])[0]
                o = oid_decode(raw[first[1]:first[2]])
                if o[:-2] == SNMP_USM_STATS:
                    why = REPORT_WORDS.get(o[-2], why)
            except (ValueError, IndexError):
                pass
            raise ValueError("a report, not an answer: %s" % why)
        iv = int.from_bytes(raw[sec[1][1]:sec[1][2]], "big").to_bytes(4, "big") + \
            int.from_bytes(raw[sec[2][1]:sec[2][2]], "big").to_bytes(4, "big") + raw[sec[5][1]:sec[5][2]]
        plain = snmp_cfb(fake.keys[1], iv, raw[it[3][1]:it[3][2]], True)
        _, s2, e2 = ber_read(plain, 0)
        sc = ber_items(plain, s2, e2)
        p = ber_items(plain, sc[2][1], sc[2][2])
        out = {}
        for vb in ber_items(plain, p[3][1], p[3][2]):
            parts = ber_items(plain, vb[1], vb[2])
            o = ".".join(str(x) for x in oid_decode(plain[parts[0][1]:parts[0][2]]))
            tag = parts[1][0]
            v = plain[parts[1][1]:parts[1][2]]
            out[o] = v.decode("utf-8", "replace") if tag == 4 else \
                str(int.from_bytes(v, "big")) if tag in (2, 0x41, 0x42, 0x43, 0x46) else v.hex()
        return out
    finally:
        s.close()
