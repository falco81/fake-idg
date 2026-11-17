"""igd_seal.py - secrets kept sealed in the database, as otp's seal_secret / unseal_secret.

What fake-igd keeps of somebody else's - the passwords and keys of the backups'
destinations, the password of the backups, the mail server's password, the proxy's,
the token of /metrics, the ACME account key and the DNS APIs' secrets - is written
to the database sealed with a key kept beside it: secrets.key in the database's
folder (/var/lib/fake-igd/secrets.key), 32 random bytes as hex, 0600, the fake-igd
account's. A copy of the database alone opens none of them; a backup carries the key
beside it (and RESTORE.md says to put it back).

The construction is otp's, stdlib only:
  hide = HMAC-SHA256(key, "hide"), sign = HMAC-SHA256(key, "sign")
  body = text XOR HMAC-SHA256(hide, "stream" + nonce + block#) ...   (nonce: 16 random bytes)
  tag  = HMAC-SHA256(sign, nonce + body)[:16]                         -> "sealed:1:" + b64url(nonce+body+tag)
  with bind: tag over "2|" + bind + "|" + nonce + body                -> "sealed:2:..."
A value bound (bind="backup:NAME", say) opens only for that bind: copied into another
row it does not open.

  import igd_seal as SEAL
  v = SEAL.seal(store, "the password", bind=None)     # -> "sealed:1:...", the key made if there is none
  SEAL.unseal(store, v, bind=None)                    # -> "the password"; None if this key did not seal it;
                                                      #    a value never sealed comes back as it is
  SEAL.is_sealed(v)                                   # -> True for "sealed:1:" / "sealed:2:"
  SEAL.key_path(store)                                # -> the folder of the database + "/secrets.key"

`store` is anything with .path (the database file) - igd_store.Store - or a folder
as a string. With get_meta/set_meta, a fingerprint of the key is noted ("seal:fp")
when it is made, and no new key is made while one is noted and the file is gone
(otp 1.0.205): every secret sealed with the lost one would silently stop opening.
FAKE_IGD_SEAL_KEY (a path) overrides where the key is, for tests.
"""
import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

SEALED = "sealed:1:"
SEALED2 = "sealed:2:"
_CACHE = {}
_LOCK = threading.Lock()
_SETTINGS_LOCK = threading.RLock()
LOOK_S = 1.0


def key_path(store=None):
    env = os.environ.get("FAKE_IGD_SEAL_KEY")
    if env:
        return env
    if isinstance(store, str):
        folder = store
    else:
        p = getattr(store, "path", None) or os.environ.get("FAKE_IGD_DB") or ""
        folder = os.path.dirname(p) if p else (os.environ.get("FAKE_IGD_STATE") or "/var/lib/fake-igd")
    return os.path.join(folder or ".", "secrets.key")


def forget():
    _CACHE.clear()


def _read(path):
    """The key (32 bytes), b"" when the file is there but not a key, None when it is not there."""
    got = _CACHE.get(path)
    if got and time.monotonic() - got[2] < LOOK_S:
        return got[1]
    try:
        st = os.stat(path)
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    except FileNotFoundError:
        _CACHE.pop(path, None)
        return None
    except OSError:
        return b""
    if got and got[0] == stamp:
        _CACHE[path] = (stamp, got[1], time.monotonic())
        return got[1]
    try:
        with open(path, encoding="ascii") as f:
            key = bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return b""
    if len(key) != 32:
        return b""
    _CACHE[path] = (stamp, key, time.monotonic())
    return key


def fingerprint(key):
    return hashlib.sha256(b"fake-igd seal|" + key).hexdigest()[:16]


def key(store=None, make=False):
    """The key every secret is sealed with: b"" when there is none (and make is False)."""
    path = key_path(store)
    k = _read(path)
    if k:
        return k
    if not make:
        return b""
    if k == b"":
        raise OSError("%s is there but cannot be read as a key - it is never replaced, because every "
                      "secret sealed with it would be lost" % path)
    noted = ""
    if hasattr(store, "get_meta"):
        try:
            noted = store.get_meta("seal:fp") or ""
        except Exception:                                   # noqa: BLE001 - a guard, not a need
            noted = ""
    if noted:
        raise OSError("%s is missing, and the database holds secrets sealed with it (%s): no new key is "
                      "made - put the key back (it is beside every backup)" % (path, noted))
    with _LOCK:
        k = secrets.token_bytes(32)
        folder = os.path.dirname(path) or "."
        os.makedirs(folder, mode=0o750, exist_ok=True)
        tmp = "%s.new-%d-%s" % (path, os.getpid(), secrets.token_hex(4))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(k.hex() + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:                             # made by another process a moment ago: theirs
            os.unlink(tmp)
            forget()
            return _read(path) or b""
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if hasattr(store, "set_meta"):
            try:
                store.set_meta("seal:fp", fingerprint(k))
            except Exception:                               # noqa: BLE001
                pass
    forget()
    return k


def _stream(hide, nonce, size):
    out = bytearray()
    block = 0
    while len(out) < size:
        out += hmac.new(hide, b"stream" + nonce + block.to_bytes(8, "big"), hashlib.sha256).digest()
        block += 1
    return bytes(out[:size])


def is_sealed(value):
    return isinstance(value, str) and (value.startswith(SEALED) or value.startswith(SEALED2))


def seal_with(k, text, bind=None):
    data = str(text).encode("utf-8")
    nonce = secrets.token_bytes(16)
    hide = hmac.new(k, b"hide", hashlib.sha256).digest()
    sign = hmac.new(k, b"sign", hashlib.sha256).digest()
    body = bytes(a ^ b for a, b in zip(data, _stream(hide, nonce, len(data))))
    if bind is not None:
        tag = hmac.new(sign, b"2|" + str(bind).encode("utf-8") + b"|" + nonce + body, hashlib.sha256).digest()[:16]
        return SEALED2 + base64.urlsafe_b64encode(nonce + body + tag).decode("ascii")
    tag = hmac.new(sign, nonce + body, hashlib.sha256).digest()[:16]
    return SEALED + base64.urlsafe_b64encode(nonce + body + tag).decode("ascii")


def unseal_with(k, value, bind=None):
    if not isinstance(value, str):
        return value
    if value.startswith(SEALED2):
        v2, prefix = True, SEALED2
    elif value.startswith(SEALED):
        v2, prefix = False, SEALED
    else:
        return value
    if v2 and bind is None:
        return None
    try:
        raw = base64.urlsafe_b64decode(value[len(prefix):].encode("ascii"))
    except (ValueError, TypeError):
        return None
    if not k or len(raw) < 32:
        return None
    nonce, body, tag = raw[:16], raw[16:-16], raw[-16:]
    sign = hmac.new(k, b"sign", hashlib.sha256).digest()
    signed = (b"2|" + str(bind).encode("utf-8") + b"|" if v2 else b"") + nonce + body
    if not hmac.compare_digest(tag, hmac.new(sign, signed, hashlib.sha256).digest()[:16]):
        return None
    hide = hmac.new(k, b"hide", hashlib.sha256).digest()
    try:
        return bytes(a ^ b for a, b in zip(body, _stream(hide, nonce, len(body)))).decode("utf-8")
    except UnicodeDecodeError:
        return None


def seal(store, text, bind=None):
    """text sealed with this installation's key (made if there is none). "" and None stay as they are,
    and a value already sealed is not sealed twice."""
    if text is None or text == "" or is_sealed(text):
        return text
    return seal_with(key(store, make=True), text, bind)


def unseal(store, value, bind=None):
    """The secret back; None where this key did not seal it; a value never sealed as it is."""
    if not is_sealed(value):
        return value
    return unseal_with(key(store), value, bind)


def unseal_or(store, value, bind=None, default=""):
    got = unseal(store, value, bind)
    return default if got is None else got


# ---- the settings of the pages (meta "settings") whose kind is "secret" ----------------
def seal_settings(store, keys):
    """The secret settings among keys sealed in place in meta "settings" (igd_panes keeps them as
    they were typed): called from a module's on_saved and background. Returns how many it sealed."""
    import json
    try:
        import igd_panes as PN
        lock = PN.SAVE_LOCK                                 # the same lock as a save of the pages
    except (ImportError, AttributeError):
        lock = _SETTINGS_LOCK
    with lock:
        try:
            saved = json.loads(store.get_meta("settings") or "{}")
        except ValueError:
            return 0
        if not isinstance(saved, dict):
            return 0
        n = 0
        for k in keys:
            v = saved.get(k)
            if isinstance(v, str) and v and not is_sealed(v):
                saved[k] = seal(store, v)
                n += 1
        if n:
            store.set_meta("settings", json.dumps(saved))
        return n


def setting(store, key_, default=""):
    """A secret setting of the pages, opened (igd_panes.value + unseal)."""
    import igd_panes as PN
    try:
        v = PN.value(store, key_)
    except KeyError:
        return default
    got = unseal(store, v)
    return default if got is None else (got or default)
