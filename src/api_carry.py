"""api_carry.py - Settings → Export and import (otp's pane `carry`, for fake-igd).

The whole configuration as one JSON file, to download and to read back here or on another
machine running fake-igd: config.json's settings, every setting saved on these pages, the
accounts of the pages (names, roles, notes), the destinations of the backups and
avahi-daemon.conf (the mDNS reflector). With the secrets, also the ntfy token and password,
the secret settings (the password of the backups), the password hashes of the accounts, the
passwords and keys of the destinations, and the certificate and key of the pages (collected
by root) - and then the file is locked with a passphrase made at that moment and shown once,
as otp's bundle_lock: scrypt (2^15, 8, 1), an HMAC-SHA256 key stream, an HMAC-SHA256 tag
over the kind and the whole.

Not in it: the events, who is signed in, the copies of the database - those move with a
backup (Settings → Backups). This machine's own paths and port (state_dir, log_file,
request_log, api_port) are neither exported nor read back.

Import: "Add to what is here" - accounts and destinations of the same name are replaced,
everything else here stays; "Exactly the file" - accounts and destinations not in it are
taken away, settings not in it go back to their defaults. Your own account is left as it is.
"""
import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import socket
import sys
import tarfile
import time

NAME = "carry"
KIND = "fake-igd-config"
LOCKED_KIND = "fake-igd-config-locked"
MACHINE_KEYS = ("state_dir", "log_file", "request_log", "api_port")
HASH_RE = re.compile(r"^scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+\Z")
ROOT_WAIT_S = 60
SETTINGS = []


# ---- otp's bundle_lock / bundle_open -------------------------------------------------------
def _key(passphrase, salt):
    return hashlib.scrypt(str(passphrase).encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def _stream(key, nonce, size):
    out, block = bytearray(), 0
    while len(out) < size:
        out += hmac.new(key, b"stream" + nonce + block.to_bytes(8, "big"), hashlib.sha256).digest()
        block += 1
    return bytes(out[:size])


def bundle_lock(data, passphrase):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    key = _key(passphrase, salt)
    raw = json.dumps(data).encode("utf-8")
    hide = hmac.new(key, b"hide", hashlib.sha256).digest()
    sign = hmac.new(key, b"sign", hashlib.sha256).digest()
    body = bytes(a ^ b for a, b in zip(raw, _stream(hide, nonce, len(raw))))
    tag = hmac.new(sign, LOCKED_KIND.encode() + b"\n" + salt + nonce + body, hashlib.sha256).digest()
    return {"kind": LOCKED_KIND, "format": 2, "made": time.time(), "from": node_name(), "version": version(),
            "locked": base64.b64encode(salt + nonce + body + tag).decode("ascii")}


def bundle_open(bundle, passphrase):
    try:
        raw = base64.b64decode(bundle.get("locked") or "")
    except (ValueError, TypeError):
        raise ValueError("the file is damaged")
    if len(raw) < 16 + 16 + 32:
        raise ValueError("the file is damaged")
    salt, nonce, body, tag = raw[:16], raw[16:32], raw[32:-32], raw[-32:]
    key = _key(passphrase, salt)
    sign = hmac.new(key, b"sign", hashlib.sha256).digest()
    if not hmac.compare_digest(tag, hmac.new(sign, LOCKED_KIND.encode() + b"\n" + salt + nonce + body,
                                             hashlib.sha256).digest()):
        raise ValueError("the passphrase is not the one the file was locked with")
    hide = hmac.new(key, b"hide", hashlib.sha256).digest()
    return json.loads(bytes(a ^ b for a, b in zip(body, _stream(hide, nonce, len(body)))).decode("utf-8"))


def passphrase_new():
    words = "abcdefghijkmnopqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(words) for _ in range(5)) for _ in range(5))


# ---- what there is -----------------------------------------------------------------------------
def node_name():
    return socket.gethostname().split(".")[0] or "fake-igd"


def version():
    v = getattr(sys.modules.get("__main__"), "VERSION", "")
    if v:
        return v
    try:
        import upnp as U
        return U.VERSION
    except Exception:                                       # noqa: BLE001
        return "?"


def U():
    import upnp
    return upnp


def PN():
    import igd_panes
    return igd_panes


def backup_mod():
    mod = sys.modules.get("api_backup")
    if mod is None:
        import api_backup as mod                            # noqa: F811
    return mod


def cfg_path():
    return getattr(sys.modules.get("__main__"), "CFG_PATH", None) or os.environ.get("FAKE_IGD_CONFIG",
                                                                                     "/etc/fake-igd/config.json")


def avahi_path():
    try:
        import upnp_mdns as M
        return M.CONF
    except Exception:                                       # noqa: BLE001
        return os.environ.get("UPNP_AVAHI_CONF", "/etc/avahi/avahi-daemon.conf")


def read_text(path, most=256 * 1024):
    try:
        with open(path, encoding="utf-8") as f:
            t = f.read(most + 1)
        return t if len(t) <= most else None
    except (OSError, UnicodeDecodeError):
        return None


def export(ctx, with_secrets):
    u = U()
    try:
        with open(cfg_path(), encoding="utf-8") as f:
            conf = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError("%s does not read: %s" % (cfg_path(), e))
    config = {k: v for k, v in conf.items() if k in u.DEFAULTS and k not in MACHINE_KEYS
              and (with_secrets or k not in u.SECRET_KEYS)}
    pn = PN()
    saved = pn.values(ctx.store)
    settings = {k: v for k, v in saved.items() if k in pn.SETTINGS
                and (with_secrets or pn.SETTINGS[k].get("kind") != "secret")}
    import igd_seal as SEAL
    for k, v in list(settings.items()):                      # opened: another machine has another key
        if pn.SETTINGS[k].get("kind") == "secret" or SEAL.is_sealed(v):
            settings[k] = SEAL.unseal_or(ctx.store, v)
    users = []
    for r in ctx.store.rows("SELECT name, role, note, must_change, hash FROM users ORDER BY name"):
        one = {"name": r["name"], "role": r["role"], "note": r["note"]}
        if with_secrets:
            one.update({"hash": r["hash"], "must_change": bool(r["must_change"])})
        users.append(one)
    bm = backup_mod()
    targets = []
    for t in bm.targets(ctx):
        t = dict(t)
        t.pop("id", None)
        if not with_secrets:
            for k in bm.SECRET_FIELDS:
                t.pop(k, None)
        targets.append(t)
    out = {"kind": KIND, "format": 1, "version": version(), "made": time.time(), "from": node_name(),
           "site": conf.get("site_name") or "", "secrets": bool(with_secrets), "config": config,
           "settings": settings, "users": users, "backup_targets": targets}
    av = read_text(avahi_path())
    if av is not None:
        out["avahi"] = av
    return out


def tls_from_root(ctx):
    """The certificate and key of the pages, collected by root - or ({}, why not)."""
    bm = backup_mod()
    try:
        got = bm.root_wait(ctx, {"do": "collect", "only": ["tls"]}, ROOT_WAIT_S)
    except bm.RbError as e:
        return {}, str(e)
    path = os.path.join(bm.base_dir(ctx), "work", got["tar"])
    tls = {}
    try:
        with tarfile.open(path, "r:") as tf:
            for m in tf.getmembers():
                if m.isreg() and m.size < 1024 * 1024:
                    text = tf.extractfile(m).read().decode("utf-8", "replace")
                    if m.name.endswith("fake-igd.pem"):
                        tls["cert"] = text
                    elif m.name.endswith("fake-igd.key"):
                        tls["key"] = text
    finally:
        os.unlink(path)
    return tls, "" if tls else "root found no certificate"


# ---- reading one back ---------------------------------------------------------------------------
def plain_of(conf, passphrase):
    if not isinstance(conf, dict):
        raise ValueError("the file is not a JSON object - is it the right file?")
    if conf.get("kind") == LOCKED_KIND:
        if not passphrase:
            raise ValueError("it is locked: the passphrase shown when it was exported opens it")
        conf = bundle_open(conf, passphrase)
    if conf.get("kind") != KIND:
        raise ValueError("that is not a file of fake-igd's Export (its kind is %r)" % str(conf.get("kind"))[:40])
    return conf


def import_users(ctx, rows, replace, me):
    import igd_store as ST
    said, made = [], []
    names = set()
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or "")
        role = str(r.get("role") or "")
        if not ST.NAME_RE.match(name) or role not in ST.ROLES:
            said.append("an account left out: %r" % name[:40])
            continue
        names.add(name.lower())
        if name.lower() == me.lower():
            continue
        note = str(r.get("note") or "")[:200]
        h = r.get("hash")
        have = ctx.store.user(name)
        if isinstance(h, str) and HASH_RE.match(h):
            now = time.time()
            if have:
                ctx.store.run("UPDATE users SET role = ?, hash = ?, note = ?, must_change = ?, changed = ? "
                              "WHERE name = ?", (role, h, note, 1 if r.get("must_change") else 0, now, name))
            else:
                ctx.store.run("INSERT INTO users (name, role, hash, note, must_change, created, changed) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?)", (name, role, h, note, 1 if r.get("must_change") else 0,
                                                               now, now))
        elif have:
            ctx.store.set_role(name, role) if have["role"] != role else None
            ctx.store.set_note(name, note)
        else:
            pw = secrets.token_urlsafe(12)
            ctx.store.add_user(name, pw, role, note, must_change=True)
            made.append({"name": name, "password": pw})
    gone = []
    if replace:
        for u in ctx.store.users():
            if u["name"].lower() not in names and u["name"].lower() != me.lower():
                try:
                    ctx.store.delete_user(u["name"])
                    gone.append(u["name"])
                except Exception as e:                      # noqa: BLE001 - the last full admin stays
                    said.append("%s stays: %s" % (u["name"], e))
    return said, made, gone


def import_targets(ctx, rows, replace):
    bm = backup_mod()
    have = bm.targets(ctx)
    by_name = {t["name"]: t for t in have}
    out = [] if replace else list(have)
    n = 0
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        old = by_name.get(str(r.get("name") or ""))
        data = dict(r)
        if "password" not in data:
            data["password"] = None                          # kept, when it is the same server
        try:
            t = bm.checked(data, old)
        except ValueError:
            data["password"] = ""
            t = bm.checked(data, None)
        for k in ("key", "pub", "key_pass", "hostkey"):
            if r.get(k):
                t[k] = r[k]
        out = [x for x in out if x["name"] != t["name"]] + [t]
        n += 1
    bm.put_targets(ctx, out[:bm.TARGETS_MOST])
    return n


def import_conf(ctx, conf, replace):
    """config.json's keys and the settings of the panes, through the API's own save - each value
    checked as when it is typed on the pages."""
    u = U()
    pn = PN()
    changes = {}
    cfg = conf.get("config") if isinstance(conf.get("config"), dict) else {}
    for k, v in cfg.items():
        if k in u.DEFAULTS and k not in MACHINE_KEYS:
            changes[k] = v
    sets = conf.get("settings") if isinstance(conf.get("settings"), dict) else {}
    for k, v in sets.items():
        if k in pn.SETTINGS:
            changes[k] = v
    if replace:
        for k, d in u.DEFAULTS.items():
            if k not in changes and k not in MACHINE_KEYS and k not in u.SECRET_KEYS:
                changes[k] = d
        for k, s in pn.SETTINGS.items():
            if k not in changes and s.get("kind") != "secret":
                changes[k] = s.get("default")
    for k in list(changes):                                   # lists as the settings take them
        if isinstance(changes[k], list):
            changes[k] = ", ".join(str(x) for x in changes[k])
    main = sys.modules.get("__main__")
    if main is None or not hasattr(main, "settings_save"):
        raise ValueError("the settings cannot be saved from here")
    who = (ctx.me or {}).get("name", "")
    return main.settings_save(changes, who, ctx.addr)


def import_system(ctx, conf):
    """avahi-daemon.conf, and the certificate and key of the pages, put back by root."""
    files = {}
    if isinstance(conf.get("avahi"), str) and conf["avahi"].strip():
        files["etc/avahi/avahi-daemon.conf"] = conf["avahi"]
    tls = conf.get("tls") if isinstance(conf.get("tls"), dict) else {}
    if isinstance(tls.get("cert"), str) and isinstance(tls.get("key"), str):
        files["etc/nginx/certs/fake-igd.pem"] = tls["cert"]
        files["etc/nginx/certs/fake-igd.key"] = tls["key"]
    if not files:
        return ["no system files in it"]
    bm = backup_mod()
    job = secrets.token_hex(8)
    path = os.path.join(bm.sub(ctx, "work"), "restore-%s.tar" % job)
    with tarfile.open(path, "w") as tf:
        for name, text in files.items():
            data = text.encode("utf-8")
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = int(time.time())
            tf.addfile(ti, io.BytesIO(data))
    os.chmod(path, 0o640)
    old = bm.ROOT_WAIT_S
    try:
        bm.ROOT_WAIT_S = ROOT_WAIT_S
        got = bm.root_restore(ctx, job, apply=False)
    finally:
        bm.ROOT_WAIT_S = old
    if not got.get("ok") and "did not answer" in " ".join(got.get("said") or []):
        return ["root has not answered yet - avahi-daemon.conf and the certificate are put in when it does"]
    return got.get("said") or []


# ---- the routes ------------------------------------------------------------------------------------
def get_carry(ctx):
    ctx.need("fulladmin")
    plain = export(ctx, False)
    return {"what": {"config": len(plain["config"]), "settings": len(plain["settings"]),
                     "users": len(plain["users"]), "backup_targets": len(plain["backup_targets"]),
                     "avahi": "avahi" in plain}, "node": node_name(), "version": version()}


def post_carry(ctx):
    ctx.need("fulladmin")
    b = ctx.body()
    act = str(b.get("action") or "")
    who = ctx.me["name"]
    if act == "export":
        if not b.get("secrets"):
            ctx.event("%s exported the configuration (without the secrets)" % who)
            return {"config": export(ctx, False), "name": "fake-igd-config-%s.json" % time.strftime("%Y%m%d-%H%M%S")}
        data = export(ctx, True)
        tls, why = tls_from_root(ctx)
        if tls:
            data["tls"] = tls
        phrase = passphrase_new()
        ctx.event("%s exported the configuration WITH the secrets (locked with a passphrase)%s"
                  % (who, "" if tls else " - without the certificate: " + why), "warn")
        return {"bundle": bundle_lock(data, phrase), "passphrase": phrase, "tls": bool(tls), "tls_said": why,
                "name": "fake-igd-config-complete-locked-%s.json" % time.strftime("%Y%m%d-%H%M%S")}
    raise ValueError("no such action")


def post_import(ctx):
    ctx.need("fulladmin")
    b = ctx.body(most=8 * 1024 * 1024)
    who = ctx.me["name"]
    conf = b.get("config")
    if isinstance(conf, dict) and isinstance(conf.get("config"), dict) and conf.get("kind") not in (KIND, LOCKED_KIND):
        conf = conf["config"]
    conf = plain_of(conf, str(b.get("passphrase") or ""))
    replace = b.get("replace") is True
    if b.get("check"):
        return {"says": {"from": conf.get("from"), "version": conf.get("version"), "made": conf.get("made"),
                         "secrets": bool(conf.get("secrets")), "config": len(conf.get("config") or {}),
                         "settings": len(conf.get("settings") or {}), "users": len(conf.get("users") or []),
                         "backup_targets": len(conf.get("backup_targets") or []), "avahi": bool(conf.get("avahi")),
                         "tls": bool(conf.get("tls"))}}
    saved = import_conf(ctx, conf, replace)
    usaid, made, gone = import_users(ctx, conf.get("users"), replace, who)
    n_t = import_targets(ctx, conf.get("backup_targets"), replace)
    sys_said = import_system(ctx, conf)
    words = "%d setting(s) changed, %d account(s), %d destination(s) of the backups%s" % (
        len(saved.get("saved") or []), len(conf.get("users") or []), n_t,
        (", %d account(s) taken away" % len(gone)) if gone else "")
    ctx.event("%s imported a configuration from %s (%s): %s" % (who, conf.get("from") or "?",
                                                                "exactly the file" if replace else "added to what was here",
                                                                words), "warn")
    return {"message": "imported - " + words, "made": made, "said": usaid + sys_said, "restart": saved.get("restart")}


ROUTES = {("GET", "/api/carry"): get_carry, ("POST", "/api/carry"): post_carry,
          ("POST", "/api/carry/import"): post_import}
