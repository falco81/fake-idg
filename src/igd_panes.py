"""igd_panes.py - how a pane of Settings is put together (1.6.0).

otp's settings are one page each - Certificates and TLS, the firewall, the network,
the time, SSH, the database, backups, mail, alerts, monitoring, updates ... - and so
are fake-igd's. Each pane is a set of files of its own, so that one never touches
another's:

  web/admin/panes/NAME.php   its markup: <div class="ctl-pane" id="pane-NAME" hidden>…
  web/assets/pane-NAME.js    its drawing: PANE_LOAD.NAME = function () {…}
  src/api_NAME.py            its API: ROUTES, SETTINGS, on_saved(), background()
  deploy/root_NAME.py        what root does for it: serve(ask) -> {said: [...], ...}

The API (fake_igd_api.py) loads every src/api_*.py; root's helper (fake_igd_web.py)
every deploy/root_*.py beside it. A module of the API:

  NAME = "tls"                       # the pane, and the kind of its root asks
  SETTINGS = [ {key, name, says, kind, default, pane, ...}, ... ]
      kind: bool | int | text | choice | list | secret | textarea
      int: min, max · choice: choices [(value, words)] · text: check (fn value -> words or "")
      only_when: (other_key, value) - asleep unless that one is so (as otp's)
      restarts / root: what a change does (said on the pages)
  ROUTES = { ("GET", "/api/tls"): fn, ("POST", "/api/tls"): fn, ... }
      fn(ctx) -> dict (the answer). ctx: me, q, body(), need("fulladmin"), store, cfg,
      setting(key), ask_root(payload) -> id, root_result(), event(words, level), addr
      A route with PUBLIC = True on its function needs no sign-in (the API token still).
  on_saved(ctx, changed)             # after its settings were saved: {key: value}
  background(ctx)                    # once a minute, in the API's own thread

Settings of a module live in the database (meta "settings"), not in config.json:
saved on the pages with the same save bar, read with setting(key).
"""
import glob
import importlib.util
import json
import os
import re
import secrets
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
MODULES = []
SETTINGS = {}          # key -> its description (dict), every module's
ROUTES = {}            # (method, path) -> (module, fn)
PREFIX_ROUTES = []     # (method, prefix, module, fn) - routes ending in "/*"


def load(log=None):
    """Every api_*.py beside this file, once."""
    if MODULES:
        return MODULES
    for path in sorted(glob.glob(os.path.join(HERE, "api_*.py"))):
        name = os.path.basename(path)[:-3]
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
        except Exception as e:                              # noqa: BLE001 - one broken pane is not all of them
            if log:
                log("api: %s does not load: %s\n%s" % (name, e, traceback.format_exc()))
            continue
        MODULES.append(mod)
        for s in getattr(mod, "SETTINGS", []) or []:
            s = dict(s)
            s.setdefault("pane", getattr(mod, "NAME", name))
            s["module"] = getattr(mod, "NAME", name)
            SETTINGS[s["key"]] = s
        for (method, path_), fn in (getattr(mod, "ROUTES", {}) or {}).items():
            if path_.endswith("/*"):
                PREFIX_ROUTES.append((method, path_[:-1], mod, fn))
            else:
                ROUTES[(method, path_)] = (mod, fn)
    return MODULES


def route(method, path):
    hit = ROUTES.get((method, path))
    if hit:
        return hit
    for m, prefix, mod, fn in PREFIX_ROUTES:
        if m == method and path.startswith(prefix):
            return mod, fn
    return None


# ---- the settings of the modules (in the database) ---------------------------------
def values(store):
    try:
        got = json.loads(store.get_meta("settings") or "{}")
    except ValueError:
        got = {}
    return got if isinstance(got, dict) else {}


def value(store, key):
    s = SETTINGS.get(key)
    if s is None:
        raise KeyError(key)
    return values(store).get(key, s.get("default"))


def view(store, secret_set=None):
    """The modules' settings as the pages draw them (the same shape as config.json's)."""
    saved = values(store)
    out, panes = [], {}
    for key, s in SETTINGS.items():
        kind = s.get("kind", "text")
        v = saved.get(key, s.get("default"))
        row = {"key": key, "name": s.get("name", key), "says": s.get("says", ""),
               "short": s.get("short"), "default": s.get("default"), "pane": s["pane"],
               "secret": kind == "secret", "bool": kind == "bool", "list": kind == "list",
               "tall": kind == "textarea", "source": "database" if key in saved else "default",
               "source_says": "saved on these pages" if key in saved else "as it comes",
               "restarts": bool(s.get("restarts")), "root": bool(s.get("root"))}
        if kind == "secret":
            row["value"] = ""
            row["set"] = bool(v)
        elif kind == "list":
            row["value"] = ", ".join(str(x) for x in (v or [])) if isinstance(v, list) else (v or "")
            d = s.get("default") or []
            row["default"] = ", ".join(str(x) for x in d) if isinstance(d, list) else d
        else:
            row["value"] = v
        if kind == "choice":
            row["choices"] = [c[0] for c in s.get("choices", [])]
            row["choice_words"] = {c[0]: c[1] for c in s.get("choices", [])}
        if kind == "int":
            row["min"], row["max"] = s.get("min", 0), s.get("max", 10 ** 9)
        if s.get("only_when"):
            row["only_when"] = list(s["only_when"])
        out.append(row)
        panes.setdefault(s["pane"], []).append(key)
    return out, panes


def check(key, raw):
    """(value, None) or (None, words) - a value of a module's setting as the pages sent it."""
    s = SETTINGS[key]
    kind = s.get("kind", "text")
    if kind == "bool":
        return raw in (True, "true", "1", "on", 1), None
    raw = "" if raw is None else str(raw)
    if kind == "int":
        try:
            v = int(raw.strip())
        except ValueError:
            return None, "%s: a whole number" % s.get("name", key)
        lo, hi = s.get("min", 0), s.get("max", 10 ** 9)
        if v < lo or v > hi:
            return None, "%s: a whole number from %s to %s" % (s.get("name", key), lo, hi)
        return v, None
    if kind == "choice":
        if raw not in [c[0] for c in s.get("choices", [])]:
            return None, "%s: not one of the choices" % s.get("name", key)
        return raw, None
    if kind == "list":
        v = [x.strip() for x in re.split(r"[,\n]+", raw) if x.strip()]
        fn = s.get("check")
        if fn:
            for one in v:
                bad = fn(one)
                if bad:
                    return None, "%s: %s" % (s.get("name", key), bad)
        return v, None
    v = raw if kind == "textarea" else raw.strip()
    if len(v) > int(s.get("most", 4000)):
        return None, "%s: too long" % s.get("name", key)
    fn = s.get("check")
    if fn and v:
        bad = fn(v)
        if bad:
            return None, "%s: %s" % (s.get("name", key), bad)
    return v, None


def save(store, changes):
    """{key: value} checked and kept; returns {module_name: {key: value}} of what changed."""
    saved = values(store)
    changed = {}
    for key, raw in changes.items():
        s = SETTINGS[key]
        if s.get("kind") == "secret" and raw in (None, "", "•" * 8):
            continue
        v, err = check(key, raw)
        if err:
            raise ValueError(err)
        if saved.get(key, s.get("default")) != v:
            saved[key] = v
            changed.setdefault(s["module"], {})[key] = v
    if changed:
        store.set_meta("settings", json.dumps(saved))
    return changed


def module(name):
    for m in MODULES:
        if getattr(m, "NAME", None) == name:
            return m
    return None


# ---- what is asked of root (a queue of files: fake-igd-web.path) ------------------
def ask_folder(state_dir):
    return os.path.join(state_dir or "/var/lib/fake-igd", "web", "ask")


def ask_root(state_dir, kind, payload, by=""):
    """One ask of root, a file of its own in web/ask/ - asks never overwrite one another."""
    if not re.match(r"^[a-z][a-z0-9]{0,30}\Z", kind):
        raise ValueError("no such kind of ask: %s" % kind)
    folder = ask_folder(state_dir)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    ident = "%d-%s" % (int(time.time() * 1000), secrets.token_hex(4))
    body = {"id": ident, "kind": kind, "by": str(by)[:80], "at": time.time(), "payload": payload}
    tmp = os.path.join(folder, ".%s-%s.tmp" % (kind, ident))
    with open(tmp, "w") as f:
        json.dump(body, f)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(folder, "%s-%s.json" % (kind, ident)))
    return ident


def root_result(state_dir, kind):
    try:
        with open(os.path.join(state_dir or "/var/lib/fake-igd", "web", "result-%s.json" % kind),
                  encoding="utf-8") as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


class Ctx(object):
    """What a module's route is given."""

    def __init__(self, handler, method, path, q, me, store, cfg, mod, add_event):
        self.handler, self.method, self.path, self.q = handler, method, path, q
        self.me, self.store, self.cfg, self.mod = me, store, cfg, mod
        self._add_event = add_event
        self.addr = handler.addr() if handler is not None else ""
        self._body = None

    def arg(self, name, default=""):
        return (self.q.get(name) or [default])[0]

    def body(self, most=1024 * 1024):
        if self._body is None:
            self._body = self.handler.body(most) if self.handler is not None else {}
        return self._body

    def need(self, role="fulladmin"):
        if not self.me:
            raise PermissionError("not signed in")
        if role == "fulladmin" and self.me.get("role") != "fulladmin":
            raise PermissionError("this account may look, not change (read only)")
        return self.me

    def setting(self, key):
        return value(self.store, key)

    def ask_root(self, payload, kind=None):
        return ask_root(self.cfg.get("state_dir"), kind or getattr(self.mod, "NAME", ""), payload,
                        (self.me or {}).get("name", ""))

    def root_result(self, kind=None):
        return root_result(self.cfg.get("state_dir"), kind or getattr(self.mod, "NAME", ""))

    def event(self, words, level="info", kind=None):
        who = (self.me or {}).get("name", "")
        self._add_event(kind or getattr(self.mod, "NAME", "settings"), words, level, who, self.addr)
