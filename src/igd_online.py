"""igd_online.py - new versions of fake-igd from the web (1.4.0).

The same road as otp's (Settings → Upgrades → From the web, otp --upgrade-online):

  1. upgrade_url is looked at for fake-igd-X.Y.Z.tar.gz packages - a GitHub folder
     through GitHub's API (its own page when the API refuses), any other page by
     the links in it, or one package's own address. HTTPS only.
  2. The newest one newer than what runs here is offered; nothing is ever put in
     by itself.
  3. Asked for, it is fetched into /var/lib/fake-igd/upgrade/ and checked by
     fake_igd_upgrade.py --inspect: signed by a release key this machine trusts,
     every file the one signed, not older than what is installed.
  4. request.json is laid down beside it; systemd (fake-igd-upgrade.path) starts
     fake-igd-upgrade.service, which checks it all again as root and runs the
     package's own install.sh --upgrade --yes. status.json and last.log say how
     it went.

Used by `upnp upgrade ...`, the console and the web pages (fake_igd_api.py).
Only the standard library.
"""
import hashlib
import html
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

DEFAULT_URL = "https://github.com/falco81/fake-idg/tree/main/release"
STATE_DIR = os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd")
UPGRADE_DIR = os.path.join(STATE_DIR, "upgrade")
LIB_DIR = os.environ.get("FAKE_IGD_LIB", "/opt/fake-igd")
HELPER = os.path.join(LIB_DIR, "fake_igd_upgrade.py")
PATH_UNIT = "/etc/systemd/system/fake-igd-upgrade.path"
PKG_RE = re.compile(r"(?:^|/)(fake-igd-(\d+)\.(\d+)\.(\d+)\.tar\.gz)(?:\?|#|$)")
MOST_PACKED = 64 * 1024 * 1024
EVERY_S = 86400


def ver_tuple(v):
    try:
        return tuple(int(x) for x in str(v).split(".")[:3])
    except ValueError:
        return (0, 0, 0)


def _get(url, limit=4 * 1024 * 1024, accept="*/*", timeout=30, version=""):
    if not str(url).startswith("https://"):
        raise ValueError("only https:// addresses are asked: %s" % url)
    req = urllib.request.Request(url, headers={
        "User-Agent": "fake-igd/%s (+upgrade check)" % (version or "?"), "Accept": accept})
    ctx = ssl.create_default_context()
    # Settings → Proxy, when it is switched on for the new versions (1.6.0, as otp's); else straight
    # (and the service's own https_proxy, as before).
    proxy = ""
    try:
        import igd_proxy
        proxy = igd_proxy.url_for(None, "upgrade")
    except Exception:                                   # noqa: BLE001 - no proxy known: straight
        proxy = ""
    opener = (lambda: igd_proxy.open_url(None, "upgrade", req, timeout=timeout, context=ctx)) if proxy else \
        (lambda: urllib.request.urlopen(req, timeout=timeout, context=ctx))
    with opener() as r:
        final = r.geturl()
        if not str(final).startswith("https://"):
            raise ValueError("it was sent on to an address that is not https: %s" % final)
        data = r.read(limit + 1)
        if len(data) > limit:
            raise ValueError("the answer from %s is bigger than %d MB" % (url, limit >> 20))
        return data, r.headers.get("Content-Type") or "", final


def _ver_of(m):
    return tuple(int(x) for x in m.group(2, 3, 4))


def online_list(url, version=""):
    """The packages at `url`: [{'name', 'version', 'url', 'bytes'}], newest first."""
    url = str(url or "").strip()
    if not url:
        raise ValueError("no address to look at (upgrade_url)")
    found = {}

    def add(name, link, size=None):
        m = PKG_RE.search("/" + name)
        if not m or not str(link).startswith("https://"):
            return
        found[m.group(1)] = {"name": m.group(1), "version": "%d.%d.%d" % _ver_of(m),
                             "v": _ver_of(m), "url": link, "bytes": size}

    gh = re.match(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
                  r"(?:/tree/([^/]+)(?:/(.*?))?)?/?$", url)
    m1 = PKG_RE.search(urllib.parse.urlparse(url).path)
    if m1:
        # One package's own address - a GitHub page of it read as the file.
        link = url
        b = re.match(r"^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$", url)
        if b:
            link = "https://raw.githubusercontent.com/%s/%s/%s" % b.groups()
        add(m1.group(1), link)
    elif gh:
        owner, repo, ref, folder = gh.group(1), gh.group(2), gh.group(3), gh.group(4) or ""
        api = "https://api.github.com/repos/%s/%s/contents/%s" % (
            owner, repo, urllib.parse.quote(folder.strip("/")))
        if ref:
            api += "?ref=" + urllib.parse.quote(ref)
        try:
            data, _ct, _f = _get(api, accept="application/vnd.github+json", version=version)
            items = json.loads(data.decode("utf-8"))
        except Exception as e:                          # noqa: BLE001
            # GitHub's API refused (60 questions an hour without an account, or not
            # let through): the folder's own page, read for the names.
            try:
                data, _ct, _f = _get(url, version=version)
            except Exception:                           # noqa: BLE001
                raise ValueError("GitHub did not answer: %s" % (getattr(e, "reason", None) or e))
            items = []
            base = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
                owner, repo, ref or "HEAD", (folder.strip("/") + "/") if folder.strip("/") else "")
            for name in set(re.findall(r"fake-igd-\d+\.\d+\.\d+\.tar\.gz", data.decode("utf-8", "replace"))):
                items.append({"type": "file", "name": name, "download_url": base + name})
        if isinstance(items, dict):
            items = [items]
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and it.get("type") == "file" and it.get("download_url"):
                add(str(it.get("name") or ""), str(it["download_url"]), it.get("size"))
    else:
        data, ct, final = _get(url, version=version)
        text = data.decode("utf-8", "replace")
        try:
            items = json.loads(text) if "json" in ct or text.lstrip()[:1] in "[{" else None
        except ValueError:
            items = None
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    link = it.get("download_url") or it.get("url") or ""
                    add(str(it.get("name") or link), urllib.parse.urljoin(final, str(link)), it.get("size"))
        else:
            for href in re.findall(r'''href\s*=\s*["']([^"']+)["']''', text, re.I):
                link = urllib.parse.urljoin(final, html.unescape(href))
                mm = PKG_RE.search(urllib.parse.urlparse(link).path)
                if mm:
                    add(mm.group(1), link)
    out = sorted(found.values(), key=lambda x: x["v"], reverse=True)
    for x in out:
        x.pop("v", None)
    return out


def look(url, here, store=None, by=""):
    """Asks the address now: {'at', 'url', 'here', 'packages', 'newest', 'newer', 'error'}.
    Kept in the store (meta 'upgrade:online') when one is given."""
    row = {"at": time.time(), "url": url, "by": by, "here": here}
    try:
        got = online_list(url, here)
        row["packages"] = got[:10]
        newest = got[0] if got else None
        row["newest"] = newest
        row["newer"] = bool(newest and ver_tuple(newest["version"]) > ver_tuple(here))
        if row["newer"] and store is not None:
            was = store.meta_json("upgrade:online") or {}
            if (was.get("newest") or {}).get("version") != newest["version"]:
                store.add_event("upgrade", "fake-igd %s is out (%s)" % (newest["version"], url), "info")
    except Exception as e:                              # noqa: BLE001
        row["error"] = str(getattr(e, "reason", None) or e).split("\n")[0][:300]
    if store is not None:
        try:
            store.set_meta("upgrade:online", json.dumps(row, default=str))
        except Exception:                               # noqa: BLE001
            pass
    return row


def view(row, here):
    """What was found last, with every version newer than this one."""
    row = dict(row or {})
    if row:
        n = row.get("newest") or {}
        row["newer"] = bool(n and ver_tuple(n.get("version")) > ver_tuple(here))
        row["here"] = here
        row["newer_list"] = sorted((p for p in row.get("packages") or []
                                    if ver_tuple(p.get("version")) > ver_tuple(here)),
                                   key=lambda p: ver_tuple(p.get("version")), reverse=True)
    return row


# ---- the package --------------------------------------------------------------------
def inspect(path):
    """What the package is, asked of fake_igd_upgrade.py - the same check root makes
    again before putting it in."""
    if not os.path.exists(HELPER):
        raise ValueError("fake_igd_upgrade.py is not installed in %s - upgrade once on the command line "
                         "(install.sh --upgrade)" % LIB_DIR)
    py = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
    try:
        r = subprocess.run([py, "-I", HELPER, "--inspect", str(path)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        got = json.loads(r.stdout.decode("utf-8", "replace") or "{}")
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        raise ValueError("the package could not be checked: %s" % e)
    if not got.get("ok"):
        raise ValueError(got.get("said") or "the package was refused")
    return got


def _into_upgrade_dir(data_or_path, name):
    """The package into the upgrade folder under its own name - made beside it and
    renamed over it, never written through a link."""
    os.makedirs(UPGRADE_DIR, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".in-", suffix=".tar.gz", dir=UPGRADE_DIR)
    try:
        with os.fdopen(fd, "wb") as out:
            if isinstance(data_or_path, bytes):
                out.write(data_or_path)
            else:
                with open(data_or_path, "rb") as src:
                    while True:
                        lump = src.read(1 << 20)
                        if not lump:
                            break
                        out.write(lump)
        os.chmod(tmp, 0o640)
        info = inspect(tmp)
        final = os.path.join(UPGRADE_DIR, "fake-igd-%s.tar.gz" % info["version"])
        os.replace(tmp, final)
        tmp = None
        h = hashlib.sha256()
        with open(final, "rb") as f:
            for lump in iter(lambda: f.read(1 << 20), b""):
                h.update(lump)
        info["sha"] = h.hexdigest()
        info["file"] = final
        # Only the newest package kept.
        for one in os.listdir(UPGRADE_DIR):
            if one.endswith(".tar.gz") and one != os.path.basename(final) and one.startswith("fake-igd-"):
                try:
                    os.unlink(os.path.join(UPGRADE_DIR, one))
                except OSError:
                    pass
        return info
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def fetch(url, version, here):
    """The package of `version` fetched from where it is published and checked: its info."""
    pk = [p for p in online_list(url, here) if p["version"] == str(version)]
    if not pk:
        raise ValueError("fake-igd %s is not at %s any more" % (version, url))
    pk = pk[0]
    if ver_tuple(pk["version"]) <= ver_tuple(here):
        raise ValueError("fake-igd %s is not newer than %s, which runs here" % (pk["version"], here))
    data, _ct, final = _get(pk["url"], limit=MOST_PACKED, timeout=300, version=here)
    try:
        info = _into_upgrade_dir(data, pk["name"])
    except ValueError as e:
        raise ValueError("the package from %s was refused: %s" % (final, e))
    if info.get("older"):
        raise ValueError("%s is older than %s, which runs here" % (info["version"], info.get("installed")))
    info["from"] = final
    return info


def take_file(path):
    """A package file given by hand, checked and laid down: its info."""
    if not os.path.isfile(path):
        raise ValueError("%s is not a file" % path)
    if os.path.getsize(path) > MOST_PACKED:
        raise ValueError("the package is bigger than 64 MB")
    info = _into_upgrade_dir(path, os.path.basename(path))
    info["from"] = os.path.abspath(path)
    return info


def take_bytes(data):
    if len(data) > MOST_PACKED:
        raise ValueError("the package is bigger than 64 MB")
    info = _into_upgrade_dir(bytes(data), "upload.tar.gz")
    info["from"] = "sent from the pages"
    return info


def ask_root(info, by):
    """request.json beside the package: systemd's fake-igd-upgrade.path starts root's part."""
    if info.get("older"):
        raise ValueError("%s is older than %s, which runs here - going back is done on the command line"
                         % (info["version"], info.get("installed")))
    if not os.path.exists(PATH_UNIT):
        raise ValueError("fake-igd-upgrade.path is not installed - upgrade once on the command line "
                         "(install.sh --upgrade)")
    now = status()
    if now.get("busy"):
        raise ValueError("an upgrade is going on already")
    ident = "%d-%s" % (int(time.time()), secrets.token_hex(4))
    req = {"id": ident, "file": os.path.basename(info["file"]), "version": info["version"],
           "sha": info["sha"], "by": str(by or "")[:100], "at": time.time()}
    fd, tmp = tempfile.mkstemp(prefix=".req-", suffix=".json", dir=UPGRADE_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(req, f)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(UPGRADE_DIR, "request.json"))
    return ident


def _read_json(name):
    try:
        with open(os.path.join(UPGRADE_DIR, name), encoding="utf-8") as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def log_lines(most=400):
    try:
        with open(os.path.join(UPGRADE_DIR, "last.log"), encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()[-most:]
    except OSError:
        return []


def status():
    """Where an upgrade asked for stands: {'state', 'id', 'version', 'said', 'at', 'asked', 'busy'}."""
    st = _read_json("status.json")
    asked = os.path.exists(os.path.join(UPGRADE_DIR, "request.json"))
    taken = os.path.exists(os.path.join(UPGRADE_DIR, "request.taken"))
    req = _read_json("request.json") if asked else {}
    out = dict(st)
    out["asked"] = asked
    if asked:
        out.update({"state": "asked", "id": req.get("id"), "version": req.get("version"),
                    "asked_at": req.get("at")})
    out["busy"] = asked or taken or st.get("state") == "running"
    # A "running" that root's part never finished (the machine restarted under it): said as such.
    if st.get("state") == "running" and not taken and time.time() - float(st.get("at") or 0) > 30 * 60:
        out["state"] = "failed"
        out["said"] = "the upgrade never said that it ended"
        out["busy"] = False
    return out


def progress(lines):
    """(percent, words) of install.sh --upgrade from its output."""
    total = 0
    done = 0
    words = ""
    for ln in lines:
        m = re.search(r"^==> Upgrading fake-igd to \S+ \((\d+) steps\)", ln)
        if m:
            total = int(m.group(1))
        if ln.startswith("==> "):
            done += 1
            words = ln[4:].strip()
        if "checked" in ln and "signed by" in ln and not done:
            words = "the package checked"
    if not lines:
        return 0, "waiting for root to take it"
    if not total:
        return (5 if lines else 0), words or "starting"
    return min(97, int(5 + 92 * done / float(total + 1))), words
