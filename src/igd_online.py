"""igd_online.py - new versions of fake-igd from the web (1.4.0; the plan, going back and what is new
per version as otp's, 1.6.1).

The same road as otp's (Settings → Upgrades → From the web, otp --upgrade-online):

  1. upgrade_url is looked at for fake-igd-X.Y.Z.tar.gz packages - a GitHub folder
     through GitHub's API (its own page when the API refuses), any other page by
     the links in it, or one package's own address. HTTPS only.
  2. The newest one newer than what runs here is offered; nothing is ever put in
     by itself.
  3. Asked for, it is fetched into /var/lib/fake-igd/upgrade/ and checked by
     fake_igd_upgrade.py --inspect: signed by a release key this machine trusts,
     every file the one signed, not older than what is installed.
  4. request.json is laid down beside it (and plan.json, what the pages draw: who
     asked, when, for which version); systemd (fake-igd-upgrade.path) starts
     fake-igd-upgrade.service, which checks it all again as root and runs the
     package's own install.sh --upgrade --yes. status.json and last.log say how
     it went; plan() puts the three together as otp's plan of one node.
  5. Going back to an older version (otp 1.0.143): only one asked for as such,
     signed, not below DOWNGRADE_FLOOR nor the floor root keeps beside the program.

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
UNIT_DIR = os.environ.get("FAKE_IGD_UNIT_DIR", "/etc/systemd/system")
PATH_UNIT = os.path.join(UNIT_DIR, "fake-igd-upgrade.path")
WEB_PATH_UNIT = os.path.join(UNIT_DIR, "fake-igd-web.path")
# The oldest version the pages may go back to (otp's DOWNGRADE_FLOOR): 1.4.0 is the first with
# root's upgrade helper, the release keys and the accounts of the pages in the database - an older
# one could not come back up from the pages. Root's helper holds the same line, and the floor root
# keeps beside the program (downgrade-floor), when there is one, as well.
DOWNGRADE_FLOOR = "1.4.0"
FLOOR_FILE = os.path.join(LIB_DIR, "downgrade-floor")
UPGRADE_TIMEOUT_S = 30 * 60
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


def changelog_sections(text):
    """{version: its section of CHANGELOG.md, heading and all} (otp's changelog_sections)."""
    out = {}
    for m in re.finditer(r"^## (\d+\.\d+\.\d+)\b.*?(?=^## |\Z)", text or "", re.M | re.S):
        out[m.group(1)] = m.group(0).strip()[:20000]
    return out


def changelog_urls(url, final=""):
    """Where the CHANGELOG.md of the packages at `url` may be: the repository's own on GitHub,
    else beside the packages or one folder up."""
    gh = re.match(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/(?:tree|blob)/([^/]+))?", url or "")
    if gh:
        return ["https://raw.githubusercontent.com/%s/%s/%s/CHANGELOG.md" % (gh.group(1), gh.group(2),
                                                                             gh.group(3) or "HEAD")]
    raw = re.match(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/", url or "")
    if raw:
        return ["https://raw.githubusercontent.com/%s/%s/%s/CHANGELOG.md" % raw.groups()]
    base = final or url or ""
    if PKG_RE.search(urllib.parse.urlparse(base).path):
        base = base.rsplit("/", 1)[0] + "/"
    elif not base.endswith("/"):
        base += "/"
    return [urllib.parse.urljoin(base, "CHANGELOG.md"), urllib.parse.urljoin(base, "../CHANGELOG.md")]


def online_changelog_sections(url, here, upto, version=""):
    """What is new in each version newer than `here` up to `upto`, read from the CHANGELOG.md
    published beside the packages: {version: text} - {} when there is none."""
    for one in changelog_urls(url):
        try:
            data, _ct, _f = _get(one, limit=2 * 1024 * 1024, timeout=20, version=version or here)
        except Exception:                               # noqa: BLE001 - nothing published: nothing said
            continue
        got = changelog_sections(data.decode("utf-8", "replace"))
        keep = {v: t for v, t in got.items() if ver_tuple(here) < ver_tuple(v) <= ver_tuple(upto)}
        if got:
            return dict(sorted(keep.items(), key=lambda x: ver_tuple(x[0]), reverse=True)[:12])
    return {}


def look(url, here, store=None, by=""):
    """Asks the address now: {'at', 'url', 'here', 'packages', 'newest', 'newer', 'error',
    'changelog'}. Kept in the store (meta 'upgrade:online') when one is given."""
    row = {"at": time.time(), "url": url, "by": by, "here": here}
    try:
        got = online_list(url, here)
        row["packages"] = got[:10]
        newest = got[0] if got else None
        row["newest"] = newest
        row["newer"] = bool(newest and ver_tuple(newest["version"]) > ver_tuple(here))
        if row["newer"]:
            # What is new in each newer version (1.6.1), when the address publishes a CHANGELOG.md.
            row["changelog"] = online_changelog_sections(url, here, newest["version"])
        if row["newer"] and store is not None:
            was = store.meta_json("upgrade:online") or {}
            if (was.get("newest") or {}).get("version") != newest["version"]:
                store.add_event("upgrade", "fake-igd %s is out (%s) - Settings → Upgrades" % (newest["version"], url),
                                "info")
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
        row["newer_list"] = sorted((dict(p) for p in row.get("packages") or []
                                    if ver_tuple(p.get("version")) > ver_tuple(here)),
                                   key=lambda p: ver_tuple(p.get("version")), reverse=True)
        notes = row.get("changelog") or {}
        for p in row["newer_list"]:
            if notes.get(p.get("version")):
                p["changelog"] = notes[p["version"]]
    return row


def installed_changelog():
    """The CHANGELOG.md beside the program (installed), or the repository's own."""
    for one in (os.path.join(LIB_DIR, "CHANGELOG.md"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "CHANGELOG.md")):
        try:
            with open(one, encoding="utf-8", errors="replace") as f:
                return f.read(4 * 1024 * 1024)
        except OSError:
            continue
    return ""


def package_changelog(url, version, here):
    """CHANGELOG.md read out of the package of `version` at `url` - read, not checked (it is
    checked when it is chosen)."""
    import io
    import tarfile
    pk = next((p for p in online_list(url, here) if p["version"] == version), None)
    if not pk:
        raise ValueError("fake-igd %s is not at %s" % (version, url))
    data, _ct, _f = _get(pk["url"], limit=MOST_PACKED, timeout=120, version=here)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            m = next((x for x in tf.getmembers() if x.isfile() and
                      x.name == "fake-igd-%s/CHANGELOG.md" % version), None)
            return tf.extractfile(m).read(4 << 20).decode("utf-8", "replace") if m else ""
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ValueError("the package of %s does not read: %s" % (version, e))


def changelog_of(url, version, here, store=None):
    """What came in `version` - and, for an older one, what going back to it from here gives up:
    the sections of the versions after it up to this one (otp's downgrade_changelog). From the
    CHANGELOG.md here, from the one published beside the packages, else from the package."""
    version = str(version or "")
    if not re.match(r"^\d+\.\d+\.\d+\Z", version):
        raise ValueError("which version?")
    mine = changelog_sections(installed_changelog())
    lost = [{"version": v, "text": mine[v]} for v in sorted(mine, key=ver_tuple, reverse=True)
            if ver_tuple(version) < ver_tuple(v) <= ver_tuple(here)]
    entry, src = mine.get(version), "here"
    if entry is None and store is not None:
        entry = ((store.meta_json("upgrade:online") or {}).get("changelog") or {}).get(version)
        src = "address"
    if entry is None:
        entry = changelog_sections(package_changelog(url, version, here)).get(version) or ""
        src = "package"
    return {"version": version, "here": here, "entry": entry, "from": src, "lost": lost}


# ---- going back (otp 1.0.143) ---------------------------------------------------------
def root_floor():
    """The oldest version the versions installed here allow, as root keeps it, or None."""
    try:
        with open(FLOOR_FILE, encoding="utf-8") as f:
            text = f.read(64).strip()
    except OSError:
        return None
    return text if re.match(r"^\d+\.\d+\.\d+\Z", text) else None


def downgrade_why_not(version, here):
    """What stands in the way of going back to `version`: [] when nothing does."""
    v = ver_tuple(version)
    if v >= ver_tuple(here):
        return ["%s is not older than %s, which runs here - that is an upgrade" % (version, here)]
    why = []
    if v < ver_tuple(DOWNGRADE_FLOOR):
        why.append("older than %s, the first that is put in from these pages and comes back from them "
                   "(root's upgrade helper, the release keys, the accounts in the database): going back "
                   "further is done as root on the command line - upnp upgrade file "
                   "fake-igd-%s.tar.gz --downgrade" % (DOWNGRADE_FLOOR, version))
    root = root_floor()
    if root and v < ver_tuple(root):
        why.append("older than %s, the oldest the versions installed on this machine allow (%s)"
                   % (root, FLOOR_FILE))
    return why


def downgrade_list(url, here):
    """The older versions at `url`, each with what stands in its way (otp's downgrade_list)."""
    url = str(url or "").strip()
    if not url:
        raise ValueError("no upgrade_url is set (Settings → Upgrades)")
    out = []
    for p in online_list(url, here):
        if ver_tuple(p["version"]) >= ver_tuple(here):
            continue
        out.append(dict(p, why=downgrade_why_not(p["version"], here)))
    out.sort(key=lambda p: ver_tuple(p["version"]), reverse=True)
    root = root_floor()
    lowest = max([DOWNGRADE_FLOOR] + ([root] if root else []), key=ver_tuple)
    for p in out:
        if not p["why"]:
            p["short"] = ""
        elif ver_tuple(p["version"]) < ver_tuple(lowest):
            p["short"] = "below %s" % lowest
        else:
            p["short"] = p["why"][0][:80]
    return {"url": url, "here": here, "versions": out, "floor": DOWNGRADE_FLOOR, "root_floor": root,
            "lowest": lowest}


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


def fetch(url, version, here, older=False):
    """The package of `version` fetched from where it is published and checked: its info.
    `older`: one to go back to (otp 1.0.143), refused when anything stands in its way."""
    if older:
        why = downgrade_why_not(version, here)
        if why:
            raise ValueError("fake-igd %s cannot be gone back to: %s" % (version, "; ".join(why)))
    pk = [p for p in online_list(url, here) if p["version"] == str(version)]
    if not pk:
        raise ValueError("fake-igd %s is not at %s any more" % (version, url))
    pk = pk[0]
    if older and ver_tuple(pk["version"]) >= ver_tuple(here):
        raise ValueError("fake-igd %s is not older than %s, which runs here" % (pk["version"], here))
    if not older and ver_tuple(pk["version"]) <= ver_tuple(here):
        raise ValueError("fake-igd %s is not newer than %s, which runs here" % (pk["version"], here))
    data, _ct, final = _get(pk["url"], limit=MOST_PACKED, timeout=300, version=here)
    try:
        info = _into_upgrade_dir(data, pk["name"])
    except ValueError as e:
        raise ValueError("the package from %s was refused: %s" % (final, e))
    if info.get("older") and not older:
        raise ValueError("%s is older than %s, which runs here" % (info["version"], info.get("installed")))
    if older and not info.get("older"):
        raise ValueError("%s is not older than %s, which is installed" % (info["version"], info.get("installed")))
    info["from"] = final
    info["downgrade"] = bool(older)
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


def ask_root(info, by, downgrade=False):
    """request.json beside the package: systemd's fake-igd-upgrade.path starts root's part.
    plan.json beside it is what the pages and `upnp upgrade follow` draw. `downgrade`: an older
    version asked for as such (root's helper takes it only so, and never below its floor)."""
    if info.get("older") and not downgrade:
        raise ValueError("%s is older than %s, which runs here - going back is asked for as such "
                         "(Settings → Upgrades → Going back, or upnp upgrade online %s --downgrade)"
                         % (info["version"], info.get("installed"), info["version"]))
    if downgrade:
        if not info.get("older"):
            raise ValueError("%s is not older than %s - that is an upgrade" % (info["version"],
                                                                               info.get("installed")))
        why = downgrade_why_not(info["version"], info.get("installed") or "")
        if why:
            raise ValueError("; ".join(why))
    if not os.path.exists(PATH_UNIT):
        raise ValueError("fake-igd-upgrade.path is not installed - upgrade once on the command line "
                         "(install.sh --upgrade)")
    now = status()
    if now.get("busy"):
        raise ValueError("an upgrade is going on already")
    ident = "%d-%s" % (int(time.time()), secrets.token_hex(4))
    at = time.time()
    req = {"id": ident, "file": os.path.basename(info["file"]), "version": info["version"],
           "sha": info["sha"], "by": str(by or "")[:100], "at": at, "downgrade": bool(downgrade)}
    plan_row = {"id": ident, "version": info["version"], "sha": info["sha"], "by": str(by or "")[:100],
                "at": at, "downgrade": bool(downgrade), "from_version": info.get("installed") or "",
                "signed_by": info.get("signed_by") or ""}
    _write_json("plan.json", plan_row)
    _write_json("request.json", req)
    return ident


def _write_json(name, data):
    os.makedirs(UPGRADE_DIR, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".w-", suffix=".json", dir=UPGRADE_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o640)
    os.replace(tmp, os.path.join(UPGRADE_DIR, name))


def cancel(by=""):
    """Stop it (otp's upgrade_cancel), for the one node there is: only while root has not taken
    it yet - once install.sh runs, it is finished."""
    p = _read_json("plan.json")
    req = os.path.join(UPGRADE_DIR, "request.json")
    if not p or not os.path.exists(req):
        if os.path.exists(os.path.join(UPGRADE_DIR, "request.taken")) or status().get("state") == "running":
            raise ValueError("root is putting it in right now - that is finished, not stopped")
        raise ValueError("no upgrade is waiting to be stopped")
    try:
        os.unlink(req)
    except FileNotFoundError:
        raise ValueError("root took it a moment ago - it is finished, not stopped")
    p["cancelled"] = {"by": str(by or "")[:100], "at": time.time()}
    _write_json("plan.json", p)
    return p


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
    part, parts, words = parts_of(lines)
    if not lines:
        return 0, "waiting for root to take it"
    if not parts:
        return (5 if lines else 0), words or "starting"
    return min(97, int(5 + 92 * part / float(parts + 1))), words


def parts_of(lines):
    """(sections begun, sections in all, the last one's words) of install.sh's output - its
    "==> ..." lines (otp 1.0.67)."""
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
    return done, total, words


def plan(here, node=""):
    """The upgrade asked for last, as otp's plan of one node: {id, version, by, at, downgrade,
    state: running | done | failed | cancelled, steps: [{name, state, said, at, asked, part,
    parts, part_words, tail}]} - or None. state of the step: waiting (handed to root),
    installing (install.sh runs), checking (install.sh ended well, the new version not yet
    answering), done, failed, cancelled."""
    import socket
    p = _read_json("plan.json")
    st = status()
    if not p:
        # Asked by a version before plan.json (1.6.0 and older): what status.json says.
        if not st.get("id"):
            return None
        p = {"id": st.get("id"), "version": st.get("version"), "at": st.get("asked_at") or st.get("at"),
             "by": "", "downgrade": False}
    now = time.time()
    at = float(p.get("at") or 0)
    step = {"name": node or socket.gethostname().split(".")[0], "asked": at, "at": at}
    mine = st.get("id") == p.get("id")
    taken = os.path.exists(os.path.join(UPGRADE_DIR, "request.taken"))
    lines = log_lines(400)
    if p.get("cancelled"):
        c = p["cancelled"]
        step.update(state="cancelled", at=c.get("at") or at,
                    said="stopped%s before root took it; nothing was changed" % (
                        (" by %s" % c["by"]) if c.get("by") else ""))
    elif mine and st.get("asked"):
        late = now - at
        step.update(state="waiting", said="handed to root (fake-igd-upgrade.service)" if late < 60 else
                    "root has not taken it for %d min - is fake-igd-upgrade.path running? "
                    "(systemctl enable --now fake-igd-upgrade.path)" % max(1, int(late // 60)))
    elif (mine and st.get("state") == "running") or (taken and mine):
        part, parts, words = parts_of(lines)
        step.update(state="installing", at=float(st.get("at") or at), part=part, parts=parts,
                    part_words=words[:120], said="install.sh --upgrade runs (root)")
    elif mine and st.get("state") == "done":
        if ver_tuple(here) == ver_tuple(p.get("version")):
            step.update(state="done", at=float(st.get("at") or at), tail=(st.get("tail") or [])[-12:],
                        said="%s, checked, running" % here)
        elif now - float(st.get("at") or at) < 600:
            step.update(state="checking", at=float(st.get("at") or at),
                        said="install.sh ended well - waiting for the pages' API to come back as %s" % p.get("version"))
        else:
            step.update(state="failed", at=float(st.get("at") or at), tail=(st.get("tail") or [])[-40:],
                        said="install.sh said it ended well, but %s still runs here" % here)
    elif mine and st.get("state") == "failed":
        step.update(state="failed", at=float(st.get("at") or at), tail=(st.get("tail") or [])[-40:],
                    said=st.get("said") or "install.sh ended with %s" % st.get("rc"))
    elif now - at > 120:
        step.update(state="failed", said="fake-igd-upgrade.service never took the request - is "
                    "fake-igd-upgrade.path installed and running? (install.sh --upgrade once on the "
                    "command line puts it in)")
    else:
        step.update(state="waiting", said="handed to root (fake-igd-upgrade.service)")
    p["steps"] = [step]
    p["state"] = {"waiting": "running", "installing": "running", "checking": "running"}.get(
        step["state"], step["state"])
    p["here"] = here
    return p
