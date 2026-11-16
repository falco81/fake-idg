"""api_tls.py - Settings → Certificates and TLS (otp's pane "web", for one server).

The certificate nginx answers these pages with, as it is now (read from its file: the
subject, the issuer, the names, how long it is good, the chain, signed by itself or not),
and what may be done with it - as otp's Certificates and TLS:

  * Upload  - PEM (the certificate, its key, the chain, the root - in any order, or all in
              one) pasted or read from files, or a PFX / PKCS#12 file with its password;
              checked here with openssl: the key is the certificate's own, it has not run
              out, the chain is put in order (each the issuer of the one before) and checked
              against the system's roots;
  * Request (CSR) - a key made here and kept for the certificate the authority sends back;
  * Self-signed   - made again, for the names in nginx's server_name and the machine's
              IPv4 addresses (as install.sh makes it);
  * TLS settings  - the protocols and ciphers (otp's presets: standard, Mozilla
              intermediate, Mozilla modern, custom), the DH parameters, whether the server
              chooses the cipher, HSTS.

Nothing here writes to /etc: what is put in is asked of root (deploy/root_tls.py), which
writes /etc/nginx/certs/fake-igd.pem and .key, edits fake-igd.conf, asks nginx -t, puts the
files back when nginx says no and reloads it. Automatic certificates (api_acme.py) put their
certificate in through the same ask (put_pem below).
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

NAME = "tls"
SETTINGS = []            # the TLS settings are otp's dialog "TLS settings", kept in the database

CERT_DIR = os.environ.get("FAKE_IGD_CERT_DIR", "/etc/nginx/certs")
NGINX_CONF = os.environ.get("FAKE_IGD_NGINX", "/etc/nginx/conf.d/fake-igd.conf")
OPENSSL = os.environ.get("FAKE_IGD_OPENSSL", "openssl")
CA_FILES = ("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/certs/ca-certificates.crt")


def files():
    return {"cert": os.path.join(CERT_DIR, "fake-igd.pem"), "key": os.path.join(CERT_DIR, "fake-igd.key"),
            "cert2": os.path.join(CERT_DIR, "fake-igd-ecdsa.pem"),
            "dh": os.path.join(CERT_DIR, "fake-igd-dh.pem"),
            "before": os.path.join(CERT_DIR, "fake-igd.pem.before-acme")}


# otp's TLS_PRESETS and DH_WORDS, as they are.
TLS_PRESETS = {
    "standard": {"protocols": ["TLSv1.2", "TLSv1.3"], "ciphers": (
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")},
    "intermediate": {"protocols": ["TLSv1.2", "TLSv1.3"], "ciphers": (
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305")},
    "modern": {"protocols": ["TLSv1.3"], "ciphers": ""},
}
DH_WORDS = {"none": "none (ECDHE only needs none)",
            "ffdhe2048": "RFC 7919 ffdhe2048", "ffdhe3072": "RFC 7919 ffdhe3072",
            "ffdhe4096": "RFC 7919 ffdhe4096", "gen2048": "made here, 2048 bits",
            "gen3072": "made here, 3072 bits (a minute or so)",
            "gen4096": "made here, 4096 bits (several minutes)"}
KEY_KINDS = ("rsa2048", "rsa3072", "rsa4096", "ec", "ec384")

PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
PEM_KEY = re.compile(r"-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[A-Za-z0-9+/=\s:,-]+?"
                     r"-----END \1-----")


# ---- openssl ------------------------------------------------------------------------------
def openssl(args, data=None, what="openssl", secret=None):
    """openssl run; a password handed over on a pipe of its own, named 'fd:@' in args (as
    otp's) - never on the command line nor in the environment."""
    rd = wr = None
    fds = ()
    if secret is not None:
        rd, wr = os.pipe()
        args = ["fd:%d" % rd if a == "fd:@" else a for a in args]
        fds = (rd,)
        os.write(wr, (str(secret) + "\n").encode("utf-8"))
        os.close(wr)
    if isinstance(data, str):
        data = data.encode("utf-8")
    try:
        got = subprocess.run([OPENSSL] + list(args), input=data, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=900, pass_fds=fds)
    except FileNotFoundError:
        raise ValueError("openssl is not on this machine")
    except subprocess.TimeoutExpired:
        raise ValueError("%s: openssl took too long" % what)
    finally:
        if rd is not None:
            os.close(rd)
    if got.returncode != 0:
        said = (got.stderr or got.stdout or b"").decode("utf-8", "replace").strip()
        raise ValueError("%s: %s" % (what, (said.splitlines() or ["openssl said no"])[-1][:200]))
    return got.stdout


def _cert_time(text):
    try:
        return datetime.strptime(re.sub(r"\s+", " ", text.strip()), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


CERT_INFO = {}


def cert_info(pem):
    """What a certificate says of itself, for the pages (otp's cert_info) - kept, the pages ask
    every few seconds."""
    k = hashlib.sha256(re.sub(r"\s+", "", pem or "").encode("ascii", "replace")).hexdigest()
    got = CERT_INFO.get(k)
    if got is None:
        got = _cert_info(pem)
        if len(CERT_INFO) > 200:
            CERT_INFO.clear()
        CERT_INFO[k] = got
    return dict(got, san=list(got.get("san") or []))


def _cert_info(pem):
    out = openssl(["x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-serial",
                   "-fingerprint", "-sha256", "-ext", "subjectAltName", "-nameopt", "RFC2253"],
                  pem, what="the certificate").decode("utf-8", "replace")
    info = {"san": []}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("subject="):
            info["subject"] = line[8:].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[7:].strip()
        elif line.startswith("notBefore="):
            info["not_before"] = _cert_time(line[10:])
        elif line.startswith("notAfter="):
            info["not_after"] = _cert_time(line[9:])
        elif line.startswith("serial="):
            info["serial"] = line[7:].strip()
        elif "Fingerprint=" in line:
            info["fingerprint"] = line.split("=", 1)[1].strip()
        elif "Subject Alternative Name" in line and i + 1 < len(lines):
            info["san"] = [x.strip().split(":", 1)[-1] for x in lines[i + 1].split(",") if x.strip()]
    info["self_signed"] = bool(info.get("subject")) and info.get("subject") == info.get("issuer")
    cn = re.search(r"(?:^|,)CN=([^,]+)", info.get("subject") or "")
    info["cn"] = cn.group(1) if cn else ""
    try:
        pub = openssl(["x509", "-noout", "-pubkey"], pem)
        txt = openssl(["pkey", "-pubin", "-noout", "-text"], pub).decode("utf-8", "replace")
        m = re.search(r"\((\d+) bit\)", txt)
        info["key"] = ("%s %s bit" % ("EC" if "ASN1 OID" in txt or "NIST" in txt else "RSA", m.group(1))) if m else ""
    except ValueError:
        info["key"] = ""
    return info


def ca_file():
    for f in (os.environ.get("FAKE_IGD_CA_BUNDLE"),) + CA_FILES:
        if f and os.path.isfile(f):
            return f
    return None


def chain_verify(leaf, chain, roots=""):
    """(True, '') when the certificate and the chain lead to a root of the system (or to `roots`, a
    private authority's root given with it); else (False, what openssl said) - otp's chain_verify."""
    ca = ca_file()
    with tempfile.TemporaryDirectory(prefix="fake-igd-chain-") as t:
        def put(name, text):
            p = os.path.join(t, name)
            with open(p, "w") as f:
                f.write(text)
            return p
        bundle = ""
        if ca:
            try:
                with open(ca) as f:
                    bundle = f.read()
            except OSError:
                bundle = ""
        bundle += "\n" + (roots or "")
        if "-----BEGIN CERTIFICATE-----" not in bundle:
            return False, "the system has no list of root authorities to check against"
        args = ["verify", "-CAfile", put("ca.pem", bundle)]
        if chain.strip():
            args += ["-untrusted", put("chain.pem", chain)]
        args.append(put("leaf.pem", leaf))
        try:
            openssl(args, what="the chain")
            return True, ""
        except ValueError as e:
            return False, re.sub(r"(error )?\S*fake-igd-chain-\S*:\s*", "", str(e))[:300]


CHAIN_STATE = {}


def chain_state(leaf, chain, roots=""):
    """Whether the certificate and its chain lead to a root of the system - as curl and every
    client that fetches nothing check it (otp 1.0.269); kept a minute."""
    k = hashlib.sha256((leaf + "|" + chain + "|" + (roots or "")).encode("utf-8", "replace")).hexdigest()
    got = CHAIN_STATE.get(k)
    if got and time.time() - got[0] < 60:
        return dict(got[1])
    if not ca_file() and not roots:
        st = {"ok": None, "words": "the system's roots are not found here - not checked"}
    else:
        ok, why = chain_verify(leaf, chain, roots)
        n = len(PEM_CERT.findall(chain))
        if ok:
            top = cert_info(PEM_CERT.findall(chain)[-1] if n else leaf).get("issuer")
            st = {"ok": True, "words": "complete - %d certificate%s up to %s" % (n + 1, "" if n == 0 else "s", _cn_of(top))}
            if roots and not chain_verify(leaf, chain)[0]:
                st["words"] += " - a private root: only clients that trust it take it"
        else:
            last = cert_info(PEM_CERT.findall(chain)[-1] if n else leaf)
            st = {"ok": False, "missing": _cn_of(last.get("issuer")),
                  "words": "incomplete - the authority %s is not sent (%s); curl, Python, a VPN client and other "
                           "clients refuse it - only browsers fetch it themselves" % (_cn_of(last.get("issuer")), why[:200])}
    if len(CHAIN_STATE) > 50:
        CHAIN_STATE.clear()
    CHAIN_STATE[k] = (time.time(), st)
    return dict(st)


# ---- the whole chain (otp 1.0.269) -------------------------------------------------------------
# nginx must send the certificate with every authority between it and a root - never the root.
# Browsers fetch a missing intermediate themselves (Authority Information Access - CA Issuers);
# curl, Python, a VPN client and monitoring do not. So whatever comes - an upload, a request signed
# elsewhere, ACME - is checked against the system's roots, and a chain that does not reach one is
# completed as browsers do it: the authority fetched from its CA Issuers address, four steps at most.
CHAIN_FETCHED = {}
CHAIN_FETCH_MOST = 262144
AIA_METADATA = frozenset(("fd00:ec2::254",))
AIA_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def aia_issuer_url(pem):
    """The CA Issuers address of a certificate."""
    try:
        out = openssl(["x509", "-noout", "-ext", "authorityInfoAccess"], pem,
                      what="the certificate").decode("utf-8", "replace")
    except ValueError:
        return ""
    m = re.search(r"CA Issuers\s*-\s*URI:(https?://\S+)", out)
    return m.group(1) if m else ""


def aia_url_ok(url):
    """A CA Issuers address asked (otp 1.0.270): http or https on their own ports, never this
    machine, a link-local address (a cloud's metadata service) or a broadcast one."""
    u = urllib.parse.urlsplit(str(url or ""))
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("not an http(s) address")
    if os.environ.get("FAKE_IGD_AIA_LOCAL") == "1":
        return              # the tests: an authority served on this machine, on a port of its own
    try:
        port = u.port
    except ValueError:
        raise ValueError("not an address")
    if port not in (None, 80, 443):
        raise ValueError("a CA Issuers address on port %d - only 80 and 443 are asked" % port)
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(u.hostname, port or 80, proto=socket.IPPROTO_TCP)}
    except (OSError, UnicodeError):
        return              # not found here: through the proxy, or not at all
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        elif ip.version == 6 and ip in AIA_NAT64:
            ip = ipaddress.ip_address(int(ip) & 0xffffffff)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or \
                (ip.version == 4 and ip.is_reserved) or str(ip) in AIA_METADATA:
            raise ValueError("%s is %s - not asked" % (u.hostname, a))


def _aia_open(req, timeout):
    """Through Settings → Proxy when it is on for ACME (otp asks CA Issuers as acme's purpose)."""
    try:
        import igd_proxy
        if igd_proxy.url_for(None, "acme"):
            return igd_proxy.open_url(None, "acme", req, timeout=timeout)
    except ImportError:
        pass
    return urllib.request.urlopen(req, timeout=timeout)


def aia_fetch(url):
    """The certificates at a CA Issuers address - DER, PEM or PKCS#7 - as PEM (kept a day; an
    answer of none kept ten minutes)."""
    got = CHAIN_FETCHED.get(url)
    if got and time.time() - got[0] < (86400 if got[1] else 600):
        return got[1]
    if not re.match(r"^https?://[A-Za-z0-9.\[\]:-]+(:\d+)?/\S*\Z", url):
        return []
    aia_url_ok(url)
    until = time.time() + 30
    raw = b""
    with _aia_open(urllib.request.Request(url, headers={"User-Agent": "fake-igd"}), 15) as r:
        while len(raw) <= CHAIN_FETCH_MOST:
            part = r.read(16384)
            if not part:
                break
            raw += part
            if time.time() > until:
                raise ValueError("it took more than 30 seconds")
    if len(raw) > CHAIN_FETCH_MOST:
        return []
    pems = []
    if b"-----BEGIN" in raw:
        text = raw.decode("ascii", "replace")
        if "-----BEGIN PKCS7-----" in text:
            try:
                text = openssl(["pkcs7", "-print_certs"], raw, what="PKCS#7").decode("ascii", "replace")
            except ValueError:
                text = ""
        pems = [m.group(0) for m in PEM_CERT.finditer(text)]
    else:
        for args in (["x509", "-inform", "DER"], ["pkcs7", "-inform", "DER", "-print_certs"]):
            try:
                text = openssl(args, raw, what="the authority").decode("ascii", "replace")
            except ValueError:
                continue
            pems = [m.group(0) for m in PEM_CERT.finditer(text)]
            if pems:
                break
    if len(CHAIN_FETCHED) > 100:
        CHAIN_FETCHED.clear()
    CHAIN_FETCHED[url] = (time.time(), pems[:6])
    return pems[:6]


def _cn_of(dn):
    m = re.search(r"(?:^|,)\s*CN\s*=\s*([^,]+)", str(dn or ""))
    return (m.group(1) if m else str(dn or "?")).strip()[:200]


def chain_order(leaf, certs):
    """(the chain from the certificate up - each the issuer of the one before it -, the rest)."""
    infos = {c: cert_info(c) for c in certs}
    rest, out, at = list(certs), [], cert_info(leaf)
    while rest:
        nxt = next((c for c in rest if infos[c].get("subject") == at.get("issuer")
                    and not infos[c].get("self_signed")), None)
        if not nxt:
            break
        out.append(nxt)
        rest.remove(nxt)
        at = infos[nxt]
    return out, rest


def _joined(xs):
    return "".join(c.strip() + "\n" for c in xs)


def chain_complete(leaf, chain_out, roots=""):
    """The chain checked against the system's roots and, where it does not reach one, completed
    from the CA Issuers addresses: (the chain, its state - {ok: True|False|None, words, fetched,
    missing, private_root}) - otp's chain_complete. Never raises: what came goes on as it came."""
    try:
        return _chain_complete(leaf, chain_out, roots)
    except Exception as e:                              # noqa: BLE001
        return chain_out, {"ok": None, "fetched": [],
                           "words": "the chain could not be checked: %s" % (str(e)[:200] or e.__class__.__name__)}


def _chain_complete(leaf, chain_out, roots=""):
    leaf = leaf.strip() + "\n"
    leaf_info = cert_info(leaf)
    if leaf_info.get("self_signed"):
        return chain_out, {"ok": None, "fetched": [],
                           "words": "self-signed - no chain; whoever connects must trust this certificate itself"}
    ordered, extra = chain_order(leaf, [c for c in chain_out if c.strip()])
    ok, why = chain_verify(leaf, _joined(ordered + extra), roots)
    fetched, chain = [], list(ordered)
    tried, root_seen, root_pem = 0, "", ""
    while not ok and tried < 4:
        tried += 1
        last = chain[-1] if chain else leaf
        info = cert_info(last)
        if info.get("self_signed"):
            break
        url = aia_issuer_url(last)
        if not url:
            why = "%s names no CA Issuers address to fetch it from" % (info.get("cn") or "the certificate")
            break
        try:
            got = aia_fetch(url)
            got_infos = [(c, cert_info(c)) for c in got]
        except Exception as e:                          # noqa: BLE001
            why = "the authority %s could not be fetched from %s: %s" % (_cn_of(info.get("issuer")), url,
                                                                         str(e)[:120])
            break
        hit = next(((c, i) for c, i in got_infos if i.get("subject") == info.get("issuer")), None)
        if not hit:
            why = "%s does not hold the authority %s" % (url, _cn_of(info.get("issuer")))
            break
        nxt, ni = hit
        if ni.get("self_signed"):
            root_seen, root_pem = ni.get("cn") or ni.get("subject"), nxt
            break                       # a root: never sent - it has to be the system's own
        chain.append(nxt)
        fetched.append(ni.get("cn") or ni.get("subject"))
        ok, why = chain_verify(leaf, _joined(chain + extra), roots)
    out = chain + extra
    n = len(chain)
    if ok:
        top = cert_info(chain[-1] if chain else leaf).get("issuer")
        words = "complete - %d certificate%s up to %s" % (n + 1, "" if n == 0 else "s", _cn_of(top))
        if fetched:
            words += " (fetched: %s - it was not sent with the certificate)" % ", ".join(fetched)
        if roots and not chain_verify(leaf, _joined(out))[0]:
            words += " - a private root: only clients that trust it take it"
        return out, {"ok": True, "words": words, "fetched": fetched}
    if root_seen:
        ok2, why2 = chain_verify(leaf, _joined(out), (roots or "") + "\n" + root_pem)
        known = False
        try:
            ca = ca_file()
            if ca:
                with open(ca, "rb") as f:
                    flat = re.sub(rb"\s+", b"", f.read(64 * 1048576))
                body = re.sub(r"-----[A-Z ]+-----|\s+", "", root_pem).encode("ascii", "replace")
                known = bool(body) and body in flat
        except OSError:
            known = False
        if ok2 and not known:
            return out, {"ok": False, "fetched": fetched, "missing": "", "private_root": root_seen,
                         "words": "it leads to %s, a root the system does not trust (a private CA?) - the chain is "
                                  "complete; the clients (curl, a VPN client, monitoring) must trust that root, "
                                  "or upload its root here" % root_seen}
        return out, {"ok": False, "fetched": fetched, "missing": "",
                     "words": "the chain up to %s does not check: %s" % (root_seen, (why2 if not ok2 else why)[:200])}
    last = cert_info(chain[-1] if chain else leaf)
    return (out if fetched else chain_out), {
        "ok": False, "fetched": fetched, "missing": _cn_of(last.get("issuer")),
        "words": "incomplete - the authority %s is not sent and could not be completed (%s); curl, Python, "
                 "a VPN client and other clients refuse it - only browsers fetch it themselves; upload the "
                 "certificate with its chain, or the missing authority" % (_cn_of(last.get("issuer")), why[:200])}


def pub_of_cert(pem):
    return openssl(["x509", "-noout", "-pubkey"], pem, what="the certificate")


def pub_of_key(pem):
    return openssl(["pkey", "-pubout"], pem, what="the key")


def key_plain(pem, password=""):
    return openssl(["pkey", "-passin", "fd:@"], pem, secret=password or "",
                   what="the key (a wrong or missing password?)").decode()


def new_key(kind):
    curve = {"ec": "P-256", "ec384": "P-384"}.get(kind)
    if curve:
        return openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:%s" % curve],
                       what="a new key").decode()
    bits = {"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}.get(kind)
    if not bits:
        raise ValueError("the key is rsa2048, rsa3072, rsa4096, ec (P-256) or ec384")
    return openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % bits],
                   what="a new key").decode()


def san_ext(names):
    out = []
    for n in names:
        n = str(n).strip()
        if not n:
            continue
        try:
            ipaddress.ip_address(n)
            out.append("IP:" + n)
        except ValueError:
            if not re.match(r"^(\*\.)?[A-Za-z0-9.-]{1,253}\Z", n):
                raise ValueError("%r is not a name or an address" % n[:80])
            out.append("DNS:" + n)
    seen = []
    for x in out:
        if x not in seen:
            seen.append(x)
    return ",".join(seen)


def subject(cn, org="", unit="", country="", city=""):
    def esc(v):
        return re.sub(r"([/\\=+,])", r"\\\1", str(v).strip())
    if not cn or not re.match(r"^[A-Za-z0-9*.:-]{1,64}\Z", cn):
        raise ValueError("the common name is a host name")
    s = "/CN=" + esc(cn)
    if org:
        s += "/O=" + esc(org)[:64]
    if unit:
        s += "/OU=" + esc(unit)[:64]
    if city:
        s += "/L=" + esc(city)[:64]
    if country:
        if not re.match(r"^[A-Za-z]{2}\Z", country):
            raise ValueError("the country is two letters (CZ)")
        s += "/C=" + country.upper()
    return s


def make_csr(cn, names, kind="rsa2048", **subj):
    key = new_key(kind)
    with tempfile.TemporaryDirectory(prefix="fake-igd-csr-") as t:
        kf = os.path.join(t, "k.pem")
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        long_ = len(cn or "") > 64 and re.match(r"^[A-Za-z0-9*.-]{1,253}\Z", cn or "")
        csr = openssl(["req", "-new", "-key", kf, "-subj", "/" if long_ else subject(cn, **subj),
                       "-addext", "subjectAltName=" + san_ext([cn] + list(names))], what="the request").decode()
    return key, csr


def make_selfsigned(cn, names, days=825, kind="rsa2048", **subj):
    key = new_key(kind)
    with tempfile.TemporaryDirectory(prefix="fake-igd-crt-") as t:
        kf = os.path.join(t, "k.pem")
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        crt = openssl(["req", "-new", "-x509", "-key", kf, "-days", str(int(days)), "-subj", subject(cn, **subj),
                       "-addext", "subjectAltName=" + san_ext([cn] + list(names))], what="the certificate").decode()
    return key, crt


def _pfx_open(pfx, password):
    got, last = None, None
    for extra in ([], ["-legacy"]):
        try:
            got = openssl(["pkcs12", "-nodes", "-passin", "fd:@"] + extra, pfx, secret=password or "",
                          what="the PFX / PKCS#12 file")
            break
        except ValueError as e:
            last = e
    if got is None:
        raise ValueError("%s - is the password right?" % last)
    return got.decode("utf-8", "replace")


def _key_kind(key_pem):
    try:
        txt = openssl(["pkey", "-noout", "-text_pub"], key_pem, what="the key").decode("utf-8", "replace")
    except ValueError:
        return "RSA"
    return "EC" if "ASN1 OID" in txt or "NIST" in txt else "RSA"


def cert_bundle(text="", pfx=b"", password="", pending_key="", pfx2=b""):
    """Whatever was sent - one PEM with everything in it, or a PFX / PKCS#12 (or two) - as the parts
    nginx needs: the certificate, its key, the chain up from it (each the issuer of the one before,
    completed from the CA Issuers addresses where it does not reach a root; a root is never sent,
    a private CA's root is kept to check with). An RSA and an ECDSA certificate of the same names
    with both their keys: both, the ECDSA one beside (otp's alt). The key is the certificate's own
    or nothing is taken."""
    certs, keys = [], []
    for one in (pfx, pfx2):
        if one:
            t = _pfx_open(one, password)
            certs += [m.group(0) for m in PEM_CERT.finditer(t) if m.group(0) not in certs]
            keys += [m.group(0) for m in PEM_KEY.finditer(t)]
    certs += [m.group(0) for m in PEM_CERT.finditer(text or "") if m.group(0) not in certs]
    keys += [m.group(0) for m in PEM_KEY.finditer(text or "")]
    if not certs:
        raise ValueError("no certificate was found in what was sent (PEM, or a PFX / PKCS#12 file)")
    if len(keys) > 2:
        raise ValueError("more than two private keys were sent - one, or an RSA and an ECDSA one")
    if keys:
        plain = [key_plain(k, password) for k in keys]
    elif pending_key:
        plain = [pending_key]
    else:
        raise ValueError("no private key came with it: send the key too (or the PFX), or make the request "
                         "here first so the key is waiting")
    pairs = []
    for k in plain:
        want = pub_of_key(k)
        leaf = next((c for c in certs if pub_of_cert(c) == want), None)
        if not leaf:
            raise ValueError("none of the certificates is the one of this key" if len(plain) == 1 else
                             "one of the two keys has no certificate of its own among those sent")
        pairs.append((leaf, k))
    if len(pairs) == 2:
        kinds = [_key_kind(k) for _l, k in pairs]
        if sorted(kinds) != ["EC", "RSA"]:
            raise ValueError("two keys are an RSA and an ECDSA one of the same names - these are %s and %s" % tuple(kinds))
        if kinds[0] == "EC":
            pairs.reverse()
    now = time.time()
    leaves = [l for l, _k in pairs]
    others = [c for c in certs if c not in leaves]
    infos = {c: cert_info(c) for c in others}
    roots = [c for c in others if infos[c]["self_signed"]]
    inter = [c for c in others if c not in roots]
    root_pem = "".join(r.strip() + "\n" for r in roots)
    out = None
    for leaf, key_pem in pairs:
        info = cert_info(leaf)
        if info.get("not_after") and info["not_after"] < now:
            raise ValueError("this certificate ran out on %s" % time.strftime("%Y-%m-%d %H:%M UTC",
                                                                             time.gmtime(info["not_after"])))
        if info.get("not_before") and info["not_before"] > now + 300:
            raise ValueError("this certificate is good only from %s - this machine's clock says it is not yet"
                             % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(info["not_before"])))
        ordered, _rest = chain_order(leaf, inter)
        chain_out, state = chain_complete(leaf, ordered, root_pem)
        one = {"cert": leaf.strip() + "\n", "chain": _joined(chain_out), "key": key_pem, "info": info,
               "chain_info": [cert_info(c) for c in chain_out], "chain_state": state}
        if out is None:
            out = dict(one, root_info=[infos[c] for c in roots], roots=root_pem)
        else:
            if sorted(set([info.get("cn")] + info.get("san", []))) != \
                    sorted(set([out["info"].get("cn")] + out["info"].get("san", []))):
                raise ValueError("the RSA and the ECDSA certificate are not of the same names")
            out["alt"] = one
    return out


# ---- what nginx has now ---------------------------------------------------------------------
def _read(path, most=1 << 20):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(most)
    except OSError:
        return ""


def server_block(text, port="443"):
    """(start, end) of the server { } that listens on `port`, or None."""
    for m in re.finditer(r"(?m)^[ \t]*server\s*\{", text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif text[i] == "#":
                j = text.find("\n", i)
                i = len(text) if j < 0 else j
                continue
            i += 1
        block = text[m.start():i + 1]
        if re.search(r"(?m)^\s*listen\s+(?:\S+:)?%s\b" % port, block):
            return m.start(), i + 1
    return None


def directive(block, name):
    """The values of a directive in a block (comments left out)."""
    pat = r"(?m)^[ \t]*%s\s+([^;#\n]*);" % r"\s+".join(re.escape(w) for w in name.split())
    return [v.strip() for v in re.findall(pat, block)]


def nginx_now():
    text = _read(NGINX_CONF)
    out = {"file": NGINX_CONF, "there": bool(text), "names": [], "protocols": [], "ciphers": "",
           "prefer": False, "dhparam": "", "hsts": 0}
    if not text:
        # Not there (yet): what install.sh writes - otp's standard.
        out.update(protocols=list(TLS_PRESETS["standard"]["protocols"]), ciphers=TLS_PRESETS["standard"]["ciphers"])
        return out
    where = server_block(text, "443")
    block = text[where[0]:where[1]] if where else text
    names = directive(block, "server_name")
    out["names"] = [n for n in (names[0].split() if names else []) if n not in ("_", "")]
    p = directive(block, "ssl_protocols")
    out["protocols"] = p[0].split() if p else ["TLSv1.2", "TLSv1.3"]
    c = directive(block, "ssl_ciphers")
    out["ciphers"] = c[0].strip("'\"") if c else ""
    pr = directive(block, "ssl_prefer_server_ciphers")
    out["prefer"] = bool(pr) and pr[0] == "on"
    dh = directive(block, "ssl_dhparam")
    out["dhparam"] = dh[0] if dh else ""
    h = directive(block, "add_header Strict-Transport-Security")
    m = re.search(r"max-age=(\d+)", h[0]) if h else None
    out["hsts"] = int(m.group(1)) if m else 0
    out["certs"] = directive(block, "ssl_certificate")
    return out


def preset_of(protocols, ciphers):
    for k, p in TLS_PRESETS.items():
        if list(protocols) == p["protocols"] and (ciphers or "") == p["ciphers"]:
            return k
        if k == "modern" and list(protocols) == ["TLSv1.3"]:
            return k
    return "custom"


def host_ips():
    """The machine's own IPv4 addresses (as install.sh's host_ips), loopback left out."""
    out = []
    try:
        r = subprocess.run(["ip", "-4", "-o", "addr", "show"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
        for m in re.finditer(r"\binet (\d+\.\d+\.\d+\.\d+)/", r.stdout):
            if not m.group(1).startswith("127.") and m.group(1) not in out:
                out.append(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    if not out:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))           # nothing is sent: only which address would go
            a = s.getsockname()[0]
            s.close()
            if not a.startswith("127."):
                out.append(a)
        except OSError:
            pass
    return out


def current(roots=""):
    """The certificate in nginx's file now: its facts, its chain and the second one beside it -
    the chain checked with the root kept beside a private authority's certificate (roots)."""
    f = files()
    text = _read(f["cert"])
    certs = [m.group(0) for m in PEM_CERT.finditer(text)]
    if not certs:
        return None
    try:
        info = cert_info(certs[0])
    except ValueError as e:
        return {"error": str(e)}
    chain = "".join(c + "\n" for c in certs[1:])
    out = {"info": info, "pem": certs[0] + "\n", "chain": chain, "chain_info": [], "file": f["cert"]}
    for c in certs[1:]:
        try:
            out["chain_info"].append(cert_info(c))
        except ValueError:
            pass
    out["chain_state"] = {"ok": None, "words": ""} if info.get("self_signed") else \
        chain_state(certs[0] + "\n", chain, roots)
    alt = [m.group(0) for m in PEM_CERT.finditer(_read(f["cert2"]))]
    if alt and f["cert2"] in nginx_now().get("certs", []):
        try:
            a_chain = "".join(c + "\n" for c in alt[1:])
            out["alt"] = {"info": cert_info(alt[0]), "pem": alt[0] + "\n", "chain": a_chain,
                          "chain_state": chain_state(alt[0] + "\n", a_chain, roots)}
        except ValueError:
            pass
    return out


SENT = {"key": None, "at": 0, "got": None}
SENT_EVERY = 60


def sent_check(cur):
    """What nginx sends now (otp 1.0.269's self-check, 1.7.1): connected to on 127.0.0.1:443 by the
    certificate's own name - first whether it is the certificate in the file (nginx took it; a reload
    not done leaves the one before), then as a client that fetches nothing (curl, a VPN client)
    checks it: the system's roots, the whole chain sent. Kept a minute."""
    info = (cur or {}).get("info") or {}
    if not info:
        return None
    name = next((n for n in info.get("san") or [] if n and "*" not in n and not re.match(r"^[0-9.:]+\Z", n)), "") \
        or info.get("cn") or ""
    key = (info.get("fingerprint"), name)
    if SENT["key"] == key and time.time() - SENT["at"] < SENT_EVERY:
        return SENT["got"]
    port = int(os.environ.get("FAKE_IGD_TLS_PORT") or 443)
    got = {"at": time.time(), "name": name}
    try:
        raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        raw_ctx.check_hostname = False
        raw_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=6) as s:
            with raw_ctx.wrap_socket(s, server_hostname=name or None) as t:
                der = t.getpeercert(binary_form=True) or b""
        fp = ":".join("%02X" % b for b in hashlib.sha256(der).digest())
        mine = (info.get("fingerprint") or "").upper()
        alt = (((cur or {}).get("alt") or {}).get("info") or {}).get("fingerprint", "").upper()
        got["fingerprint"] = fp
        if mine and fp != mine and fp != alt:
            try:
                other = cert_info(ssl.DER_cert_to_PEM_cert(der))
                was = " (%s, issued by %s)" % (other.get("cn") or other.get("subject"),
                                                "itself" if other.get("self_signed") else
                                                (other.get("issuer") or "").replace("CN=", ""))
            except ValueError:
                was = ""
            got.update(ok=False, same=False,
                       words="nginx still answers with another certificate%s, not the one in its file - it has not "
                             "been reloaded since: Settings → The service, or sudo systemctl reload nginx" % was)
        else:
            got["same"] = True
            if info.get("self_signed"):
                got.update(ok=None, words="signed by itself: every browser and client warns")
            else:
                vctx = ssl.create_default_context()
                ca = ca_file()
                if ca:
                    vctx.load_verify_locations(cafile=ca)
                vctx.check_hostname = False
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=6) as s:
                        with vctx.wrap_socket(s, server_hostname=name or None):
                            pass
                    got.update(ok=True, words="checked as a client that fetches nothing: the whole chain is sent")
                except ssl.SSLCertVerificationError as e:
                    got.update(ok=False, words="a client that fetches nothing (curl, a VPN client) refuses what "
                                                "nginx sends: %s" % str(e.verify_message or e)[:200])
    except (OSError, ssl.SSLError, ValueError) as e:
        got.update(ok=None, words="what nginx sends could not be checked: %s" % str(e)[:200])
    SENT.update(key=key, at=time.time(), got=got)
    return got


def before_acme():
    """The certificate it had before ACME replaced it (root keeps it beside), or None."""
    certs = [m.group(0) for m in PEM_CERT.finditer(_read(files()["before"]))]
    if not certs:
        return None
    try:
        info = cert_info(certs[0])
    except ValueError:
        return None
    return {"issuer": info.get("issuer"), "not_after": info.get("not_after"), "subject": info.get("subject"),
            "ran_out": bool(info.get("not_after") and info["not_after"] < time.time()),
            "how": "self-signed" if info.get("self_signed") else "uploaded"}


# ---- kept in the database ----------------------------------------------------------------------
def meta(store, k):
    try:
        got = json.loads(store.get_meta(k) or "null")
    except ValueError:
        return None
    return got if isinstance(got, (dict, list)) else None


def set_meta(store, k, v):
    store.set_meta(k, json.dumps(v))


def pending_file(cfg):
    return os.path.join(cfg.get("state_dir") or "/var/lib/fake-igd", "tls", "pending.key")


def pending_key(cfg):
    return _read(pending_file(cfg), 65536)


NAME_RE = re.compile(r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}\Z")


def names_missing(info):
    """The DNS names of a certificate (its CN and SAN; not addresses, not wildcards) nginx's
    server_name does not have."""
    have = [n.lower() for n in nginx_now()["names"]]
    out = []
    for n in [info.get("cn") or ""] + list(info.get("san") or []):
        n = str(n).strip().lower().rstrip(".")
        if NAME_RE.match(n) and n not in have and n not in out:
            out.append(n)
    return out[:50]


def chain_key(cert, chain):
    return hashlib.sha256((re.sub(r"\s+", "", cert or "") + "|" + re.sub(r"\s+", "", chain or "")).encode()).hexdigest()


def chain_keep(store, cert, chain, state, alt=None):
    """What the check found when it was put in (otp keeps it in the profile): the card says it while the
    same certificate and chain are in place - "it leads to a private root" is not found again from the file."""
    kept = {"key": chain_key(cert, chain), "state": state or {}, "at": time.time()}
    if alt:
        kept["alt"] = {"key": chain_key(alt[0], alt[1]), "state": alt[2] or {}}
    set_meta(store, "tls:chain", kept)


def chain_kept(store, cur):
    """The state found when the certificate in place was put in, over the one read from the file
    when that one says no (a private root, a chain completed meanwhile)."""
    kept = meta(store, "tls:chain") or {}
    if not cur or not cur.get("pem"):
        return
    for one, k in ((cur, kept), (cur.get("alt") or {}, kept.get("alt") or {})):
        if one.get("pem") and k.get("key") == chain_key(one["pem"], one.get("chain") or "") and \
                (one.get("chain_state") or {}).get("ok") is not True and k.get("state"):
            one["chain_state"] = dict(k["state"])


def put_pem(ctx, cert, chain, key, how, by, alt=None, keep_before=False, words="", add_names=None,
            roots=None, checked=False, state=None):
    """The certificate asked of root (root_tls.py: put) - the one way a certificate goes in,
    from here and from Automatic certificates. Returns the ask's id. add_names: DNS names root
    adds to the 443 server's server_name (asked in the dialog). The chain checked against the
    system's roots and completed from the CA Issuers addresses first (otp 1.0.269), unless the
    upload did it already (checked); roots: a private authority's root kept to check with (never sent)."""
    st2 = (alt or {}).get("chain_state")
    if not checked and not cert_info(cert).get("self_signed"):
        got, state = chain_complete(cert, PEM_CERT.findall(chain or ""), roots or "")
        chain = _joined(got)
        if alt:
            got2, st2 = chain_complete(alt["cert"], PEM_CERT.findall(alt.get("chain") or ""), roots or "")
            alt = dict(alt, chain=_joined(got2))
    set_meta(ctx.store, "tls:root", {"pem": roots or "", "at": time.time()})
    chain_keep(ctx.store, cert, chain, state, (alt["cert"], alt.get("chain") or "", st2) if alt else None)
    payload = {"action": "put", "cert": cert, "chain": chain or "", "key": key, "keep_before": bool(keep_before)}
    if add_names:
        payload["server_names_add"] = list(add_names)[:50]
    if alt:
        payload["alt"] = {"cert": alt["cert"], "chain": alt.get("chain") or "", "key": alt["key"]}
    ident = ctx.ask_root(payload, kind="tls")
    set_meta(ctx.store, "tls:asked", {"id": ident, "at": time.time(), "action": "put", "by": by, "how": how,
                                      "words": words})
    set_meta(ctx.store, "tls:how", {"how": how, "at": time.time(), "by": by})
    return ident


def web_progress(ctx):
    """What root is doing now for this pane, if anything (otp's web_progress, 1.0.50)."""
    p = os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web", "progress-tls.json")
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            got = json.loads(f.read(65536).decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(got, dict) or time.time() - float(got.get("at") or 0) > 3 * 3600:
        return None
    got["now"] = time.time()
    return got


LATE_S = 120


def ask_state(ctx):
    """How root's last ask of this pane went: working (with root's progress), waiting, done, failed
    - or late, only when root has answered nothing at all since it was asked (1.7.2)."""
    asked = meta(ctx.store, "tls:asked") or {}
    res = ctx.root_result("tls")
    # The trusted roots' asks share the kind: their answers are theirs, not the certificate's.
    if res.get("osroots"):
        osr_seen(ctx)
    elif res.get("id") and res.get("id") != (meta(ctx.store, "tls:lastres") or {}).get("id") and \
            res.get("action") != "export":
        set_meta(ctx.store, "tls:lastres", {k: res.get(k) for k in ("id", "ok", "action", "at", "said", "by")})
    if asked.get("id"):
        # Its own answer: the last one, one of the short answers kept beside it (1.7.1), or the one
        # the pages saw last.
        mine = ctx.root_result("tls", asked["id"])
        if not mine:
            seen = meta(ctx.store, "tls:lastres") or {}
            mine = seen if seen.get("id") == asked["id"] else {}
        if mine:
            return {"state": "done" if mine.get("ok") else "failed", "action": mine.get("action") or asked.get("action"),
                    "at": mine.get("at"), "said": mine.get("said") or [], "by": mine.get("by")}
        prog = web_progress(ctx)
        if prog:
            return {"state": "working", "action": asked.get("action"), "at": asked.get("at"), "said": [],
                    "progress": prog}
        # Root answered an ask made after this one: the queue is served oldest first, so this one was
        # done too - its answer was overwritten before the pages saw it (a version before 1.7.1 kept
        # none beside it). Not "late": what nginx has now is on the card.
        if res and float(res.get("at") or 0) > float(asked.get("at") or 0) + 1:
            return None
        late = time.time() - float(asked.get("at") or 0) > LATE_S
        return {"state": "late" if late else "waiting", "action": asked.get("action"), "at": asked.get("at"),
                "said": ["root has not taken it yet - is fake-igd-web.path active?"] if late else []}
    res = meta(ctx.store, "tls:lastres") or {}
    if not res:
        return None
    return {"state": "done" if res.get("ok") else "failed", "action": res.get("action"),
            "at": res.get("at"), "said": res.get("said") or [], "by": res.get("by")}


def policy_checked(b):
    preset = str(b.get("preset") or "standard")
    if preset not in list(TLS_PRESETS) + ["custom"]:
        raise ValueError("the TLS settings are standard, intermediate, modern or custom")
    out = {"preset": preset}
    if preset == "custom":
        prot = b.get("protocols") or []
        if not isinstance(prot, list) or not prot or any(p not in ("TLSv1.2", "TLSv1.3") for p in prot):
            raise ValueError("the protocols are TLSv1.2 and/or TLSv1.3")
        out["protocols"] = [p for p in ("TLSv1.2", "TLSv1.3") if p in prot]
        ciphers = str(b.get("ciphers") or "").strip()
        if ciphers:
            if not re.match(r"^[A-Za-z0-9_+!@=:.-]{1,2000}\Z", ciphers):
                raise ValueError("the ciphers are an OpenSSL cipher list")
            openssl(["ciphers", ciphers], what="OpenSSL does not know that cipher list")
        out["ciphers"] = ciphers
    else:
        out["protocols"] = list(TLS_PRESETS[preset]["protocols"])
        out["ciphers"] = TLS_PRESETS[preset]["ciphers"]
    dh = str(b.get("dh") or "none")
    if dh not in DH_WORDS:
        raise ValueError("the DH parameters are one of %s" % ", ".join(DH_WORDS))
    out["dh"] = dh
    out["prefer"] = bool(b.get("prefer"))
    try:
        hsts = int(b.get("hsts") if b.get("hsts") not in (None, "") else 63072000)
    except (TypeError, ValueError):
        raise ValueError("HSTS is a number of seconds")
    if not 0 <= hsts <= 63072000:
        raise ValueError("HSTS is 0 to 63072000 seconds (two years)")
    out["hsts"] = hsts
    return out


def kept_root(store):
    """The root of a private authority given with the certificate - kept to check with, never sent."""
    return str((meta(store, "tls:root") or {}).get("pem") or "")


def view(ctx):
    me = ctx.me or {}
    ng = nginx_now()
    pol = meta(ctx.store, "tls:policy") or {}
    preset = preset_of(ng["protocols"], ng["ciphers"])
    dh = pol.get("dh") if pol.get("dh") in DH_WORDS and ng["dhparam"] else ("none" if not ng["dhparam"] else "custom")
    acme = {}
    try:
        on = ctx.store and json.loads(ctx.store.get_meta("settings") or "{}").get("acme")
        care = meta(ctx.store, "acme:care") or {}
        st = meta(ctx.store, "acme:state") or {}
        acme = {"on": bool(on), "care": care.get("on", True), "state": {"ok": st.get("ok"), "said": st.get("said")}}
    except ValueError:
        pass
    pend = bool(pending_key(ctx.cfg))
    csr = (meta(ctx.store, "tls:csr") or {}).get("csr") if pend else ""
    roots = kept_root(ctx.store)
    cur = current(roots)
    chain_kept(ctx.store, cur)
    if cur and cur.get("info"):
        if roots and not cur["info"].get("self_signed"):
            cur["root_info"] = []
            for r in PEM_CERT.findall(roots):
                try:
                    cur["root_info"].append(cert_info(r))
                except ValueError:
                    pass
        cur["sent"] = sent_check(cur)
        top = (cur.get("chain_info") or [cur["info"]])[-1]
        cur["root_cn"] = "" if cur["info"].get("self_signed") else \
            re.sub(r"^.*?CN=([^,]+).*$", r"\1", top.get("issuer") or "")
    root = ask_state(ctx)
    policy = {"preset": preset, "protocols": ng["protocols"], "ciphers": ng["ciphers"],
              "prefer": ng["prefer"], "dh": dh, "dhparam": ng["dhparam"], "hsts": ng["hsts"]}
    if root and root.get("action") == "policy" and root.get("state") in ("waiting", "working") and pol.get("preset"):
        # Asked and not in nginx yet (DH parameters being made): what was asked, as otp keeps it at once.
        policy.update({k: pol[k] for k in ("preset", "protocols", "ciphers", "prefer", "dh", "hsts") if k in pol})
    return {"may": me.get("role") == "fulladmin", "cert": cur, "policy": policy,
            "nginx": {"file": ng["file"], "there": ng["there"]},
            "names": ng["names"], "ips": host_ips(), "host": (ng["names"] or [os.uname()[1]])[0],
            "machine": socket.gethostname(),
            "how": (meta(ctx.store, "tls:how") or {}).get("how") or "", "pending": pend, "csr": csr,
            "acme": acme, "before": before_acme(), "root": root,
            "presets": TLS_PRESETS, "dh": DH_WORDS, "at": time.time()}


# ---- the chain of the certificate in place (otp's tls_chain, tls_chain_add, 1.0.269) ---------------
def _chain_ask(ctx, who, cur, chain, alt_chain=None, words=""):
    pay = {"action": "chain", "cert": cur["pem"], "chain": chain}
    if alt_chain is not None:
        pay["alt_chain"] = alt_chain
    ident = ctx.ask_root(pay, kind="tls")
    set_meta(ctx.store, "tls:asked", {"id": ident, "at": time.time(), "action": "chain", "by": who, "words": words})
    return ident


def chain_again(ctx, who):
    """Complete the chain: the certificate in place checked again against the system's roots (and
    the root kept) and completed from its CA Issuers addresses - its second (ECDSA) one too."""
    roots = kept_root(ctx.store)
    cur = current(roots)
    if not cur or not cur.get("info"):
        raise ValueError("there is no certificate in nginx's file")
    if cur["info"].get("self_signed"):
        raise ValueError("a self-signed certificate has no chain")
    chain, state = chain_complete(cur["pem"], PEM_CERT.findall(cur.get("chain") or ""), roots)
    said, complete = state.get("words") or "", state.get("ok")
    alt = cur.get("alt") or None
    alt_chain = None
    if alt and alt.get("pem"):
        achain, ast = chain_complete(alt["pem"], PEM_CERT.findall(alt.get("chain") or ""), roots)
        if _joined(achain) != (alt.get("chain") or ""):
            alt_chain = _joined(achain)
        said += " - the second (%s) one: %s" % ((alt.get("info") or {}).get("key") or "ECDSA", ast.get("words"))
        if complete and ast.get("ok") is False:
            complete = False
    chain_keep(ctx.store, cur["pem"], _joined(chain), state,
               (alt["pem"], alt_chain if alt_chain is not None else (alt.get("chain") or ""), ast)
               if alt and alt.get("pem") else None)
    changed = _joined(chain) != (cur.get("chain") or "") or alt_chain is not None
    if changed:
        _chain_ask(ctx, who, cur, _joined(chain), alt_chain if alt_chain is not None else
                   ((alt or {}).get("chain") if alt else None), said)
        said += " - root puts the chain in nginx within a few seconds"
    ctx.event("%s checked the chain of the certificate: %s" % (who, said), "info" if complete else "warn")
    out = view(ctx)
    out.update(message=said, complete=complete)
    return out


def chain_add(ctx, who, b):
    """Upload the missing authority: only certificates of authorities, never a key; a root goes beside
    the chain (kept to check with, never sent), the rest into the chain in order."""
    roots_now = kept_root(ctx.store)
    cur = current(roots_now)
    if not cur or not cur.get("info"):
        raise ValueError("there is no certificate in nginx's file")
    text = str(b.get("text") or "")
    if len(text) > 262144:
        raise ValueError("that is far bigger than the certificates of a chain")
    if re.search(r"PRIVATE KEY", text):
        raise ValueError("only the certificates of the authorities - no private key")
    given = [m.group(0) for m in PEM_CERT.finditer(text)]
    if not given:
        raise ValueError("no certificate in it (-----BEGIN CERTIFICATE-----, or a .cer file)")
    if len(given) > 8:
        raise ValueError("%d certificates - the chain of one certificate is a few" % len(given))
    chain_now = PEM_CERT.findall(cur.get("chain") or "")
    roots = PEM_CERT.findall(roots_now)
    have = {cert_info(c).get("fingerprint") for c in chain_now + roots}
    new_roots, new_inter = [], []
    for c in given:
        ci = cert_info(c)
        if ci.get("fingerprint") in have or ci.get("fingerprint") == cur["info"].get("fingerprint"):
            continue
        (new_roots if ci.get("self_signed") else new_inter).append(c)
    if not new_roots and not new_inter:
        raise ValueError("every certificate in it is there already")
    root_now = _joined(roots + new_roots)

    def placed(leaf_pem, cur_chain):
        ordered, rest = chain_order(leaf_pem, cur_chain + [c for c in new_inter if c not in cur_chain])
        at = cert_info(ordered[-1] if ordered else leaf_pem)
        use = [c for c in new_inter if c in ordered] or \
            [c for c in new_roots if cert_info(c).get("subject") == at.get("issuer")]
        return ordered, [c for c in rest if c in cur_chain], use, at
    ordered, rest, useful, at = placed(cur["pem"], chain_now)
    alt = cur.get("alt") if (cur.get("alt") or {}).get("pem") else None
    aplaced = placed(alt["pem"], PEM_CERT.findall(alt.get("chain") or "")) if alt else None
    if not useful and not (aplaced and aplaced[2]):
        raise ValueError("none of these is the authority that signed the chain's last certificate (%s)"
                         % _cn_of(at.get("issuer")))
    if useful or not aplaced:
        chain, state = chain_complete(cur["pem"], ordered + rest, root_now)
    else:
        chain, state = chain_now, cur.get("chain_state") or {"ok": None, "words": ""}
    said, complete = state.get("words") or "", state.get("ok")
    alt_chain = None
    if aplaced and aplaced[2]:
        achain, ast = chain_complete(alt["pem"], aplaced[0] + aplaced[1], root_now)
        alt_chain = _joined(achain)
        useful = useful + [c for c in aplaced[2] if c not in useful]
        said = (said + " - " if said else "") + "the second (%s) one: %s" % (
            (alt.get("info") or {}).get("key") or "ECDSA", ast.get("words"))
        if ast.get("ok") is False:
            complete = False
    set_meta(ctx.store, "tls:root", {"pem": root_now, "at": time.time(), "by": who})
    chain_keep(ctx.store, cur["pem"], _joined(chain), state,
               (alt["pem"], alt_chain if alt_chain is not None else (alt.get("chain") or ""),
                ast if aplaced and aplaced[2] else (alt.get("chain_state") or {})) if alt else None)
    if _joined(chain) != (cur.get("chain") or "") or alt_chain is not None:
        _chain_ask(ctx, who, cur, _joined(chain), alt_chain if alt_chain is not None else
                   ((alt or {}).get("chain") if alt else None), said)
        said += " - root puts the chain in nginx within a few seconds"
    ctx.event("%s added %s to the chain of the certificate: %s" % (
        who, ", ".join(cert_info(c).get("cn") or "?" for c in useful), said), "info" if complete else "warn")
    out = view(ctx)
    out.update(message=said, complete=complete)
    return out


# ---- Download (otp's certExport, tls_export, 1.0.191) ------------------------------------------------
EXPORT_WAIT_S = 30


def _export_one(cur, kind):
    """A format without the key, made here: (file name ending, bytes, type)."""
    if kind == "pem":
        return ".crt", cur["pem"].encode(), "application/x-x509-ca-cert"
    if kind == "fullchain":
        return "-fullchain.pem", (cur["pem"] + (cur.get("chain") or "")).encode(), "application/x-pem-file"
    if kind == "der":
        return ".cer", openssl(["x509", "-outform", "DER"], cur["pem"], what="the certificate"), \
            "application/pkix-cert"
    with tempfile.TemporaryDirectory(prefix="fake-igd-p7-") as t:
        cf = os.path.join(t, "c.pem")
        with open(cf, "w") as f:
            f.write(cur["pem"] + (cur.get("chain") or ""))
        return ".p7b", openssl(["crl2pkcs7", "-nocrl", "-certfile", cf, "-outform", "DER"], what="PKCS#7"), \
            "application/x-pkcs7-certificates"


def _export_root(ctx, who, kind, which, password, legacy):
    """With the private key: root makes it (the key is root's alone) into web/export-tls.json, read
    here once and taken away."""
    ident = ctx.ask_root({"action": "export", "kind": kind, "which": which, "password": password,
                          "legacy": bool(legacy)}, kind="tls")
    folder = os.path.join(ctx.cfg.get("state_dir") or "/var/lib/fake-igd", "web")
    until = time.time() + EXPORT_WAIT_S
    while time.time() < until:
        res = ctx.root_result("tls", ident)
        if res:
            if not res.get("ok"):
                raise ValueError("root did not make it: %s" % ((res.get("said") or ["?"])[-1]))
            p = os.path.join(folder, "export-tls.json")
            try:
                fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as f:
                    got = json.loads(f.read(4 << 20).decode("utf-8"))
            except (OSError, ValueError):
                got = {}
            try:
                os.unlink(p)
            except OSError:
                pass
            if got.get("id") != ident or not got.get("data"):
                raise ValueError("root's file with it is not there - try again")
            return base64.b64decode(got["data"])
        time.sleep(0.4)
    raise ValueError("root has not made it in %d s - is fake-igd-web.path active?" % EXPORT_WAIT_S)


def export(ctx, who, b):
    import io
    import zipfile
    kind = str(b.get("kind") or "pem")
    which = str(b.get("which") or "rsa")
    if kind not in ("pem", "fullchain", "der", "p7b", "pfx", "pemkey"):
        raise ValueError("the format is pem, fullchain, der, p7b, pfx or pemkey")
    if which not in ("rsa", "ec", "both"):
        raise ValueError("which is rsa, ec or both")
    cur = current(kept_root(ctx.store))
    if not cur or not cur.get("info"):
        raise ValueError("there is no certificate in nginx's file")
    alt = cur.get("alt") if (cur.get("alt") or {}).get("pem") else None
    if which != "rsa" and not alt:
        raise ValueError("there is no second (ECDSA) certificate")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", cur["info"].get("cn") or "fake-igd")[:60] or "fake-igd"
    files = []
    for w in (["rsa", "ec"] if which == "both" else [which]):
        one = cur if w == "rsa" else alt
        name = base + ("-ecdsa" if w == "ec" and which == "both" else "")
        if kind in ("pfx", "pemkey"):
            pw = str(b.get("password") or "")
            if len(pw) < 10:
                raise ValueError("a password of 10 characters at least")
            data = _export_root(ctx, who, kind, w, pw, b.get("legacy") is True)
            files.append((name + (".pfx" if kind == "pfx" else "-key.pem"), data,
                          "application/x-pkcs12" if kind == "pfx" else "application/x-pem-file"))
        else:
            end, data, typ = _export_one(one, kind)
            files.append((name + end, data, typ))
    if len(files) == 2:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, d, _t in files:
                z.writestr(n, d)
        files = [(base + ".zip", buf.getvalue(), "application/zip")]
    if kind in ("pfx", "pemkey"):
        ctx.event("%s downloaded the certificate WITH its private key (%s%s)" % (
            who, "PFX" if kind == "pfx" else "PEM", ", both" if which == "both" else ""), "warn")
    return {"name": files[0][0], "type": files[0][2], "data": base64.b64encode(files[0][1]).decode("ascii")}


# ---- the routes --------------------------------------------------------------------------------
def get_tls(ctx):
    return view(ctx)


def _care_off(ctx, who, why):
    """A certificate put in by hand takes it out of ACME's care (otp 1.0.170)."""
    care = meta(ctx.store, "acme:care") or {}
    if care.get("on", True):
        set_meta(ctx.store, "acme:care", {"on": False, "at": time.time(), "by": who, "why": why})


def post_tls(ctx):
    me = ctx.need("fulladmin")
    who = me.get("name", "")
    b = ctx.body()
    act = str(b.get("action") or "")
    if act == "tls_upload":
        text = str(b.get("cert") or "")
        if len(text) > 400000:
            raise ValueError("that is far more than a certificate and its chain")
        pfx = [b"", b""]
        for i, k in enumerate(("pfx", "pfx2")):
            if b.get(k):
                try:
                    pfx[i] = base64.b64decode(str(b[k]), validate=True)
                except ValueError:
                    raise ValueError("the PFX / PKCS#12 file did not arrive whole")
        got = cert_bundle(text, pfx[0], str(b.get("password") or ""), pending_key(ctx.cfg), pfx[1])
        add = names_missing(got["info"]) if b.get("add_names") is True else []
        put_pem(ctx, got["cert"], got["chain"], got["key"], "uploaded", who, add_names=add, alt=got.get("alt"),
                roots=got.get("roots") or "", checked=True, state=got.get("chain_state"))
        _care_off(ctx, who, "uploaded")
        try:
            os.unlink(pending_file(ctx.cfg))
        except OSError:
            pass
        ctx.store.set_meta("tls:csr", "null")
        i = got["info"]
        ctx.event("%s put in a certificate for %s (%s, good until %s) - root puts it in nginx%s" % (
            who, i.get("cn") or ", ".join(i.get("san") or []) or "?",
            "self-signed" if i.get("self_signed") else (i.get("issuer") or "?"),
            time.strftime("%Y-%m-%d", time.gmtime(i["not_after"])) if i.get("not_after") else "?",
            "; %s added to nginx's server_name" % ", ".join(add) if add else ""))
        out = view(ctx)
        out["message"] = "checked - root puts it in nginx within a few seconds (%s)%s" % (
            got["chain_state"].get("words", ""), "; the ECDSA one beside it" if got.get("alt") else "")
        return out
    if act in ("tls_selfsigned", "tls_csr"):
        cn = str(b.get("cn") or "").strip().lower()
        names = [x.strip() for x in re.split(r"[\s,;]+", str(b.get("names") or "")) if x.strip()][:50]
        kind = str(b.get("kind") or "rsa2048")
        if kind not in KEY_KINDS:
            raise ValueError("the key is one of %s" % ", ".join(KEY_KINDS))
        subj = {"org": str(b.get("org") or "")[:64]}
        if act == "tls_selfsigned":
            try:
                days = int(b.get("days") or 825)
            except (TypeError, ValueError):
                days = 825
            if not 1 <= days <= 3650:
                raise ValueError("a self-signed certificate is good for 1 to 3650 days")
            key, crt = make_selfsigned(cn, names, days, kind, **subj)
            add = names_missing({"cn": cn, "san": names}) if b.get("add_names") is True else []
            put_pem(ctx, crt, "", key, "self-signed", who, add_names=add)
            _care_off(ctx, who, "self-signed")
            ctx.event("%s made a self-signed certificate for %s - root puts it in nginx%s" % (
                who, ", ".join([cn] + names), "; %s added to nginx's server_name" % ", ".join(add) if add else ""))
            out = view(ctx)
            out["message"] = "made - root puts it in nginx within a few seconds; the browser asks once more to accept it"
            return out
        subj.update(unit=str(b.get("unit") or "")[:64], city=str(b.get("city") or "")[:64],
                    country=str(b.get("country") or "").strip())
        key, csr = make_csr(cn, names, kind, **subj)
        p = pending_file(ctx.cfg)
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        tmp = p + ".%s.tmp" % secrets.token_hex(4)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        os.replace(tmp, p)
        set_meta(ctx.store, "tls:csr", {"csr": csr, "at": time.time(), "by": who, "cn": cn})
        ctx.event("%s made a certificate request for %s (its key waits here)" % (who, ", ".join([cn] + names)))
        out = view(ctx)
        out["csr"] = csr
        return out
    if act == "tls_csr_drop":
        try:
            os.unlink(pending_file(ctx.cfg))
        except OSError:
            pass
        ctx.store.set_meta("tls:csr", "null")
        ctx.event("%s dropped the waiting certificate request" % who)
        out = view(ctx)
        out["message"] = "the request and its key are gone"
        return out
    if act == "tls_chain":
        return chain_again(ctx, who)
    if act == "tls_chain_add":
        return chain_add(ctx, who, b)
    if act == "tls_export":
        return export(ctx, who, b)
    if act == "tls_policy":
        pol = policy_checked(b)
        ident = ctx.ask_root({"action": "policy", "protocols": pol["protocols"], "ciphers": pol["ciphers"],
                              "prefer": pol["prefer"], "dh": pol["dh"], "hsts": pol["hsts"]}, kind="tls")
        set_meta(ctx.store, "tls:policy", dict(pol, at=time.time(), by=who))
        set_meta(ctx.store, "tls:asked", {"id": ident, "at": time.time(), "action": "policy", "by": who})
        ctx.event("%s set how TLS is spoken: %s (%s), DH %s, the server chooses %s, HSTS %s" % (
            who, pol["preset"], " ".join(pol["protocols"]), pol["dh"], "yes" if pol["prefer"] else "no",
            ("%d days" % (pol["hsts"] // 86400)) if pol["hsts"] else "off"))
        out = view(ctx)
        out["message"] = "saved - root puts it in nginx" + (
            " (making DH parameters takes a while)" if pol["dh"].startswith("gen") else "")
        return out
    raise ValueError("no such action: %s" % act[:40])


# ---- the system's trusted roots (otp's osroots, 1.0.265) -----------------------------------------
# Certificate authorities of one's own put into the operating system's trust by root (root_tls.py,
# action osroots: the whole set wanted, synced). What is wanted is kept here; what root found when it
# last read the folder of local additions comes back in its answer and is kept beside it.
def _root_tls():
    import importlib.util
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (os.path.join(os.path.dirname(here), "deploy"), here, "/opt/fake-igd"):
        p = os.path.join(d, "root_tls.py")
        if os.path.isfile(p):
            mod = sys.modules.get("_igd_root_tls")
            if mod is None:
                spec = importlib.util.spec_from_file_location("_igd_root_tls", p)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                sys.modules["_igd_root_tls"] = mod
            return mod
    raise ValueError("root_tls.py is not beside the API")


OSR_EVERY = 1800


def osr_want(store):
    w = meta(store, "tls:osroots:want")
    return [x for x in w if isinstance(x, str)] if isinstance(w, list) else []


def osr_seen(ctx):
    """What root last read, taken from its answer when it is newer than what is kept."""
    seen = meta(ctx.store, "tls:osroots:seen") or {}
    res = ctx.root_result("tls")
    if res.get("osroots") and float(res.get("at") or 0) > float(seen.get("at") or 0):
        seen = {k: res.get(k) for k in ("ours", "others", "system", "flavour", "dir", "tool", "tool_there",
                                        "refused", "ok", "said", "at", "id")}
        set_meta(ctx.store, "tls:osroots:seen", seen)
    return seen


def osr_ask(ctx, do, by=""):
    pay = {"action": "osroots", "do": do}
    if do == "sync":
        pay["certs"] = osr_want(ctx.store)
    ident = ctx.ask_root(pay, kind="tls")
    set_meta(ctx.store, "tls:osroots:asked", {"id": ident, "at": time.time(), "do": do, "by": by})
    return ident


def osr_view(ctx):
    seen = osr_seen(ctx)
    asked = meta(ctx.store, "tls:osroots:asked") or {}
    waiting = bool(asked.get("id")) and asked.get("id") != seen.get("id") and time.time() - float(asked.get("at") or 0) < 600
    if not waiting and time.time() - float(seen.get("at") or 0) > OSR_EVERY and ctx.me:
        osr_ask(ctx, "list")
        waiting = True
    R = _root_tls()
    ours = {f.get("fp"): f for f in (seen.get("ours") or []) if f.get("fp")}
    certs = []
    for pem in osr_want(ctx.store):
        try:
            (p2, der), = R.osroots_blocks(pem)
            f = R.osroots_facts(p2, der)
        except Exception:                                   # noqa: BLE001 - kept, said broken
            continue
        o = ours.get(f["fp"]) or {}
        c = {k: f.get(k) for k in ("fp", "cn", "subject", "issuer", "not_before", "not_after", "key", "kind", "warn")}
        c.update(pem=p2, on=bool(o) and o.get("in_bundle") is not False)
        certs.append(c)
    # As otp's osr_node_status: "none" while nothing is wanted (a read of the folder going on is not
    # waiting for anything); waiting only for a change asked and not answered yet - said late after
    # five minutes.
    syncing = waiting and asked.get("do") == "sync"
    why = ""
    if not certs and not ours and not syncing:
        status = "failed" if seen.get("ok") is False else "none"
    elif syncing:
        status = "waiting"
        if time.time() - float(asked.get("at") or 0) > 300:
            why = "asked more than five minutes ago and not done - is fake-igd-web.path active?"
    elif seen.get("ok") is False or seen.get("refused"):
        status = "failed"
    elif certs and all(c["on"] for c in certs) and len(ours) <= len(certs):
        status = "applied"
    else:
        status = "waiting"
    if seen.get("ok") is False:
        why = (seen.get("said") or [""])[-1]
    elif seen.get("refused"):
        why = "; ".join("%s: %s" % (r.get("cn"), r.get("why")) for r in seen["refused"])
    return {"may": (ctx.me or {}).get("role") == "fulladmin", "certs": certs, "max": R.OSROOTS_MAX,
            "node": {"name": socket.gethostname(), "status": status, "why": why, "system": seen.get("system") or {},
                     "dir": seen.get("dir") or "", "tool": seen.get("tool") or "", "tool_there": seen.get("tool_there"),
                     "ours": [{k: f.get(k) for k in ("fp", "cn", "file", "in_bundle", "broken")} for f in seen.get("ours") or []],
                     "others": seen.get("others") or [], "at": seen.get("at")},
            "python": {"cafile": ca_file()}}


def get_osroots(ctx):
    ctx.need("readonly")
    return osr_view(ctx)


def post_osroots(ctx):
    me = ctx.need("fulladmin")
    who = me.get("name", "")
    b = ctx.body()
    act = str(b.get("action") or "")
    R = _root_tls()
    if act == "check":
        text = b.get("text")
        if not isinstance(text, str) or len(text) > R.OSROOTS_MAX * R.OSROOTS_PEM_MAX:
            raise ValueError("the certificates as PEM text")
        have = set()
        for pem in osr_want(ctx.store):
            try:
                have.add(R.osroots_facts(pem)["fp"])
            except Exception:                               # noqa: BLE001
                pass
        out = []
        try:
            for pem, der in R.osroots_blocks(text)[:R.OSROOTS_MAX + 1]:
                f = R.osroots_facts(pem, der)
                out.append(dict(f, pem=pem, already=f["fp"] in have))
        except R.Refused as e:
            raise ValueError(str(e))
        return {"certs": out}
    if act == "add":
        try:
            blocks = R.osroots_blocks(str(b.get("text") or ""))
        except R.Refused as e:
            raise ValueError(str(e))
        want = osr_want(ctx.store)
        fps = set()
        for pem in want:
            try:
                fps.add(R.osroots_facts(pem)["fp"])
            except Exception:                               # noqa: BLE001
                pass
        added, refused = [], []
        for pem, der in blocks:
            try:
                f = R.osroots_facts(pem, der)
            except R.Refused as e:
                raise ValueError(str(e))
            if f["refused"]:
                refused.append("%s: %s" % (f["cn"], "; ".join(f["refused"])))
                continue
            if f["fp"] in fps:
                continue
            want.append(pem)
            fps.add(f["fp"])
            added.append(f["cn"])
        if refused and not added:
            raise ValueError("; ".join(refused))
        if len(want) > R.OSROOTS_MAX:
            raise ValueError("%d at most" % R.OSROOTS_MAX)
        if not added:
            raise ValueError("there already - nothing new in it")
        set_meta(ctx.store, "tls:osroots:want", want)
        osr_ask(ctx, "sync", who)
        ctx.event("%s added to the system's trust: %s - root puts it in" % (who, ", ".join(added)), "warn")
        return dict(osr_view(ctx), message="added - root puts it into the system's trust in a moment" +
                    ("; not taken: %s" % "; ".join(refused) if refused else ""))
    if act == "remove":
        fp = str(b.get("fp") or "")
        want, gone = [], ""
        for pem in osr_want(ctx.store):
            try:
                f = R.osroots_facts(pem)
            except Exception:                               # noqa: BLE001
                continue
            if f["fp"] == fp:
                gone = f["cn"]
            else:
                want.append(pem)
        if not gone:
            raise ValueError("no such authority here")
        set_meta(ctx.store, "tls:osroots:want", want)
        osr_ask(ctx, "sync", who)
        ctx.event("%s took %s out of the system's trust - root takes it away" % (who, gone), "warn")
        return dict(osr_view(ctx), message="taken away - root takes it out of the system's trust in a moment")
    if act == "refresh":
        osr_ask(ctx, "list", who)
        return dict(osr_view(ctx), message="root reads it again - a moment")
    raise ValueError("check, add, remove or refresh")


ROUTES = {("GET", "/api/tls"): get_tls, ("POST", "/api/tls"): post_tls,
          ("GET", "/api/osroots"): get_osroots, ("POST", "/api/osroots"): post_osroots}
