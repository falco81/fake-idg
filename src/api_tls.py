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
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
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


def cert_info(pem):
    """What a certificate says of itself, for the pages (otp's cert_info)."""
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


def chain_state(leaf, chain):
    """Whether the certificate and its chain lead to a root of the system - as curl and every
    client that fetches nothing check it (otp 1.0.269)."""
    ca = ca_file()
    if not ca:
        return {"ok": None, "words": "the system's roots are not found here - not checked"}
    with tempfile.TemporaryDirectory(prefix="fake-igd-chain-") as t:
        lf, cf = os.path.join(t, "leaf.pem"), os.path.join(t, "chain.pem")
        with open(lf, "w") as f:
            f.write(leaf)
        args = ["verify", "-CAfile", ca]
        if chain.strip():
            with open(cf, "w") as f:
                f.write(chain)
            args += ["-untrusted", cf]
        try:
            openssl(args + [lf], what="checked against the system's roots")
        except ValueError as e:
            return {"ok": False, "words": "incomplete - it does not lead to a root of the system (%s): curl and "
                                          "other clients that fetch nothing refuse it" % str(e).split(": ", 1)[-1]}
    n = len(PEM_CERT.findall(chain))
    return {"ok": True, "words": "complete - %d between it and the root" % n}


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


def cert_bundle(text="", pfx=b"", password="", pending_key=""):
    """Whatever was sent - one PEM with everything in it, or a PFX / PKCS#12 - as the parts
    nginx needs: the certificate, its key, the chain up from it (each the issuer of the one
    before; a root is never sent). The key is the certificate's own or nothing is taken."""
    certs, keys = [], []
    if pfx:
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
        t = got.decode("utf-8", "replace")
        certs += [m.group(0) for m in PEM_CERT.finditer(t)]
        keys += [m.group(0) for m in PEM_KEY.finditer(t)]
    certs += [m.group(0) for m in PEM_CERT.finditer(text or "") if m.group(0) not in certs]
    keys += [m.group(0) for m in PEM_KEY.finditer(text or "")]
    if not certs:
        raise ValueError("no certificate was found in what was sent (PEM, or a PFX / PKCS#12 file)")
    if len(keys) > 1:
        raise ValueError("more than one private key was sent")
    if keys:
        key_pem = key_plain(keys[0], password)
    elif pending_key:
        key_pem = pending_key
    else:
        raise ValueError("no private key came with it: send the key too (or the PFX), or make the request "
                         "here first so the key is waiting")
    want = pub_of_key(key_pem)
    leaf = next((c for c in certs if pub_of_cert(c) == want), None)
    if not leaf:
        raise ValueError("none of the certificates is the one of this key")
    info = cert_info(leaf)
    now = time.time()
    if info.get("not_after") and info["not_after"] < now:
        raise ValueError("this certificate ran out on %s" % time.strftime("%Y-%m-%d %H:%M UTC",
                                                                         time.gmtime(info["not_after"])))
    if info.get("not_before") and info["not_before"] > now + 300:
        raise ValueError("this certificate is good only from %s - this machine's clock says it is not yet"
                         % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(info["not_before"])))
    others = [c for c in certs if c != leaf]
    infos = {c: cert_info(c) for c in others}
    roots = [c for c in others if infos[c]["self_signed"]]
    inter = [c for c in others if c not in roots]
    chain_out, at = [], info
    while inter:
        nxt = next((c for c in inter if infos[c].get("subject") == at.get("issuer")), None)
        if not nxt:
            chain_out += inter
            break
        chain_out.append(nxt)
        inter.remove(nxt)
        at = infos[nxt]
    chain = "".join(c.strip() + "\n" for c in chain_out)
    state = {"ok": None, "words": "signed by itself"} if info["self_signed"] else chain_state(leaf + "\n", chain)
    if state.get("ok") is False and roots:
        # A private authority's root given with it: checked against that root.
        with tempfile.TemporaryDirectory(prefix="fake-igd-chain-") as t:
            rf = os.path.join(t, "root.pem")
            with open(rf, "w") as f:
                f.write("".join(r + "\n" for r in roots))
            lf = os.path.join(t, "leaf.pem")
            with open(lf, "w") as f:
                f.write(leaf + "\n")
            args = ["verify", "-CAfile", rf]
            if chain:
                cf = os.path.join(t, "chain.pem")
                with open(cf, "w") as f:
                    f.write(chain)
                args += ["-untrusted", cf]
            try:
                openssl(args + [lf], what="checked against the root given")
                state = {"ok": True, "words": "complete - %d between it and the root given (%s)"
                         % (len(chain_out), infos[roots[0]].get("cn") or "a private authority")}
            except ValueError:
                pass
    return {"cert": leaf.strip() + "\n", "chain": chain, "key": key_pem, "info": info,
            "chain_info": [cert_info(c) for c in chain_out], "root_info": [infos[c] for c in roots],
            "chain_state": state}


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


def current():
    """The certificate in nginx's file now: its facts, its chain and the second one beside it."""
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
    out["chain_state"] = {"ok": None, "words": ""} if info.get("self_signed") else chain_state(certs[0] + "\n", chain)
    alt = [m.group(0) for m in PEM_CERT.finditer(_read(f["cert2"]))]
    if alt and f["cert2"] in nginx_now().get("certs", []):
        try:
            out["alt"] = {"info": cert_info(alt[0])}
        except ValueError:
            pass
    return out


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


def put_pem(ctx, cert, chain, key, how, by, alt=None, keep_before=False, words=""):
    """The certificate asked of root (root_tls.py: put) - the one way a certificate goes in,
    from here and from Automatic certificates. Returns the ask's id."""
    payload = {"action": "put", "cert": cert, "chain": chain or "", "key": key, "keep_before": bool(keep_before)}
    if alt:
        payload["alt"] = {"cert": alt["cert"], "chain": alt.get("chain") or "", "key": alt["key"]}
    ident = ctx.ask_root(payload, kind="tls")
    set_meta(ctx.store, "tls:asked", {"id": ident, "at": time.time(), "action": "put", "by": by, "how": how,
                                      "words": words})
    set_meta(ctx.store, "tls:how", {"how": how, "at": time.time(), "by": by})
    return ident


def ask_state(ctx):
    """How root's last ask of this pane went: waiting, done, failed."""
    asked = meta(ctx.store, "tls:asked") or {}
    res = ctx.root_result("tls")
    if asked.get("id") and res.get("id") != asked["id"]:
        late = time.time() - float(asked.get("at") or 0) > 120
        return {"state": "late" if late else "waiting", "action": asked.get("action"), "at": asked.get("at"),
                "said": ["root has not taken it yet - is fake-igd-web.path active?"] if late else []}
    if not res:
        return None
    return {"state": "done" if res.get("ok") else "failed", "action": res.get("action") or asked.get("action"),
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
        acme = {"on": bool(on), "care": care.get("on", True), "state": meta(ctx.store, "acme:state") or {}}
    except ValueError:
        pass
    pend = bool(pending_key(ctx.cfg))
    csr = (meta(ctx.store, "tls:csr") or {}).get("csr") if pend else ""
    return {"may": me.get("role") == "fulladmin", "cert": current(),
            "policy": {"preset": preset, "protocols": ng["protocols"], "ciphers": ng["ciphers"],
                       "prefer": ng["prefer"], "dh": dh, "dhparam": ng["dhparam"], "hsts": ng["hsts"]},
            "nginx": {"file": ng["file"], "there": ng["there"]},
            "names": ng["names"], "ips": host_ips(), "host": (ng["names"] or [os.uname()[1]])[0],
            "how": (meta(ctx.store, "tls:how") or {}).get("how") or "", "pending": pend, "csr": csr,
            "acme": acme, "before": before_acme(), "root": ask_state(ctx),
            "presets": TLS_PRESETS, "dh": DH_WORDS, "at": time.time()}


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
        pfx = b""
        if b.get("pfx"):
            try:
                pfx = base64.b64decode(str(b["pfx"]), validate=True)
            except ValueError:
                raise ValueError("the PFX / PKCS#12 file did not arrive whole")
        got = cert_bundle(text, pfx, str(b.get("password") or ""), pending_key(ctx.cfg))
        put_pem(ctx, got["cert"], got["chain"], got["key"], "uploaded", who)
        _care_off(ctx, who, "uploaded")
        try:
            os.unlink(pending_file(ctx.cfg))
        except OSError:
            pass
        ctx.store.set_meta("tls:csr", "null")
        i = got["info"]
        ctx.event("%s put in a certificate for %s (%s, good until %s) - root puts it in nginx" % (
            who, i.get("cn") or ", ".join(i.get("san") or []) or "?",
            "self-signed" if i.get("self_signed") else (i.get("issuer") or "?"),
            time.strftime("%Y-%m-%d", time.gmtime(i["not_after"])) if i.get("not_after") else "?"))
        out = view(ctx)
        out["message"] = "checked - root puts it in nginx within a few seconds (%s)" % got["chain_state"].get("words", "")
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
            put_pem(ctx, crt, "", key, "self-signed", who)
            _care_off(ctx, who, "self-signed")
            ctx.event("%s made a self-signed certificate for %s - root puts it in nginx" % (
                who, ", ".join([cn] + names)))
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


ROUTES = {("GET", "/api/tls"): get_tls, ("POST", "/api/tls"): post_tls}
