"""root_tls.py - what root does for Certificates and TLS (and Automatic certificates).

Run by fake_igd_web.py (as root, from fake-igd-web.path) for each ask of kind "tls" the API
lays down in /var/lib/fake-igd/web/ask/. The shape of otp's otp_web.py tls_*: nothing in
the ask is trusted - every value is checked against the one shape it may have.

  put       {cert, chain, key, alt?: {cert, chain, key}, keep_before}
            the certificate (and its chain) into /etc/nginx/certs/fake-igd.pem, its key into
            fake-igd.key (0600); a second (ECDSA) certificate beside it into fake-igd-ecdsa.pem
            and .key, both named in fake-igd.conf (nginx gives each client the one it takes).
            Checked first with openssl: PEM, the key the certificate's own, not run out.
            keep_before: the files there now are kept as fake-igd.pem.before-acme (Automatic
            certificates' "Back to the one before").
  put_back  the certificate from before ACME put back as it was (its key with it).
  policy    {protocols, ciphers, prefer, dh, hsts}: ssl_protocols, ssl_ciphers,
            ssl_prefer_server_ciphers, ssl_dhparam (an RFC 7919 group, or made here) and the
            Strict-Transport-Security header in fake-igd.conf's server on 443.

Every change: the files written beside their place and renamed, a copy of each kept, nginx -t
asked - and everything put back as it was when it says no; then nginx is reloaded.

Paths for tests: FAKE_IGD_CERT_DIR, FAKE_IGD_NGINX, FAKE_IGD_NGINX_BIN (nginx -t),
FAKE_IGD_NGINX_RELOAD (the reload command, words split on spaces), FAKE_IGD_OPENSSL.
"""
import os
import re
import shlex
import subprocess
import tempfile
import time

CERT_DIR = os.environ.get("FAKE_IGD_CERT_DIR", "/etc/nginx/certs")
NGINX_CONF = os.environ.get("FAKE_IGD_NGINX", "/etc/nginx/conf.d/fake-igd.conf")
NGINX_BIN = os.environ.get("FAKE_IGD_NGINX_BIN", "nginx")
RELOAD = os.environ.get("FAKE_IGD_NGINX_RELOAD", "systemctl reload nginx")
OPENSSL = os.environ.get("FAKE_IGD_OPENSSL", "openssl")

FILES = {"cert": "fake-igd.pem", "key": "fake-igd.key", "cert2": "fake-igd-ecdsa.pem", "key2": "fake-igd-ecdsa.key",
         "dh": "fake-igd-dh.pem", "before": "fake-igd.pem.before-acme", "before_key": "fake-igd.key.before-acme"}
CERT_RE = re.compile(r"^(\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----)+\s*\Z")
KEY_RE = re.compile(r"^\s*-----BEGIN (RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (RSA |EC )?PRIVATE KEY-----\s*\Z")
PROTOCOLS = ("TLSv1.2", "TLSv1.3")
DH_CHOICES = ("none", "ffdhe2048", "ffdhe3072", "ffdhe4096", "gen2048", "gen3072", "gen4096")
CIPHERS_DEFAULT = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                   "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                   "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")


class Refused(Exception):
    pass


def path(k):
    return os.path.join(CERT_DIR, FILES[k])


def openssl(args, what, data=None):
    try:
        got = subprocess.run([OPENSSL] + args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=1800)
    except FileNotFoundError:
        raise Refused("openssl is not on this machine")
    if got.returncode != 0:
        raise Refused("%s: %s" % (what, ((got.stderr or got.stdout).strip().splitlines() or ["openssl said no"])[-1][:200]))
    return got.stdout


# ---- the values of an ask, checked -------------------------------------------------------------
def pem_set(cert, key, chain, what="the certificate"):
    cert, key, chain = str(cert or "").strip(), str(key or "").strip(), str(chain or "").strip()
    if not cert or not key:
        raise Refused("%s needs its key, and a key its certificate" % what)
    if len(cert) + len(chain) > 300000 or len(key) > 20000:
        raise Refused("%s is far longer than certificates are" % what)
    if not CERT_RE.match(cert) or len(re.findall("BEGIN CERTIFICATE", cert)) != 1:
        raise Refused("%s is not one PEM certificate (-----BEGIN CERTIFICATE-----)" % what)
    if chain and not CERT_RE.match(chain):
        raise Refused("the chain of %s is not PEM certificates" % what)
    if not KEY_RE.match(key):
        raise Refused("the key of %s is not a PEM private key without a passphrase" % what)
    with tempfile.TemporaryDirectory(prefix="fake-igd-tls-") as t:
        cf, kf = os.path.join(t, "c.pem"), os.path.join(t, "k.pem")
        with open(cf, "w") as f:
            f.write(cert + "\n")
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
        a = openssl(["x509", "-in", cf, "-noout", "-pubkey"], what)
        b = openssl(["pkey", "-in", kf, "-pubout"], "the key of %s" % what)
        if a.strip() != b.strip():
            raise Refused("the key is not the one of %s" % what)
        try:
            openssl(["x509", "-in", cf, "-noout", "-checkend", "0"], what)
        except Refused:
            raise Refused("%s has run out" % what)
        if chain:
            with open(cf, "w") as f:
                f.write(chain + "\n")
            openssl(["crl2pkcs7", "-nocrl", "-certfile", cf], "the chain of %s" % what)
    return {"cert": cert + "\n", "chain": (chain + "\n") if chain else "", "key": key + "\n"}


def policy_checked(p):
    prot = p.get("protocols")
    if not isinstance(prot, list) or not prot or any(x not in PROTOCOLS for x in prot):
        raise Refused("the protocols are TLSv1.2 and/or TLSv1.3")
    out = {"protocols": [x for x in PROTOCOLS if x in prot]}
    ciphers = str(p.get("ciphers") or "").strip()
    if ciphers:
        if not re.match(r"^[A-Za-z0-9_+!@=:.-]{1,2000}\Z", ciphers):
            raise Refused("the ciphers are an OpenSSL cipher list: letters, digits, : + ! - =")
        openssl(["ciphers", ciphers], "OpenSSL does not know that cipher list")
    out["ciphers"] = ciphers
    if not isinstance(p.get("prefer"), bool):
        raise Refused("prefer is true or false")
    out["prefer"] = p["prefer"]
    dh = p.get("dh")
    if dh not in DH_CHOICES:
        raise Refused("the DH parameters are one of %s" % ", ".join(DH_CHOICES))
    out["dh"] = dh
    hsts = p.get("hsts")
    if not isinstance(hsts, int) or isinstance(hsts, bool) or not 0 <= hsts <= 63072000:
        raise Refused("HSTS is 0 to 63072000 seconds")
    out["hsts"] = hsts
    return out


# ---- nginx's file ------------------------------------------------------------------------------
def server_block(text, port="443"):
    for m in re.finditer(r"(?m)^[ \t]*server\s*\{", text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            c = text[i]
            if c == "#":
                j = text.find("\n", i)
                i = len(text) if j < 0 else j
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        block = text[m.start():i + 1]
        if re.search(r"(?m)^\s*listen\s+(?:\S+:)?%s\b" % port, block):
            return m.start(), i + 1
    return None


def set_directive(block, name, value, after=None, before=None):
    """A directive of the server's own level set to `value` (a list: one line each; None: taken
    out), its spacing kept. New ones go after the line of `after`, or before the first line of
    `before`, else before the first location."""
    def line_re(n):
        return re.compile(r"(?m)^([ \t]*)%s(\s+)[^;\n]*;[^\n]*\n" % r"\s+".join(re.escape(w) for w in n.split()))
    found = list(line_re(name).finditer(block))
    values = [] if value is None else (value if isinstance(value, list) else [value])
    if found:
        indent, gap = found[0].group(1), found[0].group(2).replace("\n", "")
        lines = "".join("%s%s%s%s;\n" % (indent, name, gap or " ", v) for v in values)
        first = found[0]
        out = block[:first.start()] + lines
        last = first.end()
        for m in found[1:]:
            out += block[last:m.start()]
            last = m.end()
        return out + block[last:]
    if not values:
        return block
    if after:
        m = line_re(after).search(block)
        if m:
            gap = m.group(2) if len(m.group(2)) > 1 else " "
            pad = " " * max(1, len(after) + len(gap) - len(name)) if len(gap) > 1 else " "
            lines = "".join("%s%s%s%s;\n" % (m.group(1), name, pad, v) for v in values)
            return block[:m.end()] + lines + block[m.end():]
    if before:
        m = re.search(r"(?m)^([ \t]*)%s\b" % re.escape(before), block)
        if m:
            lines = "".join("%s%s %s;\n" % (m.group(1), name, v) for v in values)
            return block[:m.start()] + lines + block[m.start():]
    lines = "".join("    %s %s;\n" % (name, v) for v in values)
    m = re.search(r"(?m)^[ \t]*location\b", block)
    at = m.start() if m else block.rstrip().rfind("}")
    return block[:at] + lines + ("\n" if m else "") + block[at:]


def conf_edit(fn):
    """fake-igd.conf with its 443 server changed by fn(block) -> block; the new text."""
    try:
        with open(NGINX_CONF, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise Refused("%s cannot be read: %s" % (NGINX_CONF, e))
    where = server_block(text, "443")
    if not where:
        raise Refused("%s has no server listening on 443" % NGINX_CONF)
    return text[:where[0]] + fn(text[where[0]:where[1]]) + text[where[1]:]


# ---- files: written beside, renamed, put back -------------------------------------------------
def snapshot(paths):
    got = {}
    for p in paths:
        try:
            with open(p, "rb") as f:
                got[p] = (f.read(), os.stat(p).st_mode & 0o777)
        except FileNotFoundError:
            got[p] = None
    return got


def write_file(p, data, mode):
    if isinstance(data, str):
        data = data.encode("utf-8")
    folder = os.path.dirname(p)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".%s." % os.path.basename(p), dir=folder)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        subprocess.run(["restorecon", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def put_back(snap):
    for p, was in snap.items():
        if was is None:
            try:
                os.unlink(p)
            except OSError:
                pass
        else:
            write_file(p, was[0], was[1])


def nginx_test():
    try:
        r = subprocess.run([NGINX_BIN, "-t"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=60)
    except FileNotFoundError:
        return False, "nginx is not on this machine"
    lines = [ln for ln in r.stdout.strip().splitlines() if ln.strip()]
    return r.returncode == 0, (lines[-1] if lines else "")[:400]


def nginx_reload():
    try:
        r = subprocess.run(shlex.split(RELOAD), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=60)
    except FileNotFoundError:
        return False, "%s is not on this machine" % RELOAD.split()[0]
    return r.returncode == 0, r.stdout.strip()[-300:]


def apply(writes, said):
    """writes: [(path, bytes-or-None, mode)] - None takes the file away. All of it, nginx -t,
    reload; everything as it was when nginx says no."""
    snap = snapshot([w[0] for w in writes])
    try:
        for p, data, mode in writes:
            if data is None:
                try:
                    os.unlink(p)
                except FileNotFoundError:
                    pass
            else:
                write_file(p, data, mode)
        ok, words = nginx_test()
        if not ok:
            raise Refused("nginx -t did not take it (%s) - everything is as it was" % words)
    except BaseException as e:
        put_back(snap)
        if isinstance(e, Refused):
            raise
        raise Refused("it could not be written (%s) - everything is as it was" % e)
    said.append("nginx -t: the configuration is good")
    ok, words = nginx_reload()
    said.append("nginx reloaded" if ok else "nginx could not be reloaded: %s" % words)
    return ok


# ---- the actions -------------------------------------------------------------------------------
def do_put(payload, said):
    main = pem_set(payload.get("cert"), payload.get("key"), payload.get("chain"))
    alt = None
    if payload.get("alt") is not None:
        a = payload["alt"]
        if not isinstance(a, dict):
            raise Refused("the second certificate is not an object")
        alt = pem_set(a.get("cert"), a.get("key"), a.get("chain"), "the second certificate")
    keep = payload.get("keep_before", False)
    if not isinstance(keep, bool):
        raise Refused("keep_before is true or false")
    writes = []
    if keep and os.path.isfile(path("cert")) and os.path.isfile(path("key")):
        with open(path("cert"), "rb") as f:
            old_c = f.read()
        with open(path("key"), "rb") as f:
            old_k = f.read()
        writes += [(path("before"), old_c, 0o644), (path("before_key"), old_k, 0o600)]
    writes += [(path("cert"), main["cert"] + main["chain"], 0o644), (path("key"), main["key"], 0o600)]

    def lines(block):
        if alt:
            block = set_directive(block, "ssl_certificate", [path("cert"), path("cert2")])
            block = set_directive(block, "ssl_certificate_key", [path("key"), path("key2")])
        else:
            block = set_directive(block, "ssl_certificate", path("cert"))
            block = set_directive(block, "ssl_certificate_key", path("key"))
        return block
    conf = conf_edit(lines)
    if alt:
        writes += [(path("cert2"), alt["cert"] + alt["chain"], 0o644), (path("key2"), alt["key"], 0o600)]
    else:
        writes += [(path("cert2"), None, 0), (path("key2"), None, 0)]
    writes.append((NGINX_CONF, conf, 0o644))
    subj = openssl(["x509", "-noout", "-subject", "-enddate"], "the certificate", main["cert"]).strip().replace("\n", ", ")
    ok = apply(writes, said)
    if keep and any(w[0] == path("before") for w in writes):
        said.insert(0, "the certificate there before is kept as %s" % path("before"))
    said.insert(0, "certificate: %s%s" % (subj, " (and an ECDSA one beside it)" if alt else ""))
    return ok


def do_put_back(said):
    if not (os.path.isfile(path("before")) and os.path.isfile(path("before_key"))):
        raise Refused("there is no certificate from before ACME here")
    with open(path("before"), "rb") as f:
        c = f.read().decode("utf-8", "replace")
    with open(path("before_key"), "rb") as f:
        k = f.read().decode("utf-8", "replace")
    certs = re.findall(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", c)
    if not certs:
        raise Refused("%s holds no certificate" % path("before"))
    main = pem_set(certs[0], k, "\n".join(certs[1:]), "the certificate from before")
    conf = conf_edit(lambda b: set_directive(set_directive(b, "ssl_certificate", path("cert")),
                                             "ssl_certificate_key", path("key")))
    writes = [(path("cert"), main["cert"] + main["chain"], 0o644), (path("key"), main["key"], 0o600),
              (path("cert2"), None, 0), (path("key2"), None, 0), (NGINX_CONF, conf, 0o644),
              (path("before"), None, 0), (path("before_key"), None, 0)]
    ok = apply(writes, said)
    said.insert(0, "the certificate from before ACME is back")
    return ok


def dh_pem(choice):
    if choice.startswith("ffdhe"):
        return openssl(["genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", "group:%s" % choice],
                       "the DH group %s" % choice)
    return openssl(["dhparam", choice[3:]], "making DH parameters of %s bits" % choice[3:])


def do_policy(payload, said):
    p = policy_checked(payload)
    writes = []
    dh = None
    if p["dh"] != "none":
        began = time.time()
        writes.append((path("dh"), dh_pem(p["dh"]), 0o644))
        dh = path("dh")
        said.append("DH parameters %s in %s (%d s)" % (p["dh"], dh, time.time() - began))

    def lines(block):
        block = set_directive(block, "ssl_protocols", " ".join(p["protocols"]), after="ssl_certificate_key")
        block = set_directive(block, "ssl_ciphers", p["ciphers"] or CIPHERS_DEFAULT, after="ssl_protocols")
        block = set_directive(block, "ssl_prefer_server_ciphers", "on" if p["prefer"] else "off", after="ssl_ciphers")
        block = set_directive(block, "ssl_dhparam", dh, after="ssl_prefer_server_ciphers")
        block = set_directive(block, "add_header Strict-Transport-Security",
                              '"max-age=%d" always' % p["hsts"] if p["hsts"] else None, before="add_header")
        return block
    writes.append((NGINX_CONF, conf_edit(lines), 0o644))
    ok = apply(writes, said)
    said.insert(0, "%s; %s; DH %s; the server chooses: %s; HSTS %s" % (
        " ".join(p["protocols"]), "ciphers as set" if p["ciphers"] else "the usual ciphers", p["dh"],
        "on" if p["prefer"] else "off", ("%d s" % p["hsts"]) if p["hsts"] else "off"))
    return ok


def serve(payload, ask=None):
    said = []
    act = payload.get("action") if isinstance(payload, dict) else None
    if act not in ("put", "put_back", "policy"):
        return {"ok": False, "action": str(act)[:20], "said": ["no such action"]}
    try:
        if act == "put":
            ok = do_put(payload, said)
        elif act == "put_back":
            ok = do_put_back(said)
        else:
            ok = do_policy(payload, said)
    except Refused as e:
        return {"ok": False, "action": act, "said": said + [str(e)]}
    return {"ok": bool(ok), "action": act, "said": said}


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(serve(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}), indent=1))
