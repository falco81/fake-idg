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
  acme_http {names}: the port-80 server made ready for the CA's HTTP-01 challenge - the
            location /.well-known/acme-challenge/ → acme.php put in where it is missing (a
            fake-igd.conf of an older version), the names ordered added to its server_name, so
            that nginx gives a request for any of them to fake-igd (as otp's acme_into).
  osroots   {do: list | sync, certs?: [pem], force?}: the system's trusted roots (otp's osroots, 1.0.265) -
            certificate authorities of one's own put into the operating system's trust by its own way
            (RHEL: /etc/pki/ca-trust/source/anchors + update-ca-trust extract; Debian:
            /usr/local/share/ca-certificates + update-ca-certificates), fake-igd's files named
            fake-igd-<sha256 16>.pem; anything else there only shown.
  policy    {protocols, ciphers, prefer, dh, hsts}: ssl_protocols, ssl_ciphers,
            ssl_prefer_server_ciphers, ssl_dhparam (an RFC 7919 group, or made here - made once:
            the same choice again keeps the file) and the Strict-Transport-Security header in
            fake-igd.conf's server on 443.
  chain     {cert, chain, alt_chain?}: the chain beside the certificate in place replaced (otp's
            Complete the chain, Upload the missing authority) - the certificate and its key stay;
            cert must be the one in the file.
  export    {kind: pfx | pemkey, password, legacy, which: rsa | ec}: the certificate with its
            private key, locked with the password (otp's Download with the private key) - written
            to web/export-tls.json (0640, group fake-igd), which the API reads once and takes away.

While an ask is done, how far it is goes to web/progress-tls.json (otp's progress.json, 1.0.50):
the step, how many there are, what is being done, and - making DH parameters - when it began and
about how long it takes; the pages draw it as a bar. Taken away when the ask is answered.

Every change: the files written beside their place and renamed, a copy of each kept, nginx -t
asked - and everything put back as it was when it says no; then nginx is reloaded.

Paths for tests: FAKE_IGD_CERT_DIR, FAKE_IGD_NGINX, FAKE_IGD_NGINX_BIN (nginx -t),
FAKE_IGD_NGINX_RELOAD (the reload command, words split on spaces), FAKE_IGD_OPENSSL,
FAKE_IGD_OSROOTS_FLAVOUR (rhel | debian), FAKE_IGD_OSROOTS_DIR, FAKE_IGD_OSROOTS_BUNDLE,
FAKE_IGD_OSROOTS_EXTRACT (the tool, words split on spaces), FAKE_IGD_OSROOTS_PKG.
"""
import base64
import errno
import hashlib
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time

CERT_DIR = os.environ.get("FAKE_IGD_CERT_DIR", "/etc/nginx/certs")
NGINX_CONF = os.environ.get("FAKE_IGD_NGINX", "/etc/nginx/conf.d/fake-igd.conf")
NGINX_BIN = os.environ.get("FAKE_IGD_NGINX_BIN", "nginx")
RELOAD = os.environ.get("FAKE_IGD_NGINX_RELOAD", "systemctl reload nginx")
OPENSSL = os.environ.get("FAKE_IGD_OPENSSL", "openssl")

FILES = {"cert": "fake-igd.pem", "key": "fake-igd.key", "cert2": "fake-igd-ecdsa.pem", "key2": "fake-igd-ecdsa.key",
         "dh": "fake-igd-dh.pem", "dh_choice": "fake-igd-dh.choice",
         "before": "fake-igd.pem.before-acme", "before_key": "fake-igd.key.before-acme"}
WEB_DIR = os.path.join(os.environ.get("FAKE_IGD_STATE", "/var/lib/fake-igd"), "web")
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


# ---- how far it is (otp's progress.json, 1.0.50) -------------------------------------------------
PROGRESS = {"step": 0, "total": 4, "id": ""}
DH_EXPECT_S = {"gen2048": 15, "gen3072": 120, "gen4096": 600}


def _web_write(name, text, mode=0o640):
    """A file of root's answers in web/ (the API's folder): beside, then renamed; group fake-igd."""
    try:
        dfd = os.open(WEB_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        tmp = ".%s.%d" % (name, os.getpid())
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dfd)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            try:   # on the open file, never by name in a folder the API owns
                import grp
                os.fchown(f.fileno(), 0, grp.getgrnam("fake-igd").gr_gid)
            except (KeyError, OSError):
                pass
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)


def progress(words, step=None, expect=None):
    import json
    if step is not None:
        PROGRESS["step"] = step
    if PROGRESS.get("words") != words:
        PROGRESS["words"], PROGRESS["began"] = words, time.time()
    # "beat": root says again every 10 s that it still works on it (1.7.8) - a helper ended half way
    # (killed, its unit's time limit) is seen by the pages as such, not as a bar that runs for ever.
    _web_write("progress-tls.json", json.dumps({
        "id": PROGRESS["id"], "step": PROGRESS["step"], "total": PROGRESS["total"],
        "words": words, "at": time.time(), "began": PROGRESS["began"], "beat": 10, "pid": os.getpid(),
        "expect_s": expect}))


def progress_done():
    try:
        os.unlink(os.path.join(WEB_DIR, "progress-tls.json"))
    except OSError:
        pass


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
    progress("writing the certificate and the TLS settings", 3)
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
        progress("asking nginx, and reloading it", 4)
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


ACME_LOCATION = """    # A certificate by ACME (Settings → Automatic certificates): the CA's HTTP-01
    # challenge answered on port 80 by acme.php, which asks fake-igd-api for the
    # answer while an order waits. Open to anybody - the CA asks from the internet.
    # Everything else goes to HTTPS.
    location ^~ /.well-known/acme-challenge/ {
        if ($http_content_type ~* "multipart") { return 403; }
        limit_req     zone=igd_all burst=20 nodelay;
        fastcgi_pass  @SOCK@;
        fastcgi_param SCRIPT_FILENAME @ROOT@/acme.php;
        include       fastcgi_params;
        fastcgi_read_timeout 10s;
    }
"""
NAME_RE = re.compile(r"^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}\Z")


def acme_http_text(text, names):
    """fake-igd.conf with its port-80 server ready for HTTP-01 (the text unchanged when it is)."""
    where = server_block(text, "80")
    if not where:
        raise Refused("%s has no server listening on 80" % NGINX_CONF)
    block = text[where[0]:where[1]]
    new = block
    if "acme-challenge" not in new:
        sock = re.search(r"(?m)^\s*fastcgi_pass\s+(unix:[^;\s]+);", text)
        main = server_block(text, "443")
        root = re.search(r"(?m)^\s*root\s+([^;\s]+);", text[main[0]:main[1]] if main else text)
        loc = ACME_LOCATION.replace("@SOCK@", sock.group(1) if sock else "unix:/run/php-fpm/fake-igd.sock") \
            .replace("@ROOT@", (root.group(1) if root else "/var/www/fake-igd").rstrip("/"))
        m = re.search(r"(?m)^[ \t]*location\s+/\s*\{", new)
        if not m:
            raise Refused("the port-80 server of %s has no location / to put the ACME one before" % NGINX_CONF)
        new = new[:m.start()] + loc + new[m.start():]
    m = re.search(r"(?m)^(\s*server_name\s+)([^;#]*);", new)
    if m and names:
        have = m.group(2).split()
        want = have + [n for n in names if n not in have]
        if want != have:
            new = new[:m.start()] + m.group(1) + " ".join(want) + ";" + new[m.end():]
    return text[:where[0]] + new + text[where[1]:]


def do_acme_http(payload, said):
    names = payload.get("names")
    if not isinstance(names, list) or len(names) > 100 or \
            any(not isinstance(n, str) or not NAME_RE.match(n) for n in names):
        raise Refused("the names are full DNS names, 100 at most")
    try:
        with open(NGINX_CONF, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise Refused("%s cannot be read: %s" % (NGINX_CONF, e))
    new = acme_http_text(text, [n.lower() for n in names])
    if new == text:
        said.append("port 80 answers the CA for %s already" % (", ".join(names) or "these pages"))
        return True
    ok = apply([(NGINX_CONF, new, 0o644)], said)
    said.insert(0, "port 80 answers the CA's HTTP-01 for %s" % (", ".join(names) or "these pages"))
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

    add = payload.get("server_names_add") or []
    if not isinstance(add, list) or len(add) > 50 or any(not isinstance(n, str) or not NAME_RE.match(n) for n in add):
        raise Refused("the names to add to server_name are DNS names, 50 at most")
    added = []

    def lines(block):
        if add:
            m = re.search(r"(?m)^[ \t]*server_name\s+([^;\n]*);", block)
            have = m.group(1).split() if m else []
            for n in add:
                if n.lower() not in [h.lower() for h in have]:
                    have.append(n.lower())
                    added.append(n.lower())
            if added:
                block = set_directive(block, "server_name", " ".join(x for x in have if x != "_") or "_")
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
    if added:
        said.insert(0, "nginx's server_name: %s added" % ", ".join(added))
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
    words = "making DH parameters of %s bits" % choice[3:]
    progress(words, 2, DH_EXPECT_S.get(choice))
    import threading
    stop = threading.Event()

    def beat():
        while not stop.wait(10):
            try:
                progress(words, 2, DH_EXPECT_S.get(choice))
            except Exception:                           # noqa: BLE001 - only how far it is
                pass
    t = threading.Thread(target=beat, daemon=True)
    t.start()
    try:
        return openssl(["dhparam", choice[3:]], words)
    finally:
        stop.set()


def dh_had():
    """The choice the DH file in place was made for ("" when unknown or not there)."""
    try:
        with open(path("dh_choice"), encoding="ascii", errors="replace") as f:
            had = f.read(40).strip()
    except OSError:
        return ""
    return had if had in DH_CHOICES and os.path.isfile(path("dh")) else ""


def do_policy(payload, said):
    p = policy_checked(payload)
    writes = []
    dh = None
    if p["dh"] != "none":
        dh = path("dh")
        if dh_had() == p["dh"]:
            # Made once (otp's dh_file): the same choice again keeps the parameters there.
            said.append("DH parameters %s: the ones in %s kept" % (p["dh"], dh))
        else:
            began = time.time()
            writes.append((path("dh"), dh_pem(p["dh"]), 0o644))
            writes.append((path("dh_choice"), p["dh"] + "\n", 0o644))
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


def _first_cert(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            m = re.search(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", f.read(1 << 20))
    except OSError:
        return ""
    return m.group(0) if m else ""


def _same_cert(a, b):
    return re.sub(r"\s+", "", a or "") == re.sub(r"\s+", "", b or "")


def chain_checked(chain, what):
    chain = str(chain or "").strip()
    if len(chain) > 300000:
        raise Refused("the chain of %s is far longer than chains are" % what)
    if chain and not CERT_RE.match(chain):
        raise Refused("the chain of %s is not PEM certificates" % what)
    if chain:
        with tempfile.TemporaryDirectory(prefix="fake-igd-tls-") as t:
            cf = os.path.join(t, "c.pem")
            with open(cf, "w") as f:
                f.write(chain + "\n")
            openssl(["crl2pkcs7", "-nocrl", "-certfile", cf], "the chain of %s" % what)
    return (chain + "\n") if chain else ""


def do_chain(payload, said):
    """The chain beside the certificate in place replaced (otp's tls_chain, tls_chain_add, 1.0.269):
    the certificate and its key stay as they are."""
    progress("checking what was asked", 1)
    leaf = str(payload.get("cert") or "").strip()
    now = _first_cert(path("cert"))
    if not now or not _same_cert(leaf, now):
        raise Refused("the certificate in %s is not the one this chain is for - it changed meanwhile" % path("cert"))
    writes = [(path("cert"), now.strip() + "\n" + chain_checked(payload.get("chain"), "the certificate"), 0o644)]
    if payload.get("alt_chain") is not None:
        now2 = _first_cert(path("cert2"))
        if not now2:
            raise Refused("there is no second certificate in %s" % path("cert2"))
        writes.append((path("cert2"), now2.strip() + "\n" + chain_checked(payload.get("alt_chain"),
                                                                              "the second certificate"), 0o644))
    n = len(re.findall("BEGIN CERTIFICATE", writes[0][1])) - 1
    ok = apply(writes, said)
    said.insert(0, "the chain of the certificate: %d authorit%s beside it" % (n, "y" if n == 1 else "ies"))
    return ok


EXPORT_KINDS = ("pfx", "pemkey")


def do_export(payload, said, ident=""):
    """The certificate with its private key, locked with the password (otp's tls_export with a key,
    1.0.191): into web/export-tls.json for the API, which reads it once and takes it away."""
    import json
    kind, which = payload.get("kind"), payload.get("which") or "rsa"
    pw = payload.get("password")
    if kind not in EXPORT_KINDS:
        raise Refused("the kind is pfx or pemkey")
    if which not in ("rsa", "ec"):
        raise Refused("which is rsa or ec")
    if not isinstance(pw, str) or not 10 <= len(pw) <= 200 or "\n" in pw:
        raise Refused("the password is 10 to 200 characters on one line")
    cp, kp = (path("cert"), path("key")) if which == "rsa" else (path("cert2"), path("key2"))
    try:
        with open(cp, encoding="utf-8", errors="replace") as f:
            full = f.read(1 << 20)
        with open(kp, encoding="utf-8", errors="replace") as f:
            key = f.read(65536)
    except OSError as e:
        raise Refused("the certificate or its key cannot be read: %s" % e)
    certs = re.findall(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", full)
    if not certs or not KEY_RE.match(key.strip()):
        raise Refused("%s holds no certificate and key" % cp)
    with tempfile.TemporaryDirectory(prefix="fake-igd-export-") as t:
        os.chmod(t, 0o700)
        kf, cf, chf, out = (os.path.join(t, n) for n in ("k.pem", "c.pem", "ch.pem", "out"))
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.strip() + "\n")
        with open(cf, "w") as f:
            f.write(certs[0] + "\n")
        with open(chf, "w") as f:
            f.write("".join(c + "\n" for c in certs[1:]))
        if kind == "pfx":
            args = ["pkcs12", "-export", "-in", cf, "-inkey", kf, "-out", out, "-passout", "stdin",
                    "-name", "fake-igd"]
            if certs[1:]:
                args += ["-certfile", chf]
            if payload.get("legacy") is True:
                args += ["-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1"]
            openssl(args, "the PFX file", pw + "\n")
            with open(out, "rb") as f:
                data = f.read()
        else:
            enc = openssl(["pkcs8", "-topk8", "-v2", "aes-256-cbc", "-in", kf, "-passout", "stdin"],
                          "the key, locked", pw + "\n")
            data = ("".join(c + "\n" for c in certs) + enc).encode("ascii")
    _web_write("export-tls.json", json.dumps({"id": ident, "kind": kind, "which": which, "at": time.time(),
                                               "data": base64.b64encode(data).decode("ascii")}))
    said.append("%s of %s made for the pages, locked with the password" % (
        "a PFX file" if kind == "pfx" else "PEM with the key", "the ECDSA certificate" if which == "ec" else
        "the certificate"))
    return True


# ---- the system's trusted roots (otp's osroots, 1.0.265) ---------------------------------------
# LDAPS, SMTP, syslog over TLS, ntfy, ACME, fake-igd's own connections: every program that uses the
# system's trust. Only by the system's own way of adding to it, never by touching the
# distribution's bundle: a file in the folder of local additions, then its own tool. Both tools merge
# that folder with the distribution's list every time they run - also when an update of the
# ca-certificates package runs them. fake-igd's files are named fake-igd-<sha256 16>.pem (.crt):
# only those are written and removed; anything else in the folder is only shown. What is asked is
# always the whole set wanted (`sync`).
OSROOTS_MAX = 50
OSROOTS_PEM_MAX = 20480
OSROOTS_NAME_RE = re.compile(r"^fake-igd-[0-9a-f]{16}\.(pem|crt)\Z")
OSROOTS_BLOCK_RE = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*?)-----END CERTIFICATE-----")
OSROOTS_FLAVOURS = {
    "rhel": {"dir": "/etc/pki/ca-trust/source/anchors", "ext": ".pem", "tool": ["update-ca-trust", "extract"],
             "bundle": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "pkg": ["rpm", "-q", "ca-certificates"]},
    "debian": {"dir": "/usr/local/share/ca-certificates", "ext": ".crt", "tool": ["update-ca-certificates"],
               "bundle": "/etc/ssl/certs/ca-certificates.crt",
               "pkg": ["dpkg-query", "-W", "-f=ca-certificates-${Version}", "ca-certificates"]}}


def osroots_where():
    fl = os.environ.get("FAKE_IGD_OSROOTS_FLAVOUR", "")
    if fl not in OSROOTS_FLAVOURS:
        fl = ""
        if os.path.isdir("/etc/pki/ca-trust/source") or shutil.which("update-ca-trust"):
            fl = "rhel"
        elif os.path.isdir("/usr/local/share/ca-certificates") or shutil.which("update-ca-certificates"):
            fl = "debian"
    if not fl:
        return None
    w = dict(OSROOTS_FLAVOURS[fl], flavour=fl)
    w["dir"] = os.environ.get("FAKE_IGD_OSROOTS_DIR") or w["dir"]
    w["bundle"] = os.environ.get("FAKE_IGD_OSROOTS_BUNDLE") or w["bundle"]
    if os.environ.get("FAKE_IGD_OSROOTS_EXTRACT"):
        w["tool"] = os.environ["FAKE_IGD_OSROOTS_EXTRACT"].split()
    if "FAKE_IGD_OSROOTS_PKG" in os.environ:
        w["pkg"] = os.environ["FAKE_IGD_OSROOTS_PKG"].split()
    return w


def osroots_blocks(text):
    """Each certificate of a text as (pem, der) - nothing but certificates."""
    text = str(text or "")
    if re.search(r"PRIVATE KEY|BEGIN ENCRYPTED|BEGIN PKCS7|BEGIN TRUSTED CERTIFICATE", text):
        raise Refused("no private key and nothing but certificates (-----BEGIN CERTIFICATE-----)")
    out = []
    for body in OSROOTS_BLOCK_RE.findall(text):
        b64 = re.sub(r"\s+", "", body)
        try:
            der = base64.b64decode(b64, validate=True)
        except ValueError:
            raise Refused("a certificate that is not base64")
        if not der or len(der) > OSROOTS_PEM_MAX * 3 // 4:
            raise Refused("a certificate of %d bytes - one is a few kB at most" % len(der))
        enc = base64.b64encode(der).decode("ascii")
        pem = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % "\n".join(
            enc[i:i + 64] for i in range(0, len(enc), 64))
        out.append((pem, der))
    if not out:
        raise Refused("no certificate in it (-----BEGIN CERTIFICATE-----)")
    return out


def _osroots_time(s):
    import calendar
    try:
        return calendar.timegm(time.strptime(re.sub(r"\s+", " ", s.strip()), "%b %d %H:%M:%S %Y %Z"))
    except ValueError:
        return 0


def osroots_facts(pem, der=None):
    """What one certificate is, as openssl reads it - and what stands against it (refused) or is to
    be known (warn)."""
    if der is None:
        der = osroots_blocks(pem)[0][1]
    txt = openssl(["x509", "-noout", "-text", "-nameopt", "RFC2253"], "not a certificate openssl reads", pem)

    def one(rx):
        m = re.search(rx, txt, re.M)
        return m.group(1).strip() if m else ""
    f = {"fp": hashlib.sha256(der).hexdigest(), "subject": one(r"^\s*Subject: ?(.*)$")[:400],
         "issuer": one(r"^\s*Issuer: ?(.*)$")[:400],
         "not_before": _osroots_time(one(r"Not Before\s*: (.*)$")),
         "not_after": _osroots_time(one(r"Not After\s*: (.*)$")),
         "sig": one(r"Signature Algorithm: (\S+)")[:60]}
    cn = re.search(r"(?:^|,)CN=((?:\\.|[^,])*)", f["subject"])
    f["cn"] = (cn.group(1) if cn else f["subject"])[:200]
    alg = one(r"Public Key Algorithm: (\S+)")
    bits = one(r"Public-Key: \((\d+) bit\)")
    curve = one(r"NIST CURVE: (\S+)") or one(r"ASN1 OID: (\S+)")
    if alg == "rsaEncryption":
        f["key"] = "RSA %s" % bits
    elif alg == "id-ecPublicKey":
        f["key"] = "EC %s" % (curve or bits)
    elif alg:
        f["key"] = alg.replace("ED25519", "Ed25519").replace("ED448", "Ed448")[:40]
    else:
        f["key"] = "?"
    f["bits"] = int(bits) if bits.isdigit() else 0
    bc = re.search(r"X509v3 Basic Constraints:.*\n\s*(CA:(TRUE|FALSE))", txt)
    f["ca"] = bool(bc and bc.group(2) == "TRUE")
    ku = re.search(r"X509v3 Key Usage:.*\n\s*(.*)", txt)
    f["ku_sign"] = None if not ku else ("Certificate Sign" in ku.group(1))
    f["root"] = f["subject"] == f["issuer"]
    f["kind"] = "root" if f["root"] else "intermediate"
    refused, warn = [], []
    now = time.time()
    if not bc:
        refused.append("it says nothing of being an authority (no basicConstraints CA:TRUE) - only a certificate "
                       "authority goes here")
    elif not f["ca"]:
        refused.append("it is not a certificate authority (CA:FALSE) - a server's own certificate does not go here")
    if f["ku_sign"] is False:
        refused.append("its key usage does not let it sign certificates (no keyCertSign)")
    if f["not_after"] and f["not_after"] < now:
        warn.append("it ran out on %s - nothing it signed is trusted" % time.strftime("%Y-%m-%d", time.gmtime(f["not_after"])))
    if f["not_before"] and f["not_before"] > now + 300:
        warn.append("it is valid only from %s" % time.strftime("%Y-%m-%d", time.gmtime(f["not_before"])))
    if not f["root"] and re.match(r"(?i)(sha1|md5|md2)", f["sig"]):
        warn.append("it is signed with %s - the system's crypto policy (DEFAULT) refuses it, and every chain "
                    "through it" % f["sig"])
    if f["key"].startswith("RSA") and 0 < f["bits"] < 2048:
        warn.append("its key has %d bits - the system's crypto policy (DEFAULT) refuses fewer than 2048" % f["bits"])
    f["refused"], f["warn"] = refused, warn
    return f


def osroots_dir_ok(d, make=False):
    """The folder of local additions: a folder of root's, never a link."""
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        if not make:
            return False
        os.makedirs(d, 0o755, exist_ok=True)
        st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused("%s is not a folder (a link?) - nothing is written there" % d)
    group_ok = False
    if st.st_mode & 0o020 and not st.st_mode & 0o002:
        try:
            up = os.stat(os.path.dirname(os.path.abspath(d)))
            group_ok = st.st_gid == 0 or (up.st_uid == 0 and up.st_gid == st.st_gid and up.st_mode & 0o020
                                          and not up.st_mode & 0o002)
        except OSError:
            group_ok = False
    if (st.st_uid != 0 and not os.environ.get("FAKE_IGD_OSROOTS_DIR")) or st.st_mode & 0o002 or \
            (st.st_mode & 0o020 and not group_ok):
        raise Refused("%s is not root's alone (owner %d, mode %o) - nothing is written there"
                      % (d, st.st_uid, stat.S_IMODE(st.st_mode)))
    return True


def _osroots_read(p, most=1048576):
    """A plain file's bytes - None for a link (never followed), a folder, a pipe."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EISDIR, errno.ENXIO):
            return None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, most + 1)
    finally:
        os.close(fd)
    return data[:most]


def osroots_files(d):
    out = []
    try:
        top = sorted(os.listdir(d))
    except OSError:
        return out
    for n in top[:500]:
        p = os.path.join(d, n)
        if os.path.isdir(p) and not os.path.islink(p):
            try:
                out += [(n + "/" + m, os.path.join(p, m)) for m in sorted(os.listdir(p))[:200]]
            except OSError:
                pass
        else:
            out.append((n, p))
    return out


def osroots_cert_of_file(p):
    raw = _osroots_read(p)
    if raw is None:
        return None
    text = raw.decode("ascii", "replace")
    if "-----BEGIN CERTIFICATE-----" not in text:
        try:
            got = subprocess.run([OPENSSL, "x509", "-inform", "DER"], input=raw, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30)
            if got.returncode != 0:
                return []
            text = got.stdout.decode("ascii", "replace")
        except (OSError, subprocess.SubprocessError):
            return []
    out = []
    try:
        blocks = OSROOTS_BLOCK_RE.findall(text) and osroots_blocks(
            "\n".join(m.group(0) for m in OSROOTS_BLOCK_RE.finditer(text)))
    except Refused:
        return []
    for pem, der in (blocks or [])[:20]:
        try:
            f = osroots_facts(pem, der)
            out.append({k: f[k] for k in ("fp", "cn", "subject", "issuer", "not_before", "not_after", "key", "kind", "ca")})
        except Refused:
            continue
    return out


def osroots_bundle(w):
    out = {"path": w["bundle"], "count": 0, "bytes": 0, "at": 0}
    try:
        st = os.stat(w["bundle"])
        out.update(bytes=st.st_size, at=st.st_mtime)
        with open(w["bundle"], "rb") as f:
            out["count"] = f.read(64 * 1048576).count(b"-----BEGIN CERTIFICATE-----")
    except OSError:
        out["missing"] = True
    pkg = ""
    if w.get("pkg"):
        try:
            got = subprocess.run(w["pkg"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                 timeout=30)
            if got.returncode == 0 and got.stdout.strip():
                pkg = got.stdout.strip().splitlines()[0][:120]
        except (OSError, subprocess.SubprocessError, IndexError):
            pkg = ""
    out["package"] = pkg
    return out


def _osroots_in_bundle(w, ders):
    try:
        with open(w["bundle"], "rb") as f:
            flat = re.sub(rb"\s+", b"", f.read(64 * 1048576))
    except OSError:
        return {}
    return {hashlib.sha256(d).hexdigest(): base64.b64encode(d) in flat for d in ders}


def osroots_read(w):
    """fake-igd's own, the others', the system's list."""
    ours, others = [], []
    if w and os.path.isdir(w["dir"]):
        for rel, p in osroots_files(w["dir"]):
            if OSROOTS_NAME_RE.match(rel):
                raw = _osroots_read(p, 65536)
                if raw is None:
                    others.append({"file": rel, "certs": [], "link": os.path.islink(p)})
                    continue
                try:
                    (pem, der), = osroots_blocks(raw.decode("ascii", "replace"))
                    f = osroots_facts(pem, der)
                    f.pop("refused", None)
                    f.update(file=rel, der=der, pem=pem)
                    ours.append(f)
                except (Refused, ValueError):
                    ours.append({"file": rel, "broken": True})
            else:
                if os.path.islink(p):
                    try:
                        to = os.readlink(p)[:300]
                    except OSError:
                        to = "?"
                    others.append({"file": rel, "link": to, "certs": []})
                    continue
                read_others = sum(1 for o in others if o.get("certs"))
                others.append({"file": rel, "certs": (osroots_cert_of_file(p) or []) if read_others < 60 else []})
    inb = _osroots_in_bundle(w, [f["der"] for f in ours if f.get("der")]) if w else {}
    for f in ours:
        f.pop("der", None)
        if f.get("fp"):
            f["in_bundle"] = inb.get(f["fp"])
    return {"ours": ours, "others": others[:200], "system": osroots_bundle(w) if w else {},
            "flavour": (w or {}).get("flavour", ""), "dir": (w or {}).get("dir", ""),
            "tool": " ".join((w or {}).get("tool") or []),
            "tool_there": bool(w and shutil.which(w["tool"][0]))}


def _osroots_put(d, name, pem):
    fd, tmp = tempfile.mkstemp(prefix=".fake-igd-", dir=d)
    try:
        os.fchmod(fd, 0o644)
        try:
            os.fchown(fd, 0, 0)
        except OSError:
            pass
        with os.fdopen(fd, "w") as f:
            fd = None
            f.write(pem)
        os.replace(tmp, os.path.join(d, name))
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def osroots_sync(w, certs, force=False):
    if not w:
        raise Refused("this system has neither update-ca-trust (RHEL, AlmaLinux, Rocky) nor update-ca-certificates "
                      "(Debian, Ubuntu)")
    if not isinstance(certs, list) or len(certs) > OSROOTS_MAX:
        raise Refused("the certificates wanted: a list of %d at most" % OSROOTS_MAX)
    want, refused = {}, []
    for c in certs:
        if not isinstance(c, str) or len(c) > OSROOTS_PEM_MAX:
            raise Refused("each certificate as PEM text of %d bytes at most" % OSROOTS_PEM_MAX)
        blocks = osroots_blocks(c)
        if len(blocks) != 1:
            raise Refused("one certificate in each")
        pem, der = blocks[0]
        f = osroots_facts(pem, der)
        if f["refused"]:
            refused.append({"fp": f["fp"], "cn": f["cn"], "why": "; ".join(f["refused"])})
            continue
        want["fake-igd-%s%s" % (f["fp"][:16], w["ext"])] = pem
    osroots_dir_ok(w["dir"], make=bool(want))
    said, changed = [], False
    have = {rel: p for rel, p in osroots_files(w["dir"]) if OSROOTS_NAME_RE.match(rel)} \
        if os.path.isdir(w["dir"]) else {}
    for name, pem in sorted(want.items()):
        p = have.get(name)
        if p is not None:
            raw = _osroots_read(p, 65536)
            if raw is not None and raw.decode("ascii", "replace") == pem and not os.path.islink(p):
                continue
            os.unlink(p)
        _osroots_put(w["dir"], name, pem)
        said.append("added %s" % name)
        changed = True
        if shutil.which("restorecon") and os.path.isdir("/sys/fs/selinux") and \
                not os.environ.get("FAKE_IGD_OSROOTS_DIR"):
            subprocess.run(["restorecon", "-F", os.path.join(w["dir"], name)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    for name, p in sorted(have.items()):
        if name not in want:
            os.unlink(p)
            said.append("removed %s" % name)
            changed = True
    if not changed and not force and want:
        inb = _osroots_in_bundle(w, [base64.b64decode(re.sub(r"-----[A-Z ]+-----|\s+", "", pem))
                                     for pem in want.values()])
        if inb and not all(inb.values()):
            said.append("the system's list lacked %d of them" % sum(1 for v in inb.values() if not v))
            changed = True
    if changed or force:
        if not shutil.which(w["tool"][0]):
            raise Refused("%s is not on this machine - the files are in %s, the system's list is not made again "
                          "until it runs" % (w["tool"][0], w["dir"]))
        got = subprocess.run(w["tool"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                             timeout=300)
        if got.returncode != 0:
            raise Refused("%s ended with %d: %s" % (" ".join(w["tool"]), got.returncode,
                                                    ((got.stderr or got.stdout).strip() or "-")[-300:]))
        said.append("%s run" % " ".join(w["tool"]))
    return said, refused


def do_osroots(payload, said):
    w = osroots_where()
    do = payload.get("do")
    if do == "list":
        got = osroots_read(w)
        said.append("read: %d of fake-igd's, %d of others'" % (len(got["ours"]), len(got["others"])))
        return dict(got, refused=[])
    if do == "sync":
        s2, refused = osroots_sync(w, payload.get("certs"), payload.get("force") is True)
        said.extend(s2 or ["nothing to change"])
        return dict(osroots_read(w), refused=refused)
    raise Refused("list or sync")


def serve(payload, ask=None):
    said = []
    act = payload.get("action") if isinstance(payload, dict) else None
    if act not in ("put", "put_back", "policy", "acme_http", "osroots", "chain", "export"):
        return {"ok": False, "action": str(act)[:20], "said": ["no such action"]}
    if act == "osroots":
        try:
            got = do_osroots(payload, said)
        except Refused as e:
            w = osroots_where()
            try:
                facts = osroots_read(w)
            except Exception:                    # noqa: BLE001 - what is there, when it reads
                facts = {}
            return dict(facts, ok=False, action=act, said=said + [str(e)], osroots=True)
        return dict(got, ok=True, action=act, said=said, osroots=True)
    ident = str((ask or {}).get("id") or "")[:40] if isinstance(ask, dict) else ""
    if act == "export":
        try:
            ok = do_export(payload, said, ident)
        except Refused as e:
            return {"ok": False, "action": act, "said": said + [str(e)]}
        return {"ok": bool(ok), "action": act, "said": said}
    PROGRESS.update(step=0, id=ident, words=None, began=time.time())
    try:
        progress("checking what was asked", 1)
        if act == "put":
            ok = do_put(payload, said)
        elif act == "put_back":
            ok = do_put_back(said)
        elif act == "acme_http":
            ok = do_acme_http(payload, said)
        elif act == "chain":
            ok = do_chain(payload, said)
        else:
            ok = do_policy(payload, said)
    except Refused as e:
        return {"ok": False, "action": act, "said": said + [str(e)]}
    finally:
        progress_done()
    return {"ok": bool(ok), "action": act, "said": said}


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(serve(json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}), indent=1))
