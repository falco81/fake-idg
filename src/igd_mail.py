"""igd_mail.py - how fake-igd sends mail, and the outgoing mail (1.6.0).

otp's mail, for one server: through your mail server (SMTP: STARTTLS, SMTPS or none;
PLAIN, LOGIN or CRAM-MD5), or straight to the server of each recipient's domain by its
MX record, with no relay at all. Every step of a conversation is written down, so the
pages can show what the server said.

Anything that wants to send mail (the alerts, the report, another pane) does

    import igd_mail
    igd_mail.send(store, ["admin@example.cz"], "subject", "the text", html=None, kind="alert")

which puts the mail into the outgoing mail (the table `mailq` of the database) and,
in the API, tries it at once in a thread of its own. What the receiving side does not
take at once - greylisting's "try again later", a server away, a full mailbox - waits
and is tried again by the API's background (tick() once a minute): after 1, 2, 5, 10,
15 and 30 minutes, then every hour, for mail_retry_hours. What it refuses for good is
failed. What a mail held is forgotten once it went or was given up.

The settings are the module api_mail's (Settings → Mail), kept in the database (meta
"settings"); read here by themselves, so that this works from any process.
Only the standard library.
"""
import base64
import collections
import email.message
import email.policy
import email.utils
import hashlib
import ipaddress
import json
import os
import re
import secrets
import smtplib
import socket
import ssl
import struct
import tempfile
import threading
import time

DEFAULTS = {
    "mail_mode": "off",
    "smtp_host": "",
    "smtp_port": 0,
    "smtp_security": "starttls",
    "smtp_auth": "auto",
    "smtp_user": "",
    "smtp_password": "",
    "smtp_verify": True,
    "smtp_timeout_s": 20,
    "mail_from": "",
    "mail_from_name": "",
    "mail_reply_to": "",
    "mail_helo": "",
    "mail_direct_port": 25,
    "mail_direct_tls": "if-offered",
    "mail_dns": "",
    "mail_retry_hours": 24,
    "mail_keep_days": 14,
}
CA_META = "mail:ca"
STATES = ("sending", "waiting", "sent", "failed", "expired")
KIND_WORDS = {"alert": "an alert", "report": "a report", "test": "a test", "other": "a mail"}
DELAYS = [60, 120, 300, 600, 900, 1800]            # then every hour (as otp's)
DIRECT_DEADLINE_S = 90
MOST_A_TICK = 25
ADDR_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")

SCHEMA = """
CREATE TABLE IF NOT EXISTS mailq (
    qid TEXT PRIMARY KEY,
    created REAL NOT NULL,
    kind TEXT NOT NULL DEFAULT 'other',
    by_ TEXT NOT NULL DEFAULT '',
    rcpt TEXT NOT NULL,
    done_to TEXT NOT NULL DEFAULT '[]',
    subject TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    tries INTEGER NOT NULL DEFAULT 0,
    last_try REAL,
    next_at REAL NOT NULL DEFAULT 0,
    expires REAL NOT NULL,
    sent_at REAL,
    said TEXT NOT NULL DEFAULT '',
    history TEXT NOT NULL DEFAULT '[]',
    steps TEXT NOT NULL DEFAULT '[]',
    body BLOB
);
CREATE INDEX IF NOT EXISTS mailq_state ON mailq(state);
CREATE INDEX IF NOT EXISTS mailq_created ON mailq(created);
"""
_READY = set()
TICK_LOCK = threading.Lock()


class MailError(RuntimeError):
    """What stopped a mail, with the steps up to there. permanent: refused for good (5xx);
    left: the recipients still to do when some took it."""

    def __init__(self, words, steps=None, permanent=False):
        RuntimeError.__init__(self, words)
        self.steps = steps if steps is not None else []
        self.permanent = permanent
        self.left = None
        self.queued = ""
        self.qid = ""


# ---- the settings ----------------------------------------------------------------------
def settings(store):
    """The mail settings as saved on the pages (Settings → Mail), the defaults beside them."""
    try:
        got = json.loads(store.get_meta("settings") or "{}")
    except ValueError:
        got = {}
    out = dict(DEFAULTS)
    if isinstance(got, dict):
        out.update({k: got[k] for k in DEFAULTS if k in got})
    if out.get("smtp_password"):                        # sealed in the database (igd_seal)
        import igd_seal as SEAL
        out["smtp_password"] = SEAL.unseal_or(store, out["smtp_password"])
    return out


def address_problem(addr):
    return "" if ADDR_RE.match(str(addr or "")) else "%s is not a mail address" % (addr or "(nothing)")


def addresses(text):
    """'a@x.cz, b@y.cz' (or a list) as a list - every one checked."""
    if isinstance(text, (list, tuple)):
        parts = [str(x) for x in text]
    else:
        parts = re.split(r"[,;\s]+", str(text or ""))
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        bad = address_problem(p)
        if bad:
            raise ValueError(bad)
        if p.lower() not in [x.lower() for x in out]:
            out.append(p)
    return out


def sender(c):
    addr = str(c.get("mail_from") or "").strip()
    if not addr:
        host = socket.getfqdn() or socket.gethostname() or "localhost"
        addr = "fake-igd@%s" % (host if "." in host else host + ".localdomain")
    name = str(c.get("mail_from_name") or "").strip() or "fake-igd"
    return email.utils.formataddr((name, addr)), addr


# ---- the authorities trusted for the mail server -------------------------------------------
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def split_pem(text):
    return [m.group(0).strip() for m in PEM_RE.finditer(str(text or ""))]


def describe(pem):
    """{subject, issuer, from, until, fingerprint, self_signed} of one PEM certificate, or None."""
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, TypeError):
        return None
    out = {"fingerprint": hashlib.sha256(der).hexdigest(), "subject": "", "issuer": "", "from": "", "until": ""}
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem + "\n")
        d = ssl._ssl._test_decode_cert(path)           # noqa: SLF001 - the stdlib's own reader of X.509
        name = lambda rdns: ", ".join("%s=%s" % kv for rdn in rdns for kv in rdn)   # noqa: E731
        out.update({"subject": name(d.get("subject", ())), "issuer": name(d.get("issuer", ())),
                    "from": d.get("notBefore", ""), "until": d.get("notAfter", "")})
        for k in ("from", "until"):
            try:
                out[k] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ssl.cert_time_to_seconds(out[k])))
            except (ValueError, TypeError):
                pass
    except Exception:                                   # noqa: BLE001 - the fingerprint is enough to list it
        pass
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    out["self_signed"] = bool(out["subject"]) and out["subject"] == out["issuer"]
    return out


def ca_pem(store):
    return store.get_meta(CA_META) or ""


def ca_list(store):
    return [d for d in (describe(p) for p in split_pem(ca_pem(store))) if d]


def ca_set(store, pem, mode="add", fingerprint=""):
    """The authorities trusted for the mail server, each added and taken out by itself (as otp's)."""
    have = split_pem(ca_pem(store))
    if mode == "add":
        new = split_pem(pem)
        if not new or not all(describe(p) for p in new):
            raise ValueError("that is not a certificate this can read: a PEM certificate starts "
                             "-----BEGIN CERTIFICATE-----")
        seen = {describe(p)["fingerprint"] for p in have}
        for p in new:
            fp = describe(p)["fingerprint"]
            if fp not in seen:
                have.append(p)
                seen.add(fp)
        try:
            ssl.create_default_context().load_verify_locations(cadata="\n".join(have))
        except (ssl.SSLError, ValueError) as e:
            raise ValueError("that certificate does not load: %s" % e)
    elif mode == "drop":
        keep = [p for p in have if describe(p)["fingerprint"] != str(fingerprint)]
        if len(keep) == len(have):
            raise ValueError("that certificate is not among the ones kept")
        have = keep
    elif mode == "clear":
        have = []
    else:
        raise ValueError("add, drop or clear?")
    store.set_meta(CA_META, "\n".join(have))
    return ca_list(store)


def tls_context(store, verify=True):
    ctx = ssl.create_default_context()
    pem = ca_pem(store)
    if pem.strip():
        try:
            ctx.load_verify_locations(cadata=pem)
        except (ssl.SSLError, ValueError) as e:
            raise MailError("the certificate authorities kept for mail cannot be read: %s" % e)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---- DNS: where a domain takes its mail (as otp's, no dnspython needed) ---------------------
DNS_RCODES = {1: "could not read the question", 2: "failed (SERVFAIL)", 4: "does not do that",
              5: "refused to answer"}


def own_dns(c):
    good = []
    for w in re.split(r"[\s,;]+", str(c.get("mail_dns") or "")):
        try:
            good.append(str(ipaddress.ip_address(w)))
        except ValueError:
            pass
    return good


def dns_servers(c):
    if own_dns(c):
        return own_dns(c)
    out = []
    try:
        with open(os.environ.get("FAKE_IGD_RESOLV", "/etc/resolv.conf")) as f:
            for line in f:
                bits = line.split()
                if len(bits) >= 2 and bits[0] == "nameserver":
                    out.append(bits[1])
    except OSError:
        pass
    return out or ["127.0.0.1"]


def _dns_name(data, at):
    labels, jumped, end = [], False, at
    for _ in range(64):
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at = ((n & 0x3F) << 8) | data[at + 1]
            jumped = True
            continue
        labels.append(data[at + 1:at + 1 + n].decode("ascii", "replace"))
        at += 1 + n
    return ".".join(labels), (end if jumped else at)


def _dns_ask(server, name, qtype, timeout):
    """One question to one DNS server: the raw answer (TCP when it came cut short)."""
    ident = secrets.randbits(16)
    q = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 1)
    for label in name.split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode()
        q += bytes([len(raw)]) + raw
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    q += b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    deadline = time.time() + timeout
    question = q[12:-11]
    try:
        s.connect((server, 53))
        s.send(q)
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout("no answer from %s" % server)
            s.settimeout(left)
            data = s.recv(65535)
            if len(data) >= 12 + len(question) and struct.unpack(">H", data[:2])[0] == ident \
                    and data[12:12 + len(question)].lower() == question.lower():
                break
    finally:
        s.close()
    if struct.unpack(">H", data[2:4])[0] & 0x0200:
        t = socket.create_connection((server, 53), timeout=timeout)
        try:
            t.sendall(struct.pack(">H", len(q)) + q)
            want, got = None, b""
            while want is None or len(got) < want + 2:
                chunk = t.recv(65535)
                if not chunk:
                    break
                got += chunk
                if want is None and len(got) >= 2:
                    want = struct.unpack(">H", got[:2])[0]
            data = got[2:]
        finally:
            t.close()
    return data


def _dns_records(data):
    flags, qd, an = struct.unpack(">HHH", data[2:8])
    at = 12
    for _ in range(qd):
        _, at = _dns_name(data, at)
        at += 4
    out = []
    for _ in range(an):
        rname, at = _dns_name(data, at)
        rtype, _cls, _ttl, size = struct.unpack(">HHIH", data[at:at + 10])
        at += 10
        out.append((rtype, rname, at, size))
        at += size
    return flags & 0x0F, out


def dns_mx(c, domain, timeout=5.0):
    """([(preference, host)], words): the mail servers of a domain, best first. No MX record
    is the domain itself - only when a DNS server said so, never because one did not answer."""
    domain = str(domain).strip().strip(".").lower()
    trouble = []
    for server in dns_servers(c):
        name = domain
        for _hop in range(6):
            try:
                data = _dns_ask(server, name, 15, timeout)
                rcode, recs = _dns_records(data)
            except (OSError, struct.error, IndexError, ValueError) as e:
                trouble.append("%s: %s" % (server, e))
                break
            if rcode == 3:
                raise MailError("the domain %s does not exist (DNS %s)" % (name, server), permanent=True)
            if rcode:
                trouble.append("%s %s" % (server, DNS_RCODES.get(rcode, "answered %d" % rcode)))
                break
            mx, cname, nullmx = [], None, False
            try:
                for rtype, _rname, at, _size in recs:
                    if rtype == 15:
                        pref = struct.unpack(">H", data[at:at + 2])[0]
                        host, _ = _dns_name(data, at + 2)
                        if host and host != ".":
                            mx.append((pref, host.rstrip(".").lower()))
                        else:
                            nullmx = True
                    elif rtype == 5:
                        cname, _ = _dns_name(data, at)
            except (struct.error, IndexError, ValueError) as e:
                trouble.append("%s: an answer that does not read: %s" % (server, e))
                break
            if mx:
                return sorted(mx), "MX records from DNS %s" % server
            if nullmx:
                return [], "a null MX (DNS %s): the domain takes no mail" % server
            if cname and cname.lower() != name:
                name = cname.rstrip(".").lower()
                continue
            return [(0, name)], "no MX record (DNS %s): the domain itself" % server
    raise MailError("no DNS server could say where mail for %s goes%s" % (
        domain, (": " + "; ".join(trouble)) if trouble else ""))


# ---- one conversation with one server, every step written down -----------------------------
def smtp_talk(store, c, host, port, security, auth, msg, to, steps, verify=True, timeout=None, direct=False):
    timeout = float(timeout or c.get("smtp_timeout_s") or 20)
    helo = str(c.get("mail_helo") or socket.getfqdn() or "localhost")
    ctx = tls_context(store, verify)
    if direct and security == "starttls-if":
        # TLS where offered, going straight to somebody's MX: their certificate is not
        # checked, as no mail server checks another's (otp 1.0.59).
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    began = time.time()

    def step(what, ok=True, said=""):
        steps.append({"what": what, "ok": bool(ok), "said": str(said or "")[:500]})

    def words(said):
        return said.decode("utf-8", "replace").split("\n")[0] if isinstance(said, bytes) else str(said)

    try:
        if security == "tls":
            conn = smtplib.SMTP_SSL(local_hostname=helo, timeout=timeout, context=ctx)
            conn._host = host
            code, said = conn.connect(host, port)
            if code != 220:
                conn.close()
                raise smtplib.SMTPConnectError(code, said)
            step("reached %s:%d over TLS" % (host, port), True, "%d ms" % int((time.time() - began) * 1000))
        else:
            conn = smtplib.SMTP(local_hostname=helo, timeout=timeout)
            conn._host = host
            code, said = conn.connect(host, port)
            if code != 220:
                conn.close()
                raise smtplib.SMTPConnectError(code, said)
            step("reached %s:%d" % (host, port), True, "%d ms" % int((time.time() - began) * 1000))
    except ssl.SSLCertVerificationError as e:
        step("reach the server %s:%d over TLS" % (host, port), False,
             "its certificate is not trusted: %s" % e.verify_message)
        raise MailError("the certificate of %s is not trusted - add the authority that signed it, or switch "
                        "the check off" % host, steps)
    except (OSError, smtplib.SMTPException) as e:
        step("reach the server %s:%d" % (host, port), False, e)
        raise MailError("%s:%d could not be reached: %s" % (host, port, e), steps)
    try:
        code, said = conn.ehlo()
        step("greeted it as %s" % helo, 200 <= code < 300, words(said))
        if security in ("starttls", "starttls-if"):
            if conn.has_extn("starttls"):
                try:
                    conn.starttls(context=ctx)
                except ssl.SSLCertVerificationError as e:
                    step("started TLS", False, "its certificate is not trusted: %s" % e.verify_message)
                    raise MailError("the certificate of %s is not trusted - add the authority that signed it, "
                                    "or switch the check off" % host, steps)
                conn.ehlo()
                cert = conn.sock.getpeercert() if hasattr(conn.sock, "getpeercert") else None
                who = ""
                if cert:
                    who = ", ".join("%s=%s" % kv for part in cert.get("subject", ()) for kv in part
                                    if kv[0] == "commonName")
                step("started TLS", True, (conn.sock.version() if hasattr(conn.sock, "version") else "")
                     + ((" · " + who) if who else ""))
            elif security == "starttls":
                step("start TLS", False, "the server does not offer STARTTLS")
                raise MailError("%s does not offer STARTTLS - choose TLS from the start, or none" % host, steps)
            else:
                step("stayed in plain text", True, "the server does not offer STARTTLS")
                if auth and auth != "none" and not direct:
                    step("sign in", False, "not without TLS: the password would go in plain text")
                    raise MailError("%s offered no STARTTLS, and the password is not sent in plain text - "
                                    "choose STARTTLS or TLS from the start, or Security none if a plain "
                                    "connection is meant" % host, steps)
        if auth and auth != "none" and not direct:
            user = str(c.get("smtp_user") or "")
            pw = str(c.get("smtp_password") or "")
            offered = (conn.esmtp_features.get("auth") or "").upper().split()
            try:
                if auth == "auto":
                    conn.login(user, pw)
                elif auth == "xoauth2":                         # otp's: an OAuth access token as the password
                    conn.auth("XOAUTH2", lambda challenge=None: "user=%s\x01auth=Bearer %s\x01\x01" % (user, pw),
                              initial_response_ok=True)
                else:
                    conn.user, conn.password = user, pw
                    mech = {"plain": "PLAIN", "login": "LOGIN", "cram-md5": "CRAM-MD5"}[auth]
                    fn = {"PLAIN": conn.auth_plain, "LOGIN": conn.auth_login, "CRAM-MD5": conn.auth_cram_md5}[mech]
                    conn.auth(mech, fn, initial_response_ok=(mech != "CRAM-MD5"))
                step("signed in as %s (%s)" % (user, auth.upper()), True,
                     "it offers: %s" % (" ".join(offered) or "nothing"))
            except smtplib.SMTPAuthenticationError as e:
                step("sign in as %s (%s)" % (user, auth.upper()), False,
                     "%s %s" % (e.smtp_code, words(e.smtp_error or b"")))
                raise MailError("the mail server did not take the account or the password", steps)
            except (smtplib.SMTPException, KeyError) as e:
                step("sign in as %s (%s)" % (user, auth.upper()), False,
                     "%s · it offers: %s" % (e, " ".join(offered) or "nothing"))
                raise MailError("signing in failed: %s" % e, steps)
        if msg is not None:
            # the envelope's sender: the mail's own, or - a mail without one (kept from before) - the one
            # set now; never smtplib's "None"
            env_from = email.utils.parseaddr(str(msg["Sender"] or msg["From"] or ""))[1] or sender(c)[1]
            refused = conn.send_message(msg, from_addr=env_from, to_addrs=list(to))
            if refused:
                step("handed the message over", False, "; ".join("%s: %s" % kv for kv in refused.items()))
                err = MailError("the server refused %s" % ", ".join(refused), steps,
                                permanent=all(int((v or (0,))[0] or 0) >= 500 for v in refused.values()))
                err.left = list(refused)
                raise err
            step("handed the message over", True, "for %s" % ", ".join(to))
    except smtplib.SMTPRecipientsRefused as e:
        step("handed the message over", False, "; ".join(
            "%s: %s %s" % (k, v[0], words(v[1])) for k, v in e.recipients.items()))
        raise MailError("the server would not take mail for %s: %s" % (", ".join(e.recipients), "; ".join(
            "%s %s" % (v[0], words(v[1])) for v in e.recipients.values())[:300]), steps,
                        permanent=all(int((v or (0,))[0] or 0) >= 500 for v in e.recipients.values()))
    except smtplib.SMTPSenderRefused as e:
        step("handed the message over", False, "%s %s" % (e.smtp_code, words(e.smtp_error or b"")))
        raise MailError("the server would not take mail from %s: %s %s" % (e.sender, e.smtp_code,
                                                                       words(e.smtp_error or b"")), steps,
                        permanent=int(e.smtp_code or 0) >= 500)
    except (smtplib.SMTPException, OSError) as e:
        step("talking to it", False, e)
        raise MailError("the conversation with %s broke off: %s" % (host, e), steps,
                        permanent=int(getattr(e, "smtp_code", 0) or 0) >= 500)
    finally:
        try:
            conn.quit()
        except Exception:                               # noqa: BLE001
            pass
        try:
            conn.close()
        except Exception:                               # noqa: BLE001
            pass
    return steps


def deliver_now(store, msg, to, c=None):
    """`msg` to `to` the way the settings say, now. The steps; MailError with them where it failed."""
    c = c or settings(store)
    mode = c.get("mail_mode") or "off"
    steps = []
    if mode == "off":
        raise MailError("sending mail is switched off - Settings → Mail", steps)
    if mode == "smtp":
        host = str(c.get("smtp_host") or "").strip()
        if not host:
            raise MailError("no mail server is set - Settings → Mail", steps)
        security = c.get("smtp_security") or "starttls"
        port = int(c.get("smtp_port") or 0) or {"tls": 465, "none": 25}.get(security, 587)
        return smtp_talk(store, c, host, port, security, c.get("smtp_auth") or "auto", msg, to, steps,
                         verify=bool(c.get("smtp_verify", True)))
    by_domain = collections.OrderedDict()
    for one in to:
        by_domain.setdefault(one.rsplit("@", 1)[-1].lower(), []).append(one)
    port = int(c.get("mail_direct_port") or 25)
    failed = []
    for domain, who in by_domain.items():
        try:
            try:
                mxs, how = dns_mx(c, domain)
                if not mxs:
                    raise MailError("%s takes no mail (its MX record is a null MX)" % domain, permanent=True)
            except MailError as e:
                steps.append({"what": "look up the mail servers of %s" % domain, "ok": False, "said": str(e)})
                raise MailError(str(e), steps, permanent=e.permanent)
            steps.append({"what": "looked up the mail servers of %s" % domain, "ok": True,
                          "said": ", ".join("%s (%d)" % (h, p) for p, h in mxs) + " · " + how})
            last = None
            deadline = time.time() + DIRECT_DEADLINE_S
            for _pref, host in mxs[:4]:
                left = deadline - time.time()
                if left < 3:
                    last = last or MailError("no time left to try %s" % host, steps)
                    break
                try:
                    smtp_talk(store, c, host, port,
                              "starttls" if c.get("mail_direct_tls") == "required" else "starttls-if",
                              "none", msg, who, steps, direct=True,
                              timeout=min(float(c.get("smtp_timeout_s") or 20), left / 2))
                    last = None
                    break
                except MailError as e:
                    last = e
                    if e.left is not None and len(e.left) < len(who):
                        break
            if last:
                err = MailError("no mail server of %s took it: %s" % (domain, last), steps,
                                permanent=getattr(last, "permanent", False))
                err.left = list(last.left) if last.left is not None else list(who)
                raise err
        except MailError as e:
            failed.append((e.left if e.left is not None else list(who), e))
    if failed:
        err = MailError("; ".join(str(e) for _l, e in failed), steps, permanent=all(e.permanent for _l, e in failed))
        err.left = [a for one, _e in failed for a in one]
        raise err
    return steps


def message(store, to, subject, text, html=None, c=None):
    c = c or settings(store)
    msg = email.message.EmailMessage(policy=email.policy.SMTP)
    shown, addr = sender(c)
    msg["From"] = shown
    msg["To"] = ", ".join(to)
    msg["Subject"] = str(subject or "")[:300]
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=addr.rsplit("@", 1)[-1])
    msg["Auto-Submitted"] = "auto-generated"
    if c.get("mail_reply_to"):
        msg["Reply-To"] = str(c["mail_reply_to"])
    msg.set_content(str(text or ""))
    if html:
        msg.add_alternative(str(html), subtype="html")
    return msg


# ---- the outgoing mail -----------------------------------------------------------------------
def ready(store):
    key = id(store)
    if key not in _READY:
        with store.lock:
            store.db.executescript(SCHEMA)
        _READY.add(key)


def _row(r):
    if not r:
        return None
    r = dict(r)
    for k in ("rcpt", "done_to", "history", "steps"):
        try:
            r[k] = json.loads(r.get(k) or "[]")
        except ValueError:
            r[k] = []
    r["to"] = r.pop("rcpt")
    r["by"] = r.pop("by_", "")
    r["has_body"] = r.get("body") is not None
    r.pop("body", None)
    r["kind_words"] = KIND_WORDS.get(r.get("kind"), "a mail")
    return r


def send(store, to, subject, text, html=None, kind="other", by="", now=True):
    """The mail into the outgoing mail - and, `now`, tried at once in a thread of its own.
    Returns its id. ValueError when an address is not one or mail is switched off."""
    ready(store)
    c = settings(store)
    if (c.get("mail_mode") or "off") == "off":
        raise ValueError("sending mail is switched off - Settings → Mail")
    to = addresses(to)
    if not to:
        raise ValueError("no address to send it to")
    msg = message(store, to, subject, text, html, c)
    data = msg.as_bytes()
    qid = "%013d-%s" % (int(time.time() * 1000), secrets.token_hex(4))
    t = time.time()
    store.run("INSERT INTO mailq (qid, created, kind, by_, rcpt, subject, size, state, tries, next_at, expires, body) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, 'waiting', 0, ?, ?, ?)",
              (qid, t, str(kind or "other")[:20], str(by or "")[:80], json.dumps(to), str(subject or "")[:300],
               len(data), t, t + 3600 * int(c.get("mail_retry_hours") or 24), data))
    if now:
        threading.Thread(target=_quiet_attempt, args=(store, qid), name="mail-now", daemon=True).start()
    return qid


def send_and_wait(store, to, subject, text, html=None, kind="other", by=""):
    """As send(), but the first try made here and its outcome given back:
    {qid, sent, state, said, steps, next_at}."""
    qid = send(store, to, subject, text, html, kind, by, now=False)
    try:
        steps = attempt(store, qid, raise_err=True)
        r = one(store, qid) or {}
        return {"qid": qid, "sent": True, "state": "sent", "said": r.get("said") or "sent", "steps": steps or []}
    except MailError as e:
        return {"qid": qid, "sent": False, "state": e.queued, "said": str(e), "steps": e.steps,
                "queued": e.queued}


def _quiet_attempt(store, qid):
    try:
        attempt(store, qid)
    except Exception:                                   # noqa: BLE001 - kept in the list with what it said
        pass


def delay(tries):
    return DELAYS[tries - 1] if 0 < tries <= len(DELAYS) else 3600


def attempt(store, qid, raise_err=False):
    """One try of one mail that waits. The steps when it went; None (or MailError) when not."""
    ready(store)
    t = time.time()
    if not store.run("UPDATE mailq SET state = 'sending', last_try = ? WHERE qid = ? AND state = 'waiting'",
                     (t, qid)).rowcount:
        return None                                     # taken meanwhile, or not waiting
    r = store.one("SELECT * FROM mailq WHERE qid = ?", (qid,))
    if not r:
        return None
    to = json.loads(r["rcpt"] or "[]")
    if r["body"] is None:
        store.run("UPDATE mailq SET state = 'expired', said = ? WHERE qid = ?",
                  ("what the mail held is gone - it cannot be sent", qid))
        return None
    msg = email.message_from_bytes(bytes(r["body"]), policy=email.policy.SMTP)
    err, steps = None, []
    try:
        steps = deliver_now(store, msg, to)
    except MailError as e:
        err, steps = e, e.steps
    except Exception as e:                              # noqa: BLE001
        err = MailError(str(e) or e.__class__.__name__, [])
    done_to = json.loads(r["done_to"] or "[]")
    if err is not None and err.left and len(err.left) < len(to):
        done_to = sorted(set(done_to) | (set(to) - set(err.left)))
        to = list(err.left)                             # the others took it: not sent to them again
    tries = int(r["tries"] or 0) + 1
    history = json.loads(r["history"] or "[]")[-19:]
    said = (str(err) if err else ([s for s in steps if s.get("ok")] or [{}])[-1].get("said") or "sent")[:400]
    history.append({"at": t, "ok": err is None, "said": said})
    who = ", ".join(to)
    what = KIND_WORDS.get(r["kind"], "a mail")
    common = (json.dumps(to), json.dumps(done_to), tries, t, json.dumps(steps[-14:]), json.dumps(history))
    if err is None:
        store.run("UPDATE mailq SET state = 'sent', rcpt = ?, done_to = ?, tries = ?, last_try = ?, steps = ?, "
                  "history = ?, sent_at = ?, said = ?, next_at = 0, body = NULL WHERE qid = ?",
                  common + (t, said, qid))
        if tries > 1:
            store.add_event("mail", "the mail to %s (%s) went on try %d" % (who, what, tries))
        return steps
    if err.permanent:
        state, nxt = "failed", 0
        store.add_event("mail", "the mail to %s (%s) was refused for good: %s" % (who, what, str(err)[:300]), "warn")
    elif t >= float(r["expires"] or 0):
        state, nxt = "expired", 0
        store.add_event("mail", "the mail to %s (%s) was given up after %d tries: %s" % (
            who, what, tries, str(err)[:300]), "warn")
    else:
        state, nxt = "waiting", min(t + delay(tries), float(r["expires"] or t))
        if tries == 1:
            store.add_event("mail", "the mail to %s (%s) did not go yet - tried again from the outgoing mail: %s"
                            % (who, what, str(err)[:300]), "warn")
    store.run("UPDATE mailq SET state = ?, rcpt = ?, done_to = ?, tries = ?, last_try = ?, steps = ?, history = ?, "
              "said = ?, next_at = ?" + (", body = NULL" if state == "expired" else "") + " WHERE qid = ?",
              (state,) + common + (str(err)[:400], nxt, qid))
    err.queued, err.qid = state, qid
    if raise_err:
        raise err
    return None


def tick(store):
    """Once a minute in the API: what is due tried again, the old ones forgotten."""
    ready(store)
    if not TICK_LOCK.acquire(False):
        return
    try:
        c = settings(store)
        t = time.time()
        keep_s = 86400 * int(c.get("mail_keep_days") or 14)
        store.run("DELETE FROM mailq WHERE state IN ('sent', 'failed', 'expired') AND "
                  "COALESCE(sent_at, last_try, created) < ?", (t - keep_s,))
        store.run("UPDATE mailq SET body = NULL WHERE state = 'failed' AND expires < ? AND body IS NOT NULL", (t,))
        # Left half way (the API stopped while it talked): waiting again.
        store.run("UPDATE mailq SET state = 'waiting', next_at = ? WHERE state = 'sending' AND last_try < ?",
                  (t, t - (4 * int(c.get("smtp_timeout_s") or 20) + 90)))
        if (c.get("mail_mode") or "off") == "off":
            return                                      # kept as it is until mail is switched on again
        for r in store.rows("SELECT qid, kind, rcpt, tries, said FROM mailq WHERE state = 'waiting' AND expires + 120 < ?",
                            (t,)):
            if store.run("UPDATE mailq SET state = 'expired', next_at = 0, body = NULL, said = ? WHERE qid = ? "
                         "AND state = 'waiting'", (r["said"] or "not sent in time", r["qid"])).rowcount:
                store.add_event("mail", "the mail to %s (%s) was given up after %d tries: %s" % (
                    ", ".join(json.loads(r["rcpt"] or "[]")), KIND_WORDS.get(r["kind"], "a mail"), r["tries"],
                    (r["said"] or "")[:300]), "warn")
        for r in store.rows("SELECT qid FROM mailq WHERE state = 'waiting' AND next_at <= ? ORDER BY next_at LIMIT ?",
                            (t, MOST_A_TICK)):
            try:
                attempt(store, r["qid"])
            except Exception:                           # noqa: BLE001 - the next one all the same
                pass
    finally:
        TICK_LOCK.release()


def counts(store):
    ready(store)
    got = {k: 0 for k in STATES}
    for r in store.rows("SELECT state, COUNT(*) AS n FROM mailq GROUP BY state"):
        got[r["state"]] = r["n"]
    return got


def listing(store, q="", state="", limit=50, offset=0):
    """{rows, total} - the mails as the pages list them (never what they held)."""
    ready(store)
    where, args = [], []
    if state == "open":
        where.append("state IN ('waiting', 'sending', 'failed')")
    elif state in STATES:
        where.append("state = ?")
        args.append(state)
    for word in re.split(r"\s+", str(q or "").strip()):
        if not word:
            continue
        m = re.match(r"^(to|state|kind):(.+)\Z", word, re.I)
        if m:
            k, v = m.group(1).lower(), m.group(2).replace("*", "%")
            col = {"to": "rcpt", "state": "state", "kind": "kind"}[k]
            where.append("%s LIKE ?" % col)
            args.append(("%" + v + "%") if k == "to" else v)
        else:
            where.append("(rcpt LIKE ? OR subject LIKE ? OR said LIKE ? OR kind LIKE ? OR by_ LIKE ?)")
            args += ["%" + word + "%"] * 5
    sql = (" WHERE " + " AND ".join(where)) if where else ""
    total = store.one("SELECT COUNT(*) AS n FROM mailq" + sql, args)["n"]
    rows = store.rows("SELECT qid, created, kind, by_, rcpt, done_to, subject, size, state, tries, last_try, next_at, "
                      "expires, sent_at, said, '[]' AS history, '[]' AS steps, (body IS NOT NULL) AS body "
                      "FROM mailq" + sql + " ORDER BY created DESC LIMIT ? OFFSET ?",
                      args + [int(limit), int(offset)])
    out = []
    for r in rows:
        has = bool(r.get("body"))
        r["body"] = None
        x = _row(r)
        x["has_body"] = has
        x.pop("history", None)
        x.pop("steps", None)
        out.append(x)
    return {"rows": out, "total": total}


def one(store, qid):
    ready(store)
    return _row(store.one("SELECT * FROM mailq WHERE qid = ?", (str(qid),)))


def retry(store, qids, by=""):
    """Tried again now - a mail past its time is given the time of a new one again."""
    ready(store)
    c = settings(store)
    done = []
    for qid in qids:
        r = store.one("SELECT state, expires, body IS NOT NULL AS has FROM mailq WHERE qid = ?", (str(qid),))
        if not r or r["state"] not in ("waiting", "failed") or not r["has"]:
            continue
        exp = r["expires"]
        if time.time() > float(exp or 0):
            exp = time.time() + 3600 * int(c.get("mail_retry_hours") or 24)
        if store.run("UPDATE mailq SET state = 'waiting', next_at = 0, expires = ? WHERE qid = ? AND state = ?",
                     (exp, str(qid), r["state"])).rowcount:
            done.append(str(qid))
    if done:
        store.add_event("mail", "%s asked for %d mail(s) of the outgoing mail to be sent again now" % (
            by or "somebody", len(done)), "info", by)
        threading.Thread(target=lambda: [_quiet_attempt(store, q) for q in done], name="mail-again",
                         daemon=True).start()
    return done


def drop(store, qids, by=""):
    ready(store)
    n = 0
    for qid in qids:
        n += store.run("DELETE FROM mailq WHERE qid = ?", (str(qid),)).rowcount
    if n:
        store.add_event("mail", "%s took %d mail(s) out of the outgoing mail" % (by or "somebody", n), "warn", by)
    return n


def ids_in(store, states):
    ready(store)
    marks = ", ".join("?" for _ in states)
    return [r["qid"] for r in store.rows("SELECT qid FROM mailq WHERE state IN (%s)" % marks, tuple(states))]
