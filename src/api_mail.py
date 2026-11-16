"""api_mail.py - Settings → Mail and Settings → Outgoing mail (1.6.0), as otp's.

One feature, two panes: how fake-igd sends mail (a mail server, or straight to the
recipient's), its certificate authority and a test mail; and the outgoing mail - every
mail sent and what became of it, tried again by the background, sent again or taken
away by hand. The sending itself is igd_mail.py, which every other module uses.
"""
import re
import socket
import threading
import time

import igd_mail as M
import igd_seal as SEAL

NAME = "mail"

HOST_RE = re.compile(r"^(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*\Z|^\[?[0-9A-Fa-f:.]+\]?\Z")


def _host(v):
    return "" if HOST_RE.match(v) else "a host name or an address"


def _addr(v):
    return M.address_problem(v)


def _dns(v):
    for w in re.split(r"[\s,;]+", v):
        if w and not re.match(r"^[0-9A-Fa-f:.]{2,45}\Z", w):
            return "%s is not an address of a DNS server" % w
    return ""


SETTINGS = [
    {"key": "mail_mode", "name": "Sending mail", "kind": "choice", "default": "off",
     "choices": [("off", "off - no mail is sent"), ("smtp", "through a mail server (SMTP relay)"),
                 ("direct", "straight to the recipient’s mail server (MX), no relay")],
     "says": "How fake-igd’s mail - the alerts, the report, a test - leaves this machine: through your mail "
             "server, or straight to the server of each recipient’s domain (its MX record) with no relay - "
             "which only works where port 25 may go out and the receiving side trusts this machine (SPF, a "
             "reverse DNS name)."},
    {"key": "smtp_host", "name": "Mail server", "kind": "text", "default": "", "check": _host,
     "only_when": ("mail_mode", "smtp"),
     "says": "The mail server’s name or address: smtp.example.cz, or a relay in your network. Its name is "
             "what its certificate is checked against."},
    {"key": "smtp_port", "name": "Port", "kind": "int", "default": 0, "min": 0, "max": 65535,
     "only_when": ("mail_mode", "smtp"),
     "says": "0 picks the usual one for the encryption: 587 for STARTTLS, 465 for TLS, 25 for none."},
    {"key": "smtp_security", "name": "Encryption", "kind": "choice", "default": "starttls",
     "only_when": ("mail_mode", "smtp"),
     "choices": [("starttls", "STARTTLS - plain, then encrypted (587)"),
                 ("tls", "TLS from the start - SMTPS (465)"),
                 ("starttls-if", "STARTTLS if the server offers it"), ("none", "none - plain text (25)")],
     "says": "STARTTLS on 587 is what most servers want; SMTPS on 465 is TLS from the first byte; none sends "
             "everything - the password too - in the clear, for a relay inside your own network only."},
    {"key": "smtp_auth", "name": "Signing in", "kind": "choice", "default": "auto",
     "only_when": ("mail_mode", "smtp"),
     "choices": [("none", "none - the server lets this machine send"),
                 ("auto", "whatever the server offers best (PLAIN, LOGIN, CRAM-MD5)"),
                 ("plain", "PLAIN"), ("login", "LOGIN"), ("cram-md5", "CRAM-MD5"),
                 ("xoauth2", "XOAUTH2 - an OAuth access token as the password")],
     "says": "How this machine signs in to the server. None where the relay lets this address send by itself. "
             "XOAUTH2 (Microsoft 365, Google): the password is an access token."},
    {"key": "smtp_user", "name": "Account", "kind": "text", "default": "", "most": 200,
     "only_when": ("mail_mode", "smtp"),
     "says": "The account it signs in with - often the whole address."},
    {"key": "smtp_password", "name": "Password", "kind": "secret", "default": "", "most": 500,
     "only_when": ("mail_mode", "smtp"),
     "says": "Its password (or the OAuth access token for XOAUTH2). Kept in the database sealed with the "
             "key beside it (secrets.key)."},
    {"key": "smtp_verify", "name": "Check the server’s certificate", "kind": "bool", "default": True,
     "says": "Off is for a test: a server whose certificate is not checked is one anybody on the path can "
             "pretend to be. A certificate signed by your own authority is trusted once that authority is added "
             "below."},
    {"key": "smtp_timeout_s", "name": "Wait for the server (s)", "kind": "int", "default": 20, "min": 3, "max": 300,
     "says": "How long to wait for the server to answer."},
    {"key": "mail_direct_port", "name": "Port of the recipients’ servers", "kind": "int", "default": 25,
     "min": 1, "max": 65535, "only_when": ("mail_mode", "direct"),
     "says": "Going direct: the port of the recipients’ servers. It is 25 everywhere; another only to test "
             "against a server of your own."},
    {"key": "mail_direct_tls", "name": "Encryption to the recipients’ servers", "kind": "choice",
     "default": "if-offered", "only_when": ("mail_mode", "direct"),
     "choices": [("if-offered", "encrypted where the server offers it"),
                 ("required", "encrypted, or not sent at all")],
     "says": "Going direct: whether a server that offers no STARTTLS still gets the mail, in the clear. "
             "Required is safer, but a domain whose server has no TLS then gets nothing."},
    {"key": "mail_dns", "name": "DNS servers for the recipients’ domains", "kind": "text", "default": "",
     "check": _dns, "only_when": ("mail_mode", "direct"),
     "says": "Going direct: the DNS servers asked where each recipient’s domain takes its mail (its MX record), "
             "separated by commas - 1.1.1.1, 8.8.8.8. Empty: the ones in /etc/resolv.conf."},
    {"key": "mail_from", "name": "From (address)", "kind": "text", "default": "", "check": _addr,
     "says": "The sender’s address. Your mail server may allow only its own addresses; going direct, the "
             "domain should have this machine in its SPF. Empty: fake-igd@ this machine’s full name."},
    {"key": "mail_from_name", "name": "From (name)", "kind": "text", "default": "", "most": 120,
     "says": "The name beside it, as the recipient sees it. Empty: fake-igd."},
    {"key": "mail_reply_to", "name": "Replies to", "kind": "text", "default": "", "check": _addr,
     "says": "Where a reply goes - a helpdesk, say. Empty: back to the sender."},
    {"key": "mail_helo", "name": "This machine calls itself (EHLO)", "kind": "text", "default": "",
     "check": _host,
     "says": "The name this machine greets the server with. Empty: its own full name. Going direct, it should "
             "be the name its address resolves back to."},
    {"key": "mail_retry_hours", "name": "Try a mail not delivered for (hours)", "kind": "int", "default": 24,
     "min": 1, "max": 168,
     "says": "A mail the receiving side did not take yet - greylisting (a first \"try again later\"), a server "
             "away, a full mailbox - waits in the outgoing mail and is tried again: after 1, 2, 5, 10, 15 and "
             "30 min, then every hour, for this long."},
    {"key": "mail_keep_days", "name": "Keep the list of mails sent for (days)", "kind": "int", "default": 14,
     "min": 1, "max": 365,
     "says": "How long the outgoing mail keeps a mail that went, or that was given up, in its list - what it "
             "said and when. What a mail held is never kept once it went."},
]


# ---- Settings → Mail ----------------------------------------------------------------------
def mail_get(ctx):
    c = M.settings(ctx.store)
    return {"mode": c.get("mail_mode") or "off", "ca_list": M.ca_list(ctx.store), "counts": M.counts(ctx.store),
            "sender": M.sender(c)[0]}


def test_words(ctx):
    host = socket.gethostname()
    text = ("A test from fake-igd on %s, asked by %s on these pages at %s.\n\n"
            "If you read this, mail from fake-igd arrives: the alerts and the report will too.\n"
            % (host, (ctx.me or {}).get("name", "?"), time.strftime("%Y-%m-%d %H:%M:%S")))
    html = ("<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111827\">"
            "<h2 style=\"margin:0 0 10px;font-size:18px\">fake-igd - a test</h2>"
            "<p>A test from fake-igd on <b>%s</b>, asked by %s on these pages at %s.</p>"
            "<p>If you read this, mail from fake-igd arrives: the alerts and the report will too.</p></div>"
            % (host, (ctx.me or {}).get("name", "?"), time.strftime("%Y-%m-%d %H:%M:%S")))
    return "fake-igd: a test mail from %s" % host, text, html


def mail_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    S = ctx.store
    if act == "test":
        to = M.addresses(str(b.get("to") or "").strip())
        if not to:
            raise ValueError("an address to send the test to")
        c = M.settings(S)
        if (c.get("mail_mode") or "off") == "off":
            raise ValueError("sending mail is switched off - choose how it goes above and save it first")
        kind = str(b.get("kind") or "short")
        if kind == "alert":                              # otp's "a sample token mail": what an alert looks like
            import api_alerts as AL
            cur = list(AL.problems(ctx, AL.cfg_of(S)).values())
            subject, text, html = AL.alert_mail(ctx, [], cur, [], [], test=True)
        elif kind == "report":                           # the report of the period so far
            import api_alerts as AL
            since, until = AL.period_now(AL.cfg_of(S))
            subject, text, html = AL.report_build(ctx, since, until)
        elif kind == "short":
            subject, text, html = test_words(ctx)
        else:
            raise ValueError("no such kind of test")
        began = time.time()
        if b.get("via") == "straight":
            msg = M.message(S, to, subject, text, html, c)
            try:
                steps = M.deliver_now(S, msg, to, c)
                d = {"sent": True, "said": "to %s" % ", ".join(to), "steps": steps}
            except M.MailError as e:
                d = {"sent": False, "said": str(e), "steps": e.steps}
        else:
            got = M.send_and_wait(S, to, subject, text, html, kind="test", by=me["name"])
            d = {"sent": got["sent"], "said": got["said"] if not got["sent"] else "to %s" % ", ".join(to),
                 "steps": got["steps"], "queued": got.get("queued") or (True if got["sent"] else ""),
                 "qid": got["qid"]}
        d["took_ms"] = int((time.time() - began) * 1000)
        ctx.event("%s sent a test mail to %s: %s" % (me["name"], ", ".join(to),
                                                       "sent" if d["sent"] else d["said"][:300]),
                  "info" if d["sent"] else "warn")
        return d
    if act == "ca":
        mode = str(b.get("mode") or "add")
        got = M.ca_set(S, str(b.get("ca") or ""), mode, str(b.get("fingerprint") or ""))
        ctx.event("%s %s the mail server's certificate authority (%d kept)" % (
            me["name"], {"add": "added to", "drop": "took one out of", "clear": "emptied"}.get(mode, mode), len(got)))
        return {"ca_list": got, "message": {"add": "the authority is trusted for the mail server",
                                            "drop": "that certificate is taken out",
                                            "clear": "no authority of your own is kept now"}.get(mode, "done")}
    raise ValueError("no such action")


# ---- Settings → Outgoing mail ---------------------------------------------------------------
def mailq_get(ctx):
    try:
        limit = max(10, min(500, int(ctx.arg("limit", "50"))))
        offset = max(0, int(ctx.arg("offset", "0")))
    except ValueError:
        limit, offset = 50, 0
    d = M.listing(ctx.store, ctx.arg("q"), ctx.arg("state"), limit, offset)
    c = M.settings(ctx.store)
    d.update({"counts": M.counts(ctx.store), "mode": c.get("mail_mode") or "off",
              "retry_hours": c.get("mail_retry_hours"), "keep_days": c.get("mail_keep_days"), "now": time.time()})
    return d


def mailq_one(ctx):
    r = M.one(ctx.store, ctx.arg("id"))
    if not r:
        raise ValueError("that mail is not in the outgoing mail any more")
    return r


def mailq_post(ctx):
    me = ctx.need("fulladmin")
    b = ctx.body()
    act = b.get("action")
    ids = [str(x) for x in (b.get("ids") or []) if isinstance(x, str) and re.match(r"^[0-9a-f-]{8,40}\Z", x)]
    S = ctx.store
    if act == "retry":
        done = M.retry(S, ids, me["name"])
        return {"message": "%d mail(s) are being sent again" % len(done) if done else "nothing of it can be sent again"}
    if act == "retry_all":
        done = M.retry(S, M.ids_in(S, ["waiting"]), me["name"])
        return {"message": "%d waiting mail(s) are being sent now" % len(done) if done else "nothing waits"}
    if act == "drop":
        n = M.drop(S, ids, me["name"])
        return {"message": "%d mail(s) taken out" % n}
    if act == "drop_sent":
        n = M.drop(S, M.ids_in(S, ["sent"]), me["name"])
        return {"message": "%d sent mail(s) cleared" % n}
    if act == "drop_failed":
        n = M.drop(S, M.ids_in(S, ["failed", "expired"]), me["name"])
        return {"message": "%d failed mail(s) cleared" % n}
    raise ValueError("no such action")


ROUTES = {
    ("GET", "/api/mail"): mail_get,
    ("POST", "/api/mail"): mail_post,
    ("GET", "/api/mailq"): mailq_get,
    ("GET", "/api/mailq/one"): mailq_one,
    ("POST", "/api/mailq"): mailq_post,
}


def on_saved(ctx, changed):
    SEAL.seal_settings(ctx.store, ["smtp_password"])        # kept sealed in the database (igd_seal)
    if changed.get("mail_mode") not in (None, "off"):
        # What waited while mail was off goes now - in a thread: the save does not wait for it.
        threading.Thread(target=M.tick, args=(ctx.store,), name="mail-on", daemon=True).start()


def background(ctx):
    SEAL.seal_settings(ctx.store, ["smtp_password"])        # one saved before 1.6.1 sealed now
    M.tick(ctx.store)
