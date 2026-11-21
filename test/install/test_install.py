#!/usr/bin/env python3
"""test_install.py - the installer's parts that can be run without installing: deploy/nginx_additions.py (what
install.sh --upgrade puts into an nginx fake-igd.conf that is kept) and uninstall.sh (in a mount namespace of its
own, with fake systemctl / firewall-cmd - nothing of the machine is touched).

  python3 test/install/test_install.py

What it proves (1.9.11):
  - nginx_additions on the 1.4.0 file brings it to what this version ships, and a second run adds nothing
  - a port-80 server with `listen 80 default_server;` / `listen [::]:80;` gets ACME's location too (it got none,
    without a word); one that answers with a `return` of its own gets none and it is said (the location went into
    the HTTPS server); a file indented with tabs gets /metrics (it was said to, and did not)
  - uninstall.sh goes to the end when firewalld does not reload (it stopped half way: /opt/fake-igd left)
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = os.environ.get("FAKE_IGD_TREE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # another tree to try
ADD = os.path.join(ROOT, "deploy", "nginx_additions.py")
SHIP = os.path.join(ROOT, "deploy", "nginx-fake-igd.conf")

# deploy/nginx-fake-igd.conf as 1.4.0 shipped it, cut to what the additions look at
V140 = textwrap.dedent("""\
    map $args $igd_login_key {
        "~(^|&)api=login(&|$)"   $binary_remote_addr;
        default                  "";
    }
    server {
        listen      80;
        server_name fake-igd.example.local;       # <- your hostname
        server_tokens off;
        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen      443 ssl http2;
        server_name fake-igd.example.local;       # <- your hostname
        location = /admin/ {
            fastcgi_pass   unix:/run/php-fpm/fake-igd.sock;
            include        fastcgi_params;
        }

        # ---- files ------------------------------------------------------------------
        location /assets/ {
            expires 7d;
        }
        location = /favicon.ico { return 301 /assets/favicon.svg; }

        location /        { return 404; }
    }
    """)


def servers(text):
    """[(listen lines, body)] of each top-level server { }."""
    out = []
    for m in re.finditer(r"(?m)^[ \t]*server\s*\{", text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            if not depth:
                break
            i += 1
        body = text[m.end():i]
        out.append((re.findall(r"(?m)^\s*listen\s+([^;]*);", body), body))
    return out


class NginxAdditions(unittest.TestCase):
    def run_on(self, text):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "fake-igd.conf")
        with open(p, "w") as f:
            f.write(text)
        got = subprocess.run([sys.executable, "-I", ADD, p, SHIP], capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        with open(p) as f:
            return f.read(), got.stdout.strip(), got.stderr.strip(), p

    def acme_in(self, text):
        return [ls for ls, body in servers(text) if "acme-challenge" in body]

    def test_old_file_brought_up_once(self):
        t, said, _err, p = self.run_on(V140)
        for want in ("location = /metrics", "acme-challenge", "api=passkey-login", "apple-touch-icon"):
            self.assertIn(want, t)
        self.assertEqual(self.acme_in(t), [["80"]])
        # the "# ---- files" heading stays above /assets/, /metrics goes before it
        self.assertLess(t.index("location = /metrics"), t.index("# ---- files"))
        again = subprocess.run([sys.executable, "-I", ADD, p, SHIP], capture_output=True, text=True)
        self.assertEqual(again.stdout.strip(), "")
        with open(p) as f:
            self.assertEqual(f.read(), t)

    def test_listen_80_written_otherwise(self):
        for listen in ("listen      80 default_server;\n    listen      [::]:80 default_server;",
                       "listen      [::]:80;\n    listen      80;", "listen 0.0.0.0:80;"):
            t, said, _err, _p = self.run_on(V140.replace("listen      80;", listen))
            self.assertIn("ACME", said, listen)
            self.assertEqual(len(self.acme_in(t)), 1, listen)
            self.assertNotIn("443", " ".join(self.acme_in(t)[0]))

    def test_port_80_with_its_own_return(self):
        text = V140.replace("    location / {\n        return 301 https://$host$request_uri;\n    }\n}",
                            "    return 301 https://$host$request_uri;\n}", 1)
        t, said, err, _p = self.run_on(text)
        self.assertEqual(self.acme_in(t), [])            # not into the HTTPS server
        self.assertNotIn("ACME", said)
        self.assertIn("not added", err)

    def test_tabs(self):
        t, said, _err, _p = self.run_on(V140.replace("    ", "\t"))
        self.assertIn("/metrics", said)
        self.assertEqual(t.count("location = /metrics"), 1)


FAKE_SYSTEMCTL = """#!/bin/sh
case "$*" in *is-active*firewalld*) exit 0;; esac
exit 0
"""
FAKE_FIREWALL_CMD = """#!/bin/sh
case "$*" in *--get-zones*) echo public; exit 0;; *--reload*) echo "Error: INVALID_ZONE" >&2; exit 1;; esac
exit 0
"""


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("unshare"), "needs root and unshare (a mount namespace)")
class Uninstall(unittest.TestCase):
    def test_firewalld_not_reloading(self):
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "bin")
        os.mkdir(fake)
        for name, body in (("systemctl", FAKE_SYSTEMCTL), ("firewall-cmd", FAKE_FIREWALL_CMD)):
            with open(os.path.join(fake, name), "w") as f:
                f.write(body)
            os.chmod(os.path.join(fake, name), 0o755)
        # /opt, /run, /var and /etc are a tmpfs each, in a mount namespace of its own: the machine's are not seen
        script = textwrap.dedent("""\
            set -e
            for m in /opt /run /var /etc; do mount -t tmpfs none "$m"; done
            mkdir -p /opt/fake-igd /etc/fake-igd /var/www/fake-igd /etc/nginx/conf.d
            echo '{"http_port": 5000}' > /etc/fake-igd/config.json
            touch /opt/fake-igd/x.py /etc/nginx/conf.d/fake-igd.conf
            PATH="%s:$PATH" bash "%s" > /run/out 2>&1 || echo "EXIT $?" >> /run/out
            cat /run/out
            [ -e /opt/fake-igd ] && echo "LEFT /opt/fake-igd" || true
            """) % (fake, os.path.join(ROOT, "uninstall.sh"))
        got = subprocess.run(["unshare", "--mount", "--propagation", "private", "bash", "-c", script],
                             capture_output=True, text=True, timeout=60)
        if "mount" in got.stderr and got.returncode:
            self.skipTest("no mount namespace here: " + got.stderr.strip()[-200:])
        out = got.stdout
        self.assertIn("Done.", out, out + got.stderr)
        self.assertNotIn("EXIT", out)
        self.assertNotIn("LEFT", out)
        self.assertIn("firewalld did not reload", out)


class Arguments(unittest.TestCase):
    """1.9.11: an option without its value is said (not "unbound variable"); uninstall.sh refuses an unknown one."""
    def test_install_value_missing(self):
        got = subprocess.run(["bash", os.path.join(ROOT, "install.sh"), "--server-name"], capture_output=True, text=True)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn("--server-name needs a value", got.stdout + got.stderr)
        self.assertNotIn("unbound variable", got.stdout + got.stderr)

    def test_uninstall_unknown_option(self):
        got = subprocess.run(["bash", os.path.join(ROOT, "uninstall.sh"), "--purg"], capture_output=True, text=True)
        self.assertEqual(got.returncode, 2)
        self.assertIn("I do not know the option --purg", got.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
