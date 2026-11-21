#!/usr/bin/python3 -I
"""nginx_additions.py CONF SHIPPED - what later versions need of nginx's fake-igd.conf, put in where it is
missing (as otp's install.sh does): /metrics (1.6.0) and ACME's port-80 location (1.6.0). Prints what was
added. install.sh keeps a copy first and asks nginx -t after."""
import re
import sys

p, ship = sys.argv[1], open(sys.argv[2]).read()
t = open(p).read()
said = []
sock = re.search(r'(?m)^\s*fastcgi_pass\s+(unix:[^;\s]+);', t)


def block(rx):
    m = re.search(rx, ship)
    b = m.group(0) if m else ''
    return b.replace('unix:/run/php-fpm/fake-igd.sock', sock.group(1)) if sock else b




def server_80(t):
    """(start, end) of the server { } that listens on port 80 - `listen 80 default_server;` and `listen [::]:80;`
    too (1.9.11) - or None."""
    for m in re.finditer(r'(?m)^[ \t]*server\s*\{', t):
        depth, i = 0, m.end() - 1
        while i < len(t):
            if t[i] == '{':
                depth += 1
            elif t[i] == '}':
                depth -= 1
                if not depth:
                    break
            elif t[i] == '#':
                i = t.find('\n', i)
                if i < 0:
                    return None
            i += 1
        body = t[m.end():i]
        if re.search(r'(?m)^\s*listen\s+(?:\S*:)?80(?:\s[^;]*)?;', body):
            return m.end(), i
    return None


# The line where /assets/ starts, however indented (1.9.11: a file indented with tabs was said to have /metrics
# added, and had not); the "# ---- files" heading above it stays above it.
m = re.search(r'(?m)^(?:[ \t]*# ---- files.*\n)?[ \t]*location\s+/assets/', t)
if 'location = /metrics' not in t and m:
    b = block(r'(?ms)^    # ---- Prometheus.*?^    \}\n\n')
    if b:
        t = t[:m.start()] + b + t[m.start():]
        said.append('GET /metrics for Prometheus')
if 'acme-challenge' not in t:
    # In the port-80 server only (1.9.11): one that answered with `return 301` of its own, not in a location /, had
    # the location put into the HTTPS server's, and one with `listen 80 default_server;` none at all - both
    # without a word.
    b = block(r'(?ms)^    # A certificate by ACME.*?^    \}\n')
    srv = server_80(t)
    m = srv and re.compile(r'(?m)^[ \t]*location\s+/\s*\{').search(t, srv[0], srv[1])
    if b and srv and not m and re.search(r'(?m)^\s*return\s', t[srv[0]:srv[1]]):
        sys.stderr.write("nginx_additions: ACME's port-80 location is not added - the port-80 server answers with a "
                         "return of its own; put a location / { return 301 ...; } around it and run this again\n")
    elif b and srv:
        at = m.start() if m else srv[1]
        t = t[:at] + b + t[at:]
        said.append("ACME's HTTP-01 on port 80")
    elif b:
        sys.stderr.write("nginx_additions: ACME's port-80 location is not added - no server listens on port 80\n")
if 'api=passkey-login' not in t:
    # 1.9.7: a passkey's sign-in counted with the password's (the same zone, by address)
    m = re.search(r'(?m)^(\s*)"~\(\^\|&\)api=login\(&\|\$\)"(\s+)\$binary_remote_addr;\n', t)
    if m:
        line = '%s"~(^|&)api=passkey-login(&|$)"%s$binary_remote_addr;\n' % (m.group(1), m.group(2))
        t = t[:m.end()] + line + t[m.end():]
        said.append("a passkey's sign-in in the sign-in rate limit")
if 'apple-touch-icon' not in t and 'location = /favicon.ico' in t:
    # 1.9.8: a home screen's icon and the manifest (an iPad's "Add to Home Screen")
    b = block(r'(?ms)^    # A home screen.*?^    location = /assets/manifest\.webmanifest \{.*?^    \}\n')
    if b:
        i = t.index('location = /favicon.ico')
        j = t.index('\n', i) + 1
        t = t[:j] + b + t[j:]
        said.append("the home screen's icon and manifest")
if said:
    open(p, 'w').write(t)
print('; '.join(said))
