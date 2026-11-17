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


if 'location = /metrics' not in t and 'location /assets/' in t:
    b = block(r'(?ms)^    # ---- Prometheus.*?^    \}\n\n')
    if b:
        t = t.replace('    location /assets/', b + '    location /assets/', 1)
        said.append('GET /metrics for Prometheus')
if 'acme-challenge' not in t:
    b = block(r'(?ms)^    # A certificate by ACME.*?^    \}\n')
    m = re.search(r'(?ms)^server\s*\{[^{}]*?^\s*listen\s+80;.*?^(\s*location\s+/\s*\{)', t)
    if b and m:
        t = t[:m.start(1)] + b + t[m.start(1):]
        said.append("ACME's HTTP-01 on port 80")
if 'api=passkey-login' not in t:
    # 1.9.7: a passkey's sign-in counted with the password's (the same zone, by address)
    m = re.search(r'(?m)^(\s*)"~\(\^\|&\)api=login\(&\|\$\)"(\s+)\$binary_remote_addr;\n', t)
    if m:
        line = '%s"~(^|&)api=passkey-login(&|$)"%s$binary_remote_addr;\n' % (m.group(1), m.group(2))
        t = t[:m.end()] + line + t[m.end():]
        said.append("a passkey's sign-in in the sign-in rate limit")
if said:
    open(p, 'w').write(t)
print('; '.join(said))
