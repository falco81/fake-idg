#!/usr/bin/python3 -I
"""root_facts.py PATH - install.sh writes what root found (otp 1.0.258's root-facts.json): which install.sh
put root's parts in, what nginx and the firewall made of it. A value this run did not look at is kept
from the run before. Root's, readable by all, no secret in it. Read by Settings -> Upgrades."""
import json
import os
import re
import sys
import time

path = sys.argv[1]
was = {}
try:
    if os.path.isfile(path) and not os.path.islink(path):
        with open(path) as f:
            was = json.load(f)
except (OSError, ValueError):
    was = {}
was = was if isinstance(was, dict) else {}
env = os.environ.get
now = int(time.time())
out = {"installer": re.sub(r"[^0-9.]", "", env("FACT_VERSION") or "")[:20], "at": now,
       "kind": "upgrade" if env("FACT_KIND") else "install",
       "nginx": was.get("nginx") if isinstance(was.get("nginx"), dict) else {},
       "firewall": was.get("firewall") if isinstance(was.get("firewall"), dict) else {}}
if env("FACT_NGINX_ADD") in ("ok", "failed"):
    out["nginx"] = {"additions": env("FACT_NGINX_ADD"), "at": now}
if env("FACT_FIREWALL") in ("firewalld", "iptables", "none"):
    out["firewall"] = {"state": env("FACT_FIREWALL"), "at": now}
if os.path.islink(path):
    os.unlink(path)
tmp = path + ".new"
with open(tmp, "w") as f:
    json.dump(out, f, indent=1, sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o644)
os.rename(tmp, path)
