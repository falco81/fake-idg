# fake-igd 1.6.0

A fake UPnP router (IGD) for reconnaissance: it finds out **which ports a PS5 (or any other device) wants to open**, without enabling UPnP on your real router. Everything is logged to `/var/log/fake-igd/` and controlled with the **`upnp`** command - or by its menus with **`upnp --console`**. It also shows and controls the **mDNS reflector (avahi-daemon)** running on the same server, and sends notifications to **ntfy** (ntfy.sh or your private server).

Since 1.4.0 it has **web pages** - otp's administration pages, the same header, tabs, settings rail and
popups, over nginx, php-fpm and an API of its own, with **local accounts** in SQLite - and it **upgrades
itself from the web**: `sudo upnp upgrade online`, or *Settings → Upgrades* on the pages - signed
packages only, checked and put in by root, exactly as otp does it.

```
  browser ──HTTPS──▶ nginx ──▶ php-fpm pool "fake-igd" ──▶ fake-igd-api (127.0.0.1:9862, user fake-igd)
                    (allow list,  (user fake-igd-www,        │  SQLite: accounts, sign-ins, events
                     TLS, limits)  relays only)               │  reads the logs, writes config.json
                                                              ▼
  PS5 ──SSDP 1900/udp, SOAP 5000/tcp──▶ fake-igd.service      root's helpers, started by systemd path units:
                                         (user fake-igd)       fake-igd-upgrade.path → install.sh --upgrade
                                                               fake-igd-web.path     → restart, nginx allow, iptables
```

## Installation (AlmaLinux 9)

```bash
tar xzf fake-igd-1.6.0.tar.gz
cd fake-igd-1.6.0
sudo ./install.sh
```

Releases: [release/](https://github.com/falco81/fake-idg/tree/main/release) (the last ten).
It asks a handful of questions (the pages' hostname, who may reach them, the first account),
installs everything, makes the first account and prints its password. Then open
`https://SERVER/admin/`.

The installer does everything (each step says `==> what`, as otp's):

1. Installs system packages (`logrotate`, `curl`, `xz`, `iproute`, `bash-completion`, `policycoreutils`, ...).
2. Installs **Python 3.14**:
   - from the repositories with `dnf install python3.14 python3.14-pip` (in AppStream since AlmaLinux 9.8; on older 9.x run `sudo dnf upgrade` first),
   - if the package is not available, it **builds Python 3.14.9 from source** (python.org) into `/usr/local` (`make altinstall`, the system Python 3.9 stays untouched). The archive is verified with SHA-256. Building takes a few minutes, log: `/var/log/fake-igd-python-build.log`.
3. Creates the virtualenv `/opt/fake-igd/venv` with **colorama** (from the bundled wheel in `vendor/`, works offline).
4. Creates the system user and group `fake-igd`. The user who ran `sudo` is added to the group so they can read logs with `upnp` without sudo (after logging in again).
5. Installs the service (systemd, start on boot, sandboxed), the `upnp` command, bash completion and log rotation.
6. Checks for port collisions and opens 1900/udp and 5000/tcp in **firewalld**. If firewalld is not running but iptables/nftables rules are active, it does **not** touch them and tells you to run `upnp firewall`.
7. Starts the service and shows `upnp status`.
8. The web pages: PHP 8.3 (AppStream), a php-fpm pool of its own (`fake-igd-www`), nginx with TLS
   (a self-signed certificate unless `--cert`/`--key`), SELinux (`httpd_can_network_connect`, the API's
   token labelled for the pages), the API service `fake-igd-api`, and the first account.
9. Upgrades: root's helpers `/opt/fake-igd/fake_igd_upgrade.py` and `fake_igd_web.py`, the release key
   in `/opt/fake-igd/release-keys/`, and the path units `fake-igd-upgrade.path`, `fake-igd-web.path`.
10. The firewall - **iptables, as otp**: where iptables is in use (iptables.service, or rules in INPUT)
    and firewalld is not, fake-igd's own chain `FAKE-IGD-IN` is put in place (see *Firewall* below).

| Option | Meaning |
|---|---|
| `--upgrade` | upgrade an existing installation (see below) |
| `--server-name HOST` | the pages' hostname (default: this machine's) |
| `--admin-allow CIDR,...` | who may reach the pages (default: the RFC 1918 networks) |
| `--admin-user NAME` `--admin-password -` | the first account (the password asked for; else one is made and printed) |
| `--cert FILE --key FILE` | the TLS certificate for nginx |
| `--no-web` | no pages, no nginx, no PHP - the service and the command line only |
| `--firewall` | put `FAKE-IGD-IN` in place even where iptables does not look in use |
| `--no-firewall` | leave the firewall alone (`upnp firewall` prints the rules) |
| `--uninstall [--purge]` | take it away (`--purge`: the configuration, logs, database and accounts too) |
| `--yes` | ask nothing, take the defaults |
| `--no-start` | install but do not start |
| `--python-from-source` | always build Python 3.14 from source |
| `--no-python-build` | never build from source, dnf only |
| `--force` | allow an OS other than EL9 |
| `PY_OPTIMIZE=1 ./install.sh` | build from source with PGO/LTO (faster Python, much longer build) |

### Upgrade

From the web - the newest version from `upgrade_url` (by default this repository's `release/`):

```bash
upnp upgrade check                     # what is there, and whether it is newer
sudo upnp upgrade online               # fetched, checked, put in by root - followed with a progress bar
sudo upnp upgrade online 1.4.2 --yes   # one version, without asking
sudo upnp upgrade file /root/fake-igd-1.4.2.tar.gz
upnp upgrade follow                    # one going on (the pages or another terminal started it)
upnp upgrade status                    # how the last one went;  upnp upgrade log - what install.sh said
```

Or on the pages: *Settings → Upgrades* - *Look now*, *Upgrade to X now*, or drop a package there. The
console: menu **14 Upgrades**. Or by hand, as before:

```bash
tar xzf fake-igd-1.6.0.tar.gz && cd fake-igd-1.6.0
sudo ./install.sh --upgrade
```

**What makes it safe** (otp's way, step for step): neither the pages nor `upnp upgrade` install
anything themselves. The package is laid down in `/var/lib/fake-igd/upgrade/` with a `request.json`;
systemd (`fake-igd-upgrade.path`) starts `fake-igd-upgrade.service`, which runs
`/opt/fake-igd/fake_igd_upgrade.py` as root. Root copies the package to a folder of its own and checks
it from the start: **signed** (`MANIFEST` lists the SHA-256 of every file, `MANIFEST.sig` is its
Ed25519 signature by a key in `/opt/fake-igd/release-keys/` - root's alone, put there by install.sh),
every file the one signed and nothing else in it (no links, no paths outside its folder), and **not
older** than what is installed. Then it runs the package's own `install.sh --upgrade --yes` and writes
what it said to `/var/lib/fake-igd/upgrade/last.log`. When the new version does not start, the one
before is put back. Going back to an older version is only by hand, as root:
`sudo upnp upgrade file OLDER.tar.gz --downgrade`.

`--upgrade` replaces the application, CLI, completion, systemd unit and logrotate config, refreshes the virtualenv (and recreates it if the Python minor version changed), **keeps** the configuration, logs, state and firewall, **adds new configuration keys** with their default values, restarts the service and prints `old → new` version. The new default config is always saved as `config.json.dist` for comparison.

| What | Where |
|---|---|
| Application + CLI | `/opt/fake-igd/fake-igd.py`, `/opt/fake-igd/upnp.py` |
| Python venv | `/opt/fake-igd/venv` (Python 3.14 + colorama) |
| Command | `/usr/bin/upnp` (+ `/usr/bin/fake-igd-ports` = `upnp ports`) |
| Configuration | `/etc/fake-igd/config.json` |
| Main log (everything) | `/var/log/fake-igd/fake-igd.log` |
| Port requests (JSON lines) | `/var/log/fake-igd/requests.jsonl` |
| Current "mappings" | `/var/lib/fake-igd/mappings.json` |
| Service | `fake-igd.service` (`upnp status`) |
| Log rotation | `/etc/logrotate.d/fake-igd` (weekly, 12 weeks) |
| Uninstall | `sudo /opt/fake-igd/uninstall.sh [--purge]` (keeps Python 3.14) |
| The pages' API | `/opt/fake-igd/fake_igd_api.py`, `fake-igd-api.service`, 127.0.0.1:9862, token in `/run/fake-igd-api/` |
| The pages | `/var/www/fake-igd/`, `/etc/nginx/conf.d/fake-igd.conf`, `/etc/php-fpm.d/fake-igd.conf`, `/etc/nginx/certs/fake-igd.pem` |
| Database | `/var/lib/fake-igd/fake-igd.db` (SQLite: the accounts, sign-ins, events) |
| Root's helpers | `/opt/fake-igd/fake_igd_upgrade.py`, `/opt/fake-igd/fake_igd_web.py`, `/opt/fake-igd/release-keys/` |
| Upgrades | `/var/lib/fake-igd/upgrade/` (`status.json`, `last.log`) |

---

## The web pages

`https://SERVER/admin/` - otp's administration pages, for fake-igd: the same sign-in page, header with
the state pill and *live*, tabs, settings rail, popups and save bar (otp's `core.js` and stylesheet,
unchanged).

| Tab | What |
|---|---|
| Overview | the service, mode and answer, ports, clients, interfaces, mappings, mDNS, upgrades; requests over time |
| Ports | every port asked for (client, protocol, port, count, first/last, result, description) + **DNAT rules for the router** |
| Requests | every SOAP request, newest first, each with everything it carried |
| Clients | who looked for a UPnP router or asked for ports, with PTR names |
| Mappings | what the clients believe is open now |
| mDNS | the reflector (avahi-daemon): the daemon, reflecting or not, its interfaces, and every service mDNS shows now |
| Log | fake-igd's log, coloured as `upnp log`, followed live, with a grep |
| Events | settings changed, accounts, sign-ins, upgrades - on the pages and on the command line |
| Settings | How it answers · Network · Notifications (ntfy, with a test) · Logs and state · **mDNS reflector (avahi)** - every key of avahi-daemon.conf, the daemon restarted/stopped, its journal · **Accounts** · **Pages and firewall** · The service · **Upgrades** · About |

A setting the service uses restarts `fake-igd.service` when it is saved (the pages are a service of
their own and stay); `web_allow` and the firewall's settings are put in place by root
(`fake-igd-web.path`). Every request is relayed by PHP to the API, which decides everything - as otp's.

### Every setting (1.6.0)

*Settings* holds otp's panes that fit fake-igd, each as otp draws it: **How it answers**, **UPnP network**,
**Notifications (ntfy)**, **Logs and state**, **mDNS reflector (avahi)** · **Accounts**, **Certificates and
TLS**, **Automatic certificates (ACME)**, **Firewall and access**, **SSH server and notices**, **SSH keys**,
**Local users** · **Network**, **Proxy**, **Time**, **The service**, **Restart and power off**, **Disks and
logs** · **The database**, **Backups**, **Export and import** · **Mail**, **Outgoing mail**, **Alerts and
reports**, **Monitoring** (Prometheus `/metrics`), **Syslog and SIEM**, **System updates**, **Upgrades**,
**About**. Whatever changes the system is done by root (`/opt/fake-igd/root_*.py`, asked through
`/var/lib/fake-igd/web/ask/`), checked again there; the network, the firewall and SSH go **on trial** and
come back by themselves unless kept.

### Accounts (local, SQLite)

**full admin** may change everything, **read only** may look. Passwords are kept as scrypt hashes;
ten wrong passwords from one address (six for one name) in ten minutes block signing in from there
for a while; a sign-in ends after `session_idle_minutes` without a request (and after a day).

```bash
sudo upnp user add alice                   # full admin; a password is made and printed once
sudo upnp user add bob --role readonly --password -
sudo upnp user passwd admin                # a new password, its sign-ins end
sudo upnp user role bob --role fulladmin
sudo upnp user del bob
sudo upnp user list                        # upnp user sessions - who is signed in now
upnp web                                   # the pages' address, nginx, php-fpm, the API
```

Or on the pages (*Settings → Accounts*), or in the console (menu **15 Web pages and accounts**).

## Firewall (iptables, as otp)

Where the machine uses iptables (`iptables-services`), fake-igd keeps **a chain of its own**, as otp
keeps `OTP-IN`:

```
INPUT ─► FAKE-IGD-IN: loopback, answers, SSH, ping, 1900/udp, 5000/tcp, 80/443 from web_allow ─► the rest of INPUT
```

ACCEPT rules only - anything it does not match goes back to INPUT and on to the rules that were there
before; fake-igd never changes those. Interfaces in `exclude_interfaces` are sent back to INPUT for
1900/5000. It is put in at once (`iptables-restore --noflush`) and kept in `/etc/sysconfig/iptables`
between lines starting `# fake-igd:` (checked with `iptables-restore --test` first). A change of
`http_port`, the interfaces, `web_allow` or the firewall's switches puts it in place again by itself.

```bash
sudo upnp firewall --status     # the chain, first in INPUT?, kept in the file?, its rules
sudo upnp firewall --apply      # switch it on (firewall=on) and put it in place
sudo upnp firewall --off        # the chain and its jump taken away (live and in the file)
upnp firewall                   # only print the rules, for another firewall
```

Settings: `firewall` (on/off), `firewall_ssh`, `firewall_icmp`, `web_allow`. Where firewalld runs
instead, install.sh opens the ports in its zones as before.

## The console: `upnp --console`

The same console as `otp --console` - everything by its menus, on the server's own screen or over SSH.

```
 upnp 1.3  mdsn   service active      mode active | accept | 4 interfaces | 2 clients | 5 ports | mDNS refl. on

  Main menu

     1  Status and checks
     2  Live log
     3  Live port requests
     4  Requested ports
     5  Clients
     6  Current mappings
     7  Settings
     8  Rules for the router (DNAT)
     9  Host firewall
    10  Notifications (ntfy)
    11  The service
    12  Logs and maintenance
    13  mDNS reflector (avahi)
    14  Upgrades
    15  Web pages and accounts

 Up/Down move   Enter choose   Esc back   ! shell   q leave
```

- It opens on the **live log** (every line); **Esc** goes to the main menu, **q** leaves it for the ordinary shell, **!** opens a shell that comes back with `exit`. `UPNP_CONSOLE_START=menu upnp --console` opens on the menu.
- **The bar at the top**: version, machine, whether the service runs, mode, AddPortMapping answer, interfaces, clients, ports, the mDNS reflector and the public IP - asked again every 20 s without holding anything up. A red line under it when another UPnP router is on the network, the service or avahi-daemon is not running; yellow for passive mode.
- **The menus**: arrows (or j/k) move, Enter or → chooses, Esc, ← or Backspace goes back, a number jumps to its item (`1` `3` is 13), Home/End and PgUp/PgDn. Only what changed is written, nothing blinks; a resized window (PuTTY too) is drawn again.
- **Nothing is typed at a bare prompt**: every question is a window over the menu - fields one under the other, Up/Down (Tab) between them, a choice changed with Left/Right, a password shows stars, the field's help under them; Enter checks them all first (it says which is wrong and the window stays), Esc closes it. Anything that cannot be undone asks Yes / No first - No unless chosen.
- **Lists** (ports, clients, mappings, mDNS services) scroll with a scroll bar, `/` keeps only rows with some words, Enter on one offers what can be done with it.
- **Every action is the `upnp ...` command** its window shows in its title - the console can do nothing the command line cannot. A short answer comes in a window, a long one on a screen of its own to scroll.
- **Settings → Browse and change**: every setting in its group, Enter opens a window with its help, what it is now and as it comes, and what it may be; checked before it is saved.

### The live views

The live log, the live port requests, live mDNS and the journals are screens of their own:

- The newest line at the bottom, followed as it comes (`following`). Up/PgUp/Home scroll back - the view stays (`PAUSED, 12 new below`) - Down/PgDn to the end, End or Enter follow again. Left/Right move sideways along long lines. A scroll bar on the right; the last 20 000 lines are kept.
- **Whatever is typed is a grep**, as `grep -i`: only the lines with it stay, the hits are marked. A regular expression works (`3478|3479`, `port:.*rejected`). Backspace takes a character back, Ctrl+U all of them; Esc clears it, Esc again goes back to the menu.
- Coloured (colorama): the time dim, the level by how bad, what it is about (`port:`, `ssdp:`, `http:`, `net:` ...) in cyan, addresses in magenta, accepted green, rejected / refused / failed red, a warning line yellow, an error line red.

### At login

```bash
upnp --console-at-login on        # root sees the console first when signing in (q: the shell)
upnp --console-at-login off
upnp --console-at-login status
upnp --console-users "alice bob"  # normal users too - through sudo, their own password ('*' = every one, none)
```

`/etc/profile.d/zz-upnp-console.sh` opens it in an interactive login shell only - never for a command run over SSH, scp/sftp, a script, a shell opened from the console itself (`!`), or with `UPNP_NO_CONSOLE=1`. The choice is `/etc/upnp-console-login`; an upgrade keeps it. The installer leaves it **off**.

---

## Notifications (ntfy - public or private server)

Every new port a client asks for - and another UPnP router seen on the network - can go to your phone through [ntfy](https://ntfy.sh): the public ntfy.sh or **your own ntfy server**.

```bash
sudo upnp config set ntfy_url https://ntfy.example.com/ps5      # your server + topic
sudo upnp config set ntfy_token -                                # access token (tk_...), asked for, not shown
# or user + password instead of a token:
sudo upnp config set ntfy_user alice
sudo upnp config set ntfy_password -
sudo upnp config set ntfy_ca_file /etc/pki/tls/certs/my-ca.pem   # a server with its own CA
sudo upnp config set ntfy_priority 4                             # 1 min .. 5 max
upnp notify-test                                                 # one test message, the server's answer shown
```

Or in the console: **10 Notifications (ntfy) → Set up**, one form for all of it, then a test.

| Key | Meaning |
|---|---|
| `ntfy_url` | `https://ntfy.sh/topic` or `https://your-server/topic`; empty = off |
| `ntfy_token` | access token of a private server, sent as `Authorization: Bearer` (hidden everywhere) |
| `ntfy_user` / `ntfy_password` | Basic auth instead of a token (the password hidden everywhere) |
| `ntfy_priority` | 1-5 (default 3) |
| `ntfy_tags` | tags / emoji names (default `video_game`) |
| `ntfy_ca_file` | PEM of your own certificate authority (self-hosted TLS) |
| `notify_on_renew` | notify renewals too (default off) |
| `notify_other_router` | notify when another UPnP router announces itself (default on, priority 4) |

Secrets are passed to `config set` as `-` (asked for) or `@env` (the `UPNP_VALUE` variable, what the console uses) so they never appear on a command line; `config show` and `config get` print `(hidden)`. `/etc/fake-igd/config.json` is readable by root and the `fake-igd` group only. 401 / 403 / TLS errors are explained (`check ntfy_token`, `set ntfy_ca_file`). Each sent notification is logged (`notify: sent ...`), a failed one is a warning.

---

## mDNS reflector (avahi-daemon)

The server's avahi-daemon with `enable-reflector=yes` repeats mDNS (Bonjour, AirPlay, Chromecast, printers, ...) between its networks. `upnp mdns` shows and controls it - and the console's menu **13**.

```bash
upnp mdns                                   # daemon, reflector, IPv4/IPv6, filters, interfaces (+ PTR names)
upnp mdns services                          # what mDNS shows now on every interface (avahi-browse)
upnp mdns services --type _airplay --json
upnp mdns browse                            # live: new / gone / resolved
sudo upnp mdns reflector on|off
sudo upnp mdns interfaces ens192 ens224     # allow-interfaces (all = every interface)
sudo upnp mdns filters _airplay._tcp _raop._tcp   # reflect-filters (none = every type)
sudo upnp mdns ipv6 off                     # also: ipv4, reflect-ipv
sudo upnp mdns set cache-entries-max 0      # any known key of avahi-daemon.conf
upnp mdns config                            # the lines set in the file
upnp mdns log -f                            # journalctl -u avahi-daemon
sudo upnp mdns restart                      # start, stop, enable, disable
```

Every change to `/etc/avahi/avahi-daemon.conf` keeps all its comments (a commented `#key=` line is used as the place for the value), leaves a copy beside it (`avahi-daemon.conf.bak-DATE`), checks the value first (interfaces that exist, service types like `_airplay._tcp.local`, yes/no, numbers) and restarts avahi-daemon. **When avahi-daemon does not come up with the change, the copy is put back** and the daemon started again with it. `--no-restart` only writes the file. `avahi-browse` comes with `avahi-tools` (the installer adds it when avahi is installed).

---

## PTR names

`upnp clients`, `ports`, `requests`, `mappings`, `mdns` and the console's lists show the **PTR name** (reverse DNS) of each address in a NAME column (`name` in `--json`). Lookups run side by side with a short limit, so a slow DNS never holds the output up; `--no-dns` leaves them out.

---

## Host firewall

fake-igd needs two ports open on **this server** (INPUT), on the interfaces facing the PS5:

| Port | Why |
|---|---|
| **1900/udp** | SSDP: the PS5 sends a multicast M-SEARCH to 239.255.255.250:1900 to find the router |
| **5000/tcp** (`http_port`) | the PS5 downloads the device description and sends SOAP requests |

fake-igd is **IPv4 only** - nothing is needed for **ip6tables**.

Print the exact rules for your firewall (detected automatically, limited to the interfaces fake-igd uses):

```bash
upnp firewall                                   # iptables / nft / firewalld, by the active service
upnp firewall --interface ens161 --interface ens224
upnp firewall --source 172.16.16.0/24
```

Typical iptables output:

```bash
iptables -I INPUT -i ens161 -p udp --dport 1900 -m comment --comment fake-igd -j ACCEPT
iptables -I INPUT -i ens161 -p tcp --dport 5000 -m comment --comment fake-igd -j ACCEPT
...
# optional - only if 'upnp test' on this server still gets no answer:
iptables -I INPUT -p udp --sport 1900 -m addrtype --dst-type LOCAL -m comment --comment fake-igd -j ACCEPT
service iptables save
```

`upnp test` detects this situation: if multicast gets no answer but the service answers over unicast, it reports that the firewall drops multicast SSDP and points you to `upnp firewall`.

---

## The `upnp` command

```
upnp <command> [options]        upnp --help        upnp <command> --help        upnp help <command>
```

| Command | Alias | What it does |
|---|---|---|
| `status` | `st` | service state, settings, interfaces, statistics, warning about another UPnP router |
| `ports` | `p` | summary of requested ports (client, protocol, port, count, result, description) |
| `requests` | `req`, `r` | individual requests over time |
| `mappings` | `m` | what clients believe is open (remaining lease) |
| `clients` | `c` | devices that searched for a UPnP router or requested ports |
| `log` | `l` | coloured log, `-f` follow, `-e` events only, `--level`, `--grep`, `--since` |
| `dnat` | `d` | ready-made router rules: `--format iptables \| nft \| mikrotik \| firewalld` |
| `firewall` | `fw` | host firewall rules fake-igd needs on this server |
| `config` | `cfg` | `show`, `get`, `set`, `edit`, `validate`, `path` |
| `mode` | | `active` / `passive` (no argument = print current) |
| `response` | | `accept` / `reject` (no argument = print current) |
| `test` | `t` | test fake-igd as a UPnP client, detect blocked multicast and other UPnP routers |
| `mdns` | `avahi` | the mDNS reflector (avahi-daemon): status, services, browse, control |
| `notify-test` | `nt` | send a test notification with the configured ntfy |
| `start` `stop` `restart` `enable` `disable` | | service control |
| `clear` | | truncate logs (`--requests`, `--log`, `--all`) |
| `upgrade` | `up` | new versions: `check`, `online [VERSION]`, `file PATH`, `status`, `follow`, `log` |
| `user` | `users` | the pages' accounts: `list`, `add`, `passwd`, `role`, `note`, `del`, `sessions`, `end` |
| `web` | | the pages: `status`, `apply [--restart]` |
| `version` | | versions of the CLI, Python and colorama |

Common options: `--config FILE`, `--color auto|always|never`, `--no-color` (or the `NO_COLOR` variable), `--no-dns`.
Console: `upnp --console`, `upnp --console-at-login on|off|status`, `upnp --console-users USERS`.
The `--since` filter accepts `30m`, `2h`, `7d`, `2w`, `2026-11-16` or `'2026-11-16 18:00'`.

### Typical workflow

```bash
upnp status                               # running? on which interfaces?
upnp test                                 # does fake-igd answer? another UPnP router? blocked multicast?
upnp firewall                             # if the test reports blocked multicast
upnp log -f -e                            # watch live; on the PS5 run the connection test, a game, party chat
upnp ports                                # what the PS5 requested
upnp ports --client 192.168.1.50 --min-count 2
upnp dnat --format mikrotik --wan ether1  # rules for the router
sudo upnp response reject                 # once you know the ports: stop "promising" anything to the PS5
```

### Changing the configuration from the CLI

```bash
upnp config                                         # overview with descriptions, changed values highlighted
sudo upnp config set allowed_clients 192.168.1.50   # lists: comma-separated or JSON, empty = ''
sudo upnp config set exclude_interfaces lo,ens19
sudo upnp config set ntfy_url https://ntfy.sh/my-secret-topic
sudo upnp config edit                               # $EDITOR + JSON validation
sudo upnp mode passive                              # changes restart the service automatically (--no-restart)
```

Reading (status, ports, log, ...) works without sudo for members of the `fake-igd` group. Configuration changes and `clear` require `sudo`.

---

## How UPnP IGD works (and why the fake server does not pull traffic through itself)

UPnP IGD is only a **control protocol**: a device asks the router "open port X from the outside and forward it to my IP". **It does not decide where data traffic flows** - that always goes through the **default gateway** and DNS the PS5 got from DHCP (or static settings). UPnP does not and cannot change that; the protocol has no message like "use a different gateway".

### Step by step

```
 PS5 (192.168.1.50)                 fake-igd (192.168.1.10)                Router (192.168.1.1)
 ──────────────────                 ───────────────────────                ────────────────────
 1) M-SEARCH  ── multicast 239.255.255.250:1900 ──►  everyone on the LAN hears it
                                        │
 2)           ◄── unicast "200 OK, LOCATION: http://192.168.1.10:5000/rootDesc.xml"
                                                                           (UPnP disabled → silent)
 3) GET /rootDesc.xml  ─────────────────►   "router" description + control URL
 4) SOAP GetExternalIPAddress  ─────────►   returns the real public IP
 5) SOAP AddPortMapping UDP 3478 ───────►   LOGGED  (+ accepted / rejected)
 ...
 Game / chat traffic of the PS5  ════════════════════════════════════════►  Router → internet
                              (does NOT go through fake-igd, it uses the default gateway as always)
```

1. **Discovery (SSDP):** the PS5 sends a multicast `M-SEARCH` to the LAN looking for an "InternetGatewayDevice".
2. **Answer:** whoever is a UPnP router answers with the address (`LOCATION`) of its XML description - here fake-igd. **LOCATION must point to fake-igd**, because that is where the PS5 sends the requests from steps 3-5 that we want to log. These are just a few small HTTP messages.
3. **Device description:** the PS5 downloads the XML and finds the URL of the `WANIPConnection` service in it.
4. **Queries:** `GetStatusInfo`, `GetExternalIPAddress`, ... - **the public IP must be real** (`"external_ip": "auto"`), because the PS5 may tell peers about it; fake-igd must not report a fake one.
5. **Port requests:** `AddPortMapping` (protocol, external port, internal IP and port, lease duration, description). A real router would create a DNAT rule; fake-igd only logs it.

### What this means for the PS5

- Traffic, gateway and DNS **do not change**. If fake-igd crashes, the PS5 keeps working as before.
- The only side effect is what the PS5 **believes** about open ports:

| `mapping_response` | What the PS5 gets | Consequence |
|---|---|---|
| `accept` (default) | "OK, port opened" | The PS5 may tell peers `public_IP:port` that is not actually open; the direct connection then fails and the game/chat falls back to a relay or another path - the same as without UPnP. Benefit: the PS5 keeps sending further requests → you capture all ports. |
| `reject` | error `501 ActionFailed` | The PS5 knows the port is not open and behaves exactly as without UPnP. The request is still logged. Some games stop asking for more ports after an error, so you may capture fewer. |

- `"mode": "passive"`: fake-igd **does not answer at all**, it only logs who is looking for a UPnP router on the network (and announcements of other UPnP devices). The PS5 is not affected at all, **but you will not learn the ports** - without an answer the PS5 never sends `AddPortMapping`. Useful to check who uses UPnP on the network, or whether there is another UPnP router.

**Recommended workflow:** run `mode: active` + `mapping_response: accept`, go through the connection test, party chat and the games you play on the PS5, then run `upnp ports` and `upnp dnat`, set the ports as DNAT on the router and switch fake-igd (`sudo upnp response reject`, `sudo upnp mode passive`) or stop it (`sudo upnp stop && sudo upnp disable`).

### What if something else on the network offers UPnP?

If the real router (UPnP enabled) or another device answers as well, the PS5 uses whichever answers first, so the result is unpredictable. fake-igd logs a warning `<< OTHER UPnP ROUTER ON THE NETWORK!` as soon as it sees an announcement from another IGD, and `upnp test` lists every device that answers.

---

## Configuration `/etc/fake-igd/config.json`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"active"` | `active` = answer like a UPnP router, `passive` = only listen and log |
| `mapping_response` | `"accept"` | `accept` = confirm AddPortMapping (nothing is opened), `reject` = refuse with error 501 |
| `http_port` | `5000` | TCP port for the device description and SOAP (update the firewall when changing it) |
| `external_ip` | `"auto"` | Public IP reported to clients. `auto` = detect via api.ipify.org / ifconfig.me |
| `interfaces` | `[]` | Interfaces to listen on (`["ens18", "ens19.20"]`). Empty = all |
| `exclude_interfaces` | `["lo"]` | Interfaces to skip, typically WAN if the server has one |
| `allowed_clients` | `[]` | Who to answer: IPs or subnets (`["192.168.1.50", "10.0.20.0/24"]`). Empty = everyone |
| `ntfy_url` ... `ntfy_ca_file` | | Notifications via ntfy - see *Notifications* above |
| `notify_other_router` | `true` | Notify when another UPnP router announces itself |
| `notify_on_renew` | `false` | Also notify on renewal of an already known mapping |
| `log_level` | `"INFO"` | `INFO` = all requests and events, `DEBUG` = also every packet and HTTP request |
| `log_file` | `/var/log/fake-igd/fake-igd.log` | Main log |
| `request_log` | `/var/log/fake-igd/requests.jsonl` | Machine-readable request log |
| `state_dir` | `/var/lib/fake-igd` | State (current mappings) |
| `interface_rescan_seconds` | `60` | How often to check for new/removed interfaces (VLANs, DHCP) |
| `notify_interval_seconds` | `300` | `ssdp:alive` announcement interval in active mode |
| `site_name` | `""` | what the pages call this installation (empty = the host name) |
| `web_allow` | RFC 1918 | who may reach the pages (nginx allow, and the firewall's 80/443); empty = everybody |
| `session_idle_minutes` | `120` | a sign-in to the pages ends after this long without a request |
| `api_port` | `9862` | the pages' API, on 127.0.0.1 only |
| `firewall` | `false` | iptables: the chain `FAKE-IGD-IN` (install.sh switches it on where iptables is in use) |
| `firewall_ssh` / `firewall_icmp` | `true` | the chain lets SSH (tcp 22) / ping in |
| `upgrade_url` | this repository's `release/` | where new versions are looked for: a GitHub folder, a page with links, or one package |
| `upgrade_check` | `true` | look there once a day (for the pages; nothing is put in by itself) |

After changing the configuration: `sudo systemctl restart fake-igd` - or use `sudo upnp config set KEY VALUE`, which restarts the service automatically.

> The service runs in a systemd sandbox (`ProtectSystem=strict`). It can only write to `/var/log/fake-igd` and `/var/lib/fake-igd`. If you move `log_file` or `state_dir` elsewhere, add the path to the unit as `ReadWritePaths=`.

## All interfaces

fake-igd joins the SSDP multicast group on **every** active IPv4 interface (including VLAN interfaces such as `ens18.20`) and checks for changes every minute. Each answer carries the address of the interface through which the client is reachable, so the server can sit in several VLANs at once. SSDP answers are sent from source port 1900, like real routers do.

If the server has an internet-facing interface, add it to `exclude_interfaces` and do not open the ports on it.

## What gets logged

Lines as otp writes them - `time level what: words` - so the live views colour them the same way.
Example `/var/log/fake-igd/fake-igd.log`:

```
2026-11-16 18:10:00 info  net: listening on ens192 (192.168.40.27) - http://192.168.40.27:5000/rootDesc.xml
2026-11-16 18:12:01 info  ssdp: 192.168.40.239 is looking for a UPnP device (ST=urn:schemas-upnp-org:device:InternetGatewayDevice:1, UA=...)
2026-11-16 18:12:02 info  http: 192.168.40.239 fetched the device description (via 192.168.40.27)
2026-11-16 18:12:02 info  soap: 192.168.40.239 -> AddPortMapping {"NewExternalPort": "3478", "NewProtocol": "UDP", ...}
2026-11-16 18:12:02 info  port: UDP 3478 -> 192.168.40.239:3478 asked by 192.168.40.239 (lease 3600s, '...') - accepted, new
2026-11-16 18:12:02 info  notify: sent 'UPnP: UDP 3478' to ntfy.example.com (HTTP 200)
2026-11-16 18:30:00 info  port: UDP 3478 -> 192.168.40.239:3478 asked by 192.168.40.239 (...) - accepted, renewed
2026-11-16 19:12:02 info  port: UDP 3478 of 192.168.40.239 expired
2026-11-16 19:20:00 warn  ssdp: OTHER UPnP ROUTER on the network: 192.168.40.1 announces NT=urn:schemas-upnp-org:device:InternetGatewayDevice:1
```

## Troubleshooting

| Symptom | What to check |
|---|---|
| `upnp test`: "Nobody answered", unicast probe answers | The host firewall drops multicast SSDP → `upnp firewall` and apply the rules. |
| No `SEARCH` from the PS5 | Server not in the same VLAN; switch with IGMP snooping and no querier drops multicast; firewall blocks 1900/udp (`upnp firewall`); the interface is in `exclude_interfaces`. |
| `SEARCH` but no `DESC` | Firewall blocks `http_port`/tcp; another device also answers SSDP (look for "OTHER UPnP ROUTER" in the log, `upnp test --st ssdp:all`). |
| Service does not start | `journalctl -u fake-igd -e` - typically port 5000 or 1900 is in use (`ss -lunp \| grep 1900`, e.g. another UPnP/DLNA server) or invalid JSON in config.json. |
| SELinux | `ausearch -m avc -ts recent` |
| Test without a PS5 | `upnp test` or `upnp test --add 40000/udp`; alternatively `dnf install epel-release miniupnpc` and `upnpc -s` |
| `upnp: command not found` with `sudo` | The CLI lives in `/usr/bin/upnp` - check the installation finished (`ls -l /usr/bin/upnp`). |
| `upnp` says "Permission denied" | Join the group: `sudo usermod -aG fake-igd $USER` and log in again, or use `sudo upnp ...` |
| Python 3.14 was not installed | Update the system (`sudo dnf upgrade`, AlmaLinux 9.8+ needed) or `sudo ./install.sh --python-from-source`. Build log: `/var/log/fake-igd-python-build.log` |
| Tab completion does not work | Open a new shell; the `bash-completion` package must be installed. |
| The pages say the API is not answering | `systemctl status fake-igd-api`, `journalctl -u fake-igd-api -n 50` |
| The pages say the token is unreadable | `ls -l /run/fake-igd-api/` (group `fake-igd-web`), SELinux: `ausearch -m avc -ts recent` |
| `upnp upgrade` waits for root | `systemctl enable --now fake-igd-upgrade.path`; `journalctl -u fake-igd-upgrade` |
| An upgrade was refused | `upnp upgrade status` says why (not signed by a trusted key, a file changed, older than installed) |
| Locked out by wrong passwords | wait ten minutes, or `sudo upnp user passwd NAME` |
| A client searches (`ssdp:`) but never fetches the description (`http:`) | Our SSDP answer does not reach it: a firewall on the way back, the client in another VLAN than the interface that answered, or another UPnP device answering first (`upnp test --st ssdp:all`). Look at its lines: `upnp log --grep 192.168.x.y -n 0` |
| `upnp notify-test` says 401 / 403 | Wrong or missing `ntfy_token` / `ntfy_user` + `ntfy_password`, or the token may not write to the topic. |
| `upnp notify-test` says TLS | A private server with its own CA: `sudo upnp config set ntfy_ca_file /path/to/ca.pem`. |
| `upnp mdns services` says avahi-browse is missing | `sudo dnf install avahi-tools` |
| A `upnp mdns` change was put back | avahi-daemon did not start with it - `upnp mdns log -n 30` says why; the previous file is in place again. |
