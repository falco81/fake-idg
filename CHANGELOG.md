# Changelog

Every change of the application gets a version of its own (X.Y.Z), as otp's.

## 1.7.3 (2026-11-17)

- **No more "the parts root installs are from before it" after every upgrade.** The new API starts in the
  middle of install.sh --upgrade, before install.sh has put root's parts in and written root-facts.json,
  and wrote it down as something to be done by hand. "To be done by hand" is no longer looked at while an
  upgrade goes on, and is looked at again as soon as install.sh has written root-facts.json - not ten
  minutes later. An entry already shown goes by itself once the new pages read it.
- **System updates: Stop it** (otp's). dnf is stopped while it asks and downloads - nothing is put in, the
  update is said as "stopped by NAME" in the card and the events. Once dnf puts the packages in, it
  finishes: stopped there, the system would be left half updated (otp too lets the node being updated
  finish) - the button says so.
- **Backups: Download one here without a password** (otp's): asked "Download a backup that is not
  locked?", it gives the .tar.gz not locked, written in the events as such. A backup sent to a
  destination is never unlocked, as before.

## 1.7.2 (2026-11-17)

Everything gone through once more against otp 1.0.288, in its code and side by side on the screen.

- **SNMPv3, as otp's** (Settings → Monitoring): the pages' API answers it itself - GET, GETNEXT, GETBULK,
  authPriv only (USM: HMAC-SHA-1/-256/-512, AES-128/-256; otp's AES in Python where `cryptography` is not
  there), the system group and FAKE-IGD-MIB (deploy/FAKE-IGD-MIB.txt: services, requests and ports
  asked/refused, devices, mappings, mDNS reflector, alerts, certificate, machine, disks, mail, logs,
  upgrade, every /metrics sample as a table). Traps when something goes wrong and when it is right again,
  a test and a test trap on the pane, the MIB to download, the alert "The SNMP agent not listening". The
  firewall opens its UDP port while it is on; fake-igd-api.service gets CAP_NET_BIND_SERVICE (port 161).
- **Upgrades in maintenance, as otp's**: no red "not answering" while an upgrade runs. Root's helper and
  install.sh --upgrade (by hand too) write their progress where the pages read it without the API: a band
  on every page (percent, step N of M, how long, "not answering for N s" while the API or nginx/PHP
  restart), the pill "in maintenance", the cards "maintenance" / "upgrading", no service-down alert; at
  the end the page loads the new version by itself. /healthz says "maintenance". A failed one: a red band.
- **Certificates and TLS, every function of otp's**: the chain checked and completed (missing authorities
  fetched from their CA Issuers address, or uploaded), a private CA's root kept to check with, RSA and
  ECDSA together, the second certificate's chain, Download in otp's formats (PEM, full chain, DER,
  PKCS#7, PFX with the key, PEM with a locked key), Back to the one before; **DH parameters made with
  otp's progress bar**, and made once (not again at every save). No false "root has not taken it yet":
  a long DH, or an answer overwritten before the pages saw it, is no longer "late"; the trusted roots
  are "nothing added", green, as otp's.
- **The service**: the buttons of the units in columns by their kind (log, Reload, Restart, Stop/Start).
- **Network**: IPv4 and IPv6 in one grid of five columns, each field under its fellow; the warning as
  wide as the sections, 14 px from them.
- **UPnP network** and **mDNS reflector**: the interfaces in a card of their own across the page, the
  description's address and its copy button on one line, each address on its own line, what avahi
  does on each interface.
- Settings asleep while a switch is off woke up again when it was switched on only after a save - they
  wake at once now (a switch says 1/0, the rules true/false).
- Mail and ntfy: the authority pasted is saved with the save bar (otp's way, no "Add it"); Outgoing mail
  suggests its fields; System updates shows any dnf run with otp's progress card; Overview's service card
  "vm · version · up N"; the popups of Ports and Clients no longer overflow; smaller fixes in How it
  answers, Alerts, Syslog and SIEM, Time, Backups and About (otp's words for its settings).

## 1.7.1 (2026-11-16)

- **Certificates and TLS**: "root has not taken it yet" no longer said of a certificate root did put in -
  the trusted roots, read by themselves on the same pane, overwrote the answer before the pages saw it.
  Root now keeps the short answers of the last 20 asks of each kind beside the newest one, and every pane
  finds its own ask's answer among them.
- **Certificates and TLS**: otp's **Root** and **Sent** on the certificate's card - what the chain leads
  to, and what nginx sends now, checked on 127.0.0.1:443 by the certificate's name: whether it is the
  certificate in the file at all (nginx not reloaded since says so, with the one it still answers with),
  then as curl and every client that fetches nothing checks it, with the system's roots.
- Gone through against otp's own tables (its ONLY_WHEN and NAMES): Mail - the sender, the waits, EHLO and
  the lists asleep while sending is off, the account and password while signing in is none; Restart - On
  the day only for a weekly restart; ACME - "The TXT records go into" asleep for acme-dns, its directory
  before the CA as otp's.
- The CA's certificate of ACME and of Syslog and SIEM in a box of the grid, as otp's, not a row of its own.

## 1.7.0 (2026-11-16)

**Everything gone through again, against otp, element by element** - every tab and every pane of
Settings, side by side with otp's running pages: the same cards in the same order, the same headings,
notes, controls, popups and behaviour; what otp has and fits one fake-igd server added.

- **The shell**: otp's sign-in page (with its picture, and the second step), header (the load meter,
  the account popup: what you may do, Edit the columns, your settings in a file, a new password), bars
  (php2shell, problems, trials on every page), Overview (cards that say why they have their colour, the
  chart opening the hour pressed, facets with when last seen), Ports / Requests / Clients / Mappings as
  otp's Tokens and Log (filters, otp's search language `field:value` NOT/OR, pager, a popup for every
  row), Events with the daemon's own log, the settings drawn by otp's own code (the (i) panel with the
  command line, only_when chained), a password that must be changed is asked for first.
- **Accounts**: otp's pane - the role in the row, switched off/on, a password set or made (shown once),
  must change at the next sign-in, sign-in history, Signed in now, Locked out (counted by name and by
  address, cleared by hand), the policy; **a second step by an app (TOTP)** for these accounts.
- **Upgrades**: otp's pane - To be done by hand (checked by itself, Done, a count beside Upgrades),
  this server, From the web (choose among the newer versions, what is new in each), a new version sent
  from the browser, going back to an older one (off unless switched on; never below 1.4.0), the upgrade's
  bars live, what root said. `upnp upgrade after`, `--downgrade`.
- **About** (what runs where, PHP as php-fpm runs it, the README and what is new, the console at login,
  debug and the performance meter) and **The service** (every unit: state, restarts, memory, its journal;
  restarted, stopped, started - asked twice where it hurts).
- **fake-igd's own panes**: what listens where now and a *Try it* that asks fake-igd as a PS5 does, step
  by step; the ntfy test with its steps and the server's own CA; interfaces picked from a list; **mDNS**:
  the daemon as it runs now, copies of avahi-daemon.conf put back, a live view of services coming and going.
- The panes of 1.6.0 reviewed: TLS (the system's trusted roots; the name the browser used vs the
  certificate's and nginx's names; the dialogs filled from it), ACME (where the names come from; the
  exact record missing when DNS-01 fails), Firewall and access (the health check's own list; behind a load
  balancer - real IP), SSH, **Network (every IPv6 method NetworkManager has - link-local included -, the
  form started from what nmcli has now, an IPv4 change leaves IPv6 alone)**, Time, Power, Disks, The
  database (dumps, the key beside each copy, erasing collected data), Backups, Mail (XOAUTH2), Alerts
  (failed backups, logs not reaching syslog), Syslog (sent as it happens), Proxy (ACME's DNS APIs).
- **Secrets sealed** as otp seals them (a key beside the database, `secrets.key`): mail, proxy, backup
  destinations, the metrics token, the ACME account key and DNS API tokens; 1.6.0's are sealed in place.
- `upnp user`: `must-change`, `off`/`on`, `reset-2fa`, `lockouts`, `clear`.
- Sign-ins last 12 hours at most; 5 wrong passwords for a name or 50 from an address in 15 minutes hold
  them back (Settings → Accounts).

## 1.6.0 (2026-11-16)

**Every setting of otp's that fits fake-igd, on the pages, as otp's** - each pane copied from otp's markup
and drawing, one server (no cluster), each change of the system done by root through a queue of asks
(`/var/lib/fake-igd/web/ask/`, `fake-igd-web.path`), every value checked again by root, a copy kept and
put back when a check fails, every change in the events.

- **Certificates and TLS**: the certificate as it is (chain checked, fingerprint), put in as PEM or PFX,
  a request (CSR), self-signed again (names and addresses), TLS settings as otp's (presets, protocols,
  ciphers, DH, HSTS); root writes nginx's files, asks `nginx -t`, puts the old back when it says no.
- **Automatic certificates (ACME)**: Let's Encrypt or any ACME CA, HTTP-01 (port 80 - opened to anybody
  in FAKE-IGD-IN while it is used) and DNS-01 (by hand, RFC 2136, Cloudflare, deSEC, acme-dns), RSA and
  ECDSA, ARI, renewed by itself, every order step by step.
- **Firewall and access**: who may reach the pages, the firewall on/off, your own rules (IPv4 and IPv6)
  before what fake-igd needs, each built-in rule switchable, the whole firewall as iptables-save shows it,
  **every change on trial** - put back by itself unless kept, a banner on every page.
- **SSH server and notices** (on trial, `sshd -t`; FAKE-IGD-IN follows SSH's port), **SSH keys**
  (users' keys added, made, taken away; root's shown and exported, as otp's), **Local users** (made,
  password, sudo, locked, aging, the password policy, the console at login).
- **Network** (each interface by NetworkManager, the host name - on trial), **Time** (chrony: sources,
  servers, a step, the time zone), **Restart and power off** (now, later, on a schedule).
- **Disks and logs** (the journal's cap, fake-igd's log rotation), **The database** (copies, how long
  events are kept, vacuum, download, put back), **Backups** (FTP, FTPS, SFTP, SCP, SMB or a folder,
  locked with a password, on a schedule, put back), **Export and import**.
- **Mail** and **Outgoing mail** (STARTTLS/SMTPS, PLAIN/LOGIN/CRAM-MD5, straight to MX, retried),
  **Alerts and reports** (service, API, avahi down, another UPnP router, a new version, a disk filling,
  the certificate running out, a failed upgrade, updates waiting; the report of the week),
  **Monitoring** (Prometheus `/metrics` with a token; SNMPv3 left out - it needs AES the standard library
  does not have), **Syslog and SIEM** (UDP/TCP/TLS; JSON, CEF, RFC 5424), **Proxy** (for the upgrades,
  the system updates, ACME and ntfy), **System updates** (dnf, a restart offered when needed).
- install.sh: the packages these need (NetworkManager, chrony, openssh, samba-client, bind-utils,
  dnf-plugins-core, libpwquality); /metrics and ACME's port-80 location put into an existing
  `fake-igd.conf` (a copy kept, `nginx -t` asked, put back if it says no).
- Checked: every pane and tab in a browser at 1920×960 and 1280×720 - one scroller each, no page errors;
  each pane's root part run against temp files and stand-in tools. Not run on AlmaLinux itself yet.

## 1.5.3 (2026-11-16)

- **No double scrollbar on a long list**: a table of more than 50 rows (156 mDNS services) was paged
  into a box that scrolled by itself inside the held one. A list in a held card is drawn whole now, in
  its one scrolling box (mDNS, Ports, Clients, Mappings), and nothing inside a held box ever scrolls by
  itself. Checked with 160 services, 100 ports and 70 clients at 1920×960, 1366×768 and 1280×720.
- mDNS: the four large cards over the list became otp's tiles inside the list's card (as otp's
  Enrolment) - on a smaller screen they pushed the list into a second scroller.
- The package is made from what is committed (git archive), never from what lies in the working folder.

## 1.5.2 (2026-11-16)

- **The upgrade to 1.5.1 did not start** (`No module named 'igd_panes'`): install.sh put in the
  program's modules by a list, and the new one was not on it - the version before was put back by
  itself, as it should. Every module of the package is put in now, and none an older version left behind.
- The base for the panes of Settings (each one's markup, script, API and root's part in files of its
  own), root's asks in a queue of their own (`/var/lib/fake-igd/web/ask/`, `fake-igd-web.path`
  watches it) - nothing new on the pages yet.

## 1.5.1 (2026-11-16)

- mDNS: when avahi-browse ends with an error, the error is said on the page - it was shown as a network
  with nothing on it. With `cache-entries-max=0` (no records kept, so avahi-browse is shown nothing while
  the reflector reflects all the same) the empty list says so, and how to see the services.
- The API's base for the panes of Settings to come (igd_panes.py) - nothing changes on the pages yet.

## 1.5.0 (2026-11-16)

- **The pages as otp's, one scroller everywhere**: every list tab (Ports, Requests, Clients, Log,
  Events, mDNS) is one held card whose table scrolls under headings that stay - the page itself never
  scrolls beside it, as otp's (`data-hold`, `.scroll.rowsonly`). The log no longer scrolls twice: its
  box scrolls, never the text in it. The rules for the router moved from a second card on Ports into a
  window of their own (*Rules for the router*).
- **otp's time picker** in place of the plain lists of hours - Overview, Ports, Requests, Clients,
  Events: a window stepped back and forth (‹ ›), quick choices, a calendar; the API takes `since` and
  `until`.
- **Search / Clear** beside every search box, as otp's.
- The settings menu hides at the left edge and slides out when pointed at, as otp's (the pin keeps it
  open).
- **mDNS on the pages** - the reflector avahi-daemon on this server, complete:
  - a tab of its own, **mDNS**: the daemon, the reflector, its interfaces (and those missing), and every
    service mDNS shows now (avahi-browse -a -r), filtered by words, interface and IPv4/IPv6, each with all
    it says;
  - **Settings → mDNS reflector (avahi)**: every key of `avahi-daemon.conf` fake-igd knows (the
    reflector, allow/deny-interfaces, reflect-filters, reflect-ipv, IPv4/IPv6, the cache, the rate limit,
    wide-area, publishing) in the same settings as the rest; saved, root changes the file line by line
    through `upnp_mdns.apply` - its comments kept, a copy beside it, put back when avahi-daemon does not
    come up with the change - and restarts it; the daemon restarted, stopped or started; its journal.
  - The API runs with the group `systemd-journal` for avahi-daemon's journal.

## 1.4.1 (2026-11-16)

- install.sh says where the pages are by name **and by every IPv4 address** of the machine
  (`https://192.168.40.27/admin/`), at the end of an install and of an upgrade.
- The self-signed certificate names the machine's addresses too, and every name nginx answers with.
  One made by 1.4.0 (signed by itself, without them) is made again by the upgrade - the one before
  is kept as `fake-igd.pem.before-1.4.1`; a certificate of your own is never touched.
- The firewall: the rules of 1.3 put straight into INPUT by hand (`upnp firewall | sh`,
  `--comment fake-igd`) are taken out - live and from `/etc/sysconfig/iptables` - when FAKE-IGD-IN
  is put in place; the chain does what they did. Every other rule of INPUT stays as it is.

## 1.4.0 (2026-11-16)

- **Upgrades from the web**, copied from otp step for step: `upnp upgrade check | online [VERSION] |
  file PATH | status | follow | log`. `upgrade_url` (by default this repository's `release/` folder)
  is read through GitHub's API (its own page when the API refuses), any web page by its links, or one
  package's address; HTTPS only. The package is checked by `fake_igd_upgrade.py --inspect` (otp's
  `otp_upgrade.py`): signed with Ed25519 by a release key in `/opt/fake-igd/release-keys/` (MANIFEST
  with the SHA-256 of every file, MANIFEST.sig), every file the one signed, nothing else in it, not
  older than what is installed. It is laid down in `/var/lib/fake-igd/upgrade/` with `request.json`;
  `fake-igd-upgrade.path` starts root's part, which checks it all again and runs the package's
  `install.sh --upgrade --yes`. Followed on the terminal with a progress bar (colorama). Going back:
  `upnp upgrade file OLDER --downgrade`, as root only. The console: menu 14 Upgrades.
- **The installer** rewritten in the shape of otp's: `==>` steps, a few questions (`--yes` takes the
  defaults), `--upgrade`, `--uninstall [--purge]`, `--no-web`, `--server-name`, `--admin-allow`,
  `--admin-user`, `--admin-password -`, `--cert/--key`, `--firewall/--no-firewall`. An upgrade keeps
  the version before and puts it back when the new one does not start.
- **The web pages**, otp's administration pages for fake-igd - the same `core.js` and stylesheet,
  the same sign-in page, header, tabs, settings rail, popups and save bar: Overview, Ports (with DNAT
  rules for the router), Requests, Clients, Mappings, Log (live, coloured, grep), Events, Settings
  (How it answers, Network, Notifications with a test, Logs and state, Accounts, Pages and firewall,
  The service, Upgrades - from the web or a package sent from the browser, About).
- **nginx** (TLS, an allow list, sign-in rate limits, no multipart bodies), **a php-fpm pool** of its
  own (`fake-igd-www`, PHP that only relays, php2shell guard) and **the API** `fake-igd-api.service`
  (127.0.0.1:9862, its token in `/run/fake-igd-api` for the group `fake-igd-web`), as otp's.
- **Local accounts in SQLite** (`/var/lib/fake-igd/fake-igd.db`): full admin / read only, scrypt
  hashes, wrong passwords counted by address and name, sign-ins that end; `upnp user list | add |
  passwd | role | note | del | sessions | end`; every change and sign-in in the events.
  The console: menu 15 Web pages and accounts.
- **The firewall as otp's: iptables**, a chain of fake-igd's own, `FAKE-IGD-IN`, jumped to first from
  INPUT, ACCEPT rules only (loopback, answers, SSH, ping, 1900/udp, http_port/tcp, 80/443 from
  web_allow), put in with `iptables-restore --noflush` and kept in `/etc/sysconfig/iptables` between
  `# fake-igd:` lines; `upnp firewall --apply | --off | --status`. firewalld is used only where it runs.
- New settings: `site_name`, `api_port`, `session_idle_minutes`, `web_allow`, `firewall`,
  `firewall_ssh`, `firewall_icmp`, `upgrade_url`, `upgrade_check`.
- Versions are X.Y.Z from now on; `tools/release.sh KEY` makes a signed package into `release/`.

## 1.3

- The console `upnp --console` (otp's), the mDNS reflector (avahi), ntfy notifications, PTR names.
