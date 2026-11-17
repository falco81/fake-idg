# Changelog

Every change of the application gets a version of its own (X.Y.Z), as otp's.

## 1.7.7 (2026-11-17)

**SELinux, as otp's** (otp 1.0.288's, for one server):
- **Its own policy module** `fake_igd_server` (deploy/fake_igd_server.cil, as otp_server.cil): the API's
  run folder (/run/fake-igd-api - its token and port) labelled as the web server's own run files, so the
  pages (php-fpm, httpd_t) read it under enforcing; systemd may set owner and mode in it. Compiled with
  secilc against a full reference policy.
- **install.sh** (install and every upgrade, --no-web too): puts in what SELinux needs (policycoreutils,
  libselinux-utils, policycoreutils-python-utils, audit, selinux-policy-targeted) and starts auditd where
  SELinux is on - never changes its mode; loads the module only when it changed (semodule -i, the copy
  last put in kept as .in-policy); takes the old hand-made fcontext rule away; says when the folder is still
  not labelled; root-facts.json says whether the module is in. **uninstall.sh** takes the module away.
- **Settings → SELinux** (Access): otp's SELinux card - the mode, fake-igd's module, the labels of the
  API's folder, its token and the pages, the boolean that lets the pages ask the API
  (httpd_can_network_connect), the SSH server's port, and what SELinux refused since fake-igd's needs were
  put in (from the audit log, less what the policy allows now - audit2why); the steps as otp's: Make it
  ready (and permissive), Enforce (only from permissive, with nothing missing and nothing refused),
  Permissive again; the report to download. Looked at two minutes after the start, then every half hour;
  every step in the events. Done by root (deploy/root_selinux.py), which works out what fake-igd needs
  itself - never from the request.
- **Command line**: `sudo upnp selinux [check|prepare|apply|enforce|permissive|report [FILE]]`; the
  console's "Certificates, updates, time, tests" has otp's three items.
- **Alert** "SELinux refusing" (off as it comes, as otp's); **To be done by hand**: the module in the
  policy is not this version's; SELinux refuses fake-igd something.
- Not ported (otp's only): RADIUS, PostgreSQL and load-balancer labels, the cluster's cards, High security's
  rows, the SELinux part of a backup.

## 1.7.6 (2026-11-17)

Round 4, run 3 of 3 (the last): everything of runs 1-2 checked again, a last side-by-side with otp, a bug
hunt by reading every code path for errors and races, two administrators at once, the daemon under stress,
upgrades 1.7.4 → 1.7.5 → a test version through the pages in a sandbox, a security review of the whole tree.

**Sign-in and accounts, as otp's**
- Counted as otp counts it: a name may make four times "Wrong passwords before a pause" (20), an address
  ten times (50); wrong attempts before a right password stay counted; an attempt holds its place before the
  password is checked, so many at once no longer slip past the count (30 at once: 21 got through).
- One's own password typed wrong where it is changed is counted apart ("changing a password": 5 min) - it
  no longer locks the account out of signing in; Locked out, `upnp user lockouts` and the alert say which.
- Five wrong codes of the second step end that sign-in (otp 1.0.252).
- Accounts are made, switched off, changed and removed one at a time - two full administrators removing
  each other at once could leave none.

**Two administrators at once, a full disk**
- Two "Upgrade this server" or two network changes at once both went to root - one is told it is going on.
- No room on the disk (or no right to write) for a package, a backup, a dump, a copy: said plainly, not
  "the API broke".
- `sudo upnp user add|passwd` opened the database as root - with the API stopped, root made its -wal/-shm
  files and the API could no longer write; read as the fake-igd account now.
- The API queues a burst of requests (128) instead of resetting them (40 at once: 9 reset).

**The UPnP service, under stress**
- Its HTTP backlog 128 (50 devices at once were reset); 1100 AddPortMapping from 50 threads, 5000 questions
  from 100 threads, 3000 fuzzed SSDP packets, 300 idle connections - nothing crashed or hung, memory flat.
- A device gone mid-answer is a debug line, not a traceback; another UPnP router warned once an hour; a
  failing packet warned once in 10 minutes per address.

**As otp's**
- Events in otp's groups (sign-ins, starting and stopping, backups, certificates, ...), filtered by them.
- The Requests tab's badge: the refused of the last 24 hours, red - as otp's Log.
- `upnp export-config`, `import-config`, `power` (otp's --export-config, --import-config, --restart-nodes),
  in the console too.
- The units hardened as otp's: fake-igd.service with no capabilities, a system-call filter,
  RestrictSUIDSGID; fake-igd-api.service RestrictRealtime, RestrictSUIDSGID.
- `upnp config validate` checks what `config set` and the pages check (a JSON list slipped past).
- DH parameters of 2048 bits say "usually under a minute".
- README brought up to date with everything of 1.7.x.

## 1.7.5 (2026-11-17)

Round 4, run 2 of 3: deeper - every flow end to end with root's side running in a sandbox (TOTP, lockouts,
TLS dialogs, ACME against a test CA, firewall rules and trials, SSH, local users, upgrades and their rescue,
export/import round trip, mail through a test SMTP server), the shell's popups, the command line, the API
under load.

**Security**
- Root's helpers set the group of what they write into a folder the API's account owns BY NAME, after
  writing it - that account could lay a link there between the two and have root hand the group any file
  of root's. Now on the open file (fchown) - fake_igd_web.py, root_tls.py, root_osup.py, root_fw.py.
- install.sh no longer adds the person who ran it to the group fake-igd (which may write config.json, put
  into nginx and the firewall by root) - as otp, which puts nobody in its group; it prints the command.
- The self-signed key is made under umask 077 (it was readable by all until the chmod).
- A setting with a control character is refused; interfaces take interface names only.

**Fixed**
- Two saves of Settings at once lost one (12 at once: 2 lost) - one lock now.
- The API's background: one pane's background that raised skipped the others, a SystemExit killed it for good.
- A secret (a password, a token, a key) could never be taken away from the pages: now shown to a full
  administrator as dots and its last two characters, as otp; emptied and saved, it is taken away.
- A password made by the pages or `upnp user` was always 16 characters - refused by a policy asking more.
- Clearing a locked-out address cleared every name tried from it too (and the other way round).
- A local user made on the pages was "not a user who may sign in" for SSH keys until its next read.
- ACME's "Try port 80" said "HTTP 200" as an error when port 80 did not answer.
- install.sh --upgrade put the package's logrotate file over what Settings → Disks and logs had set; a run
  again switched the firewall back on after it was switched off on the pages.
- uninstall.sh stops every unit of fake-igd, takes its SELinux label and run files away; --purge also the
  net and root state folders and the copies of the certificate, nginx's file and the pool.
- Mail: what the receiving server said ("451 Greylisted", "550 ...") is kept; a mail without From was sent
  as MAIL FROM:<None>; a test alert to a wrong address held the real alerts back for 15 minutes.
- mDNS tab: avahi-browse missing is said in the list (it was HTTP 400); whole numbers 0-9 only.
- Settings import of 1-2 MB was refused by PHP.

**As otp's**
- The UPnP service: ssdp:byebye on every interface when it stops; BOOTID grows (the start time); a search
  that came in on an interface not used is not answered (as miniupnpd); LOCATION is the address of the
  interface the search came by; presentationURL leads to these pages.
- A failed scheduled backup is tried again an hour later, three times a day at most.
- The upgrade band says "- 1.7.x runs again" when the version before was put back.
- The console has otp's "Backups and the database" and "Certificates, updates, time, tests" menus.
- Mail and Outgoing mail are shown to read-only accounts (their buttons are a full administrator's).
- A mail about something over: "✔ N over, M still so".

## 1.7.4 (2026-11-17)

Round 4, run 1 of 3: every area compared with otp 1.0.288 again, and bugs hunted - in the pages (every
button and dialog, admin and read-only, wide and low screens) and in the application (the API with bad
input, root's helpers, the command line, security).

**The PS5 and the UPnP service**
- Every step of a device is logged and shown: its M-SEARCH (ST, MX, User-Agent), what was answered (ST,
  USN, LOCATION) or why not, each fetch of the descriptions, each SOAP question (GetExternalIPAddress,
  GetStatusInfo... - also in the request log, once a minute). The Clients tab has "How far it got"
  (searched · answered · description · service · SOAP · ports) and says where a device stopped; its popup
  shows the timeline.
- SSDP answered as UDA 1.1 / miniupnpd: the ST as asked, never a later version than the device has (an
  IGD:2 search was answered with IGD:1, which a strict client throws away); upnp:rootdevice and uuid:
  searches; a unicast M-SEARCH at once. New setting igd_version: 2 makes it InternetGatewayDevice:2 with
  WANIPConnection:2 (AddAnyPortMapping, DeletePortMappingRange, GetListOfPortMappings), as miniupnpd.
- Fixed: a bad Content-Length crashed the handler or held a thread; leases outside ui4 and non-IPv4
  internal clients were taken; any "GetTotal..." action answered; mappings held before a restart of the
  service were forgotten (mappings.json now read at start); no limit on mappings (1024 now); junk rows in
  the request log; the conflict line named the wrong address.

**Security**
- An account that must change its password could use the whole API (it could make a full administrator);
  now it may only change it, as otp.
- `?api=auth-login` (the generic road) handed the session token to the page's script and passed by
  nginx's count of sign-ins - closed.
- A name typed at sign-in could add a line to the events and syslog; "End it" with a short id could end
  several sign-ins; a backup folder under a link could make root write elsewhere - all fixed.

**Upgrades, backups, network**
- install.sh --upgrade stopped half way (any failure, Ctrl-C, a hang-up, the helper's deadline) puts the
  version before back - its program, root's helpers, units and pages, without the new version's extra
  files - as otp's upgrade rescue; the pages' band says failed, never "running" for ever.
- An older package sent after a good one no longer throws the good one away; a command-line mistake
  (--run of an older package without --downgrade) no longer leaves a red band on every page; "To be
  done by hand" is not judged while install.sh --upgrade runs by hand either.
- The network change: the timer that takes it back is started before anything changes - a helper that
  died half way can no longer leave a new network with no way back; /etc/hosts names right.
- A save of Settings with one refused value keeps nothing of it.

**As otp's**
- `upnp` does what the pages do: `upnp api`, `events`, `check`, `backup now|verify`, `db`, `updates
  check|start|stop|reboot`, `time sync`, `net`, `tls`, `acme order`, `mail-test`, `siem-test`, `proxy-test`,
  `snmp-trap` (root's key /run/fake-igd-api/cli-token; "root (command line)" in the events) - and in the console.
- Monitoring: the Zabbix 7.0 template "fake-igd by SNMP" to download; the engine ID shown while SNMP is off.
- Alerts: a clock that is off, a source blocked for guessing, a certificate the CA did not renew, a change
  on trial that went back; the administration's address in the mails with "Open in the administration".
- Accounts: the Signs in and Columns columns, Columns of the tables; the second step switched on ends the
  other sign-ins. A read-only account following a link to a full administrator's pane gets the first pane.
- The php2shell banner hidden where the distribution backported the fix; About in otp's order.

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
