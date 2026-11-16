# Changelog

Every change of the application gets a version of its own (X.Y.Z), as otp's.

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
