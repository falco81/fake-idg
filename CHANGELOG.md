# Changelog

Every change of the application gets a version of its own (X.Y.Z), as otp's.

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
