# Changelog

Every change of the application gets a version of its own (X.Y.Z), as otp's.

## 1.9.4 (2026-11-17)

- IPv6 on the MikroTik is information, not a fault: UPnP's AddPortMapping asks for an IPv4 port only, and a
  router that lets no IPv6 in to a device is as it should be. The Ports tab's MikroTik column says IPv4 alone
  (what the device asked for); Gateway → MikroTik shows IPv6 closed in grey with a lock and why ("the device
  did not ask for IPv6 - open it only if you want it reachable over IPv6"), its commands as optional.
- A device's IPv6 addresses seen (Gateway for devices → Edit): a list of their own under the form - looked up
  at once by its MAC - instead of chips that stretched the fourth column: DHCPv6 and EUI-64 ones first, the
  temporary (privacy) ones folded away; a row adds the address to the box and takes it out again. Which kind
  an address is is now told by its interface half: 2001:db8:…:1::3 is a DHCPv6 one, not "a temporary one".

## 1.9.3 (2026-11-17)

- Autorefresh never scrolls or jerks a page any more. Every redraw a timer starts is drawn as a refresh
  (`liveRefreshing()`, until somebody presses a key or the pointer): what did not change is not touched at all
  (liveFill compares and leaves the page alone), what did is put in place in one step with the scroll of the
  page AND of the boxes scrolled inside it (a table's rows) kept, folds kept open or shut, the box being typed
  in kept with its caret and suggestions. The Ports, Requests, Clients, Mappings and Events tables, Overview's
  facets and MikroTik card now redraw this way; the Gateway tab's empty chart is said at once (it collapsed a
  moment later); Gateway → MikroTik's firewall card is built once and only its changed parts are put in again
  (its search box, caret, open suggestions, "Show all" and opened address lists stay).
  The main tab bar stays one line on a computer: a count that arrived a moment later (mDNS) wrapped it to two
  lines at 1280 px and pushed every page down; under 1200 px the tabs not shown are icons with their counts.
  A test walks every tab, both Gateway sub-tabs and every Settings pane, scrolled to the middle and to the
  bottom, through three refreshes: scrollTop unchanged, layout shift 0.
- Gateway → MikroTik: each port is two rows, IPv4 and IPv6, each with its own state, commands and drops.
  IPv4: public:port → dst-nat → forward → device:port. IPv6 (no NAT): from the internet on its IPv6 WAN →
  the forward rule → each of the device's IPv6 addresses. Where the IPv6 addresses came from is said: set in
  Gateway for devices, or the router's IPv6 neighbour table by its MAC - then "these may be temporary (privacy)
  addresses" and, for full admins, "Set its DHCPv6 address" (opens the device's edit dialog). No IPv6 address
  known is said calmly, not in red. The port popup has an IPv4 and an IPv6 section side by side.
- Drops from the router's own log: a badge "dropped N× (last HH:MM:SS)" on an IPv4 or IPv6 row - red when the
  rules say open (the log contradicts them) - the last lines in the port popup (time, prefix, from, to,
  in → out), and per device "What the router dropped of it (its log)": IPv4 and IPv6 apart, top ports and
  prefixes, its last lines in a popup; "only rules with log=yes write lines, and the router keeps the last
  ~1000 in memory"; "nothing dropped in the lines the router keeps" when so.
- Interfaces in the firewall viewer explain themselves: a legend (green: running, red: not running - link
  down, "list: X": member of interface list X), the dots with tooltips, the list memberships as "list: discover"
  chips, disabled ones marked.
- Gateway for devices: a device has "IPv6 addresses" (only to find it on the MikroTik - nothing in this
  server's firewall; IPv6 is never forwarded here) with "Use what is seen" (its MAC in this server's and the
  MikroTik's IPv6 neighbour tables: stable DHCPv6/EUI-64 ones vs ones that may be temporary, press one to add
  it). Shown in the devices table and on the Gateway → Devices card.
- Popups of the Gateway tab: a rule's fields and the log lines wrap - no horizontal scrollbar.
- MikroTik: the device's IPv6 WAN is the interface of the router's default IPv6 route (/ipv6 route ::/0 -
  its immediate-gw, the network that holds its gateway); the router's log is read as well (/log - only the
  lines its firewall wrote kept) and each line laid to the device and port it was dropped toward, IPv4 and IPv6
  apart; whether a prefix means a drop is told by the rules that log under it (log-prefix, action).
- A device's IPv6 addresses changed alone put nothing of the firewall on trial (they are never in iptables).
- The Gateway tab: its heading and every card under it 16 px apart on both sub-tabs; a device's way out fills
  the width of its card; a line of code in a popup (an iptables line, a RouterOS command) wraps - no scrollbar
  of its own; the line of FAKE-IGD-FWD opens in a wide popup.

## 1.9.2 (2026-11-17)

**MikroTik: each device's own way out, and its ports on its own public address.** Nothing of the router is
assumed or typed in: for every device fake-igd walks a new connection to the internet as RouterOS does - the
router's interface that holds it, a VRF, mangle prerouting (mark-routing, mark-connection and the marks after
them, passthrough), /routing rule, the routing table and its route (longest prefix, distance, the gateway to
an interface: immediate-gw, gateway%interface, the connected network, recursively), the interface out, srcnat
(masquerade, src-nat, netmap, accept) - and so the public address the internet sees it as (igd_mtpath.py). A
rule that holds for some of the traffic only (a protocol, a port, some destinations) is said and passed. Its
ports are then checked on that address and interface - a dst-nat with dst-address= and in-interface= checked
as it is - and the filter's forward chain out to the device's own interface. A device that goes out as a
private address (LTE behind another NAT) is said so.
- The router's WAN without an interface list WAN: RouterOS 7's `immediate-gw` (6 said `immediate-gateway`)
  is read; else the default routes of every table; else the interface with the public address fake-igd
  knows; else the only one with a public address. /ip vrf and /routing rule are read too.
- **Fewer connections to the router.** Over ssh a read was one connection - one sign-in and sign-out in the
  router's log - for each of its ~28 menus; now a read is two (the identity, then every menu in ONE console
  line, each after a mark of its own; a RouterOS that does not know a menu - /ip vrf on 6 - fails the whole
  line, so the rest is read in one line again and that one said missing). Try reaching it: two as well. Over
  REST one TLS connection (HTTP keep-alive) for the whole read instead of one for each menu; the RouterOS API
  already kept one.
- **Every search box alike**: a cross that empties it and a button that offers what can be typed - the same as
  **Ctrl+Space** - inside the box. Ports, Requests, Clients, Events, the mail queue as before; now also
  Mappings (client: name: port: to: proto: description: by:, with -field: and field~part), the Log (the parts
  of fake-igd's lines, WARNING/ERROR, the addresses in the lines shown), Find a setting (every part of
  Settings, to go to), the users of a setting, and the MikroTik's firewall.
- An alert mail of a port not open on the MikroTik links to that port in Gateway → MikroTik.

- Settings holds only configuration again. Settings → MikroTik is how the router is reached and trusted (the
  form, Try reaching it, How to set it up, the certificate / host key / key, Read it now) with one status line
  and a link "See what was read in Gateway → MikroTik"; the per-port table and the whole firewall moved out.
  Fields that do not apply to the way chosen (its certificate, the authority, the name on the certificate over
  ssh; "Sign in with" over REST/API) are hidden, not shown as big dimmed blocks (new per-field `hide_asleep`
  option of the panes framework - every other pane unchanged).
- The Gateway tab has two sub-tabs, in the address: #gateway/devices (default) and #gateway/mikrotik, with deep
  links #gateway/devices/IP and #gateway/mikrotik/IP[/proto/port].
  - Devices: each device a compact card - sent today, now, its own DNS/rules, drops, a small chart, what it
    may reach, its UPnP steps, its way out and ports on the MikroTik - with Details (a wide popup: top
    destinations and ports, drops, ports asked for, its connections) and Its firewall, which opens the FW
    designer as a popup right there (read-only for read-only accounts; Try a packet and Save for full admins).
  - MikroTik: the router's strip (identity, RouterOS, how and when it was read, rules, WAN, its own UPnP,
    warnings, Read it now for full admins); for each device its WAY OUT drawn as nodes - device → its interface
    → VRF / mangle / routing rule (only those that exist) → route and table → the interface out (WAN) → the
    srcnat rule → the PUBLIC address (red when it goes out as a private address or has no way) - every node
    opens the rule; what holds for some traffic only; then its ports checked on that public address
    (public:port → dst-nat #n → forward #n → device:port, each hop opens its rule), the state, IPv6, the commands
    to copy; the rules still to add merged into ranges; then the whole firewall (IPv4/IPv6, filter/nat/mangle/
    raw, the search with suggestions - port: action: chain: proto: list: if: addr: state: comment: off: - long
    chains, interfaces and address lists folded to their first 12 with "Show all", the rules that concern a
    port asked for always in sight).
  - Not configured: a clean empty state; a full admin gets "Configure it in Settings → MikroTik" (the only
    jump from the main menu into Settings, as for Gateway for devices with no device).
- Links between the main tabs, never into Settings: a device card → Clients (its popup), Requests, Ports,
  Mappings, its way on the MikroTik; a port on the MikroTik → the Ports and Mappings tabs at that port; the
  Clients, Ports and Mappings popups of a gateway device or one the MikroTik knows → its card and its way out
  (and that port on the MikroTik); the Ports tab's MikroTik column → Gateway → MikroTik at that port; the
  Overview's MikroTik card → Gateway → MikroTik; an alert of a port not open on the MikroTik → that port there.
  Also by address: #clients/IP, #requests/IP[/proto/port], #ports/IP[/proto/port], #mappings/IP[/port].
- The FW designer of a device is one shared module (gw-designer.js) used by Settings → Gateway for devices
  and by the Gateway tab.

**Sign-in with Face ID, Touch ID or Windows Hello** (a passkey, as otp's):
- **Settings → Accounts → "...with Face ID, Touch ID or Windows Hello (a passkey)"** (off by default,
  asleep until *A second step when signing in to these pages* is on), as otp 1.0.254: the second step of
  signing in to these pages, never instead of the password. At its first sign-in an account chooses the app
  or a passkey and sets it up; then it gives it at each sign-in. Accounts → Reset the second step and
  `upnp user reset-2fa NAME` take the passkeys away too; Accounts (and `upnp user list`) say "a passkey", of
  which device for which name of the pages.
- **The checks of the server** (igd_webauthn.py, otp's, standard library only): ES256, RS256 and EdDSA
  signatures; the question used once (kept with the sign-in, taken by the one answer); its type; the origin
  and the name the pages were opened by (a name over HTTPS, never an address); the user present AND verified
  (face, finger or PIN); the counter may not go back (a copied passkey, said in the events). No attestation:
  only the public half is kept, in the account's row. Wrong answers are counted as wrong codes are (the
  address and the name, and the fifth on one sign-in asks the password again). Bounded as otp 1.0.262: CBOR
  8 deep / 64 items, RSA 2048-8192 bits with a small odd exponent.
- **A passkey is for a name**: offered on these pages opened by a name over HTTPS (`https://fake-igd.example/`);
  opened by an address it is not offered, and the page says why. The pages tell the API the name they were
  reached by (X-IGD-Host, from the browser's Host).
- **Your account → Passkeys - Face ID, Touch ID** (otp 1.0.257): the account's passkeys - the device, the name
  of the pages, added, last used; the pencil names one, the bin takes one away (asked twice; never the last -
  that is the second step itself, reset by another full admin). **Add a passkey of this device**, up to 10,
  only within 15 minutes of the second step given (otp 1.0.262; said before the button is pressed). In the events.

- **A new sign-in once the second step is given** (otp 1.0.149): the app's code or the passkey, set up or
  given, ends the sign-in the password alone opened and opens one with a new token - its cookie set by the
  pages (HttpOnly, SameSite=Strict, Secure over HTTPS, as at sign-in), never shown to the page. Whoever saw the
  cookie of the password-only sign-in gets nothing: it is refused at once. Two answers at once open one sign-in.

## 1.9.1 (2026-11-17)

- The Gateway tab no longer comes apart: its heading card was marked as the page's one long card, so opened
  before the data came it took the whole window, and the cards drawn after it slid over its text (bits of
  it showing between them). The heading is an ordinary card now.
- A device's chart with nothing in its window is one line, not 200 px of nothing; the six cards on top are
  6, 3 or 2 to a row, a device's eight figures 8, 4 or 2 - never one left alone on a row.

## 1.9.0 (2026-11-17)

- **Gateway for devices: each device's own firewall** (the FW designer: the firewall button of a device, or its
  "Allowed" column). By default - nothing set - a device reaches the internet only, exactly as before. Now:
  - **DNS servers it may ask**: udp and tcp 53 (optionally DoT, tcp 853) to exactly those addresses, also in a
    private network or another network of this server; one on its own network is reached directly ("no rule
    needed"). Offered: this server's resolvers and the router.
  - **Rules of its own**: destination (address or network), protocol (tcp/udp/icmp/any), ports (single, ranges,
    lists - fifteen at most), comment, on/off, order (arrows). Toward another network of this server: -i
    DEFIF -o THAT_IF for that device (+ its MAC) to that destination only, and the answers back (-m conntrack
    --ctstate ESTABLISHED,RELATED). Never toward everything (/0-/7 refused - the internet is allowed already),
    never this server itself, never the special ranges, never a network that only partly covers one of this
    server's (split it); 64 rules at most; checked again by root - the pages are never trusted.
  - Order in FAKE-IGD-FWD: each device's DNS lines → its own rules → its drops toward every local and private
    network (counted for it) → the drops for everybody → its internet line → the final DROP.
  - The designer: a flow (the device → this server → a lane for the internet, each DNS server, each rule, ✗
    for the local networks, the private networks, everything else) with each line's packets; DNS chips with
    DoT and offered servers; rules with arrows, switches and an inline editor (protocol segments, ports checked
    as typed with examples, destination with "a network of this server" chips); **Try a packet** (destination,
    protocol, port, "another box with its address") - the verdict and the line that decides, from root's own
    evaluator run on the lines as they would be; "What root puts in"; Save on trial (Keep it / Put the old back).
  - CLI: `upnp gateway dns IP add|del DNS [--dot]`, `upnp gateway rule IP list|add --to NET [--proto] [--ports]
    [--comment]|del N`, `upnp gateway try IP DEST PROTO [PORT]`.

- **The Gateway tab** (beside Mappings): cards with their "why this colour" (forwarding, devices on, sent today
  and the rate now, dropped by FAKE-IGD-FWD and toward local networks today, the router, this server's
  address there); a card for each device - online (neighbour table / last packet), its traffic over the time
  picker's window (bytes per bucket, drops marked), what it may reach besides the internet with each line's
  packets, its drops toward local networks by network, its UPnP steps and the ports it asked for, top
  destinations and top ports now, its live connections (conntrack, the way out only) with a popup for each,
  the MikroTik's word on its ports when Settings → MikroTik has read the router (hidden otherwise); and
  FAKE-IGD-FWD line by line as a flow, grouped, with every line's counters. Read-only accounts see it all.
  Refreshed every 20 s.
- Root reads the chain's counters and the connection table once a minute while the gateway is on (an ask of
  its own, kept apart from the pages' asks); the API samples them into the database (gw_samples, setting
  `gateway_keep_days`, 7) - root never writes the database. Per device a counted drop line toward every local
  and private network (before the drops for everybody).
- CLI: `upnp gateway top`, `upnp gateway conns IP`.

- **MikroTik, read-only** (Settings → MikroTik, in isemon's form): the real router read over its REST API
  (RouterOS 7, HTTPS), its API (api-ssl or api) or ssh (a key made here - ed25519, sealed beside the database - or
  a password). Only ever prints: anything else is refused in the code before it is sent. Its certificate trusted by
  its fingerprint after Try reaching it shows it (or checked by an authority and its name), its ssh host key pinned
  after Look at its host key - another one refused before anything, the password too, is sent. How to set it up on
  the router gives the read-only group and account, step by step. Through the proxy only where switched on.
- **Every port asked for, checked on the MikroTik**: first match wins, as RouterOS walks the first packet - raw,
  the dst-nat (missing, shadowed by rule #N, disabled, forwarded elsewhere), the filter's forward chain after the
  translation (RouterOS's default "drop all from WAN not DSTNATed" recognised), IPv6 to the device's own
  addresses; "cannot tell" where it depends on what cannot be known. The RouterOS commands that would add what is
  missing, with place-before, to copy - never sent. Its own UPnP on: a warning.
- **Its whole firewall, IPv4 and IPv6**: filter, nat, mangle, raw - each table's chains as lanes, each rule a card
  (its action in colour, its matchers as chips, disabled struck, dynamic marked, comments, counters and hits since
  the read before), what concerns the ports asked for lit, a search (port:, action:, chain:, list:, if:, addr:),
  a rule opened with all its fields; interfaces with their lists, the address lists.
- Overview: the MikroTik's strip (N of M ports open); Ports tab: a column MikroTik and its state in the port's popup;
  an alert "A port asked for not open on the MikroTik" (off by default); events; `upnp mikrotik
  [status|check|rules [ipv4|ipv6] [--table T]|read|try]`; console items 26-30.
- Notifications (ntfy): **What is sent** - every kind of event switched on or off, with a priority (1-5, or as
  set above) and tags of its own, and "Send a sample" (that event's own wording, marked "[a sample]").
  UPnP (fake-igd.service): a new port accepted, a port renewed, a port refused (reject 501, conflict 718, no
  room 728, invalid 402), a port taken away (DeletePortMapping / Range), a mapping ran out, a new device
  searching for a router (first time by address + User-Agent), a device that stopped after the answer (with
  the "make this server its gateway" hint), another UPnP router, the public IP changed (looked up every 30
  minutes when auto), an interface came or went, the service started/stopped, an unclean start after a crash.
  Gateway for devices (the pages' API): a device online/offline (neighbour table, its traffic), drops toward
  local networks over `ntfy_gw_drops_per_hour` (100), forwarding turned off by something else / FAKE-IGD-FWD
  not first, a device's own rule used for the first time. System: every alert of Alerts and reports (each
  alert kind can be left out) and its "over" message.
  As it comes: new port, refused, another router, public IP on - the rest off (what 1.8.1 sent, plus the
  refusals and the IP change). `notify_on_renew` / `notify_other_router` are kept and mapped.
- Quiet hours (`ntfy_quiet_from` / `_to`, this machine's clock): only `ntfy_quiet_priority` (4) and above
  go out; the rest are held and sent as one summary when they end (`ntfy_quiet_summary`), or dropped.
  Rate limit `ntfy_rate_per_hour` (30) for each kind, then one "N more" summary.
- What was sent: the kind of each, a filter by kind, the pages' own sends with fake-igd.service's; a send
  that failed (either's) is written to Events.
- `upnp notify list|on KIND|off KIND|test KIND` (`alert:KIND` too); console 10 → 4/5/6; completion.

- Fake ntfy server (fakentfy.py): HTTP and HTTPS with a self-signed CA (ca.pem), every POST captured.
- t_daemon.py - a running fake-igd.py, real SOAP and SSDP: 33/33 - as it comes (old config without
  ntfy_events), every UPnP kind (402/718 refusals, DeletePortMapping, a 1 s lease running out, device_new
  once, device_stopped after 60 s, other router, public IP change across a restart, crash marker, stop sent
  before exit), own priority/tags, all off, rate limit 2/h, quiet hours live (priority 4 passes, 2 held ->
  one summary at the end; dropped without summary), HTTPS with/without ntfy_ca_file, --notify-test.
- t_units.py: 36/36 - rate-limit summary after the hour (clock patched), quiet summary, midnight span,
  samples bypass off/quiet, legacy mapping, defaults, settings checks, the iface event (came/gone).
- t_api.py (env 4): 20/20 - view as reader, 403 for reader on sample/save, sample wording, save mirrors the
  legacy keys + restart, bad priority/tags refused, the grid keys, What was sent kinds + filter, a 401 sample
  in Events.
- t_bg.py (in process, env 4's database; fake neighbour table via FAKE_IGD_IP, fake ip_forward via
  FAKE_IGD_PROC_SYS, fake gateway.json, fake alert problems): 21/21 - online/offline (5 s wait in the test,
  180 s live), drops over the limit once an hour, forwarding off / not first, a rule's first packet, gateway
  off, alerts with a kind left out, over on/off, alerts off, the daemon's failed send in Events once.
- CLI: list/--json, on/off (alert:updates), test over HTTPS with the CA, a TLS failure explained, a priority 9
  refused by config set, config validate.
- Pages: shot.js (switch -> save bar -> Save -> saved; sample toast; kind filter), screenshots
  $S/r4/ntfy/shots1920, shots1280; all2.js at 1920 and 1280 (admin and viewer) and pop.js both sizes: no page
  errors, no DOUBLE.

## To know
- Every switch of a UPnP kind restarts fake-igd.service (config.json, SERVICE_KEYS); a gateway or alert kind
  only needs the API to read config.json again (within a minute) - `upnp notify` says which.
- Quiet-hours holdings and rate-limit counts live in each process's memory: a restart forgets them.
- device_stopped is at most once a day per address; a "new device" is kept in state_dir/devices-seen.json
  (2000 at most).
- The alerts forwarded to ntfy follow alerts_delay_min like the mail, independent of whether mail is on.
- Times shown as NaN-NaN-NaN (a mapping's time kept as an ISO date) are read either way now.

## 1.8.1 (2026-11-17)

- Gateway for devices is in the menu's first group, fake-igd, below the mDNS reflector (it was under Server).

## 1.8.0 (2026-11-17)

**Gateway for devices** (Settings → Gateway for devices). A PS5 asks UPnP only of its *default
gateway*: with the real router as its gateway it searched, heard fake-igd's answer and went no further; with
its gateway set to the fake-igd server it fetched the description at once and asked for UDP 9308. This
server can now be the gateway of the devices chosen - and of nothing else:
- **Devices, not networks**: each by its IPv4 address, a name ("PS5 Pro") and best its MAC (offered from the
  neighbour table - "Use the MAC seen now"); a rule per device, its name in the rule's comment, with
  `--mac-source` so a box that takes its address does not pass. Picked from the devices fake-igd has seen
  (the Clients tab) or typed; switched on/off, edited, removed.
- **Only toward the internet**: forwarded only in and out of the interface of the server's default route,
  toward the router - never to another network of this server (it stays no bridge between the networks it
  reflects mDNS between), never to its own LAN, link-local, multicast, reserved, nor to any private network
  (10/8, 172.16/12, 192.168/16, 100.64/10) behind the router.
- **FAKE-IGD-FWD** first in FORWARD, ending in a DROP of its own whatever the system's FORWARD policy says, kept
  in /etc/sysconfig/iptables between fake-igd's marks; no conntrack state (the way back goes router → device).
- **Forwarding only while needed**: net.ipv4.ip_forward is turned on only after the chain is in place and
  checked, and only while a device is on; /etc/sysctl.d/90-fake-igd-gateway.conf (ip_forward, send_redirects
  0 for all, default and each interface - an ICMP redirect would send the device to the router directly)
  only while so; off, or the last device taken away: forwarding back to what it was, the file and the chain
  gone. Refused with fake-igd's firewall off or firewalld in charge (said why); fake-igd's firewall switched
  off switches it off. IPv6 forwarding never.
- **On trial** as the firewall's (Keep it / Put the old back now, on every page); back by itself after a
  restart of the machine.
- The pane: the state (forwarding, the chain, the interface, the router, the firewall, why off), the devices
  with the packets forwarded, when last through and how far they got on the Clients tab, the exact values to
  type on the PS5 (its IP, mask, gateway = this server, DNS), the warnings (a single point of failure).
- **The Clients tab**: a device stopped at "answered" is told why ("a PS5 asks only its default gateway") with
  "Make this server its gateway", opening the pane with it filled in.
- `upnp gateway [status|on|off|add IP --name N [--mac M|--mac-seen]|del IP|keep|back]`, in the console too;
  an alert when forwarding was turned off by something else or the chain is no longer first in FORWARD.

Also:
- A mapping's "Added" showed "NaN-NaN-NaN NaN:NaN:NaN": the service writes it as ISO words; every time on the
  pages now takes either.

## 1.7.14 (2026-11-17)

- **Every search of a device is written down** - once in 30 s per device and what it searched for (a device
  sends the same search two or three times at once), and so each fetch of the description. It was once in
  10 minutes, so a PS5's connection test right after an earlier search did not show at all on the Clients
  tab.

## 1.7.13 (2026-11-17)

- **The UPnP service answers a search within 50 ms.** It waited a random time up to MX seconds (UDA spreads
  the answers of many devices so); a PS5 searching with MX=1 was answered about a second later - and never
  came for the device description. fake-igd is one device: the answer goes at once (5-50 ms).
- **Spaces between things, everywhere, measured**: no two blocks closer than 8 px, the same transition with
  the same space on every tab, pane and popup - a heading 8-12 px above what it heads and 20 px below what
  came before, a row of pills (a client's steps) with air under it, a note never glued to the table, log,
  button row or box above it, an empty list with the room of a row, a folded part's contents below its
  title. Notes as wide as the boxes and tables beside them. (A checker walks every tab, pane and popup.)
- **Popups generous and responsive**: up to 1880 px (95 % of the screen), the medium ones up to 1600 px
  (90 %), the small ones 760 px, up to 94 % of the height, the whole width on a phone; the facts fill as many
  columns as fit, tables full width - still one scroller.

## 1.7.12 (2026-11-17)

- **Settings → The database → Erase the collected data** erases the history kept outside the database too
  (done by root, deploy/root_history.py): *the requests* (the request log and its rotated copies - the
  Ports, Requests and Clients tabs, the Overview's chart, the reports), *the service's log* (the devices'
  searches, how far each client got, the Log tab) and *the mappings* (fake-igd.service stopped, emptied,
  started again - a few seconds without an answer). Each says how many lines or mappings it has; the
  confirm says that no copy is kept of these. Root never takes the files from config.json: only
  fake-igd's own log and state folders, plain files, no link followed, truncated on the open file.
- **One scroller in every popup**: a list in a popup (the client's steps, a request's fields, a port's
  requests…) grows in the popup's body instead of scrolling inside it - the client's popup had two
  scrollbars, one in the other. A test now opens the popups of every tab and checks it.
- **Wider popups, as the screen allows**: the medium one up to 1180 px (it was 860-900 on any screen), the
  large ones up to 1480 px, the small ones 640 px; on a phone the whole width.

## 1.7.11 (2026-11-17)

- **SELinux → Download the report holds the whole of SELinux on the machine**, not only fake-igd's part:
  `os/processes.txt` (every process with its domain), `os/booleans.txt` (every boolean), `os/ports.txt`
  (every port type), `os/modules.txt` (every module), `os/local-changes.txt` (what was changed on this
  machine: semanage boolean/port/fcontext/login/user/module/permissive -l -C), `os/semanage-export.txt`
  and `os/listening.txt` (every listening socket with its label). The refusals in it were already the
  whole machine's.
- docs/selinux/: how fake-igd lives with SELinux, with screenshots - a kit for other applications.

## 1.7.10 (2026-11-17)

**Settings → SELinux finds out everything SELinux refuses on the server - and puts right what it may.**
- **Look again** reads every refusal since the machine started (AVC, USER_AVC, SELINUX_ERR), with its
  program and whole path or port, asks audit2why about each and sorts it by what puts it right:
  *a boolean* (the one audit2why names; never one that allows far more), *a label* (restorecon where the
  policy says another type), *a port* (semanage port for nginx, sshd, chronyd, avahi on a port with no type
  of its own; never taken from another service), *a rule of fake-igd's* (exactly the refused access, in a
  local module of its own, `fake_igd_local`, each rule in an optional block of its own), *not for a button*
  (security-sensitive targets - shadow, policy, kernel, keys, audit -, running a program, writes to
  generic types: shown with why, never allowed from here) and *not fake-igd's* (other programs: shown).
- **Put in what is selected (N)**: the page sends only which findings - root finds them again and works out
  every fix itself; a confirm lists exactly what root will do; under enforcing too; every fix in the
  events; the rows put right show green and are looked at again at once; a rule of fake-igd's can be
  taken away from the card (the last one takes the local module away). Enforcing unlocks when nothing
  fixable or not-for-a-button is left.
- The card drawn anew: findings grouped by kind with counts, select-all, the program, `SRC → TGT class
  { perms }`, the path or port, how often and when, the command root would run; fake-igd's local rules;
  a calm green "refused nothing" when so. Read-only accounts see it without buttons.
- `sudo upnp selinux look`, `fix ID...|--all`, `rules [--take-away ID]`; in the console too.
- **fake_igd_server** lets fake-igd-api.service (NoNewPrivileges) start the tools it runs in their own
  domains: chronyc (the clock - refused on a real server: "unconfined_service_t → chronyc_t process2
  { nnp_transition }", under enforcing chronyc would not run), ip, hostname, ssh/sftp/scp (backups),
  ssh-keygen, ping.
- "To be done by hand" says how many refusals the card can put right.

## 1.7.9 (2026-11-17)

- **"To be done by hand" stayed after SELinux was put right.** "SELinux: the pages may not reach fake-igd's
  API" (the boolean off after SELinux was switched on) was looked at again only every ten minutes, so it
  stayed after "Put in what fake-igd needs" on Settings → SELinux had set it. The list is looked at again
  as soon as root has done a step of SELinux (or the card has looked again), as it already was when
  install.sh writes root-facts.json.

## 1.7.8 (2026-11-17)

- **DH parameters made here never ended on the pages.** fake-igd-web.service (root's helper) had a time limit
  of 5 minutes; making DH parameters of 4096 bits takes from minutes to half an hour, so systemd ended it
  half way - nothing was changed, but the bar "making DH parameters" ran on for ever. The limit is otp's
  30 minutes now; root says every 10 seconds that it still works, and a helper ended half way is said on
  the card as such ("root stopped half way ... ask again, or choose an RFC 7919 group: ready at once")
  instead of a bar - also for one ended before this version (after half an hour). The time on the bar is
  counted from the start of the step.

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
