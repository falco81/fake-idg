<?php
/**
 * admin/index.php — the web pages of fake-igd.
 *
 * otp's administration pages, for a fake UPnP router: the same header, the
 * same tabs, the same settings down a rail at the left edge, the same popups.
 * It collects nothing itself and decides nothing: every word comes from
 * fake-igd-api over its API on localhost, and the API decides whether
 * whoever is signed in may have it.
 */
declare(strict_types=1);

require_once dirname(__DIR__) . '/igd-page.php';
require_once dirname(__DIR__) . '/igd-api.php';

if (isset($_GET['api'])) {
    $what = (string) $_GET['api'];
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    if ($post) {
        igd_guard_post();
    }
    if ($what === 'login' && $post) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $sent = sent_body();
        [$status, $body] = igd_call('/api/auth/login', 'POST', [
            'name'     => (string) ($sent['name'] ?? ''),
            'password' => (string) ($sent['password'] ?? ''),
        ], 30.0);
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' => igd_down_words()]);
            exit;
        }
        $data = json_decode($body, true);
        if ($status === 200 && is_array($data) && !empty($data['token'])) {
            igd_set_session((string) $data['token']);
            unset($data['token']);
            echo json_encode($data);
            exit;
        }
        http_response_code($status === 200 ? 400 : $status);
        echo json_encode(is_array($data) ? $data : ['ok' => false, 'error' => 'sign-in failed']);
        exit;
    }
    if ($what === 'logout' && $post) {
        igd_call('/api/auth/logout', 'POST', [], 10.0);
        igd_clear_session();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => true]);
        exit;
    }
    /* Reads apart from writes, so a GET can never reach a road that changes
       something, whatever is typed in the address bar. */
    $reads = [
        'status' => '/api/status', 'overview' => '/api/overview', 'ports' => '/api/ports',
        'requests' => '/api/requests', 'clients' => '/api/clients', 'mappings' => '/api/mappings',
        'log' => '/api/log', 'dnat' => '/api/dnat', 'events' => '/api/events',
        'settings' => '/api/settings', 'users' => '/api/users', 'upgrade' => '/api/upgrade',
        'whoami' => '/api/auth/whoami', 'root-result' => '/api/root-result',
        'mdns' => '/api/mdns', 'mdns-services' => '/api/mdns/services', 'mdns-log' => '/api/mdns/log',
    ];
    $writes = [
        'settings' => '/api/settings', 'apply' => '/api/apply', 'notify-test' => '/api/notify-test',
        'users' => '/api/users', 'upgrade' => '/api/upgrade', 'upgrade-package' => '/api/upgrade-package',
        'password' => '/api/auth/passwd',
        'mdns' => '/api/mdns',
    ];
    /* The panes of Settings (1.6.0): ?api=a-b-c is /api/a/b/c - the API says what it answers, and
       a GET never reaches what only a POST does there. */
    if (!isset($reads[$what]) && !isset($writes[$what]) && preg_match('/^[a-z0-9]+(-[a-z0-9]+){0,5}\z/', $what)) {
        $reads[$what] = '/api/' . str_replace('-', '/', $what);
        $writes[$what] = $reads[$what];
    }
    if ($post) {
        if (!isset($writes[$what])) {
            http_response_code(404);
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
            exit;
        }
        igd_relay($writes[$what], 'POST', sent_json(), in_array($what, ['upgrade', 'acme', 'osup', 'backup', 'carry'], true) ? 330.0 : 90.0);
        exit;
    }
    if (!isset($reads[$what])) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
        exit;
    }
    $query = $_GET;
    unset($query['api']);
    igd_relay($reads[$what] . ($query ? '?' . http_build_query($query) : ''), 'GET', null, 60.0);
    exit;
}

/* ---- the page ------------------------------------------------------------ */
$me      = igd_whoami();
$health  = igd_get('/api/health', 5.0);
$alive   = is_array($health);
$token_there = file_exists(IGD_TOKEN);
$token_ok    = igd_token() !== null;
$web_user    = function_exists('posix_getpwuid') && function_exists('posix_geteuid')
    ? (posix_getpwuid(posix_geteuid())['name'] ?? '?') : '?';
/* What is wrong is said in full only to the operator at the console (as otp's). */
if (!$me && !igd_local()) {
    $token_there = false;
    if (!$token_ok || empty($health['database']['ok']) || empty($health['users'])) {
        $alive = false;
    }
}
$initial = $me ? (igd_get('/api/status', 8.0) ?: null) : null;
$host    = (string) ($_SERVER['HTTP_HOST'] ?? php_uname('n'));
$site    = (string) ($health['site'] ?? '');
$title   = $site !== '' ? $site . ' · fake-igd' : 'fake-igd';
?>
<!doctype html>
<html lang="en" class="app-shell-root">
<head>
<?php igd_head($title, $nonce); ?>
</head>
<body class="app-shell fold-words<?= $me ? ' framed' : '' ?>">
<div class="wrap">

<?php if (!$me): ?>
<div class="signin">
  <div class="signbox">
    <div class="card">
    <h1 data-no-i18n><?= h($title) ?></h1>
    <p class="lede">The fake UPnP router on <span data-no-i18n><?= h($host) ?></span>. Sign in to go on.</p>
    <?php if (!$token_ok && $token_there): ?>
      <div class="offline">
        The API is running, but this page may not read what it wrote.<br><br>
        <span class="mono"><?= h(IGD_TOKEN) ?></span> exists and is not readable by
        <span class="mono"><?= h($web_user) ?></span>, which is what this page runs as.
        On the server:<br>
        <span class="mono">usermod -a -G fake-igd-web <?= h($web_user) ?></span><br>
        <span class="mono">systemctl restart php-fpm nginx</span>
      </div>
    <?php elseif (!$alive): ?>
      <div class="offline">The API is not answering. Nobody can sign in until
        <span class="mono">fake-igd-api.service</span> is running:<br>
        <span class="mono">systemctl status fake-igd-api</span> ·
        <span class="mono">journalctl -u fake-igd-api -n 50</span></div>
    <?php elseif (empty($health['database']['ok'])): ?>
      <div class="offline">The API is running, but its database will not open. On the
        server: <span class="mono">journalctl -u fake-igd-api -n 50</span></div>
    <?php elseif (empty($health['users'])): ?>
      <div class="offline">There is no account on this machine yet. Make one on the server:<br>
        <span class="mono">sudo upnp user add yourname</span></div>
    <?php endif; ?>
    <form id="signin-form" autocomplete="on">
      <input type="text" id="in-name" name="username" placeholder="name" autocomplete="username"
             autocapitalize="none" spellcheck="false" required>
      <input type="password" id="in-pass" name="password" placeholder="password"
             autocomplete="current-password" required>
      <button class="btn primary cmd" type="submit" id="in-go"><svg
        viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
        stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
        ><path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="M14 12h7"/><path
        d="M18 9l3 3-3 3"/></svg><span>Sign in</span></button>
      <div class="said" id="in-said"></div>
    </form>
    <div style="margin-top:14px;display:flex;justify-content:space-between;align-items:center">
      <span class="muted small">fake-igd <?= h(IGD_VERSION) ?></span>
      <span class="langpick" id="langpick"></span>
    </div>
    </div>
  </div>
</div>
</div>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(IGD_VERSION) ?>"></script>
<script nonce="<?= h($nonce) ?>">
(function () {
  var form = $('signin-form'), said = $('in-said'), go = $('in-go');
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    said.className = 'said';
    said.textContent = '';
    go.disabled = true;
    var words = go.querySelector('span');
    words.textContent = 'Signing in…';
    api('login', {name: $('in-name').value, password: $('in-pass').value}).then(function () {
      said.className = 'said good';
      said.textContent = 'Welcome back.';
      location.reload();
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
      go.disabled = false;
      words.textContent = 'Sign in';
      $('in-pass').value = '';
      $('in-pass').focus();
    });
  });
  $('in-name').focus();
}());
</script>
</body>
</html>
<?php exit; endif; ?>

<header>
  <h1 data-no-i18n><?= h($site ?: 'fake-igd') ?> <span class="host"><?= h($host) ?></span></h1>
  <span id="state-pill" class="pill unknown"><span class="dot"></span><span>…</span></span>
  <div class="spacer"></div>
  <div class="btnrow">
    <button type="button" class="btn small mebtn" id="me-btn" data-icon="person"
            title="The account you are signed in as: what it may do, and its password."><span class="me-name" data-no-i18n><?= h($me['name']) ?></span></button>
    <button class="btn small" id="signout" data-icon="out">Sign out</button>
  </div>
  <div class="updated" id="updated" title="Click to pause or resume the live updates">
    <b>live</b><br><span id="updated-at">…</span></div>
</header>

<div id="offline" class="offline" hidden></div>
<div id="problems" class="offline warnish" hidden></div>

<div class="tabs" role="tablist">
  <button role="tab" aria-selected="true" data-tab="overview" data-icon="chart"
          title="The shape of the day: who looked for a UPnP router, which ports were asked for, by whom.">Overview</button>
  <button role="tab" aria-selected="false" data-tab="ports" data-icon="net"
          title="Every port a client asked for with AddPortMapping, one row per client, protocol and port - and the rules for the router made from them.">Ports<span class="count" id="tabn-ports"></span></button>
  <button role="tab" aria-selected="false" data-tab="requests" data-icon="list"
          title="Every SOAP request, one by one, newest first. Click a row for all it carried.">Requests<span class="count" id="tabn-requests"></span></button>
  <button role="tab" aria-selected="false" data-tab="clients" data-icon="people"
          title="The devices that looked for a UPnP router or asked for ports.">Clients<span class="count" id="tabn-clients"></span></button>
  <button role="tab" aria-selected="false" data-tab="mappings" data-icon="router"
          title="What the clients believe is open now, with the lease left. Nothing is open on the router.">Mappings<span class="count" id="tabn-mappings"></span></button>
  <button role="tab" aria-selected="false" data-tab="mdns" data-icon="wifi"
          title="The mDNS reflector on this server (avahi-daemon): whether it runs and reflects, between which interfaces, and every service mDNS shows on them now.">mDNS<span class="count" id="tabn-mdns"></span></button>
  <button role="tab" aria-selected="false" data-tab="log" data-icon="log"
          title="fake-igd's own log, as upnp log shows it - followed live.">Log</button>
  <button role="tab" aria-selected="false" data-tab="events" data-icon="history"
          title="Every change of a setting, every account made or taken away, every sign-in and every upgrade.">Events</button>
  <button role="tab" aria-selected="false" data-tab="settings" data-icon="gear"
          title="How fake-igd answers, the network, the notifications, the accounts of these pages, the firewall and the upgrades.">Settings</button>
</div>

<!-- ===================== Overview ===================== -->
<section class="panel" id="tab-overview">
  <div class="grid top">
    <div class="card metric ok" id="card-service"><div class="label">The service</div>
      <div class="value" id="m-service">–</div><div class="sub" id="m-service-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-mode"><div class="label">Mode and answer</div>
      <div class="value" id="m-mode">–</div><div class="sub" id="m-mode-sub">&nbsp;</div></div>
    <div class="card metric ok" id="card-ports"><div class="label">Ports asked for</div>
      <div class="value" id="m-ports">–</div><div class="sub" id="m-ports-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-clients"><div class="label">Clients</div>
      <div class="value" id="m-clients">–</div><div class="sub" id="m-clients-sub">&nbsp;</div></div>
  </div>
  <div class="grid top" style="margin-top:14px">
    <div class="card metric info" id="card-ifaces"><div class="label">Interfaces</div>
      <div class="value" id="m-ifaces">–</div><div class="sub" id="m-ifaces-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-maps"><div class="label">Mappings now</div>
      <div class="value" id="m-maps">–</div><div class="sub" id="m-maps-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-mdns"><div class="label">mDNS reflector</div>
      <div class="value" id="m-mdns">–</div><div class="sub" id="m-mdns-sub">&nbsp;</div></div>
    <div class="card metric ok" id="card-upgrade"><div class="label">Upgrades</div>
      <div class="value" id="m-upgrade">–</div><div class="sub" id="m-upgrade-sub">&nbsp;</div></div>
  </div>
  <div class="card full" style="margin-top:14px">
    <h2>Requests
      <span class="right">
        <select id="ov-hours" title="How far back the chart and the cards under it look.">
          <option value="6">last 6 hours</option>
          <option value="24" selected>last 24 hours</option>
          <option value="72">last 3 days</option>
          <option value="168">last week</option>
          <option value="720">last month</option>
        </select>
      </span></h2>
    <p class="note">Every SOAP request, as one line of time: green a port asked for and confirmed,
      red refused, blue the other questions (the description, the public IP, the status).</p>
    <div class="chart" id="ov-chart"><div class="empty">…</div><div class="tip"></div></div>
    <div class="legend">
      <span><i style="background:#3fb950"></i>port asked for</span>
      <span><i style="background:#f85149"></i>refused</span>
      <span><i style="background:#58a6ff"></i>other questions</span>
    </div>
  </div>
  <div class="grid halves" style="margin-top:14px">
    <div class="card facet"><h2>Asked the most</h2><div id="ov-ports"></div></div>
    <div class="card facet"><h2>Who asks</h2><div id="ov-clients"></div></div>
    <div class="card facet"><h2>What is asked</h2><div id="ov-actions"></div></div>
    <div class="card facet"><h2>Where it listens</h2><div id="ov-ifaces"></div></div>
  </div>
</section>

<!-- ===================== Ports ===================== -->
<section class="panel" id="tab-ports" hidden>
  <div class="card full" data-hold>
    <h2>Requested ports <span class="right" id="pt-said"></span></h2>
    <p class="note">Every port a client asked for (AddPortMapping), one row per client, protocol
      and port: how many times, when first and last, what it said it was for. This is what to
      forward on the real router - <b>Rules for the router</b> makes them (as <span class="mono">upnp dnat</span>).</p>
    <div class="filterbar btnrow filters">
      <input type="search" id="pt-q" placeholder="an address, a port, a description…" style="flex:1;min-width:200px">
      <select id="pt-proto"><option value="">TCP and UDP</option><option value="TCP">TCP</option><option value="UDP">UDP</option></select>
      <span id="pt-hours" title="How far back the ports are counted."></span>
      <button class="btn cmd" id="dn-open" data-icon="router" title="Port forwarding rules for the real router, made from these ports - consecutive ports merged into ranges.">Rules for the router</button>
    </div>
    <div id="pt-table" class="scroll rowsonly"></div>
  </div>
</section>

<!-- ===================== Requests ===================== -->
<section class="panel" id="tab-requests" hidden>
  <div class="card full" data-hold>
    <h2>Requests <span class="right" id="rq-said"></span></h2>
    <p class="note">Every SOAP request fake-igd was asked, newest first - from
      <span class="mono">requests.jsonl</span>. Click a row for everything it carried.</p>
    <div class="btnrow filters">
      <input type="search" id="rq-q" placeholder="an address, a port, a description…" style="flex:1;min-width:200px">
      <select id="rq-action"><option value="">every action</option></select>
      <span id="rq-hours" title="How far back the requests go."></span>
      <select id="rq-per"><option>50</option><option selected>100</option><option>500</option></select>
    </div>
    <div id="rq-table" class="scroll rowsonly"></div>
    <div class="pager" id="rq-pager"></div>
  </div>
</section>

<!-- ===================== Clients ===================== -->
<section class="panel" id="tab-clients" hidden>
  <div class="card full" data-hold>
    <h2>Clients <span class="right" id="cl-said"></span></h2>
    <p class="note">Every device that looked for a UPnP router (SSDP M-SEARCH) or asked for
      ports - with its PTR name, what it said it is, and the ports it asked for.</p>
    <div class="btnrow filters">
      <input type="search" id="cl-q" placeholder="an address, a name…" style="flex:1;min-width:200px">
      <span id="cl-hours" title="How far back the clients are counted."></span>
    </div>
    <div id="cl-table" class="scroll rowsonly"></div>
  </div>
</section>

<!-- ===================== Mappings ===================== -->
<section class="panel" id="tab-mappings" hidden>
  <div class="card full" data-hold>
    <h2>Mappings now</h2>
    <p class="note">What the clients <b>believe</b> is open now, and the lease left. Nothing is open on
      the router: fake-igd only says so. Kept only while the answer is <i>accept</i> and the mode
      <i>active</i>.</p>
    <div id="mp-table" class="scroll rowsonly"></div>
  </div>
</section>

<!-- ===================== mDNS ===================== -->
<section class="panel" id="tab-mdns" hidden>
  <div class="grid top">
    <div class="card metric ok" id="card-avahi"><div class="label">avahi-daemon</div>
      <div class="value" id="m-avahi">–</div><div class="sub" id="m-avahi-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-refl"><div class="label">The reflector</div>
      <div class="value" id="m-refl">–</div><div class="sub" id="m-refl-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-mifs"><div class="label">Interfaces</div>
      <div class="value" id="m-mifs">–</div><div class="sub" id="m-mifs-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-msvc"><div class="label">Services seen</div>
      <div class="value" id="m-msvc">–</div><div class="sub" id="m-msvc-sub">&nbsp;</div></div>
  </div>
  <div class="card full" data-hold style="margin-top:14px">
    <h2>Services on the network <span class="right" id="ms-said"></span></h2>
    <p class="note">What mDNS shows now on every interface avahi uses - AirPlay, Chromecast, printers,
      the PS5 - asked of avahi-daemon (<span class="mono">avahi-browse -a -r</span>, as
      <span class="mono">upnp mdns services</span>). Click a row for all it says.</p>
    <div class="btnrow filters">
      <input type="search" id="ms-q" placeholder="a name, a type (_airplay), an address, an interface…" style="flex:1;min-width:200px">
      <select id="ms-iface"><option value="">every interface</option></select>
      <select id="ms-proto"><option value="">IPv4 and IPv6</option><option value="IPv4">IPv4</option><option value="IPv6">IPv6</option></select>
      <button class="btn cmd" id="ms-look" data-icon="refresh" title="Ask avahi again now - it takes a few seconds.">Look again</button>
    </div>
    <div id="ms-table" class="scroll rowsonly"></div>
  </div>
</section>

<!-- ===================== Log ===================== -->
<section class="panel" id="tab-log" hidden>
  <div class="card full" data-hold>
    <h2>The log <span class="right mono small muted" id="lg-file" data-no-i18n></span></h2>
    <p class="note">The tail of fake-igd's own log, coloured as <span class="mono">upnp log</span>
      colours it, followed live. What is typed keeps only the lines with it (a regular expression works).</p>
    <div class="btnrow filters">
      <input type="search" id="lg-q" placeholder="grep: an address, port:, ssdp:, 3478|3479…" style="flex:1;min-width:200px" spellcheck="false">
      <select id="lg-lines"><option>200</option><option selected>600</option><option>2000</option><option>10000</option></select>
      <button class="btn cmd" id="lg-pause" data-icon="pause">Pause</button>
    </div>
    <div class="scroll rowsonly" id="lg-scroll" style="margin-top:12px"><pre class="lines loglines" id="lg-out">…</pre></div>
  </div>
</section>

<!-- ===================== Events ===================== -->
<section class="panel" id="tab-events" hidden>
  <div class="card full" data-hold>
    <h2>What was done</h2>
    <p class="note">Every change of a setting, every account made or taken away, every sign-in and
      every upgrade - on these pages and on the command line. Kept in the database.</p>
    <div class="btnrow filters">
      <input type="search" id="ev-q" placeholder="anything in an event…" style="flex:1;min-width:200px">
      <select id="ev-kind"><option value="">everything</option></select>
      <span id="ev-time" title="How far back the events go."></span>
    </div>
    <div id="ev-table" class="scroll rowsonly"></div>
    <div class="pager" id="ev-pager"></div>
  </div>
</section>

<!-- ===================== Settings ===================== -->
<section class="panel" id="tab-settings" hidden>
<div class="ctl-layout">
  <nav class="ctl-nav" id="ctl-nav" aria-label="Settings sections">
    <div class="ctl-navtop">
      <button type="button" class="ctl-pin" id="ctl-pin" aria-pressed="false" aria-label="Keep this menu open"></button>
      <div class="ctl-find-wrap">
        <input type="search" id="ctl-find" placeholder="Find a setting…" autocomplete="off" aria-label="Find a setting">
        <div class="ctl-found" id="ctl-found" hidden></div>
      </div>
    </div>
    <div class="ctl-group">fake-igd</div>
    <button type="button" data-pane="answer" data-icon="router" title="Whether it answers like a UPnP router, what it says to AddPortMapping, whom it answers, the public IP it reports.">How it answers</button>
    <button type="button" data-pane="network" data-icon="net" title="The port of the description and SOAP, the interfaces it listens on and leaves out, how often it looks again.">UPnP network</button>
    <button type="button" data-pane="ntfy" data-icon="bell" title="A notification to a phone for every new port - ntfy.sh or your own ntfy server.">Notifications (ntfy)</button>
    <button type="button" data-pane="logs" data-icon="log" title="How much the log says, and where the logs and the state are.">Logs and state</button>
    <button type="button" data-pane="mdns" data-icon="wifi" title="avahi-daemon on this server: the reflector, the interfaces, the filters - every key of avahi-daemon.conf fake-igd knows - and the daemon started, stopped or restarted.">mDNS reflector (avahi)</button>
    <div class="ctl-group">Access</div>
    <button type="button" data-pane="people" data-icon="person" title="Who may open these pages, what each of them may do, and who is signed in right now.">Accounts</button>
    <button type="button" data-pane="tls" data-icon="lock" title="The certificate of these pages, and how TLS is spoken.">Certificates and TLS</button>
    <button type="button" class="fulladmin-only" data-pane="acme" data-icon="lock" title="The certificates ordered from Let's Encrypt (or another ACME CA) and renewed by themselves.">Automatic certificates</button>
    <button type="button" data-pane="web" data-icon="wall" title="Who may reach these pages, and the machine's firewall (iptables, the chain FAKE-IGD-IN) - what fake-igd needs opens by itself, your own rules beside it.">Firewall and access</button>
    <button type="button" class="fulladmin-only" data-pane="sshd" data-icon="shield" title="How the SSH server lets people in - root, passwords, the port - and the notice shown before and after signing in.">SSH server and notices</button>
    <button type="button" class="fulladmin-only" data-pane="sshkeys" data-icon="key" title="The keys that may sign in over SSH - as root or as a user who may sign in here: made here, added or taken away.">SSH keys</button>
    <button type="button" class="fulladmin-only" data-pane="osusers" data-icon="people" title="The users of this machine's own system: root shown, the others made, given a password or sudo, locked or taken away.">Local users</button>
    <div class="ctl-group">Server</div>
    <button type="button" class="fulladmin-only" data-pane="net" data-icon="ethernet" title="This machine's addresses, gateway, DNS servers, host name and IPv6 - each interface.">Network</button>
    <button type="button" class="fulladmin-only" data-pane="proxy" data-icon="globe" title="An HTTP proxy, for what you switch on: the new versions, the system updates, ACME, notifications.">Proxy</button>
    <button type="button" class="fulladmin-only" data-pane="time" data-icon="clock" title="The clock of this machine: chrony, its time servers, how far off it is, the time zone.">Time</button>
    <button type="button" class="fulladmin-only" data-pane="service" data-icon="router" title="fake-igd.service restarted, and what root last did for these pages.">The service</button>
    <button type="button" class="fulladmin-only" data-pane="power" data-icon="power" title="Restart or switch off this machine.">Restart and power off</button>
    <button type="button" class="fulladmin-only" data-pane="disks" data-icon="chart" title="The disks, and how much the system journal and fake-igd's own logs may take.">Disks and logs</button>
    <div class="ctl-group">Data</div>
    <button type="button" data-pane="db" data-icon="db" title="The database: how big it is, copies of it, how long things are kept.">The database</button>
    <button type="button" class="fulladmin-only" data-pane="backup" data-icon="archive" title="Backups of everything to another machine - FTP, FTPS, SFTP, SCP, SMB or a folder - locked with a password, on a schedule, and putting one back.">Backups</button>
    <button type="button" class="fulladmin-only" data-pane="carry" data-icon="download" title="Everything that makes this installation what it is, as one file to carry to another machine.">Export and import</button>
    <div class="ctl-group">Monitoring and updates</div>
    <button type="button" class="fulladmin-only" data-pane="mail" data-icon="mail" title="How fake-igd sends mail: a mail server, or straight to the recipient's.">Mail</button>
    <button type="button" class="fulladmin-only" data-pane="mailq" data-icon="list" title="Every mail sent and what became of it: sent, waiting for another try, failed.">Outgoing mail</button>
    <button type="button" class="fulladmin-only" data-pane="alerts" data-icon="bell" title="A mail when something is wrong, and a report of the week by mail.">Alerts and reports</button>
    <button type="button" class="fulladmin-only" data-pane="monitor" data-icon="pulse" title="Prometheus asks this machine for its metrics; SNMPv3.">Monitoring</button>
    <button type="button" class="fulladmin-only" data-pane="siem" data-icon="log" title="Every event, every sign-in and every port asked for to a syslog server or a SIEM - UDP, TCP or TLS; JSON, CEF or RFC 5424.">Syslog and SIEM</button>
    <button type="button" class="fulladmin-only" data-pane="osup" data-icon="download" title="The operating system's packages updated; a restart offered when one is needed.">System updates</button>
    <button type="button" data-pane="upgrade" data-icon="up" title="A new version from the web or as a package, checked and put in by root.">Upgrades<b class="count rail-n" id="up-badge"></b></button>
    <button type="button" data-pane="about" data-icon="info" title="Version, what is running.">About</button>
  </nav>

  <div class="ctl-main">
  <div class="card full" id="readonly-note" hidden>
    <h2>You may look, but not change</h2>
    <p class="note" style="margin:0">This account is read only. A full administrator can change that under <i>Accounts</i>.</p>
  </div>

  <div class="ctl-pane" id="pane-answer">
    <div class="ctl-head"><h2 class="ctl-title">How it answers</h2>
      <p class="ctl-lede">fake-igd answers like a UPnP router and opens nothing. A change here restarts
        fake-igd.service; the PS5 notices nothing but a moment of silence.</p></div>
    <div class="card full"><div id="sect-answer"></div></div>
  </div>

  <div class="ctl-pane" id="pane-network" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Network</h2>
      <p class="ctl-lede">Where it listens. SSDP is always 1900/udp; the description and SOAP port is
        yours to choose. fake-igd is IPv4 only.</p></div>
    <div class="card full"><div id="sect-network"></div></div>
  </div>

  <div class="ctl-pane" id="pane-ntfy" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Notifications (ntfy)</h2>
      <p class="ctl-lede">Every new port a client asks for - and another UPnP router seen on the network -
        to your phone, through ntfy.sh or your own ntfy server.</p></div>
    <div class="card full"><div id="sect-ntfy"></div>
      <div class="btnrow admin-only" style="margin-top:14px">
        <button class="btn cmd" id="nt-test" data-icon="bell" title="One test message with the saved settings; the server's answer is said here.">Send a test</button>
        <span class="muted small" id="nt-said"></span>
      </div></div>
  </div>

  <div class="ctl-pane" id="pane-logs" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Logs and state</h2>
      <p class="ctl-lede">The files are moved on the server only (<span class="mono">sudo upnp config set</span>):
        the service's sandbox needs to know the new place too.</p></div>
    <div class="card full"><div id="sect-logs"></div></div>
  </div>

  <div class="ctl-pane" id="pane-mdns" hidden>
    <div class="ctl-head"><h2 class="ctl-title">mDNS reflector (avahi)</h2>
      <p class="ctl-lede">avahi-daemon with <span class="mono">enable-reflector=yes</span> repeats mDNS
        (Bonjour, AirPlay, Chromecast, printers…) between the server's networks. Saved, the change goes into
        <span class="mono">/etc/avahi/avahi-daemon.conf</span> line by line - its comments stay, a copy is
        kept beside it - and avahi-daemon is restarted; when it does not come up with the change, the copy is
        put back. The same as <span class="mono">sudo upnp mdns ...</span>.</p></div>
    <div class="card full" id="av-missing" hidden><div class="offline" id="av-missing-words"></div></div>
    <div class="card full"><div id="sect-mdns"></div></div>
    <div class="card full">
      <h2>avahi-daemon <span class="right" id="av-tools"></span></h2>
      <div id="av-state"><p class="muted">…</p></div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-people" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Accounts</h2>
      <p class="ctl-lede">Who may open these pages - local accounts, kept in fake-igd's own database.
        <b>full admin</b> may change everything; <b>read only</b> may look and change nothing.
        On the server: <span class="mono">upnp user list</span>.</p></div>
    <div class="card full">
      <h2>Accounts <span class="right"><button class="btn cmd small primary admin-only" id="us-add" data-icon="add">Make an account</button></span></h2>
      <div id="us-table"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Signed in now</h2><div id="se-table"></div></div>
  </div>

  <div class="ctl-pane" id="pane-service" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The service</h2>
      <p class="ctl-lede">fake-igd.service, which answers the network. These pages and their API are
        a service of their own (fake-igd-api) and stay while it restarts.</p></div>
    <div class="card full"><div id="sv-state"></div>
      <div class="btnrow admin-only" style="margin-top:14px">
        <button class="btn cmd" id="sv-restart" data-icon="undo">Restart fake-igd.service</button>
        <button class="btn cmd" id="sv-apply" data-icon="wall">Put the allow list and the firewall in place again</button>
      </div></div>
  </div>

  <div class="ctl-pane" id="pane-upgrade" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Upgrades</h2>
      <p class="ctl-lede">A new version put in from here: from the web, or a package sent from this
        computer. It is checked before anything else - signed by a release key this server trusts,
        every file the one signed, not older than what runs here - and root checks it all again
        before it runs its install.sh --upgrade. The command line works as it always has.</p></div>
    <div class="card full admin-only" id="up-web-card">
      <h2>From the web</h2>
      <p class="note">Where new versions are published - the address below - is looked at once a
        day. A newer fake-igd found there is offered here and put in with one click: fetched, its
        signature checked like a package sent by hand, then put in by root. Nothing is put in by itself.</p>
      <div id="up-web"></div>
      <div id="sect-upgrade"></div>
    </div>
    <div class="card full admin-only">
      <h2>A new version</h2>
      <p class="note">The .tar.gz of a new fake-igd, as it was released.</p>
      <div class="drop" id="up-drop">
        <input type="file" id="up-file" accept=".gz,.tgz,application/gzip,application/octet-stream" hidden>
        <span id="up-drop-says">Drop the fake-igd-X.Y.Z.tar.gz here, or press to choose it</span>
      </div>
      <div id="up-pkg"></div>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd primary" id="up-start" data-icon="play" disabled>Upgrade</button>
        <button class="btn cmd" id="up-forget" data-icon="trash" hidden>Forget the package</button>
      </div>
    </div>
    <div class="card full" id="up-plan-card" hidden>
      <h2>The upgrade</h2>
      <div id="up-plan"></div>
    </div>
    <div class="card full">
      <h2>What root said last</h2>
      <p class="note"><span>The output of install.sh, the last time this server was upgraded from these pages or with upnp upgrade.</span>
        <span class="mono" data-no-i18n>/var/lib/fake-igd/upgrade/last.log</span></p>
      <details class="fold" id="up-log-fold">
        <summary>the output</summary>
        <pre class="lines" id="up-log">–</pre>
      </details>
    </div>
    <div class="card full">
      <h2>On the command line</h2>
      <p class="note">The same, as root:</p>
      <pre class="lines">upnp upgrade check                 # what is at upgrade_url, and whether it is newer
upnp upgrade online                # the newest: fetched, checked, put in - followed with a bar
upnp upgrade online 1.4.2 --yes
upnp upgrade file fake-igd-X.Y.Z.tar.gz
upnp upgrade follow                # one going on
tar xzf fake-igd-X.Y.Z.tar.gz && cd fake-igd-X.Y.Z && ./install.sh --upgrade</pre>
    </div>
  </div>

<?php foreach (glob(__DIR__ . '/panes/*.php') ?: [] as $igd_pane) { include $igd_pane; } ?>

  <div class="ctl-pane" id="pane-about" hidden>
    <div class="ctl-head"><h2 class="ctl-title">About</h2></div>
    <div class="card full"><div id="about-state"></div></div>
  </div>

  <div class="save-bar admin-only" id="save-bar">
    <button class="btn cmd primary" id="set-save" data-icon="save"
            title="Save the changed settings into /etc/fake-igd/config.json. A setting the service uses restarts it.">Save the changes</button>
    <button class="btn cmd" id="set-reset" data-icon="undo"
            title="Throw away the changes on this page and read the settings back as they are.">Put them back</button>
    <span class="muted small" id="set-said"></span>
  </div>
  </div>
</div>
</section>

</div><!-- /wrap -->

<div class="modal" id="modal" hidden>
  <div class="box" id="modal-box">
    <div class="head"><h3 id="modal-title">…</h3>
      <button class="xbtn" id="modal-x" data-icon="close" aria-label="Close"></button></div>
    <div class="body" id="modal-body"></div>
    <div class="foot" id="modal-foot"></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script nonce="<?= h($nonce) ?>">
var ME = <?= json_encode($me, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
var STATUS = <?= $initial ? json_encode($initial, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) : 'null' ?>;
</script>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(IGD_VERSION) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/admin.js?v=<?= h(IGD_VERSION) ?>"></script>
<?php foreach (glob(dirname(__DIR__) . '/assets/pane-*.js') ?: [] as $igd_js): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/<?= h(basename($igd_js)) ?>?v=<?= h(IGD_VERSION) ?>-<?= (int) @filemtime($igd_js) ?>"></script>
<?php endforeach; ?>
</body>
</html>
