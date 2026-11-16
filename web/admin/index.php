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
require_once dirname(__DIR__) . '/igd-art.php';

if (isset($_GET['api'])) {
    $what = (string) $_GET['api'];
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    if ($what === 'about-software' && !$post) {
        /* What this server runs on (otp's ?api=software, 1.0.99) - and of the pages, what this PHP
           itself is: php-fpm's, not the command line's. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        [$status, $body] = igd_call('/api/about/software', 'GET', null, 20.0);
        $data = json_decode((string) $body, true);
        if ($status !== 200 || !is_array($data)) {
            if (!$status) {
                igd_down_answer();
                exit;
            }
            http_response_code($status);
            echo $body ?: json_encode(['ok' => false, 'error' => igd_down_words()]);
            exit;
        }
        $ext = [];
        foreach (get_loaded_extensions() as $e) {
            $v = phpversion($e);
            $ext[$e] = ($v === false || $v === PHP_VERSION) ? '' : (string) $v;
        }
        ksort($ext, SORT_NATURAL | SORT_FLAG_CASE);
        $data['pages'] = [
            'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'extensions' => $ext,
            'opcache' => function_exists('opcache_get_status') && is_array(@opcache_get_status(false))
                && !empty(@opcache_get_status(false)['opcache_enabled']),
            'server' => (string) ($_SERVER['SERVER_SOFTWARE'] ?? ''),
            'os' => PHP_OS_FAMILY,
        ];
        echo json_encode($data);
        exit;
    }
    if ($what === 'upgrade-state' && !$post) {
        /* An upgrade going on (1.7.2), read here and not of the API - which is the one
           restarting: how far it is, the version of these pages on disk now, and whether the API
           answers again. Asked by the pages while the API does not answer, as otp's pages ask
           the other node while theirs restarts. Who asked it, only to a page signed in. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $u = igd_upgrading();
        if ($u && igd_session() === '') {
            unset($u['by'], $u['said'], $u['id']);
        }
        echo json_encode(['ok' => true, 'upgrading' => $u, 'pages' => IGD_VERSION,
                          'api' => igd_token() !== null && igd_get('/api/health', 2.0) !== null],
                         JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }
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
            igd_down_answer();
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
        'my-settings' => '/api/auth/settings', 'load' => '/api/load', 'suggest' => '/api/suggest',
        'request' => '/api/request',
    ];
    $writes = [
        'settings' => '/api/settings', 'apply' => '/api/apply', 'notify-test' => '/api/notify-test',
        'users' => '/api/users', 'upgrade' => '/api/upgrade', 'upgrade-package' => '/api/upgrade-package',
        'password' => '/api/auth/passwd',
        'mdns' => '/api/mdns',
        'prefs' => '/api/auth/prefs', 'columns' => '/api/auth/columns', 'my-settings' => '/api/auth/settings',
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
        igd_relay($writes[$what], 'POST', sent_json(), (in_array($what, ['upgrade', 'acme', 'osup', 'backup', 'carry', 'db'], true) || strpos($what, 'backup-') === 0 || strpos($what, 'carry-') === 0 || strpos($what, 'db-') === 0) ? 330.0 : 90.0);
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
/* Signed in with the password, the second step still to give (otp 1.0.125): the sign-in page,
   asking for it - nothing of the pages yet. The API says who it is only once it is given. */
$mfa = '';
if (!$me && igd_session() !== '') {
    $pending = igd_get('/api/auth/whoami', 5.0);
    $mfa = is_array($pending) ? (string) ($pending['mfa'] ?? '') : '';
}
$health  = igd_get('/api/health', 5.0);
$alive   = is_array($health);
$token_there = file_exists(IGD_TOKEN);
$token_ok    = igd_token() !== null;
$web_user    = function_exists('posix_getpwuid') && function_exists('posix_geteuid')
    ? (posix_getpwuid(posix_geteuid())['name'] ?? '?') : '?';
/* What the sign-in page says when something is wrong is for the operator at the console:
   which account the pages run as, where the token is, whether any account exists yet. From
   anywhere but this machine the page says only that the API is not answering (as otp's). */
if (!$me && !igd_local()) {
    $token_there = false;
    if (!$token_ok || empty($health['database']['ok']) || empty($health['users'])) {
        $alive = false;
    }
    $health = ['database' => ['ok' => true], 'users' => 1, 'site' => (string) ($health['site'] ?? '')];
}
$initial = $me ? (igd_get('/api/status', 8.0) ?: null) : null;
if ($initial && igd_upgrading()) {
    $initial['upgrading'] = igd_upgrading();
}
/* The API down while an upgrade goes on (1.7.2): said as that, followed, and the page loaded
   again by itself once the API answers - not "the API is not answering". */
$upgrading = !$me ? igd_upgrading() : null;
if ($upgrading && $upgrading['state'] !== 'running' && $alive) {
    $upgrading = null;
}
$host    = (string) ($_SERVER['HTTP_HOST'] ?? php_uname('n'));
$site    = (string) ($initial['site'] ?? ($health['site'] ?? ''));
$title   = $site !== '' ? $site . ' · fake-igd' : 'fake-igd';
?>
<!doctype html>
<html lang="en" class="app-shell-root">
<head>
<?php igd_head($title, $nonce); ?>
<link rel="stylesheet" nonce="<?= h($nonce) ?>" href="/assets/hload.css?v=<?= h(IGD_VERSION) ?>-<?= (int) @filemtime(dirname(__DIR__) . '/assets/hload.css') ?>">
</head>
<body class="app-shell fold-words<?= $me ? ' framed' : '' ?>">
<div class="wrap">

<?php if (!$me): ?>
<div class="signin">
  <div class="signbox">
    <?= igd_art_svg() ?>
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
    <?php elseif ($upgrading): ?>
      <?php $up_pc = $upgrading['state'] === 'running'
          ? (int) round(min(84, 5 + 76 * min(0.97, $upgrading['part'] / max(1, $upgrading['parts'] ?: 13))))
          : 100; ?>
      <div class="offline upband<?= $upgrading['state'] === 'failed' ? ' bad' : '' ?>" id="up-signin">
        <b><?= $upgrading['state'] === 'failed' ? 'The upgrade to fake-igd ' . h($upgrading['version']) . ' failed'
              : 'fake-igd is being ' . ($upgrading['downgrade'] ? 'taken back to ' : 'upgraded to ') . h($upgrading['version']) ?></b>
        <div class="going up-bar wide"><div class="bar"><span id="up-signin-fill" style="width:<?= $up_pc ?>%"></span></div>
          <div class="says" id="up-signin-says" data-no-i18n><?= h($upgrading['words']) ?></div></div>
        <div class="small" id="up-signin-sub"><?= $upgrading['state'] === 'failed'
              ? h($upgrading['said'] ?: 'its output is in /var/lib/fake-igd/upgrade/last.log') . ' - this page loads again once the API answers.'
              : 'fake-igd.service and these pages restart once - this page loads again by itself when they are back.' ?></div>
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
    <div id="mfa-box" data-stage="<?= h($mfa) ?>" hidden></div>
    <form id="signin-form" autocomplete="on"<?= $mfa !== '' ? ' hidden' : '' ?>>
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
    api('login', {name: $('in-name').value, password: $('in-pass').value}).then(function (d) {
      if (d && d.mfa) { form.hidden = true; mfaStep(); return; }
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
  if ($('mfa-box').dataset.stage) mfaStep();
  else $('in-name').focus();
  /* An upgrade going on (1.7.2): followed here, and the page loaded again once the API is back. */
  if ($('up-signin')) {
    var back = function () {
      fetch('?api=upgrade-state', {credentials: 'same-origin'}).then(function (r) { return r.json(); }).then(function (d) {
        var u = d.upgrading;
        if (d.api && (!u || u.state !== 'running')) { location.reload(); return; }
        if (u && u.state === 'running') {
          var pc = Math.round(Math.min(84, 5 + 76 * Math.min(0.97, u.part / Math.max(1, u.parts || 13))));
          $('up-signin-fill').style.width = pc + '%';
          $('up-signin-says').textContent = u.words + (u.parts ? ' · step ' + u.part + ' of ' + u.parts : '');
        }
      }).catch(function () { /* nginx or PHP restarting: asked again */ });
    };
    setInterval(back, 2000);
  }
}());
</script>
</body>
</html>
<?php exit; endif; ?>

<header>
  <h1 data-no-i18n><?= h($site ?: 'fake-igd') ?> <span class="host"><?= h($host) ?></span></h1>
  <span id="state-pill" class="pill unknown"><span class="dot"></span><span>…</span></span>
  <div class="hload" id="hload" hidden aria-live="off"></div>
  <div class="spacer"></div>
  <div class="btnrow">
    <button type="button" class="btn small mebtn" id="me-btn" data-icon="person"
            title="The account you are signed in as: what it may do, its password, the columns of the tables and your settings in a file."><span class="me-name" data-no-i18n><?= h($me['name']) ?></span></button>
    <button class="btn small" id="signout" data-icon="out">Sign out</button>
  </div>
  <div class="updated" id="updated" title="Click to pause or resume the live updates">
    <b>live</b><br><span id="updated-at">…</span></div>
</header>

<div id="upband" class="offline upband" hidden aria-live="polite"></div>
<div id="offline" class="offline" hidden></div>
<div id="phpsafety" class="offline" hidden></div>
<div id="problems" class="offline warnish" hidden></div>
<div id="trials" class="trials" hidden></div>

<div class="tabs" role="tablist">
  <button role="tab" aria-selected="true" data-tab="overview" data-icon="chart"
          title="The shape of the day: who looked for a UPnP router, which ports were asked for, what was answered.">Overview</button>
  <button role="tab" aria-selected="false" data-tab="ports" data-icon="net"
          title="Every port a client asked for with AddPortMapping, one row per client, protocol and port. Click a row for every request of it - and the rules for the router are made from them.">Ports<span class="count" id="tabn-ports"></span></button>
  <button role="tab" aria-selected="false" data-tab="requests" data-icon="list"
          title="Every SOAP request, newest first. Click a row for everything it carried and every step of the answer.">Requests<span class="count" id="tabn-requests"></span></button>
  <button role="tab" aria-selected="false" data-tab="clients" data-icon="people"
          title="The devices that looked for a UPnP router or asked for ports. Click a row for all of one.">Clients<span class="count" id="tabn-clients"></span></button>
  <button role="tab" aria-selected="false" data-tab="mappings" data-icon="router"
          title="What the clients believe is open now, with the lease left. Nothing is open on the router.">Mappings<span class="count" id="tabn-mappings"></span></button>
  <button role="tab" aria-selected="false" data-tab="mdns" data-icon="wifi"
          title="The mDNS reflector on this server (avahi-daemon): whether it runs and reflects, between which interfaces, and every service mDNS shows on them now.">mDNS<span class="count" id="tabn-mdns"></span></button>
  <button role="tab" aria-selected="false" data-tab="log" data-icon="log"
          title="fake-igd's own log, as upnp log shows it - followed live.">Log</button>
  <button role="tab" aria-selected="false" data-tab="events" data-icon="history"
          title="Every change of a setting, every account made or taken away, every sign-in and every upgrade - and the service's own log.">Events</button>
  <button role="tab" aria-selected="false" data-tab="settings" data-icon="gear"
          title="How fake-igd answers, the network, the notifications, the accounts of these pages, the firewall, the server, the data and the upgrades.">Settings<span class="count after-n" id="tabn-settings"></span></button>
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
      red refused, blue the other questions. Press a bar to open that hour.</p>
    <div class="chart" id="ov-chart"><div class="empty">…</div><div class="tip"></div></div>
    <div class="legend">
      <span><i style="background:#3fb950"></i>confirmed</span>
      <span><i style="background:#f85149"></i>refused</span>
      <span><i style="background:#58a6ff"></i>other questions</span>
    </div>
  </div>
  <div class="grid halves" style="margin-top:14px">
    <div class="card facet"><h2>Asked for the most</h2><div id="ov-ports"></div></div>
    <div class="card facet"><h2>What was answered</h2><div id="ov-results"></div></div>
    <div class="card facet"><h2>Who asks</h2><div id="ov-clients"></div></div>
    <div class="card facet"><h2>What is asked</h2><div id="ov-actions"></div></div>
  </div>
</section>

<!-- ===================== Ports ===================== -->
<section class="panel" id="tab-ports" hidden>
  <div class="card full" data-hold>
    <h2>Ports asked for <span class="right" id="pt-said"></span></h2>
    <p class="note">Every port a client asked for (AddPortMapping), one row per client, protocol
      and port: how many times, when first and last, what it said it was for and what it was
      answered. Click a row for every request of it. This is what to forward on the real router -
      <b>Rules for the router</b> makes them (as <span class="mono">upnp dnat</span>).</p>
    <div class="filterbar btnrow filters">
      <input type="search" id="pt-q" placeholder="an address, a port, a description - or client:, port:, proto:…" style="flex:1;min-width:200px">
      <select id="pt-proto"><option value="">TCP and UDP</option><option value="TCP">TCP only</option><option value="UDP">UDP only</option></select>
      <select id="pt-result"><option value="">every answer</option><option value="accepted">confirmed</option><option value="refused">refused</option></select>
      <span id="pt-hours" title="How far back the ports are counted."></span>
      <select id="pt-per"><option>50</option><option selected>100</option><option>500</option></select>
      <button class="btn cmd" id="dn-open" data-icon="router" title="Port forwarding rules for the real router, made from these ports - consecutive ports merged into ranges.">Rules for the router</button>
    </div>
    <div id="pt-table" class="scroll rowsonly"></div>
    <div class="pager" id="pt-pager"></div>
  </div>
</section>

<!-- ===================== Requests ===================== -->
<section class="panel" id="tab-requests" hidden>
  <div class="card full" data-hold>
    <h2>Requests <span class="right" id="rq-said"></span></h2>
    <p class="note">Every SOAP request fake-igd was asked, newest first - from
      <span class="mono">requests.jsonl</span>. Click a row for everything it carried, every step
      of the answer and what the log said at that moment. Old lines go with the log's rotation
      (Settings → Disks and logs).</p>
    <div class="btnrow filters">
      <input type="search" id="rq-q" placeholder="an address, a port, a description - or client:, port:, result:…" style="flex:1;min-width:200px">
      <select id="rq-result">
        <option value="">everything</option><option value="ports">ports asked for only</option>
        <option value="accepted">confirmed</option><option value="refused">refused</option>
        <option value="other">the other questions</option>
      </select>
      <select id="rq-action"><option value="">every action</option></select>
      <select id="rq-client"><option value="">every client</option></select>
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
      ports - with its PTR name, what it said it is, and the ports it asked for. Click a row for
      all of one.</p>
    <div class="filterbar btnrow filters">
      <input type="search" id="cl-q" placeholder="an address, a name - or agent:, port:…" style="flex:1;min-width:200px">
      <span id="cl-hours" title="How far back the clients are counted."></span>
      <select id="cl-per"><option>50</option><option selected>100</option><option>500</option></select>
    </div>
    <div id="cl-table" class="scroll rowsonly"></div>
    <div class="pager" id="cl-pager"></div>
  </div>
</section>

<!-- ===================== Mappings ===================== -->
<section class="panel" id="tab-mappings" hidden>
  <div class="card full" data-hold>
    <h2>Mappings now <span class="right" id="mp-said"></span></h2>
    <p class="note">What the clients <b>believe</b> is open now, and the lease left. Nothing is open on
      the router: fake-igd only says so. Kept only while the answer is <i>accept</i> and the mode
      <i>active</i>. Click a row for all of one.</p>
    <div class="filterbar btnrow filters">
      <input type="search" id="mp-q" placeholder="an address, a port, a description…" style="flex:1;min-width:200px">
      <select id="mp-proto"><option value="">TCP and UDP</option><option value="TCP">TCP only</option><option value="UDP">UDP only</option></select>
    </div>
    <div id="mp-table" class="scroll rowsonly"></div>
  </div>
</section>

<?php include __DIR__ . '/tabs/mdns.php'; ?>

<!-- ===================== Log ===================== -->
<section class="panel" id="tab-log" hidden>
  <div class="card full" data-hold>
    <h2>The service's own log <span class="right mono small muted" id="lg-file" data-no-i18n></span></h2>
    <p class="note">The tail of fake-igd's own log, coloured as <span class="mono">upnp log</span>
      colours it, followed live. What is typed keeps only the lines with it (a regular expression
      works). Switch the log level to <i>DEBUG</i> in Settings → Logs and state to have it say every
      step of every request.</p>
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
    <h2>What fake-igd has done</h2>
    <p class="note">Every change of a setting, every account made or taken away, every sign-in and
      every upgrade - on these pages and on the command line. Kept in the database, so it survives
      a restart.</p>
    <div class="btnrow filters">
      <input type="search" id="ev-q" placeholder="anything in an event…" style="flex:1;min-width:200px">
      <select id="ev-kind"><option value="">everything</option></select>
      <span id="ev-time" title="How far back the events go."></span>
    </div>
    <div id="ev-table" class="scroll rowsonly"></div>
    <div class="pager" id="ev-pager"></div>
  </div>
  <div class="card full fulladmin-only aside">
    <h2>The service's own log</h2>
    <p class="note">The tail of <span class="mono" id="log-file" data-no-i18n>/var/log/fake-igd/fake-igd.log</span>.
      Switch the log level to <i>DEBUG</i> in Settings → Logs and state to have it say every step
      of every request; the Log tab follows it live.</p>
    <div class="btnrow"><button class="btn cmd" id="log-read" data-icon="log">Read it</button>
      <select id="log-lines"><option>200</option><option selected>600</option><option>2000</option></select></div>
    <pre class="lines" id="log-out" style="margin-top:12px" hidden></pre>
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
    <button type="button" class="fulladmin-only" data-pane="mailq" data-icon="list" title="Every mail sent and what became of it: sent, waiting for another try, failed.">Outgoing mail <span class="nav-badge" id="mq-badge" hidden></span></button>
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

<?php foreach (glob(__DIR__ . '/panes/*.php') ?: [] as $igd_pane) { include $igd_pane; } ?>

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
var PHP_SAFETY = <?= ($me['role'] ?? '') === 'fulladmin' ? json_encode(igd_php_safety(), JSON_HEX_TAG | JSON_HEX_AMP) : 'null' ?>;
</script>
<?php foreach (['core.js', 'cols.js', 'hload.js', 'admin.js'] as $igd_js): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/<?= $igd_js ?>?v=<?= h(IGD_VERSION) ?>-<?= (int) @filemtime(dirname(__DIR__) . '/assets/' . $igd_js) ?>"></script>
<?php endforeach; ?>
<?php foreach (glob(dirname(__DIR__) . '/assets/pane-*.js') ?: [] as $igd_js): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/<?= h(basename($igd_js)) ?>?v=<?= h(IGD_VERSION) ?>-<?= (int) @filemtime($igd_js) ?>"></script>
<?php endforeach; ?>
</body>
</html>
