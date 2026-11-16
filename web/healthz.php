<?php
/* healthz.php - what a load balancer or a monitor asks: is this server able to answer? (otp's /healthz)
   200 and "ok NODE" when the API answers and its database opens; 503 and why otherwise. Nothing else
   is said, so it may be asked by anybody.
   ?check=web (the default) - the pages: nginx, PHP, the API, the database;
   ?check=service - that, and fake-igd.service running (what answers the PS5) - for monitoring. */
declare(strict_types=1);
require_once __DIR__ . '/igd-api.php';
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
/* The API not answering while an upgrade goes on (1.7.2): said as otp's /healthz says a node in
   maintenance - 503 and "maintenance NODE" - not as a server that is down. */
function igd_health_down(string $why): void
{
    http_response_code(503);
    $u = igd_upgrading();
    if ($u && $u['state'] === 'running') {
        $node = preg_replace('/[^A-Za-z0-9._-]/', '', explode('.', (string) gethostname())[0]);
        echo "maintenance $node: being upgraded to " . ($u['version'] ?: '?') . "\n";
        exit;
    }
    echo $why;
    exit;
}
if (igd_token() === null) {
    // Said as it is (otp 1.0.36): the API may well be up; it is the pages that cannot reach it.
    igd_health_down("down: the pages cannot read the API's token\n");
}
$check = (string) ($_GET['check'] ?? 'web');
if (!in_array($check, ['web', 'service'], true)) {
    $check = 'web';
}
$got = igd_get('/api/health' . ($check === 'service' ? '?check=service' : ''), 3.0);
if (!is_array($got) || empty($got['ok'])) {
    igd_health_down("down: the API is not answering\n");
}
if (isset($got['database']['ok']) && !$got['database']['ok']) {
    http_response_code(503);
    echo "down: the database does not open\n";
    exit;
}
$node = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($got['node'] ?? ''));
if ($check === 'service' && ($got['service'] ?? '') !== 'active') {
    $u = igd_upgrading();
    if ($u && $u['state'] === 'running') {
        http_response_code(503);
        echo "maintenance $node: being upgraded to " . ($u['version'] ?: '?') . "\n";
        exit;
    }
    http_response_code(503);
    echo 'down: fake-igd.service is ' . preg_replace('/[^a-z-]/', '', (string) ($got['service'] ?? 'unknown')) . " on $node\n";
    exit;
}
echo "ok $node\n";
