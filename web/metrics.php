<?php
/* metrics.php - Prometheus' scrape of this machine (as otp's, 1.6.0): GET /metrics with
   Authorization: Bearer TOKEN. The API checks the token and where the request comes from
   (POST /api/metrics/scrape - a route that needs no sign-in, the API token still); nothing
   is said without both. A wrong or missing token is a 401, a network not let in a 403,
   metrics switched off (Settings → Monitoring) a 404. */
declare(strict_types=1);
require_once __DIR__ . '/igd-api.php';
header('Cache-Control: no-store');
$auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
$token = preg_match('/^Bearer ([A-Za-z0-9_.~+\/=-]{24,200})$/', trim($auth), $m) ? $m[1] : '';
if ($token === '') {
    http_response_code(401);
    header('WWW-Authenticate: Bearer realm="fake-igd metrics"');
    header('Content-Type: text/plain; charset=utf-8');
    echo "a token is needed: Authorization: Bearer ...\n";
    exit;
}
[$status, $body] = igd_call('/api/metrics/scrape', 'POST', ['token' => $token], 15.0);
$got = json_decode($body, true);
$said = is_array($got) ? (int) ($got['status'] ?? 0) : 0;
if ($status !== 200 || $said !== 200 || !isset($got['text']) || !is_string($got['text'])) {
    $code = $status === 0 ? 503 : ($status !== 200 ? $status : ($said ?: 503));
    http_response_code($code);
    if ($code === 401) {
        header('WWW-Authenticate: Bearer realm="fake-igd metrics", error="invalid_token"');
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo ($status === 0 ? 'the API is not answering' : (string) (is_array($got) ? ($got['error'] ?? 'no') : 'no')) . "\n";
    exit;
}
header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
echo $got['text'];
