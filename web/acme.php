<?php
/* acme.php - the answer to an ACME CA's HTTP-01 challenge (otp's acme.php, for fake-igd).
   nginx's server on port 80 sends http://NAME/.well-known/acme-challenge/TOKEN here; the
   answer is kept by fake-igd-api while an order waits for the CA (Settings → Automatic
   certificates), and asked of it by a public road (the API token still). Nothing else is
   said, so anybody may ask. */
declare(strict_types=1);
require_once __DIR__ . '/igd-api.php';
header('Cache-Control: no-store');
$uri = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
if (!preg_match('#^/\.well-known/acme-challenge/([A-Za-z0-9_-]{8,256})$#', $uri, $m)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}
$got = igd_get('/api/acme/challenge?token=' . $m[1], 10.0);
if (!is_array($got) || !isset($got['auth']) || !is_string($got['auth'])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}
header('Content-Type: application/octet-stream');
echo $got['auth'];
