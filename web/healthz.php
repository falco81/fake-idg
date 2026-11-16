<?php
/* healthz.php - is this server able to answer? (as otp's /healthz)
   200 and "ok NODE" when the API answers and its database opens; 503 and why
   otherwise. Says nothing else, so anybody may ask. */
declare(strict_types=1);
require_once __DIR__ . '/igd-api.php';
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
if (igd_token() === null) {
    http_response_code(503);
    echo "down: the pages cannot read the API's token\n";
    exit;
}
$got = igd_get('/api/health', 3.0);
if (!is_array($got) || empty($got['ok'])) {
    http_response_code(503);
    echo "down: the API is not answering\n";
    exit;
}
if (isset($got['database']['ok']) && !$got['database']['ok']) {
    http_response_code(503);
    echo "down: the database does not open\n";
    exit;
}
echo 'ok ' . preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($got['node'] ?? '')) . "\n";
