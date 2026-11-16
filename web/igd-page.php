<?php
/**
 * igd-page.php — what the pages share: the headers, the head of a page.
 *
 * otp's otp-page.php, for fake-igd: one nonce per page in the
 * Content-Security-Policy, nothing loaded from anywhere but this server,
 * requests that were never this page's refused before anything is read.
 * Included by admin/index.php, never a page of its own.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

const IGD_VERSION = '1.5.1';

header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

/* The address bar, as it was typed (otp 1.0.33/1.0.61): nginx counts sign-in attempts by
   looking for api=login in it, and PHP takes the last of two `api=` or decodes `%61pi`
   into `api` where nginx does not - a request written so that the two read it
   differently is refused before either looks at it. */
$igd_query = (string) ($_SERVER['QUERY_STRING'] ?? '');
if (substr_count($igd_query, 'api=') > 1 || preg_match('/(^|&)[^=&]*%/', $igd_query)
    || preg_match('/(^|&)api=[^&]*[%+]/', $igd_query)
    || preg_match('/(^|&)(?![A-Za-z0-9_-]*(=|&|$))/', $igd_query)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => 'that address is not one of this page\'s']);
    exit;
}
unset($igd_query);

$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; "
     . "script-src 'self' 'nonce-$nonce'; "
     . "style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'nonce-$nonce'; "
     . "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
     . "base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

function h($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* The body as it came, objects kept objects (otp 1.0.61). */
function sent_json(): object
{
    $raw = file_get_contents('php://input');
    $got = $raw === false || $raw === '' ? null : json_decode($raw, false);
    return is_object($got) ? $got : new stdClass();
}

function sent_body(): array
{
    $raw = file_get_contents('php://input');
    $got = $raw === false || $raw === '' ? null : json_decode($raw, true);
    return is_array($got) ? $got : [];
}

/** Requests that were never this page's: refused before anything is read - JSON only,
    same origin only, a few hundred kilobytes (a new version's package: a few MB). */
function igd_guard_post(): void
{
    $told = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    $kind = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    $big = ($_GET['api'] ?? '') === 'upgrade-package';
    if ($told > ($big ? 96 : 1) * 1024 * 1024) {
        http_response_code(413);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'that is too much to send here']);
        exit;
    }
    $from = (string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
    $origin = (string) ($_SERVER['HTTP_ORIGIN'] ?? '');
    $foreign = false;
    if ($from === '' && $origin !== '' && $origin !== 'null') {
        $oh = strtolower((string) parse_url($origin, PHP_URL_HOST));
        $op = parse_url($origin, PHP_URL_PORT);
        $hh = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
        $want = $oh . ($op ? ':' . $op : '');
        $foreign = $oh === '' || ($hh !== $want && $hh !== $oh);
    }
    if (strpos($kind, 'application/json') !== 0
            || ($from !== '' && $from !== 'same-origin' && $from !== 'none') || $foreign) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'that request did not come from this page']);
        exit;
    }
}

/** The head of a page: the words-swapper (English only for now), the style, the icon. */
function igd_head(string $title, string $nonce): void
{
    $v = IGD_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/fake-igd.css')
       . '-' . (int) @filemtime(__DIR__ . '/assets/core.js');
    echo "<meta charset=\"utf-8\">\n";
    echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    echo '<title>' . h($title) . "</title>\n";
    echo '<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">' . "\n";
    echo '<meta name="theme-color" content="#0d1117">' . "\n";
    echo '<script nonce="' . h($nonce) . '">window.OTP_LANGS = [{"code":"en","name":"English","english":"English"}];'
       . ' window.OTP_LANG = "en";</script>' . "\n";
    echo '<script nonce="' . h($nonce) . '" src="/assets/i18n.js?v=' . h($v) . '"></script>' . "\n";
    echo '<link rel="stylesheet" nonce="' . h($nonce) . '" href="/assets/fake-igd.css?v=' . h($v) . '">' . "\n";
}
