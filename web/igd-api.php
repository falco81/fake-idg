<?php
/**
 * igd-api.php — the pages' side of the API (otp's otp-api.php, for fake-igd).
 *
 * The pages hold nothing and decide nothing: fake-igd-api.service answers on
 * http://127.0.0.1:<api_port>, and this is the thin client that talks to it.
 * Two things travel with every request: the API token the API dropped in a
 * file readable only by its account and the pages' group (fake-igd-web), and
 * the session of whoever is signed in. The browser holds the session in a
 * cookie it cannot read itself (HttpOnly) and never sees the token at all.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

const IGD_HOST = '127.0.0.1';
define('IGD_RUN', getenv('FAKE_IGD_RUN') ?: '/run/fake-igd-api');
/* api_port as the API wrote it down when it started; 9862 where it has not. */
define('IGD_PORT', (static function (): int {
    $p = (int) trim((string) @file_get_contents(IGD_RUN . '/api-port'));
    return ($p >= 1024 && $p <= 65535) ? $p : 9862;
})());
define('IGD_TOKEN', IGD_RUN . '/api-token');
const IGD_COOKIE = 'igd_session';
const IGD_COOKIE_PATH = '/admin/';

function igd_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    return strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

/** The machine itself - the operator at the console, who may be told where things are. */
function igd_local(): bool
{
    return in_array((string) ($_SERVER['REMOTE_ADDR'] ?? ''), ['127.0.0.1', '::1'], true);
}

function igd_token(): ?string
{
    if (!is_readable(IGD_TOKEN)) {
        return null;
    }
    $token = trim((string) @file_get_contents(IGD_TOKEN));
    return $token !== '' ? $token : null;
}

function igd_session(): string
{
    $got = (string) ($_COOKIE[IGD_COOKIE] ?? '');
    return preg_match('/^[A-Za-z0-9_-]{16,128}\z/', $got) === 1 ? $got : '';
}

function igd_set_session(string $token): void
{
    setcookie(IGD_COOKIE, $token, ['expires' => 0, 'path' => IGD_COOKIE_PATH, 'secure' => igd_https(),
                                   'httponly' => true, 'samesite' => 'Strict']);
}

function igd_clear_session(): void
{
    setcookie(IGD_COOKIE, '', ['expires' => time() - 3600, 'path' => IGD_COOKIE_PATH, 'secure' => igd_https(),
                               'httponly' => true, 'samesite' => 'Strict']);
}

/**
 * Ask the API. Returns [status, body-string]; status 0 means unreachable. A socket
 * spoken to by hand (as otp's): allow_url_fopen is off in the pool.
 */
function igd_call(string $path, string $method = 'GET', array|object|null $payload = null,
                  float $timeout = 30.0): array
{
    $token = igd_token();
    if ($token === null) {
        return [0, ''];
    }
    $headers = ['Accept: application/json', 'X-IGD-Token: ' . $token,
                'X-IGD-Client: ' . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''))];
    /* The name the pages were reached by (1.9.2, otp's X-Otp-Host): a passkey is bound to it - the
       API builds the name and the origin it checks from this, never from what the page sent. */
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if (preg_match('/^([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?\z/', $host)) {
        $headers[] = 'X-IGD-Host: ' . $host;
    }
    $session = igd_session();
    if ($session !== '') {
        $headers[] = 'X-IGD-Session: ' . $session;
    }
    $agent = preg_replace('/[^\x20-\x7e]/', '', substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200));
    if ($agent !== '') {
        $headers[] = 'User-Agent: ' . $agent;
    }
    $body = null;
    if ($payload !== null) {
        $body = json_encode($payload, JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            return [400, json_encode(['ok' => false, 'error' => 'a number in the request is too big']) ?: ''];
        }
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Content-Length: ' . strlen($body);
    } elseif ($method !== 'GET') {
        $headers[] = 'Content-Length: 0';
    }
    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client('tcp://' . IGD_HOST . ':' . IGD_PORT, $errno, $errstr, $timeout,
                                  STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);
    $request = $method . ' ' . $path . " HTTP/1.1\r\nHost: " . IGD_HOST . ':' . IGD_PORT
        . "\r\nConnection: close\r\n" . implode("\r\n", $headers) . "\r\n\r\n";
    if ($body !== null) {
        $request .= $body;
    }
    if (@fwrite($sock, $request) === false) {
        @fclose($sock);
        return [0, ''];
    }
    $raw = '';
    while (!feof($sock)) {
        $chunk = @fread($sock, 65536);
        if ($chunk === false || $chunk === '') {
            $info = stream_get_meta_data($sock);
            if (!empty($info['timed_out'])) {
                @fclose($sock);
                return [0, ''];
            }
            break;
        }
        $raw .= $chunk;
    }
    @fclose($sock);
    $split = strpos($raw, "\r\n\r\n");
    if ($split === false) {
        return [0, ''];
    }
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', substr($raw, 0, $split), $m)) {
        $status = (int) $m[1];
    }
    return [$status, substr($raw, $split + 4)];
}

function igd_get(string $path, float $timeout = 30.0): ?array
{
    [$status, $body] = igd_call($path, 'GET', null, $timeout);
    if ($status !== 200) {
        return null;
    }
    $data = json_decode($body, true);
    return is_array($data) ? $data : null;
}

/* An upgrade going on (1.7.2) - what otp's maintenance is to its pages: root's helper and
   install.sh --upgrade write how far it is into .upgrade.json beside these pages (root's,
   readable by all, never served by nginx: a name starting with a dot). Read here while
   fake-igd-api.service restarts, so the pages say "being upgraded" and follow it, rather
   than "the API is not answering". */
define('IGD_UPGRADE_FILE', getenv('FAKE_IGD_UPGRADE_STATE') ?: __DIR__ . '/.upgrade.json');
const IGD_UPGRADE_RUNS_S = 30 * 60;   /* a step longer than install.sh's own limit: not believed */
const IGD_UPGRADE_ENDED_S = 10 * 60;  /* an end said for as long as a page may take to see it */

/** The upgrade going on, or just ended, as root told the pages - or null. */
function igd_upgrading(): ?array
{
    static $got = false;
    if ($got !== false) {
        return $got;
    }
    $got = null;
    $f = IGD_UPGRADE_FILE;
    if (!is_file($f) || is_link($f) || @filesize($f) > 16384) {
        return null;
    }
    $d = json_decode((string) @file_get_contents($f), true);
    if (!is_array($d)) {
        return null;
    }
    $state = (string) ($d['state'] ?? '');
    $at = (float) ($d['at'] ?? 0);
    $age = time() - $at;
    if (!in_array($state, ['running', 'done', 'failed'], true) || $age < -60
        || $age > ($state === 'running' ? IGD_UPGRADE_RUNS_S : IGD_UPGRADE_ENDED_S)) {
        return null;
    }
    $text = static function ($v, int $most): string {
        $v = preg_replace('/[\x00-\x1f]/', '', (string) $v) ?? '';
        return function_exists('mb_substr') ? mb_substr($v, 0, $most) : substr($v, 0, $most);
    };
    $ver = static function ($v): string {
        return preg_match('/^\d+(\.\d+){1,3}\z/', (string) $v) ? (string) $v : '';
    };
    $got = [
        'state' => $state, 'id' => $text($d['id'] ?? '', 64),
        'version' => $ver($d['version'] ?? ''), 'from' => $ver($d['from'] ?? ''),
        'by' => $text($d['by'] ?? '', 100), 'downgrade' => !empty($d['downgrade']),
        'part' => max(0, (int) ($d['part'] ?? 0)), 'parts' => max(0, (int) ($d['parts'] ?? 0)),
        'words' => $text($d['words'] ?? '', 160), 'said' => $text($d['said'] ?? '', 300),
        'started' => (float) ($d['started'] ?? $at), 'at' => $at, 'now' => microtime(true),
        'pages' => IGD_VERSION_PAGES,
    ];
    return $got;
}

/* The version of these pages as they are on disk now: install.sh puts the new ones in half way. */
define('IGD_VERSION_PAGES', defined('IGD_VERSION') ? IGD_VERSION : '');

function igd_down_words(): string
{
    $u = igd_upgrading();
    if ($u && $u['state'] === 'running') {
        return 'fake-igd is being ' . ($u['downgrade'] ? 'taken back to ' : 'upgraded to ') . ($u['version'] ?: 'a new version')
            . ' - the API restarts with it and answers again in a moment';
    }
    return 'the API is not answering — is fake-igd-api.service running?';
}

/** The answer of an API that does not answer: 503, and - while an upgrade goes on - what it is,
    so that the page draws the upgrade rather than an error. */
function igd_down_answer(?string $words = null): void
{
    http_response_code(503);
    $u = igd_upgrading();
    $out = ['ok' => false, 'error' => $words ?? igd_down_words()];
    if ($u) {
        if (igd_session() === '') {
            unset($u['by'], $u['said'], $u['id']);      /* who asked: to a page signed in only */
        }
        $out['upgrading'] = $u;
        $out['error'] = igd_down_words();
    }
    echo json_encode($out, JSON_INVALID_UTF8_SUBSTITUTE);
}

/** A reply of the API straight through to the browser. */
function igd_relay(string $path, string $method = 'GET', array|object|null $payload = null,
                   float $timeout = 30.0): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    if (igd_token() === null) {
        igd_down_answer(igd_local()
            ? 'the API token is unreadable — is fake-igd-api.service running, and is ' . IGD_TOKEN
              . ' readable by the web server (group fake-igd-web)?'
            : igd_down_words());
        return;
    }
    [$status, $body] = igd_call($path, $method, $payload, $timeout);
    if ($status === 0) {
        igd_down_answer();
        return;
    }
    /* The status every page asks every few seconds carries the upgrade too (1.7.2): also one
       the API does not know of - install.sh --upgrade run by hand. */
    if ($status === 200 && $method === 'GET' && strpos($path, '/api/status') === 0 && igd_upgrading()) {
        $d = json_decode($body, false);         /* objects kept objects, {} never [] */
        if ($d instanceof stdClass) {
            $d->upgrading = igd_upgrading();
            $body = (string) json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        }
    }
    http_response_code($status);
    echo igd_squeeze($body);
}

/** A large answer compressed for a browser that takes gzip. */
function igd_squeeze(string $body): string
{
    $accepts = (string) ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '');
    if (strlen($body) < 2048 || !function_exists('gzencode') || headers_sent()
        || stripos($accepts, 'gzip') === false || ini_get('zlib.output_compression')) {
        return $body;
    }
    $packed = gzencode($body, 4);
    if ($packed === false) {
        return $body;
    }
    header('Content-Encoding: gzip');
    header('Vary: Accept-Encoding');
    header('Content-Length: ' . strlen($packed));
    return $packed;
}

/** Whoever is signed in, as the API sees them, or null. */
function igd_whoami(): ?array
{
    if (igd_session() === '') {
        return null;
    }
    $got = igd_get('/api/auth/whoami', 5.0);
    $who = is_array($got) ? ($got['who'] ?? null) : null;
    if (!is_array($who)) {
        return null;
    }
    /* An empty layout is an object, not a list, to the page (as otp's). */
    foreach (['prefs', 'cols'] as $k) {
        $v = $who[$k] ?? null;
        $who[$k] = (is_array($v) && $v) ? $v : new stdClass();
    }
    return $who;
}

/** PHP and php2shell (CVE-2026-109618, CVE-2026-109619), said to a full administrator at the top
    of the pages until it is fixed (otp's otp_php_safety): the version running this page, the one
    with the fix, and whether the two settings that close the way in are off
    (deploy/99-php2shell.ini). */
function igd_php_safety(): array
{
    $fixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
    $branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    if (isset($fixed[$branch])) {
        $patched = version_compare(PHP_VERSION, $fixed[$branch], '>=');
        $needs = $fixed[$branch];
    } else {
        $patched = version_compare($branch, '8.5', '>');
        $needs = $patched ? '' : '8.2.35';
    }
    $reading = (string) ini_get('enable_post_data_reading');
    $progress = (string) ini_get('session.upload_progress.enabled');
    $off = function (string $v): bool {
        return in_array(strtolower($v), ['0', '', 'off', 'false', 'no'], true);
    };
    return [
        'version'  => PHP_VERSION,
        'sapi'     => PHP_SAPI,
        'patched'  => $patched,
        'needs'    => $needs,
        'guarded'  => $off($reading) && $off($progress),
        'post_reading' => !$off($reading),
        'upload_progress' => !$off($progress),
    ];
}
