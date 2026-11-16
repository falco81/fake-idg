<?php
/**
 * igd-art.php — the picture of the sign-in page (otp's otp-art.php, for fake-igd).
 *
 * Drawn in the page's own colours (fake-igd.css: .signart), so it follows the
 * look of the page and needs nothing fetched: the PS5 asking for ports on the
 * left, fake-igd answering in the middle, the log on the right - otp's picture
 * of the administration ('radius'), with fake-igd's words. One picture: there
 * is no picking here (otp picks one per page under its enrolment pages).
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

function igd_art_svg(): string
{
    $lines = '';
    foreach ([[42, 76, ''], [56, 58, ' good'], [70, 88, ''], [84, 44, ' bad'], [98, 70, ''], [112, 52, ' good'],
              [126, 64, ''], [140, 38, ' good']] as $l) {
        $lines .= '<rect class="logline' . $l[2] . '" x="26" y="' . $l[0] . '" width="' . $l[1] . '" height="6" rx="3"/>';
    }
    $bricks = '';
    foreach ([[306, 46, 42], [352, 46, 42], [306, 68, 30], [340, 68, 54], [306, 90, 54], [364, 90, 30],
              [306, 112, 20], [360, 112, 34]] as $b) {
        $bricks .= '<rect class="brick" x="' . $b[0] . '" y="' . $b[1] . '" width="' . $b[2] . '" height="18" rx="3"/>';
    }
    return '<svg class="signart art-radius" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
        . '<title id="sa-title">What this program does</title>'
        . '<defs><radialGradient id="sa-glow" cx="50%" cy="42%" r="62%">'
        . '<stop offset="0" stop-color="var(--info)" stop-opacity=".30"/>'
        . '<stop offset="1" stop-color="var(--info)" stop-opacity=".04"/></radialGradient></defs>'
        . '<rect class="plate" x=".75" y=".75" width="418.5" height="186.5" rx="14"/>'
        . '<g>' . $lines . '</g><text class="lbl" x="26" y="32">THE PS5 ASKS</text>'
        . '<path class="halo" d="M210 40 l52 18 v38c0 30-21 50-52 60c-31-10-52-30-52-60V58z" fill="var(--info)" opacity=".35"/>'
        . '<path class="shield" d="M210 44 l48 17 v35c0 28-19 46-48 55c-29-9-48-27-48-55V61z"/>'
        /* a router: its box, its lights and its two aerials */
        . '<rect x="188" y="96" width="44" height="20" rx="4" fill="none" stroke="var(--ok)" stroke-width="3"/>'
        . '<path d="M196 106h3M205 106h3M214 106h3" stroke="var(--ok)" stroke-width="3" stroke-linecap="round"/>'
        . '<path d="M196 96 l-6-12 M224 96 l6-12" stroke="var(--ok)" stroke-width="2.5" stroke-linecap="round"/>'
        . '<text class="lbl" x="210" y="32" text-anchor="middle">A ROUTER THAT IS NOT</text>'
        . '<path class="flow" d="M118 100 H158"/>'
        . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/>'
        . '<circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
        . '<g>' . $bricks . '</g><text class="lbl" x="394" y="32" text-anchor="end">THE PORTS IT WANTS</text>'
        . '<path class="through" d="M264 100 h36 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
        . '<text class="lbl" x="210" y="172" text-anchor="middle">ASKED · ANSWERED · WRITTEN DOWN</text></svg>';
}
