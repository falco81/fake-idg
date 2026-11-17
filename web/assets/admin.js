/* The time pickers (otp's, 1.0.53), in place of the <select>s they replace. */
timePicker('ov-hours', {start: {k: 'rel', s: 86400}});
timePicker('rq-hours', {start: {k: 'rel', s: 86400}});
timePicker('pt-hours', {start: {k: 'all'}, all: true});
timePicker('cl-hours', {start: {k: 'all'}, all: true});
if ($('ev-time')) timePicker('ev-time', {start: {k: 'all'}, all: true});
/* admin.js - the web pages of fake-igd, drawn the way otp draws its administration
   (otp 1.0.288's admin.js, piece for piece, for one fake UPnP router): the same header,
   tabs, rail, popups and panels (core.js), over fake-igd-api. The page works nothing out
   for itself. The panes of Settings are each a pane-NAME.js of their own (PANE_LOAD.NAME). */
'use strict';

ADMIN = !!(ME && ME.role === 'fulladmin');
var LIVE = true, SERIAL = STATUS ? STATUS.serial : '', PANE = 'answer';
var SETTINGS = null, DIRTY = {}, DRAWN_NODE = '';
var PAGE = {ports: 0, requests: 0, clients: 0, events: 0};
/* The panes of Settings (1.6.0): each its own pane-NAME.js says how it is drawn -
   PANE_LOAD.NAME() when it is shown, PANE_TICK.NAME(status) with every live update while it is. */
var PANE_LOAD = window.PANE_LOAD || {}, PANE_TICK = window.PANE_TICK || {};
window.PANE_LOAD = PANE_LOAD; window.PANE_TICK = PANE_TICK;

function roleWords(role) { return role === 'fulladmin' ? 'full admin' : 'read only'; }
function roleTone(role) { return role === 'fulladmin' ? 'violet' : 'dim'; }

/* ---- what this account may not even see ---------------------------------- */
(function roles() {
  document.querySelectorAll('.admin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  document.querySelectorAll('.fulladmin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  if (!ADMIN) $('readonly-note').hidden = false;
  if (!ADMIN) $('save-bar').hidden = true;
}());
dressButtons(document);

/* ---- PHP and php2shell, said to an administrator (as otp's) -------------- */
(function phpSafety() {
  var box = $('phpsafety'), s = typeof PHP_SAFETY === 'undefined' ? null : PHP_SAFETY;
  if (!box || !s || s.patched) return;
  /* A distribution that backported the fix keeps the old number; the API reads the packages'
     changelog, and when it says the fix is in, so be it (otp's). */
  if (typeof STATUS !== 'undefined' && STATUS && STATUS.php && STATUS.php.fixed) return;
  box.hidden = false;
  box.classList.toggle('warnish', !!s.guarded);
  box.textContent = 'PHP ' + s.version + ' running this page may have php2shell '
    + '(CVE-2026-109618, CVE-2026-109619): remote code execution by anybody who can reach the '
    + 'web server. Update it - ' + (s.needs ? s.needs + ' or later, ' : '') + 'or the package '
    + 'your distribution fixed (dnf upgrade \'php*\') - and restart php-fpm; ./install.sh '
    + '--upgrade does it. A distribution that backported the fix keeps the old number: check '
    + 'rpm -q --changelog php-fpm | grep CVE-2026-109618.';
}());

/* ---- tabs ------------------------------------------------------------------ */
var TABS = ['overview', 'ports', 'requests', 'clients', 'mappings', 'gateway', 'mdns', 'log', 'events', 'settings'];
window.optShowTab = function (name) {
  if (TABS.indexOf(name) < 0) name = 'overview';
  /* A tab this account may not use (its button is hidden) is not opened by the address either. */
  var btn = document.querySelector('.tabs button[data-tab="' + name + '"]');
  if (btn && btn.hidden) name = 'overview';
  TAB = name;
  document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
    b.setAttribute('aria-selected', b.getAttribute('data-tab') === name ? 'true' : 'false');
  });
  TABS.forEach(function (one) { if ($('tab-' + one)) $('tab-' + one).hidden = one !== name; });
  writeHash();
  holdTheTallOnes();
  onTab(name);
};
document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
  b.onclick = function () { showTab(b.getAttribute('data-tab')); };
});
function writeHash() {
  var want = '#' + TAB + (TAB === 'settings' ? '/' + PANE : '');
  if (location.hash !== want) try { history.replaceState(null, '', want); } catch (e) { }
}
function onTab(name) {
  explainWhatWasDrawn(document);
  if (name === 'overview') loadOverview();
  if (name === 'ports') loadPorts();
  if (name === 'requests') loadRequests();
  if (name === 'clients') loadClients();
  if (name === 'mappings') loadMappings();
  if (name === 'mdns' && typeof loadMdnsTab === 'function') loadMdnsTab();
  if (name === 'gateway' && typeof loadGatewayTab === 'function') loadGatewayTab();
  if (name === 'log') loadLog(true);
  if (name === 'events') loadEvents();
  /* Coming back with changes not yet saved keeps them (otp 1.0.15, 1.0.94). */
  if (name === 'settings') loadSettings(!Object.keys(DIRTY || {}).length && !Object.keys(PENDING || {}).length);
}

/* ---- the header and the live updates -------------------------------------- */
function paintHeader(s) {
  STATUS = s;
  /* The load meter (otp 1.0.253): started the first time Settings - About has it on. */
  if (s && s.perf_meter && typeof hloadLoop === 'function' && !HLOAD.timer) hloadLoop();
  var hs = document.querySelector('header .host');
  if (hs && s.node) {
    if (hs._base === undefined) hs._base = hs.textContent;
    hs.textContent = hs._base + ' · ' + s.node;
    hs.title = 'this page is answered by ' + s.node + ' · fake-igd ' + (s.version || '');
  }
  upgradeFromStatus(s);
  var upOn = upgradeExpected();
  /* While an upgrade goes on, the service restarting is what it does (fake-igd 1.7.2): not a
     problem in the bar at the top, nor a red pill - "in maintenance", as otp's pill says. */
  var probs = (s.problems || []).filter(function (p) { return !(upOn && /^fake-igd\.service is /.test(p)); });
  var pill = $('state-pill');
  var running = s.service && s.service.state === 'active';
  var passive = s.mode === 'passive';
  var kind = upOn ? 'warn' : (!running ? 'crit' : (probs.length || passive ? 'warn' : 'ok'));
  pill.className = 'pill ' + kind;
  pill.lastChild.textContent = upOn ? 'in maintenance' : (!running ? 'not answering' : (passive ? 'listening only'
    : (kind === 'warn' ? 'answering, with trouble' : 'answering')));
  pill.title = upOn ? upgradeWords(UPG.u) + ' - fake-igd.service and these pages restart once.'
    : (running ? 'fake-igd.service is running: mode ' + s.mode + ', AddPortMapping ' + s.mapping_response
    + ', port ' + s.http_port : 'fake-igd.service is ' + (s.service ? s.service.state : 'unknown') + '.');
  explainWhatWasDrawn(pill.parentNode);
  var pr = $('problems');
  clear(pr);
  probs.forEach(function (p, i) {
    if (i) pr.appendChild(el('br'));
    pr.appendChild(document.createTextNode(p));
  });
  pr.hidden = !probs.length;
  drawShellTrials(s);
  $('updated-at').textContent = clockWords(new Date());
  var st = s.stats || {};
  $('tabn-ports').textContent = st.ports ? num(st.ports) : '';
  /* As otp's Log: the refused of the last 24 hours, red - none, no number (needs stats.refused_24h of
     upnp.status_data; without it, every request as before). */
  if (st.refused_24h !== undefined) {
    $('tabn-requests').textContent = st.refused_24h ? num(st.refused_24h) : '';
    $('tabn-requests').classList.toggle('hot', st.refused_24h > 0);
  } else $('tabn-requests').textContent = st.requests ? num(st.requests) : '';
  $('tabn-clients').textContent = st.clients ? num(st.clients) : '';
  $('tabn-mappings').textContent = st.mappings ? num(st.mappings) : '';
  /* To be done by hand: a newer version waiting, beside Upgrades and Settings (otp's afterBadge). */
  var up = s.upgrade || {};
  var n = up.busy ? '…' : (up.newer ? '1' : '');
  if ($('up-badge')) $('up-badge').textContent = n;
  $('tabn-settings').textContent = ADMIN ? n : '';
}

/* A change on trial (otp 1.0.137): the network's new address - kept with a press, or it goes back
   by itself when its time runs out. On every page, with the time left counting down. (The
   firewall's own banner is drawn by its pane, pane-web.js, beside this one.) */
var TRIALS = {list: [], skew: 0, timer: null};
function trialsHere() {
  var host = $('trials-net');
  if (host) return host;
  host = el('div', 'trials');
  host.id = 'trials-net';
  host.style.margin = '0';
  $('trials').insertBefore(host, $('trials').firstChild);
  return host;
}
function trialsShown() {
  var all = $('trials');
  all.hidden = !Array.prototype.some.call(all.children, function (c) { return !c.hidden; });
}
function drawShellTrials(s) {
  TRIALS.list = ((s && s.trials) || []).filter(function (t) { return t.kind === 'net'; });
  TRIALS.skew = s && s.now ? s.now - Date.now() / 1000 : 0;
  var host = trialsHere();
  if (!TRIALS.list.length) {
    host.hidden = true; clear(host); trialsShown();
    if (TRIALS.timer) { clearInterval(TRIALS.timer); TRIALS.timer = null; }
    return;
  }
  host.hidden = false;
  trialsShown();
  liveFill(host, function (host) {
    TRIALS.list.forEach(function (t) {
      var row = el('div', 'trial');
      var words = el('div', 'trial-words');
      words.appendChild(el('b', '', 'The new network of ' + t.node + ' waits to be kept'));
      var left = el('span', 'trial-left mono');
      left.dataset.until = t.until;
      words.appendChild(document.createTextNode(' - '));
      words.appendChild(left);
      words.appendChild(el('div', 'small', 'Not kept, ' + t.node + ' goes back to its old network by itself. '
        + 'Keep it once you have checked that this server answers at its new address.'));
      row.appendChild(words);
      var tools = el('div', 'trial-tools');
      if (ADMIN) {
        var keep = cmdButton('Keep it', 'check', 'small primary');
        keep.onclick = function () { trialDo(t, 'keep', keep); };
        var back = cmdButton('Put the old back now', 'undo', 'small danger');
        back.onclick = function () {
          confirmThen('Put the old back now?', htmlText(t.node) + ' goes back to its old network.',
            'Put it back', function () { trialDo(t, 'back', back); });
        };
        tools.appendChild(keep);
        tools.appendChild(back);
      }
      row.appendChild(tools);
      host.appendChild(row);
    });
  }, true);
  shellTrialCount();
  if (!TRIALS.timer) TRIALS.timer = setInterval(shellTrialCount, 1000);
}
function shellTrialCount() {
  var now = Date.now() / 1000 + TRIALS.skew;
  document.querySelectorAll('#trials-net .trial-left').forEach(function (x) {
    var left = parseFloat(x.dataset.until) - now;
    x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) + ' left' : 'going back now';
  });
}
function trialDo(t, action, button) {
  busy(button, true);
  api('net', {action: action}).then(function (d) {
    toast(d.message, 'good');
    setTimeout(function () { api('status').then(paintHeader).catch(function () {}); }, 1500);
  }).catch(oops).then(function () { busy(button, false); });
}

var REDRAW_OWED = false;
/* One tick at a time (otp 1.0.265): under load an answer took longer than the 5 s between ticks. */
var TICK_OUT = 0;
var TAB_LIST = {overview: 'overview', ports: 'ports', requests: 'requests', clients: 'clients',
                mappings: 'mappings', events: 'events'};
function tick() {
  if (!LIVE || document.hidden) return;
  if (TICK_OUT && Date.now() - TICK_OUT < 60000) return;
  TICK_OUT = Date.now();
  api('status').then(function (s) {
    $('offline').hidden = true;
    var moved = s.serial !== SERIAL || REDRAW_OWED;
    SERIAL = s.serial;
    paintHeader(s);
    /* Not drawn again under somebody reading it (otp 1.0.57): a selection, the pointer over a
       help panel, a box being typed in, or a page further back. */
    var here = $('tab-' + TAB);
    var paged = PAGE[TAB] > 0;
    if (moved && TAB_LIST[TAB]
        && !document.querySelector('.modal:not([hidden])')
        && !userHolds(here) && !pointerBusy(here) && !paged && !apiLatestOut(TAB_LIST[TAB])) {
      REDRAW_OWED = false;
      onTab(TAB);
    } else if (moved && TAB_LIST[TAB]) {
      REDRAW_OWED = true;
    }
    if (TAB === 'overview') paintCards();
    if (TAB === 'log' && moved) loadLog(false);
    if (TAB === 'settings' && typeof PANE_TICK[PANE] === 'function') {
      try { PANE_TICK[PANE](s); } catch (e) { /* the next tick */ }
    }
  }).catch(function (e) {
    if (e && e.busy) return;
    /* An upgrade going on (fake-igd 1.7.2): the API restarting is expected - the band at the
       top follows it (from the pages' PHP), nothing red. */
    if (e && e.upgrading) { $('offline').hidden = true; return; }
    if (upgradeExpected()) { $('offline').hidden = true; upgradeAway(); return; }
    var o = $('offline');
    o.hidden = false;
    o.textContent = 'The API is not answering: ' + (e.message || e);
  }).then(function () { TICK_OUT = 0; });
}

/* ---- an upgrade going on: the band at the top (fake-igd 1.7.2) ------------------------------
   What otp's pages show of a node in maintenance for its upgrade - the pill "in maintenance", the
   card "upgrading", the pages following the node while it restarts - for the one server here: a
   band at the top of every page with how far it is. From the API's status while it answers, from
   the pages' PHP while the API restarts (?api=upgrade-state: .upgrade.json, which root's helper
   and install.sh --upgrade write at each step, also when it was started on the command line), and
   "not answering for N s" while nginx and PHP restart themselves. Never "the API is not
   answering". At the end the page loads the new version by itself. */
var UPG = {u: null, heard: 0, away: 0, sawRunning: false, timer: null, reloading: false, asking: false};
var PAGE_VERSION = (function () {
  var sc = document.querySelector('script[src*="admin.js"]');
  var m = sc && /[?&]v=([0-9.]+)/.exec(sc.getAttribute('src') || '');
  return m ? m[1] : '';
}());
function upgradeWords(u) {
  if (!u) return '';
  if (u.state === 'done') return 'fake-igd ' + (u.version || '') + ' is in';
  if (u.state === 'failed') return 'The ' + (u.downgrade ? 'going back' : 'upgrade') + ' to fake-igd ' + (u.version || '?') + ' failed';
  return 'fake-igd is being ' + (u.downgrade ? 'taken back to ' : 'upgraded to ') + (u.version || 'a new version');
}
/* What the status says of an upgrade: the pages' own word (.upgrade.json, merged in by PHP) while
   it runs, the API's (asked, taken by root) otherwise. */
function upgradeOf(s) {
  var mine = s && s.upgrading;
  var api = s && s.upgrade;
  if (api && api.busy && !(mine && mine.state === 'running')) {
    return {state: 'running', version: api.version || '', part: 0, parts: 0, asked: api.state === 'asked',
            words: api.state === 'asked' ? 'handed to root (fake-igd-upgrade.service)' : 'install.sh --upgrade runs (root)',
            at: s.now || Date.now() / 1000, started: s.now || Date.now() / 1000, now: s.now};
  }
  return mine || null;
}
function upgradeFromStatus(s) {
  var u = upgradeOf(s);
  if (u) { upgradeHeard(u, false); upgradeEnd(s); return; }
  /* Not said any more: ended (an upgrade the pages' file did not follow), or never was. */
  if (UPG.u && UPG.u.state === 'running') { UPG.u = {state: 'done', version: s.version, part: 1, parts: 1}; upgradeEnd(s); }
  UPG.away = 0;
  drawUpBand();
}
function upgradeHeard(u, away) {
  var was = UPG.u && UPG.u.state === 'running';
  UPG.u = u;
  UPG.phpAway = false;                  /* heard of, so nginx and PHP answer again */
  UPG.heard = Date.now();
  UPG.skew = u.now ? u.now - Date.now() / 1000 : 0;
  if (u.state === 'running') UPG.sawRunning = true;
  if (away && !UPG.away) UPG.away = Date.now();
  if (!away) UPG.away = 0;
  drawUpBand();
  /* Begun just now: Settings → Upgrades, when it is open, follows it at once. */
  if (u.state === 'running' && !was && typeof paneLive === 'function' && paneLive('upgrade')
      && typeof loadUpgrade === 'function') setTimeout(function () { loadUpgrade(true); }, 0);
}
/* Whether the API and these pages may be away because of an upgrade - for as long as one runs,
   at most half an hour since it was last heard of; and a minute after its end, while the page
   loads the new version. */
function upgradeExpected() {
  if (!UPG.u) return false;
  var since = Date.now() - UPG.heard;
  if (UPG.u.state === 'running') return since < 30 * 60 * 1000;
  return UPG.reloading || (UPG.sawRunning && UPG.u.state === 'done' && since < 60 * 1000);
}
/* The API answers and the upgrade has ended: the new version's pages loaded - once, and never over
   changes not saved yet. */
function upgradeEnd(s) {
  var u = UPG.u;
  if (!u || u.state !== 'done' || !UPG.sawRunning || UPG.reloading) return;
  var key = 'igd.upgrade.reloaded';
  var mark = (u.id || '') + ':' + (s.version || u.version || '');
  var did = '';
  try { did = sessionStorage.getItem(key) || ''; } catch (e) { did = ''; }
  var unsaved = (typeof DIRTY === 'object' && DIRTY && Object.keys(DIRTY).length) ||
                (typeof PENDING === 'object' && PENDING && Object.keys(PENDING).length);
  if (did === mark || unsaved) { UPG.offerLoad = true; drawUpBand(); return; }
  UPG.reloading = true;
  drawUpBand();
  try { sessionStorage.setItem(key, mark); } catch (e) { /* a private window: loaded once all the same */ }
  setTimeout(function () { location.reload(); }, 1500);
}
/* The API does not answer and an upgrade goes on: asked of the pages' PHP how far it is - which
   may itself be restarting (nginx, php-fpm): then only how long nothing has answered. */
function upgradeAway() {
  if (!UPG.away) UPG.away = Date.now();
  drawUpBand();
  if (UPG.asking) return;
  UPG.asking = true;
  fetch('?api=upgrade-state', {credentials: 'same-origin'}).then(function (r) { return r.json(); }).then(function (d) {
    UPG.phpAway = false;
    if (d && d.upgrading) upgradeHeard(d.upgrading, !d.api);
    if (d && d.api) setTimeout(tick, 300);
  }).catch(function () { UPG.phpAway = true; drawUpBand(); })
    .then(function () { UPG.asking = false; });
}
function upgradePercent(u) {
  if (!u) return 0;
  if (u.state === 'done' || u.state === 'failed') return 100;
  if (u.asked) return 2;
  var now = Date.now() / 1000 + (UPG.skew || 0);
  var since = Math.max(0, now - Number(u.at || now));
  var parts = Number(u.parts || 0) || 13;
  return Math.round(Math.min(84, 5 + 76 * Math.min(0.97, Number(u.part || 0) / parts) + Math.min(3, since / 30)));
}
function drawUpBand() {
  var band = $('upband');
  if (!band) return;
  var u = UPG.u;
  var hid = '';
  try { hid = sessionStorage.getItem('igd.upgrade.hidden') || ''; } catch (e) { hid = ''; }
  var show = u && (u.state === 'running' || (u.state === 'done' && UPG.sawRunning)
                   || (u.state === 'failed' && hid !== String(u.id || u.at)));
  if (!show) {
    band.hidden = true;
    clear(band);
    if (UPG.timer) { clearInterval(UPG.timer); UPG.timer = null; }
    return;
  }
  var kind = u.state === 'failed' ? 'bad' : (u.state === 'done' ? 'good' : '');
  band.className = 'offline upband' + (kind ? ' ' + kind : '');
  band.hidden = false;
  liveFill(band, function (b) {
    var head = el('div', 'upband-head');
    head.appendChild(el('b', '', upgradeWords(u)));
    var bits = [];
    if (u.from) bits.push('from ' + u.from);
    if (u.by) bits.push('asked by ' + u.by);
    var t0 = Number(u.started || 0);
    if (t0 && u.state === 'running') bits.push(span(Date.now() / 1000 + (UPG.skew || 0) - t0) + ' so far');
    if (bits.length) head.appendChild(noI18n(el('span', 'upband-sub', bits.join(' · '))));
    if (u.state === 'failed') {
      var x = el('button', 'xbtn');
      x.type = 'button';
      x.setAttribute('aria-label', 'Hide');
      x.innerHTML = iconMarkup('close', 14);
      x.onclick = function () {
        try { sessionStorage.setItem('igd.upgrade.hidden', String(u.id || u.at)); } catch (e) { /* hidden till F5 */ }
        band.hidden = true;
      };
      head.appendChild(x);
    }
    b.appendChild(head);
    var pc = upgradePercent(u);
    var says = num(pc) + ' %';
    if (u.state === 'running' && u.words) says += ' · ' + u.words + (u.parts && u.part ? ' · step ' + u.part + ' of ' + u.parts : '');
    if (u.state === 'failed' && u.said) says += ' · ' + u.said;
    var bar = el('div', 'going up-bar wide' + (kind ? ' ' + kind : ''));
    var track = el('div', 'bar');
    var fill = el('span', '');
    fill.style.width = pc + '%';
    track.appendChild(fill);
    bar.appendChild(track);
    bar.appendChild(noI18n(el('div', 'says', says)));
    b.appendChild(bar);
    var line = el('div', 'small upband-line');
    if (UPG.reloading) line.textContent = 'Loading the pages of the new version…';
    else if (u.state === 'done') {
      line.appendChild(document.createTextNode('This page is still the one of ' + (PAGE_VERSION || 'the version before') + '. '));
      var a = el('a', 'fgo', 'Load it again');
      a.onclick = function () { location.reload(); };
      line.appendChild(a);
    } else if (u.state === 'failed') {
      line.appendChild(document.createTextNode('What install.sh said is in Settings → Upgrades. '));
      if (ADMIN) {
        var go = el('a', 'fgo', 'Open Upgrades');
        go.onclick = function () { location.hash = '#settings/upgrade'; };
        line.appendChild(go);
      }
    } else if (UPG.away) {
      var away = Math.round((Date.now() - UPG.away) / 1000);
      line.textContent = (UPG.phpAway ? 'nginx and PHP are restarting' : 'The API of these pages is restarting with the new version')
        + ' - not answering for ' + span(away) + ', asked again every two seconds; the page comes back by itself.';
    } else if (u.asked) {
      line.textContent = 'Handed to root: fake-igd-upgrade.service takes it in a moment.';
    } else {
      line.textContent = 'fake-igd.service and these pages restart once - for a few seconds the PS5 gets no answer. '
        + 'This page follows it and loads the new version by itself.';
    }
    b.appendChild(line);
  }, true);
  /* Counted every second while it runs; asked every two seconds while nothing answers. */
  if (u.state === 'running' && !UPG.timer) {
    UPG.timer = setInterval(function () {
      if (!UPG.u || UPG.u.state !== 'running') { clearInterval(UPG.timer); UPG.timer = null; return; }
      drawUpBand();
      UPG.beat = (UPG.beat || 0) + 1;
      if (UPG.away && !document.hidden && UPG.beat % 2 === 0) tick();
    }, 1000);
  }
}
$('updated').onclick = function () {
  LIVE = !LIVE;
  $('updated').classList.toggle('paused', !LIVE);
  $('updated').querySelector('b').textContent = LIVE ? 'live' : 'paused';
  if (LIVE) tick();
};
$('signout').onclick = function () {
  api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); });
};

/* Your account: the passkeys of this account (otp 1.0.257) - while the second step is on and it is
   a passkey. Each listed for the name of the pages it is for, named here, taken away (not the
   last: that is the second step itself); another added from this device. */
function mePasskeys(body) {
  var sec = el('div', 'me-sec me-pk');
  sec.hidden = true;
  body.appendChild(sec);
  /* Asked again after a passkey added or taken away: whether another may be added, and why not,
     are the server's (how many, the sign-in too old), never worked out here. */
  var again = function (r, d) {
    api('passkeys').then(draw).catch(function () { draw(Object.assign({}, d, {keys: r.keys || d.keys})); });
  };
  var draw = function (d) {
    clear(sec);
    if (!d || !d.on || !d.mine) { sec.hidden = true; return; }
    sec.hidden = false;
    sec.appendChild(el('h3', '', 'Passkeys - Face ID, Touch ID'));
    sec.appendChild(el('p', 'note', 'A passkey is the second step after your password, with the face, a finger or the PIN of this device. It is kept in the device (on an iPad and an iPhone in the iCloud Keychain, so on your other Apple devices too); the server has only its public half.'));
    var t = el('table', 'rows me-pk-t');
    var hr = el('tr');
    ['Passkey', 'For', 'Added', 'Last used', ''].forEach(function (w) { hr.appendChild(el('th', '', w)); });
    var th = el('thead'); th.appendChild(hr); t.appendChild(th);
    var tb = el('tbody');
    var keys = d.keys || [];
    keys.forEach(function (k) {
      var tr = el('tr');
      var nameTd = el('td', 'me-pk-name');
      var shown = noI18n(el('span', '', k.name || 'a device'));
      nameTd.appendChild(shown);
      tr.appendChild(nameTd);
      tr.appendChild(noI18n(el('td', 'mono small', k.host || '')));
      tr.appendChild(stampCell(k.at));
      tr.appendChild(stampCell(k.used));
      var act = el('td', 'me-pk-act');
      var ed = iconButton('edit', 'Name this passkey');
      var rm = iconButton('trash', keys.length > 1 ? 'Take this passkey away'
        : 'The last passkey is the second step of this account: another full admin resets it (Accounts)');
      rm.disabled = keys.length <= 1;
      ed.onclick = function () {
        if (nameTd.querySelector('input')) return;
        var box = textBox(k.name || '', 'iPad', '');
        box.maxLength = 60;
        noI18n(box);
        clear(nameTd);
        nameTd.appendChild(box);
        box.focus();
        box.select();
        var done = false;
        var back = function () { if (done) return; done = true; clear(nameTd); nameTd.appendChild(shown); };
        var save = function () {
          if (done) return;
          var v = box.value.trim();
          if (!v || v === (k.name || '')) { back(); return; }
          done = true;
          box.disabled = true;
          api('passkeys', {action: 'rename', id: k.id, name: v}).then(function (r) {
            toast(r.message || 'named', 'good');
            draw(Object.assign({}, d, {keys: r.keys}));
          }).catch(function (e) { done = false; box.disabled = false; oops(e); box.focus(); });
        };
        box.addEventListener('keydown', function (e) {
          if (e.key === 'Enter') { e.preventDefault(); save(); }
          else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); back(); }
        });
        box.addEventListener('blur', function () { setTimeout(save, 120); });
      };
      rm.onclick = function () {
        modalOver(function () {
          confirmThen('Take the passkey away',
            'The passkey <b>' + htmlText(k.name || 'a device') + '</b> for ' + htmlText(k.host || '')
            + ' no longer gives the second step of this account. The device keeps it until it is taken out there too.',
            'Take it away', function () {
              api('passkeys', {action: 'delete', id: k.id}).then(function (r) {
                toast(r.message || 'taken away', 'good');
                again(r, d);
              }).catch(oops);
            }, true);
        });
      };
      act.appendChild(ed);
      act.appendChild(rm);
      tr.appendChild(act);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    var tw = el('div', 'after-lately-w me-pk-w');
    tw.appendChild(t);
    sec.appendChild(tw);
    var said = el('div', 'said');
    var add = cmdButton('Add a passkey of this device', 'key', 'primary');
    add.type = 'button';
    var why = d.why || (!pkCan() ? pkWhy() : '');
    if (!d.can_add || !pkCan()) { add.disabled = true; if (why) { said.className = 'said'; said.textContent = why; } }
    add.onclick = function () {
      add.disabled = true;
      said.className = 'said';
      said.textContent = 'Asking the device…';
      api('passkeys', {action: 'add_begin'}).then(function (r) {
        var o = r.publicKey;
        o.challenge = pkBytes(o.challenge);
        o.user.id = pkBytes(o.user.id);
        o.excludeCredentials = (o.excludeCredentials || []).map(function (c) { return {type: c.type, id: pkBytes(c.id)}; });
        return navigator.credentials.create({publicKey: o});
      }).then(function (cr) {
        return api('passkeys', {action: 'add_finish', device: pkDevice(),
          clientDataJSON: pkText(cr.response.clientDataJSON), attestationObject: pkText(cr.response.attestationObject)});
      }).then(function (r) {
        toast(r.message || 'the passkey is added', 'good');
        again(r, Object.assign({}, d, {can_add: (r.keys || []).length < (d.max || 10)}));
      }).catch(function (e) { add.disabled = false; pkErr(said, e); });
    };
    var row = el('div', 'btnrow me-pk-add');
    row.appendChild(add);
    sec.appendChild(row);
    sec.appendChild(said);
  };
  api('passkeys').then(draw).catch(function () { sec.hidden = true; });
}

/* ---- the account signed in (otp's showMe) ---------------------------------- */
function meInitials(name, display) {
  var words = String(display || name || '?').replace(/[^\p{L}\p{N}\s._-]/gu, ' ')
    .split(/[\s._@-]+/).filter(Boolean);
  var two = words.length > 1 ? words[0][0] + words[words.length - 1][0] : String(words[0] || name || '?').slice(0, 2);
  return two.toUpperCase();
}
function showMe() {
  modal('Your account', function (body) {
    var head = el('div', 'me-head');
    var ava = noI18n(el('div', 'me-ava' + (ME.role === 'fulladmin' ? ' admin' : ''), meInitials(ME.name, ME.display)));
    ava.setAttribute('aria-hidden', 'true');
    head.appendChild(ava);
    var who = el('div', 'me-who');
    who.appendChild(noI18n(el('div', 'me-n mono', ME.name)));
    if (ME.note) who.appendChild(noI18n(el('div', 'me-d', ME.note)));
    var tags = el('div', 'me-tags');
    tags.appendChild(el('span', 'tag ' + roleTone(ME.role), roleWords(ME.role)));
    tags.appendChild(el('span', 'tag info', 'local account'));
    who.appendChild(tags);
    head.appendChild(who);
    body.appendChild(head);
    var may = el('div', 'me-sec');
    may.appendChild(el('h3', '', 'What you may do'));
    may.appendChild(el('p', '', ME.role === 'fulladmin' ? 'Anything: settings, accounts, the service, the server, the database.'
      : 'Look at every page. Nothing can be changed from this account; how your own tables are laid out is yours to change.'));
    body.appendChild(may);

    /* The passkeys of this account (otp 1.0.257): drawn when the API says they are this
       account's second step. */
    mePasskeys(body);

    /* The load meter's looks (otp 1.0.253), while Settings - About has it on. */
    if (typeof hloadAllowed === 'function' && hloadAllowed()) {
      var psec = el('div', 'me-sec');
      psec.appendChild(el('h3', '', 'The load meter'));
      hloadPickers(psec);
      body.appendChild(psec);
    }

    /* The columns of the tables - exactly otp's (and isemon's). */
    var cols = el('div', 'me-sec');
    cols.appendChild(el('h3', '', 'Columns of the tables'));
    var line = el('div', 'me-row');
    var say = el('div', 'me-say');
    say.innerHTML = '<b>Edit the columns</b><br>While this is on, the edge of any column’s '
      + 'heading can be dragged to size it and the heading itself to move it, and the right '
      + 'button on a heading hides a column, brings a hidden one back or adds an empty one '
      + 'for room; each change is kept the moment you let go. It is for this sign-in only: signing out, the sign-in '
      + 'running out or the API restarting turn it off again. Off, the tables are drawn '
      + 'as you left them and nothing can move them.';
    line.appendChild(say);
    var sw = el('label', 'sw');
    var box = el('input');
    box.type = 'checkbox';
    box.id = 'me-cols-edit';
    box.checked = COLS_EDIT;
    box.setAttribute('aria-label', 'Edit the columns');
    sw.appendChild(box);
    sw.appendChild(el('span', 'knob'));
    line.appendChild(sw);
    cols.appendChild(line);
    box.onchange = function () {
      var on = box.checked;
      box.disabled = true;
      colsSwitch(on).then(function (d) {
        box.checked = !!d.edit;
      }).catch(function (e) {
        box.checked = COLS_EDIT;
        oops(e);
      }).then(function () { box.disabled = false; });
    };
    var laid = Object.keys(COLS).length;
    cols.appendChild(el('p', '', laid ? 'You have laid out ' + num(laid) + ' table(s).'
      : 'Every table is as it comes.')).style.marginTop = '10px';
    var acts = el('div', 'me-acts');
    var back = cmdButton('Put my columns back as they come', 'undo', 'small');
    back.id = 'me-cols-reset';
    explain(back, 'Every table you have laid out goes back as it comes: the widths and the '
      + 'order of the columns, on every page. Nobody else’s change.');
    back.disabled = !laid;
    back.onclick = function () {
      back.disabled = true;
      colsReset().then(function () { showMe(); }).catch(function (e) {
        back.disabled = false;
        oops(e);
      });
    };
    acts.appendChild(back);
    cols.appendChild(acts);
    body.appendChild(cols);

    /* Your own settings, to a file and back. */
    var mine = el('div', 'me-sec');
    mine.appendChild(el('h3', '', 'Your settings in a file'));
    mine.appendChild(el('p', '', 'How you have set these pages up for yourself — the '
      + 'columns of the tables and the looks of the load meter — saved as a JSON file, and read back here '
      + 'or on another machine running fake-igd. Never your password, your role or anything else '
      + 'about the account.'));
    var io = el('div', 'me-acts');
    var out = cmdButton('Export my settings', 'download', 'small');
    out.id = 'me-export';
    out.onclick = function () { meExport(out); };
    io.appendChild(out);
    var inn = cmdButton('Import settings…', 'upload', 'small');
    inn.id = 'me-import';
    inn.onclick = function () { mePick(); };
    io.appendChild(inn);
    mine.appendChild(io);
    body.appendChild(mine);

    var pwsec = el('div', 'me-sec');
    pwsec.appendChild(el('h3', '', 'A new password'));
    var old = maskBox('', '', '');
    var nw = maskBox('', '', '');
    var nw2 = maskBox('', '', '');
    old.id = 'me-pw-old'; nw.id = 'me-pw-new'; nw2.id = 'me-pw-new2';
    var g = el('div', 'formgrid');
    g.appendChild(formField('The one you have now', old));
    g.appendChild(formField('The new one', nw));
    g.appendChild(formField('The new one again', nw2));
    pwsec.appendChild(g);
    var go = cmdButton('Change the password', 'lock', 'primary');
    go.id = 'me-pw-go';
    go.style.marginTop = '10px';
    go.onclick = function () {
      /* Typed twice (otp 1.0.273): one slip of a finger was a password nobody knew. */
      if (!old.value) { toast('type the password you have now first', 'bad'); old.focus(); return; }
      if (nw.value !== nw2.value) { toast('the two new ones are not the same', 'bad'); nw2.focus(); return; }
      busy(go, true);
      api('password', {old: old.value, 'new': nw.value}).then(function (d) {
        toast(d.message, 'good'); closeModal();
      }).catch(oops).then(function () { busy(go, false); });
    };
    pwsec.appendChild(go);
    body.appendChild(pwsec);
  }, null, 'medium');
}
$('me-btn').onclick = showMe;

/** "Edit the columns" on or off for this sign-in: the API holds it. */
function colsSwitch(on) {
  return api('columns', {edit: !!on}).then(function (d) {
    colsEditing(!!d.edit);
    colsCardSay();
    toast(d.edit ? 'Columns can be sized and moved now — each change is kept at once'
      : 'Columns are held as they are', 'good');
    return d;
  });
}

/** The file a person's own settings go into (otp's, its own kind): `settings` by section -
    `columns` and `prefs`; a version that does not know a section leaves it alone. */
var ME_FILE_KIND = 'fake-igd-user-settings';
function meExport(button) {
  if (button) button.disabled = true;
  api('my-settings').then(function (d) {
    var file = {
      kind: ME_FILE_KIND,
      format: 1,
      from: location.host,
      version: d.version || '',
      user: d.name || (ME && ME.name) || '',
      exported: new Date().toISOString(),
      settings: d.settings || {}
    };
    var blob = new Blob([JSON.stringify(file, null, 2) + '\n'], {type: 'application/json'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'fake-igd-settings-' + String(file.user || 'me').replace(/[^a-z0-9._-]/gi, '_')
      + '-' + file.exported.slice(0, 10) + '.json';
    document.body.appendChild(link);
    link.click();
    setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1500);
    var n = Object.keys((file.settings || {}).columns || {}).length;
    toast('your settings were saved to ' + link.download + ' (' + num(n) + ' table layout(s))', 'good');
  }).catch(oops).then(function () { if (button) button.disabled = false; });
}
function mePick() {
  var pick = el('input');
  pick.type = 'file';
  pick.accept = '.json,application/json';
  pick.hidden = true;
  pick.onchange = function () {
    var file = pick.files && pick.files[0];
    pick.remove();
    if (file) meImport(file);
  };
  document.body.appendChild(pick);
  pick.click();
}
function meImport(file) {
  if (file.size > 2 * 1024 * 1024) {
    toast('that file is far bigger than any settings file (' + bytes(file.size) + ')', 'bad');
    return;
  }
  var reader = new FileReader();
  reader.onerror = function () { toast('that file could not be read', 'bad'); };
  reader.onload = function () {
    var got;
    try { got = JSON.parse(String(reader.result || '')); } catch (e) {
      toast('that is not a settings file: it is not JSON', 'bad');
      return;
    }
    /* Our own file, or otp's or isemon's: the columns are kept the same way in all three. */
    var settings = got && (got.kind === ME_FILE_KIND || got.kind === 'otp-user-settings' || got.kind === 'isemon-user-settings')
      ? got.settings
      : (got && got.settings && typeof got.settings === 'object' ? got.settings : got);
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
      toast('that is not a settings file', 'bad');
      return;
    }
    var cols = settings.columns && typeof settings.columns === 'object' ? Object.keys(settings.columns).length : null;
    var other = Object.keys(settings).filter(function (k) { return k !== 'columns' && k !== 'prefs'; });
    var at = got.exported ? Date.parse(String(got.exported)) : NaN;
    modal('Import settings', function (body) {
      body.appendChild(peekFacts([
        ['Whose', got.user ? noI18n(el('span', 'mono', String(got.user))) : '–'],
        ['From', got.from ? noI18n(el('span', 'mono', String(got.from))) : '–'],
        ['Saved', isFinite(at) ? stamp(at / 1000) : '–'],
        ['Version', got.version ? noI18n(el('span', 'mono', String(got.version))) : '–']]));
      body.appendChild(el('p', 'note', 'This file holds:'));
      var list = el('ul', 'me-list');
      if (cols !== null) list.appendChild(el('li', '', 'the columns of ' + num(cols) + ' table(s)'));
      if (settings.prefs && typeof settings.prefs === 'object' && (settings.prefs.hload || settings.prefs.hpanel)) {
        list.appendChild(el('li', '', 'the looks of the load meter'));
      }
      if (other.length) list.appendChild(el('li', '', other.join(', ') + ' — not kept by this version, left alone'));
      body.appendChild(list);
      body.appendChild(el('p', 'note', 'They replace yours. Your password and your account are not touched.'));
    }, [{words: 'No, leave it', close: true},
        {words: 'Import them', cls: 'primary', close: true, go: function () {
          api('my-settings', {settings: settings}).then(function (d) {
            return api('my-settings').then(function (now) {
              colsTake((now.settings || {}).columns || {});
              colsApplyAll();
              if (ME) ME.prefs = (now.settings || {}).prefs || ME.prefs;
              return d;
            });
          }).then(function (d) {
            toast('imported: the columns of ' + num((d.took || {}).columns || 0) + ' table(s)'
              + ((d.ignored || []).length ? '; left alone: ' + d.ignored.join(', ') : ''), 'good');
            colsCardSay();
          }).catch(oops);
        }}], true);
  };
  reader.readAsText(file);
}
/** A card of the columns, where a pane has one (#cols-card, otp's on Accounts). */
function colsCardSay() {
  var laid = Object.keys(COLS).length;
  if ($('cols-count')) $('cols-count').textContent = laid ? num(laid) + ' table(s) laid out by you' : 'every table as it comes';
  var b = $('cols-edit-go');
  if (b) {
    setButtonIcon(b, COLS_EDIT ? 'check' : 'edit', COLS_EDIT ? 'Stop editing the columns' : 'Edit the columns');
    b.classList.toggle('primary', COLS_EDIT);
  }
  if ($('cols-reset')) $('cols-reset').disabled = !laid;
}
function colsCardWire() {
  if ($('cols-edit-go') && !$('cols-edit-go')._w) {
    $('cols-edit-go')._w = true;
    $('cols-edit-go').onclick = function () { colsSwitch(!COLS_EDIT).catch(oops); };
  }
  if ($('cols-reset') && !$('cols-reset')._w) {
    $('cols-reset')._w = true;
    $('cols-reset').onclick = function () {
      confirmThen('Put my columns back',
        'Every table you have laid out goes back as it comes: the widths and the order of the '
        + 'columns, on every page. Nobody else’s tables change.',
        'Put them back', function () { colsReset().then(function () { colsCardSay(); }).catch(oops); });
    };
  }
  if ($('cols-export') && !$('cols-export')._w) { $('cols-export')._w = true; $('cols-export').onclick = function () { meExport($('cols-export')); }; }
  if ($('cols-import') && !$('cols-import')._w) { $('cols-import')._w = true; $('cols-import').onclick = function () { mePick(); }; }
  colsCardSay();
}

/* ==========================================================================
   Overview
   ========================================================================== */
function upTime(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? d + ' d ' + h + ' h' : (h ? h + ' h ' + m + ' min' : m + ' min');
}
function setCard(id, value, sub, tone) {
  $('m-' + id).textContent = value;
  $('m-' + id + '-sub').textContent = sub || ' ';
  var c = $('card-' + id);
  if (tone) c.className = 'card metric ' + tone + (c.classList.contains('tappable') ? ' tappable' : '');
}
/* Why each card of the overview has its colour (otp 1.0.245): {level, words}, at the top of its popup. */
var CARD_WHY = {};
function paintCards() {
  var s = STATUS;
  if (!s) return;
  var sv = s.service || {}, st = s.stats || {};
  var on = sv.state === 'active';
  var upOn = upgradeExpected();
  /* In maintenance while it is upgraded, as otp's "This server" card says it (fake-igd 1.7.2). */
  var upTo = UPG.u && UPG.u.version ? 'fake-igd ' + UPG.u.version : 'the new version';
  setCard('service', upOn ? 'maintenance' : (on ? 'running' : (sv.state || '?')),
          upOn ? (on ? 'being upgraded to ' + upTo + ' · restarts once' : 'restarting with ' + upTo + ' - back in a moment')
             : (on ? (s.node || s.host || '') + ' · ' + s.version + ' · ' + (sv.since_at ? 'up ' + upTime(Date.now() / 1000 - sv.since_at) : 'since ' + (sv.since || '?'))
               + (Number(sv.restarts) ? ' · restarted ' + sv.restarts + ' time(s)' : '')
             : 'nothing is answered; sudo upnp start · Settings → The service'),
          upOn ? 'warn' : (on ? 'ok' : 'crit'));
  CARD_WHY['card-service'] = {level: upOn ? 'warn' : (on ? 'ok' : 'crit'), words: upOn
    ? 'Yellow: in maintenance - being upgraded to ' + upTo + '; fake-igd.service restarts once, for a few seconds nobody on the network is answered.'
    : (on ? 'Green: fake-igd.service is running and answers on the network.'
       : 'Red: fake-igd.service is ' + (sv.state || 'unknown') + ' - nobody on the network is answered, nothing is written down.')};
  var passive = s.mode !== 'active';
  setCard('mode', s.mode + ' · ' + s.mapping_response,
          (passive ? 'only listens and logs' : 'answers like a UPnP router') + ' · public IP '
          + (s.public_ip || s.external_ip || '?'), passive ? 'warn' : 'info');
  CARD_WHY['card-mode'] = {level: passive ? 'warn' : 'info', words: passive
    ? 'Yellow: passive - SSDP searches are written down, but nobody is answered, so no client asks for a port.'
    : 'Blue: active - it answers like a UPnP router, and says ' + s.mapping_response + ' to every AddPortMapping.'};
  setCard('ports', num(st.ports || 0), num(st.add || 0) + ' AddPortMapping of ' + num(st.requests || 0) + ' requests', 'ok');
  setCard('clients', num(st.clients || 0), st.last ? 'the last request ' + ago(Date.parse(st.last) / 1000) : 'nothing asked yet', 'info');
  var ifs = Object.keys(s.interfaces || {});
  setCard('ifaces', num(ifs.length), ifs.map(function (n) { return n + ' ' + s.interfaces[n]; }).join(' · ') || 'none in the log since the start',
          ifs.length ? 'info' : 'warn');
  CARD_WHY['card-ifaces'] = {level: ifs.length ? 'info' : 'warn', words: ifs.length
    ? 'Blue: it listens on ' + num(ifs.length) + ' interface(s).'
    : 'Yellow: the log says of no interface it listens on since the service last started.'};
  setCard('maps', num(st.mappings || 0), 'what the clients believe is open · port ' + s.http_port, 'info');
  var m = s.mdns;
  var mt = !m ? 'info' : (m.state === 'active' ? 'ok' : 'warn');
  setCard('mdns', !m ? 'none' : (m.reflector ? 'on' : 'off'), !m ? 'avahi-daemon is not installed here'
          : 'avahi-daemon ' + m.state, mt);
  CARD_WHY['card-mdns'] = {level: mt, words: !m ? 'Blue: avahi-daemon is not installed here.'
    : (m.state === 'active' ? 'Green: avahi-daemon runs' + (m.reflector ? ' and reflects mDNS between the interfaces.' : '; its reflector is off.')
       : 'Yellow: avahi-daemon is ' + m.state + '.')};
  var up = s.upgrade || {};
  var upBusy = up.busy || (upOn && UPG.u && UPG.u.state === 'running');
  var ut = upBusy ? 'warn' : (up.newer ? 'warn' : 'ok');
  setCard('upgrade', upBusy ? 'upgrading' : (up.newer ? up.newest : s.version),
          upBusy ? 'to fake-igd ' + (up.version || (UPG.u && UPG.u.version) || '') : (up.newer ? 'is out - this server runs ' + s.version
          : 'the newest there is'), ut);
  CARD_WHY['card-upgrade'] = {level: ut, words: upBusy ? 'Yellow: an upgrade is going on.'
    : (up.newer ? 'Yellow: fake-igd ' + up.newest + ' is out; this server runs ' + s.version + '.'
       : 'Green: this server runs the newest version there is.')};
}

/* The cards open what they count (otp 1.0.37). */
function cardOpens(id, words, go) {
  var card = $(id);
  if (!card) return;
  var go0 = go;
  go = function () { PEEK_WHY = CARD_WHY[id] || null; go0(); };
  card.classList.add('tappable');
  card.setAttribute('role', 'button');
  card.setAttribute('tabindex', '0');
  if (!card.querySelector('.goes')) {
    var arrow = el('span', 'goes');
    arrow.innerHTML = iconMarkup('next', 16);
    card.appendChild(arrow);
  }
  if (words) explain(card, words);
  card.onclick = function (e) {
    if (e && e.target && e.target.closest && e.target.closest('button,a,select,input')) return;
    go();
  };
  card.onkeydown = function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
  };
}
function peekServiceCard() {
  var s = STATUS || {};
  peek('The service: ' + (s.node || ''), function () { return Promise.resolve(s); }, function (body) {
    var sv = s.service || {};
    body.appendChild(peekFacts([['Version', s.version], ['State', sv.state + (sv.sub ? ' (' + sv.sub + ')' : '')],
      ['Since', sv.since || '–'], ['Restarted', String(sv.restarts || 0)], ['Process', sv.pid && sv.pid !== '0' ? sv.pid : '–'],
      ['At boot', sv.boot || '–']]));
    body.appendChild(el('h4', '', 'This server'));
    body.appendChild(kvTable([['Host', s.host || s.node || '–'], ['Up for', upTime(s.uptime)],
      ['The pages\' API up for', upTime(s.api_uptime)], ['Notifications', s.notifications || 'off'],
      ['Who is answered', (s.allowed_clients || []).join(', ') || 'anybody on the network']]));
    body.appendChild(el('h4', '', 'Problems'));
    if (!(s.problems || []).length) body.appendChild(el('p', 'note good', 'None.'));
    (s.problems || []).forEach(function (p) { body.appendChild(el('p', 'note bad', p)); });
  }, ADMIN ? {tab: 'settings', pane: 'service', words: 'Open Settings', icon: 'gear'} : null);
}
function peekModeCard() {
  var s = STATUS || {};
  peek('Mode and answer', function () { return Promise.resolve(s); }, function (body) {
    body.appendChild(peekFacts([['Mode', s.mode], ['AddPortMapping', s.mapping_response], ['Port', String(s.http_port)],
      ['Public IP reported', s.public_ip || s.external_ip || '–']]));
    body.appendChild(el('p', 'note', s.mode === 'active'
      ? 'Active: fake-igd answers SSDP searches and SOAP requests like a UPnP router. ' + (s.mapping_response === 'accept'
        ? 'Every AddPortMapping is confirmed - the client believes the port is open; nothing is opened anywhere.'
        : 'Every AddPortMapping is refused (error 501) - the client tries another way.')
      : 'Passive: fake-igd only listens and writes down who searches for a UPnP router; nobody is answered.'));
    if ((s.other_igd || []).length) body.appendChild(el('p', 'note bad', 'Another UPnP router is on the network: ' + s.other_igd.join(', ')));
  }, {tab: 'settings', pane: 'answer', words: 'Open Settings', icon: 'gear'});
}
function peekPortsCard() {
  peek('Ports asked for', function () { return api('ports&sort=last&per=12'); }, function (body, d) {
    var st = (STATUS || {}).stats || {};
    var c = d.counts || {};
    body.appendChild(peekFacts([['Ports', num(c.ports)], ['UDP', num(c.udp)], ['TCP', num(c.tcp)], ['Clients', num(c.clients)],
      ['AddPortMapping', num(st.add || 0)]]));
    body.appendChild(el('h4', '', 'Asked for last'));
    body.appendChild(listTable(['Port', 'Client', 'Asked', 'Last', 'What for'], d.ports, function (r) {
      var tr = el('tr', 'tappable');
      var tp = el('td'); tp.appendChild(protoTag(r.proto)); tp.appendChild(noI18n(el('span', 'mono', ' ' + r.port))); tr.appendChild(tp);
      tr.appendChild(addrCell(r.client, r.name));
      tr.appendChild(el('td', 'num', num(r.count)));
      tr.appendChild(el('td', 'muted', ago(r.last)));
      tr.appendChild(noI18n(el('td', 'small', r.description || '')));
      tr.onclick = function () { modalOver(function () { portPeek(r); }); };
      return tr;
    }, 'plain|No port has been asked for'));
  }, {tab: 'ports', words: 'Open the ports', icon: 'net'});
}
function peekClientsCard() {
  peek('Clients', function () { return api('clients&per=12'); }, function (body, d) {
    body.appendChild(peekFacts([['Clients', num(d.total)], ['Last request', ((STATUS || {}).stats || {}).last
      ? ago(Date.parse(STATUS.stats.last) / 1000) : '–']]));
    body.appendChild(el('h4', '', 'Seen last'));
    body.appendChild(clientsTable(d.clients, true));
  }, {tab: 'clients', words: 'Open the clients', icon: 'people'});
}
function peekIfacesCard() {
  var s = STATUS || {};
  peek('Interfaces', function () { return Promise.resolve(s); }, function (body) {
    var ifs = Object.keys(s.interfaces || {});
    body.appendChild(peekFacts([['Listening on', num(ifs.length)], ['Port', String(s.http_port)],
      ['Public IP', s.public_ip || s.external_ip || '–']]));
    body.appendChild(listTable(['Interface', 'Address', 'The description a client reads'], ifs, function (n) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', n)));
      tr.appendChild(noI18n(el('td', 'mono', s.interfaces[n])));
      /* The address and its copy button on one line (otp's cert-crl-url-in). */
      var url = 'http://' + s.interfaces[n] + ':' + s.http_port + '/rootDesc.xml';
      var td = el('td', 'cert-crl-url'), line = el('div', 'cert-crl-url-in');
      var u = noI18n(el('span', 'mono', url));
      u.title = url;
      line.appendChild(u);
      var cp = iconButton('copy', 'Copy the address');
      cp.onclick = function (ev) { ev.stopPropagation(); copyText(url, cp, 'the address copied'); };
      line.appendChild(cp);
      td.appendChild(line);
      tr.appendChild(td);
      return tr;
    }, 'plain if-t|None in the log since the service last started'));
  }, ADMIN ? {tab: 'settings', pane: 'network', words: 'Open Settings', icon: 'gear'} : null);
}
function peekMapsCard() {
  peek('Mappings now', function () { return api('mappings'); }, function (body, d) {
    body.appendChild(peekFacts([['Held', num((d.mappings || []).length)], ['Answer', (STATUS || {}).mapping_response || '–']]));
    body.appendChild(mappingsTable(d.mappings || [], d.now));
  }, {tab: 'mappings', words: 'Open the mappings', icon: 'router'});
}
function peekMdnsCard() {
  var m = (STATUS || {}).mdns;
  peek('mDNS reflector', function () { return api('mdns'); }, function (body, d) {
    if (!m || d.installed === false) { body.appendChild(el('p', 'note', 'avahi-daemon is not installed here.')); return; }
    var sv = d.service || {};
    body.appendChild(peekFacts([['avahi-daemon', sv.state || m.state], ['The reflector', m.reflector ? 'on' : 'off'],
      ['Interfaces', ((d.now || {}).interfaces || []).map(function (i) { return i.name || i; }).join(', ') || (sv.state === 'active' ? 'none joined' : '–')]]));
  }, {tab: 'mdns', words: 'Open mDNS', icon: 'wifi'});
}
function peekUpgradeCard() {
  peek('Upgrades', function () { return api('upgrade'); }, function (body, d) {
    var on = d.online || {}, st = d.status || {};
    body.appendChild(peekFacts([['This server', d.here], ['The newest', (on.newest || {}).version || '–'],
      ['Looked', on.at ? ago(on.at) : 'never'], ['The last upgrade', st.state || '–']]));
    if (on.newer) body.appendChild(el('p', 'note good', 'fake-igd ' + on.newest.version + ' is out.'));
    if (d.package) body.appendChild(el('p', 'note good', 'fake-igd ' + d.package.version + ' is sent and checked.'));
  }, ADMIN ? {tab: 'settings', pane: 'upgrade', words: 'Open Upgrades', icon: 'up'} : null);
}
cardOpens('card-service', 'fake-igd.service: its state, how long it has run, the problems.', peekServiceCard);
cardOpens('card-mode', 'Whether it answers like a UPnP router, and what it says to AddPortMapping.', peekModeCard);
cardOpens('card-ports', 'The ports asked for, the last of them first.', peekPortsCard);
cardOpens('card-clients', 'The devices that asked, the last of them first.', peekClientsCard);
cardOpens('card-ifaces', 'The interfaces it listens on, and the description each client reads.', peekIfacesCard);
cardOpens('card-maps', 'What the clients believe is open now.', peekMapsCard);
cardOpens('card-mdns', 'avahi-daemon and its reflector.', peekMdnsCard);
cardOpens('card-upgrade', 'The version running, and the newest there is.', peekUpgradeCard);

/* The MikroTik on Overview (1.8.2): one strip - how many of the ports asked for it carries - shown only while
   Settings → MikroTik reads it. */
function drawMikrotikCard() {
  var host = $('card-mikrotik');
  if (!host || typeof window.MT_CHECKS !== 'function') return;
  window.MT_CHECKS().then(function (d) {
    clear(host);
    host.hidden = !d.on;
    if (!d.on) return;
    var ch = d.checks || {}, sn = d.snap || {}, st = d.state || {}, S = window.MT_STATE || {};
    var k = st.ok === false ? 'crit' : (!ch.total ? 'info' : (ch.open === ch.total ? 'ok' : (ch.open ? 'warn' : 'crit')));
    host.className = 'card full mt-ov tappable ' + k;
    var top = el('div', 'mt-ov-top');
    var ic = el('span', 'mt-ov-ic');
    ic.innerHTML = iconMarkup('wall', 20);
    top.appendChild(ic);
    var w = el('div', 'mt-ov-words');
    w.appendChild(el('div', 'label', 'MikroTik' + (sn.identity ? ' · ' + sn.identity : '')));
    w.appendChild(el('div', 'mt-ov-v', st.ok === false ? 'cannot be read' : (ch.total ? num(ch.open) + ' of ' + num(ch.total) + ' port(s) open on it'
      : (sn.at ? 'read - no port asked for yet' : 'not read yet'))));
    w.appendChild(el('div', 'sub', st.ok === false ? String(st.trouble || '').slice(0, 160) : (sn.at ? 'read ' + ago(sn.at) + (sn.version ? ' · RouterOS ' + sn.version : '') : '')));
    top.appendChild(w);
    var chips = el('div', 'mt-chips');
    Object.keys(ch.counts || {}).forEach(function (s) {
      if (!S[s]) return;
      var c = el('span', 'mt-chip ' + S[s][1]);
      c.appendChild(el('b', '', num(ch.counts[s])));
      c.appendChild(el('span', '', S[s][0]));
      chips.appendChild(c);
    });
    (ch.warnings || []).forEach(function (x) { if (/UPnP is ON/.test(x)) { var c = el('span', 'mt-chip crit alone'); c.appendChild(el('span', '', 'its own UPnP is ON')); chips.appendChild(c); } });
    top.appendChild(chips);
    host.appendChild(top);
    host.onclick = function () { showTab('settings'); showPane('mikrotik'); };
    CARD_WHY['card-mikrotik'] = {level: k === 'ok' ? 'ok' : (k === 'crit' ? 'crit' : 'warn'), words: 'Settings → MikroTik reads the real router: of the ports the devices asked for, how many it carries - a dst-nat to the device and nothing that drops it.'};
  }).catch(function () { host.hidden = true; });
}
function loadOverview() {
  paintCards();
  drawMikrotikCard();
  apiLatest('overview', 'overview' + tpQuery('ov-hours', 'since', 'until')).then(function (d) {
    drawChart(d, Math.round(d.hours || 24));
    $('m-ports-sub').textContent = num(d.add) + ' AddPortMapping · ' + $('ov-hours')._range().words + ' · '
      + num(d.rejected) + ' refused';
    /* The Requests open on the same window as the overview (otp 1.0.53). */
    var win = function (f) { f.since = d.since; f.until = d.until; return f; };
    facet('ov-ports', d.top_ports, 'good', function (r) { openRequests(win({q: 'port:' + r.port + ' proto:' + String(r.proto).toLowerCase(), result: 'ports'})); });
    facet('ov-results', d.top_results, 'reject', function (r) { openRequests(win({q: 'result:' + qQuote(r.said), result: 'ports'})); });
    facet('ov-clients', d.top_clients.map(function (r) { return Object.assign({}, r, {said: r.client + (r.name ? '  ' + r.name : '')}); }), 'good',
          function (r) { openRequests(win({client: r.client})); });
    facet('ov-actions', d.top_actions, 'good', function (r) { openRequests(win({action: r.said})); });
    explainWhatWasDrawn($('tab-overview'));
  }).catch(oops);
}
$('ov-hours').onchange = loadOverview;

function facet(id, rows, tone, go) {
  var host = typeof id === 'string' ? $(id) : id;
  clear(host);
  if (!rows || !rows.length) { host.appendChild(el('p', 'muted small', 'Nothing in this window.')); return; }
  var top = rows[0].n || 1;
  /* Each one whole: the words on their own line, and under them the bar, the count and when it was last. */
  var list = el('div', 'facetlist');
  rows.forEach(function (r) {
    var row = el('div', 'fct tappable');
    var said = noI18n(el('div', 'fct-said', r.said || '–'));
    row.appendChild(said);
    var line = el('div', 'fct-line');
    var bb = el('div', 'bar' + (tone === 'good' ? ' good' : ''));
    var fill = el('span');
    fill.style.width = Math.max(3, Math.round(100 * r.n / top)) + '%';
    bb.appendChild(fill);
    line.appendChild(bb);
    line.appendChild(el('span', 'fct-n', num(r.n)));
    line.appendChild(el('span', 'fct-when muted small', ago(r.last)));
    row.appendChild(line);
    row.onclick = function () { go(r); };
    list.appendChild(row);
  });
  host.appendChild(list);
}

function drawChart(d, hours) {
  var host = $('ov-chart');
  var tip = host.querySelector('.tip');
  clear(host);
  host.appendChild(tip);
  var series = d.series || [];
  if (!series.some(function (p) { return p.accepted || p.rejected || p.other; })) {
    host.appendChild(el('div', 'empty', 'Nothing has been asked in this window'));
    return;
  }
  var W = host.clientWidth || 700, H = host.clientHeight || 230;
  var padL = 44, padR = 12, padT = 12, padB = 26;
  var w, h = Math.max(10, H - padT - padB);
  var top = Math.max(1, series.reduce(function (m, p) { return Math.max(m, p.accepted, p.rejected, p.other); }, 0));
  /* Whole numbers on the axis, four steps of the same size. */
  var unit = Math.max(1, Math.ceil(top / 4));
  var mag = Math.pow(10, Math.floor(Math.log(unit) / Math.LN10));
  unit = [1, 2, 5, 10].map(function (x) { return x * mag; }).filter(function (x) { return x >= unit; })[0] || unit;
  var ceil = unit * 4;
  padL = Math.max(44, 16 + 7 * String(num(ceil)).length);
  w = Math.max(10, W - padL - padR);
  var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
  svg.setAttribute('preserveAspectRatio', 'none');
  function make(kind, attrs) {
    var n = document.createElementNS('http://www.w3.org/2000/svg', kind);
    for (var k in attrs) if (attrs.hasOwnProperty(k)) n.setAttribute(k, attrs[k]);
    return n;
  }
  for (var g = 0; g <= 4; g++) {
    var y = padT + h - (h * g / 4);
    svg.appendChild(make('line', {x1: padL, x2: W - padR, y1: y, y2: y, stroke: '#262c37', 'stroke-width': 1}));
    var label = make('text', {x: padL - 8, y: y + 4, fill: '#5b6472', 'font-size': 11, 'text-anchor': 'end'});
    label.textContent = num(unit * g);
    svg.appendChild(label);
  }
  var step = w / Math.max(1, series.length);
  var barW = Math.max(1, Math.min(14, step * 0.28));
  series.forEach(function (p, i) {
    var x = padL + step * i + step / 2;
    [['rejected', '#f85149', -1.5], ['accepted', '#3fb950', -0.5], ['other', '#58a6ff', 0.5]].forEach(function (one) {
      var v = p[one[0]];
      if (!v) return;
      var bh = Math.max(1, h * (v / ceil));
      svg.appendChild(make('rect', {x: x + one[2] * (barW + 0.6), y: padT + h - bh, width: barW,
                                    height: bh, fill: one[1], rx: 2, opacity: 0.88}));
    });
  });
  var every = Math.max(1, Math.ceil(series.length / Math.max(3, Math.floor(w / 72))));
  series.forEach(function (p, i) {
    if (i % every) return;
    var dd = new Date(p.t * 1000);
    var t = make('text', {x: padL + step * i + step / 2, y: H - 8, fill: '#5b6472', 'font-size': 11, 'text-anchor': 'middle'});
    t.textContent = hours > 48 ? pad2(dd.getDate()) + '-' + pad2(dd.getMonth() + 1) : clockWords(dd, false);
    svg.appendChild(t);
  });
  series.forEach(function (p, i) {
    var hit = make('rect', {x: padL + step * i, y: padT, width: step, height: h, fill: 'transparent'});
    var any = p.accepted || p.rejected || p.other;
    hit.style.cursor = any ? 'pointer' : 'crosshair';
    if (any) hit.addEventListener('click', function () {
      /* To where the next bar starts (otp 1.0.61): on a day the clocks change a bar is 23 or 25 hours. */
      var next = series[i + 1] ? series[i + 1].t : Math.min(p.t + d.step, d.until || p.t + d.step);
      openRequests({since: p.t, until: next});
    });
    hit.addEventListener('mousemove', function (e) {
      var box = host.getBoundingClientRect();
      tip.innerHTML = '<b>' + stamp(p.t) + '</b><br>'
        + (p.accepted ? '<span style="color:#3fb950">' + num(p.accepted) + ' port(s) confirmed</span><br>' : '')
        + (p.rejected ? '<span style="color:#f85149">' + num(p.rejected) + ' refused</span><br>' : '')
        + (p.other ? '<span style="color:#58a6ff">' + num(p.other) + ' other question(s)</span><br>' : '')
        + '<span style="color:#8b949e">' + (any ? 'press to open' : 'nothing') + '</span>';
      tip.style.display = 'block';
      var left = e.clientX - box.left + 12;
      if (left + tip.offsetWidth > box.width) left = e.clientX - box.left - tip.offsetWidth - 12;
      tip.style.left = Math.max(0, left) + 'px';
      tip.style.top = Math.max(0, e.clientY - box.top - 12) + 'px';
    });
    hit.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
    svg.appendChild(hit);
  });
  host.appendChild(svg);
}

/* ==========================================================================
   Ports, requests, clients, mappings - otp's Tokens and Log
   ========================================================================== */
function addrCell(ip, name) {
  var td = el('td');
  td.appendChild(noI18n(el('span', 'mono', ip || '–')));
  if (name) td.appendChild(noI18n(el('span', 'sub', name)));
  return td;
}
function protoTag(p) { return noI18n(el('span', 'tag ' + (String(p).toUpperCase() === 'UDP' ? 'violet' : 'info'), String(p || '?').toUpperCase())); }
function refusedWords(r) { return /^(rej|err|fail|conf)/.test(String(r || '')); }
function resultTag(r) {
  if (!r) return el('span', 'tag dim', 'answered');
  return el('span', 'tag ' + (refusedWords(r) ? 'crit' : 'ok'), r);
}
function matches(row, q) { return !q || JSON.stringify(row).toLowerCase().indexOf(q.toLowerCase()) >= 0; }
function qQuote(v) { v = String(v || ''); return /[\s",()]/.test(v) ? '"' + v.replace(/"/g, '') + '"' : v; }
function ensureOption(sel, value) {
  if (!Array.prototype.some.call(sel.options, function (o) { return o.value === value; })) {
    var o = el('option', '', value); o.value = value; sel.appendChild(o);
  }
}
function stepsList(steps) {
  var list = el('div', 'steps');
  (steps || []).forEach(function (s) {
    var row = el('div', 'step ' + (s.ok ? 'ok' : 'bad'));
    var mark = el('span', 'step-mark');
    mark.innerHTML = iconMarkup(s.ok ? 'check' : 'cancel', 15);
    row.appendChild(mark);
    var words = el('span', 'step-words');
    words.appendChild(el('b', '', s.what));
    if (s.said) words.appendChild(el('span', 'd', s.said));
    if (s.ms !== undefined) words.appendChild(el('span', 'd', s.ms + ' ms'));
    row.appendChild(words);
    list.appendChild(row);
  });
  return list;
}
function pairsTable(pairs) {
  return listTable(['Field', 'Value'], pairs || [], function (p) {
    var tr = el('tr');
    tr.appendChild(noI18n(el('td', 'mono small', p[0])));
    tr.appendChild(noI18n(el('td', 'mono small', p[1] === null || p[1] === undefined ? '' : (typeof p[1] === 'object' ? JSON.stringify(p[1]) : String(p[1])))));
    return tr;
  });
}
/** A section of a large popup: a card with a heading, a line saying what it is for. */
function msect(title, lede, wide) {
  var box = el('section', 'msect' + (wide ? ' wide' : ''));
  box.appendChild(el('h4', '', title));
  if (lede) box.appendChild(el('p', 'msect-lede', lede));
  var body = el('div', 'msect-body');
  box.appendChild(body);
  box._body = body;
  return box;
}

/* ---- Ports ---- */
function portTools(r) {
  var tools = el('td', 'rowtools');
  var rq = iconButton('list', 'Its requests');
  rq.onclick = function (ev) { ev.stopPropagation(); openRequests({q: 'client:' + r.client + ' port:' + r.port + ' proto:' + String(r.proto).toLowerCase(), result: 'ports'}); };
  tools.appendChild(rq);
  var cl = iconButton('people', 'The client');
  cl.onclick = function (ev) { ev.stopPropagation(); clientPeek(r.client); };
  tools.appendChild(cl);
  return tools;
}
function loadPorts() {
  var per = Number($('pt-per').value);
  var mt = typeof window.MT_CHECKS === 'function' ? window.MT_CHECKS().catch(function () { return {}; }) : Promise.resolve({});
  Promise.all([apiLatest('ports', 'ports&q=' + encodeURIComponent($('pt-q').value) + '&proto=' + $('pt-proto').value
      + '&result=' + $('pt-result').value + tpQuery('pt-hours', 'since', 'until')
      + '&page=' + PAGE.ports + '&per=' + per), mt]).then(function (two) {
    var d = two[0], MTC = mtChecksMap(two[1]);
    QS.ports.said(d.q_error || '');
    var c = d.counts || {};
    $('pt-said').textContent = num(c.ports) + ' port(s) · ' + num(c.udp) + ' UDP · ' + num(c.tcp) + ' TCP · '
      + num(c.clients) + ' client(s)';
    var host = $('pt-table');
    clear(host);
    var heads = ['Client', 'Protocol', {words: 'Port', cls: 'num'}, {words: 'Asked', cls: 'num'}, 'First', 'Last', 'Answered', 'What for', ''];
    if (MTC) heads.splice(7, 0, 'MikroTik');
    host.appendChild(listTable(heads, d.ports, function (r) {
      var tr = el('tr');
      tr.appendChild(addrCell(r.client, r.name));
      var tp = el('td'); tp.appendChild(protoTag(r.proto)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'num mono', r.port + (r.internal_port && String(r.internal_port) !== String(r.port) ? ' → ' + r.internal_port : ''))));
      tr.appendChild(el('td', 'num', num(r.count)));
      tr.appendChild(stampCell(r.first));
      tr.appendChild(stampCell(r.last));
      var res = el('td');
      Object.keys(r.results || {}).forEach(function (k) {
        res.appendChild(el('span', 'tag ' + (refusedWords(k) ? 'crit' : 'ok'), k + (r.results[k] > 1 ? ' ×' + r.results[k] : '')));
      });
      tr.appendChild(res);
      if (MTC) tr.appendChild(mtCell(MTC[mtKey(r.client, r.proto, r.port)]));
      tr.appendChild(noI18n(el('td', 'small', r.description || '')));
      tr.appendChild(portTools(r));
      tr.onclick = function () { portPeek(r); };
      return tr;
    }, 'rows|No port has been asked for in this window', {own: true}));
    pager('pt-pager', PAGE.ports, per, d.total, function (p) { PAGE.ports = p; loadPorts(); });
    explainWhatWasDrawn(host);
  }).catch(oops);
}
$('pt-q').addEventListener('input', debounce(function () { PAGE.ports = 0; loadPorts(); }, 300));
['pt-proto', 'pt-result', 'pt-hours', 'pt-per'].forEach(function (id) { $(id).onchange = function () { PAGE.ports = 0; loadPorts(); }; });
/* The MikroTik's state of each port (1.8.2), for the Ports tab and its popup: null while it is not read. */
function mtKey(dev, proto, port) { return dev + '|' + String(proto).toLowerCase() + '|' + port; }
function mtChecksMap(d) {
  if (!d || !d.on || !d.checks) return null;
  var m = {};
  (d.checks.rows || []).forEach(function (x) { m[mtKey(x.device, x.proto, x.port)] = x; });
  return m;
}
function mtCell(x) {
  var td = el('td', 'mt-cell');
  var S = window.MT_STATE || {};
  if (!x) { td.appendChild(el('span', 'muted small', '–')); return td; }
  var s = S[x.state] || ['?', 'dim'];
  var t = el('span', 'tag ' + s[1], s[0]);
  explain(t, (x.state === 'ok' ? x.forward_why || x.nat_why : x.nat_why) || s[2] || '');
  td.appendChild(t);
  if (x.v6 === 'blocked') td.appendChild(el('span', 'tag crit', 'IPv6 blocked'));
  return td;
}
function portPeek(r) {
  peek(String(r.proto).toUpperCase() + ' ' + r.port + ' · ' + r.client, function () {
    return api('requests&q=' + encodeURIComponent('port:' + r.port + ' proto:' + String(r.proto).toLowerCase()
      + ' client:' + r.client) + '&result=ports&since=1&per=50');
  }, function (body, d) {
    $('modal-box').className = 'box medium';
    var res = el('span');
    Object.keys(r.results || {}).forEach(function (k) { res.appendChild(el('span', 'tag ' + (refusedWords(k) ? 'crit' : 'ok'), k + ' ×' + r.results[k])); });
    body.appendChild(peekFacts([['Client', r.client], ['Name', r.name || '–'], ['Port', String(r.proto).toUpperCase() + ' ' + r.port],
      ['To', r.internal_port || r.port], ['Asked', num(r.count) + ' time(s)'], ['Answered', res],
      ['First', stamp(r.first)], ['Last', stamp(r.last)]]));
    if (r.description) body.appendChild(noI18n(el('p', 'note', 'What it said it is for: ' + r.description)));
    body.appendChild(el('h3', 'peek-h', 'On the real router'));
    var x = (mtChecksMap(window.MT_CACHE && window.MT_CACHE.d) || {})[mtKey(r.client, r.proto, r.port)];
    if (x) {
      var S = window.MT_STATE || {}, s = S[x.state] || ['?', 'dim', ''];
      var line = el('p', 'note');
      line.appendChild(el('span', 'tag ' + s[1], 'MikroTik: ' + s[0]));
      line.appendChild(noI18n(el('span', '', ' ' + (x.state === 'ok' ? (x.forward_why || x.nat_why) : x.nat_why))));
      body.appendChild(line);
      var cmds = (x.commands || []).concat(x.v6_commands || []);
      if (cmds.length) {
        var pre = noI18n(el('pre', 'lines', cmds.join('\n')));
        copyOnClick(pre, cmds.join('\n'), 'the commands are on the clipboard - type them on the MikroTik yourself');
        body.appendChild(pre);
      }
    } else body.appendChild(el('p', 'note', 'Forward ' + String(r.proto).toUpperCase() + ' ' + r.port + ' to '
      + r.client + ':' + (r.internal_port || r.port) + ' - Rules for the router makes it for iptables, nftables, MikroTik or firewalld.'));
    body.appendChild(el('h3', 'peek-h', 'Its requests'));
    body.appendChild(requestsTable(d.requests || [], ['client', 'port', 'for']));
  }, {tab: 'requests', words: 'Open its requests', icon: 'list', go: function () {
    openRequests({q: 'client:' + r.client + ' port:' + r.port + ' proto:' + String(r.proto).toLowerCase(), result: 'ports'});
  }});
}
$('dn-open').onclick = function () {
  modal('Rules for the router (DNAT)', function (body) {
    body.appendChild(el('p', 'note', 'Port forwarding rules made from the ports asked for - consecutive ports merged into '
      + 'ranges - the same as upnp dnat. Paste them into the real router.'));
    var row = el('div', 'btnrow filters');
    var fmt = selectBox([['iptables', 'iptables'], ['nft', 'nftables'], ['mikrotik', 'MikroTik'], ['firewalld', 'firewalld']], 'iptables');
    fmt.id = 'dn-format';
    var wan = textBox('', 'the WAN interface (eth0, ether1…)'); wan.id = 'dn-wan'; wan.style.maxWidth = '260px';
    row.appendChild(fmt); row.appendChild(wan);
    body.appendChild(row);
    var out = noI18n(el('pre', 'lines', '…')); out.id = 'dn-out'; out.style.marginTop = '12px';
    body.appendChild(out);
    var make = function () {
      api('dnat&format=' + fmt.value + '&wan=' + encodeURIComponent(wan.value.trim())).then(function (d) {
        out.textContent = d.text || '(nothing)';
      }).catch(function (e) { out.textContent = e.message; });
    };
    fmt.onchange = make;
    wan.addEventListener('input', debounce(make, 400));
    make();
  }, [{words: 'Copy', icon: 'copy', go: function (b) { copyText($('dn-out').textContent, b, 'copied'); }},
      {words: 'Close', close: true}], 'large');
};

/* ---- Requests (otp's Log) ---- */
/* A click-through into the Requests (otp 1.0.100): what it looks for is written into the search
   box and the filters, in the words the box takes - client:, port:, result: - and the time picker
   set to the window clicked, so the page says what it shows and every part can be cleared. */
function openRequests(f) {
  var q = [];
  if (f.q) q.push(f.q);
  $('rq-q').value = q.join(' ');
  $('rq-result').value = f.result || '';
  if (f.action) { ensureOption($('rq-action'), f.action); $('rq-action').value = f.action; } else $('rq-action').value = '';
  if (f.client) { ensureOption($('rq-client'), f.client); $('rq-client').value = f.client; } else $('rq-client').value = '';
  var tp = $('rq-hours');
  if (f.since && tp && tp._set) {
    tp._quiet = true;
    tp._set({k: 'abs', from: Math.floor(f.since), to: Math.ceil(f.until || 0) || 0});
    tp._quiet = false;
  }
  PAGE.requests = 0;
  if ($('rq-q')._sbPaint) $('rq-q')._sbPaint();
  if (TAB === 'requests') loadRequests(); else showTab('requests');
}
/* The requests as a table; `leave` the columns a popup already says (its port, its client) - left out
   there, so the table fits the popup without a scroller of its own. */
function requestsTable(rows, leave) {
  leave = leave || [];
  var has = function (c) { return leave.indexOf(c) < 0; };
  var heads = ['When'];
  if (has('client')) heads.push('Client');
  heads.push('Action');
  if (has('port')) heads.push('Protocol', {words: 'Port', cls: 'num'});
  heads.push('To', {words: 'Lease', cls: 'num'}, 'Answered');
  if (has('for')) heads.push('What for');
  if (has('client')) heads.push('');
  return listTable(heads, rows, function (r) {
    var tr = el('tr');
    if (refusedWords(r.result)) tr.className = 'is-banned';
    tr.appendChild(stampCell(r.at));
    if (has('client')) tr.appendChild(addrCell(r.client, r.name));
    tr.appendChild(noI18n(el('td', 'mono small', r.action || '')));
    if (has('port')) {
      var tp = el('td'); if (r.protocol) tp.appendChild(protoTag(r.protocol)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'num mono', r.external_port || '')));
    }
    tr.appendChild(noI18n(el('td', 'mono small', r.internal_client ? r.internal_client + ':' + (r.internal_port || '') : '')));
    var ls = el('td', 'num muted', r.lease !== undefined && r.lease !== null && r.lease !== '' ? num(r.lease) + ' s' : '');
    ls.style.whiteSpace = 'nowrap';
    tr.appendChild(ls);
    var res = el('td');
    if (r.result || r.action === 'AddPortMapping') res.appendChild(resultTag(r.result || 'ok'));
    tr.appendChild(res);
    if (has('for')) tr.appendChild(noI18n(el('td', 'small', r.description || '')));
    if (has('client')) {
      var tools = el('td', 'rowtools');
      var cl = iconButton('people', 'The client');
      cl.onclick = function (ev) { ev.stopPropagation(); clientPeek(r.client); };
      tools.appendChild(cl);
      tr.appendChild(tools);
    }
    tr.onclick = function () { if (leave.length) modalOver(function () { requestPeek(r); }); else requestPeek(r); };
    if (leave.length) tr.classList.add('tappable');
    return tr;
  }, 'rows|Nothing was asked in this window', {own: true});
}
function loadRequests() {
  var per = Number($('rq-per').value);
  apiLatest('requests', 'requests&q=' + encodeURIComponent($('rq-q').value) + '&result=' + $('rq-result').value
      + '&action=' + encodeURIComponent($('rq-action').value) + '&client=' + encodeURIComponent($('rq-client').value)
      + tpQuery('rq-hours', 'since', 'until') + '&page=' + PAGE.requests + '&per=' + per).then(function (d) {
    QS.requests.said(d.q_error || '');
    (d.actions || []).forEach(function (a) { ensureOption($('rq-action'), a); });
    (d.clients || []).forEach(function (c) { ensureOption($('rq-client'), c); });
    var host = $('rq-table');
    clear(host);
    host.appendChild(requestsTable(d.requests));
    $('rq-said').textContent = num(d.total) + ' matching';
    pager('rq-pager', PAGE.requests, per, d.total, function (p) { PAGE.requests = p; loadRequests(); });
    explainWhatWasDrawn(host);
  }).catch(oops);
}
$('rq-q').addEventListener('input', debounce(function () { PAGE.requests = 0; loadRequests(); }, 300));
['rq-result', 'rq-action', 'rq-client', 'rq-hours', 'rq-per'].forEach(function (id) {
  $(id).onchange = function () { PAGE.requests = 0; loadRequests(); };
});
function requestPeek(r) {
  peek((r.action || 'A request') + ' · ' + r.client, function () {
    return api('request&at=' + r.at + '&client=' + encodeURIComponent(r.client) + '&action=' + encodeURIComponent(r.action || ''));
  }, function (body, d) {
    $('modal-box').className = 'box medium';
    var x = d.row;
    var res = el('span'); res.appendChild(resultTag(x.result || (x.action === 'AddPortMapping' ? 'ok' : '')));
    body.appendChild(peekFacts([['When', stamp(x.at)], ['Client', x.client], ['Name', x.name || '–'], ['Action', x.action],
      ['Answered', res]].concat(x.protocol ? [['Port', String(x.protocol).toUpperCase() + ' ' + x.external_port]] : [])));
    if (x.description) body.appendChild(noI18n(el('p', 'note', 'What it said it is for: ' + x.description)));
    body.appendChild(el('h3', 'peek-h', 'How it was answered'));
    body.appendChild(stepsList(d.steps));
    body.appendChild(el('h3', 'peek-h', 'What was asked'));
    body.appendChild(pairsTable(Object.keys(x).filter(function (k) { return k !== 'at' && k !== 'name'; }).map(function (k) { return [k, x[k]]; })));
    body.appendChild(el('h3', 'peek-h', 'What the log said then'));
    if (!(d.log || []).length) body.appendChild(el('p', 'note', 'Nothing about it within two seconds.'));
    else body.appendChild(noI18n(el('pre', 'lines', d.log.map(function (l) { return clockWords(new Date(l.at * 1000)) + ' ' + l.level + '  ' + l.words; }).join('\n'))));
    var row = el('div', 'btnrow');
    row.style.marginTop = '14px';
    var cb = cmdButton('The client', 'people', '');
    cb.onclick = function () { clientPeek(x.client); };
    row.appendChild(cb);
    if (x.external_port) {
      var pb = cmdButton('Every request of this port', 'list', '');
      pb.onclick = function () { closeModal(); openRequests({q: 'port:' + x.external_port + (x.protocol ? ' proto:' + String(x.protocol).toLowerCase() : '')}); };
      row.appendChild(pb);
    }
    body.appendChild(row);
  });
}

/* ---- Clients ---- */
/* The steps of a client on its way to a port (1.7.4): searched, answered, fetched the description, fetched
   the service's, asked SOAP questions, asked for ports - each a pill, lit when it got there; where it stopped
   in words. Read by /api/upnp/steps from fake-igd's log and its request log. */
var CL_STEPS = [['searched', 'searched', 'It looked for a UPnP router (SSDP M-SEARCH)'],
                ['answered', 'answered', 'fake-igd answered its search'],
                ['described', 'description', 'It fetched the device description (rootDesc.xml)'],
                ['service', 'service', 'It fetched the description of the service (WANIPCn.xml)'],
                ['asked', 'SOAP', 'It asked SOAP questions (GetExternalIPAddress, GetStatusInfo...)'],
                ['ports', 'ports', 'It asked for ports (AddPortMapping)']];
function stepPills(st) {
  var box = el('span', 'step-pills');
  if (!st) return box;
  var reached = st.reached || [];
  CL_STEPS.forEach(function (x, i) {
    var on = reached.indexOf(x[0]) >= 0;
    var last = !st.ports && on && i === st.furthest;
    var p = el('span', 'tag ' + (on ? (st.ports ? 'ok' : (last ? 'warn' : 'ok')) : 'dim'), x[1]);
    if (x[0] === 'answered' && !on && st.unanswered) p.className = 'tag crit';
    p.title = x[2] + (on ? '' : ' - not seen');
    box.appendChild(p);
  });
  return box;
}
function clientsTable(rows, small, steps) {
  var heads = ['Client', {words: 'Searches', cls: 'num'}, {words: 'Requests', cls: 'num'}, 'Ports', 'Last seen', 'It says it is', ''];
  if (steps) heads.splice(3, 0, 'How far it got');
  return listTable(heads, rows, function (r) {
    var tr = el('tr');
    tr.appendChild(addrCell(r.client, r.name));
    tr.appendChild(el('td', 'num', num(r.searches)));
    tr.appendChild(el('td', 'num', num(r.requests)));
    if (steps) {
      var st = steps[r.client], td = el('td');
      td.appendChild(stepPills(st));
      if (st && st.stopped) td.appendChild(el('div', 'muted small step-said', st.stopped));
      if (st && st.gateway_hint) td.appendChild(gatewayHint(r.client, r.name, true));
      tr.appendChild(td);
    }
    tr.appendChild(noI18n(el('td', 'mono small', (r.ports || []).slice(0, small ? 6 : 40).join(', ') + ((r.ports || []).length > (small ? 6 : 40) ? ' …' : ''))));
    tr.appendChild(stampCell(r.last ? Date.parse(r.last) / 1000 : null));
    tr.appendChild(noI18n(el('td', 'muted small', r.user_agent || '')));
    var tools = el('td', 'rowtools');
    var rq = iconButton('list', 'Its requests');
    rq.onclick = function (ev) { ev.stopPropagation(); closeModal(); openRequests({client: r.client}); };
    tools.appendChild(rq);
    tr.appendChild(tools);
    tr.onclick = function () { if ($('modal').hidden) clientPeek(r.client, r); else modalOver(function () { clientPeek(r.client, r); }); };
    return tr;
  }, 'rows|No client in this window', {own: true});
}
/* Stopped at "answered" (1.7.15): a PS5 asks UPnP only of its DEFAULT GATEWAY - answered by fake-igd
   while the real router is its gateway, it goes no further. The way on: this server as its gateway
   (Settings → Gateway for devices), opened with this device filled in. */
function gatewayHint(ip, name, small) {
  var box = el('div', 'gw-hint' + (small ? ' small' : ' note warn'));
  box.appendChild(el('span', '', small ? 'A PS5 asks only its default gateway. '
    : 'A PS5 asks UPnP only of its default gateway: answered by fake-igd while the router is its gateway, it goes no further. Make this server its gateway for it - only this device, only toward the router. '));
  if (ADMIN) {
    var go = function (ev) {
      if (ev) ev.stopPropagation();
      window.GW_PREFILL = {ip: ip, name: name || ''};
      closeModal();
      location.hash = '#settings/gateway';
    };
    if (small) {
      var a = el('a', 'fgo', 'Make this server its gateway');
      a.onclick = go;
      box.appendChild(a);
    } else {
      var row = el('div', 'btnrow gw-hint-go');
      var b = cmdButton('Make this server its gateway', 'router', 'small primary');
      b.onclick = go;
      row.appendChild(b);
      box.appendChild(row);
    }
  }
  return box;
}
var CL = {steps: null};
function loadClients() {
  var per = Number($('cl-per').value);
  var win = tpQuery('cl-hours', 'since', 'until');
  Promise.all([apiLatest('clients', 'clients&q=' + encodeURIComponent($('cl-q').value) + win
      + '&page=' + PAGE.clients + '&per=' + per),
               api('upnp-steps' + win.replace(/^&/, '&')).catch(function () { return {clients: {}}; })]).then(function (two) {
    var d = two[0];
    CL.steps = two[1].clients || {};
    QS.clients.said(d.q_error || '');
    $('cl-said').textContent = num(d.total) + ' client(s)';
    var host = $('cl-table');
    clear(host);
    host.appendChild(clientsTable(d.clients, false, CL.steps));
    pager('cl-pager', PAGE.clients, per, d.total, function (p) { PAGE.clients = p; loadClients(); });
    explainWhatWasDrawn(host);
  }).catch(oops);
}
$('cl-q').addEventListener('input', debounce(function () { PAGE.clients = 0; loadClients(); }, 300));
['cl-hours', 'cl-per'].forEach(function (id) { $(id).onchange = function () { PAGE.clients = 0; loadClients(); }; });
function clientPeek(ip, known) {
  peek(ip, function () {
    return Promise.all([known ? Promise.resolve({clients: [known]}) : api('clients&q=' + encodeURIComponent('client:' + ip) + '&per=10'),
                        api('ports&q=' + encodeURIComponent('client:' + ip) + '&sort=last&per=100'),
                        api('requests&client=' + encodeURIComponent(ip) + '&since=1&per=20'),
                        api('upnp-steps&client=' + encodeURIComponent(ip)).catch(function () { return {clients: {}}; })]);
  }, function (body, three) {
    $('modal-box').className = 'box medium';
    var c = (three[0].clients || [])[0] || {client: ip};
    body.appendChild(peekFacts([['Address', ip], ['Name', c.name || '–'], ['Searches', num(c.searches || 0)],
      ['Requests', num(c.requests || 0)], ['Ports', num((three[1].ports || []).length)],
      ['Last seen', c.last ? stamp(Date.parse(c.last) / 1000) : '–']]));
    if (c.user_agent) body.appendChild(noI18n(el('p', 'note', 'It says it is: ' + c.user_agent)));
    var st = ((three[3] || {}).clients || {})[ip];
    body.appendChild(el('h3', 'peek-h', 'How far it got'));
    body.appendChild(stepPills(st || {reached: [], furthest: -1}));
    if (st && st.stopped) body.appendChild(el('p', 'note warn', 'It stopped: ' + st.stopped + '.'));
    if (st && st.gateway_hint) body.appendChild(gatewayHint(ip, c.name, false));
    else if (!st) body.appendChild(el('p', 'muted small', 'Nothing of it in fake-igd\'s log.'));
    if (st) {
      var facts = [];
      if (st.searched) facts.push(['Searched for', st.searched.st + (st.searched.mx ? ' (MX ' + st.searched.mx + ')' : ''), true]);
      if (st.searched && st.searched.ua && st.searched.ua !== '-') facts.push(['Its search says', st.searched.ua, true]);
      if (st.answered) facts.push(['Answered with', st.answered.st + ' · ' + st.answered.location, true]);
      else if (st.unanswered) facts.push(['Not answered', st.unanswered.why, true]);
      if (st.described && st.described.ua) facts.push(['It fetches as', st.described.ua, true]);
      var acts = Object.keys(st.actions || {}).sort();
      if (acts.length) facts.push(['SOAP it asked', acts.map(function (a) { var x = st.actions[a]; return a + (x.errors ? ' (' + x.errors + (x.errors > 1 ? ' errors, the last: ' : ' error: ') + (x.said || '') + ')' : ''); }).join(', '), true]);
      if (facts.length) body.appendChild(peekFacts(facts.map(function (f) { return [f[0], noI18n(el('span', 'mono small', f[1]))]; })));
      var tl = (st.timeline || []).slice(-40).reverse();
      body.appendChild(el('h3', 'peek-h', 'Its steps, the last first'));
      body.appendChild(listTable(['When', 'What', ''], tl, function (x) {
        var tr = el('tr');
        tr.appendChild(stampCell(x.at));
        tr.appendChild(el('td', 'step-tl-what', x.what));
        tr.appendChild(noI18n(el('td', 'mono small step-tl-said', x.said || '')));
        return tr;
      }, 'plain|Nothing of it in the log'));
    }
    body.appendChild(el('h3', 'peek-h', 'The ports it asked for'));
    body.appendChild(listTable(['Protocol', {words: 'Port', cls: 'num'}, {words: 'Asked', cls: 'num'}, 'Last', 'Answered', 'What for'],
                               three[1].ports || [], function (r) {
      var tr = el('tr', 'tappable');
      var tp = el('td'); tp.appendChild(protoTag(r.proto)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'num mono', r.port)));
      tr.appendChild(el('td', 'num', num(r.count)));
      tr.appendChild(el('td', 'muted', ago(r.last)));
      var res = el('td');
      Object.keys(r.results || {}).forEach(function (k) { res.appendChild(el('span', 'tag ' + (refusedWords(k) ? 'crit' : 'ok'), k)); });
      tr.appendChild(res);
      tr.appendChild(noI18n(el('td', 'small', r.description || '')));
      tr.onclick = function () { modalOver(function () { portPeek(r); }); };
      return tr;
    }, 'plain|It has asked for no port'));
    body.appendChild(el('h3', 'peek-h', 'Its last requests'));
    body.appendChild(requestsTable(three[2].requests || [], ['client']));
  }, {tab: 'requests', words: 'Open its requests', icon: 'list', go: function () { openRequests({client: ip}); }});
}

/* ---- Mappings ---- */
var MAPS = null;
function mappingsTable(rows, now) {
  return listTable(['Protocol', {words: 'Port', cls: 'num'}, 'To', 'Left', 'Added', 'Asked by', 'What for'], rows, function (m) {
    var tr = el('tr');
    var tp = el('td'); tp.appendChild(protoTag(m.protocol)); tr.appendChild(tp);
    tr.appendChild(noI18n(el('td', 'num mono', m.external_port)));
    tr.appendChild(addrCell(m.internal_client + ':' + m.internal_port, m.name));
    var left = m.expires_at ? Math.max(0, Math.round(m.expires_at - (now || Date.now() / 1000))) : null;
    tr.appendChild(el('td', left === 0 ? 'muted' : '', left === null ? 'no end' : (left ? span(left) : 'run out')));
    tr.appendChild(stampCell(m.added_at));
    tr.appendChild(noI18n(el('td', 'mono small', m.requested_by || '')));
    tr.appendChild(noI18n(el('td', 'small', m.description || '')));
    tr.onclick = function () { mapPeek(m, now); };
    return tr;
  }, 'rows|No mapping now - they are kept only while the answer is accept and the mode active', {own: true});
}
function loadMappings() {
  apiLatest('mappings', 'mappings').then(function (d) {
    MAPS = d;
    drawMappings();
  }).catch(oops);
}
function drawMappings() {
  var d = MAPS || {mappings: []};
  var q = $('mp-q').value.trim(), pr = $('mp-proto').value;
  var rows = d.mappings.filter(function (m) { return (!pr || String(m.protocol).toUpperCase() === pr) && matches(m, q); });
  $('mp-said').textContent = num(rows.length) + ' held';
  var host = $('mp-table');
  clear(host);
  host.appendChild(mappingsTable(rows, d.now));
  explainWhatWasDrawn(host);
}
$('mp-q').addEventListener('input', debounce(drawMappings, 200));
$('mp-proto').onchange = drawMappings;
function mapPeek(m, now) {
  var left = m.expires_at ? Math.max(0, Math.round(m.expires_at - (now || Date.now() / 1000))) : null;
  peek(String(m.protocol).toUpperCase() + ' ' + m.external_port, function () { return Promise.resolve(m); }, function (body) {
    body.appendChild(peekFacts([['To', m.internal_client + ':' + m.internal_port], ['Name', m.name || '–'],
      ['Left', left === null ? 'no end' : span(left)], ['Added', stamp(m.added_at)], ['Asked by', m.requested_by || '–']]));
    body.appendChild(pairsTable(Object.keys(m).map(function (k) { return [k, m[k]]; })));
  }, {tab: 'requests', words: 'Open its requests', icon: 'list', go: function () {
    openRequests({q: 'port:' + m.external_port + ' proto:' + String(m.protocol).toLowerCase(), result: 'ports'});
  }});
}

/* ==========================================================================
   The log - coloured as upnp log colours it, followed live
   ========================================================================== */
var LOGV = {paused: false};
function logSpan(cls, text) { return el('span', cls, text); }
function logWords(host, text, tone, hit) {
  /* addresses magenta, accepted green, rejected red - as log_text() in upnp.py */
  var rx = /(\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b)|\b(accept(?:ed)?|signed in|in place|done|ok)\b|\b(reject(?:ed)?|refused|failed|wrong|not answering)\b/gi;
  var at = 0, m;
  var put = function (t, cls) {
    if (!t) return;
    if (hit) {
      t.split(hit).forEach(function (p, i) {
        if (i % 2 === 1) host.appendChild(el('mark', '', p));
        else if (p) host.appendChild(cls ? logSpan(cls, p) : document.createTextNode(p));
      });
      return;
    }
    host.appendChild(cls ? logSpan(cls, t) : document.createTextNode(t));
  };
  while ((m = rx.exec(text))) {
    put(text.slice(at, m.index), tone);
    put(m[0], m[1] ? 'la' : (m[2] ? 'lg' : 'lr'));
    at = m.index + m[0].length;
  }
  put(text.slice(at), tone);
}
function drawLog(lines, q) {
  var out = $('lg-out'), box = $('lg-scroll');
  var atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  clear(out);
  var hit = null;
  if (q) { try { hit = new RegExp('(' + q + ')', 'i'); } catch (e) { hit = null; } }
  lines.forEach(function (ln) {
    var m = /^(\S+ \S+) (\w+)(\s+)(.*)$/.exec(ln);
    if (!m) { logWords(out, ln + '\n', '', hit); return; }
    var lvl = m[2].toLowerCase();
    var tone = /^(error|crit|critical)$/.test(lvl) ? 'lt-bad' : (/^warn/.test(lvl) ? 'lt-warn' : (lvl === 'debug' ? 'lv-dim' : ''));
    out.appendChild(logSpan('lt', m[1] + ' '));
    out.appendChild(logSpan(tone ? (tone === 'lt-bad' ? 'lv-bad' : tone === 'lt-warn' ? 'lv-warn' : 'lv-dim') : 'lw', (m[2] + '     ').slice(0, 5) + ' '));
    var w = /^([a-z][a-z -]{1,30}): (.*)$/.exec(m[4]);
    if (w) { out.appendChild(logSpan('lw', w[1] + ': ')); logWords(out, w[2], tone, hit); }
    else logWords(out, m[4], tone, hit);
    out.appendChild(document.createTextNode('\n'));
  });
  if (!lines.length) out.appendChild(el('span', 'muted', q ? 'no line has that' : 'the log is empty'));
  if (atEnd) box.scrollTop = box.scrollHeight;
}
function loadLog(first) {
  if (LOGV.paused && !first) return;
  var q = $('lg-q').value.trim();
  apiLatest('log', 'log&lines=' + $('lg-lines').value + '&q=' + encodeURIComponent(q)).then(function (d) {
    $('lg-file').textContent = d.file || '';
    var box = $('lg-scroll');
    drawLog(d.lines, q);
    if (first) box.scrollTop = box.scrollHeight;
  }).catch(oops);
}
$('lg-q').addEventListener('input', debounce(function () { loadLog(true); }, 300));
$('lg-lines').onchange = function () { loadLog(true); };
$('lg-pause').onclick = function () {
  LOGV.paused = !LOGV.paused;
  setButtonIcon($('lg-pause'), LOGV.paused ? 'play' : 'pause', LOGV.paused ? 'Follow again' : 'Pause');
  if (!LOGV.paused) loadLog(true);
};
setInterval(function () { if (TAB === 'log' && LIVE && !document.hidden) loadLog(false); }, 3000);

/* ==========================================================================
   Events
   ========================================================================== */
function loadEvents() {
  var per = 100;
  apiLatest('events', 'events&q=' + encodeURIComponent($('ev-q').value) + '&kind=' + encodeURIComponent($('ev-kind').value)
      + tpQuery('ev-time', 'since', 'until') + '&page=' + PAGE.events + '&per=' + per).then(function (d) {
    QS.events.said(d.q_error || '');
    var sel = $('ev-kind');
    (d.kinds || []).forEach(function (k) { ensureOption(sel, k); });
    var host = $('ev-table');
    clear(host);
    host.appendChild(listTable(['When', 'Kind', 'Who', 'What'], d.events, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.at));
      var k = el('td'); k.appendChild(el('span', 'tag ' + (r.level === 'warn' || r.level === 'bad' || r.level === 'error' ? 'warn' : 'dim'), r.kind));
      tr.appendChild(k);
      tr.appendChild(noI18n(el('td', '', r.who || '')));
      tr.appendChild(noI18n(el('td', '', r.words)));
      return tr;
    }, '', {own: true}));
    pager('ev-pager', PAGE.events, per, d.total, function (p) { PAGE.events = p; loadEvents(); });
  }).catch(oops);
}
$('ev-q').addEventListener('input', debounce(function () { PAGE.events = 0; loadEvents(); }, 300));
$('ev-kind').onchange = function () { PAGE.events = 0; loadEvents(); };
if ($('ev-time')) $('ev-time').onchange = function () { PAGE.events = 0; loadEvents(); };
$('log-read').onclick = function () {
  api('log&lines=' + $('log-lines').value).then(function (d) {
    var out = $('log-out');
    out.hidden = false;
    if (d.file) $('log-file').textContent = d.file;
    out.textContent = d.lines.join('\n');
    out.scrollTop = out.scrollHeight;
  }).catch(oops);
};

/* ---- every list's search box offers its fields and values (otp 1.0.19) ---- */
var QS = {
  ports: qSuggest($('pt-q'), 'ports'),
  requests: qSuggest($('rq-q'), 'requests', function () {
    var r = $('rq-hours') && $('rq-hours')._range ? $('rq-hours')._range() : null;
    return r && r.from ? 'hours=' + Math.max(1, Math.ceil((Date.now() / 1000 - r.from) / 3600)) : '';
  }),
  clients: qSuggest($('cl-q'), 'clients'),
  events: qSuggest($('ev-q'), 'events')
};

/* ---- Search and Clear beside every search box (otp 1.0.100) ---------------- */
/** go(): draw the list again; selects: filters put back to their first choice ("every …");
    times: time pickers put back to where each started. */
function searchButtons(input, go, selects, times) {
  if (!input || input._sb) return;
  input._sb = true;
  var find = cmdButton('Search', 'search', 'sb-go');
  var clearB = cmdButton('Clear', 'close', 'sb-clear');
  find.type = clearB.type = 'button';
  find.title = 'Look for what is typed and chosen (Enter does the same)';
  clearB.title = 'Empty the search and put every filter here back';
  find.onclick = function () { go(); };
  clearB.onclick = function () {
    input.value = '';
    (selects || []).forEach(function (id) {
      var sel = typeof id === 'string' ? $(id) : id;
      if (sel && sel.options && sel.options.length) sel.value = sel.options[0].value;
    });
    (times || []).forEach(function (id) {
      var tp = $(id);
      if (tp && tp._set) { tp._quiet = true; tp._set(tp._start || {k: 'rel', s: 86400}); tp._quiet = false; }
    });
    if (input._qs) input._qs.said('');
    go();
  };
  var paint = function () {
    var busy = !!input.value.trim() || (selects || []).some(function (id) {
      var sel = typeof id === 'string' ? $(id) : id;
      return sel && sel.options && sel.options.length && sel.value !== sel.options[0].value;
    });
    clearB.classList.toggle('on', busy);
  };
  input.addEventListener('input', paint);
  (selects || []).forEach(function (id) { var sel = typeof id === 'string' ? $(id) : id; if (sel) sel.addEventListener('change', paint); });
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.defaultPrevented) go(); });
  var at = input.parentNode && input.parentNode.classList.contains('qs-wrap') ? input.parentNode : input;
  var after = at.nextSibling;
  at.parentNode.insertBefore(find, after);
  at.parentNode.insertBefore(clearB, after);
  input._sbPaint = paint;
  paint();
}
searchButtons($('pt-q'), function () { PAGE.ports = 0; loadPorts(); }, ['pt-proto', 'pt-result'], ['pt-hours']);
searchButtons($('rq-q'), function () { PAGE.requests = 0; loadRequests(); }, ['rq-result', 'rq-action', 'rq-client'], ['rq-hours']);
searchButtons($('cl-q'), function () { PAGE.clients = 0; loadClients(); }, [], ['cl-hours']);
searchButtons($('mp-q'), drawMappings, ['mp-proto']);
searchButtons($('ev-q'), function () { PAGE.events = 0; loadEvents(); }, ['ev-kind'], ['ev-time']);

/* ==========================================================================
   Settings: the rail, the panes, and the settings drawn from the API (otp's)
   ========================================================================== */
var RAIL = {pinned: false, open: null, shut: null};
function showPane(name) {
  /* A full administrator's pane followed by a link as a read-only account: the first pane instead. */
  var nb = document.querySelector('#ctl-nav button[data-pane="' + name + '"]');
  if (nb && nb.classList.contains('fulladmin-only') && !ADMIN) name = 'answer';
  if (!$('pane-' + name)) name = 'answer';
  if (name !== PANE) paneLetGo();
  PANE = name;
  document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
    b.classList.toggle('on', b.dataset.pane === name);
  });
  document.querySelectorAll('.ctl-pane').forEach(function (p) { p.hidden = p.id !== 'pane-' + name; });
  writeHash();
  if (typeof PANE_LOAD[name] === 'function') {
    try { PANE_LOAD[name](); } catch (e) { oops(e); }
  }
  if (name === 'people') setTimeout(colsCardWire, 0);
  /* The save bar where there is a setting to save, and nowhere else. */
  markDirtyCount();
}
document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
  if (!$('pane-' + b.dataset.pane)) b.hidden = true;
  b.onclick = function () { showPane(b.dataset.pane); };
});
function pinRail(on) {
  RAIL.pinned = !!on;
  var nav = $('ctl-nav'), pin = $('ctl-pin');
  nav.classList.toggle('pinned', RAIL.pinned);
  document.querySelector('.ctl-layout').classList.toggle('nav-pinned', RAIL.pinned);
  pin.setAttribute('aria-pressed', RAIL.pinned ? 'true' : 'false');
  explain(pin, RAIL.pinned ? 'The menu is staying open. Press again to let it hide itself at the edge of the screen.'
    : 'The menu hides itself at the edge of the screen and slides out when you point at it. Press this to keep it open.');
  try { localStorage.setItem('fake-igd-rail-pinned', RAIL.pinned ? '1' : '0'); } catch (e) { }
}
(function rail() {
  var nav = $('ctl-nav'), pin = $('ctl-pin');
  pin.innerHTML = iconMarkup('pin', 17);
  pin.onclick = function (e) { e.stopPropagation(); pinRail(!RAIL.pinned); };
  nav.addEventListener('mouseenter', function () {
    clearTimeout(RAIL.shut);
    RAIL.open = setTimeout(function () { nav.classList.add('open'); }, 60);
  });
  nav.addEventListener('mouseleave', function () {
    clearTimeout(RAIL.open);
    RAIL.shut = setTimeout(function () {
      if (document.activeElement && document.activeElement.id === 'ctl-find' && $('ctl-find').value) return;
      nav.classList.remove('open');
    }, 260);
  });
  var was = '0';
  try { was = localStorage.getItem('fake-igd-rail-pinned') || '0'; } catch (e) { }
  pinRail(was === '1');
}());
$('ctl-find').addEventListener('input', function () {
  var want = $('ctl-find').value.trim().toLowerCase();
  var box = $('ctl-found');
  clear(box);
  if (!want || !SETTINGS) { box.hidden = true; return; }
  var all = SETTINGS.settings.concat(typeof AV !== 'undefined' && AV.d && AV.d.keys && typeof avahiSetting === 'function'
    ? AV.d.keys.map(avahiSetting) : []);
  var hits = all.filter(function (s) {
    return (s.name + ' ' + s.key + ' ' + (s.says || '')).toLowerCase().indexOf(want) >= 0;
  }).slice(0, 12);
  if (!hits.length) box.appendChild(el('div', 'ctl-none', 'Nothing by that name'));
  hits.forEach(function (s) {
    var b = el('button', 'ctl-hit');
    b.type = 'button';
    b.appendChild(el('span', 'ctl-hit-t', s.name));
    var pane = s.key.indexOf('avahi:') === 0 ? 'mdns'
      : Object.keys(SETTINGS.panes).filter(function (p) { return SETTINGS.panes[p].indexOf(s.key) >= 0; })[0] || s.pane;
    var where = document.querySelector('.ctl-nav [data-pane="' + (pane || 'about') + '"]');
    b.appendChild(el('span', 'ctl-hit-w', where ? where.textContent.trim() : (pane || '')));
    b.onclick = function () {
      showPane(pane || 'about');
      $('ctl-find').value = '';
      box.hidden = true;
      setTimeout(function () {
        var item = document.querySelector('.set-item[data-key="' + s.key + '"]');
        if (item) {
          item.scrollIntoView({block: 'center'});
          item.classList.remove('found');
          void item.offsetWidth;
          item.classList.add('found');
          item.addEventListener('animationend', function () { item.classList.remove('found'); }, {once: true});
        }
      }, 60);
    };
    box.appendChild(b);
  });
  box.hidden = !hits.length && !want;
});

function loadSettings(redraw) {
  api('settings').then(function (d) {
    SETTINGS = d;
    /* Typed while this was on its way (otp 1.0.94): kept, not wiped by a redraw; the boxes are
       measured against what is saved now instead. */
    if (redraw !== false && !Object.keys(DIRTY).length) { drawSettings(); markDirtyCount(); }
    else {
      document.querySelectorAll('.set-item[data-key]').forEach(function (item) {
        var st = settingByKey(item.dataset.key);
        if (st && st.secret && JUST_SAVED[st.key] && !(st.key in DIRTY) && $('set-' + st.key)) $('set-' + st.key).value = '';
        if (st && $('set-' + st.key)) markDirty(item, st);
      });
    }
    JUST_SAVED = {};
    showPane(PANE || 'answer');
  }).catch(oops);
}
var JUST_SAVED = {};
function settingByKey(k) {
  if (k.indexOf('avahi:') === 0) {
    return (typeof AV !== 'undefined' && AV.d && typeof avahiSetting === 'function')
      ? (AV.d.keys || []).map(avahiSetting).filter(function (s) { return s.key === k; })[0] : null;
  }
  return ((SETTINGS && SETTINGS.settings) || []).filter(function (s) { return s.key === k; })[0];
}
function isBool(s) { return !!s.bool || typeof s.default === 'boolean'; }
function settingsPlace() {
  var pane = typeof PANE !== 'undefined' && PANE && $('pane-' + PANE);
  if (!pane || pane.hidden) return null;
  var act = document.activeElement, pick = act && pane.contains(act) ? act.closest('.set-item[data-key]') : null;
  if (!pick) {
    var all = pane.querySelectorAll('.set-item[data-key], [id$="-host"]');
    for (var i = 0; i < all.length && !pick; i++) {
      var r = all[i].getBoundingClientRect();
      if (r.height && r.bottom > 0 && r.top < window.innerHeight) pick = all[i];
    }
  }
  if (!pick) return null;
  return {sel: pick.dataset.key ? '.set-item[data-key="' + pick.dataset.key + '"]' : '#' + pick.id,
          top: pick.getBoundingClientRect().top, sc: scrollerOf(pick), pane: pane};
}
function settingsHold(place) {
  if (!place || !place.sc) return;
  var fix = function () {
    var n = place.pane.querySelector(place.sel);
    if (!n) return;
    var d = n.getBoundingClientRect().top - place.top;
    if (Math.abs(d) >= 1) place.sc.scrollTop += d;
  };
  fix();
  setTimeout(fix, 0);
  requestAnimationFrame(fix);
  setTimeout(fix, 150);
}
function drawSettings() {
  /* What is in view stays where it is (otp 1.0.280): every box is made again below. */
  var place = settingsPlace();
  paneLetGo();
  DRAWN_NODE = SETTINGS.node || '';
  Object.keys(SETTINGS.panes).forEach(function (pane) {
    var host = $('sect-' + pane);
    if (!host) return;
    clear(host);
    var grid = el('div', 'set-grid');
    SETTINGS.panes[pane].forEach(function (key) {
      var s = settingByKey(key);
      if (s) grid.appendChild(settingItem(s));
    });
    host.appendChild(grid);
  });
  if (SETTINGS.error) toast('config.json: ' + SETTINGS.error, 'bad');
  applyOnlyWhen();
  explainWhatWasDrawn($('tab-settings'));
  settingsHold(place);
}

/* What a setting does, in three lines at most (otp 1.0.156): a click opens the rest in place;
   the whole is on the name and its (i) as well. */
function saysClamped(words) {
  var box = saysBlock(words);
  box.classList.add('clamp');
  box.addEventListener('click', function () { box.classList.toggle('open'); });
  setTimeout(function () { if (box.scrollHeight > box.clientHeight + 2) box.classList.add('cut'); }, 0);
  return box;
}
/* Name, control, then the words, each in its own row of the grid, so every box on a row starts at
   the same height even where one name takes two lines (otp 1.0.20). */
function settingItem(s) {
  var item = settingItemBare(s);
  var tail = el('div', 'set-tail');
  Array.prototype.slice.call(item.children, 2).forEach(function (c) { tail.appendChild(c); });
  item.appendChild(tail);
  return item;
}
function settingItemBare(s) {
  var item = el('div', 'set-item' + (isBool(s) ? ' set-bool' : ''));
  item.dataset.key = s.key;
  var label = el('label', '', s.name || s.key);
  label.setAttribute('for', 'set-' + s.key);
  var info = el('span', 'iinfo', 'i');
  info.setAttribute('role', 'button');
  info.tabIndex = 0;
  var asText = function (v) { return richText(Array.isArray(v) ? v.join(', ') : String(v === null || v === undefined ? '' : v)); };
  var where = s.source;
  var running = s.secret ? (s.set ? 'set' : 'not set') : asText(isBool(s) ? (s.value === true || String(s.value) === '1' ? 'on' : 'off') : s.value);
  var story = '<span class="k">' + (s.cli ? 'on the command line this one is <b>' + richText(s.cli) + '</b> · ' : '')
    + 'running: ' + running
    + '<br><span class="' + (where === 'default' ? 'same' : 'diff') + '">' + richText(s.source_says || '') + '</span>'
    + (s.kept === 'database' ? '<br><span class="same">kept in fake-igd\'s database, saved on these pages</span>' : '')
    + (where !== 'default' && !s.secret && String(s.value) !== String(s.default)
       ? '<br><span class="same">the built-in default is ' + asText(isBool(s) ? (s.default ? 'on' : 'off') : s.default) + '</span>' : '')
    + (s.restarts ? '<br><span class="same">a change restarts fake-igd.service</span>' : '')
    + (s.root ? '<br><span class="same">root puts it in place (nginx, the firewall)</span>' : '') + '</span>';
  var whole = s.says || 'No words have been written for this one yet.';
  explain(info, whole, story);
  explain(label, whole, story);
  label.appendChild(info);
  if (label.firstChild && label.firstChild.nodeType === 3) {
    var txt = el('span', 'lbl-txt');
    txt.appendChild(label.firstChild);
    label.insertBefore(txt, label.firstChild);
  }
  item.appendChild(label);
  var input;
  if (isBool(s)) {
    input = switchBox(s.value === true || String(s.value) === '1');
    input._input.disabled = !ADMIN;
    input._input.addEventListener('change', function () { markDirty(item, s); });
    input.id = 'set-' + s.key;
    /* The name is a label for the checkbox itself, so a click on it flips the switch (otp 1.0.15). */
    input._input.id = 'set-' + s.key + '-sw';
    label.setAttribute('for', input._input.id);
    item.appendChild(input);
    if (s.says) item.appendChild(saysClamped(s.short || s.says));
    return item;
  }
  if (s.choices && s.choices.some(function (c) {
    return String((s.choice_words && s.choice_words[c]) || c).length > 30;
  })) item.classList.add('wide');
  if (s.choices) {
    input = selectBox(s.choices.map(function (c) { return [c, (s.choice_words && s.choice_words[c]) || c]; }), s.value);
  } else if (typeof s.min === 'number') {
    input = el('input');
    input.type = 'number';
    input.min = s.min;
    input.max = s.max;
    input.value = s.value;
  } else if (s.tall) {
    item.classList.add('tall');
    input = el('textarea');
    input.value = s.value === null || s.value === undefined ? '' : String(s.value);
    input.rows = 4;
  } else if (s.cell) {
    /* A PEM in a box of the grid, as otp's (its own cell, not a row of its own). */
    input = el('textarea', 'mono');
    input.value = s.value === null || s.value === undefined ? '' : String(s.value);
    input.rows = 1;
    input.placeholder = '-----BEGIN CERTIFICATE-----';
  } else {
    input = s.secret ? maskBox(s.value || '', '', '') : textBox(s.value === null || s.value === undefined ? '' : s.value, s.list ? 'comma separated; empty = none' : '', '');
    if (s.list || /url|file|dir|path/.test(s.key)) input.classList.add('mono');
    if (s.secret) {
      input.placeholder = s.set ? 'set - leave as it is to keep it' : 'not set';
      input.addEventListener('focus', function () { if (input.value.indexOf('•') === 0) input.select(); });
    }
  }
  input.id = 'set-' + s.key;
  input.disabled = !ADMIN;
  input.addEventListener('input', function () { markDirty(item, s); });
  input.addEventListener('change', function () { markDirty(item, s); });
  item.appendChild(input);
  if (s.says) item.appendChild(saysClamped(s.short || s.says));
  return item;
}
function readValue(s) {
  var input = $('set-' + s.key);
  if (!input) return undefined;
  if (input._get) return input._get();
  return input.value;
}
function markDirty(item, s) {
  /* Against what is saved now (otp 1.0.94), not what was when the box was drawn. */
  s = settingByKey(s.key) || s;
  var now = readValue(s);
  var was = isBool(s) ? (s.value === true || String(s.value) === '1')
    : (s.value === null || s.value === undefined ? '' : String(s.value));
  /* A secret as otp's: its dots kept are no change; emptied, it is taken away when saved. */
  var changed = isBool(s) ? !!now !== was : was !== String(now === null || now === undefined ? '' : now);
  item.classList.toggle('changed', changed);
  if (changed) DIRTY[s.key] = isBool(s) ? !!now : now; else delete DIRTY[s.key];
  markDirtyCount();
  applyOnlyWhen();
}
/* What a switch changes below it never shortens the pane while it is worked in (otp 1.0.278). */
function paneHeld(fn) {
  var pane = $('pane-' + PANE);
  var was = pane && !pane.hidden ? pane.getBoundingClientRect().height : 0;
  if (was) pane.style.minHeight = Math.ceil(was) + 'px';
  fn();
}
function paneLetGo() {
  document.querySelectorAll('[id^="pane-"]').forEach(function (p) { if (p.style.minHeight) p.style.minHeight = ''; });
}
/* Changes that are not settings (otp 1.0.56) - a list, a draft - wait for the same save bar:
   PENDING[key] = {save: function () -> Promise (false: not done), reset}. */
var PENDING = {};
function pendingSet(key, p) { p.pane = p.pane || PANE; PENDING[key] = p; markDirtyCount(); }
function pendingDrop(key) { delete PENDING[key]; markDirtyCount(); }
/* The one save bar, at the bottom (otp 1.0.123): on every pane where something is saved, and on
   no other. A pane that does something at once has its own buttons and no save bar. */
var SAVE_PANES = [];
function saveBarHere() {
  if (!ADMIN || TAB !== 'settings') return false;
  var pane = $('pane-' + PANE);
  if (!pane) return false;
  if (SAVE_PANES.indexOf(PANE) >= 0 || pane.querySelector('.set-item[data-key]')) return true;
  return Object.keys(PENDING).some(function (k) { return PENDING[k].pane === PANE; });
}
function markDirtyCount() {
  var n = Object.keys(DIRTY).length + Object.keys(PENDING).length;
  $('set-said').textContent = n ? n + ' change(s) not saved yet' : '';
  $('save-bar').classList.toggle('dirty', n > 0);
  $('save-bar').style.display = saveBarHere() ? '' : 'none';
}
/* A question as a promise: true for the button, false for anything else (otp's askThen). */
function askThen(title, words, buttonWords, danger) {
  return new Promise(function (done) {
    var said = false;
    var end = function (v) { if (!said) { said = true; done(v); } };
    confirmThen(title, words, buttonWords, function () { end(true); }, danger);
    var gen = MODAL_GEN;
    var watch = setInterval(function () {
      if (said) { clearInterval(watch); return; }
      if ($('modal').hidden || MODAL_GEN > gen + 1) { clearInterval(watch); setTimeout(function () { end(false); }, 50); }
    }, 300);
  });
}
function applyOnlyWhen() { paneHeld(applyOnlyWhenNow); }
function applyOnlyWhenNow() {
  var rules = (SETTINGS && SETTINGS.only_when) || {};
  /* Asleep when the one it depends on says so - and also when that one is asleep itself (otp
     1.0.165). The reason given is the first one up the line that is off. A value ending in -not:
     awake while the other is anything but that; *: awake once the other is filled in. */
  var seen = {};
  function valueOf(master) {
    var v = master._get ? master._get() : master.value;
    return v === true ? 'true' : (v === false ? 'false' : String(v === undefined || v === null ? '' : v));
  }
  function wake(key, depth) {
    if (seen[key]) return seen[key];
    var rule = rules[key];
    if (!rule || depth > 6) return (seen[key] = {live: true});
    var master = $('set-' + rule[0]);
    if (!master) return (seen[key] = {live: true});
    var up = wake(rule[0], depth + 1);
    if (!up.live) return (seen[key] = up);
    var now = valueOf(master);
    var want = String(rule[1]);
    /* A switch says 1/0 (wrap._get), a rule true/false (igd_panes: only_when (key, True)) - one word for both. */
    if (want === 'true' || want === 'false') now = (now === '1' || now === 'true') ? 'true' : (now === '0' || now === 'false' || now === '' ? 'false' : now);
    var live = want === '*' ? !!now.trim() : (want.slice(-4) === '-not' ? now !== want.slice(0, -4) : now === want);
    return (seen[key] = {live: live, by: rule[0], want: want, now: now});
  }
  Object.keys(rules).forEach(function (key) {
    var item = document.querySelector('.set-item[data-key="' + key + '"]');
    if (!item || !$('set-' + rules[key][0])) return;
    var w = wake(key, 0);
    item.classList.toggle('asleep', !w.live);
    var says = item.querySelector('.asleep-why');
    if (says) says.remove();
    if (!w.live) {
      var other = settingByKey(w.by) || {};
      (item.querySelector('.set-tail') || item).appendChild(el('div', 'says asleep-why', w.want === '*' ? 'Not in use until ' + other.name + ' is filled in.'
        : (isBool(other) ? 'Not in use while ' + other.name + ' is ' + (w.now === 'true' ? 'on' : 'off') + '.'
           : 'Not in use while ' + other.name + ' is “' + ((other.choice_words || {})[w.now] || w.now || 'empty') + '”.')));
    }
  });
}
$('set-save').onclick = function () {
  var own = {}, av = {};
  Object.keys(DIRTY).forEach(function (k) {
    var s = settingByKey(k);
    /* A secret's dots are not a change (otp 1.0.61). */
    if (s && s.secret && String(DIRTY[k]).indexOf('•') === 0) { delete DIRTY[k]; return; }
    if (k.indexOf('avahi:') === 0) av[k.slice(6)] = DIRTY[k]; else own[k] = DIRTY[k];
  });
  markDirtyCount();
  var keys = Object.keys(PENDING);
  if (!Object.keys(own).length && !Object.keys(av).length && !keys.length) { toast('nothing has changed'); return; }
  var restarts = Object.keys(own).some(function (k) { var s = settingByKey(k); return s && s.restarts; });
  var go = function () {
    busy($('set-save'), true);
    document.querySelectorAll('.set-item.refused').forEach(function (n) { n.classList.remove('refused'); });
    var sent = Object.assign({}, own, Object.keys(av).reduce(function (o, k) { o['avahi:' + k] = av[k]; return o; }, {}));
    var chain = Promise.resolve(true);
    if (Object.keys(own).length) chain = chain.then(function () {
      return api('settings', {changes: own}).then(function (d) {
        toast(d.message, 'good');
        if ((d.root || d.restart) && typeof loadRoot === 'function') setTimeout(loadRoot, 4000);
        return true;
      });
    });
    if (Object.keys(av).length) chain = chain.then(function (ok) {
      if (!ok) return ok;
      return api('mdns', {changes: av}).then(function (d) {
        toast(d.message, 'good');
        if (typeof avahiWait === 'function') avahiWait(d.id);
        return true;
      });
    });
    chain = chain.then(function (ok) {
      /* What was changed while the save was on its way stays changed (otp 1.0.61). */
      var left = {};
      Object.keys(DIRTY).forEach(function (k) { if (!(k in sent) || DIRTY[k] !== sent[k]) left[k] = DIRTY[k]; });
      Object.keys(sent).forEach(function (k) { JUST_SAVED[k] = 1; });
      DIRTY = left;
      markDirtyCount();
      loadSettings(Object.keys(left).length ? false : undefined);
      tick();
      return ok;
    }).catch(function (e) {
      var said = String(e.message || e);
      /* The setting the refusal names, marked and shown (otp 1.0.57). */
      var hit = (SETTINGS.settings || []).filter(function (one) {
        return said.indexOf(one.key) === 0 || said.indexOf(one.name + ':') === 0;
      }).sort(function (a, b) { return b.key.length - a.key.length; })[0];
      if (hit) {
        var item = document.querySelector('.set-item[data-key="' + hit.key + '"]');
        if (item) { item.classList.add('refused'); item.scrollIntoView({block: 'center'}); }
      }
      toast(said, 'bad');
      return false;
    });
    /* Then the rest, one after the other; the first that fails stops it. */
    keys.forEach(function (k) {
      chain = chain.then(function (ok) {
        if (ok === false || !PENDING[k]) return ok;
        var p = PENDING[k];
        return Promise.resolve(p.save()).then(function (r) {
          if (r === false) return false;
          if (PENDING[k] === p) delete PENDING[k];
          return true;
        }).catch(function (e) { oops(e); return false; });
      });
    });
    chain.then(function () { markDirtyCount(); busy($('set-save'), false); });
  };
  if (restarts && STATUS && STATUS.service && STATUS.service.state === 'active') {
    confirmThen('Save and restart?', 'A setting fake-igd.service uses is changed: it is restarted with it. '
      + 'For a few seconds nothing on the network is answered - the PS5 notices nothing more than that.', 'Save and restart', go, false);
  } else go();
};
$('set-reset').onclick = function () {
  Object.keys(PENDING).forEach(function (k) { try { PENDING[k].reset(); } catch (e) { /* drawn again anyway */ } });
  PENDING = {};
  /* The changed values forgotten too (otp 1.0.104). */
  DIRTY = {};
  document.querySelectorAll('.set-item.refused').forEach(function (n) { n.classList.remove('refused'); });
  markDirtyCount();
  loadSettings(); toast('put back as the API has them');
};
window.addEventListener('beforeunload', function (e) {
  if (Object.keys(DIRTY).length || Object.keys(PENDING).length) { e.preventDefault(); e.returnValue = ''; }
});

/* An account made with a password somebody else chose must set its own before anything (otp
   1.0.103): the form opens by itself instead of a page of dashes and refusals. */
function mustChange() {
  if (!ME || !ME.must_change) return;
  modal('Choose your own password first', function (body) {
    body.appendChild(el('p', '', 'This account was given a password by somebody else. Before anything '
      + 'else, choose one only you know - every page waits for it.'));
    var old = maskBox('', '', '');
    var nw = maskBox('', '', '');
    var nw2 = maskBox('', '', '');
    var g = el('div', 'formgrid');
    g.appendChild(formField('The one you were given', old));
    g.appendChild(formField('The new one', nw));
    g.appendChild(formField('The new one again', nw2));
    body.appendChild(g);
    var go = cmdButton('Change the password', 'lock', 'primary');
    go.id = 'mc-go';
    var row = el('div', 'me-acts');
    row.style.marginTop = '14px';
    go.onclick = function () {
      if (nw.value !== nw2.value) { toast('the two new ones are not the same', 'bad'); return; }
      busy(go, true);
      api('password', {old: old.value, 'new': nw.value}).then(function (d) {
        toast(d.message, 'good');
        ME.must_change = false;
        setTimeout(function () { location.reload(); }, 600);
      }).catch(function (e) { busy(go, false); toast(String(e && e.message || e), 'bad'); });
    };
    row.appendChild(go);
    var out = cmdButton('Sign out', 'out', '');
    out.onclick = function () { api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); }); };
    row.appendChild(out);
    body.appendChild(row);
  }, null, 'medium');
}
setTimeout(mustChange, 300);

/* ---- starting: once every pane-*.js is read ------------------------------ */
document.addEventListener('DOMContentLoaded', function start() {
  var h = (location.hash || '#overview').slice(1).split('/');
  if (h[0] === 'settings' && h[1]) PANE = h[1];
  if (STATUS) paintHeader(STATUS);
  showTab(h[0] || 'overview');
  setInterval(tick, 5000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) tick(); });
  explainWhatWasDrawn(document);
  /* A link to #settings/web, or Back: the page follows the address. */
  window.addEventListener('hashchange', function () {
    var g = (location.hash || '#overview').slice(1).split('/');
    if (TABS.indexOf(g[0]) < 0) return;
    if (g[0] === 'settings' && g[1] && g[1] !== PANE && TAB === 'settings') { showPane(g[1]); return; }
    if (g[1]) PANE = g[1];
    if (g[0] !== TAB) showTab(g[0]);
  });
});
