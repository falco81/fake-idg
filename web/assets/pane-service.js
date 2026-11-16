/* pane-service.js - Settings → The service (1.6.1): fake-igd's units, in the look and manner of
   otp's nodes (Upgrades and maintenance, High availability): a row a unit with its state, since
   when, restarts, memory; its journal in a peek; Restart / Stop / Start asked of root - twice
   where it hurts; what root did as otp's bands (To be done by hand) and Done lately. Live: every
   5 s while it is shown. */
'use strict';

var SVC = {d: null, wait: null, tries: 0};
var SVC_ACT = {restart: ['Restart', 'refresh'], stop: ['Stop', 'power'], start: ['Start', 'play'], reload: ['Reload', 'refresh']};
/* What each one does to the people using it - asked twice where it hurts. */
var SVC_ASK = {
  'fake-igd.service': {
    restart: ['Restart fake-igd.service?', 'For a few seconds nothing on the network is answered - a PS5 asking just then tries again.'],
    stop: ['Stop fake-igd.service?', 'Nothing on the network is answered until it is started again: no SSDP, no description, no SOAP. These pages stay.']},
  'fake-igd-api.service': {
    restart: ['Restart the pages\' API?', 'These pages do not answer for a few seconds and come back by themselves; you stay signed in.']},
  'nginx.service': {
    restart: ['Restart nginx?', 'These pages are away for a moment and come back by themselves. nginx -t is asked first: a configuration that does not read is said, and nginx is left running.']},
  'php-fpm.service': {
    restart: ['Restart php-fpm?', 'These pages are away for a moment and come back by themselves. php-fpm -t is asked first.']},
  'avahi-daemon.service': {
    stop: ['Stop avahi-daemon?', 'mDNS is no longer answered nor reflected between the networks until it is started again.']}
};
var SVC_STATE = {active: 'ok', reloading: 'info', activating: 'info', deactivating: 'warn', inactive: 'dim', failed: 'crit'};

function loadService(live) {
  apiLatest('service', 'service').then(function (d) {
    if (live) liveRun(function () { drawService(d, true); }); else drawService(d, false);
  }).catch(function (e) { if (!live) oops(e); });
}
function drawService(d, live) {
  SVC.d = d;
  var units = d.units || [];
  var up = units.filter(function (u) { return u.state === 'active'; }).length;
  $('sv-said').textContent = num(up) + ' of ' + num(units.length) + ' running' + (d.waiting ? ' · ' + num(d.waiting) + ' asked of root' : '');
  /* Reload has its column only while a unit can be reloaded now (nginx running): an empty column of
     every row would only push the others apart. */
  var reloads = ADMIN && units.some(function (u) { return (u.can || []).indexOf('reload') >= 0 && u.state === 'active'; });
  var heads = ['Unit', 'State', 'Since', 'At boot', {words: 'Restarts', cls: 'num'}, {words: 'Memory', cls: 'num'}, '', '', ''];
  if (reloads) heads.push('');
  liveFill($('sv-units'), function (host) {
    if (d.error) host.appendChild(el('p', 'note bad', 'systemctl could not be asked: ' + d.error));
    host.appendChild(listTable(heads, units, function (u) {
      var tr = el('tr', 'clickable');
      var nm = el('td');
      nm.appendChild(noI18n(el('b', '', u.unit)));
      if (u.unit === 'fake-igd-api.service') { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'these pages')); }
      nm.appendChild(el('span', 'sub', u.what));
      tr.appendChild(nm);
      var st = el('td');
      var tone = u.state === 'not installed' ? 'dim' : (SVC_STATE[u.state] || 'warn');
      st.appendChild(el('span', 'tag ' + tone, u.state === 'active' ? (u.sub === 'running' || !u.sub ? 'running' : u.sub) : u.state));
      if (u.state !== 'active' && u.sub && u.sub !== u.state && u.sub !== 'dead') st.appendChild(el('span', 'sub', u.sub));
      if (u.state === 'failed' && u.result) st.appendChild(el('span', 'sub', 'result: ' + u.result));
      if (u.triggers) {
        var t = u.triggers;
        st.appendChild(el('span', 'sub', t.ran ? t.unit + ' ran ' + ago(t.ran) + (t.result && t.result !== 'success' ? ' - ' + t.result : '') : t.unit + ' has not run since boot'));
      }
      tr.appendChild(st);
      var since = el('td', 'muted sv-nw', u.since ? ago(u.since) : '–');
      if (u.since) explain(since, (u.state === 'active' ? 'Running since ' : 'Not running since ') + stamp(u.since) + '.');
      tr.appendChild(since);
      var bt = el('td');
      var bw = u.boot || '';
      if (!bw) { bt.className = 'muted'; bt.textContent = '–'; }
      else bt.appendChild(el('span', 'tag ' + (bw === 'enabled' ? 'ok' : (bw === 'disabled' || bw === 'masked' ? 'warn' : 'dim')), bw));
      tr.appendChild(bt);
      var rs = el('td', 'num' + (u.restarts ? ' warn' : ''), u.restarts === null || u.restarts === undefined ? '–' : num(u.restarts));
      if (u.restarts) explain(rs, 'systemd restarted it by itself ' + num(u.restarts) + ' time(s) since it was last started by hand or at boot: it stopped or broke. Its journal says why.');
      tr.appendChild(rs);
      tr.appendChild(el('td', 'num', u.memory ? bytes(u.memory) : '–'));
      /* The buttons stand in columns by their kind - the journal, Reload, Restart, Stop or Start - each in
         its own cell, empty where a unit has none: one under the other down the table, as otp's rows. */
      var cell = function (b) { var td = el('td', 'rowtools'); if (b) td.appendChild(b); tr.appendChild(td); };
      var lg = iconButton('log', 'Its journal - the last lines');
      lg.onclick = function (ev) { ev.stopPropagation(); svcJournal(u); };
      cell(lg);
      var can = ADMIN ? (u.can || []) : [];
      var on = u.state === 'active' || u.state === 'activating';
      var mk = function (a) {
        var b = cmdButton(SVC_ACT[a][0], SVC_ACT[a][1], 'small' + (a === 'stop' ? ' danger' : ''));
        b.onclick = function (ev) { ev.stopPropagation(); svcAsk(u, a, b); };
        return b;
      };
      if (reloads) cell(can.indexOf('reload') >= 0 && u.state === 'active' ? mk('reload') : null);
      cell(can.indexOf('restart') >= 0 ? mk('restart') : null);
      cell(on && can.indexOf('stop') >= 0 ? mk('stop') : (!on && can.indexOf('start') >= 0 ? mk('start') : null));
      tr.onclick = function () { svcPeek(u); };
      return tr;
    }, 'plain'));
  }, !!live);
  drawSvcRoot(d, !!live);
  explainWhatWasDrawn($('pane-service'));
}
function svcAsk(u, a, btn) {
  var go = function () {
    busy(btn, true);
    api('service', {action: a, unit: u.unit}).then(function (r) {
      toast(r.message, 'good');
      svcWait(r.id);
      loadService();
    }).catch(oops).then(function () { busy(btn, false); });
  };
  var ask = (SVC_ASK[u.unit] || {})[a];
  if (ask) confirmThen(ask[0], ask[1], SVC_ACT[a][0], go, a === 'stop' ? undefined : false);
  else go();
}
/* Root's answer, looked for every 1.5 s for a minute: said when it comes. */
function svcWait(id) {
  clearTimeout(SVC.wait);
  SVC.tries = 0;
  var again = function () {
    api('service').then(function (d) {
      var hit = (d.lately || []).filter(function (x) { return x.id === id; })[0];
      if (hit && hit.state !== 'asked') {
        (hit.said || []).forEach(function (x) { toast(x, hit.state === 'done' ? 'good' : 'bad'); });
        if (PANE === 'service' && TAB === 'settings') drawService(d, false);
        if (PANE === 'about' && TAB === 'settings' && hit.do === 'console') drawAbout();
        return;
      }
      if (++SVC.tries < 40) SVC.wait = setTimeout(again, 1500);
      else toast('root has not answered yet - is fake-igd-web.path running?', 'bad');
    }).catch(function () { if (++SVC.tries < 40) SVC.wait = setTimeout(again, 3000); });
  };
  SVC.wait = setTimeout(again, 1200);
}
function svcFacts(u) {
  return peekFacts([['State', u.state + (u.sub ? ' (' + u.sub + ')' : '')],
                    ['Since', u.since ? stamp(u.since) : '–'], ['PID', u.pid || '–'],
                    ['Restarts', u.restarts === null || u.restarts === undefined ? '–' : num(u.restarts)],
                    ['Memory', u.memory ? bytes(u.memory) : '–'], ['Tasks', u.tasks === null || u.tasks === undefined ? '–' : num(u.tasks)],
                    ['CPU time', u.cpu_s ? span(Math.round(u.cpu_s)) : '–'], ['At boot', u.boot || '–'],
                    u.file ? ['The unit file', u.file] : null]);
}
function svcPeek(u) {
  peek(u.unit, function () { return api('service-journal&unit=' + encodeURIComponent(u.unit) + '&lines=60'); }, function (body, x) {
    body.appendChild(el('p', 'note', u.what + (u.description ? ' - ' + u.description : '') + '.'));
    body.appendChild(svcFacts(u));
    body.appendChild(el('h3', 'peek-h', 'Its journal - the last lines'));
    var pre = noI18n(el('pre', 'lines', (x.lines || []).join('\n') || '(nothing)'));
    body.appendChild(pre);
    setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
    body.appendChild(noI18n(el('p', 'muted small', 'On the server: journalctl ' + x.units.map(function (n) { return '-u ' + n; }).join(' ') + ' -n 200')));
  });
}
function svcJournal(u) {
  peek(u.unit + ' - its journal', function () { return api('service-journal&unit=' + encodeURIComponent(u.unit) + '&lines=400'); }, function (body, x) {
    var pre = noI18n(el('pre', 'lines', (x.lines || []).join('\n') || '(nothing)'));
    body.appendChild(pre);
    setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
  });
  var box = $('modal-box');
  if (box) box.className = 'box large';
}

/* What root did (otp's afterBand and Done lately, 1.0.258): a band an answer not yet marked done -
   its level's colour on the left, what root said, Done; under it the last forty. */
function svcBand(it) {
  var lvl = it.state === 'failed' ? 'bad' : (it.state === 'done' ? 'info' : 'warn');
  var band = el('div', 'after-band ' + lvl);
  band.dataset.id = it.id;
  var ic = el('div', 'after-ic');
  ic.innerHTML = iconMarkup(lvl === 'bad' ? 'close' : (lvl === 'info' ? 'check' : 'clock'));
  band.appendChild(ic);
  var body = el('div', 'after-body');
  var head = el('div', 'after-title');
  head.appendChild(noI18n(el('b', '', it.title)));
  head.appendChild(el('span', 'tag ' + ({failed: 'crit', done: 'ok', asked: 'warn'}[it.state] || 'dim'), it.how));
  body.appendChild(head);
  if (it.state === 'asked') body.appendChild(el('div', 'after-why', 'Asked of root - its answer comes within seconds.'));
  (it.said || []).forEach(function (s) { body.appendChild(noI18n(el('div', 'after-why', s))); });
  if (it.now) body.appendChild(el('div', 'after-lead', 'Now: ' + it.now));
  body.appendChild(el('div', 'after-seen', 'Asked by ' + (it.who || '?') + ' ' + stamp(it.at) + (it.done_at ? ' · answered ' + ago(it.done_at) : '')));
  band.appendChild(body);
  var tools = el('div', 'after-btns');
  if (it.unit) {
    var lg = cmdButton('Its journal', 'log', 'small');
    lg.onclick = function () { svcJournal({unit: it.unit}); };
    tools.appendChild(lg);
  }
  if (it.state !== 'asked') {
    var done = cmdButton('Done', 'check', 'small' + (it.state === 'failed' ? ' primary' : ''));
    done.onclick = function () {
      busy(done, true);
      api('service', {action: 'done', id: it.id}).then(function (d) { drawService(d, false); }).catch(oops)
        .then(function () { busy(done, false); });
    };
    tools.appendChild(done);
  }
  band.appendChild(tools);
  return band;
}
function drawSvcRoot(d, live) {
  var card = $('sv-root-card');
  if (!card || !ADMIN) return;
  var items = d.bands || [];
  var worst = items.some(function (x) { return x.state === 'failed'; }) ? 'bad' : (items.some(function (x) { return x.state === 'asked'; }) ? 'warn' : '');
  card.classList.add('after-card');
  card.classList.remove('bad', 'warn', 'info');
  if (worst) card.classList.add(worst);
  $('sv-root-said').textContent = d.waiting ? num(d.waiting) + ' waiting in the queue' : '';
  liveFill($('sv-bands'), function (host) {
    if (!items.length) { host.appendChild(el('p', 'note good after-none', 'Nothing root was asked is waiting to be looked at.')); return; }
    items.forEach(function (it) { host.appendChild(svcBand(it)); });
  }, live);
  liveFill($('sv-lately'), function (box) {
    var rows = d.lately || [];
    if (!rows.length) return;
    var head = el('div', 'after-lately-head');
    head.appendChild(el('h3', 'after-lately-h', 'Done lately'));
    var clr = cmdButton('Clear', 'trash', 'small after-lately-clear');
    clr.type = 'button';
    clr.title = 'Empty this list - what root has not answered yet stays';
    clr.onclick = function () {
      confirmThen('Clear the list?', 'What root did with the units is taken off this list; the events keep it.', 'Clear', function () {
        api('service', {action: 'clear'}).then(function (x) { toast(x.message, 'good'); drawService(x, false); }).catch(oops);
      });
    };
    head.appendChild(clr);
    box.appendChild(head);
    var tw = el('div', 'after-lately-w');
    tw.appendChild(listTable(['What', 'How', 'Who', 'When'], rows, function (x) {
      var tr = el('tr', 'clickable');
      tr.appendChild(noI18n(el('td', '', x.title)));
      tr.appendChild(el('td', 'after-how ' + ({done: 'done', failed: 'taken-back'}[x.state] || ''), x.how || ''));
      tr.appendChild(x.who ? noI18n(el('td', '', x.who)) : el('td', 'muted', '–'));
      tr.appendChild(stampCell(x.at));
      tr.onclick = function () {
        modal(x.title, function (body) {
          body.appendChild(peekFacts([['How', x.how], ['Who', x.who || '–'], ['Asked', stamp(x.at)], ['Answered', x.done_at ? stamp(x.done_at) : '–'], x.now ? ['Then', x.now] : null]));
          (x.said || []).forEach(function (s) { body.appendChild(noI18n(el('p', 'note ' + (x.state === 'failed' ? 'bad' : ''), s))); });
        }, null, 'medium');
      };
      return tr;
    }, 'rows after-lately-t'));
    box.appendChild(tw);
  }, live);
}

$('sv-apply').onclick = function () {
  var b = $('sv-apply');
  busy(b, true);
  api('apply', {}).then(function () { toast('asked root - a moment', 'good'); setTimeout(function () { if (typeof loadRoot === 'function') loadRoot(); }, 4000); })
    .catch(oops).then(function () { busy(b, false); });
};

PANE_LOAD.service = function () { loadService(false); };
PANE_TICK.service = function () { if (!document.hidden && !apiLatestOut('service')) loadService(true); };
