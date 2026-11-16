/* admin.js - the web pages of fake-igd, drawn the way otp draws its administration
   (and otp the way isemon draws its dashboard): the same header, tabs, rail, popups
   and panels (core.js), over fake-igd-api. The page works nothing out for itself. */
'use strict';

/* The time pickers (otp's), in place of the <select>s they replace. */
timePicker('ov-hours', {start: {k: 'rel', s: 86400}});
timePicker('rq-hours', {start: {k: 'rel', s: 86400}});
timePicker('pt-hours', {start: {k: 'all'}, all: true});
timePicker('cl-hours', {start: {k: 'all'}, all: true});
timePicker('ev-time', {start: {k: 'all'}, all: true});

ADMIN = !!(ME && ME.role === 'fulladmin');
var LIVE = true, SERIAL = STATUS ? STATUS.serial : '', PANE = 'answer';
var SETTINGS = null, DIRTY = {}, PENDING = {};
var PAGE = {requests: 0, events: 0};
var RAIL = {pinned: false, open: null, shut: null};
/* The panes of Settings (1.6.0): each its own pane-NAME.js says how it is drawn -
   PANE_LOAD.NAME() when it is shown, PANE_TICK.NAME() with every live update while it is. */
var PANE_LOAD = window.PANE_LOAD || {}, PANE_TICK = window.PANE_TICK || {};
window.PANE_LOAD = PANE_LOAD; window.PANE_TICK = PANE_TICK;

function roleWords(role) { return role === 'fulladmin' ? 'full admin' : 'read only'; }
function roleTone(role) { return role === 'fulladmin' ? 'violet' : 'dim'; }

/* ---- what this account may not even see ---------------------------------- */
(function roles() {
  document.querySelectorAll('.admin-only, .fulladmin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  if (!ADMIN) { $('readonly-note').hidden = false; $('save-bar').hidden = true; }
}());
dressButtons(document);

/* ---- tabs ------------------------------------------------------------------ */
var TABS = ['overview', 'ports', 'requests', 'clients', 'mappings', 'mdns', 'log', 'events', 'settings'];
window.optShowTab = function (name) {
  if (TABS.indexOf(name) < 0) name = 'overview';
  TAB = name;
  document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
    b.setAttribute('aria-selected', b.getAttribute('data-tab') === name ? 'true' : 'false');
  });
  TABS.forEach(function (one) { $('tab-' + one).hidden = one !== name; });
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
  if (name === 'mdns') loadMdnsTab();
  if (name === 'log') loadLog(true);
  if (name === 'events') loadEvents();
  if (name === 'settings') loadSettings(!Object.keys(DIRTY).length);
}

/* ---- the header and the live updates -------------------------------------- */
function paintHeader(s) {
  STATUS = s;
  var hs = document.querySelector('header .host');
  if (hs && s.node) {
    if (hs._base === undefined) hs._base = hs.textContent;
    hs.textContent = hs._base + ' · ' + s.node;
    hs.title = 'this page is answered by ' + s.node + ' · fake-igd ' + (s.version || '');
  }
  var pill = $('state-pill');
  var running = s.service && s.service.state === 'active';
  var passive = s.mode === 'passive';
  var kind = !running ? 'crit' : ((s.problems && s.problems.length) || passive ? 'warn' : 'ok');
  pill.className = 'pill ' + kind;
  pill.lastChild.textContent = !running ? 'not running' : (passive ? 'listening only (passive)'
    : (kind === 'warn' ? 'answering, with trouble' : 'answering'));
  pill.title = running ? 'fake-igd.service is running: mode ' + s.mode + ', AddPortMapping ' + s.mapping_response
    : 'fake-igd.service is ' + (s.service ? s.service.state : 'unknown') + '.';
  explainWhatWasDrawn(pill.parentNode);
  var pr = $('problems');
  clear(pr);
  (s.problems || []).forEach(function (p, i) {
    if (i) pr.appendChild(el('br'));
    pr.appendChild(document.createTextNode(p));
  });
  pr.hidden = !(s.problems && s.problems.length);
  $('updated-at').textContent = clockWords(new Date());
  var st = s.stats || {};
  $('tabn-ports').textContent = st.ports ? num(st.ports) : '';
  $('tabn-requests').textContent = st.requests ? num(st.requests) : '';
  $('tabn-clients').textContent = st.clients ? num(st.clients) : '';
  $('tabn-mappings').textContent = st.mappings ? num(st.mappings) : '';
  var up = s.upgrade || {};
  $('up-badge').textContent = up.busy ? '…' : (up.newer ? '1' : '');
}

var REDRAW_OWED = false, TICK_OUT = 0;
function tick() {
  if (!LIVE || document.hidden) return;
  if (TICK_OUT && Date.now() - TICK_OUT < 60000) return;
  TICK_OUT = Date.now();
  api('status').then(function (s) {
    $('offline').hidden = true;
    var moved = s.serial !== SERIAL || REDRAW_OWED;
    SERIAL = s.serial;
    paintHeader(s);
    var here = $('tab-' + TAB);
    var lists = ['overview', 'ports', 'requests', 'clients', 'mappings', 'events'];
    if (moved && lists.indexOf(TAB) >= 0) {
      if (!document.querySelector('.modal:not([hidden])') && !userHolds(here) && !pointerBusy(here)
          && !(TAB === 'requests' && PAGE.requests > 0) && !(TAB === 'events' && PAGE.events > 0)) {
        REDRAW_OWED = false;
        onTab(TAB);
      } else {
        REDRAW_OWED = true;
      }
    }
    if (TAB === 'overview') paintCards();
    if (TAB === 'log' && moved) loadLog(false);
    if (TAB === 'settings' && PANE === 'upgrade') loadUpgrade();
    if (TAB === 'settings' && typeof PANE_TICK[PANE] === 'function') {
      try { PANE_TICK[PANE](s); } catch (e) { /* the next tick */ }
    }
  }).catch(function (e) {
    if (e && e.busy) return;
    var o = $('offline');
    o.hidden = false;
    o.textContent = 'The API is not answering: ' + (e.message || e);
  }).then(function () { TICK_OUT = 0; });
}
$('updated').onclick = function () {
  LIVE = !LIVE;
  $('updated').classList.toggle('paused', !LIVE);
  $('updated').querySelector('b').textContent = LIVE ? 'live' : 'paused';
  if (LIVE) tick();
};
$('signout').onclick = function () {
  api('logout', {}).then(function () { location.reload(); }).catch(function () { location.reload(); });
};

/* ---- my account ------------------------------------------------------------ */
$('me-btn').onclick = function () {
  modal('Your account', function (body) {
    body.appendChild(peekFacts([['Name', ME.name], ['Role', roleWords(ME.role)], ['Note', ME.note || '–']]));
    body.appendChild(el('h4', '', 'A new password'));
    var old = maskBox('', 'the password now', 'mono'), a = maskBox('', 'at least 8 characters', 'mono'),
        b = maskBox('', 'the same again', 'mono');
    old.id = 'pw-old'; a.id = 'pw-new'; b.id = 'pw-again';
    body.appendChild(formField('The password now', old));
    body.appendChild(formField('The new one', a));
    body.appendChild(formField('Again', b));
    body.appendChild(el('div', 'said', '')).id = 'pw-said';
  }, [{words: 'Close', close: true},
      {words: 'Change the password', cls: 'primary', icon: 'key', go: function (button) {
        var said = $('pw-said');
        if ($('pw-new').value !== $('pw-again').value) { said.className = 'said bad'; said.textContent = 'those two are not the same'; return; }
        busy(button, true);
        api('password', {old: $('pw-old').value, 'new': $('pw-new').value}).then(function (d) {
          toast(d.message || 'changed', 'good');
          closeModal();
        }).catch(function (e) { said.className = 'said bad'; said.textContent = e.message; })
          .then(function () { busy(button, false); });
      }}], true);
};

/* ==========================================================================
   Overview
   ========================================================================== */
function setCard(id, value, sub, tone) {
  $('m-' + id).textContent = value;
  $('m-' + id + '-sub').textContent = sub || ' ';
  if (tone) $('card-' + id).className = 'card metric ' + tone;
}
function paintCards() {
  var s = STATUS;
  if (!s) return;
  var sv = s.service || {}, st = s.stats || {};
  setCard('service', sv.state === 'active' ? 'running' : (sv.state || '?'),
          sv.state === 'active' ? 'since ' + (sv.since || '?') + ' · restarts ' + (sv.restarts || 0)
                                : 'sudo upnp start · Settings → The service', sv.state === 'active' ? 'ok' : 'crit');
  setCard('mode', s.mode + ' · ' + s.mapping_response,
          (s.mode === 'active' ? 'answers like a UPnP router' : 'only listens and logs') + ' · public IP '
          + (s.public_ip || s.external_ip || '?'), s.mode === 'active' ? 'info' : 'warn');
  setCard('ports', num(st.ports || 0), num(st.add || 0) + ' AddPortMapping of ' + num(st.requests || 0) + ' requests', 'ok');
  setCard('clients', num(st.clients || 0), st.last ? 'the last request ' + ago(Date.parse(st.last) / 1000) : 'nothing asked yet', 'info');
  var ifs = Object.keys(s.interfaces || {});
  setCard('ifaces', num(ifs.length), ifs.map(function (n) { return n + ' ' + s.interfaces[n]; }).join(' · ') || 'none in the log since the start',
          ifs.length ? 'info' : 'warn');
  setCard('maps', num(st.mappings || 0), 'what the clients believe is open · port ' + s.http_port, 'info');
  var m = s.mdns;
  setCard('mdns', !m ? 'none' : (m.reflector ? 'on' : 'off'), !m ? 'avahi-daemon is not installed here'
          : 'avahi-daemon ' + m.state, !m ? 'info' : (m.state === 'active' ? 'ok' : 'warn'));
  var up = s.upgrade || {};
  setCard('upgrade', up.busy ? 'going on' : (up.newer ? up.newest : s.version),
          up.busy ? 'fake-igd ' + (up.version || '') + ' is being put in' : (up.newer ? 'is out - this server runs ' + s.version
          : 'the newest there is'), up.busy ? 'warn' : (up.newer ? 'warn' : 'ok'));
}
function cardGo(id, go) {
  var c = $('card-' + id);
  c.classList.add('tappable');
  c.onclick = go;
}
cardGo('service', function () { PANE = 'service'; showTab('settings'); });
cardGo('mode', function () { PANE = 'answer'; showTab('settings'); });
cardGo('ports', function () { showTab('ports'); });
cardGo('clients', function () { showTab('clients'); });
cardGo('maps', function () { showTab('mappings'); });
cardGo('ifaces', function () { PANE = 'network'; showTab('settings'); });
cardGo('upgrade', function () { PANE = 'upgrade'; showTab('settings'); });
cardGo('mdns', function () { showTab('mdns'); });

function loadOverview() {
  paintCards();
  apiLatest('overview', 'overview' + tpQuery('ov-hours', 'since', 'until')).then(function (d) {
    var hours = d.hours;
    drawChart(d, hours);
    facet('ov-ports', d.ports.map(function (r) { return {said: r.port, n: r.n}; }), 'good',
          function (r) { $('pt-q').value = r.said.split('/')[0]; showTab('ports'); });
    facet('ov-clients', d.clients.map(function (r) { return {said: r.client + (r.name ? '  ' + r.name : ''), n: r.n, ip: r.client}; }), 'good',
          function (r) { $('rq-q').value = r.ip; showTab('requests'); });
    facet('ov-actions', d.actions.map(function (r) { return {said: r.action, n: r.n}; }), 'good',
          function (r) { $('rq-action').value = r.said; showTab('requests'); });
    var s = STATUS || {}, host = $('ov-ifaces');
    clear(host);
    var ifs = Object.keys(s.interfaces || {});
    if (!ifs.length) host.appendChild(el('p', 'muted small', 'No interface in the log since the last start.'));
    ifs.forEach(function (n) {
      var row = el('div', 'fct');
      row.appendChild(noI18n(el('div', 'fct-said', n + '  ' + s.interfaces[n])));
      row.appendChild(noI18n(el('div', 'muted small mono', 'http://' + s.interfaces[n] + ':' + s.http_port + '/rootDesc.xml')));
      host.appendChild(row);
    });
    host.appendChild(el('p', 'muted small', num(d.searches) + ' SSDP search(es) for a UPnP router in this window'));
    explainWhatWasDrawn($('tab-overview'));
  }).catch(oops);
}
$('ov-hours').onchange = loadOverview;

function facet(id, rows, tone, go) {
  var host = typeof id === 'string' ? $(id) : id;
  clear(host);
  if (!rows || !rows.length) { host.appendChild(el('p', 'muted small', 'Nothing in this window.')); return; }
  var top = rows[0].n || 1;
  var list = el('div', 'facetlist');
  rows.forEach(function (r) {
    var row = el('div', 'fct tappable');
    row.appendChild(noI18n(el('div', 'fct-said', r.said || '–')));
    var line = el('div', 'fct-line');
    var bb = el('div', 'bar' + (tone === 'good' ? ' good' : ''));
    var fill = el('span');
    fill.style.width = Math.max(3, Math.round(100 * r.n / top)) + '%';
    bb.appendChild(fill);
    line.appendChild(bb);
    line.appendChild(el('span', 'fct-n', num(r.n)));
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
  var series = d.chart || [];
  if (!series.some(function (p) { return p.accepted || p.rejected || p.other; })) {
    host.appendChild(el('div', 'empty', 'Nothing has been asked in this window'));
    return;
  }
  var W = host.clientWidth || 700, H = host.clientHeight || 230;
  var padL = 44, padR = 12, padT = 12, padB = 26;
  var w, h = Math.max(10, H - padT - padB);
  var top = Math.max(1, series.reduce(function (m, p) { return Math.max(m, p.accepted, p.rejected, p.other); }, 0));
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
    var dd = new Date(p.at * 1000);
    var t = make('text', {x: padL + step * i + step / 2, y: H - 8, fill: '#5b6472', 'font-size': 11, 'text-anchor': 'middle'});
    t.textContent = hours > 48 ? pad2(dd.getDate()) + '-' + pad2(dd.getMonth() + 1) : clockWords(dd, false);
    svg.appendChild(t);
  });
  series.forEach(function (p, i) {
    var hit = make('rect', {x: padL + step * i, y: padT, width: step, height: h, fill: 'transparent'});
    hit.addEventListener('mousemove', function (e) {
      var box = host.getBoundingClientRect();
      tip.innerHTML = '<b>' + stamp(p.at) + '</b><br>'
        + (p.accepted ? '<span style="color:#3fb950">' + num(p.accepted) + ' port(s) asked for</span><br>' : '')
        + (p.rejected ? '<span style="color:#f85149">' + num(p.rejected) + ' refused</span><br>' : '')
        + (p.other ? '<span style="color:#58a6ff">' + num(p.other) + ' other question(s)</span><br>' : '')
        + (p.accepted || p.rejected || p.other ? '' : '<span style="color:#8b949e">nothing</span>');
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
   Ports, requests, clients, mappings
   ========================================================================== */
function addrCell(ip, name) {
  var td = el('td', 'mono');
  td.appendChild(noI18n(el('span', '', ip || '–')));
  if (name) { td.appendChild(el('br')); td.appendChild(noI18n(el('span', 'muted small', name))); }
  return td;
}
function protoTag(p) { return noI18n(el('span', 'tag ' + (String(p).toUpperCase() === 'UDP' ? 'violet' : 'info'), String(p || '?').toUpperCase())); }
function matches(row, q) { return !q || JSON.stringify(row).toLowerCase().indexOf(q.toLowerCase()) >= 0; }

function loadPorts() {
  apiLatest('ports', 'ports&proto=' + $('pt-proto').value + tpQuery('pt-hours', 'since', 'until')).then(function (d) {
    var q = $('pt-q').value.trim();
    var rows = d.ports.filter(function (r) { return matches(r, q); });
    $('pt-said').textContent = num(rows.length) + ' port(s)';
    var host = $('pt-table');
    clear(host);
    host.appendChild(listTable(['Client', 'Protocol', {words: 'Port', cls: 'num'}, {words: 'Asked', cls: 'num'},
                                'First', 'Last', 'Answered', 'Description'], rows, function (r) {
      var tr = el('tr', 'tappable');
      tr.appendChild(addrCell(r.client, r.name));
      var tp = el('td'); tp.appendChild(protoTag(r.proto)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'num mono', r.port + (r.internal_port && String(r.internal_port) !== String(r.port) ? ' → ' + r.internal_port : ''))));
      tr.appendChild(el('td', 'num', num(r.count)));
      tr.appendChild(stampCell(r.first));
      tr.appendChild(stampCell(r.last));
      var res = el('td');
      Object.keys(r.results || {}).forEach(function (k) {
        res.appendChild(el('span', 'tag ' + (/^rej|^err|^fail|^conf/.test(k) ? 'crit' : 'ok'), k + (r.results[k] > 1 ? ' ×' + r.results[k] : '')));
        res.appendChild(document.createTextNode(' '));
      });
      tr.appendChild(res);
      tr.appendChild(noI18n(el('td', '', r.description || '')));
      tr.onclick = function () { $('rq-q').value = String(r.port); showTab('requests'); };
      return tr;
    }, 'plain|No port has been asked for in this window', {own: true}));
    explainWhatWasDrawn(host);
  }).catch(oops);
}
['pt-hours', 'pt-proto'].forEach(function (id) { $(id).onchange = loadPorts; });
$('pt-q').addEventListener('input', debounce(loadPorts, 250));
$('dn-open').onclick = function () {
  modal('Rules for the router (DNAT)', function (body) {
    body.appendChild(el('p', 'note', 'Port forwarding rules made from the requested ports - the same as upnp dnat.'));
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

function loadRequests() {
  var per = Number($('rq-per').value);
  apiLatest('requests', 'requests' + tpQuery('rq-hours', 'since', 'until') + '&q=' + encodeURIComponent($('rq-q').value.trim())
            + '&action=' + encodeURIComponent($('rq-action').value) + '&page=' + PAGE.requests + '&per=' + per).then(function (d) {
    var sel = $('rq-action'), keep = sel.value;
    if (sel.options.length - 1 !== d.actions.length) {
      clear(sel);
      sel.appendChild(el('option', '', 'every action')).value = '';
      d.actions.forEach(function (a) { var o = el('option', '', a); o.value = a; sel.appendChild(o); });
      sel.value = keep;
    }
    $('rq-said').textContent = num(d.total) + ' request(s)';
    var host = $('rq-table');
    clear(host);
    host.appendChild(listTable(['When', 'Client', 'Action', 'Protocol', {words: 'Port', cls: 'num'}, 'To', 'Lease', 'Result', 'Description'],
                               d.requests, function (r) {
      var tr = el('tr', 'tappable');
      tr.appendChild(stampCell(r.at));
      tr.appendChild(addrCell(r.client, r.name));
      tr.appendChild(noI18n(el('td', 'mono', r.action || '')));
      var tp = el('td'); if (r.protocol) tp.appendChild(protoTag(r.protocol)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'num mono', r.external_port || '')));
      tr.appendChild(noI18n(el('td', 'mono', r.internal_client ? r.internal_client + ':' + (r.internal_port || '') : '')));
      tr.appendChild(el('td', 'muted', r.lease !== undefined && r.lease !== null && r.lease !== '' ? r.lease + ' s' : ''));
      var res = el('td');
      if (r.result) res.appendChild(el('span', 'tag ' + (/^rej|^err|^fail|^conf/.test(r.result) ? 'crit' : 'ok'), r.result));
      tr.appendChild(res);
      tr.appendChild(noI18n(el('td', '', r.description || '')));
      tr.onclick = function () {
        modal('A request', function (body) {
          body.appendChild(peekFacts([['When', stamp(r.at)], ['Client', r.client], ['Action', r.action]]));
          var pairs = Object.keys(r).filter(function (k) { return k !== 'at'; }).map(function (k) {
            return [k, typeof r[k] === 'object' ? JSON.stringify(r[k]) : r[k], 'mono'];
          });
          body.appendChild(kvTable(pairs));
        });
      };
      return tr;
    }, 'plain|Nothing was asked in this window', {own: true}));
    pager('rq-pager', PAGE.requests, per, d.total, function (p) { PAGE.requests = p; loadRequests(); });
    explainWhatWasDrawn(host);
  }).catch(oops);
}
['rq-hours', 'rq-action', 'rq-per'].forEach(function (id) { $(id).onchange = function () { PAGE.requests = 0; loadRequests(); }; });
$('rq-q').addEventListener('input', debounce(function () { PAGE.requests = 0; loadRequests(); }, 300));

function loadClients() {
  apiLatest('clients', 'clients' + tpQuery('cl-hours', 'since', 'until')).then(function (d) {
    var q = $('cl-q').value.trim();
    var rows = d.clients.filter(function (r) { return matches(r, q); });
    $('cl-said').textContent = num(rows.length) + ' client(s)';
    var host = $('cl-table');
    clear(host);
    host.appendChild(listTable(['Client', {words: 'Searches', cls: 'num'}, {words: 'Requests', cls: 'num'}, 'Ports', 'Last seen', 'It says it is'],
                               rows, function (r) {
      var tr = el('tr', 'tappable');
      tr.appendChild(addrCell(r.client, r.name));
      tr.appendChild(el('td', 'num', num(r.searches)));
      tr.appendChild(el('td', 'num', num(r.requests)));
      tr.appendChild(noI18n(el('td', 'mono small', (r.ports || []).join(', '))));
      tr.appendChild(stampCell(r.last ? Date.parse(r.last) / 1000 : null));
      tr.appendChild(noI18n(el('td', 'muted small', r.user_agent || '')));
      tr.onclick = function () { $('rq-q').value = r.client; showTab('requests'); };
      return tr;
    }, 'plain|No client in this window', {own: true}));
    explainWhatWasDrawn(host);
  }).catch(oops);
}
$('cl-hours').onchange = loadClients;
$('cl-q').addEventListener('input', debounce(loadClients, 250));

function loadMappings() {
  apiLatest('mappings', 'mappings').then(function (d) {
    var host = $('mp-table');
    clear(host);
    host.appendChild(listTable(['Protocol', {words: 'Port', cls: 'num'}, 'Target', 'Left', 'Added', 'Asked by', 'Description'],
                               d.mappings, function (m) {
      var tr = el('tr');
      var tp = el('td'); tp.appendChild(protoTag(m.protocol)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'num mono', m.external_port)));
      tr.appendChild(addrCell(m.internal_client + ':' + m.internal_port, m.name));
      var left = m.expires_at ? Math.max(0, Math.round(m.expires_at - d.now)) : null;
      tr.appendChild(el('td', left === 0 ? 'muted' : '', left === null ? 'no end' : (left ? left + ' s' : 'run out')));
      tr.appendChild(stampCell(m.added_at));
      tr.appendChild(noI18n(el('td', 'mono', m.requested_by || '')));
      tr.appendChild(noI18n(el('td', '', m.description || '')));
      return tr;
    }, 'plain|No mapping now - they are kept only while the answer is accept and the mode active', {own: true}));
  }).catch(oops);
}

/* ==========================================================================
   The log - coloured as upnp log colours it
   ========================================================================== */
var LOGV = {paused: false, lines: []};
function logSpan(cls, text) { var s = el('span', cls, text); return s; }
function logWords(host, text, tone, hit) {
  /* addresses magenta, accepted green, rejected red - as log_text() in upnp.py */
  var rx = /(\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b)|\b(accept(?:ed)?|signed in|in place|done|ok)\b|\b(reject(?:ed)?|refused|failed|wrong|not answering)\b/gi;
  var at = 0, m;
  var put = function (t, cls) {
    if (!t) return;
    if (hit) {
      var parts = t.split(hit);
      parts.forEach(function (p, i) {
        if (i % 2 === 1) { var mk = el('mark', '', p); host.appendChild(mk); }
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
    if (first) box.scrollTop = 1e9;
    drawLog(d.lines, q);
    if (first) box.scrollTop = box.scrollHeight;
  }).catch(oops);
}
$('lg-q').addEventListener('input', debounce(function () { loadLog(true); }, 300));
$('lg-lines').onchange = function () { loadLog(true); };
$('lg-pause').onclick = function () {
  LOGV.paused = !LOGV.paused;
  setButtonIcon($('lg-pause'), LOGV.paused ? 'play' : 'clock', LOGV.paused ? 'Follow again' : 'Pause');
  if (!LOGV.paused) loadLog(true);
};
setButtonIcon($('lg-pause'), 'clock', 'Pause');
setInterval(function () { if (TAB === 'log' && LIVE && !document.hidden) loadLog(false); }, 3000);

/* Search and Clear beside a search box (otp's searchButtons, as it is). */
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

/* ==========================================================================
   Events
   ========================================================================== */
function loadEvents() {
  apiLatest('events', 'events&q=' + encodeURIComponent($('ev-q').value.trim()) + '&kind=' + encodeURIComponent($('ev-kind').value)
            + tpQuery('ev-time', 'since', 'until') + '&page=' + PAGE.events + '&per=100').then(function (d) {
    var sel = $('ev-kind'), keep = sel.value;
    if (sel.options.length - 1 !== d.kinds.length) {
      clear(sel);
      sel.appendChild(el('option', '', 'everything')).value = '';
      d.kinds.forEach(function (k) { var o = el('option', '', k); o.value = k; sel.appendChild(o); });
      sel.value = keep;
    }
    var host = $('ev-table');
    clear(host);
    host.appendChild(listTable(['When', 'What', 'Who', 'From', 'Words'], d.events, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.at));
      var k = el('td'); k.appendChild(el('span', 'tag ' + (r.level === 'warn' ? 'warn' : (r.level === 'error' ? 'crit' : 'info')), r.kind)); tr.appendChild(k);
      tr.appendChild(noI18n(el('td', '', r.who || '–')));
      tr.appendChild(noI18n(el('td', 'mono muted', r.addr || '')));
      tr.appendChild(noI18n(el('td', '', r.words)));
      return tr;
    }, 'plain|Nothing has been done yet', {own: true}));
    pager('ev-pager', PAGE.events, 100, d.total, function (p) { PAGE.events = p; loadEvents(); });
  }).catch(oops);
}
$('ev-kind').onchange = function () { PAGE.events = 0; loadEvents(); };
$('ev-time').onchange = function () { PAGE.events = 0; loadEvents(); };
$('ev-q').addEventListener('input', debounce(function () { PAGE.events = 0; loadEvents(); }, 300));

/* ==========================================================================
   Settings - the rail, the panes, the save bar (otp's, piece for piece)
   ========================================================================== */
function showPane(name) {
  if (!$('pane-' + name)) name = 'answer';
  PANE = name;
  document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
    b.classList.toggle('on', b.dataset.pane === name);
  });
  document.querySelectorAll('.ctl-pane').forEach(function (p) { p.hidden = p.id !== 'pane-' + name; });
  writeHash();
  if (name === 'people') loadUsers();
  if (name === 'web') loadRoot();
  if (name === 'service') drawService();
  if (name === 'upgrade') loadUpgrade();
  if (name === 'about') drawAbout();
  if (name === 'mdns') loadAvahiPane();
  if (typeof PANE_LOAD[name] === 'function') {
    try { PANE_LOAD[name](); } catch (e) { oops(e); }
  }
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
  var hits = SETTINGS.settings.filter(function (s) {
    return (s.name + ' ' + s.key + ' ' + s.says).toLowerCase().indexOf(want) >= 0;
  }).slice(0, 12);
  if (!hits.length) box.appendChild(el('div', 'ctl-none', 'Nothing by that name'));
  hits.forEach(function (s) {
    var b = el('button', 'ctl-hit');
    b.type = 'button';
    b.appendChild(el('span', 'ctl-hit-t', s.name));
    var pane = Object.keys(SETTINGS.panes).filter(function (p) { return SETTINGS.panes[p].indexOf(s.key) >= 0; })[0];
    var where = document.querySelector('.ctl-nav [data-pane="' + (pane || 'about') + '"]');
    b.appendChild(el('span', 'ctl-hit-w', where ? where.textContent.trim() : (pane || '')));
    b.onclick = function () {
      showPane(pane || 'about');
      $('ctl-find').value = '';
      box.hidden = true;
      var item = document.querySelector('.set-item[data-key="' + s.key + '"]');
      if (item) {
        item.scrollIntoView({block: 'center'});
        item.classList.remove('found');
        void item.offsetWidth;
        item.classList.add('found');
      }
    };
    box.appendChild(b);
  });
  box.hidden = false;
});

function settingByKey(k) {
  if (k.indexOf('avahi:') === 0) return AV.d ? (AV.d.keys || []).map(avahiSetting).filter(function (s) { return s.key === k; })[0] : null;
  return SETTINGS ? SETTINGS.settings.filter(function (s) { return s.key === k; })[0] : null;
}
function loadSettings(redraw) {
  api('settings').then(function (d) {
    SETTINGS = d;
    if (redraw !== false) { DIRTY = {}; drawSettings(); }
    showPane(PANE);
  }).catch(oops);
}
function saysClamped(words) {
  var box = saysBlock(words);
  box.classList.add('clamp');
  box.addEventListener('click', function () { box.classList.toggle('open'); });
  setTimeout(function () { if (box.scrollHeight > box.clientHeight + 2) box.classList.add('cut'); }, 0);
  return box;
}
function drawSettings() {
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
  markDirtyCount();
}
/* A setting asleep while the one it depends on says so (otp's applyOnlyWhen): greyed, and said why. */
function applyOnlyWhen() {
  var rules = (SETTINGS && SETTINGS.only_when) || {};
  Object.keys(rules).forEach(function (key) {
    var item = document.querySelector('.set-item[data-key="' + key + '"]');
    var master = $('set-' + rules[key][0]);
    if (!item || !master) return;
    var now = master._get ? (master._get() ? 'true' : 'false') : String(master.value);
    var want = String(rules[key][1]);
    var live = want === '*' ? !!now.trim() : now === want;
    item.classList.toggle('asleep', !live);
    var says = item.querySelector('.asleep-why');
    if (says) says.remove();
    if (!live) {
      var other = settingByKey(rules[key][0]) || {};
      (item.querySelector('.set-tail') || item).appendChild(el('div', 'says asleep-why', want === '*'
        ? 'Not in use until ' + other.name + ' is filled in.'
        : (other.bool ? 'Not in use while ' + other.name + ' is off.' : 'Not in use while ' + other.name + ' is not “' + want + '”.')));
    }
  });
}
function readValue(s) {
  var input = $('set-' + s.key);
  if (!input) return null;
  if (s.bool) return input._get() ? '1' : '0';
  return input.value;
}
function settingItem(s) {
  var item = el('div', 'set-item' + (s.bool ? ' set-bool' : ''));
  item.dataset.key = s.key;
  var label = el('label', '', s.name);
  var info = el('span', 'iinfo', 'i');
  info.setAttribute('role', 'button');
  info.tabIndex = 0;
  var asText = function (v) { return richText(Array.isArray(v) ? v.join(', ') : String(v)); };
  var story = '<span class="k">on the command line this one is <b>sudo upnp config set ' + richText(s.key)
    + ' …</b> · now: ' + (s.secret ? (s.set ? 'set' : 'not set') : asText(s.value))
    + '<br><span class="' + (s.source === 'default' ? 'same' : 'diff') + '">' + richText(s.source_says || '') + '</span>'
    + (s.source !== 'default' && !s.secret && String(s.value) !== String(s.default)
       ? '<br><span class="same">as it comes: ' + asText(s.default) + '</span>' : '')
    + (s.restarts ? '<br><span class="same">a change restarts fake-igd.service</span>' : '')
    + (s.root ? '<br><span class="same">root puts nginx\'s allow list and the firewall in place again</span>' : '') + '</span>';
  explain(info, s.says || '', story);
  explain(label, s.says || '', story);
  if (label.firstChild && label.firstChild.nodeType === 3) {
    var txt = el('span', 'lbl-txt');
    txt.appendChild(label.firstChild);
    label.insertBefore(txt, label.firstChild);
  }
  label.appendChild(info);
  item.appendChild(label);
  var input;
  if (s.bool) {
    input = switchBox(s.value === true);
    input._input.disabled = !ADMIN;
    input._input.addEventListener('change', function () { markDirty(item, s); });
    input.id = 'set-' + s.key;
    input._input.id = 'set-' + s.key + '-sw';
    label.setAttribute('for', input._input.id);
  } else if (s.choices) {
    input = selectBox(s.choices.map(function (c) { return [c, (s.choice_words && s.choice_words[c]) || c]; }), s.value);
    if (s.choice_words) item.classList.add('wide');
  } else if (s.tall) {
    item.classList.add('tall');
    input = el('textarea');
    input.value = s.value === null || s.value === undefined ? '' : String(s.value);
    input.rows = 4;
  } else if (typeof s.min === 'number') {
    input = el('input');
    input.type = 'number';
    input.min = s.min;
    input.max = s.max;
    input.value = s.value;
  } else {
    input = s.secret ? maskBox('', '', '') : textBox(s.value, s.list ? 'comma separated; empty = none' : '', '');
    if (s.secret) input.placeholder = s.set ? 'set - leave as it is to keep it' : 'not set';
    if (s.list || /url|file|dir/.test(s.key)) input.classList.add('mono');
  }
  if (!s.bool) {
    input.id = 'set-' + s.key;
    input.disabled = !ADMIN;
    label.setAttribute('for', input.id);
    input.addEventListener('input', function () { markDirty(item, s); });
    input.addEventListener('change', function () { markDirty(item, s); });
  }
  item.appendChild(input);
  var tail = el('div', 'set-tail');
  if (s.says) tail.appendChild(saysClamped(s.says));
  item.appendChild(tail);
  return item;
}
function markDirty(item, s) {
  setTimeout(applyOnlyWhen, 0);
  var now = readValue(s);
  var was = s.bool ? (s.value === true ? '1' : '0') : (s.secret ? '' : (s.value === null || s.value === undefined ? '' : String(s.value)));
  var changed = s.secret ? now !== '' : was !== String(now);
  item.classList.toggle('changed', changed);
  if (changed) DIRTY[s.key] = s.bool ? now === '1' : now; else delete DIRTY[s.key];
  markDirtyCount();
}
function saveBarHere() {
  if (!ADMIN || TAB !== 'settings') return false;
  var pane = $('pane-' + PANE);
  return !!(pane && pane.querySelector('.set-item[data-key]'));
}
function markDirtyCount() {
  var n = Object.keys(DIRTY).length;
  $('set-said').textContent = n ? n + ' change(s) not saved yet' : '';
  $('save-bar').classList.toggle('dirty', n > 0);
  $('save-bar').style.display = saveBarHere() ? '' : 'none';
}
$('set-save').onclick = function () {
  var b = $('set-save');
  if (!Object.keys(DIRTY).length) { toast('nothing has been changed'); return; }
  var own = {}, av = {};
  Object.keys(DIRTY).forEach(function (k) {
    if (k.indexOf('avahi:') === 0) av[k.slice(6)] = DIRTY[k]; else own[k] = DIRTY[k];
  });
  var restarts = Object.keys(own).some(function (k) { var s = settingByKey(k); return s && s.restarts; });
  var go = function () {
    busy(b, true);
    var chain = Promise.resolve();
    if (Object.keys(own).length) chain = chain.then(function () {
      return api('settings', {changes: own}).then(function (d) {
        toast(d.message, 'good');
        if (d.root || d.restart) setTimeout(loadRoot, 4000);
      });
    });
    if (Object.keys(av).length) chain = chain.then(function () {
      return api('mdns', {changes: av}).then(function (d) {
        toast(d.message, 'good');
        avahiWait(d.id);
      });
    });
    chain.then(function () { DIRTY = {}; loadSettings(true); }).catch(oops).then(function () { busy(b, false); });
  };
  if (restarts && STATUS && STATUS.service && STATUS.service.state === 'active') {
    confirmThen('Save and restart?', 'A setting fake-igd.service uses is changed: it is restarted with it. '
      + 'For a few seconds nothing on the network is answered - the PS5 notices nothing more than that.', 'Save and restart', go, false);
  } else go();
};
$('set-reset').onclick = function () { DIRTY = {}; loadSettings(true); };
window.addEventListener('beforeunload', function (e) {
  if (Object.keys(DIRTY).length) { e.preventDefault(); e.returnValue = ''; }
});
$('nt-test').onclick = function () {
  var b = $('nt-test');
  busy(b, true);
  $('nt-said').textContent = '';
  api('notify-test', {}).then(function (d) { $('nt-said').className = 'small good'; $('nt-said').textContent = d.message; })
    .catch(function (e) { $('nt-said').className = 'small bad'; $('nt-said').textContent = e.message; })
    .then(function () { busy(b, false); });
};

/* ==========================================================================
   mDNS - the reflector (avahi-daemon): the tab, and its settings pane
   ========================================================================== */
var AV = {d: null, svc: null, busy: false};
function avahiSetting(k) {
  return {key: 'avahi:' + k.key, name: k.name, says: k.says, value: k.value, default: k.default,
          bool: k.bool, source: k.source, source_says: k.source_says, secret: false,
          list: k.kind === 'ifaces' || k.kind === 'list', restarts: false, root: true};
}
/* The reflector at a glance, as otp's tiles over a list (Enrolment): in the one held card. */
function paintMdnsCards(d) {
  var host = $('ms-tiles');
  clear(host);
  if (!d.installed) {
    host.appendChild(peekFacts([['avahi-daemon', 'not installed'], ['What to do', d.error || 'dnf install avahi avahi-tools']]));
    return;
  }
  var svc = AV.svc ? AV.svc.services : null, types = {};
  (svc || []).forEach(function (s) { types[s.type] = 1; });
  var tiles = peekFacts([
    ['avahi-daemon', d.service.state === 'active' ? 'running' + (d.version ? ' · avahi ' + d.version : '') : d.service.state],
    ['The reflector', d.reflector ? 'on' + (d.reflect_filters.length ? ' · only ' + d.reflect_filters.join(', ') : ' · every type') : 'off'],
    ['Interfaces', d.interfaces.map(function (i) { return i.name; }).join(', ') + (d.missing_interfaces.length ? ' · missing: ' + d.missing_interfaces.join(', ') : '')],
    ['Services seen', svc ? num(svc.length) + ' · ' + num(Object.keys(types).length) + ' type(s)' : '…']
  ]);
  var cells = tiles.querySelectorAll('.fact');
  if (cells[0]) cells[0].classList.add(d.service.state === 'active' ? 'good' : 'bad');
  cells[0].onclick = cells[1].onclick = function () { PANE = 'mdns'; showTab('settings'); };
  host.appendChild(tiles);
}
function loadMdnsTab() {
  apiLatest('mdns', 'mdns').then(function (d) {
    AV.d = d;
    paintMdnsCards(d);
    var sel = $('ms-iface'), keep = sel.value;
    clear(sel);
    sel.appendChild(el('option', '', 'every interface')).value = '';
    (d.interfaces || []).forEach(function (i) { var o = el('option', '', i.name); o.value = i.name; sel.appendChild(o); });
    sel.value = keep;
    if (!AV.svc) loadServices();
  }).catch(oops);
}
function loadServices() {
  if (AV.busy) return;
  AV.busy = true;
  busy($('ms-look'), true);
  $('ms-said').textContent = 'asking avahi…';
  api('mdns-services', undefined, 40).then(function (d) {
    AV.svc = d;
    drawServices();
  }).catch(function (e) {
    $('ms-said').textContent = '';
    var host = $('ms-table');
    clear(host);
    host.appendChild(listTable(['Type', 'Name', 'Interface', 'Protocol', 'Host', 'Address', 'TXT'], [], null,
                               'plain|' + String(e.message || e)));
  })
    .then(function () { AV.busy = false; busy($('ms-look'), false); });
}
function drawServices() {
  var d = AV.svc;
  if (!d) return;
  var q = $('ms-q').value.trim(), ifc = $('ms-iface').value, pr = $('ms-proto').value;
  var rows = d.services.filter(function (s) {
    return (!ifc || s.iface === ifc) && (!pr || s.proto === pr) && matches(s, q);
  });
  var types = {};
  d.services.forEach(function (s) { types[s.type] = 1; });
  if (AV.d) paintMdnsCards(AV.d);
  $('tabn-mdns').textContent = d.services.length ? num(d.services.length) : '';
  $('ms-said').textContent = num(rows.length) + ' of ' + num(d.services.length);
  var host = $('ms-table');
  clear(host);
  host.appendChild(listTable(['Type', 'Name', 'Interface', 'Protocol', 'Host', 'Address', 'TXT'], rows, function (s) {
    var tr = el('tr', 'tappable');
    tr.appendChild(noI18n(el('td', 'mono', s.type)));
    tr.appendChild(noI18n(el('td', '', s.name)));
    tr.appendChild(noI18n(el('td', 'mono', s.iface)));
    var tp = el('td'); tp.appendChild(el('span', 'tag ' + (s.proto === 'IPv6' ? 'violet' : 'info'), s.proto)); tr.appendChild(tp);
    tr.appendChild(noI18n(el('td', 'mono', s.host || '')));
    tr.appendChild(noI18n(el('td', 'mono', s.address ? s.address + (s.port ? ':' + s.port : '') : '')));
    tr.appendChild(noI18n(el('td', 'muted small', (s.txt || '').slice(0, 120))));
    tr.onclick = function () {
      modal(s.name, function (body) {
        body.appendChild(peekFacts([['Type', s.type], ['Interface', s.iface + ' ' + s.proto], ['Address', (s.address || '–') + (s.port ? ':' + s.port : '')]]));
        body.appendChild(kvTable(Object.keys(s).map(function (k) { return [k, s[k], 'mono']; })));
      });
    };
    return tr;
  }, 'plain|' + (d.hint || 'Nothing is shown on mDNS now - or avahi-daemon is not running'), {own: true}));
  explainWhatWasDrawn(host);
}
$('ms-look').onclick = loadServices;
['ms-iface', 'ms-proto'].forEach(function (id) { $(id).onchange = drawServices; });
$('ms-q').addEventListener('input', debounce(drawServices, 200));

function loadAvahiPane() {
  api('mdns').then(function (d) {
    AV.d = d;
    $('av-missing').hidden = !!d.installed;
    if (!d.installed) { $('av-missing-words').textContent = d.error || 'avahi is not installed here'; }
    var host = $('sect-mdns');
    clear(host);
    if (d.installed) {
      var grid = el('div', 'set-grid');
      d.keys.forEach(function (k) { grid.appendChild(settingItem(avahiSetting(k))); });
      host.appendChild(grid);
      Object.keys(DIRTY).forEach(function (key) {
        if (key.indexOf('avahi:') !== 0) return;
        var item = document.querySelector('.set-item[data-key="' + key + '"]');
        if (item) item.classList.add('changed');
      });
    }
    var st = $('av-state');
    clear(st);
    if (d.installed) {
      st.appendChild(kvTable([
        ['The daemon', d.service.state + ' (' + d.service.sub + ')', d.service.state === 'active' ? 'good' : 'bad'],
        ['Starts at boot', d.service.boot], ['Running since', d.service.since || '–'], ['Version', d.version || '–'],
        ['The file', d.config], ['Interfaces here', (d.system_interfaces || []).join(', ')],
        ['avahi-browse', d.browse_tool ? 'there' : 'missing - dnf install avahi-tools', d.browse_tool ? '' : 'bad']
      ]));
      var r = d.root || {};
      if (r.at && (r.said || []).some(function (x) { return /avahi/.test(x); })) {
        st.appendChild(el('p', 'muted small', 'root, ' + ago(r.at) + ':'));
        var ul = el('ul', 'tight');
        r.said.forEach(function (x) { ul.appendChild(el('li', /did not|not|refused/.test(x) ? 'warn' : '', x)); });
        st.appendChild(ul);
      }
    }
    var tools = $('av-tools');
    clear(tools);
    if (ADMIN && d.installed) {
      [['Restart', 'refresh', 'restart'], [d.service.state === 'active' ? 'Stop' : 'Start', 'power',
        d.service.state === 'active' ? 'stop' : 'start']].forEach(function (a) {
        var b = cmdButton(a[0], a[1], 'small' + (a[2] === 'stop' ? ' danger' : ''));
        b.onclick = function () {
          var go = function () {
            api('mdns', {action: a[2]}).then(function (x) { toast(x.message, 'good'); avahiWait(x.id); }).catch(oops);
          };
          if (a[2] === 'stop') confirmThen('Stop avahi-daemon?', 'mDNS is no longer reflected between the networks until it is started again.', 'Stop', go);
          else go();
        };
        tools.appendChild(b);
      });
    }
    if (d.installed) {
      var lg = cmdButton('Its log', 'log', 'small');
      lg.onclick = function () {
        peek('avahi-daemon - its log', function () { return api('mdns-log&lines=400'); }, function (body, x) {
          var pre = noI18n(el('pre', 'lines', x.lines.join('\n') || '(nothing)'));
          body.appendChild(pre);
          setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
        });
      };
      tools.appendChild(lg);
    }
    explainWhatWasDrawn($('pane-mdns'));
    markDirtyCount();
  }).catch(oops);
}
function avahiWait(id) {
  var tries = 0;
  var again = function () {
    api('root-result').then(function (d) {
      var r = d.result || {};
      if (r.id === id) {
        (r.said || []).forEach(function (x) { toast(x, /did not|refused|not a key/.test(x) || !r.ok ? 'bad' : 'good'); });
        if (PANE === 'mdns' && TAB === 'settings') loadAvahiPane();
        if (TAB === 'mdns') { AV.svc = null; loadMdnsTab(); }
        return;
      }
      if (++tries < 20) setTimeout(again, 1000);
      else toast('root has not answered - is fake-igd-web.path running?', 'bad');
    }).catch(function () { if (++tries < 20) setTimeout(again, 1000); });
  };
  setTimeout(again, 1200);
}

/* ---- what root did (nginx, the firewall, a restart) ------------------------ */
function loadRoot() {
  api('root-result').then(function (d) {
    var r = d.result || {}, host = $('fw-state');
    clear(host);
    if (!r.at) { host.appendChild(el('p', 'muted', 'Root has not been asked anything from these pages yet.')); return; }
    host.appendChild(el('p', 'muted small', ago(r.at) + (r.ok ? '' : ' - with trouble')));
    var ul = el('ul', 'tight');
    (r.said || []).forEach(function (s) { ul.appendChild(el('li', /refused|not|would/.test(s) ? 'warn' : '', s)); });
    host.appendChild(ul);
    var tools = $('fw-tools');
    clear(tools);
    if (ADMIN) {
      var again = cmdButton('Put it in place again', 'refresh', 'small');
      again.onclick = function () {
        busy(again, true);
        api('apply', {}).then(function () { toast('asked root - a moment', 'good'); setTimeout(loadRoot, 3500); })
          .catch(oops).then(function () { busy(again, false); });
      };
      tools.appendChild(again);
    }
  }).catch(oops);
}

/* ---- the service ------------------------------------------------------------ */
function drawService() {
  var s = STATUS || {}, sv = s.service || {}, host = $('sv-state');
  clear(host);
  host.appendChild(kvTable([
    ['fake-igd.service', sv.state + ' (' + (sv.sub || '?') + ')', sv.state === 'active' ? 'good' : 'bad'],
    ['Its PID', sv.pid && sv.pid !== '0' ? sv.pid : '–'],
    ['Running since', sv.since || '–'],
    ['Starts at boot', sv.boot || '–'],
    ['Restarts', sv.restarts],
    ['The pages\' API', 'since ' + stamp((s.web || {}).api_since)]
  ]));
}
$('sv-restart').onclick = function () {
  confirmThen('Restart fake-igd.service?', 'For a few seconds nothing on the network is answered.', 'Restart', function () {
    api('apply', {restart: true}).then(function () { toast('asked root to restart it', 'good'); setTimeout(tick, 4000); }).catch(oops);
  }, false);
};
$('sv-apply').onclick = function () {
  api('apply', {}).then(function () { toast('asked root - a moment', 'good'); }).catch(oops);
};

/* ---- accounts ----------------------------------------------------------------- */
function loadUsers() {
  api('users').then(function (d) {
    var host = $('us-table');
    clear(host);
    host.appendChild(listTable(['Name', 'Role', 'Signed in now', 'Last sign-in', 'From', 'Note'], d.users, function (u) {
      var tr = el('tr', ADMIN ? 'tappable' : '');
      var nm = el('td'); nm.appendChild(noI18n(el('b', '', u.name)));
      if (u.name.toLowerCase() === d.me.toLowerCase()) { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'you')); }
      tr.appendChild(nm);
      var rl = el('td'); rl.appendChild(el('span', 'tag ' + roleTone(u.role), roleWords(u.role))); tr.appendChild(rl);
      tr.appendChild(el('td', u.sessions ? 'good' : 'muted', u.sessions ? num(u.sessions) : '–'));
      tr.appendChild(stampCell(u.last_login));
      tr.appendChild(noI18n(el('td', 'mono muted', u.last_from || '')));
      tr.appendChild(noI18n(el('td', '', u.note || '')));
      if (ADMIN) tr.onclick = function () { userEdit(u, d.me); };
      return tr;
    }, 'plain|No account yet'));
    var se = $('se-table');
    clear(se);
    se.appendChild(listTable(['Account', 'From', 'Signed in', 'Last seen', 'Browser', ''], d.sessions, function (x) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', '', x.name)));
      tr.appendChild(noI18n(el('td', 'mono', x.addr)));
      tr.appendChild(stampCell(x.created));
      tr.appendChild(stampCell(x.seen));
      tr.appendChild(noI18n(el('td', 'muted small', (x.agent || '').slice(0, 80))));
      var td = el('td');
      var end = iconButton('close', 'End this sign-in');
      end.onclick = function () {
        api('users', {action: 'end-session', id: x.id}).then(function (r) { toast(r.message, 'good'); loadUsers(); }).catch(oops);
      };
      td.appendChild(end);
      tr.appendChild(td);
      return tr;
    }, 'plain|Nobody'));
    explainWhatWasDrawn($('pane-people'));
  }).catch(oops);
}
function saidPassword(name, pw) {
  modal('The password of ' + name, function (body) {
    body.appendChild(el('p', 'note', 'Made here and shown once - give it to its owner now.'));
    var code = noI18n(el('div', 'mono big', pw));
    copyOnClick(code, pw, 'copied');
    body.appendChild(code);
  }, null, true);
}
$('us-add').onclick = function () {
  modal('Make an account', function (body) {
    var n = textBox('', 'a name: letters, digits . _ @ -'); n.id = 'ua-name';
    var r = selectBox([['fulladmin', 'full admin - may change everything'], ['readonly', 'read only - may look']], 'readonly'); r.id = 'ua-role';
    var p = maskBox('', 'empty = make one and show it', 'mono'); p.id = 'ua-pass';
    var t = textBox('', ''); t.id = 'ua-note';
    body.appendChild(formField('Name', n));
    body.appendChild(formField('Role', r));
    body.appendChild(formField('Password', p, 'At least 8 characters. Empty: one is made and shown once.'));
    body.appendChild(formField('Note', t));
  }, [{words: 'Close', close: true}, {words: 'Make it', cls: 'primary', icon: 'add', go: function (b) {
    busy(b, true);
    api('users', {action: 'add', name: $('ua-name').value.trim(), role: $('ua-role').value,
                  password: $('ua-pass').value, note: $('ua-note').value}).then(function (d) {
      toast(d.message, 'good');
      var name = $('ua-name').value.trim();
      closeModal();
      loadUsers();
      if (d.password) saidPassword(name, d.password);
    }).catch(oops).then(function () { busy(b, false); });
  }}], true);
};
function userEdit(u, me) {
  modal(u.name, function (body) {
    body.appendChild(peekFacts([['Role', roleWords(u.role)], ['Made', stamp(u.created)], ['Last sign-in', u.last_login ? stamp(u.last_login) : 'never']]));
    var r = selectBox([['fulladmin', 'full admin - may change everything'], ['readonly', 'read only - may look']], u.role); r.id = 'ue-role';
    var p = maskBox('', 'empty = make one and show it', 'mono'); p.id = 'ue-pass';
    var t = textBox(u.note || '', ''); t.id = 'ue-note';
    body.appendChild(formField('Role', r));
    body.appendChild(formField('Note', t));
    body.appendChild(formField('A new password', p, 'Given here, its sign-ins go on; on the server: sudo upnp user passwd ' + u.name));
  }, [{words: 'Take it away', cls: 'danger left', icon: 'trash', go: function () {
        api('users', {action: 'delete', name: u.name}).then(function (d) { toast(d.message, 'good'); closeModal(); loadUsers(); }).catch(oops);
      }},
      {words: 'Close', close: true},
      {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
        busy(b, true);
        var steps = [];
        if ($('ue-role').value !== u.role) steps.push({action: 'role', name: u.name, role: $('ue-role').value});
        if ($('ue-note').value !== (u.note || '')) steps.push({action: 'note', name: u.name, note: $('ue-note').value});
        if ($('ue-pass').value) steps.push({action: 'passwd', name: u.name, password: $('ue-pass').value});
        var chain = Promise.resolve();
        steps.forEach(function (s) { chain = chain.then(function () { return api('users', s); }); });
        chain.then(function () { toast(steps.length ? 'saved' : 'nothing was changed', 'good'); closeModal(); loadUsers(); })
          .catch(oops).then(function () { busy(b, false); });
      }}]);
}

/* ---- upgrades ------------------------------------------------------------------ */
var UPG = {d: null, pkg: null};
function loadUpgrade() {
  apiLatest('upgrade', 'upgrade').then(function (d) { UPG.d = d; drawUpgrade(d); }).catch(oops);
}
function drawUpgrade(d) {
  var host = $('up-web');
  clear(host);
  var o = d.online || {};
  var facts = [['This server runs', d.here], ['Looked at', o.at ? ago(o.at) : 'not yet'],
               ['Newest there', (o.newest || {}).version || '–']];
  host.appendChild(peekFacts(facts));
  host.appendChild(noI18n(el('p', 'muted small mono', d.url)));
  if (o.error) host.appendChild(el('p', 'said bad', 'The last look: ' + o.error));
  if (!d.helper || !d.path_unit) {
    host.appendChild(el('p', 'said bad', 'Root\'s part is not installed here (' + (!d.helper ? 'fake_igd_upgrade.py' : 'fake-igd-upgrade.path')
      + ') - upgrade once on the command line: ./install.sh --upgrade'));
  }
  var row = el('div', 'btnrow');
  row.style.marginTop = '10px';
  var look = cmdButton('Look now', 'refresh', '');
  look.onclick = function () {
    busy(look, true);
    api('upgrade', {action: 'look'}).then(function () { loadUpgrade(); }).catch(oops).then(function () { busy(look, false); });
  };
  row.appendChild(look);
  var newer = o.newer_list || [];
  if (newer.length && !d.status.busy) {
    var pick = null;
    if (newer.length > 1) {
      pick = selectBox(newer.map(function (p) { return [p.version, p.version]; }), newer[0].version);
      row.appendChild(pick);
    }
    var want = function () { return pick ? pick.value : newer[0].version; };
    var go = cmdButton('Upgrade to ' + want() + ' now', 'up', 'primary');
    var only = cmdButton('Only fetch it', 'download', '');
    if (pick) pick.onchange = function () { setButtonIcon(go, 'up', 'Upgrade to ' + want() + ' now'); };
    go.onclick = function () {
      confirmThen('Upgrade to fake-igd ' + want() + '?', 'It is fetched, its signature and every file checked, and root '
        + 'runs its install.sh --upgrade. fake-igd.service and these pages restart once - the pages come back by themselves.',
        'Upgrade', function () {
          busy(go, true);
          api('upgrade', {action: 'online', version: want()}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); })
            .catch(oops).then(function () { busy(go, false); });
        }, false);
    };
    only.onclick = function () {
      busy(only, true);
      api('upgrade', {action: 'fetch', version: want()}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); })
        .catch(oops).then(function () { busy(only, false); });
    };
    row.appendChild(go);
    row.appendChild(only);
  } else if (o.at && !o.error) {
    row.appendChild(el('span', 'muted small', 'nothing newer than ' + d.here));
  }
  host.appendChild(row);
  /* the package waiting */
  var pk = d.package, ph = $('up-pkg');
  clear(ph);
  $('up-start').disabled = !pk || !pk.version || d.status.busy;
  $('up-forget').hidden = !pk || !pk.version;
  if (pk && pk.version) {
    ph.appendChild(peekFacts([['Version', pk.version], ['Signed by', pk.signed_by], ['Files', pk.files],
                              ['Came', pk.from || '–'], ['By', pk.by || '–']]));
    if (pk.changelog) {
      var det = el('details', 'fold');
      det.appendChild(el('summary', '', 'what is new'));
      det.appendChild(noI18n(el('pre', 'lines', pk.changelog)));
      ph.appendChild(det);
    }
  }
  /* the one going on, or the last */
  var st = d.status || {}, card = $('up-plan-card'), plan = $('up-plan');
  card.hidden = !st.state || st.state === 'none';
  clear(plan);
  if (!card.hidden) {
    var tone = st.state === 'done' ? 'ok' : (st.state === 'failed' ? 'crit' : 'warn');
    var line = el('div', 'btnrow');
    line.appendChild(el('span', 'tag ' + tone, st.state === 'asked' ? 'waiting for root' : st.state));
    line.appendChild(noI18n(el('b', '', 'fake-igd ' + (st.version || '?'))));
    if (st.at) line.appendChild(el('span', 'muted small', ago(st.at)));
    plan.appendChild(line);
    var bar = el('div', 'bar' + (st.state === 'failed' ? '' : ' good'));
    bar.style.marginTop = '10px';
    var fill = el('span');
    fill.style.width = Math.max(3, d.percent || 0) + '%';
    bar.appendChild(fill);
    plan.appendChild(bar);
    plan.appendChild(el('p', 'muted small', (d.percent || 0) + ' % · ' + (d.words || (st.state === 'done' ? 'done' : ''))));
    if (st.said) plan.appendChild(el('p', 'said bad', st.said));
  }
  $('up-log').textContent = (d.log || []).join('\n') || '–';
  if (st.busy) setTimeout(function () { if (TAB === 'settings' && PANE === 'upgrade') loadUpgrade(); }, 2000);
}
$('up-start').onclick = function () {
  var pk = UPG.d && UPG.d.package;
  if (!pk) return;
  confirmThen('Upgrade to fake-igd ' + pk.version + '?', 'Root checks the package again and runs its install.sh --upgrade. '
    + 'fake-igd.service and these pages restart once.', 'Upgrade', function () {
      api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); }).catch(oops);
    }, false);
};
$('up-forget').onclick = function () {
  api('upgrade', {action: 'forget'}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); }).catch(oops);
};
(function drop() {
  var zone = $('up-drop'), file = $('up-file');
  zone.onclick = function () { file.click(); };
  zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', function () { zone.classList.remove('over'); });
  zone.addEventListener('drop', function (e) { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer.files[0]) send(e.dataTransfer.files[0]); });
  file.onchange = function () { if (file.files[0]) send(file.files[0]); };
  function send(f) {
    if (!/^fake-igd-\d+\.\d+\.\d+\.tar\.gz$/.test(f.name)) { toast('that is not a fake-igd-X.Y.Z.tar.gz', 'bad'); return; }
    $('up-drop-says').textContent = 'Sending ' + f.name + '…';
    var rd = new FileReader();
    rd.onload = function () {
      var b64 = String(rd.result).split(',')[1] || '';
      api('upgrade-package', {data: b64}).then(function (d) {
        toast('fake-igd ' + d.package.version + ' checked - signed by ' + d.package.signed_by, 'good');
        loadUpgrade();
      }).catch(oops).then(function () { $('up-drop-says').textContent = 'Drop the fake-igd-X.Y.Z.tar.gz here, or press to choose it'; });
    };
    rd.readAsDataURL(f);
  }
}());

/* ---- about ----------------------------------------------------------------------- */
function drawAbout() {
  var s = STATUS || {}, host = $('about-state');
  clear(host);
  host.appendChild(kvTable([
    ['fake-igd', s.version], ['This machine', s.node], ['Mode', s.mode], ['AddPortMapping', s.mapping_response],
    ['Description and SOAP', 'port ' + s.http_port], ['Public IP', s.public_ip || s.external_ip],
    ['Notifications', s.notifications], ['Who is answered', (s.allowed_clients || []).join(', ') || 'everybody'],
    ['Signed in as', ME.name + ' (' + roleWords(ME.role) + ')']
  ]));
  host.appendChild(el('p', 'muted small', 'The same on the server: upnp status · upnp --console · upnp --help'));
}

searchButtons($('pt-q'), loadPorts, ['pt-proto'], ['pt-hours']);
searchButtons($('rq-q'), function () { PAGE.requests = 0; loadRequests(); }, ['rq-action'], ['rq-hours']);
searchButtons($('cl-q'), loadClients, [], ['cl-hours']);
searchButtons($('ev-q'), function () { PAGE.events = 0; loadEvents(); }, ['ev-kind'], ['ev-time']);

/* ---- start --------------------------------------------------------------------- */
(function start() {
  if (STATUS) paintHeader(STATUS);
  var h = (location.hash || '').replace(/^#/, '').split('/');
  if (h[0] === 'settings' && h[1]) PANE = h[1];
  showTab(h[0] || 'overview');
  setInterval(tick, 5000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) tick(); });
}());
