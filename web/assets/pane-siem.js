/* pane-siem.js - Settings → Syslog and SIEM (otp's loadSiem, drawSiem) - this one server's card. */
(function () {
'use strict';

var SI = {d: null};
function netFacts(rows) {
  var dl = el('div', 'net-facts');
  rows.forEach(function (r) {
    if (r[1] === undefined) return;
    var one = el('div', 'net-fact');
    one.appendChild(el('span', 'k', r[0]));
    var v = el('span', 'v' + (r[2] ? ' mono' : ''));
    if (r[1] instanceof Node) v.appendChild(r[1]); else v.textContent = r[1] === '' || r[1] === null ? '–' : String(r[1]);
    if (r[2]) noI18n(v);
    one.appendChild(v);
    dl.appendChild(one);
  });
  return dl;
}
function nodeCard(name, dot, tag, tagCls) {
  var c = el('div', 'card ntp-node');
  var head = el('div', 'pw-head');
  head.appendChild(el('span', 'dot ' + dot));
  head.appendChild(noI18n(el('b', '', name)));
  head.appendChild(el('span', 'tag info', 'this page'));
  if (tag) head.appendChild(el('span', 'tag ' + (tagCls || 'dim'), tag));
  c.appendChild(head);
  return c;
}
function nodeBig(c, value, words) {
  var big = el('div', 'ntp-big');
  big.appendChild(noI18n(el('span', 'ntp-off', value)));
  if (words) big.appendChild(el('span', 'muted small', ' ' + words));
  c.appendChild(big);
}
function nodeSaid(got, words) {
  var p = el('div', 'node-said ' + (got.ok ? 'ok' : 'bad'));
  p.appendChild(el('span', 'dot ' + (got.ok ? 'ok' : 'bad')));
  var t = el('div');
  t.appendChild(el('b', '', words));
  Object.keys(got.said || {}).forEach(function (k) {
    if (got.said[k] !== 'sent') t.appendChild(noI18n(el('div', 'small muted', k + ': ' + got.said[k])));
  });
  t.appendChild(el('div', 'small muted', ago(got.at)));
  p.appendChild(t);
  return p;
}

function loadSiem() {
  api('siem').then(function (d) { SI.d = d; drawSiem(); }).catch(oops);
}
function drawSiem() {
  var real = $('si-host');
  if (!real || !SI.d) return;
  liveFill(real, function (host) {
    var d = SI.d;
    if (!d.on) host.appendChild(el('p', 'note', 'Sending is off - switch it on below and say where to.'));
    var ts = d.targets || [];
    var trouble = Object.keys(d.trouble || {});
    var on = d.on && ts.length;
    var grid = el('div', 'pw-grid node-grid');
    var c = nodeCard(STATUS && STATUS.node || 'this server', !on ? 'dim' : (trouble.length ? 'warn' : 'ok'),
      !d.on ? 'off' : (!ts.length ? 'nowhere to send' : (trouble.length ? 'trouble' : 'sending')),
      !on ? 'dim' : (trouble.length ? 'warn' : 'ok'));
    var total = 0;
    Object.keys(d.sent || {}).forEach(function (k) { total += d.sent[k]; });
    var totalRun = 0;
    Object.keys(d.sent_run || {}).forEach(function (k) { totalRun += d.sent_run[k]; });
    nodeBig(c, num(totalRun), 'line(s) sent since it started');
    var waiting = 0;
    Object.keys(d.waiting || {}).forEach(function (k) { waiting = Math.max(waiting, d.waiting[k] || 0); });
    c.appendChild(netFacts([
      ['Written as', d.host || '', true], ['In the shape of', (d.format || '').toUpperCase(), true],
      ['Last sent', d.last_sent ? ago(d.last_sent) : 'never'], ['Waiting to go', num(waiting)],
      ['Dropped, the queue full', num(d.dropped || 0)], ['Read', d.at ? ago(d.at) : '']
    ]));
    ts.forEach(function (t) {
      var row = el('div', 'si-row');
      row.appendChild(el('span', 'dot ' + ((d.trouble || {})[t] ? 'bad' : ((d.sent || {})[t] ? 'ok' : 'dim'))));
      row.appendChild(noI18n(el('span', 'mono', t)));
      row.appendChild(el('span', 'muted small', num((d.sent || {})[t] || 0) + ' sent'));
      c.appendChild(row);
      if ((d.trouble || {})[t]) c.appendChild(noI18n(el('div', 'si-said small', d.trouble[t])));
    });
    if (!ts.length) c.appendChild(el('p', 'muted small', 'Nowhere to send to.'));
    if (d.test) {
      var bad = Object.keys(d.test.said || {}).filter(function (k) { return d.test.said[k] !== 'sent'; });
      c.appendChild(nodeSaid(d.test, d.test.ok ? 'The test line went to every server' : 'Not to ' + bad.join(', ')));
    }
    var row2 = el('div', 'btnrow');
    var look = cmdButton('Look again', 'refresh', 'small');
    look.onclick = function () { loadSiem(); };
    var test = cmdButton('Send a test line', 'play', 'small');
    explain(test, 'One line to every server, now - to see it arrive and how it reads.');
    test.disabled = !ADMIN || !d.on || !ts.length;
    test.onclick = function () {
      busy(test, true);
      api('siem', {action: 'test'}).then(function (x) { toast(x.message, x.test && x.test.ok ? 'good' : 'bad'); loadSiem(); })
        .catch(oops).then(function () { busy(test, false); });
    };
    row2.appendChild(look); row2.appendChild(test);
    c.appendChild(row2);
    grid.appendChild(c);
    host.appendChild(grid);
  });
  explainWhatWasDrawn($('pane-siem'));
}
PANE_LOAD.siem = loadSiem;
}());
