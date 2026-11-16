/* pane-alerts.js - Settings → Alerts and reports (otp's loadAlerts, drawAlerts, alLog). */
(function () {
'use strict';

var AL = {d: null};
function upBar(pc, kind, words, wide) {
  var box = el('div', 'going up-bar' + (wide ? ' wide' : '') + (kind ? ' ' + kind : ''));
  var bar = el('div', 'bar');
  var fill = el('span', '');
  fill.style.width = Math.max(0, Math.min(100, pc)) + '%';
  bar.appendChild(fill);
  box.appendChild(bar);
  if (words) box.appendChild(wide ? el('div', 'says', words) : noI18n(el('div', 'says', words)));
  return box;
}
function liveLetGo(host) {
  if (!host || host._letGo) return;
  host._letGo = true;
  host.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('button') : null;
    if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
  });
}

function loadAlerts() {
  api('alerts').then(function (d) { AL.d = d; drawAlerts(); }).catch(oops);
}
function alAct(action, extra, b) {
  if (b) busy(b, true);
  var q = {action: action};
  Object.keys(extra || {}).forEach(function (k) { q[k] = extra[k]; });
  return api('alerts', q).then(function (x) {
    if (b) busy(b, false);
    if (x.message) toast(x.message, 'good');
    if (x.problems) { AL.d = x; drawAlerts(); }
    return x;
  }).catch(function (e) { if (b) busy(b, false); oops(e); });
}
function drawAlerts() {
  var real = $('al-host');
  if (!real || !AL.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = AL.d, probs = d.problems || [];
    if (!d.mail) host.appendChild(el('p', 'note warn', 'Sending mail is off - Settings → Mail. Neither the alerts nor the report can go until it is on.'));
    /* What is wrong now. */
    var c = el('div', 'card full');
    var h = el('h2', '', 'What is wrong now');
    var tl = el('span', 'right');
    var look = cmdButton('Look again', 'refresh', 'small');
    look.onclick = function () { alAct('check', {}, look); };
    var test = cmdButton('Send a test alert', 'mail', 'small');
    explain(test, 'A mail to the addresses below, with what is wrong now - to see that the alerts arrive and how they look.');
    test.disabled = !ADMIN || !d.mail || !(d.to || []).length;
    test.onclick = function () { alAct('test', {}, test); };
    tl.appendChild(look); tl.appendChild(test);
    h.appendChild(tl);
    c.appendChild(h);
    if (!probs.length) {
      var ok = el('div', 'al-ok');
      ok.appendChild(el('span', 'dot ok'));
      ok.appendChild(el('span', '', 'Nothing - fake-igd.service, avahi-daemon, the disks and the certificate are as they should be.'));
      c.appendChild(ok);
    } else {
      var list = el('div', 'al-list');
      probs.forEach(function (p) {
        var it = el('div', 'al-item ' + (p.level === 'bad' ? 'bad' : 'warn'));
        var top = el('div', 'al-top');
        top.appendChild(el('span', 'tag ' + (p.level === 'bad' ? 'crit' : 'warn'), p.level === 'bad' ? 'down' : 'warning'));
        top.appendChild(noI18n(el('b', '', p.title)));
        if (p.sent) top.appendChild(el('span', 'tag info', 'mailed'));
        it.appendChild(top);
        it.appendChild(noI18n(el('div', 'al-said', p.said)));
        var foot = el('div', 'al-foot muted small');
        foot.appendChild(el('span', '', p.since ? 'since ' + ago(p.since) : 'just seen'));
        if (p.pane && $('pane-' + p.pane)) {
          var go = el('a', '', 'Open it →');
          go.href = '#settings/' + p.pane;
          go.onclick = function (e) { e.preventDefault(); showPane(p.pane); };
          foot.appendChild(go);
        }
        it.appendChild(foot);
        list.appendChild(it);
      });
      c.appendChild(list);
    }
    c.appendChild(el('p', 'muted small', (d.on ? 'The alerts are on' : 'The alerts are off - switch them on below') + (d.checked ? ' · looked ' + ago(d.checked) : '') + ' · ' + ((d.to || []).length ? 'to ' + d.to.join(', ') : 'no address yet')));
    host.appendChild(c);
    /* This machine's disks, and the certificate. */
    var grid = el('div', 'pw-grid');
    var nc = el('div', 'card pw-node');
    var hd = el('div', 'pw-head');
    hd.appendChild(el('span', 'dot ok'));
    hd.appendChild(noI18n(el('b', '', d.node || '')));
    hd.appendChild(el('span', 'tag dim', 'disks'));
    nc.appendChild(hd);
    (d.disks || []).forEach(function (dk) {
      var row = el('div', 'al-disk');
      var lab = el('div', 'al-disk-l');
      lab.appendChild(noI18n(el('span', 'mono', dk.path)));
      lab.appendChild(el('span', 'muted small', bytes(dk.free) + ' free of ' + bytes(dk.total)));
      row.appendChild(lab);
      row.appendChild(upBar(dk.pct, dk.pct >= 95 ? 'bad' : (dk.pct >= 85 ? 'warn' : 'good'), num(dk.pct) + ' %'));
      nc.appendChild(row);
    });
    if (!(d.disks || []).length) nc.appendChild(el('p', 'muted small', 'Not read.'));
    grid.appendChild(nc);
    var cc = el('div', 'card pw-node');
    var ch = el('div', 'pw-head');
    var crt = d.cert || {};
    var days = crt.until ? (crt.until - Date.now() / 1000) / 86400 : null;
    ch.appendChild(el('span', 'dot ' + (days === null ? 'bad' : (days < 3 ? 'bad' : (days < 21 ? 'warn' : 'ok')))));
    ch.appendChild(el('b', '', 'The pages\' certificate'));
    ch.appendChild(el('span', 'tag dim', 'nginx'));
    cc.appendChild(ch);
    if (crt.until) {
      var row2 = el('div', 'al-disk');
      var lab2 = el('div', 'al-disk-l');
      lab2.appendChild(noI18n(el('span', 'mono', crt.file || '')));
      lab2.appendChild(el('span', 'muted small', 'good until ' + stamp(crt.until)));
      row2.appendChild(lab2);
      row2.appendChild(upBar(Math.max(0, Math.min(100, 100 * days / 90)), days < 3 ? 'bad' : (days < 21 ? 'warn' : 'good'),
                             days < 0 ? 'run out' : num(Math.floor(days)) + ' day(s) left'));
      cc.appendChild(row2);
    } else {
      /* As the disk beside it: the file, and under it why it is not read (a Python tuple's words made plain). */
      var lab3 = el('div', 'al-disk-l');
      lab3.appendChild(noI18n(el('span', 'mono', crt.file || '–')));
      var why = String(crt.error || 'not read').replace(/^\(\s*["']?|["']?\s*,?\s*\)$/g, '');
      lab3.appendChild(noI18n(el('span', 'small bad', 'not read: ' + why.charAt(0).toLowerCase() + why.slice(1))));
      cc.appendChild(lab3);
    }
    grid.appendChild(cc);
    host.appendChild(grid);
    /* The report. */
    var rc = el('div', 'card full');
    rc.appendChild(el('h2', '', 'The report'));
    var r = d.report || {};
    rc.appendChild(el('p', 'note', 'The last period ended: ' + alDay(r.since) + ' – ' + alDay(r.until - 1) + (r.sent ? ' · its report went' : '') + '. '
      + (d.report_on ? '' : 'The report is off - switch it on below. ')
      + ((d.report_to || []).length ? 'It goes to ' + d.report_to.join(', ') + '.' : 'No address to send it to yet.')));
    var row = el('div', 'btnrow');
    var pv = cmdButton('Look at it', 'eye', '');
    explain(pv, 'The report of the last period as the mail will look, here - nothing is sent.');
    pv.onclick = function () { alPreview('last', pv); };
    var pn = cmdButton('So far', 'eye', '');
    explain(pn, 'The period going on now, up to this moment.');
    pn.onclick = function () { alPreview('now', pn); };
    var sn = cmdButton('Send it now', 'mail', 'primary');
    sn.disabled = !ADMIN || !d.mail || !(d.report_to || []).length;
    sn.onclick = function () { confirmThen('Send the report', 'The report of the last period goes now to ' + htmlText((d.report_to || []).join(', ')) + '.', 'Send it', function () { alAct('report', {period: 'last'}, sn); }, false); };
    row.appendChild(pv); row.appendChild(pn); row.appendChild(sn);
    rc.appendChild(row);
    host.appendChild(rc);
  });
  alLog();
  explainWhatWasDrawn($('pane-alerts'));
}
function alDay(t) { return t ? new Date(t * 1000).toLocaleDateString() : '–'; }
function alPreview(period, b) {
  if (!ADMIN) { toast('this account may look, not change (read only)', 'bad'); return; }
  if (b) busy(b, true);
  api('alerts', {action: 'preview', period: period}).then(function (x) {
    modal(x.subject, function (body) {
      var f = el('iframe', 'al-frame');
      f.setAttribute('sandbox', '');
      f.setAttribute('title', x.subject);
      f.srcdoc = x.html;
      body.appendChild(f);
    }, [{words: 'Close', close: true}], 'al-report');
  }).catch(oops).then(function () { if (b) busy(b, false); });
}
function alLog() {
  var real = $('al-log');
  if (!real || !AL.d) return;
  liveFill(real, function (host) {
    var log = AL.d.log || [];
    if (!log.length) return;
    var c = el('div', 'card full');
    var h = el('h2', '', 'Mails sent');
    var tl = el('span', 'right');
    var fg = cmdButton('Forget the list', 'forget', 'small');
    fg.disabled = !ADMIN;
    fg.onclick = function () { alAct('forget', {}, fg); };
    tl.appendChild(fg); h.appendChild(tl);
    c.appendChild(h);
    var KIND = {alert: ['alert', 'warn'], report: ['report', 'info'], test: ['test', 'dim']};
    c.appendChild(listTable(['When', 'What', 'Subject', 'To', ''], log, function (e) {
      var tr = el('tr');
      tr.appendChild(el('td', 'muted', ago(e.at)));
      var k = KIND[e.kind] || ['mail', 'dim'];
      var t = el('td'); t.appendChild(el('span', 'tag ' + k[1], k[0])); tr.appendChild(t);
      tr.appendChild(noI18n(el('td', 'small', e.subject || '')));
      tr.appendChild(noI18n(el('td', 'small', (e.to || []).join(', '))));
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (e.ok ? 'ok' : (e.queued === 'waiting' ? 'warn' : 'crit')), e.ok ? 'sent' : (e.queued === 'waiting' ? 'waiting' : 'not sent')));
      if (!e.ok && e.said) explain(st, e.said);
      tr.appendChild(st);
      return tr;
    }, 'plain', {own: true}));
    host.appendChild(c);
  });
}
PANE_LOAD.alerts = loadAlerts;
}());
