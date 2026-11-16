/* pane-logs.js - Settings → Logs and state (1.6.1), as otp's drawLogs: the card of this server - the
   disk the files are on, every file fake-igd writes and how big - above the settings. */
(function () {
  'use strict';
  var LS = {d: null};
  function load() {
    api('upnp-logs').then(function (d) { LS.d = d; draw(); }).catch(oops);
  }
  function draw(live) {
    var real = $('ls-host');
    if (!real || !LS.d) return;
    var P = IGDP;
    P.letGo(real);
    liveFill(real, function (host) {
      var d = LS.d;
      var worst = (d.disks || []).reduce(function (m, dk) { return Math.max(m, dk.pct || 0); }, 0);
      var missing = (d.files || []).filter(function (f) { return !f.there && /log/.test(f.what); });
      var grid = P.grid();
      var c = P.card(d, worst >= 95 || missing.length ? 'bad' : (worst >= 85 ? 'warn' : 'ok'),
                     missing.length ? 'a log is missing' : (worst >= 95 ? 'the disk is full' : 'as set'),
                     missing.length || worst >= 95 ? 'crit' : (worst >= 85 ? 'warn' : 'ok'));
      P.big(c, num(worst) + ' %', (d.disks || []).length > 1 ? 'the fullest disk' : 'of the disk used');
      (d.disks || []).forEach(function (dk) {
        var row = el('div', 'al-disk');
        var lab = el('div', 'al-disk-l');
        lab.appendChild(noI18n(el('span', 'mono', dk.path)));
        lab.appendChild(el('span', 'muted small', bytes(dk.free) + ' free of ' + bytes(dk.total)));
        row.appendChild(lab);
        row.appendChild(P.bar(dk.pct, dk.pct >= 95 ? 'bad' : (dk.pct >= 85 ? 'warn' : 'good'), num(dk.pct) + ' %'));
        c.appendChild(row);
      });
      var f = {};
      (d.files || []).forEach(function (x) { f[x.what] = x; });
      var sz = function (x) {
        if (!x) return '';
        if (!x.there) return 'not there';
        return bytes(x.size || 0) + (x.lines !== null && x.lines !== undefined ? ' · ' + num(x.lines) + ' lines' : '');
      };
      c.appendChild(P.facts([
        ['The main log', sz(f['The main log'])],
        ['The request log', sz(f['The request log'])],
        ['Rotated', d.rotated.count ? num(d.rotated.count) + ' file(s) · ' + bytes(d.rotated.size) : 'none yet'],
        ['The state folder', d.state.size === null ? 'not there' : bytes(d.state.size) + ' · ' + num(d.state.files) + ' file(s)'],
        ['The database', sz(f['The database'])],
        ['Log level', d.level || '', true],
        ['logrotate', d.logrotate ? 'daily (Disks and logs)' : 'not set up'],
        ['Read', ago(d.at)]
      ]));
      var row2 = el('div', 'btnrow');
      var again = cmdButton('Look again', 'refresh', 'small');
      again.onclick = function () { busy(again, true); api('upnp-logs').then(function (x) { LS.d = x; draw(); }).catch(oops).then(function () { busy(again, false); }); };
      row2.appendChild(again);
      var lg = cmdButton('The log', 'log', 'small');
      explain(lg, 'fake-igd\'s own log, followed as it is written (the tab Log).');
      lg.onclick = function () { showTab('log'); };
      row2.appendChild(lg);
      if ($('pane-disks')) {
        var dk = cmdButton('Disks and logs', 'chart', 'small');
        explain(dk, 'How long the logs are kept, and how much the system journal may take.');
        dk.onclick = function () { showPane('disks'); };
        row2.appendChild(dk);
      }
      c.appendChild(row2);
      grid.appendChild(c);
      /* Every file, where it is (the settings below say where; this says what is there). */
      var fc = el('div', 'card ntp-node');
      var fh = el('div', 'pw-head');
      fh.appendChild(el('b', '', 'The files'));
      fc.appendChild(fh);
      fc.appendChild(listTable(['What', 'Where', 'Size', 'Written'], d.files || [], function (x) {
        var tr = el('tr');
        var w = el('td', '', x.what);
        if (x.says) explain(w, x.says);
        tr.appendChild(w);
        tr.appendChild(noI18n(el('td', 'mono small', x.path)));
        tr.appendChild(el('td', 'num ' + (x.there ? '' : 'bad'), x.there ? bytes(x.size || 0) : 'not there'));
        tr.appendChild(el('td', 'muted small', x.at ? ago(x.at) : '–'));
        return tr;
      }, 'plain'));
      grid.appendChild(fc);
      host.appendChild(grid);
    }, live, function () { explainWhatWasDrawn(real); });
  }
  PANE_LOAD.logs = load;
  PANE_TICK.logs = function () {
    api('upnp-logs').then(function (d) { LS.d = d; draw(true); }).catch(function () {});
  };
})();
