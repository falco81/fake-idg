/* pane-disks.js - Settings → Disks and logs (otp's loadLogs / drawLogs, for one machine). */
(function () {
  'use strict';
  var LG = {d: null, poll: null};

  /* otp's nodeGrid, nodeCard, nodeBig, upBar and netFacts - the card of a machine. */
  function nodeGrid() { return el('div', 'pw-grid node-grid'); }
  function nodeCard(n, dot, tag, tagCls) {
    var c = el('div', 'card ntp-node');
    var head = el('div', 'pw-head');
    head.appendChild(el('span', 'dot ' + dot));
    head.appendChild(noI18n(el('b', '', n.node || n.name)));
    if (n.me) head.appendChild(el('span', 'tag info', 'this page'));
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

  function loadLogs() {
    api('disks').then(function (d) { LG.d = d; drawLogs(); follow(d); }).catch(oops);
  }
  PANE_LOAD.disks = loadLogs;
  /* While root has not answered yet, asked again every few seconds - as long as the pane is open. */
  function follow(d) {
    clearTimeout(LG.poll);
    if (!d || !d.waiting) return;
    LG.poll = setTimeout(function () {
      if (TAB !== 'settings' || PANE !== 'disks') return;
      loadLogs();
    }, 3000);
  }
  function rootSays(r) {
    var said = (r && r.said) || [];
    return said.length ? said.join(' · ') : '';
  }
  function drawLogs() {
    var real = $('lg-host');
    if (!real || !LG.d) return;
    liveFill(real, function (host) {
      var d = LG.d, r = d.result || {};
      var grid = nodeGrid();
      var n = {node: (STATUS && STATUS.node) || 'this machine', me: true};
      var state = !r.at ? (d.waiting ? ['warn', 'being put in', 'warn'] : ['dim', 'not asked yet', 'dim'])
        : (r.ok && d.current ? ['ok', 'as set', 'ok'] : (r.ok || d.waiting ? ['warn', 'being put in', 'warn'] : ['bad', 'failed', 'crit']));
      var c = nodeCard(n, state[0], state[1], state[2]);
      var lim = 85;
      var worst = (d.disks || []).reduce(function (m, dk) { return Math.max(m, dk.pct || 0); }, 0);
      nodeBig(c, num(worst) + ' %', 'the fullest disk');
      (d.disks || []).forEach(function (dk) {
        var row = el('div', 'al-disk');
        var lab = el('div', 'al-disk-l');
        lab.appendChild(noI18n(el('span', 'mono', dk.path)));
        lab.appendChild(el('span', 'muted small', bytes(dk.used) + ' used · ' + bytes(dk.free) + ' free of ' + bytes(dk.total)));
        explain(lab, dk.device + ' (' + dk.kind + ')' + (dk.inodes !== null && dk.inodes !== undefined ? ' · ' + num(dk.inodes) + ' % of its inodes used' : ''));
        row.appendChild(lab);
        row.appendChild(upBar(dk.pct, dk.pct >= 95 ? 'bad' : (dk.pct >= lim ? 'warn' : 'good'), num(dk.pct) + ' %'));
        c.appendChild(row);
      });
      c.appendChild(netFacts([
        ['The system journal', r.journal_use === null || r.journal_use === undefined ? '' : bytes(r.journal_use)],
        ['Its limit', r.journal_conf ? (r.journal_conf.match(/^(SystemMaxUse|MaxRetentionSec)=.*$/mg) || []).join(', ') : (r.at ? 'as the system has it' : '')],
        ['fake-igd’s logs', bytes(d.logdir_bytes)],
        ['logrotate', r.rotate_conf ? r.rotate_conf.split('\n').join(', ') : ''],
        ['fake-igd’s data', bytes(d.state_bytes)],
        ['Asked', r.at ? ago(r.at) : '']
      ]));
      var words = rootSays(r);
      if (words && r.at && !r.ok) c.appendChild(noI18n(el('div', 'si-said small', words)));
      if (ADMIN) {
        var row2 = el('div', 'btnrow');
        var again = cmdButton('Put in and look again', 'refresh', 'small');
        explain(again, 'Root puts the settings below in again and says how much the journal and the logs take.');
        again.onclick = function () { act(again, 'refresh', 'Asked of root'); };
        row2.appendChild(again);
        var rot = cmdButton('Rotate the logs now', 'archive', 'small');
        explain(rot, 'logrotate puts fake-igd’s logs aside now, rather than at their turn - the oldest past the number kept go.');
        rot.onclick = function () {
          confirmThen('Rotate fake-igd’s logs now?', 'The logs being written are put aside and new ones started; of the old ones only as many as the settings keep stay.', 'Rotate them', function () { act(rot, 'rotate', 'Asked of root'); }, false);
        };
        row2.appendChild(rot);
        var vac = cmdButton('Shrink the journal now', 'broom', 'small');
        explain(vac, 'The system journal brought down to the limits set below at once (journalctl --vacuum-size / --vacuum-time) - otherwise journald does it as it writes.');
        vac.disabled = !(d.want.journal_mb || d.want.journal_days);
        vac.onclick = function () {
          confirmThen('Shrink the system journal now?', 'What is over the limits set below is deleted from the journal now - for every service of this machine, not only fake-igd.', 'Shrink it', function () { act(vac, 'vacuum', 'Asked of root'); });
        };
        row2.appendChild(vac);
        c.appendChild(row2);
      }
      grid.appendChild(c);
      host.appendChild(grid);
    }, false, function () { explainWhatWasDrawn(real); });
    drawFiles();
  }
  function act(button, what, words) {
    busy(button, true);
    api('disks', {action: what}).then(function (x) {
      busy(button, false); LG.d = x; drawLogs(); follow(x); toast(words, 'good');
    }).catch(function (e) { busy(button, false); oops(e); });
  }
  function drawFiles() {
    var host = $('lg-files'), d = LG.d;
    if (!host) return;
    clear(host);
    $('lg-logdir').textContent = d.logdir + ' · ' + bytes(d.logdir_bytes);
    host.appendChild(listTable(['File', {words: 'Size', cls: 'num'}, 'Written'], d.logs || [], function (f) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', f.name)));
      tr.appendChild(el('td', 'num', bytes(f.bytes)));
      tr.appendChild(stampCell(f.at));
      return tr;
    }, 'plain|Nothing in the folder', {own: true}));
  }
  PANE_TICK.disks = function () { /* the sizes move slowly - asked again when the pane is opened */ };
}());
