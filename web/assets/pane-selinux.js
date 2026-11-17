(function () {
'use strict';

/* pane-selinux.js - Settings → SELinux (1.7.7): otp's SELinux card (Settings → High security, otp 1.0.233 -
   1.0.270), drawn as otp draws it, for one server.
   A card a node: the mode now and after a restart, what fake-igd needs of it (its module, the
   labels of its files, booleans, ports) and what SELinux refused since the machine started.
   The steps - made ready and permissive, enforcing, permissive again - are asked of that
   node and done by its root helper; nothing happens by itself. */
var SE = {d: null, poll: null};
function loadSelinux() {
  if (!$('se-host')) return;
  api('selinux').then(function (d) { SE.d = d; drawSelinux(); sePoll(seBusy(d)); }).catch(function (e) {
    var host = $('se-host');
    if (host) { clear(host); host.appendChild(el('p', 'note bad', String((e && e.message) || e))); }
  });
}
function seReport(btn) {
  /* A report new since the ask, by each node's own clock (1.0.252): the browser's against the
     node's, a PC a few seconds fast waited the whole 3 minutes - and for a node not asked too. */
  var end = Date.now() + 180000, before = {}, skip = [];
  Object.keys((SE.d && SE.d.reports) || {}).forEach(function (n) { before[n] = Number((SE.d.reports[n] || {}).at) || 0; });
  busy(btn, true);
  SE.rep = {words: 'asking for the report…'};
  drawSelinux();
  api('selinux', {action: 'report', node: '*'}).then(function (r) {
    skip = (r && r.busy) || [];
    return new Promise(function (done) {
      (function tick() {
        api('selinux').then(function (d) {
          SE.d = d;
          var nodes = (d.nodes || []).map(function (n) { return n.name; }).filter(function (n) { return skip.indexOf(n) < 0; });
          var reps = d.reports || {};
          var ready = nodes.filter(function (n) { return reps[n] && Number(reps[n].at) > (before[n] || 0); });
          SE.rep = {words: 'reports made: ' + ready.length + ' of ' + nodes.length + (ready.length < nodes.length ? ' - waiting for ' + nodes.filter(function (n) { return ready.indexOf(n) < 0; }).join(', ') : '')};
          drawSelinux();
          if (ready.length >= nodes.length || Date.now() > end) return done();
          setTimeout(tick, 3000);
        }).catch(function () { setTimeout(tick, 3000); });
      })();
    });
  }).then(function () {
    return api('selinux', {action: 'download'});
  }).then(function (x) {
    var bin = atob(x.file), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([bytes], {type: x.mime || 'application/gzip'}));
    a.download = x.name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    SE.rep = (x.missing || []).length ? {words: 'Downloaded - without: ' + x.missing.join('; '), bad: true}
                                      : {words: 'Downloaded.'};
    drawSelinux();
  }).catch(function (e) { SE.rep = {words: String((e && e.message) || e), bad: true}; drawSelinux(); oops(e); })
    .then(function () { busy(btn, false); });
}
function seBusy(d) {
  /* A node not said yet is waited for three minutes at most, one that said an error not at all
     (1.0.270): a node away kept the page asking every 2 s for as long as it was open. */
  if (!SE.firstAt) SE.firstAt = Date.now();
  var fresh = Date.now() - SE.firstAt < 180000;
  return ((d && d.nodes) || []).some(function (n) {
    return !!n.pending || (fresh && !n.error && !(n.state && n.state.mode));
  });
}
function sePoll(on) {
  if (on && !SE.poll) SE.poll = setInterval(function () {
    if (TAB !== 'settings' || PANE !== 'selinux') { sePoll(false); return; }
    api('selinux').then(function (d) { SE.d = d; drawSelinux(); if (!seBusy(d)) sePoll(false); }).catch(function () {});
  }, 2000);
  if (!on && SE.poll) { clearInterval(SE.poll); SE.poll = null; }
}
function seAsk(n, action) {
  return api('selinux', {node: n.name, action: action}).then(function (r) {
    toast(r.message, 'good');
    setTimeout(loadSelinux, 800);
  }).catch(oops);
}
function seModeWords(m) {
  return {Enforcing: 'enforcing', Permissive: 'permissive', Disabled: 'disabled', absent: 'not on this machine'}[m] || 'not said yet';
}
function seRow(list, good, words, more) {
  var r = el('div', 'se-row');
  r.appendChild(el('span', 'dot ' + (good === true ? 'ok' : good === false ? 'bad' : 'warn')));
  var t = el('div', 'se-row-t');
  t.appendChild(el('span', '', words));
  if (more) t.appendChild(more);
  r.appendChild(t);
  list.appendChild(r);
}
function drawSelinux() {
  var host = $('se-host');
  if (!host || !SE.d) return;
  clear(host);
  var c = el('div', 'card full se-card');
  var h = el('h2', '', 'SELinux');
  var tl = el('span', 'right');
  var look = cmdButton('Look again', 'refresh', 'small');
  look.onclick = function () {
    busy(look, true);
    Promise.all((SE.d.nodes || []).map(function (n) { return api('selinux', {node: n.name, action: 'check'}); }))
      .then(function () { setTimeout(loadSelinux, 800); }).catch(oops).then(function () { busy(look, false); });
  };
  if (ADMIN) tl.appendChild(look);
  /* The report, made by root and taken as one file (otp 1.0.236): what whoever writes fake-igd's
     module needs - nothing is changed to make it. */
  var rep = cmdButton('Download the report', 'download', 'small');
  rep.onclick = function () { seReport(rep); };
  if (ADMIN) tl.appendChild(rep);
  h.appendChild(tl);
  c.appendChild(h);
  if (SE.rep) c.appendChild(el('p', 'note small se-rep' + (SE.rep.bad ? ' bad' : ''), SE.rep.words));
  c.appendChild(el('p', 'note', 'What SELinux refuses to the web server, sshd, chronyd, avahi and the rest when it is enforcing - and what fake-igd needs of it on this server. Nothing changes here unless asked: disabled stays disabled. On the server: sudo upnp selinux check.'));
  var grid = el('div', 'se-grid');
  (SE.d.nodes || []).forEach(function (n) { grid.appendChild(seNode(n)); });
  c.appendChild(grid);
  host.appendChild(c);
}
/* ---- What SELinux refuses, found out and put right (1.7.10) ------------------------------------
   Every refusal since the machine started, grouped by what puts it right - a boolean, a label, a port,
   a rule of fake-igd's own local module - or why it is not put right here (not for a button, not
   fake-igd's). Root finds them; the page only names which of root's findings to put right. */
var SE_FIXABLE = ['boolean', 'label', 'port', 'rule'];
var SE_KINDS = [
  ['boolean', 'A boolean', 'A switch of the policy allows it - setsebool, as the policy itself offers it.', 'ok'],
  ['label', 'A label', 'The file is not labelled as the policy says it should be - restorecon puts it right.', 'ok'],
  ['port', 'A port', 'A port with no type of its own - given the type of the program that uses it.', 'ok'],
  ['rule', 'A rule of fake-igd\'s', 'Nothing of the policy allows it: exactly this, and nothing more, goes into fake-igd\'s own local module (fake_igd_local).', 'warn'],
  ['unsafe', 'Not for a button', 'fake-igd\'s, but what it would take is too much to allow from here - each says why, and what an admin could look at.', 'bad'],
  ['foreign', 'Not fake-igd\'s', 'Other programs of this machine - shown, never put right here.', 'muted']
];
SE.sel = SE.sel || {};
function seWhat(f) {
  return f.path || (f.port ? 'port ' + f.port + '/' + (f.proto || 'tcp') : '') || f.name || '';
}
function seFindingRow(f, n, fixed) {
  var fixable = SE_FIXABLE.indexOf(f.kind) >= 0 && ADMIN && !fixed;
  var row = el(fixable ? 'label' : 'div', 'se-f se-f-' + f.kind + (fixed ? ' se-f-fixed' : ''));
  if (fixable) {
    var cb = el('input');
    cb.type = 'checkbox';
    cb.checked = SE.sel[f.id] !== false;
    cb.disabled = !!n.pending;
    cb.onchange = function () { SE.sel[f.id] = cb.checked; seCount(); };
    cb.dataset.fid = f.id;
    row.appendChild(cb);
  } else {
    var mark = el('span', 'se-f-mark');
    mark.innerHTML = iconMarkup(fixed ? 'check' : (f.kind === 'foreign' ? 'ban' : (SE_FIXABLE.indexOf(f.kind) >= 0 ? 'shield' : 'cancel')), 16);
    row.appendChild(mark);
  }
  var main = el('div', 'se-f-main');
  var top = el('div', 'se-f-top');
  top.appendChild(noI18n(el('b', 'se-f-prog', f.comm || '?')));
  top.appendChild(noI18n(el('span', 'mono se-f-rule', f.source + ' → ' + f.target + '  ' + f['class'] + ' { ' + (f.perms || []).join(' ') + ' }')));
  main.appendChild(top);
  var sub = el('div', 'se-f-sub');
  var w = seWhat(f);
  if (w) sub.appendChild(noI18n(el('span', 'mono', w)));
  sub.appendChild(el('span', '', (f.count > 1 ? num(f.count) + ' times' : 'once') + ', last ' + ago(f.last) + (f.permissive ? ' (permissive: let through, written down)' : '')));
  main.appendChild(sub);
  if (fixed) main.appendChild(el('div', 'se-f-done', 'Put right just now - it goes at the next look'));
  else if (f.fix && f.fix.cmd) {
    var fx = el('div', 'se-f-fix');
    fx.appendChild(el('span', 'se-f-arrow', '→'));
    fx.appendChild(noI18n(el('code', '', f.fix.cmd)));
    main.appendChild(fx);
    if (f.says) main.appendChild(el('div', 'se-f-says', f.says));
  } else if (f.says) main.appendChild(el('div', 'se-f-says', f.says));
  row.appendChild(main);
  var cnt = el('span', 'se-f-count', num(f.count) + '×');
  row.appendChild(cnt);
  return row;
}
function seSelected() {
  var s = (SE.d && SE.d.nodes && SE.d.nodes[0] && SE.d.nodes[0].state) || {};
  return (s.findings || []).filter(function (f) { return SE_FIXABLE.indexOf(f.kind) >= 0 && SE.sel[f.id] !== false; });
}
function seCount() {
  var b = $('se-fix-go');
  if (!b) return;
  var k = seSelected().length;
  b.querySelector('span:last-child').textContent = 'Put in what is selected (' + k + ')';
  b.disabled = !k || b.dataset.pending === '1';
  document.querySelectorAll('.se-kind').forEach(function (g) {
    var all = g.querySelector('.se-kind-all');
    if (!all) return;
    var boxes = g.querySelectorAll('input[data-fid]');
    var on = Array.prototype.filter.call(boxes, function (x) { return x.checked; }).length;
    all.checked = on === boxes.length && on > 0;
    all.indeterminate = on > 0 && on < boxes.length;
  });
}
function seFix(n, btn) {
  var sel = seSelected();
  if (!sel.length) return;
  var list = sel.map(function (f) {
    return '<li><b>' + htmlText({boolean: 'boolean', label: 'label', port: 'port', rule: 'rule'}[f.kind]) + '</b> <code>'
      + htmlText(f.fix.cmd) + '</code><br><span class="muted small">' + htmlText((f.comm || '?') + ': ' + f.source + ' → ' + f.target + ' ' + f['class'] + ' { ' + f.perms.join(' ') + ' }') + '</span></li>';
  }).join('');
  var rules = sel.filter(function (f) { return f.kind === 'rule'; }).length;
  confirmThen('Put in what is selected on ' + n.name + '?',
    'Root does exactly this - nothing else - and looks again at once:<ul class="se-confirm">' + list + '</ul>'
    + (rules ? 'The rules go into fake-igd\'s own local module <code>fake_igd_local</code> - each can be taken away again below. ' : '')
    + 'Every step is written in Events. It works under enforcing too.',
    'Put it in', function () {
      busy(btn, true);
      api('selinux', {node: n.name, action: 'fix', ids: sel.map(function (f) { return f.id; })}).then(function (r) {
        toast(r.message, 'good');
        setTimeout(loadSelinux, 800);
      }).catch(oops).then(function () { busy(btn, false); });
    }, false);
}
function seRuleDrop(n, r, btn) {
  confirmThen('Take the rule away?', 'This rule goes out of fake-igd\'s local module, and the module is put into the policy again:<br><code>'
    + htmlText('(allow ' + r.source + ' ' + r.target + ' (' + r['class'] + ' (' + r.perms.join(' ') + ')))') + '</code><br>What it allowed is refused again from now on (under enforcing) - and shown here again when it is.',
    'Take it away', function () {
      busy(btn, true);
      api('selinux', {node: n.name, action: 'rule_drop', rule: r.id}).then(function (x) {
        toast(x.message, 'good');
        setTimeout(loadSelinux, 800);
      }).catch(oops).then(function () { busy(btn, false); });
    });
}
function seFindings(n, s) {
  var wrap = el('div', 'se-find');
  var all = s.findings || [];
  var fixed = n.fixed || [];
  var head = el('div', 'se-find-head');
  head.appendChild(el('h3', '', 'What SELinux refuses'));
  var d = s.denials || {};
  head.appendChild(el('span', 'muted small', d.since ? 'since fake-igd\'s needs were put in, ' + new Date(d.since * 1000).toLocaleString()
    : 'since the machine started'));
  wrap.appendChild(head);
  if (!all.length && !fixed.length) {
    var calm = el('div', 'se-calm');
    var ic = el('span', 'se-calm-ic');
    ic.innerHTML = iconMarkup('check', 20);
    calm.appendChild(ic);
    var cw = el('div', '');
    cw.appendChild(el('b', '', 'SELinux refused nothing on this server'));
    cw.appendChild(el('span', 'small', d.since ? 'Nothing since fake-igd\'s needs were put in (' + new Date(d.since * 1000).toLocaleString() + ').'
      : 'Nothing since the machine started.' + (d.settled ? ' ' + num(d.settled) + ' refused before is allowed now (a module or a boolean put in since).' : '')));
    calm.appendChild(cw);
    wrap.appendChild(calm);
  }
  if (fixed.length) {
    var gf = el('section', 'se-kind se-kind-fixed');
    var hf = el('div', 'se-kind-head');
    hf.appendChild(el('span', 'dot ok'));
    hf.appendChild(el('b', '', 'Put right just now'));
    hf.appendChild(el('span', 'count', num(fixed.length)));
    gf.appendChild(hf);
    fixed.forEach(function (f) { gf.appendChild(seFindingRow(f, n, true)); });
    wrap.appendChild(gf);
  }
  SE_KINDS.forEach(function (k) {
    var items = all.filter(function (f) { return f.kind === k[0]; });
    if (!items.length) return;
    var g = el(k[0] === 'foreign' ? 'details' : 'section', 'se-kind se-kind-' + k[0]);
    var h = el(k[0] === 'foreign' ? 'summary' : 'div', 'se-kind-head');
    var fixable = SE_FIXABLE.indexOf(k[0]) >= 0 && ADMIN;
    if (fixable) {
      var allBox = el('input', 'se-kind-all');
      allBox.type = 'checkbox';
      allBox.title = 'Select all of them';
      allBox.disabled = !!n.pending;
      allBox.onchange = function () {
        items.forEach(function (f) { SE.sel[f.id] = allBox.checked; });
        g.querySelectorAll('input[data-fid]').forEach(function (x) { x.checked = allBox.checked; });
        seCount();
      };
      h.appendChild(allBox);
    } else h.appendChild(el('span', 'dot ' + (k[3] === 'muted' ? '' : k[3])));
    h.appendChild(el('b', '', k[1]));
    h.appendChild(el('span', 'count', num(items.length)));
    h.appendChild(el('span', 'se-kind-says', k[2]));
    g.appendChild(h);
    items.forEach(function (f) { g.appendChild(seFindingRow(f, n, false)); });
    wrap.appendChild(g);
  });
  if (ADMIN && all.some(function (f) { return SE_FIXABLE.indexOf(f.kind) >= 0; })) {
    var bar = el('div', 'se-fix-bar');
    var go = cmdButton('Put in what is selected (0)', 'shield', 'primary');
    go.id = 'se-fix-go';
    if (n.pending) go.dataset.pending = '1';
    go.onclick = function () { seFix(n, go); };
    bar.appendChild(go);
    bar.appendChild(el('span', 'muted small', n.pending === 'fix' ? 'root is putting it right…' : 'Under enforcing too - nothing has to be switched off for it. What was put right is looked at again at once.'));
    wrap.appendChild(bar);
    setTimeout(seCount, 0);
  }
  var rules = ((s.local || {}).rules) || [];
  if (rules.length) {
    var det = el('details', 'se-local');
    var sm = el('summary', '');
    sm.appendChild(el('b', '', 'fake-igd\'s local rules'));
    sm.appendChild(el('span', 'count', num(rules.length)));
    sm.appendChild(el('span', 'muted small', (s.local.in_policy === false ? ' - the module is NOT in the policy' : ' fake_igd_local, in the policy')));
    det.appendChild(sm);
    rules.forEach(function (r) {
      var row = el('div', 'se-rule');
      var t = el('div', 'se-rule-t');
      t.appendChild(noI18n(el('code', '', '(allow ' + r.source + ' ' + r.target + ' (' + r['class'] + ' (' + r.perms.join(' ') + ')))')));
      t.appendChild(el('span', 'muted small', (r.why || '') + (r.at ? ' - put in ' + new Date(r.at * 1000).toLocaleString() : '') + (r.by ? ' by ' + r.by : '')));
      row.appendChild(t);
      if (ADMIN) {
        var tk = cmdButton('Take it away', 'cancel', 'small');
        tk.disabled = !!n.pending;
        tk.onclick = function () { seRuleDrop(n, r, tk); };
        row.appendChild(tk);
      }
      det.appendChild(row);
    });
    wrap.appendChild(det);
  }
  return wrap;
}
function seNode(n) {
  var s = n.state || {};
  var m = s.mode || '';
  var box = el('div', 'se-node se-' + (m || 'unknown').toLowerCase());
  var head = el('div', 'se-head');
  var nm = el('div', 'se-name');
  nm.appendChild(noI18n(el('b', '', n.name)));
  if (n.me) nm.appendChild(el('span', 'tag info', 'this one'));
  head.appendChild(nm);
  head.appendChild(el('span', 'se-mode', seModeWords(m)));
  box.appendChild(head);
  if (s.config && m !== 'absent' && s.config.toLowerCase() !== (m || '').toLowerCase() && (m !== 'Disabled' || s.relabel_pending))
    box.appendChild(el('p', 'se-next', 'After the next restart of the machine: ' + seModeWords(s.config.charAt(0).toUpperCase() + s.config.slice(1))));
  if (s.relabel_pending) box.appendChild(el('p', 'se-next', 'Every file is labelled at the next start - it takes a few minutes before the machine answers.'));
  if (s.cmdline_off) box.appendChild(el('p', 'note bad small', 'The kernel\'s command line has selinux=0 - it stays off whatever the configuration says.'));
  if (n.pending) {
    var w = el('div', 'se-wait');
    w.appendChild(el('span', 'spin'));
    w.appendChild(el('span', '', {check: 'looking…', prepare: 'making it ready…', enforce: 'switching to enforcing…', permissive: 'switching to permissive…', report: 'making its report…'}[n.pending] || 'asked…'));
    box.appendChild(w);
  }
  if (!m) {
    box.appendChild(el('p', 'muted small', 'Not said yet - the node looks within a minute.'));
    return box;
  }
  if (m === 'absent') {
    box.appendChild(el('p', 'note', 'There is no SELinux on this machine - nothing to do.'));
    return box;
  }
  var made = m === 'Disabled' && /^(permissive|enforcing)$/i.test(s.config || '') && !!s.relabel_pending;
  if (made) {
    var v = el('div', 'se-verdict ready');
    v.appendChild(el('b', '', 'Made ready - waiting for a restart of the machine'));
    v.appendChild(el('span', 'small', 'Restart it when it suits (Settings → Restart and power off). It comes up permissive; then look here again.'));
    box.appendChild(v);
  } else if (m === 'Disabled') {
    if (/^(permissive|enforcing)$/i.test(s.config || '') && !s.cmdline_off)
      box.appendChild(el('p', 'note small', 'The configuration says ' + s.config.toLowerCase() + ', but the kernel does not start SELinux - it is not switched on for it (the kernel\'s command line, or the distribution\'s own step such as selinux-activate).'));
    box.appendChild(el('p', 'note', 'Disabled - fake-igd runs as always. Made ready, it comes up permissive at the next restart of the machine: nothing is refused yet, only written down, and fake-igd\'s own needs are put in. Enforcing comes after, once nothing was refused.'));
  } else {
    var list = el('div', 'se-list');
    seRow(list, s.module === true ? true : s.module === false ? false : null,
          s.module === false ? 'fake-igd\'s module (fake_igd_server) is not installed' : 'fake-igd\'s module (fake_igd_server) installed');
    (s.labels || []).forEach(function (x) {
      seRow(list, x.ok, x.why, noI18n(el('span', 'mono small se-what', x.path + '  ' + (x.label || '?') + (x.ok ? '' : '  →  ' + x.want))));
    });
    (s.booleans || []).forEach(function (x) {
      seRow(list, x.on, x.why, noI18n(el('span', 'mono small se-what', x.name + ' = ' + (x.on ? 'on' : 'off'))));
    });
    (s.ports || []).forEach(function (x) {
      seRow(list, x.labelled, x.why, noI18n(el('span', 'mono small se-what', x.port + '/' + x.proto + '  ' + x.type)));
    });
    var d = s.denials || {};
    seRow(list, d.tool ? !d.total : null, !d.tool ? 'What SELinux refused cannot be read: ausearch is not on this machine (dnf install audit)'
      : d.since ? (d.total ? 'SELinux refused ' + num(d.total) + ' thing(s) since fake-igd\'s needs were put in' : 'Nothing refused since fake-igd\'s needs were put in')
      : d.total ? 'SELinux refused ' + num(d.total) + ' thing(s) since the machine started' : 'Nothing refused since the machine started');
    /* Refused once, allowed by the policy loaded now (1.0.238) - a newer module, a boolean: not counted. */
    /* Upgraded from before 1.0.248 (1.0.249): the old note of when otp's needs were put in is
       not read any more - what was refused since the start counts again, put right or not. */
    if (d.tool && d.since_lost && d.total) list.appendChild(el('p', 'note small', 'After the upgrade these are counted since the machine started again - also what was put right before it: when fake-igd\'s needs were last put in is kept in root\'s folder now, the old note is not read. Not new refusals: they go at the next restart of the machine, or when "Put in what fake-igd needs" changes something.'));
    if (d.tool && d.settled) seRow(list, true, num(d.settled) + ' refused before, allowed now - by a newer fake_igd_server or a boolean put in since; not counted');
    if (s.auditd === false) seRow(list, false, 'auditd does not run - what SELinux refuses is not written down (systemctl enable --now auditd)');
    box.appendChild(list);
    var probs = s.problems || [];
    if (d.tool) box.appendChild(seFindings(n, s));
    var block = (s.findings || []).filter(function (f) { return f.kind !== 'foreign'; });
    var verdict = el('div', 'se-verdict ' + (m === 'Enforcing' && !probs.length ? 'good' : s.ready ? 'ready' : probs.length ? 'bad' : ''));
    verdict.appendChild(el('b', '', m === 'Enforcing' ? (probs.length ? 'Enforcing - but something is not as fake-igd needs it' : 'Enforcing - and everything fake-igd needs is there')
      : s.ready ? 'Ready for enforcing' : 'Not ready for enforcing yet'));
    if (m === 'Permissive' && !s.ready) {
      var fixable = block.filter(function (f) { return SE_FIXABLE.indexOf(f.kind) >= 0; }).length;
      var unsafe = block.filter(function (f) { return f.kind === 'unsafe'; }).length;
      verdict.appendChild(el('span', 'small', (fixable ? fixable + ' thing(s) SELinux refused can be put right here - "Put in what is selected" below. ' : '')
        + (unsafe ? unsafe + ' thing(s) are not for a button - each says why; the report is for whoever looks after fake-igd\'s module. ' : '')
        + 'Let it run a day or two as it is used - sign-ins, the pages, the PS5 asking for ports, an upgrade - then look again.'));
    }
    box.appendChild(verdict);
  }
  if (n.error) box.appendChild(el('p', 'note bad', n.error));
  else if ((n.said || []).length && n.action !== 'check') {
    var sd = el('ul', 'note good small se-said');
    n.said.forEach(function (x) { sd.appendChild(el('li', '', x)); });
    box.appendChild(sd);
  }
  if (n.at) box.appendChild(el('p', 'muted small', 'Looked at ' + new Date(n.at * 1000).toLocaleString()));
  var row = el('div', 'btnrow se-btns');
  if ((m === 'Disabled' && !made) || m === 'Permissive') {
    var prep = cmdButton(m === 'Disabled' ? 'Make it ready (permissive)' : 'Put in what fake-igd needs', 'shield', m === 'Disabled' ? 'primary' : '');
    prep.disabled = !!n.pending;
    prep.onclick = function () {
      confirmThen(m === 'Disabled' ? 'Make SELinux ready on ' + n.name + '?' : 'Put in what fake-igd needs on ' + n.name + '?',
        htmlText(m === 'Disabled'
          ? 'The configuration says permissive and every file is labelled at the next start of the machine; fake-igd\'s module goes in. Nothing is refused while permissive - SELinux only writes down what it would refuse. The machine is not restarted now: restart it when it suits (Settings → Restart and power off).'
          : 'fake-igd\'s module, the labels of its files, the boolean and the ports it needs are put in. Still permissive: nothing is refused.'),
        m === 'Disabled' ? 'Make it ready' : 'Put it in', function () { seAsk(n, 'prepare'); });
    };
    row.appendChild(prep);
  }
  if (m === 'Permissive') {
    var enf = cmdButton('Switch to enforcing', 'lock', s.ready ? 'primary' : '');
    enf.disabled = !!n.pending || !s.ready;
    if (!s.ready) enf.title = 'Once nothing is missing and nothing was refused';
    enf.onclick = function () {
      confirmThen('Switch ' + n.name + ' to enforcing?', htmlText('From now on SELinux refuses what its policy does not allow - and stays enforcing after a restart. Nothing fake-igd needs is missing and nothing was refused since the machine started. If something stops working, "Back to permissive" here (or setenforce 0 on the machine) undoes it at once.'),
        'Switch to enforcing', function () { seAsk(n, 'enforce'); }, true);
    };
    row.appendChild(enf);
  }
  if (m === 'Enforcing') {
    var back = cmdButton('Back to permissive', 'undo', '');
    back.disabled = !!n.pending;
    back.onclick = function () {
      confirmThen('Switch ' + n.name + ' back to permissive?', htmlText('SELinux no longer refuses anything - it only writes down what it would refuse - now and after a restart.'),
        'Back to permissive', function () { seAsk(n, 'permissive'); });
    };
    row.appendChild(back);
  }
  if (row.childNodes.length && ADMIN) box.appendChild(row);
  return box;
}

PANE_LOAD.selinux = loadSelinux;
window.loadSelinux = loadSelinux;
}());
