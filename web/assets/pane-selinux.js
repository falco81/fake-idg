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
  tl.appendChild(look);
  /* The report, made by root and taken as one file (otp 1.0.236): what whoever writes fake-igd's
     module needs - nothing is changed to make it. */
  var rep = cmdButton('Download the report', 'download', 'small');
  rep.onclick = function () { seReport(rep); };
  tl.appendChild(rep);
  h.appendChild(tl);
  c.appendChild(h);
  if (SE.rep) c.appendChild(el('p', 'note small se-rep' + (SE.rep.bad ? ' bad' : ''), SE.rep.words));
  c.appendChild(el('p', 'note', 'What SELinux refuses to the web server, sshd, chronyd, avahi and the rest when it is enforcing - and what fake-igd needs of it on this server. Nothing changes here unless asked: disabled stays disabled. On the server: sudo upnp selinux check.'));
  var grid = el('div', 'se-grid');
  (SE.d.nodes || []).forEach(function (n) { grid.appendChild(seNode(n)); });
  c.appendChild(grid);
  host.appendChild(c);
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
    if ((d.groups || []).length) {
      var det = el('details', 'se-avc');
      det.appendChild(el('summary', '', 'What was refused (' + num(d.groups.length) + ')'));
      var t = el('table', 'se-avc-t');
      d.groups.forEach(function (g) {
        var tr = el('tr', '');
        tr.appendChild(el('td', 'num', num(g.count) + '×'));
        tr.appendChild(noI18n(el('td', 'mono small', g.source + ' → ' + g.target + ' ' + g['class'] + ' { ' + g.perms + ' }')));
        tr.appendChild(noI18n(el('td', 'mono small muted', g.what || '')));
        t.appendChild(tr);
      });
      det.appendChild(t);
      box.appendChild(det);
    }
    var probs = s.problems || [];
    /* Refused, and nothing fake-igd knows to put in (1.0.237): "Put in what fake-igd needs" changes
       nothing then - the report is what tells how. */
    var known = s.module !== false && !(s.labels || []).some(function (x) { return x.ok === false; }) &&
      !(s.booleans || []).some(function (x) { return x.on === false; }) &&
      !(s.ports || []).some(function (x) { return x.labelled === false; });
    if (d.total && known) {
      var hint = el('div', 'se-verdict bad');
      hint.appendChild(el('b', '', 'fake-igd does not know this one yet'));
      hint.appendChild(el('span', 'small', 'Everything fake-igd knows it needs is in place - what was refused is something its module does not cover yet. "Put in what fake-igd needs" changes nothing for it: download the report (top right) and send it, so that the module learns it.'));
      box.appendChild(hint);
    }
    var verdict = el('div', 'se-verdict ' + (m === 'Enforcing' && !probs.length ? 'good' : s.ready ? 'ready' : probs.length ? 'bad' : ''));
    verdict.appendChild(el('b', '', m === 'Enforcing' ? (probs.length ? 'Enforcing - but something is not as fake-igd needs it' : 'Enforcing - and everything fake-igd needs is there')
      : s.ready ? 'Ready for enforcing' : 'Not ready for enforcing yet'));
    if (m === 'Permissive' && !s.ready) verdict.appendChild(el('span', 'small', 'Let it run a day or two as it is used - sign-ins, the pages, the PS5 asking for ports, an upgrade - then look again.'));
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
  if (row.childNodes.length) box.appendChild(row);
  return box;
}

PANE_LOAD.selinux = loadSelinux;
window.loadSelinux = loadSelinux;
}());
