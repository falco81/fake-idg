/* pane-upgrade.js - Settings → Upgrades (1.6.1): otp's pane-upgrade (admin.js loadUpgrade, drawUpgrade,
   drawUpWeb, drawUpDown, loadAfter, drawAfter, afterBadge), for the one server fake-igd is. */
'use strict';

/* ---- upgrades (otp 1.0.37) ------------------------------------------------------- */
var UP = {timer: null, misses: 0, last: null};
var AFT = {d: null, seen: '', asked: 0, sum: null};
var UP_STATE = {waiting: ['waiting for root', 'dim'], none: ['waiting', 'dim'],
                installing: ['being put in', 'info'], checking: ['checking', 'info'],
                done: ['done', 'ok'], failed: ['failed', 'crit'], cancelled: ['stopped', 'dim']};
/* The version these pages came with: what the script was asked for as. */
var VERSION_LOADED = (function () {
  var sc = document.querySelector('script[src*="admin.js"]');
  var m = sc && /[?&]v=([0-9.]+)/.exec(sc.getAttribute('src') || '');
  return m ? m[1] : '';
}());
/* Is this settings pane the one in front, in a tab in front (otp 1.0.57)? */
function paneLive(name) {
  return TAB === 'settings' && PANE === name && $('pane-' + name) && !$('pane-' + name).hidden;
}
function upgradeAgain(ms) {
  /* Never dropped while the pane is open (otp 1.0.73): in a tab in the background it waits and
     goes on when the tab is shown again. */
  clearTimeout(UP.timer);
  UP.timer = setTimeout(function () {
    if (!paneLive('upgrade')) return;
    if (document.hidden) { UP.sleeping = true; return; }
    loadUpgrade(true);
  }, ms);
}
document.addEventListener('visibilitychange', function () {
  if (!document.hidden && UP.sleeping) { UP.sleeping = false; if (paneLive('upgrade')) loadUpgrade(); }
});
/* The package sent as it is, read here (fake-igd's API takes it in base64). */
function upgradeSend(file) {
  return new Promise(function (ok, bad) {
    var rd = new FileReader();
    rd.onerror = function () { bad(new Error('the file could not be read')); };
    rd.onload = function () { ok(String(rd.result).split(',')[1] || ''); };
    rd.readAsDataURL(file);
  }).then(function (b64) { return api('upgrade-package', {data: b64}, 300); });
}
function upHideBar(go) {
  var row = el('div', 'actions hide-row');
  var b = cmdButton('Hide this', 'close', 'small');
  b.classList.add('hide-this');
  b.onclick = function (e) {
    if (e) e.stopPropagation();
    busy(b, true);
    Promise.resolve(go()).catch(oops).then(function () { busy(b, false); });
  };
  row.appendChild(b);
  return row;
}

/* New versions on the web (otp 1.0.123): what the address had when last asked, and one click to
   put the newest in - and what is new in each, folded (1.6.1). */
function drawUpWeb(d) {
  var w = d.web || {};
  var o = w.online || {};
  liveFill($('up-web'), function (host) {
    var p = el('p', 'note ' + (o.error ? 'bad' : (o.newer ? 'good' : '')));
    if (!o.at) p.textContent = w.check ? 'Not looked at yet - within minutes, or press Look now.' : 'Not looked at: looking every day is switched off below. Look now asks once.';
    else if (o.error) p.textContent = 'Looked ' + ago(o.at) + ': ' + o.error;
    else if (o.newer) p.textContent = 'fake-igd ' + o.newest.version + ' is there - this server runs ' + (o.here || d.version) + ' (looked ' + ago(o.at) + ')';
    else if (o.newest) p.textContent = 'Nothing newer: the newest there is ' + o.newest.version + ' and this server runs ' + (o.here || d.version) + ' (looked ' + ago(o.at) + ')';
    else p.textContent = 'No fake-igd package there (looked ' + ago(o.at) + ')';
    host.appendChild(p);
    if (o.at && !o.error && o.newer && (o.newer_list || []).length > 1) {
      host.appendChild(el('p', 'note', num(o.newer_list.length) + ' versions there are newer than this one - choose which to go to; the newest is chosen.'));
    }
    if (o.url || w.url) host.appendChild(noI18n(el('p', 'mono small muted', o.url || w.url)));
    var row = el('div', 'btnrow');
    var look = cmdButton('Look now', 'refresh', '');
    look.onclick = function () {
      busy(look, true);
      api('upgrade', {action: 'online_look'}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
        .catch(oops).then(function () { busy(look, false); });
    };
    row.appendChild(look);
    var running = !!(d.plan && d.plan.state === 'running');
    var list = (o.newer_list || []).filter(function (x) { return x && x.version; });
    if (o.newer && !running) {
      /* More than one newer there (otp 1.0.142): which one, the newest chosen. */
      var pick = list[0] && list[0].version === o.newest.version ? list[0] : o.newest;
      var choose = null;
      if (list.length > 1) {
        choose = selectBox(list.map(function (x, i) {
          return [x.version, x.version + (i === 0 ? ' (the newest)' : '')];
        }), pick.version);
        explain(choose, 'The versions there newer than the one this server runs. The newest is chosen; any of them can be put in instead.');
        row.appendChild(choose);
      }
      var up = cmdButton('Upgrade to ' + pick.version + ' now', 'play', 'primary');
      var chosen = function () {
        var v = choose ? choose.value : o.newest.version;
        return list.filter(function (x) { return x.version === v; })[0] || o.newest;
      };
      if (choose) {
        choose.onchange = function () {
          setButtonIcon(up, 'play', 'Upgrade to ' + chosen().version + ' now');
        };
      }
      up.onclick = function () {
        var c = chosen();
        confirmThen('Upgrade to fake-igd ' + c.version + '?', htmlText('It is fetched from ' + (c.url || o.url) + ', its signature checked, and '
          + 'this server is upgraded: fake-igd.service and these pages restart once - for a few seconds the PS5 gets no answer, and these pages come back by themselves.'), 'Upgrade', function () {
          busy(up, true);
          api('upgrade', {action: 'online_get', version: c.version, start: true}, 330).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
            .catch(oops).then(function () { busy(up, false); });
        }, false);
      };
      row.appendChild(up);
      var only = cmdButton('Only fetch it', 'down', '');
      explain(only, 'Fetched and checked, and left ready below - put in when Upgrade is pressed.');
      only.onclick = function () {
        busy(only, true);
        api('upgrade', {action: 'online_get', version: chosen().version}, 330).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
          .catch(oops).then(function () { busy(only, false); });
      };
      row.appendChild(only);
    }
    host.appendChild(row);
    /* What is new in each newer version, folded (1.6.1): from the CHANGELOG.md published beside the
       packages, else read out of the package when it is asked for. */
    if (o.newer && list.length) {
      var notes = el('div', '');
      notes.style.marginTop = '10px';
      list.forEach(function (x) {
        var det = el('details', 'fold');
        det.appendChild(el('summary', '', 'What is new in ' + x.version));
        var body = el('div', '');
        det.appendChild(body);
        var fill = function (text, from) {
          clear(body);
          if (from === 'package') body.appendChild(el('p', 'note small', 'Read from the package at the address - it is checked only when it is chosen.'));
          body.appendChild(text ? noI18n(el('pre', 'lines', text)) : el('p', 'note', 'The package says nothing about this version.'));
        };
        if (x.changelog) fill(x.changelog, 'address');
        else {
          det.ontoggle = function () {
            if (!det.open || det._asked) return;
            det._asked = true;
            body.appendChild(el('p', 'note small muted', 'asking for it…'));
            api('upgrade', {action: 'online_changelog', version: x.version}, 150).then(function (r) {
              var c = r.changelog || {};
              fill(c.entry, c.from);
            }).catch(function (e) { det._asked = false; clear(body); body.appendChild(el('p', 'note bad', String((e && e.message) || e))); });
          };
        }
        notes.appendChild(det);
      });
      host.appendChild(notes);
    }
  });
}

/* Going back to an older version (otp 1.0.143): asked for on purpose, in a card of its own - the
   versions at upgrade_url older than this one, each with what stands in its way. */
function upDownConfirm(version, go) {
  confirmThen('Go back to fake-igd ' + version + '?', htmlText('The version running now is replaced by the older ' + version
    + ' - fake-igd.service and these pages restart once. The configuration, the database and the logs stay as they are. What came in the newer versions is gone until you upgrade again.'),
    'Go back', go, true);
}
function upDownChangelog(version) {
  api('upgrade', {action: 'downgrade_changelog', version: version}, 150).then(function (x) {
    var c = x.changelog || {};
    modal('What changed in ' + version, function (body) {
      if (c.from === 'package') body.appendChild(el('p', 'note small', 'Read from the package at the address - it is checked only when it is chosen.'));
      body.appendChild(c.entry ? noI18n(el('pre', 'lines', c.entry)) : el('p', 'note', 'The package says nothing about this version.'));
      if ((c.lost || []).length) {
        var det = el('details', 'fold');
        det.appendChild(el('summary', '', 'What going back gives up: ' + c.lost.length + ' newer version(s), up to ' + c.here));
        c.lost.forEach(function (one) { det.appendChild(noI18n(el('pre', 'lines', one.text))); });
        body.appendChild(det);
      }
    }, [{words: 'Close', close: true}], 'medium');
  }).catch(oops);
}
function drawUpDown(d) {
  var card = $('up-down-card');
  /* Offered only when switched on (otp 1.0.144): Settings → Upgrades. */
  if (card) card.hidden = !(ADMIN && d && d.downgrade_on);
  var host = $('up-down');
  if (!host || host._made || !(d && d.downgrade_on)) return;
  host._made = true;
  var row = el('div', 'btnrow');
  var show = cmdButton('Show the versions to go back to', 'list', '');
  row.appendChild(show);
  host.appendChild(row);
  var list = el('div', '');
  host.appendChild(list);
  show.onclick = function () {
    busy(show, true);
    api('upgrade', {action: 'downgrade_list'}, 90).then(function (x) {
      var g = x.downgrade || {};
      clear(list);
      var at = el('p', 'note small', 'At ' + (g.url || '?') + ' - this server runs ' + (g.here || '') + '; it may go back to ' + (g.lowest || g.floor || '?') + ' or newer.');
      at.style.marginTop = '10px';
      list.appendChild(at);
      var vs = g.versions || [];
      if (!vs.length) { list.appendChild(el('p', 'note', 'No version older than this one is there.')); return; }
      var running = !!((UP.last || {}).plan && UP.last.plan.state === 'running');
      var good = vs.filter(function (v) { return !(v.why || []).length; });
      var bad = vs.filter(function (v) { return (v.why || []).length; });
      /* One row a version, the buttons side by side (otp 1.0.145): the reasons a version is
         refused are said once, folded below - not in every row. */
      var acts = function (v, ok) {
        var cell = el('div', '');
        cell.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-left:auto';
        var notes = cmdButton('What changed', 'list', 'small');
        notes.style.whiteSpace = 'nowrap';
        notes.onclick = function () { upDownChangelog(v.version); };
        cell.appendChild(notes);
        if (ok && !running) {
          var go = cmdButton('Go back to ' + v.version, 'undo', 'small danger');
          go.style.whiteSpace = 'nowrap';
          go.onclick = function () {
            upDownConfirm(v.version, function () {
              busy(go, true);
              api('upgrade', {action: 'downgrade_get', version: v.version, start: true}, 330).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); })
                .catch(oops).then(function () { busy(go, false); });
            });
          };
          cell.appendChild(go);
        }
        return cell;
      };
      var nowrap = function (node) {
        node.style.whiteSpace = 'nowrap';
        Array.prototype.forEach.call(node.querySelectorAll('span'), function (s) { s.style.whiteSpace = 'nowrap'; });
        return node;
      };
      var rows = function (items, ok) {
        var box = el('div', 'dg-rows');
        items.forEach(function (v) {
          var r = el('div', 'dg-row');
          r.style.cssText = 'display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 16px;padding:8px 10px;border-bottom:1px solid var(--line)';
          var left = el('div', '');
          left.style.cssText = 'display:flex;align-items:center;gap:10px;min-width:9em';
          left.appendChild(noI18n(el('b', '', v.version)));
          var tag = nowrap(el('span', ok ? 'tag ok' : 'tag warn', ok ? 'yes' : (v.short || 'no')));
          if (!ok) explain(tag, (v.why || []).join('\n'));
          left.appendChild(tag);
          r.appendChild(left);
          var right = acts(v, ok);
          Array.prototype.forEach.call(right.children, nowrap);
          r.appendChild(right);
          box.appendChild(r);
        });
        return box;
      };
      if (good.length) list.appendChild(rows(good, true));
      else list.appendChild(el('p', 'note', 'No version at the address may be gone back to.'));
      if (bad.length) {
        var det = el('details', 'fold');
        det.style.marginTop = '12px';
        det.appendChild(el('summary', '', bad.length + ' older version(s) it may not go back to' + (g.lowest ? ' - below ' + g.lowest : '')));
        var reasons = [];
        bad.forEach(function (v) { (v.why || []).forEach(function (w) { if (reasons.indexOf(w) < 0) reasons.push(w); }); });
        var why = el('ul', 'note small');
        why.style.margin = '8px 0';
        reasons.forEach(function (w) { why.appendChild(el('li', 'bad', w)); });
        det.appendChild(why);
        det.appendChild(rows(bad, false));
        list.appendChild(det);
      }
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'note bad', String((e && e.message) || e))); })
      .then(function () { busy(show, false); });
  };
}

/* The upgrade as the pages were told it (fake-igd 1.7.2: .upgrade.json, which root's helper and
   install.sh --upgrade write at each step): laid over what the API said last - the API restarting
   does not answer, and install.sh run by hand is one the API never knew of. */
function upFromPages(d, u) {
  if (!d || !u || u.state !== 'running') return d;
  var p = d.plan;
  var same = p && (p.state === 'running' || (u.id && p.id === u.id));
  if (same && !(p.steps || []).length) return d;
  var step = same ? Object.assign({}, p.steps[0]) : {name: d.node || '', asked: u.started, tail: []};
  if (u.parts || u.part) {
    step.state = 'installing';
    step.at = u.at;
    step.part = u.part;
    step.parts = u.parts;
    step.part_words = u.words;
    step.said = 'install.sh --upgrade runs (root)';
  } else if (!same) {
    step.state = 'installing';
    step.at = u.at;
    step.said = u.words || 'root checks the package';
  }
  var plan = same ? Object.assign({}, p) : {id: u.id || '', version: u.version, by: u.by || '', at: u.started,
                                            downgrade: !!u.downgrade, state: 'running'};
  plan.steps = [step];
  return Object.assign({}, d, {plan: plan});
}
function drawUpgrade(d) {
  if (typeof UPG === 'object' && UPG.u) d = upFromPages(d, UPG.u);
  UP.last = d;
  var plan = d.plan;
  var running = !!(plan && plan.state === 'running');
  /* This server (otp's "The nodes", for one). */
  liveFill($('up-nodes'), function (host) {
    host.appendChild(listTable(['Server', 'Version', 'Running since', 'State', ''], d.nodes || [], function (n) {
      var tr = el('tr');
      var nm = el('td');
      nm.appendChild(noI18n(el('b', '', n.name)));
      if (n.me) { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'this page')); }
      tr.appendChild(nm);
      tr.appendChild(noI18n(el('td', 'mono', n.version || '?')));
      var s = STATUS || {};
      var since = s.web && s.web.api_since;
      tr.appendChild(el('td', 'muted', since ? ago(since) : '–'));
      var st = el('td');
      var svc = (s.service || {}).state;
      if (running) st.appendChild(el('span', 'tag warn', 'being upgraded'));
      else if (svc && svc !== 'active') st.appendChild(el('span', 'tag crit', 'not running'));
      else if (s.mode === 'passive') st.appendChild(el('span', 'tag warn', 'listening only'));
      else if (svc === 'active') st.appendChild(el('span', 'tag ok', 'in service'));
      else st.appendChild(el('span', 'tag dim', 'not known'));
      if (running) st.appendChild(el('span', 'sub', 'to ' + plan.version + (plan.by ? ' · ' + plan.by : '') + (plan.at ? ' · ' + ago(plan.at) : '')));
      else if (svc) st.appendChild(el('span', 'sub', 'fake-igd.service ' + svc + (s.mode ? ' · mode ' + s.mode : '')));
      tr.appendChild(st);
      var tools = el('td', 'rowtools');
      if (ADMIN && $('pane-service')) {
        var b = cmdButton('The service', 'router', 'small');
        explain(b, 'Settings → The service: fake-igd.service restarted, and what root last did for these pages.');
        b.onclick = function (ev) { ev.stopPropagation(); showPane('service'); };
        tools.appendChild(b);
      }
      tr.appendChild(tools);
      return tr;
    }, 'plain'));
  });
  drawUpWeb(d);
  /* The package. */
  liveFill($('up-pkg'), function (pk) {
    if (d.package) {
      var p = d.package;
      var box = el('div', 'notice good');
      box.style.marginTop = '12px';
      if (p.downgrade) box.className = 'notice warn';
      box.appendChild(el('b', '', 'fake-igd ' + p.version + (p.downgrade ? ' - older: ready to go back to' : '')));
      box.appendChild(el('div', 'small', 'signed by ' + (p.signed_by || '?') + ' · ' + num(p.files || 0) + ' files · ' + bytes(p.bytes) + ' · '
        + (p.from && /^https:/.test(p.from) ? 'fetched' : 'sent') + ' by ' + (p.by || '?') + ' · ' + ago(p.at)));
      pk.appendChild(box);
      if (p.changelog) {
        var det = el('details', 'fold');
        /* every version since the one running (otp 1.0.262), when there is more than one */
        var several = (p.changelog.match(/^## /mg) || []).length > 1;
        det.appendChild(el('summary', '', several && p.since ? 'What changed since ' + p.since : 'What changed in ' + p.version));
        det.appendChild(noI18n(el('pre', 'lines', p.changelog)));
        pk.appendChild(det);
      }
    }
  });
  $('up-forget').hidden = !d.package || running;
  $('up-start').disabled = !d.package || !d.ready || running;
  var down = !!(d.package && d.package.downgrade);
  setButtonIcon($('up-start'), down ? 'undo' : 'play', down ? 'Go back on this server' : 'Upgrade this server');
  $('up-start').classList.toggle('danger', down);
  $('up-start').classList.toggle('primary', !down);
  drawUpDown(d);
  var rd = $('up-ready');
  clear(rd);
  if (d.package && !d.ready && !running) {
    (d.not_ready || []).forEach(function (w) { rd.appendChild(el('p', 'note bad', w)); });
  }
  if (!d.helper || !d.path_unit) {
    rd.appendChild(el('p', 'note bad', 'This server cannot put a version in by itself yet: ' + (!d.helper ? 'fake_igd_upgrade.py' : 'fake-igd-upgrade.path')
      + ' is not installed. Upgrade it once on the command line (install.sh --upgrade), which puts it in.'));
  }
  /* The plan: one server, its steps as otp's for a node. */
  $('up-plan-card').hidden = !plan;
  liveFill($('up-plan'), function (ph) {
    if (!plan) return;
    ph.appendChild(el('p', 'note', (plan.downgrade ? 'Going back to ' : 'To ') + plan.version + ' · started by ' + (plan.by || '?') + ' · ' + ago(plan.at) + ' · '
      + ({running: 'going on', done: 'done', failed: 'failed', cancelled: 'stopped'})[plan.state]));
    /* How far, as bars (otp 1.0.67): the whole and the server. */
    var steps = plan.steps || [];
    var all = steps.length ? Math.round(steps.reduce(function (m, st) { return m + upPercent(st); }, 0) / steps.length) : 0;
    ph.appendChild(upBar(all, plan.state === 'failed' ? 'bad' : (plan.state === 'done' ? 'good' : ''),
                         num(all) + ' % · ' + steps.filter(function (x) { return x.state === 'done'; }).length + ' of ' + steps.length + ' server(s) done', true));
    var upTable = listTable(['Server', 'Step', 'How far', 'What happened', 'When'], steps, function (st) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', st.name)));
      var w = UP_STATE[st.state] || UP_STATE.waiting;
      var c = el('td');
      c.appendChild(el('span', 'tag ' + w[1], w[0]));
      tr.appendChild(c);
      var pc = upPercent(st);
      var bt = el('td', 'up-how');
      bt.appendChild(upBar(pc, st.state === 'failed' ? 'bad' : (st.state === 'done' ? 'good' : ''),
                           st.state === 'installing' && st.part_words ? num(pc) + ' % · ' + st.part_words : num(pc) + ' %'));
      tr.appendChild(bt);
      var said = el('td', 'small', st.said || '');
      if ((st.tail || []).length) {
        var more = el('details', 'fold');
        more.appendChild(el('summary', '', 'what install.sh said'));
        more.appendChild(noI18n(el('pre', 'lines', st.tail.join('\n'))));
        /* Left open across the redraws every 3 s (otp 1.0.69). */
        UP.tailOpen = UP.tailOpen || {};
        if (UP.tailOpen[st.name]) more.open = true;
        more.ontoggle = function () { UP.tailOpen[st.name] = more.open; };
        said.appendChild(more);
      }
      tr.appendChild(said);
      tr.appendChild(el('td', 'muted', st.at ? ago(st.at) : '–'));
      return tr;
    }, 'plain');
    /* Columns of a fixed width (otp 1.0.69): they jumped about with every redraw. */
    (upTable.querySelector('table') || upTable).classList.add('up-plan-table');
    ph.appendChild(upTable);
    if (plan.state === 'done' && VERSION_LOADED && d.version !== VERSION_LOADED) {
      var r = el('p', 'note good');
      r.appendChild(document.createTextNode('This page is still the one of ' + VERSION_LOADED + '. '));
      var a = el('a', 'fgo', 'Load it again');
      a.onclick = function () { location.reload(); };
      r.appendChild(a);
      ph.appendChild(r);
    }
    if (plan.state !== 'running' && ADMIN) ph.appendChild(upHideBar(function () {
      return api('upgrade', {action: 'hide'}).then(function (x) { drawUpgrade(x); });
    }));
  });
  /* Stop it: only while root has not taken it yet - once install.sh runs, it is finished. */
  $('up-cancel').hidden = !(ADMIN && running && plan.steps && plan.steps[0] && plan.steps[0].state === 'waiting');
  $('up-log-node').textContent = d.node || '';
  var lg = $('up-log');
  var lines = d.log || [];
  lg.textContent = lines.length ? lines.join('\n') : '–';
  noI18n(lg);
  /* Asked again every 3 s while it runs and for two minutes after it ended, every 15 s
     otherwise (otp 1.0.73). */
  if (running) UP.endedAt = 0;
  else if (UP.wasRunning && !UP.endedAt) UP.endedAt = Date.now() / 1000;
  UP.wasRunning = running || (UP.wasRunning && !UP.endedAt);
  upgradeAgain(upRunning() ? 3000 : 15000);
}
/* How far the server is (otp 1.0.67), from its step and how long it has been in it: waiting
   up to 5, install.sh 5-85 by its sections, checking 85-95, done 100. */
function upPercent(st) {
  var now = Date.now() / 1000, since = now - Number(st.at || now);
  switch (st.state) {
    case 'done': return 100;
    case 'failed': return 100;
    case 'cancelled': return 0;
    case 'waiting': return Math.round(Math.min(5, 1 + since / 6));
    case 'installing':
      var parts = Number(st.parts || 0) || 11;
      return Math.round(Math.min(84, 5 + 76 * Math.min(0.97, Number(st.part || 0) / parts) + Math.min(3, since / 30)));
    case 'checking': return Math.round(85 + Math.min(10, since / 3));
    default: return 0;
  }
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
function loadUpgrade(live) {
  /* A short deadline while an upgrade runs (otp 1.0.66): the API answering may be restarting. */
  var running = upRunning();
  clearTimeout(UP.timer);
  var mine = UP.ask = (UP.ask || 0) + 1;
  api('upgrade', undefined, running ? 8 : 0).then(function (d) {
    if (mine !== UP.ask) return;
    UP.misses = 0;
    $('up-retry').textContent = '';
    if (!VERSION_LOADED) VERSION_LOADED = d.version;
    if (live) liveRun(function () { drawUpgrade(d); }); else drawUpgrade(d);
  }).catch(function (e) {
    if (mine !== UP.ask) return;
    /* The API may be the one being restarted: asked again, always (otp 1.0.73). How far the
       upgrade is meanwhile, from the pages' PHP (fake-igd 1.7.2). */
    UP.misses = (UP.misses || 0) + 1;
    if (e.upgrading && UP.last) liveRun(function () { drawUpgrade(upFromPages(UP.last, e.upgrading)); });
    if (running || e.unreachable || UP.misses <= 3) {
      $('up-retry').textContent = 'fake-igd and these pages are restarting with the new version - asking again…';
      upgradeAgain(Math.min(2000 * UP.misses, 6000));
      return;
    }
    oops(e);
    upgradeAgain(15000);
  });
  if (ADMIN) loadAfter();
}
/* Whether an upgrade is under way, as far as this page knows (otp 1.0.73). */
function upRunning() {
  var p = UP.last && UP.last.plan;
  if (!p) return false;
  if (p.state === 'running') return true;
  return Date.now() / 1000 - Number(UP.endedAt || 0) < 120;
}
(function () {
  var box = $('up-drop');
  if (!box) return;
  var sending = false;
  var says = 'Drop the fake-igd-X.Y.Z.tar.gz here, or press to choose it';
  function send(file) {
    if (!file || sending) return;     /* chosen twice: sent once (otp 1.0.94) */
    if (!/\.(tar\.gz|tgz)$/i.test(file.name)) {
      modal('The package was not taken', function (body) {
        body.appendChild(el('p', 'note bad', file.name + ' is not a fake-igd-X.Y.Z.tar.gz'));
      }, null, true);
      return;
    }
    sending = true;
    $('up-drop-says').textContent = 'checking ' + file.name + ' (' + bytes(file.size) + ')…';
    upgradeSend(file).then(function (d) {
      sending = false;
      toast(d.message || 'checked', 'good');
      $('up-drop-says').textContent = says;
      drawUpgrade(d);
    }).catch(function (e) {
      sending = false;
      $('up-drop-says').textContent = says;
      modal('The package was not taken', function (body) {
        body.appendChild(el('p', 'note bad', String(e.message || e)));
      }, null, true);
    });
  }
  box.onclick = function () { $('up-file').click(); };
  $('up-file').onchange = function () { send(this.files && this.files[0]); this.value = ''; };
  ['dragenter', 'dragover'].forEach(function (name) {
    box.addEventListener(name, function (e) { e.preventDefault(); box.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    box.addEventListener(name, function (e) {
      e.preventDefault();
      box.classList.remove('over');
      if (name === 'drop' && e.dataTransfer && e.dataTransfer.files) send(e.dataTransfer.files[0]);
    });
  });
  $('up-start').onclick = function () {
    var d = UP.last || {};
    var p = d.package || {};
    if (p.downgrade) {
      upDownConfirm(p.version, function () {
        api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      });
      return;
    }
    confirmThen('Upgrade this server to ' + p.version,
      'This server is the only one: while it is put in and restarted - a minute or two - the PS5 gets no answer for a few seconds, and these pages stop answering for a moment.',
      'Upgrade', function () {
        api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      }, true);
  };
  $('up-forget').onclick = function () {
    confirmThen('Throw the package away', 'The package is deleted; send it again, or fetch it again, to upgrade.', 'Throw it away', function () {
      api('upgrade', {action: 'forget'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
    });
  };
  $('up-cancel').onclick = function () {
    confirmThen('Stop the upgrade', 'Root has not taken it yet: it is taken back and nothing is changed. Once install.sh runs, it is finished, not stopped.', 'Stop it', function () {
      api('upgrade', {action: 'cancel'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
    });
  };
}());

/* ==========================================================================
   To be done by hand, after an update (otp 1.0.258)
   --------------------------------------------------------------------------
   What fake-igd cannot do itself - a step a new version needs as root, what the installer left -
   drawn at the top of Settings → Upgrades, one band a thing; elsewhere only a count beside
   Upgrades in the menu and on the Settings tab. "Look again" asks now, "Done" is kept (and
   logged).
   ========================================================================== */
function afterBadge(a) {
  var b = $('up-badge');
  if (!ADMIN) { if (b) b.textContent = ''; return; }
  a = a || {};
  var n = Number(a.n || 0), lvl = n ? (a.level === 'bad' ? 'bad' : 'warn') : '';
  if (b) {
    b.textContent = n ? num(n) : '';
    b.className = 'count rail-n' + (lvl ? ' ' + lvl : '');
    b.title = n ? n + ' to be done by hand' : '';
  }
  var t = $('tabn-settings');
  if (t) {
    t.textContent = n ? num(n) : '';
    t.className = 'count after-n' + (lvl === 'bad' ? ' hot' : (lvl ? ' warm' : ''));
    t.title = n ? n + ' to be done by hand - Settings → Upgrades' : '';
  }
  /* Drawn again when the count changes while the pane is open. */
  var sig = n + ':' + lvl;
  if (AFT.seen && sig !== AFT.seen && paneLive('upgrade')) loadAfter();
  AFT.seen = sig;
}
/* The count with every live update of the header (as otp's status carries it): asked at most
   every half minute. */
function afterTick() {
  if (!ADMIN) { afterBadge(null); return; }
  if (AFT.sum) afterBadge(AFT.sum);
  if (Date.now() - AFT.asked < 30000) return;
  AFT.asked = Date.now();
  api('after&brief=1').then(function (s) {
    AFT.sum = {n: s.count, level: s.level};
    afterBadge(AFT.sum);
  }).catch(function () { AFT.asked = 0; });
}
function loadAfter() {
  if (!ADMIN || !$('after-card')) return;
  apiLatest('after', 'after').then(drawAfter).catch(oops);
}
function afterAct(body, button, then) {
  busy(button, true);
  api('after', body).then(function (d) {
    toast(d.message || 'done', 'good');
    drawAfter(d);
    if (then) then(d);
  }).catch(oops).then(function () { busy(button, false); });
}
function afterBand(it, d) {
  var lvl = it.level === 'bad' ? 'bad' : (it.level === 'info' ? 'info' : 'warn');
  var band = el('div', 'after-band ' + lvl);
  band.dataset.id = it.id;
  band.dataset.node = it.node;
  var ic = el('div', 'after-ic');
  ic.innerHTML = iconMarkup(lvl === 'bad' ? 'close' : 'flag');
  band.appendChild(ic);
  var body = el('div', 'after-body');
  var head = el('div', 'after-title');
  head.appendChild(el('b', '', it.title));
  body.appendChild(head);
  body.appendChild(el('div', 'after-why', it.why));
  (it.steps || []).forEach(function (st) {
    if (st.cmd) {
      if (st.lead) body.appendChild(el('div', 'after-lead', st.lead));
      var box = el('div', 'after-cmd');
      box.appendChild(noI18n(el('code', 'mono', st.cmd)));
      var cp = cmdButton('Copy', 'copy', 'small after-copy');
      cp.onclick = function () { copyText(st.cmd, cp, 'the command is on the clipboard'); };
      box.appendChild(cp);
      body.appendChild(box);
    } else if (st.words) {
      body.appendChild(el('div', 'after-lead', st.words));
    }
  });
  if (it.foot) body.appendChild(el('div', 'after-foot', it.foot));
  body.appendChild(el('div', 'after-seen', it.since ? 'First seen ' + stamp(it.since) : 'Just seen'));
  band.appendChild(body);
  var tools = el('div', 'after-btns');
  var pane = (it.steps || []).filter(function (st) { return st.pane && $('pane-' + st.pane); })[0];
  if (pane) {
    var open = cmdButton('Open it', 'next', 'small');
    open.onclick = function () { showPane(pane.pane); };
    tools.appendChild(open);
  }
  if (it.ack === 'auto') {
    var look = cmdButton('Look again', 'refresh', 'small');
    explain(look, 'This server looks again now.');
    look.onclick = function () { afterAct({action: 'check'}, look); };
    tools.appendChild(look);
  }
  var done = cmdButton('Done', 'check', 'small' + (it.ack === 'manual' ? ' primary' : ''));
  done.onclick = function () {
    var go = function () { afterAct({action: 'done', id: it.id}, done); };
    if (it.ack === 'manual') { go(); return; }
    confirmThen('Mark it as done?', 'As far as this server can tell it is not done yet: '
      + 'it looks for it itself and this band would go by itself. Marked done by hand, it goes now, '
      + 'and that is written in the events.', 'Mark it as done', go, false);
  };
  tools.appendChild(done);
  band.appendChild(tools);
  return band;
}
function drawAfter(d) {
  AFT.d = d;
  var card = $('after-card'), host = $('after-bands'), lately = $('after-lately');
  if (!card || !host || !d) return;
  var items = d.items || [];
  var worst = !items.length ? '' : (d.level === 'bad' ? 'bad' : (d.level === 'info' ? 'info' : 'warn'));
  card.classList.remove('bad', 'warn', 'info');
  if (worst) card.classList.add(worst);
  liveFill(host, function (host) {
    if (!items.length) {
      host.appendChild(el('p', 'note good after-none', 'Nothing is to be done by hand.'));
      return;
    }
    items.forEach(function (it) { host.appendChild(afterBand(it, d)); });
  });
  liveFill(lately, function (box) {
    /* none: no table, no heading, no Clear (otp 1.0.260) */
    var rows = d.lately || [];
    if (!rows.length) return;
    var head = el('div', 'after-lately-head');
    head.appendChild(el('h3', 'after-lately-h', 'Done lately'));
    var clr = cmdButton('Clear', 'trash', 'small after-lately-clear');
    clr.type = 'button';
    clr.title = 'Empty this list - what is still to be done stays';
    clr.onclick = function () {
      /* exactly what this page shows: a line come meanwhile stays */
      afterAct({action: 'clear_done', items: rows.map(function (x) { return [x.id || '', x.node || '', Math.floor(x.at || 0)]; })}, clr);
    };
    head.appendChild(clr);
    box.appendChild(head);
    var t = el('table', 'rows after-lately-t');
    var hr = el('tr');
    ['What', 'How', 'Who', 'When'].forEach(function (w) { hr.appendChild(el('th', '', w)); });
    var th = el('thead'); th.appendChild(hr); t.appendChild(th);
    var tb = el('tbody');
    rows.forEach(function (x) {
      var tr = el('tr');
      var what = el('td');
      what.appendChild(el('span', '', x.title || x.id));
      tr.appendChild(what);
      tr.appendChild(el('td', 'after-how ' + String(x.how || '').replace(/\s+/g, '-'), x.how || ''));
      tr.appendChild(x.who && x.who !== 'the command line' ? noI18n(el('td', '', x.who)) : el('td', x.who ? '' : 'muted', x.who || '–'));
      tr.appendChild(stampCell(x.at));
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    var tw = el('div', 'after-lately-w');
    tw.appendChild(t);
    box.appendChild(tw);
  });
  AFT.sum = {n: d.count, level: d.level};
  afterBadge(AFT.sum);
}

/* ---- the settings of the card, as otp draws them: the daily look first, the address, going back -- */
var UP_SET_WORDS = {
  upgrade_check: ['Look for a new version every day', 'Once a day (and when Look now is pressed) the address below is asked for '
    + 'fake-igd-X.Y.Z.tar.gz packages; a newer one than runs here is offered on this page - put in with one click, '
    + 'after its signature has been checked like any package sent by hand. Nothing is put in by itself.'],
  upgrade_url: ['Where new versions are looked for', 'A GitHub folder (<code>https://github.com/OWNER/REPO/tree/BRANCH/FOLDER</code>), '
    + 'a web page or folder listing that links to the packages, or one package\'s own address. HTTPS only; a proxy is '
    + 'taken from Settings → Proxy when it is switched on for the new versions.']
};
function upSettingsAsOtp() {
  if (typeof SETTINGS === 'undefined' || !SETTINGS || !SETTINGS.panes) return;
  (SETTINGS.settings || []).forEach(function (s) {
    var w = UP_SET_WORDS[s.key];
    if (w) { s.name = w[0]; s.says = w[1]; }
  });
  var keys = SETTINGS.panes.upgrade || [];
  var order = ['upgrade_check', 'upgrade_url', 'upgrade_downgrade'];
  SETTINGS.panes.upgrade = order.filter(function (k) { return keys.indexOf(k) >= 0; })
    .concat(keys.filter(function (k) { return order.indexOf(k) < 0; }));
}

/* ---- woven into the pages: the header's live update carries the count, the settings are drawn
   as otp's, the Settings tab has its count ---------------------------------------------------- */
(function () {
  var tab = document.querySelector('.tabs button[data-tab="settings"]');
  if (tab && !$('tabn-settings')) {
    var c = el('span', 'count after-n');
    c.id = 'tabn-settings';
    tab.appendChild(c);
  }
  if (typeof paintHeader === 'function') {
    var paint = paintHeader;
    paintHeader = function (s) { paint(s); try { afterTick(); } catch (e) { /* the next tick */ } };
  }
  if (typeof drawSettings === 'function') {
    var draw = drawSettings;
    drawSettings = function () { upSettingsAsOtp(); return draw.apply(this, arguments); };
  }
  if (typeof STATUS !== 'undefined' && STATUS) setTimeout(afterTick, 0);
}());

PANE_LOAD.upgrade = function () { loadUpgrade(); };
/* Its own timer asks while it is open (every 3 s while an upgrade runs, 15 s otherwise). */
PANE_TICK.upgrade = function () { };
