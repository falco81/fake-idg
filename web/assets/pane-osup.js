/* pane-osup.js - Settings → System updates (otp's loadOsup, drawOsup) - this one server. */
(function () {
'use strict';

var OU = {d: null, poll: null, hide: false, reboot: 'ask', what: 'all', asked: 0, away: 0};
try { OU.hide = localStorage.getItem('fake-igd-ou-hide') === '1'; } catch (e) { /* only a convenience */ }
var OU_STATE = {running: ['going on', 'info'], done: ['done', 'ok'], failed: ['failed', 'crit']};

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
function hideBar(go) {
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

function loadOsup() {
  api('osup').then(function (d) { OU.d = d; OU.away = 0; drawOsup(); ouPoll(ouLive(d)); }).catch(oops);
}
function ouLive(d) {
  d = d || OU.d || {};
  /* Just asked: root has not begun yet, followed until it says. */
  if (Date.now() - OU.asked < 30000) return true;
  return (d.job && d.job.state === 'running') || (d.plan && d.plan.state === 'running');
}
function ouPoll(on) {
  if (on && !OU.poll) {
    OU.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'osup') { ouPoll(false); return; }
      api('osup').then(function (d) { OU.d = d; OU.away = 0; drawOsup(true); if (!ouLive(d)) ouPoll(false); })
        .catch(function () { OU.away = OU.away || Date.now(); drawOsup(true); });
    }, 2500);
  }
  if (!on && OU.poll) { clearInterval(OU.poll); OU.poll = null; }
}
function ouAsked() { OU.asked = Date.now(); ouPoll(true); }
function ouDo(q, b) {
  if (b) busy(b, true);
  return api('osup', q).then(function (x) {
    if (x.message) toast(x.message, 'good');
    ouAsked();
    loadOsup();
    return x;
  }).catch(oops).then(function () { if (b) busy(b, false); });
}
function drawOsup(live) {
  var real = $('ou-host');
  if (!real || !OU.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = OU.d, job = d.job || {}, ck = d.check || {}, plan = d.plan || {};
    var running = job.state === 'running' || plan.state === 'running';
    var looking = job.state === 'running' && job.kind === 'check';
    if (OU.away) host.appendChild(el('p', 'note warn', 'This server is not answering for ' + span(Math.round((Date.now() - OU.away) / 1000)) + ' - restarting, perhaps; asked again every few seconds.'));
    var res = d.root || {};
    if (res.ok === false && res.at && Date.now() / 1000 - res.at < 600) host.appendChild(noI18n(el('p', 'note bad', 'Root said: ' + (res.said || []).join('; '))));
    /* A restart the update left to do. */
    var rebooting = plan.rebooting && Date.now() / 1000 - plan.rebooting < 900;
    if (d.reboot && !rebooting) {
      var rb = el('div', 'card full notice warn ou-reboot');
      rb.appendChild(el('h2', '', (d.node || 'This server') + ' needs a restart'));
      rb.appendChild(el('p', 'note', 'A new kernel or libraries are in that only a restart brings into use. For a minute or two the PS5 gets no answer, and these pages are away.'));
      var go = cmdButton('Restart ' + (d.node || 'it'), 'refresh', 'primary');
      go.disabled = !ADMIN;
      go.onclick = function () {
        confirmThen('Restart after the update', 'Restarted now: ' + htmlText(d.node || 'this server') + '.', 'Restart', function () {
          ouDo({action: 'reboot'}, go);
        }, false);
      };
      rb.appendChild(go);
      host.appendChild(rb);
    }
    if (rebooting) host.appendChild(el('p', 'note', 'Restarting - asked ' + ago(plan.rebooting) + '.'));
    /* What this server has waiting. */
    var grid = el('div', 'pw-grid');
    var c = el('div', 'card pw-node');
    var hd = el('div', 'pw-head');
    hd.appendChild(el('span', 'dot ok'));
    hd.appendChild(noI18n(el('b', '', d.node || '')));
    hd.appendChild(el('span', 'tag info', 'this page'));
    if (looking) hd.appendChild(el('span', 'tag info', 'looking…'));
    else if (ck.at && ck.state === 'done') hd.appendChild(el('span', 'tag ' + (ck.count ? 'warn' : 'ok'), ck.count ? num(ck.count) + ' waiting' : 'up to date'));
    if (ck.reboot_now || (ck.reboot_after && ck.count)) hd.appendChild(el('span', 'pw-break'));
    if (ck.reboot_now) hd.appendChild(el('span', 'tag warn', 'restart needed'));
    else if (ck.reboot_after && ck.count) hd.appendChild(el('span', 'tag info', 'restart after the update'));
    c.appendChild(hd);
    c.appendChild(netFacts([
      ['Updates waiting', ck.at ? num(ck.count || 0) : 'not looked yet'],
      ['Of them security', ck.security !== undefined && ck.security !== null ? num(ck.security) : ''],
      ['A restart', !ck.at ? '' : (ck.reboot_now ? 'needed now, before any update'
        : (ck.reboot_after && ck.count ? 'needed after the update - ' + (ck.reboot_why || []).join(', ') : 'not needed by these updates'))],
      ['Looked', ck.at ? ago(ck.at) : ''],
      ['Updated by', ck.at ? (ck.tool || 'dnf') : '', true]
    ]));
    if (ck.error) c.appendChild(noI18n(el('p', 'note bad', ck.error)));
    if ((ck.packages || []).length) {
      var more = el('details', 'fold');
      more.appendChild(el('summary', '', 'what is waiting'));
      var pk = noI18n(el('pre', 'lines', ck.packages.slice(0, 300).join('\n') + (ck.packages.length > 300 ? '\n…' : '')));
      pk.style.maxHeight = 'none';
      pk.style.overflow = 'visible';
      more.appendChild(pk);
      if (OU.pkOpen) more.open = true;
      more.ontoggle = function () { OU.pkOpen = more.open; };
      c.appendChild(more);
    }
    var row = el('div', 'btnrow');
    var look = cmdButton('Look for updates', 'search', '');
    look.disabled = !ADMIN || running || !d.helper;
    look.onclick = function () { ouDo({action: 'check'}, look); };
    row.appendChild(look);
    c.appendChild(row);
    grid.appendChild(c);
    host.appendChild(grid);
    /* The update itself. */
    if (!running) {
      var uc = el('div', 'card full');
      uc.appendChild(el('h2', '', 'Update this server'));
      uc.appendChild(el('p', 'note', 'dnf updates every package. fake-igd.service goes on answering meanwhile; a restart it needs is offered at the end.'));
      if (ck.reboot_after && ck.count) uc.appendChild(el('p', 'note warn', 'This server needs a restart after this update: ' + (ck.reboot_why || []).join(', ') + '.'));
      var seg2 = el('div', 'seg');
      [['all', 'Every update'], ['security', 'Only the security updates']].forEach(function (o) {
        var b = el('button', OU.what === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { OU.what = o[0]; drawOsup(); };
        seg2.appendChild(b);
      });
      var segb = el('div', 'seg');
      [['ask', 'Ask me when a restart is needed'], ['auto', 'Restart by itself when needed']].forEach(function (o) {
        var b = el('button', OU.reboot === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { OU.reboot = o[0]; drawOsup(); };
        segb.appendChild(b);
      });
      uc.appendChild(formField('Which', seg2));
      uc.appendChild(formField('After the update', segb));
      var row2 = el('div', 'btnrow');
      var start = cmdButton('Update it now', 'download', 'primary');
      start.disabled = !ADMIN || !d.helper;
      start.onclick = function () {
        confirmThen('Update this server', (OU.what === 'security' ? 'The security updates of the system are put in.' : 'Every package of the system is updated.')
          + (OU.reboot === 'auto' ? '<br><br>Where it needs it, the server is <b>restarted by itself</b>.' : '<br><br>A restart it needs is offered when it is done.'),
          'Update', function () { ouDo({action: 'start', reboot: OU.reboot, security: OU.what === 'security'}, start); }, false);
      };
      row2.appendChild(start);
      uc.appendChild(row2);
      if (!d.helper) uc.appendChild(el('p', 'note bad', 'Root\'s helper for this (root_osup.py) is not installed - install.sh --upgrade puts it in.'));
      host.appendChild(uc);
    }
    /* How far it is. */
    if (plan.id) {
      var pc = el('div', 'card full');
      pc.appendChild(el('h2', '', 'The update'));
      var w = OU_STATE[plan.state] || OU_STATE.running;
      pc.appendChild(el('p', 'note', 'Started by ' + (plan.by || '?') + ' · ' + ago(plan.at) + ' · ' + w[0]
        + (plan.reboot === 'auto' ? ' · restarted where needed' : '') + (plan.security ? ' · security updates only' : '')
        + (plan.said ? ' · ' + plan.said : '')));
      var pct = plan.state === 'running' ? (job.kind === 'upgrade' ? Number(job.pct || 1) : 1) : 100;
      pc.appendChild(upBar(pct, plan.state === 'failed' ? 'bad' : (plan.state === 'done' ? 'good' : ''),
        num(pct) + ' %' + (plan.state === 'running' && job.kind === 'upgrade' && job.phase ? ' · ' + job.phase : '')
        + (plan.state === 'done' ? (plan.reboot_needed ? ' · a restart is needed' : ' · no restart needed') : ''), true));
      if (plan.state !== 'running') pc.appendChild(hideBar(function () { return api('osup', {action: 'hide'}).then(function (x) { OU.d = x; drawOsup(); }); }));
      host.appendChild(pc);
    }
    /* What dnf says. */
    var lines = d.lines || [];
    if (lines.length || job.state === 'running') {
      var lc = el('div', 'card full');
      var lh = el('h2', '', 'What it says' + (job.kind ? ' - ' + (job.kind === 'check' ? 'the look for updates' : 'the update') : ''));
      var lt = el('span', 'right');
      var hb = cmdButton(OU.hide ? 'Show it' : 'Hide it', OU.hide ? 'unfold' : 'fold', 'small');
      hb.onclick = function () { OU.hide = !OU.hide; try { localStorage.setItem('fake-igd-ou-hide', OU.hide ? '1' : '0'); } catch (e) { /* only a convenience */ } drawOsup(); };
      var cb = cmdButton('Clear the window', 'broom', 'small');
      explain(cb, 'Empty the window - for every page, and after a reload too; what comes after is shown.');
      cb.disabled = !ADMIN;
      cb.onclick = function () {
        busy(cb, true);
        api('osup', {action: 'clear'}).then(function (x) { OU.d = x; drawOsup(); toast('the window is empty'); })
          .catch(function (e) { busy(cb, false); oops(e); });
      };
      lt.appendChild(hb); lt.appendChild(cb);
      lh.appendChild(lt);
      lc.appendChild(lh);
      if (!OU.hide) {
        /* The last 200 lines, in the pane's own scroll - not a scroller of its own inside it. */
        var shown = lines.slice(-200);
        var pre = noI18n(el('pre', 'lines ou-log', (lines.length > shown.length ? '… ' + num(lines.length - shown.length) + ' line(s) before\n' : '') + (shown.join('\n') || '–')));
        pre.style.maxHeight = 'none';
        pre.style.overflow = 'visible';
        lc.appendChild(pre);
      } else {
        lc.appendChild(el('p', 'muted small', 'Hidden - ' + num(lines.length) + ' line(s).'));
      }
      host.appendChild(lc);
    }
  }, live);
  explainWhatWasDrawn($('pane-osup'));
}
PANE_LOAD.osup = loadOsup;
}());
