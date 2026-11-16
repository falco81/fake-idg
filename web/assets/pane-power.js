/* Settings → Restart and power off (1.6.0) - otp's loadPower/drawPower for one server: a card for
   this machine with Restart and Power off - now or in so many minutes - what is set for later
   (cancelled with a press), and the restart followed down and up again. */
(function () {
  'use strict';
  var PW = {d: null, poll: null, failSince: 0, reload: false, tick: null};

  function loadPower() {
    api('power').then(function (d) { PW.d = d; PW.failSince = 0; drawPower(); pwPollFor(); }).catch(oops);
  }
  function live(d) {
    var p = d && d.plan;
    return !!(p && p.ask && (p.state === 'asked' || (p.state === 'going' && !p.in)));
  }
  function pwPollFor() {
    var on = live(PW.d);
    if (on && !PW.poll) PW.poll = setInterval(pwPoll, 2000);
    if (!on && PW.poll) { clearInterval(PW.poll); PW.poll = null; }
    var sched = PW.d && PW.d.scheduled && PW.d.scheduled.at;
    if (sched && !PW.tick) PW.tick = setInterval(count, 1000);
    if (!sched && PW.tick) { clearInterval(PW.tick); PW.tick = null; }
  }
  function pwPoll() {
    if (TAB !== 'settings' || PANE !== 'power') { clearInterval(PW.poll); PW.poll = null; return; }
    api('power').then(function (d) {
      var wasAway = !!PW.failSince;
      PW.d = d; PW.failSince = 0;
      drawPower(true);
      if (d.plan && d.plan.state === 'back') {
        clearInterval(PW.poll); PW.poll = null;
        toast('up again', 'good');
        if (wasAway || PW.reload) setTimeout(function () { location.reload(); }, 2500);
      }
      pwPollFor();
    }).catch(function () { if (!PW.failSince) PW.failSince = Date.now(); drawPowerAway(); });
  }
  function netFacts(rows) {
    var dl = el('div', 'net-facts');
    rows.forEach(function (r) {
      if (r[1] === undefined) return;
      var one = el('div', 'net-fact');
      one.appendChild(el('span', 'k', r[0]));
      var v = el('span', 'v' + (r[2] ? ' mono' : ''));
      v.textContent = r[1] === '' || r[1] === null ? '–' : String(r[1]);
      if (r[2]) noI18n(v);
      one.appendChild(v);
      dl.appendChild(one);
    });
    return dl;
  }
  function stateWords(p, d) {
    if (p.state === 'asked') return {k: 'wait', w: 'asked of root'};
    if (p.state === 'failed') return {k: 'bad', w: 'failed: ' + (p.said || []).join('; ')};
    if (p.state === 'skipped') return {k: 'ok', w: (p.said || []).join('; ')};
    if (p.state === 'cancelled') return {k: 'ok', w: 'cancelled'};
    if (p.state === 'back') return {k: 'ok', w: 'up again'};
    if (p.in) return {k: 'ok', w: 'set for later: ' + (p.said || []).join('; ')};
    if (p.how === 'poweroff') return {k: 'going', w: 'switching off'};
    return {k: 'going', w: d.now - (p.answered || p.at) < 15 ? 'going down' : 'restarting'};
  }
  function drawPower(quiet) {
    var real = $('pw-host');
    if (!real || !PW.d) return;
    liveFill(real, function (host) {
      var d = PW.d, n = d.node || {};
      if (d.plan && d.plan.ask) host.appendChild(progress(d));
      if (d.scheduled && d.scheduled.at) host.appendChild(schedCard(d));
      var grid = el('div', 'pw-grid');
      var c = el('div', 'card pw-node');
      var h = el('div', 'pw-head');
      h.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
      h.appendChild(noI18n(el('b', '', n.name || '')));
      h.appendChild(el('span', 'tag info', 'this page'));
      c.appendChild(h);
      c.appendChild(netFacts([
        ['State', n.alive ? 'answering' : 'not answering'],
        ['Address', n.address || '', true],
        ['Running for', n.started ? span(d.now - n.started) : ''],
        ['Version', n.version || '', true],
        ['Restart on a schedule', d.auto && d.auto.on ? (d.auto.next ? 'next ' + new Date(d.auto.next * 1000).toLocaleString(numLang()) : 'on') : 'off']
      ]));
      var row = el('div', 'btnrow');
      var when = selectBox([['0', 'now'], ['1', 'in 1 min'], ['5', 'in 5 min'], ['10', 'in 10 min'], ['15', 'in 15 min'],
                            ['30', 'in 30 min'], ['60', 'in an hour'], ['120', 'in 2 hours']], '0');
      explain(when, 'Now: in a few seconds. Later: shutdown +N - whoever is signed in at the machine is told, and it can be cancelled until then.');
      var rb = cmdButton('Restart', 'refresh', '');
      var off = cmdButton('Power off', 'power', 'danger');
      var busyNow = d.plan && d.plan.state === 'asked';
      rb.disabled = off.disabled = when.disabled = !ADMIN || !!busyNow;
      rb.onclick = function () { pwAsk('reboot', parseInt(when.value, 10) || 0, n); };
      off.onclick = function () { pwAsk('poweroff', parseInt(when.value, 10) || 0, n); };
      row.appendChild(when); row.appendChild(rb); row.appendChild(off);
      c.appendChild(row);
      grid.appendChild(c);
      host.appendChild(grid);
    }, quiet, function () { explainWhatWasDrawn(real); });
    count();
  }
  function pwAsk(how, mins, n) {
    var later = mins ? ' in ' + span(mins * 60) : '';
    var words = how === 'poweroff'
      ? 'The server is switched off' + later + '. Nothing answers - the PS5, these pages - until somebody switches it on again at the machine.'
      : 'The server restarts' + later + ': for a minute or two nothing answers.';
    if (mins) words += ' Until then it can be cancelled here.';
    confirmThen((how === 'reboot' ? 'Restart ' : 'Power off ') + (n.name || 'this machine') + later + '?', htmlText(words),
      how === 'reboot' ? 'Restart' : 'Power off', function () {
        api('power', {how: how, in: mins}).then(function (r) {
          toast(r.message, 'good');
          PW.reload = !mins && how === 'reboot';
          loadPower();
        }).catch(oops);
      }, how === 'poweroff');
  }
  function hideButton(go) {
    var b = cmdButton('Hide this', 'close', 'small');
    b.classList.add('hide-this');
    b.onclick = function (e) {
      if (e) e.stopPropagation();
      busy(b, true);
      Promise.resolve(go()).catch(oops).then(function () { busy(b, false); });
    };
    return b;
  }
  function progress(d) {
    var p = d.plan;
    var st = stateWords(p, d);
    var done = st.k === 'ok' || st.k === 'bad';
    var card = el('div', 'card full net-job');
    var what = p.how === 'cancel' ? 'Cancelling what was set' : ((p.how === 'reboot' ? 'Restart' : 'Power-off') + (p.in ? ' in ' + span(p.in * 60) : ''));
    card.appendChild(el('h2', '', what + (done ? ' - done' : ' under way')));
    var ol = el('ol', 'net-steps done');
    var li = el('li', st.k === 'ok' ? 'good' : (st.k === 'bad' ? 'bad' : ''));
    li.appendChild(el('span', 'mark', st.k === 'ok' ? '✓' : (st.k === 'bad' ? '✗' : '…')));
    li.appendChild(noI18n(el('b', '', (d.node.name || '') + ' ')));
    li.appendChild(el('span', '', st.w));
    li.appendChild(el('span', 'muted small', ' - asked ' + ago(p.at) + ' by ' + (p.by || '?')));
    if (st.k === 'going') {
      var t = Math.max(0, d.now - (p.answered || p.at));
      var bar = el('div', 'going wide');
      bar.innerHTML = '<div class="bar"><span></span></div>';
      bar.querySelector('span').style.width = Math.min(100, Math.round(t / 120 * 100)) + '%';
      li.appendChild(el('span', 'muted small', ' ' + span(t)));
      li.appendChild(bar);
    }
    ol.appendChild(li);
    card.appendChild(ol);
    if (done) {
      var row = el('div', 'actions hide-row');
      row.appendChild(hideButton(function () { return api('power', {action: 'hide'}).then(function (x) { PW.d = x; drawPower(); }); }));
      row.appendChild(el('span', 'muted small', 'Hidden by itself half an hour after it began.'));
      card.appendChild(row);
    }
    return card;
  }
  function schedCard(d) {
    var s = d.scheduled;
    var c = el('div', 'card full notice warn');
    var mode = s.mode === 'poweroff' ? 'A power-off' : (s.mode === 'reboot' ? 'A restart' : 'A shutdown (' + s.mode + ')');
    c.appendChild(el('h2', '', mode + ' is set for ' + new Date(s.at * 1000).toLocaleTimeString(numLang())));
    var p = el('p', 'note');
    p.appendChild(document.createTextNode('In '));
    var left = noI18n(el('b', 'pw-left mono', ''));
    left.dataset.until = s.at;
    p.appendChild(left);
    p.appendChild(document.createTextNode(' - set with shutdown, here or at the machine. Until then it can be cancelled.'));
    c.appendChild(p);
    var row = el('div', 'btnrow');
    var x = cmdButton('Cancel it', 'cancel', 'primary');
    x.disabled = !ADMIN;
    x.onclick = function () {
      busy(x, true);
      api('power', {action: 'cancel'}).then(function (r) { toast(r.message, 'good'); PW.reload = false; setTimeout(loadPower, 1500); })
        .catch(oops).then(function () { busy(x, false); });
    };
    row.appendChild(x);
    c.appendChild(row);
    return c;
  }
  function count() {
    var skew = PW.d ? PW.d.now - Date.now() / 1000 : 0;
    var now = Date.now() / 1000 + skew;
    document.querySelectorAll('#pw-host .pw-left').forEach(function (x) {
      var left = parseFloat(x.dataset.until) - now;
      x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) : 'now';
    });
  }
  function drawPowerAway() {
    var host = $('pw-host');
    if (!host) return;
    var box = $('pw-away');
    if (!box) { box = el('div', 'card full net-job'); box.id = 'pw-away'; host.insertBefore(box, host.firstChild); }
    clear(box);
    var away = Math.round((Date.now() - PW.failSince) / 1000);
    box.appendChild(el('h2', '', 'This page\'s server is restarting'));
    var bar = el('div', 'going wide');
    bar.innerHTML = '<div class="bar"><span></span></div>';
    bar.querySelector('span').style.width = Math.min(100, Math.round(away / 120 * 100)) + '%';
    box.appendChild(bar);
    box.appendChild(el('p', 'note', 'Not answering for ' + span(away) + ' - asked again every two seconds; the page comes back by itself.'));
  }

  PANE_LOAD.power = loadPower;
}());
