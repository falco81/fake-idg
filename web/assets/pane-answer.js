/* pane-answer.js - Settings → How it answers (1.6.1), and the small pieces of otp's that
   fake-igd's own panes share (IGDP: answer, network, ntfy, logs, mdns - read first, by name).

   As otp's panes with a machine's card above their settings (Disks and logs, Time): the card
   of this server - what it answers now, the public IP and where it came from, what was
   answered in the last 24 hours - then the settings, then "Try it" as otp's mail test: fake-igd
   asked as the PS5 asks it, every step shown. */
(function () {
  'use strict';

  /* ---- otp's pieces: nodeGrid, nodeCard, nodeBig, upBar, netFacts, stepsList, hideBar ---- */
  var P = window.IGDP = window.IGDP || {};
  P.grid = function () { return el('div', 'pw-grid node-grid'); };
  P.card = function (n, dot, tag, tagCls) {
    var c = el('div', 'card ntp-node');
    var head = el('div', 'pw-head');
    head.appendChild(el('span', 'dot ' + dot));
    head.appendChild(noI18n(el('b', '', n.node || n.name || 'this server')));
    head.appendChild(el('span', 'tag info', 'this page'));
    if (tag) head.appendChild(el('span', 'tag ' + (tagCls || 'dim'), tag));
    c.appendChild(head);
    c._head = head;
    return c;
  };
  P.big = function (c, value, words) {
    var big = el('div', 'ntp-big');
    big.appendChild(noI18n(el('span', 'ntp-off', value)));
    if (words) big.appendChild(el('span', 'muted small', ' ' + words));
    c.appendChild(big);
  };
  P.bar = function (pc, kind, words) {
    var box = el('div', 'going up-bar' + (kind ? ' ' + kind : ''));
    var bar = el('div', 'bar');
    var fill = el('span', '');
    fill.style.width = Math.max(0, Math.min(100, pc)) + '%';
    bar.appendChild(fill);
    box.appendChild(bar);
    if (words) box.appendChild(noI18n(el('div', 'says', words)));
    return box;
  };
  P.facts = function (rows) {
    var dl = el('div', 'net-facts');
    rows.forEach(function (r) {
      if (!r || r[1] === undefined) return;
      var one = el('div', 'net-fact');
      one.appendChild(el('span', 'k', r[0]));
      var v = el('span', 'v' + (r[2] ? ' mono' : '') + (r[3] ? ' ' + r[3] : ''));
      if (r[1] instanceof Node) v.appendChild(r[1]); else v.textContent = r[1] === '' || r[1] === null ? '–' : String(r[1]);
      if (r[2]) noI18n(v);
      one.appendChild(v);
      dl.appendChild(one);
    });
    return dl;
  };
  P.steps = function (steps) {
    var list = el('div', 'steps');
    (steps || []).forEach(function (s) {
      var row = el('div', 'step ' + (s.ok ? 'ok' : 'bad'));
      var mark = el('span', 'step-mark');
      mark.innerHTML = iconMarkup(s.ok ? 'check' : 'cancel', 15);
      row.appendChild(mark);
      var words = el('span', 'step-words');
      words.appendChild(el('b', '', s.what));
      if (s.said) words.appendChild(noI18n(el('span', 'd', s.said)));
      if (s.ms !== undefined) words.appendChild(el('span', 'd', s.ms + ' ms'));
      row.appendChild(words);
      list.appendChild(row);
    });
    return list;
  };
  P.hideBar = function (go) {
    var row = el('div', 'actions hide-row');
    var b = cmdButton('Hide this', 'close', 'small');
    b.classList.add('hide-this');
    b.onclick = function (e) { if (e) e.stopPropagation(); go(); };
    row.appendChild(b);
    return row;
  };
  /* What a test said, as otp's mailSteps: the outcome, every step, Hide this. */
  P.stepsOut = function (host, d, good, bad) {
    clear(host);
    host.appendChild(el('p', 'note ' + (d.sent ? 'good' : 'bad'), (d.sent ? good : bad) + d.said
      + (d.took_ms !== undefined ? ' · ' + num(d.took_ms) + ' ms' : '')));
    if ((d.steps || []).length) host.appendChild(P.steps(d.steps));
    host.appendChild(P.hideBar(function () { clear(host); }));
  };
  P.letGo = function (host) {
    if (!host || host._letGo) return;
    host._letGo = true;
    host.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('button') : null;
      if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
    });
  };
  P.svcWords = function (s) {
    return !s || !s.state ? 'not known' : s.state === 'active' ? 'running' : s.state === 'unknown' ? 'not known (no systemd?)' : s.state;
  };
  P.goLog = function (q) {
    showTab('log');
  };

  /* Interfaces chosen from a list, not typed (as otp's picks): the setting's own box kept,
     hidden, and written by the chips - so the save bar sees a change as it sees any other.
     names: [{name, ipv4, up, why}] of the machine. */
  P.ifacePick = function (key, names, none) {
    var box = $('set-' + key);
    if (!box || box.tagName !== 'INPUT') return;
    var item = box.closest('.set-item');
    var old = item.querySelector('.if-pick');
    if (old) old.remove();
    box.hidden = true;
    var wrap = el('div', 'if-pick');
    var chosen = el('div', 'chips');
    chosen.style.margin = '2px 0 8px';
    var pick = el('select');
    pick.disabled = !ADMIN;
    var list = function () { return box.value.split(/[\s,]+/).filter(Boolean); };
    var put = function (v) {
      box.value = v.join(', ');
      box.dispatchEvent(new Event('input', {bubbles: true}));
      draw();
    };
    var known = {};
    (names || []).forEach(function (n) { known[n.name] = n; });
    var draw = function () {
      clear(chosen);
      var have = list();
      if (!have.length) chosen.appendChild(el('span', 'muted small', none || 'none chosen'));
      have.forEach(function (n) {
        var c = el('span', 'chip');
        var k = known[n];
        var t = noI18n(el('span', 'mono', n));
        c.appendChild(t);
        if (!k) c.appendChild(el('span', 'tag warn', 'not on this server'));
        else if (k.ipv4) c.appendChild(noI18n(el('span', 'muted small mono', k.ipv4)));
        if (ADMIN) {
          var x = iconButton('close', 'Take it out');
          x.onclick = function () { put(list().filter(function (v) { return v !== n; })); };
          c.appendChild(x);
        }
        chosen.appendChild(c);
      });
      clear(pick);
      var o0 = el('option', '', 'add an interface…'); o0.value = ''; pick.appendChild(o0);
      (names || []).forEach(function (n) {
        if (have.indexOf(n.name) >= 0) return;
        var o = el('option', '', n.name + (n.ipv4 ? ' - ' + n.ipv4 : '') + (n.up === false ? ' (down)' : ''));
        o.value = n.name;
        pick.appendChild(o);
      });
      pick.hidden = !ADMIN || pick.options.length < 2;
    };
    pick.onchange = function () { if (pick.value) put(list().concat([pick.value])); };
    /* Put back by the save bar's Undo, or after a save: drawn from the box again. */
    box.addEventListener('change', draw);
    wrap.appendChild(chosen);
    wrap.appendChild(pick);
    box.parentNode.insertBefore(wrap, box.nextSibling);
    draw();
  };

  /* ==========================================================================
     How it answers
     ========================================================================== */
  var UA = {d: null};
  function load() {
    api('upnp-here').then(function (d) { UA.d = d; draw(); }).catch(oops);
  }
  function draw(live) {
    var real = $('ua-host');
    if (!real || !UA.d) return;
    P.letGo(real);
    liveFill(real, function (host) {
      var d = UA.d, s = d.service || {};
      var on = s.state === 'active';
      var grid = P.grid();
      var c = P.card(d, on ? 'ok' : (s.state === 'unknown' ? 'dim' : 'bad'), P.svcWords(s), on ? 'ok' : 'crit');
      P.big(c, d.mode === 'passive' ? 'passive' : 'active',
            d.mode === 'passive' ? 'only listens and logs' : 'answers like a UPnP router');
      var acc = (d.answered || {}).ok || 0, rej = 0;
      Object.keys(d.answered || {}).forEach(function (k) { if (k !== 'ok') rej += d.answered[k]; });
      var pub = d.public || {};
      c.appendChild(P.facts([
        ['AddPortMapping', d.mapping_response === 'reject' ? 'refused (error 501)' : 'accepted - nothing is opened'],
        ['Who is answered', (d.allowed_clients || []).length ? d.allowed_clients.join(', ') : 'everybody', !!(d.allowed_clients || []).length],
        ['Public IP reported', pub.now || (pub.set === 'auto' ? 'not found yet' : pub.set), true, pub.now ? '' : 'bad'],
        ['Where it came from', pub.from || (pub.said || '')],
        ['Asked in 24 hours', num(d.asked_24h || 0) + ' request(s)'],
        ['Ports accepted / refused', num(acc) + ' / ' + num(rej)],
        ['Another UPnP router', (d.other || []).length ? d.other.map(function (o) { return o.addr; }).join(', ') : 'none heard', true, (d.other || []).length ? 'bad' : ''],
        ['Running since', d.started ? stamp(d.started) : (s.since || '')],
        ['Read', ago(d.at)]
      ]));
      if (pub.said) c.appendChild(noI18n(el('div', 'si-said small', pub.said)));
      var row = el('div', 'btnrow');
      var re = cmdButton('Read it again', 'refresh', 'small');
      re.onclick = function () { busy(re, true); api('upnp-here').then(function (x) { UA.d = x; draw(); }).catch(oops).then(function () { busy(re, false); }); };
      row.appendChild(re);
      var lg = cmdButton('The log', 'log', 'small');
      explain(lg, 'fake-igd\'s own log, followed as it is written (the tab Log).');
      lg.onclick = function () { showTab('log'); };
      row.appendChild(lg);
      c.appendChild(row);
      grid.appendChild(c);
      host.appendChild(grid);
      if ((d.other || []).length) {
        host.appendChild(el('p', 'note bad', 'Another UPnP router is on the network (' + d.other.map(function (o) { return o.addr + (o.at ? ', heard ' + ago(o.at) : ''); }).join('; ')
          + '): switch UPnP off on it, or the PS5 may ask it instead of fake-igd.'));
      }
    }, live, function () { explainWhatWasDrawn(real); });
  }
  if ($('ua-try')) {
    $('ua-try').onclick = function () {
      var b = $('ua-try');
      if (Object.keys(DIRTY || {}).some(function (k) { return (SETTINGS.panes.answer || []).concat(SETTINGS.panes.network || []).indexOf(k) >= 0; })) {
        toast('save the changes first', 'bad'); return;
      }
      busy(b, true);
      $('ua-said').textContent = 'asking…';
      api('upnp-try', {add: $('ua-add').value}, 60).then(function (d) {
        $('ua-said').textContent = d.sent ? 'answers' : 'did not answer as it should';
        P.stepsOut($('ua-steps'), d, 'It answers: ', 'Not as it should: ');
      }).catch(function (e) { $('ua-said').textContent = ''; oops(e); }).then(function () { busy(b, false); });
    };
  }
  PANE_LOAD.answer = load;
  PANE_TICK.answer = function () {
    api('upnp-here').then(function (d) { UA.d = d; draw(true); }).catch(function () {});
  };
})();
