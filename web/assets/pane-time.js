/* Settings → Time (1.6.0) - otp's loadNtp/drawNtp/ntpForm for one server: the clock as chrony
   sees it, its sources, and the time servers (the settings of the pane, saved with the bar). */
(function () {
  'use strict';
  var NTP = {d: null, poll: null};

  function loadNtp() {
    api('time').then(function (d) {
      NTP.d = d;
      drawNtp();
      if (!NTP.poll) NTP.poll = setInterval(function () {
        if (TAB !== 'settings' || PANE !== 'time') { clearInterval(NTP.poll); NTP.poll = null; return; }
        api('time').then(function (x) { NTP.d = x; drawNtp(true); }).catch(function () {});
      }, 10000);
    }).catch(oops);
    serversEditor();
  }
  function ntpMs(s) {
    if (s === undefined || s === null || isNaN(s)) return '–';
    var ms = s * 1000;
    var a = Math.abs(ms);
    return (ms >= 0 ? '+' : '−') + (a >= 1000 ? (a / 1000).toFixed(2) + ' s' : (a >= 10 ? a.toFixed(1) : a.toFixed(3)) + ' ms');
  }
  function ntpHealth(d) {
    var t = d.tracking || {};
    if (!d.time) return {k: 'bad', w: 'not read yet'};
    if (!d.chrony) return {k: d.ntpsynchronized === 'yes' ? 'ok' : 'bad', w: d.ntpsynchronized === 'yes' ? 'synchronised (not chrony)' : 'chrony is not installed'};
    if (t.leap === 'Not synchronised' || !t.stratum) return {k: 'bad', w: 'not synchronised'};
    var off = Math.abs(t.offset || 0);
    if (off > 1) return {k: 'bad', w: 'synchronised, but off'};
    if (off > 0.1) return {k: 'warn', w: 'synchronised'};
    return {k: 'ok', w: 'synchronised'};
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
  var STATES = {'*': ['ok', 'followed'], '+': ['ok', 'combined'], '-': ['', 'not combined'], '?': ['crit', 'unreachable'],
                'x': ['crit', 'false ticker'], '~': ['warn', 'too variable']};
  function drawNtp(quiet) {
    var real = $('ntp-host');
    if (!real || !NTP.d) return;
    liveFill(real, function (host) {
      var D = NTP.d, nd = D.now || {}, t = nd.tracking || {};
      var h = ntpHealth(nd);
      var grid = el('div', 'pw-grid');
      var c = el('div', 'card ntp-node');
      var head = el('div', 'pw-head');
      head.appendChild(el('span', 'dot ' + (h.k === 'ok' ? 'ok' : (h.k === 'warn' ? 'warn' : 'bad'))));
      head.appendChild(noI18n(el('b', '', (STATUS && STATUS.node) || 'This machine')));
      head.appendChild(el('span', 'tag info', 'this page'));
      head.appendChild(el('span', 'tag ' + (h.k === 'ok' ? 'ok' : (h.k === 'warn' ? 'warn' : 'crit')), h.w));
      c.appendChild(head);
      var big = el('div', 'ntp-big');
      big.appendChild(noI18n(el('span', 'ntp-off', ntpMs(t.offset))));
      big.appendChild(el('span', 'muted small', ' off the time servers'));
      c.appendChild(big);
      var clock = '';
      if (nd.time) clock = new Date(nd.time * 1000).toLocaleString(numLang());
      c.appendChild(netFacts([
        ['Follows', t.ref || t.ref_id || '', true],
        ['Stratum', t.stratum !== undefined ? String(t.stratum) : '', true],
        ['Last correction', ntpMs(t.last_offset), true],
        ['Frequency', t.freq !== undefined ? t.freq.toFixed(3) + ' ppm' : '', true],
        ['Root delay / dispersion', t.root_delay !== undefined ? ntpMs(t.root_delay).replace('+', '') + ' / ' + ntpMs(t.root_disp).replace('+', '') : '', true],
        ['Leap status', t.leap || ''],
        ['Time zone', nd.timezone || '', true],
        ['Its time', clock],
        ['Read', nd.time ? ago(nd.time) : '']
      ]));
      if (nd.said) c.appendChild(el('p', 'small bad', nd.said));
      var ap = D.applied || {};
      if (ap.ask && !ap.done) c.appendChild(el('p', 'small muted', 'Time servers: asked of root ' + ago(ap.at) + '…'));
      else if (ap.at) {
        var st = el('p', 'small ' + (ap.ok ? 'muted' : 'bad'));
        st.textContent = (ap.ok ? 'Time servers set ' : 'Time servers NOT set ') + ago(ap.at) + (ap.said ? ': ' + ap.said : '');
        c.appendChild(st);
      }
      var sy0 = D.sync || {};
      if (sy0.done && Date.now() / 1000 - (sy0.at || 0) < 3600) c.appendChild(el('p', 'small ' + (sy0.ok ? 'muted' : 'bad'), 'Stepped ' + ago(sy0.at) + ': ' + (sy0.said || '')));
      var row = el('div', 'btnrow');
      var re = cmdButton('Read it again', 'refresh', 'small');
      re.onclick = function () {
        busy(re, true);
        api('time', {action: 'read'}).then(function (x) { NTP.d = x; drawNtp(); toast('read', 'good'); }).catch(oops).then(function () { busy(re, false); });
      };
      var sy = cmdButton('Step it now', 'clock', 'small');
      explain(sy, 'The clock set to the time servers at once (chronyc makestep), not slewed slowly - for a clock that is far off.');
      sy.onclick = function () {
        confirmThen('Step the clock now?', htmlText('The clock jumps to the time servers\' time at once. Logs written in that moment may look out of order.'), 'Step it', function () {
          api('time', {action: 'sync'}).then(function (r) { toast(r.message, 'good'); setTimeout(loadNtp, 5000); }).catch(oops);
        }, false);
      };
      row.appendChild(re); row.appendChild(sy);
      c.appendChild(row);
      grid.appendChild(c);
      host.appendChild(grid);
      /* Where the time comes from: chronyc sources, a row each - its sourcestats on a press. */
      var sc = el('div', 'card full');
      sc.appendChild(el('h2', '', 'Where the time comes from'));
      var srcs = nd.sources || [];
      var stats = nd.stats || {};
      if (!srcs.length) sc.appendChild(el('p', 'note', 'No source - chrony has none, or is not installed.'));
      else sc.appendChild(listTable(['State', 'Source', 'Stratum', 'Asked every', 'Reached', 'Last heard', 'Offset'], srcs, function (s) {
        var tr = el('tr', 'tappable');
        var stt = STATES[s.state] || ['', s.state];
        var td = el('td');
        td.appendChild(el('span', 'tag ' + stt[0], stt[1]));
        if (s.mode === '=') td.appendChild(el('span', 'muted small', ' peer'));
        if (s.mode === '#') td.appendChild(el('span', 'muted small', ' local clock'));
        tr.appendChild(td);
        tr.appendChild(noI18n(el('td', 'mono', s.name)));
        tr.appendChild(el('td', 'num', String(s.stratum)));
        tr.appendChild(el('td', 'num', span(Math.pow(2, s.poll || 0))));
        var r = el('td');
        var bits = el('span', 'reach');
        for (var i = 7; i >= 0; i--) bits.appendChild(el('i', (s.reach >> i) & 1 ? 'on' : ''));
        bits.title = (s.reach || 0).toString(2).padStart(8, '0') + ' - the last 8 tries';
        r.appendChild(bits);
        tr.appendChild(r);
        tr.appendChild(el('td', 'muted', s.last_rx === null || s.last_rx === undefined ? '–' : span(s.last_rx) + ' ago'));
        tr.appendChild(noI18n(el('td', 'num mono', ntpMs(s.offset) + ' ± ' + ntpMs(s.error).replace('+', ''))));
        tr.onclick = function () {
          var st = stats[s.name] || {};
          modal(s.name, function (body) {
            body.appendChild(peekFacts([['State', stt[1]], ['Stratum', String(s.stratum)], ['Offset', ntpMs(s.offset) + ' ± ' + ntpMs(s.error).replace('+', '')]]));
            body.appendChild(kvTable([
              ['Asked every', span(Math.pow(2, s.poll || 0))],
              ['Reached (the last 8 tries)', (s.reach || 0).toString(2).padStart(8, '0'), 'mono'],
              ['Last heard', s.last_rx === null || s.last_rx === undefined ? '–' : span(s.last_rx) + ' ago'],
              ['Measured offset', ntpMs(s.measured), 'mono'],
              ['Samples kept (sourcestats)', st.np !== undefined ? String(st.np) : '–', 'mono'],
              ['Runs of the residuals', st.nr !== undefined ? String(st.nr) : '–', 'mono'],
              ['Over', st.span !== undefined && st.span !== null ? span(st.span) : '–'],
              ['Frequency', st.freq !== undefined ? st.freq.toFixed(3) + ' ppm' : '–', 'mono'],
              ['Frequency skew', st.freq_skew !== undefined ? st.freq_skew.toFixed(3) + ' ppm' : '–', 'mono'],
              ['Its offset (estimated)', st.offset !== undefined ? ntpMs(st.offset) : '–', 'mono'],
              ['Standard deviation', st.std_dev !== undefined ? ntpMs(st.std_dev).replace('+', '') : '–', 'mono']
            ]));
          });
        };
        return tr;
      }, 'plain', {own: true}));
      var own = nd.own || [];
      if (own.length && !nd.managed) {
        sc.appendChild(el('p', 'muted small', 'Its own ' + (nd.conf_file || '/etc/chrony.conf') + ': '));
        sc.appendChild(noI18n(el('pre', 'mono small', own.join('\n'))));
      }
      host.appendChild(sc);
    }, !!quiet, function () { explainWhatWasDrawn(real); });
  }

  /* The servers (the setting time_servers, a line each: "pool HOST iburst"), drawn as otp's rows
     - each change written back into the setting's own box, so the save bar, its reset and the
     count of changes work as for every other setting. */
  function parseServers(text) {
    return String(text || '').split(/\n/).map(function (l) { return l.trim().split(/\s+/); }).filter(function (p) { return p.length >= 2; })
      .map(function (p) { return {host: p[1], pool: p[0] === 'pool', iburst: p.indexOf('iburst') > 1, prefer: p.indexOf('prefer') > 1, nts: p.indexOf('nts') > 1}; });
  }
  function serversText(list) {
    return list.filter(function (s) { return s.host; }).map(function (s) {
      return [(s.pool ? 'pool' : 'server'), s.host].concat(s.iburst ? ['iburst'] : [], s.prefer ? ['prefer'] : [], s.nts ? ['nts'] : []).join(' ');
    }).join('\n');
  }
  function serversEditor() {
    var item = document.querySelector('#sect-time .set-item[data-key="time_servers"]');
    var box = $('set-time_servers');
    if (!item || !box) { setTimeout(function () { if (PANE === 'time' && $('set-time_servers')) serversEditor(); }, 600); return; }
    if (box._editor) { box._editor.redraw(); return; }
    box.hidden = true;
    var host = el('div');
    box.parentNode.insertBefore(host, box.nextSibling);
    var list = parseServers(box.value);
    var write = function () {
      box.value = serversText(list);
      box.dispatchEvent(new Event('input', {bubbles: true}));
    };
    var draw = function () {
      clear(host);
      var rows = el('div', 'ntp-servers');
      list.forEach(function (s, i) {
        var row = el('div', 'ntp-srv');
        var hostIn = textBox(s.host, 'ntp.example.com', 'mono');
        hostIn.disabled = !ADMIN;
        hostIn.oninput = function () { s.host = hostIn.value.trim(); write(); };
        var kind = selectBox([['server', 'one server'], ['pool', 'a pool (several addresses)']], s.pool ? 'pool' : 'server');
        kind.disabled = !ADMIN;
        kind.onchange = function () { s.pool = kind.value === 'pool'; write(); };
        row.appendChild(hostIn); row.appendChild(kind);
        [['iburst', 'iburst', 'Four quick questions at the start: synchronised in seconds, not minutes.'],
         ['prefer', 'preferred', 'Followed before the others when it is good.'],
         ['nts', 'NTS', 'Network Time Security: the server proves who it is (time.cloudflare.com, ptbtime1.ptb.de, nts.netnod.se…). Needs TCP 4460 out.']].forEach(function (o) {
          var l = el('label', 'check small');
          var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!s[o[0]];
          cb.disabled = !ADMIN;
          cb.onchange = function () { s[o[0]] = cb.checked; write(); };
          l.appendChild(cb); l.appendChild(el('span', '', o[1]));
          explain(l, o[2]);
          row.appendChild(l);
        });
        var x = iconButton('trash', 'Take it away');
        x.disabled = !ADMIN;
        x.onclick = function () { list.splice(i, 1); write(); draw(); };
        row.appendChild(x);
        rows.appendChild(row);
      });
      host.appendChild(rows);
      if (!ADMIN) return;
      var adds = el('div', 'btnrow');
      var add = cmdButton('Add a server', 'add', 'small');
      add.onclick = function () { list.push({host: '', pool: false, iburst: true, prefer: false, nts: false}); draw(); };
      adds.appendChild(add);
      [['pool.ntp.org', true, false], ['2.almalinux.pool.ntp.org', true, false], ['time.cloudflare.com', false, true],
       ['time.google.com', false, false], ['ptbtime1.ptb.de', false, true]].forEach(function (p) {
        var b = cmdButton('+ ' + p[0], '', 'small');
        noI18n(b);
        b.onclick = function () {
          if (list.some(function (s) { return s.host === p[0]; })) return;
          list.push({host: p[0], pool: p[1], iburst: true, prefer: false, nts: p[2]}); write(); draw();
        };
        adds.appendChild(b);
      });
      host.appendChild(adds);
    };
    box._editor = {redraw: function () { list = parseServers(box.value); draw(); }};
    draw();
  }

  /* otp's ntpForm: the switch alone, then - only while it is on - the servers, their buttons and
     a grid of four; the time zone under it. The boxes are the settings' own (the save bar, its
     count and Put them back work as everywhere), laid out as otp's form. */
  var SAYS = {time_manage: 'Off: this machine keeps its own /etc/chrony.conf (AlmaLinux\'s pool, or what you set by hand) - shown and checked here, not changed. On: the servers below; the file\'s own server and pool lines are commented out, and put back when switched off again.',
              time_step_s: 'Further off than this, the clock jumps to the right time instead of being slowed or sped up gently.',
              time_step_n: 'How many updates after chronyd starts may step it: 3 is after a boot; -1 any time.',
              time_minsources: 'The clock is set only when at least this many sources agree. 1 with one server; 2 or 3 with several.',
              time_allow: 'Networks that may ask this machine for the time (UDP 123) - the PS5 and the rest of the home network, say. Empty: nobody. The firewall opens it by itself.',
              time_zone: 'Of the machine: the logs and the times on these pages.'};
  function plain(item) {
    if (!item) return null;
    var i = item.querySelector('.iinfo');
    if (i) i.remove();
    item.classList.remove('wide', 'tall', 'asleep');
    item.style.gridColumn = '';
    var why = item.querySelector('.asleep-why');
    if (why) why.remove();
    var k = item.dataset.key;
    if (k in SAYS) {
      var tail = item.querySelector('.set-tail');
      if (tail) { clear(tail); tail.appendChild(el('div', 'says', SAYS[k])); }
    }
    return item;
  }
  function layout() {
    var sect = $('sect-time');
    if (!sect) return;
    var item = function (k) { return sect.querySelector('.set-item[data-key="' + k + '"]'); };
    if (!item('time_manage') || sect.querySelector('.ntp-body')) return;
    var g0 = el('div', 'formgrid');
    g0.appendChild(plain(item('time_manage')));
    var body = el('div', 'ntp-body');
    var srv = item('time_servers');
    if (srv) {
      plain(srv);
      var lab = srv.querySelector('label');
      if (lab) lab.hidden = true;
      var tl = srv.querySelector('.set-tail');
      if (tl) tl.hidden = true;
      body.appendChild(srv);
    }
    var g = el('div', 'formgrid');
    g.style.marginTop = '14px';
    ['time_step_s', 'time_step_n', 'time_minsources', 'time_allow'].forEach(function (k) { var it = plain(item(k)); if (it) g.appendChild(it); });
    body.appendChild(g);
    var g2 = el('div', 'formgrid');
    g2.style.marginTop = '14px';
    var al = $('set-time_allow');
    if (al) al.placeholder = '192.0.2.0/24';
    var tz = plain(item('time_zone'));
    if (tz) g2.appendChild(tz);
    clear(sect);
    sect.appendChild(g0);
    sect.appendChild(body);
    sect.appendChild(g2);
    var sw = $('set-time_manage');
    var paint = function () { body.hidden = !(sw && sw._get && sw._get()); };
    if (sw && sw._input) sw._input.addEventListener('change', paint);
    paint();
  }
  (function () {
    var theirs = drawSettings;
    drawSettings = function () {
      var ow = SETTINGS && SETTINGS.only_when;
      if (ow) ['time_servers', 'time_step_s', 'time_step_n', 'time_minsources', 'time_allow'].forEach(function (k) { delete ow[k]; });
      var r = theirs.apply(this, arguments);
      try { layout(); if ($('set-time_servers')) { $('set-time_servers')._editor = null; serversEditor(); } } catch (e) { /* as the settings code drew it */ }
      return r;
    };
  }());

  PANE_LOAD.time = function () { layout(); loadNtp(); };
}());
