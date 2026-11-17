/* The Gateway tab (1.8.2): the devices this server is the gateway for, and its FORWARD chain - otp's style.
   Cards with their "why this colour", a card for each device with its traffic over time (sampled every
   minute by the API from root's reading of the counters), its DNS, rules and drops, its UPnP steps and the
   ports it asked for, its live connections (conntrack, read by root), top destinations and ports; the
   whole chain FAKE-IGD-FWD as a flow with the counters of every line; the MikroTik's word on its ports
   when that is read. Read-only accounts see it all; nothing here changes anything. */
(function () {
  'use strict';
  var GT = {d: null, steps: {}, ports: {}, timer: null, busy: false};

  function host() { return $('gt-body'); }
  function kb(n) { return n ? bytes(n) : '0 B'; }
  function rate(n) { return n ? bytes(Math.round(n)) + '/s' : 'idle'; }

  function load(quietly) {
    if (GT.busy) return;
    GT.busy = true;
    var win = tpQuery('gt-hours', 'since', 'until');
    Promise.all([api('gateway-tab' + win), api('upnp-steps' + win).catch(function () { return {clients: {}}; })]).then(function (two) {
      GT.d = two[0]; GT.steps = two[1].clients || {};
      draw(quietly);
      (GT.d.devices || []).forEach(function (x) {
        api('ports&q=' + encodeURIComponent('client:' + x.ip) + '&sort=last&per=50').then(function (p) {
          GT.ports[x.ip] = p.ports || [];
          var box = document.querySelector('#gt-ports-' + x.id);
          if (box) { clear(box); box.appendChild(portsList(GT.ports[x.ip])); }
        }).catch(function () {});
      });
    }).catch(function (e) { if (!quietly) oops(e); }).then(function () { GT.busy = false; });
  }
  window.loadGatewayTab = function () {
    load(false);
    if (!GT.timer) GT.timer = setInterval(function () { if (TAB === 'gateway' && !document.hidden) load(true); }, 20000);
  };

  /* ---- the cards ---- */
  function card(label, value, sub, tone, why, more) {
    var c = el('div', 'card metric tappable ' + tone);
    c.appendChild(el('div', 'label', label));
    c.appendChild(noI18n(el('div', 'value', value)));
    c.appendChild(el('div', 'sub', sub || ' '));
    c.onclick = function () {
      modal(label, function (body) {
        body.appendChild(el('p', 'note ' + (tone === 'ok' ? 'good' : (tone === 'crit' ? 'bad' : tone)), why));
        if (more) body.appendChild(more());
      }, null, 'narrow');
    };
    return c;
  }
  function cards(d) {
    var v = d.view || {}, lv = v.live || {}, nv = v.net || {}, ap = v.applied || {};
    var on = ap.on && lv.ip_forward === '1';
    var devs = d.devices || [], act = devs.filter(function (x) { return x.on && x.applied; });
    var g = el('div', 'grid top gt-cards');
    g.appendChild(card('Forwarding', on ? 'on' : 'off', on ? 'net.ipv4.ip_forward 1 · FAKE-IGD-FWD first' : (ap.why_off || 'nothing is forwarded'),
      on ? 'ok' : (v.on ? 'crit' : 'info'),
      on ? 'Green: this server forwards for the devices below - only toward the router, nothing else (the chain ends in a DROP).'
         : (v.on ? 'Red: switched on, but the kernel does not forward - ' + (ap.why_off || 'see Settings → Gateway for devices') + '.'
                 : 'Blue: the gateway for devices is off - nothing is forwarded, as it comes.')));
    g.appendChild(card('Devices', num(act.length) + ' of ' + num(devs.length), act.map(function (x) { return x.name; }).join(', ') || 'none forwarded',
      act.length ? 'ok' : 'info', act.length ? 'Green: these devices use this server as their gateway and are forwarded.' : 'Blue: no device is forwarded now.'));
    g.appendChild(card('Sent today', kb((d.today || {}).bytes), num((d.today || {}).pkts) + ' packets · now ' + rate((d.today || {}).rate),
      (d.today || {}).bytes ? 'ok' : 'info', 'What the devices sent through this server since midnight, from the counters sampled every minute. The answers come from the router directly - they do not pass here.'));
    g.appendChild(card('Dropped', num(d.dropped || 0), num(d.dropped_today || 0) + ' toward local networks today',
      d.dropped_today ? 'warn' : 'ok', d.dropped_today ? 'Yellow: a device tried networks it may not reach (counted for it before the drops) - see its card.'
        : 'Green: the final DROP\'s packets (anything that is no device\'s) and nothing of the devices toward local networks today.'));
    g.appendChild(card('The router', nv.router || '–', 'via ' + (nv.defif || '?'), nv.router ? 'info' : 'crit',
      nv.router ? 'The default route: the devices\' traffic goes out ' + nv.defif + ' to ' + nv.router + '.' : 'Red: this server has no default route.'));
    g.appendChild(card('This server there', nv.address ? nv.address + '/' + nv.prefix : '–', 'the devices\' Default Gateway', 'info',
      'What the devices have as their Default Gateway: this server\'s address on ' + (nv.defif || '?') + '.'));
    return g;
  }

  /* ---- a chart of bytes per bucket (the Overview's look) ---- */
  function chart(x) {
    var box = el('div', 'chart gt-chart');
    var tip = el('div', 'tip');
    box.appendChild(tip);
    var s = (x.chart || {}).series || [];
    setTimeout(function () { paintChart(box, tip, s, (x.chart || {}).step || 60); }, 0);
    return box;
  }
  function paintChart(box, tip, s, step) {
    if (!s.some(function (p) { return p.bytes || p.dropped; })) { box.appendChild(el('div', 'empty', 'Nothing went through in this window')); return; }
    var W = box.clientWidth || 700, H = box.clientHeight || 200, padL = 64, padR = 12, padT = 12, padB = 26;
    var w = Math.max(10, W - padL - padR), h = Math.max(10, H - padT - padB);
    var top = Math.max(1, s.reduce(function (m, p) { return Math.max(m, p.bytes); }, 0));
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');
    function make(k, a) { var n = document.createElementNS(NS, k); for (var i in a) n.setAttribute(i, a[i]); return n; }
    for (var g = 0; g <= 4; g++) {
      var y = padT + h - h * g / 4;
      svg.appendChild(make('line', {x1: padL, x2: W - padR, y1: y, y2: y, stroke: '#262c37', 'stroke-width': 1}));
      var t = make('text', {x: padL - 8, y: y + 4, fill: '#5b6472', 'font-size': 11, 'text-anchor': 'end'});
      t.textContent = bytes(Math.round(top * g / 4));
      svg.appendChild(t);
    }
    var bw = w / s.length;
    var pts = [];
    s.forEach(function (p, i) {
      var x = padL + bw * i + bw / 2, bh = h * p.bytes / top;
      pts.push(x + ',' + (padT + h - bh));
      if (p.dropped) svg.appendChild(make('rect', {x: x - 1.5, y: padT + h - 6, width: 3, height: 6, fill: '#f85149', rx: 1}));
    });
    var area = make('polygon', {points: (padL + bw / 2) + ',' + (padT + h) + ' ' + pts.join(' ') + ' ' + (padL + bw * (s.length - 0.5)) + ',' + (padT + h),
                                fill: 'rgba(88,166,255,.18)', stroke: 'none'});
    svg.appendChild(area);
    svg.appendChild(make('polyline', {points: pts.join(' '), fill: 'none', stroke: '#58a6ff', 'stroke-width': 1.6}));
    var every = Math.max(1, Math.ceil(s.length / Math.max(3, Math.floor(w / 80))));
    s.forEach(function (p, i) {
      if (i % every) return;
      var dd = new Date(p.t * 1000);
      var t = make('text', {x: padL + bw * i + bw / 2, y: H - 8, fill: '#5b6472', 'font-size': 11, 'text-anchor': 'middle'});
      t.textContent = step >= 3600 ? pad2(dd.getDate()) + '-' + pad2(dd.getMonth() + 1) + ' ' + pad2(dd.getHours()) + 'h' : clockWords(dd, false);
      svg.appendChild(t);
    });
    s.forEach(function (p, i) {
      var hit = make('rect', {x: padL + bw * i, y: padT, width: bw, height: h, fill: 'transparent'});
      hit.addEventListener('mousemove', function (e) {
        var b = box.getBoundingClientRect();
        tip.innerHTML = '<b>' + stamp(p.t) + '</b><br><span style="color:#58a6ff">' + bytes(p.bytes) + ' sent · ' + num(p.pkts) + ' pkts</span>'
          + (p.dns ? '<br>' + num(p.dns) + ' DNS packet(s)' : '') + (p.rules ? '<br>' + num(p.rules) + ' through its own rules' : '')
          + (p.dropped ? '<br><span style="color:#f85149">' + num(p.dropped) + ' dropped toward local networks</span>' : '');
        tip.style.display = 'block';
        var left = e.clientX - b.left + 12;
        if (left + tip.offsetWidth > b.width) left = e.clientX - b.left - tip.offsetWidth - 12;
        tip.style.left = Math.max(0, left) + 'px';
        tip.style.top = Math.max(0, e.clientY - b.top - 12) + 'px';
      });
      hit.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
      svg.appendChild(hit);
    });
    box.appendChild(svg);
  }
  function pad2(n) { return ('0' + n).slice(-2); }

  /* ---- lists with bars ---- */
  function barList(rows, label, value, max) {
    var box = el('div', 'gt-bars');
    if (!rows.length) { box.appendChild(el('p', 'muted small', 'nothing now')); return box; }
    var top = max || Math.max.apply(null, rows.map(value)) || 1;
    rows.forEach(function (r) {
      var row = el('div', 'gt-bar');
      var l = el('div', 'gt-bar-l');
      l.appendChild(label(r));
      row.appendChild(l);
      var b = el('div', 'gt-bar-b');
      var f = el('span');
      f.style.width = Math.max(2, Math.round(100 * value(r) / top)) + '%';
      b.appendChild(f);
      row.appendChild(b);
      row.appendChild(el('span', 'gt-bar-v', r._v || ''));
      box.appendChild(row);
    });
    return box;
  }
  function portsList(ps) {
    if (!ps.length) return el('p', 'muted small', 'It asked for no port in this window.');
    var w = el('div', 'gt-chips');
    ps.slice(0, 30).forEach(function (p) {
      var c = el('span', 'gt-chip');
      c.appendChild(protoTag(p.proto));
      c.appendChild(noI18n(el('span', 'mono', ' ' + p.port)));
      w.appendChild(c);
    });
    if (ps.length > 30) w.appendChild(el('span', 'muted small', '… ' + (ps.length - 30) + ' more'));
    return w;
  }
  function connTable(cs, few) {
    return listTable(['', 'To', {words: 'Port', cls: 'num'}, 'What it is', 'State', {words: 'Packets', cls: 'num'}, {words: 'Sent', cls: 'num'}, {words: 'Expires in', cls: 'num'}],
      few ? cs.slice(0, 12) : cs, function (c) {
        var tr = el('tr', 'tappable');
        var td = el('td'); td.appendChild(protoTag(c.proto)); tr.appendChild(td);
        tr.appendChild(noI18n(el('td', 'mono', c.dst)));
        tr.appendChild(noI18n(el('td', 'num mono', c.dport || '–')));
        tr.appendChild(el('td', 'small', (GT.labels || {})[c.dport] || portWords(c.dport)));
        var stc = el('td');
        stc.appendChild(c.state ? el('span', 'tag ' + (c.assured || c.replied ? 'ok' : 'dim'), c.state) : el('span', 'muted', '–'));
        tr.appendChild(stc);
        tr.appendChild(el('td', 'num', num(c.pkts)));
        tr.appendChild(el('td', 'num', kb(c.bytes)));
        tr.appendChild(el('td', 'num muted', span(c.timeout || 0)));
        tr.onclick = function () {
          modalOver(function () {
            modal('A connection to ' + c.dst, function (body) {
              body.appendChild(peekFacts([['Protocol', c.proto], ['To', noI18n(el('span', 'mono', c.dst + ':' + c.dport))],
                ['From its port', String(c.sport)], ['State', c.state || '–'], ['Packets sent', num(c.pkts)], ['Bytes sent', kb(c.bytes)],
                ['Answered', c.replied ? 'yes' : 'not seen here'], ['Expires in', span(c.timeout || 0)]]));
              body.appendChild(el('p', 'note', 'As this server\'s connection tracking has it (conntrack). It sees the way out only: the answers come from the router to the device directly, so "not seen here" is usual - and the bytes are what the device sent.'));
            }, null, 'narrow');
          });
        };
        return tr;
      }, 'rows|No connection of it now', {own: true});
  }
  function portWords(p) {
    return {53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 853: 'DNS over TLS', 123: 'NTP', 3478: 'PSN (STUN)', 3479: 'PSN (STUN)', 3480: 'PSN', 1900: 'SSDP'}[p] || '';
  }

  /* ---- a device ---- */
  function deviceCard(x) {
    var c = el('div', 'card full gt-device');
    var head = el('div', 'gt-dev-head');
    var online = (x.neigh_mac && (!x.mac || x.neigh_mac === x.mac)) || (x.seen && Date.now() / 1000 - x.seen < 600);
    head.appendChild(el('span', 'dot ' + (online ? 'ok' : 'dim')));
    var t = el('div', 'gt-dev-title');
    t.appendChild(el('b', '', x.name));
    t.appendChild(noI18n(el('span', 'mono', x.ip)));
    t.appendChild(noI18n(el('span', 'mono small muted', x.mac || 'any MAC')));
    head.appendChild(t);
    head.appendChild(el('span', 'tag ' + (x.applied ? 'ok' : (x.on ? 'warn' : 'dim')), x.applied ? 'forwarded' : (x.on ? 'not put in' : 'off')));
    head.appendChild(el('span', 'small muted', online ? 'online - ' + (x.seen ? 'last through ' + ago(x.seen) : 'in the neighbour table') : (x.seen ? 'last through ' + ago(x.seen) : 'not seen')));
    if (ADMIN && window.GW_DESIGNER) {
      var fw = cmdButton('Its firewall', 'wall', 'small');
      fw.onclick = function () { location.hash = '#settings/gateway'; setTimeout(function () { window.GW_DESIGNER && window.GW_DESIGNER(x); }, 1200); };
      head.appendChild(el('span', 'right')).appendChild(fw);
    }
    c.appendChild(head);
    var r = x.rules || [], dn = x.dns || [];
    var hitsOf = function (list) { return list.reduce(function (s, y) { return s + ((y.hits || {}).pkts || 0); }, 0); };
    c.appendChild(peekFacts([['Sent today', kb(x.today.bytes)], ['Packets today', num(x.today.pkts)], ['Now', rate(x.today.rate)],
      ['Connections now', num(x.conns_n)], ['Internet line', num((x.internet || {}).pkts || 0) + ' pkts'],
      ['DNS asked', dn.length ? num(hitsOf(dn)) + ' pkts · ' + dn.length + ' server(s)' : 'as now'],
      ['Own rules', r.length ? num(hitsOf(r)) + ' pkts · ' + r.length + ' rule(s)' : 'none'],
      ['Dropped toward local nets', num((x.dropped || {}).pkts || 0)]]));
    c.appendChild(el('h3', 'peek-h', 'Sent through this server'));
    c.appendChild(chart(x));
    var grid = el('div', 'gt-grid');
    var a = el('div', 'gt-col');
    a.appendChild(el('h3', 'peek-h', 'Top destinations now'));
    a.appendChild(barList((x.top_dst || []).map(function (y) { y._v = kb(y.bytes) + ' · ' + y.conns + ' conn'; return y; }),
      function (y) { var s = el('span', ''); s.appendChild(noI18n(el('span', 'mono', y.dst))); s.appendChild(el('span', 'muted small', ' ' + y.ports.slice(0, 4).join(', '))); return s; },
      function (y) { return y.bytes; }));
    a.appendChild(el('h3', 'peek-h', 'Top ports now'));
    a.appendChild(barList((x.top_ports || []).map(function (y) { y._v = num(y.conns) + ' conn · ' + kb(y.bytes); return y; }),
      function (y) { var s = el('span', ''); s.appendChild(protoTag(y.proto)); s.appendChild(noI18n(el('span', 'mono', ' ' + y.port))); if (y.words) s.appendChild(el('span', 'muted small', ' ' + y.words)); return s; },
      function (y) { return y.conns; }));
    grid.appendChild(a);
    var b = el('div', 'gt-col');
    b.appendChild(el('h3', 'peek-h', 'What it may reach besides the internet'));
    var lanes = el('div', 'gwf-lanes');
    dn.forEach(function (y) {
      var l = el('div', 'gwf-lane ' + (y.direct ? 'direct' : 'ok'));
      l.appendChild(el('span', 'gwf-mark', y.direct ? '·' : '✓'));
      var w = el('div', 'gwf-words'); w.appendChild(el('b', '', 'DNS ' + y.ip)); w.appendChild(el('span', 'gwf-detail', y.direct ? 'reached directly' : 'udp/tcp 53' + (y.dot ? ' + 853' : '') + ' out ' + y.via));
      l.appendChild(w); l.appendChild(el('span', 'gwf-hits', num((y.hits || {}).pkts || 0) + ' pkts'));
      lanes.appendChild(l);
    });
    r.forEach(function (y) {
      var l = el('div', 'gwf-lane ' + (y.on ? 'ok' : 'off'));
      l.appendChild(el('span', 'gwf-mark', y.on ? '✓' : '·'));
      var w = el('div', 'gwf-words'); w.appendChild(el('b', '', y.comment || 'a rule of its own'));
      w.appendChild(noI18n(el('span', 'gwf-detail mono', (y.proto === 'any' ? 'any' : y.proto + (y.ports ? ' ' + y.ports : '')) + ' → ' + y.to)));
      l.appendChild(w); l.appendChild(el('span', 'gwf-hits', num((y.hits || {}).pkts || 0) + ' pkts · ' + kb((y.hits || {}).bytes)));
      lanes.appendChild(l);
    });
    if (!dn.length && !r.length) lanes.appendChild(el('p', 'muted small', 'Nothing - the internet only, as it comes.'));
    b.appendChild(lanes);
    b.appendChild(el('h3', 'peek-h', 'Dropped toward local networks'));
    b.appendChild(barList((x.drops_by_net || []).map(function (y) { y._v = num(y.pkts) + ' pkts'; return y; }),
      function (y) { return noI18n(el('span', 'mono', y.to)); }, function (y) { return y.pkts; }));
    b.appendChild(el('h3', 'peek-h', 'Its UPnP steps'));
    var st = GT.steps[x.ip];
    b.appendChild(typeof stepPills === 'function' ? stepPills(st || {reached: [], furthest: -1}) : el('span', '', ''));
    if (st && st.stopped) b.appendChild(el('p', 'muted small', st.stopped));
    b.appendChild(el('h3', 'peek-h', 'The ports it asked for'));
    var pbox = el('div'); pbox.id = 'gt-ports-' + x.id;
    pbox.appendChild(portsList(GT.ports[x.ip] || []));
    b.appendChild(pbox);
    if (x.mikrotik && x.mikrotik.length) {
      b.appendChild(el('h3', 'peek-h', 'On the MikroTik'));
      var mt = el('div', 'gt-chips');
      x.mikrotik.forEach(function (m) {
        var ok = m.state === 'ok';
        var ch = el('a', 'gt-chip ' + (ok ? 'ok' : 'warn'));
        ch.appendChild(protoTag(m.proto));
        ch.appendChild(noI18n(el('span', 'mono', ' ' + m.port + ' ' + (ok ? '✓' : '✗'))));
        ch.title = ok ? 'DNAT and accept in place' : (m.nat_why || m.state);
        ch.onclick = function () { location.hash = '#settings/mikrotik'; };
        mt.appendChild(ch);
      });
      b.appendChild(mt);
    }
    grid.appendChild(b);
    c.appendChild(grid);
    var ch = el('div', 'gt-conn-h');
    ch.appendChild(el('h3', 'peek-h', 'Its connections now (' + num(x.conns_n) + ')'));
    if ((x.conns || []).length > 12) {
      var all = cmdButton('All of them', 'list', 'small');
      all.onclick = function () { modal('The connections of ' + x.name, function (body) { body.appendChild(connTable(x.conns, false)); }, null, 'large'); };
      ch.appendChild(all);
    }
    c.appendChild(ch);
    c.appendChild(connTable(x.conns || [], true));
    return c;
  }

  /* ---- the whole chain ---- */
  function chainCard(d) {
    var c = el('div', 'card full gt-chain');
    c.appendChild(el('h2', '', 'FAKE-IGD-FWD, line by line'));
    c.appendChild(el('p', 'note', 'FORWARD jumps here first (' + ((d.jump || [])[0] || 'no jump') + '); the first line that fits decides. FORWARD\'s own policy: ' + (d.policy || '?') + ' - never reached by a device\'s packet: the chain ends in a DROP of its own.'));
    var lines = d.chain || [];
    if (!lines.length) { c.appendChild(el('p', 'muted', 'Not in place - the gateway for devices is off.')); return c; }
    var top = Math.max.apply(null, lines.map(function (y) { return y.pkts || 0; })) || 1;
    var list = el('div', 'gt-flow');
    var groups = [], cur = null;
    lines.forEach(function (y, i) {
      var g = /dropped toward/.test(y.comment) ? 'Dropped for a device, counted for it' : (/never forwarded/.test(y.comment) ? 'Never forwarded to, for anybody'
        : (/gateway for/.test(y.comment) ? 'The internet, for each device' : (/nothing else/.test(y.comment) ? 'Nothing else' : 'Allowed for a device: its DNS and rules')));
      if (!cur || cur.name !== g) { cur = {name: g, rows: []}; groups.push(cur); }
      cur.rows.push({y: y, i: i});
    });
    groups.forEach(function (g) {
      var det = el('details', 'gt-flow-d');
      var sum = g.rows.reduce(function (s, r) { return s + (r.y.pkts || 0); }, 0);
      det.open = !/^(Dropped for|Never forwarded)/.test(g.name);
      var smy = el('summary', 'gt-flow-g');
      smy.appendChild(document.createTextNode(g.name + ' - ' + g.rows.length + ' line' + (g.rows.length > 1 ? 's' : '')));
      smy.appendChild(el('span', 'gt-flow-sum', sum ? num(sum) + ' pkts' : 'no packet'));
      det.appendChild(smy);
      g.rows.forEach(function (r) {
        var y = r.y, i = r.i;
        var row = el('div', 'gt-flow-r ' + (y.target === 'ACCEPT' ? 'ok' : 'no'));
        row.appendChild(el('span', 'gt-flow-n', String(i + 1)));
        row.appendChild(el('span', 'gwf-mark', y.target === 'ACCEPT' ? '✓' : '✗'));
        row.appendChild(noI18n(el('span', 'gt-flow-c', (y.comment || y.line).replace(/^fake-igd: /, ''))));
        var bar = el('span', 'gt-flow-b'); var f = el('span'); f.style.width = (y.pkts ? Math.max(2, Math.round(100 * y.pkts / top)) : 0) + '%'; bar.appendChild(f);
        row.appendChild(bar);
        row.appendChild(el('span', 'gt-flow-v', y.pkts ? num(y.pkts) + ' · ' + kb(y.bytes) : '–'));
        row.onclick = function () {
          modal('Line ' + (i + 1) + ' of FAKE-IGD-FWD', function (body) {
            body.appendChild(peekFacts([['Does', y.target], ['Packets', num(y.pkts)], ['Bytes', kb(y.bytes)]]));
            body.appendChild(noI18n(el('pre', 'mono small', y.line)));
          }, null, 'narrow');
        };
        det.appendChild(row);
      });
      list.appendChild(det);
    });
    c.appendChild(list);
    return c;
  }

  function draw(quietly) {
    var h = host();
    if (!h || !GT.d) return;
    var d = GT.d;
    $('gt-read').textContent = d.read_at ? 'read by root ' + ago(d.read_at) : 'not read yet';
    liveFill(h, function (box) {
      box.appendChild(cards(d));
      if (!(d.devices || []).length) {
        var e = el('div', 'card full');
        e.appendChild(el('h2', '', 'No device uses this server as its gateway'));
        e.appendChild(el('p', 'note', 'A PS5 asks UPnP only of its default gateway. Settings → Gateway for devices makes this server the gateway of the devices you choose - only theirs, only toward the router.'));
        if (ADMIN) { var go = cmdButton('Open Gateway for devices', 'router', 'primary'); go.onclick = function () { location.hash = '#settings/gateway'; }; e.appendChild(go); }
        box.appendChild(e);
      }
      (d.devices || []).forEach(function (x) { box.appendChild(deviceCard(x)); });
      box.appendChild(chainCard(d));
    }, quietly, function () { explainWhatWasDrawn(h); });
  }

  if ($('gt-hours')) {
    timePicker('gt-hours', {start: {k: 'rel', s: 86400}});
    $('gt-hours').onchange = function () { load(false); };
  }
  if ($('gt-refresh')) $('gt-refresh').onclick = function () { load(false); };
}());
