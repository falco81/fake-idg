/* The Gateway tab (1.8.2; two sub-tabs since 1.9.2), otp's style. Read-only accounts see it all; nothing
   here changes anything but a device's own firewall, through its designer, for a full admin.
     Devices (the default): the cards with their "why this colour"; a compact card for each device - what it
       sent today and now, its traffic over time (sampled every minute by the API from root's reading of the
       counters), what it may reach, its UPnP steps, its way out and ports on the MikroTik, links to its
       Clients, Requests, Ports and Mappings - and Details (a popup: top destinations and ports, drops, the
       ports it asked for, its live connections) and Its firewall (the designer, as a popup, right here);
       then the whole chain FAKE-IGD-FWD as a flow with the counters of every line.
     MikroTik: the real router as read (mt-view.js) - each device's way out and its public address, its
       ports there, the whole firewall.
   The address follows: #gateway/devices[/IP], #gateway/mikrotik[/IP[/proto/port]]. */
(function () {
  'use strict';
  var GT = {d: null, steps: {}, ports: {}, timer: null, busy: false, sub: 'devices', more: '', focus: null, gw: null};

  function host() { return $('gt-body'); }
  function kb(n) { return n ? bytes(n) : '0 B'; }
  function rate(n) { return n ? bytes(Math.round(n)) + '/s' : 'idle'; }

  /* ---- the sub-tabs ---- */
  function setSub(name) {
    GT.sub = name === 'mikrotik' ? 'mikrotik' : 'devices';
    document.querySelectorAll('#tab-gateway .gt-subtabs button[data-sub]').forEach(function (b) {
      b.setAttribute('aria-selected', b.getAttribute('data-sub') === GT.sub ? 'true' : 'false');
    });
    var dev = GT.sub === 'devices';
    if ($('gt-body')) $('gt-body').hidden = !dev;
    if ($('gt-mt')) $('gt-mt').hidden = dev;
    if ($('gt-note-devices')) $('gt-note-devices').hidden = !dev;
    if ($('gt-note-mikrotik')) $('gt-note-mikrotik').hidden = dev;
    if ($('gt-hours')) $('gt-hours').hidden = !dev;
    if ($('gt-read')) $('gt-read').hidden = !dev;
  }
  function loadSub(quietly) {
    if (GT.sub === 'mikrotik') {
      if (window.MTV) window.MTV.load($('gt-mt'), quietly);
      if (GT.focus && window.MTV) { window.MTV.focus(GT.focus); GT.focus = null; }
    } else load(quietly);
    dotMikrotik();
  }
  document.querySelectorAll('#tab-gateway .gt-subtabs button[data-sub]').forEach(function (b) {
    b.onclick = function () {
      if (GT.sub === b.getAttribute('data-sub') && !GT.more) return;
      GT.more = ''; GT.focus = null;
      setSub(b.getAttribute('data-sub'));
      writeHash();
      loadSub(false);
    };
  });
  TAB_HASH.gateway = function () { return GT.sub + (GT.more ? '/' + GT.more : ''); };
  TAB_ROUTE.gateway = function (parts) {
    var sub = parts[0] === 'mikrotik' ? 'mikrotik' : 'devices';
    var ip = parts[1] || '', proto = parts[2] || '', port = parts[3] || '';
    GT.more = [ip, ip && port ? proto : '', ip && port ? port : ''].filter(Boolean).join('/');
    GT.focus = ip ? {ip: ip, proto: proto, port: port} : null;
    setSub(sub);
    if (TAB !== 'gateway') showTab('gateway');
    else { writeHash(); loadSub(false); }
  };
  /* the MikroTik sub-tab's light: green, yellow, red - or none while it is not read */
  function dotMikrotik() {
    var dot = $('gt-subdot-mt');
    if (!dot || typeof window.MT_CHECKS !== 'function') return;
    window.MT_CHECKS().then(function (d) {
      var st = d.state || {}, ch = d.checks || {};
      var k = !d.on ? '' : (st.ok === false ? 'crit' : (!ch.total ? 'ok' : (ch.open === ch.total && !(ch.ways || []).some(function (w) { return !w.ok; }) ? 'ok' : (ch.open ? 'warn' : 'crit'))));
      dot.className = 'gt-subdot' + (k ? ' ' + k : '');
      dot.title = !d.on ? 'not read' : (st.ok === false ? 'it cannot be read' : (ch.total ? num(ch.open) + ' of ' + num(ch.total) + ' port(s) open' : 'read'));
    }).catch(function () {});
  }

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
    setSub(GT.sub);
    loadSub(false);
    if (!GT.timer) GT.timer = setInterval(function () {
      if (TAB !== 'gateway' || document.hidden) return;
      if (GT.sub === 'devices') load(true);
      else if (Date.now() - (GT.mtAt || 0) > 60000) { GT.mtAt = Date.now(); if (window.MTV) window.MTV.load(null, true); }
    }, 20000);
  };
  window.gtDeviceName = function (ip) {
    var x = ((GT.d && GT.d.devices) || []).filter(function (y) { return y.ip === ip; })[0]
      || ((GT.gw && GT.gw.devices) || []).filter(function (y) { return y.ip === ip; })[0];
    return x ? x.name : '';
  };

  /* ---- links into the other tabs: from here to them, and from them to here ---- */
  function linkBtn(words, icon, go, title) {
    var b = el('button', 'gx-link');
    b.type = 'button';
    b.innerHTML = iconMarkup(icon, 14);
    b.appendChild(document.createTextNode(words));
    if (title) b.title = title;
    b.onclick = function (ev) { ev.stopPropagation(); closeModal(); go(); };
    return b;
  }
  function devLinks(x, withMt) {
    var box = el('div', 'gx-links');
    box.appendChild(linkBtn('Clients', 'people', function () { goTab('clients', {ip: x.ip}); }, 'The Clients tab: ' + x.ip + ', with its popup'));
    box.appendChild(linkBtn('Requests', 'list', function () { goTab('requests', {ip: x.ip}); }, 'The Requests tab: what ' + x.ip + ' asked fake-igd'));
    box.appendChild(linkBtn('Ports', 'net', function () { goTab('ports', {ip: x.ip}); }, 'The Ports tab: the ports ' + x.ip + ' asked for'));
    box.appendChild(linkBtn('Mappings', 'router', function () { goTab('mappings', {ip: x.ip}); }, 'The Mappings tab: what ' + x.ip + ' holds now'));
    if (withMt) box.appendChild(linkBtn('Its way on the MikroTik', 'wall', function () { goTab('gateway', {sub: 'mikrotik', ip: x.ip}); }, 'Gateway → MikroTik: its way out and its ports there'));
    return box;
  }
  function gwDevices() {
    if (GT.gw && Date.now() - GT.gw.at < 60000) return Promise.resolve(GT.gw);
    return api('gateway').then(function (d) { GT.gw = {at: Date.now(), devices: d.devices || []}; return GT.gw; });
  }
  /* For the Clients, Ports and Mappings popups: to this device's card and to its way on the MikroTik, when
     it is a device of the gateway or the MikroTik says anything of it. Empty and hidden otherwise. */
  window.gatewayLinksFor = function (ip, port, proto) {
    var box = el('div', 'gx-links gx-links-gw');
    box.hidden = true;
    if (!ip) return box;
    Promise.all([gwDevices().catch(function () { return {devices: []}; }),
                 typeof window.MT_CHECKS === 'function' ? window.MT_CHECKS().catch(function () { return {}; }) : Promise.resolve({})]).then(function (two) {
      var dev = (two[0].devices || []).filter(function (y) { return y.ip === ip; })[0];
      var ch = (two[1] && two[1].on && two[1].checks) || {};
      var row = port ? (ch.rows || []).filter(function (r) { return r.device === ip && String(r.port) === String(port) && (!proto || r.proto === String(proto).toLowerCase()); })[0] : null;
      var mt = (ch.ways || []).some(function (w) { return w.device === ip; }) || (ch.rows || []).some(function (r) { return r.device === ip; });
      if (!dev && !mt) return;
      box.appendChild(el('span', 'gx-links-k', 'Gateway'));
      if (dev) box.appendChild(linkBtn('Its card' + (dev.name ? ' (' + dev.name + ')' : ''), 'router', function () { goTab('gateway', {sub: 'devices', ip: ip}); }, 'Gateway → Devices: its card'));
      if (mt) box.appendChild(linkBtn('Its way out on the MikroTik', 'wall', function () { goTab('gateway', {sub: 'mikrotik', ip: ip}); }, 'Gateway → MikroTik: the way it goes out and the public address'));
      if (row) {
        var S = (window.MT_STATE || {})[row.state] || ['?', 'dim'];
        var b = linkBtn('This port on the MikroTik: ' + S[0], 'wall', function () { goTab('gateway', {sub: 'mikrotik', ip: ip, proto: row.proto, port: row.port}); }, 'Gateway → MikroTik: dst-nat, forward, the device');
        b.classList.add(S[1]);
        box.appendChild(b);
      }
      box.hidden = false;
    });
    return box;
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
  function chart(x, small) {
    var box = el('div', 'chart gt-chart' + (small ? ' gt-chart-s' : ''));
    var tip = el('div', 'tip');
    box.appendChild(tip);
    var s = (x.chart || {}).series || [];
    setTimeout(function () { paintChart(box, tip, s, (x.chart || {}).step || 60, small); }, 0);
    return box;
  }
  function paintChart(box, tip, s, step, small) {
    if (!s.some(function (p) { return p.bytes || p.dropped; })) { box.classList.add('is-empty'); box.appendChild(el('div', 'empty', 'Nothing went through in this window')); return; }
    box.classList.remove('is-empty');
    var W = box.clientWidth || 700, H = box.clientHeight || 200, padL = small ? 54 : 64, padR = 12, padT = 12, padB = 26;
    var w = Math.max(10, W - padL - padR), h = Math.max(10, H - padT - padB);
    var top = Math.max(1, s.reduce(function (m, p) { return Math.max(m, p.bytes); }, 0));
    var NS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');
    function make(k, a) { var n = document.createElementNS(NS, k); for (var i in a) n.setAttribute(i, a[i]); return n; }
    var steps = small ? 2 : 4;
    for (var g = 0; g <= steps; g++) {
      var y = padT + h - h * g / steps;
      svg.appendChild(make('line', {x1: padL, x2: W - padR, y1: y, y2: y, 'class': 'gt-grid-l'}));
      var t = make('text', {x: padL - 8, y: y + 4, 'class': 'gt-axis', 'font-size': 11, 'text-anchor': 'end'});
      t.textContent = bytes(Math.round(top * g / steps));
      svg.appendChild(t);
    }
    var bw = w / s.length;
    var pts = [];
    s.forEach(function (p, i) {
      var x = padL + bw * i + bw / 2, bh = h * p.bytes / top;
      pts.push(x + ',' + (padT + h - bh));
      if (p.dropped) svg.appendChild(make('rect', {x: x - 1.5, y: padT + h - 6, width: 3, height: 6, 'class': 'gt-drop', rx: 1}));
    });
    svg.appendChild(make('polygon', {points: (padL + bw / 2) + ',' + (padT + h) + ' ' + pts.join(' ') + ' ' + (padL + bw * (s.length - 0.5)) + ',' + (padT + h), 'class': 'gt-area'}));
    svg.appendChild(make('polyline', {points: pts.join(' '), 'class': 'gt-line', fill: 'none', 'stroke-width': 1.6}));
    var every = Math.max(1, Math.ceil(s.length / Math.max(3, Math.floor(w / 80))));
    s.forEach(function (p, i) {
      if (i % every) return;
      var dd = new Date(p.t * 1000);
      var t = make('text', {x: padL + bw * i + bw / 2, y: H - 8, 'class': 'gt-axis', 'font-size': 11, 'text-anchor': 'middle'});
      t.textContent = step >= 3600 ? pad2(dd.getDate()) + '-' + pad2(dd.getMonth() + 1) + ' ' + pad2(dd.getHours()) + 'h' : clockWords(dd, false);
      svg.appendChild(t);
    });
    s.forEach(function (p, i) {
      var hit = make('rect', {x: padL + bw * i, y: padT, width: bw, height: h, fill: 'transparent'});
      hit.addEventListener('mousemove', function (e) {
        var b = box.getBoundingClientRect();
        clear(tip);
        tip.appendChild(el('b', '', stamp(p.t)));
        tip.appendChild(el('div', 'gt-tip-v', bytes(p.bytes) + ' sent · ' + num(p.pkts) + ' pkts'));
        if (p.dns) tip.appendChild(el('div', '', num(p.dns) + ' DNS packet(s)'));
        if (p.rules) tip.appendChild(el('div', '', num(p.rules) + ' through its own rules'));
        if (p.dropped) tip.appendChild(el('div', 'bad', num(p.dropped) + ' dropped toward local networks'));
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
      var c = el('button', 'gt-chip');
      c.type = 'button';
      c.appendChild(protoTag(p.proto));
      c.appendChild(noI18n(el('span', 'mono', ' ' + p.port)));
      c.title = 'The Ports tab: this port';
      c.onclick = function () { closeModal(); goTab('ports', {ip: p.client, port: p.port, proto: p.proto}); };
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
        tr.appendChild(el('td', 'small', portWords(c.dport)));
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
  function hitsOf(list) { return list.reduce(function (s, y) { return s + ((y.hits || {}).pkts || 0); }, 0); }
  function online(x) { return (x.neigh_mac && (!x.mac || x.neigh_mac === x.mac)) || (x.seen && Date.now() / 1000 - x.seen < 600); }
  function openFirewall(x) { if (window.GW_DESIGNER_OPEN) window.GW_DESIGNER_OPEN(x.id || x.ip, {saved: function () { load(true); }}); }
  function lanesOf(x, compact) {
    var lanes = el('div', 'gwf-lanes' + (compact ? ' gt-lanes-s' : ''));
    var dn = x.dns || [], r = x.rules || [];
    lanes.appendChild(laneRow(true, 'Internet', 'via the router', num((x.internet || {}).pkts || 0) + ' pkts', 'ok'));
    dn.forEach(function (y) {
      lanes.appendChild(laneRow(y.direct ? null : true, 'DNS ' + y.ip, y.direct ? 'reached directly' : 'udp/tcp 53' + (y.dot ? ' + 853' : '') + ' out ' + y.via,
        num((y.hits || {}).pkts || 0) + ' pkts', y.direct ? 'direct' : 'ok'));
    });
    r.forEach(function (y) {
      lanes.appendChild(laneRow(y.on ? true : null, y.comment || 'a rule of its own', (y.proto === 'any' ? 'any' : y.proto + (y.ports ? ' ' + y.ports : '')) + ' → ' + y.to,
        num((y.hits || {}).pkts || 0) + ' pkts' + (compact ? '' : ' · ' + kb((y.hits || {}).bytes)), y.on ? 'ok' : 'off'));
    });
    return lanes;
  }
  function laneRow(ok, title, detail, hits, cls) {
    var l = el('div', 'gwf-lane ' + cls);
    l.appendChild(el('span', 'gwf-mark', ok === null ? '·' : (ok ? '✓' : '✗')));
    var w = el('div', 'gwf-words');
    w.appendChild(noI18n(el('b', '', title)));
    if (detail) w.appendChild(noI18n(el('span', 'gwf-detail mono', detail)));
    l.appendChild(w);
    if (hits) l.appendChild(el('span', 'gwf-hits', hits));
    return l;
  }
  /* the MikroTik's word on a device: its way out and its ports */
  function mtStrip(x) {
    var rows = x.mikrotik || [];
    if (!rows.length) return null;
    var box = el('div', 'gt-mt');
    var way = (rows[0] || {}).way || null;
    var head = el('div', 'gt-mt-way');
    if (way && way.public) {
      head.appendChild(el('span', 'gt-mt-k', 'Out as'));
      head.appendChild(noI18n(el('b', 'mono ' + (way.ok ? 'good' : 'bad'), way.public)));
      if (way.out_if) head.appendChild(noI18n(el('span', 'muted small', 'out ' + way.out_if + (way.table && way.table !== 'main' ? ' · table ' + way.table : ''))));
    } else if (way && way.trouble) head.appendChild(noI18n(el('span', 'bad small', way.trouble)));
    else head.appendChild(el('span', 'gt-mt-k', 'On the MikroTik'));
    box.appendChild(head);
    if (way && way.trouble && way.public) box.appendChild(noI18n(el('div', 'bad small', way.trouble)));
    var chips = el('div', 'gt-chips gt-mt-ports');
    rows.forEach(function (m) {
      var S = (window.MT_STATE || {})[m.state] || ['?', 'dim'];
      var ch = el('button', 'gt-chip ' + S[1]);
      ch.type = 'button';
      ch.appendChild(protoTag(m.proto));
      ch.appendChild(noI18n(el('span', 'mono', ' ' + m.port)));
      ch.appendChild(el('span', 'gt-chip-s', S[0]));
      ch.title = m.state === 'ok' ? 'DNAT and accept in place' : (m.nat_why || S[0]);
      ch.onclick = function (ev) { ev.stopPropagation(); closeModal(); goTab('gateway', {sub: 'mikrotik', ip: x.ip, proto: m.proto, port: m.port}); };
      chips.appendChild(ch);
    });
    box.appendChild(chips);
    return box;
  }

  /* ---- a device: a compact card, its details in a popup ---- */
  function deviceHead(x, big) {
    var head = el('div', 'gt-dev-head');
    var on = online(x);
    var t = el('div', 'gt-dev-title');
    t.appendChild(el('span', 'dot ' + (on ? 'ok' : 'dim')));
    t.appendChild(noI18n(el('b', '', x.name)));
    t.appendChild(noI18n(el('span', 'mono', x.ip)));
    if (big) t.appendChild(noI18n(el('span', 'mono small muted', x.mac || 'any MAC')));
    head.appendChild(t);
    var st = el('div', 'gt-dev-state');
    st.appendChild(el('span', 'tag ' + (x.applied ? 'ok' : (x.on ? 'warn' : 'dim')), x.applied ? 'forwarded' : (x.on ? 'not put in' : 'off')));
    st.appendChild(el('span', 'small muted', on ? 'online' + (x.seen ? ' · last through ' + ago(x.seen) : '') : (x.seen ? 'last through ' + ago(x.seen) : 'not seen')));
    head.appendChild(st);
    return head;
  }
  function deviceCard(x) {
    var c = el('div', 'card gt-device');
    c.dataset.ip = x.ip;
    c.appendChild(deviceHead(x, false));
    var stats = el('div', 'gt-stats');
    [['Sent today', kb(x.today.bytes), num(x.today.pkts) + ' pkts'], ['Now', rate(x.today.rate), num(x.conns_n) + ' connection(s)'],
     ['Its own', num((x.dns || []).length) + ' DNS · ' + num((x.rules || []).length) + ' rule(s)', num(hitsOf(x.dns || []) + hitsOf(x.rules || [])) + ' pkts'],
     ['Dropped', num((x.dropped || {}).pkts || 0), 'toward local networks']].forEach(function (s, i) {
      var b = el('div', 'gt-stat' + (i === 3 && (x.dropped || {}).pkts ? ' warn' : ''));
      b.appendChild(el('span', 'k', s[0]));
      b.appendChild(noI18n(el('b', '', s[1])));
      b.appendChild(el('span', 'sub', s[2]));
      stats.appendChild(b);
    });
    c.appendChild(stats);
    c.appendChild(chart(x, true));
    var two = el('div', 'gt-dev-two');
    var a = el('div', 'gt-col');
    a.appendChild(el('h3', 'peek-h', 'What it may reach'));
    a.appendChild(lanesOf(x, true));
    two.appendChild(a);
    var b2 = el('div', 'gt-col');
    b2.appendChild(el('h3', 'peek-h', 'Its UPnP steps'));
    var st = GT.steps[x.ip];
    b2.appendChild(typeof stepPills === 'function' ? stepPills(st || {reached: [], furthest: -1}) : el('span', '', ''));
    if (st && st.stopped) b2.appendChild(el('p', 'muted small', st.stopped));
    var mt = mtStrip(x);
    if (mt) { b2.appendChild(el('h3', 'peek-h', 'On the MikroTik')); b2.appendChild(mt); }
    two.appendChild(b2);
    c.appendChild(two);
    var foot = el('div', 'gt-dev-foot');
    var det = cmdButton('Details', 'list', 'small primary');
    det.onclick = function () { deviceDetails(x); };
    foot.appendChild(det);
    var fw = cmdButton(ADMIN ? 'Its firewall' : 'Its firewall (read-only)', 'wall', 'small');
    explain(fw, 'Its DNS servers and rules of its own - the designer, here as a popup' + (ADMIN ? '; saved on trial.' : ', read-only.'));
    fw.onclick = function () { openFirewall(x); };
    foot.appendChild(fw);
    foot.appendChild(devLinks(x, !!(x.mikrotik && x.mikrotik.length)));
    c.appendChild(foot);
    return c;
  }
  function deviceDetails(x) {
    modal(x.name + ' · ' + x.ip, function (body) {
      body.appendChild(deviceHead(x, true));
      var r = x.rules || [], dn = x.dns || [];
      body.appendChild(peekFacts([['Sent today', kb(x.today.bytes)], ['Packets today', num(x.today.pkts)], ['Now', rate(x.today.rate)],
        ['Connections now', num(x.conns_n)], ['Internet line', num((x.internet || {}).pkts || 0) + ' pkts'],
        ['DNS asked', dn.length ? num(hitsOf(dn)) + ' pkts · ' + dn.length + ' server(s)' : 'as now'],
        ['Own rules', r.length ? num(hitsOf(r)) + ' pkts · ' + r.length + ' rule(s)' : 'none'],
        ['Dropped toward local nets', num((x.dropped || {}).pkts || 0)]]));
      body.appendChild(el('h3', 'peek-h', 'Sent through this server'));
      body.appendChild(chart(x, false));
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
      a.appendChild(el('h3', 'peek-h', 'Dropped toward local networks'));
      a.appendChild(barList((x.drops_by_net || []).map(function (y) { y._v = num(y.pkts) + ' pkts'; return y; }),
        function (y) { return noI18n(el('span', 'mono', y.to)); }, function (y) { return y.pkts; }));
      grid.appendChild(a);
      var b = el('div', 'gt-col');
      b.appendChild(el('h3', 'peek-h', 'What it may reach besides the internet'));
      b.appendChild(lanesOf(x, false));
      b.appendChild(el('h3', 'peek-h', 'Its UPnP steps'));
      var st = GT.steps[x.ip];
      b.appendChild(typeof stepPills === 'function' ? stepPills(st || {reached: [], furthest: -1}) : el('span', '', ''));
      if (st && st.stopped) b.appendChild(el('p', 'muted small', st.stopped));
      b.appendChild(el('h3', 'peek-h', 'The ports it asked for'));
      var ps = (GT.ports[x.ip] || []).map(function (p) { return Object.assign({client: x.ip}, p); });
      b.appendChild(portsList(ps));
      var mt = mtStrip(x);
      if (mt) { b.appendChild(el('h3', 'peek-h', 'On the MikroTik')); b.appendChild(mt); }
      grid.appendChild(b);
      body.appendChild(grid);
      body.appendChild(el('h3', 'peek-h', 'Its connections now (' + num(x.conns_n) + ')'));
      body.appendChild(connTable(x.conns || [], false));
      body.appendChild(el('h3', 'peek-h', 'Elsewhere'));
      body.appendChild(devLinks(x, !!(x.mikrotik && x.mikrotik.length)));
    }, [{words: ADMIN ? 'Its firewall' : 'Its firewall (read-only)', icon: 'wall', go: function () { openFirewall(x); }}, {words: 'Close', close: true}], 'large');
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
    var n = $('gt-subn-devices');
    if (n) n.textContent = (d.devices || []).length ? String((d.devices || []).length) : '';
    liveFill(h, function (box) {
      box.appendChild(cards(d));
      if (!(d.devices || []).length) {
        var e = el('div', 'card full gx-empty');
        var ic = el('span', 'gx-empty-ic');
        ic.innerHTML = iconMarkup('router', 34);
        e.appendChild(ic);
        e.appendChild(el('h2', '', 'No device uses this server as its gateway'));
        e.appendChild(el('p', 'note', 'A PS5 asks UPnP only of its default gateway. Settings → Gateway for devices makes this server the gateway of the devices you choose - only theirs, only toward the router.'));
        if (ADMIN) {
          var go = cmdButton('Configure it in Settings → Gateway for devices', 'gear', 'primary');
          go.onclick = function () { location.hash = '#settings/gateway'; };
          var row = el('div', 'btnrow gx-empty-go'); row.appendChild(go); e.appendChild(row);
        } else e.appendChild(el('p', 'muted small', 'A full administrator sets it up.'));
        box.appendChild(e);
      } else {
        var grid = el('div', 'gt-devgrid' + ((d.devices || []).length === 1 ? ' one' : ''));
        (d.devices || []).forEach(function (x) { grid.appendChild(deviceCard(x)); });
        box.appendChild(grid);
      }
      box.appendChild(chainCard(d));
    }, quietly, function () {
      explainWhatWasDrawn(h);
      if (GT.focus && GT.sub === 'devices') {
        var f = GT.focus; GT.focus = null;
        var c = h.querySelector('.gt-device[data-ip="' + f.ip + '"]');
        if (c) setTimeout(function () { c.scrollIntoView({behavior: 'smooth', block: 'start'}); c.classList.remove('gx-lit'); void c.offsetWidth; c.classList.add('gx-lit'); }, 60);
      }
    });
  }

  if ($('gt-hours')) {
    timePicker('gt-hours', {start: {k: 'rel', s: 86400}});
    $('gt-hours').onchange = function () { load(false); };
  }
  if ($('gt-refresh')) $('gt-refresh').onclick = function () {
    if (GT.sub === 'mikrotik') { window.MT_CACHE = null; if (window.MTV) window.MTV.load(null, false); dotMikrotik(); } else load(false);
  };
}());
