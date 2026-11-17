/* Gateway → MikroTik (1.9.2): the real router as it was read - READ-ONLY - on the main menu, not in Settings
   (Settings → MikroTik keeps only how it is reached). Drawn into the Gateway tab's second sub-tab:
     - the router: its identity, version, the last read, what it could not read, its warnings;
     - each device's way out to the internet through it (igd_mtpath): its interface, VRF, mangle marks,
       routing rules, the routing table and route, the WAN interface, the srcnat rule - and the PUBLIC
       address it goes out as; every node opens the rule that decided it; what holds for some traffic only;
       troubles in red;
     - under each device the ports it asked for, checked on that public address: dst-nat → forward → the
       device, with the state, IPv6, and the commands that would add what is missing (shown, never sent);
     - the whole firewall, IPv4 and IPv6, each table's chains as lanes, every rule a card.
   window.MTV.load(host, quietly), MTV.focus({ip, proto, port}); MT_CHECKS and MT_STATE for Overview and Ports. */
(function () {
  'use strict';
  var MV = {d: null, r: null, fam: 'ip', table: 'nat', q: '', mine: false, focus: null, poll: null, host: null, busy: false,
            qInput: null};
  var STATE = {
    ok: ['open', 'ok', 'The MikroTik carries it: a dst-nat to the device, and nothing in forward drops it.'],
    no_dnat: ['no dst-nat', 'crit', 'No enabled dst-nat rule sends this port to the device.'],
    no_accept: ['dropped by the filter', 'crit', 'Translated - then dropped in the forward chain of the filter.'],
    shadowed: ['shadowed', 'warn', 'A rule for it exists, but an earlier rule takes the packets first.'],
    disabled: ['disabled', 'warn', 'The rule that would carry it is switched off.'],
    elsewhere: ['forwarded elsewhere', 'warn', 'Another rule forwards this port to another device - one port goes to one device.'],
    unsure: ['cannot tell', 'dim', 'Something that decides it depends on what this cannot know (who connects, a limit, a mark) - said with the rule.']
  };
  var V6 = {open: ['IPv6 open', 'ok'], blocked: ['IPv6 blocked', 'crit'], unsure: ['IPv6: cannot tell', 'dim'], none: ['no IPv6', 'dim']};
  var WAY = {rest: 'REST over HTTPS', api: 'the API (api-ssl)', ssh: 'ssh'};
  var STAGE = {'interface': 'Its interface', vrf: 'VRF', mangle: 'Mangle', 'routing-rule': 'Routing rule', route: 'Route', srcnat: 'srcnat'};

  window.MT_STATE = STATE;
  /* For Overview and the Ports tab: the checks, read once a minute at most. */
  window.MT_CHECKS = function () {
    var now = Date.now();
    if (window.MT_CACHE && now - window.MT_CACHE.at < 60000) return Promise.resolve(window.MT_CACHE.d);
    return api('mikrotik').then(function (d) { window.MT_CACHE = {at: now, d: d}; return d; });
  };

  function live() { return TAB === 'gateway' && MV.host && !MV.host.hidden; }
  function load(host, quietly) {
    if (host) MV.host = host;
    if (MV.busy) return Promise.resolve();
    MV.busy = true;
    return Promise.all([api('mikrotik'), api('mikrotik-rules').catch(function () { return MV.r || {snap: null}; })]).then(function (two) {
      var was = MV.d && MV.d.reading;
      MV.d = two[0]; MV.r = two[1];
      window.MT_CACHE = {at: Date.now(), d: MV.d};
      draw(quietly);
      if (was && !MV.d.reading) toast((MV.d.state || {}).ok ? 'the MikroTik is read' : 'it could not be read', (MV.d.state || {}).ok ? 'good' : 'bad');
      pollFor();
    }).catch(function (e) { if (!quietly) oops(e); }).then(function () { MV.busy = false; });
  }
  function pollFor() {
    var on = !!(MV.d && MV.d.reading);
    if (on && !MV.poll) MV.poll = setInterval(function () { if (!live()) { clearInterval(MV.poll); MV.poll = null; return; } load(null, true); }, 1500);
    if (!on && MV.poll) { clearInterval(MV.poll); MV.poll = null; }
  }
  function readNow(b) {
    busy(b, true);
    api('mikrotik', {do: 'read'}, 90).then(function (x) {
      if (x.message) toast(x.message, (x.state || {}).ok === false ? 'bad' : 'good');
      return load(null, true);
    }).catch(oops).then(function () { busy(b, false); });
  }

  function tag(words, cls) { return el('span', 'tag ' + (cls || 'dim'), words); }
  function codeBlock(text, words) {
    var box = el('div', 'mt-code');
    box.appendChild(noI18n(el('pre', 'mono', text)));
    var c = iconButton('copy', words || 'Copy');
    c.classList.add('mt-copy');
    c.onclick = function (ev) { ev.stopPropagation(); copyText(text, c, 'the commands are on the clipboard - paste them into the MikroTik\'s terminal yourself'); };
    box.appendChild(c);
    return box;
  }
  function stepsOf(steps) {
    var list = el('div', 'steps');
    (steps || []).forEach(function (s) {
      var row = el('div', 'step ' + (s.ok ? 'ok' : 'bad'));
      var mark = el('span', 'step-mark');
      mark.innerHTML = iconMarkup(s.ok ? 'check' : 'cancel', 15);
      row.appendChild(mark);
      var w = el('span', 'step-words');
      w.appendChild(el('b', '', s.what));
      if (s.said) w.appendChild(noI18n(el('span', 'd', s.said)));
      row.appendChild(w);
      list.appendChild(row);
    });
    return list;
  }
  function nameOf(ip) {
    var n = '';
    ((MV.d && MV.d.checks && MV.d.checks.rows) || []).forEach(function (r) { if (r.device === ip && r.name) n = r.name; });
    if (!n && typeof window.gtDeviceName === 'function') n = window.gtDeviceName(ip) || '';
    return n;
  }
  /* links to the other tabs of the main menu - never into Settings */
  function jumps(ip, port, proto, keep) {
    var box = el('div', 'gx-links');
    var add = function (words, icon, go, title) {
      var b = el('button', 'gx-link');
      b.type = 'button';
      b.innerHTML = iconMarkup(icon, 14);
      b.appendChild(document.createTextNode(words));
      if (title) b.title = title;
      b.onclick = function (ev) { ev.stopPropagation(); closeModal(); go(); };
      box.appendChild(b);
    };
    (keep || ['card', 'clients', 'requests', 'ports', 'mappings']).forEach(function (k) {
      if (k === 'card') add('Its card', 'router', function () { goTab('gateway', {sub: 'devices', ip: ip}); }, 'Gateway → Devices: its card');
      if (k === 'clients') add('Clients', 'people', function () { goTab('clients', {ip: ip}); }, 'Clients: ' + ip);
      if (k === 'requests') add('Requests', 'list', function () { goTab('requests', {ip: ip, port: port, proto: proto}); }, 'Requests of ' + ip + (port ? ' for ' + port : ''));
      if (k === 'ports') add('Ports', 'net', function () { goTab('ports', {ip: ip, port: port, proto: proto}); }, 'Ports asked for by ' + ip + (port ? ', ' + port : ''));
      if (k === 'mappings') add('Mappings', 'router', function () { goTab('mappings', {ip: ip, port: port}); }, 'Mappings of ' + ip + (port ? ', ' + port : ''));
    });
    return box;
  }

  /* ---- the whole sub-tab ---- */
  function draw(quietly) {
    var h = MV.host;
    if (!h || !MV.d) return;
    var d = MV.d;
    liveFill(h, function (box) {
      if (!d.on) { box.appendChild(emptyState(d)); return; }
      box.appendChild(strip(d));
      box.appendChild(waysCard(d));
      var fw = el('div'); fw.id = 'mtv-fw';
      box.appendChild(fw);
    }, quietly, function () {
      if ($('mtv-fw')) paintFirewall();
      explainWhatWasDrawn(h);
      if (MV.focus) { var f = MV.focus; MV.focus = null; setTimeout(function () { showFocus(f); }, 60); }
    });
  }
  function emptyState(d) {
    var c = el('div', 'card full gx-empty');
    var ic = el('span', 'gx-empty-ic');
    ic.innerHTML = iconMarkup('wall', 34);
    c.appendChild(ic);
    c.appendChild(el('h2', '', 'The MikroTik is not read'));
    c.appendChild(el('p', 'note', 'fake-igd answers a PS5\'s UPnP and opens nothing - the real router does. Read here (read-only: it only ever asks the router to print), this shows each device\'s way out to the internet and the public address it goes out as, whether the router carries every port a device asked for, and its whole firewall, IPv4 and IPv6.'));
    if (ADMIN) {
      var go = cmdButton('Configure it in Settings → MikroTik', 'gear', 'primary');
      go.onclick = function () { location.hash = '#settings/mikrotik'; };
      var row = el('div', 'btnrow gx-empty-go'); row.appendChild(go); c.appendChild(row);
    } else c.appendChild(el('p', 'muted small', 'A full administrator sets it up.'));
    return c;
  }

  /* ---- the router: one strip ---- */
  function strip(d) {
    var st = d.state || {}, sn = d.snap || {}, ch = d.checks || null;
    var k = 'warn', t;
    if (d.reading) t = 'Being read now…';
    else if (st.ok === false) { k = 'bad'; t = 'The MikroTik cannot be read'; }
    else if (!sn.at) t = 'Not read yet';
    else if (ch && ch.total) { k = ch.open === ch.total ? 'good' : (ch.open ? 'warn' : 'bad'); t = num(ch.open) + ' of ' + num(ch.total) + ' port(s) open on it'; }
    else { k = 'good'; t = 'Read - no device has asked for a port yet'; }
    var card = el('div', 'card full gx-strip ' + k);
    var head = el('div', 'gx-strip-head');
    var ic = el('span', 'gx-strip-ic');
    ic.innerHTML = iconMarkup('wall', 24);
    head.appendChild(ic);
    var w = el('div', 'gx-strip-words');
    var who = el('div', 'gx-strip-who');
    who.appendChild(noI18n(el('b', '', sn.identity || d.conf.host || 'The MikroTik')));
    if (sn.version) who.appendChild(noI18n(el('span', 'muted', 'RouterOS ' + sn.version + (sn.board ? ' · ' + sn.board : ''))));
    w.appendChild(who);
    w.appendChild(el('div', 'gx-strip-state', t));
    head.appendChild(w);
    var acts = el('div', 'gx-strip-acts');
    if (ADMIN) {
      var rd = cmdButton('Read it now', 'refresh', 'small');
      rd.disabled = !d.conf.host || d.reading;
      explain(rd, 'Read the router now: its firewall, IPv4 and IPv6, its address lists, interfaces, routes - a few prints. Nothing is written.');
      rd.onclick = function () { readNow(rd); };
      acts.appendChild(rd);
    }
    head.appendChild(acts);
    card.appendChild(head);
    var facts = el('div', 'gx-facts');
    var fact = function (kk, v, cls) {
      var f = el('span', 'gx-fact ' + (cls || ''));
      f.appendChild(el('span', 'k', kk));
      f.appendChild(noI18n(el('span', 'v', v)));
      facts.appendChild(f);
    };
    fact('Router', d.conf.host ? d.conf.host + ':' + d.port_used : 'not set', d.conf.host ? '' : 'bad');
    fact('Read through', (WAY[d.conf.mode] || d.conf.mode) + ' · read-only');
    fact('Last read', st.at ? ago(st.at) + (st.took !== undefined ? ' (' + st.took + ' s)' : '') : 'never', st.ok === false ? 'bad' : '');
    fact('Every', d.conf.every + ' min');
    if (sn.counts) {
      var sum = function (f) { return Object.keys(sn.counts[f] || {}).reduce(function (a, t2) { return a + sn.counts[f][t2]; }, 0); };
      fact('Rules', num(sum('ip')) + ' IPv4 · ' + num(sum('ipv6')) + ' IPv6');
    }
    if (ch && ch.wan && (ch.wan.ifs || []).length) fact('WAN', ch.wan.ifs.join(', ') + ((ch.wan.addrs4 || []).length ? ' · ' + ch.wan.addrs4.join(', ') : ''));
    if (sn.upnp && sn.upnp.enabled) {
      var on = /^(true|yes)$/.test(sn.upnp.enabled);
      fact('Its own UPnP', on ? 'ON' : 'off', on ? 'bad' : 'good');
    }
    card.appendChild(facts);
    if (ch && ch.total) {
      var chips = el('div', 'mt-chips gx-counts');
      Object.keys(STATE).forEach(function (s) {
        var n = (ch.counts || {})[s] || 0;
        if (!n && s !== 'ok') return;
        var c = el('span', 'mt-chip ' + STATE[s][1]);
        c.appendChild(el('b', '', num(n)));
        c.appendChild(el('span', '', STATE[s][0]));
        explain(c, STATE[s][2]);
        chips.appendChild(c);
      });
      card.appendChild(chips);
    }
    var why = [];
    if (st.ok === false) why.push({k: 'bad', t: st.trouble});
    (ch ? ch.warnings : []).forEach(function (x) { why.push({k: 'warn', t: x}); });
    Object.keys(sn.missing || {}).forEach(function (m) { if (!/routerboard|nat6|mangle6|raw6|tracking|upnp_ifs/.test(m)) why.push({k: 'dim', t: 'Not read: ' + m + ' - ' + sn.missing[m]}); });
    if (why.length) {
      var wl = el('div', 'gx-why');
      why.forEach(function (x) { wl.appendChild(noI18n(el('div', 'gx-why-l ' + x.k, x.t))); });
      card.appendChild(wl);
    }
    if (d.reading) {
      var going = el('div', 'going wide');
      going.innerHTML = '<div class="bar"><span class="creeping"></span></div><div class="says"></div>';
      going.querySelector('span').style.width = '40%';
      going.querySelector('.says').textContent = 'Reading the router - a few prints, seconds at most.';
      card.appendChild(going);
    }
    return card;
  }

  /* ---- each device: its way out, and its ports on its public address ---- */
  function waysCard(d) {
    var ch = d.checks;
    var card = el('div', 'card full gx-ways');
    var h = el('h2', '', 'Each device\'s way out, and its ports');
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'How the MikroTik takes a new connection from the device to the internet - its interface, a VRF, the mangle marks, a routing rule, the routing table and its route, the interface out and the srcnat rule - and so the public address it goes out as. Its ports are checked on that address, as the router takes the first packet from the internet: the dst-nat, then the filter\'s forward chain. Every step opens the rule that decided it. What is missing comes as commands for you to type - fake-igd never sends them.'));
    if (!ch) { card.appendChild(el('p', 'muted', d.reading ? 'Being read…' : 'Not read yet.')); return card; }
    var ips = [];
    (ch.ways || []).forEach(function (w) { if (ips.indexOf(w.device) < 0) ips.push(w.device); });
    (ch.rows || []).forEach(function (r) { if (ips.indexOf(r.device) < 0) ips.push(r.device); });
    if (!ips.length) { card.appendChild(el('p', 'muted', 'No device has asked for a port in the last 30 days, and no device uses this server as its gateway.')); return card; }
    ips.forEach(function (ip) {
      var way = (ch.ways || []).filter(function (w) { return w.device === ip; })[0] || null;
      var rows = (ch.rows || []).filter(function (r) { return r.device === ip; });
      card.appendChild(deviceBlock(ip, way, rows));
    });
    if ((ch.merged || []).length && ch.merged.some(function (m) { return m.ports.indexOf(',') >= 0 || m.ports.indexOf('-') >= 0; })) {
      var det = el('details', 'gx-merged');
      det.appendChild(el('summary', '', 'Every rule still to add, merged into ranges'));
      det.appendChild(el('p', 'note', 'The ports that have no dst-nat yet, one rule a device and protocol. Type them on the MikroTik yourself.'));
      var spec = (MV.r && MV.r.snap && (MV.r.snap.iflists || {}).WAN) ? 'in-interface-list=WAN' : 'in-interface=' + (((ch.wan || {}).ifs || [])[0] || 'ether1');
      det.appendChild(codeBlock(ch.merged.map(function (m) {
        return '/ip firewall nat add chain=dstnat action=dst-nat protocol=' + m.proto + ' dst-port=' + m.ports + ' ' + spec + ' to-addresses=' + m.device + ' comment="fake-igd: ' + m.device + '"';
      }).join('\n')));
      card.appendChild(det);
    }
    return card;
  }
  function deviceBlock(ip, way, rows) {
    var name = nameOf(ip);
    var bad = way && !way.ok;
    var open = rows.filter(function (r) { return r.state === 'ok'; }).length;
    var blk = el('section', 'gx-dev' + (bad ? ' bad' : ''));
    blk.dataset.ip = ip;
    var head = el('div', 'gx-dev-head');
    var t = el('div', 'gx-dev-title');
    t.appendChild(el('span', 'dot ' + (!way ? 'dim' : (way.ok ? 'ok' : 'bad'))));
    t.appendChild(noI18n(el('b', '', name || ip)));
    if (name) t.appendChild(noI18n(el('span', 'mono muted', ip)));
    head.appendChild(t);
    var sum = el('div', 'gx-dev-sum');
    if (way && way.public) sum.appendChild(noI18n(tag('out as ' + way.public, way.ok ? 'ok' : 'crit')));
    else if (way) sum.appendChild(tag(way.trouble ? 'no way out' : 'way unknown', 'crit'));
    if (rows.length) sum.appendChild(tag(num(open) + ' of ' + num(rows.length) + ' port(s) open', open === rows.length ? 'ok' : (open ? 'warn' : 'crit')));
    head.appendChild(sum);
    head.appendChild(jumps(ip));
    blk.appendChild(head);
    if (way) {
      blk.appendChild(pathOf(ip, name, way));
      if (way.trouble) blk.appendChild(noI18n(el('p', 'note bad gx-trouble', way.trouble)));
      if ((way.some || []).length) {
        var some = el('div', 'gx-some');
        some.appendChild(el('b', '', 'For some of its traffic only'));
        var ul = el('ul');
        way.some.forEach(function (s) {
          var li = noI18n(el('li', s.rule ? 'tappable' : '', s.words || (s.rule || {}).words || ''));
          if (s.rule) li.onclick = function () { stepPeek({stage: s.stage, rule: s.rule, words: s.words}); };
          ul.appendChild(li);
        });
        some.appendChild(ul);
        blk.appendChild(some);
      }
    } else blk.appendChild(el('p', 'muted small', 'Its way out was not worked out - the router\'s addresses or routes were not read.'));
    if (rows.length) {
      var pl = el('div', 'gx-ports');
      var ph = el('div', 'gx-ports-h');
      ph.appendChild(el('h3', 'peek-h', 'Its ports, from the internet' + (way && way.public ? ' to ' + way.public : '')));
      pl.appendChild(ph);
      rows.forEach(function (r) { pl.appendChild(portRow(r, way)); });
      blk.appendChild(pl);
    } else blk.appendChild(el('p', 'muted small gx-noports', 'It asked fake-igd for no port in the last 30 days.'));
    return blk;
  }
  function node(label, title, sub, cls, go) {
    var n = el(go ? 'button' : 'div', 'gx-node ' + (cls || ''));
    if (go) { n.type = 'button'; n.onclick = go; n.title = 'Open the rule'; }
    n.appendChild(el('span', 'gx-node-k', label));
    n.appendChild(noI18n(el('span', 'gx-node-t', title)));
    if (sub) n.appendChild(noI18n(el('span', 'gx-node-s', sub)));
    return n;
  }
  function pathOf(ip, name, way) {
    var p = el('div', 'gx-path');
    var nodes = [node('Device', name || ip, name ? ip : '', 'dev')];
    (way.steps || []).forEach(function (s) {
      var r = s.rule || null;
      var lab = (STAGE[s.stage] || s.stage) + (r && r.n ? ' #' + r.n : '');
      var title, sub = s.words || (r ? r.words : '') || '', cls = '';
      if (s.stage === 'interface') { title = way.in_if || '?'; cls = 'if'; }
      else if (s.stage === 'vrf') { title = way.table || 'VRF'; cls = 'mark'; }
      else if (s.stage === 'mangle') { title = (r && r.comment) || 'a mark'; cls = 'mark'; }
      else if (s.stage === 'routing-rule') { title = (r && r.comment) || 'lookup ' + (way.table || ''); cls = 'mark'; }
      else if (s.stage === 'route') { lab = 'Route · table ' + (way.table || (r && r.table) || 'main'); title = way.gateway ? 'via ' + way.gateway : ((r && r.comment) || 'the route'); cls = 'route'; }
      else if (s.stage === 'srcnat') { title = way.nat || (r && r.comment) || 'srcnat'; cls = 'nat'; }
      else title = (r && r.comment) || s.stage;
      if (r && r.comment && s.stage !== 'mangle' && s.stage !== 'routing-rule' && sub.indexOf(r.comment) < 0) sub = r.comment + ' · ' + sub;
      nodes.push(node(lab, title, sub, cls, r ? function () { stepPeek(s); } : null));
      if (s.stage === 'route' && way.out_if) {
        var wan = ((((MV.d || {}).checks || {}).wan || {}).ifs || []).indexOf(way.out_if) >= 0;
        nodes.push(node('Out', way.out_if, wan ? 'the WAN' : 'its interface out', 'if'));
      }
    });
    nodes.push(node(way.ok ? 'Public address' : 'Goes out as', way.public || (way.trouble ? 'nothing' : '?'), way.ok ? 'what the internet sees' : 'not a way to the internet',
                    way.ok ? 'pub' : 'pub bad'));
    nodes.forEach(function (n, i) {
      if (i) p.appendChild(el('span', 'gx-arrow', ''));
      p.appendChild(n);
    });
    return p;
  }
  function findRule(fam, table, id) {
    var s = MV.r && MV.r.snap;
    if (!s || !id) return null;
    return (((s.rules || {})[fam] || {})[table] || []).filter(function (r) { return r['.id'] === id; })[0] || null;
  }
  function stepPeek(s) {
    var r = s.rule || {};
    var full = r.table && r.table !== 'route' ? findRule('ip', r.table, r.id) : null;
    if (full) { rulePeek(full, null, 'ip', r.table); return; }
    modal((STAGE[s.stage] || s.stage) + (r.n ? ' #' + r.n : ''), function (body) {
      body.appendChild(peekFacts([['Stage', STAGE[s.stage] || s.stage], ['Where', r.table || '–'], ['Comment', r.comment || '–']]));
      if (r.words || s.words) body.appendChild(noI18n(el('pre', 'lines', r.words || s.words)));
      body.appendChild(el('p', 'muted small', 'As the router said it at the last read.'));
    }, [{words: 'Close', close: true}], 'narrow');
  }
  function portRow(r, way) {
    var S = STATE[r.state] || STATE.unsure;
    var row = el('div', 'gx-port ' + S[1]);
    row.dataset.port = r.proto + '/' + r.port;
    row.tabIndex = 0;
    var p = el('div', 'gx-port-p');
    p.appendChild(protoTag(r.proto));
    p.appendChild(noI18n(el('b', 'mono', r.port + (r.to_port && r.to_port !== r.port ? ' → ' + r.to_port : ''))));
    if (r.description) p.appendChild(noI18n(el('span', 'small muted gx-port-d', r.description)));
    row.appendChild(p);
    var path = el('div', 'gx-mini');
    var nat = (r.rules || []).filter(function (x) { return x.table === 'nat' && x.family === 'ip'; })[0];
    var flt = (r.rules || []).filter(function (x) { return x.table === 'filter' && x.family === 'ip'; })[0];
    var hop = function (words, cls, title, go) {
      var h = el(go ? 'button' : 'span', 'gx-hop ' + cls, words);
      if (go) { h.type = 'button'; h.onclick = function (ev) { ev.stopPropagation(); go(); }; }
      if (title) h.title = title;
      path.appendChild(noI18n(h));
    };
    var sep = function () { path.appendChild(el('span', 'gx-hop-a', '→')); };
    hop((way && way.public ? way.public : (r.way || {}).public || 'its public address') + ':' + r.port, 'dim', 'From the internet, to the router\'s public address');
    sep();
    hop(r.nat === 'dnat' ? 'dst-nat' + (nat ? ' #' + nat.n : '') : 'no dst-nat', r.nat === 'dnat' ? 'ok' : 'crit', r.nat_why,
        nat ? function () { var full = findRule('ip', 'nat', nat.id); if (full) rulePeek(full, null, 'ip', 'nat'); } : null);
    sep();
    hop(r.forward === 'open' ? 'forward' + (flt ? ' #' + flt.n : '') : (r.forward === 'blocked' ? 'dropped in forward' + (flt ? ' #' + flt.n : '') : 'forward ?'),
        r.forward === 'open' ? 'ok' : (r.forward === 'blocked' ? 'crit' : 'dim'), r.forward_why,
        flt ? function () { var full = findRule('ip', 'filter', flt.id); if (full) rulePeek(full, null, 'ip', 'filter'); } : null);
    sep();
    hop(r.device + ':' + (r.to_port || r.port), r.state === 'ok' ? 'ok' : 'dim', 'The device');
    row.appendChild(path);
    var st = el('div', 'gx-port-st');
    st.appendChild(tag(S[0], S[1]));
    st.appendChild(tag((V6[r.v6] || V6.none)[0], (V6[r.v6] || V6.none)[1]));
    row.appendChild(st);
    var tools = el('div', 'gx-port-t rowtools');
    if ((r.commands || []).length || (r.v6_commands || []).length) {
      var cp = iconButton('copy', 'Copy the commands that would add what is missing');
      cp.onclick = function (ev) { ev.stopPropagation(); copyText((r.commands || []).concat(r.v6_commands || []).join('\n'), cp, 'the commands are on the clipboard'); };
      tools.appendChild(cp);
    }
    var sh = iconButton('wall', 'Show its rules in the firewall below');
    sh.onclick = function (ev) { ev.stopPropagation(); showRules(r); };
    tools.appendChild(sh);
    var pt = iconButton('net', 'The Ports tab: this port');
    pt.onclick = function (ev) { ev.stopPropagation(); goTab('ports', {ip: r.device, port: r.port, proto: r.proto}); };
    tools.appendChild(pt);
    var mp = iconButton('router', 'The Mappings tab: this port');
    mp.onclick = function (ev) { ev.stopPropagation(); goTab('mappings', {ip: r.device, port: r.port}); };
    tools.appendChild(mp);
    row.appendChild(tools);
    row.onclick = function () { portPeek(r); };
    row.onkeydown = function (ev) { if (ev.key === 'Enter') portPeek(r); };
    if (r.state !== 'ok') {
      var why = noI18n(el('div', 'gx-port-why small', r.nat_why + (r.forward === 'blocked' ? ' - ' + r.forward_why : '')));
      row.appendChild(why);
    }
    return row;
  }
  function portPeek(r) {
    var S = STATE[r.state] || STATE.unsure;
    modal((r.name ? r.name + ' · ' : '') + r.device + ' ' + r.proto.toUpperCase() + ' ' + r.port, function (body) {
      body.appendChild(peekFacts([['IPv4 on the MikroTik', S[0]], ['IPv6', (V6[r.v6] || V6.none)[0]], ['On', ((r.way || {}).public || '–') + ':' + r.port],
        ['Asked', r.asked ? num(r.asked) + ' time(s)' : '–'], ['Last asked', r.last ? stamp(Date.parse(r.last) / 1000) : '–'], ['Held now', r.held ? 'yes' : 'no'],
        ['What for', r.description || '–']]));
      body.appendChild(el('p', 'note ' + ({ok: 'good', crit: 'bad', warn: 'warn'}[S[1]] || ''), S[2]));
      body.appendChild(el('h3', 'peek-h', 'How the MikroTik takes it'));
      body.appendChild(stepsOf([{what: 'The translation (nat dstnat)', ok: r.nat === 'dnat', said: r.nat_why},
                                {what: 'The filter (forward)' + (r.nat === 'dnat' ? '' : ', once translated'), ok: r.forward === 'open', said: r.forward_why},
                                {what: 'IPv6', ok: r.v6 === 'open' || r.v6 === 'none', said: r.v6_why}]));
      (r.notes || []).forEach(function (n) { body.appendChild(noI18n(el('p', 'note warn', n))); });
      var cmds = (r.commands || []).concat(r.v6_commands || []);
      if (cmds.length) {
        body.appendChild(el('h3', 'peek-h', 'What would put it right'));
        body.appendChild(el('p', 'note', 'Commands for the MikroTik\'s terminal - fake-igd only reads, it never sends them. place-before puts a rule before the one that takes the packets first.'));
        body.appendChild(codeBlock(cmds.join('\n')));
      }
      body.appendChild(el('h3', 'peek-h', 'Elsewhere'));
      body.appendChild(jumps(r.device, r.port, r.proto));
    }, [{words: 'Show its rules', icon: 'wall', go: function () { showRules(r); }, close: true}, {words: 'Close', close: true}], 'medium');
  }
  function showRules(r) {
    MV.q = 'port:' + r.port;
    MV.table = r.nat === 'dnat' && r.forward === 'blocked' ? 'filter' : 'nat';
    MV.fam = 'ip';
    if (MV.qInput) MV.qInput.value = MV.q;
    paintFirewall();
    var fw = $('mtv-fw');
    if (fw) fw.scrollIntoView({behavior: 'smooth', block: 'start'});
  }
  function showFocus(f) {
    if (!MV.host) return;
    var blk = MV.host.querySelector('.gx-dev[data-ip="' + f.ip + '"]');
    if (!blk) return;
    var target = blk;
    if (f.port) {
      var pr = blk.querySelector('.gx-port[data-port="' + String(f.proto || '').toLowerCase() + '/' + f.port + '"]')
        || blk.querySelector('.gx-port[data-port$="/' + f.port + '"]');
      if (pr) target = pr;
    }
    target.scrollIntoView({behavior: 'smooth', block: 'center'});
    target.classList.remove('gx-lit');
    void target.offsetWidth;
    target.classList.add('gx-lit');
  }

  /* ---- the whole firewall ---- */
  var ACTION = {accept: 'ok', 'fasttrack-connection': 'ok', drop: 'crit', reject: 'crit', tarpit: 'crit', 'dst-nat': 'info', netmap: 'info',
    redirect: 'info', 'src-nat': 'violet', masquerade: 'violet', 'endpoint-independent-nat': 'violet', jump: 'dim', 'return': 'dim',
    passthrough: 'dim', log: 'warn', 'add-src-to-address-list': 'warn', 'add-dst-to-address-list': 'warn'};
  var HIDE = {'.id': 1, n: 1, chain: 1, action: 1, comment: 1, disabled: 1, dynamic: 1, invalid: 1, bytes: 1, packets: 1, hits: 1, log: 1,
    'log-prefix': 1, 'to-addresses': 1, 'to-ports': 1, 'jump-target': 1, 'hw-offload': 1, '.about': 1};
  var CHAIN_ORDER = ['prerouting', 'dstnat', 'input', 'forward', 'output', 'srcnat', 'postrouting'];
  var CHAIN_SAYS = {prerouting: 'every packet that comes in, before anything', dstnat: 'what comes in, before routing: where it is sent (DNAT)',
    input: 'to the router itself', forward: 'through the router', output: 'from the router itself', srcnat: 'what goes out: its source (masquerade)',
    postrouting: 'every packet that goes out'};
  var PORT_F = ['dst-port', 'src-port', 'port', 'to-ports'];
  /* what the search box understands - offered by its suggestions (localSuggest), matched by localMatches;
     port: is matched apart, a port in a range counts */
  var FIELDS = [
    ['port', 'a port: in dst-port, src-port, to-ports or a range of them', 'port:9308', function (r) { return PORT_F.map(function (f) { return r[f]; }).filter(Boolean).join(',').replace(/!/g, '').split(','); }],
    ['action', 'what the rule does', 'action:drop', function (r) { return r.action || 'accept'; }],
    ['chain', 'its chain', 'chain:forward', function (r) { return r.chain; }],
    ['proto', 'its protocol', 'proto:udp', function (r) { return String(r.protocol || '').replace(/^!/, ''); }],
    ['list', 'an address list it uses', 'list:WAN', function (r) { return ['src-address-list', 'dst-address-list', 'address-list'].map(function (f) { return String(r[f] || '').replace(/^!/, ''); }); }],
    ['if', 'an interface or interface list', 'if:WAN', function (r) { return ['in-interface', 'out-interface', 'in-interface-list', 'out-interface-list'].map(function (f) { return String(r[f] || '').replace(/^!/, ''); }); }],
    ['addr', 'an address it matches or translates to', 'addr:192.168.40.95', function (r) { return ['src-address', 'dst-address', 'to-addresses'].map(function (f) { return String(r[f] || '').replace(/^!/, ''); }); }],
    ['state', 'connection-state it matches', 'state:established', function (r) { return String(r['connection-state'] || '').split(','); }],
    ['comment', 'words of its comment', 'comment~fake', function (r) { return r.comment || ''; }],
    ['off', 'yes: switched off, no: on', 'off:yes', function (r) { return r.disabled ? 'yes' : 'no'; }]
  ];
  function tableRules() {
    var s = MV.r && MV.r.snap;
    if (!s) return [];
    return (((s.rules || {})[MV.fam] || {})[MV.table]) || [];
  }
  function chipsOf(r) {
    var out = [];
    Object.keys(r).forEach(function (k) {
      if (HIDE[k] || r[k] === '' || r[k] === undefined || r[k] === null) return;
      var v = String(r[k]);
      var kind = /port/.test(k) ? 'port' : (/address-list/.test(k) ? 'list' : (/address/.test(k) ? 'addr' : (/interface/.test(k) ? 'if' : (/state/.test(k) ? 'state' : (k === 'protocol' ? 'proto' : 'other')))));
      out.push({k: k, v: v, kind: kind, neg: v.charAt(0) === '!'});
    });
    var order = {proto: 0, port: 1, addr: 2, list: 3, if: 4, state: 5, other: 6};
    out.sort(function (a, b) { return (order[a.kind] - order[b.kind]) || (a.k < b.k ? -1 : 1); });
    return out;
  }
  function chipWords(c) {
    var short = {protocol: '', 'dst-port': 'dport ', 'src-port': 'sport ', 'in-interface': 'in ', 'out-interface': 'out ', 'in-interface-list': 'in ',
      'out-interface-list': 'out ', 'src-address': 'from ', 'dst-address': 'to ', 'src-address-list': 'from list ', 'dst-address-list': 'to list ',
      'connection-state': '', 'connection-nat-state': 'nat ', 'ipsec-policy': 'ipsec '};
    var pre = short[c.k] !== undefined ? short[c.k] : c.k + '=';
    var v = c.neg ? c.v.slice(1) : c.v;
    return (c.neg ? 'not ' : '') + pre + v;
  }
  function portHit(r, p) {
    return PORT_F.some(function (f) {
      return String(r[f] || '').replace(/^!/, '').split(',').some(function (x) {
        var ab = x.split('-');
        return ab.length === 2 ? (p >= +ab[0] && p <= +ab[1]) : +x === p;
      });
    });
  }
  function matches(r, q) {
    q = String(q || '').trim();
    if (!q) return true;
    var fail = false;
    var rest = q.replace(/(^|\s)(-?)port:([\d,]+)(?=\s|$)/gi, function (all, lead, not, ports) {
      var hit = ports.split(',').filter(Boolean).some(function (p) { return portHit(r, parseInt(p, 10)); });
      if (not ? hit : !hit) fail = true;
      return lead;
    });
    if (fail) return false;
    return localMatches(r, rest, FIELDS);
  }
  function searchBox() {
    if (MV.qInput) return MV.qInput;
    var q = el('input');
    q.type = 'search';
    q.placeholder = 'port:9308 · action:drop · chain:forward · list:bad · if:WAN · an address, a word…';
    q.className = 'mt-q';
    q.value = MV.q;
    q.addEventListener('input', debounce(function () { MV.q = q.value; paintFirewall(true); }, 250));
    MV.qInput = q;
    return q;
  }
  function wireSuggest(q) {
    if (q._qs || typeof localSuggest !== 'function') return;
    localSuggest(q, FIELDS, function () { return tableRules(); }, function () {
      var out = [];
      var seen = {};
      tableRules().forEach(function (r) {
        if (r.comment && !seen[r.comment] && out.length < 30) { seen[r.comment] = 1; out.push({val: qQuote(r.comment), note: 'a comment · #' + r.n}); }
      });
      return out;
    });
  }
  function paintFirewall(fromSearch) {
    var host = $('mtv-fw');
    if (!host || !MV.d) return;
    var s = MV.r && MV.r.snap;
    if (fromSearch && host.querySelector('.mt-view')) {     /* only the lanes again: the box keeps its caret */
      var v = host.querySelector('.mt-view');
      v.parentNode.replaceChild(view(s), v);
      var segs = host.querySelector('.mt-bar');
      if (segs) segs.parentNode.replaceChild(bar(s), segs);
      explainWhatWasDrawn(host);
      return;
    }
    clear(host);
    var card = el('div', 'card full mt-fw');
    var h = el('h2', '', 'Its firewall');
    if (s) h.appendChild(noI18n(el('span', 'right muted small', (s.identity || '') + ' · read ' + ago(s.at) + (s.prev_at ? ' · hits since the read before, ' + ago(s.prev_at) : ''))));
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'Every rule of its filter, NAT, mangle and raw tables, IPv4 and IPv6, in order - each table\'s chains side by side, the first rule at the top: the first that matches decides. Its action in colour, what it matches as chips, what it has counted since the router started (the bar: its share of its chain\'s bytes). What concerns the ports fake-igd was asked for is lit; a rule opens with all its fields.'));
    host.appendChild(card);
    if (!s) { card.appendChild(el('p', 'muted', 'Not read yet.')); return; }
    var q = searchBox();
    var qrow = el('div', 'mt-qrow');
    qrow.appendChild(q);
    card.appendChild(qrow);
    wireSuggest(q);
    card.appendChild(bar(s));
    card.appendChild(view(s));
    card.appendChild(legend());
    explainWhatWasDrawn(host);
  }
  function bar(s) {
    var b0 = el('div', 'mt-bar');
    var fam = el('div', 'seg');
    [['ip', 'IPv4'], ['ipv6', 'IPv6']].forEach(function (x) {
      var b = el('button', MV.fam === x[0] ? 'on' : '', x[1]);
      b.type = 'button';
      b.onclick = function () { MV.fam = x[0]; if (!((s.rules[MV.fam] || {})[MV.table] || []).length) MV.table = 'filter'; paintFirewall(true); };
      fam.appendChild(b);
    });
    b0.appendChild(fam);
    var tabs = el('div', 'seg');
    ['filter', 'nat', 'mangle', 'raw'].forEach(function (t) {
      var n = ((s.rules[MV.fam] || {})[t] || []).length;
      var b = el('button', MV.table === t ? 'on' : '');
      b.type = 'button';
      b.appendChild(document.createTextNode(t));
      b.appendChild(el('span', 'mt-n', String(n)));
      b.onclick = function () { MV.table = t; paintFirewall(true); };
      tabs.appendChild(b);
    });
    b0.appendChild(tabs);
    var mine = el('label', 'mt-mine');
    var tick = document.createElement('input');
    tick.type = 'checkbox';
    tick.checked = MV.mine;
    tick.onchange = function () { MV.mine = tick.checked; paintFirewall(true); };
    mine.appendChild(tick);
    mine.appendChild(document.createTextNode(' only what concerns fake-igd\'s ports'));
    b0.appendChild(mine);
    return b0;
  }
  function view(s) {
    var wrap = el('div', 'mt-view');
    var rules = tableRules();
    var concern = MV.r.concern || {};
    var chains = [];
    rules.forEach(function (r) { if (chains.indexOf(r.chain) < 0) chains.push(r.chain); });
    chains.sort(function (a, b) {
      var ia = CHAIN_ORDER.indexOf(a), ib = CHAIN_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a < b ? -1 : 1);
    });
    var lanes = el('div', 'mt-lanes');
    chains.forEach(function (ch) {
      var all = rules.filter(function (r) { return r.chain === ch; });
      var total = all.reduce(function (a, r) { return a + (r.bytes || 0); }, 0) || 1;
      var keep = all.filter(function (r) { return matches(r, MV.q) && (!MV.mine || concern[MV.fam + ':' + r['.id']]); });
      var lane = el('div', 'mt-lane');
      var lh = el('div', 'mt-lane-h');
      lh.appendChild(noI18n(el('b', 'mono', ch)));
      lh.appendChild(el('span', 'mt-n', keep.length === all.length ? String(all.length) : keep.length + ' / ' + all.length));
      lh.appendChild(el('span', 'muted small mt-lane-says', CHAIN_SAYS[ch] || 'a chain of its own (jumped to)'));
      lane.appendChild(lh);
      keep.forEach(function (r) { lane.appendChild(ruleCard(r, total, concern[MV.fam + ':' + r['.id']])); });
      if (!keep.length) lane.appendChild(el('div', 'mt-empty muted small', all.length ? 'nothing here matches' : 'no rule'));
      lane.appendChild(el('div', 'mt-lane-end muted small', MV.table === 'filter' || MV.table === 'raw' ? 'then: accept (a chain lets through what no rule stopped)' : (MV.table === 'nat' ? 'then: not translated' : 'then: on, unmarked')));
      lanes.appendChild(lane);
    });
    if (!chains.length) lanes.appendChild(el('div', 'mt-empty muted', 'The ' + MV.table + ' table of ' + (MV.fam === 'ip' ? 'IPv4' : 'IPv6') + ' has no rule' + ((s.missing || {})[MV.table + (MV.fam === 'ip' ? '4' : '6')] ? ' - it could not be read: ' + s.missing[MV.table + (MV.fam === 'ip' ? '4' : '6')] : '') + '.'));
    wrap.appendChild(lanes);
    wrap.appendChild(side(s));
    return wrap;
  }
  function ruleCard(r, total, concerns) {
    var a = r.action || 'accept';
    var c = el('div', 'mt-rule ' + (ACTION[a] || 'dim') + (r.disabled ? ' off' : '') + (r.dynamic ? ' dyn' : '') + (concerns ? ' mine' : '') + (r.invalid ? ' invalid' : ''));
    c.tabIndex = 0;
    var top = el('div', 'mt-rule-top');
    top.appendChild(noI18n(el('span', 'mt-num', '#' + r.n)));
    top.appendChild(noI18n(el('span', 'mt-act ' + (ACTION[a] || 'dim'), a + (r['to-addresses'] ? ' → ' + r['to-addresses'] + (r['to-ports'] ? ':' + r['to-ports'] : '') : '') + (a === 'jump' ? ' → ' + (r['jump-target'] || '') : ''))));
    if (r.disabled) top.appendChild(tag('disabled', 'dim'));
    if (r.dynamic) top.appendChild(tag('dynamic', 'info'));
    if (r.invalid) top.appendChild(tag('invalid', 'crit'));
    if (r.log) top.appendChild(tag('log', 'warn'));
    c.appendChild(top);
    if (r.comment) c.appendChild(noI18n(el('div', 'mt-comment', r.comment)));
    var chips = el('div', 'mt-chips-r');
    var list = chipsOf(r);
    list.forEach(function (x) { chips.appendChild(noI18n(el('span', 'mt-c ' + x.kind + (x.neg ? ' neg' : ''), chipWords(x)))); });
    if (!list.length) chips.appendChild(el('span', 'mt-c any', 'every packet'));
    c.appendChild(chips);
    var cnt = el('div', 'mt-count');
    var barw = el('div', 'mt-cbar');
    var fillb = el('span');
    fillb.style.width = Math.max(r.bytes ? 2 : 0, Math.round(100 * (r.bytes || 0) / total)) + '%';
    barw.appendChild(fillb);
    cnt.appendChild(barw);
    cnt.appendChild(el('span', 'small muted', num(r.packets || 0) + ' pkt · ' + bytes(r.bytes || 0) + (r.hits !== undefined ? ' · +' + num(r.hits) + ' since' : '')));
    c.appendChild(cnt);
    if (concerns) c.appendChild(noI18n(el('div', 'mt-concern small', concerns.slice(0, 4).join(' · ') + (concerns.length > 4 ? ' …' : ''))));
    c.onclick = function () { rulePeek(r, concerns); };
    c.onkeydown = function (ev) { if (ev.key === 'Enter') rulePeek(r, concerns); };
    return c;
  }
  function rulePeek(r, concerns, fam, table) {
    fam = fam || MV.fam; table = table || MV.table;
    if (!concerns && MV.r && MV.r.concern) concerns = MV.r.concern[fam + ':' + r['.id']] || null;
    modal((fam === 'ip' ? '/ip' : '/ipv6') + ' firewall ' + table + ' #' + r.n + ' · ' + r.chain + ' · ' + (r.action || ''), function (body) {
      if (r.comment) body.appendChild(noI18n(el('p', 'note', r.comment)));
      if (concerns) body.appendChild(noI18n(el('p', 'note info', 'It concerns: ' + concerns.join(' · '))));
      var keys = Object.keys(r).filter(function (k) { return k !== 'n' && k !== 'hits'; }).sort(function (a, b) {
        var top = ['.id', 'chain', 'action', 'disabled', 'dynamic', 'packets', 'bytes'];
        var ia = top.indexOf(a), ib = top.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a < b ? -1 : 1);
      });
      body.appendChild(listTable(['Field', 'Value'], keys, function (k) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono small', k)));
        var v = r[k];
        tr.appendChild(noI18n(el('td', 'mono small', k === 'bytes' ? num(v) + ' (' + bytes(v) + ')' : (k === 'packets' ? num(v) : String(v)))));
        return tr;
      }, 'plain|Nothing'));
      if (r.hits !== undefined) body.appendChild(el('p', 'muted small', num(r.hits) + ' packet(s) since the read before.'));
    }, [{words: 'Close', close: true}], 'medium');
  }
  function side(s) {
    var box = el('div', 'mt-side');
    var ifs = el('div', 'mt-panel');
    ifs.appendChild(el('h3', 'peek-h', 'Interfaces'));
    var lists = s.iflists || {};
    var inList = function (n) { return Object.keys(lists).filter(function (l) { return ['all', 'none', 'dynamic', 'static'].indexOf(l) < 0 && (lists[l] || []).indexOf(n) >= 0; }); };
    var addrs = (s.addresses4 || []).concat(MV.fam === 'ipv6' ? (s.addresses6 || []) : []);
    (s.interfaces || []).forEach(function (i) {
      var row = el('div', 'mt-if' + (i.disabled ? ' off' : ''));
      row.appendChild(el('span', 'dot ' + (i.running ? 'ok' : 'bad')));
      row.appendChild(noI18n(el('b', 'mono', i.name)));
      inList(i.name).forEach(function (l) { row.appendChild(noI18n(tag(l, l === 'WAN' ? 'warn' : (l === 'LAN' ? 'ok' : 'info')))); });
      var a = addrs.filter(function (x) { return x.interface === i.name; }).map(function (x) { return x.address; });
      if (a.length) row.appendChild(noI18n(el('div', 'mono small muted mt-if-a', a.join(' · '))));
      ifs.appendChild(row);
    });
    box.appendChild(ifs);
    var al = el('div', 'mt-panel');
    al.appendChild(el('h3', 'peek-h', 'Address lists'));
    var ll = (s.lists || {})[MV.fam] || {};
    var names = Object.keys(ll).sort();
    if (!names.length) al.appendChild(el('p', 'muted small', 'none'));
    names.forEach(function (n) {
      var d = document.createElement('details');
      d.className = 'mt-list';
      var sm = document.createElement('summary');
      sm.appendChild(noI18n(el('b', 'mono', n)));
      sm.appendChild(el('span', 'mt-n', String(ll[n].length)));
      d.appendChild(sm);
      ll[n].slice(0, 200).forEach(function (e) {
        var row = el('div', 'mt-le' + (e.disabled ? ' off' : ''));
        row.appendChild(noI18n(el('span', 'mono small', e.address)));
        if (e.comment) row.appendChild(noI18n(el('span', 'muted small', e.comment)));
        if (e.dynamic) row.appendChild(tag('dynamic', 'info'));
        d.appendChild(row);
      });
      if (ll[n].length > 200) d.appendChild(el('div', 'muted small', '… and ' + num(ll[n].length - 200) + ' more'));
      al.appendChild(d);
    });
    box.appendChild(al);
    return box;
  }
  function legend() {
    var l = el('div', 'mt-legend small muted');
    [['ok', 'accept'], ['crit', 'drop / reject'], ['info', 'dst-nat'], ['violet', 'src-nat / masquerade'], ['dim', 'jump / return / passthrough'], ['warn', 'log / address list']].forEach(function (x) {
      var s = el('span', 'mt-lg');
      s.appendChild(el('span', 'mt-sw ' + x[0]));
      s.appendChild(document.createTextNode(x[1]));
      l.appendChild(s);
    });
    var m = el('span', 'mt-lg');
    m.appendChild(el('span', 'mt-sw mine'));
    m.appendChild(document.createTextNode('concerns a port asked for'));
    l.appendChild(m);
    return l;
  }

  window.MTV = {
    load: load,
    focus: function (f) { MV.focus = f; if (MV.d && MV.host && !MV.busy) { MV.focus = null; showFocus(f); } },
    state: function () { return MV.d; },
    jumps: jumps
  };
}());
