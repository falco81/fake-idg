/* Settings → Gateway for devices (1.7.15). A PS5 asks UPnP only of its default gateway: this server made the
   gateway of chosen devices forwards their traffic to the router - only theirs, only toward the router, never
   between this server's networks. The state as a hero card (as Backups'), the devices in a table with their
   packets and how far they got, Add / Edit / Remove in popups, what to type on the PS5, and the banner of a
   change on trial on every page. Root's part: deploy/root_gateway.py. */
(function () {
  'use strict';
  var GW = {d: null, steps: {}, poll: null};

  function live() { return TAB === 'settings' && PANE === 'gateway'; }
  function load() {
    Promise.all([api('gateway'), api('upnp-steps').catch(function () { return {clients: {}}; })]).then(function (two) {
      GW.d = two[0]; GW.steps = two[1].clients || {};
      draw();
      pollFor();
      if (window.GW_PREFILL) {
        var p = window.GW_PREFILL; window.GW_PREFILL = null;
        var have = (GW.d.devices || []).filter(function (x) { return x.ip === p.ip; })[0];
        deviceEdit(have || {ip: p.ip, name: p.name || ''});
      }
    }).catch(oops);
  }
  function pollFor() {
    var a = GW.d && GW.d.asked;
    var on = !!(a && a.state === 'waiting');
    if (on && !GW.poll) GW.poll = setInterval(function () { if (!live()) { clearInterval(GW.poll); GW.poll = null; return; } quiet(); }, 2000);
    if (!on && GW.poll) { clearInterval(GW.poll); GW.poll = null; }
  }
  function quiet() {
    api('gateway').then(function (d) {
      var was = GW.d && GW.d.asked;
      GW.d = d; draw(true); pollFor();
      var a = d.asked || {};
      if (was && was.state === 'waiting' && a.id === was.id && a.state !== 'waiting') {
        toast(a.state === 'done' ? 'root has put it in' : 'root refused: ' + (a.said || []).join('; '), a.state === 'done' ? 'good' : 'bad');
        gwTrialsLoad();
      }
    }).catch(function () {});
  }
  function ask(body, words) {
    return api('gateway', body).then(function (x) {
      toast(x.message || words || 'asked', 'good');
      setTimeout(quiet, 600);
      setTimeout(gwTrialsLoad, 2500);
      return x;
    });
  }
  function bytesWords(n) { return n ? bytes(n) : '0 B'; }

  /* ---- the state: one hero card (as Backups') ---- */
  function state(d) {
    var ap = d.applied || {}, lv = d.live || {}, act = (d.devices || []).filter(function (x) { return x.on !== false; });
    if (ap.on && lv.ip_forward === '1') return {k: 'good', t: 'Forwarding is ON for ' + act.map(function (x) { return x.name; }).join(', ')};
    if (ap.on) return {k: 'bad', t: 'Switched on - but the kernel does not forward (net.ipv4.ip_forward is ' + (lv.ip_forward || '?') + ')'};
    if (d.on && (d.asked || {}).state === 'waiting') return {k: 'warn', t: 'Being switched on - root puts it in'};
    if (d.on) return {k: 'bad', t: 'Switched on here, but not put in - nothing is forwarded'};
    return {k: 'warn', t: 'Off - nothing is forwarded'};
  }
  function hero(d) {
    var st = state(d), nv = d.net || {}, lv = d.live || {}, ap = d.applied || {};
    var card = el('div', 'card full rb-hero gw-hero ' + st.k);
    var head = el('div', 'rb-hero-head');
    var ic = el('span', 'rb-hero-ic');
    ic.innerHTML = iconMarkup(st.k === 'good' ? 'check' : (st.k === 'bad' ? 'flag' : 'info'), 22);
    head.appendChild(ic);
    var words = el('div', 'rb-hero-words');
    words.appendChild(el('b', '', st.t));
    var facts = el('div', 'rb-hero-facts');
    var fact = function (k, v, cls, mono) {
      var f = el('span', 'rb-fact ' + (cls || ''));
      f.appendChild(el('span', 'k', k));
      var vv = el('span', 'v' + (mono ? ' mono' : ''), v);
      if (mono) noI18n(vv);
      f.appendChild(vv);
      facts.appendChild(f);
    };
    fact('Interface', nv.defif || 'no default route', nv.defif ? '' : 'bad', true);
    fact('Router', nv.router || '–', '', true);
    fact('This server there', nv.address ? nv.address + '/' + nv.prefix : '–', '', true);
    fact('Forwarding', lv.ip_forward === '1' ? 'on (net.ipv4.ip_forward 1)' : 'off (net.ipv4.ip_forward ' + (lv.ip_forward || '?') + ')',
         lv.ip_forward === '1' ? (ap.on ? 'good' : 'bad') : '');
    fact('FAKE-IGD-FWD', lv.chain ? (lv.first ? 'first in FORWARD' : 'NOT first in FORWARD') + (lv.ends_drop ? ', ends in DROP' : ', NO DROP at its end') : 'not in place',
         lv.chain ? (lv.first && lv.ends_drop ? 'good' : 'bad') : '');
    fact('Firewall', lv.firewall ? "fake-igd's - on" : "fake-igd's - OFF", lv.firewall ? 'good' : 'warn');
    fact('IPv6 forwarding', 'never (' + (lv.ip6_forward === '1' ? 'ON - not by fake-igd' : 'off') + ')', lv.ip6_forward === '1' ? 'warn' : '');
    if (lv.chain) fact('Dropped', num(lv.dropped || 0) + ' packet(s) not for the devices');
    fact('Read', lv.read_at ? ago(lv.read_at) : 'not yet');
    words.appendChild(facts);
    var why = [];
    if (!lv.firewall) why.push({k: 'warn', t: "fake-igd's firewall is off (Settings → Firewall and access): the gateway cannot be switched on - forwarding is turned on only behind fake-igd's own FORWARD chain, which ends in a DROP."});
    if (ap.why_off) why.push({k: 'bad', t: 'Turned off by itself: ' + ap.why_off});
    if (lv.ready && lv.firewall) why.push({k: 'bad', t: lv.ready});
    if (!nv.defif) why.push({k: 'bad', t: 'This server has no default route: there is no router to forward toward.'});
    var a = d.asked || {};
    if (a.state === 'failed') why.push({k: 'bad', t: 'Root: ' + (a.said || []).join(' · ')});
    if (d.on && !(d.devices || []).some(function (x) { return x.on !== false; })) why.push({k: 'warn', t: 'Switched on, but no device is on: nothing is forwarded.'});
    why.forEach(function (w) { words.appendChild(el('div', 'rb-hero-why small ' + w.k, w.t)); });
    head.appendChild(words);
    var acts = el('div', 'rb-hero-acts');
    if (d.on) {
      var off = cmdButton('Switch it off', 'power', 'danger');
      off.disabled = !ADMIN;
      off.onclick = function () {
        confirmThen('Switch the gateway for devices off?', 'Forwarding goes back off (as it was before), and fake-igd\'s FORWARD chain is taken away. The devices that use this server as their gateway reach nothing until they are given the router again.', 'Switch it off', function () {
          ask({action: 'off'}).catch(oops);
        });
      };
      acts.appendChild(off);
    } else {
      var on = cmdButton('Switch it on', 'power', 'primary');
      var any = (d.devices || []).some(function (x) { return x.on !== false; });
      on.disabled = !ADMIN || !any || !lv.firewall || !nv.defif;
      explain(on, !any ? 'Add a device first: forwarding is only ever for the devices defined here.'
        : (!lv.firewall ? "Switch fake-igd's firewall on first (Settings → Firewall and access)." : 'Forwarding turned on for the devices switched on below.'));
      on.onclick = function () {
        var names = (d.devices || []).filter(function (x) { return x.on !== false; }).map(function (x) { return x.name + ' (' + x.ip + ')'; }).join(', ');
        confirmThen('Switch the gateway for devices on?',
          htmlText('This server forwards the traffic of ' + names + ' to the router ' + (nv.router || '') + ' - in and out ' + (nv.defif || '') + ' only, and nothing else (fake-igd\'s chain ends in a DROP). ') +
          (d.confirm_min ? htmlText('On trial: unless you press Keep it within ' + d.confirm_min + ' min, it goes back off by itself.') : ''),
          'Switch it on', function () { ask({action: 'on'}).catch(oops); }, false);
      };
      acts.appendChild(on);
    }
    var rd = cmdButton('Read it again', 'refresh', '');
    rd.disabled = !ADMIN;
    rd.onclick = function () { busy(rd, true); ask({action: 'read'}).catch(oops).then(function () { busy(rd, false); }); };
    acts.appendChild(rd);
    head.appendChild(acts);
    card.appendChild(head);
    if (a.state === 'waiting') {
      var going = el('div', 'going wide');
      going.innerHTML = '<div class="bar"><span class="creeping"></span></div><div class="says"></div>';
      going.querySelector('span').style.width = '40%';
      going.querySelector('.says').textContent = 'Asked of root ' + ago(a.at) + ' - it puts it in within seconds.';
      card.appendChild(going);
    }
    return card;
  }

  /* ---- the devices ---- */
  function devicesCard(d) {
    var card = el('div', 'card full gw-devices');
    var top = el('h2', '', 'The devices ');
    var right = el('span', 'right');
    var add = cmdButton('Add a device', 'add', 'primary small');
    add.disabled = !ADMIN;
    add.onclick = function () { deviceEdit({}); };
    right.appendChild(add);
    top.appendChild(right);
    card.appendChild(top);
    card.appendChild(el('p', 'note', 'Each device by its IPv4 address, a name, and best its MAC as well - then a box that takes the address of another does not pass. Forwarded only in and out ' + ((d.net || {}).defif || 'the interface of the default route') + ', toward the router; the packets counted for each.'));
    card.appendChild(listTable(['Device', 'Address', 'MAC', 'Allowed', {words: 'Forwarded', cls: 'num'}, 'Last through', 'How far it got (Clients)', 'On', ''],
      d.devices || [], function (x) {
        var tr = el('tr');
        var nm = el('td', 'gw-name');
        nm.appendChild(el('b', '', x.name));
        if (x.why) nm.appendChild(el('div', 'small bad', x.why));
        else if (d.applied && d.applied.on && x.on !== false && !x.applied) nm.appendChild(el('div', 'small warn', 'not put in yet'));
        tr.appendChild(nm);
        tr.appendChild(noI18n(el('td', 'mono', x.ip)));
        tr.appendChild(noI18n(el('td', 'mono small' + (x.mac ? '' : ' muted'), x.mac || 'any (the address only)')));
        var al = el('td', 'gw-allowed');
        var chip = el('a', 'gw-allow-link', 'Internet' + ((x.dns || []).length ? ' · DNS ' + x.dns.length : '')
          + ((x.rules || []).length ? ' · ' + x.rules.length + ' rule' + (x.rules.length > 1 ? 's' : '') : ''));
        chip.onclick = function () { openDesigner(x); };
        al.appendChild(chip);
        tr.appendChild(al);
        var c = x.counters || {};
        tr.appendChild(el('td', 'num', c.out_pkts ? num(c.out_pkts) + ' pkts · ' + bytesWords(c.out_bytes) : '–'));
        if (x.seen) tr.appendChild(stampCell(x.seen));
        else {
          var seen = el('td');
          seen.appendChild(el('span', 'tag ' + (x.applied ? 'warn' : 'dim'), x.applied ? 'nothing yet' : 'not forwarded'));
          if (x.applied) seen.appendChild(el('div', 'muted small', 'is its gateway set to this server?'));
          tr.appendChild(seen);
        }
        var stp = el('td');
        var s = GW.steps[x.ip];
        if (typeof stepPills === 'function') stp.appendChild(stepPills(s || {reached: [], furthest: -1}));
        if (s && s.stopped) stp.appendChild(el('div', 'muted small step-said', s.stopped));
        tr.appendChild(stp);
        var swc = el('td');
        var sw = switchBox(x.on !== false);
        sw._input.disabled = !ADMIN;
        sw._input.onchange = function () {
          var want = sw._input.checked;
          ask({action: 'device_on', id: x.id, on: want}).catch(function (e) { sw._input.checked = !want; oops(e); });
        };
        swc.appendChild(sw);
        tr.appendChild(swc);
        var tools = el('td', 'rowtools');
        var fw = iconButton('wall', 'Its firewall: DNS servers and rules of its own');
        fw.onclick = function () { openDesigner(x); };
        tools.appendChild(fw);
        var ed = iconButton('edit', 'Edit');
        ed.disabled = !ADMIN;
        ed.onclick = function () { deviceEdit(x); };
        var rm = iconButton('trash', 'Remove');
        rm.disabled = !ADMIN;
        rm.onclick = function () {
          var last = (d.devices || []).length === 1;
          confirmThen('Remove ' + htmlText(x.name) + '?', htmlText(x.ip + ' is no longer forwarded' + (last ? ' - it is the last device: the forwarding goes off with it.' : '.')
            + ' Give it the router as its gateway again.'), 'Remove it', function () {
            ask({action: 'device_remove', id: x.id}).catch(oops);
          });
        };
        tools.appendChild(ed); tools.appendChild(rm);
        tr.appendChild(tools);
        return tr;
      }, 'rows|No device yet - Add a device: the one that stopped at "answered" on the Clients tab', {own: true}));
    return card;
  }

  /* ---- Add / Edit a device ---- */
  function deviceEdit(x) {
    var d = GW.d || {}, nv = d.net || {};
    var name = textBox(x.name || '', 'PS5 Pro');
    var ip = textBox(x.ip || '', nv.network ? 'an address in ' + nv.network : '192.168.40.95', 'mono');
    var mac = textBox(x.mac || '', 'aa:bb:cc:dd:ee:ff - empty: the address only', 'mono');
    var on = switchBox(x.on !== false);
    var said = el('div', 'muted small gw-mac-said');
    modal(x.id ? 'Edit ' + x.name : 'Add a device', function (body) {
      body.appendChild(el('p', 'note', 'The device that should use this server as its default gateway - typed, or picked from what fake-igd has seen. It has to be in ' + (nv.network || 'the network of the default route') + ' (' + (nv.defif || '?') + '), where the router is.'));
      var grid = el('div', 'set-grid gw-form');
      grid.appendChild(formField('Name', name, 'What it is, in the list and in the firewall\'s rule (letters, digits, spaces, . _ ( ) + , : / -).'));
      grid.appendChild(formField('IPv4 address', ip, 'Its address - give it a fixed one (on the PS5, or a reservation in the router\'s DHCP), or the rule no longer fits it.'));
      var macBox = el('div', 'gw-mac');
      macBox.appendChild(mac);
      var seen = cmdButton('Use the MAC seen now', 'search', 'small');
      seen.onclick = function () {
        if (!ip.value.trim()) { said.textContent = 'Type its address first.'; return; }
        busy(seen, true);
        api('gateway', {action: 'mac_seen', ip: ip.value.trim()}).then(function (r) {
          if (r.mac) mac.value = r.mac;
          said.textContent = r.message;
        }).catch(oops).then(function () { busy(seen, false); });
      };
      macBox.appendChild(seen);
      macBox.appendChild(said);
      grid.appendChild(formField('MAC address', macBox, 'With it the rule matches only this device\'s network card: another box that takes its address does not pass. From this server\'s neighbour table (ip neigh) - the device must have spoken lately.'));
      grid.appendChild(formField('Forwarded', on, 'Off: kept in the list, not forwarded.'));
      body.appendChild(grid);
      body.appendChild(el('h3', 'peek-h', 'Seen here - press one to take it'));
      var pick = el('div', 'gw-pick');
      pick.appendChild(el('p', 'muted small', 'Looking…'));
      body.appendChild(pick);
      api('clients&per=200').catch(function () { return {clients: []}; }).then(function (cl) {
        clear(pick);
        var rows = [], had = {};
        (cl.clients || []).forEach(function (c) {
          if (!inNet(c.client, nv.network) || had[c.client]) return;
          had[c.client] = 1;
          var st = GW.steps[c.client];
          rows.push({ip: c.client, name: c.name || '', mac: (d.neigh || {})[c.client] || '', what: c.user_agent || '', st: st, from: 'fake-igd saw it (Clients)'});
        });
        Object.keys(d.neigh || {}).forEach(function (a) {
          if (had[a] || a === nv.router || !inNet(a, nv.network)) return;
          had[a] = 1;
          rows.push({ip: a, name: '', mac: d.neigh[a], what: '', from: 'the neighbour table'});
        });
        pick.appendChild(listTable(['Address', 'MAC', 'Known as', 'How far it got', 'Seen in'], rows, function (r) {
          var tr = el('tr', 'tappable');
          tr.appendChild(noI18n(el('td', 'mono', r.ip)));
          tr.appendChild(noI18n(el('td', 'mono small', r.mac || '–')));
          tr.appendChild(noI18n(el('td', 'small', r.name || r.what || '–')));
          var td = el('td');
          if (r.st && typeof stepPills === 'function') td.appendChild(stepPills(r.st));
          tr.appendChild(td);
          tr.appendChild(el('td', 'muted small', r.from));
          tr.onclick = function () {
            ip.value = r.ip;
            if (r.mac) mac.value = r.mac;
            if (!name.value.trim()) name.value = /playstation|ps5|sony/i.test(r.what + ' ' + r.name) ? 'PS5' : (r.name || '');
            said.textContent = r.mac ? 'MAC from the neighbour table' : '';
          };
          return tr;
        }, 'rows|Nothing seen in ' + (nv.network || 'that network') + ' yet', {own: true}));
      });
    }, [{words: 'Cancel', close: true},
        {words: x.id ? 'Save' : 'Add it', cls: 'primary', icon: 'check', go: function (button) {
          busy(button, true);
          api('gateway', {action: 'device_save', device: {id: x.id || '', name: name.value.trim(), ip: ip.value.trim(), mac: mac.value.trim(), on: !!on._get()}})
            .then(function (r) { closeModal(); toast(r.message, 'good'); setTimeout(quiet, 600); setTimeout(gwTrialsLoad, 2500); })
            .catch(oops).then(function () { busy(button, false); });
        }}], 'medium');
  }
  function ipNum(x) { return x.split('.').reduce(function (s, o) { return s * 256 + Number(o); }, 0); }
  function inNet(a, net) {
    if (!net || !/^\d+\.\d+\.\d+\.\d+$/.test(a || '')) return false;
    var p = net.split('/'), size = Math.pow(2, 32 - Number(p[1]));
    return Math.floor(ipNum(a) / size) === Math.floor(ipNum(p[0]) / size);
  }

  /* ---- what to type on the device ---- */
  function howCard(d) {
    var nv = d.net || {};
    var card = el('div', 'card full gw-how');
    card.appendChild(el('h2', '', 'What to set on the PS5'));
    card.appendChild(el('p', 'note', 'On the PS5: Settings → Network → Settings → Set Up Internet Connection → your connection (press Options or hold it) → Advanced Settings → IP Address Settings: Manual - then these. On another device the same four values, wherever its network is set by hand.'));
    var list = (d.devices || []).length ? d.devices : [{name: 'the device', ip: 'its own address (a free one in ' + (nv.network || '?') + ')'}];
    list.forEach(function (x) {
      card.appendChild(el('h3', 'peek-h', x.name));
      card.appendChild(peekFacts([
        ['IP Address', noI18n(el('span', 'mono', x.ip))],
        ['Subnet Mask', noI18n(el('span', 'mono', nv.mask || '?'))],
        ['Default Gateway', noI18n(el('span', 'mono', nv.address || '?'))],
        ['Primary DNS', noI18n(el('span', 'mono', (nv.dns || [])[0] || nv.router || '?'))],
        ['Secondary DNS', noI18n(el('span', 'mono', (nv.dns || [])[1] || '–'))]
      ]));
    });
    card.appendChild(el('p', 'muted small', 'Default Gateway is this server\'s address on ' + (nv.defif || '?') + ' - the network the PS5 is on. The DNS servers stay what it uses now (this server\'s own are shown; the router ' + (nv.router || '') + ' is as good). MTU automatic, proxy server: do not use.'));
    return card;
  }
  function warnCard(d) {
    var nv = d.net || {};
    var card = el('div', 'card full gw-warn');
    card.appendChild(el('h2', '', 'Before you use it'));
    var ul = el('ul', 'gw-list');
    var others = Object.keys(nv.others || {}).map(function (k) { return k + ' ' + (nv.others[k] || []).join(', '); });
    [['warn', 'This server becomes a single point of failure for those devices: while it is down, restarting or being upgraded, they reach nothing. Give them the router again to go back.'],
     ['', 'After a restart it comes back by itself: the forwarding from /etc/sysctl.d/90-fake-igd-gateway.conf, the rules from /etc/sysconfig/iptables (between fake-igd\'s marks).'],
     ['', 'Nothing crosses between this server\'s networks: every one of them is a destination fake-igd drops' + (others.length ? ' (' + others.join('; ') + ')' : '') + ', and the chain ends in a DROP of its own - whatever FORWARD\'s policy says.'],
     ['', 'IPv6 is never forwarded: the devices\' IPv6 goes as it went (to the router directly). UPnP is IPv4.'],
     ['', 'A change is on trial as the firewall\'s: unless you press Keep it within ' + (d.confirm_min || 0) + ' min, it goes back by itself. Switching off is never on trial.']]
      .forEach(function (x) { var li = el('li', x[0], x[1]); ul.appendChild(li); });
    card.appendChild(ul);
    return card;
  }

  function draw(isQuiet) {
    var host = $('gw-host');
    if (!host || !GW.d) return;
    liveFill(host, function (box) {
      box.appendChild(hero(GW.d));
      box.appendChild(devicesCard(GW.d));
      box.appendChild(howCard(GW.d));
      box.appendChild(warnCard(GW.d));
    }, isQuiet, function () { explainWhatWasDrawn(host); });
  }
  /* ---- the FW designer of a device (1.8.2): its DNS servers and rules of its own - a flow on top, the lists
     below, a packet tried through the lines as root would put them in, those lines, Save on trial. ---- */
  function openDesigner(x) {
    var d = GW.d || {}, nv = d.net || {};
    var ED = {dns: (x.dns || []).map(function (y) { return {ip: y.ip, dot: !!y.dot, hits: y.hits, via: y.via, direct: y.direct}; }),
              rules: (x.rules || []).map(function (r) { return {id: r.id, to: r.to, proto: r.proto || 'any', ports: r.ports || '', comment: r.comment || '', on: r.on !== false, hits: r.hits, via: r.via, direct: r.direct}; }),
              preview: null, dirty: false, editing: null};
    var host = {};
    var others = nv.others || {};
    var netChips = Object.keys(others).map(function (k) { return {dev: k, nets: others[k]}; });
    function prv() {
      return api('gateway', {action: 'try', id: x.id, dns: ED.dns.map(function (y) { return {ip: y.ip, dot: y.dot}; }),
                             rules: ED.rules.map(function (r) { return {id: r.id, to: r.to, proto: r.proto, ports: r.ports, comment: r.comment, on: r.on}; })});
    }
    function refresh() {
      ED.dirty = true;
      prv().then(function (p) {
        ED.preview = p; host.err.textContent = '';
        (p.dns || []).forEach(function (y, i) { if (ED.dns[i]) { ED.dns[i].via = y.via; ED.dns[i].direct = y.direct; } });
        (p.rules || []).forEach(function (r, i) { if (ED.rules[i]) { ED.rules[i].via = r.via; ED.rules[i].direct = r.direct; ED.rules[i].id = ED.rules[i].id || r.id; ED.rules[i].to = r.to; } });
        paint();
      }).catch(function (e) { host.err.textContent = String(e.message || e); paint(); });
    }
    function lane(ok, title, detail, hits, cls) {
      var l = el('div', 'gwf-lane ' + (cls || (ok ? 'ok' : 'no')));
      l.appendChild(el('span', 'gwf-mark', ok === null ? '·' : (ok ? '✓' : '✗')));
      var w = el('div', 'gwf-words');
      w.appendChild(el('b', '', title));
      if (detail) w.appendChild(noI18n(el('span', 'gwf-detail mono', detail)));
      l.appendChild(w);
      if (hits) l.appendChild(el('span', 'gwf-hits', hits));
      return l;
    }
    function hitWords(h) { return h && h.pkts ? num(h.pkts) + ' pkts · ' + bytes(h.bytes) : ''; }
    function flow() {
      var f = el('div', 'gw-flow');
      var dev = el('div', 'gwf-node gwf-dev');
      dev.innerHTML = iconMarkup('router', 22);
      var dw = el('div', 'gwf-node-words');
      dw.appendChild(el('b', '', x.name));
      dw.appendChild(noI18n(el('span', 'mono', x.ip)));
      dw.appendChild(noI18n(el('span', 'mono small muted', x.mac || 'any MAC')));
      dev.appendChild(dw);
      f.appendChild(dev);
      f.appendChild(el('div', 'gwf-arrow', '→'));
      var srv = el('div', 'gwf-node gwf-srv');
      srv.innerHTML = iconMarkup('wall', 22);
      var sw = el('div', 'gwf-node-words');
      sw.appendChild(el('b', '', 'this server'));
      sw.appendChild(noI18n(el('span', 'mono', nv.address || '?')));
      sw.appendChild(noI18n(el('span', 'small muted', (nv.defif || '?') + ' · FAKE-IGD-FWD')));
      srv.appendChild(sw);
      f.appendChild(srv);
      f.appendChild(el('div', 'gwf-arrow', '→'));
      var lanes = el('div', 'gwf-lanes');
      lanes.appendChild(lane(true, 'Internet', 'via the router ' + (nv.router || '?') + ' (' + (nv.defif || '?') + ')', hitWords(x.internet)));
      ED.dns.forEach(function (y) {
        lanes.appendChild(lane(y.direct ? null : true, 'DNS ' + y.ip, y.direct ? 'on its own network - reached directly, no rule needed'
          : 'udp + tcp 53' + (y.dot ? ' and DoT tcp 853' : '') + ' out ' + (y.via || '?'), hitWords(y.hits), y.direct ? 'direct' : ''));
      });
      ED.rules.forEach(function (r) {
        var what = (r.proto === 'any' ? 'everything' : r.proto + (r.ports ? ' ' + r.ports : '')) + ' → ' + r.to + (r.via ? ' out ' + r.via : '');
        lanes.appendChild(lane(r.on ? (r.direct ? null : true) : false, r.comment || 'A rule of its own', what + (r.on ? '' : ' - switched off') + (r.direct ? ' - on its own network, reached directly' : ''),
          hitWords(r.hits), r.on ? (r.direct ? 'direct' : '') : 'off'));
      });
      var loc = Object.keys(others).map(function (k) { return k + ' ' + others[k].join(', '); });
      lanes.appendChild(lane(false, 'Your local networks', (nv.network ? nv.defif + ' ' + nv.network + ' (through this server)' : '') + (loc.length ? '; ' + loc.join('; ') : '')));
      lanes.appendChild(lane(false, 'Private networks behind the router', '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10'));
      lanes.appendChild(lane(false, 'Everything else', 'multicast, link-local, loopback - and any other device'));
      f.appendChild(lanes);
      return f;
    }
    function dnsCard() {
      var c = el('div', 'card gwd-card');
      c.appendChild(el('h3', 'peek-h', 'DNS servers it may ask'));
      c.appendChild(el('p', 'note', 'udp and tcp 53 to exactly these - also in a private network or another network of this server. Empty: as now (the internet is allowed anyway). One on its own network is reached directly.'));
      var chips = el('div', 'gwd-chips');
      ED.dns.forEach(function (y, i) {
        var ch = el('span', 'gwd-chip' + (y.direct ? ' direct' : ''));
        ch.appendChild(noI18n(el('span', 'mono', y.ip)));
        var dot = el('label', 'gwd-dot');
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!y.dot; cb.disabled = !ADMIN;
        cb.onchange = function () { y.dot = cb.checked; refresh(); };
        dot.appendChild(cb); dot.appendChild(document.createTextNode(' DoT 853'));
        ch.appendChild(dot);
        if (y.direct) ch.appendChild(el('span', 'small muted', 'direct'));
        var rm = el('button', 'gwd-x', '×'); rm.type = 'button'; rm.title = 'Take it away'; rm.disabled = !ADMIN;
        rm.onclick = function () { ED.dns.splice(i, 1); refresh(); };
        ch.appendChild(rm);
        chips.appendChild(ch);
      });
      if (!ED.dns.length) chips.appendChild(el('span', 'muted small', 'none - as now'));
      c.appendChild(chips);
      var row = el('div', 'gwd-add');
      var inp = textBox('', 'an IPv4 address', 'mono');
      var add = cmdButton('Add', 'add', 'small');
      var put = function (ip) {
        ip = (ip || '').trim();
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) { host.err.textContent = 'A DNS server is one IPv4 address.'; return; }
        if (ED.dns.some(function (y) { return y.ip === ip; })) return;
        ED.dns.push({ip: ip, dot: false}); inp.value = ''; refresh();
      };
      add.disabled = inp.disabled = !ADMIN;
      add.onclick = function () { put(inp.value); };
      inp.onkeydown = function (e) { if (e.key === 'Enter') put(inp.value); };
      row.appendChild(inp); row.appendChild(add);
      c.appendChild(row);
      var sug = el('div', 'gwd-sugg');
      var offer = [].concat(nv.dns || [], nv.router ? [nv.router] : []).filter(function (a, i, all) { return all.indexOf(a) === i && !ED.dns.some(function (y) { return y.ip === a; }); });
      if (offer.length) sug.appendChild(el('span', 'small muted', 'Offered: '));
      offer.forEach(function (a) {
        var b = el('button', 'gwd-sug mono', '+ ' + a); b.type = 'button'; b.disabled = !ADMIN;
        b.title = (nv.dns || []).indexOf(a) >= 0 ? 'this server\'s resolver - what the PS5 values below show' : 'the router';
        b.onclick = function () { put(a); };
        sug.appendChild(b);
      });
      c.appendChild(sug);
      return c;
    }
    function ruleEditor(r, i) {
      var box = el('div', 'gwd-editor');
      box.appendChild(el('h4', '', i < 0 ? 'A new rule' : 'The rule'));
      var to = textBox(r.to || '', '172.16.17.10 or 172.16.17.0/24', 'mono');
      var chips = el('div', 'gwd-netchips');
      netChips.forEach(function (n) {
        n.nets.forEach(function (net) {
          var b = el('button', 'gwd-sug mono', n.dev + ' ' + net); b.type = 'button';
          b.onclick = function () { to.value = net; check(); };
          chips.appendChild(b);
        });
      });
      var seg = el('div', 'seg gwd-seg');
      var proto = r.proto || 'tcp';
      ['tcp', 'udp', 'icmp', 'any'].forEach(function (p) {
        var b = el('button', 'seg-b' + (p === proto ? ' on' : ''), p); b.type = 'button';
        b.onclick = function () { proto = p; seg.querySelectorAll('button').forEach(function (z) { z.classList.toggle('on', z.textContent === p); }); check(); };
        seg.appendChild(b);
      });
      var ports = textBox((r.ports || '').replace(/:/g, '-'), '8080  ·  8000-8100  ·  80,443', 'mono');
      var note = textBox(r.comment || '', 'what it is for');
      var said = el('div', 'small gwd-said');
      var check = function () {
        var p = ports.value.replace(/\s/g, ''), bad = '';
        if (!/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(to.value.trim())) bad = 'The destination: an IPv4 address or network (172.16.17.10, 172.16.17.0/24).';
        else if (/\/(\d+)$/.test(to.value) && Number(/\/(\d+)$/.exec(to.value)[1]) < 8) bad = 'Not a whole range of the internet - the internet is allowed already.';
        else if (p && (proto === 'icmp' || proto === 'any')) bad = 'Ports are for tcp or udp.';
        else if (p && !/^(\d{1,5}([-:]\d{1,5})?)(,\d{1,5}([-:]\d{1,5})?)*$/.test(p)) bad = 'Ports: 8080, a range 8000-8100, or a list 80,443.';
        said.textContent = bad; said.className = 'small gwd-said' + (bad ? ' bad' : '');
        return !bad;
      };
      to.oninput = ports.oninput = check;
      var grid = el('div', 'set-grid gwd-egrid');
      var tw = el('div', 'gwd-to');
      tw.appendChild(to);
      tw.appendChild(chips);
      grid.appendChild(formField('To', tw, 'One address or one network - in a network of this server (then out that interface, its answers back) or behind the router. A network of this server: press it above.'));
      grid.appendChild(formField('Protocol', seg, 'tcp, udp, icmp (ping) or any.'));
      grid.appendChild(formField('Ports', ports, 'For tcp or udp: 8080 · 8000-8100 · 80,443,8000-8100 (fifteen at most). Empty: every port.'));
      grid.appendChild(formField('What for', note, 'In the list and in the rule\'s iptables comment.'));
      box.appendChild(grid);
      box.appendChild(said);
      var row = el('div', 'btnrow');
      var ok = cmdButton(i < 0 ? 'Add the rule' : 'Done', 'check', 'primary small');
      ok.onclick = function () {
        if (!check()) return;
        var one = {id: r.id || '', to: to.value.trim(), proto: proto, ports: ports.value.replace(/\s/g, ''), comment: note.value.trim(), on: r.on !== false};
        if (i < 0) ED.rules.push(one); else ED.rules[i] = one;
        ED.editing = null; refresh();
      };
      var no = cmdButton('Cancel', 'close', 'small');
      no.onclick = function () { ED.editing = null; paint(); };
      row.appendChild(ok); row.appendChild(no);
      box.appendChild(row);
      setTimeout(function () { try { to.focus(); } catch (e) { } }, 0);
      return box;
    }
    function rulesCard() {
      var c = el('div', 'card gwd-card');
      var h = el('h3', 'peek-h', 'Rules of its own ');
      c.appendChild(h);
      c.appendChild(el('p', 'note', 'Each allows this device - and only it - to one destination, in the order below. None: as now (the internet only). Never toward everything, never this server itself.'));
      if (!ED.rules.length && ED.editing === null) c.appendChild(el('p', 'muted small', 'No rule of its own.'));
      ED.rules.forEach(function (r, i) {
        if (ED.editing === i) { c.appendChild(ruleEditor(r, i)); return; }
        var row = el('div', 'gwd-rule' + (r.on ? '' : ' off'));
        var ord = el('span', 'gwd-ord');
        var up = el('button', 'gwd-arrow', '↑'); up.type = 'button'; up.disabled = !ADMIN || i === 0; up.title = 'Up';
        up.onclick = function () { var t = ED.rules[i - 1]; ED.rules[i - 1] = r; ED.rules[i] = t; refresh(); };
        var dn = el('button', 'gwd-arrow', '↓'); dn.type = 'button'; dn.disabled = !ADMIN || i === ED.rules.length - 1; dn.title = 'Down';
        dn.onclick = function () { var t = ED.rules[i + 1]; ED.rules[i + 1] = r; ED.rules[i] = t; refresh(); };
        ord.appendChild(el('span', 'gwd-n', String(i + 1)));
        ord.appendChild(up); ord.appendChild(dn);
        row.appendChild(ord);
        var sw = switchBox(r.on);
        sw._input.disabled = !ADMIN;
        sw._input.onchange = function () { r.on = sw._input.checked; refresh(); };
        row.appendChild(sw);
        var w = el('div', 'gwd-rule-words');
        w.appendChild(el('b', '', r.comment || 'A rule of its own'));
        w.appendChild(noI18n(el('span', 'mono small', (r.proto === 'any' ? 'any' : r.proto + (r.ports ? ' ' + r.ports.replace(/:/g, '-') : ' every port')) + ' → ' + r.to + (r.via ? '  (out ' + r.via + ')' : ''))));
        if (r.direct) w.appendChild(el('span', 'small muted', 'on its own network: reached directly, no rule needed'));
        row.appendChild(w);
        row.appendChild(el('span', 'gwd-hits small muted', r.hits && r.hits.pkts ? num(r.hits.pkts) + ' pkts · ' + bytes(r.hits.bytes) : 'no packet yet'));
        var ed = iconButton('edit', 'Change it'); ed.disabled = !ADMIN;
        ed.onclick = function () { ED.editing = i; paint(); };
        var rm = iconButton('trash', 'Take it away'); rm.disabled = !ADMIN;
        rm.onclick = function () { ED.rules.splice(i, 1); refresh(); };
        row.appendChild(ed); row.appendChild(rm);
        c.appendChild(row);
      });
      if (ED.editing === -1) c.appendChild(ruleEditor({proto: 'tcp', on: true}, -1));
      else if (ADMIN) {
        var add = cmdButton('Add a rule', 'add', 'small');
        add.disabled = ED.rules.length >= 64;
        add.onclick = function () { ED.editing = -1; paint(); };
        var r0 = el('div', 'btnrow'); r0.appendChild(add); c.appendChild(r0);
      }
      return c;
    }
    function tryCard() {
      var c = el('div', 'card gwd-card gwd-try');
      c.appendChild(el('h3', 'peek-h', 'Try a packet'));
      c.appendChild(el('p', 'note', 'From ' + x.name + ' through the rules as they would be with what is set here now - the same lines root puts in, the first that fits decides.'));
      var grid = el('div', 'gwd-trygrid');
      var dst = textBox(c._dst || '', '8.8.8.8', 'mono');
      var sel = el('select'); ['tcp', 'udp', 'icmp'].forEach(function (p) { var o = el('option', '', p); o.value = p; sel.appendChild(o); });
      var port = textBox('443', 'port', 'mono');
      var spoof = el('label', 'small'); var cb = el('input'); cb.type = 'checkbox'; spoof.appendChild(cb); spoof.appendChild(document.createTextNode(' from another box that took its address'));
      var go = cmdButton('Try it', 'play', 'primary small');
      var out = el('div', 'gwd-verdict');
      go.onclick = function () {
        busy(go, true);
        api('gateway', {action: 'try', id: x.id, dst: dst.value.trim(), proto: sel.value, port: port.value.trim(), mac_other: cb.checked,
                        dns: ED.dns.map(function (y) { return {ip: y.ip, dot: y.dot}; }),
                        rules: ED.rules.map(function (r) { return {id: r.id, to: r.to, proto: r.proto, ports: r.ports, comment: r.comment, on: r.on}; })})
          .then(function (t) {
            clear(out);
            var k = t.direct ? 'info' : (t.verdict === 'ACCEPT' ? 'ok' : 'crit');
            out.appendChild(el('span', 'tag ' + k, t.direct ? 'direct' : (t.verdict === 'ACCEPT' ? 'forwarded' : 'dropped')));
            out.appendChild(el('span', '', ' ' + t.words + (t.out ? ' · out ' + t.out : '')));
            if (t.rule) out.appendChild(noI18n(el('div', 'mono small muted', 'decided by: ' + t.rule)));
          }).catch(function (e) { clear(out); out.appendChild(el('span', 'bad', String(e.message || e))); })
          .then(function () { busy(go, false); });
      };
      grid.appendChild(formField('To', dst));
      grid.appendChild(formField('Protocol', sel));
      grid.appendChild(formField('Port', port));
      c.appendChild(grid);
      var row = el('div', 'btnrow'); row.appendChild(go); row.appendChild(spoof); c.appendChild(row);
      c.appendChild(out);
      return c;
    }
    function linesBlock() {
      var det = el('details', 'gwd-lines');
      det.appendChild(el('summary', '', 'What root puts in for ' + x.name + ' (iptables, FAKE-IGD-FWD)'));
      var lines = (ED.preview && ED.preview.lines) || x.lines || [];
      det.appendChild(noI18n(el('pre', 'mono small', lines.join('\n') + '\n# ... then the drops toward every local and private network, the internet line above, and at the end:\n-A FAKE-IGD-FWD -m comment --comment "fake-igd: nothing else is forwarded" -j DROP')));
      return det;
    }
    function paint() {
      if (!host.body) return;
      var open = host.body.querySelector('details.gwd-lines');
      var wasOpen = open && open.open;
      var dstWas = host.body.querySelector('.gwd-try input');
      clear(host.body);
      host.body.appendChild(flow());
      host.body.appendChild(host.err);
      if ((x.left_out || []).length && !ED.dirty) host.body.appendChild(el('p', 'note bad', 'Left out by root: ' + x.left_out.join('; ')));
      var two = el('div', 'gwd-two');
      two.appendChild(dnsCard());
      two.appendChild(rulesCard());
      host.body.appendChild(two);
      var t = tryCard();
      if (dstWas && dstWas.value) t.querySelector('input').value = dstWas.value;
      host.body.appendChild(t);
      var ln = linesBlock();
      if (wasOpen) ln.open = true;
      host.body.appendChild(ln);
    }
    modal('The firewall of ' + x.name, function (body) {
      host.body = body;
      host.err = el('p', 'note bad gwd-err');
      paint();
      setTimeout(function () { body.scrollTop = 0; }, 60);
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'check', admin: true, go: function (button) {
          busy(button, true);
          api('gateway', {action: 'designer_save', id: x.id, dns: ED.dns.map(function (y) { return {ip: y.ip, dot: y.dot}; }),
                          rules: ED.rules.map(function (r) { return {id: r.id, to: r.to, proto: r.proto, ports: r.ports, comment: r.comment, on: r.on}; })})
            .then(function (r) { closeModal(); toast(r.message, 'good'); setTimeout(quiet, 600); setTimeout(gwTrialsLoad, 2500); })
            .catch(function (e) { host.err.textContent = String(e.message || e); })
            .then(function () { busy(button, false); });
        }}], 'large');
  }
  window.GW_DESIGNER = openDesigner;

  PANE_LOAD.gateway = load;
  PANE_TICK.gateway = function () { };

  /* ---- a change on trial: on every page (as the firewall's banner) ---- */
  var T = {list: [], skew: 0, timer: null};
  function trialsHost() {
    var host = $('trials-gw');
    if (host) return host;
    var all = $('trials');
    if (!all) return null;
    host = el('div', 'trials');
    host.id = 'trials-gw';
    host.style.margin = '0';
    all.appendChild(host);
    return host;
  }
  function drawTrials(d) {
    T.list = (d && d.trials) || [];
    T.skew = d && d.now ? d.now - Date.now() / 1000 : 0;
    var host = trialsHost();
    if (!host) return;
    var all = $('trials');
    if (!T.list.length) {
      host.hidden = true; clear(host);
      all.hidden = !Array.prototype.some.call(all.children, function (c) { return !c.hidden; });
      if (T.timer) { clearInterval(T.timer); T.timer = null; }
      return;
    }
    host.hidden = false; all.hidden = false;
    liveFill(host, function (box) {
      T.list.forEach(function (t) {
        var row = el('div', 'trial');
        var words = el('div', 'trial-words');
        words.appendChild(el('b', '', 'The gateway for ' + ((t.devices || []).join(', ') || 'the devices') + ' waits to be kept'));
        var left = el('span', 'trial-left mono');
        left.dataset.until = t.until;
        words.appendChild(document.createTextNode(' - '));
        words.appendChild(left);
        words.appendChild(el('div', 'small', 'Not kept, the forwarding goes back to what it was by itself. Keep it once the device reaches the internet through this server.'));
        row.appendChild(words);
        var tools = el('div', 'trial-tools');
        if (ADMIN) {
          var keep = cmdButton('Keep it', 'check', 'small primary');
          keep.onclick = function () { trialDo('keep', keep); };
          var back = cmdButton('Put the old back now', 'undo', 'small danger');
          back.onclick = function () {
            confirmThen('Put the old back now?', 'The gateway for devices goes back to what it was before the change.', 'Put it back', function () { trialDo('back', back); });
          };
          tools.appendChild(keep); tools.appendChild(back);
        }
        row.appendChild(tools);
        box.appendChild(row);
      });
    }, true);
    count();
    if (!T.timer) T.timer = setInterval(count, 1000);
  }
  function count() {
    var now = Date.now() / 1000 + T.skew;
    document.querySelectorAll('#trials-gw .trial-left').forEach(function (x) {
      var left = parseFloat(x.dataset.until) - now;
      x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) + ' left' : 'going back now';
    });
  }
  function trialDo(action, button) {
    busy(button, true);
    api('gateway', {action: action}).then(function (r) {
      toast(r.message, 'good');
      setTimeout(gwTrialsLoad, 1500); setTimeout(gwTrialsLoad, 4000);
      if (live()) { setTimeout(quiet, 2000); setTimeout(quiet, 5000); }
    }).catch(oops).then(function () { busy(button, false); });
  }
  function gwTrialsLoad() {
    if (typeof ME === 'undefined' || !ME) return;
    api('gateway-trial').then(drawTrials).catch(function () {});
  }
  setTimeout(gwTrialsLoad, 1200);
  setInterval(function () { if (!document.hidden) gwTrialsLoad(); }, 10000);
}());
