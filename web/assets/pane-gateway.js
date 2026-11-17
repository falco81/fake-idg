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
        var ipc = el('td');
        ipc.appendChild(noI18n(el('div', 'mono', x.ip)));
        (x.ip6 || []).forEach(function (a) { ipc.appendChild(noI18n(el('div', 'mono small muted gw-ip6', a))); });
        tr.appendChild(ipc);
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
    var ip6 = textBox((x.ip6 || []).join(', '), '2a02:…:1::3 - empty: found by its MAC on the MikroTik', 'mono');
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
      /* 1.9.3: its IPv6 addresses - only to find it on the MikroTik; nothing here forwards IPv6 */
      var v6Box = el('div', 'gw-v6');
      v6Box.appendChild(ip6);
      var v6Seen = cmdButton('Use what is seen', 'search', 'small');
      var v6Said = el('div', 'muted small gw-v6-said');
      var v6Chips = el('div', 'gw-v6-chips');
      v6Seen.onclick = function () {
        var m = mac.value.trim();
        if (!m) { v6Said.textContent = 'Its MAC first - the IPv6 addresses are found by it.'; return; }
        busy(v6Seen, true);
        api('gateway', {action: 'v6_seen', mac: m}).then(function (r) {
          v6Said.textContent = r.message || '';
          clear(v6Chips);
          (r.seen || []).forEach(function (a) {
            var stable = /^stable/.test(a.kind || '');
            var c = el('button', 'gw-v6-chip ' + (stable ? 'ok' : 'warn'));
            c.type = 'button';
            c.appendChild(noI18n(el('span', 'mono', a.ip)));
            c.appendChild(el('span', 'small', stable ? 'stable (DHCPv6 or EUI-64)' : 'may be a temporary one'));
            c.title = (a.kind || '') + ' · seen in ' + (a.where || '?') + ' - press to add it';
            c.onclick = function () {
              var have = ip6.value.split(/[\s,]+/).filter(Boolean);
              if (have.indexOf(a.ip) < 0) have.push(a.ip);
              ip6.value = have.join(', ');
              c.classList.add('taken');
            };
            v6Chips.appendChild(c);
          });
        }).catch(oops).then(function () { busy(v6Seen, false); });
      };
      v6Box.appendChild(v6Seen);
      v6Box.appendChild(v6Said);
      v6Box.appendChild(v6Chips);
      grid.appendChild(formField('IPv6 addresses', v6Box, 'Only to find it on the MikroTik (DHCPv6 address) - nothing in this server\'s firewall; IPv6 is never forwarded here. Comma or space between them. Empty: the router\'s IPv6 neighbour table is asked by its MAC - which may give temporary (privacy) addresses.'));
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
          api('gateway', {action: 'device_save', device: {id: x.id || '', name: name.value.trim(), ip: ip.value.trim(), mac: mac.value.trim(),
                                                          ip6: ip6.value.split(/[\s,]+/).filter(Boolean), on: !!on._get()}})
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
  /* Edit a device from elsewhere (1.9.3: Gateway → MikroTik's "Set its DHCPv6 address") - full admins */
  window.GW_EDIT = function (ip) {
    return api('gateway').then(function (d) {
      GW.d = d;
      var x = (d.devices || []).filter(function (y) { return y.ip === ip || y.id === ip; })[0];
      if (!x) { toast(ip + ' is not a device of Gateway for devices', 'bad'); return; }
      deviceEdit(x);
    }).catch(oops);
  };
  function openDesigner(x) { window.GW_DESIGNER(x, GW.d, {saved: quiet}); }

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
  window.gwTrialsLoad = gwTrialsLoad;
  function gwTrialsLoad() {
    if (typeof ME === 'undefined' || !ME) return;
    api('gateway-trial').then(drawTrials).catch(function () {});
  }
  setTimeout(gwTrialsLoad, 1200);
  setInterval(function () { if (!document.hidden) gwTrialsLoad(); }, 10000);
}());
