/* Settings → Network (1.6.0) - otp's loadNet/drawNet for one server: each interface of this
   machine as NetworkManager has it, a form for the new settings, the change followed and on
   trial until kept. */
(function () {
  'use strict';
  var NET = {d: null, dev: '', poll: null, fails: 0, failSince: 0, watch: false, target: null, redirect: null, tick: null};

  function q() { return 'net&host=' + encodeURIComponent(location.hostname); }

  function loadNet() {
    api(q()).then(function (d) {
      NET.d = d; NET.fails = 0; NET.failSince = 0;
      var devs = d.now.devices || [];
      if (!NET.dev || !devs.some(function (x) { return x.dev === NET.dev; })) {
        var pick = devs.filter(function (x) { return x.dev === d.now.page_dev; })[0] ||
                   devs.filter(function (x) { return x.default; })[0] || devs[0] || {};
        NET.dev = pick.dev || '';
      }
      drawNet();
      netPollFor();
    }).catch(oops);
  }
  function jobActive(j) { return j && j.state === 'asked'; }
  function onTrial(d) { return d && d.trial && d.trial.state === 'trial'; }
  function netPollFor() {
    var live = NET.d && (jobActive(NET.d.job) || onTrial(NET.d));
    if ((live || NET.watch) && !NET.poll) NET.poll = setInterval(netPoll, 2000);
    if (!live && !NET.watch && NET.poll) { clearInterval(NET.poll); NET.poll = null; }
    if (onTrial(NET.d) && !NET.tick) NET.tick = setInterval(trialCount, 1000);
    if (!onTrial(NET.d) && NET.tick) { clearInterval(NET.tick); NET.tick = null; }
  }
  function netPoll() {
    if (TAB !== 'settings' || PANE !== 'net') { clearInterval(NET.poll); NET.poll = null; return; }
    api(q()).then(function (d) {
      var was = NET.d;
      NET.d = d; NET.fails = 0; NET.failSince = 0;
      if (NET.watch && d.job && ['done', 'failed'].indexOf(d.job.state) >= 0) {
        toast(d.job.state === 'done' ? 'the network of ' + d.job.dev + ' is changed' : 'the network of ' + d.job.dev + ' was not changed',
              d.job.state === 'done' ? 'good' : 'bad');
        NET.watch = false;
      }
      if (onTrial(was) && !onTrial(d) && d.trial && d.trial.state) {
        toast(d.trial.state === 'kept' ? 'kept: the new network stays' : 'the old network is back', d.trial.state === 'kept' ? 'good' : 'bad');
      }
      drawNet(true);
      netPollFor();
    }).catch(function () {
      /* The page's own interface changed: it does not answer here for a while. */
      NET.fails += 1;
      if (!NET.failSince) NET.failSince = Date.now();
      drawNetAway();
    });
  }
  function devOf(name) { return ((NET.d && NET.d.now.devices) || []).filter(function (x) { return x.dev === name; })[0]; }

  function drawNet(live) {
    var real = $('net-host');
    if (!real || !NET.d) return;
    liveFill(real, function (host) {
      var d = NET.d;
      var devs = d.now.devices || [];
      if (onTrial(d)) host.appendChild(trialCard(d));
      if (d.job && d.job.state) host.appendChild(progressCard(d.job));
      if (!d.now.nm) {
        var c0 = el('div', 'card full');
        c0.appendChild(el('p', 'note warn', 'NetworkManager (nmcli) is not on this machine: its network can only be set by hand' + (d.now.nm_said ? ' (' + d.now.nm_said + ')' : '') + '.'));
        host.appendChild(c0);
      }
      if (devs.length) {
        var seg = el('div', 'seg net-nodes');
        seg.style.marginBottom = '14px';
        devs.forEach(function (x) {
          var b = el('button', x.dev === NET.dev ? 'on' : '');
          b.type = 'button';
          b.appendChild(el('span', 'dot ' + (/^connected/.test(x.state) ? 'ok' : 'bad')));
          b.appendChild(noI18n(el('span', '', ' ' + x.dev)));
          if (x.dev === d.now.page_dev) b.appendChild(el('span', 'tag info', 'this page'));
          b.onclick = function () { NET.dev = x.dev; drawNet(); };
          seg.appendChild(b);
        });
        host.appendChild(seg);
      }
      var n = devOf(NET.dev);
      if (!n) {
        if (!devs.length) host.appendChild(el('p', 'note', 'No interface found - NetworkManager says none.'));
        return;
      }
      host.appendChild(nowCard(n));
      if (!jobActive(d.job) && !onTrial(d)) host.appendChild(formCard(n));
    }, live, function () { explainWhatWasDrawn(real); });
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
  function v6words(m) {
    return m === 'disabled' || m === 'ignore' || !m ? 'off' : (m === 'manual' ? 'on, set by hand' : 'on, automatic');
  }
  function nowCard(n) {
    var d = NET.d;
    var card = el('div', 'card full');
    var h = el('h2', '', 'As it is now');
    var right = el('span', 'right');
    var re = cmdButton('Read it again', 'refresh', 'small');
    re.onclick = function () {
      busy(re, true);
      api('net', {action: 'read', host: location.hostname}).then(function (x) { NET.d = x; drawNet(); toast('read', 'good'); })
        .catch(oops).then(function () { busy(re, false); });
    };
    right.appendChild(re);
    h.appendChild(right);
    card.appendChild(h);
    var conf = n.conf || {};
    card.appendChild(netFacts([
      ['Host name', d.now.hostname || '', true],
      ['Connection', (n.con || 'none') + ' (' + n.dev + (n.type ? ', ' + n.type : '') + ')', true],
      ['State', n.state || ''],
      ['IPv4', conf.ipv4_method === 'auto' ? 'automatic (DHCP)' : (conf.ipv4_method === 'manual' ? 'set by hand' : (conf.ipv4_method === 'disabled' ? 'off' : (conf.ipv4_method || '')))],
      ['IPv4 address', (conf.ipv4_method === 'manual' ? (conf.ipv4_addresses || []) : (n.addrs4 || [])).join(', ') || (n.addrs4 || []).join(', '), true],
      ['Gateway', conf.ipv4_gateway || (d.now.gw4_dev === n.dev ? d.now.gw4 : ''), true],
      ['DNS servers', ((conf.ipv4_dns || []).concat(conf.ipv6_dns || [])).join(', ') || (n.default ? (d.now.dns || []).join(', ') : ''), true],
      ['Search domains', (conf.ipv4_search || []).join(', '), true],
      ['IPv6', v6words(conf.ipv6_method)],
      ['IPv6 addresses', (n.addrs6 || []).join(', '), true],
      ['MAC address', n.mac || '', true],
      ['fake-igd answers on it', n.answers ? 'yes (SSDP and SOAP)' : 'no - left out in its settings'],
      ['Read', d.now.read_at ? ago(d.now.read_at) : '']
    ]));
    if (n.dev === d.now.page_dev) card.appendChild(el('p', 'note warn', 'These pages are reached through ' + n.dev + ': a new address here moves them with it.'));
    if (n.said) card.appendChild(el('p', 'note bad', n.said));
    return card;
  }
  function msect(title, lede) {
    var box = el('section', 'msect');
    box.appendChild(el('h4', '', title));
    if (lede) box.appendChild(el('p', 'msect-lede', lede));
    var body = el('div', 'msect-body');
    box.appendChild(body);
    box._body = body;
    return box;
  }
  function formCard(n) {
    var d = NET.d;
    var card = el('div', 'card full');
    card.appendChild(el('h2', '', 'New settings for ' + n.dev));
    var conf = n.conf || {};
    if (!d.now.nm) { card.appendChild(el('p', 'note', 'Nothing can be set from here without NetworkManager.')); return card; }
    if (!n.con) { card.appendChild(el('p', 'note', n.dev + ' has no NetworkManager connection: make one at the console (nmtui) first.')); return card; }
    var on6was = !(conf.ipv6_method === 'disabled' || conf.ipv6_method === 'ignore' || !conf.ipv6_method);
    var host = textBox(d.now.hostname || '', 'igd.example.com', 'mono');
    var m4 = selectBox([['manual', 'set by hand'], ['auto', 'automatic (DHCP)']], conf.ipv4_method === 'auto' ? 'auto' : 'manual');
    var a4Was = (conf.ipv4_addresses || [])[0] || (n.addrs4 || [])[0] || '';
    var a4 = textBox(a4Was, '192.0.2.10/24', 'mono');
    var gw = textBox(conf.ipv4_gateway || (d.now.gw4_dev === n.dev ? d.now.gw4 : ''), '192.0.2.1', 'mono');
    var dns = textBox((conf.ipv4_dns || []).filter(function (x) { return x.indexOf(':') < 0; }).join(', '), '192.0.2.53, 192.0.2.54', 'mono');
    var search = textBox((conf.ipv4_search || []).join(', '), 'example.com', 'mono');
    var s6 = switchBox(on6was);
    var mode6 = selectBox([['manual', 'set by hand'], ['auto', 'automatic (SLAAC / DHCPv6)']], conf.ipv6_method === 'auto' ? 'auto' : 'manual');
    var a6 = textBox((conf.ipv6_addresses || [])[0] || '', '2001:db8::10/64', 'mono');
    var gw6 = textBox(conf.ipv6_gateway || '', '2001:db8::1', 'mono');
    var dns6 = textBox((conf.ipv6_dns || []).join(', '), '2001:db8::53', 'mono');
    var g1 = el('div', 'formgrid');
    g1.appendChild(formField('Host name (FQDN)', host, 'The machine\'s whole name - one for the machine, whichever interface is changed.'));
    card.appendChild(g1);
    var s1 = msect('IPv4', '');
    var g2 = el('div', 'formgrid');
    g2.appendChild(formField('How', m4, 'Automatic: the address, gateway and - unless set below - DNS servers come from a DHCP server.'));
    g2.appendChild(formField('Address with its prefix', a4, 'e.g. 192.0.2.10/24 - /24 is the mask 255.255.255.0.'));
    g2.appendChild(formField('Gateway', gw, 'Empty: none on this interface (the machine\'s default route is on another one).'));
    g2.appendChild(formField('DNS servers', dns, 'Separated by commas.'));
    g2.appendChild(formField('Search domains', search));
    s1._body.appendChild(g2);
    card.appendChild(s1);
    var s2 = msect('IPv6 (dual stack)', 'Switched on, the interface takes IPv6 beside IPv4. fake-igd itself answers the PS5 over IPv4 (SSDP and SOAP); the pages answer over both where nginx listens on IPv6.');
    var r6 = el('div', 'formgrid');
    r6.appendChild(formField('IPv6', s6));
    var g6 = el('div', 'formgrid');
    g6.appendChild(formField('How', mode6));
    g6.appendChild(formField('Address with its prefix', a6, 'e.g. 2001:db8::10/64'));
    g6.appendChild(formField('Gateway', gw6));
    g6.appendChild(formField('DNS servers', dns6));
    s2._body.appendChild(r6);
    s2._body.appendChild(g6);
    card.appendChild(s2);
    var paint = function () {
      var manual4 = m4.value === 'manual';
      a4.closest('.set-item').hidden = !manual4;
      gw.closest('.set-item').hidden = !manual4;
      g6.hidden = !s6._get();
      var manual = mode6.value === 'manual';
      a6.closest('.set-item').hidden = !manual;
      gw6.closest('.set-item').hidden = !manual;
    };
    s6._input.addEventListener('change', paint);
    mode6.addEventListener('change', paint);
    m4.addEventListener('change', paint);
    /* The interface these pages are reached by (or the one fake-igd answers the PS5 on): said
       before anything is pressed, the same as otp's note on the VIP address's network. */
    var warn = el('div', 'note warn net-elsewhere');
    var words = [];
    if (n.dev === d.now.page_dev) words.push('These pages are reached through ' + n.dev + ': a new address or DHCP here moves them - the page follows the new address, you sign in there again and press Keep it within ' + d.trial_min + ' min, or it goes back by itself.');
    if (n.answers) words.push('fake-igd answers the PS5 on ' + n.dev + ': it takes the new address by itself within a minute; a PS5 that has the old one asks again.');
    warn.appendChild(el('div', 'small', words.join(' ')));
    warn.hidden = !words.length;
    card.appendChild(warn);
    if (!d.trial_min) card.appendChild(el('p', 'note bad', 'Taken back unless kept is 0: a change is kept at once - a typo in the gateway or the prefix can leave this machine unreachable.'));
    var want = function () {
      return {dev: n.dev, hostname: host.value.trim(),
              ipv4: {method: m4.value, addr: a4.value.trim(), gw: gw.value.trim(), dns: dns.value, search: search.value},
              ipv6: {on: !!s6._get(), mode: mode6.value, addr: a6.value.trim(), gw: gw6.value.trim(), dns: dns6.value}};
    };
    var planBox = el('div', 'net-plan');
    var row = el('div', 'btnrow');
    row.style.marginTop = '14px';
    var check = cmdButton('Check it', 'check', '');
    var go = cmdButton('Change it on trial', 'ethernet', 'primary');
    check.onclick = function () {
      busy(check, true);
      api('net', {action: 'plan', want: want(), host: location.hostname}).then(function (x) {
        clear(planBox);
        planBox.appendChild(el('h4', '', 'What happens'));
        var ol = el('ol', 'net-steps');
        x.plan.forEach(function (p) { ol.appendChild(el('li', '', p)); });
        planBox.appendChild(ol);
      }).catch(function (e) { clear(planBox); planBox.appendChild(el('p', 'note bad', String(e.message || e))); })
        .then(function () { busy(check, false); });
    };
    go.onclick = function () {
      var w = want();
      api('net', {action: 'plan', want: w, host: location.hostname}).then(function (x) {
        var html = '<ol class="net-steps">' + x.plan.map(function (p) { return '<li>' + htmlText(p) + '</li>'; }).join('') + '</ol>'
          + (x.want.page && x.want.changed_ip ? '<p class="note">' + htmlText('The page loses this server for a few seconds; it follows it to its new address.') + '</p>' : '');
        confirmThen('Change the network of ' + n.dev + '?', html, 'Change it', function () {
          api('net', {action: 'apply', want: w, host: location.hostname}).then(function (r) {
            toast(r.message, 'good');
            NET.watch = true;
            NET.target = {old: (a4Was || '').split('/')[0], ip: x.want.new_ip, host: x.want.hostname, oldHost: d.now.hostname || '', page: x.want.page};
            loadNet();
          }).catch(oops);
        });
      }).catch(oops);
    };
    row.appendChild(check);
    row.appendChild(go);
    card.appendChild(row);
    card.appendChild(planBox);
    setTimeout(paint, 0);
    return card;
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
  function progressCard(j) {
    var card = el('div', 'card full net-job ' + (j.state || ''));
    card.appendChild(el('h2', '', j.state === 'done' ? 'The network of ' + j.dev + ' is changed'
      : (j.state === 'failed' ? 'The network of ' + j.dev + ' was not changed' : 'Changing the network of ' + j.dev)));
    var bar = el('div', 'going wide');
    bar.innerHTML = '<div class="bar"><span></span></div>';
    bar.querySelector('span').style.width = (j.state === 'asked' ? 40 : 100) + '%';
    if (j.state === 'asked') bar.querySelector('span').classList.add('creeping');
    card.appendChild(bar);
    var ol = el('ol', 'net-steps done');
    if (j.state === 'asked') {
      var li0 = el('li', '');
      li0.appendChild(el('span', 'mark', '…'));
      li0.appendChild(el('span', '', 'asked of root ' + ago(j.at) + ' by ' + (j.by || '?')));
      ol.appendChild(li0);
    }
    (j.said || []).forEach(function (s) {
      var li = el('li', j.state === 'failed' ? 'bad' : 'good');
      li.appendChild(el('span', 'mark', j.state === 'failed' ? '✗' : '✓'));
      li.appendChild(el('span', '', s));
      ol.appendChild(li);
    });
    card.appendChild(ol);
    if (j.state === 'done' || j.state === 'failed') {
      var row = el('div', 'actions');
      row.appendChild(hideButton(function () {
        return api('net', {action: 'hide'}).then(function (x) { NET.d = x; drawNet(); });
      }));
      row.appendChild(el('span', 'muted small', 'Hidden by itself 6 hours after it was done.'));
      card.appendChild(row);
    }
    return card;
  }
  function trialCard(d) {
    var t = d.trial;
    var tc = el('div', 'card full notice warn sd-trial');
    tc.appendChild(el('h2', '', 'On trial - keep it, or it goes back'));
    var p = el('p', 'note');
    p.appendChild(document.createTextNode('The new network of ' + (t.con || '?') + ' waits to be kept - '));
    var left = noI18n(el('span', 'trial-left mono', ''));
    left.dataset.until = t.until;
    p.appendChild(left);
    tc.appendChild(p);
    tc.appendChild(el('p', 'note', 'Not kept, the connection goes back to exactly what it had by itself. Keep it once you have checked that the pages and fake-igd answer at the new address.'));
    if (t.failed) tc.appendChild(el('p', 'note bad', t.failed));
    var row = el('div', 'btnrow');
    var kp = cmdButton('Keep it', 'check', 'primary');
    kp.onclick = function () { trialDo('keep', kp); };
    var bk = cmdButton('Put the old back now', 'undo', 'danger');
    bk.onclick = function () {
      confirmThen('Put the old back now?', htmlText((t.con || 'The connection') + ' goes back to its old network at once.'), 'Put it back', function () { trialDo('back', bk); }, true);
    };
    row.appendChild(kp); row.appendChild(bk);
    tc.appendChild(row);
    setTimeout(trialCount, 0);
    return tc;
  }
  function trialCount() {
    var skew = NET.d ? NET.d.server_now - NET.d.at : 0;
    var now = Date.now() / 1000 + skew;
    document.querySelectorAll('#net-host .trial-left').forEach(function (x) {
      var left = parseFloat(x.dataset.until) - now;
      x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) + ' left' : 'going back now';
    });
  }
  function trialDo(action, button) {
    busy(button, true);
    api('net', {action: action}).then(function (r) {
      toast(r.message, 'good');
      NET.watch = true;
      setTimeout(loadNet, 1500);
    }).catch(oops).then(function () { busy(button, false); });
  }
  function drawNetAway() {
    /* The page's server does not answer at this address: the interface it is reached by changed.
       Counted, and taken to the new address when it changed. */
    var host = $('net-host');
    if (!host) return;
    var t = NET.target || {};
    var away = Math.round((Date.now() - NET.failSince) / 1000);
    var box = $('net-away');
    if (!box) {
      box = el('div', 'card full net-job');
      box.id = 'net-away';
      host.insertBefore(box, host.firstChild);
    }
    clear(box);
    box.appendChild(el('h2', '', 'This page\'s server does not answer here'));
    var bar = el('div', 'going wide');
    bar.innerHTML = '<div class="bar"><span></span></div>';
    bar.querySelector('span').style.width = Math.min(100, Math.round(away / 30 * 100)) + '%';
    box.appendChild(bar);
    box.appendChild(el('p', 'note', 'Not answering for ' + span(away) + '. The page asks again every two seconds.'));
    var newHost = '';
    if (t.page && t.ip && t.old && t.ip !== t.old && location.hostname === t.old) newHost = t.ip;
    if (t.page && t.host && t.oldHost && t.host !== t.oldHost && location.hostname.toLowerCase() === t.oldHost.toLowerCase()) newHost = t.host;
    if (newHost) {
      var url = location.protocol + '//' + (newHost.indexOf(':') >= 0 ? '[' + newHost + ']' : newHost) + (location.port ? ':' + location.port : '') + '/admin/#settings/net';
      var p = el('p', 'note');
      p.appendChild(document.createTextNode('It answers at its new address: '));
      var a = noI18n(el('a', 'mono', url)); a.href = url;
      p.appendChild(a);
      p.appendChild(document.createTextNode(' - sign in there and press Keep it.'));
      box.appendChild(p);
      if (away > 20 && !NET.redirect) { NET.redirect = setTimeout(function () { location.href = url; }, 500); }
    }
  }

  PANE_LOAD.net = loadNet;
}());
