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
        var pick = devs.filter(function (x) { return d.job && x.dev === d.job.dev; })[0] ||
                   devs.filter(function (x) { return x.dev === d.now.page_dev; })[0] ||
                   devs.filter(function (x) { return x.default; })[0] || devs[0] || {};
        NET.dev = pick.dev || '';
      }
      drawNet();
      netPollFor();
      trialsLoad();
    }).catch(oops);
  }
  function jobActive(j) { return j && j.state === 'asked'; }
  function onTrial(d) { return d && d.trial && d.trial.state === 'trial'; }
  function netPollFor() {
    var live = NET.d && (jobActive(NET.d.job) || onTrial(NET.d));
    if ((live || NET.watch) && !NET.poll) NET.poll = setInterval(netPoll, 2000);
    if (!live && !NET.watch && NET.poll) { clearInterval(NET.poll); NET.poll = null; }
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
      trialsLoad();
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
      /* While a change is under way its interface is the one shown, as otp shows the node changed. */
      if (jobActive(d.job) && d.job.dev && devOf(d.job.dev)) NET.dev = d.job.dev;
      if (devs.length > 1) {
        var seg = el('div', 'seg net-nodes');
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
      /* otp's order: the interfaces, then the change under way, then As it is now. On trial: in the
         banner on every page (#trials), as otp's - not a card here. */
      if (d.job && d.job.state) host.appendChild(progressCard(d.job));
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
  /* NetworkManager's ipv6.method, every one - in otp's words where otp has them. */
  var V6 = [['auto', 'automatic (SLAAC / DHCPv6)'], ['dhcp', 'DHCPv6 only'], ['manual', 'set by hand'],
            ['link-local', 'link-local only'], ['ignore', 'ignore (NetworkManager leaves IPv6 alone)'], ['disabled', 'off']];
  function v6words(m) {
    if (!m) return '–';
    var w = V6.filter(function (x) { return x[0] === m; })[0];
    return m === 'disabled' ? 'off' : (w ? (m === 'ignore' ? w[1] : 'on, ' + w[1]) : m);
  }
  /* Every IPv6 address the interface has, its link-local one (fe80::/64, scope link) marked. */
  function v6list(n) {
    return (n.addrs6 || []).concat((n.addrs6_ll || []).map(function (a) { return a + ' (link-local)'; })).join(', ');
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
    if (!n) {
      card.appendChild(netFacts([['Host name', d.now.hostname || '', true], ['Read', d.now.read_at ? ago(d.now.read_at) : '']]));
      card.appendChild(el('p', 'note', 'No interface found' + (d.now.nm ? ' - NetworkManager says none.' : '.')));
      if (!d.now.nm) card.appendChild(el('p', 'note warn', 'NetworkManager (nmcli) is not on this machine: its network can only be set by hand' + (d.now.nm_said ? ' (' + d.now.nm_said + ')' : '') + '.'));
      return card;
    }
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
      ['IPv6 addresses', v6list(n), true],
      ['MAC address', n.mac || '', true],
      ['fake-igd answers on it', n.answers ? 'yes (SSDP and SOAP)' : 'no - left out in its settings'],
      ['Read', d.now.read_at ? ago(d.now.read_at) : '']
    ]));
    if (n.dev === d.now.page_dev) card.appendChild(el('p', 'note warn', 'These pages are reached through ' + n.dev + ': a new address here moves them with it.'));
    if (n.said) card.appendChild(el('p', 'note bad', n.said));
    if (!d.now.nm) card.appendChild(el('p', 'note warn', 'NetworkManager (nmcli) is not on this machine: its network can only be set by hand' + (d.now.nm_said ? ' (' + d.now.nm_said + ')' : '') + '.'));
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
    card.appendChild(el('h2', '', 'New settings for ' + (n ? n.dev : (d.now.hostname || 'this machine'))));
    if (!n && d.now.nm) { card.appendChild(el('p', 'note', 'No interface to set.')); return card; }
    var conf = (n && n.conf) || {};
    if (!d.now.nm) { card.appendChild(el('p', 'note', 'Nothing can be set from here without NetworkManager.')); return card; }
    if (!n.con) { card.appendChild(el('p', 'note', n.dev + ' has no NetworkManager connection: make one at the console (nmtui) first.')); return card; }
    /* The form starts from what NetworkManager has for the connection now - never from defaults. */
    var m6was = conf.ipv6_method || 'auto';
    var on6was = m6was !== 'disabled' && m6was !== 'ignore';
    var host = textBox(d.now.hostname || '', 'igd.example.com', 'mono');
    var m4opts = [['manual', 'set by hand'], ['auto', 'automatic (DHCP)']];
    if (conf.ipv4_method && conf.ipv4_method !== 'manual' && conf.ipv4_method !== 'auto') m4opts.push([conf.ipv4_method, conf.ipv4_method + ' (as it is - set it here by hand or by DHCP)']);
    var m4 = selectBox(m4opts, conf.ipv4_method || 'manual');
    var a4Was = (conf.ipv4_addresses || [])[0] || (n.addrs4 || [])[0] || '';
    var a4 = textBox(a4Was, '192.0.2.10/24', 'mono');
    var gw = textBox(conf.ipv4_gateway || (d.now.gw4_dev === n.dev ? d.now.gw4 : ''), '192.0.2.1', 'mono');
    var dns = textBox((conf.ipv4_dns || []).filter(function (x) { return x.indexOf(':') < 0; }).join(', '), '192.0.2.53, 192.0.2.54', 'mono');
    var search = textBox((conf.ipv4_search || []).join(', '), 'example.com', 'mono');
    var s6 = switchBox(on6was);
    var v6opts = V6.slice();
    if (!V6.some(function (x) { return x[0] === m6was; })) v6opts.push([m6was, m6was + ' (as it is)']);
    var mode6 = selectBox(v6opts, m6was);
    var a6 = textBox((conf.ipv6_addresses || [])[0] || '', '2001:db8::10/64', 'mono');
    var gw6 = textBox(conf.ipv6_gateway || '', '2001:db8::1', 'mono');
    var dns6 = textBox((conf.ipv6_dns || []).join(', '), '2001:db8::53', 'mono');
    /* The switch and How say the same: off is "disabled" (or "ignore", as it was found). */
    s6._input.addEventListener('change', function () {
      if (!s6._get()) mode6.value = m6was === 'ignore' ? 'ignore' : 'disabled';
      else if (mode6.value === 'disabled' || mode6.value === 'ignore') mode6.value = on6was ? m6was : 'auto';
    });
    mode6.addEventListener('change', function () {
      s6._input.checked = mode6.value !== 'disabled' && mode6.value !== 'ignore';
    });
    var g1 = el('div', 'formgrid');
    g1.appendChild(formField('Host name (FQDN)', host, 'The machine\'s whole name - one for the machine, whichever interface is changed.'));
    card.appendChild(g1);
    var s1 = msect('IPv4', '');
    /* IPv4 and IPv6 in one grid of five columns: each field under its fellow of the other family -
       How under How, the address under the address - and in its column also while others are hidden. */
    var col = function (item, i) { item.classList.add('nc' + i); return item; };
    var g2 = el('div', 'formgrid net-grid');
    g2.appendChild(col(formField('How', m4, 'Automatic: the address, gateway and - unless set below - DNS servers come from a DHCP server.'), 1));
    g2.appendChild(col(formField('Address with its prefix', a4, 'e.g. 192.0.2.10/24 - /24 is the mask 255.255.255.0.'), 2));
    g2.appendChild(col(formField('Gateway', gw, 'Empty: none on this interface (the machine\'s default route is on another one).'), 3));
    g2.appendChild(col(formField('DNS servers', dns, 'Separated by commas.'), 4));
    g2.appendChild(col(formField('Search domains', search), 5));
    s1._body.appendChild(g2);
    card.appendChild(s1);
    var s2 = msect('IPv6 (dual stack)', 'Switched on, the interface takes IPv6 beside IPv4. fake-igd itself answers the PS5 over IPv4 (SSDP and SOAP); the pages answer over both where nginx listens on IPv6.');
    var r6 = el('div', 'formgrid');
    r6.appendChild(formField('IPv6', s6));
    var g6 = el('div', 'formgrid net-grid');
    g6.appendChild(col(formField('How', mode6), 1));
    g6.appendChild(col(formField('Address with its prefix', a6, 'e.g. 2001:db8::10/64'), 2));
    g6.appendChild(col(formField('Gateway', gw6), 3));
    g6.appendChild(col(formField('DNS servers', dns6), 4));
    s2._body.appendChild(r6);
    s2._body.appendChild(g6);
    card.appendChild(s2);
    var paint = function () {
      var manual4 = m4.value === 'manual';
      a4.closest('.set-item').hidden = !manual4;
      gw.closest('.set-item').hidden = !manual4;
      var on6 = mode6.value !== 'disabled' && mode6.value !== 'ignore';
      var manual = mode6.value === 'manual';
      a6.closest('.set-item').hidden = !manual;
      gw6.closest('.set-item').hidden = !manual;
      dns6.closest('.set-item').hidden = !on6 || mode6.value === 'link-local';
    };
    s6._input.addEventListener('change', paint);
    mode6.addEventListener('change', paint);
    m4.addEventListener('change', paint);
    /* The interface these pages are reached by (or the one fake-igd answers the PS5 on): said
       before anything is pressed, the same as otp's note on the VIP address's network. */
    var words = [];
    if (n.dev === d.now.page_dev) words.push('These pages are reached through ' + n.dev + ': a new address or DHCP here moves them - the page follows the new address, you sign in there again and press Keep it within ' + d.trial_min + ' min, or it goes back by itself.');
    if (n.answers) words.push('fake-igd answers the PS5 on ' + n.dev + ': it takes the new address by itself within a minute; a PS5 that has the old one asks again.');
    /* otp's p.note.warn, in the card's own rhythm: as wide as the sections above it, 14 px from them. */
    if (words.length) card.appendChild(el('p', 'note warn net-warn', words.join(' ')));
    if (!d.trial_min) card.appendChild(el('p', 'note bad net-warn', 'Taken back unless kept is 0: a change is kept at once - a typo in the gateway or the prefix can leave this machine unreachable.'));
    var want = function () {
      return {dev: n.dev, hostname: host.value.trim(),
              ipv4: {method: m4.value, addr: a4.value.trim(), gw: gw.value.trim(), dns: dns.value, search: search.value},
              ipv6: {method: mode6.value, addr: a6.value.trim(), gw: gw6.value.trim(), dns: dns6.value}};
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
      var row = el('div', 'actions hide-row');
      row.appendChild(hideButton(function () {
        return api('net', {action: 'hide'}).then(function (x) { NET.d = x; drawNet(); });
      }));
      row.appendChild(el('span', 'muted small', 'Hidden by itself 6 hours after it was done.'));
      card.appendChild(row);
    }
    return card;
  }
  /* A new network on trial (otp's drawTrials, kind "net"): in the banner on every page, #trials,
     beside the firewall's - with the time left counting down, Keep it and Put the old back now. */
  var NT = {list: [], skew: 0, timer: null};
  function ntHost() {
    var host = $('trials-net');
    if (host) return host;
    var all = $('trials');
    if (!all) {
      all = el('div', 'trials');
      all.id = 'trials';
      var pr = $('problems');
      if (pr && pr.parentNode) pr.parentNode.insertBefore(all, pr.nextSibling);
      else document.body.insertBefore(all, document.body.firstChild);
    }
    host = el('div', 'trials');
    host.id = 'trials-net';
    host.style.margin = '0';
    all.appendChild(host);
    return host;
  }
  function drawTrial(d) {
    NT.list = (d && d.trials) || [];
    NT.skew = d && d.now ? d.now - Date.now() / 1000 : 0;
    var host = ntHost(), all = $('trials');
    if (!NT.list.length) {
      host.hidden = true; clear(host);
      if (all) all.hidden = !Array.prototype.some.call(all.children, function (c) { return !c.hidden; });
      if (NT.timer) { clearInterval(NT.timer); NT.timer = null; }
      return;
    }
    host.hidden = false;
    if (all) all.hidden = false;
    liveFill(host, function (host) {
      NT.list.forEach(function (t) {
        var row = el('div', 'trial');
        var words = el('div', 'trial-words');
        words.appendChild(el('b', '', 'The new network of ' + (t.dev || t.con || '?') + ' waits to be kept'));
        var left = el('span', 'trial-left mono');
        left.dataset.until = t.until;
        words.appendChild(document.createTextNode(' - '));
        words.appendChild(left);
        words.appendChild(el('div', 'small', 'Not kept, ' + (t.dev || t.con || 'the interface') + ' goes back to its old network by itself. Keep it once you have checked that the pages and fake-igd answer at the new address.'));
        if (t.failed) words.appendChild(el('div', 'small bad', t.failed));
        row.appendChild(words);
        var tools = el('div', 'trial-tools');
        if (ADMIN) {
          var keep = cmdButton('Keep it', 'check', 'small primary');
          keep.onclick = function () { trialDo('keep', keep); };
          var back = cmdButton('Put the old back now', 'undo', 'small danger');
          back.onclick = function () {
            confirmThen('Put the old back now?', htmlText(t.dev || t.con || 'The interface') + ' goes back to its old network.', 'Put it back', function () { trialDo('back', back); });
          };
          tools.appendChild(keep);
          tools.appendChild(back);
        }
        row.appendChild(tools);
        host.appendChild(row);
      });
    }, true);
    trialCount();
    if (!NT.timer) NT.timer = setInterval(trialCount, 1000);
  }
  function trialCount() {
    var now = Date.now() / 1000 + NT.skew;
    document.querySelectorAll('#trials-net .trial-left').forEach(function (x) {
      var left = parseFloat(x.dataset.until) - now;
      x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) + ' left' : 'going back now';
    });
  }
  function trialsLoad() {
    if (typeof ME === 'undefined' || !ME) return;
    api('net-trial').then(drawTrial).catch(function () {});
  }
  function trialDo(action, button) {
    busy(button, true);
    api('net', {action: action}).then(function (r) {
      toast(r.message, 'good');
      NET.watch = true;
      setTimeout(trialsLoad, 1500);
      setTimeout(trialsLoad, 4000);
      if (TAB === 'settings' && PANE === 'net') setTimeout(loadNet, 1500);
    }).catch(oops).then(function () { busy(button, false); });
  }
  trialsLoad();
  setInterval(function () { if (!document.hidden) trialsLoad(); }, 10000);
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
