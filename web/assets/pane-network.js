/* pane-network.js - Settings → UPnP network (1.6.1): where fake-igd listens now - the card of this
   server with its sockets and the description's addresses - every interface of the machine and
   whether it is used, then the settings, the interfaces chosen from a list (as otp's picks). */
(function () {
  'use strict';
  var UN = {d: null};
  function load() {
    api('upnp-here').then(function (d) { UN.d = d; draw(); picks(); }).catch(oops);
  }
  function picks() {
    var d = UN.d;
    if (!d) return;
    var names = (d.kernel || []).map(function (k) { return {name: k.name, ipv4: k.ipv4, up: k.up}; });
    IGDP.ifacePick('interfaces', names, 'none chosen: every interface with IPv4 and multicast');
    IGDP.ifacePick('exclude_interfaces', names, 'none left out');
  }
  function draw(live) {
    var real = $('un-host');
    if (!real || !UN.d) return;
    var P = IGDP;
    P.letGo(real);
    liveFill(real, function (host) {
      var d = UN.d, s = d.service || {};
      var on = s.state === 'active';
      var lis = d.listening || [];
      var ssdp = (d.sockets || []).filter(function (x) { return x.proto === 'udp' && x.port === 1900; });
      var http = (d.sockets || []).filter(function (x) { return x.proto === 'tcp' && x.port === d.http_port; });
      var good = on && lis.length && ssdp.length && http.length;
      var grid = P.grid();
      var c = P.card(d, good ? 'ok' : (on ? 'warn' : (s.state === 'unknown' ? 'dim' : 'bad')),
                     !on ? P.svcWords(s) : (good ? 'listening' : (!lis.length ? 'listening nowhere' : 'a port is not open')),
                     good ? 'ok' : (on ? 'warn' : 'crit'));
      P.big(c, num(lis.length), lis.length === 1 ? 'interface listened on' : 'interfaces listened on');
      var addrs = function (l) { return l.map(function (x) { return (x.addr.indexOf(':') >= 0 ? '[' + x.addr + ']' : x.addr) + ':' + x.port; }).join(', '); };
      c.appendChild(P.facts([
        ['SSDP (udp 1900)', ssdp.length ? addrs(ssdp) : 'nobody listens', true, ssdp.length ? '' : (on ? 'bad' : '')],
        ['Description and SOAP (tcp ' + d.http_port + ')', http.length ? addrs(http) : 'nobody listens', true, http.length ? '' : (on ? 'bad' : '')],
        ['Interfaces chosen', (d.interfaces_set || []).length ? d.interfaces_set.join(', ') : 'every one', true],
        ['Left out', (d.exclude_set || []).length ? d.exclude_set.join(', ') : 'none', true],
        ['Looked at again every', d.rescan_s ? span(d.rescan_s) : ''],
        ['Announced every', d.announce_s ? span(d.announce_s) : ''],
        ['Running since', d.started ? stamp(d.started) : (s.since || '')],
        ['Read', ago(d.at)]
      ]));
      if (lis.length) {
        c.appendChild(listTable(['Interface', 'Address', 'The description'], lis, function (x) {
          var tr = el('tr');
          tr.appendChild(noI18n(el('td', 'mono', x.name)));
          tr.appendChild(noI18n(el('td', 'mono', x.ipv4)));
          var td = el('td');
          td.appendChild(noI18n(el('span', 'mono small', x.url)));
          var cp = iconButton('copy', 'Copy the address');
          cp.onclick = function () { copyText(x.url, cp, 'copied'); };
          td.appendChild(cp);
          tr.appendChild(td);
          return tr;
        }, 'plain'));
      }
      (d.said || []).slice(-3).forEach(function (w) {
        c.appendChild(noI18n(el('div', 'si-said small', (w.at ? ago(w.at) + ': ' : '') + w.words)));
      });
      var row = el('div', 'btnrow');
      var re = cmdButton('Read it again', 'refresh', 'small');
      re.onclick = function () { busy(re, true); api('upnp-here').then(function (x) { UN.d = x; draw(); drawIfaces(); }).catch(oops).then(function () { busy(re, false); }); };
      row.appendChild(re);
      c.appendChild(row);
      grid.appendChild(c);
      host.appendChild(grid);
      if (on && !lis.length) host.appendChild(el('p', 'note bad', 'fake-igd.service runs, but listens on no interface: none chosen has IPv4 and multicast (look at the interfaces below).'));
    }, live, function () { explainWhatWasDrawn(real); });
    drawIfaces();
  }
  function drawIfaces() {
    var d = UN.d, host = $('un-ifaces');
    if (!host || !d) return;
    var rows = d.kernel || [];
    var used = rows.filter(function (r) { return r.used; }).length;
    $('un-said').textContent = num(rows.length) + ' interface(s), ' + num(used) + ' used';
    var lis = {};
    (d.listening || []).forEach(function (x) { lis[x.name] = x; });
    clear(host);
    host.appendChild(listTable(['Interface', 'IPv4 address', 'State', 'MAC', 'fake-igd'], rows, function (r) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', r.name)));
      tr.appendChild(noI18n(el('td', 'mono', r.ipv4 ? r.ipv4 + (r.prefix !== null && r.prefix !== undefined ? '/' + r.prefix : '') : '–')));
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (r.up ? 'ok' : 'dim'), r.up ? 'up' : 'down'));
      if (r.loopback) { st.appendChild(document.createTextNode(' ')); st.appendChild(el('span', 'tag dim', 'loopback')); }
      tr.appendChild(st);
      tr.appendChild(noI18n(el('td', 'mono muted small', r.mac || '')));
      var u = el('td');
      if (r.used) u.appendChild(el('span', 'tag ' + (lis[r.name] || (d.service || {}).state !== 'active' ? 'ok' : 'warn'), lis[r.name] || (d.service || {}).state !== 'active' ? 'listens' : 'chosen - not yet listening'));
      else u.appendChild(el('span', 'tag dim', 'not used: ' + r.why));
      tr.appendChild(u);
      return tr;
    }, 'plain|The kernel shows no interface', {own: true}));
  }
  PANE_LOAD.network = load;
  PANE_TICK.network = function () {
    api('upnp-here').then(function (d) { UN.d = d; draw(true); }).catch(function () {});
  };
})();
