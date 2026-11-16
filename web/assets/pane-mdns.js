/* pane-mdns.js - Settings → mdns (moved out of admin.js, 1.6.1). */
'use strict';

/* ==========================================================================
   mDNS - the reflector (avahi-daemon): the tab, and its settings pane
   ========================================================================== */
var AV = {d: null, svc: null, busy: false};
function avahiSetting(k) {
  return {key: 'avahi:' + k.key, name: k.name, says: k.says, value: k.value, default: k.default,
          bool: k.bool, source: k.source, source_says: k.source_says, secret: false,
          list: k.kind === 'ifaces' || k.kind === 'list', restarts: false, root: true};
}
/* The reflector at a glance, as otp's tiles over a list (Enrolment): in the one held card. */
function paintMdnsCards(d) {
  var host = $('ms-tiles');
  clear(host);
  if (!d.installed) {
    host.appendChild(peekFacts([['avahi-daemon', 'not installed'], ['What to do', d.error || 'dnf install avahi avahi-tools']]));
    return;
  }
  var svc = AV.svc ? AV.svc.services : null, types = {};
  (svc || []).forEach(function (s) { types[s.type] = 1; });
  var tiles = peekFacts([
    ['avahi-daemon', d.service.state === 'active' ? 'running' + (d.version ? ' · avahi ' + d.version : '') : d.service.state],
    ['The reflector', d.reflector ? 'on' + (d.reflect_filters.length ? ' · only ' + d.reflect_filters.join(', ') : ' · every type') : 'off'],
    ['Interfaces', d.interfaces.map(function (i) { return i.name; }).join(', ') + (d.missing_interfaces.length ? ' · missing: ' + d.missing_interfaces.join(', ') : '')],
    ['Services seen', svc ? num(svc.length) + ' · ' + num(Object.keys(types).length) + ' type(s)' : '…']
  ]);
  var cells = tiles.querySelectorAll('.fact');
  if (cells[0]) cells[0].classList.add(d.service.state === 'active' ? 'good' : 'bad');
  cells[0].onclick = cells[1].onclick = function () { PANE = 'mdns'; showTab('settings'); };
  host.appendChild(tiles);
}
function loadMdnsTab() {
  apiLatest('mdns', 'mdns').then(function (d) {
    AV.d = d;
    paintMdnsCards(d);
    var sel = $('ms-iface'), keep = sel.value;
    clear(sel);
    sel.appendChild(el('option', '', 'every interface')).value = '';
    (d.interfaces || []).forEach(function (i) { var o = el('option', '', i.name); o.value = i.name; sel.appendChild(o); });
    sel.value = keep;
    if (!AV.svc) loadServices();
  }).catch(oops);
}
function loadServices() {
  if (AV.busy) return;
  AV.busy = true;
  busy($('ms-look'), true);
  $('ms-said').textContent = 'asking avahi…';
  api('mdns-services', undefined, 40).then(function (d) {
    AV.svc = d;
    drawServices();
  }).catch(function (e) {
    $('ms-said').textContent = '';
    var host = $('ms-table');
    clear(host);
    host.appendChild(listTable(['Type', 'Name', 'Interface', 'Protocol', 'Host', 'Address', 'TXT'], [], null,
                               'plain|' + String(e.message || e)));
  })
    .then(function () { AV.busy = false; busy($('ms-look'), false); });
}
function drawServices() {
  var d = AV.svc;
  if (!d) return;
  var q = $('ms-q').value.trim(), ifc = $('ms-iface').value, pr = $('ms-proto').value;
  var rows = d.services.filter(function (s) {
    return (!ifc || s.iface === ifc) && (!pr || s.proto === pr) && matches(s, q);
  });
  var types = {};
  d.services.forEach(function (s) { types[s.type] = 1; });
  if (AV.d) paintMdnsCards(AV.d);
  $('tabn-mdns').textContent = d.services.length ? num(d.services.length) : '';
  $('ms-said').textContent = num(rows.length) + ' of ' + num(d.services.length);
  var host = $('ms-table');
  clear(host);
  host.appendChild(listTable(['Type', 'Name', 'Interface', 'Protocol', 'Host', 'Address', 'TXT'], rows, function (s) {
    var tr = el('tr', 'tappable');
    tr.appendChild(noI18n(el('td', 'mono', s.type)));
    tr.appendChild(noI18n(el('td', '', s.name)));
    tr.appendChild(noI18n(el('td', 'mono', s.iface)));
    var tp = el('td'); tp.appendChild(el('span', 'tag ' + (s.proto === 'IPv6' ? 'violet' : 'info'), s.proto)); tr.appendChild(tp);
    tr.appendChild(noI18n(el('td', 'mono', s.host || '')));
    tr.appendChild(noI18n(el('td', 'mono', s.address ? s.address + (s.port ? ':' + s.port : '') : '')));
    tr.appendChild(noI18n(el('td', 'muted small', (s.txt || '').slice(0, 120))));
    tr.onclick = function () {
      modal(s.name, function (body) {
        body.appendChild(peekFacts([['Type', s.type], ['Interface', s.iface + ' ' + s.proto], ['Address', (s.address || '–') + (s.port ? ':' + s.port : '')]]));
        body.appendChild(kvTable(Object.keys(s).map(function (k) { return [k, s[k], 'mono']; })));
      });
    };
    return tr;
  }, 'plain|' + (d.hint || 'Nothing is shown on mDNS now - or avahi-daemon is not running'), {own: true}));
  explainWhatWasDrawn(host);
}
$('ms-look').onclick = loadServices;
['ms-iface', 'ms-proto'].forEach(function (id) { $(id).onchange = drawServices; });
$('ms-q').addEventListener('input', debounce(drawServices, 200));

function loadAvahiPane() {
  api('mdns').then(function (d) {
    AV.d = d;
    $('av-missing').hidden = !!d.installed;
    if (!d.installed) { $('av-missing-words').textContent = d.error || 'avahi is not installed here'; }
    var host = $('sect-mdns');
    clear(host);
    if (d.installed) {
      var grid = el('div', 'set-grid');
      d.keys.forEach(function (k) { grid.appendChild(settingItem(avahiSetting(k))); });
      host.appendChild(grid);
      Object.keys(DIRTY).forEach(function (key) {
        if (key.indexOf('avahi:') !== 0) return;
        var item = document.querySelector('.set-item[data-key="' + key + '"]');
        if (item) item.classList.add('changed');
      });
    }
    var st = $('av-state');
    clear(st);
    if (d.installed) {
      st.appendChild(kvTable([
        ['The daemon', d.service.state + ' (' + d.service.sub + ')', d.service.state === 'active' ? 'good' : 'bad'],
        ['Starts at boot', d.service.boot], ['Running since', d.service.since || '–'], ['Version', d.version || '–'],
        ['The file', d.config], ['Interfaces here', (d.system_interfaces || []).join(', ')],
        ['avahi-browse', d.browse_tool ? 'there' : 'missing - dnf install avahi-tools', d.browse_tool ? '' : 'bad']
      ]));
      var r = d.root || {};
      if (r.at && (r.said || []).some(function (x) { return /avahi/.test(x); })) {
        st.appendChild(el('p', 'muted small', 'root, ' + ago(r.at) + ':'));
        var ul = el('ul', 'tight');
        r.said.forEach(function (x) { ul.appendChild(el('li', /did not|not|refused/.test(x) ? 'warn' : '', x)); });
        st.appendChild(ul);
      }
    }
    var tools = $('av-tools');
    clear(tools);
    if (ADMIN && d.installed) {
      [['Restart', 'refresh', 'restart'], [d.service.state === 'active' ? 'Stop' : 'Start', 'power',
        d.service.state === 'active' ? 'stop' : 'start']].forEach(function (a) {
        var b = cmdButton(a[0], a[1], 'small' + (a[2] === 'stop' ? ' danger' : ''));
        b.onclick = function () {
          var go = function () {
            api('mdns', {action: a[2]}).then(function (x) { toast(x.message, 'good'); avahiWait(x.id); }).catch(oops);
          };
          if (a[2] === 'stop') confirmThen('Stop avahi-daemon?', 'mDNS is no longer reflected between the networks until it is started again.', 'Stop', go);
          else go();
        };
        tools.appendChild(b);
      });
    }
    if (d.installed) {
      var lg = cmdButton('Its log', 'log', 'small');
      lg.onclick = function () {
        peek('avahi-daemon - its log', function () { return api('mdns-log&lines=400'); }, function (body, x) {
          var pre = noI18n(el('pre', 'lines', x.lines.join('\n') || '(nothing)'));
          body.appendChild(pre);
          setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
        });
      };
      tools.appendChild(lg);
    }
    explainWhatWasDrawn($('pane-mdns'));
    markDirtyCount();
  }).catch(oops);
}
function avahiWait(id) {
  var tries = 0;
  var again = function () {
    api('root-result').then(function (d) {
      var r = d.result || {};
      if (r.id === id) {
        (r.said || []).forEach(function (x) { toast(x, /did not|refused|not a key/.test(x) || !r.ok ? 'bad' : 'good'); });
        if (PANE === 'mdns' && TAB === 'settings') loadAvahiPane();
        if (TAB === 'mdns') { AV.svc = null; loadMdnsTab(); }
        return;
      }
      if (++tries < 20) setTimeout(again, 1000);
      else toast('root has not answered - is fake-igd-web.path running?', 'bad');
    }).catch(function () { if (++tries < 20) setTimeout(again, 1000); });
  };
  setTimeout(again, 1200);
}

PANE_LOAD.mdns = loadAvahiPane;
