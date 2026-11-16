/* pane-mdns.js - the mDNS reflector (avahi-daemon) (1.6.1): the tab mDNS, and Settings → mDNS reflector.

   The tab as otp's Tokens / Enrolment: tiles in the held card, the filters with Search and Clear, one
   table (the one scroller), a row opens the peek popup - followed live while it is open (avahi-browse
   kept running by the API), the services as they are now or as they come and go.
   The pane as otp's Time / SSH server: the card of this server - what avahi-daemon runs with now, from
   its own journal - then what is set (the save bar puts it in through root), then the copies kept.

   Globals the page's own code uses: AV, avahiSetting (settingByKey), avahiWait (the save bar),
   loadMdnsTab (the tab). */
'use strict';

var AV = {d: null, b: null, seq: 0, events: [], paused: false, timer: null, busy: false, owed: false, wait: ''};
function avahiSetting(k) {
  return {key: 'avahi:' + k.key, name: k.name, says: k.says, value: k.value, default: k.default,
          bool: k.bool, source: k.source, source_says: k.source_says, secret: false,
          list: k.kind === 'ifaces' || k.kind === 'list', restarts: false, root: true};
}
var MS_EVENT = {'new': ['came', 'ok'], gone: ['went', 'crit'], resolved: ['changed', 'info'], start: ['asked again', 'dim']};

/* ==========================================================================
   The tab
   ========================================================================== */
function msTiles() {
  var host = $('ms-tiles'), d = AV.d, b = AV.b;
  clear(host);
  if (d && !d.installed) {
    [['avahi-daemon', 'not installed', 'bad'], ['What to do', 'dnf install avahi avahi-tools', '']].forEach(function (t) {
      var f = el('div', 'fact');
      f.appendChild(el('div', 'k', t[0]));
      f.appendChild(el('div', 'v ' + t[2], t[1]));
      host.appendChild(f);
    });
    return;
  }
  var svc = b ? b.services : [], types = {};
  svc.forEach(function (s) { types[s.type] = 1; });
  var came = 0, went = 0;
  AV.events.forEach(function (e) { if (e.event === 'new' && !e.before) came++; if (e.event === 'gone') went++; });
  var on = d && d.service.state === 'active';
  var ifs = d ? ((d.now || {}).interfaces || []).map(function (i) { return i.name; }) : [];
  [['avahi-daemon', !d ? '…' : (on ? 'running' : d.service.state), d ? (on ? 'good' : 'bad') : '', 'mdns'],
   ['The reflector', !d ? '…' : (d.reflector ? (d.reflect_filters.length ? 'on · ' + d.reflect_filters.length + ' type(s)' : 'on') : 'off'), d && !d.reflector ? 'bad' : '', 'mdns'],
   ['Interfaces', !d ? '…' : (ifs.length ? ifs.join(', ') : (on ? 'none joined' : '–')), '', 'mdns'],
   ['Services', b ? num(svc.length) : '…', '', ''],
   ['Types', b ? num(Object.keys(types).length) : '…', '', ''],
   ['Came / went', b ? num(came) + ' / ' + num(went) : '…', went ? 'warn' : '', 'live']].forEach(function (t) {
    var f = el('div', 'fact' + (t[3] ? ' tappable' : ''));
    f.appendChild(el('div', 'k', t[0]));
    f.appendChild(noI18n(el('div', 'v ' + t[2], t[1])));
    if (t[3] === 'mdns') { f.onclick = function () { PANE = 'mdns'; showTab('settings'); }; explain(f, 'The reflector and its settings: Settings → mDNS reflector (avahi).'); }
    if (t[3] === 'live') { f.onclick = function () { $('ms-view').value = 'live'; msDraw(); }; explain(f, 'Every service that came or went while this page was open.'); }
    host.appendChild(f);
  });
}
function loadMdnsTab() {
  apiLatest('mdns', 'mdns').then(function (d) {
    AV.d = d;
    msTiles();
  }).catch(oops);
  msBrowse(!AV.b);
  msFollow();
}
function msFollow() {
  clearInterval(AV.timer);
  AV.timer = setInterval(function () {
    if (TAB !== 'mdns') { clearInterval(AV.timer); AV.timer = null; return; }
    if (!LIVE || AV.paused || document.hidden) return;
    msBrowse(false, true);
  }, 3000);
}
function msBrowse(fresh, quiet) {
  if (AV.busy) return;
  AV.busy = true;
  if (!quiet) busy($('ms-look'), true);
  if (fresh) { AV.seq = 0; AV.events = []; AV.b = null; $('ms-said').textContent = 'asking avahi…'; }
  api('mdns-browse&after=' + AV.seq + (fresh ? '&fresh=1' : ''), undefined, 20).then(function (b) {
    if (b.seq < AV.seq) { AV.events = []; }               /* the API restarted: from the beginning */
    AV.seq = b.seq;
    AV.events = AV.events.concat(b.events || []).slice(-2000);
    AV.b = b;
    var here = $('tab-mdns');
    if (quiet && (document.querySelector('.modal:not([hidden])') || userHolds(here) || pointerBusy(here))) { AV.owed = true; msTiles(); return; }
    msDraw();
  }).catch(function (e) {
    $('ms-said').textContent = '';
    AV.b = AV.b || null;
    if (quiet) return;
    var host = $('ms-table');
    clear(host);
    host.appendChild(listTable(['Type', 'Name', 'Interface', 'Protocol', 'Host', 'Address', 'TXT'], [], null,
                               'plain|' + String(e.message || e)));
  }).then(function () { AV.busy = false; if (!quiet) busy($('ms-look'), false); });
}
function msOptions(sel, values, first) {
  var keep = sel.value;
  var want = [''].concat(values).join('|');
  var have = Array.prototype.map.call(sel.options, function (o) { return o.value; }).join('|');
  if (want === have) return;
  clear(sel);
  var o0 = el('option', '', first); o0.value = ''; sel.appendChild(o0);
  values.forEach(function (v) { var o = noI18n(el('option', '', v)); o.value = v; sel.appendChild(o); });
  sel.value = values.indexOf(keep) >= 0 ? keep : '';
}
function msMatch(s, q, ty, ifc, pr) {
  return (!ty || s.type === ty) && (!ifc || s.iface === ifc) && (!pr || s.proto === pr) && matches(s, q);
}
function msTxt(t) {
  var out = [], re = /"((?:[^"\\]|\\.)*)"/g, m;
  while ((m = re.exec(t || ''))) out.push(m[1].replace(/\\(.)/g, '$1'));
  return out;
}
function msPeek(s) {
  peek(s.name, function () { return Promise.resolve(s); }, function (body) {
    body.appendChild(peekFacts([['Type', s.type], ['Interface', s.iface + ' · ' + s.proto],
                                ['Address', s.address ? s.address + (s.port ? ' port ' + s.port : '') : 'not resolved'],
                                ['Host', s.host || '–'], ['Seen first', s.first ? stamp(s.first) + (s.before ? ' (there before)' : '') : '–'],
                                ['Domain', s.domain || 'local']]));
    var txt = msTxt(s.txt);
    if (txt.length) {
      body.appendChild(el('h3', 'peek-h', 'What it says of itself (TXT)'));
      body.appendChild(kvTable(txt.map(function (x) {
        var i = x.indexOf('=');
        return i > 0 ? [x.slice(0, i), x.slice(i + 1), 'mono'] : [x, '(set)', 'mono'];
      })));
    }
    body.appendChild(el('h3', 'peek-h', 'As avahi-browse said it'));
    body.appendChild(noI18n(el('pre', 'lines', ['=', s.iface, s.proto, s.name, s.type, s.domain || 'local', s.host || '',
                                                s.address || '', s.port || '', s.txt || ''].join(';'))));
  });
}
function msDraw() {
  AV.owed = false;
  var b = AV.b;
  msTiles();
  if (!b) return;
  var live = $('ms-view').value === 'live';
  var all = b.services || [];
  var types = {}, ifs = {};
  all.concat(AV.events.filter(function (e) { return e.type; })).forEach(function (s) { types[s.type] = 1; ifs[s.iface] = 1; });
  msOptions($('ms-type'), Object.keys(types).sort(), 'every type');
  msOptions($('ms-iface'), Object.keys(ifs).sort(), 'every interface');
  var q = $('ms-q').value.trim(), ty = $('ms-type').value, ifc = $('ms-iface').value, pr = $('ms-proto').value;
  var host = $('ms-table');
  $('tabn-mdns').textContent = all.length ? num(all.length) : '';
  var state = b.running ? (AV.paused ? 'paused' : 'followed live') : (b.ended || 'not followed');
  if (!live) {
    var rows = all.filter(function (s) { return msMatch(s, q, ty, ifc, pr); });
    $('ms-said').textContent = num(rows.length) + ' of ' + num(all.length) + ' · ' + state;
    clear(host);
    host.appendChild(listTable(['Type', 'Name', 'Interface', 'Protocol', 'Host', 'Address', 'Seen', 'TXT'], rows, function (s) {
      var tr = el('tr', 'tappable');
      tr.appendChild(noI18n(el('td', 'mono', s.type)));
      var n = noI18n(el('td', '', s.name));
      if (!s.before && s.first) { n.appendChild(document.createTextNode(' ')); n.appendChild(el('span', 'tag ok', 'new')); }
      tr.appendChild(n);
      tr.appendChild(noI18n(el('td', 'mono', s.iface)));
      var tp = el('td'); tp.appendChild(el('span', 'tag ' + (s.proto === 'IPv6' ? 'violet' : 'info'), s.proto)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'mono', s.host || '')));
      tr.appendChild(noI18n(el('td', 'mono', s.address ? s.address + (s.port ? ':' + s.port : '') : '')));
      tr.appendChild(s.first ? stampCell(s.first, 'muted small') : el('td', 'muted', '–'));
      tr.appendChild(noI18n(el('td', 'muted small', msTxt(s.txt).join(' · ').slice(0, 120))));
      tr.onclick = function () { msPeek(s); };
      return tr;
    }, 'plain|' + (b.hint || (all.length ? 'Nothing matches' : 'Nothing is shown on mDNS now - or avahi-daemon is not running')), {own: true}));
  } else {
    var evs = AV.events.filter(function (e) { return e.event === 'start' || (!e.before && msMatch(e, q, ty, ifc, pr)); }).slice().reverse();
    $('ms-said').textContent = num(evs.filter(function (e) { return e.event !== 'start'; }).length) + ' change(s) · ' + state;
    clear(host);
    host.appendChild(listTable(['When', 'What', 'Type', 'Name', 'Interface', 'Protocol', 'Address'], evs, function (e) {
      var tr = el('tr', e.event === 'start' ? '' : 'tappable');
      tr.appendChild(stampCell(e.at));
      var w = MS_EVENT[e.event] || [e.event, 'dim'];
      var k = el('td'); k.appendChild(el('span', 'tag ' + w[1], w[0])); tr.appendChild(k);
      if (e.event === 'start') {
        var td = el('td', 'muted small', 'avahi-browse asked again - what it knew then is in “as they are now”');
        td.colSpan = 5;
        tr.appendChild(td);
        return tr;
      }
      tr.appendChild(noI18n(el('td', 'mono', e.type)));
      tr.appendChild(noI18n(el('td', '', e.name)));
      tr.appendChild(noI18n(el('td', 'mono', e.iface)));
      var tp = el('td'); tp.appendChild(el('span', 'tag ' + (e.proto === 'IPv6' ? 'violet' : 'info'), e.proto)); tr.appendChild(tp);
      tr.appendChild(noI18n(el('td', 'mono', e.address ? e.address + (e.port ? ':' + e.port : '') : '')));
      tr.onclick = function () { msPeek(e); };
      return tr;
    }, 'plain|Nothing has come or gone since this page has been open' + (b.running ? ' - it is followed, new ones show here as they come' : ''), {own: true}));
  }
  explainWhatWasDrawn(host);
}
$('ms-look').onclick = function () { msBrowse(true); };
$('ms-pause').onclick = function () {
  AV.paused = !AV.paused;
  setButtonIcon($('ms-pause'), AV.paused ? 'play' : 'clock', AV.paused ? 'Follow again' : 'Pause');
  if (!AV.paused) msBrowse(false, true); else msDraw();
};
['ms-view', 'ms-type', 'ms-iface', 'ms-proto'].forEach(function (id) { $(id).onchange = msDraw; });
$('ms-q').addEventListener('input', debounce(msDraw, 200));
document.addEventListener('DOMContentLoaded', function () {
  searchButtons($('ms-q'), msDraw, ['ms-type', 'ms-iface', 'ms-proto']);
  /* What waited while a row was pointed at, drawn once it is let go. */
  setInterval(function () {
    var here = $('tab-mdns');
    if (AV.owed && TAB === 'mdns' && !document.querySelector('.modal:not([hidden])') && !userHolds(here) && !pointerBusy(here)) msDraw();
  }, 1000);
});

/* ==========================================================================
   Settings → mDNS reflector (avahi)
   ========================================================================== */
function loadAvahiPane() {
  api('mdns').then(function (d) { AV.d = d; drawAvahi(); }).catch(oops);
}
function avahiAct(action, b, extra) {
  if (b) busy(b, true);
  api('mdns', Object.assign({action: action}, extra || {})).then(function (x) {
    toast(x.message, 'good');
    avahiWait(x.id);
  }).catch(oops).then(function () { if (b) busy(b, false); });
}
function drawAvahi(live) {
  var real = $('av-host'), d = AV.d;
  if (!real || !d) return;
  var P = IGDP;
  P.letGo(real);
  $('av-set').hidden = !d.installed;
  $('av-file').textContent = d.installed ? d.config + (d.changed_at ? ' · changed ' + ago(d.changed_at) : '') : '';
  liveFill(real, function (host) {
    if (!d.installed) {
      host.appendChild(el('p', 'note bad', (d.error || 'avahi is not installed here') + ' - dnf install avahi avahi-tools, then look again.'));
      return;
    }
    var on = d.service.state === 'active';
    var now = d.now || {};
    var joined = now.interfaces || [];
    var grid = P.grid();
    var c = P.card(d, on ? (d.file_newer ? 'warn' : 'ok') : 'bad', on ? 'running' : d.service.state, on ? 'ok' : 'crit');
    if (on && d.file_newer) c._head.appendChild(el('span', 'tag warn', 'the file is newer'));
    if (AV.wait) c._head.appendChild(el('span', 'tag info', 'asked of root'));
    if (!on) P.big(c, 'stopped', 'nothing is reflected');
    else if (d.reflector) P.big(c, num(joined.length), joined.length === 1 ? 'interface - nothing to reflect to' : 'interfaces reflected between');
    else P.big(c, 'off', 'the reflector - avahi answers for this machine only');
    var allow = d.allow_interfaces || [], deny = d.deny_interfaces || [];
    c.appendChild(P.facts([
      ['On the interfaces now', on ? (joined.length ? joined.map(function (i) { return i.name + ' (' + i.ipv4.concat(i.ipv6).join(', ') + ')'; }).join('; ') : (now.read ? 'none joined' : 'its journal cannot be read')) : '–', true],
      ['Set to use', allow.length ? allow.join(', ') : 'every interface', true],
      ['Never used', deny.length ? deny.join(', ') : 'none', true],
      ['Missing here', (d.missing_interfaces || []).length ? d.missing_interfaces.join(', ') : 'none', true, (d.missing_interfaces || []).length ? 'bad' : ''],
      ['Reflects', d.reflector ? (d.reflect_filters.length ? d.reflect_filters.join(', ') : 'every service type') + (d.reflect_ipv ? ' · between IPv4 and IPv6' : '') : 'nothing'],
      ['Speaks', [d.ipv4 ? 'IPv4' : '', d.ipv6 ? 'IPv6' : ''].filter(Boolean).join(' and ') || 'nothing'],
      ['Records in the cache', d.cache_entries_max === '0' ? 'none - avahi-browse sees nothing' : (d.cache_entries_max || '4096'), false, d.cache_entries_max === '0' ? 'warn' : ''],
      ['Host name', now.host || '', true],
      ['Running since', on && d.since_at ? stamp(d.since_at) : (d.service.since || '')],
      ['Starts at boot', d.service.boot === 'enabled' ? 'yes' : d.service.boot],
      ['Version', d.version ? 'avahi ' + d.version : '', true],
      ['Read', ago(d.at)]
    ]));
    (now.problems || []).slice(-3).forEach(function (w) { c.appendChild(noI18n(el('div', 'si-said small', w.replace(/^\S+\s+\S+\s+/, '')))); });
    var r = d.root || {};
    if (r.at) {
      var st = el('p', 'small ' + (r.ok ? 'muted' : 'bad'));
      st.textContent = (r.ok ? 'Put in by root ' : 'NOT put in by root ') + ago(r.at) + (r.by ? ' (' + r.by + ')' : '') + ': ' + (r.said || []).join(' · ');
      c.appendChild(st);
    }
    var row = el('div', 'btnrow');
    var re = cmdButton('Read it again', 'refresh', 'small');
    re.onclick = function () { busy(re, true); api('mdns').then(function (x) { AV.d = x; drawAvahi(); }).catch(oops).then(function () { busy(re, false); }); };
    row.appendChild(re);
    if (ADMIN) {
      var rs = cmdButton('Restart', 'refresh', 'small');
      explain(rs, 'avahi-daemon restarted by root - it reads the file again.');
      rs.onclick = function () { avahiAct('restart', rs); };
      row.appendChild(rs);
      var ss = cmdButton(on ? 'Stop' : 'Start', 'power', 'small' + (on ? ' danger' : ''));
      ss.onclick = function () {
        if (on) confirmThen('Stop avahi-daemon?', 'mDNS is no longer reflected between the networks - AirPlay, Chromecast and the PS5 are not seen across them - until it is started again.', 'Stop', function () { avahiAct('stop', ss); });
        else avahiAct('start', ss);
      };
      row.appendChild(ss);
    }
    var lg = cmdButton('Its log', 'log', 'small');
    explain(lg, 'What avahi-daemon wrote in the system journal (journalctl -u avahi-daemon).');
    lg.onclick = function () {
      peek('avahi-daemon - its log', function () { return api('mdns-log&lines=400'); }, function (body, x) {
        var pre = noI18n(el('pre', 'lines', x.lines.join('\n') || '(nothing)'));
        body.appendChild(pre);
        setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
      });
    };
    row.appendChild(lg);
    var see = cmdButton('Services', 'wifi', 'small');
    explain(see, 'Every service mDNS shows now (the tab mDNS).');
    see.onclick = function () { showTab('mdns'); };
    row.appendChild(see);
    c.appendChild(row);
    grid.appendChild(c);
    host.appendChild(grid);
    if (on && d.file_newer) host.appendChild(el('p', 'note warn', 'avahi-daemon.conf was changed (' + ago(d.changed_at) + ') after avahi-daemon started (' + ago(d.since_at) + '): it still runs with what the file said before - Restart it.'));
    if ((d.missing_interfaces || []).length) host.appendChild(el('p', 'note bad', 'Set to use, but not on this server: ' + d.missing_interfaces.join(', ') + ' - avahi leaves them out. Choose the interfaces this server has below.'));
    if (d.reflector && on && joined.length < 2) host.appendChild(el('p', 'note warn', 'The reflector is on, but avahi is on ' + (joined.length ? 'one interface only' : 'no interface') + ': there is nothing to reflect between.'));
  }, live, function () { explainWhatWasDrawn(real); });
  drawAvahiSettings();
  drawAvahiCopies();
}
function drawAvahiSettings() {
  var d = AV.d, host = $('sect-mdns');
  if (!host || !d || !d.installed) return;
  var sig = JSON.stringify([d.keys.map(function (k) { return [k.key, k.value]; }), (d.kernel || []).map(function (k) { return k.name; })]);
  if (host._drawn === sig && host.querySelector('.set-grid')) return;
  if (host._drawn && document.activeElement && host.contains(document.activeElement)) return;
  host._drawn = sig;
  clear(host);
  var grid = el('div', 'set-grid');
  d.keys.forEach(function (k) { grid.appendChild(settingItem(avahiSetting(k))); });
  host.appendChild(grid);
  /* What was changed and not saved yet stays changed (another pane looked at meanwhile). */
  Object.keys(DIRTY).forEach(function (key) {
    if (key.indexOf('avahi:') !== 0) return;
    var box = $('set-' + key), item = document.querySelector('.set-item[data-key="' + key + '"]');
    if (!box || !item) return;
    if (box._input) { box._input.checked = !!DIRTY[key]; } else box.value = DIRTY[key];
    item.classList.add('changed');
  });
  var names = (d.kernel || []).filter(function (k) { return k.name !== 'lo'; });
  IGDP.ifacePick('avahi:allow-interfaces', names, 'none chosen: every interface');
  IGDP.ifacePick('avahi:deny-interfaces', names, 'none');
  explainWhatWasDrawn(host);
  markDirtyCount();
}
function drawAvahiCopies() {
  var d = AV.d, host = $('av-copies');
  if (!host || !d) return;
  clear(host);
  var list = d.copies || [];
  if (!d.installed || !list.length) return;
  var card = el('div', 'card full');
  var h = el('h2', '', 'Copies of the file');
  h.appendChild(el('span', 'right muted small', num(list.length) + ' kept'));
  card.appendChild(h);
  card.appendChild(el('p', 'note', 'Kept beside avahi-daemon.conf before each change - the last ten. Put back, what fake-igd sets in the file is as it was in the copy, and avahi-daemon is restarted with it (the file as it is now is kept as a copy first).'));
  card.appendChild(listTable(['Kept', 'The copy', 'Size', ''], list, function (c) {
    var tr = el('tr');
    tr.appendChild(stampCell(c.at));
    tr.appendChild(noI18n(el('td', 'mono small', c.name)));
    tr.appendChild(el('td', 'num muted', bytes(c.size)));
    var tools = el('td', 'rowtools');
    if (ADMIN) {
      var back = iconButton('undo', 'Put this copy back');
      back.onclick = function () {
        confirmThen('Put this copy back?', 'What fake-igd sets in avahi-daemon.conf is put back as it was in <b>' + htmlText(c.name)
          + '</b> (' + htmlText(stamp(c.at)) + '), and avahi-daemon is restarted with it.', 'Put it back', function () {
            avahiAct('restore', back, {copy: c.name});
          });
      };
      tools.appendChild(back);
    }
    tr.appendChild(tools);
    return tr;
  }, 'plain', {own: true}));
  host.appendChild(card);
}
/* Root's answer to an ask, followed: said as toasts, the pane and the tab drawn again. */
function avahiWait(id) {
  var tries = 0;
  AV.wait = id;
  if (PANE === 'mdns' && TAB === 'settings') drawAvahi(true);
  var again = function () {
    api('mdns-result').then(function (d) {
      var r = d.result || {};
      if (r.id === id) {
        AV.wait = '';
        (r.said || []).forEach(function (x) { toast(x, !r.ok ? 'bad' : 'good'); });
        if (PANE === 'mdns' && TAB === 'settings') { var s = $('sect-mdns'); if (s) s._drawn = null; loadAvahiPane(); }
        if (TAB === 'mdns') loadMdnsTab();
        return;
      }
      if (++tries < 30) setTimeout(again, 1000);
      else { AV.wait = ''; toast('root has not answered - is fake-igd-web.path running?', 'bad'); }
    }).catch(function () { if (++tries < 30) setTimeout(again, 1000); });
  };
  setTimeout(again, 1200);
}

PANE_LOAD.mdns = function () { var s = $('sect-mdns'); if (s) s._drawn = null; loadAvahiPane(); };
PANE_TICK.mdns = function () {
  api('mdns').then(function (d) { AV.d = d; drawAvahi(true); }).catch(function () {});
};
