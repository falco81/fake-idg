/* pane-proxy.js - Settings → Proxy (otp's drawProxy, pxPath, pxSteps) - tried from this server. */
(function () {
'use strict';

/* The way it went, drawn: this server, the proxy (when it went through one), the
   address - each link green, red, or still being tried. */
function pxPath(x, nodeName) {
  var box = el('div', 'px-path' + (x ? (x.ok ? ' ok' : ' bad') : ' going'));
  var steps = (x && x.steps) || [];
  var failAt = steps.filter(function (s) { return !s.ok; })[0];
  var stop = function (icon, title, sub, cls) {
    var n = el('div', 'px-stop ' + (cls || ''));
    var ic = el('span', 'px-ic');
    ic.innerHTML = iconMarkup(icon, 22);
    n.appendChild(ic);
    n.appendChild(noI18n(el('b', 'mono', title)));
    if (sub) n.appendChild(el('span', 'muted small', sub));
    return n;
  };
  var link = function (state, words) {
    var l = el('div', 'px-link ' + state);
    l.appendChild(el('span', 'px-wire'));
    if (words) l.appendChild(el('span', 'px-lw small', words));
    return l;
  };
  if (!x) {
    box.appendChild(stop('router', nodeName || (STATUS && STATUS.node) || 'fake-igd', 'this server', 'me'));
    box.appendChild(link('going', 'trying…'));
    box.appendChild(stop('globe', '…', '', ''));
    return box;
  }
  var reached = function (re) { return steps.some(function (s) { return s.ok && re.test(s.what); }); };
  box.appendChild(stop('router', x.node, 'this server', 'me'));
  if (x.mode === 'proxy') {
    var toProxy = reached(/^connected to the proxy/) ? 'ok' : 'bad';
    box.appendChild(link(toProxy, toProxy === 'ok' ? 'connected' : 'not reached'));
    box.appendChild(stop('wall', x.proxy, x.proxy_auth ? 'the proxy · with a password' : 'the proxy', toProxy === 'ok' ? 'good' : 'bad'));
    var through = x.ok ? 'ok' : (toProxy === 'ok' ? 'bad' : 'off');
    box.appendChild(link(through, through === 'ok' ? 'through the proxy' : (through === 'bad' ? 'stopped here' : '')));
  } else {
    box.appendChild(link(x.ok ? 'ok' : 'bad', 'straight'));
  }
  box.appendChild(stop(x.tls ? 'lock' : 'globe', x.host + ':' + x.port, x.tls ? x.tls.version + ' · ' + (x.tls.issuer || '') : '', x.ok ? 'good' : 'bad'));
  var top = el('div', 'px-verdict ' + (x.ok ? 'ok' : 'bad'));
  top.appendChild(el('span', 'dot ' + (x.ok ? 'ok' : 'bad')));
  var words = x.ok
    ? (x.mode === 'proxy' ? 'Reached through the proxy' : 'Reached straight') + ' - HTTP ' + x.status + ', ' + x.ms + ' ms'
    : 'Not reached: ' + ((failAt && failAt.said) || '?');
  top.appendChild(noI18n(el('b', '', words)));
  if (x.mode === 'direct' && x.why_direct) top.appendChild(el('span', 'muted small', 'straight because ' + x.why_direct));
  var wrap = el('div', 'px-result');
  wrap.appendChild(top);
  wrap.appendChild(box);
  return wrap;
}
function pxSteps(x) {
  var ul = el('div', 'px-steps');
  var plan = x.mode === 'proxy'
    ? ['the proxy looked up', 'connected to the proxy'].concat(/^https/.test(x.url) ? ['a tunnel through the proxy', 'TLS'] : []).concat(['asked for'])
    : ['looked up', 'connected to'].concat(/^https/.test(x.url) ? ['TLS'] : []).concat(['asked for']);
  var done = x.steps || [];
  done.forEach(function (s) {
    var r = el('div', 'px-step ' + (s.ok ? 'ok' : 'bad'));
    r.appendChild(el('span', 'px-n', s.ok ? '✓' : '✗'));
    var t = el('div', 'px-st');
    t.appendChild(el('b', '', s.what));
    if (s.said) t.appendChild(noI18n(el('div', 'muted small mono', s.said)));
    r.appendChild(t);
    r.appendChild(el('span', 'px-ms small muted', s.ms + ' ms'));
    ul.appendChild(r);
  });
  for (var i = done.length; i < plan.length; i++) {
    var r = el('div', 'px-step off');
    r.appendChild(el('span', 'px-n', '○'));
    var t = el('div', 'px-st');
    t.appendChild(el('b', '', 'not tried - the step before stopped it'));
    r.appendChild(t);
    ul.appendChild(r);
  }
  return ul;
}
function drawProxy() {
  var host = $('px-host');
  if (!host || host._drawn) return;
  host._drawn = true;
  clear(host);
  var c = el('div', 'card full');
  c.appendChild(el('h2', '', 'Try it'));
  c.appendChild(el('p', 'note', 'An address asked from this server the way fake-igd asks the web: through the proxy as it is saved, or straight where none is set or the address is in the list. Each step is shown. Empty: where the new versions are looked for.'));
  var row = el('div', 'btnrow');
  var url = el('input');
  url.type = 'text';
  url.placeholder = 'https://github.com/';
  url.style.flex = '1';
  url.style.minWidth = '260px';
  var go = cmdButton('Try it', 'play', 'primary');
  go.disabled = !ADMIN;
  var said = el('div', 'px-out');
  go.onclick = function () {
    busy(go, true);
    clear(said);
    var grid = el('div', 'pw-grid node-grid');
    var cd = el('div', 'card ntp-node');
    var hd = el('div', 'pw-head');
    hd.appendChild(el('span', 'dot dim'));
    hd.appendChild(noI18n(el('b', '', (STATUS && STATUS.node) || 'this server')));
    hd.appendChild(el('span', 'tag info', 'this page'));
    var tg = el('span', 'tag info', 'being tried');
    hd.appendChild(tg);
    cd.appendChild(hd);
    var body = el('div', 'px-out');
    body.appendChild(pxPath(null));
    cd.appendChild(body);
    grid.appendChild(cd);
    said.appendChild(grid);
    api('proxy', {action: 'try', url: url.value.trim()}).then(function (x) {
      var got = x.result || {};
      hd.querySelector('.dot').className = 'dot ' + (got.ok ? 'ok' : 'bad');
      hd.replaceChild(el('span', 'tag ' + (got.ok ? 'ok' : 'crit'), got.ok ? (got.mode === 'proxy' ? 'through the proxy' : 'straight') : 'not reached'), tg);
      clear(body);
      body.appendChild(pxPath(got));
      body.appendChild(pxSteps(got));
    }).catch(function (e) {
      clear(body);
      body.appendChild(el('p', 'note bad', String((e && e.message) || e)));
    }).then(function () { busy(go, false); });
  };
  url.addEventListener('keydown', function (e) { if (e.key === 'Enter') go.click(); });
  row.appendChild(url); row.appendChild(go);
  c.appendChild(row);
  c.appendChild(said);
  host.appendChild(c);
  explainWhatWasDrawn(host);
}
PANE_LOAD.proxy = drawProxy;
}());
