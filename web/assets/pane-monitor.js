/* pane-monitor.js - Settings → Monitoring (otp's drawMonitor and, 1.7.2, its drawSnmp - this one server's agent). */
(function () {
'use strict';

/* pre.wrap of otp.css - its .wrap is also the page's own box (max-width, centred): kept to the card. */
function preBox(text) {
  var pre = noI18n(el('pre', 'wrap mono small', text));
  pre.style.maxWidth = 'none';
  pre.style.margin = '0 0 10px';
  return pre;
}
/* ---- SNMPv3 (1.7.2, otp's loadSnmp / drawSnmp): the agent, its engine ID, its own test ---------- */
var SNMPV = {d: null, said: null};
function loadSnmp() {
  api('snmp').then(function (d) { SNMPV.d = d; drawSnmp(); }).catch(function () {});
}
function snmpSaid(got, words) {
  var p = el('div', 'node-said ' + (got.ok ? 'ok' : 'bad'));
  p.appendChild(el('span', 'dot ' + (got.ok ? 'ok' : 'bad')));
  var t = el('div');
  t.appendChild(el('b', '', got.error ? 'It did not go' : words));
  if (got.error) t.appendChild(noI18n(el('div', 'small muted', got.error)));
  Object.keys(got.sent || {}).forEach(function (k) {
    if (got.sent[k] !== 'sent') t.appendChild(noI18n(el('div', 'small muted', k + ': ' + got.sent[k])));
  });
  t.appendChild(el('div', 'small muted', ago(got.at)));
  p.appendChild(t);
  return p;
}
function drawSnmp() {
  var host = $('snmp-host');
  if (!host || !SNMPV.d) return;
  var P = window.IGDP;
  var d = SNMPV.d;
  clear(host);
  var card = el('div', 'card full');
  card.appendChild(el('h2', '', 'SNMPv3'));
  card.appendChild(el('p', 'note', 'This machine answers by itself, at its own address, with an engine ID of its own - the monitoring asks it as Prometheus does. authPriv only: the user and its two passphrases above. fake-igd\'s objects are under ' + d.base + ' (FAKE-IGD-MIB, deploy/FAKE-IGD-MIB.txt in the package).'));
  if (!d.on) card.appendChild(el('p', 'muted small', 'Off - switch it on above, with the user and its passphrases.'));
  else if (!d.ready) card.appendChild(el('p', 'note warn', 'On, but the user or a passphrase is not set: nothing is answered yet.'));
  var a = d.agent || {};
  var grid = P.grid();
  var c = P.card({node: d.node}, a.listening ? 'ok' : (d.on ? 'bad' : 'dim'),
    a.listening ? 'listening' : (d.on ? 'not listening' : 'off'),
    a.listening ? 'ok' : (d.on ? 'crit' : 'dim'));
  c.appendChild(P.facts([
    ['Port', a.port ? a.port + '/udp' : '–', true],
    ['Engine ID', a.engine ? copyOnClick(noI18n(el('span', 'mono small', a.engine)), a.engine, 'the engine ID was copied') : '–'],
    ['Engine boots', a.boots ? String(a.boots) : '–', true],
    ['Asked / answered', num(a.asked || 0) + ' / ' + num(a.answered || 0)],
    ['Last asked from', a.last_from ? a.last_from + ' · ' + ago(a.last_at) : 'never'],
    ['Traps sent', num(a.traps || 0)],
    ['Read', d.at ? ago(d.at) : '']
  ]));
  if (a.error) c.appendChild(noI18n(el('p', 'note bad small', a.error)));
  if (a.trap_error) c.appendChild(noI18n(el('p', 'note warn small', 'Last trap: ' + a.trap_error)));
  var said = SNMPV.said;
  if (said) c.appendChild(snmpSaid(said, said.sent ? 'The test trap went to ' + Object.keys(said.sent).join(', ') : 'It answered itself in ' + said.ms + ' ms: ' + ((said.said || {})['1.3.6.1.2.1.1.1.0'] || '')));
  if (ADMIN) {
    var row = el('div', 'btnrow');
    var t = cmdButton('Ask it', 'play', 'small');
    explain(t, 'This machine asks its own agent on 127.0.0.1 as the monitoring would: discovery, then a GET with the user and its passphrases (authPriv).');
    t.disabled = !d.on || !d.ready;
    t.onclick = function () {
      busy(t, true);
      api('snmp', {action: 'test'}).then(function (got) { SNMPV.said = got; busy(t, false); loadSnmp(); })
        .catch(function (e) { busy(t, false); oops(e); });
    };
    var tr = cmdButton('Send a test trap', 'bell', 'small');
    explain(tr, 'A trap from this machine to every receiver set, now - with its engine ID, authPriv.');
    tr.disabled = !d.on || !d.ready || !(d.trap_to || []).length;
    tr.onclick = function () {
      busy(tr, true);
      api('snmp', {action: 'trap'}).then(function (got) { SNMPV.said = got; busy(tr, false); loadSnmp(); })
        .catch(function (e) { busy(tr, false); oops(e); });
    };
    row.appendChild(t); row.appendChild(tr);
    c.appendChild(row);
  }
  grid.appendChild(c);
  card.appendChild(grid);
  /* What to put into the monitoring - net-snmp's commands and the trap receiver. */
  var user = d.user || 'USER', auth = d.auth === 'SHA-1' ? 'SHA' : d.auth, priv = d.priv === 'AES-256' ? 'AES256' : 'AES';
  var where = d.bind && d.bind !== '0.0.0.0' && d.bind !== '::' ? (d.bind.indexOf(':') >= 0 ? 'udp6:[' + d.bind + ']' : d.bind) : (d.node || location.hostname);
  var e = a.engine || 'ENGINE-ID-OF-' + (d.node || 'THIS-SERVER');
  var lines = ['# asked (net-snmp; Zabbix: SNMPv3, authPriv, ' + d.auth + ', ' + d.priv + ', security name ' + user + ')',
    'snmpwalk -v3 -l authPriv -u ' + user + ' -a ' + auth + ' -A \'…\' -x ' + priv + ' -X \'…\' ' + where + ':' + d.port + ' ' + d.base,
    '', '# traps: snmptrapd.conf on the receiver, a line for this machine\'s engine ID',
    'createUser -e 0x' + e + ' ' + user + ' ' + auth + ' \'…\' ' + priv + ' \'…\'',
    'authUser log,execute ' + user + ' priv'];
  card.appendChild(el('h3', 'peek-h', 'In the monitoring'));
  card.appendChild(preBox(lines.join('\n')));
  card.appendChild(el('p', 'muted small', 'The passphrases are not shown here - they are those set above (kept sealed). AES-256 is net-snmp\'s AES256 and Zabbix\'s AES256, not Cisco\'s AES256C.'));
  /* The MIB (otp's "Zabbix 7.0" row: its template and OTP-MIB; fake-igd has the MIB). */
  card.appendChild(el('h3', 'peek-h', 'FAKE-IGD-MIB'));
  var mp = el('p', 'note');
  mp.innerHTML = 'Every object fake-igd answers, by name - the services, the requests and the ports asked for, the devices, the mappings, the mDNS reflector, the alerts open now, the certificate, the machine and its file systems, the mail, the logs sent, every sample of /metrics - and the traps. For net-snmp: in <code>~/.snmp/mibs</code> or <code>/usr/share/snmp/mibs</code>, then <code>snmpwalk -m +FAKE-IGD-MIB …</code>; Zabbix and other managers read it the same way. It imports NET-SNMP-MIB, which net-snmp has.';
  card.appendChild(mp);
  var zr = el('div', 'btnrow');
  var b = cmdButton('Download FAKE-IGD-MIB', 'download', 'primary');
  b.id = 'snmp-file-mib';
  b.disabled = d.mib_here === false;
  if (d.mib_here === false) explain(b, 'FAKE-IGD-MIB.txt is not in this installation (install.sh puts it beside the program).');
  b.onclick = function () {
    busy(b, true);
    api('snmpfile&what=mib').then(function (r) {
      busy(b, false);
      var x = document.createElement('a');
      x.href = URL.createObjectURL(new Blob([r.text], {type: 'application/octet-stream'}));
      x.download = r.name;
      document.body.appendChild(x); x.click(); x.remove();
      setTimeout(function () { URL.revokeObjectURL(x.href); }, 1000);
      toast(r.name + ' is downloaded', 'good');
    }).catch(function (e2) { busy(b, false); oops(e2); });
  };
  zr.appendChild(b);
  card.appendChild(zr);
  host.appendChild(card);
  explainWhatWasDrawn($('pane-monitor'));
}
function drawMonitor() {
  var host = $('mon-host');
  if (!host) return;
  clear(host);
  var card = el('div', 'card full');
  card.appendChild(el('h2', '', 'Prometheus'));
  card.appendChild(el('p', 'note', 'This machine answers for itself at /metrics, with the token as Authorization: Bearer. A wrong or missing token is a 401, an address not in Only from a 403, metrics switched off a 404.'));
  var row = el('div', 'btnrow');
  var mk = cmdButton('Make a token…', 'key', 'small primary');
  explain(mk, 'A new token for Prometheus, shown once - the one before stops opening /metrics at once.');
  mk.disabled = !ADMIN;
  mk.onclick = function () {
    confirmThen('Make a new token for Prometheus?', 'The token used now stops opening /metrics at once - put the new one into Prometheus.', 'Make it', function () {
      api('monitor', {action: 'token'}).then(function (x) {
        modal('The token for Prometheus', function (body) {
          body.appendChild(el('p', 'note warn', 'Shown only now. Put it into a file Prometheus reads (bearer_token_file below), readable by it alone.'));
          var r = el('div', 'key-big-row');
          var kb = noI18n(el('div', 'key-big mono', x.token));
          kb.tabIndex = 0;
          kb.title = 'Click to select it all';
          kb.onclick = function () { var rg = document.createRange(); rg.selectNodeContents(kb); var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(rg); };
          r.appendChild(kb);
          var cp = cmdButton('Copy', 'copy', 'primary');
          cp.onclick = function () { copyText(x.token, cp, 'the token is on the clipboard'); };
          r.appendChild(cp);
          body.appendChild(r);
        }, null, 'medium');
        loadSettings();
      }).catch(oops);
    }, false);
  };
  row.appendChild(mk);
  var pv = cmdButton('What this machine answers now', 'list', 'small');
  pv.disabled = !ADMIN;
  pv.onclick = function () {
    busy(pv, true);
    api('monitor', {action: 'preview'}).then(function (x) {
      busy(pv, false);
      modal('/metrics of this machine, now', function (body) {
        var pre = noI18n(el('pre', 'mono small mon-pre', x.text));
        /* The popup scrolls, not the text in it as well. */
        pre.style.maxHeight = 'none';
        pre.style.overflow = 'visible';
        pre.style.whiteSpace = 'pre-wrap';
        body.appendChild(pre);
      }, null, 'large');
    }).catch(function (e) { busy(pv, false); oops(e); });
  };
  row.appendChild(pv);
  card.appendChild(row);
  card.appendChild(el('h3', 'peek-h', 'prometheus.yml'));
  var y = 'scrape_configs:\n  - job_name: fake-igd\n    scheme: https\n    metrics_path: /metrics\n    bearer_token_file: /etc/prometheus/fake-igd.token\n'
    + '    tls_config:\n      # the CA of this server\'s certificate, if not a public one\n      # ca_file: /etc/prometheus/fake-igd-ca.pem\n      insecure_skip_verify: false\n'
    + '    static_configs:\n      - targets: [\'' + location.hostname + ':443\']\n';
  card.appendChild(preBox(y));
  var cpy = cmdButton('Copy', 'copy', 'small');
  cpy.onclick = function () { copyText(y, cpy); };
  card.appendChild(cpy);
  host.appendChild(card);

  explainWhatWasDrawn($('pane-monitor'));
}
PANE_LOAD.monitor = function () { drawMonitor(); loadSnmp(); };
}());
