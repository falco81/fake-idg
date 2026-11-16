/* pane-monitor.js - Settings → Monitoring (otp's drawMonitor; its SNMPv3 card says why there is none here). */
(function () {
'use strict';

/* pre.wrap of otp.css - its .wrap is also the page's own box (max-width, centred): kept to the card. */
function preBox(text) {
  var pre = noI18n(el('pre', 'wrap mono small', text));
  pre.style.maxWidth = 'none';
  pre.style.margin = '0 0 10px';
  return pre;
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

  var sn = $('snmp-host');
  clear(sn);
  var sc = el('div', 'card full');
  sc.appendChild(el('h2', '', 'SNMPv3'));
  sc.appendChild(el('p', 'note', 'Not answered by fake-igd. An SNMPv3 agent needs UDP port 161 (a privileged port: the API would have to be given CAP_NET_BIND_SERVICE and the firewall opened for it), and authPriv needs AES, which Python\'s standard library has not - otp carries an AES of its own in Python for it, with a MIB of its own. Everything SNMP would say is in /metrics above; where the monitoring speaks only SNMP, the system\'s net-snmp (snmpd) can answer for this machine itself.'));
  sn.appendChild(sc);
  explainWhatWasDrawn($('pane-monitor'));
}
PANE_LOAD.monitor = drawMonitor;
}());
