/* pane-service.js - Settings → service (moved out of admin.js, 1.6.1). */
'use strict';

/* ---- the service ------------------------------------------------------------ */
function drawService() {
  var s = STATUS || {}, sv = s.service || {}, host = $('sv-state');
  clear(host);
  host.appendChild(kvTable([
    ['fake-igd.service', sv.state + ' (' + (sv.sub || '?') + ')', sv.state === 'active' ? 'good' : 'bad'],
    ['Its PID', sv.pid && sv.pid !== '0' ? sv.pid : '–'],
    ['Running since', sv.since || '–'],
    ['Starts at boot', sv.boot || '–'],
    ['Restarts', sv.restarts],
    ['The pages\' API', 'since ' + stamp((s.web || {}).api_since)]
  ]));
}
$('sv-restart').onclick = function () {
  confirmThen('Restart fake-igd.service?', 'For a few seconds nothing on the network is answered.', 'Restart', function () {
    api('apply', {restart: true}).then(function () { toast('asked root to restart it', 'good'); setTimeout(tick, 4000); }).catch(oops);
  }, false);
};
$('sv-apply').onclick = function () {
  api('apply', {}).then(function () { toast('asked root - a moment', 'good'); }).catch(oops);
};

PANE_LOAD.service = drawService;
