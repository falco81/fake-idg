/* pane-about.js - Settings → about (moved out of admin.js, 1.6.1). */
'use strict';

/* ---- about ----------------------------------------------------------------------- */
function drawAbout() {
  var s = STATUS || {}, host = $('about-state');
  clear(host);
  host.appendChild(kvTable([
    ['fake-igd', s.version], ['This machine', s.node], ['Mode', s.mode], ['AddPortMapping', s.mapping_response],
    ['Description and SOAP', 'port ' + s.http_port], ['Public IP', s.public_ip || s.external_ip],
    ['Notifications', s.notifications], ['Who is answered', (s.allowed_clients || []).join(', ') || 'everybody'],
    ['Signed in as', ME.name + ' (' + roleWords(ME.role) + ')']
  ]));
  host.appendChild(el('p', 'muted small', 'The same on the server: upnp status · upnp --console · upnp --help'));
}

PANE_LOAD.about = drawAbout;
