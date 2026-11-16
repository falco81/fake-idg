/* pane-ntfy.js - Settings → ntfy (moved out of admin.js, 1.6.1). */
'use strict';

$('nt-test').onclick = function () {
  var b = $('nt-test');
  busy(b, true);
  $('nt-said').textContent = '';
  api('notify-test', {}).then(function (d) { $('nt-said').className = 'small good'; $('nt-said').textContent = d.message; })
    .catch(function (e) { $('nt-said').className = 'small bad'; $('nt-said').textContent = e.message; })
    .then(function () { busy(b, false); });
};

PANE_LOAD.ntfy = PANE_LOAD.ntfy || function () {};
