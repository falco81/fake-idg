/* pane-upgrade.js - Settings → upgrade (moved out of admin.js, 1.6.1). */
'use strict';

/* ---- upgrades ------------------------------------------------------------------ */
var UPG = {d: null, pkg: null};
function loadUpgrade() {
  apiLatest('upgrade', 'upgrade').then(function (d) { UPG.d = d; drawUpgrade(d); }).catch(oops);
}
function drawUpgrade(d) {
  var host = $('up-web');
  clear(host);
  var o = d.online || {};
  var facts = [['This server runs', d.here], ['Looked at', o.at ? ago(o.at) : 'not yet'],
               ['Newest there', (o.newest || {}).version || '–']];
  host.appendChild(peekFacts(facts));
  host.appendChild(noI18n(el('p', 'muted small mono', d.url)));
  if (o.error) host.appendChild(el('p', 'said bad', 'The last look: ' + o.error));
  if (!d.helper || !d.path_unit) {
    host.appendChild(el('p', 'said bad', 'Root\'s part is not installed here (' + (!d.helper ? 'fake_igd_upgrade.py' : 'fake-igd-upgrade.path')
      + ') - upgrade once on the command line: ./install.sh --upgrade'));
  }
  var row = el('div', 'btnrow');
  row.style.marginTop = '10px';
  var look = cmdButton('Look now', 'refresh', '');
  look.onclick = function () {
    busy(look, true);
    api('upgrade', {action: 'look'}).then(function () { loadUpgrade(); }).catch(oops).then(function () { busy(look, false); });
  };
  row.appendChild(look);
  var newer = o.newer_list || [];
  if (newer.length && !d.status.busy) {
    var pick = null;
    if (newer.length > 1) {
      pick = selectBox(newer.map(function (p) { return [p.version, p.version]; }), newer[0].version);
      row.appendChild(pick);
    }
    var want = function () { return pick ? pick.value : newer[0].version; };
    var go = cmdButton('Upgrade to ' + want() + ' now', 'up', 'primary');
    var only = cmdButton('Only fetch it', 'download', '');
    if (pick) pick.onchange = function () { setButtonIcon(go, 'up', 'Upgrade to ' + want() + ' now'); };
    go.onclick = function () {
      confirmThen('Upgrade to fake-igd ' + want() + '?', 'It is fetched, its signature and every file checked, and root '
        + 'runs its install.sh --upgrade. fake-igd.service and these pages restart once - the pages come back by themselves.',
        'Upgrade', function () {
          busy(go, true);
          api('upgrade', {action: 'online', version: want()}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); })
            .catch(oops).then(function () { busy(go, false); });
        }, false);
    };
    only.onclick = function () {
      busy(only, true);
      api('upgrade', {action: 'fetch', version: want()}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); })
        .catch(oops).then(function () { busy(only, false); });
    };
    row.appendChild(go);
    row.appendChild(only);
  } else if (o.at && !o.error) {
    row.appendChild(el('span', 'muted small', 'nothing newer than ' + d.here));
  }
  host.appendChild(row);
  /* the package waiting */
  var pk = d.package, ph = $('up-pkg');
  clear(ph);
  $('up-start').disabled = !pk || !pk.version || d.status.busy;
  $('up-forget').hidden = !pk || !pk.version;
  if (pk && pk.version) {
    ph.appendChild(peekFacts([['Version', pk.version], ['Signed by', pk.signed_by], ['Files', pk.files],
                              ['Came', pk.from || '–'], ['By', pk.by || '–']]));
    if (pk.changelog) {
      var det = el('details', 'fold');
      det.appendChild(el('summary', '', 'what is new'));
      det.appendChild(noI18n(el('pre', 'lines', pk.changelog)));
      ph.appendChild(det);
    }
  }
  /* the one going on, or the last */
  var st = d.status || {}, card = $('up-plan-card'), plan = $('up-plan');
  card.hidden = !st.state || st.state === 'none';
  clear(plan);
  if (!card.hidden) {
    var tone = st.state === 'done' ? 'ok' : (st.state === 'failed' ? 'crit' : 'warn');
    var line = el('div', 'btnrow');
    line.appendChild(el('span', 'tag ' + tone, st.state === 'asked' ? 'waiting for root' : st.state));
    line.appendChild(noI18n(el('b', '', 'fake-igd ' + (st.version || '?'))));
    if (st.at) line.appendChild(el('span', 'muted small', ago(st.at)));
    plan.appendChild(line);
    var bar = el('div', 'bar' + (st.state === 'failed' ? '' : ' good'));
    bar.style.marginTop = '10px';
    var fill = el('span');
    fill.style.width = Math.max(3, d.percent || 0) + '%';
    bar.appendChild(fill);
    plan.appendChild(bar);
    plan.appendChild(el('p', 'muted small', (d.percent || 0) + ' % · ' + (d.words || (st.state === 'done' ? 'done' : ''))));
    if (st.said) plan.appendChild(el('p', 'said bad', st.said));
  }
  $('up-log').textContent = (d.log || []).join('\n') || '–';
  if (st.busy) setTimeout(function () { if (TAB === 'settings' && PANE === 'upgrade') loadUpgrade(); }, 2000);
}
$('up-start').onclick = function () {
  var pk = UPG.d && UPG.d.package;
  if (!pk) return;
  confirmThen('Upgrade to fake-igd ' + pk.version + '?', 'Root checks the package again and runs its install.sh --upgrade. '
    + 'fake-igd.service and these pages restart once.', 'Upgrade', function () {
      api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); }).catch(oops);
    }, false);
};
$('up-forget').onclick = function () {
  api('upgrade', {action: 'forget'}).then(function (r) { toast(r.message, 'good'); loadUpgrade(); }).catch(oops);
};
(function drop() {
  var zone = $('up-drop'), file = $('up-file');
  zone.onclick = function () { file.click(); };
  zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', function () { zone.classList.remove('over'); });
  zone.addEventListener('drop', function (e) { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer.files[0]) send(e.dataTransfer.files[0]); });
  file.onchange = function () { if (file.files[0]) send(file.files[0]); };
  function send(f) {
    if (!/^fake-igd-\d+\.\d+\.\d+\.tar\.gz$/.test(f.name)) { toast('that is not a fake-igd-X.Y.Z.tar.gz', 'bad'); return; }
    $('up-drop-says').textContent = 'Sending ' + f.name + '…';
    var rd = new FileReader();
    rd.onload = function () {
      var b64 = String(rd.result).split(',')[1] || '';
      api('upgrade-package', {data: b64}).then(function (d) {
        toast('fake-igd ' + d.package.version + ' checked - signed by ' + d.package.signed_by, 'good');
        loadUpgrade();
      }).catch(oops).then(function () { $('up-drop-says').textContent = 'Drop the fake-igd-X.Y.Z.tar.gz here, or press to choose it'; });
    };
    rd.readAsDataURL(f);
  }
}());

PANE_LOAD.upgrade = loadUpgrade;
PANE_TICK.upgrade = loadUpgrade;
