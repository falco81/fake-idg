/* pane-ntfy.js - Settings → Notifications (ntfy) (1.6.1), as otp's loadMail: the settings, a test
   with every step shown (otp's mailSteps), what was sent, the certificate authority (otp's mca-*). */
(function () {
  'use strict';
  var NT = {d: null};
  var KIND_TAG = {'a port': 'info', 'another router': 'warn', 'a test': 'dim'};

  function load() {
    return api('upnp-ntfy').then(function (d) { NT.d = d; draw(); return d; }).catch(oops);
  }
  function whenOf(t) { var ms = Date.parse(t || ''); return isNaN(ms) ? (t || '–') : dayWords(new Date(ms)); }
  function certTable(list) {
    return listTable(['It is', 'Signed by', 'Good from', 'Good until', 'Fingerprint (SHA-256)'], list, function (c) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', '', c.subject || '–')));
      var by = el('td');
      if (c.self_signed) by.appendChild(el('span', 'tag info', 'itself - a root'));
      else by.appendChild(noI18n(el('span', '', c.issuer || '–')));
      tr.appendChild(by);
      tr.appendChild(el('td', 'muted small', whenOf(c.from)));
      var left = c.until ? (Date.parse(c.until) - Date.now()) / 86400000 : null;
      var tone = left === null || isNaN(left) ? '' : (left < 0 ? 'bad' : (left < 60 ? 'warn' : 'good'));
      tr.appendChild(el('td', 'small ' + tone, whenOf(c.until)));
      var fp = noI18n(el('td', 'mono small muted fp-full'));
      var hex = (c.fingerprint || '').toLowerCase();
      var half = Math.ceil(hex.length / 4) * 2;
      [hex.slice(0, half), hex.slice(half)].forEach(function (part) {
        if (part) fp.appendChild(el('div', '', part.replace(/(..)(?=.)/g, '$1:')));
      });
      fp.title = hex.replace(/(..)(?=.)/g, '$1:');
      tr.appendChild(fp);
      return tr;
    }, 'plain', {own: true});
  }
  function draw() {
    var d = NT.d;
    if (!d) return;
    $('nt-said').textContent = d.on ? 'to ' + d.server + ' · ' + (d.auth === 'none' ? 'no sign-in' : 'signed in with ' + d.auth) : 'switched off - no topic URL';
    /* What was sent. */
    var rows = d.sends || [];
    $('nt-when').textContent = rows.length ? 'the last ' + ago(rows[0].at) : '';
    var host = $('nt-sends');
    clear(host);
    host.appendChild(listTable(['When', 'What', 'Title', 'To', 'Sent', 'What the server said', 'By'], rows, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.at));
      var k = el('td'); k.appendChild(el('span', 'tag ' + (KIND_TAG[r.kind] || 'dim'), r.kind)); tr.appendChild(k);
      tr.appendChild(noI18n(el('td', '', r.title || '')));
      tr.appendChild(noI18n(el('td', 'mono small', r.host || '')));
      var s = el('td'); s.appendChild(el('span', 'tag ' + (r.ok ? 'ok' : 'crit'), r.ok ? 'sent' : 'failed')); tr.appendChild(s);
      tr.appendChild(noI18n(el('td', 'small ' + (r.ok ? 'muted' : 'bad'), r.said || '')));
      tr.appendChild(noI18n(el('td', 'muted small', r.by || '')));
      return tr;
    }, 'plain|Nothing has been sent yet' + (d.on ? '' : ' - notifications are switched off'), {own: true}));
    /* The certificate authority. */
    var list = d.ca_list || [];
    $('nca-when').textContent = list.length ? num(list.length) + ' certificate(s) kept' : (d.ca_file ? '' : 'none imported');
    $('nca-drop').hidden = !d.ca_file;
    var st = $('nca-state');
    clear(st);
    if (d.ca_said) st.appendChild(el('p', 'note bad', d.ca_said));
    if (d.ca_file) {
      st.appendChild(el('p', 'muted small', (d.ca_ours ? 'Kept in ' : 'Set by hand: ') + d.ca_file));
      if (list.length) st.appendChild(certTable(list));
    }
    explainWhatWasDrawn($('pane-ntfy'));
  }
  $('nt-test').onclick = function () {
    var b = $('nt-test');
    if (Object.keys(DIRTY || {}).some(function (k) { return /^(ntfy_|notify_)/.test(k); })) {
      toast('save the notification settings first', 'bad'); return;
    }
    busy(b, true);
    api('upnp-ntfy', {action: 'test'}, 60).then(function (d) {
      IGDP.stepsOut($('nt-steps'), d, 'Sent: ', 'Not sent: ');
      load();
    }).catch(oops).then(function () { busy(b, false); });
  };
  /** A certificate file read into the box: PEM as it is, a DER .cer written out as PEM. */
  function readCertFile(file, box) {
    var reader = new FileReader();
    reader.onload = function () {
      var bytes = new Uint8Array(reader.result || new ArrayBuffer(0));
      var text = '';
      try { text = new TextDecoder('utf-8').decode(bytes); } catch (e) { text = ''; }
      if (text.indexOf('-----BEGIN CERTIFICATE-----') < 0 && bytes.length && bytes[0] === 0x30) {
        var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        text = '-----BEGIN CERTIFICATE-----\n' + btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '') + '\n-----END CERTIFICATE-----\n';
      }
      if (text.indexOf('-----BEGIN CERTIFICATE-----') < 0) { toast('that file has no certificate in it', 'bad'); return; }
      box.value = text.trim();
    };
    reader.readAsArrayBuffer(file);
  }
  $('nca-save').onclick = function () {
    var pem = $('nca-pem').value.trim();
    if (!pem) { toast('paste the certificate first, or read it from a file', 'bad'); return; }
    var b = $('nca-save');
    busy(b, true);
    api('upnp-ntfy', {action: 'ca', mode: 'add', ca: pem}).then(function (r) {
      toast(r.message, 'good'); $('nca-pem').value = ''; load(); loadSettings(!Object.keys(DIRTY).length);
    }).catch(oops).then(function () { busy(b, false); });
  };
  $('nca-file').onclick = function () { $('nca-input').click(); };
  $('nca-input').onchange = function () {
    var file = this.files && this.files[0];
    if (file) readCertFile(file, $('nca-pem'));
    this.value = '';
  };
  $('nca-drop').onclick = function () {
    confirmThen('Take the certificate authority away', 'The ntfy server is checked against the authorities this machine trusts again'
      + ' - a server with a certificate of your own authority is no longer reached. fake-igd.service is restarted.', 'Take it away', function () {
        api('upnp-ntfy', {action: 'ca', mode: 'drop'}).then(function (r) { toast(r.message, 'good'); load(); loadSettings(!Object.keys(DIRTY).length); }).catch(oops);
      });
  };
  PANE_LOAD.ntfy = load;
  PANE_TICK.ntfy = function () {
    if (document.activeElement && $('pane-ntfy').contains(document.activeElement) && document.activeElement.tagName === 'TEXTAREA') return;
    api('upnp-ntfy').then(function (d) {
      var was = JSON.stringify([NT.d && NT.d.sends, NT.d && NT.d.ca_list, NT.d && NT.d.url]);
      NT.d = d;
      if (was !== JSON.stringify([d.sends, d.ca_list, d.url])) draw();
    }).catch(function () {});
  };
})();
