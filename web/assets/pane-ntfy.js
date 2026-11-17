/* pane-ntfy.js - Settings → Notifications (ntfy) (1.6.1), as otp's loadMail: the settings, a test
   with every step shown (otp's mailSteps), what was sent, the certificate authority (otp's mca-*). */
(function () {
  'use strict';
  var NT = {d: null, kind: ''};
  var EV = {d: null, edit: null};
  var KIND_TAG = {port_new: 'info', port_refused: 'warn', other_router: 'warn', public_ip: 'info',
                  service_crash: 'warn', gw_forward: 'warn', gw_drops: 'warn', alerts: 'warn', alerts_over: 'ok',
                  test: 'dim', summary: 'dim'};
  var PRIO = [[1, '1 min'], [2, '2 low'], [3, '3 default'], [4, '4 high'], [5, '5 urgent']];

  function sendsPath() { return 'upnp-ntfy' + (NT.kind ? '&kind=' + encodeURIComponent(NT.kind) : ''); }
  function load() {
    return api(sendsPath()).then(function (d) { NT.d = d; draw(); return d; }).catch(oops);
  }
  function kindWords(k) {
    if (k === 'test') return 'a test';
    if (k === 'summary') return 'a summary';
    var e = EV.d && (EV.d.events || []).filter(function (x) { return x.kind === k; })[0];
    return e ? e.words : k;
  }

  /* ---- What is sent: each kind on or off, its priority and tags, a sample (1.8.2) ---- */
  function fromView(d) {
    var o = {};
    (d.events || []).forEach(function (e) { o[e.kind] = {on: !!e.on, priority: e.priority || 0, tags: e.tags || ''}; });
    (d.alert_kinds || []).forEach(function (a) { o['alert:' + a.kind] = {on: !!a.on}; });
    return o;
  }
  function loadEv() {
    return api('ntfy').then(function (d) {
      EV.d = d;
      if (!PENDING.ntev) EV.edit = fromView(d);
      drawEv();
      return d;
    }).catch(oops);
  }
  function changed() {
    pendingSet('ntev', {save: function () {
      return api('ntfy', {action: 'events', events: EV.edit}).then(function (r) {
        toast(r.message, 'good'); delete PENDING.ntev; loadEv(); return true;
      });
    }, reset: function () { EV.edit = fromView(EV.d); drawEv(); }});
  }
  function sample(kind, b) {
    busy(b, true);
    api('ntfy', {action: 'sample', kind: kind}, 30).then(function (r) {
      toast(r.message, r.ok ? 'good' : 'bad'); load();
    }).catch(oops).then(function () { busy(b, false); });
  }
  function eventRow(e) {
    var c = EV.edit[e.kind] || {on: e.on, priority: e.priority, tags: e.tags};
    var tr = el('tr', c.on ? '' : 'nte-off');
    var swc = el('td', 'nte-sw');
    var sw = switchBox(c.on);
    sw._input.disabled = !ADMIN;
    var what = el('td', 'nte-what');
    var name = el('div', 'nte-name', e.words);
    swNamedBy(sw, name);
    what.appendChild(name);
    var says = e.says + (e.kind === 'gw_drops' && EV.d ? ' More than ' + num(EV.d.drops_per_hour) + ' an hour (the setting above).' : '');
    what.appendChild(el('div', 'muted small', says));
    var dflt = el('div', 'muted small nte-dflt', (e.default ? 'on' : 'off') + ' as it comes · ' + e.by);
    what.appendChild(dflt);
    sw._input.onchange = function () {
      c.on = sw._input.checked; EV.edit[e.kind] = c; tr.className = c.on ? '' : 'nte-off';
      changed(); if (e.kind === 'alerts') drawEv();
    };
    swc.appendChild(sw);
    tr.appendChild(swc);
    tr.appendChild(what);
    var pc = el('td');
    var prio = selectBox([[0, 'as set above']].concat(PRIO), c.priority || 0);
    prio.disabled = !ADMIN;
    prio.setAttribute('aria-label', 'Priority of ' + e.words);
    prio.onchange = function () { c.priority = parseInt(prio.value, 10) || 0; EV.edit[e.kind] = c; changed(); };
    pc.appendChild(prio);
    tr.appendChild(pc);
    var tc = el('td');
    var tags = textBox(c.tags || '', 'as set above', 'nte-tags');
    tags.disabled = !ADMIN;
    tags.maxLength = 120;
    tags.setAttribute('aria-label', 'Tags of ' + e.words);
    tags.oninput = function () { c.tags = tags.value; EV.edit[e.kind] = c; changed(); };
    tc.appendChild(tags);
    tr.appendChild(tc);
    var bc = el('td', 'rowtools');
    var b = cmdButton('Send a sample', 'bell', 'small');
    b.disabled = !ADMIN || !(EV.d && EV.d.url);
    b.title = EV.d && EV.d.url ? 'Sends "' + e.words + '" in its own words now, marked as a sample' : 'No ntfy topic URL yet';
    b.onclick = function () { sample(e.kind, b); };
    bc.appendChild(b);
    tr.appendChild(bc);
    return tr;
  }
  function alertKinds() {
    var on = EV.edit.alerts && EV.edit.alerts.on;
    var box = el('div', 'nte-alerts' + (on ? '' : ' nte-off'));
    box.appendChild(el('div', 'muted small', on ? 'The alerts sent - each kind can be left out:'
      : 'Switch on "Every alert" above to send the alerts here - each kind can then be left out:'));
    var grid = el('div', 'nte-chips');
    (EV.d.alert_kinds || []).forEach(function (a) {
      var k = 'alert:' + a.kind, c = EV.edit[k] || {on: a.on};
      var chip = el('label', 'nte-chip');
      var sw = switchBox(c.on);
      sw._input.disabled = !ADMIN;
      sw._input.onchange = function () { c.on = sw._input.checked; EV.edit[k] = c; changed(); };
      chip.appendChild(sw);
      chip.appendChild(el('span', '', a.words));
      grid.appendChild(chip);
    });
    box.appendChild(grid);
    return box;
  }
  function drawEv() {
    var d = EV.d, host = $('nt-events');
    if (!d || !host || !EV.edit) return;
    var q = d.quiet || {}, bits = [];
    if (q.from && q.to) bits.push('quiet hours ' + q.from + '-' + q.to + (q.now ? ' (now' + (q.held ? ', ' + num(q.held) + ' held' : '') + ')' : ''));
    bits.push(d.rate ? 'at most ' + num(d.rate) + ' of a kind an hour' : 'no rate limit');
    var over = Object.keys(d.limited || {});
    if (over.length) bits.push(over.length + ' kind(s) held back by the rate limit');
    $('nte-said').textContent = bits.join(' · ');
    clear(host);
    ['upnp', 'gateway', 'system'].forEach(function (g) {
      var rows = (d.events || []).filter(function (e) { return e.group === g; });
      if (!rows.length) return;
      var n = rows.filter(function (e) { return (EV.edit[e.kind] || e).on; }).length;
      var h = el('h3', 'peek-h nte-group', (d.groups || {})[g] || g);
      h.appendChild(el('span', 'muted small', ' · ' + n + ' of ' + rows.length + ' on'));
      host.appendChild(h);
      host.appendChild(listTable(['On', 'What is sent', 'Priority', 'Tags', ''], rows, eventRow, 'plain nte-table', {own: true}));
      if (g === 'system') host.appendChild(alertKinds());
    });
    if (!d.url) host.appendChild(el('p', 'note', 'Nothing goes out until the topic URL above is saved.'));
    explainWhatWasDrawn($('pane-ntfy'));
  }
  $('nt-kind').onchange = function () { NT.kind = this.value; load(); };
  function whenOf(t) { var ms = Date.parse(t || ''); return isNaN(ms) ? (t || '–') : dayWords(new Date(ms)); }
  function certTable(list) {
    return listTable(['It is', 'Signed by', 'Good from', 'Good until', 'Fingerprint (SHA-256)', ''], list, function (c) {
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
      var tools = el('td', 'rowtools');
      if (ADMIN && NT.d && NT.d.ca_ours) {
        var x = iconButton('trash', 'Take this certificate out');
        x.onclick = function () {
          confirmThen('Take this certificate out', '<b>' + htmlText(c.subject || 'this certificate')
            + '</b> is no longer trusted for the ntfy server. The others stay.', 'Take it out', function () {
              api('upnp-ntfy', {action: 'ca', mode: 'drop', fingerprint: c.fingerprint}).then(function (r) {
                toast(r.message, 'good'); load(); loadSettings(!Object.keys(DIRTY).length);
              }).catch(oops);
            });
        };
        tools.appendChild(x);
      }
      tr.appendChild(tools);
      return tr;
    }, 'plain', {own: true});
  }
  function draw() {
    var d = NT.d;
    if (!d) return;
    $('nt-said').textContent = d.on ? 'to ' + d.server + ' · ' + (d.auth === 'none' ? 'no sign-in' : 'signed in with ' + d.auth) : 'switched off - no topic URL';
    /* What was sent. */
    var rows = d.sends || [];
    $('nt-when').textContent = rows.length ? 'the last one ' + ago(rows[0].at) : '';
    var ks = $('nt-kind'), kinds = (d.send_kinds || []).slice();
    if (NT.kind && kinds.indexOf(NT.kind) < 0) kinds.push(NT.kind);
    clear(ks);
    [['', 'every kind']].concat(kinds.map(function (k) { return [k, kindWords(k)]; })).forEach(function (p) {
      var o = el('option', '', p[1]); o.value = p[0]; ks.appendChild(o);
    });
    ks.value = NT.kind;
    var host = $('nt-sends');
    clear(host);
    host.appendChild(listTable(['When', 'What', 'Title', 'To', 'Sent', 'What the server said', 'By'], rows, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.at));
      var k = el('td');
      var kt = el('span', 'tag ' + (KIND_TAG[r.kind] || 'dim'), kindWords(r.kind));
      kt.title = r.kind + (r.why ? ' - ' + r.why : '');
      kt.style.cursor = 'pointer';
      kt.onclick = function () { NT.kind = NT.kind === r.kind ? '' : r.kind; load(); };
      k.appendChild(kt);
      tr.appendChild(k);
      tr.appendChild(noI18n(el('td', '', r.title || '')));
      tr.appendChild(noI18n(el('td', 'mono small', r.host || '')));
      var s = el('td'); s.appendChild(el('span', 'tag ' + (r.ok ? 'ok' : 'crit'), r.ok ? 'sent' : 'failed')); tr.appendChild(s);
      tr.appendChild(noI18n(el('td', 'small ' + (r.ok ? 'muted' : 'bad'), r.said || '')));
      tr.appendChild(noI18n(el('td', 'muted small', r.by || '')));
      return tr;
    }, 'plain|' + (NT.kind ? 'Nothing of this kind was sent' : 'Nothing has been sent yet' + (d.on ? '' : ' - notifications are switched off')), {own: true}));
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
      box.dispatchEvent(new Event('input'));
      toast('read ' + file.name + ' - Save the changes adds it', 'good');
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
  /* As otp's Mail: no Add it - what is pasted waits for the save bar at the bottom. */
  $('nca-save').hidden = true;
  $('nca-pem').addEventListener('input', function () {
    if (!$('nca-pem').value.trim()) { delete PENDING.nca; markDirtyCount(); return; }
    pendingSet('nca', {save: function () {
      return api('upnp-ntfy', {action: 'ca', mode: 'add', ca: $('nca-pem').value.trim()}).then(function (r) {
        toast(r.message, 'good'); $('nca-pem').value = ''; load(); return true;
      });
    }, reset: function () { $('nca-pem').value = ''; }});
  });
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
  PANE_LOAD.ntfy = function () { return loadEv().then(load); };
  PANE_TICK.ntfy = function () {
    if (document.activeElement && $('pane-ntfy').contains(document.activeElement) && /^(TEXTAREA|INPUT|SELECT)$/.test(document.activeElement.tagName)) return;
    if (!PENDING.ntev) {
      api('ntfy').then(function (d) {
        var same = function (x) { return JSON.stringify(x, function (k, v) { return k === 'at' ? undefined : v; }); };
        var was = same(EV.d);
        EV.d = d;
        if (was !== same(d)) { EV.edit = fromView(d); drawEv(); }
      }).catch(function () {});
    }
    api(sendsPath()).then(function (d) {
      var was = JSON.stringify([NT.d && NT.d.sends, NT.d && NT.d.ca_list, NT.d && NT.d.url]);
      NT.d = d;
      if (was !== JSON.stringify([d.sends, d.ca_list, d.url])) draw();
    }).catch(function () {});
  };
})();
