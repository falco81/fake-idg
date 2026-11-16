/* pane-tls.js - Settings → Certificates and TLS (otp's loadWeb, certCard, certUpload,
   certRequest, certSelf, certPolicy - for one server: no VIP address, no acme push). */
(function () {
  'use strict';
  var TLS = {last: null, out: false};

  function daysLeft(ts) { return ts ? Math.floor((ts - Date.now() / 1000) / 86400) : null; }
  function certTone(days) { return days === null ? 'dim' : (days < 0 ? 'crit' : (days < 21 ? 'warn' : 'ok')); }
  function saveText(name, text, type) {
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([text], {type: type || 'application/x-pem-file'}));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function loadTls() {
    if (TLS.out) return;
    TLS.out = true;
    api('tls').then(drawTls).catch(oops).then(function () { TLS.out = false; });
  }
  PANE_LOAD.tls = loadTls;
  PANE_TICK.tls = function () {
    if ($('modal') && !$('modal').hidden) return;
    if (TLS.out) return;
    TLS.out = true;
    api('tls').then(function (d) { drawTls(d); }).catch(function () {}).then(function () { TLS.out = false; });
  };

  function drawTls(d) {
    TLS.last = d;
    liveFill($('tls-certs'), function (host) {
      host.appendChild(certCard(d));
    }, undefined, function () { explainWhatWasDrawn($('pane-tls')); });
  }

  function certCard(d) {
    var cur = d.cert || null;
    var info = cur && cur.info ? cur.info : null;
    var card = el('section', 'cert-card');
    var head = el('header', 'cert-h');
    var title = el('div', 'cert-title');
    title.appendChild(el('span', 'cert-target', 'This server'));
    title.appendChild(noI18n(el('b', '', d.host || '–')));
    title.appendChild(el('span', 'tag dim', 'this one'));
    var where = (d.names || []).concat(d.ips || []);
    title.appendChild(el('span', 'cert-for', 'the certificate answered on ' + (where.length ? where.join(', ') : 'every name and address of this server')));
    head.appendChild(title);
    var days = info ? daysLeft(info.not_after) : null;
    head.appendChild(el('span', 'tag ' + certTone(days), days === null ? 'no certificate' :
      (days < 0 ? 'ran out' : (days < 21 ? days + ' days left' : 'valid'))));
    card.appendChild(head);
    if (info) {
      var b = el('div', 'cert-body');
      b.appendChild(noI18n(el('div', 'cert-cn', info.cn || info.subject || '')));
      var bar = el('div', 'cert-life');
      var span = info.not_after && info.not_before ? (info.not_after - info.not_before) : 1;
      var used = info.not_before ? Math.max(0, Math.min(1, (Date.now() / 1000 - info.not_before) / span)) : 0;
      var fill = el('span', 'cert-life-fill ' + certTone(days));
      fill.style.width = Math.round(used * 100) + '%';
      bar.appendChild(fill);
      b.appendChild(bar);
      var alt = cur.alt && cur.alt.info;
      var facts = [['Subject', noI18n(el('span', '', info.subject || '–'))],
                   ['Issued by', noI18n(el('span', '', info.self_signed ? 'itself (self-signed)' : (info.issuer || '').replace(/^CN=/, '')))],
                   ['Valid from', info.not_before ? stamp(info.not_before) : '–'],
                   ['Valid until', info.not_after ? stamp(info.not_after) : '–'],
                   ['Key', (info.key || '–') + (alt && alt.key ? ' + ' + alt.key + ' (a second certificate beside it)' : '')]];
      if (info.san && info.san.length) facts.push(['Names', noI18n(el('span', '', info.san.join(', ')))]);
      var chainEl = el('span', '');
      var cs = cur.chain_state || {};
      if (info.self_signed) chainEl.textContent = 'none - signed by itself';
      else if (cs.ok === false) { chainEl.className = 'bad'; chainEl.textContent = cs.words; }
      else if (cs.ok) { chainEl.className = 'good'; chainEl.textContent = cs.words; }
      else chainEl.textContent = (cur.chain_info || []).length + ' between it and the root' + (cs.words ? ' (' + cs.words + ')' : '');
      facts.push(['Chain', chainEl]);
      if ((cur.chain_info || []).length) {
        facts.push(['Authorities', noI18n(el('span', '', cur.chain_info.map(function (c) { return c.cn || c.subject; }).join(' → ')))]);
      }
      if (info.fingerprint) facts.push(['SHA-256', noI18n(el('span', 'mono small', info.fingerprint))]);
      var kv = el('dl', 'cert-kv');
      facts.forEach(function (f) {
        kv.appendChild(el('dt', '', f[0]));
        var dd = el('dd');
        if (f[1] && f[1].nodeType) dd.appendChild(f[1]); else dd.textContent = f[1];
        kv.appendChild(dd);
      });
      b.appendChild(kv);
      card.appendChild(b);
    } else {
      card.appendChild(el('p', 'note', cur && cur.error ? 'nginx\'s certificate does not read: ' + cur.error
        : 'There is no certificate in nginx\'s file yet.'));
    }
    /* How TLS is spoken, as chips. */
    var pol = d.policy || {};
    var chips = el('div', 'cert-chips');
    chips.appendChild(el('span', 'cchip', {standard: 'TLS 1.2 + 1.3, ECDHE', intermediate: 'Mozilla intermediate', modern: 'TLS 1.3 only', custom: 'custom'}[pol.preset] || pol.preset));
    if (pol.dh && pol.dh !== 'none') chips.appendChild(noI18n(el('span', 'cchip', 'DH ' + pol.dh)));
    if (pol.hsts) chips.appendChild(el('span', 'cchip', 'HSTS ' + Math.round(pol.hsts / 86400) + ' days'));
    if (d.pending) chips.appendChild(el('span', 'cchip warn', 'a request waits for its certificate'));
    var ac = d.acme || {};
    if (ac.on) {
      var ach = el('span', 'cchip' + (ac.care ? '' : ' dim'), ac.care ? 'renewed by ACME' : 'ACME leaves it alone');
      explain(ach, ac.care ? 'Settings → Automatic certificates renews it before it runs out. Uploading one here, or making one self-signed, takes it out of ACME’s care - it is kept as it is.'
        : 'Kept as it is: Automatic certificates does not replace it (Look after it there gives it to ACME).');
      ach.style.cursor = 'pointer';
      ach.onclick = function () { showPane('acme'); };
      chips.appendChild(ach);
      if (ac.care && ac.state && ac.state.ok === false) chips.appendChild(el('span', 'cchip warn', 'the last order failed'));
    }
    if (!d.how) chips.appendChild(el('span', 'cchip dim', 'as install.sh made it'));
    else chips.appendChild(el('span', 'cchip dim', {uploaded: 'uploaded here', 'self-signed': 'made here, self-signed', ACME: 'from the CA (ACME)'}[d.how] || d.how));
    card.appendChild(chips);
    /* What root did with the last ask. */
    var r = d.root;
    if (r) {
      var st = el('div', 'cert-state');
      var bad = r.state === 'failed' || r.state === 'late';
      st.appendChild(el('span', 'dot ' + (bad ? 'crit' : (r.state === 'done' ? 'ok' : 'warn'))));
      var what = {put: 'the certificate', policy: 'the TLS settings', put_back: 'the certificate from before ACME', acme_http: 'the ACME location of port 80'}[r.action] || 'it';
      st.appendChild(el('span', '', r.state === 'failed' ? 'root could not put ' + what + ' in: ' + ((r.said || []).slice(-1)[0] || '')
        : (r.state === 'done' ? what + ' in place - ' + ((r.said || [])[0] || '') + ' (' + ago(r.at) + ')'
          : (r.state === 'late' ? (r.said || [])[0] : what + ' being put in…'))));
      card.appendChild(st);
    }
    if (d.may) {
      var tools = el('div', 'cert-tools');
      var byHand = function (go) {
        if (!(ac.on && ac.care)) { go(); return; }
        confirmThen('ACME renews this certificate', 'One put in here by hand takes this server out of ACME’s care: it is kept as it is, not replaced at the next renewal. Settings → Automatic certificates → Look after it gives it back.', 'Go on', go, false);
      };
      var up = cmdButton('Upload', 'upload', 'small');
      up.onclick = function () { byHand(function () { certUpload(d); }); };
      tools.appendChild(up);
      var req = cmdButton(d.pending ? 'The waiting request' : 'Request (CSR)', 'list', 'small');
      req.onclick = function () { certRequest(d); };
      tools.appendChild(req);
      var ss = cmdButton('Self-signed', 'key', 'small');
      ss.onclick = function () { byHand(function () { certSelf(d); }); };
      tools.appendChild(ss);
      var pb = cmdButton('TLS settings', 'gear', 'small');
      explain(pb, 'The protocols, the ciphers, the DH parameters and HSTS of these pages - kept as they are whichever way the certificate came, ACME and its renewals too.');
      pb.onclick = function () { certPolicy(d); };
      tools.appendChild(pb);
      if (cur && cur.pem) {
        var dl = cmdButton('Download', 'download', 'small');
        dl.title = 'The certificate, PEM - alone or with its chain';
        dl.onclick = function () { certExport(d); };
        tools.appendChild(dl);
      }
      card.appendChild(tools);
    }
    return card;
  }

  /* Files read in the browser: PEM as text, a PFX as base64 (otp's readCertFiles). */
  function readCertFiles(files) {
    return Promise.all(Array.prototype.map.call(files, function (f) {
      return new Promise(function (ok, bad) {
        if (f.size > 200000) { bad(new Error(f.name + ' is far bigger than any certificate file')); return; }
        var r = new FileReader();
        r.onload = function () {
          var bytesArr = new Uint8Array(r.result);
          var text = new TextDecoder().decode(bytesArr);
          if (/-----BEGIN /.test(text)) { ok({name: f.name, pem: text}); return; }
          var bin = '';
          for (var i = 0; i < bytesArr.length; i++) bin += String.fromCharCode(bytesArr[i]);
          ok({name: f.name, pfx: btoa(bin)});
        };
        r.onerror = function () { bad(new Error(f.name + ' could not be read')); };
        r.readAsArrayBuffer(f);
      });
    }));
  }

  var CERT_PASTE_HINT = '-----BEGIN CERTIFICATE-----\n' +
    '1. the certificate of this name (the server\'s own)\n' +
    '-----END CERTIFICATE-----\n' +
    '-----BEGIN CERTIFICATE-----\n' +
    '2. the intermediate certificate(s), if there are any - one block each\n' +
    '-----END CERTIFICATE-----\n' +
    '-----BEGIN CERTIFICATE-----\n' +
    '3. the root certificate (optional)\n' +
    '-----END CERTIFICATE-----\n' +
    '-----BEGIN PRIVATE KEY-----\n' +
    '4. its private key (not needed when the request was made here)\n' +
    '-----END PRIVATE KEY-----\n\n' +
    'Any order is taken: they are sorted by themselves.';

  function certUpload(d) {
    var got = [];
    modal('A certificate for these pages', function (body) {
      body.appendChild(el('p', 'note', 'PEM files - the certificate, its key, the chain, the root, in any order or all in one - or one PFX / PKCS#12 file. Checked here before root puts it in: the key is the certificate\'s own, it has not run out, and the chain leads to a root. ' +
        (d.pending ? 'A request waits here: the certificate the authority sent back is enough, its key is here.' : 'The key has to come with it.')));
      var drop = el('div', 'drop');
      var inp = el('input'); inp.type = 'file'; inp.multiple = true; inp.hidden = true;
      inp.accept = '.pem,.crt,.cer,.key,.pfx,.p12,.chain,.ca,.txt';
      var says = el('span', '', 'Drop the files here, or press to choose them');
      drop.appendChild(inp); drop.appendChild(says);
      var list = el('div', 'cert-files');
      function take(files) {
        readCertFiles(files).then(function (r) {
          got = got.concat(r);
          clear(list);
          got.forEach(function (x) { list.appendChild(noI18n(el('span', 'cchip', x.name + (x.pfx ? ' (PFX)' : ' (PEM)')))); });
          says.textContent = 'Read: ' + got.length + ' file(s). More can be added.';
        }).catch(oops);
      }
      drop.onclick = function () { inp.click(); };
      inp.onchange = function () { take(inp.files); inp.value = ''; };
      drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
      drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); take(e.dataTransfer.files); });
      body.appendChild(drop);
      body.appendChild(list);
      var paste = el('textarea', 'mono cert-paste');
      paste.id = 'tu-paste';
      paste.rows = 16;
      paste.placeholder = CERT_PASTE_HINT;
      paste.spellcheck = false;
      body.appendChild(formField('Or paste PEM here', paste));
      var pw = secretBox('', 'only for a PFX or a key with a passphrase', 'mono');
      pw.id = 'tu-pw';
      body.appendChild(formField('Password', pw, 'Used here to open it, and not kept.'));
      body.appendChild(el('div', 'said', '')).id = 'tu-said';
    }, [{words: 'Cancel', close: true},
        {words: 'Put it in', cls: 'primary', icon: 'save', go: function (b) {
          var pem = got.filter(function (x) { return x.pem; }).map(function (x) { return x.pem; }).join('\n') + '\n' + ($('tu-paste').value || '');
          var pfx = got.filter(function (x) { return x.pfx; });
          if (pfx.length > 1) { toast('one PFX / PKCS#12 file at most', 'bad'); return; }
          if (!pfx.length && !/-----BEGIN /.test(pem)) { toast('choose the files first, or paste the PEM', 'bad'); return; }
          busy(b, true);
          api('tls', {action: 'tls_upload', cert: pem, pfx: pfx.length ? pfx[0].pfx : '',
                      password: (($('tu-pw') || {}).value) || ''}).then(function (x) {
            toast(x.message, 'good'); closeModal(); drawTls(x);
          }).catch(function (e) { $('tu-said').className = 'said bad'; $('tu-said').textContent = e.message; }).then(function () { busy(b, false); });
        }}], 'medium');
  }

  function certSubjectFields(body, d, withDays) {
    var g = el('div', 'formgrid');
    var names = (d.names || []).slice();
    var cn = textBox(names.shift() || d.host || '', 'igd.example.cz', 'mono'); cn.id = 'tcs-cn';
    var other = textBox(withDays ? names.concat(d.ips || []).join(', ') : names.join(', '), 'igd.example.cz, 192.0.2.11', 'mono'); other.id = 'tcs-names';
    var kind = selectBox([['rsa2048', 'RSA 2048'], ['rsa3072', 'RSA 3072'], ['rsa4096', 'RSA 4096'], ['ec', 'EC P-256']], 'rsa2048'); kind.id = 'tcs-kind';
    g.appendChild(formField('The name (CN)', cn, 'What people type in the browser.'));
    g.appendChild(formField('Other names', other, withDays ? 'More names or addresses it is good for, by commas - nginx\'s server_name and this machine\'s IPv4 addresses to begin with.' : 'More names or addresses it is good for, by commas.'));
    g.appendChild(formField('The key', kind));
    var org = textBox('', 'Krajský úřad'); org.id = 'tcs-org';
    g.appendChild(formField('Organisation', org));
    if (withDays) {
      var days = selectBox([['365', '1 year'], ['825', '27 months'], ['1825', '5 years'], ['3650', '10 years']], '825'); days.id = 'tcs-days';
      g.appendChild(formField('Valid for', days));
    } else {
      var unit = textBox('', 'IT'); unit.id = 'tcs-unit';
      var city = textBox('', 'Olomouc'); city.id = 'tcs-city';
      var country = textBox('CZ', 'CZ'); country.id = 'tcs-country'; country.maxLength = 2;
      g.appendChild(formField('Unit', unit));
      g.appendChild(formField('City', city));
      g.appendChild(formField('Country', country));
    }
    body.appendChild(g);
  }
  function certSubjectValues() {
    var v = function (id) { return ($(id) || {}).value || ''; };
    return {cn: v('tcs-cn').trim(), names: v('tcs-names'), kind: v('tcs-kind'), org: v('tcs-org'),
            unit: v('tcs-unit'), city: v('tcs-city'), country: v('tcs-country'), days: v('tcs-days')};
  }

  function certRequest(d) {
    if (d.pending && d.csr) { showCsr(d.csr); return; }
    modal('A certificate request for these pages', function (body) {
      body.appendChild(el('p', 'note', 'A new key is made here and stays here; the request (CSR) goes to your certificate authority. Upload what it sends back - the certificate alone is enough.'));
      certSubjectFields(body, d, false);
    }, [{words: 'Cancel', close: true},
        {words: 'Make the request', cls: 'primary', icon: 'list', go: function (b) {
          busy(b, true);
          api('tls', Object.assign({action: 'tls_csr'}, certSubjectValues())).then(function (x) {
            closeModal(); drawTls(x); showCsr(x.csr);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function showCsr(csr) {
    modal('The request for these pages', function (body) {
      body.appendChild(el('p', 'note', 'Give this to your certificate authority. The key waits here; once the certificate comes back, upload it.'));
      var pre = noI18n(el('pre', 'mono cert-csr', csr));
      copyOnClick(pre, csr, 'the request was copied');
      body.appendChild(pre);
    }, [{words: 'Drop the request', icon: 'trash', go: function () {
          modalOver(function () {
            confirmThen('Drop the request', 'Its waiting key goes too; a certificate made for it can then not be used.', 'Drop it', function () {
              api('tls', {action: 'tls_csr_drop'}).then(function (x) { toast(x.message, 'good'); closeModal(); drawTls(x); }).catch(oops);
            }, true);
          });
        }},
        {words: 'Download .csr', icon: 'download', go: function () { saveText(((TLS.last || {}).host || 'fake-igd') + '.csr', csr); }},
        {spacer: true},
        {words: 'Upload the certificate…', cls: 'primary', icon: 'upload', go: function () { closeModal(); certUpload({pending: true}); }},
        {words: 'Close', close: true}], 'medium');
  }

  function certSelf(d) {
    modal('A self-signed certificate for these pages', function (body) {
      body.appendChild(el('p', 'note warn', 'Browsers warn about a self-signed certificate until it is trusted by hand. Good for a test, or until the real one comes.'));
      certSubjectFields(body, d, true);
    }, [{words: 'Cancel', close: true},
        {words: 'Make it and put it in', cls: 'primary', icon: 'key', go: function (b) {
          busy(b, true);
          api('tls', Object.assign({action: 'tls_selfsigned'}, certSubjectValues())).then(function (x) {
            toast(x.message, 'good'); closeModal(); drawTls(x);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }

  function certExport(d) {
    var cur = d.cert || {};
    var kind;
    modal('Download the certificate', function (body) {
      body.appendChild(el('p', 'note', 'The certificate nginx answers with now. Its private key stays with root and is never sent to the pages.'));
      kind = selectBox([['pem', 'the certificate, PEM (.crt)'], ['fullchain', 'the certificate and its chain, PEM (-fullchain.pem)']], 'pem');
      body.appendChild(formField('Format', kind));
    }, [{words: 'Cancel', close: true},
        {words: 'Download', cls: 'primary', icon: 'download', go: function () {
          var name = ((cur.info || {}).cn || d.host || 'fake-igd').replace(/[^A-Za-z0-9._-]/g, '_');
          if (kind.value === 'fullchain') saveText(name + '-fullchain.pem', cur.pem + (cur.chain || ''));
          else saveText(name + '.crt', cur.pem);
          closeModal();
        }}], 'small');
  }

  function tlsRow(words, says, control) {
    var row = el('div', 'arow');
    var t = el('div', 'arow-t');
    t.appendChild(el('div', 'arow-k', words));
    t.appendChild(el('div', 'arow-s', says));
    row.appendChild(t);
    var c = el('div', 'arow-c');
    c.appendChild(control);
    row.appendChild(c);
    return row;
  }

  function certPolicy(d) {
    var prof = d.policy || {};
    var st = {preset: prof.preset || 'standard', protocols: (prof.protocols || ['TLSv1.2', 'TLSv1.3']).slice(),
              ciphers: prof.ciphers || (d.presets.standard || {}).ciphers || '',
              dh: d.dh[prof.dh] ? prof.dh : 'none', prefer: !!prof.prefer,
              hsts: (prof.hsts === undefined || prof.hsts === null) ? 63072000 : Number(prof.hsts)};
    var PRESETS = [
      ['standard', 'Standard', 'TLS 1.2 + 1.3', 'ECDHE with AES-GCM and ChaCha20. Every browser of the last ten years.', 'recommended'],
      ['intermediate', 'Mozilla intermediate', 'TLS 1.2 + 1.3', 'Adds the DHE ciphers, for old clients. Wants DH parameters.', ''],
      ['modern', 'Mozilla modern', 'TLS 1.3 only', 'The strongest; old systems and some scanners cannot connect.', ''],
      ['custom', 'Custom', 'chosen here', 'The protocols and an OpenSSL cipher list of your own.', '']];
    var dhRow;
    modal('How these pages speak TLS', function (body) {
      body.appendChild(el('h4', 'tls-h', 'Protocols and ciphers'));
      var tiles = el('div', 'tls-tiles');
      var custom = el('div', 'tls-custom');
      var used = el('details', 'tls-used');
      function paint() {
        Array.prototype.forEach.call(tiles.children, function (t) { t.classList.toggle('on', t.dataset.k === st.preset); });
        custom.hidden = st.preset !== 'custom';
        used.hidden = st.preset === 'custom';
        var p = d.presets[st.preset];
        if (p) {
          clear(used);
          used.appendChild(el('summary', '', 'The ciphers it uses'));
          used.appendChild(noI18n(el('code', 'tls-cipherlist', p.ciphers ? p.ciphers.split(':').join('\n') : 'TLS 1.3 chooses its own: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256')));
        }
        if (dhRow) dhRow.classList.toggle('dim', st.preset === 'modern' || (st.preset === 'standard' && st.dh === 'none'));
      }
      PRESETS.forEach(function (p) {
        var t = el('button', 'tls-tile');
        t.type = 'button';
        t.dataset.k = p[0];
        var top = el('div', 'tls-tile-top');
        top.appendChild(el('b', '', p[1]));
        if (p[4]) top.appendChild(el('span', 'tag ok', p[4]));
        t.appendChild(top);
        t.appendChild(el('div', 'tls-tile-prot', p[2]));
        t.appendChild(el('div', 'tls-tile-s', p[3]));
        t.onclick = function () { st.preset = p[0]; paint(); };
        tiles.appendChild(t);
      });
      body.appendChild(tiles);
      var prow = el('div', 'tls-prot');
      ['TLSv1.2', 'TLSv1.3'].forEach(function (v) {
        var b = el('button', 'tls-pill');
        b.type = 'button';
        b.textContent = v.replace('TLSv', 'TLS ');
        noI18n(b);
        var sync = function () { b.classList.toggle('on', st.protocols.indexOf(v) >= 0); };
        b.onclick = function () {
          var i = st.protocols.indexOf(v);
          if (i >= 0 && st.protocols.length > 1) st.protocols.splice(i, 1); else if (i < 0) st.protocols.push(v);
          sync();
        };
        sync();
        prow.appendChild(b);
      });
      custom.appendChild(el('div', 'tls-sub', 'Protocols'));
      custom.appendChild(prow);
      var ciphers = el('textarea', 'mono tls-ciphers');
      ciphers.rows = 4; ciphers.spellcheck = false; ciphers.value = st.ciphers;
      ciphers.oninput = function () { st.ciphers = ciphers.value; };
      custom.appendChild(el('div', 'tls-sub', 'Ciphers for TLS 1.2 (an OpenSSL list; TLS 1.3 chooses its own)'));
      custom.appendChild(ciphers);
      body.appendChild(custom);
      body.appendChild(used);
      body.appendChild(el('h4', 'tls-h', 'More'));
      var rows = el('div', 'tls-rows');
      var dh = selectBox(Object.keys(d.dh).map(function (k) { return [k, d.dh[k]]; }), st.dh);
      dh.onchange = function () { st.dh = dh.value; paint(); };
      dhRow = tlsRow('DH parameters', 'Only the DHE ciphers use them (Mozilla intermediate, or your own). An RFC 7919 group is ready at once; made here takes from seconds to minutes.', dh);
      rows.appendChild(dhRow);
      var prefer = switchBox(st.prefer);
      prefer._input.onchange = function () { st.prefer = !!prefer._get(); };
      rows.appendChild(tlsRow('The server chooses the cipher', 'Off is right for these lists: every cipher in them is strong, and the client knows best which is fast for it.', prefer));
      var seg = el('div', 'seg');
      [[0, 'off'], [15768000, '6 months'], [31536000, '1 year'], [63072000, '2 years']].forEach(function (o) {
        var b = el('button', '', o[1]);
        b.type = 'button';
        b.onclick = function () { st.hsts = o[0]; Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); };
        if (st.hsts === o[0]) b.classList.add('on');
        seg.appendChild(b);
      });
      if (!seg.querySelector('.on')) seg.children[0].classList.add('on');
      rows.appendChild(tlsRow('HSTS', 'A browser that saw it comes back only over HTTPS for that long. Turn it on once HTTPS is surely staying.', seg));
      body.appendChild(rows);
      paint();
    }, [{words: 'Cancel', close: true},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
          busy(b, true);
          api('tls', {action: 'tls_policy', preset: st.preset, protocols: st.protocols,
                      ciphers: String(st.ciphers || '').trim(), dh: st.dh, prefer: st.prefer ? 1 : 0,
                      hsts: st.hsts}).then(function (x) {
            toast(x.message, 'good'); closeModal(); drawTls(x);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
}());
