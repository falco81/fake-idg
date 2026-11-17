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

  /* The name the browser reached these pages by - when it is a DNS name, not an address. */
  function reachedAs() {
    var h = String(location.hostname || '').toLowerCase().replace(/\.$/, '');
    if (!h || h === 'localhost' || /^[0-9.]+$/.test(h) || h.indexOf(':') >= 0 || h.indexOf('.') < 0) return '';
    return h;
  }
  /* Does a list of names (a certificate's, or server_name's) name this host - wildcards too? */
  function names(list, h) {
    return (list || []).some(function (n) {
      n = String(n || '').toLowerCase();
      if (n === h) return true;
      return n.indexOf('*.') === 0 && h.split('.').slice(1).join('.') === n.slice(2);
    });
  }
  function uniq(list) {
    var out = [];
    list.forEach(function (x) { x = String(x || '').trim(); if (x && x !== '_' && out.indexOf(x) < 0) out.push(x); });
    return out;
  }
  /* "Add its names to nginx's server_name" - asked when a certificate goes in (default yes). */
  function addNamesBox(body) {
    var lab = el('label', 'check small');
    var cb = el('input'); cb.type = 'checkbox'; cb.checked = true; cb.id = 'tcs-add';
    lab.appendChild(cb);
    lab.appendChild(el('span', '', 'Add its names to nginx\'s server_name where they are missing (nginx -t first; put back when it says no)'));
    var row = el('div', '');
    row.style.marginTop = '10px';
    row.appendChild(lab);
    body.appendChild(row);
  }
  function addNames() { var cb = $('tcs-add'); return !!(cb && cb.checked); }

  function loadTls() {
    if (TLS.out) return;
    TLS.out = true;
    api('tls').then(drawTls).catch(oops).then(function () { TLS.out = false; });
  }
  PANE_LOAD.tls = function () { loadTls(); osrLoad(); };
  PANE_TICK.tls = function () {
    if ($('modal') && !$('modal').hidden) return;
    osrTick();
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
    var reached = reachedAs();
    title.appendChild(el('span', 'cert-target', 'This server'));
    title.appendChild(noI18n(el('b', '', reached || (info && info.cn) || d.host || '–')));
    title.appendChild(el('span', 'tag dim', 'this one'));
    var where = (d.names || []).concat(d.ips || []);
    /* The machine's own host name, said as the machine's - not one of the certificate's names; on the
       line under it, in the same box (one .cert-for, as otp's, so the cards stand level). */
    var fr = el('span', 'cert-for', 'the certificate answered on ' + (where.length ? where.join(', ') : 'every name and address of this server'));
    fr.appendChild(el('br'));
    fr.appendChild(document.createTextNode('this machine: '));
    fr.appendChild(noI18n(el('span', 'mono', d.machine || d.host || '?')));
    title.appendChild(fr);
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
      /* The chain as clients that fetch nothing check it (otp 1.0.269): curl, a VPN client - checked
         with the root kept beside a private authority's certificate too. */
      var chainEl = el('span', '');
      var cs = cur.chain_state || null;
      if (info.self_signed) chainEl.textContent = cur.chain_info ? (cur.chain_info.length + ' between it and the root') : '–';
      else if (cs && cs.ok === false) { chainEl.className = 'bad'; chainEl.textContent = cs.words; }
      else if (cs && cs.ok) { chainEl.className = 'good'; chainEl.textContent = cs.words; }
      else chainEl.textContent = cur.chain_info ? (cur.chain_info.length + ' between it and the root') : '–';
      facts.push(['Chain', chainEl]);
      if ((cur.chain_info || []).length) {
        facts.push(['Authorities', noI18n(el('span', '', cur.chain_info.map(function (c) { return c.cn || c.subject; }).join(' → ')))]);
      }
      /* The second (ECDSA) certificate's chain (otp 1.0.270): the one most clients take. */
      var acs = (cur.alt && cur.alt.chain_state) || null;
      if (acs && acs.words && (acs.ok === false || (acs.fetched && acs.fetched.length)))
        facts.push(['Chain (second)', el('span', acs.ok === false ? 'bad' : 'good', acs.words)]);
      facts.push(['Root', cur.root_info && cur.root_info.length ? noI18n(el('span', '', cur.root_info[0].cn || 'given')) : 'not given']);
      /* nginx checked as a client that fetches nothing, after it took the certificate (otp's Sent). */
      var sc = cur.sent;
      if (sc && sc.words && (sc.ok !== null && sc.ok !== undefined || sc.same === false) && !info.self_signed)
        facts.push(['Sent', el('span', sc.ok ? 'good' : 'bad', sc.words)]);
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
      /* The name the browser came by, not named (otp says so for a node's name too). */
      if (reached && !names([info.cn].concat(info.san || []), reached))
        card.appendChild(el('p', 'note warn', 'You reached these pages as ' + reached + ' - the certificate does not name it (it names ' + (uniq([info.cn].concat(info.san || [])).join(', ') || 'nothing') + '): the browser warns. Self-signed or a new request, below, starts from it.'));
    } else {
      card.appendChild(el('p', 'note', cur && cur.error ? 'nginx\'s certificate does not read: ' + cur.error
        : 'There is no certificate in nginx\'s file yet.'));
    }
    if (reached && (d.names || []).length && !names(d.names, reached))
      card.appendChild(el('p', 'note warn', 'nginx\'s server_name does not name ' + reached + ' (it has ' + d.names.join(', ') + ') - a certificate put in here can add it.'));
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
    /* How the one there came - said only while there is one (a file gone since is not "uploaded here"). */
    else if (info) chips.appendChild(el('span', 'cchip dim', {uploaded: 'uploaded here', 'self-signed': 'made here, self-signed', ACME: 'from the CA (ACME)'}[d.how] || d.how));
    card.appendChild(chips);
    /* What root did with the last ask. */
    var r = d.root;
    if (r && r.state === 'working' && r.progress) {
      card.appendChild(certProgress(r.progress));
    } else if (r) {
      var st = el('div', 'cert-state');
      var bad = r.state === 'failed' || r.state === 'late';
      st.appendChild(el('span', 'dot ' + (bad ? 'crit' : (r.state === 'done' ? 'ok' : 'warn'))));
      var what = {put: 'the certificate', policy: 'the TLS settings', put_back: 'the certificate from before ACME', acme_http: 'the ACME location of port 80', chain: 'the chain'}[r.action] || 'it';
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
      var bef = d.before;
      if (bef && !bef.ran_out && ac.on) tools.appendChild(putBackButton(bef));
      if (cur && cur.pem && info && !info.self_signed) {
        /* Complete the chain (otp 1.0.269): checked again against the system's roots, the missing
           intermediates fetched from their CA Issuers addresses - as browsers do. */
        var cs2 = cur.chain_state || {};
        var sc2 = cur.sent || {};
        var bad = cs2.ok === false || ((cur.alt && cur.alt.chain_state) || {}).ok === false ||
          (sc2.same && sc2.ok === false && !(cs2.ok && cur.root_info && cur.root_info.length));
        var ch = cmdButton(bad ? 'Complete the chain' : 'Check the chain', 'refresh', bad ? 'small primary' : 'small');
        explain(ch, 'Checked against the system\'s root authorities; an intermediate the certificate did not come with is fetched from its CA Issuers address, as browsers do it - so that curl, a VPN client and other clients that fetch nothing take it too.');
        ch.onclick = function () {
          busy(ch, true);
          api('tls', {action: 'tls_chain'}).then(function (x) { toast(x.message, x.complete ? 'good' : 'warn'); drawTls(x); })
            .catch(oops).then(function () { busy(ch, false); });
        };
        tools.appendChild(ch);
        /* Or by hand: when it cannot be fetched - no CA Issuers address, no way out, a private CA -
           only the missing authority, never the certificate and its key again. */
        if (bad) {
          var addc = cmdButton('Upload the missing authority', 'upload', 'small');
          addc.onclick = function () { certChainAdd(d); };
          tools.appendChild(addc);
        }
      }
      if (cur && cur.pem) {
        var dl = cmdButton('Download', 'download', 'small');
        dl.title = 'The certificate in the format chosen - PEM, DER, PKCS#7, or PFX with its private key';
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
      body.appendChild(el('p', 'note', 'PEM files - the certificate, its key, the chain, the root, in any order or all in one - or one PFX / PKCS#12 file. An RSA and an ECDSA certificate of the same names together (both keys in the PEM, or two PFX files): both are put in, the ECDSA one beside - nginx gives each client the one it takes. ' +
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
      addNamesBox(body);
      body.appendChild(el('div', 'said', '')).id = 'tu-said';
    }, [{words: 'Cancel', close: true},
        {words: 'Put it in', cls: 'primary', icon: 'save', go: function (b) {
          var pem = got.filter(function (x) { return x.pem; }).map(function (x) { return x.pem; }).join('\n') + '\n' + ($('tu-paste').value || '');
          var pfx = got.filter(function (x) { return x.pfx; });
          if (pfx.length > 2) { toast('two PFX / PKCS#12 files at most - an RSA and an ECDSA one', 'bad'); return; }
          if (!pfx.length && !/-----BEGIN /.test(pem)) { toast('choose the files first, or paste the PEM', 'bad'); return; }
          busy(b, true);
          api('tls', {action: 'tls_upload', cert: pem, pfx: pfx.length ? pfx[0].pfx : '',
                      pfx2: pfx.length > 1 ? pfx[1].pfx : '',
                      password: (($('tu-pw') || {}).value) || '', add_names: addNames()}).then(function (x) {
            toast(x.message, 'good'); closeModal(); drawTls(x);
          }).catch(function (e) { $('tu-said').className = 'said bad'; $('tu-said').textContent = e.message; }).then(function () { busy(b, false); });
        }}], 'medium');
  }

  function certSubjectFields(body, d, withDays) {
    var g = el('div', 'formgrid');
    /* The name the browser came by first, then the certificate's own, then server_name's; the
       other names all of them and this machine's IPv4 addresses - once each. */
    var info = ((d.cert || {}).info) || {};
    var dnsOnly = function (x) { return x && !/^[0-9.]+$/.test(x) && x.indexOf(':') < 0; };
    var all = uniq([reachedAs(), info.cn].concat(info.san || [], d.names || []).filter(dnsOnly).map(function (x) { return String(x).toLowerCase(); }));
    var first = all.shift() || d.host || '';
    var cn = textBox(first, 'igd.example.cz', 'mono'); cn.id = 'tcs-cn';
    var other = textBox(uniq(all.concat(d.ips || [])).join(', '), 'igd.example.cz, 192.0.2.11', 'mono'); other.id = 'tcs-names';
    var kind = selectBox([['rsa2048', 'RSA 2048'], ['rsa3072', 'RSA 3072'], ['rsa4096', 'RSA 4096'], ['ec', 'EC P-256']], 'rsa2048'); kind.id = 'tcs-kind';
    g.appendChild(formField('The name (CN)', cn, 'What people type in the browser.'));
    g.appendChild(formField('Other names', other, 'More names or addresses it is good for, by commas - the name these pages were reached by, the certificate\'s, nginx\'s server_name and this machine\'s IPv4 addresses to begin with.'));
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
      addNamesBox(body);
    }, [{words: 'Cancel', close: true},
        {words: 'Make it and put it in', cls: 'primary', icon: 'key', go: function (b) {
          busy(b, true);
          api('tls', Object.assign({action: 'tls_selfsigned', add_names: addNames()}, certSubjectValues())).then(function (x) {
            toast(x.message, 'good'); closeModal(); drawTls(x);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }

  /* What root is doing, as a bar (otp's certProgress, 1.0.50): the steps done, and in the long one -
     making DH parameters - the time gone against the time it usually takes (never shown as more than
     95 % before it is done). */
  function certProgress(p) {
    var box = el('div', 'cert-prog');
    var total = Number(p.total) || 4, step = Math.max(1, Number(p.step) || 1);
    var gone = Math.max(0, (Number(p.now) || 0) - (Number(p.at) || 0));
    var part = p.expect_s ? Math.min(0.95, gone / Number(p.expect_s)) : 0.5;
    var pct = Math.min(99, Math.round(((step - 1) + part) / total * 100));
    var head = el('div', 'cert-prog-h');
    head.appendChild(el('span', '', p.words || 'working'));
    head.appendChild(noI18n(el('b', '', pct + ' %')));
    box.appendChild(head);
    var bar = el('div', 'cert-prog-bar');
    var fill = el('span', '');
    fill.style.width = pct + '%';
    bar.appendChild(fill);
    box.appendChild(bar);
    var mm = function (sec) { sec = Math.round(sec); return Math.floor(sec / 60) + ':' + ('0' + (sec % 60)).slice(-2); };
    var where = (TLS.last && TLS.last.machine) || 'this server';
    box.appendChild(el('div', 'cert-prog-s', p.expect_s
      ? 'on ' + where + ' - ' + mm(gone) + ' so far, usually about ' + Math.round(p.expect_s / 60 || 1) + ' min'
      : 'on ' + where + ' - step ' + step + ' of ' + total));
    return box;
  }

  /* Back to the one before (otp's acmePutBackButton, 1.0.170). */
  function putBackButton(before) {
    var b = cmdButton('Back to the one before…', 'undo', 'small');
    var words = (before.issuer || '').replace(/^CN=/, '').split(',')[0];
    explain(b, 'The certificate it had before ACME replaced it' + (words ? ' - from ' + words : '') + (before.not_after ? ', good until ' + new Date(before.not_after * 1000).toLocaleDateString(numLang()) : '') + '. Put back as it was; ACME no longer renews this one. The TLS settings stay.');
    b.onclick = function () {
      confirmThen('Put the certificate from before ACME back?', 'The one from the CA is taken out and the one it had before - ' + htmlText(words || before.how || '') + ' - put back. ACME no longer renews this one (Look after it gives it back).', 'Put it back', function () {
        busy(b, true);
        api('acme', {action: 'put_back'}).then(function (x) { toast(x.message, 'good'); loadTls(); })
          .catch(function (e) { busy(b, false); oops(e); });
      }, false);
    };
    return b;
  }

  /* The dialog Upload the missing authority (otp's certChainAdd, 1.0.269). */
  function certChainAdd(d) {
    var cur = d.cert || {};
    var cs = cur.chain_state || {};
    var last = (cur.chain_info || []).length ? cur.chain_info[cur.chain_info.length - 1] : (cur.info || {});
    var missing = cs.missing || cs.private_root || String(last.issuer || '').replace(/^.*?CN=/, '').split(',')[0] || '?';
    var area;
    modal('Upload the missing authority', function (body) {
      var p = el('p', 'note');
      p.appendChild(el('span', '', 'Missing in the chain:'));
      p.appendChild(document.createTextNode(' '));
      p.appendChild(noI18n(el('b', '', missing)));
      body.appendChild(p);
      body.appendChild(el('p', 'note', 'The certificate of that authority - the intermediate (or several) your certificate authority gives with the certificate, often called "CA bundle", "intermediate" or "chain" - as PEM or a .cer / .crt file. Only certificates of authorities, never a key; the certificate and its key stay as they are. A root is kept to check with and never sent.'));
      area = noI18n(el('textarea', 'mono'));
      area.rows = 8; area.spellcheck = false; area.placeholder = '-----BEGIN CERTIFICATE-----';
      body.appendChild(area);
      var fr = el('div', 'btnrow');
      fr.style.margin = '8px 0 0';
      var pick = cmdButton('Read a file…', 'upload', 'small');
      var input = el('input'); input.type = 'file'; input.hidden = true;
      input.accept = '.pem,.crt,.cer,.der,.cert,.ca-bundle';
      pick.onclick = function () { input.click(); };
      input.onchange = function () {
        var f = input.files && input.files[0];
        if (!f) return;
        if (f.size > 262144) { toast('that file is far bigger than certificates are', 'warn'); return; }
        var r = new FileReader();
        r.onload = function () { area.value = osrFileText(r.result); };
        r.readAsArrayBuffer(f);
      };
      fr.appendChild(pick); fr.appendChild(input);
      body.appendChild(fr);
      setTimeout(function () { area.focus(); }, 60);
    }, [{words: 'Cancel', close: true}, {words: 'Add it to the chain', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      api('tls', {action: 'tls_chain_add', text: area.value.trim()}).then(function (x) {
        closeModal();
        toast(x.message, x.complete ? 'good' : 'warn');
        drawTls(x);
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  }

  /* A certificate downloaded (otp's certExport, 1.0.191): its format chosen in a window - with its
     private key (PFX, PEM) only locked with a passphrase typed twice; root makes those (the key is
     root's alone here). */
  var CERT_FORMATS = [
    ['pem', '.crt', 'The certificate', 'PEM - the certificate alone. nginx, Apache, most of Linux.', false],
    ['fullchain', '.pem', 'Certificate and chain', 'PEM - the certificate and the authorities that signed it, one file.', false],
    ['der', '.cer', 'Certificate, binary', 'DER - the certificate alone. Windows, Java, network devices.', false],
    ['p7b', '.p7b', 'Certificate and chain, PKCS#7', 'The certificate with its chain, no key. Windows and IIS import it.', false],
    ['pfx', '.pfx', 'With the private key, PKCS#12', 'The certificate, its chain and its private key in one file locked with a password. Windows, IIS, Exchange, Azure, browsers.', true],
    ['pemkey', '.pem', 'With the private key, PEM', 'The certificate, its chain and its private key locked with a passphrase (PKCS#8, AES-256).', true]
  ];
  function b64Save(name, b64, type) {
    var bin = atob(b64), arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([arr], {type: type || 'application/octet-stream'}));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function certExport(d) {
    var cur = d.cert || {};
    var info = cur.info || {};
    var st = {kind: 'pfx', legacy: false, which: 'rsa'};
    var alt = cur.alt && cur.alt.info ? cur.alt.info : null;
    modal('Download the certificate of these pages', function (body) {
      if (info.subject) body.appendChild(noI18n(el('p', 'muted small', info.subject + (info.not_after ? ' · until ' + stamp(info.not_after) : ''))));
      /* Two certificates of the same names (otp 1.0.240): which of them, or both in a .zip. */
      if (alt) {
        var sg = el('div', 'seg');
        [['rsa', 'RSA (' + (info.key || 'the main one') + ')'], ['ec', 'ECDSA (' + (alt.key || 'the second one') + ')'], ['both', 'Both (.zip)']].forEach(function (o) {
          var bb = el('button', o[0] === st.which ? 'on' : '', o[1]);
          bb.type = 'button';
          bb.onclick = function () { st.which = o[0]; Array.prototype.forEach.call(sg.children, function (x) { x.classList.toggle('on', x === bb); }); };
          sg.appendChild(bb);
        });
        var wf = formField('Which certificate', sg, 'Both: one .zip with the two files in the format below - each key locked with the same password.');
        wf.style.marginBottom = '12px';
        body.appendChild(wf);
      }
      var list = el('div', 'fmt-list');
      var keyBox = el('div', 'fmt-key');
      var draw = function () {
        list.querySelectorAll('.fmt').forEach(function (b) { b.classList.toggle('on', b.dataset.kind === st.kind); b.setAttribute('aria-checked', b.dataset.kind === st.kind ? 'true' : 'false'); });
        var f = CERT_FORMATS.filter(function (x) { return x[0] === st.kind; })[0];
        keyBox.hidden = !f[4];
        $('cx-legacy-row').hidden = st.kind !== 'pfx';
      };
      CERT_FORMATS.forEach(function (f) {
        var b = el('button', 'fmt' + (f[4] ? ' with-key' : ''));
        b.type = 'button';
        b.dataset.kind = f[0];
        b.setAttribute('role', 'radio');
        b.appendChild(el('span', 'fmt-ext', f[1]));
        var t = el('span', 'fmt-text');
        t.appendChild(el('b', '', f[2]));
        t.appendChild(el('span', 'fmt-says', f[3]));
        if (f[4]) t.appendChild(el('span', 'tag warn', 'private key'));
        b.appendChild(t);
        b.onclick = function () { st.kind = f[0]; draw(); };
        list.appendChild(b);
      });
      body.appendChild(list);
      keyBox.appendChild(el('p', 'note warn', 'The private key leaves this machine. Whoever holds the file and its password can be these pages. The download, and by whom, goes into Events.'));
      var p1 = secretBox('', '10 characters at least', 'mono');
      var p2 = secretBox('', 'the same again', 'mono');
      p1.id = 'cx-p1'; p2.id = 'cx-p2';
      p1.autocomplete = p2.autocomplete = 'new-password';
      var g = el('div', 'formgrid');
      g.appendChild(formField('Password of the file', p1));
      g.appendChild(formField('The password again', p2));
      keyBox.appendChild(g);
      var lg = switchBox(false);
      lg._input.onchange = function () { st.legacy = !!lg._get(); };
      var row = formField('For older Windows', lg, 'Windows before 10 (1709) and Server 2016 open no AES-protected PFX: 3DES then, as they need.');
      row.id = 'cx-legacy-row';
      keyBox.appendChild(row);
      body.appendChild(keyBox);
      draw();
    }, [
      {words: 'Cancel', close: true},
      {words: 'Download', cls: 'primary', icon: 'download', go: function (button) {
        var f = CERT_FORMATS.filter(function (x) { return x[0] === st.kind; })[0];
        var req = {action: 'tls_export', kind: st.kind, which: st.which};
        if (f[4]) {
          var a = $('cx-p1').value, b2 = $('cx-p2').value;
          if (a.length < 10) { toast('a password of 10 characters at least', 'bad'); $('cx-p1').focus(); return; }
          if (a !== b2) { toast('the two passwords are not the same', 'bad'); $('cx-p2').focus(); return; }
          req.password = a;
          req.legacy = st.legacy;
        }
        busy(button, true);
        api('tls', req).then(function (x) {
          b64Save(x.name, x.data, x.type);
          closeModal();
        }).catch(oops).then(function () { busy(button, false); });
      }}], 'medium');
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

  /* ---- Trusted roots of the system (otp's osrLoad, drawOsRoots, osrAdd, osrRemove) ---------- */
  var OSR = {d: null, n: 0, until: 0, out: false};
  function osrLoad(live) {
    if (!$('osr-host') || OSR.out) return;
    OSR.out = true;
    api('osroots').then(function (d) {
      OSR.d = d;
      if (live) liveRun(drawOsRoots); else drawOsRoots();
    }).catch(function (e) { if (!live) oops(e); }).then(function () { OSR.out = false; });
  }
  /* Asked every 5 s while root is at it (and for a while after a change), else every 30 s. */
  function osrTick() {
    OSR.n += 1;
    var busy = OSR.d && OSR.d.node && OSR.d.node.status === 'waiting';
    if (busy || Date.now() < OSR.until || OSR.n % 6 === 0) osrLoad(true);
  }
  function osrStatusTag(n) {
    var w = {applied: ['good', 'as wanted'], waiting: ['warn', 'waiting'], failed: ['bad', 'failed'],
             none: ['dim', 'nothing added by fake-igd']}[n.status] || ['dim', n.status || '?'];
    return el('span', 'tag ' + w[0], w[1]);
  }
  function osrDay(ts) { return ts ? new Date(ts * 1000).toLocaleDateString(numLang()) : '?'; }
  function netFacts(rows) {
    var dl = el('div', 'net-facts');
    rows.forEach(function (r) {
      var one = el('div', 'net-fact');
      one.appendChild(el('span', 'k', r[0]));
      var v = el('span', 'v' + (r[2] ? ' mono' : ''));
      v.textContent = r[1] === '' || r[1] === null || r[1] === undefined ? '–' : String(r[1]);
      if (r[2]) noI18n(v);
      one.appendChild(v);
      dl.appendChild(one);
    });
    return dl;
  }
  function drawOsRoots() {
    var real = $('osr-host');
    if (!real || !OSR.d) return;
    liveFill(real, function (host) {
      var d = OSR.d, n = d.node || {}, certs = d.certs || [];
      var tools = el('div', 'btnrow');
      tools.style.margin = '0 0 12px';
      if (d.may) {
        var add = cmdButton('Add an authority', 'upload', 'primary small');
        explain(add, 'A root or an intermediate certificate authority of your own - pasted as PEM, or a .pem, .crt or .cer file; a file with a chain adds each authority in it.');
        add.onclick = osrAdd;
        add.disabled = certs.length >= (d.max || 50);
        tools.appendChild(add);
        var again = cmdButton('Read it again', 'refresh', 'small');
        again.onclick = function () {
          busy(again, true);
          api('osroots', {action: 'refresh'}).then(function (x) { toast(x.message, 'good'); OSR.d = x; OSR.until = Date.now() + 90000; drawOsRoots(); })
            .catch(oops).then(function () { busy(again, false); });
        };
        tools.appendChild(again);
      }
      if (tools.firstChild) host.appendChild(tools);
      if (!certs.length) {
        host.appendChild(el('p', 'note', 'fake-igd has added none - this server trusts its system\'s own list alone.'));
      } else {
        host.appendChild(listTable(['Authority', 'Issued by', 'Valid', 'Key', 'SHA-256', ''], certs, function (c) {
          var tr = el('tr');
          var t = el('td');
          t.appendChild(noI18n(el('b', '', c.cn || '?')));
          t.appendChild(document.createTextNode(' '));
          t.appendChild(el('span', 'tag ' + (c.kind === 'root' ? 'info' : 'dim'), c.kind === 'root' ? 'root' : 'intermediate'));
          var days = daysLeft(c.not_after);
          if (days !== null && days < 0) t.appendChild(el('span', 'tag bad', 'ran out'));
          else if (days !== null && days < 60) t.appendChild(el('span', 'tag warn', days + ' days left'));
          (c.warn || []).forEach(function (w) { t.appendChild(el('div', 'small warn', w)); });
          tr.appendChild(t);
          tr.appendChild(noI18n(el('td', 'small', c.kind === 'root' ? '' : String(c.issuer || '').replace(/^.*?CN=/, '').split(',')[0])));
          tr.appendChild(el('td', 'small', osrDay(c.not_before) + ' – ' + osrDay(c.not_after)));
          tr.appendChild(noI18n(el('td', 'small', c.key || '?')));
          var fp = noI18n(el('td', 'mono small', String(c.fp || '').slice(0, 16) + '…'));
          copyOnClick(fp, c.fp, 'the SHA-256 fingerprint is copied');
          tr.appendChild(fp);
          var act = el('td', 'right sk-act');
          var dl = iconButton('download', 'Download it (PEM)');
          dl.onclick = function () { saveText(String(c.cn || 'ca').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) + '.pem', c.pem); };
          act.appendChild(dl);
          if (d.may) {
            var rm = iconButton('trash', 'Take it out of the system\'s trust');
            rm.onclick = function () { osrRemove(c); };
            act.appendChild(rm);
          }
          tr.appendChild(act);
          return tr;
        }, 'plain'));
      }
      var py = d.python || {};
      if (py.cafile) host.appendChild(el('p', 'muted small', 'fake-igd\'s own connections (mail, syslog, ntfy, ACME, upgrades) use the system\'s list too (' + py.cafile + ') - what is added here reaches them at their next connection.'));
      var grid = el('div', 'pw-grid');
      grid.style.marginTop = '16px';
      var c = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ok'));          /* otp: whether the node answers - this one does */
      hd.appendChild(noI18n(el('b', '', n.name || 'this server')));
      hd.appendChild(el('span', 'tag info', 'this page'));
      hd.appendChild(osrStatusTag(n));
      c.appendChild(hd);
      if (n.why) c.appendChild(el('p', 'note ' + (n.status === 'failed' ? 'bad' : 'warn'), n.why));
      var s = n.system || {};
      c.appendChild(netFacts([
        ['The system\'s own list', s.count ? s.count + ' authorities' : (s.missing ? 'not there' : '?')],
        ['Its package', s.package || '–', true],
        ['Made last', s.at ? ago(s.at) : '–'],
        ['Local additions in', n.dir || '–', true],
        ['Made by', n.tool ? n.tool + (n.tool_there === false ? ' (not on this machine)' : '') : '–', true],
        ['fake-igd\'s additions there', String((n.ours || []).length)],
        ['Read', n.at ? ago(n.at) : 'not yet']
      ]));
      var others = n.others || [];
      if (others.length) {
        c.appendChild(el('div', 'k small muted', 'Added by somebody else - fake-igd leaves them as they are:'));
        var ul = el('ul', 'small');
        ul.style.margin = '4px 0 0 18px';
        others.slice(0, 40).forEach(function (o) {
          var li = el('li');
          li.appendChild(noI18n(el('span', 'mono', o.file || '?')));
          var cs = o.certs || [];
          if (cs.length) {
            li.appendChild(noI18n(el('span', '', ' - ' + cs.map(function (x) { return (x.cn || '?'); }).join(', '))));
            cs.forEach(function (x) {
              li.appendChild(document.createTextNode(' '));
              li.appendChild(el('span', 'tag dim', x.kind === 'root' ? 'root' : (x.ca ? 'intermediate' : 'not an authority')));
            });
          } else if (o.link) li.appendChild(el('span', 'muted', ' - a link'));
          else li.appendChild(el('span', 'muted', ' - no certificate read'));
          ul.appendChild(li);
        });
        c.appendChild(ul);
      }
      grid.appendChild(c);
      host.appendChild(grid);
    }, undefined, function () { explainWhatWasDrawn($('osr-card')); });
  }
  /* A file as it comes: PEM as it is; DER (.cer) made PEM here. */
  function osrFileText(buf) {
    var bytes = new Uint8Array(buf);
    var head = '';
    for (var i = 0; i < Math.min(bytes.length, 4096); i++) head += String.fromCharCode(bytes[i]);
    if (head.indexOf('-----BEGIN') >= 0) return new TextDecoder('ascii').decode(bytes);
    var bin = '';
    for (var j = 0; j < bytes.length; j++) bin += String.fromCharCode(bytes[j]);
    var b64 = btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
    return '-----BEGIN CERTIFICATE-----\n' + b64 + '\n-----END CERTIFICATE-----\n';
  }
  function osrAdd() {
    var area, seen, timer = null, checked = '';
    modal('Add to the system\'s trust', function (body) {
      var p = el('p', 'note');
      p.innerHTML = 'A certificate authority of your own - a root, or an intermediate - as PEM (<code>-----BEGIN CERTIFICATE-----</code>), or a <code>.pem</code>, <code>.crt</code> or <code>.cer</code> file. A chain adds every authority in it. Only authorities are taken (CA:TRUE), never a private key.';
      body.appendChild(p);
      body.appendChild(el('p', 'note', 'Every program of this server trusts what they sign from then on.'));
      area = noI18n(el('textarea', 'mono'));
      area.rows = 8; area.spellcheck = false; area.placeholder = '-----BEGIN CERTIFICATE-----';
      body.appendChild(area);
      var fr = el('div', 'btnrow');
      fr.style.margin = '8px 0 4px';
      var pickB = cmdButton('Read a file…', 'upload', 'small');
      var input = el('input'); input.type = 'file'; input.hidden = true;
      input.accept = '.pem,.crt,.cer,.der,.cert,.ca-bundle';
      pickB.onclick = function () { input.click(); };
      input.onchange = function () {
        var f = input.files && input.files[0];
        if (!f) return;
        if (f.size > 1048576) { toast('that file is far bigger than certificates are', 'warn'); return; }
        var r = new FileReader();
        r.onload = function () { area.value = osrFileText(r.result); look(); };
        r.readAsArrayBuffer(f);
      };
      fr.appendChild(pickB); fr.appendChild(input);
      body.appendChild(fr);
      seen = el('div', 'osr-seen');
      body.appendChild(seen);
      var look = function () {
        var text = area.value.trim();
        if (text === checked) return;
        checked = text;
        clear(seen);
        if (!text) return;
        api('osroots', {action: 'check', text: text}).then(function (x) {
          if (area.value.trim() !== text) return;
          clear(seen);
          (x.certs || []).forEach(function (c) {
            var box = el('div', 'note');
            box.style.margin = '8px 0 0';
            box.appendChild(noI18n(el('b', '', c.cn || '?')));
            box.appendChild(document.createTextNode(' '));
            box.appendChild(el('span', 'tag ' + (c.refused.length ? 'bad' : (c.already ? 'dim' : 'good')),
              c.refused.length ? 'not taken' : (c.already ? 'there already' : (c.kind === 'root' ? 'root' : 'intermediate'))));
            box.appendChild(noI18n(el('div', 'muted small', 'SHA-256 ' + c.fp)));
            box.appendChild(el('div', 'small', 'valid ' + osrDay(c.not_before) + ' – ' + osrDay(c.not_after) + ' · ' + (c.key || '?')));
            c.refused.forEach(function (w) { box.appendChild(el('div', 'small bad', w)); });
            c.warn.forEach(function (w) { box.appendChild(el('div', 'small warn', w)); });
            seen.appendChild(box);
          });
        }).catch(function (e) {
          if (area.value.trim() !== text) return;
          clear(seen);
          seen.appendChild(el('p', 'note bad', (e && e.message) || String(e)));
        });
      };
      area.oninput = function () { clearTimeout(timer); timer = setTimeout(look, 400); };
      setTimeout(function () { area.focus(); }, 60);
    }, [{words: 'Cancel', close: true}, {words: 'Add them', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      api('osroots', {action: 'add', text: area.value.trim()}).then(function (x) {
        closeModal();
        toast(x.message, 'good');
        OSR.d = x; OSR.until = Date.now() + 90000;
        drawOsRoots();
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  }
  function osrRemove(c) {
    confirmThen('Take it out of the system\'s trust',
      'What <b>' + htmlText(c.cn || '?') + '</b> (SHA-256 <code>' + htmlText(String(c.fp).slice(0, 16)) + '…</code>) signs is no longer trusted by this server - unless the system\'s own list has it. Connections that rely on it (LDAPS, mail, syslog…) fail from their next start.',
      'Take it away', function () {
        api('osroots', {action: 'remove', fp: c.fp}).then(function (x) {
          toast(x.message, 'good');
          OSR.d = x; OSR.until = Date.now() + 90000;
          drawOsRoots();
        }).catch(oops);
      }, true);
  }
}());
