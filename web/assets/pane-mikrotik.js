/* Settings → MikroTik (1.8.2; configuration only since 1.9.2): the real router read - READ-ONLY - in isemon's
   form (its "Reading this MikroTik through its API" section, "Try reaching it" with its steps, "How to set it
   up on the router…", the key panel, the certificate pinned), Read it now and one line of how it went. What
   was read - each device's way out, its ports on the router, the whole firewall - is on the main menu:
   Gateway → MikroTik (mt-view.js). */
(function () {
  'use strict';
  var MT = {d: null, poll: null};
  var WAY = {rest: 'REST over HTTPS', api: 'the API (api-ssl)', ssh: 'ssh'};
  var TLS = {pin: 'its certificate trusted by its fingerprint', ca: 'its certificate checked by an authority', none: 'its certificate not checked', plain: 'no TLS'};

  function live() { return TAB === 'settings' && PANE === 'mikrotik'; }
  function load() {
    api('mikrotik').then(function (d) {
      MT.d = d;
      draw();
      pollFor();
    }).catch(oops);
  }
  function quiet() {
    api('mikrotik').then(function (d) {
      var was = MT.d && MT.d.reading;
      MT.d = d;
      draw(true);
      if (was && !MT.d.reading) toast((MT.d.state || {}).ok ? 'the MikroTik is read' : 'it could not be read', (MT.d.state || {}).ok ? 'good' : 'bad');
      pollFor();
    }).catch(function () {});
  }
  function pollFor() {
    var on = !!(MT.d && MT.d.reading);
    if (on && !MT.poll) MT.poll = setInterval(function () { if (!live()) { clearInterval(MT.poll); MT.poll = null; return; } quiet(); }, 1500);
    if (!on && MT.poll) { clearInterval(MT.poll); MT.poll = null; }
  }
  function ask(body) {
    return api('mikrotik', body, 90).then(function (x) {
      if (x.message) toast(x.message, 'good');
      if (x.conf) { MT.d = x; window.MT_CACHE = null; draw(true); }
      return x;
    });
  }
  function draw(again) {
    if (!MT.d) return;
    fill($('mt-hero'), hero(MT.d));
    fill($('mt-trust'), trust(MT.d));
    $('mt-conn-said').textContent = MT.d.on ? (WAY[MT.d.conf.mode] || '') + ' · ' + MT.d.conf.host + ':' + MT.d.port_used : 'off';
    explainWhatWasDrawn($('pane-mikrotik'));
  }
  function fill(host, node) { if (!host) return; clear(host); if (node) host.appendChild(node); }
  function tag(words, cls) { return el('span', 'tag ' + (cls || 'dim'), words); }
  function codeBlock(text, words) {
    var box = el('div', 'mt-code');
    var pre = noI18n(el('pre', 'mono', text));
    box.appendChild(pre);
    var c = iconButton('copy', words || 'Copy');
    c.classList.add('mt-copy');
    c.onclick = function (ev) { ev.stopPropagation(); copyText(text, c, 'the commands are on the clipboard - paste them into the MikroTik\'s terminal yourself'); };
    box.appendChild(c);
    return box;
  }
  function stepsOf(steps) {
    var list = el('div', 'steps');
    (steps || []).forEach(function (s) {
      var row = el('div', 'step ' + (s.ok ? 'ok' : 'bad'));
      var mark = el('span', 'step-mark');
      mark.innerHTML = iconMarkup(s.ok ? 'check' : 'cancel', 15);
      row.appendChild(mark);
      var w = el('span', 'step-words');
      w.appendChild(el('b', '', s.what));
      if (s.said) w.appendChild(noI18n(el('span', 'd', s.said)));
      row.appendChild(w);
      list.appendChild(row);
    });
    return list;
  }

  /* ---- the state, as one hero card ---- */
  function hero(d) {
    var st = d.state || {}, sn = d.snap || {}, ch = d.checks || null;
    var k = 'warn', t;
    if (!d.on) t = 'Off - nothing reaches the router';
    else if (d.reading) t = 'Being read now…';
    else if (st.ok === false) { k = 'bad'; t = 'The MikroTik cannot be read'; }
    else if (!sn.at) t = 'Switched on - not read yet';
    else if (ch && ch.total) {
      k = ch.open === ch.total ? 'good' : (ch.open ? 'warn' : 'bad');
      t = (sn.identity || 'The MikroTik') + ': ' + num(ch.open) + ' of ' + num(ch.total) + ' port(s) asked for are open on it';
    } else { k = 'good'; t = (sn.identity || 'The MikroTik') + ' is read - no device has asked for a port yet'; }
    var card = el('div', 'card full rb-hero mt-hero ' + k);
    var head = el('div', 'rb-hero-head');
    var ic = el('span', 'rb-hero-ic');
    ic.innerHTML = iconMarkup(k === 'good' ? 'check' : (k === 'bad' ? 'flag' : 'wall'), 22);
    head.appendChild(ic);
    var words = el('div', 'rb-hero-words');
    words.appendChild(el('b', '', t));
    var facts = el('div', 'rb-hero-facts');
    var fact = function (kk, v, cls, mono) {
      var f = el('span', 'rb-fact ' + (cls || ''));
      f.appendChild(el('span', 'k', kk));
      var vv = el('span', 'v' + (mono ? ' mono' : ''), v);
      if (mono) noI18n(vv);
      f.appendChild(vv);
      facts.appendChild(f);
    };
    if (d.on) {
      fact('Router', d.conf.host ? d.conf.host + ':' + d.port_used : 'not set', d.conf.host ? '' : 'bad', true);
      if (sn.identity) fact('It is', sn.identity + (sn.version ? ', RouterOS ' + sn.version : '') + (sn.board ? ' on ' + sn.board : ''));
      fact('Reached by', (WAY[d.conf.mode] || d.conf.mode) + (d.conf.mode === 'ssh' ? (d.conf.auth === 'key' ? ', a key' : ', a password') : ', ' + (TLS[d.conf.tls] || '')));
      fact('Signing in as', d.conf.user || '–', '', true);
      fact('Last read', st.at ? ago(st.at) + (st.took !== undefined ? ' (' + st.took + ' s)' : '') : 'never', st.ok === false ? 'bad' : '');
      if (sn.counts) fact('Rules', num(Object.keys(sn.counts.ip || {}).reduce(function (a, t2) { return a + sn.counts.ip[t2]; }, 0)) + ' IPv4 · '
        + num(Object.keys(sn.counts.ipv6 || {}).reduce(function (a, t2) { return a + sn.counts.ipv6[t2]; }, 0)) + ' IPv6');
      if (sn.upnp && sn.upnp.enabled) fact('Its own UPnP', /^(true|yes)$/.test(sn.upnp.enabled) ? 'ON' : 'off', /^(true|yes)$/.test(sn.upnp.enabled) ? 'bad' : 'good');
    } else {
      fact('Read-only', 'it only ever prints');
      fact('Ways', 'REST · API-SSL · ssh (key or password)');
    }
    words.appendChild(facts);
    if (d.on && sn.at) {
      var see = el('a', 'mt-see', 'See what was read in Gateway → MikroTik →');
      see.href = '#gateway/mikrotik';
      explain(see, 'Each device\'s way out to the internet through the router and the public address it goes out as, every port asked for on the router, and its whole firewall - on the main menu, Gateway → MikroTik.');
      words.appendChild(see);
    }
    var why = [];
    if (st.ok === false) why.push({k: 'bad', t: st.trouble});
    (ch ? ch.warnings : []).forEach(function (w) { why.push({k: 'warn', t: w}); });
    Object.keys(sn.missing || {}).forEach(function (m) { if (!/routerboard|nat6|mangle6|raw6|tracking|upnp_ifs/.test(m)) why.push({k: 'dim', t: 'Not read: ' + m + ' - ' + sn.missing[m]}); });
    why.forEach(function (w) { words.appendChild(noI18n(el('div', 'rb-hero-why small ' + w.k, w.t))); });
    head.appendChild(words);
    var acts = el('div', 'rb-hero-acts');
    var rd = cmdButton('Read it now', 'refresh', 'primary');
    rd.disabled = !ADMIN || !d.on || !d.conf.host || d.reading;
    explain(rd, 'Read the router now: its firewall, IPv4 and IPv6, its address lists, interfaces and neighbours - a few prints. Nothing is written.');
    rd.onclick = function () { busy(rd, true); ask({do: 'read'}).catch(oops).then(function () { busy(rd, false); }); };
    acts.appendChild(rd);
    var tr = cmdButton('Try reaching it', 'pulse', '');
    tr.disabled = !ADMIN || !d.conf.host;
    explain(tr, 'Sign in to the router with what is saved above and ask it its name, its version, its board and its account\'s group - every step said. Nothing is written and nothing is changed.');
    tr.onclick = function () { tryIt(tr); };
    acts.appendChild(tr);
    var gd = cmdButton('How to set it up on the router…', 'info', '');
    explain(gd, 'How to set the router up for this, step by step, with its commands: the account that may only read, and the service it reads through.');
    gd.onclick = function () { guide(d); };
    acts.appendChild(gd);
    head.appendChild(acts);
    card.appendChild(head);
    if (d.reading) {
      var going = el('div', 'going wide');
      going.innerHTML = '<div class="bar"><span class="creeping"></span></div><div class="says"></div>';
      going.querySelector('span').style.width = '40%';
      going.querySelector('.says').textContent = 'Reading the router - a few prints, seconds at most.';
      card.appendChild(going);
    }
    return card;
  }

  /* ---- Try reaching it (isemon's rosApiTry) ---- */
  function tryIt(b) {
    busy(b, true);
    api('mikrotik', {do: 'test'}, 90).then(function (x) {
      var words = 'the MikroTik ' + MT.d.conf.host;
      if (x.ok) {
        modal('It answered', function (body) {
          body.appendChild(el('p', 'note', 'This signed in to ' + words + ' (' + (WAY[x.via] || x.via) + '), asked its name, its version, its board and its account\'s group, and came back. Nothing was written and nothing was changed.'));
          body.appendChild(stepsOf(x.steps));
          if (x.can_write) body.appendChild(el('p', 'note bad', 'That account\'s group may CHANGE things (' + (x.policy || []).join(', ') + '): give it one that may only read - How to set it up on the router says how.'));
        }, [{words: 'Read it now', icon: 'refresh', cls: 'primary', close: true, admin: true, go: function () { ask({do: 'read'}).catch(oops); }}, {words: 'Close', close: true}], 'medium');
        return;
      }
      var unsure = /not trusted yet|another certificate/.test(x.trouble || '') && x.fingerprint;
      modal(unsure ? 'Its certificate - trust it?' : 'It did not answer', function (body) {
        if (unsure) {
          body.appendChild(el('p', 'note', 'The router answered over TLS with this certificate. Nothing was sent to it - not the password. Compare its fingerprint with the router\'s own (on its console: /certificate print detail, or in WinBox) and trust it only if they are the same.'));
          var c = x.cert || {};
          var f = el('div', 'facts');
          [['Fingerprint (SHA-256)', x.fingerprint_words], ['Subject', c.subject || '–'], ['Issued by', c.issuer || '–'], ['Good until', c.until || '–']].forEach(function (p) {
            var cell = el('div', 'fact' + (p[0].indexOf('Finger') === 0 ? ' wide' : ''));
            cell.appendChild(el('span', 'k', p[0]));
            cell.appendChild(noI18n(el('span', 'v mono', p[1])));
            f.appendChild(cell);
          });
          body.appendChild(f);
          if (/another certificate/.test(x.trouble)) body.appendChild(el('p', 'note bad', 'It is NOT the certificate trusted before. If it was not replaced on purpose, somebody in between may be answering instead of the router.'));
        } else {
          body.appendChild(el('p', 'note', 'What came back when reaching ' + words + ', step by step:'));
        }
        body.appendChild(stepsOf(x.steps));
        if (!unsure) body.appendChild(el('p', 'note', MT.d.conf.mode === 'ssh'
          ? 'The usual causes, in the order they usually are: its host key is not trusted yet (Look at its host key, below); the public half of the key is not on the router; the account has no ssh permission; the address or port is wrong.'
          : 'The usual causes, in the order they usually are: ' + (MT.d.conf.mode === 'rest' ? 'www-ssl is off (or not for this machine\'s address - /ip service print); RouterOS older than 7.1 has no REST' : 'api-ssl (or api) is not switched on, or not for this machine\'s address') + '; the account or its password is wrong; the address or port is wrong.'));
      }, unsure ? [{words: 'Not now', close: true}, {words: 'Trust this certificate', icon: 'lock', cls: 'primary', close: true, admin: true, go: function () {
        ask({do: 'trust', fingerprint: x.fingerprint}).then(function () { tryIt(b); }).catch(oops);
      }}] : [{words: 'Close', close: true}], 'medium');
    }).catch(oops).then(function () { busy(b, false); });
  }

  /* ---- How to set it up on the router (isemon's rosApiGuide) ---- */
  function guide(d) {
    var mode = d.conf.mode, user = d.conf.user || 'fake-igd-read';
    modal('Setting it up: MikroTik ' + ({rest: 'REST', api: 'API', ssh: 'over ssh'}[mode] || '') + ' (read-only)', function (body) {
      body.classList.add('guide');
      body.appendChild(el('p', 'note', 'This reads the router and writes nothing to it: the account it signs in with may read and use ' + ({rest: 'the REST API', api: 'the API', ssh: 'ssh'}[mode]) + ', and nothing else. Type these on the MikroTik (its terminal, WinBox\'s New Terminal, or ssh as its administrator).'));
      var step = function (n, title, html, code) {
        var s = el('div', 'mt-step');
        var h = el('div', 'mt-step-h');
        h.appendChild(el('span', 'mt-step-n', String(n)));
        h.appendChild(el('b', '', title));
        s.appendChild(h);
        var p = el('p', 'note');
        p.innerHTML = html;
        s.appendChild(p);
        if (code) s.appendChild(codeBlock(code));
        body.appendChild(s);
      };
      var lines = String(d.guide[mode] || '').split('\n');
      step(1, 'An account that may only read', 'A group allowed <b>read</b> and <b>' + ({rest: 'rest-api', api: 'api', ssh: 'ssh'}[mode]) + '</b> and nothing else, and an account in it - choose its password, and put the same one in <i>Its password</i> here' + (mode === 'ssh' ? ' (or sign in with the key below)' : '') + ':', lines.slice(0, 2).join('\n'));
      if (mode === 'ssh') {
        step(2, 'Its key', d.key.public ? 'The public half of the key made here, given to that account (RouterOS 7; on RouterOS 6 put it in a file and <span class="mono">/user ssh-keys import public-key-file=… user=' + htmlText(user) + '</span>):'
          : '<b>Make a key</b> below first - then its command is here.', d.key.public ? lines.filter(function (l) { return l.indexOf('ssh-keys') >= 0; }).join('\n') : '');
        step(3, 'The service', 'ssh, open to this machine alone - and its host key, which you trust here after <b>Look at its host key</b>:', lines[lines.length - 1] + '\n/ip ssh print');
      } else if (mode === 'rest') {
        step(2, 'HTTPS (www-ssl)', 'RouterOS 7\'s REST API is on the web service: www-ssl needs a certificate. A self-signed one is fine - it is trusted here by its fingerprint:', '/certificate add name=www-ssl common-name=' + (d.conf.host || 'router') + ' days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server\n/certificate sign www-ssl\n/ip service set www-ssl certificate=www-ssl disabled=no' + (d.this ? ' address=' + d.this : '') + '\n/certificate print detail where name=www-ssl');
      } else {
        step(2, 'api-ssl', 'The API over TLS, open to this machine alone - its certificate trusted here by its fingerprint (a self-signed one as above, or one an authority signed):', lines[lines.length - 1] + (d.conf.tls === 'plain' ? '\n/ip service set api disabled=no' + (d.this ? ' address=' + d.this : '') : ''));
      }
      body.appendChild(el('p', 'note', 'Then, here: fill the settings in, Save, and Try reaching it. ' + (mode !== 'ssh' && d.conf.tls === 'pin' ? 'The first try shows its certificate - Trust this certificate once its fingerprint is the one /certificate print detail shows.' : '') + ' The router is read from then on every ' + d.conf.every + ' min.'));
    }, [{words: 'Close', close: true}], 'medium');
  }

  /* ---- the certificate, the host key, the key (isemon's panels) ---- */
  function trust(d) {
    if (!d.on) return null;
    var box = el('div', 'subpanel mt-trust');
    if (d.conf.mode !== 'ssh') {
      if (d.conf.tls !== 'pin') {
        box.appendChild(el('p', 'btnhelp', d.conf.tls === 'ca' ? 'Its certificate is checked by ' + (MT.d.conf.tls_name ? 'an authority, for the name ' + MT.d.conf.tls_name : 'an authority, for its address') + '.' : 'Its certificate is not checked - anybody in between could answer instead of the router.'));
        return box;
      }
      var h = el('div', 'mt-trust-row');
      h.appendChild(el('span', 'k', 'Its certificate'));
      if (d.pin) {
        h.appendChild(tag('trusted', 'ok'));
        h.appendChild(noI18n(el('code', 'mono small mt-fp', d.pin_words)));
        var f = cmdButton('Forget it', 'forget', 'danger small');
        f.disabled = !ADMIN;
        explain(f, 'Forget the trusted certificate: the next Try reaching it shows the one the router answers with, to trust again. Until then nothing is read.');
        f.onclick = function () { confirmThen('Forget its certificate?', 'The certificate trusted now is forgotten: nothing is read until Try reaching it shows the one the router answers with and you trust it again.', 'Forget it', function () { ask({do: 'trust-forget'}).catch(oops); }); };
        h.appendChild(f);
      } else {
        h.appendChild(tag('not trusted yet', 'warn'));
        h.appendChild(el('span', 'muted small', 'Try reaching it shows its certificate - then Trust this certificate.'));
      }
      box.appendChild(h);
      return box;
    }
    /* ssh: its host key, and the key made here */
    var hk = el('div', 'mt-trust-row');
    hk.appendChild(el('span', 'k', 'Its host key'));
    if ((d.hostkeys || []).length) {
      hk.appendChild(tag('trusted', 'ok'));
      d.hostkeys.forEach(function (x) { hk.appendChild(noI18n(el('code', 'mono small mt-fp', x.type + ' ' + x.fingerprint))); });
    } else hk.appendChild(tag('not trusted yet', 'warn'));
    var look = cmdButton('Look at its host key', 'eye', 'small');
    look.disabled = !ADMIN || !d.conf.host;
    explain(look, 'Ask the router for its ssh host key (ssh-keyscan) and show its fingerprint - to compare with /ip ssh print on its console and trust it. Until it is trusted, nothing is sent to it.');
    look.onclick = function () {
      busy(look, true);
      api('mikrotik', {do: 'hostkey-scan'}, 60).then(function (x) {
        modal('Its ssh host key - trust it?', function (body) {
          body.appendChild(el('p', 'note', 'The router shows these host keys now. Compare one with the router\'s own and trust it only if they are the same - from then on a router answering with another key is refused before anything is sent.'));
          (x.keys || []).forEach(function (k) {
            var row = el('div', 'mt-trust-row');
            row.appendChild(tag(k.type, 'info'));
            row.appendChild(noI18n(el('code', 'mono small mt-fp', k.fingerprint)));
            var t = cmdButton('Trust this host key', 'lock', 'primary small');
            t.disabled = !ADMIN;
            t.onclick = function () { closeModal(); ask({do: 'hostkey-trust', fingerprint: k.fingerprint}).catch(oops); };
            row.appendChild(t);
            body.appendChild(row);
          });
          if ((x.known || []).length && !(x.keys || []).some(function (k) { return x.known.some(function (j) { return j.fingerprint === k.fingerprint; }); }))
            body.appendChild(el('p', 'note bad', 'NONE of these is the host key trusted before (' + x.known.map(function (j) { return j.fingerprint; }).join(', ') + '). If the router was not re-keyed on purpose, somebody in between may be answering.'));
        }, [{words: 'Close', close: true}], 'medium');
      }).catch(oops).then(function () { busy(look, false); });
    };
    hk.appendChild(look);
    if ((d.hostkeys || []).length) {
      var fg = cmdButton('Forget it', 'forget', 'danger small');
      fg.disabled = !ADMIN;
      fg.onclick = function () { confirmThen('Forget its host key?', 'The host key trusted now is forgotten: nothing is sent to the router until Look at its host key shows it and you trust it again.', 'Forget it', function () { ask({do: 'hostkey-forget'}).catch(oops); }); };
      hk.appendChild(fg);
    }
    box.appendChild(hk);
    if (d.conf.auth !== 'key') return box;
    var kb = el('div', 'mt-keybox');
    var note = el('p', 'note');
    note.innerHTML = 'Made here, and its private half never leaves this machine (kept sealed beside the database). Put the <b>public</b> half on the router.';
    kb.appendChild(note);
    if (!d.can_keygen) kb.appendChild(el('p', 'note warn', 'ssh-keygen is not on this machine, so a key cannot be made or read here: dnf install openssh-clients. A password still works.'));
    var bar = el('div', 'btnrow');
    var mk = cmdButton(d.key.set ? 'Make a new key' : 'Make a key', 'key', 'admin-only');
    var own = cmdButton('Use my own', 'upload', 'admin-only');
    var dl = cmdButton('Download the public key', 'download', '');
    var fo = cmdButton('Forget it', 'forget', 'danger admin-only');
    mk.disabled = !ADMIN || !d.can_keygen; own.disabled = !ADMIN || !d.can_keygen; dl.disabled = !d.key.public; fo.disabled = !ADMIN || !d.key.set;
    mk.onclick = function () {
      confirmThen('Make a key for the MikroTik', 'A fresh ed25519 pair is made here. The private half stays on this machine and the public half is shown for you to put on the router.' + (d.key.set ? '<br><br><b>The key kept now is replaced</b>, so until the new public half is on the router this cannot sign in.' : ''), 'Make one', function () { ask({do: 'keygen'}).catch(oops); }, false);
    };
    own.onclick = function () {
      modal('Use my own key for the MikroTik', function (body) {
        var p = el('p', 'note');
        p.innerHTML = 'An OpenSSH private key without a passphrase, whole, including its <span class="mono">BEGIN</span> and <span class="mono">END</span> lines. It is kept sealed in this machine\'s database and never shown back; its public half is worked out here.';
        body.appendChild(p);
        var area = el('textarea');
        area.rows = 10; area.id = 'mt-key-area'; area.spellcheck = false;
        area.placeholder = '-----BEGIN OPENSSH PRIVATE KEY-----';
        body.appendChild(area);
      }, [{words: 'Cancel', close: true}, {words: 'Keep this key', cls: 'primary', close: true, go: function () {
        ask({do: 'key', key: $('mt-key-area').value}).catch(oops);
      }}], 'medium');
    };
    dl.onclick = function () {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([d.key.public + '\n'], {type: 'text/plain'}));
      a.download = 'fake-igd-read.pub';
      document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    };
    fo.onclick = function () {
      confirmThen('Forget the key for the MikroTik', 'The private key is deleted from this machine. Unless the router takes a password instead, nothing here reaches it until a new key is made and put on it.', 'Forget it', function () { ask({do: 'key-forget'}).catch(oops); });
    };
    [mk, own, dl, fo].forEach(function (x) { bar.appendChild(x); });
    kb.appendChild(bar);
    if (d.key.public) {
      kb.appendChild(el('p', 'btnhelp', 'The public half, and the command that gives it to the account on RouterOS 7 (click to copy):'));
      kb.appendChild(codeBlock('/user ssh-keys add user=' + (d.conf.user || 'fake-igd-read') + ' key="' + d.key.public + '"'));
    } else kb.appendChild(el('p', 'btnhelp', 'No key yet - make one, or sign in with a password.'));
    box.appendChild(kb);
    return box;
  }

  PANE_LOAD.mikrotik = load;
})();
