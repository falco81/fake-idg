/* Settings → MikroTik (1.8.2): the real router read - READ-ONLY - in isemon's form (its "Reading this MikroTik
   through its API" section, "Try reaching it" with its steps, "How to set it up on the router…", the key panel,
   the certificate pinned), and two things of fake-igd's own: every port a device asked for, checked against
   the MikroTik's firewall (open / no dst-nat / no accept / shadowed / disabled / elsewhere / cannot tell, with
   the commands that would add what is missing - shown, never sent), and the WHOLE firewall drawn: IPv4 and
   IPv6, each table's chains as lanes, every rule a card in its order - its action in colour, what it matches
   as chips, its counters, what concerns fake-igd's devices lit up; a rule opens with all its fields. */
(function () {
  'use strict';
  var MT = {d: null, r: null, fam: 'ip', table: 'nat', q: '', mine: false, lists: false, poll: null};
  var STATE = {
    ok: ['open', 'ok', 'The MikroTik carries it: a dst-nat to the device, and nothing in forward drops it.'],
    no_dnat: ['no dst-nat', 'crit', 'No enabled dst-nat rule sends this port to the device.'],
    no_accept: ['dropped by the filter', 'crit', 'Translated - then dropped in the forward chain of the filter.'],
    shadowed: ['shadowed', 'warn', 'A rule for it exists, but an earlier rule takes the packets first.'],
    disabled: ['disabled', 'warn', 'The rule that would carry it is switched off.'],
    elsewhere: ['forwarded elsewhere', 'warn', 'Another rule forwards this port to another device - one port goes to one device.'],
    unsure: ['cannot tell', 'dim', 'Something that decides it depends on what this cannot know (who connects, a limit, a mark) - said with the rule.']
  };
  var V6 = {open: ['IPv6 open', 'ok'], blocked: ['IPv6 blocked', 'crit'], unsure: ['IPv6: cannot tell', 'dim'], none: ['no IPv6', 'dim']};
  var WAY = {rest: 'REST over HTTPS', api: 'the API (api-ssl)', ssh: 'ssh'};
  var TLS = {pin: 'its certificate trusted by its fingerprint', ca: 'its certificate checked by an authority', none: 'its certificate not checked', plain: 'no TLS'};

  function live() { return TAB === 'settings' && PANE === 'mikrotik'; }
  function load() {
    Promise.all([api('mikrotik'), api('mikrotik-rules').catch(function () { return {snap: null}; })]).then(function (two) {
      MT.d = two[0]; MT.r = two[1];
      draw();
      pollFor();
    }).catch(oops);
  }
  function quiet() {
    Promise.all([api('mikrotik'), api('mikrotik-rules').catch(function () { return MT.r; })]).then(function (two) {
      var was = MT.d && MT.d.reading;
      MT.d = two[0]; MT.r = two[1];
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
      if (x.conf) { MT.d = x; }
      return api('mikrotik-rules').then(function (r) { MT.r = r; draw(true); return x; });
    });
  }
  function draw(again) {
    if (!MT.d) return;
    var keep = $('mt-fw') ? $('mt-fw').querySelector('.mt-lanes') : null;
    var scroll = keep ? keep.scrollLeft : 0;
    fill($('mt-hero'), hero(MT.d));
    fill($('mt-trust'), trust(MT.d));
    fill($('mt-ports'), ports(MT.d));
    fill($('mt-fw'), firewall());
    $('mt-conn-said').textContent = MT.d.on ? (WAY[MT.d.conf.mode] || '') + ' · ' + MT.d.conf.host + ':' + MT.d.port_used : 'off';
    var lanes = $('mt-fw').querySelector('.mt-lanes');
    if (lanes && again) lanes.scrollLeft = scroll;
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

  /* ---- every port asked for, on the MikroTik ---- */
  function ports(d) {
    if (!d.on) return null;
    var ch = d.checks;
    var card = el('div', 'card full mt-ports');
    var h = el('h2', '', 'The ports asked for, on the MikroTik');
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'Every port a device asked fake-igd for in the last 30 days, and the mappings held now - as the MikroTik\'s firewall takes the first packet of a connection from the internet: raw prerouting, the dst-nat, then the filter\'s forward chain (first match wins); IPv6 to the device\'s own addresses. What is missing comes with the commands that would add it - for you to type: fake-igd never sends them.'));
    if (!ch) { card.appendChild(el('p', 'muted', d.reading ? 'Being read…' : 'Not read yet - Read it now, above.')); return card; }
    var chips = el('div', 'mt-chips');
    Object.keys(STATE).forEach(function (s) {
      var n = (ch.counts || {})[s] || 0;
      if (!n && s !== 'ok') return;
      var c = el('span', 'mt-chip ' + STATE[s][1]);
      c.appendChild(el('b', '', num(n)));
      c.appendChild(el('span', '', STATE[s][0]));
      explain(c, STATE[s][2]);
      chips.appendChild(c);
    });
    if (ch.wan && ch.wan.ifs && ch.wan.ifs.length) {
      var w = el('span', 'mt-chip dim');
      w.appendChild(el('span', '', 'WAN: ' + ch.wan.ifs.join(', ') + (ch.wan.addrs4.length ? ' · ' + ch.wan.addrs4.join(', ') : '')));
      explain(w, 'The router\'s side toward the internet, as ' + ch.wan.how + ' says.');
      chips.appendChild(noI18n(w));
    }
    card.appendChild(chips);
    card.appendChild(listTable(['Device', 'Port', {words: 'Asked', cls: 'num'}, 'IPv4 on the MikroTik', 'Why', 'IPv6', ''], ch.rows, function (r) {
      var tr = el('tr', 'tappable mt-row ' + (STATE[r.state] || STATE.unsure)[1]);
      var dev = el('td');
      dev.appendChild(noI18n(el('div', 'mono', r.device)));
      if (r.name) dev.appendChild(el('div', 'muted small', r.name));
      tr.appendChild(dev);
      var pt = el('td');
      pt.appendChild(el('span', 'tag ' + (r.proto === 'udp' ? 'violet' : 'info'), r.proto.toUpperCase()));
      pt.appendChild(noI18n(el('span', 'mono mt-port', ' ' + r.port + (r.to_port !== r.port ? ' → ' + r.to_port : ''))));
      tr.appendChild(pt);
      tr.appendChild(el('td', 'num', r.asked ? num(r.asked) : (r.held ? 'held' : '–')));
      var s = el('td');
      s.appendChild(tag((STATE[r.state] || STATE.unsure)[0], (STATE[r.state] || STATE.unsure)[1]));
      tr.appendChild(s);
      tr.appendChild(noI18n(el('td', 'small mt-why', r.state === 'ok' ? (r.forward_why || r.nat_why) : (r.nat_why + (r.forward === 'blocked' ? ' - ' + r.forward_why : '')))));
      var v6 = el('td');
      v6.appendChild(tag((V6[r.v6] || V6.none)[0], (V6[r.v6] || V6.none)[1]));
      tr.appendChild(v6);
      var tools = el('td', 'rowtools');
      if ((r.commands || []).length || (r.v6_commands || []).length) {
        var cp = iconButton('copy', 'Copy the commands that would add what is missing');
        cp.onclick = function (ev) { ev.stopPropagation(); copyText((r.commands || []).concat(r.v6_commands || []).join('\n'), cp, 'the commands are on the clipboard'); };
        tools.appendChild(cp);
      }
      var sh = iconButton('wall', 'Show its rules in the firewall below');
      sh.onclick = function (ev) { ev.stopPropagation(); showRules(r); };
      tools.appendChild(sh);
      tr.appendChild(tools);
      tr.onclick = function () { portPeek(r); };
      return tr;
    }, 'rows|No device has asked for a port in the last 30 days', {own: true}));
    if ((ch.merged || []).length > 0 && (ch.merged || []).some(function (m) { return m.ports.indexOf(',') >= 0 || m.ports.indexOf('-') >= 0; })) {
      card.appendChild(el('h3', 'peek-h', 'Rules to add, merged into ranges'));
      card.appendChild(el('p', 'note', 'The ports that have no dst-nat yet, one rule a device and protocol. Type them on the MikroTik yourself; the filter\'s default "drop all from WAN not DSTNATed" lets what they translate through.'));
      var spec = (MT.r && MT.r.snap && (MT.r.snap.iflists || {}).WAN) ? 'in-interface-list=WAN' : 'in-interface=ether1';
      card.appendChild(codeBlock(ch.merged.map(function (m) {
        return '/ip firewall nat add chain=dstnat action=dst-nat protocol=' + m.proto + ' dst-port=' + m.ports + ' ' + spec + ' to-addresses=' + m.device + ' comment="fake-igd: ' + m.device + '"';
      }).join('\n')));
    }
    return card;
  }
  function portPeek(r) {
    modal((r.name ? r.name + ' · ' : '') + r.device + ' ' + r.proto.toUpperCase() + ' ' + r.port, function (body) {
      var f = el('div', 'facts');
      [['IPv4 on the MikroTik', (STATE[r.state] || STATE.unsure)[0]], ['IPv6', (V6[r.v6] || V6.none)[0]], ['Asked', r.asked ? num(r.asked) + ' time(s)' : '–'],
       ['Last asked', r.last ? stamp(Date.parse(r.last) / 1000) : '–'], ['Held now', r.held ? 'yes' : 'no'], ['What for', r.description || '–']].forEach(function (p) {
        var cell = el('div', 'fact');
        cell.appendChild(el('span', 'k', p[0]));
        cell.appendChild(noI18n(el('span', 'v', p[1])));
        f.appendChild(cell);
      });
      body.appendChild(f);
      body.appendChild(el('p', 'note', (STATE[r.state] || STATE.unsure)[2]));
      body.appendChild(el('h3', 'peek-h', 'How the MikroTik takes it'));
      var st = [{what: 'The translation (nat dstnat)', ok: r.nat === 'dnat', said: r.nat_why},
                {what: 'The filter (forward)' + (r.nat === 'dnat' ? '' : ', once translated'), ok: r.forward === 'open', said: r.forward_why},
                {what: 'IPv6', ok: r.v6 === 'open' || r.v6 === 'none', said: r.v6_why}];
      body.appendChild(stepsOf(st));
      (r.notes || []).forEach(function (n) { body.appendChild(el('p', 'note warn', n)); });
      var cmds = (r.commands || []).concat(r.v6_commands || []);
      if (cmds.length) {
        body.appendChild(el('h3', 'peek-h', 'What would put it right'));
        body.appendChild(el('p', 'note', 'Commands for the MikroTik\'s terminal - fake-igd only reads, it never sends them. place-before puts a rule before the one that takes the packets first.'));
        body.appendChild(codeBlock(cmds.join('\n')));
      }
    }, [{words: 'Show its rules', icon: 'wall', go: function () { showRules(r); }, close: true}, {words: 'Close', close: true}], 'medium');
  }
  function showRules(r) {
    MT.q = 'port:' + r.port;
    MT.table = r.nat === 'dnat' && r.forward === 'blocked' ? 'filter' : 'nat';
    MT.fam = 'ip';
    draw(true);
    var fw = $('mt-fw');
    if (fw) fw.scrollIntoView({behavior: 'smooth', block: 'start'});
  }

  /* ---- the whole firewall ---- */
  var ACTION = {accept: 'ok', 'fasttrack-connection': 'ok', drop: 'crit', reject: 'crit', tarpit: 'crit', 'dst-nat': 'info', netmap: 'info',
    redirect: 'info', 'src-nat': 'violet', masquerade: 'violet', 'endpoint-independent-nat': 'violet', jump: 'dim', 'return': 'dim',
    passthrough: 'dim', log: 'warn', 'add-src-to-address-list': 'warn', 'add-dst-to-address-list': 'warn'};
  var HIDE = {'.id': 1, n: 1, chain: 1, action: 1, comment: 1, disabled: 1, dynamic: 1, invalid: 1, bytes: 1, packets: 1, hits: 1, log: 1,
    'log-prefix': 1, 'to-addresses': 1, 'to-ports': 1, 'jump-target': 1, 'hw-offload': 1, '.about': 1};
  var CHAIN_ORDER = ['prerouting', 'dstnat', 'input', 'forward', 'output', 'srcnat', 'postrouting'];
  var CHAIN_SAYS = {prerouting: 'every packet that comes in, before anything', dstnat: 'what comes in, before routing: where it is sent (DNAT)',
    input: 'to the router itself', forward: 'through the router', output: 'from the router itself', srcnat: 'what goes out: its source (masquerade)',
    postrouting: 'every packet that goes out'};
  function tableRules() {
    var s = MT.r && MT.r.snap;
    if (!s) return [];
    return (((s.rules || {})[MT.fam] || {})[MT.table]) || [];
  }
  function chipsOf(r) {
    var out = [];
    Object.keys(r).forEach(function (k) {
      if (HIDE[k] || r[k] === '' || r[k] === undefined || r[k] === null) return;
      var v = String(r[k]);
      var kind = /port/.test(k) ? 'port' : (/address-list/.test(k) ? 'list' : (/address/.test(k) ? 'addr' : (/interface/.test(k) ? 'if' : (/state/.test(k) ? 'state' : (k === 'protocol' ? 'proto' : 'other')))));
      out.push({k: k, v: v, kind: kind, neg: v.charAt(0) === '!'});
    });
    var order = {proto: 0, port: 1, addr: 2, list: 3, if: 4, state: 5, other: 6};
    out.sort(function (a, b) { return (order[a.kind] - order[b.kind]) || (a.k < b.k ? -1 : 1); });
    return out;
  }
  function chipWords(c) {
    var short = {protocol: '', 'dst-port': 'dport ', 'src-port': 'sport ', 'in-interface': 'in ', 'out-interface': 'out ', 'in-interface-list': 'in ',
      'out-interface-list': 'out ', 'src-address': 'from ', 'dst-address': 'to ', 'src-address-list': 'from list ', 'dst-address-list': 'to list ',
      'connection-state': '', 'connection-nat-state': 'nat ', 'ipsec-policy': 'ipsec '};
    var pre = short[c.k] !== undefined ? short[c.k] : c.k + '=';
    var v = c.neg ? c.v.slice(1) : c.v;
    return (c.neg ? 'not ' : '') + pre + v;
  }
  function matches(r, q) {
    if (!q) return true;
    return q.split(/\s+/).every(function (w) {
      if (!w) return true;
      var m = /^(port|action|chain|addr|list|if|comment):(.*)$/i.exec(w);
      if (m) {
        var k = m[1].toLowerCase(), v = m[2].toLowerCase();
        if (k === 'action') return String(r.action || '').toLowerCase() === v;
        if (k === 'chain') return String(r.chain || '').toLowerCase() === v;
        if (k === 'comment') return String(r.comment || '').toLowerCase().indexOf(v) >= 0;
        if (k === 'port') {
          var p = parseInt(v, 10);
          return ['dst-port', 'src-port', 'port', 'to-ports'].some(function (f) {
            return String(r[f] || '').replace(/^!/, '').split(',').some(function (x) {
              var ab = x.split('-');
              return ab.length === 2 ? (p >= +ab[0] && p <= +ab[1]) : +x === p;
            });
          });
        }
        if (k === 'list') return ['src-address-list', 'dst-address-list', 'address-list'].some(function (f) { return String(r[f] || '').toLowerCase().indexOf(v) >= 0; });
        if (k === 'if') return ['in-interface', 'out-interface', 'in-interface-list', 'out-interface-list'].some(function (f) { return String(r[f] || '').toLowerCase().indexOf(v) >= 0; });
        if (k === 'addr') return ['src-address', 'dst-address', 'to-addresses'].some(function (f) { return String(r[f] || '').indexOf(v) >= 0; });
      }
      return JSON.stringify(r).toLowerCase().indexOf(w.toLowerCase()) >= 0;
    });
  }
  function firewall() {
    var s = MT.r && MT.r.snap;
    if (!MT.d.on && !s) return null;
    var card = el('div', 'card full mt-fw');
    var h = el('h2', '', 'Its firewall');
    if (s) h.appendChild(el('span', 'right muted small', (s.identity || '') + ' · read ' + ago(s.at) + (s.prev_at ? ' · hits since the read before, ' + ago(s.prev_at) : '')));
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'Every rule of its filter, NAT, mangle and raw tables, IPv4 and IPv6, in order - each table\'s chains side by side, the first rule at the top: the first that matches decides. Its action in colour, what it matches as chips, what it has counted since the router started (the bar: its share of its chain\'s bytes). What concerns the ports fake-igd was asked for is lit; a rule opens with all its fields.'));
    if (!s) { card.appendChild(el('p', 'muted', 'Not read yet.')); return card; }
    /* the bar: IPv4 / IPv6, the tables, the search */
    var bar = el('div', 'mt-bar');
    var fam = el('div', 'seg');
    [['ip', 'IPv4'], ['ipv6', 'IPv6']].forEach(function (x) {
      var b = el('button', MT.fam === x[0] ? 'on' : '', x[1]);
      b.type = 'button';
      b.onclick = function () { MT.fam = x[0]; if (!((s.rules[MT.fam] || {})[MT.table] || []).length) MT.table = 'filter'; draw(true); };
      fam.appendChild(b);
    });
    bar.appendChild(fam);
    var tabs = el('div', 'seg');
    ['filter', 'nat', 'mangle', 'raw'].forEach(function (t) {
      var n = ((s.rules[MT.fam] || {})[t] || []).length;
      var b = el('button', MT.table === t ? 'on' : '');
      b.type = 'button';
      b.appendChild(document.createTextNode(t));
      b.appendChild(el('span', 'mt-n', n ? String(n) : '0'));
      b.onclick = function () { MT.table = t; draw(true); };
      tabs.appendChild(b);
    });
    bar.appendChild(tabs);
    var q = el('input');
    q.type = 'search';
    q.placeholder = 'port:9308 · action:drop · chain:forward · list:bad · if:WAN · an address, a word…';
    q.value = MT.q;
    q.className = 'mt-q';
    q.addEventListener('input', debounce(function () { MT.q = q.value; var at = q.selectionStart; draw(true); var nq = $('mt-fw').querySelector('.mt-q'); if (nq) { nq.focus(); try { nq.setSelectionRange(at, at); } catch (e) { } } }, 250));
    bar.appendChild(q);
    var mine = el('label', 'mt-mine');
    var tick = document.createElement('input');
    tick.type = 'checkbox';
    tick.checked = MT.mine;
    tick.onchange = function () { MT.mine = tick.checked; draw(true); };
    mine.appendChild(tick);
    mine.appendChild(document.createTextNode(' only what concerns fake-igd\'s ports'));
    bar.appendChild(mine);
    card.appendChild(bar);
    /* the lanes, and the side */
    var wrap = el('div', 'mt-view');
    var rules = tableRules();
    var concern = MT.r.concern || {};
    var chains = [];
    rules.forEach(function (r) { if (chains.indexOf(r.chain) < 0) chains.push(r.chain); });
    chains.sort(function (a, b) {
      var ia = CHAIN_ORDER.indexOf(a), ib = CHAIN_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a < b ? -1 : 1);
    });
    var lanes = el('div', 'mt-lanes');
    var shown = 0;
    chains.forEach(function (ch) {
      var mine2 = rules.filter(function (r) { return r.chain === ch; });
      var total = mine2.reduce(function (a, r) { return a + (r.bytes || 0); }, 0) || 1;
      var keep = mine2.filter(function (r) { return matches(r, MT.q) && (!MT.mine || concern[MT.fam + ':' + r['.id']]); });
      var lane = el('div', 'mt-lane');
      var lh = el('div', 'mt-lane-h');
      lh.appendChild(noI18n(el('b', 'mono', ch)));
      lh.appendChild(el('span', 'muted small', CHAIN_SAYS[ch] || 'a chain of its own (jumped to)'));
      lh.appendChild(el('span', 'mt-n', keep.length === mine2.length ? String(mine2.length) : keep.length + ' / ' + mine2.length));
      lane.appendChild(lh);
      keep.forEach(function (r) { lane.appendChild(ruleCard(r, total, concern[MT.fam + ':' + r['.id']])); shown++; });
      if (!keep.length) lane.appendChild(el('div', 'mt-empty muted small', mine2.length ? 'nothing here matches' : 'no rule'));
      var end = el('div', 'mt-lane-end muted small', MT.table === 'filter' || MT.table === 'raw' ? 'then: accept (a chain lets through what no rule stopped)' : (MT.table === 'nat' ? 'then: not translated' : 'then: on, unmarked'));
      lane.appendChild(end);
      lanes.appendChild(lane);
    });
    if (!chains.length) lanes.appendChild(el('div', 'mt-empty muted', 'The ' + MT.table + ' table of ' + (MT.fam === 'ip' ? 'IPv4' : 'IPv6') + ' has no rule' + ((s.missing || {})[MT.table + (MT.fam === 'ip' ? '4' : '6')] ? ' - it could not be read: ' + s.missing[MT.table + (MT.fam === 'ip' ? '4' : '6')] : '') + '.'));
    wrap.appendChild(lanes);
    wrap.appendChild(side(s));
    card.appendChild(wrap);
    card.appendChild(legend());
    return card;
  }
  function ruleCard(r, total, concerns) {
    var a = r.action || 'accept';
    var c = el('div', 'mt-rule ' + (ACTION[a] || 'dim') + (r.disabled ? ' off' : '') + (r.dynamic ? ' dyn' : '') + (concerns ? ' mine' : '') + (r.invalid ? ' invalid' : ''));
    c.tabIndex = 0;
    var top = el('div', 'mt-rule-top');
    top.appendChild(noI18n(el('span', 'mt-num', '#' + r.n)));
    var act = el('span', 'mt-act ' + (ACTION[a] || 'dim'), a + (r['to-addresses'] ? ' → ' + r['to-addresses'] + (r['to-ports'] ? ':' + r['to-ports'] : '') : '') + (a === 'jump' ? ' → ' + (r['jump-target'] || '') : ''));
    top.appendChild(noI18n(act));
    if (r.disabled) top.appendChild(tag('disabled', 'dim'));
    if (r.dynamic) top.appendChild(tag('dynamic', 'info'));
    if (r.invalid) top.appendChild(tag('invalid', 'crit'));
    if (r.log) top.appendChild(tag('log', 'warn'));
    c.appendChild(top);
    if (r.comment) c.appendChild(noI18n(el('div', 'mt-comment', r.comment)));
    var chips = el('div', 'mt-chips-r');
    var list = chipsOf(r);
    list.forEach(function (x) { chips.appendChild(noI18n(el('span', 'mt-c ' + x.kind + (x.neg ? ' neg' : ''), chipWords(x)))); });
    if (!list.length) chips.appendChild(el('span', 'mt-c any', 'every packet'));
    c.appendChild(chips);
    var cnt = el('div', 'mt-count');
    var barw = el('div', 'mt-cbar');
    var fillb = el('span');
    fillb.style.width = Math.max(r.bytes ? 2 : 0, Math.round(100 * (r.bytes || 0) / total)) + '%';
    barw.appendChild(fillb);
    cnt.appendChild(barw);
    cnt.appendChild(el('span', 'small muted', num(r.packets || 0) + ' pkt · ' + bytes(r.bytes || 0) + (r.hits !== undefined ? ' · +' + num(r.hits) + ' since' : '')));
    c.appendChild(cnt);
    if (concerns) c.appendChild(noI18n(el('div', 'mt-concern small', concerns.slice(0, 4).join(' · ') + (concerns.length > 4 ? ' …' : ''))));
    c.onclick = function () { rulePeek(r, concerns); };
    c.onkeydown = function (ev) { if (ev.key === 'Enter') rulePeek(r, concerns); };
    return c;
  }
  function rulePeek(r, concerns) {
    modal((MT.fam === 'ip' ? '/ip' : '/ipv6') + ' firewall ' + MT.table + ' #' + r.n + ' · ' + r.chain + ' · ' + (r.action || ''), function (body) {
      if (r.comment) body.appendChild(noI18n(el('p', 'note', r.comment)));
      if (concerns) body.appendChild(noI18n(el('p', 'note info', 'It concerns: ' + concerns.join(' · '))));
      var keys = Object.keys(r).filter(function (k) { return k !== 'n' && k !== 'hits'; }).sort(function (a, b) {
        var top = ['.id', 'chain', 'action', 'disabled', 'dynamic', 'packets', 'bytes'];
        var ia = top.indexOf(a), ib = top.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || (a < b ? -1 : 1);
      });
      body.appendChild(listTable(['Field', 'Value'], keys, function (k) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono small', k)));
        var v = r[k];
        tr.appendChild(noI18n(el('td', 'mono small', k === 'bytes' ? num(v) + ' (' + bytes(v) + ')' : (k === 'packets' ? num(v) : String(v)))));
        return tr;
      }, 'plain|Nothing'));
      if (r.hits !== undefined) body.appendChild(el('p', 'muted small', num(r.hits) + ' packet(s) since the read before.'));
    }, [{words: 'Close', close: true}], 'medium');
  }
  function side(s) {
    var box = el('div', 'mt-side');
    /* the interfaces, with their lists */
    var ifs = el('div', 'mt-panel');
    ifs.appendChild(el('h3', 'peek-h', 'Interfaces'));
    var lists = s.iflists || {};
    var inList = function (n) { return Object.keys(lists).filter(function (l) { return ['all', 'none', 'dynamic', 'static'].indexOf(l) < 0 && (lists[l] || []).indexOf(n) >= 0; }); };
    var addrs = (s.addresses4 || []).concat(MT.fam === 'ipv6' ? (s.addresses6 || []) : []);
    (s.interfaces || []).forEach(function (i) {
      var row = el('div', 'mt-if' + (i.disabled ? ' off' : ''));
      row.appendChild(el('span', 'dot ' + (i.running ? 'ok' : 'bad')));
      row.appendChild(noI18n(el('b', 'mono', i.name)));
      inList(i.name).forEach(function (l) { row.appendChild(tag(l, l === 'WAN' ? 'warn' : (l === 'LAN' ? 'ok' : 'info'))); });
      var a = addrs.filter(function (x) { return x.interface === i.name; }).map(function (x) { return x.address; });
      if (a.length) row.appendChild(noI18n(el('div', 'mono small muted mt-if-a', a.join(' · '))));
      ifs.appendChild(row);
    });
    box.appendChild(ifs);
    /* the address lists */
    var al = el('div', 'mt-panel');
    al.appendChild(el('h3', 'peek-h', 'Address lists'));
    var ll = (s.lists || {})[MT.fam] || {};
    var names = Object.keys(ll).sort();
    if (!names.length) al.appendChild(el('p', 'muted small', 'none'));
    names.forEach(function (n) {
      var d = document.createElement('details');
      d.className = 'mt-list';
      var sm = document.createElement('summary');
      sm.appendChild(noI18n(el('b', 'mono', n)));
      sm.appendChild(el('span', 'mt-n', String(ll[n].length)));
      d.appendChild(sm);
      ll[n].slice(0, 200).forEach(function (e) {
        var row = el('div', 'mt-le' + (e.disabled ? ' off' : ''));
        row.appendChild(noI18n(el('span', 'mono small', e.address)));
        if (e.comment) row.appendChild(noI18n(el('span', 'muted small', e.comment)));
        if (e.dynamic) row.appendChild(tag('dynamic', 'info'));
        d.appendChild(row);
      });
      if (ll[n].length > 200) d.appendChild(el('div', 'muted small', '… and ' + num(ll[n].length - 200) + ' more'));
      al.appendChild(d);
    });
    box.appendChild(al);
    return box;
  }
  function legend() {
    var l = el('div', 'mt-legend small muted');
    [['ok', 'accept'], ['crit', 'drop / reject'], ['info', 'dst-nat'], ['violet', 'src-nat / masquerade'], ['dim', 'jump / return / passthrough'], ['warn', 'log / address list']].forEach(function (x) {
      var s = el('span', 'mt-lg');
      s.appendChild(el('span', 'mt-sw ' + x[0]));
      s.appendChild(document.createTextNode(x[1]));
      l.appendChild(s);
    });
    var m = el('span', 'mt-lg');
    m.appendChild(el('span', 'mt-sw mine'));
    m.appendChild(document.createTextNode('concerns a port asked for'));
    l.appendChild(m);
    return l;
  }

  PANE_LOAD.mikrotik = load;
  /* For Overview and the Ports tab: the checks, read once a minute at most. */
  window.MT_CHECKS = function () {
    var now = Date.now();
    if (window.MT_CACHE && now - window.MT_CACHE.at < 60000) return Promise.resolve(window.MT_CACHE.d);
    return api('mikrotik').then(function (d) { window.MT_CACHE = {at: now, d: d}; return d; });
  };
  window.MT_STATE = STATE;
})();
