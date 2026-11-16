/* Settings → SSH keys (otp's loadSshKeys / drawSshKeys, 1.0.158, 1.0.240, 1.0.280).
   Whose keys: root's - only shown, put on and taken away by root on the machine itself - or
   a user's who may sign in here: their own ~/.ssh/authorized_keys, listed, a key added (a
   line of your own, or made here - its private half shown once, kept nowhere), exported,
   taken away. One row a key, by its fingerprint. */
(function () {
  var SK = {d: null, poll: null, asked: 0, user: 'root', askedU: {}, until: 0};

  function netFacts(rows) {
    var dl = el('div', 'net-facts');
    rows.forEach(function (r) {
      if (r[1] === undefined) return;
      var one = el('div', 'net-fact');
      one.appendChild(el('span', 'k', r[0]));
      var v = el('span', 'v' + (r[2] ? ' mono' : ''));
      if (r[1] instanceof Node) v.appendChild(r[1]); else v.textContent = r[1] === '' || r[1] === null ? '–' : String(r[1]);
      if (r[2]) noI18n(v);
      one.appendChild(v);
      dl.appendChild(one);
    });
    return dl;
  }
  function rbPanel(note) {
    var box = el('div', 'subpanel rb-panel');
    var p = el('p', 'note');
    p.innerHTML = note;
    box.appendChild(p);
    var row = el('div', 'btnrow');
    box.appendChild(row);
    var below = el('div', 'rb-below');
    box.appendChild(below);
    return {box: box, row: row, below: below};
  }
  function rbCopyme(text, said) {
    var code = noI18n(el('code', 'copyme', text));
    explain(code, 'Click to copy.');
    code.onclick = function () { copyText(text, code, said || 'Copied'); };
    return code;
  }
  function liveLetGo(host) {
    if (!host || host._letGo) return;
    host._letGo = true;
    host.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('button') : null;
      if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
    });
  }

  function users() { return ((SK.d && SK.d.users) || []).map(function (u) { return u.name; }).sort(); }
  function keysOf(user) { return (((SK.d && SK.d.keys_of) || {})[user] || {}); }
  function pending() { return !!(SK.d && SK.d.pending); }
  function poll(on) {
    if (on && !SK.poll) {
      SK.poll = setInterval(function () {
        if (TAB !== 'settings' || PANE !== 'sshkeys') { poll(false); return; }
        api('sshkeys').then(function (d) {
          SK.d = d; draw(true);
          if (!pending() && Date.now() >= SK.until) {
            poll(false);
            /* A read lost under another one's answer: asked once more. */
            if (!keysOf(SK.user).at && Date.now() - (SK.askedU[SK.user] || 0) > 8000) askUser(SK.user);
          }
        }).catch(function () {});
      }, 2000);
    }
    if (!on && SK.poll) { clearInterval(SK.poll); SK.poll = null; }
  }
  function askUser(user) {
    SK.askedU[user] = Date.now();
    SK.until = Date.now() + 15000;
    api('sshkeys', {action: 'refresh', user: user}).then(function (d) { SK.d = d; draw(true); poll(true); }).catch(function () {});
  }
  function load() {
    api('sshkeys').then(function (d) {
      SK.d = d; draw();
      /* Read afresh when the pane is opened. */
      if (Date.now() - SK.asked > 20000) {
        SK.asked = Date.now();
        askUser(SK.user);
      }
      poll(pending() || Date.now() < SK.until);
    }).catch(oops);
  }
  function kind(k) {
    var t = String(k.type || '?').toUpperCase();
    return t + (k.bits && t !== 'ED25519' ? ' ' + k.bits : '');
  }
  function draw(live) {
    var real = $('sk-host');
    if (!real || !SK.d) return;
    liveLetGo(real);
    liveFill(real, function (host) {
      var d = SK.d, sd = d.sshd || {};
      var me = SK.user;
      if (d.late) host.appendChild(el('p', 'note bad', d.late));
      if (sd.there && sd.permit_root === 'no' && me === 'root')
        host.appendChild(el('p', 'note warn', 'sshd does not let root sign in at all (PermitRootLogin no) - the keys below are not used until it does.'));
      if (sd.there && sd.pubkey === 'no')
        host.appendChild(el('p', 'note warn', 'sshd takes no keys (PubkeyAuthentication no).'));
      var mine = keysOf(me);
      if (mine.error) host.appendChild(el('p', 'note bad', mine.error));
      if (d.last && d.last.at && !d.last.ok && Date.now() / 1000 - d.last.at < 600)
        host.appendChild(el('p', 'note bad', 'Refused for ' + d.last.user + ': ' + d.last.said));
      /* Whose keys: root, or a user who may sign in here. */
      var us = users();
      if (me !== 'root' && us.indexOf(me) < 0 && d.at) { SK.user = me = 'root'; mine = keysOf(me); }
      var who = el('div', 'card full sk-who');
      var wh = el('div', 'sk-who-row');
      wh.appendChild(el('span', 'k', 'Whose keys'));
      var sel = el('select', 'mono');
      var o0 = el('option', '', 'root'); o0.value = 'root'; sel.appendChild(o0);
      us.forEach(function (u) { var o = noI18n(el('option', '', u)); o.value = u; sel.appendChild(o); });
      sel.value = me;
      sel.onchange = function () {
        SK.user = sel.value;
        if (Date.now() - (SK.askedU[SK.user] || 0) > 20000) askUser(SK.user);
        draw();
      };
      wh.appendChild(sel);
      wh.appendChild(el('span', 'muted small', us.length
        ? 'root, or one of the ' + us.length + ' users who may sign in here (a login shell, UID 1000 and up) - their own ~/.ssh/authorized_keys, written as they are.'
        : 'Only root: no other user who may sign in (a login shell, UID 1000 and up) is on this server - Local users makes one.'));
      who.appendChild(wh);
      host.appendChild(who);
      if (me === 'root') host.appendChild(rootNote());
      else host.appendChild(userCard(d, me));
      var card = el('div', 'card full');
      var h = el('h2', '', me === 'root' ? 'Keys that may sign in as root' : 'Keys that may sign in as');
      if (me !== 'root') h.appendChild(noI18n(el('span', 'mono', ' ' + me)));
      var tools = el('span', 'right');
      if (me !== 'root') {
        var add = cmdButton('Add a key', 'upload', 'small');
        explain(add, 'A key you have already - its public line or .pub file, or the private key, of which only the public half is used.');
        add.onclick = addKey;
        tools.appendChild(add);
      }
      var again = iconButton('refresh', 'Read the keys again');
      again.onclick = function () { askUser(SK.user); toast('asked again'); };
      tools.appendChild(again);
      h.appendChild(tools);
      card.appendChild(h);
      var keys = mine.keys || [];
      if (!keys.length) {
        card.appendChild(el('p', 'note', !mine.at ? 'Reading the keys…' : me === 'root'
          ? 'No key lets root in over SSH here.' : 'No key lets ' + me + ' in over SSH here.'));
      } else {
        var box = el('div', 'scroll rowsonly');
        box.appendChild(listTable(['Key', 'Fingerprint', 'Comment', ''], keys, function (k) {
          var tr = el('tr');
          var t = el('td');
          t.appendChild(el('span', 'tag ' + (String(k.type).toUpperCase() === 'ED25519' ? 'good' : 'info'), kind(k)));
          if (k.options) t.appendChild(el('span', 'tag warn', 'with options'));
          if (!k.readable) t.appendChild(el('span', 'tag bad', 'not read'));
          tr.appendChild(t);
          tr.appendChild(noI18n(el('td', 'mono small', k.fp || '–')));
          tr.appendChild(noI18n(el('td', 'small', k.comment || '–')));
          var a = el('td', 'right sk-act');
          var ex = iconButton('download', 'Export this key - its public half, as a .pub file');
          ex.disabled = !k.text;
          ex.onclick = function () { exportKey(k); };
          a.appendChild(ex);
          if (me !== 'root') {
            var rm = iconButton('trash', 'Take this key away');
            rm.disabled = !k.fp;
            rm.onclick = function () { dropKey(k); };
            a.appendChild(rm);
          }
          tr.appendChild(a);
          return tr;
        }, 'plain', {own: true}));
        card.appendChild(box);
      }
      if (d.pending) card.appendChild(el('p', 'muted small', 'Being written…'));
      host.appendChild(card);
      /* This server's facts. */
      var grid = el('div', 'pw-grid');
      var c = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (d.at ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', d.node || 'this server')));
      hd.appendChild(el('span', 'tag info', 'this page'));
      c.appendChild(hd);
      if (me !== 'root') {
        c.appendChild(netFacts([
          ['Keys', String(keys.length)],
          ['The user', 'may sign in here'],
          ['With a password', sd.there ? (sd.password || '?') : ''],
          ['SSH port', sd.port || '', true],
          ['The file', mine.file || '~' + me + '/.ssh/authorized_keys', true],
          ['Read', mine.at ? ago(mine.at) : 'not yet']
        ]));
      } else {
        c.appendChild(netFacts([
          ['Keys', String(keys.length)],
          ['Root may sign in', sd.there ? (sd.permit_root || '?') : 'sshd is not here'],
          ['With a password', sd.there ? (sd.password || '?') : ''],
          ['SSH port', sd.port || '', true],
          ['The file', mine.file || '/root/.ssh/authorized_keys', true],
          ['Read', mine.at ? ago(mine.at) : 'not yet']
        ]));
      }
      grid.appendChild(c);
      host.appendChild(grid);
    }, live);
  }
  /* Root's keys are only shown (otp 1.0.280): put on and taken away by root on the machine itself. */
  function rootNote() {
    var card = el('div', 'card full');
    card.appendChild(el('h2', '', 'Keys for root'));
    var p = el('p', 'note');
    p.innerHTML = 'Root\'s keys are only shown here - none is made, put on or taken away from these pages. That is done by root on the machine itself, in <code>/root/.ssh/authorized_keys</code>. A key for another user who may sign in here is made or added here: choose them under <b>Whose keys</b>.';
    card.appendChild(p);
    return card;
  }
  /* A key for a user: made here, its private half shown once - remembered nowhere. */
  function userCard(d, user) {
    var card = el('div', 'card full');
    var h = el('h2', '', 'A key for');
    h.appendChild(noI18n(el('span', 'mono', ' ' + user)));
    card.appendChild(h);
    var P = rbPanel('Its <b>public</b> half goes into <code>~' + htmlText(user) + '/.ssh/authorized_keys</code> - written as ' + htmlText(user) + ', so that the folder and the file are theirs. The <b>private</b> half is never kept here: it is shown to you once, to hand over. The key is then in the list below - exported or taken away there; a key of their own is added there too.');
    if (!d.keygen) {
      var miss = el('p', 'note');
      miss.style.color = 'var(--warn)';
      miss.textContent = 'ssh-keygen is not on this machine, so a key cannot be made here: dnf install openssh-clients.';
      P.box.insertBefore(miss, P.row);
    }
    var mk = cmdButton('Make a key', 'key', '');
    explain(mk, 'Make a fresh pair here - Ed25519, or RSA 4096 where something old needs RSA. Its private half is shown to you once; its public half goes into ' + user + '\'s authorized_keys.');
    mk.disabled = !d.keygen;
    mk.onclick = function () {
      var kd = 'ed25519';
      modal('Make a key for ' + user, function (body) {
        body.appendChild(el('p', 'note', 'A fresh pair is made here. Its private half is shown to you once, to download or copy, and kept nowhere; its public half goes into ' + user + '\'s authorized_keys. A key there before stays until it is taken away in the list below.'));
        var sg = el('div', 'seg');
        [['ed25519', 'Ed25519 (the strongest, and short)'], ['rsa4096', 'RSA 4096 (where something old needs RSA)']].forEach(function (o) {
          var b = el('button', o[0] === kd ? 'on' : '', o[1]);
          b.type = 'button';
          b.onclick = function () { kd = o[0]; Array.prototype.forEach.call(sg.children, function (x) { x.classList.remove('on'); }); b.classList.add('on'); };
          sg.appendChild(b);
        });
        body.appendChild(formField('The kind', sg));
      }, [{words: 'Cancel', close: true}, {words: 'Make one', cls: 'primary', icon: 'key', go: function (b) {
        busy(b, true);
        api('sshkeys', {action: 'uk_make', user: user, kind: kd}).then(function (x) {
          showMade(x, user);
          SK.until = Date.now() + 15000;
          return api('sshkeys');
        }).then(function (d2) { SK.d = d2; draw(); poll(true); })
          .catch(function (e) { busy(b, false); oops(e); });
      }}], 'medium');
    };
    P.row.appendChild(mk);
    card.appendChild(P.box);
    return card;
  }
  function showMade(x, user) {
    modal('Keep the private key now', function (body) {
      var w = el('p', 'note warn');
      w.textContent = 'This is the only time it is shown. Whoever holds it signs in to ' + ((SK.d && SK.d.node) || 'this server') + ' as ' + user + '.';
      body.appendChild(w);
      var area = noI18n(el('textarea', 'mono'));
      area.rows = 9; area.readOnly = true; area.value = x.private; area.spellcheck = false;
      body.appendChild(area);
      var row = el('div', 'btnrow');
      var dl = cmdButton('Download the key', 'download', 'primary');
      dl.onclick = function () { save(x.private, x.file); };
      var cp = cmdButton('Copy it', 'copy', '');
      cp.onclick = function () { copyText(x.private, cp, 'the private key is on the clipboard'); };
      row.appendChild(dl); row.appendChild(cp);
      row.style.margin = '12px 0 16px';
      body.appendChild(row);
      body.appendChild(el('p', 'btnhelp', 'Its public half, put on the server - click it to copy:'));
      body.appendChild(rbCopyme(x.pub, 'the public key is on the clipboard'));
      body.appendChild(noI18n(el('p', 'muted small mono', x.fp)));
      body.appendChild(el('p', 'btnhelp', 'Then, on your machine: ssh -i ' + x.file + ' ' + user + '@' + ((SK.d && SK.d.node) || '…')));
    }, [{words: 'I have kept it', cls: 'primary', close: true}], 'medium');
  }
  function save(text, file) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], {type: 'application/octet-stream'}));
    a.download = file;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
  /* One key's public half as a .pub file, named by its comment. */
  function exportKey(k) {
    var name = String(k.comment || k.type || 'key').replace(/[^A-Za-z0-9@._-]+/g, '_').replace(/^[._]+/, '').slice(0, 60) || 'key';
    save(k.text + '\n', name + '.pub');
    toast('the key is exported as ' + name + '.pub', 'good');
  }
  function addKey() {
    var area, pp, ppf, user = SK.user;
    modal('Add a key for ' + user, function (body) {
      var p = el('p', 'note');
      p.innerHTML = 'One line of a <code>.pub</code> file: <code>ssh-ed25519 AAAA… you@laptop</code>. Ed25519, ECDSA or RSA of 3072 bits and more; options before the key are not taken here. A private key is taken too: its public half is worked out here and the private half is not kept.';
      body.appendChild(p);
      area = noI18n(el('textarea', 'mono'));
      area.rows = 4; area.spellcheck = false; area.placeholder = 'ssh-ed25519 AAAA… you@laptop';
      body.appendChild(area);
      var fr = el('div', 'btnrow');
      fr.style.margin = '8px 0 4px';
      var pickB = cmdButton('Read a file…', 'upload', 'small');
      var input = el('input'); input.type = 'file'; input.hidden = true;
      pickB.onclick = function () { input.click(); };
      input.onchange = function () {
        var f = input.files && input.files[0];
        if (!f) return;
        if (f.size > 65536) { toast('that file is far bigger than a key', 'warn'); return; }
        f.text().then(function (t) { t = t.trim(); area.value = t.indexOf('PRIVATE KEY') >= 0 ? t : t.split(/\r?\n/)[0]; ppShow(); });
      };
      fr.appendChild(pickB); fr.appendChild(input);
      body.appendChild(fr);
      pp = maskBox('', '', 'mono');
      ppf = formField('Its passphrase, if the private key has one', pp);
      var ppShow = function () { ppf.hidden = area.value.indexOf('PRIVATE KEY') < 0; };
      area.oninput = ppShow;
      ppShow();
      body.appendChild(ppf);
      setTimeout(function () { area.focus(); }, 60);
    }, [{words: 'Cancel', close: true}, {words: 'Add it', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      api('sshkeys', {action: 'add', line: area.value.trim(), passphrase: pp.value, user: user}).then(function (x) {
        closeModal(); toast(x.message, 'good'); SK.d = x; SK.until = Date.now() + 15000; draw(); poll(true);
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  }
  function dropKey(k) {
    var user = SK.user;
    confirmThen('Take the key away', htmlText(user) + ' no longer signs in with <code>' + htmlText(k.fp || '') + '</code>' + (k.comment ? ' (' + htmlText(k.comment) + ')' : '') + '.',
      'Take it away', function () {
        api('sshkeys', {action: 'drop', fp: k.fp, user: user}).then(function (x) { toast(x.message, 'good'); SK.d = x; SK.until = Date.now() + 15000; draw(); poll(true); }).catch(oops);
      }, true);
  }
  PANE_LOAD.sshkeys = load;
  PANE_TICK.sshkeys = function () {
    if (SK.poll) return;
    api('sshkeys').then(function (d) { SK.d = d; draw(true); }).catch(function () {});
  };
})();
