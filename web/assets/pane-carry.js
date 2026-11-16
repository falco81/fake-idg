/* pane-carry.js - Settings → Export and import (otp's ex-plain, ex-whole, ex-load, for fake-igd). */
(function () {
  'use strict';
  function saveFile(name, text) {
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function loadCarry() {
    var host = $('ex-what');
    if (!host || !ADMIN) return;
    api('carry').then(function (d) {
      clear(host);
      var w = d.what || {};
      host.appendChild(peekFacts([
        ['Settings of config.json', num(w.config)], ['Settings saved on these pages', num(w.settings)],
        ['Accounts', num(w.users)], ['Destinations of the backups', num(w.backup_targets)],
        ['avahi-daemon.conf', w.avahi ? 'in it' : 'not readable here'], ['fake-igd', d.version]
      ]));
      host.appendChild(el('p', 'btnhelp', 'On the command line the same file is read by nothing else: carry it to the other machine and use Import a file… there.'));
    }).catch(oops);
  }
  PANE_LOAD.carry = loadCarry;

  if ($('ex-plain')) $('ex-plain').onclick = function () {
    api('carry', {action: 'export'}).then(function (d) { saveFile(d.name, JSON.stringify(d.config, null, 2)); toast(d.name, 'good'); }).catch(oops);
  };
  if ($('ex-whole')) $('ex-whole').onclick = function () {
    confirmThen('Export with the secrets', 'The ntfy token and password, the password of the backups, the password hashes of the accounts, the passwords and keys of the destinations of the backups and the private key of the pages’ certificate go into the file - locked with a passphrase made now and shown once. The file opens only with it.',
      'Export them', function () {
        toast('root collects the certificate - a moment', 'good');
        api('carry', {action: 'export', secrets: true}, 330).then(function (d) {
          saveFile(d.name, JSON.stringify(d.bundle, null, 2));
          modal('The passphrase of the file', function (body) {
            body.appendChild(el('p', 'note', 'The file opens only with this passphrase - it is not shown again and not kept here. Write it down apart from the file.'));
            if (!d.tls) body.appendChild(el('p', 'note warn', 'The certificate of the pages is not in it: ' + (d.tls_said || 'root did not give it') + '.'));
            body.appendChild(el('p', '', '')).appendChild(copyOnClick(noI18n(el('span', 'keytext', d.passphrase)), d.passphrase, 'the passphrase was copied'));
          }, [{words: 'Close', close: true}], 'small');
        }).catch(oops);
      });
  };
  if ($('ex-load')) $('ex-load').onclick = function () { $('ex-file').click(); };
  if ($('ex-file')) $('ex-file').onchange = function () {
    var f = this.files && this.files[0];
    this.value = '';
    if (!f) return;
    f.text().then(function (t) {
      var conf;
      try { conf = JSON.parse(t); } catch (e) { toast('the file is not JSON - is it the right file?', 'bad'); return; }
      if (!conf || typeof conf !== 'object' || Array.isArray(conf)) { toast('the file is not JSON - is it the right file?', 'bad'); return; }
      var locked = conf.kind === 'fake-igd-config-locked';
      var phrase = null;
      var go = function (replace) {
        api('carry-import', {config: conf, replace: replace, passphrase: phrase ? phrase.value : ''}, 330).then(function (d) {
          toast(d.message, 'good');
          if ((d.made && d.made.length) || (d.said && d.said.length)) {
            modal('Imported', function (body) {
              (d.said || []).forEach(function (s) { body.appendChild(noI18n(el('p', 'note', s))); });
              if (d.made && d.made.length) {
                body.appendChild(el('p', 'note', 'These accounts were not here and the file has no passwords for them: each was made with a password shown only now, to be changed at the first sign-in.'));
                body.appendChild(kvTable(d.made.map(function (m) { return [m.name, copyOnClick(noI18n(el('span', 'keytext', m.password)), m.password, 'copied')]; })));
              }
            }, [{words: 'Close', close: true}], 'medium');
          }
          loadSettings();
        }).catch(oops);
      };
      modal('Import ' + f.name, function (body) {
        if (locked) {
          body.appendChild(el('p', 'note', 'Exported with the secrets, it is locked: the passphrase shown when it was exported opens it.'));
          phrase = textBox('', 'the passphrase', 'mono');
          phrase.type = 'password';
          noI18n(phrase);
          body.appendChild(formField('Passphrase', phrase));
        } else if (conf.kind === 'fake-igd-config') {
          body.appendChild(peekFacts([['From', conf.from || '?'], ['fake-igd', conf.version || '?'], ['Made', conf.made ? stamp(conf.made) : '?'],
            ['Accounts', num((conf.users || []).length)], ['Destinations', num((conf.backup_targets || []).length)]]));
        }
        body.appendChild(el('p', 'note', 'Accounts and destinations of the backups of the same name are replaced; the settings, avahi-daemon.conf and (with the secrets) the certificate of the pages in it are saved. Your own account is left as it is.'));
        body.appendChild(el('p', 'note', 'Add to what is here: anything not in the file stays. Exactly the file: accounts and destinations not in it are taken away, and settings not in it go back to their defaults - as when a whole configuration is put back.'));
        body.appendChild(el('p', 'note', 'This machine’s own folders and the port of the pages’ API stay as they are.'));
      }, [{words: 'Close', close: true},
          {words: 'Exactly the file', cls: 'danger', icon: 'upload', close: true, go: function () { go(true); }},
          {words: 'Add to what is here', cls: 'primary', icon: 'upload', close: true, go: function () { go(false); }}], 'medium');
    }).catch(oops);
  };
}());
