/* pane-people.js - Settings → people (moved out of admin.js, 1.6.1). */
'use strict';

/* ---- accounts ----------------------------------------------------------------- */
function loadUsers() {
  api('users').then(function (d) {
    var host = $('us-table');
    clear(host);
    host.appendChild(listTable(['Name', 'Role', 'Signed in now', 'Last sign-in', 'From', 'Note'], d.users, function (u) {
      var tr = el('tr', ADMIN ? 'tappable' : '');
      var nm = el('td'); nm.appendChild(noI18n(el('b', '', u.name)));
      if (u.name.toLowerCase() === d.me.toLowerCase()) { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'you')); }
      tr.appendChild(nm);
      var rl = el('td'); rl.appendChild(el('span', 'tag ' + roleTone(u.role), roleWords(u.role))); tr.appendChild(rl);
      tr.appendChild(el('td', u.sessions ? 'good' : 'muted', u.sessions ? num(u.sessions) : '–'));
      tr.appendChild(stampCell(u.last_login));
      tr.appendChild(noI18n(el('td', 'mono muted', u.last_from || '')));
      tr.appendChild(noI18n(el('td', '', u.note || '')));
      if (ADMIN) tr.onclick = function () { userEdit(u, d.me); };
      return tr;
    }, 'plain|No account yet'));
    var se = $('se-table');
    clear(se);
    se.appendChild(listTable(['Account', 'From', 'Signed in', 'Last seen', 'Browser', ''], d.sessions, function (x) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', '', x.name)));
      tr.appendChild(noI18n(el('td', 'mono', x.addr)));
      tr.appendChild(stampCell(x.created));
      tr.appendChild(stampCell(x.seen));
      tr.appendChild(noI18n(el('td', 'muted small', (x.agent || '').slice(0, 80))));
      var td = el('td');
      var end = iconButton('close', 'End this sign-in');
      end.onclick = function () {
        api('users', {action: 'end-session', id: x.id}).then(function (r) { toast(r.message, 'good'); loadUsers(); }).catch(oops);
      };
      td.appendChild(end);
      tr.appendChild(td);
      return tr;
    }, 'plain|Nobody'));
    explainWhatWasDrawn($('pane-people'));
  }).catch(oops);
}
function saidPassword(name, pw) {
  modal('The password of ' + name, function (body) {
    body.appendChild(el('p', 'note', 'Made here and shown once - give it to its owner now.'));
    var code = noI18n(el('div', 'mono big', pw));
    copyOnClick(code, pw, 'copied');
    body.appendChild(code);
  }, null, true);
}
$('us-add').onclick = function () {
  modal('Make an account', function (body) {
    var n = textBox('', 'a name: letters, digits . _ @ -'); n.id = 'ua-name';
    var r = selectBox([['fulladmin', 'full admin - may change everything'], ['readonly', 'read only - may look']], 'readonly'); r.id = 'ua-role';
    var p = maskBox('', 'empty = make one and show it', 'mono'); p.id = 'ua-pass';
    var t = textBox('', ''); t.id = 'ua-note';
    body.appendChild(formField('Name', n));
    body.appendChild(formField('Role', r));
    body.appendChild(formField('Password', p, 'At least 8 characters. Empty: one is made and shown once.'));
    body.appendChild(formField('Note', t));
  }, [{words: 'Close', close: true}, {words: 'Make it', cls: 'primary', icon: 'add', go: function (b) {
    busy(b, true);
    api('users', {action: 'add', name: $('ua-name').value.trim(), role: $('ua-role').value,
                  password: $('ua-pass').value, note: $('ua-note').value}).then(function (d) {
      toast(d.message, 'good');
      var name = $('ua-name').value.trim();
      closeModal();
      loadUsers();
      if (d.password) saidPassword(name, d.password);
    }).catch(oops).then(function () { busy(b, false); });
  }}], true);
};
function userEdit(u, me) {
  modal(u.name, function (body) {
    body.appendChild(peekFacts([['Role', roleWords(u.role)], ['Made', stamp(u.created)], ['Last sign-in', u.last_login ? stamp(u.last_login) : 'never']]));
    var r = selectBox([['fulladmin', 'full admin - may change everything'], ['readonly', 'read only - may look']], u.role); r.id = 'ue-role';
    var p = maskBox('', 'empty = make one and show it', 'mono'); p.id = 'ue-pass';
    var t = textBox(u.note || '', ''); t.id = 'ue-note';
    body.appendChild(formField('Role', r));
    body.appendChild(formField('Note', t));
    body.appendChild(formField('A new password', p, 'Given here, its sign-ins go on; on the server: sudo upnp user passwd ' + u.name));
  }, [{words: 'Take it away', cls: 'danger left', icon: 'trash', go: function () {
        api('users', {action: 'delete', name: u.name}).then(function (d) { toast(d.message, 'good'); closeModal(); loadUsers(); }).catch(oops);
      }},
      {words: 'Close', close: true},
      {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
        busy(b, true);
        var steps = [];
        if ($('ue-role').value !== u.role) steps.push({action: 'role', name: u.name, role: $('ue-role').value});
        if ($('ue-note').value !== (u.note || '')) steps.push({action: 'note', name: u.name, note: $('ue-note').value});
        if ($('ue-pass').value) steps.push({action: 'passwd', name: u.name, password: $('ue-pass').value});
        var chain = Promise.resolve();
        steps.forEach(function (s) { chain = chain.then(function () { return api('users', s); }); });
        chain.then(function () { toast(steps.length ? 'saved' : 'nothing was changed', 'good'); closeModal(); loadUsers(); })
          .catch(oops).then(function () { busy(b, false); });
      }}]);
}

PANE_LOAD.people = loadUsers;
