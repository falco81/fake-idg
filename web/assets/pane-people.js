/* pane-people.js - Settings → Accounts: otp's loadUsers, its lockouts and its popups (1.6.1).
   The accounts with their row tools (the role, who it is and its sign-ins, a new password, off/on,
   remove, somebody's columns put back, the second step reset), who is signed in now, who is locked
   out, the card of the columns of the tables (#cols-card, wired by admin.js) - and the settings of
   the pane (sect-people) drawn by the shell. */
'use strict';

/* ---- accounts ------------------------------------------------------------- */
var US = {d: null};
var MFA_TAG = {app: 'an app'};
function pkCount(n) { return n === 1 ? '1 passkey' : num(n) + ' passkeys'; }
function loadUsers() {
  if (typeof colsCardSay === 'function') colsCardSay();
  api('users').then(function (d) {
    US.d = d;
    var host = $('us-table');
    clear(host);
    host.appendChild(listTable(['Name', 'Role', 'Signs in', 'State', 'Second step', 'Last signed in', 'From', 'Columns', 'Note', ''], d.users, function (u) {
      var tr = el('tr');
      var n = el('td'); n.appendChild(noI18n(el('span', 'mono', u.name)));
      tr.appendChild(n);
      var r = el('td'); r.appendChild(el('span', 'tag ' + roleTone(u.role), roleWords(u.role))); tr.appendChild(r);
      /* How it signs in (otp's): every account here with a password of its own - there is no directory. */
      /* ...and its passkeys, which sign it in by themselves (1.9.7): how many, of which devices. */
      var how = el('td', 'muted');
      how.appendChild(el('span', '', 'a password here'));
      if (u.passkeys) {
        var pks = el('span', 'sub', pkCount(u.passkeys));
        pks.title = u.passkeys_said || '';
        how.appendChild(pks);
      }
      tr.appendChild(how);
      var st = el('td'); st.appendChild(el('span', 'tag ' + (u.disabled ? 'crit' : 'ok'), u.disabled ? 'off' : 'on'));
      if (u.must_change) { st.appendChild(document.createTextNode(' ')); st.appendChild(el('span', 'tag info', 'to change at sign-in')); }
      tr.appendChild(st);
      /* The second step of signing in: how it is given, or not yet. */
      var mf = el('td', 'small');
      if (u.mfa) {
        mf.appendChild(el('span', 'tag ok', MFA_TAG[u.mfa.kind] || u.mfa.kind));
        if (u.mfa.at) mf.appendChild(el('span', 'sub', 'since ' + stamp(u.mfa.at)));
      } else {
        mf.appendChild(el('span', 'muted', d.mfa_on ? 'set up at the next sign-in' : '–'));
      }
      tr.appendChild(mf);
      tr.appendChild(u.last_login ? stampCell(u.last_login) : el('td', 'muted', 'never'));
      tr.appendChild(noI18n(el('td', 'mono small', u.last_from || '')));
      tr.appendChild(el('td', 'muted small', u.cols_tables ? num(u.cols_tables) + ' table(s) laid out' : 'as they come'));
      tr.appendChild(noI18n(el('td', 'muted small', u.note || '')));
      var tools = el('td', 'rowtools');
      /* Every row has the same buttons in the same places (otp 1.0.18): one that does not
         apply to this account is there, dimmed, and says why. */
      if (ADMIN) {
        /* The role first, the buttons as one group after it. */
        var role = selectBox(d.roles.map(function (x) { return [x.role, x.words]; }), u.role);
        /* One's own role changed asks first (otp 1.0.256): the list shows the old role until
           it is confirmed. */
        role.onchange = function () {
          var to = role.value;
          if (!userIsMe(u.name) || to === u.role) { userDo({action: 'role', name: u.name, role: to}); return; }
          role.value = u.role;
          confirmThen('Change your own role', 'You are signed in as <b>' + htmlText(u.name) + '</b>. '
            + 'Made ' + htmlText(roleWordsOf(d.roles, to)) + ', you can no longer change the settings, the accounts or this role on these pages - '
            + 'another full admin has to give it back.', 'Change my role', function () {
              userDo({action: 'role', name: u.name, role: to});
            });
        };
        role.style.marginRight = '10px';
        tools.appendChild(role);
      }
      var info = iconButton('person', 'Who it is: its note, whether it changes its password at the next sign-in, and its sign-ins');
      info.onclick = function (ev) { ev.stopPropagation(); userInfo(u); };
      tools.appendChild(info);
      if (ADMIN) {
        var pw = iconButton('lock', 'Set a new password');
        pw.onclick = function (ev) { ev.stopPropagation(); userPassword(u); };
        tools.appendChild(pw);
        var off = iconButton('power', u.disabled ? 'Let it sign in again' : 'Stop it signing in');
        /* Switching an account off asks first (otp 1.0.256): it ends its sign-ins at once -
           one's own too, and then there is no way back from here. */
        off.onclick = function () {
          if (u.disabled) { userDo({action: 'enable', name: u.name}); return; }
          if (userIsMe(u.name)) {
            confirmThen('Switch your own account off', 'You are signed in as <b>' + htmlText(u.name) + '</b>. '
              + 'Switched off, you are signed out at once and cannot sign in again - '
              + 'only another full admin can switch it back on.', 'Switch me off', function () {
                userDo({action: 'disable', name: u.name});
              });
          } else {
            confirmThen('Switch the account ' + u.name + ' off', 'It cannot sign in until it is switched on again; its sign-ins now are ended.',
              'Switch off', function () { userDo({action: 'disable', name: u.name}); });
          }
        };
        var x = iconButton('trash', 'Remove it');
        x.onclick = function () {
          confirmThen('Remove the account ' + u.name, userIsMe(u.name)
            ? 'You are signed in as <b>' + htmlText(u.name) + '</b>: you are signed out at once, and it cannot sign in any more.'
            : 'It cannot sign in any more.', 'Remove it', function () {
              userDo({action: 'delete', name: u.name});
            });
        };
        tools.appendChild(off); tools.appendChild(x);
        /* Somebody's own layout of the tables, put back as it comes (otp's). */
        var cb = iconButton('undo', u.cols_tables
          ? u.name + ' has laid out ' + num(u.cols_tables) + ' table(s) by hand. Put every one of them back as it comes: the widths, the order and the hidden columns. Nothing else of theirs changes.'
          : u.name + ' has every table as it comes: nothing to put back.');
        cb.classList.add('cols-back');
        if (u.cols_tables) {
          cb.onclick = function (ev) {
            ev.stopPropagation();
            confirmThen('The columns of ' + u.name,
              'Every table ' + htmlText(u.name) + ' has laid out goes back as it comes. They see it '
              + 'the next time a page loads.',
              'Put them back', function () {
                colsReset(u.name).then(function () {
                  if (userIsMe(u.name) && typeof colsCardSay === 'function') colsCardSay();
                  loadUsers();
                }).catch(oops);
              });
          };
        } else {
          cb.disabled = true;
        }
        tools.appendChild(cb);
        var mr = iconButton('shield', u.mfa
          ? 'Reset the second step: ' + u.name + ' sets it up again at the next sign-in. Their sign-ins are ended.'
          : u.name + ' has no second step set up: nothing to reset.');
        if (u.mfa) {
          mr.onclick = function (ev) {
            ev.stopPropagation();
            confirmThen('Reset the second step of ' + u.name + '?',
              htmlText('The app ' + u.name + ' gives the second step with is taken away, and their sign-ins are ended. At the next sign-in they set it up again - with the password alone, so do it only when you know it is them (a lost phone, a new one). Their passkeys stay.'),
              'Reset it', function () {
                api('users', {action: 'mfa_reset', name: u.name}).then(function (r) { toast(r.message, 'good'); loadUsers(); }).catch(oops);
              }, true);
          };
        } else {
          mr.disabled = true;
        }
        tools.appendChild(mr);
        /* Its passkeys taken away (1.9.7) - a lost iPhone: it signs in with its password then. */
        var pr = iconButton('key', u.passkeys
          ? 'Take away the passkeys of ' + u.name + ' (' + pkCount(u.passkeys) + '): they no longer sign in. The password does, as before.'
          : u.name + ' has no passkey: nothing to take away.');
        if (u.passkeys) {
          pr.onclick = function (ev) {
            ev.stopPropagation();
            confirmThen('Take away the passkeys of ' + u.name + '?',
              htmlText('Every passkey of ' + u.name + ' (' + pkCount(u.passkeys) + (u.passkeys_said ? ': ' + u.passkeys_said : '')
                + ') no longer signs them in. Their password does, as before, and they can add passkeys again under Your account.'),
              'Take them away', function () {
                api('users', {action: 'passkeys_remove', name: u.name}).then(function (r) { toast(r.message, 'good'); loadUsers(); }).catch(oops);
              }, true);
          };
        } else {
          pr.disabled = true;
        }
        tools.appendChild(pr);
      }
      tr.appendChild(tools);
      return tr;
    }));
    explainWhatWasDrawn(host);
  }).catch(oops);
  loadLockouts();
  if (ADMIN) api('sessions').then(function (d) {
    var host = $('se-table');
    clear(host);
    host.appendChild(listTable(['Who', 'Where', 'From', 'Since', 'Last asked', ''], d.sessions, function (s) {
      var tr = el('tr');
      var who = el('td'); who.appendChild(noI18n(el('span', 'mono', s.name)));
      if (s.me) { who.appendChild(document.createTextNode(' ')); who.appendChild(el('span', 'tag info', 'this one')); }
      tr.appendChild(who);
      var wh = el('td', '', s.mfa ? 'these pages - ' + (s.mfa === 'enrol' ? 'setting up the second step' : 'the second step to give') : 'these pages');
      if (s.agent) { var ag = noI18n(el('span', 'sub', browserWords(s.agent))); ag.title = s.agent; wh.appendChild(ag); }
      tr.appendChild(wh);
      tr.appendChild(noI18n(el('td', 'mono small', s.addr)));
      tr.appendChild(stampCell(s.created));
      tr.appendChild(el('td', 'muted', ago(s.seen)));
      var tools = el('td', 'rowtools');
      var x = cmdButton('End it', 'cancel', 'small');
      /* Asked first (otp 1.0.61): it may be your own. */
      x.onclick = function () {
        confirmThen('End this sign-in', htmlText(String(s.name || '?')) + (s.addr ? ' from ' + htmlText(String(s.addr)) : '')
          + ' is signed out at once' + (s.me ? ' - it is yours, this one.' : '.'), 'End it', function () {
          api('sessions', {id: s.id}).then(function () { if (s.me) location.reload(); else loadUsers(); }).catch(oops);
        });
      };
      tools.appendChild(x);
      tr.appendChild(tools);
      return tr;
    }));
  }).catch(oops);
}
/* The browser of a sign-in in a few words, its whole User-Agent in the title. */
function browserWords(a) {
  a = String(a || '');
  var b = /Edg\//.test(a) ? 'Edge' : /OPR\//.test(a) ? 'Opera' : /Firefox\//.test(a) ? 'Firefox'
    : /Chrome\//.test(a) ? 'Chrome' : /Safari\//.test(a) ? 'Safari' : /curl\//.test(a) ? 'curl' : '';
  var o = /Windows/.test(a) ? 'Windows' : /iPhone|iPad/.test(a) ? 'iOS' : /Android/.test(a) ? 'Android'
    : /Mac OS X/.test(a) ? 'macOS' : /Linux/.test(a) ? 'Linux' : '';
  return (b || o) ? [b, o].filter(Boolean).join(' on ') : a.slice(0, 40);
}
/** Is this account the one signed in now (otp 1.0.256)? */
function userIsMe(name) {
  return !!(ME && ME.name && String(name || '').toLowerCase() === String(ME.name).toLowerCase());
}
/** The words of a role as the accounts list gives them (otp 1.0.256). */
function roleWordsOf(roles, role) {
  var r = (roles || []).filter(function (x) { return x.role === role; })[0];
  return r ? r.words : role;
}
function userDo(body, after) {
  /* Drawn again either way (otp 1.0.44): a refused change stayed in its box. One's own
     account switched off, removed or made read only: the page as it is now. */
  api('users', body).then(function (d) {
    toast(d.message, 'good');
    if (d.password) userSaidPassword(body.name, d.password);
    if (userIsMe(body.name) && (body.action === 'disable' || body.action === 'delete' || body.action === 'role')) {
      setTimeout(function () { location.reload(); }, 900);
      return;
    }
    loadUsers();
    if (after) after(d);
  }).catch(function (e) { oops(e); loadUsers(); });
}
/* A password made here is shown once - the page never has it again. */
function userSaidPassword(name, pw) {
  modal('The password of ' + name, function (body) {
    body.appendChild(el('p', 'note', 'Made here and shown this once - give it to its owner now. Pressed, it is copied.'));
    var code = noI18n(el('div', 'mono big', pw));
    code.style.cssText = 'font-size:22px;letter-spacing:.06em;padding:14px 0;cursor:pointer;user-select:all';
    copyOnClick(code, pw, 'copied');
    body.appendChild(code);
  }, [{words: 'Close', close: true}], true);
}
/* The few boxes of a question in a popup (otp's askInModal). */
function userAsk(title, lede, fields, words, icon, go, extra) {
  var boxes = [];
  modal(title, function (body) {
    if (lede) body.appendChild(el('p', 'note', lede));
    var g = el('div', 'formgrid');
    fields.forEach(function (f) {
      var input = f.type === 'password' ? maskBox('', '', '') : el('input');
      if (f.type !== 'password') input.type = f.type || 'text';
      input.placeholder = f.placeholder || '';
      input.autocomplete = 'off';
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); $('modal-foot').querySelector('.btn.primary').click(); }
      });
      boxes.push(input);
      g.appendChild(formField(f.label, input, f.says));
    });
    if (extra) extra(g);
    body.appendChild(g);
    setTimeout(function () { if (boxes[0]) boxes[0].focus(); }, 60);
  }, [{words: 'Close', close: true}, {words: words, cls: 'primary', icon: icon, go: function (b) {
    go(boxes.map(function (x) { return x.value; }), b);
  }}], 'medium');
}
function userPassword(u) {
  var least = (US.d && US.d.password_min) || 8;
  var must = null;
  userAsk('A new password for ' + u.name, 'Both empty: one is made here and shown once. Their sign-ins now are ended.',
    [{label: 'The new one (' + least + ' characters at least)', type: 'password'},
     {label: 'Again', type: 'password'}], 'Set it', 'lock', function (v) {
      if (v[0] || v[1]) {
        if (v[0].length < least) { toast(least + ' characters at least', 'bad'); return; }
        if (v[0] !== v[1]) { toast('the two are not the same', 'bad'); return; }
      }
      closeModal();
      userDo({action: 'password', name: u.name, password: v[0], must_change: must._get()});
    }, function (g) {
      must = switchBox(true);
      g.appendChild(formField('They choose their own at the next sign-in', must,
        'Off: the password set here is theirs to keep.'));
    });
}
/* Who it is (the person button): its facts, its note, whether it changes its password at the
   next sign-in - and its sign-ins, from the events. */
function userInfo(u) {
  var note = null, must = null;
  modal(u.name, function (body) {
    body.appendChild(peekFacts([
      ['Role', roleWords(u.role)], ['State', u.disabled ? 'switched off - it cannot sign in' : 'on'],
      ['Made', stamp(u.created)], ['Changed', u.changed ? stamp(u.changed) : '–'],
      ['Last signed in', u.last_login ? stamp(u.last_login) + (u.last_from ? ' from ' + u.last_from : '') : 'never'],
      ['Signed in now', u.sessions ? num(u.sessions) : 'no'],
      ['Second step', u.mfa ? (MFA_TAG[u.mfa.kind] || u.mfa.kind) + ', since ' + stamp(u.mfa.at)
        : (US.d && US.d.mfa_on ? 'set up at the next sign-in' : '–')],
      ['Passkeys', u.passkeys ? pkCount(u.passkeys) + (u.passkeys_said ? ' (' + u.passkeys_said + ')' : '') : 'none']
    ]));
    var g = el('div', 'formgrid');
    note = textBox(u.note || '', 'who it is, what it is for');
    note.maxLength = 200;
    note.disabled = !ADMIN;
    g.appendChild(formField('Note', note));
    must = switchBox(u.must_change);
    must._input.disabled = !ADMIN;
    g.appendChild(formField('Changes its password at the next sign-in', must,
      'Asked by the pages once it is signed in; a new password set here asks it by itself.'));
    body.appendChild(g);
    var h = el('h3', '', 'Its sign-ins');
    h.style.marginTop = '18px';
    body.appendChild(h);
    var list = el('div', 'scroll rowsonly');
    list.style.maxHeight = '320px';
    list.appendChild(el('p', 'muted small', 'Reading…'));
    body.appendChild(list);
    api('users-history&name=' + encodeURIComponent(u.name)).then(function (d) {
      clear(list);
      list.appendChild(listTable(['When', 'From', 'What'], d.rows, function (r) {
        var tr = el('tr');
        tr.appendChild(stampCell(r.at));
        tr.appendChild(noI18n(el('td', 'mono small', r.addr || '')));
        var w = el('td', 'small' + (r.level === 'warn' || r.level === 'bad' ? ' warn' : ''));
        w.appendChild(noI18n(document.createTextNode(r.words)));
        tr.appendChild(w);
        return tr;
      }, 'plain|No sign-in yet'));
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'said bad', String(e.message || e))); });
  }, ADMIN ? [{words: 'Close', close: true}, {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
    var steps = [];
    if (note.value !== (u.note || '')) steps.push({action: 'note', name: u.name, note: note.value});
    if (!!must._get() !== !!u.must_change) steps.push({action: 'must_change', name: u.name, on: !!must._get()});
    if (!steps.length) { closeModal(); return; }
    busy(b, true);
    var chain = Promise.resolve();
    steps.forEach(function (s) { chain = chain.then(function () { return api('users', s); }); });
    chain.then(function () { toast('saved', 'good'); closeModal(); loadUsers(); })
      .catch(oops).then(function () { busy(b, false); });
  }}] : [{words: 'Close', close: true}]);
}
$('us-add').onclick = function () {
  var least = (US.d && US.d.password_min) || 8;
  var name, role, pw, note;
  modal('A new account', function (body) {
    var g = el('div', 'formgrid');
    name = textBox('', '', 'mono');
    role = selectBox([['readonly', 'read only'], ['fulladmin', 'full admin']], 'readonly');
    pw = secretBox('', least + ' characters at least', 'mono');
    note = textBox('', '', '');
    g.appendChild(formField('Name', name));
    g.appendChild(formField('Role', role));
    g.appendChild(formField('A first password', pw, 'They choose their own at the first sign-in. Empty: one is made here and shown once.'));
    g.appendChild(formField('Note', note));
    body.appendChild(g);
    setTimeout(function () { name.focus(); }, 60);
  }, [{words: 'Close', close: true}, {words: 'Make it', cls: 'primary', icon: 'add', go: function (b) {
    busy(b, true);         // one account per press (otp 1.0.61)
    var who = name.value.trim();
    api('users', {action: 'add', name: who, role: role.value, password: pw.value, note: note.value, must_change: 1})
      .then(function (d) {
        toast(d.message, 'good'); closeModal(); loadUsers();
        if (d.password) userSaidPassword(who, d.password);
      }).catch(oops)
      .then(function () { busy(b, false); });
  }}], true);
};

/* ---- locked out ----------------------------------------------------------- */
/* Who has wrong attempts counted and how long the lockout still runs (otp 1.0.112) - cleared
   one by one or all at once. Fetched again every 10 s while the card is on the screen; the
   time left counts down every second in between. */
var LO = {data: null, skew: 0, fetched: 0, timer: null};
function loadLockouts() {
  if (!ADMIN || !$('lo-table')) return;
  api('lockouts').then(function (d) {
    LO.data = d;
    LO.skew = d.now - Date.now() / 1000;
    LO.fetched = Date.now();
    drawLockouts();
    if (!LO.timer) LO.timer = setInterval(loTick, 1000);
  }).catch(function (e) { if (LO.timer) { clearInterval(LO.timer); LO.timer = null; } oops(e); });
}
function loTick() {
  var c = $('lo-card');
  if (!c || !c.offsetParent) { clearInterval(LO.timer); LO.timer = null; return; }
  if (document.hidden) return;     /* skipped, not stopped (otp 1.0.252) */
  if (Date.now() - LO.fetched > 10000) { LO.fetched = Date.now(); loadLockouts(); return; }
  drawLockouts();
}
function loNow() { return Date.now() / 1000 + LO.skew; }
function loClear(body, words) {
  api('lockouts', body).then(function (r) {
    toast(words || r.message, 'good');
    loadLockouts();
  }).catch(oops);
}
/* How far a count has got towards its limit (otp 1.0.137): a bar that fills. */
function loBar(n, limit, locked) {
  var bar = el('div', 'lo-bar' + (locked ? ' full' : ''));
  var fill = el('i');
  fill.style.width = (limit ? Math.min(100, Math.round(100 * n / limit)) : 0) + '%';
  bar.appendChild(fill);
  return bar;
}
function drawLockouts() {
  var d = LO.data;
  var host = $('lo-table');
  if (!d || !host) return;
  var now = loNow();
  var rows = [];
  (d.nodes || []).forEach(function (n) {
    (n.rows || []).forEach(function (r) {
      if (r.forgets <= now) return;
      var x = Object.assign({}, r);
      if (x.locked && x.until <= now) x.locked = false;
      rows.push(x);
    });
  });
  rows.sort(function (a, b) { return (b.locked - a.locked) || (b.last - a.last); });
  liveFill($('lo-tools'), function (tools) {
    var locked = rows.filter(function (r) { return r.locked; }).length;
    if (!rows.length) return;
    if (locked) { var lc = el('span', 'small bad', num(locked) + ' locked out'); lc.style.marginRight = '12px'; tools.appendChild(lc); }
    var all = cmdButton('Clear them all', 'broom', 'small');
    all.onclick = function () {
      confirmThen('Clear every lockout?', 'Every count of wrong attempts is forgotten'
        + ' - the locked out may try again at once. Events keeps a line saying who did it.', 'Clear them all', function () {
        loClear({action: 'clear_all'});
      }, false);
    };
    tools.appendChild(all);
  }, true);
  liveFill(host, function (host) {
    if (!rows.length) {
      host.appendChild(el('p', 'note good', 'Nobody is locked out, and no wrong attempt is being counted.'));
      return;
    }
    host.appendChild(listTable(['State', 'Who', 'Where', 'How many', 'Tried', 'Last', ''], rows, function (r) {
      var tr = el('tr', r.locked ? 'lo-locked' : '');
      var st = el('td');
      if (r.locked) {
        st.appendChild(el('span', 'tag crit', 'locked out'));
        st.appendChild(el('div', 'small', span(r.until - now) + ' left'));
      } else {
        st.appendChild(el('span', 'tag load', 'counting'));
        st.appendChild(el('div', 'small muted', 'forgotten in ' + span(r.forgets - now)));
      }
      tr.appendChild(st);
      var who = el('td');
      who.appendChild(noI18n(el('div', 'mono', r.who || '(no name)')));
      who.appendChild(el('div', 'small muted', r.by === 'address' ? 'an address' : 'a name'));
      tr.appendChild(who);
      var wh = el('td', 'small', r.what);
      wh.appendChild(el('div', 'small muted', r.words));
      tr.appendChild(wh);
      var w = el('td', 'num lo-count');
      var line = el('div');
      line.appendChild(noI18n(el('b', '', num(r.fails))));
      line.appendChild(document.createTextNode(' / ' + num(r.limit)));
      w.appendChild(line);
      w.appendChild(loBar(r.fails, r.limit, r.locked));
      tr.appendChild(w);
      var tried = el('td', 'small');
      if ((r.others || []).length) {
        tried.appendChild(el('div', 'muted', r.by === 'address' ? 'names:' : 'from:'));
        tried.appendChild(noI18n(el('div', 'mono', r.others.slice().reverse().join(', '))));
      } else tried.textContent = '–';
      tr.appendChild(tried);
      tr.appendChild(el('td', 'muted small', ago(r.last - LO.skew)));
      var a = el('td', 'rowtools');
      var x = cmdButton('Clear', 'broom', 'small');
      explain(x, 'Its count of wrong attempts is forgotten: it may try again at once.');
      x.onclick = function () {
        loClear({action: 'clear', kind: r.kind, who: r.who}, 'cleared: ' + (r.who || '(no name)'));
      };
      a.appendChild(x);
      tr.appendChild(a);
      return tr;
    }, 'plain'));
  }, true);
}

PANE_LOAD.people = loadUsers;
