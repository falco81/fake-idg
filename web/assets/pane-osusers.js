/* Settings → Local users (otp's loadOsUsers / drawOsUsers / pwpCard, 1.0.243 - 1.0.252).
   The users of this server's own system: root, shown and never changed, and the users of the
   normal range (UID 1000 and up) - made, given a password, sudo, locked or taken away by root.
   Under them the password policy, one for every local user, put into the system's own files;
   and what was done last, with what root said. */
(function () {
  var OSU = {d: null, poll: null, asked: 0, ask: 0, all: false};
  var PWP_EDIT = null, PWP_BASE = null, PWP_OPEN = false;

  function liveLetGo(host) {
    if (!host || host._letGo) return;
    host._letGo = true;
    host.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('button') : null;
      if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
    });
  }
  function load() {
    api('osusers').then(function (d) {
      OSU.d = d; draw();
      if (Date.now() - OSU.asked > 20000) {
        OSU.asked = Date.now();
        api('osusers', {action: 'refresh'}).then(function () { poll(true); }).catch(function () {});
      }
      poll(!!d.pending);
    }).catch(oops);
  }
  function poll(on) {
    if (on) OSU.ask = Date.now();
    if (on && !OSU.poll) {
      OSU.poll = setInterval(function () {
        if (TAB !== 'settings' || PANE !== 'osusers') { poll(false); return; }
        api('osusers').then(function (d) {
          /* Kept as it is only while something is being typed in it. */
          var a = document.activeElement, host = $('osu-host');
          var typing = a && host && host.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName) && a.type !== 'checkbox';
          OSU.d = d; draw(!!typing);
          if (!d.pending && Date.now() - OSU.ask > 6000) poll(false);
        }).catch(function () {});
      }, 2000);
    }
    if (!on && OSU.poll) { clearInterval(OSU.poll); OSU.poll = null; }
  }
  function rows() {
    var by = {}, order = [];
    ((OSU.d && OSU.d.users) || []).forEach(function (u) {
      if (!by[u.name]) { by[u.name] = u; order.push(u.name); }
    });
    var rank = function (n) { var u = by[n]; return u.root ? 0 : u.login ? 1 : 2; };
    order.sort(function (a, b) { return rank(a) - rank(b) || (a < b ? -1 : 1); });
    var noShell = order.filter(function (n) { return rank(n) === 2; }).length;
    return {by: by, order: order, shown: order.filter(function (n) { return OSU.all || rank(n) < 2; }), noShell: noShell};
  }
  function day(d) {
    if (d === null || d === undefined) return '';
    return new Date(d * 86400000).toISOString().slice(0, 10);
  }
  function shellOf(s) { return String(s || '').split('/').pop() || '–'; }
  function consoleOn(name) {
    var c = (OSU.d && OSU.d.console) || {};
    return c.users === '*' ? true : (c.users || []).indexOf(name) >= 0;
  }
  function draw(live) {
    var real = $('osu-host');
    if (!real || !OSU.d) return;
    liveLetGo(real);
    liveFill(real, function (host) {
      var d = OSU.d;
      if (d.late) host.appendChild(el('p', 'note bad', d.late));
      if (!d.openssl) host.appendChild(el('p', 'note warn', 'openssl is not on this machine - a password cannot be given from these pages (dnf install openssl).'));
      var R = rows();
      var card = el('div', 'card full osu-card');
      var h = el('h2', '', 'Users of this server');
      var tools = el('span', 'right');
      var add = cmdButton('Add a user', 'add', 'small primary');
      explain(add, 'A new user of the system, with a home folder of its own.');
      var again = iconButton('refresh', 'Read the users again');
      tools.appendChild(add); tools.appendChild(again);
      h.appendChild(tools);
      card.appendChild(h);
      add.onclick = function () { addUser(); };
      again.onclick = function () {
        api('osusers', {action: 'refresh'}).then(function () { poll(true); toast('asked again'); }).catch(oops);
      };
      if (!d.at) {
        card.appendChild(el('p', 'note', 'Reading the users of this server…'));
      } else {
        if (R.noShell) {
          var sa = check('Also the ' + R.noShell + ' accounts with no shell (they may not sign in)', OSU.all);
          sa.box.classList.add('osu-all');
          sa.input.onchange = function () { OSU.all = sa.input.checked; draw(); };
          card.appendChild(sa.box);
        }
        var box = el('div', 'scroll rowsonly');
        box.appendChild(listTable(['User', 'UID', 'Shell', 'Password', 'Here', ''], R.shown, function (name) {
          var u = R.by[name], tr = el('tr', u.root ? 'osu-root' : '');
          var who = el('td', 'osu-who');
          who.appendChild(noI18n(el('span', 'acct-ava' + (u.root ? ' root' : ''), name.slice(0, 2).toUpperCase())));
          var nm = el('span', 'osu-nm');
          nm.appendChild(noI18n(el('span', 'mono osu-name', name)));
          if (u.gecos) nm.appendChild(noI18n(el('span', 'muted small', u.gecos)));
          who.appendChild(nm);
          var tags = el('span', 'osu-tags');
          if (u.root) tags.appendChild(el('span', 'tag dim', 'view only'));
          if (!u.root && u.sudo) tags.appendChild(el('span', 'tag warn', 'sudo'));
          if (!u.login) tags.appendChild(el('span', 'tag dim', 'no shell'));
          if (!u.root && u.login && consoleOn(name)) tags.appendChild(el('span', 'tag info', 'upnp console'));
          who.appendChild(tags);
          tr.appendChild(who);
          tr.appendChild(noI18n(el('td', 'mono small', String(u.uid))));
          tr.appendChild(noI18n(el('td', 'mono small', shellOf(u.shell))));
          var pw = el('td', 'small');
          if (!u.password) pw.appendChild(el('span', 'tag dim', 'none'));
          else if (u.must_change) pw.appendChild(el('span', 'tag info', 'to change at sign-in'));
          else pw.appendChild(noI18n(el('span', 'muted', u.changed ? day(u.changed) : 'set')));
          tr.appendChild(pw);
          var c = el('td');
          if (u.locked) c.appendChild(el('span', 'tag bad', 'locked'));
          else c.appendChild(el('span', 'tag good', 'yes'));
          tr.appendChild(c);
          var a = el('td', 'right osu-act');
          if (u.root) {
            var see = iconButton('eye', 'root is shown only - it is changed on the machine itself, never from these pages');
            see.onclick = function () { edit(name); };
            a.appendChild(see);
          } else {
            var ed = iconButton('edit', 'Change ' + name + ': the password, sudo, locked, the shell - or take the user away');
            ed.onclick = function () { edit(name); };
            a.appendChild(ed);
          }
          tr.appendChild(a);
          return tr;
        }, 'osu-table', {own: true}));
        card.appendChild(box);
        if (R.order.filter(function (n) { return R.by[n].login; }).length <= 1)
          card.appendChild(el('p', 'note', 'Only root is on this server - Add a user makes one.'));
      }
      host.appendChild(card);
      host.appendChild(pwpCard(d));
      /* What was done last, with what root said. */
      var said = (d.done || []).slice().sort(function (a, b) { return (b.at || 0) - (a.at || 0); });
      if (said.length) {
        var lc = el('div', 'card full');
        lc.appendChild(el('h2', '', 'Done last'));
        var lb = el('div', 'scroll rowsonly');
        lb.appendChild(listTable(['When', 'User', 'Who', 'What came of it'], said.slice(0, 8), function (s) {
          var tr = el('tr');
          tr.appendChild(noI18n(el('td', 'small mono', stamp(s.at))));
          tr.appendChild(noI18n(el('td', 'small mono', s.name || '–')));
          tr.appendChild(noI18n(el('td', 'small', s.by || '–')));
          var w = el('td', 'small');
          w.appendChild(el('span', 'tag ' + (s.ok ? 'good' : 'bad'), s.ok ? 'done' : 'refused'));
          if (s.said) w.appendChild(noI18n(el('span', 'muted', ' ' + s.said)));
          tr.appendChild(w);
          return tr;
        }, 'plain', {own: true}));
        lc.appendChild(lb);
        host.appendChild(lc);
      }
      if (d.pending) host.appendChild(el('p', 'note info', 'Being done by root…'));
    }, live);
  }

  /* ---- the password policy (otp's pwpCard, 1.0.245) ---- */
  var PWP_HELP = {
    managed: 'On: fake-igd writes the values below into this server\'s files - /etc/security/pwquality.conf.d/50-fake-igd.conf, its lines in pwhistory.conf and faillock.conf, the aging lines of /etc/login.defs - and puts them in again when they are other ones. With authselect, the features with-pwhistory and with-faillock are switched on only when they are needed. Off: what fake-igd wrote is taken out again, and the policy is the one the system has.',
    minlen: 'The fewest characters a new password may have (pam_pwquality: minlen). Only a new password is checked - one set before stays until it is changed.',
    minclass: 'How many of the four kinds of characters a new password must have at least: small letters, capitals, digits, the others (pam_pwquality: minclass). Any: no kinds asked for.',
    maxrepeat: 'The most times one character may come in a row - with 3, "aaa" is taken and "aaaa" is not (pam_pwquality: maxrepeat). 0: as many as wanted.',
    difok: 'How many characters of the new password must not be in the old one (pam_pwquality: difok). Checked only where the old password is typed too - passwd by the user, a password run out at sign-in; not when root or these pages set it.',
    dictcheck: 'A new password that is a word of the dictionary (cracklib\'s), also turned around or with little changed, is refused (pam_pwquality: dictcheck).',
    usercheck: 'A new password with the user\'s name in it, also turned around, is refused (pam_pwquality: usercheck).',
    runs: 'On: a password is good for the days set here; after them the user must change it at the next sign-in - over SSH with a key too (login.defs: PASS_MAX_DAYS; chage -M). Off: a password never runs out.',
    max_days: 'How many days a password is good after it was set (login.defs: PASS_MAX_DAYS; chage -M). Then it must be changed at the next sign-in.',
    warn_days: 'How many days before a password runs out the user is told so at sign-in (login.defs: PASS_WARN_AGE; chage -W).',
    min_days: 'How many days after a change the password may not be changed again - so that the last passwords cannot be gone through at once to come back to the old one (login.defs: PASS_MIN_DAYS; chage -m). 0: changed again at once.',
    remember: 'How many of a user\'s last passwords cannot be taken again (pam_pwhistory: remember; they are kept hashed in /etc/security/opasswd). 0: any. With authselect, its feature with-pwhistory is switched on for it.',
    existing: 'login.defs holds the days only for the users made after it. On: the days set here are put on every local user there now too (chage) - never on root, nor on a user with no password (a key only), who could never give a new one. Off: the users there now keep their own days; each user\'s are in their popup.',
    deny: 'After so many wrong passwords - counted within the time set here - the user is locked (pam_faillock: deny). 0: never locked. root is never locked. An SSH key never counts and is never kept out: the lock keeps out the password (at the console, for sudo). With authselect, its feature with-faillock is switched on for it.',
    unlock_time: 'How long a locked user stays locked, in seconds (pam_faillock: unlock_time). 0: until root unlocks them - faillock --user NAME --reset.',
    fail_interval: 'Wrong passwords are counted within so many seconds (pam_faillock: fail_interval) - those before do not count towards the lock.'
  };
  var PWP_DEFAULTS = {managed: 'off', minlen: 12, minclass: 3, maxrepeat: 3, difok: 5, dictcheck: 'on', usercheck: 'on',
    runs: 'off', max_days: 99999, warn_days: 7, min_days: 0, remember: 5, existing: 'off', deny: 0, unlock_time: 900, fail_interval: 900};
  function pwpNum(v, min, max) {
    var i = el('input', 'mono pwp-num'); i.type = 'number'; i.min = min; i.max = max; i.value = v; return i;
  }
  function pwpInfo(key, also) {
    var words = PWP_HELP[key];
    if (!words) return null;
    var story = '<span class="k">' + (PWP_DEFAULTS[key] !== undefined ? '<span class="same">the built-in default is ' + richText(String(PWP_DEFAULTS[key])) + '</span>' : '') + '</span>';
    var i = el('span', 'iinfo', 'i');
    i.setAttribute('role', 'button');
    i.tabIndex = 0;
    i.addEventListener('click', function (ev) { ev.stopPropagation(); ev.preventDefault(); });
    explain(i, words, story);
    (also || []).forEach(function (x) { explain(x, words, story); x.removeAttribute('aria-label'); });
    return i;
  }
  function pwpInfoOn(box, key) {
    var w = box.querySelector('.osu-sw-w');
    var i = pwpInfo(key, w ? [w] : []);
    if (i && w) {
      var inp = box.querySelector('input');
      if (inp) { inp.removeAttribute('aria-labelledby'); inp.setAttribute('aria-label', w.textContent); }
      w.appendChild(document.createTextNode(' ')); w.appendChild(i);
    }
    return box;
  }
  function pwpField(label, input, says, key) {
    var f = formField(label, input, says);
    f.classList.add('pwp-f');
    var l = f.querySelector('label');
    var i = key && pwpInfo(key, l ? [l] : []);
    if (i && l) {
      if (input && input.setAttribute) input.setAttribute('aria-label', l.textContent);
      l.appendChild(i);
    }
    return f;
  }
  function pwpCard(d) {
    var c = d.policy || {};
    if (!PWP_EDIT || JSON.stringify(PWP_EDIT) === JSON.stringify(PWP_BASE)) {
      PWP_EDIT = JSON.parse(JSON.stringify(c));
      PWP_BASE = JSON.parse(JSON.stringify(c));
    }
    var e = PWP_EDIT;
    var unsaved = JSON.stringify(e) !== JSON.stringify(c);
    var card = el('div', 'card full pwp-card');
    var h = el('h2', '', 'Password policy');
    var st = el('span', 'right pwp-state');
    var pn = d.policy_now || {};
    var chip = el('span', 'hs-light ' + (pn.error ? 'gone' : !d.policy_applied ? 'unknown' : (c.managed ? 'on' : 'off')));
    chip.appendChild(el('span', 'dot'));
    chip.appendChild(el('span', 'hs-light-v', pn.error ? 'refused' : !d.policy_applied ? 'being put in…' : c.managed ? 'as set here' : 'the system\'s own'));
    if (pn.error) explain(chip, pn.error);
    st.appendChild(chip);
    h.appendChild(st);
    card.appendChild(h);
    if (unsaved) card.appendChild(el('p', 'note warn', JSON.stringify(PWP_BASE) !== JSON.stringify(c) ?
      'Changed here and not saved - and saved meanwhile elsewhere: Save puts this whole draft in, As it is saved shows what is saved now.' :
      'Changed here and not saved yet.'));
    card.appendChild(el('p', 'muted small', 'For every local user, however the password is changed - passwd, a password run out at sign-in, these pages. Put into this server\'s own files: pam_pwquality, pam_pwhistory, pam_faillock and login.defs (with authselect, the features that put the modules in). Not set here, the server keeps what its system has, and nothing is written.'));
    var how = el('details', 'pwp-how');
    how.appendChild(el('summary', '', 'With SSH keys and sudo'));
    ['A password that runs out is asked to be changed at the next sign-in - over SSH with a key too (sshd asks PAM\'s account step). A user with no password (a key only) is given no aging, so is never asked for one.',
     'The lockout does not keep a key out - it keeps out the password (at the console, for sudo).',
     'sudo - upnp --console of a normal user too - asks for the user\'s own password: the policy is the one for it; a user locked by wrong passwords cannot use sudo until the lock ends.',
     'root is never locked, and never given aging here.'].forEach(function (t) { how.appendChild(el('p', 'small muted', t)); });
    card.appendChild(how);
    var on = check('Set by fake-igd', e.managed, e.managed ? '' : 'Off: as the system has it - what fake-igd wrote before is taken out again.');
    on.input.onchange = function () { e.managed = on.input.checked; draw(); };
    card.appendChild(pwpInfoOn(on.box, 'managed'));
    if (e.managed) {
      var grid = el('div', 'pwp-grid');
      var col = function (title) { var c1 = el('div', 'pwp-col'); c1.appendChild(el('h3', '', title)); grid.appendChild(c1); return c1; };
      var bind = function (input, key) { input.onchange = input.oninput = function () { e[key] = parseInt(input.value, 10) || 0; }; return input; };
      var flag = function (box, words, key, says) {
        var s1 = check(words, !!e[key], says);
        s1.input.onchange = function () { e[key] = s1.input.checked ? 1 : 0; };
        box.appendChild(pwpInfoOn(s1.box, key));
      };
      var a = col('The password');
      a.appendChild(pwpField('Characters at least', bind(pwpNum(e.minlen, 6, 128), 'minlen'), '', 'minlen'));
      var kinds = selectBox([['0', 'any'], ['1', '1'], ['2', '2'], ['3', '3'], ['4', 'all 4']], String(e.minclass));
      kinds.onchange = function () { e.minclass = parseInt(kinds.value, 10); };
      a.appendChild(pwpField('Kinds of characters at least', kinds, 'small letters, capitals, digits, the others', 'minclass'));
      a.appendChild(pwpField('The same character in a row at most', bind(pwpNum(e.maxrepeat, 0, 20), 'maxrepeat'), '0: as many as wanted', 'maxrepeat'));
      a.appendChild(pwpField('Characters not in the old one', bind(pwpNum(e.difok, 0, 20), 'difok'), '', 'difok'));
      flag(a, 'No word of the dictionary', 'dictcheck');
      flag(a, 'Not the user\'s name', 'usercheck');
      var b = col('How long it is good');
      var runs = check('A password runs out', e.max_days < 99999);
      b.appendChild(pwpInfoOn(runs.box, 'runs'));
      var maxI = bind(pwpNum(e.max_days < 99999 ? e.max_days : 90, 1, 99998), 'max_days');
      var maxF = pwpField('Good for (days)', maxI, '', 'max_days');
      maxF.hidden = !(e.max_days < 99999);
      runs.input.onchange = function () { maxF.hidden = !runs.input.checked; e.max_days = runs.input.checked ? (parseInt(maxI.value, 10) || 90) : 99999; };
      b.appendChild(maxF);
      b.appendChild(pwpField('Warned so many days before', bind(pwpNum(e.warn_days, 0, 365), 'warn_days'), '', 'warn_days'));
      b.appendChild(pwpField('The least days between two changes', bind(pwpNum(e.min_days, 0, 365), 'min_days'), '0: changed again at once', 'min_days'));
      b.appendChild(pwpField('The last passwords not taken again', bind(pwpNum(e.remember, 0, 50), 'remember'), '0: any; needs pam_pwhistory', 'remember'));
      flag(b, 'Also for the users there now', 'existing', 'Without it, the days are for users made from now on (login.defs); a user\'s own are in their popup.');
      var g = col('Wrong passwords');
      g.appendChild(pwpField('Locked after so many wrong (faillock)', bind(pwpNum(e.deny, 0, 100), 'deny'), '0: never locked; root never', 'deny'));
      g.appendChild(pwpField('...for (seconds)', bind(pwpNum(e.unlock_time, 0, 86400), 'unlock_time'), '0: until unlocked by root (faillock --reset)', 'unlock_time'));
      g.appendChild(pwpField('...counted within (seconds)', bind(pwpNum(e.fail_interval, 60, 86400), 'fail_interval'), '', 'fail_interval'));
      card.appendChild(grid);
    }
    var row = el('div', 'btnrow');
    var save = cmdButton('Save the policy', 'save', 'small primary');
    save.onclick = function () {
      busy(save, true);
      api('osusers', {action: 'policy', policy: e}).then(function (x) { toast(x.message, 'good'); PWP_EDIT = null; PWP_BASE = null; OSU.d = x; draw(); poll(true); })
        .catch(function (er) { busy(save, false); oops(er); });
    };
    var back = cmdButton('As it is saved', 'undo', 'small');
    back.onclick = function () { PWP_EDIT = null; PWP_BASE = null; draw(); };
    row.appendChild(save); row.appendChild(back);
    card.appendChild(row);
    /* What this server has in effect, read from its files. */
    if (pn.pwquality) {
      var det = el('details', 'pwp-now');
      det.open = !!PWP_OPEN;
      det.ontoggle = function () { PWP_OPEN = det.open; };
      det.appendChild(el('summary', '', 'In effect on this server'));
      var yes = function (v) { return v ? 'yes' : 'no'; };
      var R = [
        ['Characters at least', function (p) { return p.pwquality.minlen; }],
        ['Kinds of characters at least', function (p) { return p.pwquality.minclass; }],
        ['The same character in a row at most', function (p) { return p.pwquality.maxrepeat || '–'; }],
        ['No word of the dictionary', function (p) { return yes(p.pwquality.dictcheck); }],
        ['The last passwords not taken again', function (p) { return p.pam.pwhistory ? p.remember : 'no (pam_pwhistory not in PAM)'; }],
        ['Good for (days)', function (p) { return p.aging.max_days >= 99999 ? 'no end' : p.aging.max_days; }],
        ['Warned so many days before', function (p) { return p.aging.warn_days; }],
        ['The least days between two changes', function (p) { return p.aging.min_days; }],
        ['Locked after so many wrong (faillock)', function (p) { return !p.pam.faillock ? 'no (pam_faillock not in PAM)' : p.faillock.deny ? p.faillock.deny + ' / ' + p.faillock.unlock_time + ' s' : '–'; }],
        ['pam_pwquality in PAM', function (p) { return yes(p.pam.pwquality); }],
        ['authselect', function (p) { return p.authselect ? p.authselect.profile + (p.authselect.features.length ? ' + ' + p.authselect.features.join(', ') : '') : 'not used'; }]
      ];
      det.appendChild(listTable(['Rule', 'Here'], R, function (r) {
        var tr = el('tr');
        tr.appendChild(el('td', 'small', r[0]));
        var v;
        try { v = r[1](pn); } catch (x) { v = undefined; }
        var t = v === undefined ? '–' : String(v);
        tr.appendChild(el('td', /^[0-9 /s–.]+$/.test(t) ? 'small mono' : 'small', t));
        return tr;
      }, 'plain', {own: true}));
      if (e.managed && pn.pam && pn.pam.read && !pn.pam.pwquality)
        det.appendChild(el('p', 'note warn', 'pam_pwquality is not in this server\'s PAM - the rules of the password are not kept there by passwd.'));
      if (e.managed && e.deny && pn.pam && !pn.pam.faillock && !pn.authselect)
        det.appendChild(el('p', 'note warn', 'pam_faillock is not in this server\'s PAM, and authselect does not manage it - the lockout is not in use.'));
      card.appendChild(det);
    }
    return card;
  }

  /* ---- the popups ---- */
  function shellSelect(cur) {
    var all = ((OSU.d && OSU.d.shells) || []).slice();
    if (!all.length) all = ['/bin/bash'];
    if (cur && all.indexOf(cur) < 0) all.unshift(cur);
    var sel = el('select', 'mono');
    all.forEach(function (s) { var o = noI18n(el('option', '', s + (/nologin$/.test(s) ? '  (may not sign in)' : ''))); o.value = s; sel.appendChild(o); });
    sel.value = cur || (all.indexOf('/bin/bash') >= 0 ? '/bin/bash' : all[0]);
    return sel;
  }
  function pwPair(body, need) {
    var a = maskBox('', '', 'mono'), b = maskBox('', '', 'mono');
    var min = (OSU.d && OSU.d.pw_min) || 8;
    body.appendChild(formField(need ? 'The new password' : 'Password (empty: none - the user signs in with a key only)', a, min + ' characters at least. It goes to root as its hash only and is kept nowhere.'));
    body.appendChild(formField('The password again', b));
    return function () {
      if (!a.value && !need) return {ok: true, value: ''};
      if (a.value.length < min) return {ok: false, said: 'the password is ' + min + ' characters at least'};
      if (a.value !== b.value) return {ok: false, said: 'the two passwords are not the same'};
      return {ok: true, value: a.value};
    };
  }
  /* An on/off switch with its words (otp 1.0.244: switches, not boxes to tick). */
  function check(words, on, says) {
    var row = el('div', 'osu-chk osu-sw');
    var sw = switchBox(on);
    row.appendChild(sw);
    var txt = el('span', 'osu-sw-t');
    var w = el('span', 'osu-sw-w', words);
    txt.appendChild(w);
    swNamedBy(sw, w);
    if (says) txt.appendChild(el('span', 'muted small osu-says', says));
    row.appendChild(txt);
    w.onclick = function () { if (!sw._input.disabled) sw._input.click(); };
    return {box: row, input: sw._input};
  }
  function done(x) { closeModal(); toast(x.message, 'good'); OSU.d = x; draw(); poll(true); }
  function addUser() {
    var nameI, gecos, shell, pw, sudo, must;
    var admin = (OSU.d && OSU.d.admin_group) || 'wheel';
    modal('Add a user', function (body) {
      body.appendChild(el('p', 'note', 'A user of the system - not of these pages. A home folder of its own; SSH keys for it are put on in SSH keys, once it is there.'));
      nameI = noI18n(textBox('', 'e.g. jnovak', 'mono'));
      nameI.autocomplete = 'off'; nameI.spellcheck = false;
      body.appendChild(formField('Name', nameI, 'Small letters, digits, _ . and -; 32 at most, starting with a letter.'));
      gecos = textBox('', 'e.g. Jan Novák');
      body.appendChild(formField('Full name', gecos));
      shell = shellSelect('');
      body.appendChild(formField('Shell', shell));
      pw = pwPair(body, false);
      must = check('To be changed at the first sign-in', true, 'The user chooses their own at once.');
      body.appendChild(must.box);
      sudo = check('May become root with sudo', false, 'A member of ' + admin + ' - with their own password.');
      body.appendChild(sudo.box);
      setTimeout(function () { nameI.focus(); }, 60);
    }, [{words: 'Cancel', close: true}, {words: 'Add the user', cls: 'primary', icon: 'add', go: function (b) {
      var n = nameI.value.trim(), p = pw();
      if (!/^[a-z_][a-z0-9_.-]{0,31}$/.test(n)) { toast('a name is small letters, digits, _ . and -, starting with a letter', 'warn'); return; }
      if (!p.ok) { toast(p.said, 'warn'); return; }
      if (sudo.input.checked && !p.value) { toast('sudo asks for the user\'s own password - give them one, or they cannot use sudo', 'warn'); return; }
      if (rows().by[n]) { toast(n + ' is there already', 'warn'); return; }
      busy(b, true);
      api('osusers', {action: 'add', name: n, gecos: gecos.value.trim(), shell: shell.value, password: p.value,
                      must_change: !!(p.value && must.input.checked), sudo: sudo.input.checked}).then(done)
        .catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  }
  function edit(name) {
    var R = rows(), u = R.by[name] || {};
    var gecos, shell, pw, must, home;
    modal(u.root ? 'root' : name, function (body) {
      /* The facts. */
      var facts = el('div', 'osu-facts');
      var f = el('div', 'osu-fact');
      f.appendChild(noI18n(el('div', 'osu-fact-h', (OSU.d && OSU.d.node) || name)));
      var kv = function (k, v, words) { var r = el('div', 'kv-mini'); r.appendChild(el('span', 'k', k)); var x = el('span', 'v' + (words ? '' : ' mono'), v); r.appendChild(words ? x : noI18n(x)); f.appendChild(r); };
      kv('UID', String(u.uid));
      kv('Home', u.home + (u.home_there ? '' : ' (not there)'));
      kv('Shell', u.shell || '–');
      kv('Groups', (u.groups || []).join(', ') || '–');
      kv('Password', !u.password ? 'none' : u.must_change ? 'to change at sign-in' : u.changed ? 'set on ' + day(u.changed) : 'set', true);
      if (u.expires) kv('Expires', day(u.expires));
      var stg = el('div', 'osu-fact-tags');
      stg.appendChild(el('span', 'tag ' + (u.locked ? 'bad' : 'good'), u.locked ? 'locked' : 'may sign in'));
      if (u.sudo && !u.root) stg.appendChild(el('span', 'tag warn', 'sudo'));
      f.appendChild(stg);
      facts.appendChild(f);
      body.appendChild(facts);
      if (u.root) {
        body.appendChild(el('p', 'note', 'root is shown here only. Its password, its shell and whether it may sign in are changed on the machine itself - over SSH as root, or at its console - never from these pages. Its SSH keys are in SSH keys; whether it may sign in over SSH, in SSH server and notices.'));
        return;
      }
      /* Who they are. */
      var s1 = el('div', 'osu-sect');
      s1.appendChild(el('h3', '', 'Name and shell'));
      gecos = textBox(u.gecos || '', 'e.g. Jan Novák');
      s1.appendChild(formField('Full name', gecos));
      shell = shellSelect(u.shell);
      s1.appendChild(formField('Shell', shell));
      var sv = cmdButton('Save', 'save', 'small');
      sv.onclick = function () {
        api('osusers', {action: 'set', name: name, gecos: gecos.value.trim(), shell: shell.value}).then(function (x) { toast(x.message, 'good'); OSU.d = x; poll(true); }).catch(oops);
      };
      var r1 = el('div', 'btnrow'); r1.appendChild(sv); s1.appendChild(r1);
      body.appendChild(s1);
      /* The password. */
      var s2 = el('div', 'osu-sect');
      s2.appendChild(el('h3', '', 'Password'));
      pw = pwPair(s2, true);
      must = check('To be changed at the next sign-in', false);
      s2.appendChild(must.box);
      var sp = cmdButton('Set the password', 'key', 'small');
      sp.onclick = function () {
        var p = pw();
        if (!p.ok) { toast(p.said, 'warn'); return; }
        api('osusers', {action: 'password', name: name, password: p.value, must_change: must.input.checked}).then(function (x) {
          toast(x.message, 'good'); OSU.d = x; poll(true);
          s2.querySelectorAll('input.masked').forEach(function (i) { i.value = ''; });
        }).catch(oops);
      };
      var r2 = el('div', 'btnrow'); r2.appendChild(sp); s2.appendChild(r2);
      body.appendChild(s2);
      /* Its own password aging. */
      var sa = el('div', 'osu-sect');
      sa.appendChild(el('h3', '', 'Password aging'));
      var ag = el('div', 'pwp-aging');
      var mx = pwpNum(u.max_days === null || u.max_days === undefined ? 99999 : u.max_days, 0, 99999);
      var mn = pwpNum(u.min_days || 0, 0, 365), wn = pwpNum(u.warn_days === undefined || u.warn_days === null ? 7 : u.warn_days, 0, 365);
      ag.appendChild(pwpField('Good for (days)', mx, '99999: no end'));
      ag.appendChild(pwpField('Warned so many days before', wn));
      ag.appendChild(pwpField('The least days between two changes', mn));
      sa.appendChild(ag);
      if (u.pw_ends) sa.appendChild(el('p', 'muted small', 'The password runs out on ' + day(u.pw_ends) + '.'));
      var sg = cmdButton('Save the aging', 'save', 'small');
      sg.onclick = function () {
        api('osusers', {action: 'aging', name: name, max_days: mx.value, min_days: mn.value, warn_days: wn.value}).then(function (x) { toast(x.message, 'good'); OSU.d = x; poll(true); }).catch(oops);
      };
      var ra = el('div', 'btnrow'); ra.appendChild(sg); sa.appendChild(ra);
      body.appendChild(sa);
      /* sudo, sign-in, the console at login. */
      var s3 = el('div', 'osu-sect');
      s3.appendChild(el('h3', '', 'What they may do'));
      if (u.sudo && !u.password)
        s3.appendChild(el('p', 'note warn', 'May use sudo, but has no password: sudo asks for their own password, so they cannot use it (nor upnp --console through it) until they have one - set it above.'));
      var r3 = el('div', 'btnrow');
      var su = cmdButton(u.sudo ? 'Take sudo away' : 'Give sudo', 'shield', 'small');
      explain(su, 'sudo: may become root with their own password (a member of ' + ((OSU.d && OSU.d.admin_group) || 'wheel') + ').');
      su.onclick = function () {
        api('osusers', {action: 'sudo', name: name, on: !u.sudo}).then(done).catch(oops);
      };
      var lk = cmdButton(u.locked ? 'Unlock' : 'Lock', 'lock', 'small');
      explain(lk, u.locked ? 'May sign in again - with the password, or a key.' : 'May not sign in at all - neither with the password nor with an SSH key - until unlocked. Nothing of theirs is taken away.');
      lk.onclick = function () {
        api('osusers', {action: u.locked ? 'unlock' : 'lock', name: name}).then(done).catch(oops);
      };
      r3.appendChild(su); r3.appendChild(lk);
      s3.appendChild(r3);
      if (u.login) {
        var con = (OSU.d && OSU.d.console) || {};
        var cs = check('The upnp console when they sign in', consoleOn(name), con.users === '*'
          ? 'Every normal user has it now (upnp --console-users \'*\'); off: every one but ' + name + '.'
          : 'Through sudo, with their own password - q leaves it for the shell (upnp --console-users).');
        cs.input.disabled = !u.sudo && !consoleOn(name);
        if (cs.input.disabled) cs.box.appendChild(el('span', 'muted small', ' needs sudo'));
        cs.input.onchange = function () {
          api('osusers', {action: 'console', name: name, on: cs.input.checked}).then(function (x) { toast(x.message, 'good'); OSU.d = x; poll(true); }).catch(oops);
        };
        s3.appendChild(cs.box);
      }
      body.appendChild(s3);
      /* Taken away. */
      var s4 = el('div', 'osu-sect');
      s4.appendChild(el('h3', '', 'Take the user away'));
      home = check('Its home folder too', false, (u.home || '') + ' - with everything in it, SSH keys among it.');
      s4.appendChild(home.box);
      body.appendChild(s4);
    }, u.root ? [{words: 'Close', close: true}] : [{words: 'Take the user away', cls: 'danger', icon: 'trash', left: true, go: function () {
      api('osusers', {action: 'drop', name: name, home: home.input.checked}).then(done).catch(oops);
    }}, {words: 'Close', close: true}], 'medium');
  }

  PANE_LOAD.osusers = load;
  PANE_TICK.osusers = function () {
    if (OSU.poll) return;
    var a = document.activeElement, host = $('osu-host');
    if (a && host && host.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)) return;
    api('osusers').then(function (d) { OSU.d = d; draw(true); }).catch(function () {});
  };
})();
