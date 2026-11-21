/* Settings → SSH server and notices (otp's loadSshd / drawSshd, 1.0.163).
   One wish - the settings below, saved with the bar at the bottom - put in by root as a
   drop-in of fake-igd's own, checked by sshd -t, and on trial until Keep it. Above it,
   what sshd has now on this server and the state of the last change. */
(function () {
  var SD = {d: null, poll: null};
  var SD_STATE = {done: ['as wished', 'ok'], trial: ['on trial', 'warn'], waiting: ['being put in', 'info'],
                  failed: ['refused', 'crit'], back: ['went back', 'warn']};
  var NOTICE_KEYS = ['sshd_notice', 'sshd_notice_ssh', 'sshd_notice_console', 'sshd_notice_motd'];

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
  function liveLetGo(host) {
    if (!host || host._letGo) return;
    host._letGo = true;
    host.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('button') : null;
      if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
    });
  }
  function busyNow(d) { return d && (d.pending || d.state === 'waiting' || d.state === 'trial'); }
  function poll(on) {
    if (on && !SD.poll) {
      SD.poll = setInterval(function () {
        if (TAB !== 'settings' || PANE !== 'sshd') { poll(false); return; }
        api('sshd').then(function (d) { SD.d = d; draw(true); if (!busyNow(d)) poll(false); }).catch(function () {});
      }, 3000);
    }
    if (!on && SD.poll) { clearInterval(SD.poll); SD.poll = null; }
  }
  function load() {
    layout();
    api('sshd').then(function (d) { SD.d = d; draw(); poll(busyNow(d)); }).catch(oops);
  }
  /* otp draws this pane's wish as a form of its own (drawSshd: formField, a grid "formgrid sd-grid",
     Root signs in as three buttons, Who may sign in picked from the accounts, the notice's places as
     ticks). Here the settings code draws the boxes - so the save bar, its count and Put them back
     work as everywhere - and they are laid out as otp's form, each box still the setting's own. */
  var FORM_KEYS = ['sshd_permit_root', 'sshd_password', 'sshd_port', 'sshd_tries', 'sshd_allow_users', 'sshd_trial_min'];
  var WHERE = [['sshd_notice_ssh', 'Before signing in over SSH', 'sshd\'s Banner - needs fake-igd to set the SSH server'],
               ['sshd_notice_console', 'At the console', 'the console\'s sign-in screen (/etc/issue.d, or /etc/issue)'],
               ['sshd_notice_motd', 'After signing in', 'the message of the day']];
  function plain(item) {
    if (!item) return null;
    var i = item.querySelector('.iinfo');
    if (i) i.remove();
    var says = item.querySelector('.says.clamp');
    if (says) { says.classList.remove('clamp', 'cut'); says.onclick = null; }
    item.classList.remove('wide', 'tall', 'asleep');
    var why = item.querySelector('.asleep-why');
    if (why) why.remove();
    var k = item.dataset.key;
    if (k in SAYS) {
      var tail = item.querySelector('.set-tail');
      if (tail) { clear(tail); if (SAYS[k]) tail.appendChild(el('div', 'says', SAYS[k])); }
    }
    return item;
  }
  var SAYS = {sshd_manage: 'Off: this server keeps sshd as the system has it, and fake-igd\'s file is taken away.',
              sshd_permit_root: '', sshd_password: 'Off: only keys sign in, for everybody.',
              sshd_port: 'Another than 22: the firewall lets it in by itself, the old one too while it is on trial.',
              sshd_tries: 'Wrong passwords or keys before sshd closes it (MaxAuthTries).',
              sshd_allow_users: 'The accounts that may sign in over SSH (AllowUsers) - or everybody. Root left out of the list signs in only at the console.',
              sshd_trial_min: 'Unless kept within this, root puts back what it had. 0: no trial - not advised.'};
  function boxOf(k) { return $('set-' + k); }
  function changed(box, ev) { box.dispatchEvent(new Event(ev || 'change', {bubbles: true})); }
  function manageOn() { var m = boxOf('sshd_manage'); return !!(m && m._get && m._get()); }
  function layout() {
    var sect = $('sect-sshd'), nh = $('sd-notice');
    if (!sect || !nh) return;
    var item = function (k) { return document.querySelector('#pane-sshd .set-item[data-key="' + k + '"]'); };
    if (!item('sshd_manage')) return;
    var keep = {};
    ['sshd_notice'].concat(WHERE.map(function (o) { return o[0]; })).forEach(function (k) { keep[k] = item(k); });
    clear(nh);
    item = function (k) { return keep[k] || document.querySelector('#pane-sshd .set-item[data-key="' + k + '"]'); };
    var g0 = el('div', 'formgrid');
    g0.appendChild(plain(item('sshd_manage')));
    var g = el('div', 'formgrid sd-grid');
    FORM_KEYS.forEach(function (k) { var it = plain(item(k)); if (it) g.appendChild(it); });
    clear(sect);
    sect.appendChild(g0);
    sect.appendChild(g);
    /* Root signs in: three buttons, as otp's - the select kept, hidden, as the setting's box. */
    var sel = boxOf('sshd_permit_root');
    if (sel && !sel._seg) {
      var seg = el('div', 'seg');
      [['prohibit-password', 'With a key only'], ['yes', 'With a key or a password'], ['no', 'Not at all']].forEach(function (o) {
        var b = el('button', '', o[1]);
        b.type = 'button';
        b.dataset.v = o[0];
        b.onclick = function () { sel.value = o[0]; changed(sel); paint(); };
        seg.appendChild(b);
      });
      sel.hidden = true;
      sel.parentNode.insertBefore(seg, sel);
      sel._seg = seg;
    }
    /* Who may sign in: the accounts of this machine, picked - or everybody. */
    var au = boxOf('sshd_allow_users');
    if (au && !au._pick) {
      au.hidden = true;
      var pick = accountPicker(au);
      au.parentNode.insertBefore(pick, au);
      au._pick = pick;
    }
    /* The notice: its words, and where it is shown as three ticks. */
    var words = plain(item('sshd_notice'));
    if (words) {
      var ta = words.querySelector('textarea, input');
      ta.rows = 6;
      ta.classList.add('mono', 'sd-notice');
      ta.placeholder = 'Authorised use only. Every connection is logged.';
      var says = words.querySelector('.says');
      if (says) says.textContent = 'Plain text, as many lines as needed - often what the security policy wants said.';
      nh.appendChild(words);
    }
    var wh = el('div', 'sd-where');
    WHERE.forEach(function (o) {
      var it = item(o[0]);
      var sw = it && it.querySelector('label.sw');
      if (!it || !sw) return;
      it.hidden = true;
      nh.appendChild(it);
      var lab = el('label', 'chk');
      var cb = el('input');
      cb.type = 'checkbox';
      cb.checked = !!sw._get();
      cb.dataset.key = o[0];
      cb.onchange = function () { sw._input.checked = cb.checked; changed(sw._input); };
      lab.appendChild(cb);
      lab.appendChild(el('span', '', o[1]));
      lab.appendChild(el('span', 'muted small', o[2]));
      wh.appendChild(lab);
    });
    nh.appendChild(wh);
    var man = boxOf('sshd_manage');
    if (man && man._input && !man._paints) { man._paints = true; man._input.addEventListener('change', paint); }
    paint();
  }
  /* What the wish leaves on or off, as otp's form: the grid greyed and its boxes shut while
     fake-igd does not set the SSH server; Before signing in over SSH with it. */
  function paint() {
    var on = manageOn(), g = document.querySelector('#sect-sshd .sd-grid');
    if (!g) return;
    g.classList.toggle('off', !on);
    g.querySelectorAll('input, select, textarea, button').forEach(function (x) { x.disabled = !on || !ADMIN; });
    var pk = g.querySelector('.acct-pick');
    if (pk) pk.classList.toggle('off', !on || !ADMIN);
    var sel = boxOf('sshd_permit_root');
    if (sel && sel._seg) Array.prototype.forEach.call(sel._seg.children, function (b) { b.classList.toggle('on', b.dataset.v === sel.value); });
    document.querySelectorAll('#sd-notice .sd-where input').forEach(function (cb) {
      var sw = boxOf(cb.dataset.key);
      if (sw) cb.checked = !!sw._get();
      cb.disabled = !ADMIN || (cb.dataset.key === 'sshd_notice_ssh' && !on);
    });
    notes();
  }
  /* otp's notes under the form: said from the wish as it is in the boxes, before it is saved. */
  function notes() {
    var host = $('sd-form-notes');
    if (!host) return;
    clear(host);
    var on = manageOn(), now = (SD.d && SD.d.now) || {};
    var sel = boxOf('sshd_permit_root'), pw = boxOf('sshd_password');
    var permit = sel ? sel.value : 'prohibit-password', pass = pw ? !!pw._get() : true;
    if (on && !now.keys && (permit === 'prohibit-password' || !pass) && permit !== 'no')
      host.appendChild(el('p', 'note bad', 'Root has no key on this server - add one to /root/.ssh/authorized_keys first (SSH keys shows them), or this is refused.'));
    if (on && !pass && permit === 'yes')
      host.appendChild(el('p', 'note', 'Passwords off: root signs in with a key either way.'));
  }
  /* otp's accountPicker (1.0.242): root and the users who may sign in here, several, or everybody -
     written into the setting's own box as a list. */
  var ACCTS = {names: null, at: 0, waiting: []};
  function accounts(cb) {
    if (ACCTS.names && Date.now() - ACCTS.at < 60000) { cb(ACCTS.names); return; }
    if (!ADMIN) { cb([]); return; }     /* the accounts are a full administrator's to read (no 403 for a viewer) */
    ACCTS.waiting.push(cb);
    if (ACCTS.waiting.length > 1) return;
    var done = function (names) {
      ACCTS.names = names; ACCTS.at = Date.now();
      var w = ACCTS.waiting; ACCTS.waiting = [];
      w.forEach(function (f) { try { f(names); } catch (e) { /* gone */ } });
    };
    api('sshkeys').then(function (d) {
      var seen = {}, names = [];
      ((d && d.users) || []).forEach(function (u) { if (u && u.name && !seen[u.name]) { seen[u.name] = 1; names.push(u.name); } });
      done(names.sort());
    }).catch(function () { done([]); });
  }
  function accountPicker(box) {
    var cur = String(box.value || '').split(/[\s,;]+/).filter(Boolean);
    var write = function () { box.value = cur.join(', '); changed(box, 'input'); };
    var pick = el('details', 'acct-pick');
    var sum = el('summary', '');
    pick.appendChild(sum);
    var panel = el('div', 'acct-panel');
    pick.appendChild(panel);
    var said = function () {
      clear(sum);
      if (!cur.length) {
        var ev0 = el('span', 'acct-every');
        ev0.innerHTML = iconMarkup('people', 14);
        ev0.appendChild(el('span', '', 'Everybody'));
        sum.appendChild(ev0);
        return;
      }
      cur.forEach(function (n) {
        var chip = el('span', 'acct-chip');
        chip.appendChild(noI18n(el('span', 'mono', n)));
        var x = el('button', 'acct-x', '×');
        x.type = 'button';
        x.title = 'Take it away';
        x.onclick = function (e) {
          e.preventDefault(); e.stopPropagation();
          if (pick.classList.contains('off')) return;
          cur = cur.filter(function (m) { return m !== n; });
          said(); draw(ACCTS.names || []); write();
        };
        chip.appendChild(x);
        sum.appendChild(chip);
      });
    };
    var draw = function (names) {
      clear(panel);
      var all = ['root'].concat(names.filter(function (n) { return n !== 'root'; }));
      cur.forEach(function (n) { if (all.indexOf(n) < 0) all.push(n); });
      var ev = el('label', 'acct-row acct-row-every');
      var evc = el('input'); evc.type = 'checkbox'; evc.checked = !cur.length;
      var evi = el('span', 'acct-ava every'); evi.innerHTML = iconMarkup('people', 14);
      ev.appendChild(evc); ev.appendChild(evi); ev.appendChild(el('span', 'acct-name', 'Everybody'));
      panel.appendChild(ev);
      var boxes = [];
      all.forEach(function (n) {
        var r = el('label', 'acct-row');
        var c = el('input'); c.type = 'checkbox'; c.value = n; c.checked = cur.indexOf(n) >= 0;
        r.appendChild(c);
        r.appendChild(noI18n(el('span', 'acct-ava' + (n === 'root' ? ' root' : ''), n.slice(0, 2).toUpperCase())));
        r.appendChild(noI18n(el('span', 'acct-name mono', n)));
        if (n !== 'root' && names.indexOf(n) < 0) r.appendChild(el('span', 'tag dim', 'not listed by this machine'));
        panel.appendChild(r);
        boxes.push(c);
      });
      evc.onchange = function () {
        if (evc.checked) { cur = []; boxes.forEach(function (c) { c.checked = false; }); }
        else if (!cur.length) { evc.checked = true; return; }
        said(); write();
      };
      boxes.forEach(function (c) {
        c.onchange = function () {
          cur = boxes.filter(function (x) { return x.checked; }).map(function (x) { return x.value; });
          evc.checked = !cur.length;
          said(); write();
        };
      });
    };
    said();
    panel.appendChild(el('p', 'muted small', 'reading the users of this machine…'));
    accounts(draw);
    var shut = function (e) {
      if (!pick.isConnected) { document.removeEventListener('click', shut); return; }
      if (pick.open && !pick.contains(e.target)) pick.open = false;
    };
    document.addEventListener('click', shut);
    sum.addEventListener('click', function (e) { if (pick.classList.contains('off')) e.preventDefault(); });
    return pick;
  }
  /* Laid out again whenever the settings are drawn again (after a save, after Put them back);
     the sleeping-while-off of these keys is the form's own (greyed, not said under each box). */
  (function () {
    var theirs = drawSettings;
    drawSettings = function () {
      var ow = SETTINGS && SETTINGS.only_when;
      if (ow) FORM_KEYS.concat(['sshd_notice_ssh']).forEach(function (k) { delete ow[k]; });
      var r = theirs.apply(this, arguments);
      try { layout(); } catch (e) { /* drawn as the settings code drew it */ }
      return r;
    };
  }());
  function act(action, b) {
    if (b) busy(b, true);
    api('sshd', {action: action}).then(function (r) { toast(r.message, 'good'); SD.d = r; draw(); poll(true); })
      .catch(function (e) { if (b) busy(b, false); oops(e); });
  }
  function permitWords(v) {
    return ({'without-password': 'with a key only', 'prohibit-password': 'with a key only', 'yes': 'yes', 'no': 'no'})[v] || v;
  }
  function draw(live) {
    var real = $('sd-host');
    if (!real || !SD.d) return;
    liveLetGo(real);
    liveFill(real, function (host) {
      var d = SD.d, now = d.now || {}, v = now.values || {}, c = d.conf || {};
      var skew = (d.now_at || Date.now() / 1000) - Date.now() / 1000;
      if (!d.helper) host.appendChild(el('p', 'note bad', 'The root helper of this server is not installed (install.sh --upgrade puts it in).'));
      if (d.late) host.appendChild(el('p', 'note bad', d.late));
      /* On trial: keep it, or put it back. */
      var trial = now.trial || {};
      if (d.state === 'trial' && trial.until) {
        var tc = el('div', 'card full notice warn sd-trial');
        tc.appendChild(el('h2', '', 'On trial - keep it, or it goes back'));
        var left = Math.max(0, Math.round(trial.until - (Date.now() / 1000 + skew)));
        tc.appendChild(el('p', 'note', 'Open a new SSH session to this server now, with the port and the way of signing in as set, and keep the one you have open. Works: Keep it. Unless kept, root puts back what it had in ' + span(left) + '.'));
        var row = el('div', 'btnrow');
        var kp = cmdButton('Keep it', 'check', 'primary');
        kp.onclick = function () { act('keep', kp); };
        var bk = cmdButton('Put it back now', 'undo', '');
        bk.onclick = function () { confirmThen('Put the SSH server back', 'Root puts back what it had before the change on trial.', 'Put it back', function () { act('back', bk); }, false); };
        row.appendChild(kp); row.appendChild(bk);
        tc.appendChild(row);
        host.appendChild(tc);
      }
      if (d.state === 'failed') host.appendChild(el('p', 'note bad', 'Refused: ' + ((now.said || [])[0] || now.error || 'root said no') + ' - it is as it was.'));
      if (d.state === 'back' || d.state === 'failed') {
        if (d.state === 'back') host.appendChild(el('p', 'note warn', 'The last change went back (' + (now.back_why || 'not kept in time') + ')' + (now.back_at ? ', ' + ago(now.back_at) : '') + ' - sshd is as it was before it.'));
        var ar = el('div', 'btnrow');
        var again2 = cmdButton('Put it in again', 'refresh', 'small');
        explain(again2, 'The settings below as they are saved, put in again by root - on trial again.');
        again2.onclick = function () { act('apply', again2); };
        ar.appendChild(again2);
        host.appendChild(ar);
      }
      /* This server, as sshd has it. */
      var grid = el('div', 'pw-grid');
      var cd = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (now.at ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', d.node || 'this server')));
      hd.appendChild(el('span', 'tag info', 'this page'));
      var w = SD_STATE[d.state] || SD_STATE.done;
      if ((d.wish || {}).hash) hd.appendChild(el('span', 'tag ' + w[1], w[0]));
      cd.appendChild(hd);
      cd.appendChild(netFacts([
        ['Port', v.port || '', true],
        ['Root may sign in', v.permitrootlogin ? permitWords(v.permitrootlogin) : (now.there === false ? 'sshd is not here' : '')],
        ['Passwords', v.passwordauthentication || ''],
        ['Tries a connection', v.maxauthtries || '', true],
        ['Who may sign in', v.allowusers || 'everybody'],
        ['Keys of root', now.keys === undefined ? '0' : String(now.keys)],
        ['SELinux', now.selinux || '–', true],
        ['Read', now.read_at ? ago(now.read_at) : 'not yet']
      ]));
      if (now.there === false) cd.appendChild(el('p', 'note bad', 'sshd is not on this server (dnf install openssh-server).'));
      if (now.dropins === false && now.there !== false) cd.appendChild(el('p', 'note warn', 'This sshd does not read sshd_config.d - fake-igd cannot set it here.'));
      grid.appendChild(cd);
      host.appendChild(grid);
      setTimeout(notes, 0);
    }, live);
  }
  PANE_LOAD.sshd = load;
  PANE_TICK.sshd = function () {
    if (SD.poll) return;
    api('sshd').then(function (d) { SD.d = d; draw(true); if (busyNow(d)) poll(true); }).catch(function () {});
  };
})();
