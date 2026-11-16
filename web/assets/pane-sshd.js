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
    noticeCard();
    api('sshd').then(function (d) { SD.d = d; draw(); poll(busyNow(d)); }).catch(oops);
  }
  /* The notice's settings in a card of their own, as otp has them: drawn by the settings code
     into the pane's grid, moved here (drawn again there after every save). */
  function noticeCard() {
    var host = $('sd-notice');
    if (!host) return;
    clear(host);
    var grid = el('div', 'set-grid');
    NOTICE_KEYS.forEach(function (k) {
      var item = document.querySelector('#sect-sshd .set-item[data-key="' + k + '"]');
      if (item) grid.appendChild(item);
    });
    host.appendChild(grid);
  }
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
      if (d.pending) hd.appendChild(el('span', 'tag info', 'asked of root'));
      var tools = el('span', 'right');
      var again = iconButton('refresh', 'Read again what sshd has');
      again.onclick = function () { act('refresh'); };
      tools.appendChild(again);
      hd.appendChild(tools);
      cd.appendChild(hd);
      cd.appendChild(netFacts([
        ['Port', v.port || '', true],
        ['Root may sign in', v.permitrootlogin ? permitWords(v.permitrootlogin) : (now.there === false ? 'sshd is not here' : '')],
        ['Passwords', v.passwordauthentication || ''],
        ['Keys', v.pubkeyauthentication || ''],
        ['Tries a connection', v.maxauthtries || '', true],
        ['Who may sign in', v.allowusers || 'everybody'],
        ['Keys of root', now.keys === undefined ? '' : String(now.keys)],
        ['Banner', v.banner && v.banner !== 'none' ? v.banner : 'none', true],
        ['SELinux', now.selinux || '–', true],
        ['fake-igd\'s file', now.dropin ? 'sshd_config.d/00-fake-igd.conf' : 'none', true],
        ['Read', now.read_at ? ago(now.read_at) : 'not yet']
      ]));
      if (now.there === false) cd.appendChild(el('p', 'note bad', 'sshd is not on this server (dnf install openssh-server).'));
      if (now.dropins === false && now.there !== false) cd.appendChild(el('p', 'note warn', 'This sshd does not read sshd_config.d - fake-igd cannot set it here.'));
      if (now.dropin) {
        var det = el('details', '');
        det.appendChild(el('summary', 'small', 'What fake-igd\'s file says'));
        var pre = noI18n(el('pre', 'lines', now.dropin));
        pre.style.maxHeight = 'none'; pre.style.overflow = 'visible';
        det.appendChild(pre);
        cd.appendChild(det);
      }
      grid.appendChild(cd);
      host.appendChild(grid);
      /* What the wish would do, said before it is saved (otp's notes under the form). */
      if (c.manage && !now.keys && (c.permit_root === 'prohibit-password' || !c.password) && c.permit_root !== 'no')
        host.appendChild(el('p', 'note bad', 'Root has no key here - add one to /root/.ssh/authorized_keys on the machine first (SSH keys shows them), or this is refused.'));
      if (c.manage && !c.password && c.permit_root === 'yes')
        host.appendChild(el('p', 'note', 'Passwords off: root signs in with a key either way.'));
      if (c.manage && Number(c.port) !== 22)
        host.appendChild(el('p', 'muted small', 'Port ' + c.port + ': SELinux and firewalld let it in by themselves; fake-igd\'s own firewall (FAKE-IGD-IN) lets in ' + ((now.ports || [22]).join(', ')) + '.'));
    }, live);
  }
  PANE_LOAD.sshd = load;
  PANE_TICK.sshd = function () {
    if (SD.poll) return;
    api('sshd').then(function (d) { SD.d = d; draw(true); if (busyNow(d)) poll(true); }).catch(function () {});
  };
})();
