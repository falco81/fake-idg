/* pane-backup.js - Settings → Backups (otp's loadRbackup, drawRbTop, drawRbTargets, drawRbRuns, rbEdit,
   rbTry, rbListThere, the putting back - for fake-igd, one machine). */
(function () {
  'use strict';
  var RB = null, RB_POLL = null, EDIT = {form: null, cur: null, pin: null, check: null, paintHost: null};
  var RB_KIND_ICON = {folder: 'db', ftp: 'upload', ftps: 'lock', sftp: 'terminal', scp: 'terminal', smb: 'net'};
  var RB_KIND_SAYS = {
    folder: 'A folder on this machine - an NFS or other share mounted here. Root writes into it.',
    ftp: 'Plain FTP: the password and the file go over unencrypted - only inside a network you trust (the file itself is locked).',
    ftps: 'FTP over TLS - explicit (port 21) or implicit (990); the server’s certificate checked.',
    sftp: 'SSH file transfer: a key made here or your own, or a password; the server’s host key checked.',
    scp: 'scp over SSH, and ssh to list and take away old ones - needs a shell on the server.',
    smb: 'A Windows or Samba share: the account, its domain, SMB3 encryption.'
  };

  function rbBytes(n) {
    n = Number(n || 0);
    if (n < 1024) return num(n) + ' B';
    var u = ['kB', 'MB', 'GB', 'TB'], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
  }
  function rbWhere(t) {
    if (t.kind === 'folder') return t.path || '';
    if (t.kind === 'smb') return '\\\\' + t.host + (t.port && t.port !== 445 ? ':' + t.port : '') + '\\' + (t.share || '') + (t.path ? '\\' + String(t.path).replace(/\//g, '\\') : '');
    return (t.user ? t.user + '@' : '') + t.host + (t.port ? ':' + t.port : '') + '/' + String(t.path || '').replace(/^\//, '');
  }
  function hideButton(go) {
    var b = cmdButton('Hide this', 'close', 'small');
    b.classList.add('hide-this');
    b.onclick = function (e) { if (e) e.stopPropagation(); go(); };
    return b;
  }
  function hideBar(go, words) {
    var row = el('div', 'actions hide-row');
    row.appendChild(hideButton(go));
    if (words) row.appendChild(el('span', 'muted small', words));
    return row;
  }
  function saveBytes(name, b64, type) {
    var raw = atob(b64), arr = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([arr], {type: type || 'application/octet-stream'}));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function loadRbackup() {
    var top = $('rb-top');
    if (!top) return;
    if (!ADMIN) {
      clear(top);
      top.appendChild(el('p', 'note', 'Only a full administrator sees and changes the backups: they hold every account.'));
      return;
    }
    api('backup').then(function (d) {
      RB = d;
      drawRbTop();
      drawRbTargets();
      drawRbRuns();
      rbPassTools();
      if (d.job && d.job.running) rbWatch();
      explainWhatWasDrawn($('pane-backup'));
    }).catch(oops);
  }
  PANE_LOAD.backup = loadRbackup;

  /* "Make a strong one" beside the password of the backups: a long random one, shown once. */
  function rbPassTools() {
    var item = document.querySelector('.set-item[data-key="rbackup_password"]');
    if (!item || item.querySelector('.rb-gen')) return;
    var b = cmdButton('Make a strong one', 'key', 'small rb-gen');
    b.style.alignSelf = 'flex-start';
    b.onclick = function () {
      var a = new Uint8Array(24);
      crypto.getRandomValues(a);
      var abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
      var pw = '';
      for (var i = 0; i < a.length; i++) { pw += abc.charAt(a[i] % abc.length); if (i % 6 === 5 && i < a.length - 1) pw += '-'; }
      var box = item.querySelector('input');
      if (box) {
        if (box._set) box._set(pw); else box.value = pw;
        box.dispatchEvent(new Event('input', {bubbles: true}));
        box.dispatchEvent(new Event('change', {bubbles: true}));
      }
      modal('The password of the backups', function (body) {
        body.appendChild(el('p', 'note', 'Put it into your password vault now - this is the only time it is shown whole. Without it no backup can be opened, by anybody. Then press Save the changes.'));
        body.appendChild(noI18n(el('div', 'rb-pass mono', pw)));
        var c = cmdButton('Copy', 'copy', 'small');
        c.onclick = function () { copyText(pw, c, 'Copied'); };
        body.appendChild(c);
      }, [{words: 'Close', close: true}], true);
    };
    var says = item.querySelector('.says');
    if (says) says.parentNode.insertBefore(b, says); else item.appendChild(b);
  }

  function drawRbTop() {
    var host = $('rb-top');
    clear(host);
    var d = RB;
    var card = el('div', 'card full rb-hero');
    var mine = (d.runs || [])[0];
    var on = (d.targets || []).filter(function (t) { return t.enabled; });
    var state = !on.length ? 'warn' : (!mine ? 'warn' : (mine.ok ? 'good' : 'bad'));
    card.classList.add(state);
    var head = el('div', 'rb-hero-head');
    var ic = el('span', 'rb-hero-ic');
    ic.innerHTML = iconMarkup(state === 'good' ? 'check' : (state === 'bad' ? 'flag' : 'info'), 22);
    head.appendChild(ic);
    var words = el('div', 'rb-hero-words');
    var title = !on.length ? 'No destination yet - backups go nowhere'
      : (!mine ? 'No backup of this machine has been sent yet'
        : (mine.ok ? 'The last backup of ' + d.node + ' went to every destination'
          : 'The last backup of ' + d.node + ' did not reach every destination'));
    words.appendChild(el('b', '', title));
    var facts = el('div', 'rb-hero-facts');
    var fact = function (k, v, cls) {
      var f = el('span', 'rb-fact ' + (cls || ''));
      f.appendChild(el('span', 'k', k));
      f.appendChild(el('span', 'v', v));
      facts.appendChild(f);
    };
    if (mine) fact('Last', ago(mine.at) + (mine.bytes ? ' · ' + rbBytes(mine.bytes) : ''));
    fact('Next', d.next ? new Date(d.next).toLocaleString(numLang(), {weekday: 'short', day: 'numeric', month: 'numeric', hour: '2-digit', minute: '2-digit'}) : 'by hand only', d.next ? '' : 'warn');
    fact('Locked', d.locked ? 'with the password (AES-256)' : 'NOT locked - set the password', d.locked ? 'good' : 'bad');
    fact('Destinations', num(on.length) + ' of ' + num((d.targets || []).length) + ' switched on');
    var tried = (d.verified || [])[0];
    fact('Tried', tried ? (tried.ok ? 'can be put back' : 'NOT GOOD') + ' · ' + ago(tried.at) : 'never', tried ? (tried.ok ? 'good' : 'bad') : 'warn');
    words.appendChild(facts);
    if (mine && (!mine.ok || mine.warning)) {
      var bad = (mine.targets || []).filter(function (x) { return !x.ok; });
      var why = el('div', 'rb-hero-why small ' + (mine.ok ? 'warn' : 'bad'));
      why.textContent = mine.error || bad.map(function (x) { return x.name + ': ' + (x.error || 'failed'); }).join(' · ') || mine.warning;
      words.appendChild(why);
    }
    head.appendChild(words);
    var acts = el('div', 'rb-hero-acts');
    var now = cmdButton('Back up now', 'upload', 'primary');
    now.id = 'rb-now';
    now.disabled = !on.length || (d.job && d.job.running);
    explain(now, 'A backup made now and sent to every destination switched on - the same as the scheduled one.');
    now.onclick = function () {
      busy(now, true);
      api('backup', {action: 'run'}).then(function (x) { toast(x.message, 'good'); RB.job = x.job; rbWatch(); })
        .catch(function (e) { busy(now, false); oops(e); });
    };
    acts.appendChild(now);
    var tryb = cmdButton('Try the newest', 'check', '');
    tryb.disabled = !on.length || (d.job && d.job.running);
    explain(tryb, 'The newest backup of this machine fetched back from the first destination, opened with the password, every file checked and the database read through - nothing is put back.');
    tryb.onclick = function () {
      busy(tryb, true);
      api('backup', {action: 'verify'}).then(function (x) { toast(x.message, 'good'); RB.job = x.job; rbWatch(); })
        .catch(function (e) { busy(tryb, false); oops(e); });
    };
    acts.appendChild(tryb);
    var dl = cmdButton('Download one here', 'download', '');
    /* Pressable as otp's; with no password it says why not and takes you to the password (otp asks
       whether to download it unlocked - fake-igd never writes an unlocked backup). */
    explain(dl, 'A backup made now, saved on the computer you are sitting at - locked with the password as the others.');
    dl.onclick = function () {
      if (!d.locked) {
        confirmThen('Set the password of the backups first', 'No password of the backups is set: a backup holds <b>every account and every secret</b> of this installation, and fake-igd writes none that is not locked. Set it, save, and download one then.', 'Set the password', function () {
          var box = $('set-rbackup_password');
          if (box) { box.scrollIntoView({block: 'center'}); box.focus(); }
        }, false);
        return;
      }
      busy(dl, true);
      api('backup', {action: 'download'}).then(function (x) {
        toast(x.message, 'good'); RB.job = x.job; rbWatch(function (j) {
          if (!j.result || !j.result.ready) return;
          api('backup', {action: 'download_get', ready: j.result.ready}).then(function (y) {
            saveBytes(y.name, y.data);
            toast(y.name + ' · ' + rbBytes(y.bytes), 'good');
          }).catch(oops);
        });
      }).catch(function (e) { busy(dl, false); oops(e); });
    };
    acts.appendChild(dl);
    var back = cmdButton('Put one back…', 'undo', '');
    back.onclick = rbPutBackFile;
    acts.appendChild(back);
    var guide = cmdButton('How to put it back', 'book', '');
    explain(guide, 'RESTORE.md - the exact steps to bring everything back from a backup, filled in with this installation, as every backup carries it. To read now, and to keep apart from the backups.');
    guide.onclick = rbGuide;
    acts.appendChild(guide);
    head.appendChild(acts);
    card.appendChild(head);
    var going = el('div', 'going wide');
    going.id = 'rb-going';
    going.hidden = !(d.job && d.job.running);
    going.innerHTML = '<div class="bar"><span id="rb-going-fill"></span></div><div class="says" id="rb-going-says"></div>';
    card.appendChild(going);
    if (!d.tools.openssl) card.appendChild(el('p', 'note bad', 'openssl is not on this machine: backups cannot be locked (dnf install openssl).'));
    host.appendChild(card);
    drawRbTried();
  }

  /* The backups tried: each try, every check of it; the list can be emptied - the backups stay. */
  function drawRbTried() {
    var card = $('rb-tried-card'), host = $('rb-tried'), tools = $('rb-tried-tools');
    if (!card) return;
    var rows = RB.verified || [];
    card.hidden = !rows.length;
    clear(host);
    clear(tools);
    if (!rows.length) return;
    var forget = function (q) {
      api('backup', Object.assign({action: 'verified_forget'}, q)).then(function (d) {
        toast(d.message, 'good'); RB.verified = d.verified || []; drawRbTried();
      }).catch(oops);
    };
    var wipe = cmdButton('Clear the list', 'trash', 'small');
    wipe.onclick = function () {
      confirmThen('Clear the list of backups tried?', 'Every try goes from this list. <b>The backups themselves stay where they are.</b> Events keeps a line saying who cleared it.', 'Clear the list', function () { forget({all: 1}); }, true);
    };
    tools.appendChild(wipe);
    var list = el('div', 'rb-tried');
    rows.slice(0, 8).forEach(function (v, i) {
      var it = el('details', 'rb-try ' + (v.ok ? 'good' : 'bad'));
      if (i === 0 && !v.ok) it.open = true;
      var sm = el('summary');
      sm.appendChild(el('span', 'dot ' + (v.ok ? 'ok' : 'bad')));
      sm.appendChild(el('b', '', v.ok ? 'Can be put back' : 'Not good'));
      sm.appendChild(noI18n(el('span', 'mono small', v.file || '?')));
      sm.appendChild(el('span', 'muted small', '·'));
      sm.appendChild(el('span', 'muted small', ago(v.at)));
      sm.appendChild(el('span', 'muted small', '·'));
      sm.appendChild(noI18n(el('span', 'muted small', (v.node || '') + ' → ' + (v.target_name || ''))));
      var x = el('button', 'xbtn rb-try-x');
      x.type = 'button';
      x.setAttribute('data-icon', 'close');
      x.title = 'Take it off the list';
      x.onclick = function (e) { e.preventDefault(); e.stopPropagation(); forget({at: v.at}); };
      sm.appendChild(x);
      it.appendChild(sm);
      var ul = el('div', 'rb-checks');
      (v.checks || []).forEach(function (k) {
        var row = el('div', 'rb-check');
        row.appendChild(el('span', 'dot ' + (k.ok ? 'ok' : 'bad')));
        row.appendChild(el('span', '', k.what));
        if (k.said) row.appendChild(noI18n(el('span', 'muted small', '- ' + k.said)));
        ul.appendChild(row);
      });
      it.appendChild(ul);
      list.appendChild(it);
    });
    host.appendChild(list);
    dressButtons(host);
  }

  /* RESTORE.md on the pages: read here, downloaded as the file. */
  function rbGuide() {
    api('backup', {action: 'restore_md'}).then(function (d) {
      modal('How to put a backup back', function (body) {
        var lede = el('p', 'note');
        lede.innerHTML = 'The <code>RESTORE.md</code> every backup carries, as one made now would have it. Keep a copy apart from the backups - with the password of the backups in a vault.';
        body.appendChild(lede);
        var doc = noI18n(el('div', 'md-doc'));
        doc.appendChild(mdRender(d.md));
        body.appendChild(doc);
      }, [{words: 'Close', close: true},
          {words: 'Download RESTORE.md', cls: 'primary', icon: 'download', go: function () {
            var a = el('a');
            a.href = URL.createObjectURL(new Blob([d.md], {type: 'text/markdown;charset=utf-8'}));
            a.download = d.name || 'RESTORE.md';
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
          }}], 'large');
    }).catch(oops);
  }
  function mdInline(text) {
    var frag = document.createDocumentFragment();
    var re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g, last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      var t = m[0];
      if (t.charAt(0) === '`') frag.appendChild(el('code', '', t.slice(1, -1)));
      else if (t.slice(0, 2) === '**') frag.appendChild(el('b', '', t.slice(2, -2)));
      else frag.appendChild(el('i', '', t.slice(1, -1)));
      last = re.lastIndex;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    return frag;
  }
  function mdRender(md) {
    var out = document.createDocumentFragment();
    var lines = String(md || '').split('\n'), i = 0, para = [];
    var flush = function () {
      if (!para.length) return;
      var p = el('p');
      p.appendChild(mdInline(para.join(' ')));
      out.appendChild(p);
      para = [];
    };
    while (i < lines.length) {
      var ln = lines[i];
      if (/^```/.test(ln)) {
        flush();
        var code = [];
        i += 1;
        while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i += 1; }
        i += 1;
        var wrap = el('div', 'md-code');
        wrap.appendChild(el('pre', '', code.join('\n')));
        var cp = iconButton('copy', 'Copy');
        (function (txt, b) { b.onclick = function () { copyText(txt, b, 'copied'); }; })(code.join('\n'), cp);
        wrap.appendChild(cp);
        out.appendChild(wrap);
        continue;
      }
      var h = /^(#{1,4})\s+(.*)$/.exec(ln);
      if (h) { flush(); var hn = el('h' + Math.min(6, h[1].length + 2)); hn.appendChild(mdInline(h[2])); out.appendChild(hn); i += 1; continue; }
      if (/^\|/.test(ln)) {
        flush();
        var rows = [];
        while (i < lines.length && /^\|/.test(lines[i])) { rows.push(lines[i]); i += 1; }
        var tbl = el('table', 'md-table'), tb = el('tbody');
        rows.forEach(function (r, n) {
          if (/^\|[\s|:-]+\|$/.test(r)) return;
          var cells = r.replace(/^\|/, '').replace(/\|$/, '').split('|');
          var tr = el('tr');
          cells.forEach(function (c) { var td = el(n === 0 && rows.length > 1 && /^\|[\s|:-]+\|$/.test(rows[1]) ? 'th' : 'td'); td.appendChild(mdInline(c.trim())); tr.appendChild(td); });
          tb.appendChild(tr);
        });
        tbl.appendChild(tb);
        out.appendChild(tbl);
        continue;
      }
      if (/^\s*[-*] /.test(ln)) {
        flush();
        var ul = el('ul');
        while (i < lines.length && /^\s*[-*] /.test(lines[i])) {
          var li = el('li');
          li.appendChild(mdInline(lines[i].replace(/^\s*[-*] /, '')));
          ul.appendChild(li);
          i += 1;
        }
        out.appendChild(ul);
        continue;
      }
      if (!ln.trim()) { flush(); i += 1; continue; }
      para.push(ln.trim());
      i += 1;
    }
    flush();
    return out;
  }

  /* The job going on: the bar under the buttons, every second while the pane is open. */
  function rbWatch(done) {
    if (RB_POLL) return;
    var step = function () {
      api('backup-job').then(function (x) {
        var j = x.job || {};
        var g = $('rb-going');
        if (g) {
          g.hidden = !j.running;
          var f = $('rb-going-fill');
          if (f) f.style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
          var sy = $('rb-going-says');
          if (sy) sy.textContent = (j.what ? j.what + ' — ' : '') + (j.says || '');
        }
        if (j.running) { RB_POLL = setTimeout(step, TAB === 'settings' && PANE === 'backup' ? 1000 : 5000); return; }
        RB_POLL = null;
        if (j.error) toast(j.what + ': ' + j.error, 'bad');
        else if (j.result && j.result.targets) toast(j.result.ok ? 'the backup went to every destination' : 'the backup did not reach every destination', j.result.ok ? 'good' : 'bad');
        else if (j.result && j.result.checks) toast(j.result.ok ? 'the newest backup can be put back' : 'the newest backup is NOT good', j.result.ok ? 'good' : 'bad');
        if (done) done(j);
        if (TAB === 'settings' && PANE === 'backup') loadRbackup();
      }).catch(function () { RB_POLL = null; });
    };
    step();
  }

  function drawRbTargets() {
    var host = $('rb-targets');
    clear(host);
    var add = cmdButton('Add a destination', 'add', 'primary small');
    add.onclick = rbPickKind;
    var ah = $('rb-add-host');
    clear(ah);
    ah.appendChild(add);
    var ts = RB.targets || [];
    if (!ts.length) {
      var empty = el('div', 'rb-empty');
      empty.appendChild(el('p', '', 'No destination yet. A backup kept only on this machine is lost with it: add a place on another machine.'));
      host.appendChild(empty);
      return;
    }
    var grid = el('div', 'rb-grid');
    ts.forEach(function (t) {
      var c = el('div', 'rb-card' + (t.enabled ? '' : ' off'));
      var top = el('div', 'rb-card-top');
      var ic = el('span', 'rb-kind k-' + t.kind);
      ic.innerHTML = iconMarkup(RB_KIND_ICON[t.kind] || 'db', 18);
      top.appendChild(ic);
      var nm = el('div', 'rb-card-name');
      nm.appendChild(noI18n(el('b', '', t.name)));
      nm.appendChild(el('span', 'rb-kind-words', t.kind_words));
      top.appendChild(nm);
      var sw = switchBox(t.enabled);
      explain(sw, t.enabled ? 'Backups go here. Switch off to stop sending, keeping everything set.' : 'Switched off: nothing is sent here.');
      sw._input.onchange = function () {
        api('backup', {action: 'save', id: t.id, target: {kind: t.kind, enabled: sw._get(), name: t.name, host: t.host, port: t.port, path: t.path, user: t.user, share: t.share, domain: t.domain, smb_encrypt: t.smb_encrypt, implicit: t.implicit, tls_check: t.tls_check, pin: t.pin, passive: t.passive}})
          .then(function () { loadRbackup(); }).catch(function (e) { oops(e); loadRbackup(); });
      };
      top.appendChild(sw);
      c.appendChild(top);
      c.appendChild(noI18n(el('div', 'rb-where mono', rbWhere(t))));
      var chips = el('div', 'rb-chips');
      var chip = function (w, cls, tip) { var x = el('span', 'tag ' + (cls || 'dim'), w); if (tip) x.title = tip; chips.appendChild(x); };
      if (t.has_password) chip('password', 'dim');
      if (t.has_key) chip('ssh key', 'violet');
      if (t.ssh_cert) chip('ssh certificate', 'violet');
      if (t.kind === 'sftp' || t.kind === 'scp') chip(t.hostkey ? 'host key trusted' : 'host key not trusted yet', t.hostkey ? 'ok' : 'warn', (t.hostkey_fp || []).join('\n'));
      if (t.kind === 'ftps') chip({system: 'certificate: system authorities', pin: 'certificate pinned', none: 'certificate NOT checked'}[t.tls_check] || '', t.tls_check === 'none' ? 'warn' : 'ok');
      if (t.kind === 'smb' && t.smb_encrypt) chip('SMB3 encrypted', 'ok');
      if (t.kind === 'ftp') chip('not encrypted on the way', 'warn');
      c.appendChild(chips);
      var last = t.last;
      var ls = el('div', 'rb-last ' + (last ? (last.ok ? 'good' : 'bad') : 'muted'));
      ls.textContent = last ? (last.ok ? '✓ last sent ' + ago(last.at) + ' · ' + rbBytes(last.bytes) : '✗ ' + ago(last.at) + ': ' + (last.error || 'failed')) : 'nothing sent here yet';
      c.appendChild(ls);
      var acts = el('div', 'rb-acts');
      var tr = cmdButton('Try it', 'play', 'small');
      tr.onclick = function () { rbTry(t, null, tr); };
      acts.appendChild(tr);
      var ed = cmdButton('Edit', 'edit', 'small');
      ed.onclick = function () { rbEdit(t); };
      acts.appendChild(ed);
      var ls2 = cmdButton('Backups there', 'list', 'small');
      ls2.onclick = function () { rbListThere(t); };
      acts.appendChild(ls2);
      var del = iconButton('trash', 'Take this destination away');
      del.onclick = function () {
        confirmThen('Take the destination ' + htmlText(t.name) + ' away?', 'Nothing is deleted on the server; backups simply stop going there, and its keys set here are forgotten.', 'Take it away', function () {
          api('backup', {action: 'delete', id: t.id}).then(function (x) { toast(x.message, 'good'); loadRbackup(); }).catch(oops);
        });
      };
      acts.appendChild(del);
      c.appendChild(acts);
      grid.appendChild(c);
    });
    host.appendChild(grid);
  }

  function drawRbRuns() {
    var host = $('rb-runs');
    clear(host);
    var runs = RB.runs || [];
    var tools = $('rb-runs-tools');
    if (tools) {
      clear(tools);
      if (runs.length) {
        var wipe = cmdButton('Clear the list', 'trash', 'small');
        wipe.onclick = function () {
          confirmThen('Clear the list of backups sent?', 'Every line goes from this list. <b>The backups themselves stay where they went</b> - delete them under <i>Backups there</i> on a destination. Events keeps a line saying who cleared it.', 'Clear the list', function () {
            api('backup', {action: 'runs_forget', all: 1}).then(function (d) { toast(d.message, 'good'); RB.runs = d.runs || []; drawRbRuns(); }).catch(oops);
          }, true);
        };
        tools.appendChild(wipe);
      }
    }
    if (!runs.length) { host.appendChild(el('p', 'note', 'No backup sent yet.')); return; }
    host.appendChild(listTable(['When', 'File', 'Size', 'Where it went', 'Who', ''], runs, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.at));
      var f = el('td', 'mono small');
      f.appendChild(noI18n(el('span', '', r.file || '–')));
      if (r.file && r.system === false) { f.appendChild(document.createTextNode(' ')); f.appendChild(el('span', 'tag warn', 'without the system’s files')); }
      tr.appendChild(f);
      tr.appendChild(el('td', 'num', r.bytes ? rbBytes(r.bytes) : '–'));
      var w = el('td');
      if (r.error) w.appendChild(el('span', 'small bad', r.error));
      (r.targets || []).forEach(function (x) {
        var s = el('span', 'tag namepill ' + (x.ok ? 'ok' : 'crit'), (x.ok ? '✓ ' : '✗ ') + x.name);
        explain(s, x.ok ? (x.secs + ' s' + ((x.taken_away || []).length ? ' · taken away: ' + x.taken_away.join(', ') : '') + (x.warning ? ' · ' + x.warning : '')) : (x.error || ''));
        noI18n(s);
        w.appendChild(s);
        w.appendChild(document.createTextNode(' '));
      });
      tr.appendChild(w);
      tr.appendChild(noI18n(el('td', 'muted small', r.by || 'the schedule')));
      var a = el('td', 'rowtools');
      var del = iconButton('trash', 'Take it off the list');
      del.onclick = function () {
        api('backup', {action: 'runs_forget', at: r.at, file: r.file || ''}).then(function (d) { toast(d.message, 'good'); RB.runs = d.runs || []; drawRbRuns(); }).catch(oops);
      };
      a.appendChild(del);
      tr.appendChild(a);
      return tr;
    }, 'plain', {own: true}));
  }

  function rbPickKind() {
    modal('Where should the backups go?', function (body) {
      var g = el('div', 'rb-kinds');
      (RB.kinds || []).forEach(function (k) {
        var b = el('button', 'rb-kind-tile');
        b.type = 'button';
        var ic = el('span', 'rb-kind k-' + k.kind);
        ic.innerHTML = iconMarkup(RB_KIND_ICON[k.kind] || 'db', 20);
        b.appendChild(ic);
        b.appendChild(el('b', '', k.words));
        b.appendChild(el('span', 'small muted', RB_KIND_SAYS[k.kind] || ''));
        var need = {sftp: ['ssh', 'sftp'], scp: ['ssh', 'scp'], smb: ['smbclient']}[k.kind] || [];
        var missing = need.filter(function (x) { return !RB.tools[x]; });
        if (missing.length) b.appendChild(el('span', 'small bad', 'missing here: ' + missing.join(', ') + (k.kind === 'smb' ? ' (dnf install samba-client)' : ' (dnf install openssh-clients)')));
        b.onclick = function () { closeModal(); setTimeout(function () { rbEdit({kind: k.kind, enabled: 1, port: k.port}); }, 30); };
        g.appendChild(b);
      });
      body.appendChild(g);
    }, [{words: 'Close', close: true}], 'medium');
  }

  /* The editor of one destination. A new one is saved before a key is made for it. */
  function rbEdit(t) {
    t = t || {};
    var isNew = !t.id;
    var cur = {id: t.id};
    EDIT.cur = cur;
    EDIT.pin = EDIT.check = EDIT.paintHost = null;
    modal(isNew ? 'A new destination: ' + (t.kind_words || (RB.kinds.filter(function (k) { return k.kind === t.kind; })[0] || {}).words || t.kind) : t.name, function (body) {
      body.classList.add('rb-ed');
      var f = {};
      var sec = function (title, says) {
        var s = el('div', 'rb-sec');
        s.appendChild(el('h4', '', title));
        if (says) s.appendChild(el('p', 'small muted', says));
        var g = el('div', 'formgrid');
        s.appendChild(g);
        body.appendChild(s);
        return g;
      };
      var g0 = sec('What it is called', '');
      f.name = textBox(t.name || '', 'NAS in the server room');
      g0.appendChild(formField('Name', f.name));
      f.enabled = switchBox(t.enabled === undefined ? 1 : t.enabled);
      g0.appendChild(formField('Backups go here', f.enabled));
      var g1 = sec('Where', t.kind === 'folder' ? 'A whole path on this machine (an NFS or CIFS mount); root writes into it, never under the system’s own folders.' : '');
      if (t.kind === 'folder') {
        f.path = textBox(t.path || '', '/mnt/backup/fake-igd', 'mono');
        var fp = formField('The folder', f.path);
        fp.classList.add('wide');
        g1.appendChild(fp);
      } else {
        f.host = textBox(t.host || '', 'backup.example.com', 'mono');
        g1.appendChild(formField('The server', f.host));
        f.port = textBox(t.port || '', String({ftp: 21, ftps: t.implicit ? 990 : 21, sftp: 22, scp: 22, smb: 445}[t.kind] || ''), 'mono');
        g1.appendChild(formField('Port', f.port));
        if (t.kind === 'smb') {
          f.share = textBox(t.share || '', 'backup', 'mono');
          g1.appendChild(formField('The share', f.share));
          f.path = textBox(t.path || '', 'fake-igd\\nightly', 'mono');
          g1.appendChild(formField('The folder in it', f.path, 'Made if it is not there.'));
        } else {
          f.path = textBox(t.path || '', t.kind === 'ftp' || t.kind === 'ftps' ? 'fake-igd/backups' : '/home/backup/fake-igd', 'mono');
          g1.appendChild(formField('The folder there', f.path, 'Made if it is not there. Without / at the start: under the account’s home.'));
        }
      }
      if (t.kind !== 'folder') {
        var g2 = sec('Signing in', t.kind === 'sftp' || t.kind === 'scp' ? 'A key (below) or a password - or both.' : '');
        f.user = textBox(t.user || '', t.kind === 'smb' ? 'backup' : 'fake-igd-backup', 'mono');
        g2.appendChild(formField('Account', f.user));
        f.password = maskBox(t.password || '', t.has_password ? '' : '(none)', 'mono');
        g2.appendChild(formField('Password', f.password, t.has_password ? 'Kept. Type a new one to change it.' : ''));
        if (t.kind === 'smb') {
          f.domain = textBox(t.domain || '', 'CORP', 'mono');
          g2.appendChild(formField('Domain (workgroup)', f.domain));
          f.smb_encrypt = switchBox(t.smb_encrypt === undefined ? 1 : t.smb_encrypt);
          g2.appendChild(formField('SMB3 encryption required', f.smb_encrypt, 'Everything on the wire encrypted; a server that cannot is refused.'));
        }
        if (t.kind === 'ftp' || t.kind === 'ftps') {
          f.passive = switchBox(t.passive === undefined ? 1 : t.passive);
          g2.appendChild(formField('Passive mode', f.passive, 'The usual one, through firewalls and NAT.'));
        }
      }
      if (t.kind === 'ftps') rbFtpsBlock(body, t, f);
      if (t.kind === 'sftp' || t.kind === 'scp') rbSshBlock(body, t, f, cur);
      var out = el('div', 'rb-try-out');
      out.id = 'rb-try-out';
      body.appendChild(out);
      EDIT.form = f;
    }, [
      {words: 'Close', close: true},
      {words: 'Try it', icon: 'play', go: function (b) { rbTry(cur.id ? rbTarget(cur.id) || t : t, rbFormData(t.kind), b, true); }},
      {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
        busy(b, true);
        rbSaveForm(t.kind, cur).then(function () { busy(b, false); toast('saved', 'good'); closeModal(); loadRbackup(); })
          .catch(function (e) { busy(b, false); oops(e); });
      }}], 'large');
  }
  function rbTarget(id) { return (RB.targets || []).filter(function (x) { return x.id === id; })[0]; }
  function rbFormData(kind) {
    var f = EDIT.form || {};
    var v = function (k) { return f[k] ? (f[k]._get ? f[k]._get() : f[k].value) : undefined; };
    var d = {kind: kind};
    ['name', 'enabled', 'host', 'port', 'path', 'user', 'password', 'share', 'domain', 'smb_encrypt', 'passive', 'implicit', 'tls_check', 'pin', 'ssh_cert'].forEach(function (k) {
      var x = v(k);
      if (x !== undefined) d[k] = typeof x === 'string' ? x.trim() : x;
    });
    if (f.password) d.password = f.password.value;
    return d;
  }
  function rbSaveForm(kind, cur) {
    return api('backup', {action: 'save', id: cur.id || '', target: rbFormData(kind)}).then(function (x) {
      cur.id = x.target.id;
      var i = (RB.targets || []).map(function (t) { return t.id; }).indexOf(x.target.id);
      if (i >= 0) RB.targets[i] = x.target; else RB.targets.push(x.target);
      return x.target;
    });
  }
  function rbNeedSaved(kind, cur) {
    return cur.id ? Promise.resolve(rbTarget(cur.id)) : rbSaveForm(kind, cur);
  }
  function rbConfirm(title, words, yes, go, danger) {
    modalOver(function () { confirmThen(title, words, yes, go, danger); });
  }
  function rbCopyme(text, said) {
    var code = noI18n(el('code', 'copyme', text));
    explain(code, 'Click to copy.');
    code.onclick = function () { copyText(text, code, said || 'Copied'); };
    return code;
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
  function rbTryButton(t, cur) {
    var b = cmdButton('Try reaching it', 'pulse', 'primary');
    explain(b, 'Sign in, write a small file, find it in the list and take it away again - with what is typed above, saved or not.');
    b.onclick = function () { rbTry(cur.id ? (rbTarget(cur.id) || t) : t, rbFormData(t.kind), b, true); };
    return b;
  }
  function rbSshBlock(body, t, f, cur) {
    var s = el('div', 'rb-sec');
    s.appendChild(el('h4', '', 'The SSH key'));
    var P = rbPanel('A key is better than a password: made here, it never leaves this machine except when you download it, and the server holds only its <b>public</b> half - in <code>~/.ssh/authorized_keys</code> of the account.');
    if (!RB.tools['ssh-keygen']) {
      var miss = el('p', 'note warn', 'ssh-keygen is not on this machine, so a key cannot be made or read here: dnf install openssh-clients. A password still works.');
      P.box.insertBefore(miss, P.row);
    }
    var mk = cmdButton('Make a key', 'key', '');
    explain(mk, 'Make a fresh ed25519 pair here. The private half stays on this machine; the public half is shown below for you to put on the server. Any key already kept is replaced.');
    var own = cmdButton('Use my own', 'upload', '');
    explain(own, 'Use a private key you already have. Paste it whole, with its BEGIN and END lines; its public half is worked out here.');
    var dl = cmdButton('Download it', 'download', '');
    explain(dl, 'The private half as a file, for keeping somewhere safe. That it was downloaded, and by whom, is written into Events.');
    var fg = cmdButton('Forget it', 'forget', 'danger');
    explain(fg, 'Delete the private key from this machine. Unless the server takes a password instead, nothing here reaches it until a new key is made and put on it.');
    [mk, own, dl, fg].forEach(function (b) { P.row.appendChild(b); });
    P.row.appendChild(el('span', 'spacer'));
    P.row.appendChild(rbTryButton(t, cur));
    var state = {pub: t.pub, has: !!t.has_key};
    var paint = function () {
      clear(P.below);
      dl.disabled = fg.disabled = !state.has;
      mk.disabled = own.disabled = !RB.tools['ssh-keygen'];
      if (!state.has || !state.pub) { P.below.appendChild(el('p', 'btnhelp', 'No key yet — make one, or let it sign in with a password.')); return; }
      P.below.appendChild(el('p', 'btnhelp', 'The public half. Click it to copy.'));
      P.below.appendChild(rbCopyme(state.pub, 'the public key is on the clipboard'));
      var u = (f.user && f.user.value) || 'the account';
      P.below.appendChild(el('p', 'btnhelp', 'On the server, as ' + u + ':'));
      P.below.appendChild(rbCopyme("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '" + state.pub + "' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"));
    };
    mk.onclick = function () {
      rbConfirm('Make a key for ' + htmlText((f.name && f.name.value) || t.name || 'this destination'),
        'A fresh ed25519 pair is made here. The private half stays on this machine and the public half is shown for you to put on the server.' + (state.has ? '<br><br><b>The key kept now is replaced</b>, so until the new public half is on the server, backups cannot sign in there.' : ''),
        'Make one', function () {
          rbNeedSaved(t.kind, cur).then(function () { return api('backup', {action: 'keygen', id: cur.id}); })
            .then(function (x) { state.pub = x.pub; state.has = true; paint(); toast('a new key was made — put the public half on the server', 'good'); })
            .catch(oops);
        }, false);
    };
    own.onclick = function () {
      modalOver(function () {
        modal('Use my own key', function (body2) {
          var p = el('p', 'note');
          p.innerHTML = 'An OpenSSH private key, whole, including its <code>BEGIN</code> and <code>END</code> lines. It is kept in this machine’s database and never shown back. Its public half is worked out here.';
          body2.appendChild(p);
          var area = el('textarea', 'mono');
          area.rows = 11;
          area.id = 'rb-paste-area';
          area.spellcheck = false;
          area.placeholder = '-----BEGIN OPENSSH PRIVATE KEY-----';
          body2.appendChild(area);
          var pp = maskBox('', '', 'mono');
          pp.id = 'rb-paste-pp';
          body2.appendChild(formField('Its passphrase, if it has one', pp));
        }, [{words: 'Cancel', close: true},
            {words: 'Keep this key', cls: 'primary', close: true, go: function () {
              var key = $('rb-paste-area').value, pass = $('rb-paste-pp').value;
              rbNeedSaved(t.kind, cur).then(function () { return api('backup', {action: 'key_paste', id: cur.id, key: key, passphrase: pass}); })
                .then(function (x) { state.pub = x.pub; state.has = true; paint(); toast('the key was stored', 'good'); })
                .catch(oops);
            }}]);
      });
    };
    dl.onclick = function () {
      rbConfirm('Download the private key', 'The private half leaves this machine as a file. Anybody holding it can sign in to the server as <code>' + htmlText((f.user && f.user.value) || 'that account') + '</code>. That it was downloaded, and by whom, is written into Events.', 'Download it', function () {
        api('backup', {action: 'key_download', id: cur.id}).then(function (x) {
          var a = document.createElement('a');
          a.href = URL.createObjectURL(new Blob([x.pem], {type: 'application/octet-stream'}));
          a.download = x.file;
          document.body.appendChild(a); a.click(); a.remove();
        }).catch(oops);
      }, false);
    };
    fg.onclick = function () {
      rbConfirm('Forget the key', 'The private key is deleted from this machine. Unless the server takes a password instead, backups will not reach it until a new key is made and put on it.', 'Forget it', function () {
        api('backup', {action: 'key_forget', id: cur.id}).then(function () { state.has = false; state.pub = ''; paint(); toast('the key is gone'); }).catch(oops);
      });
    };
    paint();
    s.appendChild(P.box);
    f.ssh_cert = el('textarea', 'mono rb-area small');
    f.ssh_cert.value = t.ssh_cert || '';
    f.ssh_cert.placeholder = 'ssh-ed25519-cert-v01@openssh.com AAAA…';
    var cf = formField('SSH certificate of the key (only if the server wants one)', f.ssh_cert);
    cf.style.marginTop = '12px';
    s.appendChild(cf);
    body.appendChild(s);
    var h = el('div', 'rb-sec');
    h.appendChild(el('h4', '', 'The server’s host key'));
    var H = rbPanel('The key the server proves itself with. Trusted once, after comparing its fingerprint with the server’s own (<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on it); a server answering with any other is refused - somebody in between, or the server reinstalled.');
    var hf = cmdButton('Forget it', 'forget', 'danger');
    H.row.appendChild(hf);
    H.row.appendChild(el('span', 'spacer'));
    H.row.appendChild(rbTryButton(t, cur));
    var paintHost = function (fps) {
      clear(H.below);
      hf.disabled = !(fps && fps.length);
      if (fps && fps.length) {
        H.below.appendChild(el('p', 'btnhelp ro', 'Trusted. Click to copy.'));
        fps.forEach(function (x) { H.below.appendChild(rbCopyme(x)); });
      } else {
        H.below.appendChild(el('p', 'btnhelp', 'Not trusted yet — Try reaching it shows the fingerprint to trust.'));
      }
    };
    hf.onclick = function () {
      rbConfirm('Forget the host key', 'Backups stop going there until it is trusted again - and its saved password is forgotten with it, to be typed again.', 'Forget it', function () {
        api('backup', {action: 'hostkey_forget', id: cur.id}).then(function (x) {
          paintHost([]);
          if (x && x.message) toast(x.message, 'good');
          if (EDIT.form && EDIT.form.password) { EDIT.form.password.value = ''; EDIT.form.password.placeholder = '(none)'; }
        }).catch(oops);
      });
    };
    paintHost(t.hostkey_fp);
    EDIT.paintHost = paintHost;
    h.appendChild(H.box);
    body.appendChild(h);
  }
  function rbFtpsBlock(body, t, f) {
    var s = el('div', 'rb-sec');
    s.appendChild(el('h4', '', 'TLS'));
    var g = el('div', 'formgrid');
    f.implicit = selectBox([['0', 'explicit - AUTH TLS on port 21'], ['1', 'implicit - TLS from the start, port 990']], t.implicit ? '1' : '0');
    f.implicit._get = function () { return f.implicit.value === '1' ? 1 : 0; };
    f.implicit.onchange = function () { if (f.port && (!f.port.value || f.port.value === '21' || f.port.value === '990')) f.port.value = f.implicit.value === '1' ? '990' : '21'; };
    g.appendChild(formField('TLS', f.implicit));
    f.tls_check = selectBox([['system', 'against the authorities this machine trusts'], ['pin', 'pinned: exactly this certificate'], ['none', 'not checked (not safe)']], t.tls_check || 'system');
    g.appendChild(formField('The server’s certificate is checked', f.tls_check));
    s.appendChild(g);
    f.pin = textBox(t.pin || '', '64 hex digits - Try reaching it shows the server’s', 'mono');
    var pinf = formField('Pinned SHA-256 fingerprint', f.pin);
    s.appendChild(pinf);
    var show = function () { pinf.hidden = f.tls_check.value !== 'pin'; };
    f.tls_check.onchange = show;
    show();
    EDIT.pin = f.pin;
    EDIT.check = f.tls_check;
    body.appendChild(s);
  }
  function rbTry(t, data, button, inEditor) {
    if (button) busy(button, true);
    var ask = {action: 'try', id: t.id || ''};
    if (data) ask.target = data;
    api('backup', ask).then(function (x) {
      if (button) busy(button, false);
      var show = function (host) {
        clear(host);
        if (x.hostkey_needed) {
          host.appendChild(el('p', 'note warn', 'The server shows this host key. Compare it with the server’s own fingerprint before you trust it:'));
          (x.fingerprints || []).forEach(function (fp) { host.appendChild(noI18n(el('div', 'mono small', fp))); });
          var tb = cmdButton('Trust it', 'check', 'small primary');
          tb.onclick = function () {
            var save = (inEditor && EDIT.form) ? rbSaveForm(t.kind, EDIT.cur || {id: t.id}) : Promise.resolve(t);
            save.then(function (saved) {
              return api('backup', {action: 'hostkey_trust', id: saved.id, hostkey: x.hostkey}).then(function (y) {
                toast(y.message || 'trusted', 'good');
                if (/password/.test(y.message || '') && EDIT.form && EDIT.form.password) { EDIT.form.password.value = ''; EDIT.form.password.placeholder = '(none)'; }
                if (EDIT.paintHost) EDIT.paintHost(y.fingerprints);
                t.id = saved.id;
                rbTry(saved, inEditor ? rbFormData(t.kind) : null, button, inEditor);
              });
            }).catch(oops);
          };
          host.appendChild(tb);
          return;
        }
        var box = el('div', 'note ' + (x.works ? 'good' : 'bad'));
        box.appendChild(el('b', '', x.works ? 'It works (' + x.secs + ' s)' : 'It does not work'));
        var ul = el('ul', 'rb-steps');
        (x.steps || []).forEach(function (s) { ul.appendChild(el('li', '', '✓ ' + s)); });
        if (x.error) ul.appendChild(noI18n(el('li', 'bad', '✗ ' + x.error)));
        box.appendChild(ul);
        var sc = x.server_cert;
        if (sc && sc.fingerprint) {
          var p = el('div', 'small');
          p.appendChild(el('span', '', 'The server’s certificate: '));
          p.appendChild(noI18n(el('span', 'mono', 'SHA-256 ' + sc.fingerprint)));
          box.appendChild(p);
          if (inEditor && EDIT.pin) {
            var pin = cmdButton('Pin this certificate', 'pin', 'small');
            pin.onclick = function () { EDIT.check.value = 'pin'; EDIT.check.onchange(); EDIT.pin.value = sc.fingerprint; toast('pinned - Save to keep it', 'good'); };
            box.appendChild(pin);
          }
        }
        host.appendChild(box);
        if (inEditor) host.appendChild(hideBar(function () { clear(host); }));
      };
      var host = inEditor ? $('rb-try-out') : null;
      if (host) show(host);
      else modal('Trying ' + (t.name || ''), function (body) { var hh = el('div'); body.appendChild(hh); show(hh); }, [{words: 'Close', close: true}], 'medium');
      if (!inEditor) loadRbackup();
    }).catch(function (e) { if (button) busy(button, false); oops(e); });
  }
  function rbListThere(t) {
    modal('Backups at ' + t.name, function (body) {
      var host = el('div');
      host.appendChild(el('p', 'center muted', 'Asking…'));
      body.appendChild(host);
      api('backup', {action: 'list', id: t.id}).then(function (x) {
        clear(host);
        var files = x.files || [];
        if (!files.length) { host.appendChild(el('p', 'note', 'No backup of fake-igd there.')); return; }
        host.appendChild(listTable(['Made', 'Machine', 'Size', ''], files, function (fl) {
          var tr = el('tr');
          var w = el('td');
          w.appendChild(el('div', '', new Date(fl.when * 1000).toLocaleString(numLang())));
          w.appendChild(noI18n(el('div', 'mono small muted', fl.name)));
          tr.appendChild(w);
          var n = el('td');
          n.appendChild(noI18n(el('span', '', fl.node)));
          if (fl.mine) { n.appendChild(document.createTextNode(' ')); n.appendChild(el('span', 'tag info', 'this machine')); }
          tr.appendChild(n);
          var sz = el('td', 'num');
          sz.textContent = rbBytes(fl.bytes);
          if (!fl.encrypted) { sz.appendChild(document.createTextNode(' ')); sz.appendChild(el('span', 'tag bad', 'not locked')); }
          tr.appendChild(sz);
          var a = el('td', 'rowtools');
          var dl = iconButton('download', 'Download it');
          dl.onclick = function () {
            busy(dl, true);
            api('backup', {action: 'download', id: t.id, name: fl.name}).then(function (j) {
              toast('it is being fetched - the download starts when it is here', 'good');
              rbWatch(function (jj) {
                busy(dl, false);
                if (!jj.result || !jj.result.ready) return;
                api('backup', {action: 'download_get', ready: jj.result.ready}).then(function (y) { saveBytes(y.name, y.data); }).catch(oops);
              });
            }).catch(function (e) { busy(dl, false); oops(e); });
          };
          a.appendChild(dl);
          var pb = iconButton('undo', 'Put this back…');
          pb.onclick = function () { rbPutBackConfirm({id: t.id, name: fl.name, encrypted: fl.encrypted, when: fl.when, node: fl.node}); };
          a.appendChild(pb);
          var del = iconButton('trash', 'Delete it there');
          del.onclick = function () {
            confirmThen('Delete ' + htmlText(fl.name) + '?', 'It is deleted at ' + htmlText(t.name) + ', with its checksum and its RESTORE.md.', 'Delete it', function () {
              api('backup', {action: 'delete_file', id: t.id, name: fl.name}).then(function () { toast('deleted', 'good'); rbListThere(t); }).catch(oops);
            });
          };
          a.appendChild(del);
          tr.appendChild(a);
          return tr;
        }, 'plain', {own: true}));
      }).catch(function (e) { clear(host); host.appendChild(el('p', 'note bad', String(e.message || e))); });
    }, [{words: 'Close', close: true}], 'large');
  }
  function rbPutBackConfirm(what) {
    var pwBox = null;
    modal('Put this backup back?', function (body) {
      var facts = [];
      if (what.when) facts.push(['Made', new Date(what.when * 1000).toLocaleString(numLang())]);
      if (what.node) facts.push(['On', what.node]);
      if (what.manifest) {
        var m = what.manifest;
        facts = [['Made', m.made_words], ['On', m.node + ' (' + (m.host || '') + ')'], ['fake-igd', m.version], ['The system’s files', m.system ? 'in it' : 'not in it']];
      }
      if (what.said) body.appendChild(el('p', 'note warn', what.said));
      if (facts.length) body.appendChild(peekFacts(facts));
      body.appendChild(el('p', 'note warn', 'Everything in the database is replaced with what the backup holds - accounts, settings, events, the destinations of the backups, and who is signed in: you sign in again afterwards, with an account the backup has. config.json is put back too (this machine’s paths and port stay), and root puts back avahi-daemon.conf, nginx’s fake-igd.conf, the certificate and key, then nginx’s allow list, the firewall and fake-igd.service. A copy of the database as it is now is made first (Settings → The database).'));
      pwBox = maskBox('', what.encrypted === false ? '(not locked)' : 'the password of the backups - empty: the one set here', 'mono');
      body.appendChild(formField('Its password', pwBox, 'Only when it was locked with another password than the one set here now.'));
    }, [{words: 'No, leave it', close: true},
        {words: 'Put it back', cls: 'danger', icon: 'undo', close: true, go: function () {
          var ask = {action: 'restore', password: pwBox.value};
          if (what.upload) { ask.upload = what.upload; ask.file = what.file; } else { ask.id = what.id; ask.name = what.name; }
          api('backup', ask).then(function (x) { toast(x.message, 'good'); rbRestoreWatch(); }).catch(oops);
        }}], 'medium');
  }
  function rbRestoreWatch() {
    modal('Putting the backup back', function (body) {
      var bar = el('div', 'going wide');
      bar.innerHTML = '<div class="bar"><span id="rbr-fill"></span></div><div class="says" id="rbr-says"></div>';
      body.appendChild(bar);
    }, [{words: 'Close', close: true}], 'medium');
    var empty = 0;
    var step = function () {
      /* Not after its popup is closed, nor for ever on nothing (otp 1.0.206). */
      if (!$('rbr-fill')) return;
      api('backup-job').then(function (d) {
        var j = d.job || {};
        if (!j.running && !j.what && !j.result && !j.error && ++empty > 60) {
          if ($('rbr-says')) $('rbr-says').textContent = 'No word of it for a minute - the service may have started again. Load the page again to see what is here now.';
          return;
        }
        if ($('rbr-fill')) $('rbr-fill').style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
        if ($('rbr-says')) $('rbr-says').textContent = (j.what || '') + (j.says ? ' — ' + j.says : '');
        if (j.running) { setTimeout(step, 1000); return; }
        if (!j.what && !j.result && !j.error) { setTimeout(step, 1000); return; }
        if (j.error) { if ($('rbr-says')) $('rbr-says').textContent = j.error; toast('putting it back failed: ' + j.error, 'bad'); return; }
        var r = j.result || {};
        var said = $('rbr-says');
        if (said) {
          clear(said);
          said.appendChild(el('div', '', 'Put back.'));
          (r.said || []).forEach(function (x) { said.appendChild(noI18n(el('div', 'small', x))); });
          if (r.safety) said.appendChild(el('div', 'small muted', 'What was here is kept as ' + r.safety));
        }
        toast('the backup is back', 'good');
      }).catch(function (e) {
        if (/signed in|401/i.test(String(e && e.message || e))) {
          if ($('rbr-says')) $('rbr-says').textContent = 'Put back. Sign in again - with an account the backup has.';
          setTimeout(function () { location.reload(); }, 3500);
          return;
        }
        setTimeout(step, 2000);
      });
    };
    setTimeout(step, 500);
  }
  function rbPutBackFile() {
    var file = el('input');
    file.type = 'file';
    file.accept = '.enc,.gz';
    file.onchange = function () {
      var fl = file.files[0];
      if (!fl) return;
      toast('sending ' + fl.name + '…', 'good');
      var rd = new FileReader();
      rd.onload = function () {
        var b64 = String(rd.result).split(',')[1] || '';
        api('backup-restore', {data: b64, name: fl.name}).then(function (d) {
          rbPutBackConfirm({upload: d.upload, file: fl.name, encrypted: d.locked, manifest: d.manifest, said: d.said});
        }).catch(oops);
      };
      rd.readAsDataURL(fl);
    };
    file.click();
  }
  PANE_TICK.backup = function () { };
}());
