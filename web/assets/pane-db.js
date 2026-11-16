/* pane-db.js - Settings → The database (otp's loadDb, drawDisk, drawCounts, keptTable,
   the putting back - for fake-igd's one SQLite file). */
(function () {
  'use strict';
  var DB = {d: null};
  var TABLE_SAID = {users: 'accounts', sessions: 'sign-ins', fails: 'wrong passwords counted',
                    events: 'events', meta: 'notes of its own', mailq: 'the outgoing mail', sqlite_sequence: 'SQLite’s own counters'};
  var KIND_SAID = {copy: 'the file on this machine', 'before-restore': 'the file on this machine, before a restore', upload: 'the file on this machine', sqlite: 'a copy of the file'};
  var WATCH = null;

  function loadDb() {
    api('db').then(function (d) {
      DB.d = d;
      $('db-size').textContent = bytes(d.size) + ' · ' + d.where;
      drawEngine(d);
      drawDisk(d);
      drawCounts(d);
      keptTable($('db-backups'), d.copies || [], {
        kind: 'copy', head: 'Copies kept (' + d.keep + ' at most)',
        where: 'They are files on this machine, under ' + d.backup_dir + ', each with the key '
          + 'that opens its secrets beside it. Copy them off it if they are to survive the machine.'
      });
      keptTable($('db-dumps'), d.dumps || [], {
        kind: 'dump', head: 'Dumps kept (' + d.keep + ' at most)',
        where: 'They are files on this machine, under ' + d.dump_dir + ', each with the key '
          + 'that opens its secrets beside it. Copy them off it if they are to survive the machine.'
      });
      dumpCard(d);
      drawErasable(d.erasable || {});
      explainWhatWasDrawn($('pane-db'));
    }).catch(oops);
  }
  PANE_LOAD.db = loadDb;

  /* ---- which database everything is kept in -------------------------------- */
  function drawEngine(d) {
    $('db-engine-file').textContent = d.config_file || 'the config file';
    $('db-engine-now').textContent = 'the file on this machine · ' + d.where;
    var host = $('db-engine-says');
    clear(host);
    var c = d.counts || {};
    host.appendChild(peekFacts([
      ['In use now', d.version],
      ['Where', noI18n(el('span', 'mono', d.where))],
      ['Holding', num(c.users || 0) + ' account(s), ' + num(c.events || 0) + ' event(s)'],
      ['Room it takes', bytes(d.size || 0)]
    ]));
  }
  function dumpCard(d) {
    var says = $('db-dump-says');
    clear(says);
    var info = d.dump || {};
    $('db-dump-now').textContent = info.words || '';
    var line = el('p', 'note good');
    line.appendChild(document.createTextNode(d.daily ? 'Tonight’s will be ' : 'None is made tonight - the copy of every day is off above; a dump made now will be '));
    line.appendChild(el('b', '', info.words || 'a dump'));
    if (info.suffix) {
      line.appendChild(document.createTextNode(', written as '));
      line.appendChild(noI18n(el('code', '', info.suffix)));
    }
    line.appendChild(document.createTextNode('.'));
    says.appendChild(line);
  }

  /* ---- a job: its bar (otp's db-going) ---------------------------------------- */
  function dbBusyButtons(on) {
    ['db-backup', 'db-dump-make', 'db-optimize', 'db-check', 'db-prune', 'db-tidy',
     'db-restore', 'dump-restore', 'erase-go'].forEach(function (id) {
      var b = $(id);
      if (b) b.disabled = on || (id === 'erase-go' && !erasePicked().length)
        || ((id === 'db-restore' || id === 'dump-restore') && !b._held);
    });
  }
  function going(words, pct) {
    var box = $('db-going');
    box.hidden = false;
    $('db-going-fill').style.width = pct + '%';
    $('db-going-says').textContent = words;
  }
  /* A job of the database: the bar runs while it is asked, and says how it ended. */
  function job(what, body, done) {
    if (WATCH) return;
    WATCH = true;
    dbBusyButtons(true);
    going(what + '…', 5);
    var t0 = Date.now();
    var tick = setInterval(function () { going(what + '… (' + Math.round((Date.now() - t0) / 1000) + ' s)', Math.min(90, 5 + (Date.now() - t0) / 400)); }, 500);
    return api('db', body).then(function (x) {
      clearInterval(tick); WATCH = null; dbBusyButtons(false);
      going('done' + (x.before !== undefined ? ': ' + bytes(x.before) + ' → ' + bytes(x.after) : '')
        + (x.copy ? ' · a copy made first: ' + x.copy : ''), 100);
      if (done) done(x);
      loadDb();
    }).catch(function (e) {
      clearInterval(tick); WATCH = null; dbBusyButtons(false);
      going(String((e && e.message) || e), 100);
      oops(e);
    });
  }

  /* ---- the disk under it ---------------------------------------------------- */
  function drawDisk(d) {
    var host = $('db-disk');
    clear(host);
    var disk = d.disk || {};
    var grew = d.growth || {};
    if (!disk.total) {
      host.appendChild(el('p', 'note', 'The disk this is on could not be measured.'));
      return;
    }
    var share = Number(disk.share || 0);
    var line = el('div', 'disk-bar ' + (share >= 92 ? 'crit' : (share >= 80 ? 'warn' : 'ok')));
    var fill = el('span');
    fill.style.width = Math.max(1, Math.min(100, share)) + '%';
    line.appendChild(fill);
    host.appendChild(line);
    var says = el('p', 'note');
    says.appendChild(el('b', '', bytes(disk.free)));
    says.appendChild(document.createTextNode(' free of ' + bytes(disk.total) + ' on '));
    says.appendChild(noI18n(el('span', 'mono', disk.where || '')));
    says.appendChild(document.createTextNode(' — '));
    says.appendChild(el('span', '', share + '% of it is used'));
    if (grew.a_day) {
      says.appendChild(document.createTextNode(', and this database has been growing '));
      says.appendChild(el('b', '', bytes(grew.a_day)));
      says.appendChild(document.createTextNode(' a day over the last ' + grew.over_days + ' day(s).'));
    } else {
      says.appendChild(document.createTextNode('. How fast it is growing is not known yet: the size is noted once a day, and two are needed.'));
    }
    host.appendChild(says);
    host.appendChild(el('p', 'note', 'That disk holds ' + (disk.holds || '') + '.'));
    if (disk.days_left !== null && disk.days_left !== undefined) {
      host.appendChild(el('p', 'note ' + (disk.days_left < 45 ? 'bad' : ''), disk.days_left > 3650
        ? 'At that rate the disk has years left.'
        : 'At that rate the disk has about ' + num(disk.days_left) + ' day(s) left. Forgetting old records, under the keep-for number above, is what shortens it.'));
    }
    var parts = d.parts || [];
    if (parts.length) {
      var wrap = listTable(['File', 'What it is', {words: 'Size', cls: 'num'}], parts, function (one) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono', one.name)));
        tr.appendChild(el('td', 'muted', one.what));
        tr.appendChild(el('td', 'num', bytes(one.bytes)));
        return tr;
      }, 'plain', {own: true});
      wrap.style.marginTop = '10px';
      host.appendChild(wrap);
    }
  }

  /* ---- what is in it -------------------------------------------------------- */
  function drawCounts(d) {
    var host = $('db-counts');
    clear(host);
    var rows = (d.tables || []).slice().sort(function (a, b) {
      return (b.bytes || 0) - (a.bytes || 0) || (b.rows || 0) - (a.rows || 0);
    });
    var known = rows.some(function (t) { return t.bytes !== null && t.bytes !== undefined; });
    host.appendChild(listTable(['What', 'Table', {words: 'Rows', cls: 'num'}]
        .concat(known ? [{words: 'Size', cls: 'num'}] : []), rows, function (t) {
      var tr = el('tr');
      tr.appendChild(el('td', '', TABLE_SAID[t.table] || t.table));
      tr.appendChild(noI18n(el('td', 'mono muted small', t.table)));
      tr.appendChild(el('td', 'num', t.rows === null ? '–' : num(t.rows)));
      if (known) tr.appendChild(el('td', 'num', t.bytes === null || t.bytes === undefined ? '–' : bytes(t.bytes)));
      return tr;
    }, 'plain', {own: true}));
    var key = el('p', 'note ' + (d.key_there ? '' : 'bad'));
    key.appendChild(document.createTextNode(d.key_there ? 'The key that opens its secrets: ' : 'The key that opens its secrets is not made yet (it is made with the first secret saved): '));
    key.appendChild(noI18n(el('span', 'mono', d.key)));
    host.appendChild(key);
    if (d.free) {
      host.appendChild(el('p', 'btnhelp', bytes(d.free) + ' free inside it, which SQLite uses again; Give the disk back hands it to the operating system.'));
    }
  }

  /* ---- the two lists of files kept beside it --------------------------------- */
  function keptTable(into, rows, opts) {
    clear(into);
    if (!into || !rows || !rows.length) return;
    var dump = opts.kind === 'dump';
    into.appendChild(el('h4', '', opts.head));
    into.appendChild(listTable(['Name', dump ? 'What it is' : 'Taken off', {words: 'Size', cls: 'num'},
                                'Made', 'Key beside it', {words: '', cls: 'act'}], rows, function (b) {
      var line = el('tr');
      line.appendChild(noI18n(el('td', 'mono', b.name)));
      line.appendChild(el('td', b.kind === 'before-restore' ? 'muted' : '', KIND_SAID[b.kind] || b.kind));
      line.appendChild(el('td', 'num', bytes(b.bytes)));
      line.appendChild(stampCell(b.at));
      line.appendChild(el('td', b.key ? 'good' : 'bad', b.key ? 'yes' : 'no'));
      var act = el('td', 'rowtools');
      if (ADMIN) {
        var take = cmdButton('Download', 'down', 'small');
        explain(take, dump
          ? 'Save this dump to the machine you are sitting at - with the key that opens its secrets, locked with a passphrase you give, or without it.'
          : 'Save this copy to the machine you are sitting at - with the key that opens its secrets, locked with a passphrase you give, or without it.');
        take.onclick = function () { dbDownloadAsk({name: b.name, kind: dump ? 'dump' : '', key: b.key}); };
        act.appendChild(take);
        var back = cmdButton('Restore', 'undo', 'small danger');
        explain(back, 'Put <b>this</b> one back, without downloading it and uploading it again: everything in the live database is replaced by what is in this file. You are shown what is in it and asked first, and a copy of what is being replaced is made before anything changes.');
        back.onclick = function () { restoreKept(b, opts.kind); };
        act.appendChild(back);
        var gone = cmdButton('Delete', 'trash', 'small danger');
        explain(gone, 'Delete this file, and the key beside it, from the server. The live database is not touched.');
        gone.onclick = function () {
          confirmThen(dump ? 'Delete this dump?' : 'Delete this copy?', 'The file ' + htmlText(b.name)
            + ' and the key beside it are deleted from this machine. The live database is not touched, and the others stay where they are.', 'Delete it', function () {
              api('db', {action: 'delete', name: b.name, kind: opts.kind}).then(function (x) { toast(x.message, 'good'); loadDb(); }).catch(oops);
            });
        };
        act.appendChild(gone);
      }
      line.appendChild(act);
      return line;
    }, 'plain', {own: true}));
    into.appendChild(el('p', 'btnhelp', opts.where));
  }

  /* ---- erasing what was collected ----------------------------------------- */
  function drawErasable(d) {
    var host = $('erase-list');
    var was = {};
    Array.prototype.forEach.call(host.querySelectorAll('input[type=checkbox]'), function (b) { was[b.dataset.group] = b.checked; });
    clear(host);
    $('erase-size').textContent = bytes(d.bytes || 0) + ' in all';
    (d.groups || []).forEach(function (g) {
      var row = el('label', 'erase-one' + (g.rows ? '' : ' empty'));
      var box = document.createElement('input');
      box.type = 'checkbox';
      box.dataset.group = g.key;
      box.checked = !!was[g.key];
      box.disabled = !ADMIN || !g.rows;
      box.onchange = markErase;
      row.appendChild(box);
      var words = el('div', 'erase-words');
      var top = el('div', 'erase-top');
      top.appendChild(el('span', 'erase-name', g.name));
      top.appendChild(el('span', 'tag ' + (g.rows ? 'info' : 'dim'), g.rows ? num(g.rows) + ' row(s)' : 'already empty'));
      words.appendChild(top);
      words.appendChild(el('div', 'erase-says', g.says));
      row.appendChild(words);
      host.appendChild(row);
    });
    markErase();
  }
  function erasePicked() {
    return Array.prototype.filter.call(document.querySelectorAll('#erase-list input[type=checkbox]'),
      function (b) { return b.checked; }).map(function (b) { return b.dataset.group; });
  }
  function markErase() {
    var picked = erasePicked();
    var go = $('erase-go');
    go.disabled = !ADMIN || !picked.length || !!WATCH;
    setButtonIcon(go, 'forget', picked.length ? 'Erase ' + picked.length + ' of these…' : 'Erase what is ticked…');
  }
  $('erase-go').onclick = function () {
    var picked = erasePicked();
    if (!picked.length) return;
    var names = Array.prototype.filter.call(document.querySelectorAll('#erase-list input[type=checkbox]'),
      function (b) { return b.checked; }).map(function (b) {
        return b.closest('.erase-one').querySelector('.erase-name').textContent;
      });
    modal(picked.length === 1 ? 'Erase this?' : 'Erase these ' + picked.length + '?', function (body) {
      body.appendChild(el('p', 'note', 'This erases, for good:'));
      var ul = el('ul', 'ask-list');
      names.forEach(function (n) { ul.appendChild(el('li', '', n)); });
      body.appendChild(ul);
      body.appendChild(el('p', 'note', 'The accounts, the destinations of the backups and every setting are not touched.'));
      body.appendChild(el('p', 'muted', 'A copy of the database is made first, so this can be undone by restoring it.'));
    }, [{words: 'No, leave it', close: true}, {words: 'Erase it', cls: 'danger', icon: 'forget', close: true, go: function () {
      job('Erasing ' + names.join(', '), {action: 'erase', groups: picked, tidy: $('erase-tidy').checked}, function (x) {
        toast(x.message, 'good');
      });
    }}], true);
  };

  /* ---- a file to the machine you sit at -------------------------------------- */
  function saveBytes(name, b64) {
    var raw = atob(b64), arr = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    var a = el('a');
    a.href = URL.createObjectURL(new Blob([arr], {type: 'application/octet-stream'}));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function dbDownload(o, phrase, button) {
    if (button) busy(button, true);
    if (!o.name) toast('it is being made; the download starts when it is ready', 'good');
    var body = {action: 'download', name: o.name || '', kind: o.kind || ''};
    if (phrase !== undefined) body.passphrase = phrase;
    return api('db', body).then(function (x) {
      saveBytes(x.name, x.data);
      toast(x.name + (phrase !== undefined ? ' - keep the passphrase apart from the file' : ' · ' + bytes(x.bytes)), 'good');
      return x;
    }).catch(oops).then(function (x) { if (button) busy(button, false); return x; });
  }
  /* otp's dbDownloadAsk: with the key, locked with a passphrase - one file that is all of it - or without it. */
  function dbDownloadAsk(o) {
    var what = o.kind === 'dump' ? 'dump' : 'copy';
    var st = {with_: true};
    modal(o.name ? 'Download ' + o.name : (what === 'dump' ? 'Download a dump made now' : 'Download a copy made now'), function (body) {
      var seg = el('div', 'seg');
      var withB = el('button', 'on', 'With the key'), noB = el('button', '', 'Without the key');
      withB.type = noB.type = 'button';
      seg.appendChild(withB); seg.appendChild(noB);
      body.appendChild(seg);
      var withBox = el('div');
      withBox.appendChild(el('p', 'note', 'One file that is all of it: the ' + what + ' and the key that opens its secrets, locked with the passphrase below. Put back here or on another machine (Put a ' + what + ' back), the passphrase opens the key again. Lost, the key in the file is lost with it - it is not kept anywhere.'));
      var p1 = secretBox('', '10 characters at least', 'mono');
      var p2 = secretBox('', 'the same again', 'mono');
      p1.id = 'dbk-p1'; p2.id = 'dbk-p2';
      var g = el('div', 'formgrid');
      g.appendChild(formField('Passphrase', p1));
      g.appendChild(formField('The passphrase again', p2));
      withBox.appendChild(g);
      body.appendChild(withBox);
      var noBox = el('div');
      noBox.hidden = true;
      noBox.appendChild(el('p', 'note warn', 'The ' + what + ' alone opens no secret on another machine: the key is the .key file beside it in /var/lib/fake-igd/' + (what === 'dump' ? 'dumps' : 'backups') + ' (or /var/lib/fake-igd/secrets.key). Keep the two together.'));
      body.appendChild(noBox);
      withB.onclick = function () { st.with_ = true; withB.classList.add('on'); noB.classList.remove('on'); withBox.hidden = false; noBox.hidden = true; };
      noB.onclick = function () { st.with_ = false; noB.classList.add('on'); withB.classList.remove('on'); withBox.hidden = true; noBox.hidden = false; };
      if (o.name && !o.key) { withB.disabled = true; withB.title = 'There is no key beside this one'; noB.onclick(); }
    }, [
      {words: 'Cancel', close: true},
      {words: 'Download', cls: 'primary', icon: 'down', go: function (button) {
        if (!st.with_) { closeModal(); dbDownload(o); return; }
        var a = $('dbk-p1').value, b2 = $('dbk-p2').value;
        if (a.length < 10) { toast('a passphrase of 10 characters at least', 'bad'); return; }
        if (a !== b2) { toast('the two passphrases are not the same', 'bad'); return; }
        dbDownload(o, a, button).then(function (x) { if (x) closeModal(); });
      }}]);
  }
  function dbAskPassphrase(d, fileName) {
    modal('The key in ' + fileName, function (body) {
      body.appendChild(el('p', 'note', 'This file holds the database and the key that opens its secrets, locked with a passphrase. Give it, and both are put back.'));
      var p = secretBox('', '', 'mono');
      p.id = 'dbk-open';
      body.appendChild(formField('Passphrase', p));
      setTimeout(function () { p.focus(); }, 50);
    }, [
      {words: 'Cancel', close: true},
      {words: 'Open it', cls: 'primary', icon: 'key', go: function (button) {
        var pass = $('dbk-open').value;
        busy(button, true);
        api('db', {action: 'restore_upload', upload: d.upload, passphrase: pass, check: true}).then(function (x) {
          closeModal();
          setTimeout(function () {
            askBeforeRestoring(x.says, fileName + ' (with its key)', function () {
              return api('db', {action: 'restore_upload', upload: d.upload, passphrase: pass, file: fileName});
            });
          }, 30);
        }).catch(oops).then(function () { busy(button, false); });
      }}]);
  }

  /* ---- putting one back -------------------------------------------------------- */
  function restoreKept(b, kind) {
    api('db', {action: 'restore_kept', name: b.name, kind: kind, check: true}).then(function (d) {
      askBeforeRestoring(d.says, b.name, function () { return api('db', {action: 'restore_kept', name: b.name, kind: kind}); });
    }).catch(oops);
  }
  function askBeforeRestoring(says, what, go) {
    var n = (says && says.counts) || {};
    modal('Put this database back?', function (body) {
      body.appendChild(peekFacts([
        ['File', noI18n(el('span', 'mono', String(what)))], ['What it is', KIND_SAID[says.kind] || 'the file'], ['Size', bytes(says.bytes || 0)],
        ['Tables', num(says.tables || 0)], ['Accounts', num(n.users || 0)],
        ['Full administrators', num(says.admins || 0)], ['Events', num(n.events || 0)],
        ['The newest event', says.last_event ? stamp(says.last_event) : '–']
      ]));
      var warn = el('p', 'note bad');
      warn.textContent = 'Putting it back replaces everything in the live database with what is in that file. A copy of what is being replaced is made first and kept with the others, so this can be undone — but everything recorded since that file was made will only be in that copy.';
      body.appendChild(warn);
      body.appendChild(el('p', 'btnhelp', 'You will probably be signed out: who is signed in came with the file like everything else. The key that opens its secrets is taken from beside the file, or from inside a downloaded copy; where there is none, the key in use stays.'));
    }, [
      {words: 'No, leave it', close: true},
      {words: 'Restore it', cls: 'danger', icon: 'undo', close: true, go: function () {
        go().then(function (done) {
          toast('the database was restored; what it replaced is in ' + done.safety + ' — ' + done.key, 'good');
          setTimeout(function () { window.location.reload(); }, 2500);
        }).catch(oops);
      }}], true);
  }
  function dropBox(ids, empty) {
    var box = $(ids.drop), go = $(ids.go);
    if (!box) return;
    function picked(file) {
      go._held = file || null;
      var says = $(ids.what);
      clear(says);
      says.hidden = !go._held;
      go.disabled = !go._held;
      $(ids.says).textContent = go._held ? go._held.name + ' · ' + bytes(go._held.size) : empty;
      if (!go._held) return;
      says.appendChild(el('p', 'btnhelp', 'Nothing has happened yet. Press Restore from this file and it will be read first — if it is not one of ours, if it is damaged, or if it has no full administrator in it, it is refused and nothing here changes.'));
    }
    box.onclick = function () { $(ids.file).click(); };
    $(ids.file).onchange = function () { picked(this.files && this.files[0]); this.value = ''; };
    ['dragenter', 'dragover'].forEach(function (name) {
      box.addEventListener(name, function (e) { e.preventDefault(); box.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      box.addEventListener(name, function (e) {
        e.preventDefault();
        box.classList.remove('over');
        if (name === 'drop' && e.dataTransfer && e.dataTransfer.files) picked(e.dataTransfer.files[0]);
      });
    });
    go.onclick = function () {
      var held = go._held;
      if (!held) return;
      busy(go, true);
      var rd = new FileReader();
      rd.onload = function () {
        var b64 = String(rd.result).split(',')[1] || '';
        api('db-upload', {data: b64, name: held.name}).then(function (d) {
          if (d.locked) { dbAskPassphrase(d, held.name); return; }
          askBeforeRestoring(d.says, held.name, function () {
            return api('db', {action: 'restore_upload', upload: d.upload, file: held.name});
          });
        }).catch(oops).then(function () { busy(go, false); });
      };
      rd.onerror = function () { busy(go, false); toast('the file could not be read', 'bad'); };
      rd.readAsDataURL(held);
    };
  }

  /* ---- the buttons ---------------------------------------------------------------- */
  function simple(id, body, after) {
    var b = $(id);
    if (!b) return;
    b.onclick = function () {
      busy(b, true);
      api('db', body).then(function (x) { toast(x.message, x.good === false ? 'bad' : 'good'); if (after) after(x); loadDb(); })
        .catch(oops).then(function () { busy(b, false); });
    };
  }
  simple('db-backup', {action: 'copy'});
  simple('db-tidy', {action: 'tidy'});
  simple('db-check', {action: 'check'}, function (x) {
    if (x.good) return;
    modal('The database is damaged', function (body) {
      body.appendChild(el('p', 'note bad', 'SQLite’s integrity check says:'));
      body.appendChild(noI18n(el('pre', 'lines', (x.said || []).join('\n'))));
      body.appendChild(el('p', 'note', 'Put the newest good copy back (below), or one from Settings → Backups.'));
    }, [{words: 'Close', close: true}], 'medium');
  });
  simple('db-dump-make', {action: 'dump'});
  if ($('db-download')) $('db-download').onclick = function () { dbDownloadAsk({now: true}); };
  if ($('db-dump-get')) $('db-dump-get').onclick = function () { dbDownloadAsk({now: true, kind: 'dump'}); };
  if ($('db-optimize')) $('db-optimize').onclick = function () {
    confirmThen('Give the disk back?', 'The whole file is rebuilt (SQLite’s VACUUM). Meanwhile nothing can be written to it - a sign-in waits until it is done - and there has to be room on the disk for a second copy of it.', 'Give it back', function () {
      job('Giving the disk back', {action: 'vacuum'}, function (x) {
        toast('the disk is given back: ' + bytes(x.before) + ' → ' + bytes(x.after), 'good');
      });
    }, false);
  };
  if ($('db-prune')) $('db-prune').onclick = function () {
    modal('Forget records older than…', function (body) {
      body.appendChild(el('p', 'note', 'The events older than this are forgotten now, whatever “Keep the events” says. The accounts and the settings are not touched.'));
      var days = textBox('90', 'days', 'mono');
      days.id = 'db-prune-days';
      body.appendChild(formField('Older than (days)', days));
    }, [{words: 'Close', close: true},
        {words: 'Forget them', cls: 'danger', icon: 'forget', close: true, go: function () {
          api('db', {action: 'prune', days: Number($('db-prune-days').value)}).then(function (x) { toast(x.message, 'good'); loadDb(); }).catch(oops);
        }}], true);
  };
  dropBox({drop: 'db-drop', file: 'db-file', says: 'db-drop-says', what: 'db-upload-what', go: 'db-restore'},
          'Drop a database file here, or press to choose one');
  dropBox({drop: 'dump-drop', file: 'dump-file', says: 'dump-drop-says', what: 'dump-upload-what', go: 'dump-restore'},
          'Drop a dump here, or press to choose one');
}());
