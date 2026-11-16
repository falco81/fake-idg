/* pane-db.js - Settings → The database (otp's loadDb, drawDisk, drawCounts, keptTable,
   the putting back - for fake-igd's one SQLite file). */
(function () {
  'use strict';
  var DB = {d: null};
  var TABLE_SAID = {users: 'The accounts of the pages', sessions: 'Who is signed in', fails: 'Wrong passwords counted',
                    events: 'Events', meta: 'Settings and small values', sqlite_sequence: 'SQLite’s own counters'};
  var KIND_SAID = {copy: 'a copy', 'before-restore': 'made before a restore', upload: 'sent'};

  function loadDb() {
    api('db').then(function (d) {
      DB.d = d;
      $('db-size').textContent = bytes(d.size) + ' · ' + d.where;
      drawDisk(d);
      drawCounts(d);
      keptTable($('db-backups'), d.copies || [], d);
      explainWhatWasDrawn($('pane-db'));
    }).catch(oops);
  }
  PANE_LOAD.db = loadDb;

  /* ---- the disk under it ---------------------------------------------------- */
  function drawDisk(d) {
    var host = $('db-disk');
    clear(host);
    var disk = d.disk || {};
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
    says.appendChild(el('span', '', share + '% of it is used.'));
    host.appendChild(says);
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
    var kept = el('p', 'note');
    kept.textContent = (d.events_keep_days ? 'The events are kept for ' + num(d.events_keep_days) + ' day(s)'
      : 'The events are kept for ever (the newest 20 000)') + (d.tidied ? ' - last trimmed ' + ago(d.tidied) + '.' : '.')
      + ' ' + d.version + '.';
    host.appendChild(kept);
    if (d.free) {
      host.appendChild(el('p', 'btnhelp', bytes(d.free) + ' free inside it, which SQLite uses again; Give the disk back hands it to the operating system.'));
    }
  }

  /* ---- the copies kept beside it ------------------------------------------- */
  function keptTable(into, rows, d) {
    clear(into);
    if (!into) return;
    into.appendChild(el('h4', '', 'Copies kept (' + d.keep + ' at most)'));
    if (!rows.length) {
      into.appendChild(el('p', 'note', d.daily ? 'None yet - the first is made tonight at ' + d.at + ', or now with Make a copy now.'
        : 'None - the daily copy is off; Make a copy now makes one.'));
      return;
    }
    into.appendChild(listTable(['Name', 'Made as', {words: 'Size', cls: 'num'}, 'Made', {words: '', cls: 'act'}], rows, function (b) {
      var line = el('tr');
      line.appendChild(noI18n(el('td', 'mono', b.name)));
      line.appendChild(el('td', b.kind === 'copy' ? '' : 'muted', KIND_SAID[b.kind] || b.kind));
      line.appendChild(el('td', 'num', bytes(b.bytes)));
      line.appendChild(stampCell(b.at));
      var act = el('td', 'rowtools');
      if (ADMIN) {
        var take = cmdButton('Download', 'down', 'small');
        explain(take, 'Save this copy to the machine you are sitting at.');
        take.onclick = function () { dbDownload(b.name, take); };
        act.appendChild(take);
        var back = cmdButton('Restore', 'undo', 'small danger');
        explain(back, 'Put <b>this</b> one back, without downloading it and uploading it again: everything in the live database is replaced by what is in this file. You are shown what is in it and asked first, and a copy of what is being replaced is made before anything changes.');
        back.onclick = function () { restoreKept(b); };
        act.appendChild(back);
        var gone = cmdButton('Delete', 'trash', 'small danger');
        explain(gone, 'Delete this file from the server. The live database is not touched.');
        gone.onclick = function () {
          confirmThen('Delete this copy?', 'The file ' + htmlText(b.name) + ' is deleted from this machine. The live database is not touched, and the others stay where they are.', 'Delete it', function () {
            api('db', {action: 'delete', name: b.name}).then(function (x) { toast(x.message, 'good'); loadDb(); }).catch(oops);
          });
        };
        act.appendChild(gone);
      }
      line.appendChild(act);
      return line;
    }, 'plain', {own: true}));
    into.appendChild(el('p', 'btnhelp', 'They are files on this machine, under ' + d.backup_dir + '. Copy them off it if they are to survive the machine - Settings → Backups does it on a schedule.'));
  }

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
  function dbDownload(name, button) {
    if (button) busy(button, true);
    if (!name) toast('it is being made; the download starts when it is ready', 'good');
    api('db', {action: 'download', name: name || ''}).then(function (x) {
      saveBytes(x.name, x.data);
      toast(x.name + ' · ' + bytes(x.bytes), 'good');
    }).catch(oops).then(function () { if (button) busy(button, false); });
  }

  /* ---- putting one back -------------------------------------------------------- */
  function restoreKept(b) {
    api('db', {action: 'restore_kept', name: b.name, check: true}).then(function (d) {
      askBeforeRestoring(d.says, b.name, function () { return api('db', {action: 'restore_kept', name: b.name}); });
    }).catch(oops);
  }
  function askBeforeRestoring(says, what, go) {
    var n = (says && says.counts) || {};
    modal('Put this database back?', function (body) {
      body.appendChild(peekFacts([
        ['File', noI18n(el('span', 'mono', String(what)))], ['Size', bytes(says.bytes || 0)],
        ['Tables', num(says.tables || 0)], ['Accounts', num(n.users || 0)],
        ['Full administrators', num(says.admins || 0)], ['Events', num(n.events || 0)],
        ['The newest event', says.last_event ? stamp(says.last_event) : '–']
      ]));
      var warn = el('p', 'note bad');
      warn.textContent = 'Putting it back replaces everything in the live database with what is in that file. A copy of what is being replaced is made first and kept with the others, so this can be undone — but everything recorded since that file was made will only be in that copy.';
      body.appendChild(warn);
      body.appendChild(el('p', 'btnhelp', 'You will probably be signed out: who is signed in came with the file like everything else.'));
    }, [
      {words: 'No, leave it', close: true},
      {words: 'Restore it', cls: 'danger', icon: 'undo', close: true, go: function () {
        go().then(function (done) {
          toast(done.message, 'good');
          setTimeout(function () { window.location.reload(); }, 2500);
        }).catch(oops);
      }}], true);
  }
  function dropBox() {
    var box = $('db-drop'), go = $('db-restore'), empty = 'Drop a database file here, or press to choose one';
    if (!box) return;
    function picked(file) {
      go._held = file || null;
      var says = $('db-upload-what');
      clear(says);
      says.hidden = !go._held;
      go.disabled = !go._held;
      $('db-drop-says').textContent = go._held ? go._held.name + ' · ' + bytes(go._held.size) : empty;
      if (!go._held) return;
      says.appendChild(el('p', 'btnhelp', 'Nothing has happened yet. Press Restore from this file and it will be read first — if it is not fake-igd’s database, if it is damaged, or if it has no full administrator in it, it is refused and nothing here changes.'));
    }
    box.onclick = function () { $('db-file').click(); };
    $('db-file').onchange = function () { picked(this.files && this.files[0]); this.value = ''; };
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
  if ($('db-download')) $('db-download').onclick = function () { dbDownload('', $('db-download')); };
  if ($('db-optimize')) $('db-optimize').onclick = function () {
    confirmThen('Give the disk back?', 'The whole file is rebuilt (SQLite’s VACUUM). Meanwhile nothing can be written to it - a sign-in waits until it is done - and there has to be room on the disk for a second copy of it.', 'Give it back', function () {
      busy($('db-optimize'), true);
      api('db', {action: 'vacuum'}).then(function (x) {
        toast('the disk is given back: ' + bytes(x.before) + ' → ' + bytes(x.after), 'good');
        loadDb();
      }).catch(oops).then(function () { busy($('db-optimize'), false); });
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
  dropBox();
}());
