/* pane-mail.js - Settings → Mail and Settings → Outgoing mail (otp's loadMail, loadMailq).
   One feature, two panes; drawn as otp draws them. */
(function () {
'use strict';

/* ---- otp's small pieces these two need ---------------------------------- */
function stepsList(steps) {
  var list = el('div', 'steps');
  (steps || []).forEach(function (s) {
    var row = el('div', 'step ' + (s.ok ? 'ok' : 'bad'));
    var mark = el('span', 'step-mark');
    mark.innerHTML = iconMarkup(s.ok ? 'check' : 'cancel', 15);
    row.appendChild(mark);
    var words = el('span', 'step-words');
    words.appendChild(el('b', '', s.what));
    if (s.said) words.appendChild(noI18n(el('span', 'd', s.said)));
    if (s.ms !== undefined) words.appendChild(el('span', 'd', s.ms + ' ms'));
    row.appendChild(words);
    list.appendChild(row);
  });
  return list;
}
function hideButton(go) {
  var b = cmdButton('Hide this', 'close', 'small');
  b.classList.add('hide-this');
  b.onclick = function (e) {
    if (e) e.stopPropagation();
    busy(b, true);
    Promise.resolve(go()).catch(oops).then(function () { busy(b, false); });
  };
  return b;
}
function hideBar(go, words) {
  var row = el('div', 'actions hide-row');
  row.appendChild(hideButton(go));
  if (words) row.appendChild(el('span', 'muted small', words));
  return row;
}
function certTable(list, drop) {
  return listTable(['It is', 'Signed by', 'Good from', 'Good until', 'Fingerprint (SHA-256)', ''], list, function (c) {
    var tr = el('tr');
    tr.appendChild(noI18n(el('td', '', c.subject || '–')));
    var by = el('td');
    if (c.self_signed) by.appendChild(el('span', 'tag info', 'itself - a root'));
    else by.appendChild(noI18n(el('span', '', c.issuer || '–')));
    tr.appendChild(by);
    var when = function (t) { var ms = Date.parse(t || ''); return isNaN(ms) ? (t || '–') : dayWords(new Date(ms)); };
    tr.appendChild(el('td', 'muted small', when(c.from)));
    var left = c.until ? (Date.parse(c.until) - Date.now()) / 86400000 : null;
    var tone = left === null || isNaN(left) ? '' : (left < 0 ? 'bad' : (left < 60 ? 'warn' : 'good'));
    tr.appendChild(el('td', 'small ' + tone, when(c.until)));
    var fp = noI18n(el('td', 'mono small muted fp-full'));
    var hex = (c.fingerprint || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    var half = Math.ceil(hex.length / 4) * 2;
    [hex.slice(0, half), hex.slice(half)].forEach(function (part) {
      if (part) fp.appendChild(el('div', '', part.replace(/(..)(?=.)/g, '$1:')));
    });
    fp.title = hex.replace(/(..)(?=.)/g, '$1:');
    tr.appendChild(fp);
    var tools = el('td', 'rowtools');
    if (ADMIN && drop) {
      var x = iconButton('trash', 'Take this certificate out');
      x.onclick = function () { drop(c); };
      tools.appendChild(x);
    }
    tr.appendChild(tools);
    return tr;
  }, 'plain', {own: true});
}
/** A certificate file read into a box: PEM as it is, a DER .cer written out as PEM. */
function readCertFile(file, box) {
  var reader = new FileReader();
  reader.onload = function () {
    var bytes = new Uint8Array(reader.result || new ArrayBuffer(0));
    var text = '';
    try { text = new TextDecoder('utf-8').decode(bytes); } catch (e) { text = ''; }
    if (text.indexOf('-----BEGIN CERTIFICATE-----') < 0 && bytes.length && bytes[0] === 0x30) {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      text = '-----BEGIN CERTIFICATE-----\n' + btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
        + '\n-----END CERTIFICATE-----';
    }
    var ok = text.indexOf('-----BEGIN CERTIFICATE-----') >= 0;
    box.value = ok ? text.trim() : '';
    box.dispatchEvent(new Event('input'));
    toast(ok ? 'read ' + file.name + ' - Add it keeps it' : file.name + ' is not a certificate', ok ? 'good' : 'bad');
  };
  reader.readAsArrayBuffer(file);
}

/* ---- Settings → Mail ------------------------------------------------------- */
var MAIL = null;
function loadMail() {
  setTimeout(mailViaShown, 0);
  return api('mail').then(function (d) {
    MAIL = d;
    var list = d.ca_list || [];
    $('mca-when').textContent = list.length ? num(list.length) + ' certificate(s) kept' : 'none imported';
    $('mca-drop').hidden = !list.length || !ADMIN;
    var host = $('mca-state');
    clear(host);
    if (list.length) {
      host.appendChild(certTable(list, function (c) {
        confirmThen('Take this certificate out', '<b>' + htmlText(c.subject || 'this certificate')
          + '</b> is no longer trusted for the mail server. The others stay.', 'Take it out', function () {
            api('mail', {action: 'ca', mode: 'drop', fingerprint: c.fingerprint}).then(function (r) {
              toast(r.message, 'good'); loadMail();
            }).catch(oops);
          });
      }));
    }
    $('mail-said').textContent = {off: 'switched off', smtp: 'through a mail server', direct: 'straight to the recipients'}[d.mode] || '';
    explainWhatWasDrawn($('pane-mail'));
    return d;
  }).catch(oops);
}
function mailSteps(host, d) {
  clear(host);
  if (d.queued === 'waiting') {
    /* Through the outgoing mail: not taken yet, tried again by itself. */
    host.appendChild(el('p', 'note warn', 'Waiting in the outgoing mail: ' + d.said + ' - it is tried again by itself.'));
    var go = cmdButton('Outgoing mail', 'list', 'small');
    go.onclick = function () { showPane('mailq'); };
    host.appendChild(go);
  } else {
    host.appendChild(el('p', 'note ' + (d.sent ? 'good' : 'bad'), (d.sent ? (d.queued ? 'Sent through the outgoing mail: ' : 'Sent: ') : 'Not sent: ') + d.said
      + (d.took_ms !== undefined ? ' · ' + num(d.took_ms) + ' ms' : '')));
  }
  if ((d.steps || []).length) host.appendChild(stepsList(d.steps));
  host.appendChild(hideBar(function () { clear(host); }));
}
/* The choice of how a test mail goes - there only while mail goes straight
   to the recipient's server (as otp's). */
function mailViaShown() {
  var via = $('mail-test-via');
  if (!via) return;
  var mode = $('set-mail_mode');
  var v = mode ? String(mode._get ? mode._get() : mode.value) : String(((settingByKey('mail_mode') || {}).value) || '');
  via.hidden = v !== 'direct';
}
document.addEventListener('change', function (e) {
  if (e.target && e.target.id === 'set-mail_mode') mailViaShown();
}, true);
$('mail-test').onclick = function () {
  var b = $('mail-test');
  if (Object.keys(DIRTY || {}).some(function (k) { return /^(mail_|smtp_)/.test(k); })) {
    toast('save the mail settings first', 'bad'); return;
  }
  var to = $('mail-to').value.trim();
  if (!to) { toast('the address to send the test to', 'bad'); $('mail-to').focus(); return; }
  busy(b, true);
  var via = !$('mail-test-via').hidden ? $('mail-test-via').value : 'queue';
  api('mail', {action: 'test', to: to, via: via}).then(function (d) {
    mailSteps($('mail-steps'), d);
  }).catch(oops).then(function () { busy(b, false); });
};
$('mail-to').addEventListener('keydown', function (e) { if (e.key === 'Enter') $('mail-test').click(); });
$('mca-save').onclick = function () {
  var pem = $('mca-pem').value.trim();
  if (!pem) { toast('paste the certificate first, or read it from a file', 'bad'); return; }
  busy($('mca-save'), true);
  api('mail', {action: 'ca', mode: 'add', ca: pem}).then(function (r) {
    toast(r.message, 'good'); $('mca-pem').value = ''; loadMail();
  }).catch(oops).then(function () { busy($('mca-save'), false); });
};
$('mca-file').onclick = function () { $('mca-input').click(); };
$('mca-input').onchange = function () {
  var file = this.files && this.files[0];
  if (file) readCertFile(file, $('mca-pem'));
  this.value = '';
};
$('mca-drop').onclick = function () {
  confirmThen('Take every certificate of the mail server away',
    'The mail server’s certificate will then have to be signed by an authority this machine already trusts, or the check has to be switched off.',
    'Take them all away', function () {
      api('mail', {action: 'ca', mode: 'clear'}).then(function (r) { toast(r.message, 'good'); loadMail(); }).catch(oops);
    });
};
PANE_LOAD.mail = loadMail;

/* ---- Settings → Outgoing mail ---------------------------------------------- */
var MQ = {page: 0, per: 50, timer: null};
var MQ_STATE_WORDS = {sending: ['being sent', 'info'], waiting: ['waiting', 'warn'], sent: ['sent', 'ok'],
                      failed: ['failed', 'crit'], expired: ['given up', 'dim']};
function mailqWatch(on) {
  clearInterval(MQ.timer);
  MQ.timer = null;
  /* Drawn again every 10 s while it is looked at - what waits moves by itself. */
  if (on) MQ.timer = setInterval(function () {
    if (PANE !== 'mailq' || TAB !== 'settings') { mailqWatch(false); return; }
    if (document.hidden) return;
    if (!document.querySelector('.modal:not([hidden])')) loadMailq(true);
  }, 10000);
}
function mailqStateTag(st) {
  var w = MQ_STATE_WORDS[st] || [st || '?', 'dim'];
  return el('span', 'tag ' + w[1], w[0]);
}
function loadMailq(quiet) {
  if (!quiet) { mailqWatch(true); holdTheTallOnes(); }
  apiLatest('mailq', 'mailq&q=' + encodeURIComponent($('mq-q').value) + '&state=' + $('mq-state').value
      + '&limit=' + MQ.per + '&offset=' + MQ.page * MQ.per).then(function (d) {
    var c = d.counts || {};
    var chips = $('mq-chips');
    clear(chips);
    [['waiting', 'waiting for another try'], ['sending', 'being sent'], ['failed', 'failed'],
     ['sent', 'sent'], ['expired', 'given up']].forEach(function (x) {
      var ch = el('button', 'mq-chip ' + (MQ_STATE_WORDS[x[0]] || ['', ''])[1] + ($('mq-state').value === x[0] ? ' on' : ''));
      ch.type = 'button';
      ch.appendChild(el('b', '', num(c[x[0]] || 0)));
      ch.appendChild(el('span', '', x[1]));
      ch.onclick = function () { $('mq-state').value = $('mq-state').value === x[0] ? '' : x[0]; MQ.page = 0; loadMailq(); };
      chips.appendChild(ch);
    });
    $('mq-said').textContent = (d.mode === 'off' ? 'Sending mail is switched off (Settings → Mail): nothing is sent or tried again. · ' : '')
      + 'A mail not taken is tried again for ' + d.retry_hours + ' h; the list keeps what went or failed for ' + d.keep_days + ' days.';
    liveFill($('mq-table'), function (host) {
      host.appendChild(listTable(['Made', 'To', 'What', 'State', {words: 'Tries', cls: 'num'}, 'Next try / went', 'What it said', ''], d.rows, function (r) {
        var tr = el('tr');
        tr.appendChild(stampCell(r.created));
        var to = el('td');
        to.appendChild(noI18n(el('span', 'mono', (r.to || []).join(', '))));
        if ((r.done_to || []).length) to.appendChild(noI18n(el('span', 'sub', 'taken by ' + r.done_to.join(', '))));
        tr.appendChild(to);
        var what = el('td');
        what.appendChild(el('span', '', r.kind_words || r.kind));
        if (r.subject) what.appendChild(noI18n(el('span', 'sub', r.subject)));
        tr.appendChild(what);
        var st = el('td');
        st.appendChild(mailqStateTag(r.state));
        tr.appendChild(st);
        tr.appendChild(el('td', 'num', num(r.tries || 0)));
        if (r.state === 'sent') tr.appendChild(stampCell(r.sent_at));
        else if (r.state === 'waiting') {
          var nx = el('td', 'small');
          var left = (r.next_at || 0) - Date.now() / 1000;
          nx.textContent = left > 5 ? 'in ' + span(left) : 'now';
          nx.title = 'tried until ' + dayWords(new Date((r.expires || 0) * 1000)) + ' ' + clockWords(new Date((r.expires || 0) * 1000));
          tr.appendChild(nx);
        } else tr.appendChild(el('td', 'muted small', r.state === 'sending' ? 'now' : '–'));
        var said = el('td', 'muted small mq-said');
        said.textContent = r.said || '';
        said.title = r.said || '';
        noI18n(said);
        tr.appendChild(said);
        var tools = el('td', 'rowtools');
        if (ADMIN) {
          if ((r.state === 'waiting' || r.state === 'failed') && r.has_body) {
            var again = iconButton('refresh', 'Send it again now');
            again.onclick = function (e) { e.stopPropagation(); mailqDo('retry', [r.qid]); };
            tools.appendChild(again);
          }
          var x = iconButton('trash', 'Take it out of the outgoing mail');
          x.onclick = function (e) {
            e.stopPropagation();
            confirmThen('Take the mail out', 'The mail to <b>' + htmlText((r.to || []).join(', ')) + '</b> ('
              + htmlText(r.kind_words || '') + ') goes from the list' + (r.state === 'waiting' ? ' and is not tried again' : '') + '.',
              'Take it out', function () { mailqDo('drop', [r.qid]); }, true);
          };
          tools.appendChild(x);
        }
        tr.appendChild(tools);
        tr.onclick = function () { mailqPeek(r.qid); };
        tr.classList.add('tappable');
        return tr;
      }, 'rows|Nothing has been sent yet', {own: true}));
    }, !!quiet);
    pager('mq-pager', MQ.page, MQ.per, d.total, function (p) { MQ.page = p; loadMailq(); });
    explainWhatWasDrawn($('pane-mailq'));
  }).catch(oops);
}
function mailqDo(act, ids) {
  return api('mailq', {action: act, ids: ids || []}).then(function (x) {
    toast(x.message, 'good');
    loadMailq(true);
    setTimeout(function () { if (PANE === 'mailq') loadMailq(true); }, 2500);
  }).catch(oops);
}
function mailqPeek(qid) {
  api('mailq-one&id=' + encodeURIComponent(qid)).then(function (r) {
    modal('A mail to ' + (r.to || []).join(', '), function (body) {
      var kv = el('div', 'me-kv');
      var row = function (k, v) { kv.appendChild(el('div', 'k', k)); var d = el('div', 'v'); if (typeof v === 'string') d.appendChild(noI18n(el('span', '', v))); else d.appendChild(v); kv.appendChild(d); };
      var at = function (ts) { var d = new Date((ts || 0) * 1000); return dayWords(d) + ' ' + clockWords(d); };
      row('State', mailqStateTag(r.state));
      row('What', el('span', '', r.kind_words || '')); if (r.subject) row('Subject', r.subject);
      row('Made', at(r.created) + (r.by ? ' · ' + r.by : ''));
      if ((r.done_to || []).length) row('Taken by', r.done_to.join(', '));
      if (r.state === 'sent') row('Went', at(r.sent_at));
      if (r.state === 'waiting') row('Next try', at(r.next_at));
      row('Tried until', at(r.expires));
      row('Size', bytes(r.size || 0));
      body.appendChild(kv);
      if ((r.history || []).length) {
        body.appendChild(el('h3', '', 'Tries'));
        body.appendChild(listTable(['When', '', 'What it said'], r.history.slice().reverse(), function (h) {
          var tr = el('tr');
          tr.appendChild(stampCell(h.at));
          var t = el('td'); t.appendChild(el('span', 'tag ' + (h.ok ? 'ok' : 'warn'), h.ok ? 'taken' : 'not taken')); tr.appendChild(t);
          tr.appendChild(noI18n(el('td', 'small', h.said || '')));
          return tr;
        }, 'rows', {own: true}));
      }
      if ((r.steps || []).length) {
        body.appendChild(el('h3', '', 'The last try, step by step'));
        body.appendChild(stepsList(r.steps));
      }
      if (!r.has_body && (r.state === 'sent' || r.state === 'expired'))
        body.appendChild(el('p', 'note muted small', 'What the mail held is not kept once it went or was given up.'));
    }, [{words: 'Take it out', icon: 'trash', cls: 'danger', hidden: !ADMIN, go: function () { closeModal(); mailqDo('drop', [qid]); }},
        {spacer: true},
        {words: 'Send it again now', icon: 'refresh', cls: 'primary', hidden: !ADMIN || !r.has_body || !(r.state === 'waiting' || r.state === 'failed'),
         go: function () { closeModal(); mailqDo('retry', [qid]); }},
        {words: 'Close', close: true}].filter(function (b) { return !b.hidden; }), 'medium');
  }).catch(oops);
}
$('mq-q').addEventListener('input', debounce(function () { MQ.page = 0; loadMailq(); }, 300));
$('mq-state').onchange = function () { MQ.page = 0; loadMailq(); };
$('mq-retry-all').onclick = function () { mailqDo('retry_all'); };
$('mq-drop-sent').onclick = function () {
  confirmThen('Clear the sent mails', 'The mails that went leave the list (the events still say they went).', 'Clear them', function () { mailqDo('drop_sent'); });
};
$('mq-drop-failed').onclick = function () {
  confirmThen('Clear the failed mails', 'The mails refused for good, or given up, leave the list - they are not tried again.', 'Clear them', function () { mailqDo('drop_failed'); }, true);
};
PANE_LOAD.mailq = function () { MQ.page = 0; loadMailq(); };
}());
