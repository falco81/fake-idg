/* pane-about.js - Settings → About (1.6.1): otp's drawAbout, drawConsoleLogin, drawSoftware and
   accountPicker, for one fake-igd server. The settings of the pane (the performance meter, the
   debug log) are drawn by the generic settings code into #sect-about, with the save bar; the
   console at login waits for the same save bar (as otp's pendingSet). */
'use strict';

var ABOUT = {d: null, con: null, sw: null};

/* ---- about ---------------------------------------------------------------- */
function drawAbout() {
  var s = STATUS || {};
  var host = $('about-state');
  /* What STATUS has at once, the rest when the API answers - never an empty card. */
  if (!ABOUT.d) {
    clear(host);
    host.appendChild(el('h2', '', 'fake-igd ' + (s.version || '')));
    host.appendChild(el('p', 'muted small', 'asking…'));
  }
  api('about').then(function (d) {
    ABOUT.d = d;
    clear(host);
    host.appendChild(el('h2', '', 'fake-igd ' + (d.version || s.version || '')));
    var c = d.counts || {};
    host.appendChild(peekFacts([['Running for', d.since ? span(d.uptime || 0) : (d.state || 'not running')],
                                ['Answering', (d.listening || []).join(', ') || 'not listening'],
                                ['Clients', num(c.clients || 0)], ['Ports asked', num(c.ports || 0)],
                                ['Mappings', num(c.mappings || 0)], ['Database', d.database || 'SQLite']]));
    var a = c.actions || {};
    host.appendChild(kvTable(Object.keys(a).sort().map(function (k) { return [k, num(a[k])]; })));
    host.appendChild(el('p', 'muted small', 'One Python program (' + (d.program || '/opt/fake-igd/fake-igd.py')
      + '), the standard library, an API for these pages and the PHP pages that ask it. On the server: upnp --help.'));
    drawAboutDocs(host, d);
    if (ADMIN && d.console) drawConsoleLogin(host, d.console);
    drawSoftware(host);
  }).catch(function (e) {
    clear(host);
    host.appendChild(el('h2', '', 'fake-igd ' + (s.version || '')));
    host.appendChild(el('p', 'note bad', String((e && e.message) || e)));
  });
}

/* The README and the CHANGELOG of what runs - read from beside the program, drawn as text. */
function drawAboutDocs(host, d) {
  var row = el('div', 'btnrow');
  var docs = d.docs || {};
  [['readme', 'The README', 'book', 'What fake-igd is, how it is installed and used - the README of the version that runs here.'],
   ['changelog', 'What is new', 'history', 'Every version and what it changed - the CHANGELOG of the version that runs here.']].forEach(function (x) {
    if (!docs[x[0]]) return;
    var b = cmdButton(x[1], x[2], 'small');
    explain(b, x[3]);
    b.onclick = function () { aboutDoc(x[0], x[1]); };
    row.appendChild(b);
  });
  if (row.childNodes.length) host.appendChild(row);
}
function aboutDoc(name, title) {
  peek(title, function () { return api('about-doc&name=' + name); }, function (body, d) {
    body.appendChild(noI18n(el('p', 'mono small muted', d.file + ' · ' + bytes(d.size || 0))));
    body.appendChild(aboutMarkdown(d.text || ''));
  });
  var box = $('modal-box');
  if (box) box.className = 'box large';
}
/* **bold** and `code` of a line, as elements - text only, never HTML. */
function aboutInline(tag, cls, text) {
  var e = noI18n(el(tag, cls));
  String(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/).forEach(function (part) {
    if (!part) return;
    if (/^\*\*[^*]+\*\*$/.test(part)) e.appendChild(el('b', '', part.slice(2, -2)));
    else if (/^`[^`]+`$/.test(part)) e.appendChild(el('code', '', part.slice(1, -1)));
    else e.appendChild(document.createTextNode(part));
  });
  return e;
}
/* Markdown as plain elements: headings, lists, code blocks, paragraphs - text only, never HTML. */
function aboutMarkdown(text) {
  var out = el('div', 'about-doc');
  var lines = String(text).split('\n'), i = 0, para = [], list = null;
  var flush = function () {
    if (para.length) { out.appendChild(aboutInline('p', 'note', para.join(' '))); para = []; }
    list = null;
  };
  while (i < lines.length) {
    var ln = lines[i];
    if (/^```/.test(ln)) {
      flush();
      var code = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i++; }
      out.appendChild(noI18n(el('pre', 'mono small', code.join('\n'))));
      i++;
      continue;
    }
    var h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { flush(); out.appendChild(aboutInline(h[1].length <= 2 ? 'h3' : 'h4', h[1].length <= 2 ? 'sw-h' : '', h[2])); i++; continue; }
    var li = ln.match(/^\s*[-*]\s+(.*)$/);
    if (li) {
      if (para.length) { out.appendChild(aboutInline('p', 'note', para.join(' '))); para = []; }
      if (!list) { list = el('ul', 'tight'); out.appendChild(list); }
      list.appendChild(aboutInline('li', '', li[1]));
      i++;
      continue;
    }
    if (!ln.trim()) { flush(); i++; continue; }
    if (list && /^\s{2,}/.test(ln)) { var more = aboutInline('span', '', ' ' + ln.trim()); while (more.firstChild) list.lastChild.appendChild(more.firstChild); i++; continue; }
    list = null;
    para.push(ln.trim());
    i++;
  }
  flush();
  return out;
}

/* The upnp console when root signs in at the console or over SSH (otp's drawConsoleLogin, 1.0.141):
   a switch - and the normal users it opens for too; root writes /etc/upnp-console-login. The switch
   only says what it will be; the save bar at the bottom does it, as with every other setting. */
function drawConsoleLogin(host, n) {
  var box = el('div', 'sw-box');
  host.appendChild(box);
  box.appendChild(el('h3', 'sw-h', 'The console at login'));
  box.appendChild(el('p', 'note', 'On: root signing in at the machine\'s console or over SSH lands in the upnp console (upnp --console); q leaves it for the shell. Off: the ordinary shell, and upnp --console opens it. Commands run over SSH, scp and sftp never get it. On the server: upnp --console-at-login on|off.'));
  box.appendChild(el('p', 'note', 'For normal users too: they land in it through sudo, after their own password - only those who may become root with sudo (wheel); anybody else gets a line saying so and the ordinary shell. In Events their changes are marked with their name. On the server: upnp --console-users "alice bob" (or * or none).'));
  if (n.there === false && !n.on) box.appendChild(el('p', 'muted small', 'Not set yet: ' + n.file + ' is written the first time it is saved.'));
  if (!n.profile) box.appendChild(el('p', 'note warn', '/etc/profile.d/zz-upnp-console.sh is missing - nothing opens the console at login until the installer is run again.'));
  var row = el('div', 'kv-row con-row');
  var sw = switchBox(!!n.on);
  sw._input.disabled = !!n.pending;
  var name = noI18n(el('b', '', n.name));
  row.appendChild(sw);
  swNamedBy(sw, name);
  var whoC = el('div', 'con-who');
  whoC.appendChild(name);
  whoC.appendChild(el('span', 'tag info', 'this one'));
  row.appendChild(whoC);
  if (n.pending) whoC.appendChild(el('span', 'muted small', 'being switched…'));
  if (n.error) row.appendChild(el('p', 'note bad con-err', n.error));
  var key = 'about:console';
  var hasU = n.users === '*' ? '*' : (n.users || []);
  var mine = DIRTY[key] && !sw._input.disabled ? DIRTY[key] : null;
  var want = mine ? mine.users : hasU;
  if (mine) { sw._input.checked = mine.on; row.classList.add('changed'); }
  var same = function (a, b) { return JSON.stringify(a === '*' ? '*' : (a || [])) === JSON.stringify(b === '*' ? '*' : (b || [])); };
  var usersNow = want;
  var changed = function () {
    var on = sw._input.checked, users = usersNow;
    var diff = on !== !!n.on || !same(users, n.users);
    row.classList.toggle('changed', diff);
    if (diff) DIRTY[key] = {on: on, users: users}; else delete DIRTY[key];
    markDirtyCount();
  };
  var uwrap = el('div', 'con-users');
  uwrap.appendChild(el('span', 'muted small', 'normal users:'));
  uwrap.appendChild(aboutPicker(want, n.accounts || [], {none: 'Nobody', every: 'Every normal user',
    disabled: sw._input.disabled, change: function (v) { usersNow = v; changed(); }}));
  row.appendChild(uwrap);
  sw._input.onchange = changed;
  box.appendChild(row);
  if (n.pending) setTimeout(function () { if (PANE === 'about' && TAB === 'settings') drawAbout(); }, 2000);
}

/* otp's accountPicker (o.none: nobody [], every normal user '*', or these) - the names are the
   users Settings → Local users read last. */
function aboutPicker(cur, names, o) {
  var star = cur === '*';
  cur = star ? [] : (cur || []).slice();
  var value = function () { return star ? '*' : cur.slice(); };
  var box = el('details', 'acct-pick');
  var sum = el('summary', '');
  box.appendChild(sum);
  var panel = el('div', 'acct-panel');
  box.appendChild(panel);
  if (o.disabled) box.classList.add('off');
  var redraw = null;
  var said = function () {
    clear(sum);
    if (!cur.length) {
      var ev0 = el('span', 'acct-every' + (!star ? ' nobody' : ''));
      ev0.innerHTML = iconMarkup('people', 14);
      ev0.appendChild(el('span', '', !star ? o.none : o.every));
      sum.appendChild(ev0);
      return;
    }
    cur.forEach(function (n) {
      var chip = el('span', 'acct-chip');
      chip.appendChild(noI18n(el('span', 'mono', n)));
      if (!o.disabled) {
        var x = el('button', 'acct-x', '×');
        x.type = 'button';
        x.title = 'Take it away';
        x.onclick = function (e) {
          e.preventDefault(); e.stopPropagation();
          cur = cur.filter(function (m) { return m !== n; });
          said(); if (redraw) redraw(); if (o.change) o.change(value());
        };
        chip.appendChild(x);
      }
      sum.appendChild(chip);
    });
  };
  var all = names.filter(function (n) { return n !== 'root'; });
  cur.forEach(function (n) { if (all.indexOf(n) < 0) all.push(n); });
  var nob = el('label', 'acct-row acct-row-every');
  var nbc = el('input'); nbc.type = 'checkbox'; nbc.checked = !star && !cur.length; nbc.disabled = !!o.disabled;
  var nbi = el('span', 'acct-ava'); nbi.textContent = '–';
  nob.appendChild(nbc); nob.appendChild(nbi); nob.appendChild(el('span', 'acct-name', o.none));
  var find = null;
  if (all.length > 7) {
    find = el('input', 'acct-find');
    find.type = 'search'; find.placeholder = 'find a user'; find.spellcheck = false; find.autocomplete = 'off';
    panel.appendChild(find);
    localSuggest(find, [], function () { return []; }, function () { return all.map(function (n) { return {val: n}; }); });
  }
  panel.appendChild(nob);
  var ev = el('label', 'acct-row acct-row-every');
  var evc = el('input'); evc.type = 'checkbox'; evc.checked = star; evc.disabled = !!o.disabled;
  var evi = el('span', 'acct-ava every'); evi.innerHTML = iconMarkup('people', 14);
  ev.appendChild(evc); ev.appendChild(evi); ev.appendChild(el('span', 'acct-name', o.every));
  panel.appendChild(ev);
  var boxes = [], rows = [];
  all.forEach(function (n) {
    var r = el('label', 'acct-row');
    var c = el('input'); c.type = 'checkbox'; c.value = n; c.checked = cur.indexOf(n) >= 0; c.disabled = !!o.disabled;
    r.appendChild(c);
    r.appendChild(noI18n(el('span', 'acct-ava', n.slice(0, 2).toUpperCase())));
    r.appendChild(noI18n(el('span', 'acct-name mono', n)));
    if (names.indexOf(n) < 0) r.appendChild(el('span', 'tag dim', 'not listed by Local users'));
    panel.appendChild(r);
    boxes.push(c); rows.push([n, r]);
  });
  if (find) find.oninput = function () {
    var q = find.value.trim().toLowerCase();
    rows.forEach(function (x) { x[1].hidden = q && x[0].toLowerCase().indexOf(q) < 0; });
  };
  if (!all.length) panel.appendChild(el('p', 'muted small', 'No normal user who may sign in is known yet - Settings → Local users reads them.'));
  var tops = function () { nbc.checked = !star && !cur.length; evc.checked = star; };
  redraw = function () { boxes.forEach(function (c) { c.checked = cur.indexOf(c.value) >= 0; }); tops(); };
  var changed = function () { said(); if (o.change) o.change(value()); };
  evc.onchange = function () {
    star = evc.checked; if (star) { cur = []; boxes.forEach(function (c) { c.checked = false; }); }
    tops(); changed();
  };
  nbc.onchange = function () { star = false; cur = []; boxes.forEach(function (c) { c.checked = false; }); tops(); changed(); };
  boxes.forEach(function (c) {
    c.onchange = function () {
      star = false;
      cur = boxes.filter(function (x) { return x.checked; }).map(function (x) { return x.value; });
      tops(); changed();
    };
  });
  said();
  var shut = function (e) {
    if (!box.isConnected) { document.removeEventListener('click', shut); return; }
    if (box.open && !box.contains(e.target)) box.open = false;
  };
  document.addEventListener('click', shut);
  if (o.disabled) sum.onclick = function (e) { e.preventDefault(); };
  return box;
}

/* The console at login goes with the save bar (otp's pendingSet): taken out of DIRTY, asked of
   root, and the rest saved as ever. */
(function () {
  var b = $('set-save');
  if (!b) return;
  var plain = b.onclick;
  b.onclick = function (e) {
    var mine = DIRTY['about:console'];
    if (!mine) return plain && plain.call(b, e);
    delete DIRTY['about:console'];
    busy(b, true);
    api('about-console', {on: mine.on, users: mine.users}).then(function (r) {
      toast(r.message, 'good');
      busy(b, false);
      if (Object.keys(DIRTY).length && plain) plain.call(b, e);
      else { markDirtyCount(); if (PANE === 'about') drawAbout(); }
    }).catch(function (err) {
      DIRTY['about:console'] = mine;
      busy(b, false);
      markDirtyCount();
      oops(err);
    });
  };
})();

/* What it runs on (otp's drawSoftware, 1.0.99): fake-igd, Python and its modules, the libraries
   under them, the pages' PHP and its extensions, nginx and the rest beside it. */
function drawSoftware(host) {
  var box = el('div', 'sw-box');
  host.appendChild(box);
  box.appendChild(el('h3', 'sw-h', 'What it runs on'));
  var wait = el('p', 'muted small', 'asking…');
  box.appendChild(wait);
  api('about-software').then(function (d) {
    box.removeChild(wait);
    var nodes = d.nodes || [];
    var pages = d.pages || {};
    var sw = function (n, f) { var x = n.software || {}; return f(x) || ''; };
    var prog = function (k) { return function (x) { return (x.programs || {})[k]; }; };
    var mod = function (k) { return function (x) { return (x.modules || {})[k] || ''; }; };
    var rows = [
      ['fake-igd', function (x) { return x.fake_igd; }],
      ['group:Python'],
      ['Python', function (x) { return x.python; }],
      ['where', function (x) { return x.python_path; }],
      ['colorama', mod('colorama')],
      ['OpenSSL (Python’s)', function (x) { return x.openssl; }],
      ['SQLite (library)', function (x) { return x.sqlite; }],
      ['group:The database'],
      ['server', function (x) { return x.database; }],
      ['group:The pages'],
      ['nginx', prog('nginx')],
      ['php-fpm', prog('php-fpm')],
      ['PHP (command line)', function (x) { return x.php_cli; }],
      ['group:The system'],
      ['system', function (x) { return x.os; }],
      ['kernel', function (x) { return x.kernel + (x.arch ? ' · ' + x.arch : ''); }],
      ['systemd', prog('systemd')],
      ['OpenSSL (system)', prog('openssl')],
      ['avahi-daemon', prog('avahi-daemon')],
      ['iptables', prog('iptables')],
      ['firewalld', prog('firewalld')]
    ];
    var t = el('table', 'rows sw-table');
    var th = el('thead'), hr = el('tr');
    hr.appendChild(el('th', '', ''));
    nodes.forEach(function (n) {
      var c = el('th', '');
      c.appendChild(noI18n(el('span', '', n.name)));
      if (n.me) c.appendChild(el('span', 'tag info', 'this one'));
      hr.appendChild(c);
    });
    th.appendChild(hr); t.appendChild(th);
    var tb = el('tbody');
    rows.forEach(function (r) {
      var tr = el('tr');
      if (r[0].indexOf('group:') === 0) {
        tr.className = 'sw-group';
        var g = el('td', '', r[0].slice(6));
        g.colSpan = nodes.length + 1;
        tr.appendChild(g);
        tb.appendChild(tr);
        return;
      }
      var vals = nodes.map(function (n) { return sw(n, r[1]); });
      if (!vals.some(function (v) { return v; })) return;     /* nowhere: not shown */
      tr.appendChild(el('td', 'k', r[0]));
      vals.forEach(function (v) { tr.appendChild(noI18n(el('td', 'mono small', v || '–'))); });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    box.appendChild(t);
    /* The pages: this PHP itself, as php-fpm runs it. */
    if (pages.php) {
      box.appendChild(el('h3', 'sw-h', 'The pages’ PHP (as php-fpm runs it here)'));
      box.appendChild(peekFacts([['PHP', pages.php], ['How', pages.sapi], ['OPcache', pages.opcache ? 'on' : 'off'],
                                 ['Web server', pages.server || '–']]));
      var ex = el('div', 'sw-ext');
      Object.keys(pages.extensions || {}).forEach(function (k) {
        var v = pages.extensions[k];
        ex.appendChild(noI18n(el('span', 'tag namepill', k + (v ? ' ' + v : ''))));
      });
      box.appendChild(el('div', 'muted small', 'Its extensions (' + num(Object.keys(pages.extensions || {}).length) + '):'));
      box.appendChild(ex);
    }
    explainWhatWasDrawn(box);
  }).catch(function (e) { wait.textContent = String(e.message || e); });
}

/* The performance meter (otp's hload.js, 1.0.253): started the first time the status says it is
   on, where the page has the meter (#hload and hloadLoop) - its ticks ask nothing while it is off. */
setInterval(function () {
  if (typeof hloadLoop !== 'function' || typeof HLOAD !== 'object' || !$('hload')) return;
  if (STATUS && STATUS.perf_meter && !HLOAD.timer) hloadLoop();
}, 3000);

PANE_LOAD.about = drawAbout;
