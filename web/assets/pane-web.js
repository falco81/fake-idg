/* Settings → Firewall and access (1.6.0) - otp's pane "fw" (loadFw, drawFw, drawFwAccess,
   drawFwBody, fwRuleEdit) for one server, and otp's banner of a change on trial (drawTrials).
   Who may reach the pages (nginx's allow list, and 80/443 in the firewall) and the machine's
   firewall: fake-igd's own chain FAKE-IGD-IN, the rules of your own first, then what fake-igd's
   functions need. Root puts it in (deploy/root_fw.py) - on trial: unless kept, it goes back. */
var FW = {last: null, timer: null, fam: '4', draft: null, dirty: false, ver: 0, otherOpen: false};
/* What the old pane drew, asked for by the save bar after a change root puts in place: this pane now. */
function loadRoot() { if (fwPaneLive()) loadFw(); }

function fwPaneLive() {
  return typeof TAB !== 'undefined' && TAB === 'settings' && PANE === 'web' && $('pane-web') && !$('pane-web').hidden;
}
/* Changes wait for the save bar, as everywhere else in Settings: what is shown is the
   draft, what root found comes live. The save bar is the one of Settings: its Save puts
   this pane's draft in too, its Put them back forgets it. */
function fwFromServer(d) {
  return JSON.parse(JSON.stringify({on: !!d.conf.on, off: d.conf.off || [], rules: d.conf.rules || [],
                                    access: d.access, access_changed: false}));
}
function fwDirty() {
  fwMarkBar();
  if (FW.last) drawFw(FW.last);
}
function fwMarkBar() {
  FW.dirty = true;
  FW.ver = (FW.ver || 0) + 1;
  fwPaintBar();
}
function fwPaintBar() {
  if (PANE !== 'web' || !$('save-bar')) return;
  var n = Object.keys(DIRTY).length + (FW.dirty ? 1 : 0);
  $('set-said').textContent = n ? n + ' change(s) not saved yet' : '';
  $('save-bar').classList.toggle('dirty', n > 0);
}
function fwAsk(title, words, yes, danger) {
  return new Promise(function (resolve) {
    modal(title, function (body) {
      var p = el('p', 'note');
      p.textContent = words;
      p.style.marginBottom = '0';
      body.appendChild(p);
    }, [{words: 'No, leave it', close: true, go: function () { resolve(false); }},
        {words: yes, cls: danger === false ? 'primary' : 'danger', once: true, close: true, go: function () { resolve(true); }}], true);
  });
}
function fwSave(button) {
  if (!FW.draft || !FW.dirty) return Promise.resolve(true);
  var dr = FW.draft, was = FW.last ? !!FW.last.conf.on : false, ver = FW.ver;
  var go = function () {
    var body = {action: 'save', on: dr.on, off: dr.off, rules: dr.rules};
    if (dr.access_changed) body.access = dr.access;
    busy(button, true);
    return api('fw', body).then(function (x) {
      busy(button, false);
      toast(x.message, 'good');
      /* Changed while it was being saved: kept, still to be saved. */
      if (FW.ver !== ver) return false;
      FW.dirty = false; FW.draft = null;
      fwPaintBar();
      loadFw();
      setTimeout(trialsLoad, 2500);
      setTimeout(trialsLoad, 6000);
      return true;
    }, function (e) { busy(button, false); throw e; });
  };
  var ask = Promise.resolve(true);
  if (dr.on && !was) {
    ask = fwAsk('Let fake-igd look after the firewall',
      'fake-igd puts a chain of its own, FAKE-IGD-IN, first in INPUT, for IPv4 and IPv6, and keeps it in /etc/sysconfig/iptables and ip6tables. Your own rules stay as they are; FAKE-IGD-IN only lets in - what it does not let in goes on to them. SSH stays open (a rule of fake-igd\'s, which you can turn off).',
      'Turn it on', false);
  } else if (!dr.on && was) {
    ask = fwAsk('Take fake-igd\'s rules away', 'The chain FAKE-IGD-IN and its jump go; the rest of the firewall stays exactly as it is. ' +
      'Whatever only FAKE-IGD-IN let in (SSDP and SOAP for the PS5, the pages) is then up to your own rules.', 'Take them away');
  }
  return ask.then(function (yes) { return yes ? go() : false; });
}
function loadFw() {
  if (!ADMIN) {
    var lede = $('fw-lede');
    if (lede) lede.textContent = 'The firewall and who may reach the pages are shown to full administrators only.';
    return;
  }
  apiLatest('fw', 'fw').then(drawFw).catch(oops);
  clearInterval(FW.timer);
  FW.timer = setInterval(function () {
    if (!fwPaneLive()) { clearInterval(FW.timer); return; }
    if (document.hidden) return;
    if ($('modal') && !$('modal').hidden) return;
    if (apiLatestOut('fw')) return;
    apiLatest('fw', 'fw').then(function (d) { liveRun(function () { drawFw(d); }); }).catch(function () {});
  }, 5000);
}
function fwFam(f) {
  f = Number(f) || 0;
  return noI18n(el('span', 'fam fam' + (f || 'x'), f ? 'IPv' + f : 'IPv4 + IPv6'));
}
function fwWhat(r) {
  var proto = r.proto === 'any' ? 'everything' : (r.proto === 'icmp' && Number(r.family) === 6 ? 'ICMPv6' : r.proto.toUpperCase());
  return proto + (r.port ? ' ' + r.port : '');
}
function fwAction(a) {
  return el('span', 'fwact fwact-' + a, {accept: 'ACCEPT', drop: 'DROP', reject: 'REJECT'}[a] || a);
}
function fwSources(r) {
  return (r.sources || (r.source ? [r.source] : [])).join(', ');
}
function fwRuleLine(r) {
  var line = el('div', 'fw-rl');
  line.appendChild(fwFam(r.family));
  if (r.words) {
    line.appendChild(el('span', 'fw-from', r.words));
    return line;
  }
  line.appendChild(noI18n(el('code', 'fw-what', fwWhat(r))));
  line.appendChild(el('span', 'fw-from', r.source ? 'from ' : 'from anywhere'));
  if (r.source) line.lastChild.appendChild(noI18n(el('code', '', r.source)));
  if (r.iface) {
    line.appendChild(el('span', 'fw-from', 'on '));
    line.lastChild.appendChild(noI18n(el('code', '', r.iface)));
  }
  return line;
}

function drawFw(d) {
  FW.last = d;
  if (!FW.draft || (!FW.dirty && !liveWorkedIn($('fw-master')) && !liveWorkedIn($('fw-access'))
                    && !liveWorkedIn($('fw-body')))) FW.draft = fwFromServer(d);
  var dr = FW.draft;
  /* What is drawn is the draft; the automatic rules follow what is turned off in it. */
  d = Object.assign({}, d, {conf: Object.assign({}, d.conf, {on: dr.on, off: dr.off, rules: dr.rules}), access: dr.access});
  d.auto = (d.auto || []).map(function (a) {
    return Object.assign({}, a, {on: a.fixed || dr.off.indexOf(a.key) < 0});
  });
  drawFwAccess(d);
  /* The switch: fake-igd looks after its rules, or leaves the firewall alone. */
  liveFill($('fw-master'), function (master) {
    var sw = switchBox(d.conf.on);
    sw.classList.add('big');
    sw._input.disabled = !d.may;
    sw._input.onchange = function () { FW.draft.on = !!sw._get(); fwDirty(); };
    var lab = el('label', 'fw-master');
    lab.appendChild(sw);
    lab.appendChild(el('span', '', d.conf.on ? 'fake-igd looks after its rules' : 'fake-igd leaves the firewall alone'));
    master.appendChild(lab);
  });
  $('fw-lede').textContent = d.conf.on
    ? 'In INPUT first: the chain FAKE-IGD-IN - loopback and answers, your own rules in their order, then what fake-igd\'s functions need. What it does not let in goes on to the rules that were there before.'
    : 'Off: nothing is changed in the firewall. Turned on, what fake-igd\'s functions need is let in by itself, and the rules of your own with it.';
  drawFwBody(d);
  explainWhatWasDrawn($('pane-web'));
  if (FW.dirty) fwPaintBar();
}

function drawFwAccess(d) {
  var host = $('fw-access');
  liveFill(host, function (host) {
    var rows = el('div', 'fw-acc');
    var acc = FW.draft.access || (FW.draft.access = {any: true, from: []});
    acc.any = !!acc.any;
    acc.from = (acc.from || []).slice();
    var row = el('div', 'fw-acc-row');
    var t = el('div', 'fw-acc-t');
    t.appendChild(el('b', '', 'The administration'));
    t.appendChild(el('div', 'arow-s', 'https://…/admin/ - these pages'));
    row.appendChild(t);
    var c = el('div', 'fw-acc-c');
    var seg = el('div', 'seg');
    var box = el('textarea', 'mono fw-nets');
    box.rows = 2; box.spellcheck = false;
    box.placeholder = '10.0.0.0/8, 192.168.10.0/24, 2001:db8::/32';
    box.value = acc.from.join(', ');
    box.disabled = !d.may;
    box.oninput = function () {
      FW.draft.access.from = box.value.split(/[\s,;]+/).filter(Boolean);
      FW.draft.access_changed = true; fwMarkBar();
    };
    [[true, 'Everybody'], [false, 'Only from']].forEach(function (o) {
      var b = el('button', '', o[1]);
      b.type = 'button';
      b.disabled = !d.may;
      b.onclick = function () {
        FW.draft.access.any = o[0];
        Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); });
        box.hidden = o[0];
        FW.draft.access_changed = true; fwMarkBar();
      };
      if (acc.any === o[0]) b.classList.add('on');
      seg.appendChild(b);
    });
    box.hidden = acc.any;
    c.appendChild(seg);
    c.appendChild(box);
    row.appendChild(c);
    rows.appendChild(row);
    host.appendChild(rows);
    var foot = el('div', 'fw-acc-foot');
    var always = el('div', 'fw-always');
    always.appendChild(el('span', 'arow-s', 'Always let in:'));
    ['127.0.0.1', '::1'].forEach(function (a) { always.appendChild(noI18n(el('code', 'cchip', a))); });
    foot.appendChild(always);
    if (!acc.any && acc.from.some(function (n) { return n.indexOf(':') >= 0; })) {
      foot.appendChild(el('span', 'tag dim', 'IPv6 networks open the firewall; nginx\'s list takes IPv4'));
    }
    host.appendChild(foot);
  });
}

function drawFwBody(d) {
  var body = $('fw-body');
  liveFill(body, function (body) {
    var fw = d.fw || {};
    if (fw.backend === 'firewalld') {
      body.appendChild(el('p', 'note warn', 'firewalld is running on this machine: what comes in must get through it as well. ' +
        'install.sh opened 1900/udp and 5000/tcp there; for the rest of what is set here: firewall-cmd --permanent --add-port=…, or ' +
        'dnf install iptables-services; systemctl disable --now firewalld; systemctl enable --now iptables ip6tables.'));
    } else if (fw.iptables === false) {
      body.appendChild(el('p', 'note warn', 'There is no iptables on this machine (dnf install iptables-services).'));
    }
    if (d.waiting) body.appendChild(el('p', 'note warn', 'Root has not put the last change in yet (fake-igd-web.path) - a moment.'));
    var r = d.root || {};
    if (r.at && r.ok === false && (r.said || []).length && !d.waiting) {
      var bad = el('div', 'note bad');
      bad.appendChild(el('b', '', 'Root did not put it in: '));
      bad.appendChild(noI18n(el('span', '', r.said[r.said.length - 1])));
      if (d.may) {
        var again = cmdButton('Try again', 'refresh', 'small');
        again.onclick = function () {
          busy(again, true);
          api('fw', {action: 'apply'}).then(function (x) { toast(x.message, 'good'); setTimeout(loadFw, 2500); })
            .catch(oops).then(function () { busy(again, false); });
        };
        bad.appendChild(again);
      }
      body.appendChild(bad);
    }
    /* How a packet goes: one line, so the order is plain. */
    var flow = el('div', 'fw-flow' + (d.conf.on ? '' : ' off'));
    [['INPUT', ''], ['FAKE-IGD-IN: loopback and answers', 'auto'], ['your rules', 'mine'], ['what fake-igd needs', 'auto'], ['the rest of INPUT', 'rest']].forEach(function (s, i) {
      if (i) flow.appendChild(el('span', 'fw-arrow', '→'));
      flow.appendChild(el('span', 'fw-step ' + s[1], s[0]));
    });
    body.appendChild(flow);

    /* Your own rules. */
    var h1 = el('div', 'fw-h');
    h1.appendChild(el('h3', '', 'Rules of your own'));
    if (d.may) {
      var add = cmdButton('Add a rule', 'add', 'small primary');
      add.onclick = function () { fwRuleEdit(d, null); };
      h1.appendChild(add);
    }
    body.appendChild(h1);
    body.appendChild(el('p', 'note', 'Looked at in this order, right after loopback and the answers to what this machine asked (which nothing can shut out): a DROP or REJECT here wins over what fake-igd lets in below. From one or more addresses or networks, on every interface or one.'));
    var mine = (d.conf.rules || []);
    body.appendChild(listTable(['', 'Action', 'IP', 'What', 'From', 'Interface', 'Note', ''], mine, function (r, i) {
      var tr = el('tr', r.disabled ? 'dim' : '');
      tr.appendChild(el('td', 'num muted', String(i + 1)));
      var a = el('td'); a.appendChild(fwAction(r.action)); tr.appendChild(a);
      var f = el('td'); f.appendChild(fwFam(r.family)); tr.appendChild(f);
      tr.appendChild(noI18n(el('td', 'mono', fwWhat(r))));
      tr.appendChild(fwSources(r) ? noI18n(el('td', 'mono', fwSources(r))) : el('td', 'muted', 'anywhere'));
      var sc = el('td'); sc.appendChild(r.iface ? noI18n(el('span', 'tag', r.iface)) : el('span', 'tag dim', 'every one')); tr.appendChild(sc);
      tr.appendChild(noI18n(el('td', 'muted', r.note || '')));
      var tools = el('td', 'acts');
      if (d.may) {
        var up = iconButton('up', 'Earlier'); up.disabled = i === 0;
        up.onclick = function () { fwMove(i, -1); };
        var dn = iconButton('down', 'Later'); dn.disabled = i === mine.length - 1;
        dn.onclick = function () { fwMove(i, 1); };
        var ed = iconButton('edit', 'Change it'); ed.onclick = function () { fwRuleEdit(d, r); };
        var rm = iconButton('trash', 'Take it away');
        rm.onclick = function () { FW.draft.rules.splice(i, 1); fwDirty(); };
        [up, dn, ed, rm].forEach(function (b) { tools.appendChild(b); });
      }
      tr.appendChild(tools);
      return tr;
    }, 'plain fw-table|None yet - fake-igd\'s own rules below are enough for what it does', {own: true}));

    /* What fake-igd lets in by itself. */
    var h2 = el('div', 'fw-h');
    h2.appendChild(el('h3', '', 'What fake-igd lets in by itself'));
    body.appendChild(h2);
    body.appendChild(el('p', 'note', 'Worked out from what is set up, and changed with it: the port of the description and SOAP, the interfaces fake-igd answers on (and those left out, sent back to INPUT), who may reach the pages. What keeps the machine working cannot be turned off.'));
    var grid = el('div', 'fw-auto');
    (d.auto || []).forEach(function (item) {
      var card = el('div', 'fw-auto-card' + (item.on ? '' : ' off'));
      var top = el('div', 'fw-auto-top');
      var t = el('div', '');
      t.appendChild(el('b', '', item.title));
      t.appendChild(el('div', 'arow-s', item.why));
      top.appendChild(t);
      if (item.fixed) {
        top.appendChild(el('span', 'tag ok', 'always'));
      } else {
        var sw = switchBox(item.on);
        swNamedBy(sw, t);
        sw._input.disabled = !d.may;
        sw._input.onchange = function () {
          var off = FW.draft.off.filter(function (k) { return k !== item.key; });
          if (!sw._get()) off.push(item.key);
          FW.draft.off = off;
          fwDirty();
        };
        top.appendChild(sw);
      }
      card.appendChild(top);
      var list = el('div', 'fw-auto-rules');
      var rules = item.rules || [];
      if (!rules.length) list.appendChild(el('span', 'muted', item.key === 'pages' ? (d.pages_here ? 'nobody: the list is empty' : 'no pages on this machine (installed with --no-web)') : 'nothing'));
      rules.slice(0, 12).forEach(function (r) { list.appendChild(fwRuleLine(r)); });
      if (rules.length > 12) list.appendChild(el('span', 'muted', '… and ' + (rules.length - 12) + ' more'));
      (item.skip || []).forEach(function (i) {
        var l = el('div', 'fw-rl');
        l.appendChild(fwFam(4));
        l.appendChild(el('span', 'fw-from', 'not on '));
        l.lastChild.appendChild(noI18n(el('code', '', i)));
        l.appendChild(el('span', 'fw-from', '(left out - back to INPUT)'));
        list.appendChild(l);
      });
      card.appendChild(list);
      grid.appendChild(card);
    });
    body.appendChild(grid);

    /* Everything else: read only. */
    var other = el('details', 'fw-other');
    other.appendChild(el('summary', '', 'The whole firewall on this machine (read only)'));
    var seg = el('div', 'seg');
    var pre = noI18n(el('pre', 'fw-pre'));
    /* In the one scroller of the pane: the whole of it, not a box of its own that scrolls. */
    pre.style.maxHeight = 'none'; pre.style.overflow = 'visible';
    pre.style.whiteSpace = 'pre-wrap'; pre.style.wordBreak = 'break-all';
    /* Every chain of the filter table as iptables-save shows it, FAKE-IGD-IN's lines marked -
       root reads it after every change, and again when asked. */
    var full = fw.full || null;
    var paint = function () {
      var lines = full ? (full[FW.fam] || []) : [];
      clear(pre);
      if (!lines.length) pre.textContent = '(nothing - or not known yet)';
      lines.forEach(function (line, i) {
        var ours = /FAKE-IGD-IN/.test(line);
        var sp = el('span', ours ? 'fw-line fw-ours' : 'fw-line', line);
        pre.appendChild(sp);
        if (i < lines.length - 1) pre.appendChild(document.createTextNode('\n'));
      });
      Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x.dataset.f === FW.fam); });
    };
    [['4', 'IPv4 (iptables)'], ['6', 'IPv6 (ip6tables)']].forEach(function (o) {
      var b = el('button', '', o[1]); b.type = 'button'; b.dataset.f = o[0];
      b.onclick = function () { FW.fam = o[0]; paint(); };
      seg.appendChild(b);
    });
    other.appendChild(seg);
    other.appendChild(pre);
    var foot = el('p', 'note');
    foot.appendChild(document.createTextNode(full
      ? 'The filter table as iptables-save shows it, read ' + (fw.full_at ? ago(fw.full_at) : '?') + '. The marked lines are fake-igd\'s (the chain FAKE-IGD-IN and the jump to it); the rest are yours, and fake-igd never changes them. '
      : 'Not read yet: root reads it after every change, or now. '));
    if (d.may) {
      var again = el('a', 'fgo', 'Read it again');
      again.onclick = function () {
        again.textContent = 'reading…';
        FW.otherOpen = true;
        api('fw', {action: 'read'}).then(function () {
          setTimeout(loadFw, 2000);
          setTimeout(loadFw, 5000);
        }).catch(oops);
      };
      foot.appendChild(again);
    }
    other.appendChild(foot);
    paint();
    if (FW.otherOpen) other.open = true;
    other.ontoggle = function () { FW.otherOpen = other.open; };
    body.appendChild(other);
  });
}

function fwMove(i, dir) {
  var list = FW.draft.rules, j = i + dir;
  if (j < 0 || j >= list.length) return;
  var t = list[i]; list[i] = list[j]; list[j] = t;
  fwDirty();
}
function fwRow(words, says, control) {
  var row = el('div', 'arow');
  var t = el('div', 'arow-t');
  t.appendChild(el('div', 'arow-k', words));
  t.appendChild(el('div', 'arow-s', says));
  row.appendChild(t);
  var c = el('div', 'arow-c');
  c.appendChild(control);
  row.appendChild(c);
  return row;
}
function fwRuleEdit(d, r) {
  var st = Object.assign({family: 0, proto: 'tcp', port: '', sources: [], iface: '', action: 'accept', note: '', disabled: false}, r || {});
  st.sources = (st.sources || []).slice();
  modal(r ? 'Change the rule' : 'A rule of your own', function (body) {
    var rows = el('div', 'tls-rows');
    var segOf = function (opts, key, after) {
      var seg = el('div', 'seg');
      opts.forEach(function (o) {
        var b = el('button', '', o[1]); b.type = 'button';
        b.onclick = function () { st[key] = o[0]; Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); if (after) after(); };
        if (String(st[key]) === String(o[0])) b.classList.add('on');
        seg.appendChild(b);
      });
      return seg;
    };
    rows.appendChild(fwRow('Action', 'ACCEPT lets it in; DROP says nothing; REJECT answers that it is closed.',
      segOf([['accept', 'Accept'], ['drop', 'Drop'], ['reject', 'Reject']], 'action')));
    rows.appendChild(fwRow('IP version', 'Taken from the addresses when they are given.',
      segOf([[0, 'Both'], [4, 'IPv4'], [6, 'IPv6']], 'family')));
    var port = textBox('', '', 'mono'); port.value = st.port; port.placeholder = '443 · 8000-8100 · 80,443';
    port.oninput = function () { st.port = port.value.trim(); };
    var portRow = fwRow('Port', 'One, a range, or several by commas. Empty: every port.', port);
    var paintPort = function () { portRow.classList.toggle('dim', ['tcp', 'udp'].indexOf(st.proto) < 0); port.disabled = ['tcp', 'udp'].indexOf(st.proto) < 0; if (port.disabled) { port.value = ''; st.port = ''; } };
    rows.appendChild(fwRow('Protocol', '', segOf([['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP'], ['vrrp', 'VRRP'], ['any', 'Any']], 'proto', paintPort)));
    rows.appendChild(portRow);
    var src = textBox('', '', 'mono'); src.value = st.sources.join(', '); src.placeholder = '192.0.2.0/24 · 2001:db8::/32 · empty = anywhere';
    src.oninput = function () { st.sources = src.value.split(/[\s,;]+/).filter(Boolean); };
    rows.appendChild(fwRow('From', 'An address or a network, or several by commas.', src));
    var ifc = textBox('', '', 'mono'); ifc.value = st.iface; ifc.placeholder = 'eth0 · empty = every interface'; ifc.maxLength = 15;
    ifc.oninput = function () { st.iface = ifc.value.trim(); };
    rows.appendChild(fwRow('Interface', 'Only what comes in on this one.', ifc));
    var note = textBox('', ''); note.value = st.note; note.placeholder = 'Zabbix agent'; note.maxLength = 80;
    note.oninput = function () { st.note = note.value; };
    rows.appendChild(fwRow('Note', 'Shown here and as the comment of the rule in iptables.', note));
    var dis = switchBox(!st.disabled);
    dis._input.onchange = function () { st.disabled = !dis._get(); };
    rows.appendChild(fwRow('In force', 'Off keeps it here without putting it in.', dis));
    body.appendChild(rows);
    paintPort();
  }, [{words: 'Cancel', close: true},
      {words: r ? 'Change it' : 'Add it', cls: 'primary', icon: 'check', go: function (b) {
        /* Checked by the API now, kept in the draft until Save. */
        busy(b, true);
        api('fw', {action: 'rule_check', rule: st}).then(function (x) {
          var got = Object.assign({}, x.rule, {id: r ? r.id : 'n' + Date.now().toString(36)});
          var list = FW.draft.rules;
          var i = r ? list.findIndex(function (y) { return y.id === r.id; }) : -1;
          if (i >= 0) list[i] = got; else list.push(got);
          closeModal(); fwDirty();
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}

/* The save bar of Settings, with this pane's draft in it. */
(function () {
  var save = $('set-save'), reset = $('set-reset');
  if (save) {
    var theirSave = save.onclick;
    save.onclick = function (e) {
      if (PANE !== 'web' || !FW.dirty) return theirSave && theirSave.call(save, e);
      fwSave(save).then(function (ok) {
        if (ok && Object.keys(DIRTY).length && theirSave) theirSave.call(save, e);
      }, oops);
    };
  }
  if (reset) {
    var theirReset = reset.onclick;
    reset.onclick = function (e) {
      if (PANE === 'web' && FW.dirty) { FW.dirty = false; FW.draft = null; fwPaintBar(); loadFw(); }
      if (theirReset) theirReset.call(reset, e);
    };
  }
  if (typeof markDirtyCount === 'function') {
    var theirCount = markDirtyCount;
    markDirtyCount = function () { theirCount(); if (FW.dirty) fwPaintBar(); };
  }
  /* web_allow, firewall, firewall_ssh, firewall_icmp are drawn above, as otp draws them,
     and saved on trial - not in the grid of settings as well. */
  if (typeof drawSettings === 'function') {
    var theirDraw = drawSettings;
    drawSettings = function () {
      var own = ['web_allow', 'firewall', 'firewall_ssh', 'firewall_icmp'];
      if (SETTINGS && SETTINGS.panes && SETTINGS.panes.web) {
        SETTINGS.panes.web = SETTINGS.panes.web.filter(function (k, i, all) { return own.indexOf(k) < 0 && all.indexOf(k) === i; });
      }
      return theirDraw.apply(this, arguments);
    };
  }
  window.addEventListener('beforeunload', function (e) {
    if (FW.dirty) { e.preventDefault(); e.returnValue = ''; }
  });
}());

PANE_LOAD.web = function () {
  loadFw();
  setTimeout(function () { if (FW.dirty) fwPaintBar(); }, 0);
};

/* ---- A change on trial: on every page, with the time left counting down (otp's drawTrials) ---- */
var FW_TRIALS = {list: [], skew: 0, timer: null, poll: null};
function trialsHost() {
  var host = $('trials-fw');
  if (host) return host;
  var all = $('trials');
  if (!all) {
    all = el('div', 'trials');
    all.id = 'trials';
    var pr = $('problems');
    if (pr && pr.parentNode) pr.parentNode.insertBefore(all, pr.nextSibling);
    else document.body.insertBefore(all, document.body.firstChild);
  }
  host = el('div', 'trials');
  host.id = 'trials-fw';
  host.style.margin = '0';
  all.appendChild(host);
  return host;
}
function drawTrials(d) {
  FW_TRIALS.list = (d && d.trials) || [];
  FW_TRIALS.skew = d && d.now ? d.now - Date.now() / 1000 : 0;
  var host = trialsHost();
  var all = $('trials');
  if (!FW_TRIALS.list.length) {
    host.hidden = true; clear(host);
    if (all) all.hidden = !Array.prototype.some.call(all.children, function (c) { return !c.hidden; });
    if (FW_TRIALS.timer) { clearInterval(FW_TRIALS.timer); FW_TRIALS.timer = null; }
    return;
  }
  host.hidden = false;
  if (all) all.hidden = false;
  liveFill(host, function (host) {
    FW_TRIALS.list.forEach(function (t) {
      var row = el('div', 'trial');
      var words = el('div', 'trial-words');
      words.appendChild(el('b', '', 'The change of the firewall and access waits to be kept'));
      var left = el('span', 'trial-left mono');
      left.dataset.until = t.until;
      words.appendChild(document.createTextNode(' - '));
      words.appendChild(left);
      words.appendChild(el('div', 'small', 'Not kept, the rules and who may reach the pages as they were before come back by themselves. Keep it once you have checked that SSH and the pages still answer.'));
      row.appendChild(words);
      var tools = el('div', 'trial-tools');
      if (ADMIN) {
        var keep = cmdButton('Keep it', 'check', 'small primary');
        keep.onclick = function () { trialDo(t, 'keep', keep); };
        var back = cmdButton('Put the old back now', 'undo', 'small danger');
        back.onclick = function () {
          confirmThen('Put the old back now?', 'The firewall and who may reach the pages go back to what they were before the change.',
            'Put it back', function () { trialDo(t, 'back', back); });
        };
        tools.appendChild(keep);
        tools.appendChild(back);
      }
      row.appendChild(tools);
      host.appendChild(row);
    });
  }, true);
  trialCount();
  if (!FW_TRIALS.timer) FW_TRIALS.timer = setInterval(trialCount, 1000);
}
function trialCount() {
  var now = Date.now() / 1000 + FW_TRIALS.skew;
  document.querySelectorAll('#trials-fw .trial-left').forEach(function (x) {
    var left = parseFloat(x.dataset.until) - now;
    x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) + ' left' : 'going back now';
  });
}
function trialDo(t, action, button) {
  busy(button, true);
  api('fw-trial', {action: action}).then(function (d) {
    toast(d.message, 'good');
    setTimeout(trialsLoad, 1500);
    setTimeout(trialsLoad, 4000);
    if (fwPaneLive()) { setTimeout(loadFw, 2500); setTimeout(loadFw, 5000); }
  }).catch(oops).then(function () { busy(button, false); });
}
function trialsLoad() {
  if (typeof ME === 'undefined' || !ME) return;
  api('fw-trial').then(drawTrials).catch(function () {});
}
trialsLoad();
FW_TRIALS.poll = setInterval(function () { if (!document.hidden) trialsLoad(); }, 10000);
