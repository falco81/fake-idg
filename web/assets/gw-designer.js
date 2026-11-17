/* The FW designer of a device (1.8.2; shared since 1.9.2): its DNS servers and rules of its own - a flow on
   top, the lists below, a packet tried through the lines as root would put them in, those lines, Save on
   trial. Configuration, so it is kept in Settings → Gateway for devices - and opened as a popup from the
   Gateway tab's device card as well, with no trip to Settings. Read-only accounts see it read-only: nothing
   changes, no packet is tried (that asks the API as a full admin), no Save.
     GW_DESIGNER(device, view, opts)   device and view as GET /api/gateway gives them; opts.saved() after Save
     GW_DESIGNER_OPEN(ipOrId, opts)    the same, asked of the API first (from the Gateway tab) */
(function () {
  'use strict';
  /* ---- the FW designer of a device (1.8.2): its DNS servers and rules of its own - a flow on top, the lists
     below, a packet tried through the lines as root would put them in, those lines, Save on trial. ---- */
  function openDesigner(x, d, opts) {
    d = d || {}; opts = opts || {};
    var nv = d.net || {};
    var ED = {dns: (x.dns || []).map(function (y) { return {ip: y.ip, dot: !!y.dot, hits: y.hits, via: y.via, direct: y.direct}; }),
              rules: (x.rules || []).map(function (r) { return {id: r.id, to: r.to, proto: r.proto || 'any', ports: r.ports || '', comment: r.comment || '', on: r.on !== false, hits: r.hits, via: r.via, direct: r.direct}; }),
              preview: null, dirty: false, editing: null};
    var host = {};
    var others = nv.others || {};
    var netChips = Object.keys(others).map(function (k) { return {dev: k, nets: others[k]}; });
    function prv() {
      return api('gateway', {action: 'try', id: x.id, dns: ED.dns.map(function (y) { return {ip: y.ip, dot: y.dot}; }),
                             rules: ED.rules.map(function (r) { return {id: r.id, to: r.to, proto: r.proto, ports: r.ports, comment: r.comment, on: r.on}; })});
    }
    function refresh() {
      ED.dirty = true;
      prv().then(function (p) {
        ED.preview = p; host.err.textContent = '';
        (p.dns || []).forEach(function (y, i) { if (ED.dns[i]) { ED.dns[i].via = y.via; ED.dns[i].direct = y.direct; } });
        (p.rules || []).forEach(function (r, i) { if (ED.rules[i]) { ED.rules[i].via = r.via; ED.rules[i].direct = r.direct; ED.rules[i].id = ED.rules[i].id || r.id; ED.rules[i].to = r.to; } });
        paint();
      }).catch(function (e) { host.err.textContent = String(e.message || e); paint(); });
    }
    function lane(ok, title, detail, hits, cls) {
      var l = el('div', 'gwf-lane ' + (cls || (ok ? 'ok' : 'no')));
      l.appendChild(el('span', 'gwf-mark', ok === null ? '·' : (ok ? '✓' : '✗')));
      var w = el('div', 'gwf-words');
      w.appendChild(el('b', '', title));
      if (detail) w.appendChild(noI18n(el('span', 'gwf-detail mono', detail)));
      l.appendChild(w);
      if (hits) l.appendChild(el('span', 'gwf-hits', hits));
      return l;
    }
    function hitWords(h) { return h && h.pkts ? num(h.pkts) + ' pkts · ' + bytes(h.bytes) : ''; }
    function flow() {
      var f = el('div', 'gw-flow');
      var dev = el('div', 'gwf-node gwf-dev');
      dev.innerHTML = iconMarkup('router', 22);
      var dw = el('div', 'gwf-node-words');
      dw.appendChild(el('b', '', x.name));
      dw.appendChild(noI18n(el('span', 'mono', x.ip)));
      dw.appendChild(noI18n(el('span', 'mono small muted', x.mac || 'any MAC')));
      dev.appendChild(dw);
      f.appendChild(dev);
      f.appendChild(el('div', 'gwf-arrow', '→'));
      var srv = el('div', 'gwf-node gwf-srv');
      srv.innerHTML = iconMarkup('wall', 22);
      var sw = el('div', 'gwf-node-words');
      sw.appendChild(el('b', '', 'this server'));
      sw.appendChild(noI18n(el('span', 'mono', nv.address || '?')));
      sw.appendChild(noI18n(el('span', 'small muted', (nv.defif || '?') + ' · FAKE-IGD-FWD')));
      srv.appendChild(sw);
      f.appendChild(srv);
      f.appendChild(el('div', 'gwf-arrow', '→'));
      var lanes = el('div', 'gwf-lanes');
      lanes.appendChild(lane(true, 'Internet', 'via the router ' + (nv.router || '?') + ' (' + (nv.defif || '?') + ')', hitWords(x.internet)));
      ED.dns.forEach(function (y) {
        lanes.appendChild(lane(y.direct ? null : true, 'DNS ' + y.ip, y.direct ? 'on its own network - reached directly, no rule needed'
          : 'udp + tcp 53' + (y.dot ? ' and DoT tcp 853' : '') + ' out ' + (y.via || '?'), hitWords(y.hits), y.direct ? 'direct' : ''));
      });
      ED.rules.forEach(function (r) {
        var what = (r.proto === 'any' ? 'everything' : r.proto + (r.ports ? ' ' + r.ports : '')) + ' → ' + r.to + (r.via ? ' out ' + r.via : '');
        lanes.appendChild(lane(r.on ? (r.direct ? null : true) : false, r.comment || 'A rule of its own', what + (r.on ? '' : ' - switched off') + (r.direct ? ' - on its own network, reached directly' : ''),
          hitWords(r.hits), r.on ? (r.direct ? 'direct' : '') : 'off'));
      });
      var loc = Object.keys(others).map(function (k) { return k + ' ' + others[k].join(', '); });
      lanes.appendChild(lane(false, 'Your local networks', (nv.network ? nv.defif + ' ' + nv.network + ' (through this server)' : '') + (loc.length ? '; ' + loc.join('; ') : '')));
      lanes.appendChild(lane(false, 'Private networks behind the router', '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10'));
      lanes.appendChild(lane(false, 'Everything else', 'multicast, link-local, loopback - and any other device'));
      f.appendChild(lanes);
      return f;
    }
    function dnsCard() {
      var c = el('div', 'card gwd-card');
      c.appendChild(el('h3', 'peek-h', 'DNS servers it may ask'));
      c.appendChild(el('p', 'note', 'udp and tcp 53 to exactly these - also in a private network or another network of this server. Empty: as now (the internet is allowed anyway). One on its own network is reached directly.'));
      var chips = el('div', 'gwd-chips');
      ED.dns.forEach(function (y, i) {
        var ch = el('span', 'gwd-chip' + (y.direct ? ' direct' : ''));
        ch.appendChild(noI18n(el('span', 'mono', y.ip)));
        var dot = el('label', 'gwd-dot');
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!y.dot; cb.disabled = !ADMIN;
        cb.onchange = function () { y.dot = cb.checked; refresh(); };
        dot.appendChild(cb); dot.appendChild(document.createTextNode(' DoT 853'));
        ch.appendChild(dot);
        if (y.direct) ch.appendChild(el('span', 'small muted', 'direct'));
        var rm = el('button', 'gwd-x', '×'); rm.type = 'button'; rm.title = 'Take it away'; rm.disabled = !ADMIN;
        rm.onclick = function () { ED.dns.splice(i, 1); refresh(); };
        ch.appendChild(rm);
        chips.appendChild(ch);
      });
      if (!ED.dns.length) chips.appendChild(el('span', 'muted small', 'none - as now'));
      c.appendChild(chips);
      var row = el('div', 'gwd-add');
      var inp = textBox('', 'an IPv4 address', 'mono');
      var add = cmdButton('Add', 'add', 'small');
      var put = function (ip) {
        ip = (ip || '').trim();
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) { host.err.textContent = 'A DNS server is one IPv4 address.'; return; }
        if (ED.dns.some(function (y) { return y.ip === ip; })) return;
        ED.dns.push({ip: ip, dot: false}); inp.value = ''; refresh();
      };
      add.disabled = inp.disabled = !ADMIN;
      add.onclick = function () { put(inp.value); };
      inp.onkeydown = function (e) { if (e.key === 'Enter') put(inp.value); };
      row.appendChild(inp); row.appendChild(add);
      c.appendChild(row);
      var sug = el('div', 'gwd-sugg');
      var offer = [].concat(nv.dns || [], nv.router ? [nv.router] : []).filter(function (a, i, all) { return all.indexOf(a) === i && !ED.dns.some(function (y) { return y.ip === a; }); });
      if (offer.length) sug.appendChild(el('span', 'small muted', 'Offered: '));
      offer.forEach(function (a) {
        var b = el('button', 'gwd-sug mono', '+ ' + a); b.type = 'button'; b.disabled = !ADMIN;
        b.title = (nv.dns || []).indexOf(a) >= 0 ? 'this server\'s resolver - what the PS5 values below show' : 'the router';
        b.onclick = function () { put(a); };
        sug.appendChild(b);
      });
      c.appendChild(sug);
      return c;
    }
    function ruleEditor(r, i) {
      var box = el('div', 'gwd-editor');
      box.appendChild(el('h4', '', i < 0 ? 'A new rule' : 'The rule'));
      var to = textBox(r.to || '', '172.16.17.10 or 172.16.17.0/24', 'mono');
      var chips = el('div', 'gwd-netchips');
      netChips.forEach(function (n) {
        n.nets.forEach(function (net) {
          var b = el('button', 'gwd-sug mono', n.dev + ' ' + net); b.type = 'button';
          b.onclick = function () { to.value = net; check(); };
          chips.appendChild(b);
        });
      });
      var seg = el('div', 'seg gwd-seg');
      var proto = r.proto || 'tcp';
      ['tcp', 'udp', 'icmp', 'any'].forEach(function (p) {
        var b = el('button', 'seg-b' + (p === proto ? ' on' : ''), p); b.type = 'button';
        b.onclick = function () { proto = p; seg.querySelectorAll('button').forEach(function (z) { z.classList.toggle('on', z.textContent === p); }); check(); };
        seg.appendChild(b);
      });
      var ports = textBox((r.ports || '').replace(/:/g, '-'), '8080  ·  8000-8100  ·  80,443', 'mono');
      var note = textBox(r.comment || '', 'what it is for');
      var said = el('div', 'small gwd-said');
      var check = function () {
        var p = ports.value.replace(/\s/g, ''), bad = '';
        if (!/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(to.value.trim())) bad = 'The destination: an IPv4 address or network (172.16.17.10, 172.16.17.0/24).';
        else if (/\/(\d+)$/.test(to.value) && Number(/\/(\d+)$/.exec(to.value)[1]) < 8) bad = 'Not a whole range of the internet - the internet is allowed already.';
        else if (p && (proto === 'icmp' || proto === 'any')) bad = 'Ports are for tcp or udp.';
        else if (p && !/^(\d{1,5}([-:]\d{1,5})?)(,\d{1,5}([-:]\d{1,5})?)*$/.test(p)) bad = 'Ports: 8080, a range 8000-8100, or a list 80,443.';
        said.textContent = bad; said.className = 'small gwd-said' + (bad ? ' bad' : '');
        return !bad;
      };
      to.oninput = ports.oninput = check;
      var grid = el('div', 'set-grid gwd-egrid');
      var tw = el('div', 'gwd-to');
      tw.appendChild(to);
      tw.appendChild(chips);
      grid.appendChild(formField('To', tw, 'One address or one network - in a network of this server (then out that interface, its answers back) or behind the router. A network of this server: press it above.'));
      grid.appendChild(formField('Protocol', seg, 'tcp, udp, icmp (ping) or any.'));
      grid.appendChild(formField('Ports', ports, 'For tcp or udp: 8080 · 8000-8100 · 80,443,8000-8100 (fifteen at most). Empty: every port.'));
      grid.appendChild(formField('What for', note, 'In the list and in the rule\'s iptables comment.'));
      box.appendChild(grid);
      box.appendChild(said);
      var row = el('div', 'btnrow');
      var ok = cmdButton(i < 0 ? 'Add the rule' : 'Done', 'check', 'primary small');
      ok.onclick = function () {
        if (!check()) return;
        var one = {id: r.id || '', to: to.value.trim(), proto: proto, ports: ports.value.replace(/\s/g, ''), comment: note.value.trim(), on: r.on !== false};
        if (i < 0) ED.rules.push(one); else ED.rules[i] = one;
        ED.editing = null; refresh();
      };
      var no = cmdButton('Cancel', 'close', 'small');
      no.onclick = function () { ED.editing = null; paint(); };
      row.appendChild(ok); row.appendChild(no);
      box.appendChild(row);
      setTimeout(function () { try { to.focus(); } catch (e) { } }, 0);
      return box;
    }
    function rulesCard() {
      var c = el('div', 'card gwd-card');
      var h = el('h3', 'peek-h', 'Rules of its own ');
      c.appendChild(h);
      c.appendChild(el('p', 'note', 'Each allows this device - and only it - to one destination, in the order below. None: as now (the internet only). Never toward everything, never this server itself.'));
      if (!ED.rules.length && ED.editing === null) c.appendChild(el('p', 'muted small', 'No rule of its own.'));
      ED.rules.forEach(function (r, i) {
        if (ED.editing === i) { c.appendChild(ruleEditor(r, i)); return; }
        var row = el('div', 'gwd-rule' + (r.on ? '' : ' off'));
        var ord = el('span', 'gwd-ord');
        var up = el('button', 'gwd-arrow', '↑'); up.type = 'button'; up.disabled = !ADMIN || i === 0; up.title = 'Up';
        up.onclick = function () { var t = ED.rules[i - 1]; ED.rules[i - 1] = r; ED.rules[i] = t; refresh(); };
        var dn = el('button', 'gwd-arrow', '↓'); dn.type = 'button'; dn.disabled = !ADMIN || i === ED.rules.length - 1; dn.title = 'Down';
        dn.onclick = function () { var t = ED.rules[i + 1]; ED.rules[i + 1] = r; ED.rules[i] = t; refresh(); };
        ord.appendChild(el('span', 'gwd-n', String(i + 1)));
        ord.appendChild(up); ord.appendChild(dn);
        row.appendChild(ord);
        var sw = switchBox(r.on);
        sw._input.disabled = !ADMIN;
        sw._input.onchange = function () { r.on = sw._input.checked; refresh(); };
        row.appendChild(sw);
        var w = el('div', 'gwd-rule-words');
        w.appendChild(el('b', '', r.comment || 'A rule of its own'));
        w.appendChild(noI18n(el('span', 'mono small', (r.proto === 'any' ? 'any' : r.proto + (r.ports ? ' ' + r.ports.replace(/:/g, '-') : ' every port')) + ' → ' + r.to + (r.via ? '  (out ' + r.via + ')' : ''))));
        if (r.direct) w.appendChild(el('span', 'small muted', 'on its own network: reached directly, no rule needed'));
        row.appendChild(w);
        row.appendChild(el('span', 'gwd-hits small muted', r.hits && r.hits.pkts ? num(r.hits.pkts) + ' pkts · ' + bytes(r.hits.bytes) : 'no packet yet'));
        var ed = iconButton('edit', 'Change it'); ed.disabled = !ADMIN;
        ed.onclick = function () { ED.editing = i; paint(); };
        var rm = iconButton('trash', 'Take it away'); rm.disabled = !ADMIN;
        rm.onclick = function () { ED.rules.splice(i, 1); refresh(); };
        row.appendChild(ed); row.appendChild(rm);
        c.appendChild(row);
      });
      if (ED.editing === -1) c.appendChild(ruleEditor({proto: 'tcp', on: true}, -1));
      else if (ADMIN) {
        var add = cmdButton('Add a rule', 'add', 'small');
        add.disabled = ED.rules.length >= 64;
        add.onclick = function () { ED.editing = -1; paint(); };
        var r0 = el('div', 'btnrow'); r0.appendChild(add); c.appendChild(r0);
      }
      return c;
    }
    function tryCard() {
      var c = el('div', 'card gwd-card gwd-try');
      c.appendChild(el('h3', 'peek-h', 'Try a packet'));
      c.appendChild(el('p', 'note', 'From ' + x.name + ' through the rules as they would be with what is set here now - the same lines root puts in, the first that fits decides.'));
      var grid = el('div', 'gwd-trygrid');
      var dst = textBox(c._dst || '', '8.8.8.8', 'mono');
      var sel = el('select'); ['tcp', 'udp', 'icmp'].forEach(function (p) { var o = el('option', '', p); o.value = p; sel.appendChild(o); });
      var port = textBox('443', 'port', 'mono');
      var spoof = el('label', 'small'); var cb = el('input'); cb.type = 'checkbox'; spoof.appendChild(cb); spoof.appendChild(document.createTextNode(' from another box that took its address'));
      var go = cmdButton('Try it', 'play', 'primary small');
      var out = el('div', 'gwd-verdict');
      go.onclick = function () {
        busy(go, true);
        api('gateway', {action: 'try', id: x.id, dst: dst.value.trim(), proto: sel.value, port: port.value.trim(), mac_other: cb.checked,
                        dns: ED.dns.map(function (y) { return {ip: y.ip, dot: y.dot}; }),
                        rules: ED.rules.map(function (r) { return {id: r.id, to: r.to, proto: r.proto, ports: r.ports, comment: r.comment, on: r.on}; })})
          .then(function (t) {
            clear(out);
            var k = t.direct ? 'info' : (t.verdict === 'ACCEPT' ? 'ok' : 'crit');
            out.appendChild(el('span', 'tag ' + k, t.direct ? 'direct' : (t.verdict === 'ACCEPT' ? 'forwarded' : 'dropped')));
            out.appendChild(el('span', '', ' ' + t.words + (t.out ? ' · out ' + t.out : '')));
            if (t.rule) out.appendChild(noI18n(el('div', 'mono small muted', 'decided by: ' + t.rule)));
          }).catch(function (e) { clear(out); out.appendChild(el('span', 'bad', String(e.message || e))); })
          .then(function () { busy(go, false); });
      };
      grid.appendChild(formField('To', dst));
      grid.appendChild(formField('Protocol', sel));
      grid.appendChild(formField('Port', port));
      c.appendChild(grid);
      var row = el('div', 'btnrow'); row.appendChild(go); row.appendChild(spoof); c.appendChild(row);
      c.appendChild(out);
      return c;
    }
    function linesBlock() {
      var det = el('details', 'gwd-lines');
      det.appendChild(el('summary', '', 'What root puts in for ' + x.name + ' (iptables, FAKE-IGD-FWD)'));
      var lines = (ED.preview && ED.preview.lines) || x.lines || [];
      det.appendChild(noI18n(el('pre', 'mono small', lines.join('\n') + '\n# ... then the drops toward every local and private network, the internet line above, and at the end:\n-A FAKE-IGD-FWD -m comment --comment "fake-igd: nothing else is forwarded" -j DROP')));
      return det;
    }
    function paint() {
      if (!host.body) return;
      var open = host.body.querySelector('details.gwd-lines');
      var wasOpen = open && open.open;
      var dstWas = host.body.querySelector('.gwd-try input');
      clear(host.body);
      if (!ADMIN) host.body.appendChild(el('p', 'note info', 'Read-only: what is set for ' + x.name + ' now. A full administrator changes it here or in Settings → Gateway for devices.'));
      host.body.appendChild(flow());
      host.body.appendChild(host.err);
      if ((x.left_out || []).length && !ED.dirty) host.body.appendChild(el('p', 'note bad', 'Left out by root: ' + x.left_out.join('; ')));
      var two = el('div', 'gwd-two');
      two.appendChild(dnsCard());
      two.appendChild(rulesCard());
      host.body.appendChild(two);
      if (ADMIN) {
        var t = tryCard();
        if (dstWas && dstWas.value) t.querySelector('input').value = dstWas.value;
        host.body.appendChild(t);
      }
      var ln = linesBlock();
      if (wasOpen) ln.open = true;
      host.body.appendChild(ln);
    }
    modal('The firewall of ' + x.name, function (body) {
      host.body = body;
      host.err = el('p', 'note bad gwd-err');
      paint();
      setTimeout(function () { body.scrollTop = 0; }, 60);
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'check', admin: true, go: function (button) {
          busy(button, true);
          api('gateway', {action: 'designer_save', id: x.id, dns: ED.dns.map(function (y) { return {ip: y.ip, dot: y.dot}; }),
                          rules: ED.rules.map(function (r) { return {id: r.id, to: r.to, proto: r.proto, ports: r.ports, comment: r.comment, on: r.on}; })})
            .then(function (r) {
              closeModal(); toast(r.message, 'good');
              if (typeof opts.saved === 'function') setTimeout(opts.saved, 600);
              if (typeof window.gwTrialsLoad === 'function') setTimeout(window.gwTrialsLoad, 2500);
            })
            .catch(function (e) { host.err.textContent = String(e.message || e); })
            .then(function () { busy(button, false); });
        }}], 'large');
  }
  window.GW_DESIGNER = openDesigner;
  window.GW_DESIGNER_OPEN = function (key, opts) {
    return api('gateway').then(function (d) {
      var x = (d.devices || []).filter(function (y) { return y.id === key || y.ip === key; })[0];
      if (!x) { toast('that device is no longer in Gateway for devices', 'bad'); return; }
      openDesigner(x, d, opts);
    }).catch(oops);
  };
}());
