/* pane-acme.js - Settings → Automatic certificates (otp's loadAcme, drawAcme, acmeDnsGuide -
   for one server: one certificate, no VIP address, no cluster). */
(function () {
  'use strict';
  var AC = {d: null, poll: null, probe: null, logPage: 0, out: false};
  var AC_DNS = {at: 0, rows: null, own: null};

  function loadAcme() {
    api('acme').then(function (d) { AC.d = d; drawAcme(); acPoll(d.work && d.work.busy); }).catch(oops);
  }
  PANE_LOAD.acme = loadAcme;
  PANE_TICK.acme = function () {
    if (AC.poll || AC.out || ($('modal') && !$('modal').hidden)) return;
    AC.out = true;
    api('acme').then(function (d) { AC.d = d; drawAcme(); }).catch(function () {}).then(function () { AC.out = false; });
  };
  function acPoll(on) {
    if (on && !AC.poll) AC.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'acme') { acPoll(false); return; }
      api('acme').then(function (d) { AC.d = d; drawAcme(); if (!(d.work && d.work.busy) && !d.manual) acPoll(false); }).catch(function () {});
    }, 2000);
    if (!on && AC.poll) { clearInterval(AC.poll); AC.poll = null; }
  }

  /* otp's nodeCard, nodeBig, netFacts, nodeSaid - the shapes the card is drawn with. */
  function nodeCard(name, dot, tag, tagCls) {
    var c = el('div', 'card ntp-node');
    var head = el('div', 'pw-head');
    head.appendChild(el('span', 'dot ' + dot));
    head.appendChild(noI18n(el('b', '', name)));
    head.appendChild(el('span', 'tag info', 'this page'));
    if (tag) head.appendChild(el('span', 'tag ' + (tagCls || 'dim'), tag));
    c.appendChild(head);
    return c;
  }
  function nodeBig(c, value, words) {
    var big = el('div', 'ntp-big');
    big.appendChild(noI18n(el('span', 'ntp-off', value)));
    if (words) big.appendChild(el('span', 'muted small', ' ' + words));
    c.appendChild(big);
  }
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
  function nodeSaid(got, words) {
    var p = el('div', 'node-said ' + (got.ok ? 'ok' : 'bad'));
    p.appendChild(el('span', 'dot ' + (got.ok ? 'ok' : 'bad')));
    var t = el('div');
    t.appendChild(el('b', '', got.error ? 'It did not go' : words));
    if (got.error) t.appendChild(noI18n(el('div', 'small muted', got.error)));
    t.appendChild(el('div', 'small muted', ago(got.at)));
    p.appendChild(t);
    return p;
  }
  function dateOf(ts) { return ts ? new Date(ts * 1000).toLocaleDateString(numLang()) : ''; }

  function drawAcme() {
    var real = $('ac-host');
    if (!real || !AC.d) return;
    liveFill(real, function (host) {
      var d = AC.d;
      if (!d.on) host.appendChild(el('p', 'note', 'Off - switch it on below, say which names and the CA, and save.'));
      if (d.work && d.work.busy) {
        var g = el('div', 'going wide');
        g.innerHTML = '<div class="bar"><span style="width:60%"></span></div>';
        var w = el('div', 'says');
        w.appendChild(noI18n(el('b', '', (d.names || []).join(', '))));
        w.appendChild(document.createTextNode(': '));
        w.appendChild(el('span', '', d.work.says || 'ordering…'));
        g.appendChild(w);
        host.appendChild(g);
      }
      /* By hand (DNS-01): the record to put in, and the order waiting for it. */
      if (d.manual) {
        var mc = el('div', 'card full ac-manual');
        mc.appendChild(el('h2', '', 'Put this TXT record in DNS'));
        mc.appendChild(el('p', 'note warn', 'The order waits for it - up to an hour. Put it in, wait until DNS carries it, then say so. Take it away again once the certificate has come.'));
        mc.appendChild(netFacts([['Name', d.manual.rr, true], ['Type', 'TXT', true], ['Value', d.manual.txt, true], ['TTL', '60', true]]));
        var mr = el('div', 'btnrow');
        var cp = cmdButton('Copy the value', 'copy', 'small');
        cp.onclick = function () { copyText(d.manual.txt); };
        var dn = cmdButton('It is in DNS', 'check', 'small primary');
        dn.disabled = !!d.manual.done || !d.may;
        dn.onclick = function () { api('acme', {action: 'manual_done'}).then(function (x) { AC.d = x; drawAcme(); acPoll(true); }).catch(oops); };
        var gv = cmdButton('Give the order up', 'close', 'small');
        gv.disabled = !d.may;
        gv.onclick = function () { api('acme', {action: 'manual_drop'}).then(function (x) { AC.d = x; drawAcme(); }).catch(oops); };
        mr.appendChild(cp); mr.appendChild(dn); mr.appendChild(gv);
        mc.appendChild(mr);
        host.appendChild(mc);
      }
      var grid = el('div', 'pw-grid node-grid');
      var t = d.card || {};
      var st = t.state || {};
      var left = t.not_after ? Math.floor((t.not_after - Date.now() / 1000) / 86400) : null;
      var acme = t.how === 'ACME';
      var dot = !acme ? 'dim' : (st.ok === false ? 'warn' : (left !== null && left < 14 ? 'warn' : 'ok'));
      var c = nodeCard((d.names || [])[0] || 'these pages', dot,
        acme ? (st.ok === false ? 'the last try failed' : 'from the CA') : (t.not_after ? 'not from the CA' : 'no certificate'),
        acme ? (st.ok === false ? 'warn' : 'ok') : 'dim');
      var care = el('span', 'tag ' + (t.care && t.wanted ? 'info' : 'dim'),
        !t.wanted ? 'no name yet' : (t.care ? 'ACME renews it' : 'its own certificate is kept'));
      explain(care, !t.wanted ? 'The names of the certificate (Settings below) are empty, and nginx\'s server_name has no full DNS name.'
        : (t.care ? 'Renewed by ACME before it runs out. A certificate put in by hand on Certificates and TLS takes it out of ACME’s care.'
          : 'The certificate put in on Certificates and TLS (uploaded, from a request, self-signed) stays: ACME does not replace it. Look after it, or Order it now, gives it to ACME.'));
      c.querySelector('.pw-head').appendChild(care);
      nodeBig(c, left !== null ? num(left) : '–', left !== null ? 'days left' : '');
      var due = t.due ? t.due : (acme && t.ari && t.ari.pick ? 'renewed at ' + stamp(t.ari.pick) + ' (the CA\'s window)' : '');
      c.appendChild(netFacts([
        ['For', (d.names || []).join(', '), true],
        ['The names', d.names_from === 'nginx' ? 'from nginx\'s server_name' : (d.names_from === 'setting' ? 'as given (The names of the certificate)' : 'none yet')],
        ['Issued by', t.issuer || '', true], ['Keys', t.keys || '', true],
        ['Good until', dateOf(t.not_after)],
        ['Last ordered', st.ordered_at ? ago(st.ordered_at) : 'never'],
        ['Next', d.on ? (due || (acme ? 'when fewer than ' + (AC.d.days || 30) + ' days are left' : '–')) : 'off']
      ]));
      /* Where the names come from, said plainly (a CNAME made for another name than nginx's
         server_name fails with NXDOMAIN, and nothing on the page said which name was ordered). */
      if (d.names_from === 'nginx') c.appendChild(el('p', 'note warn small', 'The names are taken from nginx\'s server_name: ' + (d.names || []).join(', ') + ' - The names of the certificate is empty. If that is not the name your DNS has, give the right one (Its names…).'));
      else if (!d.names_from) c.appendChild(el('p', 'note warn small', 'No name: The names of the certificate is empty, and nginx\'s server_name has no full DNS name - give them (Its names…).'));
      if (st.ok === false && st.said && !(d.work && d.work.busy)) c.appendChild(nodeSaid({ok: false, error: st.said, at: st.failed_at}, ''));
      if ((st.steps || []).length) {
        var det = el('details', 'acme-steps-done');
        det.appendChild(el('summary', 'small muted', 'What the last order did'));
        stepsInto(det, st.steps);
        c.appendChild(det);
      }
      var pr = AC.probe;
      if (pr) c.appendChild(nodeSaid({ok: pr.ok, at: pr.at, error: pr.ok ? '' : pr.said}, 'Port 80 answers as the CA will ask it'));
      var tr = d.tls_root;
      if (tr && tr.state === 'failed') c.appendChild(nodeSaid({ok: false, at: tr.at, error: 'root could not put it in: ' + ((tr.said || []).slice(-1)[0] || '')}, ''));
      if (d.may) {
        var row = el('div', 'btnrow');
        var probe = cmdButton('Try port 80', 'play', 'small');
        probe.hidden = d.challenge === 'dns-01';
        var first = (d.names || []).filter(function (n) { return n.indexOf('*.') !== 0; })[0];
        explain(probe, first ? 'http://' + first + '/.well-known/acme-challenge/ asked from this server, as the CA will ask it - whether it reaches fake-igd. A firewall in front of the server may still stop the CA from outside.'
          : 'The names of the certificate are not known yet: give them in Settings below (or Its names…).');
        probe.disabled = !first;
        probe.onclick = function () {
          busy(probe, true);
          api('acme', {action: 'probe'}).then(function (x) {
            busy(probe, false); AC.probe = x; drawAcme();
          }).catch(function (e) { busy(probe, false); oops(e); });
        };
        var order = cmdButton('Order it now', 'download', 'small primary');
        order.disabled = !d.on || !t.wanted || (d.work && d.work.busy);
        explain(order, !d.on ? 'Switch it on below first.' : (!t.wanted ? 'Give its names first (Its names…).'
          : 'Ordered from the CA now and put in nginx by root. ACME renews it from then on.'));
        order.onclick = function () {
          var go = function () {
            busy(order, true);
            api('acme', {action: 'order'}).then(function (x) { busy(order, false); toast(x.message, 'good'); AC.d = x; drawAcme(); acPoll(true); })
              .catch(function (e) { busy(order, false); oops(e); });
          };
          if (t.not_after && !acme) {
            confirmThen('Replace the certificate of these pages?',
              'It has one put in on Certificates and TLS' + (t.issuer ? ' (' + htmlText(t.issuer.replace(/^CN=/, '').split(',')[0]) + ')' : '') + '. The one from the CA takes its place once it comes, and ACME renews it from then on - the one it has now is kept to go back to. Its TLS settings stay as they are.',
              'Order it', go, false);
          } else go();
        };
        var cb = cmdButton(t.care ? 'Leave it alone' : 'Look after it', t.care ? 'cancel' : 'refresh', 'small');
        cb.disabled = !t.wanted;
        explain(cb, t.care ? 'ACME stops renewing this one; the certificate it has stays.'
          : 'ACME renews this one from now on - at the next look (within the hour) if it is not from the CA yet.');
        cb.onclick = function () {
          busy(cb, true);
          api('acme', {action: 'care', on: !t.care}).then(function (x) { AC.d = x; drawAcme(); })
            .catch(function (e) { busy(cb, false); oops(e); });
        };
        var nm = cmdButton('Its names…', 'edit', 'small');
        explain(nm, 'The DNS names the certificate is for. Empty: the full DNS names in nginx\'s server_name' + ((d.names_nginx || []).length ? ' (' + d.names_nginx.join(', ') + ')' : '') + '.');
        nm.onclick = function () { acmeNameAsk(d); };
        row.appendChild(probe); row.appendChild(order); row.appendChild(cb); row.appendChild(nm);
        if (t.before && !t.before.ran_out) row.appendChild(acmePutBackButton(t.before));
        c.appendChild(row);
      }
      grid.appendChild(c);
      host.appendChild(grid);
      if (d.on && d.dns_guide) host.appendChild(acmeDnsGuide(d));
      if (d.account && d.account.kid) {
        var a = el('p', 'muted small', 'The account at the CA: ');
        a.appendChild(noI18n(el('span', 'mono', d.account.kid)));
        if (d.account.key) a.appendChild(noI18n(el('span', '', ' · ' + d.account.key)));
        host.appendChild(a);
      }
    }, undefined, function () { explainWhatWasDrawn($('pane-acme')); });
    drawLog();
  }

  function stepsInto(box, steps) {
    var t0 = steps[0][0];
    steps.forEach(function (x) {
      var r = el('div', 'acme-step small');
      r.appendChild(noI18n(el('span', 'muted mono acme-step-t', '+' + Math.round(x[0] - t0) + ' s')));
      r.appendChild(el('span', 'acme-step-w', x[1]));
      box.appendChild(r);
    });
  }

  /* The orders, newest first: a page of 20 at a time, drawn whole (no box of its own that scrolls). */
  var LOG_PER = 20;
  function drawLog() {
    var host = $('ac-log');
    if (!host || !AC.d) return;
    var rows = AC.d.log || [];
    var pages = Math.max(1, Math.ceil(rows.length / LOG_PER));
    if (AC.logPage >= pages) AC.logPage = pages - 1;
    var said = $('ac-log-said');
    if (said) said.textContent = rows.length ? rows.length + (rows.length === 1 ? ' order' : ' orders') : '';
    liveFill(host, function (box) {
      var some = rows.slice(AC.logPage * LOG_PER, (AC.logPage + 1) * LOG_PER);
      var tbl = listTable(['When', 'How it went', 'For', 'By', {words: 'Took', cls: 'num'}, 'Good until'], some, function (r) {
        var tr = el('tr', 'clickable');
        tr.appendChild(stampCell(r.at));
        var ok = el('td');
        ok.appendChild(el('span', 'tag ' + (r.ok ? 'ok' : 'warn'), r.ok ? 'came' : 'failed'));
        if (!r.ok && r.said) ok.appendChild(noI18n(el('span', 'muted small', ' ' + String(r.said).slice(0, 90))));
        tr.appendChild(ok);
        tr.appendChild(noI18n(el('td', 'mono small', (r.names || []).join(', '))));
        tr.appendChild(noI18n(el('td', 'small', r.by || '')));
        tr.appendChild(el('td', 'num', r.took !== undefined ? num(Math.round(r.took)) + ' s' : ''));
        tr.appendChild(el('td', 'small', r.not_after ? dateOf(r.not_after) : '–'));
        tr.onclick = function () { logPeek(r); };
        return tr;
      }, 'plain|No certificate has been ordered yet', {own: true});
      box.appendChild(tbl);
      if (rows.length > LOG_PER) {
        var pg = el('div', 'pager');
        box.appendChild(pg);
        pager(pg, AC.logPage, LOG_PER, rows.length, function (p) { AC.logPage = p; drawLog(); });
      }
    });
  }
  function logPeek(r) {
    modal('The order of ' + new Date(r.at * 1000).toLocaleString(numLang()), function (body) {
      body.appendChild(kvTable([['How it went', r.ok ? 'the certificate came' : 'it failed'],
                                ['For', (r.names || []).join(', ')], ['Asked by', r.by || ''],
                                ['The CA', r.ca || ''], ['Checked by', r.challenge || ''],
                                ['Issued by', r.issuer || '–'], ['Keys', r.keys || '–'],
                                ['Good until', r.not_after ? stamp(r.not_after) : '–'],
                                ['Took', (r.took || 0) + ' s']].concat(r.ok ? [] : [['Why', r.said || '']])));
      if ((r.steps || []).length) {
        body.appendChild(el('h4', 'tls-h', 'Step by step'));
        var box = el('div', 'acme-steps-done');
        stepsInto(box, r.steps);
        body.appendChild(box);
      }
    }, [{words: 'Close', close: true}], 'medium');
  }

  function acmePutBackButton(before) {
    var b = cmdButton('Back to the one before…', 'undo', 'small');
    var words = (before.issuer || '').replace(/^CN=/, '').split(',')[0];
    explain(b, 'The certificate it had before ACME replaced it' + (words ? ' - from ' + words : '') + (before.not_after ? ', good until ' + dateOf(before.not_after) : '') + '. Put back as it was; ACME no longer renews it. The TLS settings stay.');
    b.onclick = function () {
      confirmThen('Put the certificate from before ACME back?', 'The one from the CA is taken out and the one it had before - ' + htmlText(words || before.how || '') + ' - put back. ACME no longer renews it (Look after it gives it back).', 'Put it back', function () {
        busy(b, true);
        api('acme', {action: 'put_back'}).then(function (x) { toast(x.message, 'good'); AC.d = x; drawAcme(); })
          .catch(function (e) { busy(b, false); oops(e); });
      }, false);
    };
    return b;
  }

  function acmeNameAsk(d) {
    var box;
    modal('The names of the certificate', function (body) {
      body.appendChild(el('p', 'note', 'The full DNS names it is for - the first goes into the certificate as its name (CN), all of them in its alternative names (SAN). The CA gives it only for names that point at this server (HTTP-01) or whose TXT records can be put in (DNS-01).'));
      box = textBox(d.names_given ? (d.names || []).join(', ') : '', (d.names_nginx || []).join(', ') || 'igd.example.cz', 'mono');
      box.autocomplete = 'off';
      body.appendChild(formField('DNS names', box, 'By commas. Empty: the full DNS names in nginx\'s server_name.'));
      setTimeout(function () { box.focus(); }, 60);
    }, [{words: 'Close', close: true}, {words: 'Keep it', cls: 'primary', icon: 'save', go: function (b) {
      busy(b, true);
      api('acme', {action: 'names', names: box.value.trim()}).then(function (x) {
        closeModal(); AC.d = x; drawAcme(); toast('kept', 'good'); loadSettings();
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  }

  var ACME_DNS_STEPS = {
    'http-01': ['Each name points at the address that reaches port 80 of this server - from the internet, or from your own CA.',
                'Port 80 is open to it - the firewall in front of the server, and this server\'s own.',
                'Try port 80 on the card, then Order it now.'],
    desec: ['Sign up at desec.io (free) and confirm the mail.',
            'Add a domain there: a free one - yourname.dedyn.io - or one of your own whose DNS is at deSEC.',
            'Token management: make a token. Give it below as The deSEC API token, with The domain at deSEC, and save.',
            'In the DNS of your own domain put the CNAME records below - once; they stay for every renewal.',
            'Check DNS here, then Order it now. Renewals go by themselves.'],
    cloudflare: ['A token at Cloudflare (My Profile → API Tokens) with Zone - DNS - Edit for the zone, given below.',
                 'Where the DNS of your domain is not at Cloudflare: a zone that is, as The TXT records go into, and the CNAME records below in your DNS.',
                 'Order it now. Renewals go by themselves.'],
    rfc2136: ['A TSIG key the DNS server lets update the _acme-challenge records (tsig-keygen), given below with the server and the zone.',
              'With The TXT records go into: the CNAME records below in your DNS, and the key allowed in that zone.',
              'Order it now. Renewals go by themselves.'],
    acmedns: ['Register at the acme-dns server (POST /register) - it gives a user, a key and a subdomain; give them below.',
              'In your DNS put the CNAME records below - once.',
              'Check DNS here, then Order it now. Renewals go by themselves.'],
    manual: ['At every order - renewals too - the TXT record is shown here: put it in your DNS, then say It is in DNS.',
             'Better: a CNAME once in your DNS to a zone fake-igd can write to (deSEC is free) - then nothing is by hand any more.']
  };
  function acmeDnsGuide(d) {
    var g = d.dns_guide;
    var key = g.challenge === 'http-01' ? 'http-01' : g.dns;
    var card = el('div', 'card full acme-dns');
    card.appendChild(el('h2', '', 'In your DNS'));
    card.appendChild(el('p', 'note', g.challenge === 'http-01'
      ? 'HTTP-01: the CA asks port 80 of each name - so each name points at this server, and port 80 is open to the CA.'
      : (g.dns === 'manual' ? 'DNS-01 by hand: the CA reads a TXT record you put in at every order.'
        : 'DNS-01: the CA reads a TXT record fake-igd puts in. What has to be in your DNS for it - once - is below.')));
    if (g.names_from === 'nginx') card.appendChild(el('p', 'note warn', 'For ' + (d.names || []).join(', ') + ' - the names in nginx\'s server_name, as The names of the certificate is empty. A record made for another name does not count: give that name in The names of the certificate.'));
    var ol = el('ol', 'acme-steps');
    (ACME_DNS_STEPS[key] || []).forEach(function (w) { ol.appendChild(el('li', '', w)); });
    card.appendChild(ol);
    var checked = AC_DNS.rows && Date.now() / 1000 - AC_DNS.at < 600 ? AC_DNS.rows : null;
    var rows = (g.rows || []).map(function (r, i) {
      var c = checked && checked[i] && checked[i].record === r.record ? checked[i] : {};
      return Object.assign({}, r, {ok: c.ok, said: c.said});
    });
    var t = listTable([{words: 'Certificate', cls: 'dw-c'}, {words: 'Record', cls: 'dw-r'}, {words: 'Type', cls: 'dw-t'},
                       {words: 'Points at / value', cls: 'dw-v'}, {words: 'In DNS now', cls: 'dw-s'}], rows, function (r) {
      var tr = el('tr');
      tr.appendChild(r.zone ? el('td', '', 'its zone at deSEC') : noI18n(el('td', '', r.name)));
      var pair = function (text, under) {
        var td = el('td', 'mono small dns-cell'), box = el('div', 'dns-val');
        var tx = noI18n(el('span', 'dns-t', text));
        tx.title = text;
        box.appendChild(tx);
        var b = iconButton('copy', 'Copy');
        b.onclick = function () { copyText(text, b); };
        box.appendChild(b);
        td.appendChild(box);
        if (under) td.appendChild(el('div', 'muted dns-under', under));
        tr.appendChild(td);
      };
      var lone = function (words) {
        var td = el('td', 'mono small');
        td.appendChild(el('span', 'muted', words || ''));
        tr.appendChild(td);
      };
      if (r.record) pair(r.record); else lone(r.why);
      tr.appendChild(noI18n(el('td', 'mono small', r.type || '')));
      if (r.type === 'CNAME' || r.type === 'NS' || (r.type === 'A' && r.value))
        pair(r.value, r.type === 'A' ? 'or the public address in front of it' : '');
      else lone(r.type === 'TXT' ? (r.value || r.why) : '');
      var st = el('td', 'small');
      if (r.check) {
        if (r.ok === undefined) st.appendChild(el('span', 'muted', 'not checked yet'));
        else {
          st.appendChild(el('span', 'tag ' + (r.ok ? 'ok' : 'warn'), r.ok ? 'there' : 'not yet'));
          if (r.said && !r.ok) st.appendChild(el('div', 'muted', r.said));
        }
      } else st.appendChild(el('span', 'muted', r.type === 'TXT' && !r.value ? 'fake-igd puts it in' : '–'));
      tr.appendChild(st);
      return tr;
    }, 'plain|No name to order it for yet', {own: true});
    card.appendChild(t);
    var row = el('div', 'btnrow');
    var chk = cmdButton('Check DNS', 'search', 'small');
    explain(chk, 'Each record looked up from this server now, through its DNS servers - as the CA will look. A record just put in may take a while to show (its TTL).');
    chk.disabled = !(g.rows || []).some(function (r) { return r.check; }) || !d.may;
    chk.onclick = function () {
      busy(chk, true);
      api('acme', {action: 'dns_check'}).then(function (x) {
        AC_DNS = {at: Date.now() / 1000, rows: x.rows, own: x.own_resolvers};
        busy(chk, false); drawAcme();
      }).catch(function (e) { busy(chk, false); oops(e); });
    };
    row.appendChild(chk);
    if (checked && AC_DNS.own === false) {
      card.appendChild(el('p', 'note warn small', 'Checked with this machine’s DNS servers - inside your network they may see what the internet does not. Set DNS servers for ACME (below) to public ones, 1.1.1.1, 9.9.9.9, to see what the CA sees.'));
    }
    if (checked) {
      var when = el('span', 'muted small');
      when.appendChild(el('span', '', 'checked'));
      when.appendChild(document.createTextNode(' '));
      when.appendChild(el('span', '', ago(AC_DNS.at)));
      row.appendChild(when);
    }
    card.appendChild(row);
    return card;
  }
  /* The names' setting says what an empty box means here and now: the names nginx's server_name
     has - in its placeholder and under it. */
  function namesHint() {
    var box = $('set-acme_names'), item = document.querySelector('.set-item[data-key="acme_names"]');
    if (!box || !item || !AC.d) return;
    var ng = AC.d.names_nginx || [];
    box.placeholder = ng.length ? 'empty = the names in nginx\'s server_name: ' + ng.join(', ')
      : 'empty = nginx\'s server_name - it has no full DNS name';
    var tail = item.querySelector('.set-tail') || item;
    var was = tail.querySelector('.acme-names-now');
    if (was) was.remove();
    if (!AC.d.names_given) tail.appendChild(el('div', 'says acme-names-now', ng.length
      ? 'Now empty: the certificate is for ' + ng.join(', ') + ' - from nginx\'s server_name.'
      : 'Now empty, and nginx\'s server_name has no full DNS name: nothing can be ordered.'));
  }
  (function () {
    var theirs = drawSettings;
    drawSettings = function () {
      var r = theirs.apply(this, arguments);
      try { namesHint(); } catch (e) { /* as the settings code drew it */ }
      return r;
    };
  }());
  var theirDraw = drawAcme;
  drawAcme = function () { var r = theirDraw.apply(this, arguments); try { namesHint(); } catch (e) { /* later */ } return r; };
}());
