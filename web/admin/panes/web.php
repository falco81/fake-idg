<?php /* Settings → Firewall and access (the pane of the firewall and who may reach the pages). */ ?>
  <div class="ctl-pane" id="pane-web" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Firewall and access</h2>
      <p class="ctl-lede">Who may reach these pages (nginx's allow list), and the machine's firewall - as
        otp's: a chain of fake-igd's own, <span class="mono">FAKE-IGD-IN</span>, jumped to first from
        INPUT, with ACCEPT rules only. Anything it does not match goes on to the rules that were there
        before; fake-igd never changes those. Root puts it in place when it is saved.</p></div>
    <div class="card full"><div id="sect-web"></div></div>
    <div class="card full">
      <h2>What root did last <span class="right" id="fw-tools"></span></h2>
      <div id="fw-state"><p class="muted">…</p></div>
    </div>
  </div>

