<?php /* Settings → Firewall and access (otp's pane "fw"): who may reach the pages, and the firewall. */ ?>
  <div class="ctl-pane" id="pane-web" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Firewall and access</h2>
      <p class="ctl-lede">Who may reach which pages, and the machine's own firewall: what fake-igd's
        functions need is let in by itself (SSDP and SOAP for the PS5, the pages, SSH), and you add
        whatever else you want - for IPv4 and IPv6. Every change goes back by itself unless kept.</p></div>
    <div class="card full">
      <h2>Who may reach the pages</h2>
      <p class="note">The administration and the health check share ports 80 and 443, so who sees
        which is said by nginx, page by page; the firewall below opens the ports only to these networks.
        The machine itself is always let in.</p>
      <div id="fw-access"></div>
    </div>
    <div class="card full">
      <div class="fw-top"><div><h2>The firewall (iptables / ip6tables)</h2>
        <p class="note" id="fw-lede"></p></div>
        <div id="fw-master"></div></div>
      <div id="fw-body"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Settings</h2><div id="sect-web"></div></div>
  </div>
