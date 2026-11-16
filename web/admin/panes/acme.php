<?php /* Settings → Automatic certificates (otp's pane "acme", for one server). Drawn by pane-acme.js. */ ?>
  <div class="ctl-pane" id="pane-acme" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Automatic certificates</h2>
      <p class="ctl-lede">The certificate of these pages ordered from Let's Encrypt or another ACME CA
        and renewed by itself well before it runs out. The CA checks the name by asking it on port 80
        (HTTP-01), or by a record in DNS (DNS-01) for a server it cannot see from the internet.</p></div>
    <div id="ac-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-acme"></div></div>
  </div>
