<?php /* Settings → Network (otp's pane "network", for one server: each interface of this machine). */ ?>
  <div class="ctl-pane" id="pane-net" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Network</h2>
      <p class="ctl-lede">Each interface's address, gateway, DNS servers and - switched on - IPv6, and the host
        name of this machine, as NetworkManager has them. A change is put in by root at once, on trial: the
        connection is brought up with it, and unless somebody presses Keep it in time, the machine goes back
        to exactly what it had by itself.</p></div>
    <div id="net-host"></div>
    <div class="card full fulladmin-only"><h2>Taken back unless kept</h2><div id="sect-net"></div></div>
  </div>
