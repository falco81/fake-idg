<?php /* Settings → MikroTik (1.8.2): the real router read - READ-ONLY - as isemon reads one; for every port a
         device asked for, whether the MikroTik carries it; and its whole firewall, IPv4 and IPv6. Drawn by
         pane-mikrotik.js; the API's part src/api_mikrotik.py, igd_mikrotik.py, igd_mtcheck.py. */ ?>
  <div class="ctl-pane" id="pane-mikrotik" hidden>
    <div class="ctl-head"><h2 class="ctl-title">MikroTik</h2>
      <p class="ctl-lede">fake-igd answers a PS5's UPnP and opens nothing - the real router does. Read here, the
        MikroTik says for every port a device asked for whether it carries it: a dst-nat to the device, nothing in
        its filter that drops it, IPv6 let through. And its whole firewall, IPv4 and IPv6, as it is. <b>Read-only</b>:
        fake-igd only ever asks it to print - what is missing is shown as commands for you to type, never sent.</p></div>
    <div id="mt-hero"></div>
    <div class="card full mt-conn">
      <h2>Reading the MikroTik <span class="right muted small" id="mt-conn-said"></span></h2>
      <p class="note">Its own connection, its own account that may only read, and its own settings - nothing is ever
        written to the router from here. REST (RouterOS 7), the RouterOS API (api-ssl) or ssh; the certificate or the
        host key trusted here after you have seen it.</p>
      <div id="sect-mikrotik"></div>
      <div id="mt-trust"></div>
    </div>
    <div id="mt-ports"></div>
    <div id="mt-fw"></div>
  </div>
