<?php /* Settings → MikroTik (1.8.2; configuration only since 1.9.2): how the real router is read - READ-ONLY -
         as isemon reads one. What was read (each device's way out, its ports, the whole firewall) is on the
         main menu: Gateway → MikroTik (mt-view.js). Drawn by pane-mikrotik.js; the API's part
         src/api_mikrotik.py, igd_mikrotik.py, igd_mtcheck.py, igd_mtpath.py. */ ?>
  <div class="ctl-pane" id="pane-mikrotik" hidden>
    <div class="ctl-head"><h2 class="ctl-title">MikroTik</h2>
      <p class="ctl-lede">fake-igd answers a PS5's UPnP and opens nothing - the real router does. Here: how the
        MikroTik is reached and trusted. What it says - each device's way out to the internet and the public
        address it goes out as, whether it carries every port a device asked for, its whole firewall - is on the
        main menu, <b>Gateway → MikroTik</b>. <b>Read-only</b>: fake-igd only ever asks it to print.</p></div>
    <div id="mt-hero"></div>
    <div class="card full mt-conn">
      <h2>Reading the MikroTik <span class="right muted small" id="mt-conn-said"></span></h2>
      <p class="note">Its own connection, its own account that may only read, and its own settings - nothing is ever
        written to the router from here. REST (RouterOS 7), the RouterOS API (api-ssl) or ssh; the certificate or the
        host key trusted here after you have seen it.</p>
      <div id="sect-mikrotik"></div>
      <div id="mt-trust"></div>
    </div>
  </div>
