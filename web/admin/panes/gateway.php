<?php /* Settings → Gateway for devices (1.7.15): this server as the default gateway of chosen devices -
         a PS5 asks UPnP only of its gateway. Drawn by pane-gateway.js; root's part deploy/root_gateway.py. */ ?>
  <div class="ctl-pane" id="pane-gateway" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Gateway for devices</h2>
      <p class="ctl-lede">A PS5 asks UPnP only of its <b>default gateway</b>. With the real router as its gateway it
        searches, hears fake-igd's answer and goes no further - it never fetches the description and never asks
        for a port. Here this server becomes the gateway of the devices you choose, and forwards their traffic to
        the router: only theirs, only toward the router - never to another network of this server, which stays no
        bridge between its networks. Nothing is forwarded by default.</p></div>
    <div id="gw-host"></div>
  </div>
