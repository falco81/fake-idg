<?php /* Settings → the pane service (moved out of index.php, 1.6.1). */ ?>
  <div class="ctl-pane" id="pane-service" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The service</h2>
      <p class="ctl-lede">fake-igd.service, which answers the network. These pages and their API are
        a service of their own (fake-igd-api) and stay while it restarts.</p></div>
    <div class="card full"><div id="sv-state"></div>
      <div class="btnrow admin-only" style="margin-top:14px">
        <button class="btn cmd" id="sv-restart" data-icon="undo">Restart fake-igd.service</button>
        <button class="btn cmd" id="sv-apply" data-icon="wall">Put the allow list and the firewall in place again</button>
      </div></div>
  </div>
