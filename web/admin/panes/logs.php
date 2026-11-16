<?php /* Settings → Logs and state (otp's pane "logs": the card of this server - its files and the disk
   they are on - above the settings). */ ?>
  <div class="ctl-pane" id="pane-logs" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Logs and state</h2>
      <p class="ctl-lede">What fake-igd writes and where: its log, the log of every request, the mappings the
        clients hold and the database of these pages - how big each is, and how full the disk they are on.
        The files are moved on the server only (<span class="mono">sudo upnp config set</span>): the service's
        sandbox needs to know the new place too. How long the logs are kept is under Disks and logs.</p></div>
    <div id="ls-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-logs"></div></div>
  </div>
