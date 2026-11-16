<?php /* Settings → the pane mdns (moved out of index.php, 1.6.1). */ ?>
  <div class="ctl-pane" id="pane-mdns" hidden>
    <div class="ctl-head"><h2 class="ctl-title">mDNS reflector (avahi)</h2>
      <p class="ctl-lede">avahi-daemon with <span class="mono">enable-reflector=yes</span> repeats mDNS
        (Bonjour, AirPlay, Chromecast, printers…) between the server's networks. Saved, the change goes into
        <span class="mono">/etc/avahi/avahi-daemon.conf</span> line by line - its comments stay, a copy is
        kept beside it - and avahi-daemon is restarted; when it does not come up with the change, the copy is
        put back. The same as <span class="mono">sudo upnp mdns ...</span>.</p></div>
    <div class="card full" id="av-missing" hidden><div class="offline" id="av-missing-words"></div></div>
    <div class="card full"><div id="sect-mdns"></div></div>
    <div class="card full">
      <h2>avahi-daemon <span class="right" id="av-tools"></span></h2>
      <div id="av-state"><p class="muted">…</p></div>
    </div>
  </div>
