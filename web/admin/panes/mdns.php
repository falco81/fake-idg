<?php /* Settings → mDNS reflector (avahi) (otp's panes that set a system file through root - Time, SSH
   server: the card of this server - what the daemon runs with now - then what is set, then the copies). */ ?>
  <div class="ctl-pane" id="pane-mdns" hidden>
    <div class="ctl-head"><h2 class="ctl-title">mDNS reflector (avahi)</h2>
      <p class="ctl-lede">avahi-daemon with <span class="mono">enable-reflector=yes</span> repeats mDNS (Bonjour,
        AirPlay, Chromecast, printers, the PS5's Remote Play) between this server's networks. What is set here is
        put in by root into <span class="mono">/etc/avahi/avahi-daemon.conf</span> line by line - its comments
        stay, a copy is kept beside it - and avahi-daemon is restarted; when it does not come up with the change,
        the copy is put back by itself. The same as <span class="mono">sudo upnp mdns ...</span>.</p></div>
    <div id="av-host"></div>
    <div class="card full" id="av-set"><h2>What is set <span class="right muted small" id="av-file"></span></h2>
      <div id="sect-mdns"></div></div>
    <div id="av-copies"></div>
  </div>
