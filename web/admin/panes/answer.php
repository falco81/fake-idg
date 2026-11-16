<?php /* Settings → How it answers (otp's pane "radius": the settings, with the card of this server
   above them as otp's Disks and logs / Time have it, and a test as otp's mail test). */ ?>
  <div class="ctl-pane" id="pane-answer">
    <div class="ctl-head"><h2 class="ctl-title">How it answers</h2>
      <p class="ctl-lede">fake-igd answers like a UPnP router - and opens nothing. What a PS5 asks for is
        only written down. A change here restarts fake-igd.service; the PS5 notices nothing but a moment
        of silence.</p></div>
    <div id="ua-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-answer"></div></div>
    <div class="card full">
      <h2>Try it <span class="right muted small" id="ua-said"></span></h2>
      <p class="note">Asks fake-igd from this server the way a PS5 asks a router, and shows every step: the
        SSDP search on the network (and another UPnP router, should one answer too), the device description,
        its WANIPConnection service, GetStatusInfo and the public IP it reports - and, chosen, an
        AddPortMapping of port 9 and its DeletePortMapping (written down as <span class="mono">upnp-cli-test</span>,
        left out of the ports). Save the changes first.</p>
      <div class="btnrow admin-only filters">
        <select id="ua-add">
          <option value="">the search, the description and the public IP</option>
          <option value="udp">… and a test AddPortMapping, UDP</option>
          <option value="tcp">… and a test AddPortMapping, TCP</option>
        </select>
        <button class="btn cmd primary" id="ua-try" data-icon="play">Try it</button>
      </div>
      <div id="ua-steps"></div>
    </div>
  </div>
