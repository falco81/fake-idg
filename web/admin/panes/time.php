<?php /* Settings → Time (otp's pane "time", for one server: chrony and the time zone). */ ?>
  <div class="ctl-pane" id="pane-time" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Time</h2>
      <p class="ctl-lede">The logs, the times on these pages and what the PS5 asked when are only as right as
        this machine's clock. It keeps it with chrony; here is how far off it is, which servers it follows,
        and the time servers and the time zone it is set to.</p></div>
    <div id="ntp-host"></div>
    <div class="card full" id="ntp-form">
      <h2>The time servers</h2>
      <div id="sect-time"></div>
      <p class="muted small">Saved with the bar at the bottom; root then puts them in by itself within seconds.</p>
    </div>
  </div>
