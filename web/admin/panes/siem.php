<?php /* Settings → Syslog and SIEM (as otp's). */ ?>
  <div class="ctl-pane" id="pane-siem" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Syslog and SIEM</h2>
      <p class="ctl-lede">Every event, every sign-in to these pages and every port asked for - who, from where,
        what was answered - to a syslog server or a SIEM (Graylog, Splunk, Elastic, Wazuh, QRadar, Sentinel), as
        RFC 5424 syslog over UDP, TCP or TLS. Sent by the API's background once a minute; what was sent last is
        remembered for each server, so one that was away gets what it missed. Off until switched on.</p></div>
    <div id="si-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-siem"></div></div>
  </div>
