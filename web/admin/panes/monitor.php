<?php /* Settings → Monitoring (as otp's): Prometheus' /metrics and SNMPv3 (1.7.2). */ ?>
  <div class="ctl-pane" id="pane-monitor" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Monitoring</h2>
      <p class="ctl-lede">Prometheus asks this machine for its metrics at <code>https://SERVER/metrics</code>:
        the requests and the ports asked for, the devices, the mappings, the mDNS services, the services' states,
        the disks, the memory and the load, the mail, the alerts open now. And SNMPv3: this machine answers it
        itself, and sends traps when something is wrong.</p></div>
    <div class="card full"><h2>Settings</h2><div id="sect-monitor"></div></div>
    <div id="snmp-host"></div>
    <div id="mon-host"></div>
  </div>
