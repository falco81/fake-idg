<?php /* Settings → Disks and logs (otp's pane `logs`: the file systems, the journal, fake-igd's own logs). */ ?>
  <div class="ctl-pane" id="pane-disks" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Disks and logs</h2>
      <p class="ctl-lede">How full this machine's disks are, and how much the system journal and fake-igd's own
        logs may take - put in by root (the journal's drop-in in <span class="mono">/etc/systemd/journald.conf.d</span>,
        <span class="mono">/etc/logrotate.d/fake-igd</span>) whenever it is changed here, and looked at again every
        six hours.</p></div>
    <div id="lg-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-disks"></div></div>
    <div class="card full">
      <h2>fake-igd’s own logs <span class="right muted small" id="lg-logdir"></span></h2>
      <p class="note">What is in the folder of the logs now - the logs being written and the ones logrotate has
        put aside (<span class="mono">.1</span>, <span class="mono">.2.gz</span> …). They go when there are more of
        them than the settings above keep.</p>
      <div id="lg-files"></div>
    </div>
  </div>
