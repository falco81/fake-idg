<?php /* Settings → Backups (otp's pane `backup`: everything, locked, to another machine - and back). */ ?>
  <div class="ctl-pane" id="pane-backup" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Backups</h2>
      <p class="ctl-lede">A backup is everything: the whole database (the accounts, the events, every setting
        saved on these pages, these destinations), this machine's config.json, and what only root may read -
        avahi-daemon.conf, nginx's fake-igd.conf, the certificate and key of the pages, the journal's and
        logrotate's limits, fake-igd's lines of the firewall - with RESTORE.md, the exact steps to bring it all
        back on a machine installed from nothing. Locked with the password below; sent to every destination
        switched on - a folder, FTP, FTPS, SFTP, SCP or a Windows/Samba share.</p></div>
    <div id="rb-top"></div>
    <div class="card full" id="rb-tried-card" hidden><h2>Backups tried <span class="right" id="rb-tried-tools"></span></h2><div id="rb-tried"></div></div>
    <div class="card full"><h2>When, how many, and the password</h2><div id="sect-backup"></div></div>
    <div class="card full"><h2>Where they go <span class="right" id="rb-add-host"></span></h2>
      <div id="rb-targets"></div></div>
    <div class="card full"><h2>What was sent <span class="right" id="rb-runs-tools"></span></h2><div id="rb-runs"></div></div>
  </div>
