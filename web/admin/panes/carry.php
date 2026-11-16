<?php /* Settings → Export and import (otp's pane `carry`: the whole configuration as one file). */ ?>
  <div class="ctl-pane" id="pane-carry" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Export and import</h2>
      <p class="ctl-lede">The whole configuration as one file: the settings (config.json's and every one
        saved on these pages), the accounts of these pages, the destinations of the backups and the mDNS
        reflector's avahi-daemon.conf - with the secrets, also the password hashes, the passwords and keys of
        the destinations, the ntfy token and the certificate and key of the pages. The events and the copies
        of the database are not in it: they move with a backup (Settings → Backups). This machine's own
        folders and port are neither exported nor read back.</p></div>
    <div class="card full">
      <div class="btnrow">
        <button class="btn cmd admin-only" id="ex-plain" data-icon="download">Export</button>
        <button class="btn cmd danger admin-only" id="ex-whole" data-icon="key">Export with the secrets</button>
        <button class="btn cmd admin-only" id="ex-load" data-icon="upload">Import a file…</button>
        <input type="file" id="ex-file" accept=".json" hidden>
      </div>
    </div>
  </div>
