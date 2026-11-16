<?php /* Settings → Local users (otp's pane "osusers": the system's users, the password policy). */ ?>
  <div class="ctl-pane" id="pane-osusers" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Local users</h2>
      <p class="ctl-lede">The users of this server's own system - who may sign in to the machine itself, over SSH
        or at its console; not the accounts of these pages. root is shown and never changed here; the others
        (UID 1000 and up) are made, given a password or sudo, locked or taken away by root. A password typed
        here goes to root as its hash only and is kept nowhere. Every change is written into Events.</p></div>
    <div id="osu-host"></div>
  </div>
