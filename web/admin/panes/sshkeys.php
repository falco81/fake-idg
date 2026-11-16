<?php /* Settings → SSH keys (otp's pane "sshkeys": root's keys shown, every user's listed, added, made, taken away). */ ?>
  <div class="ctl-pane" id="pane-sshkeys" hidden>
    <div class="ctl-head"><h2 class="ctl-title">SSH keys</h2>
      <p class="ctl-lede">The keys that may sign in to this server over SSH - as root (the lines of
        /root/.ssh/authorized_keys, only shown here: put on and taken away by root on the machine itself) or as
        any user who may sign in here (their own ~/.ssh/authorized_keys, written as they are). A key made here
        for a user is shown once, to be kept by you, and kept nowhere on the server; one of your own is put on by
        its public half. Every change is written into Events.</p></div>
    <div id="sk-host"></div>
  </div>
