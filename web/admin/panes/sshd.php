<?php /* Settings → SSH server and notices (otp's pane "sshd": the drop-in, on trial, and the notices). */ ?>
  <div class="ctl-pane" id="pane-sshd" hidden>
    <div class="ctl-head"><h2 class="ctl-title">SSH server and notices</h2>
      <p class="ctl-lede">How this server's SSH server lets people in - root with a key or a password, the port,
        who may sign in - and the notice shown before signing in over SSH, at the console and after signing in.
        Put in by root as a file of fake-igd's own beside the system's, checked by sshd before it is used, and on
        trial: unless it is kept in time, root puts back what it had by itself.</p></div>
    <div id="sd-host"></div>
    <div class="card full"><h2>The SSH server</h2><div id="sect-sshd"></div><div id="sd-form-notes"></div></div>
    <div class="card full"><h2>The notice</h2><div id="sd-notice"></div>
      <p class="muted small">Saved with the bar at the bottom; root then puts it in by itself within seconds.</p></div>
  </div>
