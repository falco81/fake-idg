<?php /* Settings → the pane ntfy (moved out of index.php, 1.6.1). */ ?>
  <div class="ctl-pane" id="pane-ntfy" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Notifications (ntfy)</h2>
      <p class="ctl-lede">Every new port a client asks for - and another UPnP router seen on the network -
        to your phone, through ntfy.sh or your own ntfy server.</p></div>
    <div class="card full"><div id="sect-ntfy"></div>
      <div class="btnrow admin-only" style="margin-top:14px">
        <button class="btn cmd" id="nt-test" data-icon="bell" title="One test message with the saved settings; the server's answer is said here.">Send a test</button>
        <span class="muted small" id="nt-said"></span>
      </div></div>
  </div>
