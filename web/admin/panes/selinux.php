<?php /* Settings → SELinux (1.7.7) - otp's SELinux card of Settings → High security, for one server. */ ?>
  <div class="ctl-pane" id="pane-selinux" hidden>
    <div class="ctl-head"><h2 class="ctl-title">SELinux</h2>
      <p class="ctl-lede">What SELinux refuses on this server when it is enforcing, and what fake-igd needs of it:
        its own module (fake_igd_server), the labels of its files, the boolean that lets the pages ask the API, the
        SSH server's port. Looked at every half hour; the steps - made ready and permissive, enforcing, permissive
        again - are done by root only when asked here or with <span class="mono">sudo upnp selinux</span>.</p></div>
    <div id="se-host"><p class="muted small">Reading…</p></div>
  </div>
