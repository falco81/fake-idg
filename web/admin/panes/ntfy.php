<?php /* Settings → Notifications (ntfy) (otp's pane "mail": the settings, a test with every step shown,
   what was sent, and the certificate authority of a server of your own). */ ?>
  <div class="ctl-pane" id="pane-ntfy" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Notifications (ntfy)</h2>
      <p class="ctl-lede">Every new port a client asks for - and another UPnP router heard on the network - can
        be sent to your phone as it happens. It goes to a topic of ntfy.sh, or of an ntfy server of your own,
        signed in with a token or a user and password; the phone subscribes to the same topic in the ntfy app.</p></div>
    <div class="card full"><div id="sect-ntfy"></div></div>
    <div class="card full">
      <h2>Try it <span class="right muted small" id="nt-said"></span></h2>
      <p class="note">Sends one test notification the way every notification goes, and shows every step: the
        server looked up, reached, TLS and whose certificate it shows, the message handed over and what the
        server said. Save the changes first.</p>
      <div class="btnrow admin-only filters">
        <button class="btn cmd primary" id="nt-test" data-icon="bell">Send a test</button>
      </div>
      <div id="nt-steps"></div>
    </div>
    <div class="card full">
      <h2>What was sent <span class="right muted small" id="nt-when"></span></h2>
      <p class="note">The last notifications fake-igd.service sent - or could not send - as its log says, and the
        tests sent from here. Newest first.</p>
      <div id="nt-sends"></div>
    </div>
    <div class="card full">
      <h2>The certificate authority <span class="right muted small" id="nca-when"></span></h2>
      <p class="note">Needed only when your own ntfy server's certificate was signed by an authority of your own
        that this machine does not already trust. Paste one (or a whole chain), or read it from the .crt / .pem /
        .cer file, and press Save the changes below: it is kept beside config.json and set as the CA certificate of the ntfy
        server - fake-igd.service is restarted with it. Each is listed below.</p>
      <div id="nca-state"></div>
      <textarea id="nca-pem" rows="5" class="mono admin-only" style="width:100%;margin-top:10px"
                placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"></textarea>
      <div class="btnrow admin-only" style="margin-top:10px">
        <button class="btn cmd primary" id="nca-save" data-icon="save">Add it</button>
        <button class="btn cmd" id="nca-file" data-icon="upload">Read a file…</button>
        <button class="btn cmd danger" id="nca-drop" data-icon="trash">Take them all away</button>
        <input type="file" id="nca-input" accept=".pem,.crt,.cer,.txt" hidden>
      </div>
    </div>
  </div>
