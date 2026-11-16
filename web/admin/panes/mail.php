<?php /* Settings → Mail (as otp's): how fake-igd sends mail, its certificate authority, a test. */ ?>
  <div class="ctl-pane" id="pane-mail" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Mail</h2>
      <p class="ctl-lede">The alerts, the report of the week and a test can be sent by mail. The mail leaves
        through your mail server (SMTP), or straight to the server of the recipient's domain with no relay at
        all; what is not taken at once waits in the outgoing mail and is tried again.</p></div>
    <div class="card full"><div id="sect-mail"></div></div>
    <div class="card full">
      <h2>Try it <span class="right muted small" id="mail-said"></span></h2>
      <p class="note">Sends a short message - or a sample of an alert or of the report - the way the alerts would
        go, and shows every step: the server reached, TLS, signing in, the message handed over and what the server
        said. Save the changes first.</p>
      <div class="btnrow admin-only filters">
        <input type="email" id="mail-to" placeholder="somebody@example.cz" style="flex:1;min-width:240px">
        <select id="mail-test-kind"><option value="short">a short message</option><option value="alert">a sample alert</option><option value="report">a sample report (the period so far)</option></select>
        <select id="mail-test-via" title="With mail sent straight to the recipient's server: this once, every step shown here - or through the outgoing mail, as the alerts go: tried now, and tried again by itself while the other side does not take it yet (greylisting)." hidden><option value="queue">through the outgoing mail</option><option value="straight">straight, this once (to see every step)</option></select>
        <button class="btn cmd primary" id="mail-test" data-icon="mail">Send a test</button>
      </div>
      <div id="mail-steps"></div>
    </div>
    <div class="card full">
      <h2>The certificate authority <span class="right muted small" id="mca-when"></span></h2>
      <p class="note">Needed only when the mail server's certificate was signed by an authority of your own that this machine does not already trust. Paste one (or a whole chain), or read it from the .crt / .pem / .cer file, and press Add it. Each is listed and can be taken out by itself.</p>
      <div id="mca-state"></div>
      <textarea id="mca-pem" rows="5" class="mono admin-only" style="width:100%;margin-top:10px"
                placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"></textarea>
      <div class="btnrow admin-only" style="margin-top:10px">
        <button class="btn cmd primary" id="mca-save" data-icon="save">Add it</button>
        <button class="btn cmd" id="mca-file" data-icon="upload">Read a file…</button>
        <button class="btn cmd danger" id="mca-drop" data-icon="trash">Take them all away</button>
        <input type="file" id="mca-input" accept=".pem,.crt,.cer,.txt" hidden>
      </div>
    </div>
  </div>
