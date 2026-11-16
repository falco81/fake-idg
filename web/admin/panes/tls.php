<?php /* Settings → Certificates and TLS (otp's pane "web", for one server). Drawn by pane-tls.js. */ ?>
  <div class="ctl-pane" id="pane-tls" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Certificates and TLS</h2>
      <p class="ctl-lede">How these pages speak HTTPS - the certificate nginx answers with, its chain,
        the protocols, the ciphers.</p></div>
    <div class="card full">
      <h2>Certificates</h2>
      <p class="note">The one these pages answer with, on every name and address of this server. A
        certificate is sent as PEM files (the certificate, its key, the chain, the root - in any order,
        or all in one file) or as a PFX / PKCS#12 file, with its password or without; or the request is
        made here and only what the authority sends back is uploaded. Root puts it in nginx and asks
        nginx before reloading it.</p>
      <div id="tls-certs" class="cert-grid"></div>
    </div>
  </div>
