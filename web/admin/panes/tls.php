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
    <!-- The system's trusted roots (otp 1.0.265): certificate authorities of one's own put into the
         trust of the operating system, beside the distribution's list. -->
    <div class="card full" id="osr-card">
      <h2>Trusted roots of the system</h2>
      <p class="note">Certificate authorities of your own - your company's root, an intermediate -
        trusted by the operating system of this server as a whole: curl, dnf, LDAPS, SMTP, syslog over
        TLS, fake-igd's own connections - every program that uses the system's trust. The
        distribution's own list stays as it is and keeps coming with the system's updates; these are
        added beside it, the way the system itself takes local additions (update-ca-trust on RHEL,
        AlmaLinux and Rocky, update-ca-certificates on Debian and Ubuntu), and stay there through
        those updates.</p>
      <div id="osr-host"></div>
    </div>
  </div>
