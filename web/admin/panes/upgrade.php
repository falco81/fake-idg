<?php /* Settings → Upgrades (1.6.1): otp's pane-upgrade, card for card, for the one server fake-igd is. */ ?>
  <div class="ctl-pane" id="pane-upgrade" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Upgrades</h2>
      <p class="ctl-lede">A new version put in from here: from the web, or a package sent from this
        computer - checked, then put in by root, while fake-igd.service and these pages restart once.
        The command line (upnp upgrade, install.sh --upgrade) works as it always has.</p></div>
    <!-- What an update cannot do itself (otp 1.0.258): counted beside Upgrades in the menu and on the
         Settings tab until it is done; the first card of the pane. -->
    <div class="card full fulladmin-only after-card" id="after-card">
      <h2>To be done by hand</h2>
      <p class="note">What fake-igd cannot do itself and somebody has to - a step a new version needs on
        the command line, what the installer left to you (SELinux, the firewall, nginx, PHP). Kept
        here and counted beside Upgrades in the menu until it is done. One that can be checked goes by
        itself once it is so.</p>
      <div id="after-bands"></div>
      <div id="after-lately"></div>
    </div>
    <div class="card full">
      <h2>This server</h2>
      <p class="note">fake-igd.service answers the PS5; these pages and their API run beside it. While a
        new version is put in, both restart once: for a few seconds nothing is answered on the network,
        and these pages come back by themselves.</p>
      <div id="up-nodes"></div>
    </div>
    <div class="card full admin-only" id="up-web-card">
      <h2>From the web</h2>
      <p class="note">Where new versions are published - the address below - is looked at once a
        day. A newer fake-igd found there is offered here, and put in with one click: fetched, its
        signature checked like a package sent by hand, then put in by root. Nothing is put in by
        itself.</p>
      <div id="up-web"></div>
      <div id="sect-upgrade"></div>
    </div>
    <div class="card full admin-only">
      <h2>A new version</h2>
      <p class="note">The .tar.gz of a new fake-igd, as it was released. It is checked before
        anything else: it must be signed by a release key this server trusts, every file in
        it must be the one signed, and it must not be older than what runs here. Root checks
        it all again before it is put in.</p>
      <div class="drop" id="up-drop">
        <input type="file" id="up-file" accept=".gz,.tgz,application/gzip,application/octet-stream" hidden>
        <span id="up-drop-says">Drop the fake-igd-X.Y.Z.tar.gz here, or press to choose it</span>
      </div>
      <div id="up-pkg"></div>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd primary" id="up-start" data-icon="play" disabled>Upgrade</button>
        <button class="btn cmd" id="up-forget" data-icon="trash" hidden>Forget the package</button>
      </div>
      <div id="up-ready"></div>
    </div>
    <div class="card full admin-only" id="up-down-card" hidden>
      <h2>Going back to an older version</h2>
      <p class="note">Only to a version that is safe: one signed by a release key this server trusts,
        and not older than 1.4.0 - the first that is put in from these pages and comes back from them -
        nor than the floor root keeps beside the program, when there is one. Nothing kept is put back
        nor changed: the configuration, the database and the logs stay as they are and the older
        version runs with them. The package is checked like an upgrade's before anything is put in;
        then root puts it in, as in an upgrade.</p>
      <div id="up-down"></div>
    </div>
    <div class="card full" id="up-plan-card" hidden>
      <h2>The upgrade</h2>
      <div id="up-plan"></div>
      <p class="note small" id="up-retry" style="min-height:1.4em;margin:6px 0 0"></p>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd danger admin-only" id="up-cancel" data-icon="cancel" hidden>Stop it</button>
      </div>
    </div>
    <div class="card full">
      <h2>What root said last <span class="mono small muted" id="up-log-node" data-no-i18n></span></h2>
      <p class="note"><span>The output of install.sh, the last time this server was upgraded from these pages or with upnp upgrade.</span>
        <span class="mono" data-no-i18n>/var/lib/fake-igd/upgrade/last.log</span></p>
      <!-- Folded until asked for (otp 1.0.196): a long log pushed the rest down. -->
      <details class="fold" id="up-log-fold">
        <summary>the output</summary>
        <pre class="lines" id="up-log">–</pre>
      </details>
    </div>
    <div class="card full">
      <h2>On the command line</h2>
      <p class="note">The same, by hand, as root:</p>
      <pre class="lines">upnp upgrade check                       # what is at upgrade_url, and whether it is newer
upnp upgrade online                      # the newest: fetched, checked, put in - followed with a bar
upnp upgrade online 1.6.2 --yes          # that one
upnp upgrade file fake-igd-X.Y.Z.tar.gz  # a package you have
upnp upgrade follow                      # one going on, with its progress bar
upnp upgrade status                      # how the last one went, and what is to be done by hand
upnp upgrade check --downgrade           # the older versions there, and which may be gone back to
upnp upgrade online 1.6.0 --downgrade    # going back to one of them
tar xzf fake-igd-X.Y.Z.tar.gz && cd fake-igd-X.Y.Z && ./install.sh --upgrade</pre>
    </div>
  </div>
