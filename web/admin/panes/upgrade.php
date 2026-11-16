<?php /* Settings → the pane upgrade (moved out of index.php, 1.6.1). */ ?>
  <div class="ctl-pane" id="pane-upgrade" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Upgrades</h2>
      <p class="ctl-lede">A new version put in from here: from the web, or a package sent from this
        computer. It is checked before anything else - signed by a release key this server trusts,
        every file the one signed, not older than what runs here - and root checks it all again
        before it runs its install.sh --upgrade. The command line works as it always has.</p></div>
    <div class="card full admin-only" id="up-web-card">
      <h2>From the web</h2>
      <p class="note">Where new versions are published - the address below - is looked at once a
        day. A newer fake-igd found there is offered here and put in with one click: fetched, its
        signature checked like a package sent by hand, then put in by root. Nothing is put in by itself.</p>
      <div id="up-web"></div>
      <div id="sect-upgrade"></div>
    </div>
    <div class="card full admin-only">
      <h2>A new version</h2>
      <p class="note">The .tar.gz of a new fake-igd, as it was released.</p>
      <div class="drop" id="up-drop">
        <input type="file" id="up-file" accept=".gz,.tgz,application/gzip,application/octet-stream" hidden>
        <span id="up-drop-says">Drop the fake-igd-X.Y.Z.tar.gz here, or press to choose it</span>
      </div>
      <div id="up-pkg"></div>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd primary" id="up-start" data-icon="play" disabled>Upgrade</button>
        <button class="btn cmd" id="up-forget" data-icon="trash" hidden>Forget the package</button>
      </div>
    </div>
    <div class="card full" id="up-plan-card" hidden>
      <h2>The upgrade</h2>
      <div id="up-plan"></div>
    </div>
    <div class="card full">
      <h2>What root said last</h2>
      <p class="note"><span>The output of install.sh, the last time this server was upgraded from these pages or with upnp upgrade.</span>
        <span class="mono" data-no-i18n>/var/lib/fake-igd/upgrade/last.log</span></p>
      <details class="fold" id="up-log-fold">
        <summary>the output</summary>
        <pre class="lines" id="up-log">–</pre>
      </details>
    </div>
    <div class="card full">
      <h2>On the command line</h2>
      <p class="note">The same, as root:</p>
      <pre class="lines">upnp upgrade check                 # what is at upgrade_url, and whether it is newer
upnp upgrade online                # the newest: fetched, checked, put in - followed with a bar
upnp upgrade online 1.4.2 --yes
upnp upgrade file fake-igd-X.Y.Z.tar.gz
upnp upgrade follow                # one going on
tar xzf fake-igd-X.Y.Z.tar.gz && cd fake-igd-X.Y.Z && ./install.sh --upgrade</pre>
    </div>
  </div>
