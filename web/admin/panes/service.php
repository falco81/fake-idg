<?php /* Settings → The service (1.6.1): the systemd units fake-igd lives on, each with its state, since when,
         its restarts, its memory and its journal; Restart / Stop / Start asked of root (deploy/root_service.py);
         what root did, as otp's bands. In otp's look: its nodes and maintenance cards. */ ?>
  <div class="ctl-pane" id="pane-service" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The service</h2>
      <p class="ctl-lede">fake-igd is a handful of systemd units: fake-igd.service answers the network, and these
        pages are nginx, php-fpm and an API of their own (fake-igd-api) that stay while it restarts. What needs
        root - starting and stopping a unit among them - is asked of root and done by it within seconds.</p></div>
    <div class="card full">
      <h2>The units <span class="right" id="sv-said"></span></h2>
      <p class="note">Each unit as systemd says it now: running or not, since when, how many times systemd
        restarted it by itself, how much memory it holds. A row opens its last lines of the journal. Stopping
        fake-igd.service stops the answers to the PS5; the pages, their API, nginx and php-fpm are only
        restarted - stopped, nothing could start them again from here.</p>
      <div id="sv-units"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd" id="sv-apply" data-icon="wall"
                title="Root writes nginx's allow list (who may reach these pages) and fake-igd's firewall chain again, as the settings say.">Put the allow list and the firewall in place again</button>
      </div>
    </div>
    <div class="card full admin-only" id="sv-root-card">
      <h2>What root did <span class="right" id="sv-root-said"></span></h2>
      <p class="note">Every Restart, Stop and Start here - and the console at login of Settings → About - is
        asked of root through its queue (fake-igd-web.path) and done by deploy/root_service.py, for these units
        and nothing else. Its answer stays here until it is marked done; the list below keeps the last forty.</p>
      <div id="sv-bands"></div>
      <div id="sv-lately"></div>
    </div>
    <div class="card full">
      <h2>On the server</h2>
      <p class="note">The same from a shell on the machine, as root - and what works when these pages do not.</p>
      <details class="lb-guide ha-cli-fold" id="sv-cli-fold">
        <summary><b>The commands</b><span class="tag dim">systemctl · journalctl · upnp</span></summary>
        <div class="ha-cli-in">
      <table class="plain ha-cli">
        <thead><tr><th>Command</th><th>What it does</th></tr></thead>
        <tbody>
          <tr><td data-no-i18n>upnp status</td>
            <td>fake-igd.service and what it answers: its state, the mode, the port, the public IP, the interfaces.</td></tr>
          <tr><td data-no-i18n>upnp start<br>upnp stop<br>upnp restart</td>
            <td>fake-igd.service started, stopped or restarted - the same as the buttons above.</td></tr>
          <tr><td data-no-i18n>systemctl status fake-igd fake-igd-api nginx php-fpm avahi-daemon</td>
            <td>Every unit of this page at once, each with its last lines.</td></tr>
          <tr><td data-no-i18n>journalctl -u fake-igd -n 100<br>journalctl -u fake-igd-api -f</td>
            <td>A unit's journal: the last hundred lines, or as it is written.</td></tr>
          <tr><td data-no-i18n>systemctl restart fake-igd-api</td>
            <td>The pages' API, when the pages say it does not answer.</td></tr>
          <tr><td data-no-i18n>nginx -t &amp;&amp; systemctl reload nginx<br>php-fpm -t &amp;&amp; systemctl restart php-fpm</td>
            <td>The web server and PHP, each asked about its configuration first.</td></tr>
          <tr><td data-no-i18n>systemctl status fake-igd-web.path fake-igd-web.service</td>
            <td>Root's queue: when the buttons here ask and nothing happens, this is where to look.</td></tr>
        </tbody>
      </table>
        </div>
      </details>
    </div>
  </div>
