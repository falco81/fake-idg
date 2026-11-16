<?php /* The tab mDNS (otp's Tokens / Enrolment: tiles in the held card, the filters with Search and Clear,
   the table, a row opens the peek popup; followed live as otp's live views are). */ ?>
<!-- ===================== mDNS ===================== -->
<section class="panel" id="tab-mdns" hidden>
  <div class="card full" data-hold>
    <h2>Services on the network <span class="right" id="ms-said"></span></h2>
    <p class="note">Everything mDNS shows on the interfaces avahi uses - AirPlay, Chromecast, printers, the PS5 -
      asked of avahi-daemon (<span class="mono">avahi-browse -a -r</span>) and followed while this page is open:
      as they are now, or as they come and go. Click a row for all it says.</p>
    <div class="facts" id="ms-tiles"></div>
    <div class="filterbar btnrow filters">
      <input type="search" id="ms-q" placeholder="a name, a type (_airplay), an address, a host…" style="flex:1;min-width:200px">
      <select id="ms-view" title="The services as they are now, or every one that came, went or changed while this page was open.">
        <option value="now">as they are now</option><option value="live">as they come and go</option></select>
      <select id="ms-type"><option value="">every type</option></select>
      <select id="ms-iface"><option value="">every interface</option></select>
      <select id="ms-proto"><option value="">IPv4 and IPv6</option><option value="IPv4">IPv4</option><option value="IPv6">IPv6</option></select>
      <button class="btn cmd" id="ms-pause" data-icon="clock" title="Stop following for a while - the table stays as it is.">Pause</button>
      <button class="btn cmd" id="ms-look" data-icon="refresh" title="Ask avahi from the beginning again - every service it knows is said once more.">Look again</button>
    </div>
    <div id="ms-table" class="scroll rowsonly"></div>
  </div>
</section>
