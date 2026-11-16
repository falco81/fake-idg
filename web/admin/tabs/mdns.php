<?php /* The tab mDNS (moved out of index.php, 1.6.1). */ ?>
<!-- ===================== mDNS ===================== -->
<section class="panel" id="tab-mdns" hidden>
  <div class="card full" data-hold>
    <h2>Services on the network <span class="right" id="ms-said"></span></h2>
    <p class="note">What mDNS shows now on every interface avahi uses - AirPlay, Chromecast, printers,
      the PS5 - asked of avahi-daemon (<span class="mono">avahi-browse -a -r</span>, as
      <span class="mono">upnp mdns services</span>). Click a row for all it says.</p>
    <div class="facts" id="ms-tiles"></div>
    <div class="btnrow filters">
      <input type="search" id="ms-q" placeholder="a name, a type (_airplay), an address, an interface…" style="flex:1;min-width:200px">
      <select id="ms-iface"><option value="">every interface</option></select>
      <select id="ms-proto"><option value="">IPv4 and IPv6</option><option value="IPv4">IPv4</option><option value="IPv6">IPv6</option></select>
      <button class="btn cmd" id="ms-look" data-icon="refresh" title="Ask avahi again now - it takes a few seconds.">Look again</button>
    </div>
    <div id="ms-table" class="scroll rowsonly"></div>
  </div>
</section>
