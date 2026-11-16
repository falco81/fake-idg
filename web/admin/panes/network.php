<?php /* Settings → UPnP network (otp's pane "radius" for where it listens: the settings, with what
   listens where now above them - the interfaces of this server and the sockets - as otp shows it). */ ?>
  <div class="ctl-pane" id="pane-network" hidden>
    <div class="ctl-head"><h2 class="ctl-title">UPnP network</h2>
      <p class="ctl-lede">Where fake-igd listens: SSDP on 1900/udp, and the device description and SOAP on the
        port below, on every interface with IPv4 chosen here - looked at again by itself, so an interface that
        comes up later is listened on too. fake-igd is IPv4 only. A change restarts fake-igd.service, and
        root opens the port in fake-igd's firewall when it is on.</p></div>
    <div id="un-host"></div>
    <div class="card full">
      <h2>The interfaces of this server <span class="right muted small" id="un-said"></span></h2>
      <p class="note">Every interface the kernel has, whether fake-igd listens on it - and why not - and where the
        PS5 finds the device description on the ones it listens on. Chosen interfaces are added in the settings
        below; none chosen means every one with IPv4 and multicast.</p>
      <div id="un-ifaces"></div>
    </div>
    <div class="card full"><h2>Settings</h2><div id="sect-network"></div></div>
  </div>
