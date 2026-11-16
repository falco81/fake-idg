<?php /* Settings → Accounts: otp's pane-people, for fake-igd's own accounts (1.6.1). */ ?>
  <div class="ctl-pane" id="pane-people" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Accounts</h2>
      <p class="ctl-lede">Who may open these pages. <b>full admin</b> may change everything;
        <b>read only</b> may look and change nothing. On the server: <span class="mono">upnp user list</span>.</p></div>
    <div class="card full">
      <h2>Accounts <span class="right"><button class="btn cmd small primary admin-only" id="us-add" data-icon="add">Make an account</button></span></h2>
      <div id="us-table"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Signed in now</h2><div id="se-table"></div></div>
    <div class="card full fulladmin-only" id="lo-card"><h2>Locked out <span class="right" id="lo-tools"></span></h2>
      <p class="note">Addresses and names with wrong attempts still counted - passwords, and codes of the second
        step - at the limit they are locked out until the time runs out. Clear one, or all of them,
        and they may try again at once.</p>
      <div id="lo-table"></div></div>
    <div class="card full"><div id="sect-people"></div></div>
  </div>
