<?php /* Settings → the pane people (moved out of index.php, 1.6.1). */ ?>
  <div class="ctl-pane" id="pane-people" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Accounts</h2>
      <p class="ctl-lede">Who may open these pages - local accounts, kept in fake-igd's own database.
        <b>full admin</b> may change everything; <b>read only</b> may look and change nothing.
        On the server: <span class="mono">upnp user list</span>.</p></div>
    <div class="card full">
      <h2>Accounts <span class="right"><button class="btn cmd small primary admin-only" id="us-add" data-icon="add">Make an account</button></span></h2>
      <div id="us-table"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Signed in now</h2><div id="se-table"></div></div>
  </div>
