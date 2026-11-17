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
    <div class="card full" id="cols-card">
      <h2>Columns of the tables <span class="right" id="cols-count"></span></h2>
      <p class="note">Every table on these pages can be laid out the way you read it. Press
        your name at the top right and switch on <b>Edit the columns</b>; then drag the edge of
        a column's heading to make it wider or narrower, and drag the heading itself to move
        the column. The right button on a heading hides a column, brings a hidden one back or
        adds an empty one for room. Twice on an edge puts that table's widths back. Each change
        is kept with your account the moment you let go, not in this browser, and comes back
        wherever you sign in; nobody else's tables change. The switch is for this sign-in
        only: signing out, the sign-in running out or the API restarting turn it off
        again, and the columns stay as you left them.</p>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd" id="cols-edit-go" data-icon="edit"
                title="The same switch as under your name: on for this sign-in only.">Edit the columns</button>
        <button class="btn cmd" id="cols-reset" data-icon="undo"
                title="Every table back as it comes: the widths and the order of the columns you set, on every page. Nobody else's are touched.">Put my columns back as they come</button>
        <button class="btn cmd" id="cols-export" data-icon="download"
                title="How you have set these pages up for yourself, saved as a JSON file.">Export my settings</button>
        <button class="btn cmd" id="cols-import" data-icon="upload"
                title="Read a file saved by Export my settings - here or on another machine running fake-igd.">Import settings…</button>
      </div>
    </div>
    <div class="card full"><div id="sect-people"></div></div>
  </div>
