<?php /* Settings → The database (otp's pane `db`: the file, its copies, how long things are kept). */ ?>
  <div class="ctl-pane" id="pane-db" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The database</h2>
      <p class="ctl-lede">One database holds everything these pages keep: the accounts, who is signed in,
        the wrong passwords, the events and the settings saved here. It is one SQLite file on this machine,
        <span class="mono">/var/lib/fake-igd/fake-igd.db</span>, owned by the fake-igd account - and every
        copy of it is a whole SQLite file too, which opens with nothing but <span class="mono">sqlite3</span>.</p></div>
    <div class="card full"><div id="sect-db"></div></div>

    <div class="card full">
      <h2>The disk it is on</h2>
      <p class="note">How much room there is where this database's files live. The copies below are on
        the same disk: a copy kept only on this machine is lost with it - Settings → Backups sends
        everything to another one.</p>
      <div id="db-disk"></div>
    </div>

    <div class="card full">
      <h2>What is in it <span class="right" id="db-size"></span></h2>
      <p class="note">A copy is consistent even while the API is writing to it: it is made by SQLite's
        own backup, page by page under one lock, and kept gzip'd.</p>
      <p class="btnhelp">These are <b>every row in each table</b>, which is not the number on the tabs
        above: those count what the page they belong to is showing.</p>
      <div id="db-counts"></div>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd admin-only" id="db-backup" data-icon="save"
                title="Copy the database as it is into the backups folder on this machine, now, rather than waiting for tonight.">Make a copy now</button>
        <button class="btn cmd admin-only" id="db-download" data-icon="down"
                title="Make a copy now and save it to the machine you are sitting at. Nothing is kept here.">Download it</button>
        <button class="btn cmd admin-only" id="db-check" data-icon="check"
                title="Ask the database to read itself through and say whether anything in it is broken - SQLite's integrity check. It only reads.">Check it</button>
        <button class="btn cmd admin-only" id="db-tidy" data-icon="broom"
                title="Throws away exactly what the &quot;keep the events&quot; number above already says is too old. It happens by itself every hour; this is the same thing, now. Lowering that number deletes nothing by itself: this is what does it.">Apply what is kept, now</button>
        <button class="btn cmd danger admin-only" id="db-prune" data-icon="forget"
                title="Forgets the events older than an age you choose here, whatever the &quot;keep&quot; number says. The accounts and the settings are not touched.">Forget records older than…</button>
        <button class="btn cmd admin-only" id="db-optimize" data-icon="db"
                title="Gives the space back to the DISK. Deleting rows frees room inside the database and SQLite reuses it; nothing hands it back to the operating system until the whole file is rebuilt - SQLite's VACUUM. It holds the database shut while it runs and needs room for a second copy of it. Worth doing after throwing a lot away, and not otherwise.">Give the disk back</button>
      </div>
      <div id="db-backups" style="margin-top:18px"></div>
      <div class="admin-only" id="db-upload" style="margin-top:18px">
        <h4>Put a copy back</h4>
        <p class="note">A database from somewhere else — one downloaded from here, or a file
          copied off the backups folder. It replaces everything: every account, every setting saved
          on these pages and every event. Nothing happens until it has been read, checked and shown
          to you.</p>
        <div class="drop" id="db-drop">
          <input type="file" id="db-file" accept=".gz,.db,.sqlite,.sqlite3,application/octet-stream" hidden>
          <span id="db-drop-says">Drop a database file here, or press to choose one</span>
        </div>
        <div id="db-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="db-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>
  </div>
