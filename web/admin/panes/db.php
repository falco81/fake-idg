<?php /* Settings → The database (otp's pane `db`: the file, its dumps and copies, how long things are kept). */ ?>
  <div class="ctl-pane" id="pane-db" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The database</h2>
      <p class="ctl-lede">One database holds everything these pages keep: the accounts, who is signed in, the
        events, the outgoing mail and the settings saved here. It is one SQLite file on this machine. The secrets
        in it - the passwords of the backups' destinations, of the mail server and the proxy, the ACME account
        key - are sealed with a key kept beside it, in the state folder - and every copy and every dump is kept
        with that key beside it.</p></div>
    <div class="card full"><div id="sect-db"></div></div>

    <div class="card full" id="db-dump-card">
      <h2>The dumps it keeps <span class="right" id="db-dump-now"></span></h2>
      <p class="note">Every night at the time above, the database is dumped <b>by its own engine's own
        program</b> — on the file, SQLite's own backup, which is the file. It is the format SQLite's own tools
        read, so it can be put back by somebody who has never heard of this program: <code>sqlite3</code>
        opens it.</p>
      <p class="note">A dump goes back into <b>the engine it came off</b>. A copy, which the card below makes,
        is the same file gzip'd.</p>
      <div id="db-dump-says"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd" id="db-dump-make" data-icon="save"
                title="Dump the database now, with the engine's own program, rather than waiting for tonight. It is kept with the others and counts as one of them.">Make one now</button>
        <button class="btn cmd" id="db-dump-get" data-icon="down"
                title="Dump the database now and save it to the machine you are sitting at. Nothing is kept here.">Download one</button>
      </div>
      <div id="db-dumps" style="margin-top:18px"></div>
      <div class="admin-only" id="db-dump-upload" style="margin-top:18px">
        <h4>Put a dump back</h4>
        <p class="note">A dump from somewhere else — one downloaded from here, or a file copied off the dumps
          folder. It replaces everything: every account, every setting saved on these pages and every event.
          Nothing happens until it has been read, checked and shown to you.</p>
        <div class="drop" id="dump-drop">
          <input type="file" id="dump-file" accept=".db,.tar,.gz,application/octet-stream" hidden>
          <span id="dump-drop-says">Drop a dump here, or press to choose one</span>
        </div>
        <div id="dump-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="dump-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>

    <div class="card full" id="db-engine-card">
      <h2>Which one it is <span class="right" id="db-engine-now"></span></h2>
      <p class="note">This installation keeps everything in one database: the file on this machine (SQLite).
        fake-igd has no other engine - no MariaDB or PostgreSQL to move to - so there is nothing to choose here:
        this says what it is. Where it is kept is the state folder of <b id="db-engine-file">the config file</b>.</p>
      <div id="db-engine-says"></div>
    </div>

    <div class="card full">
      <h2>The disk it is on</h2>
      <p class="note">How much room there is where this database's files live, how fast it is growing, and how
        long one will hold the other. Measured, not guessed: the size is noted once a day and what is shown is
        the slope of the last fortnight.</p>
      <div id="db-disk"></div>
    </div>

    <div class="card full">
      <h2>What is in it <span class="right" id="db-size"></span></h2>
      <p class="note">A copy is consistent even while the API is writing to it: it is made by SQLite's own
        backup, page by page under one lock, and kept gzip'd.</p>
      <p class="btnhelp">These are <b>every row in each table</b>, which is not the number on the tabs above:
        those count what the page they belong to is showing.</p>
      <div id="db-counts"></div>
      <div class="going wide" id="db-going" hidden>
        <div class="bar"><span id="db-going-fill"></span></div>
        <div class="says" id="db-going-says"></div>
      </div>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd admin-only" id="db-backup" data-icon="save"
                title="Copy the database as it is into the backups folder on this machine, now, rather than waiting for tonight.">Make a copy now</button>
        <button class="btn cmd admin-only" id="db-download" data-icon="down"
                title="Make a copy now and save it to the machine you are sitting at, with the key that opens its secrets inside it. Nothing is kept here.">Download it</button>
        <button class="btn cmd admin-only" id="db-check" data-icon="check"
                title="Ask the database to read itself through and say whether anything in it is broken - SQLite's integrity check. It only reads; on a large one it takes a while.">Check it</button>
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
          <input type="file" id="db-file" accept=".gz,.db,.tar,.sqlite,.sqlite3,application/octet-stream" hidden>
          <span id="db-drop-says">Drop a database file here, or press to choose one</span>
        </div>
        <div id="db-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="db-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>

    <div class="card full">
      <h2>Erase the collected data <span class="right" id="erase-size"></span></h2>
      <p class="note">What is recorded of what happened can be thrown away without anybody losing anything they
        need: nobody has to sign in again and nothing stops working. Choose what goes; nothing is erased that
        you have not ticked.</p>
      <p class="note"><b>The accounts, the destinations of the backups and every setting are never touched by
        this.</b> They are not options you could tick by mistake: they are not in the list at all.</p>
      <div id="erase-list" class="erase-list"></div>
      <div class="btnrow admin-only" style="margin-top:14px;align-items:center">
        <button class="btn cmd danger" id="erase-go" data-icon="forget"
                title="Erase everything ticked above. It cannot be undone — but a copy of the database is made just before it, and it can be restored.">Erase what is ticked…</button>
        <label class="check small" id="erase-tidy-wrap">
          <input type="checkbox" id="erase-tidy" checked
                 title="Rebuild the database afterwards so the space actually goes back to the disk. SQLite does not give room back by itself when rows are deleted — it is reused inside instead.">
          <span>rebuild it afterwards, to give the disk back</span>
        </label>
      </div>
    </div>
  </div>
