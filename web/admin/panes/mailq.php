<?php /* Settings → Outgoing mail (as otp's): every mail sent and what became of it. */ ?>
  <div class="ctl-pane" id="pane-mailq" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Outgoing mail</h2>
      <p class="ctl-lede">Every mail this server sends - an alert, the report, a test - goes through here. What
        the receiving side does not take at once (greylisting's "try again later", a server away, a full
        mailbox) waits and is tried again by itself; what it refuses for good is shown as failed. What a mail
        held is never kept once it went.</p></div>
    <div class="card full held mq-held">
      <div class="mq-chips" id="mq-chips"></div>
      <div class="btnrow filters" style="margin-top:12px">
        <input type="search" id="mq-q" placeholder="an address, what the server said… (to:*@example.cz, state:waiting, kind:alert…)" style="flex:1;min-width:260px">
        <select id="mq-state">
          <option value="">every state</option>
          <option value="open">waiting or failed</option>
          <option value="waiting">waiting for another try</option>
          <option value="sending">being sent</option>
          <option value="sent">sent</option>
          <option value="failed">failed</option>
          <option value="expired">given up</option>
        </select>
        <button class="btn cmd admin-only" id="mq-retry-all" data-icon="refresh">Send every waiting one now</button>
        <button class="btn cmd admin-only" id="mq-drop-sent" data-icon="trash">Clear the sent ones</button>
        <button class="btn cmd danger admin-only" id="mq-drop-failed" data-icon="trash">Clear the failed ones</button>
      </div>
      <div id="mq-said" class="muted small" style="margin:8px 0 0"></div>
      <div id="mq-table" class="scroll rowsonly" style="margin-top:10px"></div>
      <div id="mq-pager" class="pager"></div>
    </div>
  </div>
