const { chromium } = require('playwright');
const { execSync } = require('child_process');
const fs = require('fs');
const S = '/tmp/claude-0/-home-user-fake-idg/93600ac6-8aaa-5893-944b-ee67919241cd/scratchpad';
const E = S + '/env9', F = '/home/user/fake-idg/web/.upgrade.json', OUT = S + '/kit/shots';
const now = () => Date.now() / 1000;
let started = now();
function tell(state, part, words, extra) {
  fs.writeFileSync(F, JSON.stringify(Object.assign({state, id: 'k1', version: '1.7.8', from: '1.7.7', by: 'admin on the pages',
    part, parts: 13, words, started, at: now()}, extra || {})));
}
const kill = () => execSync(`pkill -f "[f]ake_igd_api.py --config ${E}/etc/config.json" || true`);
const killphp = () => execSync(`pkill -f "[p]hp -S 127.0.0.1:8099" || true`);
const start = () => execSync(`cd /home/user/fake-idg/src && UPNP_AVAHI_CONF=${E}/avahi.conf FAKE_IGD_STATE=${E}/state FAKE_IGD_RUN=${E}/run FAKE_IGD_NO_DNS=1 FAKE_IGD_DB=${E}/state/fake-igd.db nohup python3 fake_igd_api.py --config ${E}/etc/config.json > ${E}/api.log 2>&1 &`);
const startphp = () => execSync(`cd /home/user/fake-idg/web && PHP_CLI_SERVER_WORKERS=4 FAKE_IGD_RUN=${E}/run nohup php -S 127.0.0.1:8099 -t /home/user/fake-idg/web ${E}/router.php > ${E}/php.log 2>&1 &`);
(async () => {
  const mode = process.argv[2];
  const b = await chromium.launch();
  const p = await b.newPage({viewport: {width: 1600, height: 900}, deviceScaleFactor: 1});
  p.on('pageerror', e => console.log('PAGEERR', e.message));
  try { fs.unlinkSync(F); } catch (e) {}
  await p.goto('http://127.0.0.1:8099/admin/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('header', {timeout: 10000}); await p.waitForTimeout(1500);
  const go = async (pane) => { await p.click('.tabs button[data-tab="settings"]'); await p.waitForTimeout(800);
    await p.evaluate(pn => document.querySelector(`#ctl-nav [data-pane="${pn}"]`).click(), pane); await p.waitForTimeout(1500); };
  const shot = async (n) => { await p.screenshot({path: `${OUT}/${n}.png`}); console.log('shot', n); };
  if (mode === 'a') {
    started = now();
    tell('running', 1, 'root checks the package'); await p.waitForTimeout(5000); await shot('01-running-overview');
    await go('upgrade'); await p.waitForTimeout(3000);
    const c = await p.$('#up-plan-card'); if (c) { await c.scrollIntoViewIfNeeded(); await p.waitForTimeout(500); }
    await shot('02-running-upgrades-pane');
    tell('running', 7, 'The services'); kill(); await p.waitForTimeout(8000); await shot('03-api-down');
    tell('running', 9, 'The web pages (nginx, php-fpm)'); killphp(); await p.waitForTimeout(7000); await shot('04-nginx-php-restarting');
    startphp(); await p.waitForTimeout(4000); await shot('05-php-back-api-down');
    start(); await p.waitForTimeout(6000); await shot('06-api-back');
    tell('done', 13, 'fake-igd 1.7.8 runs'); await p.waitForTimeout(9000); await shot('07-done-reloaded');
  } else if (mode === 'b') {
    started = now() - 95;
    tell('failed', 7, 'The services', {said: 'install.sh --upgrade stopped (exit 1) - 1.7.7 runs again'});
    await p.waitForTimeout(6000); await shot('08-failed');
  } else if (mode === 'c') {
    await p.context().clearCookies();
    started = now() - 30;
    tell('running', 7, 'The services'); kill();
    await p.goto('http://127.0.0.1:8099/admin/'); await p.waitForTimeout(6000); await shot('09-signin-during-upgrade');
    start(); await p.waitForTimeout(1000);
  }
  try { fs.unlinkSync(F); } catch (e) {}
  await b.close();
})();
