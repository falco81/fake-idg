#!/usr/bin/env bash
# fake-igd - uninstaller (also: ./install.sh --uninstall [--purge])
# Usage:  sudo ./uninstall.sh [--purge]
#   --purge  also remove the configuration, the logs, the state, the database (the accounts of the
#            pages) and the system users and groups
# Python 3.14 and the packages (nginx, php-fpm) are not removed - other software may use them:
#   dnf remove python3.14 nginx php-fpm
set -euo pipefail

APP=fake-igd
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }

echo "==> Stopping the services"
for u in $APP fake-igd-api fake-igd-upgrade.path fake-igd-web.path; do
  systemctl disable --now "$u" 2>/dev/null || true
done
# root's helpers may be at work (a pane's ask, an upgrade): stopped too, not left running from /opt
for u in fake-igd-web.service fake-igd-upgrade.service; do
  systemctl stop "$u" 2>/dev/null || true
done

echo "==> The firewall"
if [[ -x /usr/bin/python3 && -f /opt/$APP/fake_igd_web.py ]] && command -v iptables >/dev/null; then
  /usr/bin/python3 -I /opt/$APP/fake_igd_web.py --firewall-off 2>/dev/null | sed 's/^/    /' || true
fi
if systemctl is-active --quiet firewalld; then
  port=$(python3 -c "import json;print(json.load(open('/etc/$APP/config.json')).get('http_port',5000))" 2>/dev/null || echo 5000)
  for z in $(firewall-cmd --get-zones); do
    firewall-cmd --quiet --permanent --zone="$z" --remove-port=1900/udp 2>/dev/null || true
    firewall-cmd --quiet --permanent --zone="$z" --remove-port="$port/tcp" 2>/dev/null || true
  done
  firewall-cmd --quiet --reload
  echo "    firewalld: 1900/udp and $port/tcp closed in every zone (http/https left as they are)"
fi

echo "==> The web pages"
rm -f /etc/nginx/conf.d/$APP.conf /etc/php-fpm.d/$APP.conf
rm -rf "/var/www/${APP:?}"
systemctl reload nginx 2>/dev/null || true
systemctl reload php-fpm 2>/dev/null || true
echo "    nginx's fake-igd.conf, the php-fpm pool and /var/www/$APP taken away"
echo "    kept: /etc/nginx/certs/$APP.pem and .key"

echo "==> The program, the venv, the command and the units"
rm -f /etc/systemd/system/$APP.service /etc/systemd/system/fake-igd-api.service \
      /etc/systemd/system/fake-igd-upgrade.path /etc/systemd/system/fake-igd-upgrade.service \
      /etc/systemd/system/fake-igd-web.path /etc/systemd/system/fake-igd-web.service \
      /etc/logrotate.d/$APP /etc/bash_completion.d/upnp /etc/profile.d/zz-upnp-console.sh
for b in /usr/bin/upnp /usr/bin/$APP-ports /usr/local/bin/$APP-ports; do
  if [[ -f "$b" ]] && grep -q "$APP" "$b" 2>/dev/null; then rm -f "$b"; fi
done
systemctl daemon-reload
rm -rf "/opt/${APP:?}"
# SELinux: the label install.sh gave the API's run folder (so the pages read its token)
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -d '/run/fake-igd-api(/.*)?' 2>/dev/null || true
fi
rm -rf /run/fake-igd-api /run/fake-igd-osup-proxy.json /run/fake-igd-osup.lock

if [[ $PURGE -eq 1 ]]; then
  echo "==> --purge: the configuration, the logs, the state, the database, the users"
  rm -rf "/etc/${APP:?}" "/var/log/${APP:?}" "/var/lib/${APP:?}" "/var/log/${APP:?}-python-build.log" \
         "/var/lib/${APP:?}-net" "/var/lib/${APP:?}-root" \
         /etc/upnp-console-login /etc/nginx/certs/$APP.pem /etc/nginx/certs/$APP.key \
         /etc/nginx/certs/$APP.pem.before-* /etc/nginx/certs/$APP.key.before-* \
         /etc/nginx/conf.d/$APP.conf.before-* /etc/php-fpm.d/$APP.conf.before-*
  pkill -u "$APP" 2>/dev/null && sleep 1 || true
  for u in "$APP" "$APP-www"; do userdel "$u" 2>/dev/null || true; done
  for g in "$APP" "$APP-www" "$APP-web"; do groupdel "$g" 2>/dev/null || true; done
else
  echo "    kept: /etc/$APP, /var/log/$APP, /var/lib/$APP (the database with the accounts), the users (--purge takes them)"
fi
echo "    Python 3.14, nginx and php-fpm are kept."
# What the panes changed of the machine itself is the machine's now, and stays: said, so it is known.
for f in /etc/ssh/sshd_config.d/00-$APP.conf /etc/systemd/journald.conf.d/00-$APP.conf \
         /etc/sysctl.d/90-$APP-ipv6.conf /etc/php.d/99-php2shell.ini; do
  [[ -e "$f" ]] && echo "    kept (the machine's settings, made on the pages or by the installer): $f"
done
echo "Done."
