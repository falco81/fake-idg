#!/usr/bin/env bash
# fake-igd - uninstaller
# Usage:  sudo ./uninstall.sh [--purge]
#   --purge  also remove the configuration, logs, state and the system user/group
# Python 3.14 is not removed (other software may use it):
#   package:       dnf remove python3.14
#   from source:   rm -rf /usr/local/bin/python3.14* /usr/local/lib/python3.14 ...
set -euo pipefail

APP=fake-igd
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }

echo "==> Stopping the service"
systemctl disable --now $APP 2>/dev/null || true

echo "==> Firewall"
if systemctl is-active --quiet firewalld; then
  port=$(cat /var/lib/$APP/.firewall-port 2>/dev/null || echo 5000)
  for z in $(firewall-cmd --get-zones); do
    firewall-cmd --quiet --permanent --zone="$z" --remove-port=1900/udp 2>/dev/null || true
    firewall-cmd --quiet --permanent --zone="$z" --remove-port="$port/tcp" 2>/dev/null || true
  done
  firewall-cmd --quiet --reload
  echo "    ports 1900/udp and $port/tcp removed from all zones"
else
  echo "    firewalld is not running"
  if command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -q fake-igd; then
    echo "    iptables rules tagged 'fake-igd' found - remove them with:"
    echo "      iptables -S INPUT | grep fake-igd | sed 's/^-A/-D/' | xargs -L1 iptables && service iptables save"
  fi
fi

echo "==> Removing the application, venv, CLI and completion"
rm -f /etc/systemd/system/$APP.service /etc/logrotate.d/$APP /etc/bash_completion.d/upnp \
      /etc/profile.d/zz-upnp-console.sh
for b in /usr/bin/upnp /usr/bin/$APP-ports /usr/local/bin/$APP-ports; do
  if [[ -f "$b" ]] && grep -q "$APP" "$b" 2>/dev/null; then rm -f "$b"; fi
done
systemctl daemon-reload
rm -rf "/opt/${APP:?}"

if [[ $PURGE -eq 1 ]]; then
  echo "==> --purge: configuration, logs, state, user"
  rm -rf "/etc/${APP:?}" "/var/log/${APP:?}" "/var/lib/${APP:?}" "/var/log/${APP:?}-python-build.log" \
         /etc/upnp-console-login
  pkill -u "$APP" 2>/dev/null && sleep 1 || true
  userdel "$APP" 2>/dev/null || echo "    WARNING: could not remove user $APP (is a process of it still running?)" >&2
  groupdel "$APP" 2>/dev/null || true
else
  echo "    kept: /etc/$APP, /var/log/$APP, /var/lib/$APP, user $APP (remove with --purge)"
fi
echo "    Python 3.14 kept (see the comment in uninstall.sh)."
echo "Done."
