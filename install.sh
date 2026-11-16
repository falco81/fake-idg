#!/usr/bin/env bash
# fake-igd 1.3 - complete installer for AlmaLinux 9 (and compatible EL9)
#
# Installs all dependencies including Python 3.14, a virtualenv with colorama,
# the fake-igd service (systemd, start on boot), the `upnp` CLI and its console
# (`upnp --console`), bash completion, log rotation, and opens the ports in firewalld.
# When avahi-daemon is installed, avahi-tools too (for `upnp mdns services`).
#
# Usage:  sudo ./install.sh [options]
#   --upgrade              upgrade an existing installation (keeps config, logs, state
#                          and firewall; adds new config keys; restarts the service)
#   --no-firewall          do not open ports in firewalld
#   --no-start             install but do not start the service
#   --python-from-source   always build Python 3.14 from source (python.org)
#   --no-python-build      never build from source (dnf only)
#   --force                continue on an OS other than EL9
#   -h, --help             this help
#
# Environment variables:
#   PY_SRC_VER / PY_SRC_SHA256  another 3.14.x version from source (with its SHA-256 from python.org)
#   PY_OPTIMIZE=1          build from source with --enable-optimizations (PGO, much slower)
set -euo pipefail

APP=fake-igd
APP_VERSION=1.3
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPT_DIR=/opt/$APP
VENV=$OPT_DIR/venv
ETC_DIR=/etc/$APP
LOG_DIR=/var/log/$APP
STATE_DIR=/var/lib/$APP
UNIT=/etc/systemd/system/$APP.service
BIN_DIR=/usr/bin            # /usr/bin because sudo's secure_path on EL9 does not include /usr/local/bin

PY_MINOR=3.14
PY_SRC_VER=${PY_SRC_VER:-3.14.9}
PY_SRC_SHA256=${PY_SRC_SHA256:-e02d9ac21cebda6e46435369744a92c65cc7cd8669697694122cf97ffacd1e53}
PY_SRC_URL=https://www.python.org/ftp/python/$PY_SRC_VER/Python-$PY_SRC_VER.tar.xz
PY_BUILD_LOG=/var/log/$APP-python-build.log

DO_FIREWALL=1; DO_START=1; FORCE=0; PY_SOURCE=auto; UPGRADE=0
for arg in "$@"; do
  case "$arg" in
    --upgrade)            UPGRADE=1 ;;
    --no-firewall)        DO_FIREWALL=0 ;;
    --no-start)           DO_START=0 ;;
    --python-from-source) PY_SOURCE=always ;;
    --no-python-build)    PY_SOURCE=never ;;
    --force)              FORCE=1 ;;
    -h|--help)            n=$(grep -n '^set -euo' "$0" | cut -d: -f1); sed -n "2,$((n-1))p" "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg (see --help)" >&2; exit 1 ;;
  esac
done

if [[ -t 1 ]]; then c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_b=$'\e[1m'; c_off=$'\e[0m'
else c_ok=; c_warn=; c_err=; c_b=; c_off=; fi
STEP=0
step() { STEP=$((STEP + 1)); echo; echo "${c_ok}${c_b}[$STEP]${c_off}${c_b} $*${c_off}"; }
note() { echo "    $*"; }
warn() { echo "${c_warn}WARNING:${c_off} $*" >&2; }
die()  { echo "${c_err}${c_b}ERROR:${c_off} $*" >&2; exit 1; }
trap 'echo "${c_err}Installation failed at line $LINENO (command: $BASH_COMMAND).${c_off}" >&2' ERR

# ================================================================ checks
[[ $EUID -eq 0 ]] || die "Run as root:  sudo ./install.sh"
for f in src/$APP.py src/upnp.py src/upnp_console.py src/upnp_mdns.py console/zz-upnp-console.sh config/config.json systemd/$APP.service logrotate/$APP completion/upnp uninstall.sh; do
  [[ -f "$SRC_DIR/$f" ]] || die "The package is missing $f - are you running install.sh from the extracted directory?"
done

OLD_VERSION=""
if [[ -f "$OPT_DIR/VERSION" ]]; then OLD_VERSION=$(cat "$OPT_DIR/VERSION"); fi
if [[ $UPGRADE -eq 1 ]]; then
  [[ -n "$OLD_VERSION" || -f "$OPT_DIR/$APP.py" ]] || die "No existing installation found in $OPT_DIR - run without --upgrade."
  echo "${c_b}fake-igd - upgrade ${OLD_VERSION:-unknown} → $APP_VERSION${c_off}"
  DO_FIREWALL=0
else
  echo "${c_b}fake-igd $APP_VERSION - installation${c_off}"
  if [[ -n "$OLD_VERSION" ]]; then note "existing installation $OLD_VERSION found (tip: ./install.sh --upgrade)"; fi
fi

step "System check"
# read os-release in a subshell so it cannot overwrite our variables (e.g. VERSION)
OS_RELEASE=${OS_RELEASE:-/etc/os-release}
os_field() { ( . "$OS_RELEASE" 2>/dev/null; eval "echo \"\${$1:-}\"" ); }
OS_ID=$(os_field ID)
OS_LIKE=$(os_field ID_LIKE)
OS_VER=$(os_field VERSION_ID)
OS_PRETTY=$(os_field PRETTY_NAME)
note "OS: ${OS_PRETTY:-unknown}  ($(uname -m))"
EL9=0
if [[ "${OS_VER%%.*}" == "9" && " $OS_ID $OS_LIKE " =~ (rhel|almalinux|centos|rocky) ]]; then EL9=1; fi
if [[ $EL9 -ne 1 ]]; then
  [[ $FORCE -eq 1 ]] || die "This installer is for AlmaLinux 9 / EL9. Use --force to continue anyway."
  warn "Unsupported system, continuing because of --force."
fi
command -v dnf >/dev/null || die "dnf is missing."
command -v systemctl >/dev/null || die "systemd is missing."

# ================================================================ base packages
step "System dependencies"
BASE_PKGS=(logrotate tar xz curl ca-certificates shadow-utils iproute bash-completion policycoreutils)
missing=()
for p in "${BASE_PKGS[@]}"; do rpm -q "$p" &>/dev/null || missing+=("$p"); done
if (( ${#missing[@]} )); then
  note "installing: ${missing[*]}"
  dnf -y -q install "${missing[@]}"
else
  note "everything is already installed"
fi
if rpm -q avahi &>/dev/null && ! rpm -q avahi-tools &>/dev/null; then
  note "avahi is installed - adding avahi-tools (avahi-browse for 'upnp mdns services')"
  dnf -y -q install avahi-tools || warn "avahi-tools could not be installed - 'upnp mdns services' will not work"
fi

# ================================================================ Python 3.14
find_python() {
  local c
  for c in /usr/bin/python$PY_MINOR /usr/local/bin/python$PY_MINOR; do
    if [[ -x "$c" ]] && "$c" -c "import sys; assert sys.version_info[:2] == (${PY_MINOR/./, })" 2>/dev/null; then
      echo "$c"; return 0
    fi
  done
  return 1
}

python_ok() {   # check the modules the application needs
  "$1" -c 'import ssl, json, venv, ensurepip, http.server, xml.etree.ElementTree, ipaddress, fcntl, urllib.request' 2>/dev/null
}

build_python() {
  note "building Python $PY_SRC_VER from source (takes several minutes, log: $PY_BUILD_LOG)"
  dnf -y -q install gcc make pkgconf-pkg-config openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel \
      sqlite-devel readline-devel ncurses-devel gdbm-devel libuuid-devel libzstd-devel expat-devel
  local tmp; tmp=$(mktemp -d /tmp/fake-igd-python.XXXXXX)
  note "downloading $PY_SRC_URL"
  curl -fsSL --retry 3 -o "$tmp/py.tar.xz" "$PY_SRC_URL" || die "Downloading Python failed."
  echo "$PY_SRC_SHA256  $tmp/py.tar.xz" | sha256sum -c --quiet - || die "SHA-256 checksum of the Python archive does not match!"
  note "SHA-256 verified"
  tar -xJf "$tmp/py.tar.xz" -C "$tmp"
  local opts=(--prefix=/usr/local --with-ensurepip=install --enable-loadable-sqlite-extensions)
  if [[ "${PY_OPTIMIZE:-0}" == "1" ]]; then opts+=(--enable-optimizations --with-lto); fi
  ( cd "$tmp/Python-$PY_SRC_VER" && ./configure "${opts[@]}" && make -j"$(nproc)" && make altinstall ) \
    >"$PY_BUILD_LOG" 2>&1 || { tail -n 30 "$PY_BUILD_LOG" >&2; die "Building Python failed, see $PY_BUILD_LOG"; }
  rm -rf "$tmp"
  note "Python installed to /usr/local/bin/python$PY_MINOR"
}

step "Python $PY_MINOR"
PY=""
if [[ $PY_SOURCE != always ]]; then
  PY=$(find_python || true)
  if [[ -z "$PY" ]]; then
    note "trying the python$PY_MINOR package from the repositories (AlmaLinux 9.8+ AppStream)"
    if dnf -y -q install "python$PY_MINOR" "python$PY_MINOR-pip" 2>/dev/null || dnf -y -q install "python$PY_MINOR" 2>/dev/null; then
      PY=$(find_python || true)
    else
      note "python$PY_MINOR is not in the repositories (older minor release? try: dnf upgrade)"
    fi
  fi
fi
if [[ -z "$PY" ]]; then
  [[ $PY_SOURCE == never ]] && die "Python $PY_MINOR is not available and building is disabled (--no-python-build). Update the system: dnf upgrade"
  build_python
  PY=$(find_python || true)
  [[ -n "$PY" ]] || die "Could not install Python $PY_MINOR."
fi
python_ok "$PY" || die "$PY lacks required modules (ssl/venv/ensurepip...). Try --python-from-source."
note "using $PY ($("$PY" --version 2>&1))"

# ================================================================ user
step "System user and group $APP"
if id "$APP" &>/dev/null; then
  note "already exists"
else
  useradd --system --no-create-home --home-dir "$STATE_DIR" --shell /sbin/nologin --comment "fake-igd UPnP logger" "$APP"
  note "created"
fi
ADDED_USER=""
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] && ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx "$APP"; then
  usermod -aG "$APP" "$SUDO_USER"
  ADDED_USER=$SUDO_USER
  note "user $SUDO_USER added to group $APP (read logs with 'upnp' without sudo after logging in again)"
fi

# ================================================================ application + venv
WAS_ACTIVE=0
systemctl is-active --quiet $APP && WAS_ACTIVE=1

step "Application in $OPT_DIR"
install -d -m 0755 "$OPT_DIR"
install -m 0755 "$SRC_DIR/src/$APP.py" "$OPT_DIR/$APP.py"
install -m 0755 "$SRC_DIR/src/upnp.py" "$OPT_DIR/upnp.py"
install -m 0644 "$SRC_DIR/src/upnp_console.py" "$OPT_DIR/upnp_console.py"
install -m 0644 "$SRC_DIR/src/upnp_mdns.py" "$OPT_DIR/upnp_mdns.py"
install -m 0755 "$SRC_DIR/uninstall.sh" "$OPT_DIR/uninstall.sh"
install -m 0755 "$SRC_DIR/install.sh" "$OPT_DIR/install.sh"
if [[ -f "$SRC_DIR/README.md" ]]; then install -m 0644 "$SRC_DIR/README.md" "$OPT_DIR/README.md"; fi
echo "$APP_VERSION" > "$OPT_DIR/VERSION"
note "done${OLD_VERSION:+ (previous version: $OLD_VERSION)}"

step "Virtualenv $VENV (Python $PY_MINOR + colorama)"
if [[ -x "$VENV/bin/python" ]] && ! "$VENV/bin/python" -c "import sys; assert sys.version_info[:2] == (${PY_MINOR/./, })" 2>/dev/null; then
  note "existing venv uses a different Python version, recreating"
  rm -rf "$VENV"
fi
if [[ -x "$VENV/bin/python" ]]; then
  "$PY" -m venv --upgrade "$VENV" >/dev/null 2>&1 || true     # follow Python patch updates
else
  "$PY" -m venv "$VENV"
fi
if ls "$SRC_DIR"/vendor/colorama-*.whl &>/dev/null; then
  "$VENV/bin/python" -m pip install -q --disable-pip-version-check --no-index --find-links "$SRC_DIR/vendor" --upgrade colorama \
    || warn "Installing colorama from the package failed."
fi
if ! "$VENV/bin/python" -c 'import colorama' 2>/dev/null; then
  "$VENV/bin/python" -m pip install -q --disable-pip-version-check --upgrade colorama \
    || warn "Could not install colorama - the CLI will use raw ANSI colours instead."
fi
note "$("$VENV/bin/python" --version), colorama $("$VENV/bin/python" -c 'import colorama; print(colorama.__version__)' 2>/dev/null || echo 'missing')"
"$VENV/bin/python" -m py_compile "$OPT_DIR/$APP.py" "$OPT_DIR/upnp.py" "$OPT_DIR/upnp_console.py" "$OPT_DIR/upnp_mdns.py" \
  || die "Syntax check failed."
rm -rf "$OPT_DIR/__pycache__"

step "upnp command, bash completion"
for b in upnp $APP-ports; do
  if [[ -e "$BIN_DIR/$b" ]] && rpm -qf "$BIN_DIR/$b" &>/dev/null; then
    die "$BIN_DIR/$b belongs to RPM package $(rpm -qf "$BIN_DIR/$b") - not overwriting it."
  fi
done
cat > "$BIN_DIR/upnp" <<EOF
#!/bin/sh
# fake-igd CLI (installed by $APP $APP_VERSION)
exec $VENV/bin/python -I $OPT_DIR/upnp.py "\$@"
EOF
cat > "$BIN_DIR/$APP-ports" <<EOF
#!/bin/sh
exec $BIN_DIR/upnp ports "\$@"
EOF
chmod 0755 "$BIN_DIR/upnp" "$BIN_DIR/$APP-ports"
rm -f /usr/local/bin/$APP-ports      # leftover from 1.0
install -D -m 0644 "$SRC_DIR/completion/upnp" /etc/bash_completion.d/upnp
install -D -m 0644 "$SRC_DIR/console/zz-upnp-console.sh" /etc/profile.d/zz-upnp-console.sh
note "upnp → $OPT_DIR/upnp.py   (help: upnp --help, the console: upnp --console)"
if [[ -f /etc/upnp-console-login ]]; then
  note "the console at login: $(head -n 1 /etc/upnp-console-login) (kept as it is)"
else
  note "the console at login: off - switch it on with: upnp --console-at-login on"
fi

# ================================================================ config and directories
step "Configuration $ETC_DIR/config.json"
install -d -m 0750 -o root -g "$APP" "$ETC_DIR"
if [[ -f "$ETC_DIR/config.json" ]]; then
  install -m 0640 -o root -g "$APP" "$SRC_DIR/config/config.json" "$ETC_DIR/config.json.dist"
  added=$("$VENV/bin/python" - "$ETC_DIR/config.json" "$ETC_DIR/config.json.dist" <<'PYEOF'
import json, os, sys
cur_p, dist_p = sys.argv[1], sys.argv[2]
cur = json.load(open(cur_p, encoding="utf-8"))
dist = json.load(open(dist_p, encoding="utf-8"))
new = [k for k in dist if k not in cur]
if new:
    merged = {k: cur.get(k, dist[k]) for k in dist}
    merged.update({k: v for k, v in cur.items() if k not in merged})
    st = os.stat(cur_p)
    tmp = cur_p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, st.st_mode & 0o777)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, cur_p)
print(" ".join(new))
PYEOF
)
  note "existing configuration kept, new defaults saved as config.json.dist"
  if [[ -n "$added" ]]; then note "new keys added with default values: $added"; fi
else
  install -m 0640 -o root -g "$APP" "$SRC_DIR/config/config.json" "$ETC_DIR/config.json"
  note "default configuration created"
fi
"$VENV/bin/python" -m json.tool "$ETC_DIR/config.json" >/dev/null || die "$ETC_DIR/config.json is not valid JSON."
HTTP_PORT=$("$VENV/bin/python" -c "import json;print(int(json.load(open('$ETC_DIR/config.json')).get('http_port',5000)))")

step "Log and state directories"
install -d -m 0750 -o "$APP" -g "$APP" "$LOG_DIR" "$STATE_DIR"
note "$LOG_DIR  $STATE_DIR"

step "systemd service and logrotate"
sed "s|@VENV@|$VENV|g; s|@OPT@|$OPT_DIR|g; s|@ETC@|$ETC_DIR|g" "$SRC_DIR/systemd/$APP.service" > "$UNIT"
chmod 0644 "$UNIT"
install -m 0644 "$SRC_DIR/logrotate/$APP" /etc/logrotate.d/$APP
systemctl daemon-reload
if command -v systemd-analyze >/dev/null; then
  systemd-analyze verify "$UNIT" 2>&1 | grep -v -e '^$' | sed 's/^/    /' || true
fi
note "$UNIT"

if command -v restorecon >/dev/null; then
  restorecon -RF "$OPT_DIR" "$ETC_DIR" "$LOG_DIR" "$STATE_DIR" "$UNIT" /etc/logrotate.d/$APP \
                 "$BIN_DIR/upnp" "$BIN_DIR/$APP-ports" /etc/bash_completion.d/upnp /etc/profile.d/zz-upnp-console.sh \
                 2>/dev/null || true
  if [[ -x /usr/local/bin/python$PY_MINOR ]]; then
    restorecon -RF /usr/local/bin "/usr/local/lib/python$PY_MINOR" 2>/dev/null || true
  fi
fi

# ================================================================ port collisions
step "Port check"
if ss -Hltn "sport = :$HTTP_PORT" | grep -q . && ! ss -Hltnp "sport = :$HTTP_PORT" | grep -q "$APP\|python"; then
  ss -Hltnp "sport = :$HTTP_PORT" | sed 's/^/    /'
  die "TCP port $HTTP_PORT is already used by another program. Change http_port in $ETC_DIR/config.json and run the installer again."
fi
if ss -Hlunp "sport = :1900" | grep -v -e "$APP" -e python | grep -q .; then
  warn "Another program already listens on UDP 1900 (another UPnP/DLNA server?):"
  ss -Hlunp "sport = :1900" | sed 's/^/    /' >&2
  warn "fake-igd will run alongside it, but that program may answer the PS5 too."
else
  note "1900/udp and $HTTP_PORT/tcp are free"
fi

# ================================================================ firewall
FW_HINT=""
if systemctl is-active --quiet firewalld; then
  if [[ $DO_FIREWALL -eq 1 ]]; then
    step "firewalld (1900/udp, $HTTP_PORT/tcp)"
    zones=$(firewall-cmd --get-active-zones | grep -v '^[[:space:]]' || true)
    [[ -n "$zones" ]] || zones=$(firewall-cmd --get-default-zone)
    for z in $zones; do
      firewall-cmd --quiet --permanent --zone="$z" --add-port=1900/udp
      firewall-cmd --quiet --permanent --zone="$z" --add-port="$HTTP_PORT/tcp"
      note "zone $z: opened"
    done
    firewall-cmd --quiet --reload
    echo "$HTTP_PORT" > "$STATE_DIR/.firewall-port"
    chown "$APP:$APP" "$STATE_DIR/.firewall-port"
    warn "Ports are open in ALL active zones. If the server has an internet-facing interface, remove them from its zone:"
    warn "  firewall-cmd --permanent --zone=<zone> --remove-port=$HTTP_PORT/tcp --remove-port=1900/udp && firewall-cmd --reload"
  fi
else
  step "Host firewall"
  if systemctl is-active --quiet nftables; then FW_HINT="nftables"
  elif systemctl is-active --quiet iptables || { command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -qvE '^-P INPUT ACCEPT$'; }; then FW_HINT="iptables"
  fi
  if [[ -n "$FW_HINT" ]]; then
    warn "firewalld is not running, but $FW_HINT rules are active. The installer does NOT change them."
    warn "Allow 1900/udp and $HTTP_PORT/tcp on the LAN interfaces - print the exact rules with:  upnp firewall"
  else
    note "no active host firewall detected"
  fi
fi

# ================================================================ start
trap - ERR
step "Service $APP"
systemctl enable --quiet $APP
if [[ $DO_START -eq 1 ]]; then
  if [[ $WAS_ACTIVE -eq 1 || $UPGRADE -eq 1 ]]; then systemctl restart $APP; else systemctl start $APP; fi
  sleep 3
  if systemctl is-active --quiet $APP; then
    note "${c_ok}running${c_off} and starts automatically on boot"
  else
    systemctl status $APP --no-pager -l || true
    die "The service did not start - see: journalctl -u $APP -e  and  $LOG_DIR/$APP.log"
  fi
  echo
  "$BIN_DIR/upnp" status || true
else
  note "enabled on boot, not started (--no-start). Start it with: upnp start"
fi

echo
if [[ $UPGRADE -eq 1 ]]; then
  echo "${c_ok}${c_b}Done - fake-igd upgraded ${OLD_VERSION:-?} → $APP_VERSION.${c_off}"
else
  echo "${c_ok}${c_b}Done - fake-igd $APP_VERSION installed.${c_off}"
fi
cat <<EOF
  Console:       upnp --console         (menus, opens on the live log; q leaves it)
  CLI:           upnp --help            (upnp status | test | firewall | ports | log -f | dnat | mdns ...)
  Config:        $ETC_DIR/config.json  (upnp config / sudo upnp config set ...)
  Logs:          $LOG_DIR/
  Python:        $PY  →  venv $VENV
  Upgrade:       sudo ./install.sh --upgrade   (from a newer extracted package)
  Uninstall:     sudo $OPT_DIR/uninstall.sh [--purge]
EOF
if [[ -n "$ADDED_USER" ]]; then echo "  ${c_warn}User $ADDED_USER was added to group $APP - log out and back in.${c_off}"; fi
if [[ -n "$FW_HINT" ]]; then echo "  ${c_warn}Host firewall ($FW_HINT): run 'upnp firewall' and apply the rules, then 'upnp test'.${c_off}"; fi
echo "  Tab completion works in new shells."
echo
echo "Remember: UPnP on the router must be DISABLED and the server must be in the same VLAN as the PS5."
