#!/usr/bin/env bash
#
# install.sh — set up fake-igd on AlmaLinux 9 (and Rocky / RHEL 9).
#
# The same shape as otp's installer: packages, Python 3.14 with colorama, the
# service account, the configuration, the systemd units, log rotation, the
# `upnp` command and its console, nginx with TLS and a php-fpm pool of
# fake-igd's own for the web pages, SELinux, the firewall (iptables: a chain of
# fake-igd's own, as otp's OTP-IN), the first account of the pages, and a
# check that it all works. Run it from inside the unpacked folder, as root:
#
#     sudo ./install.sh
#
# Everything it asks can be given on the command line; --help lists it.
# --upgrade replaces the program and the pages and restarts, keeping the
# configuration, the logs, the state and the accounts. --uninstall removes
# the services and the pages and keeps everything recorded.
#
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(sed -n "s/^__version__ = '\(.*\)'.*/\1/p" "$SOURCE_DIR/src/fake-igd.py" 2>/dev/null | head -n1)"
VERSION="${VERSION:-unknown}"
APP=fake-igd
SERVICE_USER="fake-igd"
WEB_GROUP="fake-igd-web"
POOL_USER="fake-igd-www"
OPT_DIR=/opt/$APP
VENV=$OPT_DIR/venv
ETC_DIR=/etc/$APP
CONFIG_FILE=$ETC_DIR/config.json
LOG_DIR=/var/log/$APP
STATE_DIR=/var/lib/$APP
WEB_DIR=/var/www/$APP
CERT_DIR=/etc/nginx/certs
NGINX_CONF=/etc/nginx/conf.d/$APP.conf
UNIT_DIR=/etc/systemd/system
BIN_DIR=/usr/bin            # /usr/bin: sudo's secure_path on EL9 does not include /usr/local/bin

PY_MINOR=3.14
PY_SRC_VER=${PY_SRC_VER:-3.14.9}
PY_SRC_SHA256=${PY_SRC_SHA256:-e02d9ac21cebda6e46435369744a92c65cc7cd8669697694122cf97ffacd1e53}
PY_SRC_URL=https://www.python.org/ftp/python/$PY_SRC_VER/Python-$PY_SRC_VER.tar.xz
PY_BUILD_LOG=/var/log/$APP-python-build.log

ASSUME_YES=""
WITH_WEB="yes"
DO_UPGRADE=""
DO_UNINSTALL=""
PURGE=""
REWRITE_NGINX=""
FIREWALL="auto"            # auto: iptables when it is in use here; on / off
DO_START="yes"
FORCE=""
PY_SOURCE=auto
PHP_STREAM="8.3"

SERVER_NAME="$(hostname -f 2>/dev/null || hostname)"
ADMIN_ALLOW=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""
CERT_FILE=""
KEY_FILE=""
SITE_NAME=""

# ---------------------------------------------------------------------------
# Saying things (otp's words and colours)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_HEAD=$'\033[1;36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
    C_BAD=$'\033[1;31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_HEAD=""; C_OK=""; C_WARN=""; C_BAD=""; C_DIM=""; C_OFF=""
fi
step()  { printf '\n%s==> %s%s\n' "$C_HEAD" "$1" "$C_OFF"; }
say()   { printf '    %s\n' "$1"; }
note()  { printf '    %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
good()  { printf '    %s%s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn()  { printf '    %s%s%s\n' "$C_WARN" "$1" "$C_OFF"; }
fail()  { printf '\n%sERROR: %s%s\n' "$C_BAD" "$1" "$C_OFF" >&2; exit 1; }
# Whatever stops this script says what and where - never a silent end.
trap 'rc=$?; printf "\n%sERROR: line %s: \"%s\" ended with %s; nothing after it was done.%s\n" "${C_BAD:-}" "$LINENO" "$BASH_COMMAND" "$rc" "${C_OFF:-}" >&2; exit "$rc"' ERR

ask() {          # ask VAR "prompt" "default"
    local var="$1" prompt="$2" default="${3:-}" answer
    if [[ -n "$ASSUME_YES" ]]; then
        printf -v "$var" '%s' "${!var:-$default}"
        return
    fi
    if [[ -n "${!var:-}" ]]; then default="${!var}"; fi
    if [[ -n "$default" ]]; then
        read -r -p "    $prompt [$default]: " answer
    else
        read -r -p "    $prompt: " answer
    fi
    printf -v "$var" '%s' "${answer:-$default}"
}

ask_secret() {
    local var="$1" prompt="$2" answer again
    [[ -n "$ASSUME_YES" ]] && return
    while true; do
        read -r -s -p "    $prompt: " answer; echo
        [[ -z "$answer" ]] && { printf -v "$var" '%s' ''; return; }
        if (( ${#answer} < 8 )); then
            warn "that is shorter than eight characters"
            continue
        fi
        read -r -s -p "    and again: " again; echo
        [[ "$answer" == "$again" ]] && { printf -v "$var" '%s' "$answer"; return; }
        warn "those two are not the same"
    done
}

confirm() {      # confirm "question" [default y|n]
    local default="${2:-y}" answer
    [[ -n "$ASSUME_YES" ]] && [[ "$default" == "y" ]] && return 0
    [[ -n "$ASSUME_YES" ]] && return 1
    read -r -p "    $1 [$( [[ $default == y ]] && echo Y/n || echo y/N )] " answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

cidr_list_ok() {
    python3 - "$1" <<'PY'
import ipaddress, sys
bad = []
for one in sys.argv[1].split(','):
    one = one.strip()
    if not one:
        continue
    try:
        ipaddress.ip_network(one, strict=False)
    except ValueError:
        bad.append(one)
if bad:
    sys.stderr.write('not an address or a network: %s\n' % ', '.join(bad))
    sys.exit(1)
PY
}

usage() {
    cat <<EOF
fake-igd installer $VERSION — a fake UPnP router (IGD) that logs which ports a PS5 asks for

Usage: sudo ./install.sh [options]

  --server-name HOST        the web pages' hostname (default: $SERVER_NAME)
  --admin-allow CIDR[,..]   who may reach the web pages (nginx allow; default the RFC 1918 networks)
  --admin-user NAME         the first account of the pages (admin)
  --admin-password -        its password, read from the terminal or standard input
                            (or FAKE_IGD_ADMIN_PASSWORD; otherwise one is made and printed)
  --cert FILE --key FILE    the TLS certificate and key for nginx (else one is made, self-signed)
  --site-name NAME          what to call this installation on the pages
  --no-web                  the UPnP service and the command line only: no pages, no nginx, no PHP
  --rewrite-nginx           write nginx's fake-igd.conf afresh even where one is there
  --firewall                put fake-igd's iptables chain (FAKE-IGD-IN) in place even where
                            iptables does not look in use; by default it is put in place when
                            it is (iptables.service or rules in INPUT) and firewalld is not
  --no-firewall             leave the firewall alone (upnp firewall prints the rules)
  --no-start                install but do not start the services
  --python-from-source      always build Python 3.14 from source (python.org)
  --no-python-build         never build from source (dnf only)
  --upgrade                 replace the program and the pages, restart; keep everything else
  --uninstall [--purge]     remove the services and the pages; --purge also the configuration,
                            the logs, the state, the database and the accounts
  --force                   go on on another OS than EL9
  --yes                     never ask; take the defaults
  --help                    this

  PY_SRC_VER / PY_SRC_SHA256   another 3.14.x from source (with its SHA-256 from python.org)
  PY_OPTIMIZE=1                build from source with PGO/LTO (faster Python, much longer build)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-name)        SERVER_NAME="$2"; shift 2;;
        --admin-allow)        ADMIN_ALLOW="$2"; shift 2;;
        --admin-user)         ADMIN_USER="$2"; shift 2;;
        --admin-password)     ADMIN_PASSWORD="$2"; shift 2;;
        --cert)               CERT_FILE="$2"; shift 2;;
        --key)                KEY_FILE="$2"; shift 2;;
        --site-name)          SITE_NAME="$2"; shift 2;;
        --no-web)             WITH_WEB=""; shift;;
        --rewrite-nginx)      REWRITE_NGINX="yes"; shift;;
        --firewall)           FIREWALL="on"; shift;;
        --no-firewall)        FIREWALL="off"; shift;;
        --no-start)           DO_START=""; shift;;
        --python-from-source) PY_SOURCE=always; shift;;
        --no-python-build)    PY_SOURCE=never; shift;;
        --upgrade)            DO_UPGRADE="yes"; shift;;
        --uninstall)          DO_UNINSTALL="yes"; shift;;
        --purge)              PURGE="yes"; shift;;
        --force)              FORCE="yes"; shift;;
        -y|--yes)             ASSUME_YES="yes"; shift;;
        -h|--help)            usage; exit 0;;
        *) fail "I do not know the option $1 — try --help";;
    esac
done
# The first account's password not on the command line (otp 1.0.249): "-" reads it.
if [[ "$ADMIN_PASSWORD" == "-" ]]; then
    ADMIN_PASSWORD=""
    if [[ -t 0 ]]; then
        IFS= read -r -s -p "The password of the first account: " ADMIN_PASSWORD; echo
        IFS= read -r -s -p "Again: " _again; echo
        [[ "$_again" == "$ADMIN_PASSWORD" ]] || fail "--admin-password -: the two were not the same"
        unset _again
    else
        IFS= read -r ADMIN_PASSWORD || true
    fi
    [[ -n "$ADMIN_PASSWORD" ]] || fail "--admin-password -: no password was read"
elif [[ -n "$ADMIN_PASSWORD" ]]; then
    warn "--admin-password: the password is on the command line (ps, the shell's history) -"
    warn "  next time give --admin-password - (read from the terminal) or FAKE_IGD_ADMIN_PASSWORD"
elif [[ -n "${FAKE_IGD_ADMIN_PASSWORD:-}" ]]; then
    ADMIN_PASSWORD="$FAKE_IGD_ADMIN_PASSWORD"
fi
unset FAKE_IGD_ADMIN_PASSWORD
[[ -n "$ADMIN_ALLOW" ]] && { cidr_list_ok "$ADMIN_ALLOW" || fail "--admin-allow takes addresses and networks, comma separated"; }
# Asked from the pages or `upnp upgrade`: nobody is there to answer.
[[ -n "${FAKE_IGD_UPGRADE_FROM_PAGES:-}" ]] && ASSUME_YES=yes

[[ $EUID -eq 0 ]] || fail "run this as root: sudo ./install.sh"
for f in src/$APP.py src/upnp.py src/upnp_console.py src/upnp_mdns.py src/upnp_admin.py src/igd_store.py \
         src/igd_online.py src/fake_igd_api.py deploy/fake_igd_upgrade.py deploy/fake_igd_web.py \
         config/config.json systemd/$APP.service logrotate/$APP completion/upnp console/zz-upnp-console.sh uninstall.sh; do
    [[ -f "$SOURCE_DIR/$f" ]] || fail "the package is missing $f - run install.sh from inside the unpacked folder"
done

OS_PRETTY="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}" )"
OS_MAJOR="$( . /etc/os-release 2>/dev/null; v="${VERSION_ID:-}"; printf '%s' "${v%%.*}" )"
OS_FAMILY="$( . /etc/os-release 2>/dev/null; printf '%s %s' "${ID:-}" "${ID_LIKE:-}" )"

# ===========================================================================
# Taking it away
# ===========================================================================
if [[ -n "$DO_UNINSTALL" ]]; then
    step "Taking fake-igd away"
    [[ -n "$PURGE" ]] && warn "--purge: the configuration, the logs, the state, the database and the accounts go too"
    ASSUME_YES="" confirm "Go on?" n || { say "nothing done"; exit 0; }
    exec bash "$SOURCE_DIR/uninstall.sh" ${PURGE:+--purge}
fi

# ===========================================================================
# The parts
# ===========================================================================
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]; }

find_python() {
    local c
    for c in /usr/bin/python$PY_MINOR /usr/local/bin/python$PY_MINOR; do
        if [[ -x "$c" ]] && "$c" -c "import sys; assert sys.version_info[:2] == (${PY_MINOR/./, })" 2>/dev/null; then
            echo "$c"; return 0
        fi
    done
    return 1
}

python_ok() {   # the modules the application needs
    "$1" -c 'import ssl, json, venv, ensurepip, sqlite3, hashlib, http.server, xml.etree.ElementTree, ipaddress, fcntl, urllib.request; hashlib.scrypt' 2>/dev/null
}

build_python() {
    say "building Python $PY_SRC_VER from source (takes several minutes, log: $PY_BUILD_LOG)"
    dnf -y -q install gcc make pkgconf-pkg-config openssl-devel bzip2-devel libffi-devel zlib-devel xz-devel \
        sqlite-devel readline-devel ncurses-devel gdbm-devel libuuid-devel libzstd-devel expat-devel
    local tmp; tmp=$(mktemp -d /tmp/fake-igd-python.XXXXXX)
    say "downloading $PY_SRC_URL"
    curl -fsSL --retry 3 -o "$tmp/py.tar.xz" "$PY_SRC_URL" || fail "downloading Python failed"
    echo "$PY_SRC_SHA256  $tmp/py.tar.xz" | sha256sum -c --quiet - || fail "the SHA-256 of the Python archive does not match"
    good "SHA-256 checked"
    tar -xJf "$tmp/py.tar.xz" -C "$tmp"
    local opts=(--prefix=/usr/local --with-ensurepip=install --enable-loadable-sqlite-extensions)
    if [[ "${PY_OPTIMIZE:-0}" == "1" ]]; then opts+=(--enable-optimizations --with-lto); fi
    ( cd "$tmp/Python-$PY_SRC_VER" && ./configure "${opts[@]}" && make -j"$(nproc)" && make altinstall ) \
        >"$PY_BUILD_LOG" 2>&1 || { tail -n 30 "$PY_BUILD_LOG" >&2; fail "building Python failed, see $PY_BUILD_LOG"; }
    rm -rf "$tmp"
    good "Python installed to /usr/local/bin/python$PY_MINOR"
}

ensure_python() {
    step "Python $PY_MINOR"
    PY=""
    if [[ $PY_SOURCE != always ]]; then
        PY=$(find_python || true)
        if [[ -z "$PY" ]]; then
            say "trying the python$PY_MINOR package from the repositories (AlmaLinux 9.8+ AppStream)"
            if dnf -y -q install "python$PY_MINOR" "python$PY_MINOR-pip" 2>/dev/null || dnf -y -q install "python$PY_MINOR" 2>/dev/null; then
                PY=$(find_python || true)
            else
                note "python$PY_MINOR is not in the repositories (an older minor release? dnf upgrade)"
            fi
        fi
    fi
    if [[ -z "$PY" ]]; then
        [[ $PY_SOURCE == never ]] && fail "Python $PY_MINOR is not there and building it is off (--no-python-build): dnf upgrade"
        build_python
        PY=$(find_python || true)
        [[ -n "$PY" ]] || fail "Python $PY_MINOR could not be installed"
    fi
    python_ok "$PY" || fail "$PY lacks modules fake-igd needs (ssl, venv, sqlite3, scrypt…) - try --python-from-source"
    good "$PY ($("$PY" --version 2>&1))"
}

install_program() {
    step "The program in $OPT_DIR"
    install -d -m 0755 "$OPT_DIR"
    install -m 0755 "$SOURCE_DIR/src/$APP.py" "$OPT_DIR/$APP.py"
    install -m 0755 "$SOURCE_DIR/src/upnp.py" "$OPT_DIR/upnp.py"
    install -m 0755 "$SOURCE_DIR/src/fake_igd_api.py" "$OPT_DIR/fake_igd_api.py"
    # Every module of the package (1.5.2): a list here missed a new one (igd_panes, 1.5.1).
    local m
    for m in "$SOURCE_DIR"/src/*.py; do
        case "$(basename "$m")" in fake-igd.py|upnp.py|fake_igd_api.py) continue;; esac
        install -m 0644 "$m" "$OPT_DIR/$(basename "$m")"
    done
    # ...and none that a version before shipped and this one does not (an old pane's API).
    for m in "$OPT_DIR"/api_*.py; do
        [[ -f "$m" && ! -f "$SOURCE_DIR/src/$(basename "$m")" ]] && rm -f "$m"
    done
    install -m 0755 "$SOURCE_DIR/uninstall.sh" "$OPT_DIR/uninstall.sh"
    install -m 0755 "$SOURCE_DIR/install.sh" "$OPT_DIR/install.sh"
    local doc
    for doc in README.md CHANGELOG.md; do
        [[ -f "$SOURCE_DIR/$doc" ]] && install -m 0644 "$SOURCE_DIR/$doc" "$OPT_DIR/$doc"
    done
    echo "$VERSION" > "$OPT_DIR/VERSION"
    good "fake-igd $VERSION${OLD_VERSION:+ (it was $OLD_VERSION)}"

    say "virtualenv $VENV (Python $PY_MINOR + colorama)"
    if [[ -x "$VENV/bin/python" ]] && ! "$VENV/bin/python" -c "import sys; assert sys.version_info[:2] == (${PY_MINOR/./, })" 2>/dev/null; then
        note "the virtualenv runs another Python - made again"
        rm -rf "$VENV"
    fi
    if [[ -x "$VENV/bin/python" ]]; then
        "$PY" -m venv --upgrade "$VENV" >/dev/null 2>&1 || true
    else
        "$PY" -m venv "$VENV"
    fi
    if ls "$SOURCE_DIR"/vendor/colorama-*.whl &>/dev/null; then
        "$VENV/bin/python" -m pip install -q --disable-pip-version-check --no-index --find-links "$SOURCE_DIR/vendor" --upgrade colorama \
            || warn "colorama from the package would not install"
    fi
    if ! "$VENV/bin/python" -c 'import colorama' 2>/dev/null; then
        "$VENV/bin/python" -m pip install -q --disable-pip-version-check --upgrade colorama \
            || warn "colorama could not be installed - the command line writes the same colours by hand"
    fi
    good "$("$VENV/bin/python" --version), colorama $("$VENV/bin/python" -c 'import colorama; print(colorama.__version__)' 2>/dev/null || echo 'missing')"
    "$VENV/bin/python" -m py_compile "$OPT_DIR"/*.py || fail "the program does not compile"
    rm -rf "$OPT_DIR/__pycache__"

    say "the upnp command, bash completion, the console at login, log rotation"
    for b in upnp $APP-ports; do
        if [[ -e "$BIN_DIR/$b" ]] && rpm -qf "$BIN_DIR/$b" &>/dev/null; then
            fail "$BIN_DIR/$b belongs to the RPM package $(rpm -qf "$BIN_DIR/$b") - not written over"
        fi
    done
    cat > "$BIN_DIR/upnp" <<EOF
#!/bin/sh
# fake-igd CLI (installed by $APP $VERSION)
exec $VENV/bin/python -I $OPT_DIR/upnp.py "\$@"
EOF
    cat > "$BIN_DIR/$APP-ports" <<EOF
#!/bin/sh
exec $BIN_DIR/upnp ports "\$@"
EOF
    chmod 0755 "$BIN_DIR/upnp" "$BIN_DIR/$APP-ports"
    rm -f /usr/local/bin/$APP-ports
    install -D -m 0644 "$SOURCE_DIR/completion/upnp" /etc/bash_completion.d/upnp
    install -D -m 0644 "$SOURCE_DIR/console/zz-upnp-console.sh" /etc/profile.d/zz-upnp-console.sh
    install -m 0644 "$SOURCE_DIR/logrotate/$APP" /etc/logrotate.d/$APP
    good "upnp → $OPT_DIR/upnp.py   (upnp --help, upnp --console)"
    if [[ -f /etc/upnp-console-login ]]; then
        note "the console at login: $(head -n 1 /etc/upnp-console-login) (kept as it is)"
    fi
}

install_config() {
    step "Configuration $CONFIG_FILE"
    install -d -m 0750 -o root -g "$SERVICE_USER" "$ETC_DIR"
    if [[ -L "$CONFIG_FILE" ]]; then
        fail "$CONFIG_FILE is a link - root does not write through one; put the file itself there"
    elif [[ -f "$CONFIG_FILE" ]]; then
        install -m 0640 -o root -g "$SERVICE_USER" "$SOURCE_DIR/config/config.json" "$ETC_DIR/config.json.dist"
        ADDED_KEYS=$("$VENV/bin/python" - "$CONFIG_FILE" "$ETC_DIR/config.json.dist" <<'PY'
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
PY
)
        good "kept as it is; the new defaults are in config.json.dist"
        [[ -n "$ADDED_KEYS" ]] && say "new keys, with their defaults: $ADDED_KEYS"
    else
        install -m 0660 -o root -g "$SERVICE_USER" "$SOURCE_DIR/config/config.json" "$CONFIG_FILE"
        ADDED_KEYS="(all)"
        good "the defaults written"
    fi
    # The pages save settings into it (fake-igd-api, as fake-igd): the group may write it.
    chown root:"$SERVICE_USER" "$CONFIG_FILE"
    chmod 0660 "$CONFIG_FILE"
    cfg_set() {     # cfg_set KEY JSON-VALUE
        "$VENV/bin/python" - "$CONFIG_FILE" "$1" "$2" <<'PY'
import json, sys
p, k, v = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
with open(p, "r+", encoding="utf-8") as f:
    d = json.load(f)
    d[k] = v
    f.seek(0)
    json.dump(d, f, ensure_ascii=False, indent=2)
    f.write("\n")
    f.truncate()
PY
    }
    if [[ -n "$ADMIN_ALLOW" ]]; then
        cfg_set web_allow "$(python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.argv[1].split(",") if x.strip()]))' "$ADMIN_ALLOW")"
    fi
    [[ -n "$SITE_NAME" ]] && cfg_set site_name "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$SITE_NAME")"
    "$VENV/bin/python" -m json.tool "$CONFIG_FILE" >/dev/null || fail "$CONFIG_FILE is not valid JSON"
    HTTP_PORT=$("$VENV/bin/python" -c "import json;print(int(json.load(open('$CONFIG_FILE')).get('http_port',5000)))")
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR" "$STATE_DIR"
    for d in "$STATE_DIR/upgrade" "$STATE_DIR/web"; do
        [[ -L "$d" ]] && fail "$d is a symbolic link, which it never should be; look at it before running this again"
        install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$d"
    done
    good "$LOG_DIR  $STATE_DIR"
}

install_upgrader() {
    step "Upgrades from the pages and upnp upgrade"
    install -m 0755 -o root -g root "$SOURCE_DIR/deploy/fake_igd_upgrade.py" "$OPT_DIR/fake_igd_upgrade.py"
    install -m 0755 -o root -g root "$SOURCE_DIR/deploy/fake_igd_web.py" "$OPT_DIR/fake_igd_web.py"
    # root's part of each pane (1.6.0): root's alone, exactly the package's
    local rm_
    for rm_ in "$OPT_DIR"/root_*.py; do
        [[ -f "$rm_" && ! -f "$SOURCE_DIR/deploy/$(basename "$rm_")" ]] && rm -f "$rm_"
    done
    for rm_ in "$SOURCE_DIR"/deploy/root_*.py; do
        [[ -f "$rm_" ]] && install -m 0644 -o root -g root "$rm_" "$OPT_DIR/$(basename "$rm_")"
    done
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/web/ask"
    install -d -m 0755 -o root -g root "$OPT_DIR/release-keys"
    local k
    for k in "$SOURCE_DIR"/deploy/release-keys/*.pub; do
        [[ -f "$k" ]] && install -m 0644 -o root -g root "$k" "$OPT_DIR/release-keys/"
    done
    # Exactly the package's keys (otp 1.0.44): one a release no longer ships is trusted no longer.
    for k in "$OPT_DIR"/release-keys/*.pub; do
        [[ -f "$k" ]] || continue
        [[ -f "$SOURCE_DIR/deploy/release-keys/$(basename "$k")" ]] || rm -f "$k"
    done
    for u in fake-igd-upgrade.path fake-igd-upgrade.service fake-igd-web.path fake-igd-web.service; do
        install -m 0644 "$SOURCE_DIR/deploy/$u" "$UNIT_DIR/$u"
    done
    systemctl daemon-reload
    systemctl enable --now fake-igd-upgrade.path fake-igd-web.path >/dev/null 2>&1 \
        || warn "the path units would not start - systemctl status fake-igd-upgrade.path"
    good "packages signed by $(ls "$OPT_DIR/release-keys" 2>/dev/null | sed 's/\.pub$//' | paste -sd, - || true) are taken"
    command -v openssl >/dev/null || warn "openssl is missing - a package's signature cannot be checked"
}

install_units() {
    step "The services"
    local u
    for u in "$APP.service:systemd/$APP.service" "fake-igd-api.service:deploy/fake-igd-api.service"; do
        sed "s|@VENV@|$VENV|g; s|@OPT@|$OPT_DIR|g; s|@ETC@|$ETC_DIR|g" "$SOURCE_DIR/${u#*:}" > "$UNIT_DIR/${u%%:*}"
        chmod 0644 "$UNIT_DIR/${u%%:*}"
    done
    systemctl daemon-reload
    if command -v restorecon >/dev/null; then
        restorecon -RF "$OPT_DIR" "$ETC_DIR" "$LOG_DIR" "$STATE_DIR" "$UNIT_DIR"/fake-igd* /etc/logrotate.d/$APP \
                       "$BIN_DIR/upnp" "$BIN_DIR/$APP-ports" /etc/bash_completion.d/upnp /etc/profile.d/zz-upnp-console.sh \
                       2>/dev/null || true
        [[ -x /usr/local/bin/python$PY_MINOR ]] && restorecon -RF /usr/local/bin "/usr/local/lib/python$PY_MINOR" 2>/dev/null || true
    fi
    systemctl enable --quiet $APP fake-igd-api
    if [[ -n "$DO_START" ]]; then
        systemctl restart fake-igd-api
        systemctl restart $APP
        sleep 3
        local bad=""
        for u in $APP fake-igd-api; do
            if systemctl is-active --quiet "$u"; then good "$u.service is running"
            else bad="$bad $u"; warn "$u.service did not start - the last of its log:"; journalctl -u "$u" -n 15 --no-pager || true
            fi
        done
        [[ -z "$bad" ]] || return 1
    else
        note "enabled at boot, not started (--no-start): upnp start; systemctl start fake-igd-api"
    fi
    return 0
}

# ---- PHP (otp's ensure_php, for the RHEL family) -------------------------------------
php_fpm_version() {
    local b v
    b="$(command -v php-fpm 2>/dev/null || true)"; [[ -z "$b" && -x /usr/sbin/php-fpm ]] && b=/usr/sbin/php-fpm
    [[ -n "$b" ]] || { echo ""; return; }
    v="$("$b" -v 2>/dev/null | head -n 1 | awk '{print $2}')"
    echo "${v%%[-+~]*}"
}
php_guard() {           # the second layer, for every PHP on the machine (otp's)
    local dir
    for dir in /etc/php.d; do
        [[ -d "$dir" ]] || continue
        if [[ -f "$dir/99-php2shell.ini" ]] && grep -q 'upload_progress.enabled *= *0' "$dir/99-php2shell.ini"; then
            continue
        fi
        install -m 0644 "$SOURCE_DIR/deploy/99-php2shell.ini" "$dir/99-php2shell.ini"
        good "$dir/99-php2shell.ini - session upload progress off, sessions strict"
    done
}
ensure_php() {
    step "PHP"
    if ! command -v php-fpm >/dev/null 2>&1 && [[ ! -x /usr/sbin/php-fpm ]]; then
        local streams now
        streams="$(dnf -q module list php 2>/dev/null || true)"
        now="$(dnf -q module list --enabled php 2>/dev/null || true)"
        now="$(awk '/^php /{print $2; exit}' <<< "$now")"
        if [[ -z "$now" ]] && grep -qE "^php +${PHP_STREAM//./\\.}( |$)" <<< "$streams"; then
            say "PHP comes from the stream php:$PHP_STREAM"
            dnf module enable -y "php:$PHP_STREAM" >/dev/null
        elif [[ -n "$now" ]]; then
            note "the PHP stream php:$now is enabled already: it is kept"
        fi
        dnf install -y -q php-fpm php-cli php-common
    else
        note "php-fpm is installed: left as it is (updates come with dnf upgrade)"
    fi
    local pv
    pv="$(php_fpm_version)"
    [[ -n "$pv" ]] || fail "php-fpm is not there after installing it"
    ver_ge "$pv" 8.0 || fail "php-fpm here is $pv: the pages need PHP 8.0 or newer (or install with --no-web)"
    good "php-fpm $pv"
    php_guard
}

# The machine's own IPv4 addresses (1.4.1): the pages are reached by them as often as by the name.
host_ips() { hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.' || true; }
# The names nginx answers with, as its file says (an upgrade keeps the file, and its name).
nginx_names() { [[ -f "$NGINX_CONF" ]] && sed -n 's/^[[:space:]]*server_name[[:space:]]\{1,\}\([^;]*\);.*/\1/p' "$NGINX_CONF" | head -n 1 || true; }
make_cert() {           # make_cert "name1 name2" - self-signed, for the names and every address here
    local names="$1" san="" n
    for n in $names; do san+="DNS:$n,"; done
    for n in $(host_ips); do san+="IP:$n,"; done
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$CERT_DIR/fake-igd.key" -out "$CERT_DIR/fake-igd.pem" \
        -subj "/CN=${names%% *}" -addext "subjectAltName=${san%,}" 2>/dev/null
    chmod 0600 "$CERT_DIR/fake-igd.key"
}
cert_selfmade() {       # the certificate there is one of ours: signed by itself, made by this installer
    local c="$CERT_DIR/fake-igd.pem"
    [[ -f "$c" ]] || return 1
    [[ "$(openssl x509 -in "$c" -noout -subject 2>/dev/null | sed 's/^subject=//')" == \
       "$(openssl x509 -in "$c" -noout -issuer 2>/dev/null | sed 's/^issuer=//')" ]]
}
cert_lacks() {          # what of the names and addresses here the certificate does not name
    local c="$CERT_DIR/fake-igd.pem" have n out=""
    have="$(openssl x509 -in "$c" -noout -ext subjectAltName 2>/dev/null || true)"
    for n in $1; do grep -q "DNS:$n\b" <<< "$have" || out+="$n "; done
    for n in $(host_ips); do grep -q "IP Address:$n\b" <<< "$have" || out+="$n "; done
    echo "${out% }"
}
pages_say() {           # where the pages are: by name and by every address
    local n first="The pages:     "
    for n in $(nginx_names) $(host_ips); do say "$first https://$n/admin/"; first="               "; done
}

allow_lines() {         # allow_lines "a,b" -> nginx allow lines, or the defaults
    local list="$1" out="" one
    if [[ -z "$list" ]]; then
        printf '        allow 192.168.0.0/16;\n        allow 172.16.0.0/12;\n        allow 10.0.0.0/8;'
        return
    fi
    IFS=',' read -r -a cidrs <<< "$list"
    for one in "${cidrs[@]}"; do
        one="$(echo "$one" | xargs)"
        [[ -n "$one" ]] && out+="        allow $one;"$'\n'
    done
    printf '%s' "${out%$'\n'}"
}

install_pages() {
    step "The web pages (nginx, php-fpm)"
    install -d -m 0755 "$WEB_DIR" "$WEB_DIR/admin" "$WEB_DIR/assets"
    # every page of the package (1.6.0: acme.php too), none an older one left behind
    find "$WEB_DIR" -maxdepth 1 -type f -name '*.php' -delete 2>/dev/null || true
    install -m 0644 "$SOURCE_DIR"/web/*.php "$SOURCE_DIR/web/.user.ini" "$WEB_DIR/"
    install -m 0644 "$SOURCE_DIR/web/admin/index.php" "$WEB_DIR/admin/"
    # the panes of Settings (1.6.0): exactly the package's
    rm -rf "$WEB_DIR/admin/panes" "$WEB_DIR/admin/tabs"
    if compgen -G "$SOURCE_DIR/web/admin/tabs/*.php" >/dev/null; then
        install -d -m 0755 "$WEB_DIR/admin/tabs"
        install -m 0644 "$SOURCE_DIR"/web/admin/tabs/*.php "$WEB_DIR/admin/tabs/"
    fi
    if compgen -G "$SOURCE_DIR/web/admin/panes/*.php" >/dev/null; then
        install -d -m 0755 "$WEB_DIR/admin/panes"
        install -m 0644 "$SOURCE_DIR"/web/admin/panes/*.php "$WEB_DIR/admin/panes/"
    fi
    # Only the files of this version (an old one's left behind would be served).
    find "$WEB_DIR/assets" -maxdepth 1 -type f -delete 2>/dev/null || true
    install -m 0644 "$SOURCE_DIR"/web/assets/* "$WEB_DIR/assets/"
    chown -R root:root "$WEB_DIR"
    good "$WEB_DIR"

    # ---- the pool ------------------------------------------------------------
    local pool_dir=/etc/php-fpm.d sock=/run/php-fpm/fake-igd.sock owner=nginx
    install -d -m 0755 "$pool_dir"
    local pool_new pool_changed=yes
    pool_new="$(sed -e "s|^listen = .*|listen = $sock|" -e "s|^listen.owner = .*|listen.owner = $owner|" \
                    -e "s|^listen.group = .*|listen.group = $owner|" "$SOURCE_DIR/deploy/php-fpm-fake-igd.conf")"
    if [[ -f "$pool_dir/fake-igd.conf" ]] && [[ "$(cat "$pool_dir/fake-igd.conf")" == "$pool_new" ]]; then
        pool_changed=""
    elif [[ -f "$pool_dir/fake-igd.conf" ]]; then
        cp -p "$pool_dir/fake-igd.conf" "$pool_dir/fake-igd.conf.before-$VERSION"
        note "the pool as it was is in $pool_dir/fake-igd.conf.before-$VERSION"
    fi
    [[ -n "$pool_changed" ]] && { printf '%s\n' "$pool_new" > "$pool_dir/fake-igd.conf"; chmod 0644 "$pool_dir/fake-igd.conf"; }
    good "$pool_dir/fake-igd.conf - a pool of fake-igd's own, as $POOL_USER, on $sock"
    systemctl enable php-fpm >/dev/null 2>&1 || true
    if [[ -n "$pool_changed" || ! -S "$sock" ]] || ! systemctl is-active --quiet php-fpm; then
        systemctl restart php-fpm || warn "php-fpm would not start - php-fpm -t says why"
    fi

    # ---- the certificate -------------------------------------------------------
    install -d -m 0755 "$CERT_DIR"
    if [[ -n "$CERT_FILE" && -n "$KEY_FILE" ]]; then
        install -m 0644 "$CERT_FILE" "$CERT_DIR/fake-igd.pem"
        install -m 0600 "$KEY_FILE" "$CERT_DIR/fake-igd.key"
        good "your certificate is in $CERT_DIR"
    elif [[ -f "$CERT_DIR/fake-igd.pem" && -f "$CERT_DIR/fake-igd.key" ]]; then
        local lacks names
        names="$(nginx_names)"; names="${names:-$SERVER_NAME}"
        lacks="$(cert_lacks "$names")"
        if [[ -n "$lacks" ]] && cert_selfmade; then
            # One this installer made, without the addresses (1.4.0) or a name: made again (1.4.1).
            cp -p "$CERT_DIR/fake-igd.pem" "$CERT_DIR/fake-igd.pem.before-$VERSION"
            cp -p "$CERT_DIR/fake-igd.key" "$CERT_DIR/fake-igd.key.before-$VERSION"
            make_cert "$names"
            good "the self-signed certificate made again, for $names and $(host_ips | paste -sd' ' -) (it lacked: $lacks)"
            note "the browser asks once more to accept it; the one before is fake-igd.pem.before-$VERSION"
        elif [[ -n "$lacks" ]]; then
            good "$CERT_DIR/fake-igd.pem is already there (yours - kept; it does not name: $lacks)"
        else
            good "$CERT_DIR/fake-igd.pem is already there"
        fi
    else
        warn "no certificate given - making one this machine signs itself"
        note "Browsers will complain about it. Replace $CERT_DIR/fake-igd.pem and fake-igd.key with a"
        note "real pair and reload nginx (or ./install.sh --upgrade --cert FILE --key FILE)."
        make_cert "$SERVER_NAME"
        good "made for $SERVER_NAME and $(host_ips | paste -sd' ' -)"
    fi

    # ---- nginx ---------------------------------------------------------------------
    # A file that is there is kept (otp 1.0.36): its server name and its allow list stay.
    install -D -m 0644 "$SOURCE_DIR/deploy/nginx-fake-igd.conf" "$OPT_DIR/nginx-fake-igd.conf"
    if [[ -f "$NGINX_CONF" && -z "$REWRITE_NGINX" ]]; then
        good "$NGINX_CONF is already there and kept (--rewrite-nginx writes it afresh)"
        note "the one this version ships is $OPT_DIR/nginx-fake-igd.conf, for comparing"
        # What later versions need of it, put in where it is missing (as otp's): a copy kept, nginx
        # asked, the copy put back when it says no (1.6.0: /metrics, ACME's port-80 location).
        local nbak="$NGINX_CONF.before-$VERSION" said
        cp -a "$NGINX_CONF" "$nbak"
        said="$("$VENV/bin/python" -I "$SOURCE_DIR/deploy/nginx_additions.py" "$NGINX_CONF" "$SOURCE_DIR/deploy/nginx-fake-igd.conf" || true)"
        if nginx -t >/dev/null 2>&1; then
            if [[ -n "$said" ]]; then good "$NGINX_CONF brought up to this version: $said (its copy: $nbak)"
            else rm -f "$nbak"; fi
        else
            cp -a "$nbak" "$NGINX_CONF"
            warn "nginx did not take the additions ($said), so $NGINX_CONF is as it was"
        fi
    else
        [[ -f "$NGINX_CONF" ]] && cp -a "$NGINX_CONF" "$NGINX_CONF.before-$VERSION"
        local allow="$ADMIN_ALLOW"
        if [[ -z "$allow" ]]; then
            allow="$("$VENV/bin/python" -c "import json; print(','.join(json.load(open('$CONFIG_FILE')).get('web_allow') or []))" 2>/dev/null || true)"
        fi
        "$VENV/bin/python" - "$SOURCE_DIR/deploy/nginx-fake-igd.conf" "$NGINX_CONF" "$SERVER_NAME" "$(allow_lines "$allow")" "$sock" <<'PY'
import re, sys
src, dst, host, admin, sock = sys.argv[1:6]
text = open(src).read().replace('fake-igd.example.local', host)
text = text.replace('unix:/run/php-fpm/fake-igd.sock;', 'unix:%s;' % sock)
text, n = re.subn(r'(# ADMIN-ALLOW-BEGIN\n).*?(\n\s*# ADMIN-ALLOW-END)', lambda m: m.group(1) + admin + m.group(2),
                  text, flags=re.S)
if n != 1:
    sys.exit('the allow lines were not where they were expected')
open(dst, 'w').write(text)
PY
        chmod 0644 "$NGINX_CONF"
        good "$NGINX_CONF for $SERVER_NAME"
    fi
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t || true
        fail "nginx does not read its configuration; sort that out and run this again"
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx || warn "nginx could not be started again - systemctl status nginx; journalctl -u nginx -n 30"

    # ---- SELinux ---------------------------------------------------------------
    if command -v getenforce >/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        say "SELinux is $(getenforce)"
        setsebool -P httpd_can_network_connect 1 2>/dev/null || warn "could not set httpd_can_network_connect"
        if command -v semanage >/dev/null; then
            # The API's token is read by the pages (httpd_t): the folder systemd makes is labelled for them.
            semanage fcontext -a -t httpd_var_run_t '/run/fake-igd-api(/.*)?' 2>/dev/null \
                || semanage fcontext -m -t httpd_var_run_t '/run/fake-igd-api(/.*)?' 2>/dev/null || true
            [[ -d /run/fake-igd-api ]] && restorecon -R /run/fake-igd-api 2>/dev/null || true
        else
            warn "semanage is missing (policycoreutils-python-utils) - the pages may not read the API's token"
        fi
        restorecon -R "$WEB_DIR" "$CERT_DIR" "$NGINX_CONF" /etc/php-fpm.d 2>/dev/null || true
        good "the pages may talk to the API on 127.0.0.1"
        note "If the pages say the token is unreadable: ausearch -m avc -ts recent | audit2allow -M fake-igd-local"
    fi
}

# ---- the firewall: iptables as otp's OTP-IN (or firewalld, where that is what runs) ------
iptables_in_use() {
    systemctl is-active --quiet iptables && return 0
    command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -qvE '^-P INPUT ACCEPT$'
}
open_firewall() {
    step "The firewall"
    if systemctl is-active --quiet firewalld; then
        if [[ "$FIREWALL" == "off" ]]; then note "--no-firewall: firewalld left as it is"; return 0; fi
        local zones z
        zones=$(firewall-cmd --get-active-zones | grep -v '^[[:space:]]' || true)
        [[ -n "$zones" ]] || zones=$(firewall-cmd --get-default-zone)
        for z in $zones; do
            firewall-cmd --quiet --permanent --zone="$z" --add-port=1900/udp
            firewall-cmd --quiet --permanent --zone="$z" --add-port="$HTTP_PORT/tcp"
            [[ -n "$WITH_WEB" ]] && firewall-cmd --quiet --permanent --zone="$z" --add-service=https --add-service=http
        done
        firewall-cmd --quiet --reload
        good "firewalld: 1900/udp, $HTTP_PORT/tcp${WITH_WEB:+, http and https} open in: $zones"
        return 0
    fi
    if ! command -v iptables >/dev/null; then
        note "no firewall here (no firewalld, no iptables): nothing to open"
        return 0
    fi
    local on
    on="$("$VENV/bin/python" -c "import json; print('1' if json.load(open('$CONFIG_FILE')).get('firewall') else '')")"
    if [[ "$FIREWALL" == "off" ]]; then
        note "--no-firewall: iptables left as it is - upnp firewall prints the rules"
        return 0
    fi
    if [[ -z "$on" ]]; then
        if [[ "$FIREWALL" == "on" ]] || { iptables_in_use && { [[ -z "$DO_UPGRADE" ]] || [[ " $ADDED_KEYS " == *" firewall "* ]]; }; }; then
            cfg_set firewall true
            on=1
            say "iptables is in use here: fake-igd's own chain FAKE-IGD-IN is put in place (as otp's OTP-IN)"
        else
            note "fake-igd's chain is off (firewall=off) - switch it on with: sudo upnp firewall --apply"
            return 0
        fi
    fi
    /usr/bin/python3 -I "$OPT_DIR/fake_igd_web.py" --apply | sed 's/^/    /' || warn "the chain could not be put in place - sudo upnp firewall --status"
    note "INPUT → FAKE-IGD-IN (ACCEPT only: loopback, answers, SSH, ping, 1900/udp, $HTTP_PORT/tcp${WITH_WEB:+, 80/443 from web_allow})"
    note "→ the rest of INPUT as it was. sudo upnp firewall --status · --off takes it away"
    if ! systemctl is-active --quiet iptables; then
        warn "iptables.service is not running: the chain is live now; it is kept over a reboot only"
        warn "where /etc/sysconfig/iptables is loaded at boot (dnf install iptables-services)"
    fi
}

first_account() {
    step "The first account of the pages"
    local have
    have="$("$BIN_DIR/upnp" user list --json --no-color 2>/dev/null | "$VENV/bin/python" -c 'import json,sys
want = sys.argv[1].strip().lower()
try:
    rows = json.load(sys.stdin)
except ValueError:
    rows = []
print("all" if rows else "", "yes" if any(str(r.get("name","")).lower() == want for r in rows) else "")' "$ADMIN_USER" 2>/dev/null || true)"
    if [[ "$have" == *yes* ]]; then
        if [[ -n "$ADMIN_PASSWORD" ]]; then
            UPNP_PASSWORD="$ADMIN_PASSWORD" "$BIN_DIR/upnp" user passwd "$ADMIN_USER" --password @env >/dev/null \
                && good "$ADMIN_USER was there; its password is now the one given here"
        else
            good "$ADMIN_USER is there already and was left alone"
        fi
        return 0
    fi
    if [[ "$have" == all* && -z "$ADMIN_PASSWORD" ]]; then
        good "there are accounts already: $("$BIN_DIR/upnp" user list --json --no-color 2>/dev/null | "$VENV/bin/python" -c 'import json,sys; print(", ".join(r["name"] for r in json.load(sys.stdin)))' 2>/dev/null || true)"
        return 0
    fi
    local made=""
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD="$("$VENV/bin/python" -c 'import secrets; print(secrets.token_urlsafe(12))')"
        made=yes
    fi
    [[ ${#ADMIN_PASSWORD} -ge 8 ]] || fail "--admin-password needs at least eight characters"
    UPNP_PASSWORD="$ADMIN_PASSWORD" "$BIN_DIR/upnp" user add "$ADMIN_USER" --role fulladmin --password @env \
        --note "made by the installer" >/dev/null || fail "the first account could not be made"
    good "$ADMIN_USER may sign in, as a full admin"
    if [[ -n "$made" ]]; then
        printf '\n    %sname:     %s%s\n' "$C_OK" "$ADMIN_USER" "$C_OFF"
        printf '    %spassword: %s%s\n\n' "$C_OK" "$ADMIN_PASSWORD" "$C_OFF"
        warn "Write that down now — it is not shown again."
    fi
}

does_it_work() {
    step "Does it work"
    "$BIN_DIR/upnp" status || true
    if [[ -n "$WITH_WEB" ]]; then
        local code
        code="$(curl --noproxy '*' -k -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:443:127.0.0.1" "https://$SERVER_NAME/healthz" || true)"
        [[ "$code" == "200" ]] && good "https://$SERVER_NAME/healthz answers" || warn "https://$SERVER_NAME/healthz answered $code"
        code="$(curl --noproxy '*' -k -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:443:127.0.0.1" -F a=b "https://$SERVER_NAME/admin/" || true)"
        [[ "$code" == "403" ]] && good "a multipart body is refused (php2shell)" || warn "a multipart body was answered $code, not 403"
    fi
}

pages_there() { [[ -f "$NGINX_CONF" || -d "$WEB_DIR" ]]; }

base_packages() {
    step "Packages"
    # 1.6.0, the panes of Settings: the network and the time (NetworkManager, chrony), SSH and the local
    # users (openssh, libpwquality), backups (openssh-clients, samba-client), DNS-01 by RFC 2136 (bind-utils),
    # the system's updates and whether a restart is needed (dnf-plugins-core)
    local need=(logrotate tar xz curl ca-certificates shadow-utils iproute bash-completion policycoreutils
                openssl util-linux python3 NetworkManager chrony openssh-server openssh-clients samba-client
                bind-utils dnf-plugins-core libpwquality)
    command -v semanage >/dev/null || need+=(policycoreutils-python-utils)
    command -v iptables >/dev/null || systemctl is-active --quiet firewalld || need+=(iptables-nft)
    [[ -n "$WITH_WEB" ]] && need+=(nginx)
    local missing=() p
    for p in "${need[@]}"; do rpm -q "$p" &>/dev/null || missing+=("$p"); done
    if (( ${#missing[@]} )); then
        say "installing: ${missing[*]}"
        dnf -y -q install "${missing[@]}" || fail "the packages could not be installed: ${missing[*]}"
    else
        good "everything needed is already here"
    fi
    if rpm -q avahi &>/dev/null && ! rpm -q avahi-tools &>/dev/null; then
        say "avahi is installed - adding avahi-tools (avahi-browse for 'upnp mdns services')"
        dnf -y -q install avahi-tools || warn "avahi-tools could not be installed - 'upnp mdns services' will not work"
    fi
}

accounts() {
    step "The accounts it runs as"
    getent group "$WEB_GROUP" >/dev/null || groupadd --system "$WEB_GROUP"
    if id "$SERVICE_USER" &>/dev/null; then
        good "$SERVICE_USER already exists"
    else
        useradd --system --no-create-home --home-dir "$STATE_DIR" --shell /sbin/nologin --comment "fake-igd UPnP logger" "$SERVICE_USER"
        good "made $SERVICE_USER (the UPnP service and the pages' API)"
    fi
    usermod -a -G "$WEB_GROUP" "$SERVICE_USER"
    if [[ -n "$WITH_WEB" ]]; then
        if ! id "$POOL_USER" &>/dev/null; then
            useradd --system --no-create-home --home-dir "$WEB_DIR" --shell /sbin/nologin --comment "fake-igd web pages" "$POOL_USER"
            good "made $POOL_USER (the pages' php-fpm pool)"
        fi
        usermod -a -G "$WEB_GROUP" "$POOL_USER"
        good "$POOL_USER may read the API token, through $WEB_GROUP - and nothing else of fake-igd's"
    fi
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] && ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx "$SERVICE_USER"; then
        usermod -aG "$SERVICE_USER" "$SUDO_USER"
        ADDED_USER=$SUDO_USER
        good "$SUDO_USER may read the logs with upnp without sudo (after signing in again)"
    fi
}

# ===========================================================================
OLD_VERSION=""
[[ -f "$OPT_DIR/VERSION" ]] && OLD_VERSION=$(cat "$OPT_DIR/VERSION")
ADDED_KEYS=""
ADDED_USER=""

if [[ -z "$FORCE" ]]; then
    [[ "$OS_MAJOR" == "9" && " $OS_FAMILY " =~ (rhel|almalinux|centos|rocky) ]] \
        || fail "this installer is for AlmaLinux 9 / EL9 ($OS_PRETTY here) - --force goes on anyway"
fi
command -v dnf >/dev/null || fail "dnf is missing"
command -v systemctl >/dev/null || fail "systemd is missing"

# ===========================================================================
# An upgrade: the program, the pages - and nothing else
# ===========================================================================
if [[ -n "$DO_UPGRADE" ]]; then
    [[ -n "$OLD_VERSION" || -f "$OPT_DIR/$APP.py" ]] || fail "fake-igd is not installed here; run this without --upgrade"
    # A machine that has the pages is upgraded with them; one from before them (1.3) gets them now,
    # unless --no-web was given.
    steps=8
    [[ -n "$WITH_WEB" ]] && steps=$((steps + 3))
    step "Upgrading fake-igd to $VERSION ($steps steps)"
    say "${OLD_VERSION:-an unknown version} → $VERSION, on ${OS_PRETTY:-?}"
    [[ -n "${FAKE_IGD_UPGRADE_BY:-}" ]] && say "asked by ${FAKE_IGD_UPGRADE_BY}"
    # The version before kept until the new one runs (otp 1.0.287): put back when it does not stay up.
    UPGRADE_OLD="$OPT_DIR/.before-upgrade"
    rm -rf "$UPGRADE_OLD"
    if mkdir -p -m 0700 "$UPGRADE_OLD" && (cd "$OPT_DIR" && cp -p ./*.py VERSION "$UPGRADE_OLD/" 2>/dev/null); then
        [[ -d "$WEB_DIR" ]] && cp -rp "$WEB_DIR" "$UPGRADE_OLD/web"
        touch "$UPGRADE_OLD/complete"
    fi
    upgrade_put_old_back() {
        [[ -f "$UPGRADE_OLD/complete" ]] || return 1
        warn "the version before is put back"
        cp -p "$UPGRADE_OLD"/*.py "$UPGRADE_OLD/VERSION" "$OPT_DIR/" || return 1
        if [[ -d "$UPGRADE_OLD/web" ]]; then rm -rf "$WEB_DIR"; cp -rp "$UPGRADE_OLD/web" "$WEB_DIR"; fi
        systemctl restart $APP fake-igd-api 2>/dev/null || true
        return 0
    }
    base_packages
    ensure_python
    accounts
    install_program
    install_config
    install_upgrader
    if [[ -n "$WITH_WEB" ]]; then
        ensure_php
    fi
    if ! install_units; then
        upgrade_put_old_back && warn "the version before runs again - look at what stopped the new one (journalctl -u fake-igd -u fake-igd-api)"
        fail "the new version did not start"
    fi
    if [[ -n "$WITH_WEB" ]]; then
        install_pages
        first_account
    fi
    open_firewall
    rm -rf "$UPGRADE_OLD"
    does_it_work
    step "Done"
    good "fake-igd ${OLD_VERSION:-?} → $VERSION"
    if [[ -n "$WITH_WEB" ]]; then pages_say; fi
    exit 0
fi

# ===========================================================================
# A fresh install
# ===========================================================================
step "Looking at this machine"
say "${OS_PRETTY:-unknown} ($(uname -m))"
[[ -n "$OLD_VERSION" ]] && note "fake-igd $OLD_VERSION is installed here already (an upgrade: ./install.sh --upgrade)"

base_packages
ensure_python
[[ -n "$WITH_WEB" ]] && ensure_php
accounts

if [[ -z "$ASSUME_YES" ]]; then
    step "A few questions"
    note "Enter to keep what is in brackets."
    if [[ -n "$WITH_WEB" ]]; then
        ask SERVER_NAME "The pages' hostname"
        ask ADMIN_ALLOW "Who may reach the pages (CIDRs, empty = RFC 1918)"
        [[ -n "$ADMIN_ALLOW" ]] && { cidr_list_ok "$ADMIN_ALLOW" || fail "addresses and networks, comma separated"; }
        ask ADMIN_USER "The first account of the pages"
        [[ -n "$ADMIN_PASSWORD" ]] || ask_secret ADMIN_PASSWORD "Its password (empty = make one and print it)"
    fi
fi

install_program
install_config

step "Port check"
if ss -Hltn "sport = :$HTTP_PORT" | grep -q . && ! ss -Hltnp "sport = :$HTTP_PORT" | grep -q "$APP\|python"; then
    ss -Hltnp "sport = :$HTTP_PORT" | sed 's/^/    /'
    fail "TCP port $HTTP_PORT is used by another program. Change http_port in $CONFIG_FILE and run this again."
fi
if ss -Hlunp "sport = :1900" | grep -v -e "$APP" -e python | grep -q .; then
    warn "Another program listens on UDP 1900 already (another UPnP/DLNA server?):"
    ss -Hlunp "sport = :1900" | sed 's/^/    /' >&2
    warn "fake-igd runs beside it, but that program may answer the PS5 too."
else
    good "1900/udp and $HTTP_PORT/tcp are free"
fi

install_upgrader
install_units || fail "sort that out and run this again (journalctl -u fake-igd -u fake-igd-api)"
if [[ -n "$WITH_WEB" ]]; then
    install_pages
    first_account
fi
open_firewall
does_it_work

step "Done"
if [[ -n "$WITH_WEB" ]]; then pages_say; fi
say "The console:    upnp --console         (menus, opens on the live log; q leaves it)"
say "The command:    upnp --help            (status | test | ports | log -f | dnat | upgrade | user ...)"
say "Configuration:  $CONFIG_FILE  (the pages, or sudo upnp config set ...)"
say "Upgrades:       sudo upnp upgrade online   (or the pages: Settings → Upgrades)"
say "Taking it away: sudo $OPT_DIR/uninstall.sh [--purge]"
[[ -n "$ADDED_USER" ]] && warn "$ADDED_USER was added to the group $SERVICE_USER - sign out and in again."
echo
say "Remember: UPnP on the router must be OFF, and this server in the same VLAN as the PS5."
exit 0
