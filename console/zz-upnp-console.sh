# The upnp console when root signs in (fake-igd 1.3).
# Switched with `upnp --console-at-login on|off`; q in the console leaves it for this
# shell, and `upnp --console` opens it again. Nothing happens for a command run over
# SSH, scp/sftp, a non-interactive shell, a shell opened from the console itself, or
# when UPNP_NO_CONSOLE is set.
# For normal users too, those named by `upnp --console-users` (or *): through sudo,
# with their own password - only who may become root with sudo gets it; anybody else
# is told so and keeps the ordinary shell.
if [ -n "${PS1:-}" ] && [ -t 0 ] && [ -t 1 ] && [ -z "${UPNP_CONSOLE:-}" ] \
   && [ -z "${UPNP_NO_CONSOLE:-}" ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] \
   && [ -x /usr/bin/upnp ] \
   && [ -f /etc/upnp-console-login ] && [ ! -L /etc/upnp-console-login ]; then
    if [ "$(id -u 2>/dev/null)" = "0" ]; then
        if [ "$(head -c 2 /etc/upnp-console-login 2>/dev/null)" = "on" ]; then
            export UPNP_CONSOLE=1
            /usr/bin/upnp --console
        fi
    elif [ "$(id -u 2>/dev/null)" -ge 1000 ] 2>/dev/null; then
        _upnp_users=" $(sed -n 's/^users: //p' /etc/upnp-console-login 2>/dev/null | head -n 1) "
        _upnp_me="$(id -un 2>/dev/null)"
        case "$_upnp_users" in
            *" * "*|*" $_upnp_me "*)
                export UPNP_CONSOLE=1
                if id -Gn 2>/dev/null | tr ' ' '\n' | grep -qxE 'wheel|sudo|admin' \
                   || sudo -n true 2>/dev/null; then
                    echo "upnp: the console - sudo asks for your password (Ctrl+C: the ordinary shell)"
                    sudo -p "[sudo] password for %p: " env UPNP_CONSOLE=1 /usr/bin/upnp --console
                else
                    echo "upnp: the console is set to open for you, but it needs sudo rights (the wheel group) - the ordinary shell"
                fi
                ;;
        esac
        unset _upnp_users _upnp_me
    fi
fi
