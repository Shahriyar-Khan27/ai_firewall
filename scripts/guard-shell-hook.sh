# AI Execution Firewall — opt-in shell hook for bash/zsh.
#
# Source this file from your ~/.bashrc or ~/.zshrc to route dangerous commands
# through the firewall. Each wrapped name forwards to `guard run`, which exits
# with the same status code as the underlying command.
#
#   source /path/to/scripts/guard-shell-hook.sh
#
# To wrap additional commands, append them to GUARD_WRAPPED_CMDS before sourcing.

GUARD_WRAPPED_CMDS=${GUARD_WRAPPED_CMDS:-"rm mv dd chmod chown"}

if ! command -v guard >/dev/null 2>&1; then
    echo "[guard-shell-hook] 'guard' CLI not on PATH; aborting" >&2
    return 1 2>/dev/null || exit 1
fi

_guard_wrap() {
    local verb="$1"; shift
    guard run "$verb $*"
}

for _cmd in $GUARD_WRAPPED_CMDS; do
    eval "${_cmd}() { _guard_wrap ${_cmd} \"\$@\"; }"
done
unset _cmd
