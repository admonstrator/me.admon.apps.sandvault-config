#!/bin/bash
# Device test for Sandvault Config on a real Mac with sandvault installed.
#
#   scripts/verify-on-mac.sh capture   read-only: runs svctl's inspection commands and captures the raw
#                                      macOS output our parsers were written against (captures/<time>/)
#   scripts/verify-on-mac.sh guided    step by step: helper, sandbox rules, firewall + proxy, panic,
#                                      learn mode. Every step asks first and says how to undo it.
#
# svctl is taken from $SVCTL, else .build/release/svctl (built on demand with `swift build -c release`).
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODE="${1:-}"
HOST_USER="${USER}"
SANDBOX_USER="sandvault-${HOST_USER}"

say()  { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
ask()  { local answer; read -r -p "   $* [y/N] " answer; [[ "$answer" == [yY]* ]]; }
pause() { read -r -p "   Press Return to continue " _; }

[[ "$OSTYPE" == darwin* ]] || { echo "This script runs on macOS only." >&2; exit 1; }
[[ $EUID -ne 0 ]] || { echo "Run as your normal user, not root." >&2; exit 1; }
case "$MODE" in capture|guided) ;; *) sed -n '2,10p' "$0"; exit 2 ;; esac

SVCTL="${SVCTL:-$ROOT/.build/release/svctl}"
if [[ ! -x "$SVCTL" ]]; then
    say "Building svctl, svctl-helper and sandvault-netd (release)"
    (cd "$ROOT" && swift build -c release)
fi
BIN="$(dirname "$SVCTL")"

# Runs a command, keeps going on failure, prints the exit code.
run() {
    printf '   $ %s\n' "$*"
    set +e
    "$@"
    local code=$?
    set -e
    printf '   -> exit %d\n' "$code"
    return 0
}

###############################################################################
# capture (read-only)
###############################################################################
capture() {
    local out
    out="$ROOT/captures/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$out"
    say "Read-only capture into $out"
    note "Nothing is changed on this Mac. Review the files before you share them: they contain your user"
    note "name, the sandbox's process list and sandbox denials of the last 30 minutes."

    {
        sw_vers
        uname -a
        sv --version 2>&1 || echo "sv not on PATH"
        "$SVCTL" --version
    } > "$out/system.txt" 2>&1

    say "svctl views"
    for command in "doctor" "status" "ps --tree" "sessions" "net --listening --traffic" "violations --for 10s --suggest" \
                   "rules status" "firewall status" "proxy status" "netd status"; do
        # shellcheck disable=SC2086 # word splitting of the subcommand is intended
        { echo "\$ svctl $command"; "$SVCTL" $command 2>&1; echo "exit $?"; } >> "$out/svctl.txt" || true
        # shellcheck disable=SC2086
        "$SVCTL" $command --json > "$out/svctl-$(echo "$command" | tr ' -' '__').json" 2>/dev/null || true
    done
    note "$(grep -c '^\$ svctl' "$out/svctl.txt") views written to svctl.txt"

    say "Raw command output for the test fixtures"
    local predicate='((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")'
    # Only the sandbox user's processes; other users' command lines stay out of the capture.
    /bin/ps -axww -o pid=,ppid=,user=,ruser=,%cpu=,%mem=,rss=,etime=,state=,command= \
        | awk -v u="$SANDBOX_USER" '$3 == u' > "$out/ps-axww.txt" || true
    # Environment values are redacted except the ones the parser reads. A value runs up to the next
    # ` NAME=`, so values with spaces (an app path in PATH) are redacted completely.
    sudo -n -u "$SANDBOX_USER" /usr/bin/env /bin/ps -E -ww -U "$SANDBOX_USER" -o pid=,command= 2> "$out/ps-environment.stderr" \
        | perl -pe 's/(?<= )(?!SV_SESSION_ID=)([A-Za-z_][A-Za-z0-9_]*)=(?!,).*?(?= [A-Za-z_][A-Za-z0-9_]*=|$)/$1=<redacted>/g' \
        > "$out/ps-environment.txt" || true
    sudo -n -u "$SANDBOX_USER" /usr/bin/env /bin/ps -E -ww -U "$SANDBOX_USER" -o pid=,command= 2>/dev/null \
        | grep -oE 'SV_SESSION_ID=[0-9A-Fa-f-]{36}' | sort | uniq -c > "$out/ps-environment-session-ids.txt" || true
    local code=0
    # shellcheck disable=SC2024 # the capture files belong to the host user on purpose
    sudo -n -u "$SANDBOX_USER" /usr/bin/env /usr/sbin/lsof -w -nP -i -a -u "$SANDBOX_USER" -F pcPtnT \
        > "$out/lsof-sandbox.txt" 2> "$out/lsof-sandbox.stderr" || code=$?
    echo "exit $code" > "$out/lsof-sandbox.exit"
    local pids
    pids="$(awk '{print $1}' "$out/ps-axww.txt" | paste -sd'|' -)"
    /usr/bin/nettop -P -L 1 -x -J bytes_in,bytes_out 2>/dev/null \
        | awk -F, -v pids="^(${pids:-none})$" 'NR == 1 { print; next } { n = split($1, a, "."); if (a[n] ~ pids) print }' \
        > "$out/nettop.csv" || true
    # macOS does not store the kernel's sandbox reports; only a live stream sees them (10 s here).
    /usr/bin/perl -e 'alarm 10; exec @ARGV' /usr/bin/log stream --style ndjson --predicate "$predicate" \
        > "$out/log-violations.ndjson" 2> "$out/log.stderr" || true
    /usr/bin/dscl . -read "/Users/$SANDBOX_USER" UniqueID PrimaryGroupID NFSHomeDirectory UserShell > "$out/dscl-user.txt" 2>&1 || true
    /usr/bin/dscl . -read "/Groups/$SANDBOX_USER" PrimaryGroupID > "$out/dscl-group.txt" 2>&1 || true
    /usr/bin/dscl . -read /Users/nobody-here > "$out/dscl-record-missing.txt" 2>&1 || true
    /usr/sbin/dseditgroup -o checkmember -m "$HOST_USER" "$SANDBOX_USER" > "$out/dseditgroup-member.txt" 2>&1 || true
    /usr/sbin/dseditgroup -o checkmember -m "$SANDBOX_USER" staff > "$out/dseditgroup-not-member.txt" 2>&1 || true
    /bin/ls -led "/Users/Shared/sv-$HOST_USER" > "$out/ls-led-workspace.txt" 2>&1 || true
    cat "/etc/sudoers.d/50-nopasswd-for-$SANDBOX_USER" > "$out/sudoers.txt" 2>&1 || true
    cat "/var/sandvault/sandbox-$SANDBOX_USER.sb" > "$out/sandbox-profile.sb" 2>&1 || true
    id -u "$SANDBOX_USER" > "$out/id-u.txt" 2>&1 || true
    code=0
    launchctl print "gui/$(id -u)/me.admon.apps.sandvault-config.netd" > "$out/launchctl-print-netd.txt" 2>&1 || code=$?
    echo "exit $code" > "$out/launchctl-print-netd.exit"
    for file in "$HOME"/.local/state/sandvault/chrome-*.log "$HOME"/.local/state/sandvault/ios-bridge-*.log; do
        [[ -f "$file" ]] && head -20 "$file" > "$out/$(basename "$file")"
    done
    note "$(ls "$out" | wc -l | tr -d ' ') files. Commit them to a branch or keep them for the next session."
}

###############################################################################
# guided (changes the system, each step reversible)
###############################################################################
guided() {
    say "Guided device test"
    note "Every step asks before it changes anything and names its undo command."
    note "Open a second terminal for 'svctl asks --follow' and 'svctl netlog --follow' when the firewall steps start."

    say "1 · Privileged helper"
    note "Installs $BIN/svctl-helper to /Library/PrivilegedHelperTools, an argument-exact sudoers rule and a"
    note "LaunchDaemon for boot restore. Needs your admin password. Undo: svctl helper uninstall"
    if ask "Install the helper?"; then
        run "$SVCTL" helper install
        run "$SVCTL" helper status
    fi

    say "2 · Sandbox rules (sandbox-exec profile)"
    note "Shows the managed block and applies it to sv's profile. Undo: svctl rules reset --yes"
    run "$SVCTL" rules preview
    if ask "Apply the hardened preset and check that osascript is denied in the sandbox?"; then
        run "$SVCTL" rules preset hardened
        run "$SVCTL" rules apply --yes
        note "Expected: osascript fails with 'Operation not permitted'."
        run sv shell -- /usr/bin/osascript -e 'return 1'
        note "Expected: the host home stays unreadable (sv's own rule)."
        run sv shell -- /bin/ls "$HOME"
        if ask "Reset the rules again?"; then run "$SVCTL" rules reset --yes; run "$SVCTL" rules preset standard; fi
    fi

    say "3 · Learn mode"
    note "Streams sandbox denials for 20 seconds while a denied write runs in the sandbox."
    if ask "Run it?"; then
        ( sleep 3; sv shell -- /usr/bin/touch "/Users/Shared/sandvault-config-probe" >/dev/null 2>&1 || true ) &
        run "$SVCTL" violations --for 20s --suggest
        wait || true
    fi

    say "4 · netd, proxy and firewall"
    note "Installs the netd LaunchAgent, sets proxy-only and loads the pf anchor. Undo: svctl firewall off"
    if ask "Start netd and switch the sandbox to proxy-only?"; then
        run "$SVCTL" netd install
        run "$SVCTL" firewall mode proxy-only
        run "$SVCTL" firewall preview
        run "$SVCTL" firewall apply --yes
        note "Now run 'svctl asks --follow' in a second terminal and answer the prompt for example.com."
        pause
        note "Expected: HTTPS through the transparent proxy, decided by your answer."
        run sv shell -- /usr/bin/curl -sS -m 40 -o /dev/null -w '%{http_code}\n' https://example.com
        note "Expected: a LAN address is blocked."
        run sv shell -- /usr/bin/curl -sS -m 5 -o /dev/null -w '%{http_code}\n' http://192.168.1.1
        note "Expected: a raw TCP port that is not 80/443 is blocked."
        run sv shell -- /usr/bin/nc -z -G 5 1.1.1.1 853
        run "$SVCTL" netlog --limit 20
        run "$SVCTL" net --listening
        if ask "Turn the firewall off again?"; then run "$SVCTL" firewall off; fi
    fi

    say "5 · Panic"
    note "Blocks all network access of $SANDBOX_USER and kills its processes. Undo: svctl firewall off"
    if ask "Trigger panic?"; then
        run "$SVCTL" panic --yes
        run "$SVCTL" ps
        run sv shell -- /usr/bin/curl -sS -m 5 -o /dev/null -w '%{http_code}\n' https://example.com
        run "$SVCTL" firewall off
    fi

    say "6 · Doctor after the test"
    run "$SVCTL" doctor
    note "Done. Remove the helper with 'svctl helper uninstall' if you do not want to keep it."
}

"$MODE"
