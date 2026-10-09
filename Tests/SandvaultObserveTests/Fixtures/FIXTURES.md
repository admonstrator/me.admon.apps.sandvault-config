# Fixtures for SandvaultObserveTests

Host user `alice`, sandbox user `sandvault-alice`. Files marked **real** were captured with
`scripts/verify-on-mac.sh capture` on macOS 27.0.1 (26A434, arm64) with sv 1.32.0 on 2026-10-09; the host user name
is replaced by `alice`, nothing else is changed (uid 601, gid 600 as captured). The `-session` files come from a
second capture with `sv` running claude and `python3 -m http.server 8765`. Files marked synthetic were written
from the documented output format; they cover cases the capture did not contain (running sessions, sockets, traffic,
denials by sandbox processes).

| File | Command on a Mac | Status |
|---|---|---|
| `ps-axww.txt` | `/bin/ps -axww -o pid=,ppid=,user=,%cpu=,%mem=,rss=,etime=,state=,command=` (one line uses a decimal comma, as with a German locale) | synthetic (format confirmed by `ps-axww-idle.txt`) |
| `ps-axww-idle.txt` | the same, sandbox user's lines only, no session running: eight macOS per-user agents left over from earlier sessions | real |
| `ps-axww-session.txt` | the same during a session (the root-owned sudo launcher is not part of the capture) | real |
| `ps-environment.txt` | `sudo -n -u sandvault-alice /usr/bin/env /bin/ps -E -ww -U sandvault-alice -o pid=,command=` | synthetic |
| `ps-environment-idle.txt` | the same, no session running. The system agents print no environment; only the `ps` itself does (values redacted) | real |
| `ps-environment-session.txt` | `ps -E` during that session: Python and claude carry `SV_SESSION_ID`, the Apple binaries `zsh` and `caffeinate` print no environment. Values redacted except `SV_SESSION_ID` | real |
| `lsof-sandbox.txt` | `sudo -n -u sandvault-alice /usr/bin/env /usr/sbin/lsof -w -nP -i -a -u sandvault-alice -F pcPtnT` | synthetic |
| `lsof-sandbox-warning.stderr.txt` | stderr of the same command without `-w`, with no sockets (stdout empty, exit 1) | real |
| `lsof-sandbox-listener.txt` | lsof during that session: one IPv6 listener, process named `Python` | real |
| `nettop.csv` | `/usr/bin/nettop -P -L 1 -x -J bytes_in,bytes_out` | synthetic |
| `nettop-header-only.csv` | the same, filtered to the sandbox user's pids: none had traffic, only the header is left | real |
| `nettop-session.csv` | nettop during that session, run by the host user: lists the sandbox's `Python.86064` | real |
| `nettop-time.csv` | same command; variant with a leading `time` column | synthetic |
| `log-violations.ndjson` | `/usr/bin/log show --style ndjson --last 10m --predicate '((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")'` (normal, duplicate-report, reporting-subsystem copy, System Policy and other noise) | synthetic |
| `log-violations-host-only.ndjson` | the same with `--last 30m`: two denials of host processes (one "301 duplicate reports for"), then the closing `{"count":2,"finished":1}` | real |
| `log-violations-none.ndjson` | `log show` with nothing found: only `{"count":0,"finished":1}` | real |
| `dscl-user.txt` | `/usr/bin/dscl . -read /Users/sandvault-alice UniqueID PrimaryGroupID NFSHomeDirectory UserShell` | real |
| `dscl-group.txt` | `/usr/bin/dscl . -read /Groups/sandvault-alice PrimaryGroupID` | real |
| `dscl-record-missing.txt` | `/usr/bin/dscl . -read /Users/nobody-here` (stdout and stderr) | real |
| `dseditgroup-member.txt` | `/usr/sbin/dseditgroup -o checkmember -m alice sandvault-alice` | real |
| `dseditgroup-not-member.txt` | `/usr/sbin/dseditgroup -o checkmember -m sandvault-alice staff` | real |
| `ls-led-workspace.txt` | `/bin/ls -led /Users/Shared/sv-alice`; the mode ends in `@` (extended attributes win over `+` for the ACL) | real |
| `ls-led-workspace-no-acl.txt` | `/bin/ls -led /Users/Shared/sv-alice` with ACLs stripped (`chmod -N`) and mode 775 | synthetic |
| `sudoers.txt` | `cat /etc/sudoers.d/50-nopasswd-for-sandvault-alice` | real |
| `sandbox-profile.sb` | `cat /var/sandvault/sandbox-sandvault-alice.sb` | real |
| `chrome.log` | `cat ~/.local/state/sandvault/chrome-<session>.log` during `sv --browser` | synthetic |
| `ios-bridge.log` | `cat ~/.local/state/sandvault/ios-bridge-<session>.log` during `sv --ios` | synthetic |
| `sv-version.txt` | `sv --version` | synthetic (matches the captured `sv version 1.32.0`) |
