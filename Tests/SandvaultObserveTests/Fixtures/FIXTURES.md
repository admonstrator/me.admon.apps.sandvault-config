# Fixtures for SandvaultObserveTests

Host user `alice`, sandbox user `sandvault-alice` (uid/gid 502). Every fixture below is **synthetic**: written
from the documented output format of the macOS command, not captured on a Mac. Replace each with real output
(same users or adjust the tests) and remove the word `synthetic` from its row.

| File | Command on a Mac | Status |
|---|---|---|
| `ps-axww.txt` | `/bin/ps -axww -o pid=,ppid=,user=,%cpu=,%mem=,rss=,etime=,state=,command=` (one line uses a decimal comma, as with a German locale) | synthetic |
| `ps-environment.txt` | `sudo -n -u sandvault-alice /usr/bin/env /bin/ps -E -ww -U sandvault-alice -o pid=,command=` | synthetic |
| `lsof-sandbox.txt` | `sudo -n -u sandvault-alice /usr/bin/env /usr/sbin/lsof -nP -i -a -u sandvault-alice -F pcPtnT` | synthetic |
| `nettop.csv` | `/usr/bin/nettop -P -L 1 -x -J bytes_in,bytes_out` | synthetic |
| `nettop-time.csv` | same command; variant with a leading `time` column | synthetic |
| `log-violations.ndjson` | `/usr/bin/log show --style ndjson --last 10m --predicate '((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")'` (normal, duplicate-report, reporting-subsystem copy, System Policy and other noise) | synthetic |
| `dscl-user.txt` | `/usr/bin/dscl . -read /Users/sandvault-alice UniqueID PrimaryGroupID NFSHomeDirectory UserShell` | synthetic |
| `dscl-group.txt` | `/usr/bin/dscl . -read /Groups/sandvault-alice PrimaryGroupID` | synthetic |
| `dscl-record-missing.txt` | stderr of `/usr/bin/dscl . -read /Users/nobody-here` | synthetic |
| `dseditgroup-member.txt` | `/usr/sbin/dseditgroup -o checkmember -m alice sandvault-alice` | synthetic |
| `dseditgroup-not-member.txt` | `/usr/sbin/dseditgroup -o checkmember -m sandvault-alice staff` | synthetic |
| `ls-led-workspace.txt` | `/bin/ls -led /Users/Shared/sv-alice` after `sv build --rebuild` | synthetic |
| `ls-led-workspace-no-acl.txt` | `/bin/ls -led /Users/Shared/sv-alice` with ACLs stripped (`chmod -N`) and mode 775 | synthetic |
| `sudoers.txt` | `cat /etc/sudoers.d/50-nopasswd-for-sandvault-alice` | synthetic (from sv 1.32.0 source) |
| `sandbox-profile.sb` | `cat /var/sandvault/sandbox-sandvault-alice.sb` (comments shortened) | synthetic (from sv 1.32.0 source) |
| `chrome.log` | `cat ~/.local/state/sandvault/chrome-<session>.log` during `sv --browser` | synthetic |
| `ios-bridge.log` | `cat ~/.local/state/sandvault/ios-bridge-<session>.log` during `sv --ios` | synthetic |
| `sv-version.txt` | `sv --version` | synthetic (from sv 1.32.0 source) |
