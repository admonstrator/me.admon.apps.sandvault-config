# SandvaultEnforceTests fixtures

## Command output

| File | Produced on a Mac by | Status |
|---|---|---|
| `sandbox-sandvault-alice.sb` | `cat /var/sandvault/sandbox-sandvault-alice.sb` after `sv build` (sv v1.32.0) | **real**: sv lines 1602-1690 with `$SHARED_WORKSPACE=/Users/Shared/sv-alice`, `$SANDVAULT_USER=sandvault-alice`, trailing newline from `echo`; byte-identical to the profile captured on macOS 27.0.1 (host user renamed) |
| `dscl-read-uniqueid.txt` | `dscl . -read /Users/sandvault-alice UniqueID` | synthetic (format and uid 601 confirmed by the capture on macOS 27.0.1) |
| `id-u.txt` | `id -u sandvault-alice` | real (macOS 27.0.1) |
| `pfctl-s-info-enabled.txt` | `sudo pfctl -s info` (stdout, pf enabled) | synthetic |
| `pfctl-s-info-disabled.txt` | `sudo pfctl -s info` (stdout, pf disabled) | synthetic |
| `pfctl-E.stderr.txt` | `sudo pfctl -E` (stderr; the token line may be on stdout on some releases, both are parsed) | synthetic |
| `pfctl-sr.txt` | `sudo pfctl -a com.apple/sandvault-config -sr` after `svctl firewall apply` in mode blocked | synthetic |
| `eslogger-activity.ndjson` | `sudo eslogger exec open close create write rename unlink --format json` while the sandbox (uid 601) runs a git command and claude edits files in `/Users/Shared/sv-alice`: one line per event kind (open for reading and writing, close with and without `modified`, create and rename to a new path and to an existing file, unlink), an event of the host user (uid 501), uid 6010, sudo run by the sandbox (euid 0, ruid 601), a `fork` event, a text line and a cut-off line | synthetic, written from the documented `es_message_t` serialisation |
| `eslogger-not-permitted.stderr.txt` | stderr of the same command when the starting app lacks Full Disk Access | synthetic; the exact wording is unknown, the helper matches `NOT_PERMITTED`, `not permitted`, `Full Disk Access` and `TCC` |

## Golden files (`golden/`)

Output of our own generators, not of macOS commands. Regenerate with `SV_UPDATE_GOLDEN=1 swift test` and review the diff.

| File | Content |
|---|---|
| `sbpl-standard-rules.sb` | managed block body: standard preset, file rules (subpath, literal, prefix, read-write), mach and exec rules |
| `sbpl-hardened.sb` | managed block body: hardened preset followed by a user rule that overrides one entry |
| `profile-apply.diff` | `diff -u` of sv's profile against the candidate with the block |
| `pf-blocked.conf`, `pf-open.conf`, `pf-open-nolan-allowall-exceptions.conf`, `pf-proxy-only.conf`, `pf-proxy-only-blockall.conf`, `pf-proxy-only-allowall.conf` | anchor text per mode and option combination, uid 601 |
| `sudoers-alice` | `/etc/sudoers.d/60-sandvault-config-alice` as `helper install` writes it |
| `launchdaemon.plist` | `/Library/LaunchDaemons/me.admon.apps.sandvault-config.pf.plist` |
