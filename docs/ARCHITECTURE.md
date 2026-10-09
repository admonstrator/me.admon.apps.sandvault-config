# Architecture

## 1 · Overview

Sandvault Config complements [sandvault](https://github.com/webcoyote/sandvault) (`sv`). `sv` creates the
`sandvault-$USER` account, the sudoers rule, the `sandbox-exec` profile and the shared workspace
`/Users/Shared/sv-$USER`, and starts sessions. We observe what the sandbox does, decide what it may do, and
make moving work into it fast.

| Component | Runs as | Purpose |
|---|---|---|
| `SandvaultConfig.app` | host user | Menu bar status, windows, prompts, setup |
| `svctl` | host user | CLI for every feature, scripting |
| `sandvault-netd` | host user (LaunchAgent) | Proxy, transparent listeners, DNS forwarder, policy, connection log, control socket |
| `svctl-helper` | root via `sudo -n` | Writes the profile block, loads the pf anchor, panic, integrity, boot restore |

| Module | Owner | Content |
|---|---|---|
| `SandvaultCore` | lead (contract) | Environment and paths, `CommandRunner`, config, snapshots, control and helper protocols, `ManagedBlock`, `GitSafe`, `AddressRange` |
| `SandvaultObserve` | agent A | status/doctor, processes, sessions, connections, traffic, violations, rule suggestions |
| `SandvaultEnforce` | agent B | SBPL and pf generation, profile merge, helper logic, panic, integrity |
| `SandvaultNet` | agent C | Proxy, DNS, policy engine, TLS inspection, connection log, control socket |
| `SandvaultWorkflow` | agent D | Hand-off, repos, tools, migration |
| `App/` | agent E | SwiftUI app |

## 2 · Security model

The sandbox user is the adversary.

- Our config, the CA key, logs and the control socket live under `~/Library/Application Support/me.admon.apps.sandvault-config/`.
  sv's profile denies the sandbox every read under `/Users` except its own home and the shared workspace.
- Files we put into the shared workspace (CA bundle, `.zshenv` block, hand-off briefings) are sandbox-writable.
  We never execute them and treat their content as untrusted when we read it back.
- The helper is the privilege boundary: it takes typed JSON (`AppliedState`) on stdin, derives the user from
  `SUDO_USER`, writes only fixed paths, and generates SBPL/pf text itself with strict validation.
- Git never runs as the host user inside a sandbox clone: `git status`/`log` would execute filters, fsmonitor or
  `gpg.program` from the clone's config, and reading the config first races with the sandbox rewriting it.
  Every git call against a clone runs as the sandbox user under sv's profile (`SandboxedCommand.git`, §7). Only
  host-side git in the host repository (`git fetch sandvault`) runs as the host user, with `GitSafe` hardening,
  `--no-tags` and `--no-recurse-submodules`.
- Code the sandbox can write (its dotfiles, `$SHARED_WORKSPACE/user`) is only ever executed as the sandbox user
  under `sandbox-exec` with sv's profile, never as the bare sandbox user and never as the host user.
- Enforcement is pf (per user) plus sandbox-exec; proxy variables in the sandbox are only hints for cooperative tools.

## 3 · Contract (SandvaultCore)

- `SandvaultEnvironment.current()` derives the host user like `sv` (also from inside the sandbox and under sudo);
  every sv path is a computed property. `AppPaths` holds our own paths (`configFile`, `effectiveControlSocket`,
  `helperPath`, `pfAnchor`, `publicCABundle`, `sharedZshenv`, ...).
- `CommandRunner.run` / `.lines` is the only way to run processes. `CommandInvocation.asSandvault` runs a tool as
  the sandbox user without a password; `CommandInvocation.viaHelper` runs the helper. `FakeCommandRunner` serves
  fixtures by exact argv or longest prefix.
- `AppConfig` (`ConfigStore`, JSON, mode 0600, atomic) holds `SandboxSettings`, `NetworkPolicy`, `HandoffSettings`,
  tool grants and hand-off records. Every type decodes missing keys to defaults; new fields go at the end with a default.
- Snapshots: `SandboxProcess`, `SandboxSession`, `HostHelperProcess`, `SandboxConnection`, `ProcessTraffic`,
  `SandboxViolation`, `RuleSuggestion`, `ConnectionRecord`, `Check` / `CheckReport`.
- Control protocol (`ControlRequest` / `ControlEvent`, JSON Lines via `ControlCodec`) between netd and clients.
- Helper protocol (`HelperSubcommand`, `AppliedState`, `HelperResult`, `HelperClient`).
- Seams implemented in one module and consumed in another: `ProcessAttributor` and `LocalPortSource` (Observe → netd),
  `PolicyApplier` (Enforce → svctl, netd, app). Factories: `Observe.makeProcessAttributor`,
  `Observe.makeLocalPortSource`, `Enforce.makePolicyApplier`.
- `SharedFiles` is the only way to read or write inside the shared workspace (sandbox-writable): it walks
  paths with `openat(O_NOFOLLOW)`, creates with `O_EXCL`, replaces with `renameat`, so a symlink the sandbox
  planted never redirects a host-user write or read. Never use `FileManager`/`Data.write` there.
- `CheckProvider` per module (`Observe/Enforce/Net.makeCheckProvider`); `svctl doctor` concatenates them.
- CLI: each area registers its commands in `Sources/svctl/<Area>/<Area>Commands.swift`; shared options in
  `GlobalOptions` (`--json`, `--config`), output helpers in `Output`.

## 4 · Observe

Read-only views of the sandbox plus the few actions that only touch sandbox processes. Every API is a small
`Sendable` struct holding `environment` and `runner` with `async` functions that return value snapshots; nothing
prints. The CLI commands refuse to run off macOS (`SandvaultError.unsupportedPlatform`).

| Area | API | Source |
|---|---|---|
| Processes, sessions | `ProcessMonitor.snapshot()` -> `ProcessSnapshot` (`processes`, `sessions`, `helpers`, `environmentReadable`, `tree()`, `session(matching:)`); `sandboxProcesses()`, `helpers()` | `ps -axww -o pid=,ppid=,user=,ruser=,%cpu=,%mem=,rss=,etime=,state=,command=`, then `asSandvault(/bin/ps -E -ww -U <sandbox> -o pid=,command=)` |
| Control | `ProcessController.terminate(pid:force:)`, `terminateSession(_:force:)`, `terminateAll()`, `throttle(pid:nice:background:)` -> `ControlReport` | `asSandvault(/bin/kill)`, `renice`, `taskpolicy -b`; sv's sudoers: `sudo -n /bin/launchctl bootout user/<uid>`, `sudo -n /usr/bin/pkill -9 -u <sandbox>` |
| Sockets, traffic | `ConnectionMonitor.connections()`, `traffic(pids:)` | `asSandvault(/usr/sbin/lsof -w -nP -i -a -u <sandbox> -F pcPtnT)`, `nettop -P -L 1 -x -J bytes_in,bytes_out` |
| ICMP | `ICMPActivity.find(in:)` (`ping`, `ping6`, `traceroute`, `traceroute6`, `mtr` with the target from the command line) | the process list |
| netd seams | `Observe.makeProcessAttributor`, `Observe.makeLocalPortSource` | lsof cache; ps + helper logs |
| Violations | `ViolationMonitor.stream()`, `collect(for:onEach:)`; `SandboxViolation.occurrences` | `log stream --style ndjson --predicate <sandbox predicate>` |
| Learn mode | `RuleSuggester.suggestions(for:environment:)` -> `[RuleSuggestion]` | violations |
| Doctor | `Observe.makeCheckProvider` (`ObserveChecks`, ids in `ObserveChecks.ids`) | dscl, dseditgroup, sudo, ls -led, files |
| Overview | `StatusSummary.collect(environment:runner:firewallMode:checks:)` | the above |

**Sandbox processes** are those whose effective or real user is the sandbox user. The real user matters for setuid
tools: `/sbin/ping` runs as root, so `ps` shows `root` as its user, and lsof (`-u` matches the owner of the socket)
and pf (`user` matches TCP and UDP only) never see it. Its real user stays the sandbox user, also after its shell
has ended. The app marks such processes with their effective user, `ping (root)`.

**Sessions.** `SV_SESSION_ID` is read from the environment that `ps -E` appends to each command line (last
`SV_SESSION_ID=<uuid>` word, strict UUID). A process without one inherits from its parent. When `ps -E` is not
possible, ids come from the session launcher: sv's `sudo --login ... /usr/bin/env -i ... SV_SESSION_ID=<uuid>` runs
as root, so only the host side can create it and the sandbox cannot forge it. A session's root is the member whose
parent is outside the group; its command is the agent (`claude`, `codex`, ...) closest to the root, else the root's
name. Host helpers: Chrome by `--user-data-dir=.../.local/state/sandvault/chrome-data-<uuid>` (main process only, no
`--type=`), the iOS bridge by `sv-ios-bridge --udid` and the session of its parent `sv`; ports come from
`chrome-<uuid>.log` / `ios-bridge-<uuid>.log`. The `ps`/`lsof` this module runs as the sandbox user are left out.

**Control.** A pid is signalled only after a fresh `ps` shows it is a sandbox process, and the signal is sent as the
sandbox user, so the kernel refuses anything else too (a setuid tool accepts it: its real user is the sender).
`terminateAll` follows sv's uninstall: bootout, wait, `pkill -9` only for survivors; the argv matches sv's sudoers
lines exactly. `pkill -u` matches the effective user, so setuid survivors then get `kill -KILL` as the sandbox user. Reports list each command with its
outcome and the pids still alive after a short settle delay.

**netd seams.** The attributor keeps one lsof snapshot (port and protocol -> pid, name) for 2 s. A miss joins the
running refresh or starts one at most every 100 ms, and a lookup waits at most 200 ms before answering `nil`; a
failing lsof clears the cache rather than serving stale owners. Local ports are TCP listeners of the sandbox on
loopback or wildcard plus the ports of live host helpers; UDP is left out because an unconnected UDP socket is not a
listener.

**Violations.** Lines that are not JSON or not `Sandbox: <name>(<pid>) deny(<n>) <operation> [<target>]` are
skipped (e.g. `System Policy:` denials). `<n> duplicate report(s) for ...` keeps its count in `occurrences`. The
same message for the same pid within one second is dropped once (kernel and reporting subsystem). Attribution
uses a pid cache of the sandbox user that refreshes on unknown pids at most once a second; short-lived processes
can exit first and then stay unattributed (`--all` shows them).

**Learn mode.** File operations become an allow `FileRule`: the file as `literal`, or its directory as `subpath`
once two or more files in it were hit (never for directories fewer than three levels deep). Read plus write becomes
`readWrite`. `mach-lookup` becomes a `MachRule`, `process-exec*` an allow `ExecRule`; network and other operations
yield nothing. Paths inside another user's home carry a note that POSIX permissions are needed as well. Ids are
derived from the rule, so repeated calls return equal suggestions.

**Doctor.** `sv.installed` (PATH and Homebrew prefixes, `sv --version`, warning outside 1.32.x),
`sv.install-marker`, `account.user`, `account.group`, `account.not-staff`, `account.host-in-group`, `sudoers.file`
(the `/usr/bin/env` rule is required, the kill rules are a warning), `sudoers.works`, `profile.present`,
`profile.managed-block` (present/absent/damaged only), `workspace.permissions` (owner, group, mode 770, inheritable
group ACL), `ssh.remote-login` (never a failure), `umask` (same test as sv), `homebrew.permissions` (same test as
sv). Every command has a timeout; a missing command or a timeout yields `unknown`. `svctl doctor` appends the
Enforce and Net providers and exits 1 on any failure.

**CLI.** `svctl status`, `doctor`, `ps [--tree] [--session <id>]`, `sessions`, `kill <pid> | --session <id> | --all
[--force] [--yes]`, `throttle <pid> [--nice <n>] [--background]`, `net [--listening] [--traffic]` (also lists running
ICMP tools),
`violations [--for 30s|5m|1h] [--all] [--suggest]` (live until Ctrl-C, or for the given time and then a summary;
`--suggest` needs `--for`); all take `--json` (`violations --json` without `--for` prints JSON Lines).

**Confirmed on macOS 27.0.1** (capture of 2026-10-09, no session running): the output of `dscl`, `dseditgroup`,
`ls -led` (the mode ends in `@`, not `+`, when the workspace also has extended attributes), sv's sudoers file and
profile, `ps -axww` and the `log show --style ndjson` format, including `N duplicate reports for Sandbox:` and the
closing `{"count":…,"finished":1}` object. lsof exits 1 when the sandbox user has no sockets, and as that user
it warns about file systems in the host's home (Xcode's CoreDevice DeviceFS); hence `-w`, and warnings alone are
no error. The macOS per-user agents (`lsd`, `cfprefsd`, `secd`, `trustd`, ...) keep running for days after the
last session and count as sandbox processes. A second capture during a session confirmed `SV_SESSION_ID` via
`ps -E`, lsof's `-F` output for a listener, and that `nettop` run by the host user lists sandbox processes.
`ps -E` prints no environment for Apple binaries (`zsh`, `caffeinate`, the agents above), so their session comes
from the parent chain and sv's launcher; agent lookup walks every root of a session for that reason.

Sandbox denials of the session reach `log stream` as kernel messages (`processID` 0, sender `Sandbox.kext`,
level Error) in the parsed format. `log show`, even with `--info --debug`, does not have them a few seconds later:
macOS 27 does not store them. Learn mode is therefore live only: `svctl violations` and the app's learn mode
follow `log stream`; there is no look back.

**Still open:** lsof with established outbound connections, `taskpolicy -b -p` on another user's process, lsof latency through sudo against the 200 ms
budget, and whether the reporting subsystem duplicates kernel reports (it did not report the probe at all).

## 5 · Enforce

Sandbox rules and the firewall live in `config.json` (`SandboxSettings`, `NetworkPolicy`). Nothing takes effect
until an apply: svctl, netd or the app send an `AppliedState` to the root helper, which generates SBPL and pf text
itself, validates it with the system tool and writes fixed paths.

```
config.json ─▶ HelperPolicyApplier ─sudo -n─▶ svctl-helper ─▶ SBPLGenerator ─sandbox-exec─▶ /var/sandvault/sandbox-sandvault-$USER.sb
   (svctl, netd, app)        (AppliedState JSON)         └▶ PFAnchorGenerator ─pfctl -n─▶ anchor com.apple/sandvault-config
```

### 5.1 Managed block (SBPL)

`SBPLGenerator.block(for:)` returns the body between the `ManagedBlock.sandboxProfile` markers, or `nil` when the
standard preset has no rules (then no block is written). Order: hardened preset, then file, mach and exec rules in
config order. sv's profile is last-match-wins and the block sits at its end, so user rules override sv and the preset.

| Rule | SBPL |
|---|---|
| `FileRule` | `(allow\|deny file-read*\|file-write*\|file-read* file-write* (subpath\|literal\|prefix "<path>"))` |
| `MachRule` | `(allow\|deny mach-lookup (global-name "<name>"))` |
| `ExecRule` | `(allow\|deny process-exec (literal "<path>"))` |

Every rule gets a comment line `;; rule <uuid>: <note>`. Validation rejects, never repairs: paths absolute, no
control, format or line-separator characters, no empty, `.` or `..` components, at most 1024 bytes, then `\` and `"`
are escaped; mach names `[A-Za-z0-9._-]{1,255}`; notes are reduced to letters, digits and plain punctuation on one
line (no `<`/`>`); a body that contains a marker string is rejected, so `ManagedBlock` always finds the real block.
SBPL matches real paths: `/private/tmp`, not `/tmp`. The same validation runs when a rule is added to the config.

**Hardened preset** (`HardenedPreset.entries`, opt-in). Verify on a real Mac before relying on it; service names
change between macOS releases.

| Denied | Why |
|---|---|
| exec `/usr/bin/osascript`, `/usr/bin/osacompile` | AppleScript/JXA drives GUI apps of the logged-in session; applets run outside the sandbox |
| exec `/usr/bin/automator`, `/usr/bin/shortcuts` | the same through Automator and the Shortcuts service |
| exec `/usr/bin/open` | LaunchServices opens apps, files and URLs in the logged-in session (also breaks `gh auth login --web`) |
| exec `/bin/launchctl` | launchd jobs start without the sandbox-exec profile (also breaks `brew services`) |
| exec `/usr/sbin/screencapture` | screen of the logged-in session |
| exec `/usr/bin/tccutil`, `/usr/sbin/networksetup`, `/usr/sbin/systemsetup`, `/usr/bin/dscl` | privacy decisions, network and system settings, accounts |
| mach `com.apple.pasteboard.1` | clipboard: read secrets, plant commands |
| mach `com.apple.coreservices.launchservicesd` | LaunchServices on behalf of the caller |
| mach `com.apple.coreservices.appleevents` | Apple Events; sv denies `com.apple.appleeventsd`, which may not be the registered name |

Not denied on purpose: `security` and `defaults` (sv's `configure` runs them every session) and every service TLS,
DNS or the keychain need (`trustd`, `securityd`, `mDNSResponder`, `configd`, `ocspd`).

### 5.2 Profile merge and drift

`ProfileMerge` works on text only: `candidate(profile:body:)` replaces or removes the block, `svPart(of:)` is the
profile without the block. `ProfileInspector.plan(for:)` reads sv's profile (0444, no root needed) and the helper's
record and returns a `ProfilePlan` (current, candidate, `[DiffLine]`, `unifiedDiff`, `drift`, `svPartChanged`).
`ProfileDrift`: `inSync`, `missing` (block gone, typically `sv --rebuild`), `outdated`, `unexpected` (block present,
config empty), `profileMissing`. `svPartChanged` compares the SHA-256 of sv's part with the one stored at the last
apply. `Enforce.reapplyIfMissing` implements `SandboxSettings.autoReapply` (only for `missing`).

### 5.3 pf anchor

`PFAnchorGenerator.rules(for:uid:)` returns the anchor text (`nil` for `off`: the anchor is flushed). Rules name the
uid (`user 601`), never the account; the uid comes from `dscl . -read /Users/<sandbox> UniqueID` (fallback
`id -u`) and must be 500 or above. Every group carries a comment in the generated text.

| Mode | Groups, in order |
|---|---|
| `off` | none |
| `open` | netd ports; exceptions; LAN guard (`blockLAN`, `PrivateNetworks.lan`); localhost; `pass out` everything else |
| `watch` | `rdr` and `route-to` for 80/443/53 as in `proxyOnly`; IPv6 to 80/443/53 refused (clients fall back to IPv4 through netd); then as `open` |
| `proxyOnly` | `rdr` 80/443/53 on lo0 to netd; `route-to (lo0 127.0.0.1)` for 80/443/53 out on `! lo0` (IPv4); pass for the re-routed packet on lo0; netd ports; exceptions; localhost; `block return out log quick` for everything else (IPv4 and IPv6) |
| `blocked` | `block return log quick` in and out on every interface |

Localhost: `allowAll` passes every loopback port; `sandboxAndHelpers` passes netd plus `dynamicLocalPorts` and
refuses the rest of loopback; `blockAll` passes netd only. `AppliedState` does not separate sv's host helpers from
the sandbox's own listeners, so `blockAll` also blocks Chrome CDP and the iOS bridge.

Subtleties, handled in the text:
- A packet re-routed with `route-to (lo0 ...)` is evaluated again as "out on lo0" with its original destination.
  Localhost blocks therefore name loopback destinations only, and a dedicated `pass out quick on lo0 ... to ! 127.0.0.0/8
  port {53 80 443}` lets the re-routed flow through before the final block.
- Replies of the sandbox's own listeners are outbound packets of a sandbox socket. `pass in quick on lo0 ... user
  <uid> keep state` creates state for connections the host opens to them, so the outbound blocks never see the replies.
  From other machines the sandbox's listeners get no answer in `proxyOnly` and none from LAN hosts under the LAN guard.
- Exceptions come before the guards: an explicit grant to a LAN or loopback address works. In `proxyOnly`, 80, 443
  and 53 always go through netd, exceptions for those ports included.

Known limits: the `rdr` rules cannot match a user, so any local user's lo0 packets to this Mac's own non-loopback
addresses on 80/443/53 are redirected while `proxyOnly` is on; DNS through mDNSResponder (most macOS lookups) is not
the sandbox's socket and is not redirected (netd sees names through SNI and Host instead); existing pf states survive
a mode change until the connection ends (panic kills the processes); a `set skip on lo0` in `/etc/pf.conf` disables
the redirect; one host user per Mac can own the anchor. ICMP has no owner for pf: `ping` and `traceroute` pass in
every mode, `blocked` included; only an exec rule on `/sbin/ping` and `/usr/sbin/traceroute` stops them.

### 5.4 Root helper

`svctl-helper <subcommand> --json` runs as root through sudo; `PrivilegedHelper.run` holds all logic and is tested
against a temporary root (`HelperContext.root`) with `FakeCommandRunner`. Input: `AppliedState` JSON on stdin (max
1 MiB, version 1). Output: one `HelperResult` line; exit 0 iff ok. The host user is `SUDO_USER` (validated, not
`root`, not `sandvault-*`); the sandbox uid must differ from `SUDO_UID`.

| Subcommand | Does |
|---|---|
| `profile-apply` | generate, stage beside the profile (root:wheel 0444), `sandbox-exec -f <staged> /usr/bin/true`, rename; back up sv's profile once per sv-part hash |
| `profile-reset` | the same with the block removed |
| `pf-apply` | `pfctl -a <anchor> -n -f -`, `pfctl -a <anchor> -f -`, `pfctl -E` when pf is off or we hold no token; skips an identical, still loaded anchor; `--release-panic` ends a panic |
| `pf-disable` | `pfctl -a <anchor> -F all`, `pfctl -X <token>` |
| `panic` | anchor in `blocked`, then `launchctl bootout user/<uid>` and `pkill -9 -u <sandbox>`; both steps run even if one fails; latches: `pf-apply` without `--release-panic` keeps `blocked` |
| `status` | SHA-256 of helper, our sudoers file, sv's sudoers file, profile, block, sv's part, `pfctl -a <anchor> -sn` + `-sr`, compared with the last apply (`HelperStatus`, `tampered`) |
| `restore` | LaunchDaemon at boot: drops the stale token and re-loads the persisted anchor with the stored uid (no `SUDO_USER`) |
| `install` | copy the binary to `AppPaths.helperPath` (0755), write the sudoers file (validated with `visudo -c -f`, 0440), create `rootStateDir`, write `AppPaths.launchDaemonPlist` (0644, `RunAtLoad`, not loaded until the next boot) |
| `uninstall` | firewall off, block removed, `launchctl bootout system/<label>`, every file above deleted |

`install` and `uninstall` are the only subcommands that take `--user`/`--source`, and they are not reachable without a
password: the sudoers rule lists the exact argv of the unattended subcommands
(`PrivilegedHelper.unattendedArguments`), not the bare helper path. A bare `NOPASSWD: <helper>` would let any process
of the host user run `install --source <its own binary>` and get root without a password.

Root state in `AppPaths.rootStateDir`: `helper-record.json` (0644: hashes, token, mode, panic flag; the unprivileged
side reads `svPartSHA256` from it), `applied-state.json` (0600, for `restore`), `profile-backup-<hash>.sb` (0600).

### 5.5 API and CLI

- `Enforce.makePolicyApplier(runner:)` returns a `HelperPolicyApplier` (actor): `applyFirewall(_:)` (netd; returns
  without sudo when mode, LAN, localhost, ports, exceptions and the sorted port set are unchanged),
  `applyFirewall(_:releasingPanic:)`, `applyProfile`, `resetProfile`, `disableFirewall`, `panic`, `status() -> HelperStatus`, `invalidate()`.
- `Enforce.makeCheckProvider`: checks `enforce.helper`, `enforce.profile`, `enforce.profile.sv-part`, `enforce.firewall`, `enforce.integrity`, `enforce.panic`.
- `Enforce.profilePlan`, `Enforce.firewallPreview`, `Enforce.reapplyIfMissing`; `SBPLGenerator`, `PFAnchorGenerator`, `ProfileMerge`, `ProfileInspector`, `LineDiff`, `SandboxAccount.resolveUID`.
- Config edits: `SandboxSettings.add(_:)` for `FileRule`/`MachRule`/`ExecRule`/`RuleSuggestion.Proposal` (validated; a repeat moves to the end), `removeRule(idPrefix:)`, `rules: [SandboxRule]`; `NetworkPolicy.add(_: PortException)`, `removeException(idPrefix:)`.
- `svctl rules list|add <read|write|rw> <path> [--subpath|--literal|--prefix] [--deny] [--note]|mach <allow|deny> <name>|exec <deny|allow> <path>|remove <id>|preset <standard|hardened>|preview|diff [--profile <file>]|apply [--yes]|reset [--yes]|status`
- `svctl firewall status|mode <off|open|proxy-only|blocked>|lan <on|off>|localhost <sandbox-and-helpers|allow-all|block-all>|except add <tcp|udp> <dest> [port] [--note]|except remove <id>|preview [--uid <n>]|apply [--yes]|off`
- `svctl panic [--yes]` (also sets mode `blocked` in the config, so later applies keep it), `svctl helper install [--source]|uninstall|status`. All accept `--json`; `apply`, `reset` and `panic` ask unless `--yes` (required with `--json`). On Linux the config edits, `preview`, `diff --profile <file>` and `status` work; the rest fail with "unsupported on this platform".

### 5.6 Verify on a Mac

Each step is undone by `svctl firewall off`, `svctl rules reset --yes` and finally `svctl helper uninstall`.

1. `svctl helper install`, then `sudo -n -l /Library/PrivilegedHelperTools/me.admon.apps.sandvault-config.helper status --json` prints the command, and `sudo -n ... install --json` is refused.
2. Profile: `svctl rules exec deny /usr/bin/whoami && svctl rules apply`; `sv shell -- whoami` fails with "Operation not permitted"; `svctl rules reset --yes`; `cmp` the profile with the backup in `rootStateDir`.
3. Hardened: `svctl rules preset hardened && svctl rules apply --yes`; in `sv shell`: `osascript -e 1`, `pbpaste`, `open https://example.com` fail; `git`, `curl https://example.com`, `security find-certificate -a | head` and a Claude session work.
4. `user <uid>` matching: `svctl firewall mode open && svctl firewall apply`; `sudo pfctl -a com.apple/sandvault-config -sr`; in `sv shell` `curl -m5 http://<router ip>` is refused while the same curl as the host user works.
5. Redirect: start netd, `svctl firewall mode proxy-only && svctl firewall apply`; `sudo pfctl -a com.apple/sandvault-config -sn` shows the rdr rules; in `sv shell` `env -u http_proxy -u https_proxy curl -v https://example.com` shows up in netd's log; `nc -vz -w3 1.1.1.1 22` is refused; the host user's traffic is unchanged.
6. Localhost: as host `python3 -m http.server 8765 --bind 127.0.0.1`; in `sv shell` `curl -m3 127.0.0.1:8765` is refused; a server in `sv shell` on port 8000 is reachable from the host browser; with `localhost allow-all` both work.
7. Panic: `svctl panic --yes` ends all sandbox processes and leaves `blocked`; `svctl firewall mode open && svctl firewall apply --yes` (or `svctl firewall off`) ends it. Reboot once with the firewall on: `sudo pfctl -a com.apple/sandvault-config -sr` shows the rules again and `/Library/Application Support/me.admon.apps.sandvault-config/restore.log` has the result.
8. Rollback: `svctl firewall off`; `sudo pfctl -a com.apple/sandvault-config -sr` is empty and `sudo pfctl -s References` no longer lists our token.

## 6 · Net

`sandvault-netd run` (LaunchAgent `<bundle id>.netd`, host user) builds a `NetDaemon` from `NetdOptions` and the
seams `Observe.makeProcessAttributor`, `Observe.makeLocalPortSource`, `Enforce.makePolicyApplier`. All listeners
are SwiftNIO on `127.0.0.1`, ports from `NetworkPolicy.ports`:

| Listener | Input | Target |
|---|---|---|
| explicit proxy (18080) | `CONNECT host:port`, absolute-form `http://` requests | tunnel, or origin-form request without hop-by-hop and `Proxy-*` headers |
| transparent HTTP (18081) | pf-redirected port 80 | `Host` header, port 80 |
| transparent TLS (18443) | pf-redirected port 443 | SNI of the buffered ClientHello, port 443; bytes are replayed |
| DNS (18053, UDP + TCP) | pf-redirected port 53 | upstream from `--upstream-dns` or the first `nameserver` of `/etc/resolv.conf` |
| control | `AppPaths.effectiveControlSocket`, mode 0600 | `ControlRequest` / `ControlEvent` lines |

**Decision path** (`NetRuntime.authorize`, one per connection, one per plain HTTP request):
`PolicyEngine.evaluate` (exact > longer `*.suffix` > `*`; deny > allow > ask; no match → `defaultAction`; ports
other than 80/443 need an explicit `allow`; in `watch` only `deny` rules refuse, everything else is allowed on every
port) → `ask` goes to `AskCoordinator` → resolution: `DnsOverride` (exempt
from the guard), IP literal, or `getaddrinfo` on NIO's thread pool → addresses in `PrivateNetworks.all` are dropped
when `blockPrivateDestinations` → connect. A refusal answers `403` with one line naming the rule or default and
`svctl proxy allow <host>`; the transparent TLS listener just closes. DNS: deny → NXDOMAIN, override → synthesized
A/AAAA, ask → REFUSED while the ask is raised, allow → forwarded.

**Asks** are raised only while a control client subscribes to `.asks` (else `askFallback` applies at once). Concurrent
asks for one host share one `AskRequest`; the connection waits up to `askTimeoutSeconds`. An answer is remembered for
30 s (so the DNS query that raised it and the connection after it agree); `*Always` saves a rule through
`ConfigStore` (`.host` exact, `.domain` → `*.<registrable domain>`, see `RegistrableDomain`) and swaps the policy.

**TLS inspection** applies when `inspection.enabled` and the matching rule has `inspect` (not for IP literals):
`CAStore` keeps the P-256 CA in `AppPaths.caDir` (`ca-key.pem` 0600, `ca-cert.pem`), `InspectionService` signs a
30-day leaf per host with one in-memory key and caches the server context; ALPN `http/1.1` only; the upstream side
verifies against the platform roots. Requests and responses become `HTTPSummary` entries with
`inspection.redactHeaders` replaced by `<redacted>`; bodies are relayed, never stored. `CAPublisher` writes the CA
and a bundle (system roots + CA) into `_sandvault-config/` through `SharedFiles`.

**Sandbox environment**: `SandboxEnvironmentBlock` writes `ManagedBlock.zshenv` into `$SHARED_WORKSPACE/user/.zshenv`
through `SharedFiles` (proxy variables, `NO_PROXY`, CA variables with inspection; removed when the mode is `off`).
netd syncs it on start and on every reload; `svctl proxy env apply|remove` does it by hand.

**Records**: every decision yields a `ConnectionRecord` (raw bytes on the client socket, duration, process from the
client's source port). `ConnectionLog` appends JSON Lines to `AppPaths.connectionLog` (rotation at 10 MB, three old
files) and keeps the last 1000 for `.recent`; records are also pushed to `.connections` subscribers. Every 5 s netd
pushes `.status` and, in `open`/`proxyOnly` with `localhost == .sandboxAndHelpers`, `LocalPortRefresher` calls
`applyFirewall` when the allowed loopback ports changed (errors logged once per kind).

**Client API** for svctl and the app: `ControlClient` (`connect`, `request`, `events`, typed `status`, `subscribe`,
`answer`, `pendingAsks`, `recent`, `reloadConfig`), the config edits on `NetworkPolicy` (`upsertDomainRule`,
`removeDomainRule(selector:)`, `upsertDnsOverride`, `removeDnsOverride(selector:)`), `ConnectionLog.read`,
`CAStore`, `CAPublisher`, `SandboxEnvironmentBlock`, `NetdLaunchAgent`, `Net.makeCheckProvider` (`net.netd`,
`net.ports`, `net.launchagent`, `net.ca`, `net.zshenv`).

**CLI**: `svctl proxy status|rules|allow <pattern> [--inspect]|deny|ask|remove <id-prefix|pattern>|default
<allow|deny|ask>|inspection <on|off>|env apply|env remove`, `svctl dns list|override <pattern> <address>|remove`,
`svctl ca create|show|publish|remove`, `svctl netlog [--follow] [--limit n] [--denied] [--host text]`,
`svctl asks [--follow] [--answer <id-prefix> <allow-once|allow-always|deny-once|deny-always> [--domain]]`,
`svctl netd install [--executable path]|uninstall|status|restart`. Config edits send `reloadConfig` when netd answers.

Limits: HTTP upgrades (WebSocket over plain `ws://`) are not forwarded; in `watch` and `proxyOnly`, TLS on 443
without SNI (an IP address as host) is refused, because netd cannot learn the original destination without root; a plain HTTP request body is not
back-pressured; inspection covers HTTP/1.1 only (clients negotiating `h2` fall back through ALPN).

## 7 · Workflow

Moving work into the sandbox and back. Every service is a `Sendable` struct over `SandvaultEnvironment`, a
`CommandRunner` and, where it records something, the `ConfigStore`. Everything inside the shared workspace goes through
`SharedFiles`, rooted at a `SharedLayout` (tests pass a temporary root). The factories in `Workflow` return the
protocols of `WorkflowModels.swift`; the concrete types are public for callers that need more.

| Protocol | Type | Runs |
|---|---|---|
| `HandoffService` | `RepositoryHandoff` (`readiness(of:)`, `handOff(_:)`, `handOff(_:launch:)`) | plain git on the host repository; `osascript`, `open -na Ghostty` |
| `RepoService` | `SandboxRepositories` (`repositories()`, `fetchBack(_:)`) | `SandboxedCommand.git` in `repos/<name>` (sandbox user, sv's profile); `git fetch --no-tags --no-recurse-submodules sandvault` in the host repository |
| `ToolService` | `ToolAccess` (`status(of:)`, `grant(_:method:)`, `sandboxLookupInvocation`) | `/bin/zsh -lc 'command -v'`, `otool -L`, `brew info --json=v2`, `brew install`, the sandbox lookup |
| `MigrationService` | `ConfigMigration` (`plan`, `apply`, `location(of:)`), `SecretScan` | `git config --global --get user.name` and `user.email` |
| `KeyService` | `AuthorizedKeyStore` (`keys`, `add`, `remove`, `parse`) | `ssh-keygen -l -f` |
| (none) | `SandvaultDefaults` (`read`, `set`, `clear`), `SvOptions.validate` | nothing |

**Readiness.** A source is local when it is a directory (as sv-clone decides); otherwise it must look like a remote URL
(`https`, `ssh`, `git`, scp-like; `file://` and `<transport>::` are refused). Nothing is contacted, and the host
repository is trusted (plain git through the runner). Severities follow what happens in the sandbox:

| Finding | Severity | Why |
|---|---|---|
| not a git working tree, not its root, inside the shared workspace or the sandbox home, no `origin` remote | blocker (`notGitRepository`) | git clone or sv-clone v1.32 fails (sv-clone line 156 needs `origin`); the sandbox's own files are never treated as a trusted repository |
| no commits | blocker | nothing to clone |
| uncommitted changes | warning | they stay behind unless `includeUncommitted` |
| tracked symlink to `/Users/…` or `/Volumes/…` (outside the workspace and sandbox home), into the checkout itself, or relative and leaving the repository | warning | it dangles in the clone; links to system paths pass |
| tracked `.env*` (templates such as `.env.example` pass) | warning | secrets in git and in the clone |
| submodule with a local URL (relative URLs count when `origin` is local) | warning | sv-clone does not check out submodules, and `git submodule update` in the sandbox cannot read the path |
| `repos/<name>` exists but is not a clone | warning | git clone fails unless it is empty |
| untracked files (count); untracked or ignored `.env*` and `.envrc`; tracked `.envrc`; `.venv`/`venv` whose `pyvenv.cfg` `home` is outside; `.git` as a file; `count-objects` above 1 GB; an existing clone | info | not copied, recreate it, `direnv allow` needed, sv-clone fetches into the clone and leaves its working tree alone |

One group shows at most 20 findings, then one that counts the rest.

**Hand-off.** `handOff` re-runs the check and refuses blockers, sv options outside `SvOptions` and `includeUncommitted`
for a URL. With a task or uncommitted changes it writes `$SHARED_WORKSPACE/tmp/handoff-<repo>.md` (0640: source,
branch, clone path, task, and the instruction to `git apply` `handoff-<repo>.patch`, made with `git diff --binary
--no-ext-diff --no-textconv HEAD` and fixed `a/` `b/` prefixes; untracked files are not in it; a stale patch is
removed). The command is `sv-clone [-k|-w] <resolved source> -- <sv options> <agent> [-- <prompt>]` with the prompt
`Read <briefing> and continue the task described there.`, passed the way each agent keeps a first prompt interactive:
positional for claude, codex and pi, `--prompt-interactive` for gemini, `--prompt` for opencode, none for muse and
shell (after `sv shell --` the words are a command). `ShellQuoting` builds the line: POSIX single quotes with `'\''`;
only `[A-Za-z0-9_./:,+@-]` stays bare, so zsh's `=cmd`, `~` and globs never expand. It is round-trip tested through
`/bin/sh` and bash.

| Terminal | Invocation |
|---|---|
| Terminal | `osascript -e 'on run argv' -e 'tell application "Terminal"' -e activate -e 'do script (item 1 of argv)' -e 'end tell' -e 'end run' <command>` |
| iTerm2 | the same with `set newWindow to (create window with default profile)` and `tell current session of newWindow to write text (item 1 of argv)`; the user's shell runs it, so the window stays (as upstream's launcher does) |
| Ghostty | `open -na Ghostty --args --command=/bin/zsh -lc '<command>; exec "$SHELL" -l'` (Ghostty runs `--command` through a shell, as upstream's launcher relies on) |

The command reaches AppleScript as an `argv` item, never inside a string literal. A failed launch (for example a
missing Automation permission) throws and records nothing; otherwise a `HandoffRecord` replaces the one of the same
repository. Off macOS, and with `launch: false` (`svctl handoff --print`), the briefing and record are written and the
command comes back with `launched: false`.

**Way back.** The host never runs git inside a clone. `GitSafe`'s overrides do not cover everything git executes from a
repository's config: `status` runs a `clean` filter whenever it re-hashes a file, `log` runs `gpg.program` under
`log.showSignature`, and reading the config first to neutralize it would race with a sandbox that rewrites it in a loop.
So every git call on a clone goes through `SandboxedCommand.git`, the same wrapper the tool lookup uses:

```
sudo -n -u sandvault-$USER /usr/bin/env -i HOME=/Users/sandvault-$USER USER=sandvault-$USER PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/sandbox-exec -f /var/sandvault/sandbox-sandvault-$USER.sb \
  /usr/bin/git <GitSafe hardening> -c safe.directory=* -C <clone> <arguments>
```

Whatever the clone's config makes git run then stays as confined as the agent. `safe.directory=*` is needed because
the host owns the clone. `repositories()` lists the real directories in `repos/` (no symlinks, hidden names or control
characters) and asks git only where `.git` is a directory. Per clone: `symbolic-ref` (the branch is validated before it
goes into a host ref), `log -1 --format='%H %ct'` with `log.showSignature=false` (signature output would precede the
line), `rev-list --left-right --count @{upstream}...HEAD`, and `--no-optional-locks status --porcelain=v1 -z
--ignore-submodules=all` (dirty when it prints anything). The output is untrusted: one line within a byte limit (256,
128, 64, 32), no control characters, strict number and hash formats, otherwise unknown. Unfetched commits combine the
trusted host side (`rev-parse` of `sandvault/<branch>`, before the first fetch the host's own branch) with a sandboxed
`rev-list --count <commit>..HEAD` in the clone. Off macOS the sandboxed git cannot run: branch, head, date, counts and
unfetched stay `nil` and `dirty` stays `false` (the contract has no unknown for it); the deploy key
(`_sandvault/.ssh/deploy_<name>` exists) is still reported. `fetchBack` stays host-side in the host repository: it
checks the `sandvault` remote and runs `git fetch --no-tags --no-recurse-submodules sandvault` with the hardening.
upload-pack serves the clone's objects without worktree filters, fsmonitor or signatures, and without tags the sandbox
cannot plant any in the host repository. A test plants a filter, `core.fsmonitor` and `gpg.program` in a clone, runs
`repositories()` and `fetchBack` with the sandboxed path disabled and checks that nothing fired and no host git call
named the clone; plain git in the clone fires them.

**Tools.** `status` validates the name (`[A-Za-z0-9._+-]{1,64}`), resolves it with `/bin/zsh -lc 'command -v -- <name>'`
and classifies location (`sharedUser`, `sandboxHome`, `hostHome`, Homebrew prefixes including `/usr/local/Cellar`,
else `system`) and kind: Mach-O by magic, copyable when `otool -L` lists only `/usr/lib` and `/System` libraries;
scripts by `#!`, copyable when the interpreter is a system, Homebrew or shared path, or `/usr/bin/env <x>` with `<x>`
found in the sandbox. Reachability runs as the sandbox user with sv's session environment **inside sv's profile**:

```
sudo -n -u sandvault-$USER /usr/bin/env -i HOME=… USER=… SHELL=/bin/zsh SHARED_WORKSPACE=… PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/sandbox-exec -f /var/sandvault/sandbox-sandvault-$USER.sb \
  /bin/zsh -c 'source ~/.zshenv; source ~/.zprofile; print -r -- sandvault-config:lookup; command -v -- <name>'
```

The sandbox can write its shell files, so they never run outside sandbox-exec; the marker line separates "not found"
from "could not check". Options: `available`, else `brew` (formula from a Cellar path or `brew info --json=v2`, which
runs only for a missing tool and not for one already in Homebrew) before `copy`. `grant` installs or copies
(`user/bin/<name>`, 0750, through `SharedFiles`; sv's `.zprofile` puts that directory first on the PATH), checks again
and records a `ToolGrant` only when the sandbox now finds the tool.

**Migration.** `~/.claude/settings.json`, `CLAUDE.md`, `commands|agents|skills/**` (at most 500 files, depth 8), a
generated `.gitconfig` with the `[user]` name and email (quoted; control characters refused), `~/.zshrc`, `.zprofile`
and `.zshenv` go to the same relative paths under `$SHARED_WORKSPACE/user`, which sv's `configure` rsyncs into the
sandbox home each session (zsh files are sourced from there). Blocked, with a reason: missing, symlinks (never
followed), non-regular files, files over 1 MB, credential names (`.credentials.json`, `*.pem|key|p12|pfx`, `id_*` but
not `.pub`, `.netrc`, `.env*`), `.npmrc` with `_authToken`, and `SecretScan.patterns`: `sk-ant-`, `ghp_`,
`github_pat_`, `gho_` (each followed by 16+ token characters, so prose mentioning a prefix passes), `xox[abp]-`,
`AKIA[0-9A-Z]{16}`, private key headers, JSON keys containing `api key|token|secret` with a non-path value of 12+
characters, and shell assignments to `*API_KEY|TOKEN|SECRET|PASSWORD*` with a literal value of 12+ characters. A
reason names the pattern and line, never the match. `.zshenv` loses our `defaults` block and keeps the network block
netd maintains in the shared copy. `apply` re-reads and re-checks every file and writes only entries the plan approved
(0640, 0750 for executable sources).

**Keys.** `authorized_keys.d` is host-only (`AtomicFile`, files 0600, directory 0700). `add` takes exactly one plain key
line of a known type (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256|384|521`, `sk-…@openssh.com`) whose base64 blob
names the same type, without options and without `PRIVATE KEY`, then checks it with `ssh-keygen -l -f` and removes it
again on failure. `keys` shows what sv will do: a private key makes sv abort, a file ssh-keygen rejects is ignored. sv
applies the directory on its next run (`AuthorizedKeyStore.appliedNote`).

**Defaults.** `SandvaultDefaults` keeps `export SANDVAULT_ARGS='…'` in `ManagedBlock(name: "defaults", commentPrefix:
"#")` of the host's `~/.zshenv` (`AtomicFile`, mode kept; a symlinked `~/.zshenv` is edited at its target) and reports
an assignment outside the block. `SvOptions` allows the session options that take no value (`-s/--ssh`, `-v`, `-vv`,
`-vvv`, `-n/--no-build`, `-b/--browser`, `--chrome`, `--lightpanda`, `-i/--ios`, `-I/--ios-gui`,
`-N/--native-install`) and refuses `-x/--no-sandbox`, `-r/--rebuild` (it drops the managed rules block) and the options
that exit or work only standalone; hand-offs use the same list.

**CLI.** `svctl handoff <path|url> [--agent <name>] [--task <text> | --task-file <file|->] [--include-uncommitted]
[--terminal terminal|iterm2|ghostty] [--deploy-key none|ro|rw] [--sv-option=<opt>]… [--check-only] [--print]`
(defaults from `HandoffSettings`; exit 1 on a blocker), `svctl repos [list] | fetch <name>`, `svctl tools check <name> |
grant <name> [--method brew|copy|available] | list`, `svctl migrate plan <items…> | apply <items…> [--yes]` (items
`all`, `claude-settings`, `claude-memory`, `claude-commands`, `claude-agents`, `claude-skills`, `git-identity`, `zshrc`,
`zprofile`, `zshenv`), `svctl keys list | add <name> <file|-> | remove <name>`, `svctl defaults show | set -- <options…> |
clear`; all take `--json`. Off macOS, `handoff --check-only`, `migrate plan`, `keys`, `defaults` and `tools list` work;
opening a terminal and `tools check|grant` refuse with "unsupported on this platform"; commands that need the shared
workspace say that it is missing.

**Only a Mac can confirm:** every synthetic fixture in `Tests/SandvaultWorkflowTests/Fixtures`; the Automation prompt
for Terminal and iTerm2 on the first hand-off; Ghostty's handling of `--command`; the first-prompt flags of gemini,
opencode and pi; that `sandbox-exec` started through `sudo -u <sandbox> /usr/bin/env -i` reads sv's profile and finds
Homebrew tools after `.zprofile`; that `/usr/bin/git` (the Command Line Tools shim) runs as the sandbox user inside the
profile and accepts the host-owned clone with `safe.directory=*`; how `otool` behaves without the Command Line Tools
(reported as "libraries unknown").

## 8 · App

`SandvaultConfig.app` (macOS 14, `LSUIElement`, bundle id `me.admon.apps.sandvault-config`) is two layers (D24):
`SandvaultAppModel`, a package library with every piece of logic, `@MainActor @Observable` and free of SwiftUI and
AppKit, so it builds and tests on Linux; and `App/SandvaultConfig/`, SwiftUI views plus a little AppKit glue that only
place what the models expose. Views never run commands or read files; titles, summaries and formats come from the
models.

```
AppEnvironment.live ─▶ AppModel ─┬▶ ConfigEditor ──▶ config.json (fresh read, change, save) ─▶ reloadConfig
  (every service behind          ├▶ NetdLink ──────▶ control socket: subscribe status, connections, asks
   a protocol)                   └▶ one model per screen ─▶ Observe / Enforce / Net / Workflow
```

**Composition root.** `AppEnvironment` holds `SandvaultEnvironment`, `AppPaths`, the `CommandRunner`, `ConfigStore`,
`BundledTools`, an `AppClock` (now, sleep), `PreferencesStore` and one protocol per service: `ProcessSource`,
`ProcessControlling`, `ConnectionSource`, `ViolationSource` (Observe's structs conform directly), `DoctorSource`
(the three `CheckProvider`s per config), `StatusSource` (`StatusSummary.collect`), `PolicyControl`
(`HelperPolicyApplier`), `ProfileSource` (`ProfileInspector`), `SandboxUIDSource`, `LocalPortSource`,
`HelperInstalling`, `NetdConnector` / `NetdClient` (`ControlClient`: status, subscribe, answer, pendingAsks, recent,
reloadConfig, events), `NetdAgentControl` (`NetdLaunchAgent`), `CAControl` (`CAStore`, `CAPublisher`,
`SandboxEnvironmentBlock`) and the five workflow services. `AppEnvironment.live(bundled:)` wires the real factories;
the tests build the same struct from fakes.

**ConfigEditor** is the app's only writer of config.json. `edit(reloadNetd:_:)` re-reads the file, applies one change,
saves, and sends `reloadConfig` over a one-shot connection when netd runs, so an edit never overwrites what svctl or netd
(ask answers) saved in the meantime; a damaged file makes the edit fail instead of being replaced. `reloadIfChanged()`
re-reads on modification time while the app polls.

**NetdLink** keeps one subscription to `.status`, `.connections` and `.asks` for as long as the app runs (netd raises asks
only while someone listens, D22). It holds the latest `NetdStatus`, the last 1000 records and the pending asks;
when the connection ends it forgets the asks, waits 0.5 s doubling to 15 s, reconnects and subscribes again.
`retryNow()` skips the wait after a netd install or restart.

**Simple and expert window.** Without expert mode (`AppPreferences.expertMode`, off by default, a toggle in Settings)
the sidebar has Overview, Activity, Repos & Hand-off and Settings (`Screen.simple`, `AppModel.screens`); a hidden
page asked for (the next step's firewall link) opens the overview instead. The overview then shows the protection
level, the next step only while setup is incomplete, sessions and the newest five activity lines; the doctor sections
and the raw firewall state only in expert mode. `ProtectionLevel` maps four choices onto the policy: Off (`off`),
Watch (`watch`), Ask (`proxyOnly` with default action `ask`), Block All (`blocked`, processes keep running).
`FirewallModel.setProtection` saves and applies at once, without the rule preview; any other combination reads as
"custom settings from expert mode". The menu bar offers the same four levels, or the five modes in expert mode.

| Screen | Model | What it does |
|---|---|---|
| Overview | `OverviewModel` | doctor sections of Observe, Enforce, Net; `StatusSummary`; sessions; `SetupState.nextStep` (install sv, create the sandbox, install the helper, end a panic, start netd, turn on the firewall, apply it, ready) |
| Activity | `ActivityModel` | one list: running ICMP tools (from the process snapshot), hosts netd saw (`HostGroup`, Allow = `*.<registrable domain>`, Block = the host), then direct connections from lsof grouped by address (loopback left out; 80/443/53 left out while pf hands them to netd); a summary line and a hint when host names cannot be seen (Off, Open, netd down) |
| Processes | `ProcessesModel` | snapshot, tree rows, session groups; terminate, kill, throttle, end session, end all with the `ControlReport` as a message |
| Network | `NetworkModel` | lsof sockets and nettop traffic (polled on this page only); netd records grouped by host (`HostGroup`: allowed, denied, ports, processes, bytes, last decision); Allow Host, Allow Domain (`*.<registrable domain>`), Deny via `upsertDomainRule` and reload |
| Firewall & Proxy | `FirewallModel` | mode, LAN guard, localhost, port exceptions (pf, take effect on apply); default action, ask fallback and timeout, domain rules, DNS overrides, private destinations (netd, reloaded at once); inspection with CA create and publish and the `.zshenv` sync; `prepareApply` builds the `AppliedState` and the anchor text (`Enforce.firewallPreview`), `confirmApply` sends it with `releasingPanic: true`; panic saves `blocked` first, then calls the helper; Turn Off saves `off` and flushes |
| Sandbox Rules & Learn | `RulesModel` | preset, auto re-apply, file, mach and exec rules (`SandboxSettings.add`); profile plan with drift and diff; apply and reset; learn mode follows `ViolationMonitor.stream()` (or the last 10 minutes), `RuleSuggester` suggestions, accept adds the proposal, dismiss hides it for the session |
| (panels) | `AsksModel` | pending asks oldest first, countdown, host or domain scope, answers through `NetdLink` |
| Tools | `ToolsModel` | `ToolService.status`, grant by method, grants from the config |
| Repos & Hand-off | `HandoffModel`, `ReposModel` | readiness first; the button stays disabled with a reason until a repository is chosen, checked and free of blockers; agent, task, uncommitted changes, deploy key, terminal from the settings; repositories with Fetch Back |
| Migration | `MigrationModel`, `KeysModel` | item selection, plan preview with blocked entries and reasons, copy; keys in `authorized_keys.d` |
| Settings | `SettingsModel` | helper install and uninstall, netd LaunchAgent install, restart, uninstall, default agent, terminal, refresh interval, the svctl symlink command |

Errors become `UserMessage` values (kind, title, detail, suggested command taken from the error text). A workflow
service that throws `notImplemented` turns its screen into "not available yet" (`Availability`), not an error.

**Polling.** `AppModel.setVisible(_:_:)` tracks the main window and the menu bar window. While either is visible, one
task re-reads config.json if it changed and takes a process snapshot every `refreshInterval` (default 2 s); with the
window open it also reads sockets on the Activity and Network pages and refreshes the overview checks at most every 30 s. When both
are closed nothing polls; only the netd subscription stays (asks, menu bar state).

**Menu bar.** `MenuBarSummary.state` picks the symbol (`AppModel.menuBarSymbol`, which does not read the connection
records, so the icon is not redrawn per record): blocked or panic `xmark.shield.fill`, pending asks
`exclamationmark.shield.fill`, watch or proxy-only without netd `exclamationmark.triangle`, off `shield.slash`, open
`shield.lefthalf.filled`, watch `eye`, proxy-only `checkmark.shield.fill`. The window shows sessions, processes, denials of the last
hour, the firewall mode (choosing one saves it and opens the Firewall page with the rules to confirm), Hand Off a
Repository (folder picker), Open Window, a two-step Panic, Firewall Off, and the last five denied hosts with Allow.

**Asks.** `AskPanelController` observes `AsksModel.pending` (`withObservationTracking`) and opens one floating
non-activating `NSPanel` per ask (host, process, port, countdown, host or domain scope, Allow Once, Allow Always, Deny
Once, Deny Always); a panel closes when netd resolves its ask. While the app is not active, `AskNotifier` also posts a
user notification whose actions carry the same four answers (`AskDecision` raw values).

**Hand-off by drop.** Folders dropped on the Repos & Hand-off page or on the menu bar window go to
`AppModel.handOff(paths:)`, which takes the first directory, opens the page and runs the readiness check.

**Helper and netd installation.** The helper is installed with the bundled binary (D27):
`osascript -e 'do shell script "<helper> install --source <helper> --user <name> --json" with administrator privileges'`.
`AdministratorScript` single-quotes every argument for the shell, then escapes backslash and double quote for the
AppleScript string; osascript receives the script as one argv element. The helper's JSON line is read back from
osascript's output; a cancelled password dialog (-128) is reported as cancelled. Uninstall runs the installed helper
(or the bundled one) with `uninstall --user <name> --json`. netd is installed through `NetdLaunchAgent` with the bundled
`sandvault-netd`: the same LaunchAgent `svctl netd install` writes, so the app and the CLI never disagree about it
(`SMAppService` is not used).

**Bundle and project.** `App/project.yml` (XcodeGen; the `.xcodeproj` is generated, D2): the local package
(`packages: SandvaultConfig: path: ..`), scheme `SandvaultConfig`, Swift 6, macOS 14, ad-hoc signing (`-`), no hardened
runtime, no App Sandbox. `svctl`, `svctl-helper` and `sandvault-netd` are XcodeGen `tool` targets (`BundledSvctl`,
`BundledHelper`, `BundledNetd`: target and module names differ from the package's executable targets; `productName`
and `PRODUCT_NAME` give the product names, since XcodeGen names the product reference after `productName`) whose
sources are `../Sources/<name>` and which link the package's library products; the app embeds them with a copy-files
phase into
`Contents/MacOS` (`copy: destination: executables`) and finds them with `Bundle.main.url(forAuxiliaryExecutable:)`.
The executables import ArgumentParser, which the package uses but does not export, so `project.yml` references
`swift-argument-parser` with the same URL and requirement as `Package.swift`; Xcode resolves both to one checkout.
The bundled svctl finds the helper and netd next to itself, as it does in a SwiftPM build.

**Verified off the Mac:** `xcodegen generate` (XcodeGen 2.44.1, built on Linux) accepts the spec and produces the
scheme, the three tool targets with their product names and an "Embed Dependencies" copy phase to Executables; the
SwiftUI layer type-checks in Swift 6 mode against stub SwiftUI, AppKit and UserNotifications modules with macOS 14
signatures (a scratch harness, not in the repository).

**Only a Mac can confirm:** that `xcodebuild` compiles the app against the real SDK (CI), the tools landing in
`Contents/MacOS`, the `osascript` password dialog and the helper's JSON passing through `do shell script`, floating ask
panels over full-screen apps, notification actions from an ad-hoc signed `LSUIElement` app (macOS may not deliver them
without a signature), `MenuBarExtra` window `onAppear`/`onDisappear` as the polling trigger, and drag and drop of Finder
folders onto the menu bar window.
