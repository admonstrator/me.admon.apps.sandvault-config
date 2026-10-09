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
- Git on sandbox-writable repositories always goes through `GitSafe` (same hardening as `sv-clone`).
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
| Processes, sessions | `ProcessMonitor.snapshot()` -> `ProcessSnapshot` (`processes`, `sessions`, `helpers`, `environmentReadable`, `tree()`, `session(matching:)`); `sandboxProcesses()`, `helpers()` | `ps -axww -o pid=,ppid=,user=,%cpu=,%mem=,rss=,etime=,state=,command=`, then `asSandvault(/bin/ps -E -ww -U <sandbox> -o pid=,command=)` |
| Control | `ProcessController.terminate(pid:force:)`, `terminateSession(_:force:)`, `terminateAll()`, `throttle(pid:nice:background:)` -> `ControlReport` | `asSandvault(/bin/kill)`, `renice`, `taskpolicy -b`; sv's sudoers: `sudo -n /bin/launchctl bootout user/<uid>`, `sudo -n /usr/bin/pkill -9 -u <sandbox>` |
| Sockets, traffic | `ConnectionMonitor.connections()`, `traffic(pids:)` | `asSandvault(/usr/sbin/lsof -nP -i -a -u <sandbox> -F pcPtnT)`, `nettop -P -L 1 -x -J bytes_in,bytes_out` |
| netd seams | `Observe.makeProcessAttributor`, `Observe.makeLocalPortSource` | lsof cache; ps + helper logs |
| Violations | `ViolationMonitor.recent(last:)`, `stream()`; `SandboxViolation.occurrences` | `log show` / `log stream --style ndjson --predicate <sandbox predicate>` |
| Learn mode | `RuleSuggester.suggestions(for:environment:)` -> `[RuleSuggestion]` | violations |
| Doctor | `Observe.makeCheckProvider` (`ObserveChecks`, ids in `ObserveChecks.ids`) | dscl, dseditgroup, sudo, ls -led, files |
| Overview | `StatusSummary.collect(environment:runner:firewallMode:checks:)` | the above |

**Sessions.** `SV_SESSION_ID` is read from the environment that `ps -E` appends to each command line (last
`SV_SESSION_ID=<uuid>` word, strict UUID). A process without one inherits from its parent. When `ps -E` is not
possible, ids come from the session launcher: sv's `sudo --login ... /usr/bin/env -i ... SV_SESSION_ID=<uuid>` runs
as root, so only the host side can create it and the sandbox cannot forge it. A session's root is the member whose
parent is outside the group; its command is the agent (`claude`, `codex`, ...) closest to the root, else the root's
name. Host helpers: Chrome by `--user-data-dir=.../.local/state/sandvault/chrome-data-<uuid>` (main process only, no
`--type=`), the iOS bridge by `sv-ios-bridge --udid` and the session of its parent `sv`; ports come from
`chrome-<uuid>.log` / `ios-bridge-<uuid>.log`. The `ps`/`lsof` this module runs as the sandbox user are left out.

**Control.** A pid is signalled only after a fresh `ps` shows it belongs to the sandbox user, and the signal is
sent as that user, so the kernel refuses anything else too. `terminateAll` follows sv's uninstall: bootout, wait,
`pkill -9` only for survivors; the argv matches sv's sudoers lines exactly. Reports list each command with its
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
[--force] [--yes]`, `throttle <pid> [--nice <n>] [--background]`, `net [--listening] [--traffic]`,
`violations [--last 10m] [--follow] [--all] [--suggest]`; all take `--json` (`violations --follow --json` prints
JSON Lines).

**Only a Mac can confirm:** the exact output of every fixture in `Tests/SandvaultObserveTests/Fixtures`
(all synthetic), whether `nettop` run by the host user sees the sandbox user's processes, whether `taskpolicy -b -p`
works on another user's process, lsof latency through sudo against the 200 ms budget, whether sandbox denials
arrive at default log level and whether the reporting subsystem duplicates kernel reports.

## 5 · Enforce

_Agent B fills this section._

## 6 · Net

_Agent C fills this section._

## 7 · Workflow

_Agent D fills this section (phase 2)._

## 8 · App

_Agent E fills this section (phase 2)._
