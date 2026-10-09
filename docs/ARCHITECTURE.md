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

_Agent A fills this section._

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
the redirect; one host user per Mac can own the anchor.

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

_Agent C fills this section._

## 7 · Workflow

_Agent D fills this section (phase 2)._

## 8 · App

_Agent E fills this section (phase 2)._
