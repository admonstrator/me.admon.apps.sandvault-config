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
- CLI: each area registers its commands in `Sources/svctl/<Area>/<Area>Commands.swift`; shared options in
  `GlobalOptions` (`--json`, `--config`), output helpers in `Output`.

## 4 · Observe

_Agent A fills this section._

## 5 · Enforce

_Agent B fills this section._

## 6 · Net

_Agent C fills this section._

## 7 · Workflow

_Agent D fills this section (phase 2)._

## 8 · App

_Agent E fills this section (phase 2)._
