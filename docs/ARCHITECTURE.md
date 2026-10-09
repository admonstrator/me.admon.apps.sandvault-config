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

_Agent B fills this section._

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
other than 80/443 need an explicit `allow`) → `ask` goes to `AskCoordinator` → resolution: `DnsOverride` (exempt
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

Limits: HTTP upgrades (WebSocket over plain `ws://`) are not forwarded; a plain HTTP request body is not
back-pressured; inspection covers HTTP/1.1 only (clients negotiating `h2` fall back through ALPN).

## 7 · Workflow

_Agent D fills this section (phase 2)._

## 8 · App

_Agent E fills this section (phase 2)._
