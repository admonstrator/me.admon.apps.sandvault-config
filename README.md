# Sandvault Config

A native macOS companion for [sandvault](https://github.com/webcoyote/sandvault) (`sv`): overview, control and
fine-grained permissions for the `sandvault-$USER` account that AI agents run in.

`sv` keeps creating the sandbox account and starting sessions. Sandvault Config adds what is missing around it:

- **See** what the sandbox does: processes per session, sockets and traffic, every domain it contacts, sandbox denials.
- **Forbid** what is dangerous: a per-user firewall (pf) that can force all web traffic through a local proxy,
  blocks the LAN and host services on localhost, a hardened `sandbox-exec` preset, and a panic switch.
- **Grant** what you choose: domain rules with Little Snitch style prompts, DNS overrides, sandbox rules learned from
  denials, host commands made available inside the sandbox.
- **Move work in and out quickly**: hand a repository to Claude Code (or Codex, Gemini, ...) in one step, fetch the
  agent's commits back, migrate your Claude and shell configuration without credentials.

Status: 0.1.0, built and unit-tested on Linux and macOS CI. Behaviour that depends on a real Mac (pf rules,
`sandbox-exec`, sudo, the unified log, the SwiftUI app at runtime) still needs the device test below.

## Components

| Part | Runs as | Purpose |
|---|---|---|
| `SandvaultConfig.app` | you | Menu bar status, main window, ask prompts, setup |
| `svctl` | you | Command line for every feature (`svctl --help`) |
| `sandvault-netd` | you (LaunchAgent) | Proxy, transparent listeners, DNS forwarder, connection log, control socket |
| `svctl-helper` | root through an argument-exact sudoers rule | Writes the managed block of sv's sandbox profile, loads the pf anchor, panic |

## Requirements

- macOS 14 or later, sandvault 1.32 (`brew install sandvault`, then `sv build`)
- Xcode 16 or later for the app, [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)

## Build

```bash
swift build -c release            # svctl, svctl-helper, sandvault-netd in .build/release
swift test

cd App && xcodegen generate       # then open SandvaultConfig.xcodeproj, or:
xcodebuild -project SandvaultConfig.xcodeproj -scheme SandvaultConfig -configuration Release build
```

The app bundles all three executables in `Contents/MacOS`.

## First steps

```bash
svctl doctor                      # is sandvault set up correctly? every finding names its fix
svctl status                      # sessions, processes, listening ports, firewall mode

svctl helper install              # once, admin password: privileged helper + sudoers rule
svctl netd install                # proxy, DNS and connection log as a LaunchAgent

svctl firewall mode watch         # everything allowed, every host the sandbox uses is logged
svctl firewall mode proxy-only    # only web traffic, through netd and your domain rules
svctl firewall apply              # shows the pf rules, then loads them
svctl asks --follow               # answer prompts for unknown domains (the app does this too)

svctl handoff ~/src/my-app --agent claude --task "Fix the failing tests"
svctl repos                       # what the agents committed; svctl repos fetch my-app
```

Rolling back is always one command: `svctl firewall off`, `svctl rules reset`, `svctl helper uninstall`.

## Commands

| Area | Commands |
|---|---|
| Observe | `status`, `doctor`, `ps`, `sessions`, `kill`, `throttle`, `net`, `violations` (learn mode with `--suggest`) |
| Enforce | `rules` (sandbox profile block, presets, diff, apply), `firewall` (modes, LAN, localhost, exceptions), `panic`, `helper` |
| Network | `proxy` (domain rules, default action, inspection), `dns` (overrides), `ca`, `netlog`, `asks`, `netd` |
| Workflow | `handoff`, `repos`, `tools` (check and grant commands), `migrate`, `keys` (`authorized_keys.d`), `defaults` (`SANDVAULT_ARGS`) |

Every command accepts `--json`.

## Security model

The sandbox user is treated as the adversary.

- Configuration, CA key, logs and the control socket live in your home directory, which sv's profile hides from the sandbox.
- Writes into the shared workspace never follow a symlink the sandbox planted (`SharedFiles`).
- Git never runs as you inside a sandbox clone; it runs as the sandbox user under sv's profile.
- The helper accepts typed JSON only, generates SBPL and pf text itself, and its sudoers rule lists each allowed call
  with its exact arguments.
- Enforcement is pf per user plus `sandbox-exec`; proxy variables inside the sandbox only help cooperative tools.

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), decisions: [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Device test

```bash
scripts/verify-on-mac.sh capture  # read-only: svctl views plus raw macOS output for the test fixtures
scripts/verify-on-mac.sh guided   # helper, rules, learn mode, proxy-only firewall, panic; asks before each step
```

## Kurz auf Deutsch

Sandvault Config ergänzt sandvault um Überblick und Kontrolle. Die App und `svctl` zeigen, welche Prozesse in der
Sandbox laufen und wohin sie sich verbinden. Eine Firewall nur für den Sandbox-User leitet den Webverkehr über einen
lokalen Proxy, der bei unbekannten Domains nachfragt wie Little Snitch. Gefährliches lässt sich sperren: das lokale
Netz, Dienste des Hosts, Werkzeuge wie `osascript`, im Notfall alles per Not-Aus. Freigeben geht gezielt: Domains,
DNS-Overrides, Sandbox-Regeln aus dem Lernmodus, Befehle vom Host. Ein Repository geht mit einem Befehl an Claude,
und die Commits holst Du genauso schnell zurück.

Vor dem ersten echten Einsatz bitte `scripts/verify-on-mac.sh capture` und danach `guided` laufen lassen. Die
pf-Regeln, das Sandbox-Profil und die App selbst sind bisher nur kompiliert und mit Fixtures getestet, nicht auf
einem echten Mac ausgeführt.

## License

Not yet chosen. sandvault is Apache 2.0; the only part of it in this repository is its sandbox profile text, used as a test fixture.
