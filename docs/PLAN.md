# Plan: Sandvault Config, eine macOS-App zur Kontrolle von sandvault

## Context

sandvault (`sv`, upstream webcoyote/sandvault v1.32.0) isoliert KI-Agenten in einem eigenen macOS-User `sandvault-$USER`. Dazu kommen ein `sandbox-exec`-Profil, eine sudoers-Freigabe und ein Shared Workspace `/Users/Shared/sv-$USER`. Das funktioniert gut, aber es fehlt an Überblick und Kontrolle:
- Man sieht nicht, welche Prozesse laufen und welche Verbindungen offen sind.
- Es gibt keine Möglichkeit, gezielt etwas freizugeben oder zu sperren, und keine Firewall im Stil von Little Snitch.
- Der Umzug von Repos und Konfigurationen in die Sandbox ist mühsam.

Ziel ist eine native macOS-App (SwiftUI, Menüleiste plus Fenster) samt CLI `svctl`. Sie **ergänzt** `sv` und ersetzt es nicht. Schwerpunkte: ein Repo schnell an Claude übergeben, sicherstellen, dass aus der Sandbox nichts ausbricht, und gezielt freigeben können.

Das Repo ist leer. Upstream liegt zum Nachschlagen im Scratchpad (`…/scratchpad/ref/sandvault`).

## Entscheidungen (kommen nach `docs/DECISIONS.md`)

| Nr. | Frage | Entscheidung |
|---|---|---|
| D1 | Oberfläche | Native macOS-App (SwiftUI, MenuBarExtra + Fenster) plus CLI `svctl` |
| D2 | Technik | Komplett in Swift, kein Rust. Kernmodule als SwiftPM-Paket (unter Linux testbar), die App als Xcode-Projekt per XcodeGen (`project.yml`, `.xcodeproj` wird nicht eingecheckt) |
| D3 | Verhältnis zu sv | Ergänzen: `sv` bzw. `sv-clone` installieren und starten Sessions, wir lesen, steuern und erweitern |
| D4 | Regeln wirksam machen | Verwalteter Block zwischen Markern am Ende von `/var/sandvault/sandbox-sandvault-$USER.sb`. Vor dem Schreiben wird mit `sandbox-exec -f <kandidat> /usr/bin/true` validiert. Wird der Block durch `sv --rebuild` überschrieben, erkennt das Tool die Abweichung und wendet ihn neu an |
| D5 | Sprache | UI, CLI und Meldungen auf Englisch. README mit deutschem Abschnitt. Code, Kommentare und Commits auf Englisch |
| D6 | Netzwerk | Monitor + Firewall pro Sandbox-User (pf) + Proxy/DNS mit Rückfrage + optionale TLS-Inspektion. Keine Network Extension |
| D7 | Kontrolle | Regel-Editor + Lernmodus, Vorlage „Gehärtet“ mit Not-Aus und Integritätsprüfung, Befehle freigeben |
| D8 | Workflow | Repo-Übergabe an einen Agenten, Rückweg samt Repo-Status, Prozesse und Sessions, Konfig-Migration |
| D9 | Root-Rechte | Root-eigener Helper unter `/Library/PrivilegedHelperTools/me.admon.apps.sandvault-config.helper`, freigegeben per sudoers-Regel `/etc/sudoers.d/60-sandvault-config-$USER` (wie `sv` es selbst macht). Einmalige Installation mit Admin-Passwort. Der Helper nimmt nur typisierte JSON-Daten an, nie fertigen SBPL- oder pf-Text |
| D10 | Proxy-Technik | SwiftNIO + swift-nio-ssl + swift-certificates (laufen auf Linux, also hier testbar) |
| D11 | Mindestversion | macOS 26 (seit 2026-10-10, vorher 14), Swift-6-Sprachmodus |
| D12 | Später | Secret-Scan, Audit-Log, Network Extension, Lokalisierung, Signierung/Notarisierung, Lizenzdatei |

## Architektur

**Komponenten**
1. **App** `SandvaultConfig.app` läuft als Host-User ohne Rechte. Menüleisten-Symbol mit Zustand (Sessions, Prozesse, blockierte Verbindungen), Not-Aus und Schnellübergabe. Dazu ein Fenster mit Seitenleiste: Overview · Processes · Network · Firewall & Proxy · Sandbox Rules & Learn · Tools · Repos & Handoff · Migration · Settings. Ein Rückfrage-Panel bei unbekannten Domains.
2. **`sandvault-netd`** läuft als LaunchAgent des Host-Users, unabhängig davon, ob die App offen ist. Er enthält:
   - den expliziten Proxy auf `127.0.0.1:18080` (CONNECT und absolute URIs),
   - transparente Listener für HTTP (18081) und TLS (18443, Ziel aus SNI bzw. dem Host-Header, also ohne Abfrage des pf-States),
   - einen DNS-Forwarder auf 18053 (UDP/TCP) mit Sperren, Overrides und Protokoll,
   - die Policy-Engine (allow/deny/ask, Wildcards, private Adressbereiche standardmäßig gesperrt),
   - das Verbindungsprotokoll (JSONL mit Rotation, Header redigiert),
   - die TLS-Inspektion mit eigener CA (Schlüssel liegt nur im Host-Home, Datei mit Rechten 0600).
   Die Steuerung läuft über einen Unix-Socket im Host-Home, den die Sandbox nicht erreicht. Das Protokoll sind JSON-Zeilen.
3. **`svctl`** ist die CLI für alle Funktionen und wird auch von Skripten genutzt.
4. **`svctl-helper`** läuft als Root, nur per `sudo -n`. Er wendet den Profilblock an bzw. setzt ihn zurück, lädt den pf-Anker `com.apple/sandvault-config` per `pfctl -a` (die Standard-`pf.conf` wertet `com.apple/*` aus, wir fassen `pf.conf` also nicht an) und kann ihn wieder entfernen. Weitere Aufgaben: `pfctl -E/-X` mit Token, der Not-Aus, die Integritäts-Hashes und ein LaunchDaemon, der pf nach dem Booten aus dem root-eigenen Zustand in `/Library/Application Support/me.admon.apps.sandvault-config/` wiederherstellt.

**Sicherheitsmodell:** Die Sandbox gilt als Gegner.
- Konfiguration, CA-Schlüssel und Steuer-Socket liegen im Host-Home, das die Sandbox laut sv-Profil nicht lesen darf.
- Der Helper leitet alle Pfade aus `SUDO_USER` ab und escaped bzw. verwirft Sonderzeichen in SBPL-Strings.
- Git-Aufrufe auf Repos, in die die Sandbox schreiben kann, laufen immer gehärtet, nach dem Muster von `sv-clone` `git_repo()` mit `-c core.fsmonitor= -c core.sshCommand= -c core.hooksPath=/dev/null -c core.pager=cat -c protocol.ext.allow=never`.
- Proxy-Umgebungsvariablen und CA-Variablen in `$SHARED_WORKSPACE/user/.zshenv` sind nur eine Hilfe für kooperative Programme. Durchgesetzt wird über pf.

**pf-Anker (Modi: open · proxy-only · blocked):**
- Per `route-to (lo0 127.0.0.1) … user sandvault-$USER` und `rdr` auf `lo0` landen die Ports 80, 443 und 53 auf den Listenern von netd. Das Verfahren ist für macOS dokumentiert (mitmproxy transparent mode, dort mit `user { != nobody }`).
- Freigaben für die Proxy-Ports und für eigene Ausnahmen (CIDR/Port).
- LAN- und localhost-Sperre. Ausgenommen sind die Ports, auf denen die eigenen Listener der Sandbox und die Host-Helfer von sv (Chrome CDP, iOS-Bridge) lauschen; netd erkennt diese Ports laufend und lädt den Anker neu.
- Abschluss mit `block return out quick log … user sandvault-$USER` für IPv4 und IPv6.

**Repo-Layout**
```
Package.swift                 # alle Targets, im Vertrag festgelegt
Sources/SandvaultCore/        # Vertrag: Umgebung/Pfade, CommandRunner, Config, Modelle, Protokolle, ManagedBlock, GitSafe
Sources/SandvaultObserve/     # Agent A
Sources/SandvaultEnforce/     # Agent B
Sources/SandvaultNet/         # Agent C
Sources/SandvaultWorkflow/    # Agent D (Phase 2)
Sources/svctl/                # CLI, Unterordner je Agent, Registrierung in Commands.swift (merge=union)
Sources/sandvault-netd/  Sources/svctl-helper/
Tests/<Modul>Tests/Fixtures/  # echte macOS-Ausgaben als Fixtures
App/project.yml  App/SandvaultConfig/   # Agent E (Phase 2)
docs/PLAN.md  docs/DECISIONS.md  docs/ARCHITECTURE.md (§1–3 Lead, §4 A, §5 B, §6 C, §7 D, §8 E)
.github/workflows/ci.yml      # Linux: swift build/test · macOS: swift build/test + xcodegen + xcodebuild
```

## Phasen und Orchestrierung (Skill opus-orchester)

### Phase 0: Lead
1. `main` anlegen: Initial-Commit mit README-Gerüst und `.gitignore` (u. a. `.build/`, `*.xcodeproj`, `.claude/worktrees`), dann `git push -u origin main`. Danach `claude/funny-keller-go1r1i` von `main` abzweigen.
2. Swift-Toolchain für Linux installieren (swift.org, aktuelles 6.x für Ubuntu 24.04). Prüfen, ob GitHub Actions für das Repo laufen.
3. **Vertrags-Commit** „Contract: core models, runner, protocols, package layout“:
   - `Package.swift` mit allen Targets und Abhängigkeiten (swift-argument-parser, swift-nio, swift-nio-ssl, swift-certificates, swift-crypto).
   - `SandvaultEnvironment`: alle sv-Konstanten aus `sv` Z. 129–209 (User, Gruppe, Workspace, `_sandvault`, Profilpfad, sudoers, Install-Marker, `~/.local/state/sandvault`, `authorized_keys.d`).
   - `CommandRunner` plus `FakeCommandRunner` und `runAsSandvault()`, gebaut als `sudo -n -u sandvault-$USER /usr/bin/env …`. Das ist erlaubt, weil sv in seinen sudoers `/usr/bin/env` als Sandbox-User freigibt.
   - `AppConfig` (Codable, atomar, 0600) mit den Regeltypen `FileRule`, `MachRule`, `ExecRule`, `SandboxPreset` und `NetworkPolicy` (Mode, `DomainRule` allow/deny/ask + inspect, `DnsOverride`, `PortException`, LAN- und localhost-Policy, Ports).
   - Snapshot-Modelle (`SandboxProcess`, `SandboxConnection`, `SandboxViolation`, `ConnectionRecord`), das Modell `Check` für status/doctor, `ControlMessage` (Socket-Protokoll), `HelperCommand` + `AppliedState`, `ManagedBlock` (Marker extrahieren und ersetzen) und `GitSafe`.
   - Leere Modul-Stubs, `Commands.swift`, die CI und die Doku-Gerüste.
   - Gate: `swift build; echo $?` und `swift test; echo $?`. Committen und pushen.

### Phase 1: drei Agenten parallel (Opus, Worktree, Hintergrund)
- **A · Observe** (`SandvaultObserve`, `svctl status|doctor|ps|kill|throttle|net|violations`):
  - status/doctor prüft User, Gruppe und UID per dscl, Workspace-Rechte und ACLs, sudoers, Profil und Drift, Remote Login, `sv --version`, umask und die Rechte unter Homebrew. Jeder Check bekommt einen Hinweis zur Behebung.
  - Der Prozessbaum kommt aus `ps eww` als Sandbox-User; daraus stammt auch `SV_SESSION_ID` für die Session-Zuordnung. Host-Helfer (Chrome, iOS-Bridge) werden mit angezeigt.
  - Beenden mit `kill` als Sandbox-User; alles beenden über die vorhandenen sv-sudoers-Befehle (`launchctl bootout`, `pkill -9 -u`). Drosseln per `renice` bzw. `taskpolicy`.
  - Verbindungen per `lsof -nP -i -F` als Sandbox-User, Datenmengen per `nettop -P -L 1 -x`.
  - Verstöße per `log stream/show --style ndjson` mit dem Prädikat `((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")`. Das Format `Sandbox: proc(pid) deny(1) op target` wird geparst, der Prozess über einen PID-Cache dem User zugeordnet. Daraus entstehen gruppierte Regelvorschläge vom Typ `FileRule` bzw. `MachRule`.
- **B · Enforce** (`SandvaultEnforce`, `svctl-helper`, `svctl rules|firewall|panic|helper`):
  - SBPL-Generator für den verwalteten Block inklusive Vorlage „Gehärtet“. Sie verbietet die Ausführung von u. a. `osascript`, `screencapture`, `tccutil`, `networksetup`, `dscl` und sperrt die Mach-Dienste von Pasteboard und LaunchServices. Die Vorlage ist opt-in und wird vorher per Testlauf geprüft.
  - Merge in das Profil mit Backup, Erkennung von Drift, Reset.
  - pf-Generator für alle Modi und die dynamischen localhost-Ports.
  - Helper: strikte Validierung; Installation und Deinstallation (Helper-Binary, sudoers mit `visudo -c`, LaunchDaemon); Integritäts-Hashes; Not-Aus (pf blocked und alle Prozesse beenden).
  - Für die Generatoren gibt es Golden-File-Tests und Tests gegen Injection.
- **C · Net** (`SandvaultNet`, `sandvault-netd`, `svctl proxy|dns|ca|netlog`):
  - Proxy (explizit und transparent über SNI/Host), DNS-Forwarder (Upstream aus `scutil --dns` bzw. `resolv.conf`; Sperre per NXDOMAIN, Override per synthetischem A-Record).
  - Policy-Engine. Bei Rückfrage wird die Verbindung bis zu 30 s gehalten; ohne Antwort gilt die Standardaktion (deny).
  - Verbindungsprotokoll und Socket-Server. Die Zuordnung zum Prozess läuft über den Quellport plus die Daten von Agent A aus dem Vertrag.
  - TLS-Inspektion: CA erzeugen, Leaf-Zertifikate pro Host, redigierte Header. Ein CA-Bundle (System-Roots plus eigene CA) liegt im Shared Workspace.
  - Verwalteter `.zshenv`-Block mit den Proxy- und CA-Variablen.
  - Smoke-Tests mit echtem `curl` gegen einen laufenden netd unter Linux.

### Phase 2: zwei Agenten parallel, Vertragsergänzung vorab
- **D · Workflow** (`SandvaultWorkflow`, `svctl handoff|repos|tools|migrate|keys`):
  - Übergabe: zuerst ein Bereitschafts-Check (Symlinks nach außen, `.venv` bzw. `pyvenv.cfg` mit Host-Python, `.envrc`, Submodule mit lokalen Pfaden, `.git` als Datei, nicht committete Änderungen). Nicht committete Änderungen können optional per `git diff --binary`/`apply` mitgenommen werden. Danach `sv-clone <pfad> -- <agent>`, Prompt-Datei unter `$SHARED_WORKSPACE/tmp/handoff-<repo>.md` und Start im wählbaren Terminal (Terminal, iTerm2, Ghostty).
  - Repo-Register mit ahead/behind und neuen Sandbox-Commits; `git fetch sandvault` per Klick; Deploy-Keys über `gh` anzeigen und widerrufen.
  - Befehle freigeben: auflösen und einordnen (System, Homebrew, Host-Home; Mach-O mit `otool -L`, Skript mit Shebang). Freigabe per `brew install` oder als Kopie nach `user/bin`; danach eine Kontrolle als Sandbox-User.
  - Migration von Claude-Settings, CLAUDE.md, Commands und Skills, git-Identität und zsh. Credentials, History und Projects werden ausgeschlossen, Token-Muster blockiert; vor dem Kopieren gibt es eine Vorschau. Editor für `authorized_keys.d` (private Schlüssel werden abgelehnt) und Block für `SANDVAULT_ARGS`.
- **E · App** (`App/`):
  - XcodeGen-Projekt mit drei Bestandteilen: der App (LSUIElement), `sandvault-netd` und `svctl-helper` als eingebettete Executables.
  - Alle Bildschirme aus der Architektur oben, das Rückfrage-Panel, Mitteilungen und Drag & Drop eines Repos auf das Menüleisten-Symbol bzw. das Fenster.
  - Einrichtungsablauf für den Helper (`osascript … with administrator privileges`). netd wird per `SMAppService.agent` registriert; falls das nicht geht, per `~/Library/LaunchAgents` und `launchctl bootstrap`.
  - E baut gegen den Vertrag und die gemergten Module A–C, die APIs von D sind als Stubs im Vertrag.

### Phase 3: Lead
Merges, die gesamte Prüfkette, eine Rauchprobe der Naht netd ↔ CLI ↔ Steuer-Socket unter Linux und `scripts/verify-on-mac.sh` (geführter Gerätetest mit Rückbau). Dazu Changelog, README (auch auf Deutsch), Version 0.1.0, Push und CI-Kontrolle. Einen PR gibt es nur auf Wunsch.

## Verifikation
- **Hier (Linux):**
  - `swift build` und `swift test` mit explizit geprüftem Exit-Code. Fixture-Tests für alle Parser (ps, lsof -F, nettop, log ndjson, dscl), Golden-File-Tests für SBPL und pf, Tests gegen Injection.
  - Echter Lauf von netd: `curl -x http://127.0.0.1:18080 https://…` für Allow, Deny und Ask (Antwort per `svctl`), Abfragen gegen den DNS-Port, `curl --cacert` mit Inspektion und einem Eintrag im Protokoll.
- **CI (macOS-Runner):** Paket bauen und testen, `xcodegen && xcodebuild build` für die App.
- **Auf Deinem Mac** (`scripts/verify-on-mac.sh`): zuerst nur lesend (status, ps, net, 10 s violations). Danach in Schritten: Helper installieren, Regeln mit Diff anwenden, in `sv shell` gezielt Verbotenes versuchen, Proxy-only mit Rückfrage, Not-Aus. Jeder Schritt lässt sich mit `svctl firewall off`, `svctl rules reset` und `svctl helper uninstall` zurücknehmen.

## Erst auf dem Mac zu bestätigen
1. Ob pf `user`, `route-to` und `rdr` pro User auf Deinem macOS greifen, ob der Unteranker `com.apple/…` ausgewertet wird und ob das Token von `pfctl -E` hält.
2. `log stream` braucht Admin-Rechte. Das Meldungsformat kann je nach macOS-Version abweichen, und kurzlebige Prozesse lassen sich schwer dem User zuordnen.
3. Ob `nettop` fremde Prozesse ohne Root sieht. Ob `taskpolicy` auf Prozesse des Sandbox-Users wirkt.
4. Ob die Vorlage „Gehärtet“ Agenten stört. Deshalb ist sie opt-in, mit Testlauf und Lernmodus.
5. Ob `SMAppService.agent` bei lokal signierter App funktioniert (es gibt einen Fallback).
6. TLS-Inspektion klappt nur bei Programmen, die die CA aus den Umgebungsvariablen übernehmen. Für alle anderen bleibt die Domain eben ohne Inspektion.
7. DNS über `mDNSResponder` lässt sich nicht pro User umlenken. Abgedeckt wird das über Proxy und SNI; nur direkte DNS-Pakete werden umgeleitet.
8. Die SwiftUI-Oberfläche wird hier nie ausgeführt, nur in der CI kompiliert.
