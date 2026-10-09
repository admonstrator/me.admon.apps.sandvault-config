# Changelog

## Unreleased

Abgeglichen mit echten Ausgaben von macOS 27.0.1 und sv 1.32.0 (`scripts/verify-on-mac.sh capture`).

### Neu
- **Einfaches Fenster:** Standardmäßig zeigt die App nur Übersicht, Aktivität, Repos & Hand-off und Einstellungen.
  Der Schalter „Expert mode“ in den Einstellungen blendet die übrigen Seiten wieder ein.
- **Schutzstufen:** Off, Watch, Ask und Block All auf der Übersicht und im Menü. Die Wahl gilt sofort, ohne
  Regelvorschau.
- **Firewall-Modus `watch`:** Alles bleibt erlaubt, aber Web und DNS laufen über netd. Damit erscheint jeder Host,
  mit dem die Sandbox spricht. netd weist nur ab, was eine Deny-Regel nennt. `svctl firewall mode watch`.
- **Sandbox-Seite:** Shell oder Agent (Claude, Codex und die übrigen) mit einem Klick in einer neuen Sandbox-Sitzung
  starten, wahlweise im Shared Workspace oder in einem Klon. Ohne Sandbox legt „Create Sandbox“ sie mit einem Preset
  an (Everyday, Careful, Offline, Unrestricted): Regeln und Schutzstufe werden gespeichert, `sv build` läuft im
  Terminal, danach werden Regeln und Firewall angewendet. „Rebuild“ und „Delete Sandbox…“ rufen `sv --rebuild build`
  und `sv uninstall` auf. Pro macOS-Benutzer gibt es weiterhin genau eine Sandbox, so wie sv sie anlegt.
- **Dock:** Die App hat ein Symbol und erscheint standardmäßig im Dock (abschaltbar in den Einstellungen). Das
  Dock-Menü und das Menüleisten-Fenster starten Shell und Standard-Agent direkt.
- **Aktivität:** eine Liste mit Hosts (Allow, Block), direkten Verbindungen ohne Hostnamen und laufenden
  ping/traceroute.

### Behoben
- Ghostty öffnete beim Start aus der App (Sitzung, Rebuild, Hand-off) nur die gespeicherten Fenster mit der
  normalen Shell, ohne sv. Die App startet Ghostty jetzt mit `--window-save-state=never`, damit das neue Fenster den
  Befehl ausführt, und mit `--quit-after-last-window-closed=true`, damit keine leeren Instanzen liegen bleiben.
- `ping` und `traceroute` fehlten überall. Sie laufen setuid als root, daher zeigte ps root als Benutzer. Prozesse
  zählen jetzt auch über den realen Benutzer zur Sandbox; die App markiert sie als `ping (root)`. `svctl net` und die
  Aktivitätsseite listen sie mit ihrem Ziel. Filtern kann pf ICMP nicht, das geht nur über eine Ausführungsregel.
- HTTPS direkt auf eine IP-Adresse über den transparenten Weg (Programme, die `HTTPS_PROXY` ignorieren) wurde in
  Watch, Ask und Proxy only abgewiesen. Ohne SNI wusste netd nicht, wohin die Verbindung sollte. netd nimmt jetzt die
  Zieladresse, die lsof für den Socket der Sandbox meldet, und entscheidet nach ihr wie bei jedem anderen Host.
- Erlaubte Verbindungen, die trotzdem scheiterten, standen im Log als „erlaubt“ da. netd hält jetzt den Grund fest:
  nicht auflösbar, keine Verbindung, oder die Gegenseite schließt, bevor sie ein Byte schickt. Letzteres verursacht
  auf dem Mac typischerweise ein Netzwerkfilter wie Little Snitch oder AdGuard, der netd nicht kennt. Die Aktivität
  zeigt solche Hosts als „Failed“ mit Grund, `svctl netlog` als `FAILED: ...`, und netd.log nennt sie ebenfalls.
- `svctl kill --all` beendet übrig gebliebene setuid-Programme jetzt als Sandbox-Benutzer; `pkill -u` erfasst sie nicht.
- `svctl status` und `svctl net` brachen ab, wenn die Sandbox keine offenen Sockets hatte: lsof endet dann mit
  Exit 1 und warnt als Sandbox-User zusätzlich über das DeviceFS von Xcode im Host-Home. lsof läuft jetzt mit `-w`,
  und reine Warnungen gelten nicht mehr als Fehler.
- `svctl doctor` meldete „netd ports“ als unbekannt, auch wenn die Firewall aus ist. Damit stand das Gesamturteil
  von `svctl status` auf „?“. Ohne Firewall wird die Prüfung jetzt übersprungen.
- `scripts/verify-on-mac.sh capture` redigiert Umgebungswerte mit Leerzeichen jetzt vollständig, behält
  `SV_SESSION_ID` und schreibt die Exit-Codes von lsof und `launchctl print` mit.
- Die Session-Zuordnung sucht den Agenten jetzt unter allen Wurzeln einer Session. macOS zeigt die Umgebung von
  Apple-Programmen wie `zsh -i` nicht an; ohne sichtbaren Launcher zerfiel eine Session sonst in mehrere Wurzeln, und
  als Befehl stand „Python“ statt „claude“.
- Der Lernmodus arbeitet nur noch live. macOS 27 speichert die Sandbox-Meldungen des Kernels nicht im Log, daher
  fand `log show` nie etwas.
  - `svctl violations` folgt dem Log bis Ctrl-C, mit `--for 2m` für eine feste Zeit samt Zusammenfassung.
  - `--suggest` braucht `--for`.
  - `--last` und `--follow` entfallen, ebenso „Read Last 10 Minutes“ in der App.
  - Der geführte Gerätetest scheiterte vorher an `--follow --suggest`, das die CLI ablehnte.

### Tests
- Fixtures für dscl, dseditgroup, `ls -led`, sudoers und das sv-Profil durch echte Ausgaben ersetzt; neue echte
  Fixtures für ps ohne Session, lsof ohne Sockets, nettop ohne Zeilen, das Unified Log und `launchctl print` ohne
  Dienst, dazu Prozesse, Umgebung, lsof und nettop einer laufenden Session.
- ps liest zusätzlich `ruser=`; in den echten ps-Fixtures wurde die Spalte nachträglich mit dem Benutzerwert ergänzt.
  421 Tests.

## 0.1.0 · 2026-10-09

Erste Ausbaustufe: Kernmodule, CLI, Netzwerkdienst, Root-Helper und die macOS-App. Alles ist unter Linux und auf
macOS in der CI gebaut und getestet (387 Tests). Auf einem echten Mac ausgeführt wurde noch nichts.

### Neu
- **Überblick:** `svctl status` und `doctor` mit 14 Prüfungen zu sandvault und weiteren für Helper, Firewall und netd.
  Prozesse mit Session-Zuordnung, Beenden und Drosseln, Sockets und Datenmenge pro Prozess.
- **Lernmodus:** Sandbox-Verstöße aus dem Unified Log, live oder rückblickend, mit Regelvorschlägen.
- **Sandbox-Regeln:** ein verwalteter Block im Profil von sv mit Datei-, Mach- und Ausführungsregeln. Dazu die
  Vorlage „Gehärtet“, Diff und Erkennung, wenn `sv --rebuild` den Block entfernt hat.
- **Firewall pro Sandbox-User** (pf-Anker `com.apple/sandvault-config`):
  - Modi `off`, `open`, `proxy-only` und `blocked`.
  - Schutz für LAN und localhost sowie Port-Ausnahmen.
  - Not-Aus mit Sperre: Er bleibt aktiv, bis er ausdrücklich gelöst wird.
- **sandvault-netd:**
  - expliziter und transparenter Proxy für HTTP und TLS (Ziel aus SNI),
  - Rückfrage bei unbekannten Domains und Domainregeln,
  - DNS-Forwarder mit Sperren und Overrides,
  - Schutz vor privaten Zielen,
  - optionale TLS-Inspektion mit eigener CA,
  - Verbindungsprotokoll und Steuer-Socket.
- **Workflow:**
  - Repo-Übergabe an einen Agenten über `sv-clone` mit vorherigem Bereitschafts-Check, Briefing und auf Wunsch
    nicht committeten Änderungen,
  - Rückweg (`git fetch sandvault`),
  - Befehle prüfen und freigeben,
  - Konfig-Migration mit Secret-Filter,
  - SSH-Keys für `authorized_keys.d` und Voreinstellungen für `SANDVAULT_ARGS`.
- **App:** Menüleiste mit Zustand und Schnellaktionen, Hauptfenster mit neun Seiten, Rückfrage-Panel und
  Mitteilungen, Einrichtung von Helper und netd. Die drei Programme sind ins Bundle eingebaut.
- `scripts/verify-on-mac.sh` für den Gerätetest, nur lesend oder geführt.

### Sicherheit
- Die sudoers-Regel des Helpers erlaubt nur exakt benannte Aufrufe. Mit einer freien Regel käme ein beliebiger
  Prozess zu Root ohne Passwort.
- Git läuft in Sandbox-Clones nur als Sandbox-User unter dem Profil von sv. Sonst könnten Filter, fsmonitor oder
  `gpg.program` aus dem Clone Code als Host-User ausführen.
- Schreiben in den Shared Workspace folgt nie einem Symlink, den die Sandbox gelegt hat.
- Code, den die Sandbox schreiben kann, läuft nur sandboxed. Ein Beispiel ist die Prüfung, ob ein Befehl verfügbar ist.

### Behoben
- **Proxy ohne Root-Rechte:** netd setzte auf jeder angenommenen Verbindung `SO_DEBUG` statt `TCP_NODELAY`.
  `ChannelOptions.socketOption(.tcp_nodelay)` landet auf der Ebene `SOL_SOCKET`, wo dieselbe Nummer `SO_DEBUG`
  bedeutet. Unter Linux ohne `CAP_NET_ADMIN` schloss das jede Proxy-Verbindung sofort; aufgefallen ist es im
  CI-Container. Jetzt `ChannelOptions.tcpOption(.tcp_nodelay)`.
- **Hänger in der CI:** Alle Integrationstests haben ein Zeitlimit von einer Minute, und jeder CI-Job hat ein
  eigenes Timeout. Ein Fehler wird damit rot, statt stundenlang zu warten.

### Bekannte Grenzen
- **Nicht auf echter Hardware geprüft:** pf (`user`, `route-to`, `rdr`), die Regeln der Vorlage „Gehärtet“,
  `log stream`, `nettop` für fremde Prozesse und die App zur Laufzeit. Das klärt `scripts/verify-on-mac.sh`.
- **Synthetische Fixtures:** Die meisten Fixtures für macOS-Ausgaben sind synthetisch, bis `capture` echte liefert.
- **DNS:** Was über `mDNSResponder` läuft, lässt sich nicht pro User umleiten; die Kontrolle läuft über Proxy und SNI.
  Split-DNS per VPN wird noch nicht berücksichtigt.
- **Nicht committete Änderungen:** Sie gehen als Patch-Datei mit, die der Agent zuerst anwendet.
  sv-clone 1.32 lehnt lokale Repos ohne `origin` ab.
- **Proxy:** Keine WebSocket-Upgrades, kein Backpressure bei Upload-Bodies, kein TLS-Alert bei einer Sperre auf
  dem transparenten Port.
- **Signierung:** Die App ist ad-hoc signiert. Ob Mitteilungs-Aktionen ohne Developer-ID ankommen, ist offen.
