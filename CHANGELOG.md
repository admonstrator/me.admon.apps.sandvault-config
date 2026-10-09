# Changelog

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
