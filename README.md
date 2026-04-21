# Trojacare

Windows-Forensik-Scanner-Suite — prüft deinen PC auf Malware, Rootkits,
versteckte Persistenz und forensische Spuren.

**Alles read-only. Keine Änderungen am System. Keine externen Abhängigkeiten.**

![Screenshot](https://github.com/MaxiSlibar/trojacare/raw/main/docs/screenshot.png)

## Download — Zwei Versionen

### 🎯 Trojacare.exe (Standalone) — empfohlen für Endnutzer

Ein einzelnes .exe. Doppelklick, UAC bestätigen, läuft. Keine anderen
Dateien nötig. Scan-Scripts sind in der EXE eingebettet.

→ [Download Trojacare.exe](https://github.com/MaxiSlibar/trojacare/releases/latest)

### ⚙️ Trojacare-Lite.exe + Scripts (Modular) — für Entwickler/Auditoren

EXE ist nur die GUI, die Scan-Scripts liegen daneben als `.ps1`. Du kannst
die Scripts selbst lesen, editieren, erweitern — ohne neu zu kompilieren.

→ [Download Trojacare-Lite.zip](https://github.com/MaxiSlibar/trojacare/releases/latest)

## Was wird geprüft

### 1. Netzwerk-Scan (2–15 Min)
Aktive TCP/UDP-Verbindungen mit Prozess + Pfad + Signatur, lauschende
Ports, Autostart-Einträge, automatisch startende Dienste, Firewall-Regeln,
DNS-Cache, Hosts-Datei.

### 2. Stealth-Scan (5–20 Min)
- **Prozesslisten-Diff** (WMI vs. Get-Process vs. tasklist) → Rootkits
- **Namens-Imitation** (svchost aus User-Pfad, Unicode-Tricks)
- **Parent-Anomalien** (Office → PowerShell, lsass-Parent ≠ wininit)
- **Fileless-Prozesse** (laufend ohne Image auf Disk)
- **DLL-Sideloading** (unsignierte DLLs in signierten Prozessen)
- **WMI Event-Subscriptions** (stiller Persistenzort)
- **Encoded PowerShell**, COM-Hijacking, Alternate Data Streams

### 3. Forensics (3–10 Min)
- **Boot/Shutdown/Sleep/Wake** aus System-Eventlog (30 Tage)
- **Logon/Logoff/Lock** mit User, LogonType, Source-IP
- **Datenträger-Plugs**: jeder je angesteckte Datenträger mit
  Hersteller, Modell, Seriennummer, Größe
- **USB-Registry-Historie** (auch entfernte Geräte)
- **Prefetch**: welche EXEs wann liefen
- **Recent Files, JumpLists, UserAssist** (ROT13-decoded)

### 4. Deep-Scan (5–20 Min)
- **BAM** (Background Activity Moderator) - was wirklich lief
- **AppInit_DLLs**, **IFEO Debugger**, **Winlogon Shell/Userinit**
- **LSA Security/Authentication Packages** (Credential-Theft-Risiko)
- **Winsock LSP** Provider
- **Root-CA-Whitelist-Check** → fremde CAs = MitM-Indikator
- **BITS-Jobs** (Hintergrund-Downloads)
- **PowerShell-History** aller User auf verdächtige Kommandos
- **Browser-Extensions** (Chrome/Edge/Opera/Brave)
- **Named Pipes**, **Print Monitors**, **Active Setup StubPath**

## GUI

Zwei Tabs:
- **Scans** — Buttons mit Dauer-Angabe + Live-Log
- **Berichte** — Report-Viewer direkt in der App:
  - Dropdown mit allen bisherigen Scans (Datum)
  - Zusammenfassung mit Severity-Farben (CRIT/HIGH/MED)
  - Funde als sortierbare Tabelle
  - Alle Dateien mit Inhalts-Vorschau

## Eigene Builds

### Voraussetzungen
- Windows 10/11
- PowerShell 5.1+
- Admin-Rechte

### Beide EXEs bauen

```powershell
git clone https://github.com/MaxiSlibar/trojacare.git
cd trojacare
powershell -ExecutionPolicy Bypass -File .\build-all.ps1
```

Das erzeugt `Trojacare.exe` (Standalone) **und** `Trojacare-Lite.exe`
(Modular). Erstmaliger Build installiert automatisch `ps2exe`-Modul.

### Einzeln

```powershell
.\build-standalone.ps1   # → Trojacare.exe (alle Scripts eingebettet)
.\build.ps1              # → Trojacare-Lite.exe (braucht Scripts daneben)
```

### Ohne Build starten
```powershell
powershell -ExecutionPolicy Bypass -File .\trojacare.ps1
```

## Was Trojacare NICHT kann

- **Kernel-Rootkits** die sich vor allen Windows-APIs verstecken
- **UEFI-Implants** (Mainboard-Flash)
- **Hypervisor-Rootkits** (Windows als Gast sieht Hypervisor nicht)
- **Staatstrojaner** mit gestohlenen gültigen Signaturen erscheinen als Valid

Für diese Klassen: Offline-Scan von sauberem USB-Medium (Kaspersky Rescue
Disk, ESET SysRescue, Tails mit `chipsec`).

## Severity-Level

- **CRIT** — fast sicher Malware (AppCertDll, IFEO auf System-EXEs)
- **HIGH** — starkes Warnsignal (Sideloading, unbekannte Root-CA)
- **MED** — auffällig, oft False Positive (COM-Hijack-Kandidat)
- **LOW** — zur Info (User-Pfad-EXE im BAM)

**Häufige False Positives:**
- Gaming-Software (Razer, Logitech, Oculus) legt lokale Root-CAs an
- Steam/Epic/Riot laufen aus User-Pfad
- Microsoft Defender erscheint als "Unknown Signature" (Prozess
  schützt sich selbst vor Lese-Zugriffen)

Immer konkrete Pfad + Signatur anschauen bevor Panik.

## Hinweise

### SmartScreen-Warnung
Die EXE ist nicht code-signiert. Windows warnt beim ersten Start:
**"Weitere Informationen" → "Trotzdem ausführen"**.

### Windows Defender / AMSI
Die Scripts erwähnen Schlüsselwörter wie `Mimikatz` (zur Erkennung in
PS-History). Die EXE setzt automatisch eine Defender-Exclusion für ihren
Arbeitsordner während des Laufs und entfernt sie beim Beenden.

### Reports
Landen in `trojacare-reports\` neben der EXE. Pro Scan ein Unterordner
mit Zeitstempel. CSV + TXT + SUMMARY.txt.

## Lizenz

MIT. Nutzung auf eigene Gefahr. Keine Haftung.

## Autor

**MaxiSlibar** — https://github.com/MaxiSlibar

## Contributing

PRs willkommen für:
- Weitere Persistenz-Vektoren
- Bessere Whitelists (weniger False Positives)
- Deutsch-Englisch-Übersetzung
- Parser für AmCache, SRUM, MFT

## Verwandte Tools

Wenn Trojacare nicht reicht:
- **Sysinternals** (Autoruns, Process Explorer, TCPView)
- **Eric Zimmerman Tools** (AmCacheParser, MFTECmd)
- **KAPE** (Live-Response-Sammelwerkzeug)
- **Volatility** (RAM-Analyse)
- **Loki / Thor** (IOC-Scanner)
