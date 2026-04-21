# Trojacare

Windows-Forensik-Scanner-Suite zum Prüfen des eigenen PCs auf Malware,
Rootkits, versteckte Persistenz und forensische Spuren.

**Alles read-only, keine Änderungen am System. Keine Installation, keine
externen Abhängigkeiten — nur Windows-PowerShell.**

## Warum

Defender findet Alltags-Malware gut, aber:

- **Fileless / Living-off-the-Land** (PowerShell, WMI, Scheduled Tasks)
- **Persistenz** in AppInit_DLLs, IFEO, LSA-Packages, Winsock-LSP, COM-Hijacks
- **Process Hollowing** und Namens-Imitation (svchost aus AppData)
- **Man-in-the-Middle** via installierter Root-CAs
- **BAM-Historie, Prefetch, USB-Plug-Events** — forensische Spurensuche

Trojacare schaut gezielt dort nach, **ohne zu blocken oder zu verändern.**
Alle Scripts lassen sich selbst lesen und sind ca. 200–400 Zeilen.

## Schnellstart

PowerShell **als Administrator** öffnen:

```powershell
cd <Pfad zu trojacare>
powershell -ExecutionPolicy Bypass -File .\trojacare.ps1
```

Menü auswählen. Ergebnisse landen in `reports\<zeitstempel>\`.
Zuerst `SUMMARY.txt` lesen.

## Hinweis zu Windows Defender / AMSI

Die Scripts erwähnen Schlüsselwörter wie `Mimikatz`, `Invoke-Expression`,
`EncodedCommand` — zur **Erkennung** in PowerShell-History. Defender/AMSI
kann das als verdächtig markieren und blockieren.

Workaround (nur während des Scans):

```powershell
Add-MpPreference -ExclusionPath (Get-Location).Path
# ... Scan laufen lassen ...
Remove-MpPreference -ExclusionPath (Get-Location).Path
```

## Die sechs Scans

### `Scan-Connections.ps1` — Netzwerk-Grundlagen
TCP/UDP-Verbindungen mit Prozess + Pfad + Signatur, lauschende Ports,
Autostart-Einträge, automatisch startende Dienste, Firewall-Regeln,
DNS-Cache, Hosts-Datei. Basis-Inventur.

### `Scan-Stealth.ps1` — Tarnung und Persistenz
- **Prozesslisten-Diff** (WMI vs. Get-Process vs. tasklist) → Rootkits
- **Namens-Imitation** (svchost aus User-Pfad, Unicode-Tricks)
- **Parent-Anomalien** (Office → PowerShell, lsass-Parent ≠ wininit)
- **Fileless** (laufender Prozess ohne Image auf Disk)
- **DLL-Sideloading** (unsignierte DLLs in signierten Prozessen)
- **WMI Event-Subscriptions** (stiller Persistenzort)
- **Encoded PowerShell**, `rundll32` mit User-Pfad-DLLs
- **COM-Hijacking** (HKCU InprocServer32)
- **Alternate Data Streams** in Startup-Ordnern
- **Orphan-Verbindungen** (Netztraffic ohne zuordenbaren Prozess)

### `Scan-Forensics.ps1` — Nutzungs-Historie (30 Tage)
- **Boot/Shutdown/Sleep/Wake** aus System-Eventlog
- **Logon/Logoff/Lock** mit User, LogonType, Source-IP (Security-Log)
- **Datenträger-Plugs**: jeder je angesteckte Datenträger mit Hersteller,
  Modell, **Seriennummer**, Größe (Partition/Diagnostic Log)
- **USB-Historie** aus Registry (auch entfernte Geräte)
- **Prefetch**: welche EXEs wann liefen
- **Recent Files, JumpLists, RecentDocs, UserAssist** (ROT13-decoded)

### `Scan-Deep.ps1` — Tiefen-Persistenz
- **BAM** (Background Activity Moderator)
- **AppInit_DLLs**, **IFEO Debugger**, **Winlogon Shell/Userinit**
- **LSA Security/Authentication Packages** (Credential-Theft-Risiko)
- **Winsock LSP** Provider
- **Root-CA-Whitelist-Check** → fremde CAs = MitM-Indikator
- **BITS-Jobs** (Hintergrund-Downloads)
- **PowerShell-History** aller User auf verdächtige Kommandos
- **Browser-Extensions** (Chrome/Edge/Opera/Brave)
- **Named Pipes**, **Print Monitors**, **Active Setup StubPath**

### `Scan-Window.ps1` — Zeitfenster-Forensik
Für konkrete Vorfälle: enges Zeitfenster angeben, sieht alles darin:
Logons, gelaufene Programme, USB-Plugs, geänderte Dateien, Netzwerk-
Events. Beispiel: "Zwischen 11:09 und 11:14 war jemand am PC — was hat
er gemacht?"

```powershell
.\Scan-Window.ps1 -Start '2026-04-21 11:09:00' -End '2026-04-21 11:14:00'
```

### `Monitor-Network.ps1` — Beacon-Fang
Pollt TCP-Verbindungen über Stunden. Malware die alle 2-5 Min zu einem
C2-Server callt, landet oben in der Häufigkeitsliste.

```powershell
.\Monitor-Network.ps1 -DurationMinutes 60
```

## Was Trojacare NICHT kann

- **Kernel-Rootkits** die sich vor allen Windows-APIs verstecken
- **UEFI-Implants** (sitzen im Mainboard-Flash)
- **Hypervisor-Rootkits** (Windows als Gast sieht den Hypervisor nicht)
- **Staatstrojaner** mit gestohlenen gültigen Signaturzertifikaten erscheinen
  als `Valid` signiert
- **Live-RAM-Analyse** (braucht externe Tools wie Volatility)

Für diese Klassen: Offline-Scan von sauberem USB-Medium
(Kaspersky Rescue Disk, ESET SysRescue, Tails mit `chipsec`).

## Wie interpretieren

Jedes Finding hat eine Severity:

- **CRIT** — fast sicher Malware. AppCertDll, IFEO-Hijack auf System-EXEs,
  Winlogon-Shell manipuliert, Encoded-PowerShell in BAM.
- **HIGH** — starkes Warnsignal. Sideloading, unbekannte Root-CA,
  Fileless-Prozess, WMI-Subscription.
- **MED** — auffällig, oft False Positive. COM-Hijack-Kandidat,
  LOLBin-Scheduled-Task, nicht-MS-Task mit rundll32.
- **LOW** — zur Info. User-Pfad-EXE im BAM, Script-Datei in AppData.

False Positives sind häufig bei harmlosen Tools:
- Gaming-Software (Razer, Logitech, Oculus) legt lokale Root-CAs an
- Steam/Epic/Riot laufen aus User-Pfad
- Office-Installer nutzen `rundll32`

Immer den konkreten Pfad + Signatur anschauen bevor Panik.

## Lizenz

MIT. Nutzung auf eigene Gefahr. Keine Haftung für Schäden.

## Contributing

PRs willkommen für:
- Weitere Persistenz-Vektoren
- Bessere Whitelists (weniger False Positives)
- Korrigierter/erweiterter Deutsch-Text / Englisch-Übersetzung
- Parser für AmCache, SRUM, MFT (Offline-Forensik)

## Verwandte Tools

Wenn Trojacare nicht reicht:

- **Sysinternals** (Autoruns, Process Explorer, Process Monitor, TCPView)
- **AmCacheParser** / **MFTECmd** (Eric Zimmerman Tools)
- **KAPE** (Live-Response-Sammelwerkzeug)
- **Volatility** (RAM-Analyse)
- **Loki** / **Thor** (IOC-Scanner)
