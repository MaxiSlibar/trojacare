# Trojacare EXE bauen

So baust du aus der PowerShell-GUI eine eigenständige `Trojacare.exe`
zum Verteilen.

## Einmalig: ps2exe installieren

```powershell
Install-Module -Name ps2exe -Scope CurrentUser -Force
```

## Build

```powershell
cd D:\WORKSPACE\trojacare
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Erstellt `Trojacare.exe` im gleichen Ordner (~150 KB).

## Verteilen

Die `.exe` **allein** reicht nicht — sie braucht die Scan-Scripts im
selben Ordner. Pack alles zusammen in eine ZIP:

```
trojacare.zip
├── Trojacare.exe           # Doppelklick zum Starten
├── Scan-Connections.ps1
├── Scan-Stealth.ps1
├── Scan-Forensics.ps1
├── Scan-Deep.ps1
├── Scan-Window.ps1
├── Monitor-Network.ps1
├── README.md
└── LICENSE
```

Wer die ZIP kriegt:
1. Entpacken
2. Doppelklick auf `Trojacare.exe`
3. UAC mit **Ja** bestätigen
4. GUI öffnet sich — Knopf drücken, Scan läuft, Report landet in
   `reports\<zeitstempel>\`

## Hinweise

- **Windows-Defender / SmartScreen** blockiert unsignierte EXEs beim
  ersten Start. Der User muss "Weitere Informationen" → "Trotzdem
  ausführen" klicken. Das ist normal.
- Die EXE ist **nicht** signiert (keine Code-Signing-Zertifikate).
  Für echte Distribution bräuchtest du ein Code-Signing-Zertifikat
  (~200 €/Jahr).
- AMSI / Defender könnte die Scan-Scripts trotzdem blockieren. Die EXE
  setzt automatisch eine Exclusion während des Laufs.

## Alternative: Ohne Build

Wer sich traut, kann auch direkt die PowerShell-GUI starten:

```powershell
powershell -ExecutionPolicy Bypass -File .\trojacare-gui.ps1
```

Dann wird keine EXE gebraucht. Für Nicht-Techniker ist die EXE aber
komfortabler (Doppelklick, UAC, fertig).
