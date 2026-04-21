<#
.SYNOPSIS
  Trojacare - Windows Trojaner/Forensik-Scanner-Suite
  Einheitlicher Launcher mit Menue.

.DESCRIPTION
  Startet einen von mehreren Scans gegen den laufenden Windows-PC.
  Alle Scans sind read-only. Ergebnisse werden in .\reports\ abgelegt.

.NOTES
  Als Administrator ausfuehren fuer vollstaendige Ergebnisse.

    powershell -ExecutionPolicy Bypass -File .\trojacare.ps1

  Hinweis: Windows Defender kann die Scripts blockieren (AMSI erkennt
  Schluesselwoerter wie "Mimikatz"). In dem Fall Ordner ausnehmen:

    Add-MpPreference -ExclusionPath (Get-Location).Path

  Nach dem Scan wieder entfernen:

    Remove-MpPreference -ExclusionPath (Get-Location).Path
#>

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$banner = @"

   ______            _
  /_  __/___  ____ _(_)___ ________ ________
   / / / __ \/ __ ``/ / __ ``/ ___/ _ ``/ ___/ _ \
  / / / /_/ / /_/ / / /_/ / /__/  __/ /  /  __/
 /_/  \____/\__, /_/\__,_/\___/\___/_/   \___/
           /____/   Windows-Forensik-Scanner

"@

Clear-Host
Write-Host $banner -ForegroundColor Cyan
if (-not $isAdmin) {
    Write-Host ' [!] Nicht als Admin gestartet - viele Checks bleiben leer.' -ForegroundColor Yellow
    Write-Host '     Rechtsklick auf PowerShell > Als Administrator ausfuehren' -ForegroundColor Yellow
    Write-Host ''
}

$menu = @(
    @{ Key='1'; File='Scan-Connections.ps1';  Name='Netzwerk-Scan';     Info='TCP/UDP, lauschende Ports, Autostart, Services, DNS-Cache' }
    @{ Key='2'; File='Scan-Stealth.ps1';      Name='Stealth-Scan';      Info='Rootkit-Indikatoren, Sideloading, WMI-Persistenz, Namens-Imitation' }
    @{ Key='3'; File='Scan-Forensics.ps1';    Name='Forensics';         Info='PC-An/Aus, Logons, USB-Historie, Prefetch, Recent Files' }
    @{ Key='4'; File='Scan-Deep.ps1';         Name='Deep-Scan';         Info='AppInit_DLLs, IFEO, LSA, Winsock LSP, Root-CAs, BITS-Jobs' }
    @{ Key='5'; File='Scan-Window.ps1';       Name='Zeitfenster-Scan';  Info='Alles in einem engen Zeitfenster (wenn du einen Vorfall hast)' }
    @{ Key='6'; File='Monitor-Network.ps1';   Name='Netzwerk-Monitor';  Info='Loggt neue Verbindungen ueber Stunden (Beacon-Fang)' }
    @{ Key='A'; File=$null;                   Name='ALLE scannen';      Info='Laeuft 1-4 nacheinander' }
    @{ Key='Q'; File=$null;                   Name='Beenden';           Info='' }
)

Write-Host '  Verfuegbare Scans:' -ForegroundColor White
Write-Host ''
foreach ($m in $menu) {
    $color = if ($m.Key -eq 'Q') { 'DarkGray' } else { 'White' }
    Write-Host ('  [{0}] {1,-22} {2}' -f $m.Key, $m.Name, $m.Info) -ForegroundColor $color
}
Write-Host ''
$choice = (Read-Host '  Auswahl').ToUpper().Trim()

function Invoke-Scan([string]$file) {
    $path = Join-Path $scriptDir $file
    if (-not (Test-Path $path)) {
        Write-Host "  FEHLT: $file" -ForegroundColor Red
        return
    }
    Write-Host ''
    Write-Host "  >>> $file" -ForegroundColor Cyan
    Write-Host ''
    if ($file -eq 'Scan-Window.ps1') {
        $s = Read-Host '  Startzeit (YYYY-MM-DD HH:MM)'
        $e = Read-Host '  Endzeit   (YYYY-MM-DD HH:MM)'
        & $path -Start ([datetime]$s) -End ([datetime]$e)
    }
    elseif ($file -eq 'Monitor-Network.ps1') {
        $mins = Read-Host '  Dauer in Minuten (Standard 60)'
        if ([string]::IsNullOrWhiteSpace($mins)) { $mins = 60 }
        & $path -DurationMinutes ([int]$mins)
    }
    else {
        & $path
    }
}

switch ($choice) {
    'Q' { return }
    'A' {
        foreach ($k in '1','2','3','4') {
            $m = $menu | Where-Object Key -eq $k
            Invoke-Scan $m.File
        }
    }
    default {
        $m = $menu | Where-Object Key -eq $choice
        if (-not $m -or -not $m.File) {
            Write-Host "  Ungueltige Auswahl: $choice" -ForegroundColor Red
            return
        }
        Invoke-Scan $m.File
    }
}

Write-Host ''
Write-Host '  Fertig. Ergebnisse in: ' -NoNewline
Write-Host (Join-Path $scriptDir 'reports') -ForegroundColor Green
