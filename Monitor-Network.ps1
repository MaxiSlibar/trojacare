<#
.SYNOPSIS
  Langzeit-Netzwerkbeobachtung, um Beaconing-Trojaner zu fangen.

.DESCRIPTION
  Pollt TCP-Verbindungen alle N Sekunden und schreibt jede NEUE
  Remote-Verbindung in ein Log. Trojaner, die nur alle paar Minuten
  kurz ihren C2-Server kontaktieren, erscheinen hier als wiederkehrende
  Verbindungen zur gleichen IP - auch wenn der Basis-Scan sie verpasst.

.PARAMETER DurationMinutes
  Wie lange laufen. 0 = endlos (Strg+C zum Beenden).

.PARAMETER IntervalSeconds
  Polling-Intervall. Niedriger fangt kuerzere Beacons, erzeugt aber
  mehr Last. 5s ist ein guter Default.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Monitor-Network.ps1 -DurationMinutes 60
#>

[CmdletBinding()]
param(
    [int]$DurationMinutes = 60,
    [int]$IntervalSeconds = 5,
    [string]$OutputRoot
)

$ErrorActionPreference = 'SilentlyContinue'

if ([string]::IsNullOrEmpty($OutputRoot)) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
                 elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
                 else { (Get-Location).Path }
    $OutputRoot = Join-Path $scriptDir 'reports'
}

$stamp   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$outDir  = Join-Path $OutputRoot "monitor_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$logFile = Join-Path $outDir 'connections.csv'
$sumFile = Join-Path $outDir 'SUMMARY.txt'

'Timestamp,PID,Process,Path,LocalPort,RemoteAddress,RemotePort,State' |
    Out-File $logFile -Encoding UTF8

$seen = @{}
$start = Get-Date
$end   = if ($DurationMinutes -gt 0) { $start.AddMinutes($DurationMinutes) } else { [datetime]::MaxValue }

Write-Host "Monitoring laeuft. Log: $logFile"
Write-Host "Ende: $(if ($DurationMinutes) { $end } else { 'Strg+C zum Beenden' })"
Write-Host ''

$tick = 0
while ((Get-Date) -lt $end) {
    $tick++
    $now = Get-Date
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        # privat / loopback ignorieren
        if ($c.RemoteAddress -match '^(127\.|10\.|192\.168\.|169\.254\.|::1|fe80:|0\.0\.0\.0)') { continue }
        if ($c.RemoteAddress -match '^172\.(1[6-9]|2\d|3[01])\.') { continue }

        $key = "$($c.OwningProcess)|$($c.RemoteAddress)|$($c.RemotePort)"
        if ($seen.ContainsKey($key)) {
            $seen[$key].Count++
            $seen[$key].Last = $now
            continue
        }

        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pname = if ($p) { $p.ProcessName } else { '<?>' }
        $ppath = if ($p) { $p.Path } else { $null }

        $seen[$key] = [pscustomobject]@{
            Process = $pname; Path = $ppath
            RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort
            First = $now; Last = $now; Count = 1
            PID = $c.OwningProcess
        }

        "{0},{1},{2},{3},{4},{5},{6},{7}" -f `
            $now.ToString('s'), $c.OwningProcess, $pname, $ppath,
            $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State |
            Out-File $logFile -Append -Encoding UTF8

        Write-Host ("[{0}] NEU: {1} (PID {2}) -> {3}:{4}" -f `
            $now.ToString('HH:mm:ss'), $pname, $c.OwningProcess, $c.RemoteAddress, $c.RemotePort)
    }

    # alle 60 Ticks Zwischenstand
    if ($tick % 60 -eq 0) {
        Write-Host ("  ... {0} eindeutige Verbindungen bisher" -f $seen.Count) -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds $IntervalSeconds
}

# Zusammenfassung: wer hat wie oft rausgefunkt
$summary = @()
$summary += "=== TROJACARE NETWORK MONITOR ==="
$summary += "Start: $start"
$summary += "Ende:  $(Get-Date)"
$summary += "Eindeutige Verbindungen: $($seen.Count)"
$summary += ''
$summary += 'Top-Ziele nach Auftrittshaeufigkeit (Beaconing-Verdacht oben):'

$top = $seen.Values | Sort-Object Count -Descending |
    Select-Object Count,Process,PID,RemoteAddress,RemotePort,First,Last,Path
$summary += ($top | Format-Table -AutoSize -Wrap | Out-String)

# pro Prozess aggregiert
$summary += 'Pro Prozess:'
$byProc = $seen.Values | Group-Object Process |
    Select-Object @{n='Process';e={$_.Name}},
                  @{n='UniqueTargets';e={$_.Count}},
                  @{n='TotalHits';e={($_.Group | Measure-Object Count -Sum).Sum}} |
    Sort-Object TotalHits -Descending
$summary += ($byProc | Format-Table -AutoSize | Out-String)

$summary -join "`r`n" | Out-File $sumFile -Encoding UTF8
Write-Host ''
Write-Host "FERTIG. -> $sumFile" -ForegroundColor Green
