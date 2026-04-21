<#
.SYNOPSIS
  Laser-Scan auf ein enges Zeitfenster - was ist zwischen Boot und Shutdown passiert?

.PARAMETER Start
  Startzeit (inklusive), z.B. '2026-04-21 11:09:00'

.PARAMETER End
  Endzeit (inklusive), z.B. '2026-04-21 11:14:00'

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Scan-Window.ps1 -Start '2026-04-21 11:09:00' -End '2026-04-21 11:14:00'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetime]$Start,
    [Parameter(Mandatory)][datetime]$End,
    [string]$OutputRoot
)

$ErrorActionPreference = 'SilentlyContinue'

if ([string]::IsNullOrEmpty($OutputRoot)) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputRoot = Join-Path $scriptDir 'reports'
}
$stamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$outDir = Join-Path $OutputRoot "window_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "Zeitfenster: $Start bis $End"
Write-Host "Report: $outDir"
Write-Host ''

# ---------- 1. ALLE Logon-Events ----------
Write-Host '[1] Logon/Logoff/Lock/Unlock/Credentials...'
$logonIds = 4624,4625,4634,4647,4648,4672,4776,4778,4779,4800,4801,4802,4803
$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$logonIds; StartTime=$Start; EndTime=$End} |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
        [pscustomobject]@{
            Time        = $_.TimeCreated
            Id          = $_.Id
            Meaning     = switch($_.Id){
                4624{'LOGON ERFOLGREICH'};4625{'LOGON FEHLGESCHLAGEN'};4634{'Logoff'};4647{'User-Logoff'}
                4648{'Logon mit expl. Creds'};4672{'Admin-Rechte zugewiesen'};4776{'Credential-Validation'}
                4778{'RDP-Reconnect'};4779{'RDP-Disconnect'};4800{'LOCK'};4801{'UNLOCK'}
                4802{'Screensaver an'};4803{'Screensaver aus'}
            }
            User        = $d['TargetUserName']
            Domain      = $d['TargetDomainName']
            LogonType   = $d['LogonType']  # 2=console, 3=network, 10=RDP
            IpAddress   = $d['IpAddress']
            WorkStation = $d['WorkstationName']
            ProcessName = $d['ProcessName']
            LogonProcess= $d['LogonProcessName']
        }
    } | Sort-Object Time
$logons | Export-Csv (Join-Path $outDir '01_logons.csv') -NoTypeInformation -Encoding UTF8
$logons | Format-Table -AutoSize | Out-File (Join-Path $outDir '01_logons.txt') -Width 500

# ---------- 2. Was hat im Fenster wirklich gelaufen? (BAM) ----------
Write-Host '[2] BAM - was lief im Fenster...'
$bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
if (-not (Test-Path $bamPath)) { $bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
$bamHits = @()
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object {
        $userSID = $_.PSChildName
        $props = Get-ItemProperty $_.PSPath
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^Sequence|^Version' } | ForEach-Object {
            $val = $_.Value
            if ($val -is [byte[]] -and $val.Length -ge 8) {
                try {
                    $ft = [bitconverter]::ToInt64($val, 0)
                    if ($ft -gt 0) {
                        $t = [datetime]::FromFileTime($ft)
                        if ($t -ge $Start -and $t -le $End) {
                            $bamHits += [pscustomobject]@{
                                UserSID = $userSID; Program = $_.Name; Time = $t
                            }
                        }
                    }
                } catch {}
            }
        }
    }
}
$bamHits | Sort-Object Time | Export-Csv (Join-Path $outDir '02_bam_window.csv') -NoTypeInformation -Encoding UTF8

# ---------- 3. Prefetch im Fenster ----------
Write-Host '[3] Prefetch-Dateien im Fenster...'
$pf = "$env:SystemRoot\Prefetch"
$pfHits = Get-ChildItem $pf -Filter '*.pf' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $Start -and $_.LastWriteTime -le $End } |
    Sort-Object LastWriteTime |
    Select-Object Name,CreationTime,LastWriteTime,
        @{n='LikelyExe';e={ ($_.Name -split '\.pf$')[0] -replace '-[A-F0-9]{8}$','' }}
$pfHits | Export-Csv (Join-Path $outDir '03_prefetch_window.csv') -NoTypeInformation -Encoding UTF8

# ---------- 4. USB-Plugs im Fenster ----------
Write-Host '[4] USB/Datentraeger im Fenster...'
$diskPlugs = Get-WinEvent -LogName 'Microsoft-Windows-Partition/Diagnostic' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $Start -and $_.TimeCreated -le $End -and $_.Id -eq 1006 } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $d = @{}; foreach ($x in $xml.Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
        [pscustomobject]@{
            Time = $_.TimeCreated; Manufacturer = $d['Manufacturer']; Model = $d['Model']
            SerialNumber = $d['SerialNumber']; BusType = $d['BusType']; DiskSize = $d['DiskSize']
        }
    }
$diskPlugs | Export-Csv (Join-Path $outDir '04_disks_window.csv') -NoTypeInformation -Encoding UTF8

$pnp = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $Start -and $_.TimeCreated -le $End } |
    Select-Object TimeCreated,Id,Message
$pnp | Export-Csv (Join-Path $outDir '05_pnp_window.csv') -NoTypeInformation -Encoding UTF8

# ---------- 5. Datei-System: was wurde im Fenster geschrieben? ----------
Write-Host '[5] Geaenderte Dateien im Fenster (User-Ordner)...'
$hotSpots = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Pictures",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:PUBLIC",
    "$env:ProgramData"
)
$fileChanges = @()
foreach ($h in $hotSpots) {
    if (-not (Test-Path $h)) { continue }
    Get-ChildItem $h -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Start -and $_.LastWriteTime -le $End } |
        Select-Object -First 500 |
        ForEach-Object {
            $fileChanges += [pscustomobject]@{
                Path = $_.FullName; LastWrite = $_.LastWriteTime
                Created = $_.CreationTime; Size = $_.Length
            }
        }
}
$fileChanges | Sort-Object LastWrite | Export-Csv (Join-Path $outDir '06_files_modified.csv') -NoTypeInformation -Encoding UTF8

# ---------- 6. Recent-Ordner-Eintraege im Fenster ----------
Write-Host '[6] Zuletzt geoeffnete Dateien...'
$recent = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $Start -and $_.LastWriteTime -le $End } |
    Select-Object Name,CreationTime,LastWriteTime
$recent | Export-Csv (Join-Path $outDir '07_recent_window.csv') -NoTypeInformation -Encoding UTF8

# ---------- 7. Netzwerk-Aktivitaet (Eventlogs) ----------
Write-Host '[7] Netzwerk-Events...'
$netEvents = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-NetworkProfile/Operational';
    StartTime=$Start; EndTime=$End
} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message
$netEvents | Export-Csv (Join-Path $outDir '08_network_events.csv') -NoTypeInformation -Encoding UTF8

# WLAN verbindet/trennt
$wlan = Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $Start -and $_.TimeCreated -le $End } |
    Select-Object TimeCreated,Id,Message
$wlan | Export-Csv (Join-Path $outDir '09_wlan_events.csv') -NoTypeInformation -Encoding UTF8

# ---------- 8. Installierte Software im Fenster ----------
Write-Host '[8] Software-Installs im Fenster...'
$msi = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message
$msi | Export-Csv (Join-Path $outDir '10_msi_events.csv') -NoTypeInformation -Encoding UTF8

# ---------- 9. Alle Eventlog-Eintraege im Fenster (komprimiert) ----------
Write-Host '[9] Kompletter Eventlog-Dump im Fenster...'
$allEvents = @()
foreach ($log in 'System','Security','Application','Setup') {
    $allEvents += Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$Start; EndTime=$End} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated,LogName,Id,LevelDisplayName,ProviderName,
            @{n='Msg';e={($_.Message -split "`n")[0]}}
}
$allEvents | Sort-Object TimeCreated | Export-Csv (Join-Path $outDir '11_all_events.csv') -NoTypeInformation -Encoding UTF8

# ---------- Zusammenfassung ----------
$summary = @()
$summary += "=== ZEITFENSTER-ANALYSE ==="
$summary += "Fenster: $Start bis $End"
$summary += "Dauer:   $([math]::Round(($End - $Start).TotalMinutes,1)) Min"
$summary += ''
$summary += "--- LOGONS ($($logons.Count)) ---"
$summary += ($logons | Select Time,Meaning,User,LogonType,IpAddress,LogonProcess | Format-Table -AutoSize | Out-String)
$summary += "--- PROGRAMME GELAUFEN (BAM, $($bamHits.Count)) ---"
$summary += ($bamHits | Format-Table -AutoSize -Wrap | Out-String)
$summary += "--- PREFETCH ($($pfHits.Count)) ---"
$summary += ($pfHits | Select LastWriteTime,LikelyExe | Format-Table -AutoSize | Out-String)
$summary += "--- USB/PLATTEN ($($diskPlugs.Count)) ---"
$summary += ($diskPlugs | Format-Table -AutoSize -Wrap | Out-String)
$summary += "--- GEAENDERTE DATEIEN ($($fileChanges.Count)) ---"
$summary += ($fileChanges | Select LastWrite,Size,Path | Format-Table -AutoSize -Wrap | Out-String)
$summary += "--- ZULETZT GEOEFFNET ($($recent.Count)) ---"
$summary += ($recent | Format-Table -AutoSize | Out-String)

$summary -join "`r`n" | Out-File (Join-Path $outDir 'SUMMARY.txt') -Encoding UTF8

Write-Host ''
Write-Host "FERTIG -> $outDir" -ForegroundColor Green
Write-Host "Lies: $(Join-Path $outDir 'SUMMARY.txt')"
