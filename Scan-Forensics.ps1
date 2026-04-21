<#
.SYNOPSIS
  Rekonstruiert Nutzungshistorie: PC-An/Aus-Zeiten, angeschlossene USB-/Wechselmedien,
  Datentraeger-Zugriffe, zuletzt geoeffnete Dateien.

.DESCRIPTION
  Quellen:
   - System-Eventlog (Boot/Shutdown/Sleep/Wake)
   - Security-Eventlog (Logon/Logoff, falls aktiviert)
   - Microsoft-Windows-Partition/Diagnostic (Details zu jedem angeschlossenen Datentraeger)
   - Microsoft-Windows-Kernel-PnP (Geraete-Plug-Events)
   - Microsoft-Windows-DriverFrameworks-UserMode (USB-Plug mit Zeitstempel)
   - Microsoft-Windows-Storage-ClassPnP (physische Datentraeger)
   - Registry USBSTOR, USB, MountedDevices, MountPoints2 (welche Medien ueberhaupt je drinsteckten)
   - Prefetch (was wurde ausgefuehrt und wann)
   - Recent Files / JumpLists / Shellbags (was wurde geoeffnet)
   - SRUM-Existenzcheck (Ressourcennutzung pro App - braucht separate Tools zum Lesen)

.NOTES
  Admin erforderlich. Manche Logs sind groesse-limitiert und rollieren schnell.
#>

[CmdletBinding()]
param(
    [int]$Days = 30,
    [string]$OutputRoot
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

if ([string]::IsNullOrEmpty($OutputRoot)) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
                 elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
                 else { (Get-Location).Path }
    $OutputRoot = Join-Path $scriptDir 'reports'
}

$stamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$outDir = Join-Path $OutputRoot "forensics_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$since  = (Get-Date).AddDays(-$Days)

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Forensics-Report: $outDir"
Write-Host "Zeitfenster: seit $since ($Days Tage)"
if (-not $isAdmin) { Write-Warning 'Nicht als Admin - viele Logs bleiben leer.' }

# ---------- 1. PC An/Aus-Zeiten ----------
Write-Host '[1] Boot/Shutdown/Sleep-Events...'
# 6005 = Event Log Service gestartet (Boot)
# 6006 = Event Log Service beendet (sauberer Shutdown)
# 6008 = unsauberer Shutdown
# 1074 = Shutdown initiiert (mit User/Grund)
# 42   = System geht schlafen   (Kernel-Power)
# 107  = System wacht auf       (Kernel-Power)
# 12   = Betriebssystem gestartet (Kernel-General)
# 13   = Betriebssystem herunterfahren (Kernel-General)
$powerEvents = @()
$powerEvents += Get-WinEvent -FilterHashtable @{ LogName='System'; Id=6005,6006,6008,1074; StartTime=$since } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,ProviderName,
        @{n='Meaning';e={ switch($_.Id){6005{'Boot (EventLog gestartet)'};6006{'Shutdown (sauber)'};6008{'Shutdown (UNSAUBER)'};1074{'Shutdown ausgeloest'}} }},
        @{n='User';e={ $_.Properties[6].Value }},
        Message

$powerEvents += Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=42,107; StartTime=$since } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,ProviderName,
        @{n='Meaning';e={ if($_.Id -eq 42){'Sleep'}else{'Wake'} }},
        @{n='User';e={ $null }},
        Message

$powerEvents += Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-General'; Id=12,13; StartTime=$since } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,ProviderName,
        @{n='Meaning';e={ if($_.Id -eq 12){'OS gestartet'}else{'OS heruntergefahren'} }},
        @{n='User';e={ $null }},
        Message

$powerEvents | Sort-Object TimeCreated |
    Export-Csv (Join-Path $outDir '01_power_events.csv') -NoTypeInformation -Encoding UTF8

# ---------- 2. Logon/Logoff ----------
Write-Host '[2] Logon/Logoff-Events...'
# 4624 = Logon, 4634 = Logoff, 4647 = User-initiated Logoff
# 4800/4801 = Workstation locked/unlocked
$logons = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4634,4647,4800,4801; StartTime=$since } -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        [pscustomobject]@{
            Time       = $_.TimeCreated
            Id         = $_.Id
            Meaning    = switch($_.Id){4624{'Logon'};4634{'Logoff'};4647{'User-Logoff'};4800{'Lock'};4801{'Unlock'}}
            User       = $data['TargetUserName']
            Domain     = $data['TargetDomainName']
            LogonType  = $data['LogonType']
            IpAddress  = $data['IpAddress']
            WorkStation= $data['WorkstationName']
        }
    }
$logons | Export-Csv (Join-Path $outDir '02_logon_events.csv') -NoTypeInformation -Encoding UTF8

# ---------- 3. USB-/Wechselmedien (Event-basiert, praezise Zeiten) ----------
Write-Host '[3] USB/Wechselmedien-Events...'
# Microsoft-Windows-Partition/Diagnostic Event 1006 = Datentraeger eingesteckt (mit Seriennummer, Modell, Groesse)
$partitionEvents = Get-WinEvent -LogName 'Microsoft-Windows-Partition/Diagnostic' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $since -and $_.Id -eq 1006 } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        [pscustomobject]@{
            Time         = $_.TimeCreated
            Manufacturer = $data['Manufacturer']
            Model        = $data['Model']
            Revision     = $data['Revision']
            SerialNumber = $data['SerialNumber']
            ParentId     = $data['ParentId']
            DiskSize     = $data['DiskSize']
            Capabilities = $data['Capabilities']
            BusType      = $data['BusType']
            PartitionTable = $data['PartitionTableBytes']
        }
    }
$partitionEvents | Export-Csv (Join-Path $outDir '03_disk_attach_events.csv') -NoTypeInformation -Encoding UTF8

# Microsoft-Windows-Kernel-PnP Events (Device-Plug)
$pnpEvents = Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $since } |
    Select-Object TimeCreated,Id,LevelDisplayName,Message -First 500
$pnpEvents | Export-Csv (Join-Path $outDir '04_pnp_events.csv') -NoTypeInformation -Encoding UTF8

# DriverFrameworks-UserMode (USB plug/unplug, Event IDs 2003/2004/2100/2101/2102)
$usbEvents = Get-WinEvent -LogName 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $since -and $_.Id -in 2003,2004,2100,2101,2102,2105 } |
    Select-Object TimeCreated,Id,Message -First 1000
$usbEvents | Export-Csv (Join-Path $outDir '05_usb_driver_events.csv') -NoTypeInformation -Encoding UTF8

# ---------- 4. USB-Historie aus Registry (auch laengst entfernte Geraete) ----------
Write-Host '[4] USB-Registry-Historie...'
$usbHistory = @()

# USBSTOR = Massenspeicher
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object {
    $class = $_.PSChildName   # z.B. "Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
    Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
        $serial = $_.PSChildName
        $props  = Get-ItemProperty $_.PSPath
        $firstInst = $null; $lastInst = $null; $lastRemove = $null
        $propsKey = Join-Path $_.PSPath 'Properties\{83da6326-97a6-4088-9453-a1923f573b29}'
        if (Test-Path "$propsKey\0064") { $firstInst  = [datetime]::FromFileTimeUtc([bitconverter]::ToInt64((Get-ItemProperty "$propsKey\0064").'(default)',0)) }
        if (Test-Path "$propsKey\0066") { $lastInst   = [datetime]::FromFileTimeUtc([bitconverter]::ToInt64((Get-ItemProperty "$propsKey\0066").'(default)',0)) }
        if (Test-Path "$propsKey\0067") { $lastRemove = [datetime]::FromFileTimeUtc([bitconverter]::ToInt64((Get-ItemProperty "$propsKey\0067").'(default)',0)) }

        $usbHistory += [pscustomobject]@{
            Kind         = 'USBSTOR'
            Class        = $class
            Serial       = $serial
            FriendlyName = $props.FriendlyName
            FirstInstall = $firstInst
            LastArrival  = $lastInst
            LastRemoval  = $lastRemove
        }
    }
}

# USB = alle USB-Geraete (nicht nur Storage)
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -ErrorAction SilentlyContinue | ForEach-Object {
    $vidpid = $_.PSChildName
    Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath
        $usbHistory += [pscustomobject]@{
            Kind         = 'USB'
            Class        = $vidpid
            Serial       = $_.PSChildName
            FriendlyName = "$($props.DeviceDesc) | $($props.Mfg)"
            FirstInstall = $null; LastArrival = $null; LastRemoval = $null
        }
    }
}
$usbHistory | Export-Csv (Join-Path $outDir '06_usb_registry_history.csv') -NoTypeInformation -Encoding UTF8

# MountedDevices = welche Laufwerksbuchstaben/Volumes waren je gemountet
$mounted = Get-ItemProperty 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
if ($mounted) {
    $mounted.PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS' } |
        ForEach-Object {
            $bytes = $_.Value
            $str = if ($bytes -is [byte[]]) { [Text.Encoding]::Unicode.GetString($bytes) } else { "$bytes" }
            [pscustomobject]@{ MountPoint = $_.Name; Identifier = $str }
        } | Export-Csv (Join-Path $outDir '07_mounted_devices.csv') -NoTypeInformation -Encoding UTF8
}

# MountPoints2 pro User = welche Geraete der User je im Explorer gesehen hat
$userHives = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
$mp2 = @()
foreach ($h in $userHives) {
    $mp2Path = "$($h.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    if (Test-Path $mp2Path) {
        Get-ChildItem $mp2Path | ForEach-Object {
            $mp2 += [pscustomobject]@{ UserSID = $h.PSChildName; Volume = $_.PSChildName }
        }
    }
}
$mp2 | Export-Csv (Join-Path $outDir '08_mountpoints2.csv') -NoTypeInformation -Encoding UTF8

# ---------- 5. Prefetch (was wurde ausgefuehrt) ----------
Write-Host '[5] Prefetch...'
$pf = "$env:SystemRoot\Prefetch"
if (Test-Path $pf) {
    Get-ChildItem $pf -Filter '*.pf' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $since } |
        Sort-Object LastWriteTime -Descending |
        Select-Object Name,CreationTime,LastWriteTime,
            @{n='LikelyExe';e={ ($_.Name -split '\.pf$')[0] -replace '-[A-F0-9]{8}$','' }} |
        Export-Csv (Join-Path $outDir '09_prefetch.csv') -NoTypeInformation -Encoding UTF8
}

# ---------- 6. Recent Files (User) ----------
Write-Host '[6] Recent Files / JumpLists...'
$recent = @()
$recentPaths = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
    "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations",
    "$env:APPDATA\Microsoft\Office\Recent"
)
foreach ($rp in $recentPaths) {
    if (Test-Path $rp) {
        Get-ChildItem $rp -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $since } |
            ForEach-Object {
                $recent += [pscustomobject]@{
                    Source       = $rp
                    Name         = $_.Name
                    LastWrite    = $_.LastWriteTime
                    Created      = $_.CreationTime
                    Size         = $_.Length
                }
            }
    }
}
$recent | Sort-Object LastWrite -Descending |
    Export-Csv (Join-Path $outDir '10_recent_files.csv') -NoTypeInformation -Encoding UTF8

# RecentDocs-Registry pro User
$recentDocs = @()
foreach ($h in $userHives) {
    $rdPath = "$($h.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    if (Test-Path $rdPath) {
        Get-ChildItem $rdPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $recentDocs += [pscustomobject]@{ UserSID = $h.PSChildName; Extension = $_.PSChildName; Entries = ($_.ValueCount) }
        }
    }
}
$recentDocs | Export-Csv (Join-Path $outDir '11_recentdocs_summary.csv') -NoTypeInformation -Encoding UTF8

# UserAssist (welche Programme gestartet, Klick-Counter) - ROT13-encoded
$ua = @()
foreach ($h in $userHives) {
    $uaPath = "$($h.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    if (Test-Path $uaPath) {
        Get-ChildItem $uaPath | ForEach-Object {
            $count = Join-Path $_.PSPath 'Count'
            if (Test-Path $count) {
                $vals = Get-ItemProperty $count
                $vals.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object {
                        # ROT13 decode
                        $decoded = -join ($_.Name.ToCharArray() | ForEach-Object {
                            $c = [int]$_
                            if     ($c -ge 65 -and $c -le 90)  { [char](((($c-65)+13)%26)+65) }
                            elseif ($c -ge 97 -and $c -le 122) { [char](((($c-97)+13)%26)+97) }
                            else                               { [char]$c }
                        })
                        $ua += [pscustomobject]@{ UserSID = $h.PSChildName; Entry = $decoded }
                    }
            }
        }
    }
}
$ua | Export-Csv (Join-Path $outDir '12_userassist.csv') -NoTypeInformation -Encoding UTF8

# ---------- 7. SRUM-Check ----------
Write-Host '[7] SRUM-Datenbank (Ressourcennutzung)...'
$srum = "$env:SystemRoot\System32\sru\SRUDB.dat"
if (Test-Path $srum) {
    $info = Get-Item $srum
    "SRUM vorhanden: $($info.FullName)`nGroesse: $([math]::Round($info.Length/1MB,2)) MB`nLetzte Aenderung: $($info.LastWriteTime)`n`nZum Auslesen: Tool wie srum-dump oder KAPE nutzen. Enthaelt Netzwerknutzung und Laufzeit pro App der letzten ~30 Tage." |
        Out-File (Join-Path $outDir '13_srum_info.txt') -Encoding UTF8
}

# ---------- 8. Physische Datentraeger ----------
Write-Host '[8] Physische Datentraeger-Liste...'
Get-PhysicalDisk | Select-Object FriendlyName,SerialNumber,MediaType,BusType,Size,HealthStatus |
    Export-Csv (Join-Path $outDir '14_physical_disks.csv') -NoTypeInformation -Encoding UTF8

# ---------- Zusammenfassung ----------
Write-Host '[9] Zusammenfassung...'
$summary = @()
$summary += "=== TROJACARE FORENSICS ==="
$summary += "Erstellt: $(Get-Date)"
$summary += "Zeitfenster: seit $since ($Days Tage)"
$summary += "Admin: $isAdmin"
$summary += ''

$summary += "--- PC AN/AUS (letzte 20) ---"
$summary += ($powerEvents | Sort-Object TimeCreated -Descending | Select-Object -First 20 TimeCreated,Meaning,User |
    Format-Table -AutoSize | Out-String)

$summary += "--- LOGONS (letzte 20 interaktive) ---"
$summary += ($logons | Where-Object { $_.LogonType -in '2','10','11' } | Sort-Object Time -Descending | Select-Object -First 20 Time,Meaning,User,LogonType,IpAddress |
    Format-Table -AutoSize | Out-String)

$summary += "--- ANGESCHLOSSENE DATENTRAEGER (Event 1006) ---"
$summary += ($partitionEvents | Sort-Object Time -Descending | Select-Object Time,Manufacturer,Model,SerialNumber,DiskSize,BusType |
    Format-Table -AutoSize | Out-String)

$summary += "--- USB-GERAETE JE ANGESCHLOSSEN (Registry) ---"
$summary += ($usbHistory | Sort-Object LastArrival -Descending | Select-Object Kind,FriendlyName,Serial,FirstInstall,LastArrival,LastRemoval |
    Format-Table -AutoSize -Wrap | Out-String)

$summary += "--- ZULETZT AUSGEFUEHRTE PROGRAMME (Prefetch Top 30) ---"
if (Test-Path $pf) {
    $summary += (Get-ChildItem $pf -Filter '*.pf' | Sort-Object LastWriteTime -Descending | Select-Object -First 30 LastWriteTime,Name |
        Format-Table -AutoSize | Out-String)
}

$summary -join "`r`n" | Out-File (Join-Path $outDir 'SUMMARY.txt') -Encoding UTF8

Write-Host ''
Write-Host "FERTIG. -> $outDir" -ForegroundColor Green
Write-Host "Lies: $(Join-Path $outDir 'SUMMARY.txt')"
