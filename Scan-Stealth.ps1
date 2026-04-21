<#
.SYNOPSIS
  Sucht nach Tarn-Techniken, die der Basis-Scan nicht sieht.

.DESCRIPTION
  Prueft gezielt Indikatoren fuer Prozess-Tarnung und versteckte Persistenz:
   - Prozesslisten-Diff (tasklist vs. WMI vs. Get-Process) -> Rootkit-Hinweis
   - Namens-Imitation (svchost/explorer/lsass aus falschen Pfaden, mit/ohne Parent)
   - Parent-Child-Anomalien (svchost von etwas anderem als services.exe)
   - Prozesse deren Image-Datei geloescht wurde (nur im Speicher)
   - Unsignierte DLLs in signierten Prozessen (Sideloading)
   - WMI Event-Subscriptions (beliebter Persistenz-Ort)
   - Verdaechtige Scheduled Task Trigger (Logon/Idle + PowerShell/rundll32)
   - Treiber ohne gueltige Signatur
   - Netzverbindungen ohne auffindbaren Prozess
   - PowerShell/Wscript mit encoded command in Command-Line
   - COM-Hijacking-Kandidaten (HKCU InprocServer32)
   - Alternate Data Streams in Startup-Ordnern
#>

[CmdletBinding()]
param([string]$OutputRoot)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

if ([string]::IsNullOrEmpty($OutputRoot)) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot }
                 elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
                 else { (Get-Location).Path }
    $OutputRoot = Join-Path $scriptDir 'reports'
}

$stamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$outDir = Join-Path $OutputRoot "stealth_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Stealth-Report: $outDir"
if (-not $isAdmin) { Write-Warning 'Nicht als Admin - viele Checks sind eingeschraenkt.' }

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Severity,$Category,$Detail,$Evidence) {
    $findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category; Detail = $Detail; Evidence = $Evidence
    })
}

# ---------- 1. Prozesslisten-Diff ----------
Write-Host '[1] Prozesslisten-Diff...'
$wmiProcs = Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,ParentProcessId,CommandLine
$psProcs  = Get-Process | Select-Object Id,ProcessName,Path
$tasklist = (tasklist /fo csv /nh 2>$null) | ConvertFrom-Csv -Header 'Name','PID','Session','SessionNum','Mem'

$wmiIds = $wmiProcs.ProcessId | Sort-Object -Unique
$psIds  = $psProcs.Id | Sort-Object -Unique
$tlIds  = ($tasklist.PID | ForEach-Object { [int]$_ }) | Sort-Object -Unique

$onlyInWmi = $wmiIds | Where-Object { $_ -notin $psIds }
$onlyInPs  = $psIds  | Where-Object { $_ -notin $wmiIds }
$onlyInTl  = $tlIds  | Where-Object { $_ -notin $wmiIds }

if ($onlyInWmi) { Add-Finding 'HIGH' 'Rootkit-Hinweis' 'PIDs in WMI aber nicht in Get-Process' ($onlyInWmi -join ',') }
if ($onlyInPs)  { Add-Finding 'HIGH' 'Rootkit-Hinweis' 'PIDs in Get-Process aber nicht in WMI' ($onlyInPs  -join ',') }
if ($onlyInTl)  { Add-Finding 'MED'  'Rootkit-Hinweis' 'PIDs in tasklist aber nicht in WMI'    ($onlyInTl  -join ',') }

$wmiProcs | Export-Csv (Join-Path $outDir 'processes_wmi.csv') -NoTypeInformation -Encoding UTF8

# ---------- 2. Namens-Imitation ----------
Write-Host '[2] Namens-Imitation...'
$systemNames = @{
    'svchost.exe'  = 'C:\Windows\System32\svchost.exe'
    'lsass.exe'    = 'C:\Windows\System32\lsass.exe'
    'csrss.exe'    = 'C:\Windows\System32\csrss.exe'
    'winlogon.exe' = 'C:\Windows\System32\winlogon.exe'
    'services.exe' = 'C:\Windows\System32\services.exe'
    'explorer.exe' = 'C:\Windows\explorer.exe'
    'smss.exe'     = 'C:\Windows\System32\smss.exe'
    'wininit.exe'  = 'C:\Windows\System32\wininit.exe'
    'spoolsv.exe'  = 'C:\Windows\System32\spoolsv.exe'
    'taskhostw.exe'= 'C:\Windows\System32\taskhostw.exe'
}
foreach ($p in $wmiProcs) {
    $n = $p.Name.ToLower()
    if ($systemNames.ContainsKey($n) -and $p.ExecutablePath) {
        $expected = $systemNames[$n].ToLower()
        if ($p.ExecutablePath.ToLower() -ne $expected) {
            Add-Finding 'CRIT' 'Namens-Imitation' "$n aus falschem Pfad" "PID=$($p.ProcessId) Path=$($p.ExecutablePath)"
        }
    }
    # Unicode-Tricks im Namen
    if ($p.Name -match '[^\x00-\x7F]') {
        Add-Finding 'HIGH' 'Unicode-Tarnung' 'Nicht-ASCII im Prozessnamen' "PID=$($p.ProcessId) Name=$($p.Name)"
    }
}

# ---------- 3. Parent-Child-Anomalien ----------
Write-Host '[3] Parent-Child-Anomalien...'
$procById = @{}
foreach ($p in $wmiProcs) { $procById[$p.ProcessId] = $p }

function Get-ParentName($ppid) {
    if ($procById.ContainsKey($ppid)) { return $procById[$ppid].Name.ToLower() }
    return $null
}

foreach ($p in $wmiProcs) {
    $n = $p.Name.ToLower()
    $parent = Get-ParentName $p.ParentProcessId
    if ($n -eq 'svchost.exe' -and $parent -and $parent -ne 'services.exe') {
        Add-Finding 'HIGH' 'Parent-Anomalie' "svchost-Parent ist $parent statt services.exe" "PID=$($p.ProcessId) PPID=$($p.ParentProcessId)"
    }
    if ($n -eq 'lsass.exe' -and $parent -and $parent -ne 'wininit.exe') {
        Add-Finding 'CRIT' 'Parent-Anomalie' "lsass-Parent ist $parent statt wininit.exe" "PID=$($p.ProcessId) PPID=$($p.ParentProcessId)"
    }
    # Office -> PowerShell/cmd = klassischer Malware-Trigger
    if ($parent -in @('winword.exe','excel.exe','outlook.exe','powerpnt.exe') -and
        $n -in @('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe')) {
        Add-Finding 'CRIT' 'Office-Spawn' "$parent hat $n gestartet" "PID=$($p.ProcessId) CMD=$($p.CommandLine)"
    }
}

# ---------- 4. Nur-im-Speicher-Prozesse ----------
Write-Host '[4] Prozesse ohne Image auf Disk...'
foreach ($p in $wmiProcs) {
    if ($p.ExecutablePath -and -not (Test-Path $p.ExecutablePath)) {
        Add-Finding 'HIGH' 'Fileless' 'Image-Pfad existiert nicht mehr' "PID=$($p.ProcessId) Name=$($p.Name) Path=$($p.ExecutablePath)"
    }
}

# ---------- 5. Unsignierte DLLs in signierten Prozessen ----------
Write-Host '[5] Sideloading (unsignierte DLLs)...'
$sideloadRows = @()
# Problematische Prozess-Namen die beim Module-Enum BSODs ausloesen koennen
$skipProcesses = @(
    'vgc','vgk','Vanguard','vgtray',       # Riot Vanguard Anti-Cheat
    'EasyAntiCheat','EasyAntiCheat_EOS',   # EAC
    'BEService','BEDaisy','BattlEye',      # BattlEye
    'FACEIT','kernelbridge','esportal',    # FACEIT/ESportal
    'mhyprot','GenshinImpact',             # Genshin mhyprot-Treiber
    'GameGuard','NPDLL','npggNT',          # nProtect GameGuard
    'HSP','ESEA'                            # HSP / ESEA
)
foreach ($p in (Get-Process | Where-Object { $_.Path -and (Test-Path $_.Path -ErrorAction SilentlyContinue) -and $skipProcesses -notcontains $_.ProcessName })) {
    $exeSig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue
    if (-not $exeSig -or $exeSig.Status -ne 'Valid') { continue }
    try { $modules = $p.Modules } catch { continue }
    foreach ($m in $modules) {
        if (-not $m.FileName) { continue }
        if (-not (Test-Path $m.FileName -ErrorAction SilentlyContinue)) { continue }
        if ($m.FileName -match '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\') {
            $ms = Get-AuthenticodeSignature -FilePath $m.FileName -ErrorAction SilentlyContinue
            if ($ms -and $ms.Status -ne 'Valid') {
                $row = [pscustomobject]@{
                    Process = $p.ProcessName; PID = $p.Id
                    Module = $m.FileName; Status = $ms.Status
                }
                $sideloadRows += $row
                Add-Finding 'HIGH' 'DLL-Sideloading' "Unsignierte DLL in $($p.ProcessName)" "PID=$($p.Id) DLL=$($m.FileName)"
            }
        }
    }
}
$sideloadRows | Export-Csv (Join-Path $outDir 'sideloaded_dlls.csv') -NoTypeInformation -Encoding UTF8

# ---------- 6. WMI Event-Subscriptions ----------
Write-Host '[6] WMI Event-Subscriptions...'
$wmiSubs = @()
foreach ($ns in @('root\subscription','root\default')) {
    $filters   = Get-CimInstance -Namespace $ns -ClassName __EventFilter      -ErrorAction SilentlyContinue
    $consumers = Get-CimInstance -Namespace $ns -ClassName __EventConsumer    -ErrorAction SilentlyContinue
    $bindings  = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $wmiSubs += [pscustomobject]@{
            Namespace = $ns; Type='Consumer'; Name=$c.Name
            Details = ($c | Out-String).Trim()
        }
        Add-Finding 'HIGH' 'WMI-Persistenz' "EventConsumer $($c.Name) in $ns" ($c.Name)
    }
    foreach ($f in $filters) {
        $wmiSubs += [pscustomobject]@{
            Namespace = $ns; Type='Filter'; Name=$f.Name
            Details = $f.Query
        }
    }
    foreach ($b in $bindings) {
        $wmiSubs += [pscustomobject]@{
            Namespace = $ns; Type='Binding'; Name=''
            Details = "Filter=$($b.Filter) Consumer=$($b.Consumer)"
        }
    }
}
$wmiSubs | Export-Csv (Join-Path $outDir 'wmi_subscriptions.csv') -NoTypeInformation -Encoding UTF8

# ---------- 7. Verdaechtige Scheduled Tasks ----------
Write-Host '[7] Scheduled Tasks mit verdaechtigen Actions...'
$suspTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
    [pscustomobject]@{
        TaskName = $_.TaskName; TaskPath = $_.TaskPath; Author = $_.Author; Actions = $actions
    }
} | Where-Object {
    $_.Actions -match 'powershell|rundll32|mshta|wscript|cscript|regsvr32|-enc |-EncodedCommand|FromBase64|AppData\\|\\Temp\\|\\ProgramData\\|hidden'
}
$suspTasks | Export-Csv (Join-Path $outDir 'suspicious_tasks.csv') -NoTypeInformation -Encoding UTF8
foreach ($t in $suspTasks) {
    Add-Finding 'MED' 'Task-Persistenz' "$($t.TaskName) nutzt LOLBin/encoded" $t.Actions
}

# ---------- 8. Treiber ohne Signatur ----------
Write-Host '[8] Treiber...'
$drivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
    $path = $_.PathName -replace '^\\\?\?\\','' -replace '"',''
    $path = $path -replace '^\\SystemRoot\\',"$env:SystemRoot\"
    $sig = $null
    if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
        try {
            $sigObj = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            if ($sigObj) { $sig = $sigObj.Status }
        } catch {}
    }
    [pscustomobject]@{
        Name = $_.Name; DisplayName = $_.DisplayName; Path = $path; Signature = $sig
    }
}
$drivers | Export-Csv (Join-Path $outDir 'drivers.csv') -NoTypeInformation -Encoding UTF8
foreach ($d in $drivers | Where-Object { $_.Signature -and $_.Signature -ne 'Valid' }) {
    Add-Finding 'HIGH' 'Treiber' "$($d.Name) signatur=$($d.Signature)" $d.Path
}

# ---------- 9. Verbindungen ohne Prozess ----------
Write-Host '[9] Orphan-Verbindungen...'
$conns = Get-NetTCPConnection -State Established
foreach ($c in $conns) {
    if (-not $procById.ContainsKey($c.OwningProcess)) {
        Add-Finding 'HIGH' 'Orphan-Verbindung' "TCP zu $($c.RemoteAddress):$($c.RemotePort) ohne Prozess" "PID=$($c.OwningProcess)"
    }
}

# ---------- 10. Encoded/Suspicious Command Lines ----------
Write-Host '[10] Command-Line-Analyse...'
foreach ($p in $wmiProcs) {
    $cl = $p.CommandLine
    if (-not $cl) { continue }
    if ($cl -match '-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s') {
        Add-Finding 'CRIT' 'Encoded-PS' 'PowerShell EncodedCommand' "PID=$($p.ProcessId) CMD=$cl"
    }
    if ($cl -match 'FromBase64String|IEX\s*\(|Invoke-Expression.*DownloadString|Net\.WebClient') {
        Add-Finding 'HIGH' 'PS-Download' 'Typisches Download-Execute' "PID=$($p.ProcessId) CMD=$cl"
    }
    if ($cl -match 'rundll32.*,\s*[A-Z][a-zA-Z0-9_]+\s') {
        if ($cl -match '\\AppData\\|\\Temp\\|\\ProgramData\\|\.tmp|\.dat\b') {
            Add-Finding 'HIGH' 'Rundll32-Tarnung' 'rundll32 mit Datei in User-Pfad' "PID=$($p.ProcessId) CMD=$cl"
        }
    }
}

# ---------- 11. COM-Hijacking-Kandidaten ----------
Write-Host '[11] COM-Hijacking (HKCU)...'
$hkcuCom = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
$comRows = @()
foreach ($clsid in $hkcuCom) {
    $inproc = Join-Path $clsid.PSPath 'InprocServer32'
    if (Test-Path $inproc) {
        $val = (Get-ItemProperty $inproc).'(default)'
        $comRows += [pscustomobject]@{ CLSID = $clsid.PSChildName; Dll = $val }
        Add-Finding 'MED' 'COM-Hijacking' "HKCU CLSID $($clsid.PSChildName)" $val
    }
}
$comRows | Export-Csv (Join-Path $outDir 'hkcu_com.csv') -NoTypeInformation -Encoding UTF8

# ---------- 12. ADS in Startup-Ordnern ----------
Write-Host '[12] Alternate Data Streams...'
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:TEMP",
    "$env:APPDATA"
)
$adsRows = @()
foreach ($sp in $startupPaths) {
    if (-not (Test-Path $sp)) { continue }
    Get-ChildItem -Path $sp -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -notmatch 'Zone\.Identifier' }
        foreach ($s in $streams) {
            $adsRows += [pscustomobject]@{ File = $_.FullName; Stream = $s.Stream; Size = $s.Length }
            Add-Finding 'HIGH' 'ADS' "Versteckter Stream $($s.Stream)" $_.FullName
        }
    }
}
$adsRows | Export-Csv (Join-Path $outDir 'alternate_data_streams.csv') -NoTypeInformation -Encoding UTF8

# ---------- Report ----------
$findings | Sort-Object @{e='Severity';desc=$true},Category |
    Export-Csv (Join-Path $outDir 'findings.csv') -NoTypeInformation -Encoding UTF8

$counts = $findings | Group-Object Severity | Select-Object Name,Count
$summary = @()
$summary += "=== TROJACARE STEALTH-SCAN ==="
$summary += "Zeit: $(Get-Date) | Admin: $isAdmin"
$summary += ''
$summary += 'Funde nach Schweregrad:'
$summary += ($counts | Format-Table -AutoSize | Out-String)
$summary += ''
$summary += 'Top-Befunde:'
$summary += ($findings | Sort-Object @{e='Severity';desc=$true} |
    Select-Object -First 50 Severity,Category,Detail,Evidence |
    Format-Table -AutoSize -Wrap | Out-String)
$summary -join "`r`n" | Out-File (Join-Path $outDir 'SUMMARY.txt') -Encoding UTF8

Write-Host ''
Write-Host "FERTIG. $($findings.Count) Funde. -> $outDir" -ForegroundColor Green
Write-Host "Lies: $(Join-Path $outDir 'SUMMARY.txt')"
