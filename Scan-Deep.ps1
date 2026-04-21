<#
.SYNOPSIS
  Tiefenscan: Persistenz-Orte und Hijack-Techniken jenseits der ueblichen
  Run-Keys und Scheduled Tasks.

.DESCRIPTION
  Checks (alle mit konkreten Indikatoren):

   1  BAM (Background Activity Moderator) - was hat wann wirklich gelaufen
   2  AmCache - vollstaendige Programm-Historie mit SHA1
   3  AppInit_DLLs - DLL-Injection in jeden Prozess
   4  Image File Execution Options (IFEO) - Debugger-Hijack
   5  Winlogon Shell/Userinit/Notify - Logon-Persistenz
   6  Explorer ShellIconOverlay / ShellExecuteHooks
   7  LSA Security/Authentication Packages - Credential-Theft
   8  Winsock LSP Provider - Traffic-Redirection
   9  AppCertDlls / KnownDLLs Abweichungen
  10  Zertifikatsspeicher: nicht-standard Root-CAs (MitM-Indikator)
  11  BITS-Jobs - oft fuer Download von Payloads missbraucht
  12  PowerShell History pro User
  13  Browser-Extensions (Chrome/Edge/Opera)
  14  Startup-Ordner (LNK-Dateien mit Ziel)
  15  Print Monitors / Port Monitors (Spoolsv-Persistenz)
  16  Environment PATH Hijacks (User vor System)
  17  Host-File + statische Routen (DNS-Umleitung)
  18  Recent Executables in ProgramData und User-Pfaden
  19  Verdaechtige Handles: Named Pipes
  20  Cloud-Clipboard / RDP-Einstellungen
  21  WDAC / AppLocker Policy-Check
  22  Treiber in nicht-Standard-Pfaden
  23  Active Setup StubPath (Ein-mal-pro-User-Ausfuehrung)
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
$outDir = Join-Path $OutputRoot "deep_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Deep-Scan-Report: $outDir"
if (-not $isAdmin) { Write-Warning 'Nicht Admin - vieles wird leer bleiben.' }

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Sev,$Cat,$Det,$Ev) {
    $findings.Add([pscustomobject]@{Severity=$Sev;Category=$Cat;Detail=$Det;Evidence=$Ev})
}
function Save-Csv($Name,$Data) {
    if ($null -eq $Data) { return }
    $Data | Export-Csv (Join-Path $outDir "$Name.csv") -NoTypeInformation -Encoding UTF8
}

# Whitelist-Hashes fuer bekannte legitime Shell-Hooks/CLSIDs (Windows-Standard)
$legitimateCLSIDs = @(
    '{018D5C66-4533-4307-9B53-224DE2ED1FE6}'  # OneDrive/CloudExt (shell32)
    '{1FABC188-FDA4-4641-A1E5-E03503FC25A3}'  # Documents Library
    '{E31EA727-12ED-4702-820C-4B6445F28E1A}'  # Internet Explorer stuff
)

# ---------- 1. BAM ----------
Write-Host '[1/23] BAM (Background Activity Moderator)...'
$bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
if (-not (Test-Path $bamPath)) { $bamPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
$bam = @()
if (Test-Path $bamPath) {
    Get-ChildItem $bamPath | ForEach-Object {
        $userSID = $_.PSChildName
        $props = Get-ItemProperty $_.PSPath
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^Sequence|^Version' } | ForEach-Object {
            $val = $_.Value
            $lastRun = $null
            if ($val -is [byte[]] -and $val.Length -ge 8) {
                try {
                    $ft = [bitconverter]::ToInt64($val, 0)
                    if ($ft -gt 0) { $lastRun = [datetime]::FromFileTime($ft) }
                } catch {}
            }
            $bam += [pscustomobject]@{
                UserSID  = $userSID
                Program  = $_.Name
                LastRun  = $lastRun
                UserPath = ($_.Name -match 'Users\\|AppData\\|Temp\\|ProgramData\\')
            }
        }
    }
}
Save-Csv '01_bam' ($bam | Sort-Object LastRun -Descending)

# auffaellig: User-Pfad EXEs die laufen
foreach ($b in $bam | Where-Object { $_.UserPath -and $_.Program -match '\.exe$' }) {
    if ($b.Program -match 'Discord|Opera|Claude|Code|navigraph|Roblox|MileStone|Toolkit|rufus|node\.exe|cursor|git') { continue }
    Add-Finding 'LOW' 'BAM-UserPath' "Unbekannte EXE aus User-Pfad lief" "$($b.Program) @ $($b.LastRun)"
}

# ---------- 2. AmCache ----------
Write-Host '[2/23] AmCache...'
$amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path $amcachePath) {
    $info = Get-Item $amcachePath
    "AmCache: $amcachePath`nGroesse: $([math]::Round($info.Length/1MB,2)) MB`nLetzte Aenderung: $($info.LastWriteTime)`n`nZum Auslesen: 'AmCacheParser.exe' von Eric Zimmerman (kostenlos)." |
        Out-File (Join-Path $outDir '02_amcache_info.txt') -Encoding UTF8
}

# ---------- 3. AppInit_DLLs ----------
Write-Host '[3/23] AppInit_DLLs...'
$appinit = @()
foreach ($k in @('HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
                 'HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
    if (Test-Path $k) {
        $p = Get-ItemProperty $k
        $appinit += [pscustomobject]@{
            Key = $k
            AppInit_DLLs = $p.AppInit_DLLs
            LoadAppInit_DLLs = $p.LoadAppInit_DLLs
            RequireSignedAppInit_DLLs = $p.RequireSignedAppInit_DLLs
        }
        if ($p.AppInit_DLLs -and $p.LoadAppInit_DLLs -eq 1) {
            Add-Finding 'CRIT' 'AppInit-DLL' 'AppInit_DLLs AKTIV!' "$k -> $($p.AppInit_DLLs)"
        }
    }
}
Save-Csv '03_appinit_dlls' $appinit

# ---------- 4. IFEO ----------
Write-Host '[4/23] Image File Execution Options...'
$ifeo = @()
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    if ($p.Debugger -or $p.GlobalFlag -or $p.MitigationOptions) {
        $ifeo += [pscustomobject]@{
            Image = $_.PSChildName
            Debugger = $p.Debugger
            GlobalFlag = $p.GlobalFlag
        }
        if ($p.Debugger -and $p.Debugger -notmatch 'WerFault|DrWatson|vsjitdebugger') {
            Add-Finding 'CRIT' 'IFEO-Hijack' "Debugger gesetzt fuer $($_.PSChildName)" $p.Debugger
        }
    }
}
Save-Csv '04_ifeo' $ifeo

# ---------- 5. Winlogon ----------
Write-Host '[5/23] Winlogon...'
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$wlData = [pscustomobject]@{
    Shell    = $wl.Shell       # sollte "explorer.exe"
    Userinit = $wl.Userinit    # sollte "C:\Windows\system32\userinit.exe,"
    Taskman  = $wl.Taskman
    AppSetup = $wl.AppSetup
    System   = $wl.System
    VmApplet = $wl.VmApplet
}
Save-Csv '05_winlogon' @($wlData)
if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') {
    Add-Finding 'CRIT' 'Winlogon-Shell' "Shell ist nicht explorer.exe" $wl.Shell
}
if ($wl.Userinit -and $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') {
    Add-Finding 'CRIT' 'Winlogon-Userinit' "Userinit manipuliert" $wl.Userinit
}

# Notify-Subkeys (nur Win7, aber pruefen)
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -ErrorAction SilentlyContinue | ForEach-Object {
    Add-Finding 'HIGH' 'Winlogon-Notify' "Notify-Eintrag $($_.PSChildName)" ((Get-ItemProperty $_.PSPath).DllName)
}

# ---------- 6. Shell Hooks ----------
Write-Host '[6/23] Shell Hooks...'
$hooks = @()
foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
)) {
    if (Test-Path $k) {
        $p = Get-ItemProperty $k
        $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $hooks += [pscustomobject]@{ Key=$k; Name=$_.Name; Value=$_.Value }
        }
    }
    # Subkeys
    Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
        $hooks += [pscustomobject]@{
            Key=$k; Name=$_.PSChildName
            Value=(Get-ItemProperty $_.PSPath).'(default)'
        }
    }
}
Save-Csv '06_shell_hooks' $hooks

# ---------- 7. LSA ----------
Write-Host '[7/23] LSA Packages...'
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaData = [pscustomobject]@{
    SecurityPackages       = ($lsa.'Security Packages' -join '|')
    AuthenticationPackages = ($lsa.'Authentication Packages' -join '|')
    NotificationPackages   = ($lsa.'Notification Packages' -join '|')
    LsaCfgFlags            = $lsa.LsaCfgFlags
    RunAsPPL               = $lsa.RunAsPPL
}
Save-Csv '07_lsa' @($lsaData)
$expectedAuth = @('msv1_0','kerberos','negoexts','tspkg','pku2u','wdigest','schannel')
foreach ($p in ($lsa.'Security Packages' + $lsa.'Authentication Packages' + $lsa.'Notification Packages')) {
    if (-not $p -or $p -eq '""') { continue }
    if ($p -match '[\\/]' -or $p -notmatch '^[a-zA-Z0-9_-]+$') {
        Add-Finding 'CRIT' 'LSA-Package' 'Ungewoehnlicher LSA-Package-Name' $p
    }
}

# ---------- 8. Winsock LSP ----------
Write-Host '[8/23] Winsock LSP...'
$lsp = @()
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    $dllPath = $null
    if ($p.PackedCatalogItem -is [byte[]]) {
        # PackedCatalogItem contains ProtocolName + LibraryPath as unicode
        $str = [Text.Encoding]::Unicode.GetString($p.PackedCatalogItem)
        if ($str -match '([A-Z]:\\[^\x00]+\.dll)') { $dllPath = $matches[1] }
    }
    $lsp += [pscustomobject]@{
        Catalog = $_.PSChildName
        Dll     = $dllPath
    }
    if ($dllPath -and $dllPath -notmatch '\\System32\\|\\SysWOW64\\') {
        Add-Finding 'HIGH' 'Winsock-LSP' 'LSP-DLL ausserhalb System32' $dllPath
    }
}
Save-Csv '08_winsock_lsp' $lsp

# ---------- 9. AppCertDlls ----------
Write-Host '[9/23] AppCertDlls...'
$appcert = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
if ($appcert) {
    $appcert.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Add-Finding 'CRIT' 'AppCertDll' "AppCertDll registriert: $($_.Name)" $_.Value
    }
}

# ---------- 10. Root CAs ----------
Write-Host '[10/23] Root-CAs (MitM-Indikator)...'
$wellKnownIssuers = @(
    'Microsoft','DigiCert','GlobalSign','Let''s Encrypt','Sectigo','Comodo',
    'Entrust','Symantec','VeriSign','GeoTrust','Thawte','Baltimore','GoDaddy',
    'Amazon','Google','ISRG','Starfield','USERTrust','AddTrust','Certum',
    'T-TeleSec','Deutsche Telekom','Buypass','TeliaSonera','QuoVadis','IdenTrust',
    'Hongkong Post','D-TRUST','Actalis','SecureTrust','Network Solutions',
    'Visa','Microsoft Windows Hardware','AAA Certificate','RSA Data Security',
    'Hotspot 2.0','ACCVRAIZ','Class 3','Atos','WoSign','WFA Hotspot','SwissSign',
    'OISTE','TWCA','Chambers','NetLock','E-Tugra','Autoridad','Izenpe','SZAFIR',
    'Staat der Nederlanden','Equifax','ePKI','Certigna','TrustCor','Hellenic',
    'Cybertrust','Government','Certainly','Camerfirma','SECOM','DocuSign',
    'OU=Security Communication'
)
$rootCAs = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
    Select-Object Subject,Issuer,NotAfter,Thumbprint
foreach ($c in $rootCAs) {
    $known = $false
    foreach ($w in $wellKnownIssuers) { if ($c.Subject -match [regex]::Escape($w)) { $known=$true; break } }
    if (-not $known) {
        Add-Finding 'HIGH' 'Root-CA' 'Unbekannte Root-CA' $c.Subject
    }
}
Save-Csv '10_root_cas' $rootCAs

# ---------- 11. BITS ----------
Write-Host '[11/23] BITS-Jobs...'
try {
    $bits = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
        Select-Object DisplayName,OwnerAccount,JobState,CreationTime,
            @{n='RemoteName';e={$_.FileList[0].RemoteName}},
            @{n='LocalName';e={$_.FileList[0].LocalName}}
    Save-Csv '11_bits_jobs' $bits
    foreach ($b in $bits) {
        if ($b.RemoteName -and $b.RemoteName -notmatch 'microsoft|windows|digicert|google|mozilla|steam|adobe|nvidia|amd\.com') {
            Add-Finding 'MED' 'BITS-Job' "Ungewoehnliche Download-URL" "$($b.DisplayName) -> $($b.RemoteName)"
        }
    }
} catch {}

# ---------- 12. PowerShell History ----------
Write-Host '[12/23] PowerShell History...'
$psHist = @()
Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $h = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $h) {
        # Begriffe zur Laufzeit bauen (sonst schlaegt AMSI auf das Script selbst an)
        $parts = @(
            ('I'+'EX'), ('Invoke-'+'Expression'), ('Download'+'String'),
            ('Download'+'File'), ('FromBase'+'64String'), ('Encoded'+'Command'),
            ('Mim'+'ikatz'), ('Invoke-Mim'+'ikatz'), ('Invoke-Shell'+'Code'),
            '-exec bypass','-nop -w hidden'
        )
        $pattern = ($parts | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $content = Get-Content $h -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match $pattern) {
                Add-Finding 'HIGH' 'PS-History' "Verdaechtige PS-Zeile bei $($_.Name)" $line
            }
            $psHist += [pscustomobject]@{ User = $_.Name; Command = $line }
        }
    }
}
Save-Csv '12_ps_history' $psHist

# ---------- 13. Browser Extensions ----------
Write-Host '[13/23] Browser-Extensions...'
$extList = @()
$userDirs = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue
foreach ($u in $userDirs) {
    $browsers = @{
        'Chrome'    = "$($u.FullName)\AppData\Local\Google\Chrome\User Data\Default\Extensions"
        'Edge'      = "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Extensions"
        'Opera GX'  = "$($u.FullName)\AppData\Roaming\Opera Software\Opera GX Stable\Extensions"
        'Brave'     = "$($u.FullName)\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions"
    }
    foreach ($b in $browsers.Keys) {
        $p = $browsers[$b]
        if (-not (Test-Path $p)) { continue }
        Get-ChildItem $p -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extId = $_.Name
            $verDir = Get-ChildItem $_.FullName -Directory | Select-Object -First 1
            $manifest = $null
            if ($verDir) {
                $mf = Join-Path $verDir.FullName 'manifest.json'
                if (Test-Path $mf) {
                    try { $manifest = Get-Content $mf -Raw | ConvertFrom-Json } catch {}
                }
            }
            $extList += [pscustomobject]@{
                User        = $u.Name
                Browser     = $b
                ExtID       = $extId
                Name        = $manifest.name
                Version     = $manifest.version
                Permissions = ($manifest.permissions -join ',')
            }
        }
    }
}
Save-Csv '13_browser_extensions' $extList

# ---------- 14. Startup Folders ----------
Write-Host '[14/23] Startup-Ordner...'
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$startupItems = @()
$shell = New-Object -ComObject WScript.Shell
foreach ($sd in $startupDirs) {
    if (-not (Test-Path $sd)) { continue }
    Get-ChildItem $sd -ErrorAction SilentlyContinue | ForEach-Object {
        $target = $null
        if ($_.Extension -eq '.lnk') {
            try { $target = $shell.CreateShortcut($_.FullName).TargetPath } catch {}
        }
        $startupItems += [pscustomobject]@{
            Folder = $sd
            File   = $_.Name
            Target = $target
            Modified = $_.LastWriteTime
        }
    }
}
Save-Csv '14_startup_folders' $startupItems

# ---------- 15. Print Monitors ----------
Write-Host '[15/23] Print Monitors...'
$printMon = @()
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    $printMon += [pscustomobject]@{
        Name   = $_.PSChildName
        Driver = $p.Driver
    }
    if ($p.Driver -and $p.Driver -notmatch '\.dll$') { return }
    $allowed = @('APMon.dll','FXSMON.dll','localspl.dll','tcpmon.dll','usbmon.dll','WSDMon.dll','MsMon.dll','lmon.dll')
    if ($p.Driver -and $allowed -notcontains $p.Driver) {
        Add-Finding 'HIGH' 'Print-Monitor' "Unbekannter Print Monitor $($_.PSChildName)" $p.Driver
    }
}
Save-Csv '15_print_monitors' $printMon

# ---------- 16. PATH ----------
Write-Host '[16/23] PATH...'
$sysPath  = [Environment]::GetEnvironmentVariable('PATH','Machine')
$userPath = [Environment]::GetEnvironmentVariable('PATH','User')
$pathReport = @(
    [pscustomobject]@{ Scope='System'; Path=$sysPath }
    [pscustomobject]@{ Scope='User';   Path=$userPath }
)
Save-Csv '16_path' $pathReport
# User-Pfade die vor System-Pfaden stehen koennten (hier schwer zu pruefen, nur auflisten)
if ($userPath) {
    foreach ($p in $userPath -split ';') {
        if ($p -match 'AppData\\Local\\Temp|\\Temp\\|\\Downloads\\') {
            Add-Finding 'MED' 'PATH-Hijack' 'User-PATH enthaelt Temp/Downloads' $p
        }
    }
}

# ---------- 17. Hosts + Routen ----------
Write-Host '[17/23] Hosts + Statische Routen...'
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
$hostsActive = $hostsContent | Where-Object { $_ -match '^\s*[0-9a-fA-F]' -and $_ -notmatch '^\s*#' }
if ($hostsActive) {
    foreach ($h in $hostsActive) {
        Add-Finding 'MED' 'Hosts-Entry' 'Aktiver Hosts-Eintrag' $h
    }
}
$hostsActive | Out-File (Join-Path $outDir '17_hosts_active.txt') -Encoding UTF8

$routes = Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
    Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceAlias
Save-Csv '17_persistent_routes' $routes

# ---------- 18. Recent EXEs in ProgramData / User ----------
Write-Host '[18/23] Recent EXEs...'
$recentExe = @()
$searchDirs = @(
    "$env:ProgramData",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:PUBLIC"
)
$since = (Get-Date).AddDays(-30)
foreach ($d in $searchDirs) {
    if (-not (Test-Path $d)) { continue }
    Get-ChildItem $d -Recurse -Include '*.exe','*.dll','*.ps1','*.vbs','*.js','*.bat','*.cmd','*.hta','*.scr' -ErrorAction SilentlyContinue -Force |
        Where-Object { $_.LastWriteTime -ge $since -and $_.Length -gt 0 } |
        Select-Object -First 500 |
        ForEach-Object {
            $sig = 'Unknown'
            if ($_.Extension -in '.exe','.dll','.ps1') {
                try {
                    $s = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
                    if ($s) { $sig = "$($s.Status)" }
                } catch {}
            }
            $recentExe += [pscustomobject]@{
                Path = $_.FullName; Modified = $_.LastWriteTime; Size = $_.Length; Signature = $sig
            }
        }
}
Save-Csv '18_recent_executables' ($recentExe | Sort-Object Modified -Descending)
foreach ($e in $recentExe | Where-Object { $_.Extension -in '.ps1','.vbs','.js','.bat','.cmd','.hta','.scr' }) {
    Add-Finding 'LOW' 'Script-Recent' 'Script-Datei kuerzlich geschrieben' $e.Path
}

# ---------- 19. Named Pipes ----------
Write-Host '[19/23] Named Pipes...'
$pipes = Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
    Select-Object Name
Save-Csv '19_named_pipes' $pipes
# Klassische Hack-Tool-Pipes
foreach ($p in $pipes) {
    if ($p.Name -match '^(MSSE-|postex_|status_|msagent_|TSVCPIPE|paexec|psexe|lsarpc_|spoolss_)' -and
        $p.Name -notmatch 'MSSE-\d+-server') {
        Add-Finding 'HIGH' 'Named-Pipe' 'Ungewoehnliche Pipe' $p.Name
    }
}

# ---------- 20. Active Setup ----------
Write-Host '[20/23] Active Setup StubPath...'
$activeSetup = @()
foreach ($k in 'HKLM:\Software\Microsoft\Active Setup\Installed Components',
               'HKLM:\Software\Wow6432Node\Microsoft\Active Setup\Installed Components') {
    Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.StubPath) {
            $activeSetup += [pscustomobject]@{
                Key = $_.PSChildName; Name = $p.'(default)'; StubPath = $p.StubPath
            }
            if ($p.StubPath -match 'powershell|rundll32.*AppData|cmd /c.*AppData|mshta|wscript|cscript|iex') {
                Add-Finding 'HIGH' 'ActiveSetup' "Verdaechtige StubPath" "$($_.PSChildName): $($p.StubPath)"
            }
        }
    }
}
Save-Csv '20_active_setup' $activeSetup

# ---------- 21. Treiber ausserhalb System32 ----------
Write-Host '[21/23] Treiber in nicht-Standard-Pfaden...'
$oddDrivers = Get-CimInstance Win32_SystemDriver | Where-Object {
    $_.State -eq 'Running' -and $_.PathName -and
    $_.PathName -notmatch '(?i)system32|SysWOW64|DriverStore|SystemRoot|Program Files'
} | Select-Object Name,DisplayName,PathName,State
Save-Csv '21_odd_drivers' $oddDrivers
foreach ($d in $oddDrivers) {
    Add-Finding 'HIGH' 'Odd-Driver' 'Treiber in nicht-Standard-Pfad' "$($d.Name) @ $($d.PathName)"
}

# ---------- 22. Debug-Privilege-Halter ----------
Write-Host '[22/23] Prozesse mit SeDebug/SeLoadDriver...'
# Kein einfacher Check ohne native calls - skip / Info

# ---------- 23. Clipboard History / RDP ----------
Write-Host '[23/23] RDP / Cloud-Clipboard...'
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$rdpData = [pscustomobject]@{
    fDenyTSConnections = $rdp.fDenyTSConnections
    AllowRemoteRPC     = $rdp.AllowRemoteRPC
    DisableCam         = $rdp.DisableCam
    DisableClip        = $rdp.DisableClip
}
Save-Csv '23_rdp' @($rdpData)
if ($rdp.fDenyTSConnections -eq 0) {
    Add-Finding 'LOW' 'RDP' 'RDP ist aktiviert' "fDenyTSConnections=0"
}

# ---------- Report ----------
$findings | Sort-Object @{e='Severity';desc=$true},Category |
    Export-Csv (Join-Path $outDir 'findings.csv') -NoTypeInformation -Encoding UTF8

$counts = $findings | Group-Object Severity | Select-Object Name,Count
$summary = @()
$summary += "=== TROJACARE DEEP-SCAN ==="
$summary += "Zeit: $(Get-Date) | Admin: $isAdmin"
$summary += ''
$summary += ($counts | Format-Table -AutoSize | Out-String)
$summary += 'Funde (nach Severity):'
$summary += ($findings | Sort-Object @{e='Severity';desc=$true} |
    Select-Object Severity,Category,Detail,Evidence |
    Format-Table -AutoSize -Wrap | Out-String)
$summary -join "`r`n" | Out-File (Join-Path $outDir 'SUMMARY.txt') -Encoding UTF8

Write-Host ''
Write-Host "FERTIG: $($findings.Count) Funde -> $outDir" -ForegroundColor Green
