<#
.SYNOPSIS
  Sammelt einen umfassenden Netzwerk- und Prozess-Snapshot zur Trojaner-Analyse.

.DESCRIPTION
  Schreibt einen Report nach .\reports\<timestamp>\ mit:
   - Aktive TCP/UDP-Verbindungen inkl. Prozess, Pfad, Signatur
   - Lauschende Ports
   - Laufende Prozesse (unsigniert / aus User-Pfaden hervorgehoben)
   - Autostart-Eintraege (Registry Run-Keys, Scheduled Tasks, Dienste)
   - Firewall-Regeln (nur aktivierte)
   - DNS-Cache
   - Hosts-Datei
   - Offene Freigaben
   - System-Basisinfos
  CSV + lesbare TXT-Zusammenfassung.

.NOTES
  Als Administrator ausfuehren fuer vollstaendige Ergebnisse.
  Ausfuehrungsrichtlinie ggf. temporaer lockern:
    powershell -ExecutionPolicy Bypass -File .\Scan-Connections.ps1
#>

[CmdletBinding()]
param(
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
$outDir = Join-Path $OutputRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Report-Verzeichnis: $outDir"
Write-Host ("Admin-Modus: {0}" -f $isAdmin)
if (-not $isAdmin) {
    Write-Warning 'Nicht als Admin gestartet - einige Daten (Pfade, Signaturen fremder Prozesse) fehlen.'
}

# ---------- Hilfsfunktionen ----------

$processCache = @{}
function Get-ProcInfo {
    param([int]$ProcId)
    if ($processCache.ContainsKey($ProcId)) { return $processCache[$ProcId] }
    $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    $path = $null; $company = $null; $sigStatus = 'Unknown'; $signer = $null
    $procName = '<beendet>'
    if ($p) {
        $procName = $p.ProcessName
        try { $path = $p.Path } catch {}
        try { $company = $p.Company } catch {}
        if ($path -and (Test-Path $path)) {
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = "$($sig.Status)"
                if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            }
        }
    }
    $userPath = $false
    if ($path) { $userPath = ($path -match '\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\') }
    $info = [pscustomobject]@{
        PID       = $ProcId
        Name      = $procName
        Path      = $path
        Company   = $company
        Signature = $sigStatus
        Signer    = $signer
        UserPath  = $userPath
    }
    $processCache[$ProcId] = $info
    $info
}

function Save-Data {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Data
    )
    $csv = Join-Path $outDir "$Name.csv"
    $txt = Join-Path $outDir "$Name.txt"
    $Data | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $Data | Format-Table -AutoSize | Out-File -FilePath $txt -Encoding UTF8 -Width 500
}

# ---------- 1. TCP-Verbindungen ----------
Write-Host '[1/9] TCP-Verbindungen...'
$tcp = Get-NetTCPConnection | ForEach-Object {
    $pi = Get-ProcInfo -ProcId $_.OwningProcess
    [pscustomobject]@{
        State         = $_.State
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        PID           = $_.OwningProcess
        Process       = $pi.Name
        Path          = $pi.Path
        Signature     = $pi.Signature
        Signer        = $pi.Signer
        UserPath      = $pi.UserPath
    }
} | Sort-Object State, RemoteAddress
Save-Data -Name '01_tcp_connections' -Data $tcp

# ---------- 2. UDP-Endpunkte ----------
Write-Host '[2/9] UDP-Endpunkte...'
$udp = Get-NetUDPEndpoint | ForEach-Object {
    $pi = Get-ProcInfo -ProcId $_.OwningProcess
    [pscustomobject]@{
        LocalAddress = $_.LocalAddress
        LocalPort    = $_.LocalPort
        PID          = $_.OwningProcess
        Process      = $pi.Name
        Path         = $pi.Path
        Signature    = $pi.Signature
        UserPath     = $pi.UserPath
    }
} | Sort-Object LocalPort
Save-Data -Name '02_udp_endpoints' -Data $udp

# ---------- 3. Lauschende Ports ----------
Write-Host '[3/9] Lauschende Ports...'
$listen = $tcp | Where-Object State -eq 'Listen' |
    Select-Object LocalAddress,LocalPort,PID,Process,Path,Signature,UserPath |
    Sort-Object LocalPort
Save-Data -Name '03_listening_ports' -Data $listen

# ---------- 4. Prozesse ----------
Write-Host '[4/9] Prozesse...'
$procs = Get-Process | ForEach-Object {
    $pi = Get-ProcInfo -ProcId $_.Id
    $startTime = $null
    try { $startTime = $_.StartTime } catch {}
    $cpuTime = $null
    try { $cpuTime = $_.CPU } catch {}
    [pscustomobject]@{
        PID       = $_.Id
        Name      = $_.ProcessName
        Path      = $pi.Path
        Company   = $pi.Company
        Signature = $pi.Signature
        Signer    = $pi.Signer
        UserPath  = $pi.UserPath
        StartTime = $startTime
        CPU       = $cpuTime
    }
} | Sort-Object Name
Save-Data -Name '04_processes' -Data $procs

# ---------- 5. Autostart ----------
Write-Host '[5/9] Autostart-Eintraege...'
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$autostart = foreach ($k in $runKeys) {
    if (Test-Path $k) {
        $props = Get-ItemProperty -Path $k
        $props.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object {
                [pscustomobject]@{
                    Key   = $k
                    Name  = $_.Name
                    Value = $_.Value
                }
            }
    }
}
Save-Data -Name '05_autostart_registry' -Data $autostart

# Scheduled Tasks (Nicht-Microsoft)
$tasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled'
} | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    [pscustomobject]@{
        TaskName  = $_.TaskName
        TaskPath  = $_.TaskPath
        State     = $_.State
        Author    = $_.Author
        Action    = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        LastRun   = $info.LastRunTime
        NextRun   = $info.NextRunTime
    }
}
Save-Data -Name '06_scheduled_tasks' -Data $tasks

# Dienste (Auto-Start, nicht von Microsoft)
$services = Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' } |
    ForEach-Object {
        $pi = if ($_.ProcessId) { Get-ProcInfo -ProcId $_.ProcessId } else { $null }
        [pscustomobject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            State       = $_.State
            StartMode   = $_.StartMode
            PathName    = $_.PathName
            StartName   = $_.StartName
            Signature   = if ($pi) { $pi.Signature } else { $null }
            Signer      = if ($pi) { $pi.Signer } else { $null }
        }
    } | Sort-Object Name
Save-Data -Name '07_services_auto' -Data $services

# ---------- 6. Firewall-Regeln (aktiv, erlaubend) ----------
Write-Host '[6/9] Firewall-Regeln...'
$fw = Get-NetFirewallRule -Enabled True -Action Allow |
    ForEach-Object {
        $app  = $_ | Get-NetFirewallApplicationFilter
        $port = $_ | Get-NetFirewallPortFilter
        $addr = $_ | Get-NetFirewallAddressFilter
        [pscustomobject]@{
            DisplayName = $_.DisplayName
            Direction   = $_.Direction
            Action      = $_.Action
            Profile     = $_.Profile
            Program     = $app.Program
            Protocol    = $port.Protocol
            LocalPort   = ($port.LocalPort -join ',')
            RemotePort  = ($port.RemotePort -join ',')
            RemoteAddr  = ($addr.RemoteAddress -join ',')
        }
    }
Save-Data -Name '08_firewall_rules' -Data $fw

# ---------- 7. DNS-Cache ----------
Write-Host '[7/9] DNS-Cache...'
$dns = Get-DnsClientCache |
    Select-Object Entry,Name,Type,Status,Section,TimeToLive,Data |
    Sort-Object Entry
Save-Data -Name '09_dns_cache' -Data $dns

# ---------- 8. Hosts-Datei + Freigaben + Sysinfo ----------
Write-Host '[8/9] Hosts / Shares / Sysinfo...'
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsFile) {
    Copy-Item $hostsFile (Join-Path $outDir '10_hosts.txt') -Force
}

Get-SmbShare | Export-Csv (Join-Path $outDir '11_smb_shares.csv') -NoTypeInformation -Encoding UTF8

$sysinfo = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = (Get-CimInstance Win32_OperatingSystem).Caption
    Version      = (Get-CimInstance Win32_OperatingSystem).Version
    LastBoot     = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Timestamp    = Get-Date
    Admin        = $isAdmin
}
$sysinfo | ConvertTo-Json | Out-File (Join-Path $outDir '00_sysinfo.json') -Encoding UTF8

# ---------- 9. Zusammenfassung / Auffaelligkeiten ----------
Write-Host '[9/9] Zusammenfassung...'
$summary = @()
$summary += "=== TROJACARE SCAN-REPORT ==="
$summary += "Zeit:        $(Get-Date)"
$summary += "Rechner:     $env:COMPUTERNAME"
$summary += "User:        $env:USERNAME"
$summary += "Admin:       $isAdmin"
$summary += ""
$summary += "--- AUFFAELLIGKEITEN ---"
$summary += ""

# A: Etablierte Verbindungen aus User-Pfaden
$suspConn = $tcp | Where-Object { $_.State -eq 'Established' -and $_.UserPath }
$summary += "[A] Etablierte Verbindungen von Prozessen aus User-/AppData-/Temp-Pfaden: $($suspConn.Count)"
if ($suspConn) {
    $summary += ($suspConn | Format-Table Process,PID,RemoteAddress,RemotePort,Path -AutoSize | Out-String)
}

# B: Unsignierte / ungueltig signierte Prozesse mit Netzwerkaktivitaet
$netPids = ($tcp | Where-Object State -eq 'Established').PID | Select-Object -Unique
$unsignedNet = $procs | Where-Object {
    $netPids -contains $_.PID -and $_.Signature -notin @('Valid','NotSigned') -or
    ($netPids -contains $_.PID -and $_.Signature -eq 'NotSigned')
}
$summary += "[B] Prozesse mit Netzverkehr und fehlender/ungueltiger Signatur: $($unsignedNet.Count)"
if ($unsignedNet) {
    $summary += ($unsignedNet | Format-Table Name,PID,Signature,Path -AutoSize | Out-String)
}

# C: Lauschende Ports aussen
$externalListen = $listen | Where-Object { $_.LocalAddress -in @('0.0.0.0','::') }
$summary += "[C] Extern erreichbare lauschende Ports: $($externalListen.Count)"
$summary += ($externalListen | Format-Table LocalPort,Process,PID,Path -AutoSize | Out-String)

# D: Verdaechtige Remote-IPs (nicht privat)
function Test-PrivateIP([string]$ip) {
    if ([string]::IsNullOrEmpty($ip)) { return $true }
    if ($ip -match '^(127\.|10\.|192\.168\.|169\.254\.|::1|fe80:|0\.0\.0\.0)') { return $true }
    if ($ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
    return $false
}
$extRemote = $tcp | Where-Object {
    $_.State -eq 'Established' -and -not (Test-PrivateIP $_.RemoteAddress)
} | Group-Object RemoteAddress | Sort-Object Count -Descending
$summary += "[D] Aktive externe Ziele (Haeufigkeit):"
$summary += ($extRemote | Select-Object Count,Name | Format-Table -AutoSize | Out-String)

# E: Scheduled Tasks nicht von Microsoft
$summary += "[E] Scheduled Tasks ausserhalb \Microsoft\: $($tasks.Count)"

# F: Autostart-Eintraege
$summary += "[F] Run-Key Autostart-Eintraege: $($autostart.Count)"
if ($autostart) {
    $summary += ($autostart | Format-Table Name,Value -AutoSize | Out-String)
}

$summary -join "`r`n" | Out-File (Join-Path $outDir 'SUMMARY.txt') -Encoding UTF8

Write-Host ''
Write-Host "FERTIG. Report: $outDir" -ForegroundColor Green
Write-Host "Lies zuerst: $(Join-Path $outDir 'SUMMARY.txt')"
