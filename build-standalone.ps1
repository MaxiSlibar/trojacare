<#
.SYNOPSIS
  Baut eine STANDALONE Trojacare.exe mit allen Scan-Scripts eingebettet.
.DESCRIPTION
  Liest alle Scan-*.ps1 und Monitor-*.ps1, kodiert sie Base64, bettet sie
  in eine kombinierte GUI ein, kompiliert das Ganze zu einer einzigen EXE.

  Die fertige EXE ist ca. 200-300 KB und laeuft ohne weitere Dateien.
  Scripts werden beim Start nach %TEMP%\trojacare\ extrahiert, nach
  Schliessen der GUI wieder geloescht.
#>

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
Set-Location $scriptDir

Write-Host 'Trojacare - Standalone-Build' -ForegroundColor Cyan
Write-Host ''

# --- ps2exe sicherstellen ---
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installiere ps2exe (einmalig)...' -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

# --- Scan-Scripts einsammeln und Base64-kodieren ---
$scriptFiles = @(
    'Scan-Connections.ps1'
    'Scan-Stealth.ps1'
    'Scan-Forensics.ps1'
    'Scan-Deep.ps1'
    'Scan-Window.ps1'
    'Monitor-Network.ps1'
)

$embedded = @{}
foreach ($f in $scriptFiles) {
    if (-not (Test-Path $f)) { Write-Host "FEHLT: $f" -ForegroundColor Red; continue }
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path $f))
    $embedded[$f] = [Convert]::ToBase64String($bytes)
    Write-Host ("  + {0,-30} ({1} KB)" -f $f, [math]::Round($bytes.Length/1KB,1))
}

# --- Embedded-Block als PowerShell-Code generieren ---
$embeddedBlock = "`$embeddedScripts = @{`n"
foreach ($k in $embedded.Keys) {
    $embeddedBlock += "    '$k' = '$($embedded[$k])'`n"
}
$embeddedBlock += "}`n"

# --- Standalone-GUI-Script zusammenbauen ---
$standaloneGui = @'
#Requires -RunAsAdministrator
<# Trojacare Standalone GUI - alle Scan-Scripts eingebettet #>

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# === EINGEBETTETE SCRIPTS ===
__EMBEDDED_BLOCK__
# === ENDE EINGEBETTETE SCRIPTS ===

# Scripts zur Laufzeit nach %TEMP%\trojacare\ extrahieren
$workDir = Join-Path $env:TEMP 'trojacare'
if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }
foreach ($k in $embeddedScripts.Keys) {
    $target = Join-Path $workDir $k
    $bytes = [Convert]::FromBase64String($embeddedScripts[$k])
    [IO.File]::WriteAllBytes($target, $bytes)
}

# Reports-Ordner im Benutzer-Dokumenten-Verzeichnis (oder neben EXE)
$exeDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $exeDir) { $exeDir = [Environment]::GetFolderPath('Desktop') }
$reportsRoot = Join-Path $exeDir 'trojacare-reports'
if (-not (Test-Path $reportsRoot)) { New-Item -ItemType Directory -Path $reportsRoot -Force | Out-Null }

$scans = @(
    @{ Name='1. Netzwerk-Scan';      File='Scan-Connections.ps1'; Info='Wer verbindet sich wohin? Autostart, lauschende Ports, DNS-Cache.' }
    @{ Name='2. Stealth-Scan';       File='Scan-Stealth.ps1';     Info='Versteckte Malware, Rootkit-Hinweise, WMI-Persistenz.' }
    @{ Name='3. Forensics (30 Tage)';File='Scan-Forensics.ps1';   Info='PC an/aus, Logons, USB-Historie, Prefetch.' }
    @{ Name='4. Deep-Scan';          File='Scan-Deep.ps1';        Info='AppInit-DLLs, IFEO, LSA, Root-Zertifikate (MitM-Check).' }
)

$form              = New-Object Windows.Forms.Form
$form.Text         = 'Trojacare - Forensik-Scanner'
$form.Size         = New-Object Drawing.Size(720,580)
$form.StartPosition= 'CenterScreen'
$form.BackColor    = [Drawing.Color]::FromArgb(30,30,35)
$form.ForeColor    = [Drawing.Color]::White
$form.Font         = New-Object Drawing.Font('Segoe UI',10)
$form.MinimumSize  = $form.Size

$header = New-Object Windows.Forms.Label
$header.Text = 'TROJACARE'
$header.Font = New-Object Drawing.Font('Segoe UI',20,[Drawing.FontStyle]::Bold)
$header.ForeColor = [Drawing.Color]::FromArgb(100,200,255)
$header.Location = New-Object Drawing.Point(20,15)
$header.Size = New-Object Drawing.Size(400,40)
$form.Controls.Add($header)

$subtitle = New-Object Windows.Forms.Label
$subtitle.Text = 'Prueft deinen Windows-PC auf Malware und forensische Spuren'
$subtitle.Location = New-Object Drawing.Point(22,55)
$subtitle.Size = New-Object Drawing.Size(680,20)
$subtitle.ForeColor = [Drawing.Color]::Gray
$form.Controls.Add($subtitle)

$y = 95; $buttons = @()
foreach ($s in $scans) {
    $btn = New-Object Windows.Forms.Button
    $btn.Text = $s.Name
    $btn.Location = New-Object Drawing.Point(20,$y)
    $btn.Size = New-Object Drawing.Size(220,35)
    $btn.BackColor = [Drawing.Color]::FromArgb(45,45,55)
    $btn.ForeColor = [Drawing.Color]::White
    $btn.FlatStyle = 'Flat'
    $btn.TextAlign = 'MiddleLeft'
    $btn.Padding = New-Object Windows.Forms.Padding(10,0,0,0)
    $btn.Tag = $s.File

    $lbl = New-Object Windows.Forms.Label
    $lbl.Text = $s.Info
    $lbl.Location = New-Object Drawing.Point(250,($y+8))
    $lbl.Size = New-Object Drawing.Size(440,40)
    $lbl.ForeColor = [Drawing.Color]::LightGray

    $form.Controls.Add($btn)
    $form.Controls.Add($lbl)
    $buttons += $btn
    $y += 50
}

$allBtn = New-Object Windows.Forms.Button
$allBtn.Text = 'ALLE Scans nacheinander starten'
$allBtn.Location = New-Object Drawing.Point(20,($y+10))
$allBtn.Size = New-Object Drawing.Size(670,40)
$allBtn.BackColor = [Drawing.Color]::FromArgb(30,120,60)
$allBtn.ForeColor = [Drawing.Color]::White
$allBtn.FlatStyle = 'Flat'
$allBtn.Font = New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
$form.Controls.Add($allBtn)

$output = New-Object Windows.Forms.TextBox
$output.Location = New-Object Drawing.Point(20,($y+60))
$output.Size = New-Object Drawing.Size(670,200)
$output.Multiline = $true
$output.ScrollBars = 'Vertical'
$output.BackColor = [Drawing.Color]::FromArgb(15,15,20)
$output.ForeColor = [Drawing.Color]::LightGreen
$output.Font = New-Object Drawing.Font('Consolas',9)
$output.ReadOnly = $true
$output.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($output)

$statusLabel = New-Object Windows.Forms.Label
$statusLabel.Text = 'Bereit.'
$statusLabel.Location = New-Object Drawing.Point(20,($y+275))
$statusLabel.Size = New-Object Drawing.Size(450,20)
$statusLabel.ForeColor = [Drawing.Color]::Gray
$statusLabel.Anchor = 'Bottom,Left'
$form.Controls.Add($statusLabel)

$openBtn = New-Object Windows.Forms.Button
$openBtn.Text = 'Report-Ordner oeffnen'
$openBtn.Location = New-Object Drawing.Point(480,($y+270))
$openBtn.Size = New-Object Drawing.Size(210,30)
$openBtn.BackColor = [Drawing.Color]::FromArgb(45,45,55)
$openBtn.ForeColor = [Drawing.Color]::White
$openBtn.FlatStyle = 'Flat'
$openBtn.Anchor = 'Bottom,Right'
$form.Controls.Add($openBtn)

function Write-Log($msg, $color='LightGreen') {
    $output.SelectionColor = [Drawing.Color]::$color
    $output.AppendText("$(Get-Date -f 'HH:mm:ss')  $msg`r`n")
    [System.Windows.Forms.Application]::DoEvents()
}

function Invoke-ScanFile($file) {
    $path = Join-Path $workDir $file
    if (-not (Test-Path $path)) { Write-Log "FEHLT: $file" 'Red'; return }
    $statusLabel.Text = "Scan laeuft: $file ..."
    Write-Log "Starte $file"
    try {
        & $path -OutputRoot $reportsRoot *>&1 | ForEach-Object {
            $line = $_.ToString()
            if ($line.Trim()) { Write-Log $line }
        }
        Write-Log "Fertig: $file" 'Cyan'
    } catch { Write-Log "Fehler: $_" 'Red' }
    $statusLabel.Text = 'Bereit.'
}

foreach ($btn in $buttons) {
    $btn.Add_Click({
        $buttons + @($allBtn) | ForEach-Object { $_.Enabled = $false }
        Invoke-ScanFile $this.Tag
        $buttons + @($allBtn) | ForEach-Object { $_.Enabled = $true }
    }.GetNewClosure())
}

$allBtn.Add_Click({
    $buttons + @($allBtn) | ForEach-Object { $_.Enabled = $false }
    foreach ($s in $scans) { Invoke-ScanFile $s.File }
    Write-Log '===== ALLE SCANS ABGESCHLOSSEN =====' 'Yellow'
    $buttons + @($allBtn) | ForEach-Object { $_.Enabled = $true }
})

$openBtn.Add_Click({ Start-Process explorer.exe $reportsRoot })

try { Add-MpPreference -ExclusionPath $workDir -ErrorAction Stop } catch {}

$form.Add_FormClosing({
    try { Remove-MpPreference -ExclusionPath $workDir -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
})

Write-Log "Trojacare bereit. Reports: $reportsRoot"
[void]$form.ShowDialog()
'@

$standaloneGui = $standaloneGui -replace '__EMBEDDED_BLOCK__', $embeddedBlock

$tempScript = Join-Path $scriptDir '_trojacare-standalone.ps1'
Set-Content -Path $tempScript -Value $standaloneGui -Encoding UTF8

Write-Host ''
Write-Host "Generiertes Script: $tempScript" -ForegroundColor Gray
Write-Host 'Kompiliere...' -ForegroundColor Yellow

$out = Join-Path $scriptDir 'Trojacare.exe'
Invoke-PS2EXE `
    -InputFile $tempScript `
    -OutputFile $out `
    -NoConsole `
    -Title 'Trojacare' `
    -Product 'Trojacare Forensik-Scanner' `
    -Description 'Standalone Windows-Forensik-Scanner' `
    -Version '1.0.0.0' `
    -RequireAdmin

Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

if (Test-Path $out) {
    $size = [math]::Round((Get-Item $out).Length/1KB,1)
    Write-Host ''
    Write-Host "FERTIG: $out ($size KB)" -ForegroundColor Green
    Write-Host 'Diese EXE laeuft STANDALONE - keine weiteren Dateien noetig.' -ForegroundColor Green
} else {
    Write-Host 'Build fehlgeschlagen.' -ForegroundColor Red
}
