<#
.SYNOPSIS
  Baut eine STANDALONE Trojacare.exe mit allen Scan-Scripts eingebettet
  und integriertem Report-Viewer.
#>

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
Set-Location $scriptDir

Write-Host 'Trojacare - Standalone-Build' -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installiere ps2exe (einmalig)...' -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

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

$embeddedBlock = "`$embeddedScripts = @{`n"
foreach ($k in $embedded.Keys) {
    $embeddedBlock += "    '$k' = '$($embedded[$k])'`n"
}
$embeddedBlock += "}`n"

$standaloneGui = @'
#Requires -RunAsAdministrator
<# Trojacare Standalone GUI #>

# UTF-8 erzwingen
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

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
# === ENDE ===

$workDir = Join-Path $env:TEMP 'trojacare'
if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null }
foreach ($k in $embeddedScripts.Keys) {
    [IO.File]::WriteAllBytes((Join-Path $workDir $k), [Convert]::FromBase64String($embeddedScripts[$k]))
}

$exeDir = $null
try { $exeDir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) } catch {}
if (-not $exeDir) { $exeDir = [Environment]::GetFolderPath('Desktop') }
$reportsRoot = Join-Path $exeDir 'trojacare-reports'
if (-not (Test-Path $reportsRoot)) { New-Item -ItemType Directory -Path $reportsRoot -Force | Out-Null }

$scans = @(
    @{ Name='Netzwerk-Scan';       File='Scan-Connections.ps1'; Info='Verbindungen, Ports, Autostart, DNS-Cache' }
    @{ Name='Stealth-Scan';        File='Scan-Stealth.ps1';     Info='Rootkit-Hinweise, WMI-Persistenz, Sideloading' }
    @{ Name='Forensics (30 Tage)'; File='Scan-Forensics.ps1';   Info='PC an/aus, Logons, USB-Historie, Prefetch' }
    @{ Name='Deep-Scan';           File='Scan-Deep.ps1';        Info='AppInit, IFEO, LSA, Root-Zertifikate' }
)

# ========== FORM ==========
$form = New-Object Windows.Forms.Form
$form.Text = 'Trojacare'
$form.Size = New-Object Drawing.Size(960,720)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [Drawing.Color]::FromArgb(30,30,35)
$form.ForeColor = [Drawing.Color]::White
$form.Font = New-Object Drawing.Font('Segoe UI',10)
$form.MinimumSize = New-Object Drawing.Size(800,600)

$header = New-Object Windows.Forms.Label
$header.Text = 'TROJACARE'
$header.Font = New-Object Drawing.Font('Segoe UI',22,[Drawing.FontStyle]::Bold)
$header.ForeColor = [Drawing.Color]::FromArgb(100,200,255)
$header.Location = New-Object Drawing.Point(20,12)
$header.Size = New-Object Drawing.Size(400,40)
$form.Controls.Add($header)

$subtitle = New-Object Windows.Forms.Label
$subtitle.Text = 'Windows-Forensik-Scanner - prüft deinen PC auf Malware & Spuren'
$subtitle.Location = New-Object Drawing.Point(22,52)
$subtitle.Size = New-Object Drawing.Size(900,20)
$subtitle.ForeColor = [Drawing.Color]::Gray
$form.Controls.Add($subtitle)

# ========== TABS ==========
$tabs = New-Object Windows.Forms.TabControl
$tabs.Location = New-Object Drawing.Point(15,80)
$tabs.Size = New-Object Drawing.Size(915,590)
$tabs.Anchor = 'Top,Bottom,Left,Right'
$tabs.Font = New-Object Drawing.Font('Segoe UI',10)
$form.Controls.Add($tabs)

# ------ TAB 1: SCANS ------
$tabScan = New-Object Windows.Forms.TabPage
$tabScan.Text = '  Scans  '
$tabScan.BackColor = [Drawing.Color]::FromArgb(40,40,48)
$tabs.TabPages.Add($tabScan)

$y = 20; $buttons = @()
foreach ($s in $scans) {
    $btn = New-Object Windows.Forms.Button
    $btn.Text = $s.Name
    $btn.Location = New-Object Drawing.Point(20,$y)
    $btn.Size = New-Object Drawing.Size(240,40)
    $btn.BackColor = [Drawing.Color]::FromArgb(60,60,75)
    $btn.ForeColor = [Drawing.Color]::White
    $btn.FlatStyle = 'Flat'
    $btn.Font = New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)
    $btn.TextAlign = 'MiddleLeft'
    $btn.Padding = New-Object Windows.Forms.Padding(12,0,0,0)
    $btn.Tag = $s.File

    $lbl = New-Object Windows.Forms.Label
    $lbl.Text = $s.Info
    $lbl.Location = New-Object Drawing.Point(275,($y+11))
    $lbl.Size = New-Object Drawing.Size(620,20)
    $lbl.ForeColor = [Drawing.Color]::LightGray

    $tabScan.Controls.Add($btn)
    $tabScan.Controls.Add($lbl)
    $buttons += $btn
    $y += 55
}

$allBtn = New-Object Windows.Forms.Button
$allBtn.Text = '▶  ALLE Scans nacheinander'
$allBtn.Location = New-Object Drawing.Point(20,($y+10))
$allBtn.Size = New-Object Drawing.Size(875,45)
$allBtn.BackColor = [Drawing.Color]::FromArgb(30,140,70)
$allBtn.ForeColor = [Drawing.Color]::White
$allBtn.FlatStyle = 'Flat'
$allBtn.Font = New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
$allBtn.Anchor = 'Top,Left,Right'
$tabScan.Controls.Add($allBtn)

$logLabel = New-Object Windows.Forms.Label
$logLabel.Text = 'Live-Log:'
$logLabel.Location = New-Object Drawing.Point(20,($y+70))
$logLabel.Size = New-Object Drawing.Size(200,18)
$logLabel.ForeColor = [Drawing.Color]::Gray
$tabScan.Controls.Add($logLabel)

$output = New-Object Windows.Forms.RichTextBox
$output.Location = New-Object Drawing.Point(20,($y+92))
$output.Size = New-Object Drawing.Size(875,220)
$output.ScrollBars = 'Vertical'
$output.BackColor = [Drawing.Color]::FromArgb(15,15,20)
$output.ForeColor = [Drawing.Color]::LightGreen
$output.Font = New-Object Drawing.Font('Consolas',9)
$output.ReadOnly = $true
$output.Anchor = 'Top,Bottom,Left,Right'
$output.DetectUrls = $false
$tabScan.Controls.Add($output)

$statusLabel = New-Object Windows.Forms.Label
$statusLabel.Text = 'Bereit. Wähle einen Scan.'
$statusLabel.Location = New-Object Drawing.Point(20,($y+320))
$statusLabel.Size = New-Object Drawing.Size(600,22)
$statusLabel.ForeColor = [Drawing.Color]::Gray
$statusLabel.Anchor = 'Bottom,Left'
$tabScan.Controls.Add($statusLabel)

# ------ TAB 2: BERICHTE ------
$tabReport = New-Object Windows.Forms.TabPage
$tabReport.Text = '  Berichte  '
$tabReport.BackColor = [Drawing.Color]::FromArgb(40,40,48)
$tabs.TabPages.Add($tabReport)

$reportLabel = New-Object Windows.Forms.Label
$reportLabel.Text = 'Bericht auswählen:'
$reportLabel.Location = New-Object Drawing.Point(20,20)
$reportLabel.Size = New-Object Drawing.Size(200,20)
$reportLabel.ForeColor = [Drawing.Color]::LightGray
$tabReport.Controls.Add($reportLabel)

$reportCombo = New-Object Windows.Forms.ComboBox
$reportCombo.Location = New-Object Drawing.Point(20,42)
$reportCombo.Size = New-Object Drawing.Size(600,25)
$reportCombo.DropDownStyle = 'DropDownList'
$reportCombo.BackColor = [Drawing.Color]::FromArgb(60,60,75)
$reportCombo.ForeColor = [Drawing.Color]::White
$tabReport.Controls.Add($reportCombo)

$refreshBtn = New-Object Windows.Forms.Button
$refreshBtn.Text = '⟳ Aktualisieren'
$refreshBtn.Location = New-Object Drawing.Point(630,41)
$refreshBtn.Size = New-Object Drawing.Size(130,27)
$refreshBtn.BackColor = [Drawing.Color]::FromArgb(60,60,75)
$refreshBtn.ForeColor = [Drawing.Color]::White
$refreshBtn.FlatStyle = 'Flat'
$tabReport.Controls.Add($refreshBtn)

$openFolderBtn = New-Object Windows.Forms.Button
$openFolderBtn.Text = '📁 Ordner'
$openFolderBtn.Location = New-Object Drawing.Point(770,41)
$openFolderBtn.Size = New-Object Drawing.Size(125,27)
$openFolderBtn.BackColor = [Drawing.Color]::FromArgb(60,60,75)
$openFolderBtn.ForeColor = [Drawing.Color]::White
$openFolderBtn.FlatStyle = 'Flat'
$openFolderBtn.Anchor = 'Top,Right'
$tabReport.Controls.Add($openFolderBtn)

# Sub-Tabs innerhalb Berichte
$reportTabs = New-Object Windows.Forms.TabControl
$reportTabs.Location = New-Object Drawing.Point(20,80)
$reportTabs.Size = New-Object Drawing.Size(875,470)
$reportTabs.Anchor = 'Top,Bottom,Left,Right'
$tabReport.Controls.Add($reportTabs)

$summaryTab = New-Object Windows.Forms.TabPage
$summaryTab.Text = '  Zusammenfassung  '
$summaryTab.BackColor = [Drawing.Color]::FromArgb(40,40,48)
$reportTabs.TabPages.Add($summaryTab)

$summaryView = New-Object Windows.Forms.RichTextBox
$summaryView.Dock = 'Fill'
$summaryView.BackColor = [Drawing.Color]::FromArgb(22,22,28)
$summaryView.ForeColor = [Drawing.Color]::White
$summaryView.Font = New-Object Drawing.Font('Consolas',10)
$summaryView.ReadOnly = $true
$summaryView.DetectUrls = $false
$summaryTab.Controls.Add($summaryView)

$findingsTab = New-Object Windows.Forms.TabPage
$findingsTab.Text = '  Funde (CSV)  '
$findingsTab.BackColor = [Drawing.Color]::FromArgb(40,40,48)
$reportTabs.TabPages.Add($findingsTab)

$findingsGrid = New-Object Windows.Forms.DataGridView
$findingsGrid.Dock = 'Fill'
$findingsGrid.BackgroundColor = [Drawing.Color]::FromArgb(22,22,28)
$findingsGrid.ForeColor = [Drawing.Color]::White
$findingsGrid.GridColor = [Drawing.Color]::FromArgb(60,60,75)
$findingsGrid.AlternatingRowsDefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(28,28,36)
$findingsGrid.DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(22,22,28)
$findingsGrid.DefaultCellStyle.ForeColor = [Drawing.Color]::White
$findingsGrid.DefaultCellStyle.SelectionBackColor = [Drawing.Color]::FromArgb(60,120,180)
$findingsGrid.ColumnHeadersDefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(60,60,75)
$findingsGrid.ColumnHeadersDefaultCellStyle.ForeColor = [Drawing.Color]::White
$findingsGrid.EnableHeadersVisualStyles = $false
$findingsGrid.ReadOnly = $true
$findingsGrid.AutoSizeColumnsMode = 'Fill'
$findingsGrid.AllowUserToAddRows = $false
$findingsGrid.RowHeadersVisible = $false
$findingsTab.Controls.Add($findingsGrid)

$filesTab = New-Object Windows.Forms.TabPage
$filesTab.Text = '  Alle Dateien  '
$filesTab.BackColor = [Drawing.Color]::FromArgb(40,40,48)
$reportTabs.TabPages.Add($filesTab)

$filesList = New-Object Windows.Forms.ListBox
$filesList.Dock = 'Top'
$filesList.Height = 150
$filesList.BackColor = [Drawing.Color]::FromArgb(22,22,28)
$filesList.ForeColor = [Drawing.Color]::White
$filesList.Font = New-Object Drawing.Font('Consolas',9)
$filesList.BorderStyle = 'None'
$filesTab.Controls.Add($filesList)

$fileContent = New-Object Windows.Forms.RichTextBox
$fileContent.Dock = 'Fill'
$fileContent.BackColor = [Drawing.Color]::FromArgb(22,22,28)
$fileContent.ForeColor = [Drawing.Color]::White
$fileContent.Font = New-Object Drawing.Font('Consolas',9)
$fileContent.ReadOnly = $true
$fileContent.DetectUrls = $false
$fileContent.WordWrap = $false
$fileContent.ScrollBars = 'Both'
$filesTab.Controls.Add($fileContent)

# ========== LOGIK ==========
function Write-Log($msg, $color='LightGreen') {
    $output.SelectionStart = $output.TextLength
    $output.SelectionLength = 0
    try { $output.SelectionColor = [Drawing.Color]::$color } catch {}
    $output.AppendText("$(Get-Date -f 'HH:mm:ss')  $msg`r`n")
    $output.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

function Refresh-Reports {
    $reportCombo.Items.Clear()
    if (-not (Test-Path $reportsRoot)) { return }
    $dirs = Get-ChildItem $reportsRoot -Directory | Sort-Object LastWriteTime -Descending
    foreach ($d in $dirs) {
        $label = "{0}  -  {1}" -f $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $d.Name
        [void]$reportCombo.Items.Add($label)
        $reportCombo.Tag = @($reportCombo.Tag) + $d.FullName
    }
    if ($reportCombo.Items.Count -gt 0) {
        $reportCombo.SelectedIndex = 0
    }
}

function Load-Report($path) {
    # Summary
    $summaryView.Clear()
    $summaryFile = Join-Path $path 'SUMMARY.txt'
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile -Raw -Encoding UTF8
        $summaryView.Text = $content

        # Severity-Zeilen einfärben
        $lines = $content -split "`n"
        $offset = 0
        foreach ($line in $lines) {
            $len = $line.Length + 1
            if ($line -match 'CRIT') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(255,80,80)
                $summaryView.SelectionFont = New-Object Drawing.Font('Consolas',10,[Drawing.FontStyle]::Bold)
            } elseif ($line -match '\bHIGH\b') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::Orange
            } elseif ($line -match '\bMED\b') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::Gold
            } elseif ($line -match '===|---') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(100,200,255)
            }
            $offset += $len
        }
        $summaryView.Select(0,0)
    } else {
        $summaryView.Text = "(Keine SUMMARY.txt in diesem Report)"
    }

    # Findings als Tabelle
    $findingsGrid.DataSource = $null
    $findingsFile = Join-Path $path 'findings.csv'
    if (Test-Path $findingsFile) {
        try {
            $csv = Import-Csv $findingsFile -Encoding UTF8
            if ($csv) {
                $dt = New-Object System.Data.DataTable
                foreach ($col in $csv[0].PSObject.Properties.Name) { [void]$dt.Columns.Add($col) }
                foreach ($row in $csv) {
                    $dr = $dt.NewRow()
                    foreach ($col in $dt.Columns) { $dr[$col.ColumnName] = [string]$row.$($col.ColumnName) }
                    $dt.Rows.Add($dr)
                }
                $findingsGrid.DataSource = $dt

                # Severity-Spalte farblich markieren
                if ($findingsGrid.Columns['Severity']) {
                    foreach ($row in $findingsGrid.Rows) {
                        $sev = $row.Cells['Severity'].Value
                        $color = switch ($sev) {
                            'CRIT' { [Drawing.Color]::FromArgb(100,20,20) }
                            'HIGH' { [Drawing.Color]::FromArgb(100,60,0) }
                            'MED'  { [Drawing.Color]::FromArgb(80,70,0) }
                            default { $null }
                        }
                        if ($color) { $row.DefaultCellStyle.BackColor = $color }
                    }
                }
            }
        } catch {
            $findingsGrid.DataSource = $null
        }
    }

    # Alle Dateien im Report-Ordner
    $filesList.Items.Clear()
    Get-ChildItem $path -File | Sort-Object Name | ForEach-Object {
        [void]$filesList.Items.Add($_.Name)
    }
    $filesList.Tag = $path
    $fileContent.Clear()
}

$reportCombo.Add_SelectedIndexChanged({
    $idx = $reportCombo.SelectedIndex
    if ($idx -lt 0) { return }
    $paths = @($reportCombo.Tag)
    if ($idx -lt $paths.Count) {
        Load-Report $paths[$idx]
    }
})

$filesList.Add_SelectedIndexChanged({
    if ($filesList.SelectedItem -and $filesList.Tag) {
        $fp = Join-Path $filesList.Tag $filesList.SelectedItem
        if (Test-Path $fp) {
            try {
                $fileContent.Text = Get-Content $fp -Raw -Encoding UTF8
            } catch {
                $fileContent.Text = "(Datei kann nicht gelesen werden: $_)"
            }
        }
    }
})

$refreshBtn.Add_Click({ Refresh-Reports })
$openFolderBtn.Add_Click({ Start-Process explorer.exe $reportsRoot })

function Invoke-ScanFile($file) {
    $path = Join-Path $workDir $file
    if (-not (Test-Path $path)) { Write-Log "FEHLT: $file" 'Red'; return }
    $statusLabel.Text = "Scan läuft: $file ..."
    Write-Log "Starte $file"
    try {
        & $path -OutputRoot $reportsRoot *>&1 | ForEach-Object {
            $line = $_.ToString()
            if ($line.Trim()) { Write-Log $line }
        }
        Write-Log "Fertig: $file" 'Cyan'
    } catch { Write-Log "Fehler: $_" 'Red' }
    $statusLabel.Text = 'Bereit.'
    Refresh-Reports
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
    $tabs.SelectedTab = $tabReport
})

try { Add-MpPreference -ExclusionPath $workDir -ErrorAction Stop } catch {}

$form.Add_FormClosing({
    try { Remove-MpPreference -ExclusionPath $workDir -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
})

Write-Log "Trojacare bereit. Reports: $reportsRoot"
Refresh-Reports
[void]$form.ShowDialog()
'@

$standaloneGui = $standaloneGui -replace '__EMBEDDED_BLOCK__', $embeddedBlock

$tempScript = Join-Path $scriptDir '_trojacare-standalone.ps1'
# UTF-8 mit BOM damit ps2exe korrekt liest
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($tempScript, $standaloneGui, $utf8Bom)

Write-Host ''
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
    Write-Host 'Standalone - keine weiteren Dateien noetig.' -ForegroundColor Green
} else {
    Write-Host 'Build fehlgeschlagen.' -ForegroundColor Red
}
