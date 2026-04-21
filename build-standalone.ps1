<#
.SYNOPSIS
  Baut Trojacare.exe - standalone, alle Scan-Scripts eingebettet.
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

# Pure-ASCII Script - Umlaute werden zur Laufzeit aus [char]-Codes gebaut
$standaloneGui = @'
#Requires -RunAsAdministrator

# Unicode-Zeichen zur Laufzeit konstruieren (ASCII-safe fuer ps2exe)
$UE = [char]0x00FC  # ü
$AE = [char]0x00E4  # ä
$OE = [char]0x00F6  # ö
$SZ = [char]0x00DF  # ß
$ARROW = [char]0x25B6 + ' '  # ▶
$REFRESH = [char]0x21BB + ' '  # ↻

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

# Execution Policy fuer diesen Prozess auf Bypass (damit eingebettete Scripts laufen)
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue } catch {}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

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

# Texte mit Umlauten
$subtitleText = "Windows-Forensik-Scanner $([char]0x2022) pr${UE}ft deinen PC auf Malware und Spuren"
$readyText = "Bereit. W${AE}hle einen Scan."
$allBtnText = "${ARROW} ALLE Scans nacheinander starten"
$refreshText = "${REFRESH} Aktualisieren"
$folderText = "Report-Ordner ${OE}ffnen"

$scans = @(
    @{ Name='Netzwerk-Scan';          File='Scan-Connections.ps1'; Info='Verbindungen, Ports, Autostart, DNS-Cache';       Duration='~30 Sek' }
    @{ Name='Stealth-Scan';           File='Scan-Stealth.ps1';     Info='Rootkit-Hinweise, WMI-Persistenz, Sideloading';    Duration='~1-2 Min' }
    @{ Name="Forensics (30 Tage)";    File='Scan-Forensics.ps1';   Info='PC an/aus, Logons, USB-Historie, Prefetch';        Duration='~2-3 Min' }
    @{ Name='Deep-Scan';              File='Scan-Deep.ps1';        Info='AppInit, IFEO, LSA, Root-Zertifikate';             Duration='~3-5 Min' }
)

# ========== FARBEN ==========
$C_BG      = [Drawing.Color]::FromArgb(28,30,38)
$C_PANEL   = [Drawing.Color]::FromArgb(38,42,52)
$C_PANEL2  = [Drawing.Color]::FromArgb(45,50,62)
$C_ACCENT  = [Drawing.Color]::FromArgb(100,180,255)
$C_GREEN   = [Drawing.Color]::FromArgb(50,160,90)
$C_TEXT    = [Drawing.Color]::FromArgb(235,235,240)
$C_MUTED   = [Drawing.Color]::FromArgb(150,155,165)
$C_BORDER  = [Drawing.Color]::FromArgb(70,75,90)

# ========== FORM ==========
$form = New-Object Windows.Forms.Form
$form.Text = 'Trojacare'
$form.Size = New-Object Drawing.Size(1000,740)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $C_BG
$form.ForeColor = $C_TEXT
$form.Font = New-Object Drawing.Font('Segoe UI',10)
$form.MinimumSize = New-Object Drawing.Size(900,620)

# Header-Panel mit Farbverlauf-Effekt
$headerPanel = New-Object Windows.Forms.Panel
$headerPanel.Location = New-Object Drawing.Point(0,0)
$headerPanel.Size = New-Object Drawing.Size(1000,90)
$headerPanel.BackColor = [Drawing.Color]::FromArgb(22,25,32)
$headerPanel.Anchor = 'Top,Left,Right'
$form.Controls.Add($headerPanel)

$header = New-Object Windows.Forms.Label
$header.Text = 'TROJACARE'
$header.Font = New-Object Drawing.Font('Segoe UI Semibold',24,[Drawing.FontStyle]::Bold)
$header.ForeColor = $C_ACCENT
$header.Location = New-Object Drawing.Point(25,15)
$header.Size = New-Object Drawing.Size(400,40)
$header.BackColor = [Drawing.Color]::Transparent
$headerPanel.Controls.Add($header)

$subtitle = New-Object Windows.Forms.Label
$subtitle.Text = $subtitleText
$subtitle.Location = New-Object Drawing.Point(27,55)
$subtitle.Size = New-Object Drawing.Size(700,22)
$subtitle.ForeColor = $C_MUTED
$subtitle.BackColor = [Drawing.Color]::Transparent
$subtitle.Font = New-Object Drawing.Font('Segoe UI',10)
$headerPanel.Controls.Add($subtitle)

$authorLabel = New-Object Windows.Forms.Label
$authorLabel.Text = "by MaxiSlibar $([char]0x2022) v1.0 $([char]0x2022) MIT"
$authorLabel.Location = New-Object Drawing.Point(780,60)
$authorLabel.Size = New-Object Drawing.Size(200,18)
$authorLabel.ForeColor = $C_MUTED
$authorLabel.BackColor = [Drawing.Color]::Transparent
$authorLabel.TextAlign = 'MiddleRight'
$authorLabel.Anchor = 'Top,Right'
$authorLabel.Font = New-Object Drawing.Font('Segoe UI',8)
$headerPanel.Controls.Add($authorLabel)

# ========== TABS ==========
$tabs = New-Object Windows.Forms.TabControl
$tabs.Location = New-Object Drawing.Point(15,100)
$tabs.Size = New-Object Drawing.Size(955,595)
$tabs.Anchor = 'Top,Bottom,Left,Right'
$tabs.Font = New-Object Drawing.Font('Segoe UI',10)
$tabs.Padding = New-Object Drawing.Point(15,6)
$form.Controls.Add($tabs)

# ------ TAB 1: SCANS ------
$tabScan = New-Object Windows.Forms.TabPage
$tabScan.Text = 'Scans'
$tabScan.BackColor = $C_PANEL
$tabScan.Padding = New-Object Windows.Forms.Padding(10)
$tabs.TabPages.Add($tabScan)

$y = 20; $buttons = @()
foreach ($s in $scans) {
    $card = New-Object Windows.Forms.Panel
    $card.Location = New-Object Drawing.Point(15,$y)
    $card.Size = New-Object Drawing.Size(910,55)
    $card.BackColor = $C_PANEL2
    $card.Anchor = 'Top,Left,Right'
    $tabScan.Controls.Add($card)

    $btn = New-Object Windows.Forms.Button
    $btn.Text = $s.Name
    $btn.Location = New-Object Drawing.Point(0,0)
    $btn.Size = New-Object Drawing.Size(250,55)
    $btn.BackColor = [Drawing.Color]::FromArgb(55,65,85)
    $btn.ForeColor = $C_TEXT
    $btn.FlatStyle = 'Flat'
    $btn.FlatAppearance.BorderSize = 0
    $btn.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(70,90,120)
    $btn.Font = New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
    $btn.TextAlign = 'MiddleCenter'
    $btn.Cursor = 'Hand'
    $btn.Tag = $s.File
    $card.Controls.Add($btn)

    $lbl = New-Object Windows.Forms.Label
    $lbl.Text = $s.Info
    $lbl.Location = New-Object Drawing.Point(265,10)
    $lbl.Size = New-Object Drawing.Size(530,20)
    $lbl.ForeColor = $C_MUTED
    $lbl.Font = New-Object Drawing.Font('Segoe UI',10)
    $card.Controls.Add($lbl)

    $durLbl = New-Object Windows.Forms.Label
    $durLbl.Text = "Dauer: $($s.Duration)"
    $durLbl.Location = New-Object Drawing.Point(265,30)
    $durLbl.Size = New-Object Drawing.Size(300,18)
    $durLbl.ForeColor = [Drawing.Color]::FromArgb(120,180,220)
    $durLbl.Font = New-Object Drawing.Font('Segoe UI',9,[Drawing.FontStyle]::Italic)
    $card.Controls.Add($durLbl)

    $buttons += $btn
    $y += 65
}

$allBtn = New-Object Windows.Forms.Button
$allBtn.Text = "$allBtnText  (~7-11 Min insgesamt)"
$allBtn.Location = New-Object Drawing.Point(15,($y+10))
$allBtn.Size = New-Object Drawing.Size(910,50)
$allBtn.BackColor = $C_GREEN
$allBtn.ForeColor = [Drawing.Color]::White
$allBtn.FlatStyle = 'Flat'
$allBtn.FlatAppearance.BorderSize = 0
$allBtn.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(65,180,105)
$allBtn.Font = New-Object Drawing.Font('Segoe UI',12,[Drawing.FontStyle]::Bold)
$allBtn.Cursor = 'Hand'
$allBtn.Anchor = 'Top,Left,Right'
$tabScan.Controls.Add($allBtn)

$logLabel = New-Object Windows.Forms.Label
$logLabel.Text = 'Live-Log'
$logLabel.Location = New-Object Drawing.Point(15,($y+75))
$logLabel.Size = New-Object Drawing.Size(200,18)
$logLabel.ForeColor = $C_MUTED
$logLabel.Font = New-Object Drawing.Font('Segoe UI',9)
$tabScan.Controls.Add($logLabel)

$output = New-Object Windows.Forms.RichTextBox
$output.Location = New-Object Drawing.Point(15,($y+95))
$output.Size = New-Object Drawing.Size(910,200)
$output.ScrollBars = 'Vertical'
$output.BackColor = [Drawing.Color]::FromArgb(15,18,24)
$output.ForeColor = [Drawing.Color]::FromArgb(120,220,140)
$output.Font = New-Object Drawing.Font('Consolas',9)
$output.ReadOnly = $true
$output.Anchor = 'Top,Bottom,Left,Right'
$output.DetectUrls = $false
$output.BorderStyle = 'FixedSingle'
$tabScan.Controls.Add($output)

$statusLabel = New-Object Windows.Forms.Label
$statusLabel.Text = $readyText
$statusLabel.Location = New-Object Drawing.Point(15,($y+305))
$statusLabel.Size = New-Object Drawing.Size(600,22)
$statusLabel.ForeColor = $C_MUTED
$statusLabel.Anchor = 'Bottom,Left'
$tabScan.Controls.Add($statusLabel)

# ------ TAB 2: BERICHTE ------
$tabReport = New-Object Windows.Forms.TabPage
$tabReport.Text = 'Berichte'
$tabReport.BackColor = $C_PANEL
$tabReport.Padding = New-Object Windows.Forms.Padding(10)
$tabs.TabPages.Add($tabReport)

$reportLabel = New-Object Windows.Forms.Label
$reportLabel.Text = "Bericht ausw${AE}hlen:"
$reportLabel.Location = New-Object Drawing.Point(15,15)
$reportLabel.Size = New-Object Drawing.Size(200,20)
$reportLabel.ForeColor = $C_TEXT
$reportLabel.Font = New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)
$tabReport.Controls.Add($reportLabel)

$reportCombo = New-Object Windows.Forms.ComboBox
$reportCombo.Location = New-Object Drawing.Point(15,38)
$reportCombo.Size = New-Object Drawing.Size(640,26)
$reportCombo.DropDownStyle = 'DropDownList'
$reportCombo.BackColor = $C_PANEL2
$reportCombo.ForeColor = $C_TEXT
$reportCombo.FlatStyle = 'Flat'
$reportCombo.Font = New-Object Drawing.Font('Segoe UI',10)
$tabReport.Controls.Add($reportCombo)

$refreshBtn = New-Object Windows.Forms.Button
$refreshBtn.Text = $refreshText
$refreshBtn.Location = New-Object Drawing.Point(665,37)
$refreshBtn.Size = New-Object Drawing.Size(130,28)
$refreshBtn.BackColor = $C_PANEL2
$refreshBtn.ForeColor = $C_TEXT
$refreshBtn.FlatStyle = 'Flat'
$refreshBtn.FlatAppearance.BorderColor = $C_BORDER
$refreshBtn.Cursor = 'Hand'
$tabReport.Controls.Add($refreshBtn)

$openFolderBtn = New-Object Windows.Forms.Button
$openFolderBtn.Text = $folderText
$openFolderBtn.Location = New-Object Drawing.Point(800,37)
$openFolderBtn.Size = New-Object Drawing.Size(140,28)
$openFolderBtn.BackColor = $C_PANEL2
$openFolderBtn.ForeColor = $C_TEXT
$openFolderBtn.FlatStyle = 'Flat'
$openFolderBtn.FlatAppearance.BorderColor = $C_BORDER
$openFolderBtn.Anchor = 'Top,Right'
$openFolderBtn.Cursor = 'Hand'
$tabReport.Controls.Add($openFolderBtn)

$reportTabs = New-Object Windows.Forms.TabControl
$reportTabs.Location = New-Object Drawing.Point(15,78)
$reportTabs.Size = New-Object Drawing.Size(925,485)
$reportTabs.Anchor = 'Top,Bottom,Left,Right'
$tabReport.Controls.Add($reportTabs)

$summaryTab = New-Object Windows.Forms.TabPage
$summaryTab.Text = 'Zusammenfassung'
$summaryTab.BackColor = $C_PANEL
$reportTabs.TabPages.Add($summaryTab)

$summaryView = New-Object Windows.Forms.RichTextBox
$summaryView.Dock = 'Fill'
$summaryView.BackColor = [Drawing.Color]::FromArgb(20,22,28)
$summaryView.ForeColor = $C_TEXT
$summaryView.Font = New-Object Drawing.Font('Consolas',10)
$summaryView.ReadOnly = $true
$summaryView.DetectUrls = $false
$summaryView.BorderStyle = 'None'
$summaryTab.Controls.Add($summaryView)

$findingsTab = New-Object Windows.Forms.TabPage
$findingsTab.Text = 'Funde'
$findingsTab.BackColor = $C_PANEL
$reportTabs.TabPages.Add($findingsTab)

$findingsGrid = New-Object Windows.Forms.DataGridView
$findingsGrid.Dock = 'Fill'
$findingsGrid.BackgroundColor = [Drawing.Color]::FromArgb(20,22,28)
$findingsGrid.ForeColor = $C_TEXT
$findingsGrid.GridColor = $C_BORDER
$findingsGrid.BorderStyle = 'None'
$findingsGrid.AlternatingRowsDefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(28,32,40)
$findingsGrid.DefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(22,25,32)
$findingsGrid.DefaultCellStyle.ForeColor = $C_TEXT
$findingsGrid.DefaultCellStyle.SelectionBackColor = [Drawing.Color]::FromArgb(60,120,180)
$findingsGrid.DefaultCellStyle.SelectionForeColor = [Drawing.Color]::White
$findingsGrid.ColumnHeadersDefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(50,55,70)
$findingsGrid.ColumnHeadersDefaultCellStyle.ForeColor = $C_TEXT
$findingsGrid.ColumnHeadersDefaultCellStyle.Font = New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)
$findingsGrid.ColumnHeadersHeight = 32
$findingsGrid.RowTemplate.Height = 26
$findingsGrid.EnableHeadersVisualStyles = $false
$findingsGrid.ReadOnly = $true
$findingsGrid.AutoSizeColumnsMode = 'Fill'
$findingsGrid.AllowUserToAddRows = $false
$findingsGrid.RowHeadersVisible = $false
$findingsGrid.Font = New-Object Drawing.Font('Segoe UI',9)
$findingsTab.Controls.Add($findingsGrid)

$filesTab = New-Object Windows.Forms.TabPage
$filesTab.Text = 'Alle Dateien'
$filesTab.BackColor = $C_PANEL
$reportTabs.TabPages.Add($filesTab)

$split = New-Object Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Horizontal'
$split.SplitterDistance = 150
$split.BackColor = $C_PANEL
$split.Panel1.BackColor = [Drawing.Color]::FromArgb(20,22,28)
$split.Panel2.BackColor = [Drawing.Color]::FromArgb(20,22,28)
$filesTab.Controls.Add($split)

$filesList = New-Object Windows.Forms.ListBox
$filesList.Dock = 'Fill'
$filesList.BackColor = [Drawing.Color]::FromArgb(20,22,28)
$filesList.ForeColor = $C_TEXT
$filesList.Font = New-Object Drawing.Font('Consolas',9)
$filesList.BorderStyle = 'None'
$split.Panel1.Controls.Add($filesList)

$fileContent = New-Object Windows.Forms.RichTextBox
$fileContent.Dock = 'Fill'
$fileContent.BackColor = [Drawing.Color]::FromArgb(20,22,28)
$fileContent.ForeColor = $C_TEXT
$fileContent.Font = New-Object Drawing.Font('Consolas',9)
$fileContent.ReadOnly = $true
$fileContent.DetectUrls = $false
$fileContent.WordWrap = $false
$fileContent.ScrollBars = 'Both'
$fileContent.BorderStyle = 'None'
$split.Panel2.Controls.Add($fileContent)

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
    $reportCombo.Tag = @()
    if (-not (Test-Path $reportsRoot)) { return }
    $dirs = Get-ChildItem $reportsRoot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    $paths = @()
    foreach ($d in $dirs) {
        $label = '{0}   -   {1}' -f $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $d.Name
        [void]$reportCombo.Items.Add($label)
        $paths += $d.FullName
    }
    $reportCombo.Tag = $paths
    if ($reportCombo.Items.Count -gt 0) { $reportCombo.SelectedIndex = 0 }
}

function Load-Report($path) {
    $summaryView.Clear()
    $summaryFile = Join-Path $path 'SUMMARY.txt'
    if (Test-Path $summaryFile) {
        $content = Get-Content $summaryFile -Raw -Encoding UTF8
        $summaryView.Text = $content
        $lines = $content -split "`n"
        $offset = 0
        foreach ($line in $lines) {
            $len = $line.Length + 1
            if ($line -match '\bCRIT\b') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(255,90,90)
                $summaryView.SelectionFont = New-Object Drawing.Font('Consolas',10,[Drawing.FontStyle]::Bold)
            } elseif ($line -match '\bHIGH\b') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(255,160,80)
            } elseif ($line -match '\bMED\b') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(230,200,80)
            } elseif ($line -match '===') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(100,200,255)
                $summaryView.SelectionFont = New-Object Drawing.Font('Consolas',10,[Drawing.FontStyle]::Bold)
            } elseif ($line -match '---') {
                $summaryView.Select($offset, $len)
                $summaryView.SelectionColor = [Drawing.Color]::FromArgb(120,170,210)
            }
            $offset += $len
        }
        $summaryView.Select(0,0)
    } else {
        $summaryView.Text = "(Keine SUMMARY.txt in diesem Report)"
    }

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
                if ($findingsGrid.Columns['Severity']) {
                    foreach ($row in $findingsGrid.Rows) {
                        $sev = $row.Cells['Severity'].Value
                        $color = switch ($sev) {
                            'CRIT' { [Drawing.Color]::FromArgb(110,30,30) }
                            'HIGH' { [Drawing.Color]::FromArgb(100,60,20) }
                            'MED'  { [Drawing.Color]::FromArgb(80,70,20) }
                            default { $null }
                        }
                        if ($color) { $row.DefaultCellStyle.BackColor = $color }
                    }
                }
            }
        } catch {}
    }

    $filesList.Items.Clear()
    Get-ChildItem $path -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
        [void]$filesList.Items.Add($_.Name)
    }
    $filesList.Tag = $path
    $fileContent.Clear()
}

$reportCombo.Add_SelectedIndexChanged({
    $idx = $reportCombo.SelectedIndex
    if ($idx -lt 0) { return }
    $paths = @($reportCombo.Tag)
    if ($idx -lt $paths.Count) { Load-Report $paths[$idx] }
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
    $statusLabel.Text = "Scan l${AE}uft: $file ..."
    Write-Log "Starte $file"
    try {
        # Script als ScriptBlock laden - umgeht ExecutionPolicy komplett
        $content = Get-Content -Raw -LiteralPath $path -Encoding UTF8
        $sb = [ScriptBlock]::Create($content)
        & $sb -OutputRoot $reportsRoot *>&1 | ForEach-Object {
            $line = $_.ToString()
            if ($line.Trim()) { Write-Log $line }
        }
        Write-Log "Fertig: $file" 'Cyan'
    } catch { Write-Log "Fehler: $_" 'Red' }
    $statusLabel.Text = $readyText
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

Write-Log "Trojacare bereit."
Write-Log "Reports werden gespeichert in: $reportsRoot"
Refresh-Reports
[void]$form.ShowDialog()
'@

$standaloneGui = $standaloneGui -replace '__EMBEDDED_BLOCK__', $embeddedBlock

$tempScript = Join-Path $scriptDir '_trojacare-standalone.ps1'
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
    -Description 'Windows-Forensik-Scanner - Malware, Rootkits, Persistenz, Spurenanalyse' `
    -Company 'MaxiSlibar' `
    -Copyright '(c) 2026 MaxiSlibar - MIT Lizenz' `
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
