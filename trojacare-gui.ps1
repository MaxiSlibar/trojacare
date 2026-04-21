<#
.SYNOPSIS
  Trojacare GUI - Punkt-und-Klick-Forensik-Scanner fuer Nicht-Techniker.
.DESCRIPTION
  WinForms GUI. Startet die Scan-Scripts per Knopfdruck, elevatet sich selbst,
  managed Defender-Exclusion automatisch, oeffnet Report-Ordner am Ende.
#>

# --- Self-elevate ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# --- Scan-Definitionen ---
$scans = @(
    @{ Name='1. Netzwerk-Scan';      File='Scan-Connections.ps1'; Info='Wer verbindet sich wohin? Autostart-Programme, lauschende Ports, DNS-Cache.' }
    @{ Name='2. Stealth-Scan';       File='Scan-Stealth.ps1';     Info='Versteckte Malware, Rootkit-Hinweise, WMI-Persistenz, DLL-Injektion.' }
    @{ Name='3. Forensics (30 Tage)';File='Scan-Forensics.ps1';   Info='Wann war der PC an? Wer war eingeloggt? Welche USB-Sticks wurden gesteckt?' }
    @{ Name='4. Deep-Scan';          File='Scan-Deep.ps1';        Info='Tiefe Persistenz-Checks: AppInit-DLLs, IFEO, LSA, Root-Zertifikate (MitM-Check).' }
)

# --- Form ---
$form              = New-Object Windows.Forms.Form
$form.Text         = 'Trojacare - Forensik-Scanner'
$form.Size         = New-Object Drawing.Size(720,580)
$form.StartPosition= 'CenterScreen'
$form.BackColor    = [Drawing.Color]::FromArgb(30,30,35)
$form.ForeColor    = [Drawing.Color]::White
$form.Font         = New-Object Drawing.Font('Segoe UI',10)
$form.MinimumSize  = $form.Size

# --- Header ---
$header          = New-Object Windows.Forms.Label
$header.Text     = 'TROJACARE'
$header.Font     = New-Object Drawing.Font('Segoe UI',20,[Drawing.FontStyle]::Bold)
$header.ForeColor= [Drawing.Color]::FromArgb(100,200,255)
$header.Location = New-Object Drawing.Point(20,15)
$header.Size     = New-Object Drawing.Size(400,40)
$form.Controls.Add($header)

$subtitle          = New-Object Windows.Forms.Label
$subtitle.Text     = 'Prueft deinen Windows-PC auf Malware und forensische Spuren'
$subtitle.Location = New-Object Drawing.Point(22,55)
$subtitle.Size     = New-Object Drawing.Size(680,20)
$subtitle.ForeColor= [Drawing.Color]::Gray
$form.Controls.Add($subtitle)

# --- Scan-Buttons mit Info ---
$y = 95
$buttons = @()
foreach ($s in $scans) {
    $btn              = New-Object Windows.Forms.Button
    $btn.Text         = $s.Name
    $btn.Location     = New-Object Drawing.Point(20,$y)
    $btn.Size         = New-Object Drawing.Size(220,35)
    $btn.BackColor    = [Drawing.Color]::FromArgb(45,45,55)
    $btn.ForeColor    = [Drawing.Color]::White
    $btn.FlatStyle    = 'Flat'
    $btn.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(80,80,90)
    $btn.TextAlign    = 'MiddleLeft'
    $btn.Padding      = New-Object Windows.Forms.Padding(10,0,0,0)
    $btn.Tag          = $s.File

    $lbl            = New-Object Windows.Forms.Label
    $lbl.Text       = $s.Info
    $lbl.Location   = New-Object Drawing.Point(250,($y+8))
    $lbl.Size       = New-Object Drawing.Size(440,40)
    $lbl.ForeColor  = [Drawing.Color]::LightGray

    $form.Controls.Add($btn)
    $form.Controls.Add($lbl)
    $buttons += $btn
    $y += 50
}

# --- Alle-Scannen-Button ---
$allBtn = New-Object Windows.Forms.Button
$allBtn.Text      = 'ALLE Scans nacheinander starten'
$allBtn.Location  = New-Object Drawing.Point(20,($y+10))
$allBtn.Size      = New-Object Drawing.Size(670,40)
$allBtn.BackColor = [Drawing.Color]::FromArgb(30,120,60)
$allBtn.ForeColor = [Drawing.Color]::White
$allBtn.FlatStyle = 'Flat'
$allBtn.Font      = New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
$form.Controls.Add($allBtn)

# --- Output-Box ---
$output              = New-Object Windows.Forms.TextBox
$output.Location     = New-Object Drawing.Point(20,($y+60))
$output.Size         = New-Object Drawing.Size(670,200)
$output.Multiline    = $true
$output.ScrollBars   = 'Vertical'
$output.BackColor    = [Drawing.Color]::FromArgb(15,15,20)
$output.ForeColor    = [Drawing.Color]::LightGreen
$output.Font         = New-Object Drawing.Font('Consolas',9)
$output.ReadOnly     = $true
$output.Anchor       = 'Top,Bottom,Left,Right'
$form.Controls.Add($output)

# --- Status + Report-Button ---
$statusLabel          = New-Object Windows.Forms.Label
$statusLabel.Text     = 'Bereit. Waehle einen Scan.'
$statusLabel.Location = New-Object Drawing.Point(20,($y+275))
$statusLabel.Size     = New-Object Drawing.Size(450,20)
$statusLabel.ForeColor= [Drawing.Color]::Gray
$statusLabel.Anchor   = 'Bottom,Left'
$form.Controls.Add($statusLabel)

$openBtn            = New-Object Windows.Forms.Button
$openBtn.Text       = 'Report-Ordner oeffnen'
$openBtn.Location   = New-Object Drawing.Point(480,($y+270))
$openBtn.Size       = New-Object Drawing.Size(210,30)
$openBtn.BackColor  = [Drawing.Color]::FromArgb(45,45,55)
$openBtn.ForeColor  = [Drawing.Color]::White
$openBtn.FlatStyle  = 'Flat'
$openBtn.Anchor     = 'Bottom,Right'
$form.Controls.Add($openBtn)

# --- Logik ---
function Write-Log($msg, $color='LightGreen') {
    $output.SelectionColor = [Drawing.Color]::$color
    $output.AppendText("$(Get-Date -f 'HH:mm:ss')  $msg`r`n")
    [System.Windows.Forms.Application]::DoEvents()
}

function Invoke-ScanFile($file) {
    $path = Join-Path $scriptDir $file
    if (-not (Test-Path $path)) {
        Write-Log "FEHLER: $file nicht gefunden in $scriptDir" 'Red'
        return
    }
    $statusLabel.Text = "Scan laeuft: $file ..."
    Write-Log "Starte $file"
    [System.Windows.Forms.Application]::DoEvents()

    try {
        & $path *>&1 | ForEach-Object {
            $line = $_.ToString()
            if ($line.Trim()) { Write-Log $line }
        }
        Write-Log "Fertig: $file" 'Cyan'
    } catch {
        Write-Log "Fehler: $_" 'Red'
    }
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

$openBtn.Add_Click({
    $reports = Join-Path $scriptDir 'reports'
    if (-not (Test-Path $reports)) { New-Item -ItemType Directory -Path $reports -Force | Out-Null }
    Start-Process explorer.exe $reports
})

# --- Defender-Exclusion-Hinweis einmal ---
try {
    Add-MpPreference -ExclusionPath $scriptDir -ErrorAction Stop
    Write-Log "Defender-Exclusion fuer diesen Ordner aktiv (wird beim Schliessen entfernt)" 'Yellow'
    $form.Add_FormClosing({
        try { Remove-MpPreference -ExclusionPath $scriptDir -ErrorAction SilentlyContinue } catch {}
    })
} catch {
    Write-Log "Hinweis: Defender kann Scans blockieren. Als Admin starten." 'Orange'
}

Write-Log 'Trojacare bereit. Ergebnisse landen in \reports\'
[void]$form.ShowDialog()
