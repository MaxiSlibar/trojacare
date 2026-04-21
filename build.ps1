<#
.SYNOPSIS
  Baut Trojacare-Lite.exe - Modular-Version (braucht Scan-*.ps1 nebendran).
.DESCRIPTION
  Fuer die Standalone-Version (alle Scripts in der EXE eingebettet)
  siehe build-standalone.ps1.
#>

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
Set-Location $scriptDir

Write-Host 'Trojacare - Lite-Build (Modular)' -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installiere ps2exe (einmalig)...' -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

$in  = Join-Path $scriptDir 'trojacare-gui.ps1'
$out = Join-Path $scriptDir 'Trojacare-Lite.exe'

Write-Host "Kompiliere: $in"
Write-Host "Ziel:       $out"

Invoke-PS2EXE `
    -InputFile $in `
    -OutputFile $out `
    -NoConsole `
    -Title 'Trojacare Lite' `
    -Product 'Trojacare Forensik-Scanner (Lite)' `
    -Description 'Modulare Version - Scan-Scripts muessen daneben liegen' `
    -Company 'MaxiSlibar' `
    -Copyright '(c) 2026 MaxiSlibar - MIT Lizenz' `
    -Version '1.0.0.0' `
    -RequireAdmin

if (Test-Path $out) {
    $size = [math]::Round((Get-Item $out).Length/1KB,1)
    Write-Host ''
    Write-Host "FERTIG: $out ($size KB)" -ForegroundColor Green
    Write-Host ''
    Write-Host 'Zum Verteilen: EXE + alle 6 Scan-*.ps1 + Monitor-Network.ps1' -ForegroundColor Cyan
    Write-Host 'in EINEN ZIP packen. User entpacken, Trojacare-Lite.exe starten.' -ForegroundColor Cyan
} else {
    Write-Host 'Build fehlgeschlagen.' -ForegroundColor Red
}
