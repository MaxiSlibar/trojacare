<#
.SYNOPSIS
  Baut aus trojacare-gui.ps1 eine .exe.
.DESCRIPTION
  Nutzt das Modul ps2exe (https://github.com/MScholtes/PS2EXE).
  Installiert es automatisch wenn noch nicht vorhanden.
#>

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

Write-Host 'Trojacare - Build-Script' -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installiere ps2exe...' -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

$in  = Join-Path $scriptDir 'trojacare-gui.ps1'
$out = Join-Path $scriptDir 'Trojacare.exe'

Write-Host "Kompiliere: $in"
Write-Host "Ziel:       $out"

Invoke-PS2EXE `
    -InputFile $in `
    -OutputFile $out `
    -NoConsole `
    -Title 'Trojacare' `
    -Product 'Trojacare Forensik-Scanner' `
    -Description 'Windows-Forensik-Scanner-Suite' `
    -Version '1.0.0.0' `
    -RequireAdmin `
    -IconFile (Join-Path $scriptDir 'trojacare.ico') -ErrorAction SilentlyContinue

if (-not (Test-Path $out)) {
    Write-Host 'Ohne Icon nochmal versuchen...' -ForegroundColor Yellow
    Invoke-PS2EXE `
        -InputFile $in `
        -OutputFile $out `
        -NoConsole `
        -Title 'Trojacare' `
        -Product 'Trojacare Forensik-Scanner' `
        -Description 'Windows-Forensik-Scanner-Suite' `
        -Version '1.0.0.0' `
        -RequireAdmin
}

if (Test-Path $out) {
    $size = [math]::Round((Get-Item $out).Length/1KB,1)
    Write-Host "FERTIG: $out ($size KB)" -ForegroundColor Green
    Write-Host ''
    Write-Host 'Zum Verteilen die EXE + alle Scan-*.ps1 zusammen packen.' -ForegroundColor Cyan
    Write-Host 'Empfohlen: trojacare.zip mit:' -ForegroundColor Cyan
    Write-Host '  Trojacare.exe'
    Write-Host '  Scan-Connections.ps1'
    Write-Host '  Scan-Stealth.ps1'
    Write-Host '  Scan-Forensics.ps1'
    Write-Host '  Scan-Deep.ps1'
    Write-Host '  Scan-Window.ps1'
    Write-Host '  Monitor-Network.ps1'
    Write-Host '  README.md'
    Write-Host '  LICENSE'
} else {
    Write-Host 'Build fehlgeschlagen.' -ForegroundColor Red
}
