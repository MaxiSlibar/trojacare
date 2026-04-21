<#
.SYNOPSIS
  Baut beide EXE-Varianten: Trojacare.exe (Standalone) + Trojacare-Lite.exe (Modular).
#>

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
Set-Location $scriptDir

Write-Host '================================' -ForegroundColor Cyan
Write-Host ' Trojacare - Build BEIDE Versionen' -ForegroundColor Cyan
Write-Host '================================' -ForegroundColor Cyan
Write-Host ''

Write-Host '[1/2] Standalone (alle Scripts eingebettet)' -ForegroundColor Yellow
Write-Host '----------------------------------------------'
& (Join-Path $scriptDir 'build-standalone.ps1')
Write-Host ''

Write-Host '[2/2] Lite (braucht Scan-*.ps1 daneben)' -ForegroundColor Yellow
Write-Host '----------------------------------------'
& (Join-Path $scriptDir 'build.ps1')
Write-Host ''

Write-Host '================================' -ForegroundColor Green
Write-Host ' ALLES FERTIG' -ForegroundColor Green
Write-Host '================================' -ForegroundColor Green
Get-ChildItem $scriptDir -Filter '*.exe' | Select-Object Name,@{n='KB';e={[math]::Round($_.Length/1KB,1)}} | Format-Table -AutoSize
