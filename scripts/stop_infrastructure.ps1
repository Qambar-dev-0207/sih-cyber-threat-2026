<#
.SYNOPSIS
    Single-command infrastructure teardown script for SIH26145 on Windows/PowerShell.
.DESCRIPTION
    Stops and removes all containers, networks, and optionally volumes.
#>

param (
    [switch]$Volumes = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SIH26145 — Stopping Containerized Infrastructure Stack         " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

if (-not $Volumes) {
    Write-Host "[+] Stopping containers and preserving persistent volumes..." -ForegroundColor White
    docker compose down --remove-orphans
} else {
    Write-Host "[+] Stopping containers and removing persistent volumes (-v)..." -ForegroundColor Yellow
    docker compose down -v --remove-orphans
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] SIH26145 Infrastructure stack stopped cleanly." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to cleanly stop containers." -ForegroundColor Red
}
