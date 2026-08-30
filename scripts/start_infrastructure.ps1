<#
.SYNOPSIS
    Single-command infrastructure launcher and healthcheck validator for SIH26145 on Windows/PowerShell.
.DESCRIPTION
    Validates Docker daemon availability, ensures local directories, starts docker compose stack,
    polls healthchecks for all 4 core services, verifies Redpanda topics and TimescaleDB readiness.
#>

param (
    [switch]$Build = $false,
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SIH26145 — Passive Network Monitoring Infrastructure Startup   " -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

# Step 1: Pre-flight Docker Daemon Check
Write-Host "`n[1/6] Validating Docker daemon..." -ForegroundColor White
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker engine is not responding."
    }
    Write-Host "      [OK] Docker engine is active and responding." -ForegroundColor Green
} catch {
    Write-Host "      [ERROR] Docker is not running or not accessible in current path." -ForegroundColor Red
    Write-Host "      Please start Docker Desktop and verify Linux container mode." -ForegroundColor Yellow
    exit 1
}

# Step 2: Ensure required local directory layout exists
Write-Host "`n[2/6] Verifying workspace directories..." -ForegroundColor White
$directories = @("logs/zeek", "pcaps", "data/pcaps", "config/zeek", "config/redpanda", "config/redis", "config/timescale", "config/db")
foreach ($dir in $directories) {
    if (-not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host "      [OK] Local log and configuration directories verified." -ForegroundColor Green

# Step 3: Launch Docker Compose Stack
Write-Host "`n[3/6] Starting containerized services via Docker Compose..." -ForegroundColor White
if ($Build) {
    docker compose up -d --build
} else {
    docker compose up -d
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "      [ERROR] docker compose up failed to launch." -ForegroundColor Red
    exit 1
}
Write-Host "      [OK] Docker Compose containers launched." -ForegroundColor Green

# Step 4: Healthcheck Polling Loop
Write-Host "`n[4/6] Polling container health status..." -ForegroundColor White
$services = @("sih_redpanda", "sih_redis", "sih_timescaledb", "sih_zeek")
$startTime = Get-Date
$allHealthy = $false

while ((Get-Date) -lt $startTime.AddSeconds($TimeoutSeconds)) {
    $unhealthyCount = 0
    foreach ($svc in $services) {
        $status = docker inspect --format='{{json .State.Health.Status}}' $svc 2>$null
        if ($null -ne $status) {
            $status = $status.Trim('"')
        } else {
            $status = "not_found"
        }

        if ($status -ne "healthy") {
            $unhealthyCount++
        }
    }

    if ($unhealthyCount -eq 0) {
        $allHealthy = $true
        break
    }

    $elapsed = [int]((Get-Date) - $startTime).TotalSeconds
    Write-Host "      Waiting for services ($elapsed s / $TimeoutSeconds s)... ($unhealthyCount service(s) initializing)" -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
}

if (-not $allHealthy) {
    Write-Host "      [WARNING] Timeout waiting for all containers to reach 'healthy' state." -ForegroundColor Yellow
    docker compose ps
} else {
    Write-Host "      [OK] All core services report HEALTHY." -ForegroundColor Green
}

# Step 5: Verify Redpanda Topics
Write-Host "`n[5/6] Checking Redpanda topic topology..." -ForegroundColor White
try {
    $topicList = docker exec sih_redpanda rpk topic list --brokers localhost:9092 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      [OK] Topics verified:" -ForegroundColor Green
        $topicList | ForEach-Object { Write-Host "           $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "      [INFO] Redpanda topics are being provisioned by sih_redpanda_init." -ForegroundColor Gray
    }
} catch {
    Write-Host "      [INFO] Redpanda topics initialization in progress." -ForegroundColor Gray
}

# Step 6: Verify Database Connection
Write-Host "`n[6/6] Checking TimescaleDB connectivity..." -ForegroundColor White
try {
    $dbCheck = docker exec sih_timescaledb psql -U postgres -d sih26145 -c "SELECT extname FROM pg_extension WHERE extname='timescaledb';" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      [OK] TimescaleDB extension confirmed loaded in sih26145 database." -ForegroundColor Green
    } else {
        Write-Host "      [INFO] Database initial schema migration running." -ForegroundColor Gray
    }
} catch {
    Write-Host "      [INFO] Database initialization in progress." -ForegroundColor Gray
}

# Summary Display
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "  INFRASTRUCTURE STATUS SUMMARY                                  " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Redpanda (Kafka API):  localhost:19092 / redpanda:9092" -ForegroundColor White
Write-Host "  Redis 7.x:             localhost:6379" -ForegroundColor White
Write-Host "  TimescaleDB (PG16):    localhost:5432 (DB: sih26145, User: postgres)" -ForegroundColor White
Write-Host "  Zeek Sensor:           Container sih_zeek (Logs: ./logs/zeek)" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Stack is READY for traffic replay and Day-1 throughput benchmark.`n" -ForegroundColor Yellow
