#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Refresh MCP Cortex Port Forwarding

.DESCRIPTION
    Updates port forwarding when WSL IP address changes after restart.

.PARAMETER Port
    External port for PostgreSQL (default: 5433)

.EXAMPLE
    .\refresh-forwarding.ps1
    .\refresh-forwarding.ps1 -Port 5433

.NOTES
    Version: 1.0.0
    Run this script if WSL IP changes and users cannot connect
#>

param(
    [int]$Port = 5433
)

$ErrorActionPreference = "Stop"

function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Failure { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }
function Write-Info { param($Message) Write-Host "🔍 $Message" -ForegroundColor Cyan }
function Write-Section {
    param($Message)
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host " $Message" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
}

Write-Section "REFRESH PORT FORWARDING"

# Check administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Failure "Requires Administrator privileges"
    exit 1
}

# Get Windows IP
Write-Section "[1] DETECTING NETWORK IPs"
try {
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1
    $primaryAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
    $windowsIP = (Get-NetIPAddress -InterfaceIndex $primaryAdapter.ifIndex -AddressFamily IPv4).IPAddress
    Write-Success "Windows IP: $windowsIP"
} catch {
    Write-Failure "Cannot detect Windows IP: $_"
    exit 1
}

# Get current WSL IP
try {
    $wslTest = wsl echo "test" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Failure "WSL is not running - please start WSL first"
        exit 1
    }

    $wslIP = wsl ip addr show eth0 2>&1 | Select-String "inet " | ForEach-Object {
        if ($_ -match "inet\s+(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
    } | Select-Object -First 1

    if ($wslIP) {
        Write-Success "WSL IP: $wslIP"
    } else {
        Write-Failure "Cannot detect WSL IP"
        exit 1
    }
} catch {
    Write-Failure "WSL check failed: $_"
    exit 1
}

# Check current port forwarding
Write-Section "[2] CHECKING CURRENT PORT FORWARDING"
$existingForward = netsh interface portproxy show v4tov4 | Select-String "$Port"

if ($existingForward) {
    Write-Info "Current forwarding on port $Port found"
    Write-Host $existingForward -ForegroundColor Gray

    # Extract current target IP
    if ($existingForward -match "(\d+\.\d+\.\d+\.\d+)\s+$Port") {
        $currentTarget = $matches[1]
        Write-Info "Currently forwarding to: $currentTarget"

        if ($currentTarget -eq $wslIP) {
            Write-Success "Port forwarding is already correct - no update needed"
            exit 0
        } else {
            Write-Info "WSL IP has changed from $currentTarget to $wslIP"
        }
    }
}

# Remove old forwarding
Write-Section "[3] UPDATING PORT FORWARDING"
Write-Info "Removing old port forwarding..."
netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=0.0.0.0 2>&1 | Out-Null

# Add new forwarding
Write-Info "Creating new port forwarding: $windowsIP:$Port -> $wslIP:$Port"
netsh interface portproxy add v4tov4 listenport=$Port listenaddress=0.0.0.0 connectport=$Port connectaddress=$wslIP

if ($LASTEXITCODE -eq 0) {
    Write-Success "Port forwarding updated successfully"
} else {
    Write-Failure "Failed to update port forwarding"
    exit 1
}

# Verify
Write-Section "[4] VERIFICATION"
Write-Info "Current port forwarding rules:"
netsh interface portproxy show v4tov4 | Write-Host -ForegroundColor Gray

# Test connectivity
Write-Info "`nTesting connectivity..."
$testResult = Test-NetConnection -ComputerName $windowsIP -Port $Port -WarningAction SilentlyContinue

if ($testResult.TcpTestSucceeded) {
    Write-Success "Port $Port is accessible on $windowsIP"
    Write-Host "`n✅ Port forwarding refresh complete!" -ForegroundColor Green
} else {
    Write-Failure "Cannot connect to port $Port"
    Write-Info "Check if PostgreSQL is running: wsl docker-compose ps"
}

Write-Host "`n📋 Users can now connect to: $windowsIP:$Port" -ForegroundColor Cyan
