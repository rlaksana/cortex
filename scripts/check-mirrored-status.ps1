#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Read-Only WSL2 Mirrored Networking Status Checker

.DESCRIPTION
    Checks if WSL2 mirrored networking mode is currently active.
    DOES NOT modify any configuration or restart WSL.

.NOTES
    Version: 2.0.0 (Read-Only)
    Author: MCP Cortex Team
#>

$ErrorActionPreference = "Continue"

# Color output functions
function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Failure { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }
function Write-Info { param($Message) Write-Host "🔍 $Message" -ForegroundColor Cyan }
function Write-Section { param($Message) Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Magenta; Write-Host " $Message" -ForegroundColor Magenta; Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta }

Write-Section "WSL2 MIRRORED MODE STATUS CHECK (READ-ONLY)"
Write-Host "This script will NOT modify any settings or restart WSL`n" -ForegroundColor Yellow

# Step 1: Check if WSL is running
Write-Section "[1] WSL STATUS"
try {
    # Try to execute a simple command in WSL to check if it's running
    $testResult = wsl echo "test" 2>&1
    if ($LASTEXITCODE -eq 0 -and $testResult -eq "test") {
        Write-Success "WSL is running and responsive"

        # Show WSL distributions
        $wslList = wsl -l -v 2>&1 | Out-String
        Write-Host $wslList
    } else {
        Write-Failure "WSL is not running or not responsive"
        Write-Info "Try: wsl"
        exit 1
    }
} catch {
    Write-Failure "Cannot check WSL status: $_"
    exit 1
}

# Step 2: Check .wslconfig
Write-Section "[2] CONFIGURATION CHECK"
$wslConfigPath = "$env:USERPROFILE\.wslconfig"

if (Test-Path $wslConfigPath) {
    Write-Info "Found .wslconfig at: $wslConfigPath"
    $configContent = Get-Content $wslConfigPath -Raw
    Write-Host "`n$configContent`n" -ForegroundColor Gray

    if ($configContent -match "networkingMode\s*=\s*mirrored") {
        Write-Success ".wslconfig is configured for mirrored mode"
    } else {
        Write-Info ".wslconfig does NOT have mirrored mode enabled"
        Write-Host "To enable, add this to .wslconfig:" -ForegroundColor Yellow
        Write-Host "[wsl2]" -ForegroundColor Yellow
        Write-Host "networkingMode=mirrored" -ForegroundColor Yellow
    }
} else {
    Write-Info "No .wslconfig found (default NAT mode)"
}

# Step 3: Check current networking mode
Write-Section "[3] ACTIVE NETWORKING MODE"
try {
    $currentMode = wsl wslinfo --networking-mode 2>&1

    if ($currentMode -match "mirrored") {
        Write-Success "WSL is running in MIRRORED mode"
    } elseif ($currentMode -match "nat") {
        Write-Info "WSL is running in NAT mode"
    } elseif ($currentMode -match "none") {
        Write-Failure "WSL networking is DISABLED (mode: none)"
        Write-Info "This usually means mirrored mode failed to start"
        Write-Info "Try restarting WSL: wsl --shutdown, then wsl"
    } else {
        Write-Info "Current mode: $currentMode"
    }
} catch {
    Write-Failure "Cannot detect networking mode: $_"
}

# Step 4: Network adapter detection
Write-Section "[4] NETWORK ADAPTERS"
try {
    $allAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed

    Write-Info "Active network adapters:"
    foreach ($adapter in $allAdapters) {
        Write-Host "   • $($adapter.Name) ($($adapter.InterfaceDescription)) - $($adapter.LinkSpeed)"
    }

    # Get primary adapter using default route
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($defaultRoute) {
        $primaryAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
        Write-Host ""
        Write-Success "Primary adapter: $($primaryAdapter.Name) ($($primaryAdapter.InterfaceDescription))"
    }
} catch {
    Write-Failure "Network adapter detection error: $_"
}

# Step 5: IP address comparison
Write-Section "[5] IP ADDRESS COMPARISON"
try {
    # Get Windows IP from primary adapter
    if ($primaryAdapter) {
        $windowsIP = (Get-NetIPAddress -InterfaceIndex $primaryAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    } else {
        $windowsIP = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.InterfaceAlias -notmatch "vEthernet" } |
            Select-Object -First 1).IPAddress
    }

    # Get WSL IP
    $wslIP = wsl ip addr show eth0 2>&1 | Select-String "inet " | ForEach-Object {
        if ($_ -match "inet\s+(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
    } | Select-Object -First 1

    Write-Host "🌐 Windows IP: $windowsIP" -ForegroundColor Cyan
    Write-Host "🌐 WSL IP: $wslIP" -ForegroundColor Cyan
    Write-Host ""

    if ($windowsIP -and $wslIP) {
        if ($windowsIP -eq $wslIP) {
            Write-Success "IP ADDRESSES MATCH → Mirrored mode is ACTIVE and WORKING!"
            Write-Host ""
            Write-Host "📋 Implications:" -ForegroundColor Green
            Write-Host "   • No port forwarding needed" -ForegroundColor Green
            Write-Host "   • Users connect to: postgresql://cortex:password@$windowsIP:5433/cortex_prod" -ForegroundColor Green
            Write-Host "   • Installation is SIMPLE (no netsh commands needed)" -ForegroundColor Green
        } else {
            Write-Info "IP addresses DO NOT match → Using NAT mode"
            Write-Host ""
            Write-Host "📋 NAT Mode Setup Required:" -ForegroundColor Yellow
            Write-Host "   • Port forwarding needed: 0.0.0.0:5433 → $wslIP:5433" -ForegroundColor Yellow
            Write-Host "   • Users connect to: postgresql://cortex:password@$windowsIP:5433/cortex_prod" -ForegroundColor Yellow
            Write-Host "   • Installation is MORE COMPLEX (netsh portproxy required)" -ForegroundColor Yellow
        }
    } else {
        Write-Failure "Cannot determine IP addresses"
        if (-not $wslIP) {
            Write-Info "WSL has no IP address - networking may be broken"
            Write-Info "Try: wsl --shutdown, then wsl"
        }
    }
} catch {
    Write-Failure "Failed to compare IP addresses: $_"
}

# Step 6: Final recommendation
Write-Section "[6] SUMMARY"

if ($windowsIP -and $wslIP -and ($windowsIP -eq $wslIP)) {
    Write-Host "✅✅✅ MIRRORED MODE IS WORKING ✅✅✅`n" -ForegroundColor Green
    Write-Host "You can proceed with SIMPLE installation scripts for your 20 users." -ForegroundColor Green
    exit 0
} else {
    Write-Host "📊 MIRRORED MODE IS NOT ACTIVE`n" -ForegroundColor Yellow
    Write-Host "Recommended: Use NAT mode with port forwarding for your 20 users." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To enable mirrored mode:" -ForegroundColor Cyan
    Write-Host "1. Edit $wslConfigPath" -ForegroundColor Cyan
    Write-Host "2. Add: [wsl2]" -ForegroundColor Cyan
    Write-Host "        networkingMode=mirrored" -ForegroundColor Cyan
    Write-Host "3. Run: wsl --shutdown" -ForegroundColor Cyan
    Write-Host "4. Start WSL: wsl" -ForegroundColor Cyan
    Write-Host "5. Run this script again to verify" -ForegroundColor Cyan
    exit 1
}
