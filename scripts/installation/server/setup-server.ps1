#Requires -RunAsAdministrator

<#
.SYNOPSIS
    MCP Cortex Server Setup - NAT Mode with Port Forwarding

.DESCRIPTION
    Sets up PostgreSQL Docker container and configures Windows port forwarding
    for 20 users to access via LAN.

.PARAMETER DbPassword
    PostgreSQL password (optional, defaults to generated password)

.PARAMETER Port
    External port for PostgreSQL (default: 5433)

.EXAMPLE
    .\setup-server.ps1
    .\setup-server.ps1 -DbPassword "my-secure-password"

.NOTES
    Version: 1.0.0
    Requires: Docker in WSL, Administrator privileges
#>

param(
    [string]$DbPassword = "",
    [int]$Port = 5433
)

$ErrorActionPreference = "Stop"

# Color output functions
function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Failure { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }
function Write-Info { param($Message) Write-Host "🔍 $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "⚠️  $Message" -ForegroundColor Yellow }
function Write-Section {
    param($Message)
    Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host " $Message" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
}

Write-Section "MCP CORTEX SERVER SETUP"
Write-Host "NAT Mode with Port Forwarding for Multi-User Access`n" -ForegroundColor Yellow

# Check administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Failure "This script requires Administrator privileges"
    Write-Info "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

# Step 1: Detect Windows IP
Write-Section "[1] DETECTING NETWORK CONFIGURATION"

try {
    # Get primary network adapter
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Select-Object -First 1
    $primaryAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
    $windowsIP = (Get-NetIPAddress -InterfaceIndex $primaryAdapter.ifIndex -AddressFamily IPv4).IPAddress

    Write-Success "Primary adapter: $($primaryAdapter.Name)"
    Write-Success "Windows IP: $windowsIP"
    Write-Info "This IP will be used by your 20 users to connect"
} catch {
    Write-Failure "Cannot detect network configuration: $_"
    exit 1
}

# Step 2: Check WSL
Write-Section "[2] CHECKING WSL STATUS"

try {
    $wslTest = wsl echo "test" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Failure "WSL is not running"
        Write-Info "Starting WSL..."
        wsl echo "WSL started"
    }
    Write-Success "WSL is running"

    # Get WSL IP
    $wslIP = wsl ip addr show eth0 2>&1 | Select-String "inet " | ForEach-Object {
        if ($_ -match "inet\s+(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
    } | Select-Object -First 1

    if ($wslIP) {
        Write-Success "WSL IP: $wslIP"
    } else {
        Write-Failure "Cannot detect WSL IP address"
        exit 1
    }
} catch {
    Write-Failure "WSL check failed: $_"
    exit 1
}

# Step 3: Check Docker
Write-Section "[3] CHECKING DOCKER IN WSL"

try {
    $dockerCheck = wsl docker --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Docker is installed in WSL"
        Write-Info "$dockerCheck"
    } else {
        Write-Failure "Docker is not installed in WSL"
        Write-Info "Please install Docker in WSL first"
        exit 1
    }

    # Check if Docker is running
    $dockerRunning = wsl docker ps 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Docker daemon is not running"
        Write-Info "Starting Docker..."
        wsl sudo service docker start 2>&1 | Out-Null
        Start-Sleep -Seconds 3
    }
    Write-Success "Docker daemon is running"
} catch {
    Write-Failure "Docker check failed: $_"
    exit 1
}

# Step 4: Setup PostgreSQL
Write-Section "[4] SETTING UP POSTGRESQL"

$projectPath = wsl pwd 2>&1
Write-Info "Project path: $projectPath"

# Generate password if not provided
if ([string]::IsNullOrEmpty($DbPassword)) {
    $DbPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})
    Write-Info "Generated database password: $DbPassword"
}

# Check if docker-compose.yml exists
$composeExists = wsl test -f docker-compose.yml 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Success "Found docker-compose.yml"

    # Check if .env exists, create if not
    $envExists = wsl test -f .env.production 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Info "Creating .env.production file..."
        $envContent = @"
DATABASE_URL=postgresql://cortex:$DbPassword@localhost:5432/cortex_prod
DB_PASSWORD=$DbPassword
LOG_LEVEL=info
NODE_ENV=production
"@
        $envContent | wsl tee .env.production | Out-Null
        Write-Success ".env.production created"
    }

    # Start Docker Compose
    Write-Info "Starting PostgreSQL container..."
    wsl docker-compose up -d 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Success "PostgreSQL container started"
        Start-Sleep -Seconds 5

        # Verify container is running
        $containerStatus = wsl docker-compose ps 2>&1 | Select-String "Up"
        if ($containerStatus) {
            Write-Success "Container is healthy"
        } else {
            Write-Warning "Container may not be healthy - check docker-compose logs"
        }
    } else {
        Write-Failure "Failed to start PostgreSQL container"
        exit 1
    }
} else {
    Write-Failure "docker-compose.yml not found in current directory"
    Write-Info "Please run this script from the mcp-cortex directory"
    exit 1
}

# Step 5: Configure Port Forwarding
Write-Section "[5] CONFIGURING PORT FORWARDING"

try {
    # Check if port forwarding already exists
    $existingForward = netsh interface portproxy show v4tov4 | Select-String "$Port"

    if ($existingForward) {
        Write-Info "Removing existing port forwarding on port $Port..."
        netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=0.0.0.0 | Out-Null
    }

    # Create new port forwarding
    Write-Info "Creating port forwarding: $windowsIP:$Port -> $wslIP:$Port"
    netsh interface portproxy add v4tov4 listenport=$Port listenaddress=0.0.0.0 connectport=$Port connectaddress=$wslIP | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Port forwarding configured successfully"

        # Show current forwarding rules
        Write-Info "`nActive port forwarding rules:"
        netsh interface portproxy show v4tov4 | Write-Host -ForegroundColor Gray
    } else {
        Write-Failure "Failed to configure port forwarding"
        exit 1
    }
} catch {
    Write-Failure "Port forwarding setup failed: $_"
    exit 1
}

# Step 6: Configure Windows Firewall
Write-Section "[6] CONFIGURING WINDOWS FIREWALL"

try {
    # Check if firewall rule exists
    $firewallRule = Get-NetFirewallRule -DisplayName "MCP Cortex PostgreSQL" -ErrorAction SilentlyContinue

    if ($firewallRule) {
        Write-Info "Firewall rule already exists"
    } else {
        Write-Info "Creating firewall rule for port $Port..."
        New-NetFirewallRule -DisplayName "MCP Cortex PostgreSQL" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $Port `
            -Action Allow `
            -Profile Any | Out-Null

        Write-Success "Firewall rule created"
    }
} catch {
    Write-Warning "Firewall configuration failed: $_"
    Write-Info "You may need to manually allow port $Port in Windows Firewall"
}

# Step 7: Test Connectivity
Write-Section "[7] TESTING CONNECTIVITY"

try {
    Write-Info "Testing local connectivity..."
    $testResult = Test-NetConnection -ComputerName $windowsIP -Port $Port -WarningAction SilentlyContinue

    if ($testResult.TcpTestSucceeded) {
        Write-Success "Port $Port is accessible on $windowsIP"
    } else {
        Write-Warning "Cannot connect to port $Port - may need firewall adjustment"
    }
} catch {
    Write-Warning "Connectivity test failed: $_"
}

# Step 8: Generate Connection Info
Write-Section "[8] CONNECTION INFORMATION FOR USERS"

$connectionString = "postgresql://cortex:$DbPassword@$windowsIP:$Port/cortex_prod"

Write-Host "`n📋 INSTALLATION COMPLETE!`n" -ForegroundColor Green

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " CONNECTION DETAILS FOR YOUR 20 USERS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server IP:        $windowsIP" -ForegroundColor Yellow
Write-Host "Port:             $Port" -ForegroundColor Yellow
Write-Host "Database:         cortex_prod" -ForegroundColor Yellow
Write-Host "Username:         cortex" -ForegroundColor Yellow
Write-Host "Password:         $DbPassword" -ForegroundColor Yellow
Write-Host ""
Write-Host "Connection String:" -ForegroundColor Cyan
Write-Host $connectionString -ForegroundColor White
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Save connection info to file
$infoFile = "CONNECTION_INFO.txt"
$infoContent = @"
MCP CORTEX SERVER CONNECTION INFORMATION
========================================

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

SERVER DETAILS
--------------
Windows IP:       $windowsIP
WSL IP:           $wslIP
Port:             $Port
Database:         cortex_prod
Username:         cortex
Password:         $DbPassword

CONNECTION STRING
-----------------
$connectionString

USER INSTALLATION COMMAND
-------------------------
Windows users:
  .\install-windows.ps1 -ServerIP $windowsIP -Port $Port -Password "$DbPassword"

Mac users:
  ./install-mac.sh $windowsIP $Port $DbPassword

Linux users:
  ./install-linux.sh $windowsIP $Port $DbPassword

MAINTENANCE
-----------
If WSL restarts and IP changes, run:
  .\refresh-forwarding.ps1

To view current port forwarding:
  netsh interface portproxy show v4tov4

To stop PostgreSQL:
  wsl docker-compose down

To start PostgreSQL:
  wsl docker-compose up -d

TROUBLESHOOTING
---------------
Check PostgreSQL logs:
  wsl docker-compose logs -f postgres

Test port forwarding:
  Test-NetConnection -ComputerName $windowsIP -Port $Port

Check firewall:
  Get-NetFirewallRule -DisplayName "MCP Cortex PostgreSQL"
"@

$infoContent | Out-File -FilePath $infoFile -Encoding UTF8
Write-Success "Connection info saved to: $infoFile"

Write-Host "`n📦 Next Steps:" -ForegroundColor Green
Write-Host "1. Share the connection info above with your 20 users" -ForegroundColor White
Write-Host "2. Users run the appropriate install script for their platform" -ForegroundColor White
Write-Host "3. If WSL restarts, run refresh-forwarding.ps1" -ForegroundColor White
Write-Host ""
