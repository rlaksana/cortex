<#
.SYNOPSIS
    MCP Cortex Client Installer for Windows

.DESCRIPTION
    Installs MCP Cortex MCP server configuration for Claude Desktop on Windows.

.PARAMETER ServerIP
    IP address of the MCP Cortex server (required)

.PARAMETER Port
    PostgreSQL port (default: 5433)

.PARAMETER Password
    Database password (required)

.EXAMPLE
    .\install-windows.ps1 -ServerIP 10.10.254.177 -Password "your-password"
    .\install-windows.ps1 -ServerIP 192.168.1.100 -Port 5433 -Password "secure-pass"

.NOTES
    Version: 1.0.0
    Supports: Claude Desktop
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,

    [int]$Port = 5433,

    [Parameter(Mandatory=$true)]
    [string]$Password
)

$ErrorActionPreference = "Stop"

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

Write-Section "MCP CORTEX CLIENT INSTALLER FOR WINDOWS"
Write-Host "This will configure Claude Desktop to use MCP Cortex`n" -ForegroundColor Yellow

# Step 1: Locate Claude Desktop config
Write-Section "[1] LOCATING CLAUDE DESKTOP"

$claudeConfigPaths = @(
    "$env:APPDATA\Claude\claude_desktop_config.json",
    "$env:LOCALAPPDATA\Claude\claude_desktop_config.json",
    "$env:USERPROFILE\.claude\config.json",
    "$env:USERPROFILE\.claude.json"
)

$claudeConfigPath = $null
foreach ($path in $claudeConfigPaths) {
    if (Test-Path $path) {
        $claudeConfigPath = $path
        Write-Success "Found Claude Desktop config: $path"
        break
    }
}

if (-not $claudeConfigPath) {
    Write-Failure "Claude Desktop config not found"
    Write-Info "Searched locations:"
    foreach ($path in $claudeConfigPaths) {
        Write-Host "  - $path" -ForegroundColor Gray
    }
    Write-Warning "`nPlease ensure Claude Desktop is installed"
    Write-Info "Or manually specify config path"
    exit 1
}

# Step 2: Backup existing config
Write-Section "[2] BACKING UP CONFIGURATION"

$backupPath = "$claudeConfigPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
try {
    Copy-Item $claudeConfigPath $backupPath -Force
    Write-Success "Backup created: $backupPath"
} catch {
    Write-Failure "Failed to create backup: $_"
    exit 1
}

# Step 3: Load and update config
Write-Section "[3] UPDATING CONFIGURATION"

try {
    $config = Get-Content $claudeConfigPath -Raw | ConvertFrom-Json

    # Ensure mcpServers object exists
    if (-not $config.mcpServers) {
        $config | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value (New-Object PSObject)
    }

    # Build DATABASE_URL
    $databaseUrl = "postgresql://cortex:$Password@$ServerIP:$Port/cortex_prod"

    # Create cortex-memory configuration
    $cortexConfig = @{
        command = "node"
        args = @("path/to/mcp-cortex/dist/index.js")
        env = @{
            DATABASE_URL = $databaseUrl
            LOG_LEVEL = "error"
            NODE_ENV = "production"
        }
    }

    # Add or update cortex-memory server
    if ($config.mcpServers.PSObject.Properties.Name -contains "cortex-memory") {
        Write-Info "Updating existing cortex-memory configuration"
        $config.mcpServers."cortex-memory" = $cortexConfig
    } else {
        Write-Info "Adding new cortex-memory configuration"
        $config.mcpServers | Add-Member -MemberType NoteProperty -Name "cortex-memory" -Value $cortexConfig
    }

    # Save updated config
    $config | ConvertTo-Json -Depth 10 | Set-Content $claudeConfigPath -Encoding UTF8
    Write-Success "Configuration updated successfully"

} catch {
    Write-Failure "Failed to update configuration: $_"
    Write-Warning "Restoring backup..."
    Copy-Item $backupPath $claudeConfigPath -Force
    exit 1
}

# Step 4: Test connection
Write-Section "[4] TESTING CONNECTION"

Write-Info "Testing connectivity to $ServerIP:$Port..."
$testResult = Test-NetConnection -ComputerName $ServerIP -Port $Port -WarningAction SilentlyContinue

if ($testResult.TcpTestSucceeded) {
    Write-Success "Server is reachable on $ServerIP:$Port"
} else {
    Write-Failure "Cannot connect to $ServerIP:$Port"
    Write-Warning "Please check:"
    Write-Host "  1. Server IP is correct: $ServerIP" -ForegroundColor Yellow
    Write-Host "  2. Server is running (ask administrator)" -ForegroundColor Yellow
    Write-Host "  3. Firewall allows port $Port" -ForegroundColor Yellow
    Write-Host "  4. You are on the same network" -ForegroundColor Yellow
    Write-Host "`nConfiguration was saved, but connection test failed" -ForegroundColor Yellow
    exit 1
}

# Step 5: Installation complete
Write-Section "[5] INSTALLATION COMPLETE"

Write-Host "`n✅✅✅ MCP CORTEX INSTALLED SUCCESSFULLY ✅✅✅`n" -ForegroundColor Green

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " CONFIGURATION DETAILS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Config file:      $claudeConfigPath" -ForegroundColor White
Write-Host "Backup:           $backupPath" -ForegroundColor White
Write-Host "Server:           $ServerIP:$Port" -ForegroundColor White
Write-Host "Database:         cortex_prod" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`n📋 Next Steps:" -ForegroundColor Green
Write-Host "1. Restart Claude Desktop for changes to take effect" -ForegroundColor White
Write-Host "2. Open Claude Desktop" -ForegroundColor White
Write-Host "3. MCP Cortex tools will be available (memory.store, memory.find)" -ForegroundColor White
Write-Host "4. Claude may prompt for tool approval - this is normal" -ForegroundColor White

Write-Host "`n⚠️  Important Notes:" -ForegroundColor Yellow
Write-Host "- MCP tools require approval on first use (security feature)" -ForegroundColor Gray
Write-Host "- If connection fails, run test-connection.js to diagnose" -ForegroundColor Gray
Write-Host "- Contact administrator if you cannot connect" -ForegroundColor Gray

Write-Host "`n🎉 Installation complete! Enjoy using MCP Cortex!`n" -ForegroundColor Green
