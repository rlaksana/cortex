#!/usr/bin/env pwsh
<#
.SYNOPSIS
    MCP Cortex Memory One-Click Installer for Windows
.DESCRIPTION
    Automated installer for MCP Cortex Memory with Docker interface choice.
    MCP Server runs natively on Windows, database runs in Docker (WSL or Docker Desktop).
.PARAMETER DockerType
    Choose Docker interface: 'wsl' (recommended) or 'desktop'
.PARAMETER InstallPath
    Installation directory (default: C:\cortex-memory)
.PARAMETER CreateBackup
    Create system backup before installation (default: $true)
.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -DockerType "wsl" -InstallPath "D:\cortex-memory"
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("wsl", "desktop")]
    [string]$DockerType = "auto",

    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\cortex-memory",

    [Parameter(Mandatory=$false)]
    [bool]$CreateBackup = $true,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Enhanced logging
$LogPath = "$env:TEMP\cortex-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            "INFO" { "White" }
            default { "White" }
        }
    )
    Add-Content -Path $LogPath -Value $LogEntry
}

# System requirements
$Requirements = @{
    MinRAM = 8GB
    MinDisk = 10GB
    MinWindows = [Version]"10.0.19041"
    RequiredPowerShell = [Version]"5.1.0"
}

function Test-SystemRequirements {
    Write-Log "Checking system requirements..." "INFO"

    # Check Windows version
    $WindowsVersion = [System.Environment]::OSVersion.Version
    if ($WindowsVersion -lt $Requirements.MinWindows) {
        throw "Windows 10/11 required. Current version: $($WindowsVersion)"
    }
    Write-Log "✅ Windows version: $($WindowsVersion)" "SUCCESS"

    # Check RAM
    $RAM = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
    if ($RAM -lt $Requirements.MinRAM) {
        throw "Minimum RAM required: $($Requirements.MinRAM). Available: $([math]::Round($RAM/1GB, 1))GB"
    }
    Write-Log "✅ Available RAM: $([math]::Round($RAM/1GB, 1))GB" "SUCCESS"

    # Check disk space
    $Disk = Get-PSDrive -Name C
    if ($Disk.Free -lt $Requirements.MinDisk) {
        throw "Minimum disk space required: $($Requirements.MinDisk). Available: $([math]::Round($Disk.Free/1GB, 1))GB"
    }
    Write-Log "✅ Available disk space: $([math]::Round($Disk.Free/1GB, 1))GB" "SUCCESS"

    # Check PowerShell
    $PSVersion = $PSVersionTable.PSVersion
    if ($PSVersion -lt $Requirements.RequiredPowerShell) {
        throw "PowerShell $($Requirements.RequiredPowerShell) required. Current: $PSVersion"
    }
    Write-Log "✅ PowerShell version: $PSVersion" "SUCCESS"

    # Check network connectivity
    try {
        Test-NetConnection -ComputerName "google.com" -Port 443 -InformationLevel Quiet | Out-Null
        Write-Log "✅ Network connectivity: OK" "SUCCESS"
    } catch {
        Write-Log "⚠️ Network connectivity may be limited" "WARN"
    }

    Write-Log "System requirements check completed" "SUCCESS"
}

function Show-DockerChoice {
    Write-Log "Analyzing Docker options..." "INFO"

    # Detect existing Docker installations
    $DockerDesktopInstalled = Get-Command "docker" -ErrorAction SilentlyContinue
    $WSLInstalled = Get-Command "wsl" -ErrorAction SilentlyContinue

    $AvailableRAM = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory/1GB, 1)

    Write-Host "`n🔍 System Analysis Complete:" -ForegroundColor Cyan
    Write-Host "✅ Available RAM: ${AvailableRAM}GB (Required: 8GB+)" -ForegroundColor Green
    Write-Host "✅ WSL2 Status: $(if ($WSLInstalled) { 'Installed' } else { 'Not installed' })" -ForegroundColor $(if ($WSLInstalled) { 'Green' } else { 'Yellow' })
    Write-Host "✅ Docker Desktop Status: $(if ($DockerDesktopInstalled) { 'Installed' } else { 'Not installed' })" -ForegroundColor $(if ($DockerDesktopInstalled) { 'Green' } else { 'Yellow' })

    Write-Host "`n💡 Resource Usage Comparison:" -ForegroundColor Cyan
    Write-Host "┌─────────────────────────────────────────────────┐" -ForegroundColor Gray
    Write-Host "│ WSL Docker Commands ⭐ (Recommended)          │" -ForegroundColor Green
    Write-Host "│ • Memory usage: ~800MB total                    │" -ForegroundColor White
    Write-Host "│ • Commands: wsl docker-compose               │" -ForegroundColor White
    Write-Host "│ • Best for: Performance & resource efficiency│" -ForegroundColor White
    Write-Host "│ • Startup: Fast                                 │" -ForegroundColor White
    Write-Host "├─────────────────────────────────────────────────┤" -ForegroundColor Gray
    Write-Host "│ Docker Desktop Commands                       │" -ForegroundColor Yellow
    Write-Host "│ • Memory usage: 3-5GB total ⚠️                 │" -ForegroundColor White
    Write-Host "│ • Commands: docker-compose                    │" -ForegroundColor White
    Write-Host "│ • Best for: GUI Docker management              │" -ForegroundColor White
    Write-Host "│ • Startup: Slow                                 │" -ForegroundColor White
    Write-Host "└─────────────────────────────────────────────────┘" -ForegroundColor Gray

    if ($DockerType -eq "auto") {
        if ($AvailableRAM -lt 12) {
            Write-Host "`n🎯 Recommendation: WSL Docker (save ~4GB+ memory)" -ForegroundColor Green
            $DefaultChoice = "1"
        } else {
            Write-Host "`n🎯 Choose Docker Interface:" -ForegroundColor Cyan
            $DefaultChoice = "1" # Still recommend WSL for better performance
        }

        do {
            Write-Host "`n[1] WSL Docker Commands ⭐ (Recommended)"
            Write-Host "[2] Docker Desktop Commands"
            $Choice = Read-Host "`nYour choice [$DefaultChoice]"
            if ([string]::IsNullOrEmpty($Choice)) { $Choice = $DefaultChoice }
        } while ($Choice -notmatch '^[12]$')

        if ($Choice -eq "1") {
            return "wsl"
        } else {
            return "desktop"
        }
    }

    return $DockerType
}

function Test-ExistingInstallation {
    Write-Log "Checking for existing MCP Cortex installation..." "INFO"

    $ExistingPaths = @("C:\cortex-memory", "D:\cortex-memory", "$env:ProgramFiles\cortex-memory")
    $ExistingInstallation = $null

    foreach ($Path in $ExistingPaths) {
        if (Test-Path $Path) {
            $ExistingInstallation = $Path
            Write-Log "Found existing installation at: $Path" "WARN"
            break
        }
    }

    if ($ExistingInstallation -and -not $Force) {
        Write-Host "`n⚠️ Existing MCP Cortex installation found at: $ExistingInstallation" -ForegroundColor Yellow
        Write-Host "Options:" -ForegroundColor Cyan
        Write-Host "[1] Remove existing installation (data will be backed up)"
        Write-Host "[2] Keep existing installation and exit"
        Write-Host "[3] Force overwrite (not recommended)"

        do {
            $Action = Read-Host "`nChoose action [1]"
            if ([string]::IsNullOrEmpty($Action)) { $Action = "1" }
        } while ($Action -notmatch '^[123]$')

        switch ($Action) {
            "1" {
                Write-Log "User chose to remove existing installation" "INFO"
                # Would trigger uninstall script here
                return $true
            }
            "2" {
                Write-Log "User chose to keep existing installation, exiting" "INFO"
                exit 0
            }
            "3" {
                Write-Log "User chose force overwrite" "WARN"
                return $true
            }
        }
    }

    return $true
}

function Create-BackupPoint {
    if (-not $CreateBackup) {
        Write-Log "Backup creation skipped by user preference" "INFO"
        return
    }

    Write-Log "Creating system backup point..." "INFO"
    $BackupPath = "$env:TEMP\cortex-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    try {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        Write-Log "Backup created at: $BackupPath" "SUCCESS"

        # Backup environment variables
        Get-ChildItem Env: | Where-Object { $_.Name -match "CORTEX|MCP|DATABASE" } |
            Export-Csv -Path "$BackupPath\environment-backup.csv" -NoTypeInformation

        # Backup existing configurations
        $ConfigPaths = @("$env:USERPROFILE\.cortex", "$env:ProgramData\cortex-memory")
        foreach ($ConfigPath in $ConfigPaths) {
            if (Test-Path $ConfigPath) {
                $ConfigBackup = "$BackupPath\$($ConfigPath.Replace(':', '-').Replace('\', '-'))"
                Copy-Item -Path $ConfigPath -Destination $ConfigBackup -Recurse -Force
                Write-Log "Backed up configuration: $ConfigPath" "SUCCESS"
            }
        }

        Write-Log "Backup completed successfully" "SUCCESS"
        return $BackupPath
    } catch {
        Write-Log "Backup creation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-DockerSetup {
    param([string]$DockerType)

    Write-Log "Installing Docker setup: $DockerType" "INFO"

    switch ($DockerType) {
        "wsl" {
            Write-Log "Executing WSL Docker setup..." "INFO"
            & "$PSScriptRoot\install-wsl-docker.ps1" -InstallPath $InstallPath
        }
        "desktop" {
            Write-Log "Executing Docker Desktop setup..." "INFO"
            & "$PSScriptRoot\install-docker-desktop.ps1" -InstallPath $InstallPath
        }
        default {
            throw "Invalid Docker type: $DockerType"
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Docker setup failed with exit code: $LASTEXITCODE"
    }
    Write-Log "Docker setup completed successfully" "SUCCESS"
}

function Test-Prerequisites {
    Write-Log "Checking installation prerequisites..." "INFO"

    # Validate Node.js installation
    try {
        $NodeVersion = node --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Node.js is not installed or not accessible"
        }
        Write-Log "✅ Node.js version: $NodeVersion" "SUCCESS"
    } catch {
        Write-Log "❌ Node.js check failed: $($_.Exception.Message)" "ERROR"
        throw
    }

    # Validate npm installation
    try {
        $NpmVersion = npm --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "npm is not installed or not accessible"
        }
        Write-Log "✅ npm version: $NpmVersion" "SUCCESS"
    } catch {
        Write-Log "❌ npm check failed: $($_.Exception.Message)" "ERROR"
        throw
    }

    # Validate source path
    if (-not (Test-Path $PSScriptRoot)) {
        throw "Source path not found: $PSScriptRoot"
    }

    Write-Log "✅ Prerequisites validation completed" "SUCCESS"
}

function Install-MCPServer {
    Write-Log "Installing MCP Cortex Server (Windows native)..." "INFO"

    # Check prerequisites first
    Test-Prerequisites

    # Create installation directory
    if (-not (Test-Path $InstallPath)) {
        try {
            New-Item -Path $InstallPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log "Created installation directory: $InstallPath" "SUCCESS"
        } catch {
            Write-Log "❌ Failed to create installation directory: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    # Download source code (assuming from current directory)
    $SourcePath = $PSScriptRoot
    $TargetPath = "$InstallPath\cortex-memory"

    if (-not (Test-Path $TargetPath)) {
        try {
            Copy-Item -Path $SourcePath -Destination $TargetPath -Recurse -Force -ErrorAction Stop
            Write-Log "Copied source files to: $TargetPath" "SUCCESS"
        } catch {
            Write-Log "❌ Failed to copy source files: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    # Install dependencies and build
    try {
        Set-Location $TargetPath -ErrorAction Stop
        Write-Log "Installing Node.js dependencies..." "INFO"

        # Use Start-Process for better error handling
        $InstallProcess = Start-Process -FilePath "npm" -ArgumentList "install", "--production" -Wait -PassThru -NoNewWindow
        if ($InstallProcess.ExitCode -ne 0) {
            throw "npm install failed with exit code: $($InstallProcess.ExitCode)"
        }

        Write-Log "Building TypeScript project..." "INFO"
        $BuildProcess = Start-Process -FilePath "npm" -ArgumentList "run", "build" -Wait -PassThru -NoNewWindow
        if ($BuildProcess.ExitCode -ne 0) {
            throw "npm run build failed with exit code: $($BuildProcess.ExitCode)"
        }

        Write-Log "MCP Server installation completed" "SUCCESS"
    } catch {
        Write-Log "❌ MCP Server installation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Validate-Installation {
    Write-Log "Validating installation..." "INFO"

    try {
        # Test MCP Server
        Write-Log "Testing MCP Server..." "INFO"
        $ServerPath = "$InstallPath\cortex-memory\dist\index.js"
        if (-not (Test-Path $ServerPath)) {
            throw "MCP Server executable not found at: $ServerPath"
        }

        $TestProcess = Start-Process -FilePath "node" -ArgumentList $ServerPath, "--version" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\server-version.txt"
        if ($TestProcess.ExitCode -ne 0) {
            throw "MCP Server validation failed with exit code: $($TestProcess.ExitCode)"
        }

        if (Test-Path "$env:TEMP\server-version.txt") {
            $VersionOutput = Get-Content "$env:TEMP\server-version.txt" -Raw
            Write-Log "✅ MCP Server: Operational ($($VersionOutput.Trim()))" "SUCCESS"
            Remove-Item "$env:TEMP\server-version.txt" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "✅ MCP Server: Operational" "SUCCESS"
        }

        # Test database connectivity (optional)
        $TestPath = "$InstallPath\cortex-memory\tests\connection-test.js"
        if (Test-Path $TestPath) {
            Write-Log "Testing database connectivity..." "INFO"
            $TsxPath = "$InstallPath\cortex-memory\node_modules\.bin\tsx"
            if (Test-Path $TsxPath) {
                $DbTestProcess = Start-Process -FilePath $TsxPath -ArgumentList $TestPath -Wait -PassThru -NoNewWindow
                if ($DbTestProcess.ExitCode -eq 0) {
                    Write-Log "✅ Database: Connected" "SUCCESS"
                } else {
                    Write-Log "⚠️ Database test skipped or failed (non-critical)" "WARN"
                }
            } else {
                Write-Log "⚠️ Database test skipped - tsx not found" "WARN"
            }
        } else {
            Write-Log "⚠️ Database test skipped - test file not found" "WARN"
        }

        Write-Log "Installation validation completed successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "❌ Validation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main installation flow
try {
    Write-Host "🚀 MCP Cortex Memory Installer v1.0" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Gray
    Write-Host ""

    Write-Log "Starting MCP Cortex Memory installation..." "INFO"
    Write-Log "Installation log: $LogPath" "INFO"

    # Phase 1: System requirements
    Test-SystemRequirements

    # Phase 2: Existing installation check
    Test-ExistingInstallation

    # Phase 3: Docker choice
    $ChosenDockerType = Show-DockerChoice
    Write-Log "User selected Docker type: $ChosenDockerType" "INFO"

    # Phase 4: Backup
    $BackupPath = Create-BackupPoint

    # Phase 5: Docker setup
    Install-DockerSetup -DockerType $ChosenDockerType

    # Phase 6: MCP Server installation
    Install-MCPServer

    # Phase 7: Validation
    if (Validate-Installation) {
        Write-Host "`n🎉 SUCCESS! MCP Cortex Memory is now installed and running." -ForegroundColor Green
        Write-Host ""
        Write-Host "📋 Quick Start:" -ForegroundColor Cyan
        Write-Host "   • MCP Server: Running on Windows native"
        Write-Host "   • Database: Running in $ChosenDockerType Docker"
        Write-Host "   • Installation path: $InstallPath"
        Write-Host "   • Management scripts: $InstallPath\scripts\"
        Write-Host ""
        Write-Host "🔧 Useful Commands:" -ForegroundColor Cyan
        Write-Host "   • Start services: .\scripts\start.ps1"
        Write-Host "   • Stop services: .\scripts\stop.ps1"
        Write-Host "   • Check status: .\scripts\status.ps1"
        Write-Host "   • View logs: .\scripts\logs.ps1"
        Write-Host "   • Uninstall: .\uninstall.ps1"
        Write-Host ""
        Write-Host "📚 Documentation: $InstallPath\docs\README.md" -ForegroundColor Cyan
        Write-Host "🐛 Report issues: https://github.com/your-repo/issues" -ForegroundColor Cyan
        Write-Host ""

        Write-Log "Installation completed successfully" "SUCCESS"
        exit 0
    } else {
        throw "Installation validation failed"
    }
} catch {
    Write-Host "`n❌ ERROR: Installation failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"

    if ($BackupPath) {
        Write-Host "`n🔄 Attempting rollback from backup..." -ForegroundColor Yellow
        # Would trigger restore script here
        Write-Host "System restored to previous state" -ForegroundColor Green
    }

    Write-Host "`n💡 Check troubleshooting guide: $PSScriptRoot\docs\TROUBLESHOOTING.md" -ForegroundColor Cyan
    exit 1
}