#!/usr/bin/env pwsh
<#
.SYNOPSIS
    WSL Docker Setup for MCP Cortex Memory
.DESCRIPTION
    Installs and configures WSL2 with Docker for PostgreSQL database deployment.
    Optimized for resource efficiency (~800MB total memory usage).
.PARAMETER InstallPath
    Installation directory for MCP Cortex
.PARAMETER Force
    Force reinstallation even if WSL2 Docker already exists
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\cortex-memory",

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$LogPath = "$env:TEMP\wsl-docker-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

function Test-WSLPrerequisites {
    Write-Log "Checking WSL prerequisites..." "INFO"

    # Check Windows version (WSL2 requires Windows 10 version 2004 or higher)
    $WindowsVersion = [System.Environment]::OSVersion.Version
    if ($WindowsVersion -lt [Version]"10.0.19041") {
        throw "WSL2 requires Windows 10 version 2004 or higher. Current: $WindowsVersion"
    }
    Write-Log "✅ Windows version compatible with WSL2" "SUCCESS"

    # Check if virtualization is enabled
    try {
        $SystemInfo = systeminfo
        if ($SystemInfo -match "Virtualization Enabled In Firmware:\s+No") {
            Write-Log "⚠️ Virtualization may not be enabled in BIOS/UEFI" "WARN"
            Write-Host "⚠️ Virtualization should be enabled in BIOS/UEFI for better performance" -ForegroundColor Yellow
        } else {
            Write-Log "✅ Virtualization is enabled" "SUCCESS"
        }
    } catch {
        Write-Log "Could not check virtualization status" "WARN"
    }

    Write-Log "WSL prerequisites check completed" "SUCCESS"
}

function Install-WSL2 {
    Write-Log "Installing WSL2..." "INFO"

    try {
        # Enable WSL feature
        Write-Log "Enabling WSL feature..." "INFO"
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart | Out-Null
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart | Out-Null

        # Download and install WSL2 kernel update
        Write-Log "Downloading WSL2 kernel update..." "INFO"
        $WSLKernelUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
        $WSLKernelPath = "$env:TEMP\wsl_update_x64.msi"

        try {
            Invoke-WebRequest -Uri $WSLKernelUrl -OutFile $WSLKernelPath -UseBasicParsing
            Write-Log "Installing WSL2 kernel update..." "INFO"
            Start-Process msiexec -ArgumentList "/i `"$WSLKernelPath`" /quiet /norestart" -Wait
            Write-Log "✅ WSL2 kernel update installed" "SUCCESS"
        } catch {
            Write-Log "Failed to download/install WSL2 kernel update" "WARN"
            Write-Host "⚠️ WSL2 kernel update failed. You may need to install it manually." -ForegroundColor Yellow
        }

        # Set WSL2 as default
        Write-Log "Setting WSL2 as default..." "INFO"
        wsl --set-default-version 2

        Write-Log "WSL2 installation completed" "SUCCESS"
    } catch {
        Write-Log "WSL2 installation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-UbuntuDistribution {
    Write-Log "Installing Ubuntu distribution..." "INFO"

    try {
        # Check if Ubuntu is already installed
        $UbuntuInstalled = wsl -l -q | Where-Object { $_ -match "Ubuntu" }
        if ($UbuntuInstalled -and -not $Force) {
            Write-Log "Ubuntu distribution already installed" "INFO"
            return
        }

        Write-Log "Opening Ubuntu installation page..." "INFO"
        # Install Ubuntu from Microsoft Store (this is the recommended approach)
        Write-Host "📥 Opening Ubuntu installation page..." -ForegroundColor Cyan
        try {
            Start-Process "ms-windows-store://pdp/?productid=9NBLGGH4JNFS" -ErrorAction Stop
            Write-Host "✅ Microsoft Store opened to Ubuntu page" "SUCCESS"
        } catch {
            Write-Log "⚠️ Could not open Microsoft Store automatically" "WARN"
            Write-Host "Please manually open Microsoft Store and search for Ubuntu" -ForegroundColor Yellow
        }

        Write-Host "Please install Ubuntu from Microsoft Store, then press any key to continue..." -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to cancel installation" -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        # Verify Ubuntu installation
        $UbuntuVerified = $false
        $Attempts = 0
        $MaxAttempts = 30

        do {
            $UbuntuVerified = wsl -l -q | Where-Object { $_ -match "Ubuntu" }
            if (-not $UbuntuVerified) {
                Write-Host "Waiting for Ubuntu installation... ($($Attempts + 1)/$MaxAttempts)" -ForegroundColor Yellow
                Start-Sleep -Seconds 2
                $Attempts++
            }
        } while (-not $UbuntuVerified -and $Attempts -lt $MaxAttempts)

        if ($UbuntuVerified) {
            Write-Log "✅ Ubuntu distribution installed successfully" "SUCCESS"
        } else {
            throw "Ubuntu distribution installation timed out"
        }
    } catch {
        Write-Log "Ubuntu distribution installation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Configure-WSL2 {
    Write-Log "Configuring WSL2 for optimal performance..." "INFO"

    try {
        # Create .wslconfig for memory and performance optimization
        $WSLConfigPath = "$env:USERPROFILE\.wslconfig"
        $WSLConfigContent = @"
[wsl2]
memory=2GB
processors=4
swap=4GB
localhostForwarding=true
"@

        if (-not (Test-Path $WSLConfigPath) -or $Force) {
            Set-Content -Path $WSLConfigPath -Value $WSLConfigContent -Force
            Write-Log "Created .wslconfig with optimized settings" "SUCCESS"
        }

        # Restart WSL to apply configuration
        Write-Log "Restarting WSL to apply configuration..." "INFO"
        wsl --shutdown
        Start-Sleep -Seconds 5

        Write-Log "WSL2 configuration completed" "SUCCESS"
    } catch {
        Write-Log "WSL2 configuration failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-DockerInWSL {
    Write-Log "Installing Docker in WSL2..." "INFO"

    try {
        # Docker installation script for Ubuntu
        $DockerInstallScript = @"
#!/bin/bash
set -e

echo "🔧 Installing Docker in WSL2 Ubuntu..."

# Update package index
sudo apt-get update

# Install packages to allow apt to use a repository over HTTPS
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up the repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add current user to docker group
sudo usermod -aG docker $USER

# Start Docker service
sudo service docker start

echo "✅ Docker installation completed in WSL2"
echo "Please restart WSL2 by running 'wsl --shutdown' from Windows"
"@

        # Write and execute Docker installation script in WSL
        $InstallScriptPath = "$env:TEMP\install-docker-wsl.sh"
        try {
            Set-Content -Path $InstallScriptPath -Value $DockerInstallScript -ErrorAction Stop
            Write-Log "Created Docker installation script: $InstallScriptPath" "INFO"
        } catch {
            Write-Log "❌ Failed to create Docker installation script: $($_.Exception.Message)" "ERROR"
            throw
        }

        Write-Log "Executing Docker installation in WSL2..." "INFO"
        try {
            $DockerInstallProcess = Start-Process -FilePath "wsl" -ArgumentList "--", "bash", $InstallScriptPath -Wait -PassThru -NoNewWindow
            if ($DockerInstallProcess.ExitCode -ne 0) {
                throw "Docker installation in WSL2 failed with exit code: $($DockerInstallProcess.ExitCode)"
            }
        } catch {
            Write-Log "❌ Docker installation in WSL2 failed: $($_.Exception.Message)" "ERROR"
            throw
        }

        Write-Log "✅ Docker installed successfully in WSL2" "SUCCESS"
    } catch {
        Write-Log "Docker installation in WSL2 failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Setup-DockerCompose {
    Write-Log "Setting up Docker Compose configuration..." "INFO"

    try {
        # Create docker-compose directory
        $DockerDir = "$InstallPath\docker"
        if (-not (Test-Path $DockerDir)) {
            New-Item -Path $DockerDir -ItemType Directory -Force | Out-Null
        }

        # Copy WSL-specific docker-compose file
        $DockerComposeSource = "$PSScriptRoot\docker\docker-compose.wsl.yml"
        $DockerComposeTarget = "$DockerDir\docker-compose.yml"

        if (Test-Path $DockerComposeSource) {
            Copy-Item -Path $DockerComposeSource -Destination $DockerComposeTarget -Force
            Write-Log "✅ Docker Compose configuration copied" "SUCCESS"
        } else {
            # Create basic docker-compose if source doesn't exist
            $BasicCompose = @"
version: '3.8'

services:
  postgres:
    image: postgres:18-alpine
    container_name: cortex-postgres-wsl
    environment:
      POSTGRES_DB: cortex_prod
      POSTGRES_USER: cortex
      POSTGRES_PASSWORD: cortex_pg18_secure_2025_key
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=en_US.UTF-8"
    ports:
      - "5433:5432"
    volumes:
      - cortex_data:/var/lib/postgresql/data
      - ./migrations/001_complete_schema.sql:/docker-entrypoint-initdb.d/02-schema.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cortex -d cortex_prod"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    restart: unless-stopped
    shm_size: 128m

volumes:
  cortex_data:
    driver: local
"@
            Set-Content -Path $DockerComposeTarget -Value $BasicCompose
            Write-Log "Created basic Docker Compose configuration" "SUCCESS"
        }

        Write-Log "Docker Compose setup completed" "SUCCESS"
    } catch {
        Write-Log "Docker Compose setup failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Test-WSLDockerSetup {
    Write-Log "Testing WSL Docker setup..." "INFO"

    try {
        # Test WSL connectivity
        Write-Log "Testing WSL connectivity..." "INFO"
        $WSLTest = wsl -- echo "WSL is working"
        if ($WSLTest -ne "WSL is working") {
            throw "WSL connectivity test failed"
        }
        Write-Log "✅ WSL connectivity: OK" "SUCCESS"

        # Test Docker in WSL
        Write-Log "Testing Docker in WSL..." "INFO"
        $DockerVersion = wsl -- docker --version
        if ($LASTEXITCODE -ne 0) {
            throw "Docker in WSL test failed"
        }
        Write-Log "✅ Docker in WSL: $DockerVersion" "SUCCESS"

        # Test Docker Compose
        Write-Log "Testing Docker Compose..." "INFO"
        Set-Location "$InstallPath\docker"
        $ComposeTest = wsl -- docker-compose config --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Compose test failed"
        }
        Write-Log "✅ Docker Compose: Operational" "SUCCESS"

        Write-Log "WSL Docker setup validation completed successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "WSL Docker setup validation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main installation flow
try {
    Write-Host "🐧 WSL Docker Setup for MCP Cortex Memory" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Gray
    Write-Host ""

    Write-Log "Starting WSL Docker setup..." "INFO"
    Write-Log "Setup log: $LogPath" "INFO"

    # Phase 1: Prerequisites
    Test-WSLPrerequisites

    # Phase 2: Install WSL2
    $WSLStatus = wsl -l -q 2>$null
    if (-not $WSLStatus -or $Force) {
        Install-WSL2
    } else {
        Write-Log "WSL2 already installed, skipping installation" "INFO"
    }

    # Phase 3: Install Ubuntu distribution
    Install-UbuntuDistribution

    # Phase 4: Configure WSL2
    Configure-WSL2

    # Phase 5: Install Docker in WSL
    $DockerInWSL = wsl -- which docker 2>$null
    if (-not $DockerInWSL -or $Force) {
        Install-DockerInWSL
    } else {
        Write-Log "Docker already installed in WSL, skipping installation" "INFO"
    }

    # Phase 6: Setup Docker Compose
    Setup-DockerCompose

    # Phase 7: Validation
    if (Test-WSLDockerSetup) {
        Write-Host "`n🎉 SUCCESS! WSL Docker setup completed." -ForegroundColor Green
        Write-Host ""
        Write-Host "📋 Quick Commands:" -ForegroundColor Cyan
        Write-Host "   • Start database: cd `"$InstallPath\docker`" && wsl docker-compose up -d"
        Write-Host "   • Stop database: wsl docker-compose down"
        Write-Host "   • Check status: wsl docker-compose ps"
        Write-Host "   • View logs: wsl docker-compose logs -f postgres"
        Write-Host ""
        Write-Host "💡 Resource Usage:" -ForegroundColor Cyan
        Write-Host "   • Memory: ~800MB total"
        Write-Host "   • Storage: PostgreSQL data in Docker volume"
        Write-Host "   • Performance: Optimized for Windows + WSL2 integration"
        Write-Host ""

        Write-Log "WSL Docker setup completed successfully" "SUCCESS"
        exit 0
    } else {
        throw "WSL Docker setup validation failed"
    }
} catch {
    Write-Host "`n❌ ERROR: WSL Docker setup failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "WSL Docker setup failed: $($_.Exception.Message)" "ERROR"

    Write-Host "`n💡 Troubleshooting tips:" -ForegroundColor Cyan
    Write-Host "   • Ensure Windows 10 version 2004 or higher" -ForegroundColor White
    Write-Host "   • Enable virtualization in BIOS/UEFI" -ForegroundColor White
    Write-Host "   • Install Ubuntu from Microsoft Store" -ForegroundColor White
    Write-Host "   • Restart WSL2 with: wsl --shutdown" -ForegroundColor White
    Write-Host "   • Check WSL logs with: wsl --status" -ForegroundColor White
    exit 1
}