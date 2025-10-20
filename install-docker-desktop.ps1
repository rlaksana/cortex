#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Docker Desktop Setup for MCP Cortex Memory
.DESCRIPTION
    Installs and configures Docker Desktop for PostgreSQL database deployment.
    Higher resource usage (3-5GB) but provides GUI management capabilities.
.PARAMETER InstallPath
    Installation directory for MCP Cortex
.PARAMETER Force
    Force reinstallation even if Docker Desktop already exists
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "C:\cortex-memory",

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$LogPath = "$env:TEMP\docker-desktop-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

function Test-DockerDesktopPrerequisites {
    Write-Log "Checking Docker Desktop prerequisites..." "INFO"

    # Check Windows version (Docker Desktop requires Windows 10 version 2004 or higher)
    $WindowsVersion = [System.Environment]::OSVersion.Version
    if ($WindowsVersion -lt [Version]"10.0.19041") {
        throw "Docker Desktop requires Windows 10 version 2004 or higher. Current: $WindowsVersion"
    }
    Write-Log "✅ Windows version compatible with Docker Desktop" "SUCCESS"

    # Check available memory (Docker Desktop requires significant memory)
    $AvailableRAM = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory/1GB, 1)
    if ($AvailableRAM -lt 8) {
        Write-Log "⚠️ System has less than 8GB RAM. Docker Desktop requires significant resources" "WARN"
        Write-Host "⚠️ Warning: Docker Desktop requires substantial memory (3-5GB)" -ForegroundColor Yellow
    } else {
        Write-Log "✅ Available RAM: ${AvailableRAM}GB (sufficient for Docker Desktop)" "SUCCESS"
    }

    # Check virtualization (required for Docker Desktop)
    try {
        $SystemInfo = systeminfo
        if ($SystemInfo -match "Virtualization Enabled In Firmware:\s*No") {
            throw "Virtualization is not enabled in BIOS/UEFI. Docker Desktop requires virtualization"
        }
        Write-Log "✅ Virtualization is enabled (required for Docker Desktop)" "SUCCESS"
    } catch {
        throw "Could not verify virtualization status. Docker Desktop requires virtualization to be enabled"
    }

    # Check Hyper-V (optional but recommended for Docker Desktop)
    try {
        $HyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
        if ($HyperV.State -ne "Enabled") {
            Write-Log "⚠️ Hyper-V is not enabled (recommended for better performance)" "WARN"
            Write-Host "⚠️ Consider enabling Hyper-V for better Docker Desktop performance" -ForegroundColor Yellow
        } else {
            Write-Log "✅ Hyper-V is enabled (optimal for Docker Desktop)" "SUCCESS"
        }
    } catch {
        Write-Log "Could not check Hyper-V status" "WARN"
    }

    Write-Log "Docker Desktop prerequisites check completed" "SUCCESS"
}

function Download-DockerDesktop {
    Write-Log "Downloading Docker Desktop..." "INFO"

    try {
        # Get latest Docker Desktop download URL
        $DockerDownloadUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
        $DownloadPath = "$env:TEMP\DockerDesktopInstaller.exe"

        Write-Log "Downloading Docker Desktop from: $DockerDownloadUrl" "INFO"
        Write-Host "📥 Downloading Docker Desktop..." -ForegroundColor Cyan

        # Verify download directory exists
        $TempDir = Split-Path $DownloadPath
        if (-not (Test-Path $TempDir)) {
            New-Item -Path $TempDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # Download with progress tracking using Invoke-WebRequest (more secure)
        try {
            $WebResponse = Invoke-WebRequest -Uri $DockerDownloadUrl -OutFile $DownloadPath -UseBasicParsing -ErrorAction Stop

            # Verify file was downloaded and has reasonable size
            if (Test-Path $DownloadPath) {
                $FileInfo = Get-Item $DownloadPath
                if ($FileInfo.Length -lt 10MB) {
                    throw "Downloaded file is too small ($( [math]::Round($FileInfo.Length/1MB, 2) ) MB) - may be incomplete"
                }
                Write-Log "✅ Docker Desktop downloaded successfully" "SUCCESS"
                Write-Log "Downloaded to: $DownloadPath ($([math]::Round($FileInfo.Length/1MB, 2)) MB)" "INFO"
                return $DownloadPath
            } else {
                throw "Docker Desktop download failed - file not created"
            }
        } catch {
            Write-Log "❌ Docker Desktop download failed: $($_.Exception.Message)" "ERROR"
            if (Test-Path $DownloadPath) {
                Remove-Item $DownloadPath -Force -ErrorAction SilentlyContinue
            }
            throw
        }
    } catch {
        Write-Log "❌ Docker Desktop download failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-DockerDesktop {
    param([string]$InstallerPath)

    Write-Log "Installing Docker Desktop..." "INFO"

    try {
        Write-Host "🚀 Installing Docker Desktop..." -ForegroundColor Cyan
        Write-Host "⚠️ This may take several minutes and requires administrator privileges" -ForegroundColor Yellow

        # Verify installer exists
        if (-not (Test-Path $InstallerPath)) {
            throw "Installer not found: $InstallerPath"
        }

        # Check file size to ensure complete download
        $InstallerInfo = Get-Item $InstallerPath
        if ($InstallerInfo.Length -lt 10MB) {
            throw "Installer file appears incomplete ($( [math]::Round($InstallerInfo.Length/1MB, 2) ) MB)"
        }

        # Show user what's happening
        Write-Host "📦 Running Docker Desktop installer..." -ForegroundColor Cyan
        Write-Host "   This will run silently in the background" -ForegroundColor Gray
        Write-Host "   Installation may take 5-10 minutes" -ForegroundColor Gray
        Write-Host ""

        # Run installer silently with better error handling
        try {
            $Process = Start-Process -FilePath $InstallerPath -ArgumentList "/quiet", "/norestart" -Wait -PassThru -ErrorAction Stop

            if ($Process.ExitCode -ne 0) {
                $ExitCode = $Process.ExitCode
                Write-Log "❌ Docker Desktop installation failed with exit code: $ExitCode" "ERROR"

                # Provide context for common exit codes
                switch ($ExitCode) {
                    1603 { Write-Log "💡 Fatal error during installation - try running as Administrator" "INFO" }
                    1641 { Write-Log "💡 Restart required - please restart your computer and try again" "INFO" }
                    3010 { Write-Log "💡 Another installation is in progress - please wait and try again" "INFO" }
                    default { Write-Log "💡 Check Docker Desktop installation logs for details" "INFO" }
                }

                throw "Docker Desktop installation failed with exit code: $ExitCode"
            }

            Write-Log "✅ Docker Desktop installation completed" "SUCCESS"
        } catch {
            Write-Log "❌ Docker Desktop installation failed: $($_.Exception.Message)" "ERROR"
            throw
        }
    } catch {
        Write-Log "❌ Docker Desktop installation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Configure-DockerDesktop {
    Write-Log "Configuring Docker Desktop settings..." "INFO"

    try {
        # Wait for Docker Desktop to start
        Write-Log "Waiting for Docker Desktop to start..." "INFO"
        $DockerReady = $false
        $Attempts = 0
        $MaxAttempts = 60

        do {
            try {
                $DockerVersion = docker --version 2>$null
                if ($DockerVersion) {
                    $DockerReady = $true
                    Write-Log "✅ Docker Desktop is running: $DockerVersion" "SUCCESS"
                }
            } catch {
                Write-Host "Waiting for Docker Desktop to start... ($($Attempts + 1)/$MaxAttempts)" -ForegroundColor Yellow
                Start-Sleep -Seconds 5
                $Attempts++
            }
        } while (-not $DockerReady -and $Attempts -lt $MaxAttempts)

        if (-not $DockerReady) {
            throw "Docker Desktop failed to start within expected time"
        }

        # Configure Docker Desktop settings for optimal performance
        Write-Log "Configuring Docker Desktop for optimal performance..." "INFO"

        # Create Docker daemon configuration
        $DockerConfigPath = "$env:USERPROFILE\.docker\daemon.json"
        $DockerConfigDir = Split-Path $DockerConfigPath

        if (-not (Test-Path $DockerConfigDir)) {
            New-Item -Path $DockerConfigDir -ItemType Directory -Force | Out-Null
        }

        $DockerConfig = @{
            "memory-swap" = 4096  # 4GB swap limit
            "memory" = 3072       # 3GB memory limit
            "cpu-quota" = 51200    # CPU limit (50% of 4 cores)
            "cpu-period" = 100000
            "log-driver" = "json-file"
            "log-opts" = @{
                "max-size" = "10m"
                "max-file" = "3"
            }
            "storage-driver" = "overlay2"
            "experimental" = $false
            "registry-mirrors" = @()
            "insecure-registries" = @()
        }

        $DockerConfigJson = $DockerConfig | ConvertTo-Json -Depth 10
        Set-Content -Path $DockerConfigPath -Value $DockerConfigJson -Force

        Write-Log "✅ Docker Desktop configuration optimized" "SUCCESS"
        Write-Host "💡 Docker Desktop configured with 3GB memory limit" -ForegroundColor Cyan

        # Restart Docker Desktop to apply configuration
        Write-Log "Restarting Docker Desktop to apply configuration..." "INFO"
        Stop-Process -Name "Docker Desktop" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10

        # Wait for Docker Desktop to restart
        $DockerRestarted = $false
        $RestartAttempts = 0
        $MaxRestartAttempts = 30

        do {
            try {
                $DockerVersion = docker --version 2>$null
                if ($DockerVersion) {
                    $DockerRestarted = $true
                    Write-Log "✅ Docker Desktop restarted successfully" "SUCCESS"
                }
            } catch {
                Write-Host "Waiting for Docker Desktop to restart... ($($RestartAttempts + 1)/$MaxRestartAttempts)" -ForegroundColor Yellow
                Start-Sleep -Seconds 5
                $RestartAttempts++
            }
        } while (-not $DockerRestarted -and $RestartAttempts -lt $MaxRestartAttempts)

        if (-not $DockerRestarted) {
            Write-Log "⚠️ Docker Desktop may need manual restart" "WARN"
        }

        Write-Log "Docker Desktop configuration completed" "SUCCESS"
    } catch {
        Write-Log "Docker Desktop configuration failed: $($_.Exception.Message)" "ERROR"
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

        # Copy Docker Desktop-specific docker-compose file
        $DockerComposeSource = "$PSScriptRoot\docker\docker-compose.desktop.yml"
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
    container_name: cortex-postgres-desktop
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
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M

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

function Test-DockerDesktopSetup {
    Write-Log "Testing Docker Desktop setup..." "INFO"

    try {
        # Test Docker command
        Write-Log "Testing Docker command..." "INFO"
        $DockerVersion = docker --version
        if ($LASTEXITCODE -ne 0) {
            throw "Docker command test failed"
        }
        Write-Log "✅ Docker command: $DockerVersion" "SUCCESS"

        # Test Docker Compose
        Write-Log "Testing Docker Compose..." "INFO"
        Set-Location "$InstallPath\docker"
        $ComposeTest = docker-compose config --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Compose test failed"
        }
        Write-Log "✅ Docker Compose: Operational" "SUCCESS"

        # Test Docker system info
        Write-Log "Testing Docker system..." "INFO"
        $SystemInfo = docker system df --format "{{.Type}}\t{{.Size}}" --no-stream
        Write-Log "Docker system info: $SystemInfo" "INFO"

        Write-Log "Docker Desktop setup validation completed successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Docker Desktop setup validation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main installation flow
try {
    Write-Host "🐳 Docker Desktop Setup for MCP Cortex Memory" -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Gray
    Write-Host ""

    Write-Log "Starting Docker Desktop setup..." "INFO"
    Write-Log "Setup log: $LogPath" "INFO"

    # Phase 1: Prerequisites
    Test-DockerDesktopPrerequisites

    # Phase 2: Check if Docker Desktop already installed
    $DockerInstalled = Get-Command "docker" -ErrorAction SilentlyContinue
    if ($DockerInstalled -and -not $Force) {
        Write-Log "Docker Desktop already installed, checking configuration..." "INFO"
        Configure-DockerDesktop
    } else {
        # Phase 3: Download Docker Desktop
        $InstallerPath = Download-DockerDesktop

        # Phase 4: Install Docker Desktop
        Install-DockerDesktop -InstallerPath $InstallerPath

        # Phase 5: Configure Docker Desktop
        Configure-DockerDesktop
    }

    # Phase 6: Setup Docker Compose
    Setup-DockerCompose

    # Phase 7: Validation
    if (Test-DockerDesktopSetup) {
        Write-Host "`n🎉 SUCCESS! Docker Desktop setup completed." -ForegroundColor Green
        Write-Host ""
        Write-Host "📋 Quick Commands:" -ForegroundColor Cyan
        Write-Host "   • Start database: cd `"$InstallPath\docker`" && docker-compose up -d"
        Write-Host "   • Stop database: docker-compose down"
        Write-Host "   • Check status: docker-compose ps"
        Write-Host "   • View logs: docker-compose logs -f postgres"
        Write-Host "   • Docker Desktop: Launch from Start menu"
        Write-Host ""
        Write-Host "💡 Resource Usage:" -ForegroundColor Cyan
        Write-Host "   • Memory: 3-5GB total"
        Write-Host "   • Storage: PostgreSQL data in Docker volume"
        Write-Host "   • Performance: Configured for optimal usage"
        Write-Host "   • Management: GUI available through Docker Desktop"
        Write-Host ""

        Write-Log "Docker Desktop setup completed successfully" "SUCCESS"
        exit 0
    } else {
        throw "Docker Desktop setup validation failed"
    }
} catch {
    Write-Host "`n❌ ERROR: Docker Desktop setup failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Docker Desktop setup failed: $($_.Exception.Message)" "ERROR"

    Write-Host "`n💡 Troubleshooting tips:" -ForegroundColor Cyan
    Write-Host "   • Ensure virtualization is enabled in BIOS/UEFI" -ForegroundColor White
    Write-Host "   • Check Windows 10 version 2004 or higher" -ForegroundColor White
    Write-Host "   • Restart Docker Desktop manually if needed" -ForegroundColor White
    Write-Host "   • Check Docker Desktop logs for detailed errors" -ForegroundColor White
    Write-Host "   • Verify available system memory (8GB+ recommended)" -ForegroundColor White
    exit 1
}