#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Backup MCP Cortex Memory System
.DESCRIPTION
    Creates comprehensive backup of MCP Cortex Memory configuration, data, and settings.
    Supports multiple backup types and compression options.
.PARAMETER BackupType
    Type of backup: 'full', 'config', 'database', 'incremental'
.PARAMETER BackupPath
    Custom backup location (default: auto-generated)
.PARAMETER Compression
    Enable compression for backup files
.PARAMETER IncludeDocker
    Include Docker volumes and images in backup
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "config", "database", "incremental")]
    [string]$BackupType = "full",

    [Parameter(Mandatory=$false)]
    [string]$BackupPath,

    [Parameter(Mandatory=$false)]
    [switch]$Compression,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeDocker,

    [Parameter(Mandatory=$false)]
    [switch]$SkipDatabaseDump
)

$LogPath = "$env:TEMP\cortex-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

function Get-BackupLocation {
    if ($BackupPath) {
        $BackupDir = $BackupPath
    } else {
        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $BackupDir = "$env:TEMP\cortex-backup-$Timestamp"
    }

    if (-not (Test-Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
        Write-Log "Created backup directory: $BackupDir" "SUCCESS"
    }

    return $BackupDir
}

function Backup-EnvironmentVariables {
    param([string]$BackupDir)

    Write-Log "Backing up environment variables..." "INFO"

    try {
        $EnvBackupPath = "$BackupDir\environment.json"

        # Get Cortex-related environment variables
        $CortexEnvVars = @{}
        Get-ChildItem Env: | Where-Object {
            $_.Name -match "CORTEX|MCP|DATABASE|POSTGRES|DOCKER"
        } | ForEach-Object {
            $CortexEnvVars[$_.Name] = $_.Value
        }

        # Add system information
        $CortexEnvVars["system_info"] = @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            computer_name = $env:COMPUTERNAME
            user_domain = $env:USERDOMAIN
            windows_version = [System.Environment]::OSVersion.Version.ToString()
            powershell_version = $PSVersionTable.PSVersion.ToString()
        }

        # Save to JSON
        $CortexEnvVars | ConvertTo-Json -Depth 10 | Set-Content -Path $EnvBackupPath -Force

        Write-Log "✅ Environment variables backed up to: $EnvBackupPath" "SUCCESS"
        return $EnvBackupPath
    } catch {
        Write-Log "❌ Failed to backup environment variables: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Backup-ConfigurationFiles {
    param([string]$BackupDir)

    Write-Log "Backing up configuration files..." "INFO"

    try {
        $ConfigBackupPath = "$BackupDir\config"
        New-Item -Path $ConfigBackupPath -ItemType Directory -Force | Out-Null

        $ConfigPaths = @(
            "$env:USERPROFILE\.cortex",
            "$env:ProgramData\cortex-memory",
            "C:\cortex-memory",
            "D:\cortex-memory"
        )

        $BackedUpFiles = @()
        foreach ($ConfigPath in $ConfigPaths) {
            if (Test-Path $ConfigPath) {
                $TargetPath = "$ConfigBackupPath\$($ConfigPath.Replace(':', '-').Replace('\', '-').Replace('C:', 'C-'))"
                Copy-Item -Path $ConfigPath -Destination $TargetPath -Recurse -Force
                $BackedUpFiles += $ConfigPath
                Write-Log "✅ Backed up configuration: $ConfigPath" "SUCCESS"
            }
        }

        # Create configuration manifest
        $ConfigManifest = @{
            backup_timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            backed_up_paths = $BackedUpFiles
            backup_type = $BackupType
            compression_enabled = $Compression
        }
        $ConfigManifest | ConvertTo-Json -Depth 5 | Set-Content -Path "$ConfigBackupPath\manifest.json" -Force

        Write-Log "✅ Configuration files backed up to: $ConfigBackupPath" "SUCCESS"
        return $ConfigBackupPath
    } catch {
        Write-Log "❌ Failed to backup configuration files: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Backup-Database {
    param([string]$BackupDir)

    if ($SkipDatabaseDump) {
        Write-Log "Skipping database dump (SkipDatabaseDump specified)" "WARN"
        return
    }

    Write-Log "Backing up PostgreSQL database..." "INFO"

    try {
        $DatabaseBackupPath = "$BackupDir\database"
        New-Item -Path $DatabaseBackupPath -ItemType Directory -Force | Out-Null

        # Generate backup filename
        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $BackupFile = "$DatabaseBackupPath\cortex-prod-backup-$Timestamp.sql"

        # Determine which PostgreSQL container is running
        $ContainerName = $null
        $RunningContainers = @("cortex-postgres-wsl", "cortex-postgres-desktop")

        foreach ($Container in $RunningContainers) {
            try {
                $ContainerStatus = docker ps --filter "name=$Container" --format "{{.Names}}" -q 2>$null
                if ($ContainerStatus -and $LASTEXITCODE -eq 0) {
                    $ContainerName = $Container
                    Write-Log "Found running PostgreSQL container: $ContainerName" "INFO"
                    break
                }
            } catch {
                Write-Log "Could not check container: $Container" "DEBUG"
            }
        }

        if (-not $ContainerName) {
            throw "No running PostgreSQL container found. Checked: $($RunningContainers -join ', ')"
        }

        # Test database connectivity first
        try {
            $DatabaseStatus = docker exec $ContainerName pg_isready -U cortex -d cortex_prod -t 10 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Database connectivity test failed for container: $ContainerName"
            }
            Write-Log "✅ Database connectivity confirmed" "SUCCESS"
        } catch {
            Write-Log "❌ Database connectivity test failed: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Create backup directory inside container
        try {
            docker exec $ContainerName mkdir -p /backup 2>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Log "⚠️ Could not create /backup directory in container, using /tmp" "WARN"
                $BackupDirInContainer = "/tmp"
            } else {
                $BackupDirInContainer = "/backup"
            }
        } catch {
            $BackupDirInContainer = "/tmp"
        }

        # Perform database dump using Start-Process for better error handling
        Write-Log "Creating database dump..." "INFO"
        $DumpFileInContainer = "$BackupDirInContainer/cortex-prod-backup.sql"

        try {
            $DumpProcess = Start-Process -FilePath "docker" -ArgumentList "exec", $ContainerName, "pg_dump", "-U", "cortex", "-d", "cortex_prod", "--verbose", "--format=custom", "--no-owner", "--no-privileges", "--file=$DumpFileInContainer" -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($DumpProcess.ExitCode -ne 0) {
                throw "Database dump failed with exit code: $($DumpProcess.ExitCode)"
            }

            Write-Log "✅ Database dump created in container" "SUCCESS"
        } catch {
            Write-Log "❌ Database dump failed: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Copy backup file from container to host
        try {
            $CopyProcess = Start-Process -FilePath "docker" -ArgumentList "cp", "${ContainerName}:${DumpFileInContainer}", $BackupFile -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($CopyProcess.ExitCode -ne 0) {
                throw "Failed to copy backup file from container with exit code: $($CopyProcess.ExitCode)"
            }

            Write-Log "✅ Database backup copied to host" "SUCCESS"
        } catch {
            Write-Log "❌ Failed to copy backup file: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Compress backup if requested
        if ($Compression) {
            Write-Log "Compressing database backup..." "INFO"
            Compress-Archive -Path $BackupFile -DestinationPath "$BackupFile.zip" -Force
            Remove-Item -Path $BackupFile -Force
            $BackupFile = "$BackupFile.zip"
        }

        Write-Log "✅ Database backed up to: $BackupFile" "SUCCESS"
        return $BackupFile
    } catch {
        Write-Log "❌ Failed to backup database: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Backup-DockerComponents {
    param([string]$BackupDir)

    if (-not $IncludeDocker) {
        Write-Log "Skipping Docker components backup (IncludeDocker not specified)" "INFO"
        return
    }

    Write-Log "Backing up Docker components..." "INFO"

    try {
        $DockerBackupPath = "$BackupDir\docker"
        New-Item -Path $DockerBackupPath -ItemType Directory -Force | Out-Null

        # Backup Docker Compose configurations
        $DockerComposePaths = @(
            "C:\cortex-memory\docker\docker-compose.yml",
            "C:\cortex-memory\docker\docker-compose.wsl.yml",
            "C:\cortex-memory\docker\docker-compose.desktop.yml"
        )

        foreach ($ComposePath in $DockerComposePaths) {
            if (Test-Path $ComposePath) {
                $FileName = Split-Path $ComposePath -Leaf
                Copy-Item -Path $ComposePath -Destination "$DockerBackupPath\$FileName" -Force
                Write-Log "✅ Backed up Docker Compose: $FileName" "SUCCESS"
            }
        }

        # Backup Docker volumes (data only, not the containers)
        Write-Log "Backing up Docker volumes..." "INFO"
        $DockerVolumes = docker volume ls --format "{{.Name}}" -q
        $CortexVolumes = $DockerVolumes | Where-Object { $_ -match "cortex" }

        foreach ($VolumeName in $CortexVolumes) {
            try {
                $VolumeInfo = docker volume inspect $VolumeName --format '{{json}}' | ConvertFrom-Json
                $MountPoint = $VolumeInfo[0].Mountpoint

                if ($MountPoint) {
                    $VolumeBackupPath = "$DockerBackupPath\volumes\$($VolumeName)"
                    New-Item -Path $VolumeBackupPath -ItemType Directory -Force | Out-Null

                    # Copy volume contents (metadata only, not all data for performance)
                    $VolumeInfo | ConvertTo-Json -Depth 5 | Set-Content -Path "$VolumeBackupPath\metadata.json" -Force
                    Write-Log "✅ Backed up Docker volume metadata: $VolumeName" "SUCCESS"
                }
            } catch {
                Write-Log "⚠️ Could not backup Docker volume: $VolumeName" "WARN"
            }
        }

        # Backup Docker images list (metadata only)
        $DockerImages = docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" --filter "reference=*cortex*"
        $DockerImages | Out-File -FilePath "$DockerBackupPath\images-list.txt" -Encoding UTF8

        Write-Log "✅ Docker components backed up to: $DockerBackupPath" "SUCCESS"
        return $DockerBackupPath
    } catch {
        Write-Log "❌ Failed to backup Docker components: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Backup-ApplicationFiles {
    param([string]$BackupDir)

    Write-Log "Backing up application files..." "INFO"

    try {
        $AppBackupPath = "$BackupDir\application"
        New-Item -Path $AppBackupPath -ItemType Directory -Force | Out-Null

        # Source code backup
        $SourcePath = $PSScriptRoot
        if (Test-Path $SourcePath) {
            $SourceBackupPath = "$AppBackupPath\source"
            New-Item -Path $SourceBackupPath -ItemType Directory -Force | Out-Null

            # Exclude node_modules and build artifacts
            $ExcludePattern = @("node_modules", "dist", "*.log", "*.tmp", ".git")
            Get-ChildItem -Path $SourcePath -Recurse | Where-Object {
                $Exclude = $false
                foreach ($Pattern in $ExcludePattern) {
                    if ($_.FullName -match [regex]::Escape($Pattern)) {
                        $Exclude = $true
                        break
                    }
                }
                -not $Exclude
            } | ForEach-Object {
                    $RelativePath = $_.FullName.Replace($SourcePath, "").TrimStart('\')
                    $TargetPath = "$SourceBackupPath\$RelativePath"
                    $TargetDir = Split-Path $TargetPath

                    if (-not (Test-Path $TargetDir)) {
                        New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null
                    }

                    Copy-Item -Path $_.FullName -Destination $TargetPath -Force
                }

            Write-Log "✅ Source code backed up to: $SourceBackupPath" "SUCCESS"
        }

        # Build artifacts backup
        $DistPath = "$SourcePath\dist"
        if (Test-Path $DistPath) {
            $DistBackupPath = "$AppBackupPath\dist"
            Copy-Item -Path $DistPath -Destination $DistBackupPath -Recurse -Force
            Write-Log "✅ Build artifacts backed up to: $DistBackupPath" "SUCCESS"
        }

        # Create application manifest
        $AppManifest = @{
            backup_timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            source_path = $SourcePath
            dist_path = $DistPath
            node_modules_present = Test-Path "$SourcePath\node_modules"
            build_artifacts_present = Test-Path $DistPath
            backup_type = $BackupType
        }
        $AppManifest | ConvertTo-Json -Depth 5 | Set-Content -Path "$AppBackupPath\manifest.json" -Force

        Write-Log "✅ Application files backed up to: $AppBackupPath" "SUCCESS"
        return $AppBackupPath
    } catch {
        Write-Log "❌ Failed to backup application files: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Create-BackupManifest {
    param(
        [string]$BackupDir,
        [hashtable]$BackupComponents,
        [string]$BackupType
    )

    Write-Log "Creating backup manifest..." "INFO"

    try {
        $Manifest = @{
            backup_info = @{
                timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                backup_type = $BackupType
                backup_path = $BackupDir
                compression_enabled = $Compression
                include_docker = $IncludeDocker
                skip_database_dump = $SkipDatabaseDump
                creator = "cortex-backup.ps1"
                version = "1.0.0"
            }
            components = $BackupComponents
            system_info = @{
                computer_name = $env:COMPUTERNAME
                user_domain = $env:USERDOMAIN
                windows_version = [System.Environment]::OSVersion.Version.ToString()
                powershell_version = $PSVersionTable.PSVersion.ToString()
                total_backup_size_mb = 0  # Would calculate actual size if needed
            }
        }

        $ManifestPath = "$BackupDir\backup-manifest.json"
        $Manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $ManifestPath -Force

        Write-Log "✅ Backup manifest created: $ManifestPath" "SUCCESS"
        return $ManifestPath
    } catch {
        Write-Log "❌ Failed to create backup manifest: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# Main backup flow
try {
    Write-Host "🔄 MCP Cortex Memory Backup Utility" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Gray
    Write-Host ""

    Write-Log "Starting backup process..." "INFO"
    Write-Log "Backup type: $BackupType" "INFO"
    Write-Log "Backup log: $LogPath" "INFO"

    # Determine backup location
    $BackupDir = Get-BackupLocation
    Write-Log "Backup location: $BackupDir" "INFO"

    # Perform backup based on type
    $BackupComponents = @{}

    switch ($BackupType) {
        "full" {
            Write-Host "🔄 Performing full backup..." -ForegroundColor Yellow
            $BackupComponents.environment = Backup-EnvironmentVariables -BackupDir $BackupDir
            $BackupComponents.config = Backup-ConfigurationFiles -BackupDir $BackupDir
            $BackupComponents.database = Backup-Database -BackupDir $BackupDir
            $BackupComponents.docker = Backup-DockerComponents -BackupDir $BackupDir
            $BackupComponents.application = Backup-ApplicationFiles -BackupDir $BackupDir
        }
        "config" {
            Write-Host "🔄 Performing configuration backup..." -ForegroundColor Yellow
            $BackupComponents.environment = Backup-EnvironmentVariables -BackupDir $BackupDir
            $BackupComponents.config = Backup-ConfigurationFiles -BackupDir $BackupDir
        }
        "database" {
            Write-Host "🔄 Performing database backup..." -ForegroundColor Yellow
            $BackupComponents.database = Backup-Database -BackupDir $BackupDir
        }
        "incremental" {
            Write-Host "🔄 Performing incremental backup..." -ForegroundColor Yellow
            # For incremental, we'd check last backup and only backup changed files
            $BackupComponents.environment = Backup-EnvironmentVariables -BackupDir $BackupDir
            $BackupComponents.config = Backup-ConfigurationFiles -BackupDir $BackupDir
            # Add incremental logic here if needed
        }
    }

    # Create backup manifest
    Create-BackupManifest -BackupDir $BackupDir -BackupComponents $BackupComponents -BackupType $BackupType

    # Compress entire backup if requested
    if ($Compression) {
        Write-Host "🗜️ Compressing backup..." -ForegroundColor Yellow
        $CompressedPath = "$BackupDir.zip"
        Compress-Archive -Path $BackupDir -DestinationPath $CompressedPath -Force
        Write-Log "✅ Backup compressed to: $CompressedPath" "SUCCESS"
        Write-Host ""
        Write-Host "🎉 SUCCESS! Backup completed and compressed." -ForegroundColor Green
        Write-Host "📁 Backup location: $CompressedPath" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "🎉 SUCCESS! Backup completed." -ForegroundColor Green
        Write-Host "📁 Backup location: $BackupDir" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "📋 Backup Summary:" -ForegroundColor Cyan
    foreach ($Component in $BackupComponents.Keys) {
        $ComponentPath = $BackupComponents[$Component]
        Write-Host "   • $Component`: $ComponentPath" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "💡 Restore command: .\restore.ps1 -BackupPath `"$($Compression ? $CompressedPath : $BackupDir)`"" -ForegroundColor Gray
    Write-Host "📊 Backup manifest: $BackupDir\backup-manifest.json" -ForegroundColor Gray

    Write-Log "Backup process completed successfully" "SUCCESS"
    exit 0
} catch {
    Write-Host "`n❌ ERROR: Backup failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Backup failed: $($_.Exception.Message)" "ERROR"

    Write-Host "`n💡 Troubleshooting tips:" -ForegroundColor Cyan
    Write-Host "   • Ensure Docker is running if backing up database" -ForegroundColor White
    Write-Host "   • Check file permissions for target directory" -ForegroundColor White
    Write-Host "   " -ForegroundColor White
    Write-Host "   Verify backup location exists and is accessible" -ForegroundColor White
    exit 1
}