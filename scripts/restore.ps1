#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Restore MCP Cortex Memory System from backup
.DESCRIPTION
    Restores MCP Cortex Memory from comprehensive backup with validation and rollback support.
    Supports different backup types and provides detailed restore logging.
.PARAMETER BackupPath
    Path to backup directory or compressed backup file
.PARAMETER RestoreType
    Type of restore: 'full', 'config', 'database', 'selective'
.PARAMETER Force
    Skip confirmation prompts and restore without user interaction
.PARAMETER ValidateBeforeRestore
    Validate backup integrity before starting restore process
.PARAMETER CreateRestoreBackup
    Create backup of current state before restore
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Backup path does not exist: $_"
        }
        if (-not (Test-Path $_ -PathType Leaf) -and -not (Test-Path $_ -PathType Container)) {
            throw "Backup path must be a file or directory: $_"
        }
        return $true
    })]
    [string]$BackupPath,

    [Parameter(Mandatory=$false)]
    [ValidateSet("full", "config", "database", "selective")]
    [string]$RestoreType = "full",

    [Parameter(Mandatory=$false)]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    [switch]$ValidateBeforeRestore,

    [Parameter(Mandatory=$false)]
    [switch]$CreateRestoreBackup,

    [Parameter(Mandatory=$false)]
    [ValidateSet("environment", "config", "database", "application")]
    [string[]]$RestoreComponents = @()
)

$LogPath = "$env:TEMP\cortex-restore-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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
            "DEBUG" { "Gray" }
            default { "White" }
        }
    )
    Add-Content -Path $LogPath -Value $LogEntry
}

function Test-AdminPrivileges {
    Write-Log "Checking administrator privileges..." "INFO"

    try {
        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
        if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Administrator privileges required"
        }
        Write-Log "✅ Administrator privileges confirmed" "SUCCESS"
    } catch {
        Write-Log "❌ Administrator privileges check failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Backup-CurrentState {
    Write-Log "Creating backup of current state before restore..." "INFO"

    try {
        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $PreRestoreBackup = "$env:TEMP\cortex-prerestore-$Timestamp"

        if (-not (Test-Path $PreRestoreBackup)) {
            New-Item -Path $PreRestoreBackup -ItemType Directory -Force | Out-Null
        }

        # Backup current configuration files
        $ConfigBackupPath = "$PreRestoreBackup\current-config"
        New-Item -Path $ConfigBackupPath -ItemType Directory -Force | Out-Null

        $ConfigPaths = @(
            "$env:USERPROFILE\.cortex",
            "$env:ProgramData\cortex-memory",
            "C:\cortex-memory",
            "D:\cortex-memory"
        )

        foreach ($ConfigPath in $ConfigPaths) {
            if (Test-Path $ConfigPath) {
                $TargetPath = "$ConfigBackupPath\$($ConfigPath.Replace(':', '-').Replace('\', '-').Replace('C:', 'C-'))"
                Copy-Item -Path $ConfigPath -Destination $TargetPath -Recurse -Force
                Write-Log "✅ Backed up current configuration: $ConfigPath" "SUCCESS"
            }
        }

        # Backup current environment variables
        $EnvBackupPath = "$PreRestoreBackup\current-environment.json"
        $CortexEnvVars = @{}
        Get-ChildItem Env: | Where-Object { $_.Name -match "CORTEX|MCP|DATABASE|POSTGRES|DOCKER" } |
            ForEach-Object { $CortexEnvVars[$_.Name] = $_.Value }

        if ($CortexEnvVars.Count -gt 0) {
            $CortexEnvVars | ConvertTo-Json -Depth 10 | Set-Content -Path $EnvBackupPath -Force
            Write-Log "✅ Backed up current environment variables" "SUCCESS"
        }

        Write-Log "✅ Pre-restore backup created at: $PreRestoreBackup" "SUCCESS"
        return $PreRestoreBackup
    } catch {
        Write-Log "❌ Failed to create pre-restore backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Test-BackupIntegrity {
    param([string]$BackupDir)

    Write-Log "Validating backup integrity..." "INFO"

    try {
        $ManifestPath = "$BackupDir\backup-manifest.json"
        if (-not (Test-Path $ManifestPath)) {
            throw "Backup manifest not found at: $ManifestPath"
        }

        $Manifest = Get-Content -Path $ManifestPath | ConvertFrom-Json
        Write-Log "✅ Backup manifest loaded" "INFO"
        Write-Log "Backup timestamp: $($Manifest.backup_info.timestamp)" "INFO"
        Write-Log "Backup type: $($Manifest.backup_info.backup_type)" "INFO"

        # Validate backup components
        $ExpectedComponents = $Manifest.components.PSObject.Properties.Name
        $MissingComponents = @()

        foreach ($Component in $ExpectedComponents) {
            $ComponentPath = $Manifest.components.$Component
            if ($Component -eq "database") {
                # Check for database backup files
                $DbFiles = Get-ChildItem -Path "$BackupDir\database" -Filter "*.sql*" -ErrorAction SilentlyContinue
                if ($DbFiles.Count -eq 0) {
                    $MissingComponents += $Component
                }
            } elseif ($Component -eq "environment") {
                if (-not (Test-Path "$BackupDir\environment.json")) {
                    $MissingComponents += $Component
                }
            } else {
                if (-not (Test-Path $ComponentPath)) {
                    $MissingComponents += $Component
                }
            }
        }

        if ($MissingComponents.Count -gt 0) {
            throw "Missing backup components: $($MissingComponents -join ', ')"
        }

        Write-Log "✅ Backup integrity validation passed" "SUCCESS"
        return $Manifest
    } catch {
        Write-Log "❌ Backup integrity validation failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-EnvironmentVariables {
    param([string]$BackupDir)

    Write-Log "Restoring environment variables..." "INFO"

    try {
        $EnvBackupPath = "$BackupDir\environment.json"
        if (-not (Test-Path $EnvBackupPath)) {
            Write-Log "⚠️ Environment variables backup not found, skipping" "WARN"
            return
        }

        $EnvData = Get-Content -Path $EnvBackupPath | ConvertFrom-Json
        $RestoredCount = 0

        foreach ($EnvVar in $EnvData.PSObject.Properties) {
            if ($EnvVar.Name -match "CORTEX|MCP|DATABASE|POSTGRES|DOCKER") {
                [System.Environment]::SetEnvironmentVariable($EnvVar.Name, $EnvVar.Value, "User")
                $RestoredCount++
                Write-Log "✅ Restored environment variable: $($EnvVar.Name)" "SUCCESS"
            }
        }

        Write-Log "✅ Environment variables restored ($RestoredCount variables)" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to restore environment variables: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-ConfigurationFiles {
    param([string]$BackupDir)

    Write-Log "Restoring configuration files..." "INFO"

    try {
        $ConfigBackupPath = "$BackupDir\config"
        if (-not (Test-Path $ConfigBackupPath)) {
            Write-Log "⚠️ Configuration backup not found, skipping" "WARN"
            return
        }

        $RestorePaths = @{
            "C-cortex-memory" = "C:\cortex-memory"
            "D-cortex-memory" = "D:\cortex-memory"
            "C-Users-Richard-cortex" = "$env:USERPROFILE\.cortex"
            "C-ProgramData-cortex-memory" = "$env:ProgramData\cortex-memory"
        }

        $RestoredCount = 0
        foreach ($BackupDirName in $RestorePaths.Keys) {
            $BackupSourcePath = "$ConfigBackupPath\$BackupDirName"
            $RestoreTargetPath = $RestorePaths[$BackupDirName]

            if (Test-Path $BackupSourcePath) {
                # Create parent directory if needed
                $ParentDir = Split-Path $RestoreTargetPath -Parent
                if (-not (Test-Path $ParentDir)) {
                    New-Item -Path $ParentDir -ItemType Directory -Force | Out-Null
                }

                Copy-Item -Path $BackupSourcePath -Destination $RestoreTargetPath -Recurse -Force
                Write-Log "✅ Restored configuration: $RestoreTargetPath" "SUCCESS"
                $RestoredCount++
            }
        }

        Write-Log "✅ Configuration files restored ($RestoredCount configurations)" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to restore configuration files: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-Database {
    param([string]$BackupDir)

    Write-Log "Restoring PostgreSQL database..." "INFO"

    try {
        $DatabaseBackupPath = "$BackupDir\database"
        if (-not (Test-Path $DatabaseBackupPath)) {
            Write-Log "⚠️ Database backup not found, skipping" "WARN"
            return
        }

        # Find the most recent database backup file
        $BackupFiles = Get-ChildItem -Path $DatabaseBackupPath -Filter "*.sql*" | Sort-Object LastWriteTime -Descending
        if ($BackupFiles.Count -eq 0) {
            throw "No database backup files found"
        }

        $SelectedBackup = $BackupFiles[0]
        Write-Log "Using database backup: $($SelectedBackup.Name)" "INFO"

        # Check if Docker is running and accessible
        try {
            $DockerStatus = docker version 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Docker is not running or accessible"
            }
        } catch {
            throw "Docker command failed - Docker may not be running"
        }

        # Determine which PostgreSQL container is running
        $ContainerName = $null
        foreach ($Container in @("cortex-postgres-wsl", "cortex-postgres-desktop")) {
            $ContainerStatus = docker ps --filter "name=$Container" --format "{{.Names}}" -q
            if ($ContainerStatus) {
                $ContainerName = $Container
                break
            }
        }

        if (-not $ContainerName) {
            throw "No running Cortex PostgreSQL container found"
        }

        Write-Log "Using PostgreSQL container: $ContainerName" "INFO"

        # Validate backup file before proceeding
        if (-not (Test-Path $SelectedBackup.FullName)) {
            throw "Backup file not found: $($SelectedBackup.FullName)"
        }

        $BackupFileInfo = Get-Item $SelectedBackup.FullName
        if ($BackupFileInfo.Length -lt 1KB) {
            throw "Backup file appears to be empty or corrupted: $($SelectedBackup.FullName)"
        }

        # Copy backup file to container
        $ContainerBackupPath = "/tmp/restore-backup.sql"
        try {
            $CopyProcess = Start-Process -FilePath "docker" -ArgumentList "cp", "`"$($SelectedBackup.FullName)`"", "${ContainerName}:${ContainerBackupPath}" -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($CopyProcess.ExitCode -ne 0) {
                throw "Failed to copy backup file to container with exit code: $($CopyProcess.ExitCode)"
            }

            Write-Log "✅ Backup file copied to container" "SUCCESS"
        } catch {
            Write-Log "❌ Failed to copy backup file: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Verify backup file exists in container
        try {
            $CheckProcess = Start-Process -FilePath "docker" -ArgumentList "exec", $ContainerName, "test", "-f", $ContainerBackupPath -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($CheckProcess.ExitCode -ne 0) {
                throw "Backup file not found in container after copy"
            }
        } catch {
            Write-Log "❌ Backup file verification failed: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Drop existing database and recreate with proper error handling
        Write-Log "Dropping existing database..." "INFO"
        try {
            $DropProcess = Start-Process -FilePath "docker" -ArgumentList "exec", $ContainerName, "psql", "-U", "cortex", "-c", "DROP DATABASE IF EXISTS cortex_prod;" -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($DropProcess.ExitCode -ne 0) {
                Write-Log "⚠️ Warning: Failed to drop existing database (may not exist)" "WARN"
            }

            $CreateProcess = Start-Process -FilePath "docker" -ArgumentList "exec", $ContainerName, "psql", "-U", "cortex", "-c", "CREATE DATABASE cortex_prod;" -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($CreateProcess.ExitCode -ne 0) {
                throw "Failed to recreate database with exit code: $($CreateProcess.ExitCode)"
            }

            Write-Log "✅ Database recreated successfully" "SUCCESS"
        } catch {
            Write-Log "❌ Database recreation failed: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Restore database
        Write-Log "Restoring database from backup..." "INFO"
        try {
            $RestoreProcess = Start-Process -FilePath "docker" -ArgumentList "exec", $ContainerName, "pg_restore", "-U", "cortex", "-d", "cortex_prod", "--verbose", "--clean", "--if-exists", $ContainerBackupPath -Wait -PassThru -NoNewWindow -ErrorAction Stop

            if ($RestoreProcess.ExitCode -ne 0) {
                throw "Database restore failed with exit code: $($RestoreProcess.ExitCode)"
            }

            Write-Log "✅ Database restored successfully" "SUCCESS"
        } catch {
            Write-Log "❌ Database restore failed: $($_.Exception.Message)" "ERROR"
            throw
        }

        # Clean up temporary backup file
        docker exec $ContainerName rm -f $ContainerBackupPath 2>$null

        Write-Log "✅ Database restored successfully" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to restore database: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-ApplicationFiles {
    param([string]$BackupDir)

    Write-Log "Restoring application files..." "INFO"

    try {
        $AppBackupPath = "$BackupDir\application"
        if (-not (Test-Path $AppBackupPath)) {
            Write-Log "⚠️ Application files backup not found, skipping" "WARN"
            return
        }

        $SourceBackupPath = "$AppBackupPath\source"
        if (Test-Path $SourceBackupPath) {
            $TargetPath = $PSScriptRoot
            Write-Log "Restoring source code to: $TargetPath" "INFO"

            # Backup current source if exists
            if (Test-Path $TargetPath) {
                $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $CurrentSourceBackup = "$env:TEMP\cortex-current-source-$Timestamp"
                Copy-Item -Path $TargetPath -Destination $CurrentSourceBackup -Recurse -Force
                Write-Log "Current source backed up to: $CurrentSourceBackup" "INFO"
            }

            # Restore source files (exclude node_modules)
            Get-ChildItem -Path $SourceBackupPath -Recurse | Where-Object {
                $_.FullName -notmatch "node_modules" -and
                $_.FullName -notmatch "\.git" -and
                $_.FullName -notmatch "dist"
            } | ForEach-Object {
                $RelativePath = $_.FullName.Replace($SourceBackupPath, "").TrimStart('\')
                $TargetFile = "$TargetPath\$RelativePath"
                $TargetDir = Split-Path $TargetFile -Parent

                if (-not (Test-Path $TargetDir)) {
                    New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null
                }

                Copy-Item -Path $_.FullName -Destination $TargetFile -Force
            }

            Write-Log "✅ Application source files restored" "SUCCESS"
        }

        $DistBackupPath = "$AppBackupPath\dist"
        if (Test-Path $DistBackupPath) {
            $TargetDistPath = "$PSScriptRoot\dist"
            Copy-Item -Path $DistBackupPath -Destination $TargetDistPath -Recurse -Force
            Write-Log "✅ Build artifacts restored" "SUCCESS"
        }

        Write-Log "✅ Application files restored successfully" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to restore application files: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-RestoreReport {
    param(
        [string]$BackupPath,
        [hashtable]$RestoreComponents,
        [string]$RestoreType,
        [string]$PreRestoreBackup
    )

    Write-Log "Generating restore report..." "INFO"

    try {
        $ReportPath = "$env:TEMP\cortex-restore-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $Report = @{
            restore_info = @{
                timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                user = $env:USERNAME
                computer = $env:COMPUTERNAME
                script = "restore.ps1"
                version = "1.0.0"
                restore_type = $RestoreType
                backup_source = $BackupPath
                pre_restore_backup = $PreRestoreBackup
            }
            components_restored = $RestoreComponents
            system_changes = @{
                environment_variables_restored = $RestoreComponents.ContainsKey("environment")
                configuration_restored = $RestoreComponents.ContainsKey("config")
                database_restored = $RestoreComponents.ContainsKey("database")
                application_files_restored = $RestoreComponents.ContainsKey("application")
            }
            recommendations = @(
                "Restart MCP Cortex Memory service",
                "Verify database connectivity",
                "Test restored configuration",
                "Check application functionality"
            )
            next_steps = @(
                "Run health check: .\health-check.ps1",
                "Start MCP server: npm start",
                "Verify data integrity"
            )
        }

        $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Force
        Write-Log "✅ Restore report generated: $ReportPath" "SUCCESS"
        return $ReportPath
    } catch {
        Write-Log "⚠️ Could not generate restore report" "WARN"
    }
}

# Main restore flow
try {
    Write-Host "🔄 MCP Cortex Memory Restore Utility" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Gray
    Write-Host ""

    Write-Log "Starting restore process..." "INFO"
    Write-Log "Backup source: $BackupPath" "INFO"
    Write-Log "Restore type: $RestoreType" "INFO"
    Write-Log "Restore log: $LogPath" "INFO"

    # Phase 1: Admin privileges check
    Test-AdminPrivileges

    # Phase 2: Validate backup path and prepare backup directory
    if (Test-Path $BackupPath -PathType Container) {
        $BackupDir = $BackupPath
    } elseif (Test-Path $BackupPath -PathType Leaf) {
        # Handle compressed backup
        if ($BackupPath -match "\.zip$") {
            Write-Log "Extracting compressed backup..." "INFO"
            $ExtractPath = "$env:TEMP\cortex-extract-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
            Expand-Archive -Path $BackupPath -DestinationPath $ExtractPath -Force
            $BackupDir = $ExtractPath
            Write-Log "✅ Backup extracted to: $ExtractPath" "SUCCESS"
        } else {
            throw "Unsupported backup format. Please provide .zip file or directory."
        }
    } else {
        throw "Backup path not found: $BackupPath"
    }

    # Phase 3: Validate backup integrity (if requested)
    if ($ValidateBeforeRestore) {
        $Manifest = Test-BackupIntegrity -BackupDir $BackupDir
    }

    # Phase 4: Create pre-restore backup (if requested)
    $PreRestoreBackup = $null
    if ($CreateRestoreBackup) {
        $PreRestoreBackup = Backup-CurrentState
    }

    # Phase 5: Show restore summary and get confirmation
    Write-Host "📋 Restore Summary:" -ForegroundColor Cyan
    Write-Host "   • Backup source: $BackupPath" -ForegroundColor White
    Write-Host "   • Restore type: $RestoreType" -ForegroundColor White
    Write-Host "   • Target system: $env:COMPUTERNAME" -ForegroundColor White
    if ($PreRestoreBackup) {
        Write-Host "   • Pre-restore backup: $PreRestoreBackup" -ForegroundColor White
    }
    Write-Host ""

    if (-not $Force) {
        Write-Host "⚠️ WARNING: This will overwrite current MCP Cortex Memory data and configuration." -ForegroundColor Yellow
        Write-Host "   • All current configuration will be replaced" -ForegroundColor Red
        Write-Host "   • Database will be restored from backup" -ForegroundColor Red
        Write-Host "   • Application files may be overwritten" -ForegroundColor Red
        Write-Host ""
        Write-Host "Continue? (y/N): " -ForegroundColor Yellow -NoNewline
        $Continue = Read-Host
        if ($Continue -notmatch '^[Yy]$') {
            Write-Log "Restore cancelled by user" "INFO"
            exit 0
        }
    }

    # Phase 6: Perform restore based on type
    $RestoreComponents = @{}

    switch ($RestoreType) {
        "full" {
            Write-Host "🔄 Performing full restore..." -ForegroundColor Yellow
            $RestoreComponents.environment = Restore-EnvironmentVariables -BackupDir $BackupDir
            $RestoreComponents.config = Restore-ConfigurationFiles -BackupDir $BackupDir
            $RestoreComponents.database = Restore-Database -BackupDir $BackupDir
            $RestoreComponents.application = Restore-ApplicationFiles -BackupDir $BackupDir
        }
        "config" {
            Write-Host "🔄 Performing configuration restore..." -ForegroundColor Yellow
            $RestoreComponents.environment = Restore-EnvironmentVariables -BackupDir $BackupDir
            $RestoreComponents.config = Restore-ConfigurationFiles -BackupDir $BackupDir
        }
        "database" {
            Write-Host "🔄 Performing database restore..." -ForegroundColor Yellow
            $RestoreComponents.database = Restore-Database -BackupDir $BackupDir
        }
        "selective" {
            Write-Host "🔄 Performing selective restore..." -ForegroundColor Yellow
            if ($RestoreComponents.Contains("environment")) {
                $RestoreComponents.environment = Restore-EnvironmentVariables -BackupDir $BackupDir
            }
            if ($RestoreComponents.Contains("config")) {
                $RestoreComponents.config = Restore-ConfigurationFiles -BackupDir $BackupDir
            }
            if ($RestoreComponents.Contains("database")) {
                $RestoreComponents.database = Restore-Database -BackupDir $BackupDir
            }
            if ($RestoreComponents.Contains("application")) {
                $RestoreComponents.application = Restore-ApplicationFiles -BackupDir $BackupDir
            }
        }
    }

    # Phase 7: Generate restore report
    $ReportPath = Generate-RestoreReport -BackupPath $BackupPath -RestoreComponents $RestoreComponents -RestoreType $RestoreType -PreRestoreBackup $PreRestoreBackup

    Write-Host ""
    Write-Host "🎉 SUCCESS! MCP Cortex Memory has been restored." -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Restore Summary:" -ForegroundColor Cyan
    foreach ($Component in $RestoreComponents.Keys) {
        $ComponentPath = $RestoreComponents[$Component]
        Write-Host "   • $Component`: $ComponentPath" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "📊 Restore report: $ReportPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "💡 Next Steps:" -ForegroundColor Cyan
    Write-Host "   • Run health check: .\health-check.ps1" -ForegroundColor White
    Write-Host "   • Start MCP server: npm start" -ForegroundColor White
    Write-Host "   • Verify data integrity and functionality" -ForegroundColor White
    if ($PreRestoreBackup) {
        Write-Host "   • Pre-restore backup available at: $PreRestoreBackup" -ForegroundColor Gray
    }
    Write-Host ""

    Write-Log "Restore process completed successfully" "SUCCESS"
    exit 0
} catch {
    Write-Host "`n❌ ERROR: Restore failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Restore failed: $($_.Exception.Message)" "ERROR"

    Write-Host "`n💡 Troubleshooting tips:" -ForegroundColor Cyan
    Write-Host "   • Verify backup integrity and accessibility" -ForegroundColor White
    Write-Host "   • Ensure Docker is running if restoring database" -ForegroundColor White
    Write-Host "   • Check file permissions for target directories" -ForegroundColor White
    Write-Host "   • Review the restore log for detailed errors" -ForegroundColor White
    Write-Host "   • Use pre-restore backup if available to recover" -ForegroundColor White
    exit 1
}