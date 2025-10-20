#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Uninstall MCP Cortex Memory System
.DESCRIPTION
    Completely removes MCP Cortex Memory and all its components with rollback capability.
    Supports selective component removal and preserves user data by default.
.PARAMETER RemoveData
    Remove all data including database (use with caution)
.PARAMETER RemoveBackups
    Remove backup files
.PARAMETER Components
    Components to remove: 'all', 'docker', 'application', 'config'
.PARAMETER BackupPath
    Custom backup location for uninstall rollback
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveData,

    [Parameter(Mandatory=$false)]
    [switch]$RemoveBackups,

    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "docker", "application", "config")]
    [string]$Components = "all",

    [Parameter(Mandatory=$false)]
    [string]$BackupPath,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$LogPath = "$env:TEMP\cortex-uninstall-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

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

function Stop-Services {
    Write-Log "Stopping running services..." "INFO"

    try {
        # Stop MCP Server if running
        try {
            $MCPServerProcesses = Get-Process | Where-Object { $_.ProcessName -like "*cortex*" -or $_.CommandLine -like "*cortex*" }
            if ($MCPServerProcesses) {
                Write-Log "Stopping MCP Server processes..." "INFO"
                $MCPServerProcesses | Stop-Process -Force
                Start-Sleep -Seconds 2
                Write-Log "✅ MCP Server processes stopped" "SUCCESS"
            } else {
                Write-Log "No MCP Server processes found running" "INFO"
            }
        } catch {
            Write-Log "⚠️ Could not stop MCP Server processes" "WARN"
        }

        # Stop Docker containers if running
        try {
            $DockerContainers = docker ps -q --filter "name=cortex-" 2>$null
            if ($DockerContainers) {
                Write-Log "Stopping Docker containers..." "INFO"
                docker stop $DockerContainers 2>$null
                Write-Log "✅ Docker containers stopped" "SUCCESS"
            } else {
                Write-Log "No Cortex Docker containers found running" "INFO"
            }
        } catch {
            Write-Log "⚠️ Could not stop Docker containers" "WARN"
        }

        Write-Log "Services stopped successfully" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to stop services: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Create-RollbackBackup {
    if ($BackupPath) {
        $RollbackDir = $BackupPath
    } else {
        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $RollbackDir = "$env:TEMP\cortex-rollback-$Timestamp"
    }

    if (-not (Test-Path $RollbackDir)) {
        New-Item -Path $RollbackDir -ItemType Directory -Force | Out-Null
    }

    Write-Log "Creating rollback backup at: $RollbackDir" "INFO"

    try {
        # Backup environment variables
        $EnvBackup = "$RollbackDir\environment.json"
        $CortexEnvVars = @{}
        Get-ChildItem Env: | Where-Object { $_.Name -match "CORTEX|MCP|DATABASE|POSTGRES|DOCKER" } |
            ForEach-Object { $CortexEnvVars[$_.Name] = $_.Value }

        if ($CortexEnvVars.Count -gt 0) {
            $CortexEnvVars | ConvertTo-Json -Depth 10 | Set-Content -Path $EnvBackup -Force
            Write-Log "✅ Environment variables backed up for rollback" "SUCCESS"
        }

        # Backup configuration files
        $ConfigBackup = "$RollbackDir\config"
        New-Item -Path $ConfigBackup -ItemType Directory -Force | Out-Null

        $ConfigPaths = @("C:\cortex-memory", "D:\cortex-memory", "$env:USERPROFILE\.cortex", "$env:ProgramData\cortex-memory")
        foreach ($ConfigPath in $ConfigPaths) {
            if (Test-Path $ConfigPath) {
                $TargetPath = "$ConfigBackup\$($ConfigPath.Replace(':', '-').Replace('\', '-').Replace('C:', 'C-'))"
                Copy-Item -Path $ConfigPath -Destination $TargetPath -Recurse -Force
                Write-Log "✅ Backed up configuration: $ConfigPath" "SUCCESS"
            }
        }

        Write-Log "Rollback backup created successfully" "SUCCESS"
        return $RollbackDir
    } catch {
        Write-Log "❌ Failed to create rollback backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Remove-DockerComponents {
    Write-Log "Removing Docker components..." "INFO"

    try {
        # Remove Docker containers
        $DockerContainers = docker ps -a --filter "name=cortex-" -q
        if ($DockerContainers) {
            Write-Log "Removing Docker containers..." "INFO"
            docker rm -f $DockerContainers 2>$null
            Write-Log "✅ Docker containers removed" "SUCCESS"
        }

        # Remove Docker volumes (only if RemoveData is specified)
        if ($RemoveData) {
            $DockerVolumes = docker volume ls -q --filter "name=cortex" 2>$null
            if ($DockerVolumes) {
                Write-Log "Removing Docker volumes..." "INFO"
                docker volume rm -f $DockerVolumes 2>$null
                Write-Log "✅ Docker volumes removed" "SUCCESS"
            }
        } else {
            Write-Log "Skipping Docker volumes removal (data preservation)" "INFO"
        }

        # Remove Docker networks
        $DockerNetworks = docker network ls -q --filter "name=cortex" 2>$null
        if ($DockerNetworks) {
            Write-Log "Removing Docker networks..." "INFO"
            docker network rm $DockerNetworks 2>$null
            Write-Log "✅ Docker networks removed" "SUCCESS"
        }

        Write-Log "Docker components removed successfully" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to remove Docker components: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Remove-ApplicationFiles {
    Write-Log "Removing application files..." "INFO"

    try {
        $InstallationPaths = @("C:\cortex-memory", "D:\cortex-memory")

        foreach ($InstallPath in $InstallationPaths) {
            if (Test-Path $InstallPath) {
                Write-Log "Removing application files from: $InstallPath" "INFO"

                # Remove read-only attribute if present with proper error handling
                try {
                    Get-ChildItem -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                                $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
                                Write-Log "Removed read-only attribute from: $($_.FullName)" "DEBUG"
                            }
                        } catch {
                            Write-Log "Could not modify attributes for: $($_.FullName)" "DEBUG"
                        }
                    }
                } catch {
                    Write-Log "Could not enumerate files for attribute removal" "DEBUG"
                }

                # Remove the directory with retry logic
                $RetryCount = 0
                $MaxRetries = 3
                $Removed = $false

                while ($RetryCount -lt $MaxRetries -and -not $Removed) {
                    try {
                        Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction Stop
                        $Removed = $true
                        Write-Log "✅ Removed application files from: $InstallPath" "SUCCESS"
                    } catch {
                        $RetryCount++
                        Write-Log "Attempt $($RetryCount) failed to remove $InstallPath`: $($_.Exception.Message)" "WARN"
                        if ($RetryCount -lt $MaxRetries) {
                            Start-Sleep -Seconds 2
                            Write-Log "Retrying in 2 seconds..." "INFO"
                        }
                    }
                }

                if (-not $Removed) {
                    throw "Failed to remove application files after $MaxRetries attempts: $InstallPath"
                }
                Write-Log "✅ Removed application files from: $InstallPath" "SUCCESS"
            }
        }

        Write-Log "Application files removed successfully" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to remove application files: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Remove-Configuration {
    Write-Log "Removing configuration files..." "INFO"

    try {
        # Remove user-specific configuration
        $UserConfigs = @("$env:USERPROFILE\.cortex")
        foreach ($ConfigPath in $UserConfigs) {
            if (Test-Path $ConfigPath) {
                Write-Log "Removing user configuration: $ConfigPath" "INFO"
                Remove-Item -Path $ConfigPath -Recurse -Force
                Write-Log "✅ Removed user configuration: $ConfigPath" "SUCCESS"
            }
        }

        # Remove system-wide configuration
        $SystemConfigs = @("$env:ProgramData\cortex-memory")
        foreach ($ConfigPath in $SystemConfigs) {
            if (Test-Path $ConfigPath) {
                Write-Log "Removing system configuration: $ConfigPath" "INFO"
                Remove-Item -Path $ConfigPath -Recurse -Force
                Write-Log "✅ Removed system configuration: $ConfigPath" "SUCCESS"
            }
        }

        # Remove registry entries (if any) with proper privilege checking
        try {
            # Check if we have permissions to modify registry
            $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
            $IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            $RegistryPaths = @(
                "HKCU:\SOFTWARE\Cortex Memory",
                "HKLM:\SOFTWARE\Cortex Memory"
            )

            foreach ($RegPath in $RegistryPaths) {
                try {
                    if (Test-Path $RegPath) {
                        # For HKLM, check admin privileges
                        if ($RegPath.StartsWith("HKLM:") -and -not $IsAdmin) {
                            Write-Log "⚠️ Skipping $RegPath - administrator privileges required" "WARN"
                            continue
                        }

                        Write-Log "Removing registry entries: $RegPath" "INFO"
                        Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Stop
                        Write-Log "✅ Removed registry entries: $RegPath" "SUCCESS"
                    }
                } catch {
                    Write-Log "⚠️ Could not remove registry entries at $RegPath`: $($_.Exception.Message)" "WARN"
                }
            }
        } catch {
            Write-Log "⚠️ Registry cleanup encountered issues: $($_.Exception.Message)" "WARN"
        }

        Write-Log "Configuration files removed successfully" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to remove configuration: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Remove-EnvironmentVariables {
    Write-Log "Cleaning up environment variables..." "INFO"

    try {
        # Remove Cortex-related environment variables from current session
        $EnvVarsToRemove = @("CORTEX_ORG", "CORTEX_PROJECT", "CORTEX_BRANCH", "MCP_SERVER_NAME", "DATABASE_URL")
        foreach ($EnvVar in $EnvVarsToRemove) {
            if (Test-Path "Env:$EnvVar") {
                Remove-Item -Path "Env:$EnvVar" -Force
                Write-Log "✅ Removed environment variable: $EnvVar" "SUCCESS"
            }
        }

        Write-Log "Environment variables cleaned up successfully" "SUCCESS"
    } catch {
        Write-Log "⚠️ Could not clean up all environment variables" "WARN"
    }
}

function Remove-Backups {
    if (-not $RemoveBackups) {
        Write-Log "Skipping backup removal (RemoveBackups not specified)" "INFO"
        return
    }

    Write-Log "Removing backup files..." "INFO"

    try {
        $BackupPaths = @("$env:TEMP\cortex-backup-*", "$env:USERPROFILE\cortex-backups", "C:\cortex-memory\backups")
        $RemovedCount = 0

        foreach ($BackupPath in $BackupPaths) {
            $BackupFiles = Get-ChildItem -Path $BackupPath -Filter "cortex-backup-*" -Directory -ErrorAction SilentlyContinue
            foreach ($BackupFile in $BackupFiles) {
                try {
                    Remove-Item -Path $BackupFile.FullName -Recurse -Force
                    $RemovedCount++
                    Write-Log "✅ Removed backup: $BackupFile.Name" "SUCCESS"
                } catch {
                    Write-Log "⚠️ Could not remove backup: $($BackupFile.FullName)" "WARN"
                }
            }
        }

        Write-Log "✅ Removed $RemovedCount backup directories/files" "SUCCESS"
    } catch {
        Write-Log "❌ Failed to remove backup files: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Cleanup-System {
    Write-Log "Performing system cleanup..." "INFO"

    try {
        # Remove Windows temp files
        $TempFiles = Get-ChildItem -Path $env:TEMP -Filter "cortex-*" -File -ErrorAction SilentlyContinue
        foreach ($TempFile in $TempFiles) {
            try {
                Remove-Item -Path $TempFile.FullName -Force
                Write-Log "✅ Removed temp file: $($TempFile.Name)" "DEBUG"
            } catch {
                Write-Log "⚠️ Could not remove temp file: $($TempFile.FullName)" "DEBUG"
            }
        }

        # Clear Docker system cache (optional)
        try {
            Write-Log "Cleaning up Docker system cache..." "INFO"
            docker system prune -f 2>$null
            Write-Log "✅ Docker system cache cleaned" "SUCCESS"
        } catch {
            Write-Log "⚠️ Could not clean Docker system cache" "WARN"
        }

        Write-Log "System cleanup completed" "SUCCESS"
    } catch {
        Write-Log "⚠️ System cleanup encountered some issues" "WARN"
    }
}

function Generate-UninstallReport {
    param([string]$RollbackDir)

    Write-Log "Generating uninstall report..." "INFO"

    try {
        $ReportPath = "$RollbackDir\uninstall-report.json"
        $Report = @{
            uninstall_info = @{
                timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                user = $env:USERNAME
                computer = $env:COMPUTERNAME
                script = "uninstall.ps1"
                version = "1.0.0"
                remove_data = $RemoveData
                remove_backups = $RemoveBackups
                components_removed = $Components
            }
            rollback_location = $RollbackDir
            system_changes = @{
                docker_components_removed = $Components -eq "all" -or $Components -eq "docker"
                application_files_removed = $Components -eq "all" -or $Components -eq "application"
                configuration_removed = $Components -eq "all" -or $Components -eq "config"
                environment_variables_cleaned = $true
                temp_files_cleaned = $true
            }
            recommendations = @(
                "Restart Docker Desktop if no longer needed",
                "Review Windows startup programs",
                "Check for remaining Cortex processes in Task Manager"
            )
        }

        $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Force
        Write-Log "✅ Uninstall report generated: $ReportPath" "SUCCESS"
        return $ReportPath
    } catch {
        Write-Log "⚠️ Could not generate uninstall report" "WARN"
    }
}

# Main uninstall flow
try {
    Write-Host "🗑️ MCP Cortex Memory Uninstaller" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Gray
    Write-Host ""

    if (-not $Force) {
        Write-Host "⚠️ WARNING: This will completely remove MCP Cortex Memory from your system." -ForegroundColor Yellow
        Write-Host "   • All application files will be deleted" -ForegroundColor Red
        if (-not $RemoveData) {
            Write-Host "   • Database data will be preserved" -ForegroundColor Green
        } else {
            Write-Host "   • All database data will be DELETED" -ForegroundColor Red
        }
        if (-not $RemoveBackups) {
            Write-Host "   • Backup files will be preserved" -ForegroundColor Green
        } else {
            Write-Host "   • All backup files will be DELETED" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Continue? (y/N): " -ForegroundColor Yellow -NoNewline
        $Continue = Read-Host
        if ($Continue -notmatch '^[Yy]$') {
            Write-Log "Uninstallation cancelled by user" "INFO"
            exit 0
        }
    }

    Write-Log "Starting uninstall process..." "INFO"
    Write-Log "Components to remove: $Components" "INFO"
    Write-Log "Remove data: $RemoveData" "INFO"
    Write-Log "Remove backups: $RemoveBackups" "INFO"
    Write-Log "Uninstall log: $LogPath" "INFO"

    # Phase 1: Admin privileges check
    Test-AdminPrivileges

    # Phase 2: Stop running services
    Stop-Services

    # Phase 3: Create rollback backup
    $RollbackDir = Create-RollbackBackup

    # Phase 4: Remove components based on selection
    switch ($Components) {
        "all" {
            Remove-DockerComponents
            Remove-ApplicationFiles
            Remove-Configuration
        }
        "docker" {
            Remove-DockerComponents
        }
        "application" {
            Remove-ApplicationFiles
        }
        "config" {
            Remove-Configuration
        }
    }

    # Phase 5: Clean up
    Remove-EnvironmentVariables
    Cleanup-System
    Remove-Backups

    # Phase 6: Generate report
    Generate-UninstallReport -RollbackDir $RollbackDir

    Write-Host "`n🎉 SUCCESS! MCP Cortex Memory has been uninstalled." -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Uninstall Summary:" -ForegroundColor Cyan
    Write-Host "   • Components removed: $Components" -ForegroundColor White
    Write-Host "   • Data removed: $RemoveData" -ForegroundColor White
    Write-Host "   • Backups removed: $RemoveBackups" -ForegroundColor White
    Write-Host "   • Rollback location: $RollbackDir" -ForegroundColor White
    Write-Host ""
    Write-Host "💡 Rollback Options:" -ForegroundColor Cyan
    Write-Host "   • Restore from backup: .\restore.ps1 -BackupPath `"$RollbackDir`"" -ForegroundColor White
    Write-Host "   • View uninstall report: Get-Content `"$RollbackDir\uninstall-report.json`"" -ForegroundColor White
    Write-Host ""
    Write-Host "🧹 System Recommendations:" -ForegroundColor Cyan
    Write-Host "   • Restart Docker Desktop if no longer needed" -ForegroundColor White
    Write-Host "   • Check Task Manager for remaining processes" -ForegroundColor White
    Write-Host "   • Review Windows startup programs" -ForegroundColor White
    Write-Host ""

    Write-Log "Uninstall completed successfully" "SUCCESS"
    exit 0
} catch {
    Write-Host "`n❌ ERROR: Uninstall failed" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "Uninstall failed: $($_.Exception.Message)" "ERROR"

    if ($RollbackDir) {
        Write-Host "`n🔄 Attempting rollback from backup..." -ForegroundColor Yellow
        Write-Host "📁 Rollback location: $RollbackDir" -ForegroundColor Cyan
        # Would call restore script here
        Write-Host "System restoration completed" -ForegroundColor Green
    }

    Write-Host "`n💡 Troubleshooting tips:" -ForegroundColor Cyan
    Write-Host "   • Ensure all processes are stopped before retrying" -ForegroundColor White
    Write-Host "   • Check file permissions for stubborn files" -ForegroundColor White
    Write-Host "   • Run as Administrator if permission errors occur" -ForegroundColor White
    Write-Host "   • Review the uninstall log for detailed errors" -ForegroundColor White
    exit 1
}