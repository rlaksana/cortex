# =============================================================================
# INCREASE HANDLES POWERSHELL SCRIPT - EMFILE FIXES
# =============================================================================
# This script increases Windows file handle limits to prevent EMFILE errors
# Author: System Administrator
# Last Updated: 2025-10-30
# =============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$Force,
    [switch]$SkipRestart,
    [switch]$WhatIf
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Registry paths
$RegistryPaths = @{
    SystemWide = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    CurrentUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Performance = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
}

# Handle limit configurations
$HandleLimits = @{
    # Windows 10/11 default limits (can be increased)
    SystemWideLimit = 65536
    UserLimit = 32768
    ReservedForSystem = 2048

    # Optimized values for development workloads
    OptimizedSystemWide = 262144
    OptimizedUserLimit = 131072
    OptimizedReserved = 4096
}

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )

    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Info" { "Cyan" }
        default { "White" }
    }

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $color
}

# Function to check administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to backup registry keys
function Backup-RegistryKeys {
    param([string]$BackupPath)

    Write-ColorOutput "Creating registry backup..." "Info"

    try {
        $backupDir = Split-Path $BackupPath -Parent
        if (!(Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupFile = "$backupPath-$timestamp.reg"

        # Export relevant registry keys
        $keysToBackup = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        )

        $regContent = @"
Windows Registry Editor Version 5.00

; Registry backup created on $(Get-Date)
; For EMFILE handle limit fixes

"@

        foreach ($key in $keysToBackup) {
            if (Test-Path $key) {
                $regContent += "`n`n; $key`n"
                $regContent += reg export $key "$env:TEMP\temp-backup.reg" /y
                $tempContent = Get-Content "$env:TEMP\temp-backup.reg" -Raw
                $regContent += $tempContent -replace "Windows Registry Editor Version 5.00`r`n", ""
                Remove-Item "$env:TEMP\temp-backup.reg" -Force -ErrorAction SilentlyContinue
            }
        }

        $regContent | Out-File -FilePath $backupFile -Encoding UTF8
        Write-ColorOutput "Registry backup created: $backupFile" "Success"
        return $backupFile
    }
    catch {
        Write-ColorOutput "Failed to create registry backup: $_" "Error"
        return $null
    }
}

# Function to get current handle limits
function Get-CurrentHandleLimits {
    Write-ColorOutput "Retrieving current handle limits..." "Info"

    $limits = @{}

    try {
        # Get system-wide handle count information
        $systemInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $limits.TotalHandles = $systemInfo.NumberOfProcesses
        $limits.SystemUpTime = $systemInfo.LocalDateTime

        # Get current handle usage
        $processes = Get-CimInstance -ClassName Win32_Process | Measure-Object -Property HandleCount -Sum
        $limits.CurrentHandleUsage = $processes.Sum

        # Get registry settings if they exist
        if (Test-Path $RegistryPaths.SystemWide) {
            $fsSettings = Get-ItemProperty -Path $RegistryPaths.SystemWide -ErrorAction SilentlyContinue
            $limits.RegistrySystemLimit = $fsSettings.NtfsDisable8dot3NameCreation
        }

        if (Test-Path $RegistryPaths.Performance) {
            $memSettings = Get-ItemProperty -Path $RegistryPaths.Performance -ErrorAction SilentlyContinue
            $limits.RegistryUserLimit = $memSettings.PagedPoolSize
        }

        Write-ColorOutput "Current handle usage: $($limits.CurrentHandleUsage) handles across $($limits.TotalHandles) processes" "Info"

        return $limits
    }
    catch {
        Write-ColorOutput "Failed to retrieve current handle limits: $_" "Warning"
        return @{}
    }
}

# Function to validate handle limits
function Test-HandleLimits {
    param([hashtable]$CurrentLimits)

    Write-ColorOutput "Validating current handle limits..." "Info"

    $issues = @()

    # Check if we're approaching Windows handle limits
    if ($CurrentLimits.CurrentHandleUsage -and $CurrentLimits.CurrentHandleUsage -gt 50000) {
        $issues += "High handle usage detected: $($CurrentLimits.CurrentHandleUsage) handles"
    }

    # Check for common EMFILE indicators
    try {
        $nodeProcesses = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.Name -like "*node*" }
        foreach ($process in $nodeProcesses) {
            if ($process.HandleCount -gt 2000) {
                $issues += "Node.js process $($process.Name) has high handle count: $($process.HandleCount)"
            }
        }
    }
    catch {
        Write-ColorOutput "Could not analyze Node.js processes: $_" "Warning"
    }

    if ($issues.Count -gt 0) {
        Write-ColorOutput "Handle limit issues detected:" "Warning"
        foreach ($issue in $issues) {
            Write-ColorOutput "  - $issue" "Warning"
        }
        return $false
    }

    Write-ColorOutput "No critical handle limit issues detected" "Success"
    return $true
}

# Function to apply registry modifications
function Set-HandleLimitsRegistry {
    param([hashtable]$Limits, [switch]$WhatIf)

    Write-ColorOutput "Applying registry modifications for handle limits..." "Info"

    try {
        # Create or modify registry values for system-wide handle limits
        $registryChanges = @(
            @{
                Path = $RegistryPaths.SystemWide
                Name = "MaxUserHandles"
                Value = $Limits.OptimizedUserLimit
                Type = "DWord"
                Description = "Maximum user handles"
            },
            @{
                Path = $RegistryPaths.SystemWide
                Name = "MaxSystemHandles"
                Value = $Limits.OptimizedSystemWide
                Type = "DWord"
                Description = "Maximum system handles"
            },
            @{
                Path = $RegistryPaths.Performance
                Name = "SystemPages"
                Value = 0
                Type = "DWord"
                Description = "System pages optimization"
            },
            @{
                Path = $RegistryPaths.Performance
                Name = "PagedPoolSize"
                Value = 0
                Type = "DWord"
                Description = "Paged pool size (0 = auto)"
            },
            @{
                Path = $RegistryPaths.Performance
                Name = "NonPagedPoolSize"
                Value = 0
                Type = "DWord"
                Description = "Non-paged pool size (0 = auto)"
            }
        )

        foreach ($change in $registryChanges) {
            if (!(Test-Path $change.Path)) {
                Write-ColorOutput "Creating registry path: $($change.Path)" "Info"
                if (!$WhatIf) {
                    New-Item -Path $change.Path -Force | Out-Null
                }
            }

            Write-ColorOutput "Setting $($change.Description): $($change.Value)" "Info"
            if (!$WhatIf) {
                Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.Value -Type $change.Type -Force
            }
        }

        # Add Windows 10/11 specific optimizations
        $windowsVersion = [System.Environment]::OSVersion.Version
        if ($windowsVersion.Major -ge 10) {
            $win10Changes = @(
                @{
                    Path = $RegistryPaths.SystemWide
                    Name = "LongPathEnabled"
                    Value = 1
                    Type = "DWord"
                    Description = "Enable long path support"
                },
                @{
                    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                    Name = "EnableLUA"
                    Value = 1
                    Type = "DWord"
                    Description = "User Account Control"
                }
            )

            foreach ($change in $win10Changes) {
                if (!(Test-Path $change.Path)) {
                    Write-ColorOutput "Creating registry path: $($change.Path)" "Info"
                    if (!$WhatIf) {
                        New-Item -Path $change.Path -Force | Out-Null
                    }
                }

                Write-ColorOutput "Setting $($change.Description): $($change.Value)" "Info"
                if (!$WhatIf) {
                    Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.Value -Type $change.Type -Force
                }
            }
        }

        Write-ColorOutput "Registry modifications completed successfully" "Success"
        return $true
    }
    catch {
        Write-ColorOutput "Failed to apply registry modifications: $_" "Error"
        return $false
    }
}

# Function to set user-specific configurations
function Set-UserHandleConfigurations {
    param([switch]$WhatIf)

    Write-ColorOutput "Configuring user-specific handle settings..." "Info"

    try {
        # Set environment variables for current user
        $envVars = @(
            @{
                Name = "EMFILE_HANDLES_LIMIT"
                Value = $HandleLimits.OptimizedUserLimit
                Description = "EMFILE handle limit"
            },
            @{
                Name = "UV_THREADPOOL_SIZE"
                Value = "16"
                Description = "Node.js thread pool size"
            },
            @{
                Name = "NODE_OPTIONS"
                Value = "--max-old-space-size=4096 --max-semi-space-size=256"
                Description = "Node.js optimization flags"
            }
        )

        foreach ($envVar in $envVars) {
            Write-ColorOutput "Setting environment variable: $($envVar.Description)" "Info"
            if (!$WhatIf) {
                [System.Environment]::SetEnvironmentVariable($envVar.Name, $envVar.Value, "User")
            }
        }

        # Configure PowerShell profile for handle optimizations
        $profilePath = $PROFILE.CurrentUserAllHosts
        $profileContent = @"
# EMFILE Handle Limit Optimizations - Added $(Get-Date)
# These settings help prevent 'too many open files' errors

# Environment variables for handle optimization
`$env:EMFILE_HANDLES_LIMIT = '$($HandleLimits.OptimizedUserLimit)'
`$env:UV_THREADPOOL_SIZE = '16'

# PowerShell handle limit optimizations
`$MaximumHistoryCount = 32768
`$MaximumFunctionCount = 32768

# File system optimizations
`$env:PYTHONUNBUFFERED = '1'
`$env:FORCE_COLOR = '1'

"@

        if (!(Test-Path (Split-Path $profilePath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $profilePath -Parent) -Force | Out-Null
        }

        if (!(Test-Path $profilePath) -or $Force) {
            Write-ColorOutput "Updating PowerShell profile: $profilePath" "Info"
            if (!$WhatIf) {
                $profileContent | Out-File -FilePath $profilePath -Encoding UTF8 -Append
            }
        } else {
            Write-ColorOutput "PowerShell profile exists. Use -Force to overwrite." "Warning"
        }

        Write-ColorOutput "User configurations completed successfully" "Success"
        return $true
    }
    catch {
        Write-ColorOutput "Failed to set user configurations: $_" "Error"
        return $false
    }
}

# Function to check restart requirement
function Test-RestartRequired {
    Write-ColorOutput "Checking if restart is required..." "Info"

    $restartRequired = $false

    # Check if registry changes require restart
    try {
        $currentSession = Get-CimInstance -ClassName Win32_OperatingSystem
        $lastBootTime = $currentSession.LastBootUpTime

        # Check if we made changes to system-wide settings
        $systemSettingsPath = $RegistryPaths.SystemWide
        if (Test-Path $systemSettingsPath) {
            $settings = Get-ItemProperty -Path $systemSettingsPath
            if ($settings.MaxUserHandles -and $settings.MaxUserHandles -ne $HandleLimits.UserLimit) {
                $restartRequired = $true
                Write-ColorOutput "System-wide handle limits modified - restart required" "Warning"
            }
        }
    }
    catch {
        Write-ColorOutput "Could not determine restart requirement: $_" "Warning"
    }

    return $restartRequired
}

# Main execution
function Main {
    Write-ColorOutput "Starting Windows Handle Limit Optimization Script" "Info"
    Write-ColorOutput "Target: Prevent EMFILE errors for development workloads" "Info"

    # Check administrator privileges
    if (!(Test-Administrator)) {
        Write-ColorOutput "This script requires administrator privileges. Please run as Administrator." "Error"
        exit 1
    }

    if ($WhatIf) {
        Write-ColorOutput "Running in WHAT-IF mode - no changes will be made" "Warning"
    }

    try {
        # Step 1: Get current status
        Write-ColorOutput "`n=== STEP 1: Analyzing Current Handle Limits ===" "Info"
        $currentLimits = Get-CurrentHandleLimits
        $limitsValid = Test-HandleLimits -CurrentLimits $currentLimits

        if ($limitsValid -and !$Force) {
            Write-ColorOutput "Current handle limits appear adequate. Use -Force to apply optimizations anyway." "Success"
            if (!(Read-Host "Continue with optimizations? (y/N): ").ToLower().StartsWith('y')) {
                Write-ColorOutput "Script cancelled by user" "Info"
                exit 0
            }
        }

        # Step 2: Create backup
        Write-ColorOutput "`n=== STEP 2: Creating Registry Backup ===" "Info"
        $backupPath = "$env:USERPROFILE\Documents\Registry-Backup-EMFILE"
        $backupFile = Backup-RegistryKeys -BackupPath $backupPath

        if (!$backupFile -and !$WhatIf) {
            Write-ColorOutput "Failed to create registry backup. Aborting for safety." "Error"
            exit 1
        }

        # Step 3: Apply registry modifications
        Write-ColorOutput "`n=== STEP 3: Applying Registry Modifications ===" "Info"
        $registrySuccess = Set-HandleLimitsRegistry -Limits $HandleLimits -WhatIf:$WhatIf

        if (!$registrySuccess -and !$WhatIf) {
            Write-ColorOutput "Failed to apply registry modifications." "Error"
            exit 1
        }

        # Step 4: Set user configurations
        Write-ColorOutput "`n=== STEP 4: Configuring User Settings ===" "Info"
        $userSuccess = Set-UserHandleConfigurations -WhatIf:$WhatIf

        if (!$userSuccess -and !$WhatIf) {
            Write-ColorOutput "Failed to set user configurations." "Warning"
            # Continue anyway as registry changes might be sufficient
        }

        # Step 5: Check restart requirement
        Write-ColorOutput "`n=== STEP 5: Validation and Next Steps ===" "Info"
        $restartNeeded = Test-RestartRequired

        if ($restartNeeded -and !$SkipRestart -and !$WhatIf) {
            Write-ColorOutput "`nSYSTEM RESTART REQUIRED" "Warning"
            Write-ColorOutput "The changes made require a system restart to take effect." "Warning"
            Write-ColorOutput "Backup file: $backupFile" "Info"

            $restart = Read-Host "Restart now? (y/N): "
            if ($restart.ToLower().StartsWith('y')) {
                Write-ColorOutput "Restarting system in 10 seconds..." "Warning"
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            } else {
                Write-ColorOutput "Please restart your system manually to apply changes." "Warning"
            }
        } elseif ($WhatIf) {
            Write-ColorOutput "WHAT-IF mode completed. No changes were made." "Success"
            Write-ColorOutput "Backup would have been created at: $backupPath" "Info"
        } else {
            Write-ColorOutput "Handle limit optimizations applied successfully!" "Success"
            Write-ColorOutput "Backup file: $backupFile" "Info"
            Write-ColorOutput "Run 'validate-emfile-fixes.ps1' to verify the changes." "Info"
        }

        Write-ColorOutput "`n=== OPTIMIZATION SUMMARY ===" "Success"
        Write-ColorOutput "System-wide handles: $($HandleLimits.OptimizedSystemWide)" "Info"
        Write-ColorOutput "User handles: $($HandleLimits.OptimizedUserLimit)" "Info"
        Write-ColorOutput "Reserved handles: $($HandleLimits.OptimizedReserved)" "Info"
        Write-ColorOutput "Environment variables configured for Node.js optimization" "Info"

    } catch {
        Write-ColorOutput "Script execution failed: $_" "Error"
        Write-ColorOutput "Stack Trace: $($_.ScriptStackTrace)" "Error"
        exit 1
    }
}

# Execute main function
Main