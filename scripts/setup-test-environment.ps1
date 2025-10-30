# =============================================================================
# SETUP TEST ENVIRONMENT POWERSHELL SCRIPT - EMFILE OPTIMIZATIONS
# =============================================================================
# This script configures the test environment with EMFILE prevention settings
# Author: System Administrator
# Last Updated: 2025-10-30
# =============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$Force,
    [switch]$SkipNodeCheck,
    [switch]$ValidateAfterSetup,
    [string]$ProjectRoot = $PWD
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Node.js optimization settings
$NodeOptimizations = @{
    NodeOptions = "--max-old-space-size=4096 --max-semi-space-size=256 --optimize-for-size --gc-interval=100"
    UvThreadpoolSize = "16"
    NodeMaxSemiSpaceSize = "256"
    NodeMaxOldSpaceSize = "4096"
    NodeMaxExecutableSize = "4096"
}

# Test environment variables
$TestEnvironmentVars = @{
    EMFILE_HANDLES_LIMIT = "131072"
    UV_THREADPOOL_SIZE = "16"
    NODE_OPTIONS = $NodeOptimizations.NodeOptions
    NODE_ENV = "test"
    LOG_LEVEL = "error"
    TEST_TIMEOUT = "30000"
    TEST_WORKERS = "4"
    FORCE_COLOR = "1"
    NO_COLOR = "0"
    CI = "false"
    DEBUG = "test:*"
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
        "Header" { "Magenta" }
        default { "White" }
    }

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $color
}

# Function to validate Node.js installation
function Test-NodeInstallation {
    Write-ColorOutput "Validating Node.js installation..." "Info"

    try {
        $nodeVersion = node --version
        $npmVersion = npm --version

        Write-ColorOutput "Node.js version: $nodeVersion" "Success"
        Write-ColorOutput "NPM version: $npmVersion" "Success"

        # Check Node.js version compatibility
        $versionParts = $nodeVersion -replace 'v', '' -split '\.'
        $majorVersion = [int]$versionParts[0]

        if ($majorVersion -lt 18) {
            Write-ColorOutput "Node.js version $nodeVersion is too old. Version 18+ recommended." "Warning"
            return $false
        }

        # Check available memory for Node.js
        $availableMemory = (Get-CimInstance -ClassName Win32_OperatingSystem).TotalVisibleMemorySize * 1024
        $recommendedMemory = 4GB

        if ($availableMemory -lt $recommendedMemory) {
            Write-ColorOutput "Available memory may be insufficient for optimal Node.js performance." "Warning"
        }

        return $true
    }
    catch {
        Write-ColorOutput "Node.js not found or not working: $_" "Error"
        return $false
    }
}

# Function to set system environment variables
function Set-SystemEnvironmentVariables {
    param([hashtable]$Variables, [switch]$Force)

    Write-ColorOutput "Configuring system environment variables..." "Info"

    $changesMade = @()

    foreach ($var in $Variables.GetEnumerator()) {
        $currentValue = [System.Environment]::GetEnvironmentVariable($var.Key, "Machine")

        if ($currentValue -ne $var.Value -or $Force) {
            Write-ColorOutput "Setting machine-wide variable: $($var.Key) = $($var.Value)" "Info"

            try {
                [System.Environment]::SetEnvironmentVariable($var.Key, $var.Value, "Machine")
                $changesMade += $var.Key
                Write-ColorOutput "Successfully set: $($var.Key)" "Success"
            }
            catch {
                Write-ColorOutput "Failed to set $($var.Key): $_" "Error"
            }
        } else {
            Write-ColorOutput "Variable $($var.Key) already set to desired value" "Info"
        }
    }

    if ($changesMade.Count -gt 0) {
        Write-ColorOutput "Environment variables updated: $($changesMade -join ', ')" "Success"
    } else {
        Write-ColorOutput "All environment variables already configured" "Info"
    }

    return $changesMade.Count -gt 0
}

# Function to set user environment variables
function Set-UserEnvironmentVariables {
    param([hashtable]$Variables, [switch]$Force)

    Write-ColorOutput "Configuring user environment variables..." "Info"

    $changesMade = @()

    foreach ($var in $Variables.GetEnumerator()) {
        $currentValue = [System.Environment]::GetEnvironmentVariable($var.Key, "User")

        if ($currentValue -ne $var.Value -or $Force) {
            Write-ColorOutput "Setting user variable: $($var.Key) = $($var.Value)" "Info"

            try {
                [System.Environment]::SetEnvironmentVariable($var.Key, $var.Value, "User")
                $changesMade += $var.Key
                Write-ColorOutput "Successfully set: $($var.Key)" "Success"
            }
            catch {
                Write-ColorOutput "Failed to set $($var.Key): $_" "Error"
            }
        } else {
            Write-ColorOutput "Variable $($var.Key) already set to desired value" "Info"
        }
    }

    if ($changesMade.Count -gt 0) {
        Write-ColorOutput "User environment variables updated: $($changesMade -join ', ')" "Success"
    } else {
        Write-ColorOutput "All user environment variables already configured" "Info"
    }

    return $changesMade.Count -gt 0
}

# Function to configure PowerShell profiles
function Set-PowerShellProfiles {
    param([string]$ProjectRoot, [switch]$Force)

    Write-ColorOutput "Configuring PowerShell profiles for test environment..." "Info"

    $profiles = @(
        $PROFILE.CurrentUserCurrentHost,
        $PROFILE.CurrentUserAllHosts
    )

    $profileContent = @"
# =============================================================================
# TEST ENVIRONMENT CONFIGURATION - EMFILE OPTIMIZATIONS
# Auto-generated by setup-test-environment.ps1 on $(Get-Date)
# =============================================================================

# EMFILE prevention settings
`$env:EMFILE_HANDLES_LIMIT = "$($TestEnvironmentVars.EMFILE_HANDLES_LIMIT)"
`$env:UV_THREADPOOL_SIZE = "$($TestEnvironmentVars.UV_THREADPOOL_SIZE)"
`$env:NODE_OPTIONS = "$($TestEnvironmentVars.NODE_OPTIONS)"

# Test environment settings
`$env:NODE_ENV = "test"
`$env:LOG_LEVEL = "error"
`$env:FORCE_COLOR = "1"

# Performance optimizations
`$MaximumHistoryCount = 32768
`$MaximumFunctionCount = 32768

# Project-specific shortcuts
function Invoke-TestSuite {
    param([string]$TestPattern = "*.test.ts")
    Write-Host "Running test suite with EMFILE optimizations..." -ForegroundColor Cyan
    npm test -- --testNamePattern "`$TestPattern"
}

function Invoke-TestWithCoverage {
    Write-Host "Running tests with coverage..." -ForegroundColor Cyan
    npm run test:coverage
}

function Invoke-PerformanceTest {
    Write-Host "Running performance tests..." -ForegroundColor Cyan
    npm run test:performance
}

Write-Host "Test environment configuration loaded. Type 'Get-Help Invoke-*' for available commands." -ForegroundColor Green
"@

    foreach ($profilePath in $profiles) {
        if (![string]::IsNullOrEmpty($profilePath)) {
            $profileDir = Split-Path $profilePath -Parent
            if (!(Test-Path $profileDir)) {
                New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
            }

            $configMarker = "# TEST ENVIRONMENT CONFIGURATION - EMFILE OPTIMIZATIONS"
            $existingContent = ""

            if (Test-Path $profilePath) {
                $existingContent = Get-Content $profilePath -Raw
            }

            if ($existingContent -match $configMarker -and !$Force) {
                Write-ColorOutput "Profile $profilePath already configured. Use -Force to overwrite." "Warning"
                continue
            }

            try {
                if ($Force -and $existingContent -match $configMarker) {
                    # Remove existing configuration
                    $existingContent = $existingContent -replace "(?s)$configMarker.*?(?=\n#|\Z)", ""
                    $existingContent = $existingContent.Trim()
                    $existingContent | Out-File -FilePath $profilePath -Encoding UTF8
                }

                $profileContent | Out-File -FilePath $profilePath -Encoding UTF8 -Append
                Write-ColorOutput "Configured PowerShell profile: $profilePath" "Success"
            }
            catch {
                Write-ColorOutput "Failed to configure PowerShell profile $profilePath`: $_" "Error"
            }
        }
    }
}

# Function to configure project environment files
function Set-ProjectEnvironmentFiles {
    param([string]$ProjectRoot, [switch]$Force)

    Write-ColorOutput "Configuring project environment files..." "Info"

    $envTestPath = Join-Path $ProjectRoot ".env.test"
    $envBackupPath = Join-Path $ProjectRoot ".env.test.backup"

    try {
        # Backup existing .env.test if it exists
        if (Test-Path $envTestPath) {
            Write-ColorOutput "Backing up existing .env.test file..." "Info"
            Copy-Item $envTestPath $envBackupPath -Force
        }

        # Read existing content or create new content
        $existingContent = ""
        if (Test-Path $envTestPath) {
            $existingContent = Get-Content $envTestPath -Raw
        }

        # Check if EMFILE settings already exist
        $emfileMarker = "# EMFILE PREVENTION SETTINGS"
        if ($existingContent -match $emfileMarker -and !$Force) {
            Write-ColorOutput ".env.test already contains EMFILE settings. Use -Force to overwrite." "Warning"
            return
        }

        # Add EMFILE prevention settings
        $emfileSettings = @"

# =============================================================================
# EMFILE PREVENTION SETTINGS - AUTO-GENERATED
# Added by setup-test-environment.ps1 on $(Get-Date)
# =============================================================================

# Node.js handle limit optimizations
EMFILE_HANDLES_LIMIT=$($TestEnvironmentVars.EMFILE_HANDLES_LIMIT)
UV_THREADPOOL_SIZE=$($TestEnvironmentVars.UV_THREADPOOL_SIZE)
NODE_OPTIONS=$($TestEnvironmentVars.NODE_OPTIONS)

# Test performance optimizations
TEST_TIMEOUT=$($TestEnvironmentVars.TEST_TIMEOUT)
TEST_WORKERS=$($TestEnvironmentVars.TEST_WORKERS)
NODE_MAX_SEMI_SPACE_SIZE=$($NodeOptimizations.NodeMaxSemiSpaceSize)
NODE_MAX_OLD_SPACE_SIZE=$($NodeOptimizations.NodeMaxOldSpaceSize)

# Windows-specific test settings
FORCE_COLOR=1
NO_COLOR=0
DEBUG=test:*
"@

        if ($Force -and $existingContent -match $emfileMarker) {
            # Remove existing EMFILE settings
            $existingContent = $existingContent -replace "(?s)$emfileMarker.*?(?=\n#|$)", ""
            $existingContent = $existingContent.Trim()
        }

        $newContent = $existingContent + $emfileSettings
        $newContent | Out-File -FilePath $envTestPath -Encoding UTF8

        Write-ColorOutput "Updated .env.test with EMFILE prevention settings" "Success"
    }
    catch {
        Write-ColorOutput "Failed to configure project environment files: $_" "Error"
    }
}

# Function to configure Windows performance settings
function Set-WindowsPerformanceSettings {
    Write-ColorOutput "Configuring Windows performance settings for testing..." "Info"

    try {
        # Set Windows power plan to High Performance
        try {
            $powerPlan = Get-CimInstance -Namespace "root\cimv2\power" -Class Win32_PowerPlan | Where-Object { $_.ElementName -like "*High*" -or $_.ElementName -like "*Performance*" }
            if ($powerPlan) {
                powercfg /setactive $powerPlan.InstanceID
                Write-ColorOutput "Set power plan to High Performance" "Success"
            }
        }
        catch {
            Write-ColorOutput "Could not set power plan: $_" "Warning"
        }

        # Optimize Windows for programs (not background services)
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type DWord -Force
            Write-ColorOutput "Optimized Windows for foreground programs" "Success"
        }
        catch {
            Write-ColorOutput "Could not set Windows priority control: $_" "Warning"
        }

        # Configure system file cache settings
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 -Type DWord -Force
            Write-ColorOutput "Optimized system file cache" "Success"
        }
        catch {
            Write-ColorOutput "Could not set system file cache: $_" "Warning"
        }

    }
    catch {
        Write-ColorOutput "Failed to configure Windows performance settings: $_" "Warning"
    }
}

# Function to validate test environment setup
function Test-TestEnvironmentSetup {
    param([string]$ProjectRoot)

    Write-ColorOutput "Validating test environment setup..." "Info"

    $validationResults = @{}

    # Check environment variables
    foreach ($var in $TestEnvironmentVars.GetEnumerator()) {
        $currentValue = [System.Environment]::GetEnvironmentVariable($var.Key)
        if ($currentValue -eq $var.Value) {
            $validationResults["$($var.Key)"] = $true
            Write-ColorOutput "✓ $($var.Key): $($currentValue)" "Success"
        } else {
            $validationResults["$($var.Key)"] = $false
            Write-ColorOutput "✗ $($var.Key): expected '$($var.Value)', got '$($currentValue)'" "Error"
        }
    }

    # Check project files
    $envTestPath = Join-Path $ProjectRoot ".env.test"
    if (Test-Path $envTestPath) {
        $content = Get-Content $envTestPath -Raw
        $hasEmfileSettings = $content -match "EMFILE_PREVENTION_SETTINGS"

        if ($hasEmfileSettings) {
            $validationResults[".env.test"] = $true
            Write-ColorOutput "✓ .env.test contains EMFILE settings" "Success"
        } else {
            $validationResults[".env.test"] = $false
            Write-ColorOutput "✗ .env.test missing EMFILE settings" "Error"
        }
    } else {
        $validationResults[".env.test"] = $false
        Write-ColorOutput "✗ .env.test file not found" "Error"
    }

    # Check PowerShell profiles
    $profiles = @($PROFILE.CurrentUserCurrentHost, $PROFILE.CurrentUserAllHosts)
    $profilesConfigured = 0

    foreach ($profilePath in $profiles) {
        if (![string]::IsNullOrEmpty($profilePath) -and (Test-Path $profilePath)) {
            $content = Get-Content $profilePath -Raw
            if ($content -match "TEST_ENVIRONMENT_CONFIGURATION") {
                $profilesConfigured++
            }
        }
    }

    if ($profilesConfigured -gt 0) {
        $validationResults["PowerShell Profiles"] = $true
        Write-ColorOutput "✓ PowerShell profiles configured ($profilesConfigured profiles)" "Success"
    } else {
        $validationResults["PowerShell Profiles"] = $false
        Write-ColorOutput "✗ No PowerShell profiles configured" "Error"
    }

    # Summary
    $totalChecks = $validationResults.Count
    $passedChecks = ($validationResults.Values | Where-Object { $_ -eq $true }).Count
    $successRate = [math]::Round(($passedChecks / $totalChecks) * 100, 2)

    Write-ColorOutput "`n=== VALIDATION SUMMARY ===" "Header"
    Write-ColorOutput "Passed: $passedChecks/$totalChecks ($successRate%)" "Info"

    if ($successRate -ge 90) {
        Write-ColorOutput "Test environment setup completed successfully!" "Success"
        return $true
    } elseif ($successRate -ge 70) {
        Write-ColorOutput "Test environment setup mostly complete. Some manual configuration may be needed." "Warning"
        return $true
    } else {
        Write-ColorOutput "Test environment setup incomplete. Please review errors above." "Error"
        return $false
    }
}

# Main execution
function Main {
    Write-ColorOutput "Setting up Windows Test Environment with EMFILE Optimizations" "Header"
    Write-ColorOutput "Project Root: $ProjectRoot" "Info"

    try {
        # Step 1: Validate Node.js installation
        Write-ColorOutput "`n=== STEP 1: Validating Node.js Installation ===" "Header"
        if (!$SkipNodeCheck) {
            $nodeValid = Test-NodeInstallation
            if (!$nodeValid) {
                Write-ColorOutput "Node.js validation failed. Please install Node.js 18+ and try again." "Error"
                exit 1
            }
        } else {
            Write-ColorOutput "Skipping Node.js validation (-SkipNodeCheck specified)" "Warning"
        }

        # Step 2: Configure system environment variables
        Write-ColorOutput "`n=== STEP 2: Configuring System Environment ===" "Header"
        $systemVarsChanged = Set-SystemEnvironmentVariables -Variables $TestEnvironmentVars -Force:$Force

        # Step 3: Configure user environment variables
        Write-ColorOutput "`n=== STEP 3: Configuring User Environment ===" "Header"
        $userVarsChanged = Set-UserEnvironmentVariables -Variables $TestEnvironmentVars -Force:$Force

        # Step 4: Configure PowerShell profiles
        Write-ColorOutput "`n=== STEP 4: Configuring PowerShell Profiles ===" "Header"
        Set-PowerShellProfiles -ProjectRoot $ProjectRoot -Force:$Force

        # Step 5: Configure project environment files
        Write-ColorOutput "`n=== STEP 5: Configuring Project Files ===" "Header"
        Set-ProjectEnvironmentFiles -ProjectRoot $ProjectRoot -Force:$Force

        # Step 6: Configure Windows performance settings
        Write-ColorOutput "`n=== STEP 6: Optimizing Windows Performance ===" "Header"
        Set-WindowsPerformanceSettings

        # Step 7: Validate setup
        Write-ColorOutput "`n=== STEP 7: Validating Setup ===" "Header"
        if ($ValidateAfterSetup) {
            $validationPassed = Test-TestEnvironmentSetup -ProjectRoot $ProjectRoot

            if (!$validationPassed) {
                Write-ColorOutput "Setup validation failed. Please review errors above." "Error"
                exit 1
            }
        }

        # Summary
        Write-ColorOutput "`n=== SETUP COMPLETE ===" "Success"
        Write-ColorOutput "Test environment configured with EMFILE optimizations" "Success"

        if ($systemVarsChanged -or $userVarsChanged) {
            Write-ColorOutput "Environment variables were changed. Restart PowerShell to use new values." "Warning"
        }

        Write-ColorOutput "`nNext steps:" "Info"
        Write-ColorOutput "1. Restart your PowerShell terminal to load new environment variables" "Info"
        Write-ColorOutput "2. Run 'validate-emfile-fixes.ps1' to verify the configuration" "Info"
        Write-ColorOutput "3. Run your test suite: npm test" "Info"
        Write-ColorOutput "4. Monitor for EMFILE errors and adjust settings if needed" "Info"

    } catch {
        Write-ColorOutput "Setup failed: $_" "Error"
        Write-ColorOutput "Stack Trace: $($_.ScriptStackTrace)" "Error"
        exit 1
    }
}

# Execute main function
Main