# =============================================================================
# VALIDATE EMFILE FIXES POWERSHELL SCRIPT
# =============================================================================
# This script validates that EMFILE prevention fixes are properly applied
# Author: System Administrator
# Last Updated: 2025-10-30
# =============================================================================

param(
    [switch]$Detailed,
    [switch]$Benchmark,
    [switch]$FixIssues,
    [string]$ProjectRoot = $PWD
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Validation thresholds
$ValidationThresholds = @{
    MinSystemHandles = 50000
    MinUserHandles = 25000
    MaxProcessHandles = 2000
    RecommendedMemoryMB = 4096
    WarningHandleUsage = 0.8
    CriticalHandleUsage = 0.9
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
        "Benchmark" { "White" }
        default { "White" }
    }

    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $color
}

# Function to get system handle information
function Get-SystemHandleInfo {
    Write-ColorOutput "Retrieving system handle information..." "Info"

    try {
        # Get overall system statistics
        $systemInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMemoryGB = [math]::Round($systemInfo.TotalVisibleMemorySize / 1MB, 2)
        $freeMemoryGB = [math]::Round($systemInfo.FreePhysicalMemory / 1MB, 2)

        # Get process information with handle counts
        $processes = Get-CimInstance -ClassName Win32_Process |
                    Select-Object Name, ProcessId, HandleCount, WorkingSetSize |
                    Sort-Object HandleCount -Descending

        $totalHandles = ($processes | Measure-Object -Property HandleCount -Sum).Sum
        $avgHandlesPerProcess = [math]::Round($totalHandles / $processes.Count, 2)
        $maxHandlesPerProcess = ($processes | Measure-Object -Property HandleCount -Maximum).Maximum

        # Get Node.js specific processes
        $nodeProcesses = $processes | Where-Object { $_.Name -like "*node*" }
        $nodeTotalHandles = ($nodeProcesses | Measure-Object -Property HandleCount -Sum).Sum

        return @{
            TotalMemoryGB = $totalMemoryGB
            FreeMemoryGB = $freeMemoryGB
            TotalProcesses = $processes.Count
            TotalHandles = $totalHandles
            AverageHandlesPerProcess = $avgHandlesPerProcess
            MaxHandlesPerProcess = $maxHandlesPerProcess
            NodeProcesses = $nodeProcesses.Count
            NodeTotalHandles = $nodeTotalHandles
            TopProcessByHandles = $processes | Select-Object -First 10
            SystemInfo = $systemInfo
        }
    }
    catch {
        Write-ColorOutput "Failed to retrieve system handle information: $_" "Error"
        return $null
    }
}

# Function to validate registry settings
function Test-RegistrySettings {
    Write-ColorOutput "Validating registry handle limit settings..." "Info"

    $results = @{}

    try {
        # Check system-wide handle limits
        $systemRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
        if (Test-Path $systemRegPath) {
            $systemSettings = Get-ItemProperty -Path $systemRegPath -ErrorAction SilentlyContinue

            $results.MaxUserHandles = @{
                Exists = [bool]($systemSettings.PSObject.Properties.Name -contains "MaxUserHandles")
                Value = $systemSettings.MaxUserHandles
                Expected = 131072
                Status = if ($systemSettings.MaxUserHandles -ge 131072) { "Pass" } else { "Fail" }
            }

            $results.MaxSystemHandles = @{
                Exists = [bool]($systemSettings.PSObject.Properties.Name -contains "MaxSystemHandles")
                Value = $systemSettings.MaxSystemHandles
                Expected = 262144
                Status = if ($systemSettings.MaxSystemHandles -ge 262144) { "Pass" } else { "Fail" }
            }

            $results.LongPathEnabled = @{
                Exists = [bool]($systemSettings.PSObject.Properties.Name -contains "LongPathEnabled")
                Value = $systemSettings.LongPathEnabled
                Expected = 1
                Status = if ($systemSettings.LongPathEnabled -eq 1) { "Pass" } else { "Warning" }
            }
        } else {
            Write-ColorOutput "System registry path not found: $systemRegPath" "Warning"
        }

        # Check memory management settings
        $memoryRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        if (Test-Path $memoryRegPath) {
            $memorySettings = Get-ItemProperty -Path $memoryRegPath -ErrorAction SilentlyContinue

            $results.LargeSystemCache = @{
                Exists = [bool]($memorySettings.PSObject.Properties.Name -contains "LargeSystemCache")
                Value = $memorySettings.LargeSystemCache
                Expected = 1
                Status = if ($memorySettings.LargeSystemCache -eq 1) { "Pass" } else { "Warning" }
            }

            $results.PagedPoolSize = @{
                Exists = [bool]($memorySettings.PSObject.Properties.Name -contains "PagedPoolSize")
                Value = $memorySettings.PagedPoolSize
                Expected = 0
                Status = if ($memorySettings.PagedPoolSize -eq 0) { "Pass" } else { "Warning" }
            }
        } else {
            Write-ColorOutput "Memory management registry path not found: $memoryRegPath" "Warning"
        }

        # Display results
        foreach ($key in $results.Keys) {
            $result = $results[$key]
            $color = switch ($result.Status) {
                "Pass" { "Green" }
                "Warning" { "Yellow" }
                "Fail" { "Red" }
                default { "White" }
            }

            $status = if ($result.Exists) { "$($result.Value) (Expected: $($result.Expected))" } else { "Not Set" }
            Write-Host "  $key`: $status" -ForegroundColor $color
        }

        return $results
    }
    catch {
        Write-ColorOutput "Failed to validate registry settings: $_" "Error"
        return @{}
    }
}

# Function to validate environment variables
function Test-EnvironmentVariables {
    Write-ColorOutput "Validating environment variables..." "Info"

    $expectedVars = @{
        "EMFILE_HANDLES_LIMIT" = "131072"
        "UV_THREADPOOL_SIZE" = "16"
        "NODE_OPTIONS" = "--max-old-space-size=4096 --max-semi-space-size=256"
        "NODE_ENV" = "test"
        "TEST_TIMEOUT" = "30000"
        "TEST_WORKERS" = "4"
    }

    $results = @{}

    foreach ($var in $expectedVars.GetEnumerator()) {
        $machineValue = [System.Environment]::GetEnvironmentVariable($var.Key, "Machine")
        $userValue = [System.Environment]::GetEnvironmentVariable($var.Key, "User")
        $processValue = [System.Environment]::GetEnvironmentVariable($var.Key, "Process")

        $results[$var.Key] = @{
            Machine = $machineValue
            User = $userValue
            Process = $processValue
            Expected = $var.Value
            Status = if ($processValue -eq $var.Value) { "Pass" } else { "Fail" }
        }

        $color = switch ($results[$var.Key].Status) {
            "Pass" { "Green" }
            default { "Red" }
        }

        Write-Host "  $($var.Key): $processValue" -ForegroundColor $color
        if ($Detailed) {
            Write-Host "    Machine: $machineValue" -ForegroundColor Gray
            Write-Host "    User: $userValue" -ForegroundColor Gray
            Write-Host "    Expected: $($var.Value)" -ForegroundColor Gray
        }
    }

    return $results
}

# Function to validate project configuration
function Test-ProjectConfiguration {
    param([string]$ProjectRoot)

    Write-ColorOutput "Validating project configuration..." "Info"

    $results = @{}

    # Check .env.test file
    $envTestPath = Join-Path $ProjectRoot ".env.test"
    if (Test-Path $envTestPath) {
        $content = Get-Content $envTestPath -Raw

        $envChecks = @{
            "EMFILE_HANDLES_LIMIT" = $content -match "EMFILE_HANDLES_LIMIT=131072"
            "UV_THREADPOOL_SIZE" = $content -match "UV_THREADPOOL_SIZE=16"
            "NODE_OPTIONS" = $content -match "NODE_OPTIONS=.*max-old-space-size=4096"
            "TEST_TIMEOUT" = $content -match "TEST_TIMEOUT=30000"
        }

        foreach ($check in $envChecks.GetEnumerator()) {
            $results[$check.Key] = @{
                Status = if ($check.Value) { "Pass" } else { "Fail" }
                File = ".env.test"
            }

            $color = if ($check.Value) { "Green" } else { "Red" }
            Write-Host "  $($check.Key) in .env.test: $($check.Value)" -ForegroundColor $color
        }

        $results[".env.test"] = @{
            Status = "Pass"
            File = $envTestPath
            Size = (Get-Item $envTestPath).Length
            LastModified = (Get-Item $envTestPath).LastWriteTime
        }
    } else {
        Write-ColorOutput "  .env.test: File not found" -ForegroundColor Red
        $results[".env.test"] = @{
            Status = "Fail"
            File = "Not found"
        }
    }

    # Check package.json test scripts
    $packageJsonPath = Join-Path $ProjectRoot "package.json"
    if (Test-Path $packageJsonPath) {
        $packageContent = Get-Content $packageJsonPath -Raw | ConvertFrom-Json

        $testScriptExists = [bool]($packageContent.scripts.PSObject.Properties.Name -contains "test")
        $coverageScriptExists = [bool]($packageContent.scripts.PSObject.Properties.Name -contains "test:coverage")

        $results["package.json"] = @{
            Status = if ($testScriptExists) { "Pass" } else { "Warning" }
            TestScript = $testScriptExists
            CoverageScript = $coverageScriptExists
        }

        Write-Host "  package.json test script: $testScriptExists" -ForegroundColor $(if ($testScriptExists) { "Green" } else { "Yellow" })
    } else {
        Write-ColorOutput "  package.json: File not found" -ForegroundColor Red
    }

    # Check if test directories exist
    $testDirs = @("tests", "test", "__tests__")
    $foundTestDir = $false

    foreach ($dir in $testDirs) {
        $testDirPath = Join-Path $ProjectRoot $dir
        if (Test-Path $testDirPath) {
            Write-Host "  Test directory found: $dir" -ForegroundColor Green
            $foundTestDir = $true
            $results["TestDirectory"] = @{
                Status = "Pass"
                Path = $testDirPath
            }
            break
        }
    }

    if (!$foundTestDir) {
        Write-Host "  No test directory found" -ForegroundColor Yellow
        $results["TestDirectory"] = @{
            Status = "Warning"
            Path = "Not found"
        }
    }

    return $results
}

# Function to run performance benchmarks
function Invoke-PerformanceBenchmark {
    Write-ColorOutput "Running performance benchmarks..." "Info"

    $benchmarkResults = @{}

    try {
        # Memory allocation test
        $memoryTest = {
            $arrays = @()
            for ($i = 0; $i -lt 100; $i++) {
                $arrays += ,(New-Object byte[] 1024KB)
            }
            return $arrays.Count
        }

        $memoryTime = Measure-Command { & $memoryTest }
        $benchmarkResults.MemoryAllocation = @{
            TimeMs = $memoryTime.TotalMilliseconds
            Status = if ($memoryTime.TotalMilliseconds -lt 5000) { "Pass" } else { "Warning" }
        }

        Write-Host "  Memory allocation test: $($memoryTime.TotalMilliseconds)ms" -ForegroundColor $(if ($memoryTime.TotalMilliseconds -lt 5000) { "Green" } else { "Yellow" })

        # File handle test
        $tempFiles = @()
        $fileHandleTest = {
            param($count)
            $files = @()
            for ($i = 0; $i -lt $count; $i++) {
                $tempFile = [System.IO.Path]::GetTempFileName()
                $files += $tempFile
                [System.IO.File]::WriteAllText($tempFile, "test content $i")
            }
            return $files.Count
        }

        $handleTime = Measure-Command { $tempFiles = & $fileHandleTest 100 }
        $benchmarkResults.FileHandles = @{
            TimeMs = $handleTime.TotalMilliseconds
            FilesCreated = $tempFiles.Count
            Status = if ($handleTime.TotalMilliseconds -lt 10000) { "Pass" } else { "Warning" }
        }

        Write-Host "  File handle test (100 files): $($handleTime.TotalMilliseconds)ms" -ForegroundColor $(if ($handleTime.TotalMilliseconds -lt 10000) { "Green" } else { "Yellow" })

        # Cleanup temp files
        foreach ($file in $tempFiles) {
            try { Remove-Item $file -Force -ErrorAction SilentlyContinue } catch { }
        }

        # CPU performance test
        $cpuTest = {
            $result = 0
            for ($i = 0; $i -lt 1000000; $i++) {
                $result += [Math]::Sqrt($i)
            }
            return $result
        }

        $cpuTime = Measure-Command { & $cpuTest }
        $benchmarkResults.CPU = @{
            TimeMs = $cpuTime.TotalMilliseconds
            Status = if ($cpuTime.TotalMilliseconds -lt 2000) { "Pass" } else { "Warning" }
        }

        Write-Host "  CPU performance test: $($cpuTime.TotalMilliseconds)ms" -ForegroundColor $(if ($cpuTime.TotalMilliseconds -lt 2000) { "Green" } else { "Yellow" })

    }
    catch {
        Write-ColorOutput "Performance benchmark failed: $_" "Error"
        $benchmarkResults.Error = $_.ToString()
    }

    return $benchmarkResults
}

# Function to fix common issues
function Repair-EMFIssues {
    param([hashtable]$ValidationResults)

    Write-ColorOutput "Attempting to fix identified issues..." "Info"

    $fixesApplied = @()

    try {
        # Fix environment variables
        $envVars = @{
            "EMFILE_HANDLES_LIMIT" = "131072"
            "UV_THREADPOOL_SIZE" = "16"
            "NODE_OPTIONS" = "--max-old-space-size=4096 --max-semi-space-size=256"
        }

        foreach ($var in $envVars.GetEnumerator()) {
            $currentValue = [System.Environment]::GetEnvironmentVariable($var.Key, "User")
            if ($currentValue -ne $var.Value) {
                Write-ColorOutput "Setting environment variable: $($var.Key)" "Info"
                [System.Environment]::SetEnvironmentVariable($var.Key, $var.Value, "User")
                $fixesApplied += "Environment variable: $($var.Key)"
            }
        }

        # Fix registry settings if running as admin
        if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
            if (Test-Path $regPath) {
                Write-ColorOutput "Setting registry handle limits..." "Info"
                Set-ItemProperty -Path $regPath -Name "MaxUserHandles" -Value 131072 -Type DWord -Force
                Set-ItemProperty -Path $regPath -Name "LongPathEnabled" -Value 1 -Type DWord -Force
                $fixesApplied += "Registry: Handle limits"
            }
        } else {
            Write-ColorOutput "Administrator privileges required for registry fixes" "Warning"
        }

        Write-ColorOutput "Fixes applied: $($fixesApplied.Count)" "Success"
        foreach ($fix in $fixesApplied) {
            Write-ColorOutput "  - $fix" "Info"
        }

    }
    catch {
        Write-ColorOutput "Failed to apply fixes: $_" "Error"
    }

    return $fixesApplied
}

# Function to generate comprehensive report
function New-ValidationReport {
    param(
        [hashtable]$SystemInfo,
        [hashtable]$RegistryResults,
        [hashtable]$EnvironmentResults,
        [hashtable]$ProjectResults,
        [hashtable]$BenchmarkResults
    )

    Write-ColorOutput "`n=== COMPREHENSIVE VALIDATION REPORT ===" "Header"

    # System Overview
    Write-ColorOutput "`n--- System Overview ---" "Benchmark"
    Write-Host "Total Memory: $($SystemInfo.TotalMemoryGB)GB (Free: $($SystemInfo.FreeMemoryGB)GB)" -ForegroundColor White
    Write-Host "Total Processes: $($SystemInfo.TotalProcesses)" -ForegroundColor White
    Write-Host "Total Handles: $($SystemInfo.TotalHandles)" -ForegroundColor White
    Write-Host "Average Handles/Process: $($SystemInfo.AverageHandlesPerProcess)" -ForegroundColor White
    Write-Host "Node.js Processes: $($SystemInfo.NodeProcesses) (Handles: $($SystemInfo.NodeTotalHandles))" -ForegroundColor White

    # Handle Usage Analysis
    $handleUsageRatio = [math]::Round(($SystemInfo.TotalHandles / 50000) * 100, 2)
    $usageColor = if ($handleUsageRatio -lt 80) { "Green" } elseif ($handleUsageRatio -lt 90) { "Yellow" } else { "Red" }
    Write-Host "Handle Usage: $handleUsageRatio% of typical limit" -ForegroundColor $usageColor

    # Top Processes by Handles
    if ($Detailed) {
        Write-ColorOutput "`n--- Top 5 Processes by Handle Count ---" "Benchmark"
        $SystemInfo.TopProcessByHandles | Select-Object -First 5 | ForEach-Object {
            Write-Host "  $($_.Name): $($_.HandleCount) handles" -ForegroundColor Gray
        }
    }

    # Registry Status
    Write-ColorOutput "`n--- Registry Settings Status ---" "Benchmark"
    $registryPassed = ($RegistryResults.Values | Where-Object { $_.Status -eq "Pass" }).Count
    $registryTotal = $RegistryResults.Count
    Write-Host "Registry Settings: $registryPassed/$registryTotal optimal" -ForegroundColor $(if ($registryPassed -eq $registryTotal) { "Green" } else { "Yellow" })

    # Environment Variables Status
    Write-ColorOutput "`n--- Environment Variables Status ---" "Benchmark"
    $envPassed = ($EnvironmentResults.Values | Where-Object { $_.Status -eq "Pass" }).Count
    $envTotal = $EnvironmentResults.Count
    Write-Host "Environment Variables: $envPassed/$envTotal correct" -ForegroundColor $(if ($envPassed -eq $envTotal) { "Green" } else { "Red" })

    # Project Configuration Status
    Write-ColorOutput "`n--- Project Configuration Status ---" "Benchmark"
    $projectPassed = ($ProjectResults.Values | Where-Object { $_.Status -eq "Pass" }).Count
    $projectTotal = $ProjectResults.Count
    Write-Host "Project Configuration: $projectPassed/$projectTotal optimal" -ForegroundColor $(if ($projectPassed -eq $projectTotal) { "Green" } else { "Yellow" })

    # Performance Benchmarks
    if ($Benchmark -and $BenchmarkResults) {
        Write-ColorOutput "`n--- Performance Benchmarks ---" "Benchmark"
        foreach ($benchmark in $BenchmarkResults.GetEnumerator()) {
            $color = switch ($benchmark.Value.Status) {
                "Pass" { "Green" }
                "Warning" { "Yellow" }
                default { "Red" }
            }
            Write-Host "$($benchmark.Key): $($benchmark.Value.TimeMs)ms" -ForegroundColor $color
        }
    }

    # Overall Assessment
    $totalChecks = $registryTotal + $envTotal + $projectTotal
    $totalPassed = $registryPassed + $envPassed + $projectPassed
    $overallScore = [math]::Round(($totalPassed / $totalChecks) * 100, 2)

    Write-ColorOutput "`n--- Overall Assessment ---" "Header"
    $scoreColor = if ($overallScore -ge 90) { "Green" } elseif ($overallScore -ge 70) { "Yellow" } else { "Red" }
    Write-Host "Overall Score: $overallScore%" -ForegroundColor $scoreColor

    if ($overallScore -ge 90) {
        Write-ColorOutput "✓ EMFILE prevention configuration is optimal" "Success"
    } elseif ($overallScore -ge 70) {
        Write-ColorOutput "⚠ EMFILE prevention configuration is mostly complete" "Warning"
    } else {
        Write-ColorOutput "✗ EMFILE prevention configuration needs attention" "Error"
    }

    # Recommendations
    Write-ColorOutput "`n--- Recommendations ---" "Info"
    if ($SystemInfo.TotalHandles -gt 40000) {
        Write-Host "- Consider reducing handle usage or increasing limits" -ForegroundColor Yellow
    }
    if ($SystemInfo.NodeProcesses -gt 5) {
        Write-Host "- Monitor Node.js processes for handle leaks" -ForegroundColor Yellow
    }
    if ($SystemInfo.FreeMemoryGB -lt 2) {
        Write-Host "- Consider increasing available memory" -ForegroundColor Yellow
    }
    if ($envPassed -lt $envTotal) {
        Write-Host "- Restart PowerShell to apply environment variable changes" -ForegroundColor Cyan
    }

    return @{
        OverallScore = $overallScore
        TotalChecks = $totalChecks
        PassedChecks = $totalPassed
        Recommendations = @()
    }
}

# Main execution
function Main {
    Write-ColorOutput "EMFILE Fixes Validation Script" "Header"
    Write-ColorOutput "Project Root: $ProjectRoot" "Info"

    try {
        # Step 1: System Information
        Write-ColorOutput "`n=== STEP 1: System Information Analysis ===" "Header"
        $systemInfo = Get-SystemHandleInfo

        if (!$systemInfo) {
            Write-ColorOutput "Failed to retrieve system information" "Error"
            exit 1
        }

        # Step 2: Registry Validation
        Write-ColorOutput "`n=== STEP 2: Registry Settings Validation ===" "Header"
        $registryResults = Test-RegistrySettings

        # Step 3: Environment Variables Validation
        Write-ColorOutput "`n=== STEP 3: Environment Variables Validation ===" "Header"
        $environmentResults = Test-EnvironmentVariables

        # Step 4: Project Configuration Validation
        Write-ColorOutput "`n=== STEP 4: Project Configuration Validation ===" "Header"
        $projectResults = Test-ProjectConfiguration -ProjectRoot $ProjectRoot

        # Step 5: Performance Benchmarks
        if ($Benchmark) {
            Write-ColorOutput "`n=== STEP 5: Performance Benchmarks ===" "Header"
            $benchmarkResults = Invoke-PerformanceBenchmark
        } else {
            $benchmarkResults = @{}
        }

        # Step 6: Apply Fixes if requested
        if ($FixIssues) {
            Write-ColorOutput "`n=== STEP 6: Applying Fixes ===" "Header"
            $allResults = @{
                SystemInfo = $systemInfo
                RegistryResults = $registryResults
                EnvironmentResults = $environmentResults
                ProjectResults = $projectResults
                BenchmarkResults = $benchmarkResults
            }
            Repair-EMFIssues -ValidationResults $allResults
        }

        # Step 7: Generate Report
        Write-ColorOutput "`n=== STEP 7: Validation Report ===" "Header"
        $report = New-ValidationReport -SystemInfo $systemInfo -RegistryResults $registryResults -EnvironmentResults $environmentResults -ProjectResults $projectResults -BenchmarkResults $benchmarkResults

        Write-ColorOutput "`nValidation completed successfully!" "Success"

    } catch {
        Write-ColorOutput "Validation failed: $_" "Error"
        Write-ColorOutput "Stack Trace: $($_.ScriptStackTrace)" "Error"
        exit 1
    }
}

# Execute main function
Main