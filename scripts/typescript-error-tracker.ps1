#!/usr/bin/env pwsh

<#
.SYNOPSIS
    PowerShell TypeScript Error Tracker - Daily Monitoring Script
.DESCRIPTION
    Tracks TypeScript errors and generates trend analysis for Windows environments
.PARAMETER ProjectRoot
    Root directory of the project (defaults to script parent directory)
.PARAMETER ConfigFile
    Path to TypeScript error budget configuration file
.PARAMETER OutputDir
    Directory for output reports and logs
.PARAMETER GenerateHtml
    Generate HTML report in addition to JSON
.EXAMPLE
    .\typescript-error-tracker.ps1 -ProjectRoot "D:\workspace\my-project" -GenerateHtml
#>

param(
    [string]$ProjectRoot = $PSScriptRoot,
    [string]$ConfigFile = "$PSScriptRoot\..\config\typescript-error-budget.json",
    [string]$OutputDir = "$PSScriptRoot\..\artifacts\typescript-tracking",
    [switch]$GenerateHtml = $false,
    [switch]$Verbose = $false
)

# Strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Configuration
$TrendFile = Join-Path $OutputDir "trends.json"
$DailyReport = Join-Path $OutputDir "daily-$(Get-Date -Format 'yyyy-MM-dd').json"
$WeeklyReport = Join-Path $OutputDir "weekly-$(Get-Date -Format 'yyyy-WW').json"

# Logging functions
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor Cyan
}

function Write-ErrorLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-WarningLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-SuccessLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

# Create directories
function Ensure-Directories {
    Write-Log "Creating directories..."
    $dirs = @(
        $OutputDir,
        "$OutputDir\daily",
        "$OutputDir\weekly",
        "$OutputDir\monthly",
        "$OutputDir\reports"
    )

    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            if ($Verbose) { Write-Log "Created directory: $dir" }
        }
    }
}

# Load configuration
function Load-Configuration {
    $config = @{
        errorBudget = @{
            critical = 0
            high = 5
            medium = 20
        }
    }

    if (Test-Path $ConfigFile) {
        Write-Log "Loading configuration from $ConfigFile"
        try {
            $configData = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            if ($configData.errorBudget) {
                $config.errorBudget.critical = $configData.errorBudget.overall.maxErrorCount
                if ($configData.errorBudget.categories.critical) {
                    $config.errorBudget.critical = $configData.errorBudget.categories.critical.maxErrorCount
                }
                if ($configData.errorBudget.categories.high) {
                    $config.errorBudget.high = $configData.errorBudget.categories.high.maxErrorCount
                }
                if ($configData.errorBudget.categories.medium) {
                    $config.errorBudget.medium = $configData.errorBudget.categories.medium.maxErrorCount
                }
            }
        }
        catch {
            Write-WarningLog "Failed to parse configuration file: $($_.Exception.Message)"
        }
    }
    else {
        Write-WarningLog "Configuration file not found at $ConfigFile, using defaults"
    }

    return $config
}

# Run TypeScript compiler and capture errors
function Analyze-TypeScriptErrors {
    Write-Log "Analyzing TypeScript errors..."

    Push-Location $ProjectRoot

    try {
        # Run TypeScript compiler
        $npmOutput = & npm run type-check 2>&1
        $compilationSuccess = $LASTEXITCODE -eq 0

        # Parse errors from output
        $errorCount = 0
        $criticalCount = 0
        $highCount = 0
        $mediumCount = 0
        $lowCount = 0

        $errorCodes = @{}
        $errorFiles = @{}

        $errors = @()

        foreach ($line in $npmOutput) {
            # Parse TypeScript error format: file(line,column): error TS####: message
            if ($line -match '^(.+)\((\d+),(\d+)\):\s+error\s+TS(\d+):\s+(.+)$') {
                $file = $Matches[1]
                $errorLine = $Matches[2]
                $errorColumn = $Matches[3]
                $errorCode = $Matches[4]
                $message = $Matches[5]

                # Get relative path
                $relativeFile = $file.Replace($ProjectRoot, "").TrimStart("\", "/")

                # Track errors
                if (-not $errorCodes.ContainsKey($errorCode)) {
                    $errorCodes[$errorCode] = 0
                }
                $errorCodes[$errorCode]++

                if (-not $errorFiles.ContainsKey($relativeFile)) {
                    $errorFiles[$relativeFile] = 0
                }
                $errorFiles[$relativeFile]++

                # Categorize errors based on code
                switch ($errorCode) {
                    {$_ -in @("2307","2322","2339","2345","2352","2362","2365")} {
                        $criticalCount++
                    }
                    {$_ -in @("18048","7005","7006","7016","7017","7023")} {
                        $highCount++
                    }
                    {$_ -in @("2564","2391","2367","7031","7034")} {
                        $mediumCount++
                    }
                    default {
                        $lowCount++
                    }
                }

                $errorCount++

                # Store detailed error information
                $errors += @{
                    file = $relativeFile
                    line = [int]$errorLine
                    column = [int]$errorColumn
                    code = $errorCode
                    message = $message
                }
            }
        }

        # Convert error codes hashtable to object for JSON serialization
        $errorCodesObject = [PSCustomObject]@{}
        foreach ($key in $errorCodes.Keys) {
            $errorCodesObject | Add-Member -NotePropertyName $key -NotePropertyValue $errorCodes[$key]
        }

        # Convert error files hashtable to object
        $errorFilesObject = [PSCustomObject]@{}
        foreach ($key in $errorFiles.Keys) {
            $errorFilesObject | Add-Member -NotePropertyName $key -NotePropertyValue $errorFiles[$key]
        }

        # Build metrics object
        $metrics = [PSCustomObject]@{
            timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            date = (Get-Date).ToString("yyyy-MM-dd")
            compilationSuccess = $compilationSuccess
            totalErrors = $errorCount
            criticalErrors = $criticalCount
            highErrors = $highCount
            mediumErrors = $mediumCount
            lowErrors = $lowCount
            errorsByCode = $errorCodesObject
            errorsByFile = $errorFilesObject
            errorDetails = $errors
            errorBudgetStatus = [PSCustomObject]@{
                critical = [PSCustomObject]@{
                    current = $criticalCount
                    budget = $config.errorBudget.critical
                    withinBudget = ($criticalCount -le $config.errorBudget.critical)
                }
                high = [PSCustomObject]@{
                    current = $highCount
                    budget = $config.errorBudget.high
                    withinBudget = ($highCount -le $config.errorBudget.high)
                }
                medium = [PSCustomObject]@{
                    current = $mediumCount
                    budget = $config.errorBudget.medium
                    withinBudget = ($mediumCount -le $config.errorBudget.medium)
                }
            }
        }

        return $metrics
    }
    finally {
        Pop-Location
    }
}

# Load historical trends
function Load-Trends {
    if (Test-Path $TrendFile) {
        Write-Log "Loading historical trends from $TrendFile"
        try {
            return Get-Content $TrendFile -Raw | ConvertFrom-Json
        }
        catch {
            Write-WarningLog "Failed to parse trends file: $($_.Exception.Message)"
            return @{ daily = @(); weekly = @(); monthly = @() }
        }
    }
    else {
        Write-Log "No trends file found, creating new"
        return @{ daily = @(); weekly = @(); monthly = @() }
    }
}

# Update trends with current data
function Update-Trends {
    param($CurrentMetrics, $TrendsData)

    Write-Log "Updating trends..."

    # Add current metrics to daily array
    $TrendsData.daily += $CurrentMetrics

    # Keep only last 30 days of daily data
    if ($TrendsData.daily.Count -gt 30) {
        $TrendsData.daily = $TrendsData.daily | Select-Object -Last 30
    }

    # Generate weekly summary if it's Monday (day of week = 1)
    $dayOfWeek = (Get-Date).DayOfWeek.value__
    if ($dayOfWeek -eq 1 -and $TrendsData.daily.Count -ge 7) {
        Write-Log "Generating weekly summary..."

        $lastSevenDays = $TrendsData.daily | Select-Object -Last 7
        $weeklySummary = [PSCustomObject]@{
            week = (Get-Date).ToString("yyyy-WW")
            totalErrors = ($lastSevenDays | Measure-Object -Property totalErrors -Sum).Sum
            avgErrors = [math]::Round(($lastSevenDays | Measure-Object -Property totalErrors -Average).Average, 2)
            criticalErrors = ($lastSevenDays | Measure-Object -Property criticalErrors -Sum).Sum
            dataPoints = $lastSevenDays.Count
        }

        $TrendsData.weekly += $weeklySummary

        # Keep only last 12 weeks
        if ($TrendsData.weekly.Count -gt 12) {
            $TrendsData.weekly = $TrendsData.weekly | Select-Object -Last 12
        }
    }

    # Save updated trends
    $TrendsData | ConvertTo-Json -Depth 10 | Out-File -FilePath $TrendFile -Encoding UTF8

    return $TrendsData
}

# Generate trend analysis
function Generate-TrendAnalysis {
    param($TrendsData)

    Write-Log "Generating trend analysis..."

    $analysis = [PSCustomObject]@{
        period = "last 30 days"
        dailyDataPoints = $TrendsData.daily.Count
        weeklyDataPoints = $TrendsData.weekly.Count
        trends = $null
        patterns = $null
    }

    # Calculate trends
    if ($TrendsData.daily.Count -ge 2) {
        $firstDay = $TrendsData.daily[0]
        $lastDay = $TrendsData.daily[-1]

        $analysis.trends = [PSCustomObject]@{
            errorTrend = $lastDay.totalErrors - $firstDay.totalErrors
            criticalErrorTrend = $lastDay.criticalErrors - $firstDay.criticalErrors
            avgDailyErrors = [math]::Round(($TrendsData.daily | Measure-Object -Property totalErrors -Average).Average, 2)
        }
    }
    else {
        $analysis.trends = [PSCustomObject]@{
            errorTrend = 0
            criticalErrorTrend = 0
            avgDailyErrors = 0
        }
    }

    # Analyze patterns
    if ($TrendsData.daily.Count -gt 0) {
        # Find most common error code
        $allErrorCodes = @{}
        foreach ($day in $TrendsData.daily) {
            foreach ($code in $day.errorsByCode.PSObject.Properties) {
                if (-not $allErrorCodes.ContainsKey($code.Name)) {
                    $allErrorCodes[$code.Name] = 0
                }
                $allErrorCodes[$code.Name] += $code.Value
            }
        }

        $mostCommonError = if ($allErrorCodes.Keys.Count -gt 0) {
            $maxCode = ($allErrorCodes.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1)
            [PSCustomObject]@{
                code = $maxCode.Key
                totalFreq = $maxCode.Value
            }
        } else { $null }

        # Find most problematic file
        $allErrorFiles = @{}
        foreach ($day in $TrendsData.daily) {
            foreach ($file in $day.errorsByFile.PSObject.Properties) {
                if (-not $allErrorFiles.ContainsKey($file.Name)) {
                    $allErrorFiles[$file.Name] = 0
                }
                $allErrorFiles[$file.Name] += $file.Value
            }
        }

        $mostProblematicFile = if ($allErrorFiles.Keys.Count -gt 0) {
            $maxFile = ($allErrorFiles.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1)
            [PSCustomObject]@{
                file = $maxFile.Key
                totalErrors = $maxFile.Value
            }
        } else { $null }

        $analysis.patterns = [PSCustomObject]@{
            mostCommonError = $mostCommonError
            mostProblematicFile = $mostProblematicFile
        }
    }

    return $analysis
}

# Generate daily report
function Generate-DailyReport {
    param($Metrics, $TrendsData, $Analysis)

    Write-Log "Generating daily report..."

    $recommendations = @()

    # Critical budget recommendations
    if (-not $Metrics.errorBudgetStatus.critical.withinBudget) {
        $recommendations += "Address critical errors immediately - they may impact runtime behavior"
    }

    # High budget recommendations
    if (-not $Metrics.errorBudgetStatus.high.withinBudget) {
        $recommendations += "Review and fix high severity type errors to prevent regressions"
    }

    # Trend recommendations
    if ($Analysis.trends.errorTrend -gt 0) {
        $recommendations += "Error count is trending upward - investigate recent changes"
    }
    elseif ($Analysis.trends.errorTrend -lt 0) {
        $recommendations += "Error count is improving - continue current approach"
    }

    $recommendations += "Run automated TypeScript fix scripts to reduce error count"

    $report = [PSCustomObject]@{
        reportType = "daily"
        date = (Get-Date).ToString("yyyy-MM-dd")
        generatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        metrics = $Metrics
        trendAnalysis = $Analysis
        status = [PSCustomObject]@{
            overall = if ($Metrics.errorBudgetStatus.critical.withinBudget -and $Metrics.errorBudgetStatus.high.withinBudget) { "healthy" } else { "warning" }
            budgetStatus = [PSCustomObject]@{
                critical = $Metrics.errorBudgetStatus.critical
                high = $Metrics.errorBudgetStatus.high
                medium = $Metrics.errorBudgetStatus.medium
            }
        }
        recommendations = $recommendations
        nextActions = @(
            "Review detailed error analysis in the full report",
            "Run appropriate ts-fix scripts based on error patterns",
            "Monitor trends over the next few days",
            "Update baseline if metrics are within acceptable range"
        )
    }

    # Save JSON report
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $DailyReport -Encoding UTF8

    return $report
}

# Generate HTML report
function Generate-HtmlReport {
    param($ReportData)

    if (-not $GenerateHtml) { return }

    Write-Log "Generating HTML report..."

    $HtmlReportPath = Join-Path $OutputDir "reports\daily-$(Get-Date -Format 'yyyy-MM-dd').html"

    $date = $ReportData.date
    $totalErrors = $ReportData.metrics.totalErrors
    $criticalErrors = $ReportData.metrics.criticalErrors
    $highErrors = $ReportData.metrics.highErrors
    $status = $ReportData.status.overall

    $statusColor = switch ($status) {
        "healthy" { "#28a745" }
        "warning" { "#ffc107" }
        "critical" { "#dc3545" }
        default { "#6c757d" }
    }

    $criticalColor = if ($criticalErrors -gt 0) { "#dc3545" } else { "#28a745" }
    $highColor = if ($highErrors -gt 5) { "#ffc107" } else { "#28a745" }

    # Generate HTML content
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypeScript Daily Error Report - $date</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
        .status.healthy { background: #d4edda; color: #155724; }
        .status.warning { background: #fff3cd; color: #856404; }
        .status.critical { background: #f8d7da; color: #721c24; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { padding: 20px; border: 1px solid #dee2e6; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 10px; }
        .metric-label { color: #6c757d; }
        .section { margin: 30px 0; }
        .section h2 { color: #495057; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }
        .recommendations { list-style: none; padding: 0; }
        .recommendations li { padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; background: #f8f9fa; }
        .error-breakdown { margin: 20px 0; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .table th { background: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 TypeScript Daily Error Report</h1>
            <p>Date: $date</p>
            <p>Generated: $(Get-Date)</p>
            <div class="status $status" style="background-color: $statusColor; color: white;">
                $status - $totalErrors total errors
            </div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">$totalErrors</div>
                <div class="metric-label">Total Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: $criticalColor">$criticalErrors</div>
                <div class="metric-label">Critical Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: $highColor">$highErrors</div>
                <div class="metric-label">High Severity Errors</div>
            </div>
        </div>

        <div class="section">
            <h2>💡 Recommendations</h2>
            <ul class="recommendations">
                $($ReportData.recommendations | ForEach-Object { "<li>$_</li>" })
            </ul>
        </div>

        <div class="section">
            <h2>📋 Next Actions</h2>
            <ul class="recommendations">
                $($ReportData.nextActions | ForEach-Object { "<li>$_</li>" })
            </ul>
        </div>

        <div class="footer">
            <p><em>Report generated by TypeScript Error Tracker (PowerShell)</em></p>
            <p><em>For detailed analysis, check the JSON report in artifacts/typescript-tracking/</em></p>
        </div>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $HtmlReportPath -Encoding UTF8
    Write-Log "HTML report saved to $HtmlReportPath"
}

# Main execution
function Main {
    try {
        Write-Log "Starting TypeScript Error Tracker (PowerShell)"

        # Setup
        Ensure-Directories
        $config = Load-Configuration

        # Analyze current state
        Write-Log "Analyzing TypeScript errors..."
        $currentMetrics = Analyze-TypeScriptErrors

        # Load historical data
        $trendsData = Load-Trends

        # Update trends
        $updatedTrends = Update-Trends -CurrentMetrics $currentMetrics -TrendsData $trendsData

        # Generate analysis
        $analysis = Generate-TrendAnalysis -TrendsData $updatedTrends

        # Generate reports
        Write-Log "Generating reports..."
        $dailyReport = Generate-DailyReport -Metrics $currentMetrics -TrendsData $updatedTrends -Analysis $analysis

        # Generate HTML report if requested
        Generate-HtmlReport -ReportData $dailyReport

        # Display summary
        Write-Log ""
        Write-Log "Daily TypeScript Error Summary:"
        Write-Log "  Total Errors: $($currentMetrics.totalErrors)"
        Write-Log "  Critical Errors: $($currentMetrics.criticalErrors)"
        Write-Log "  Status: $($dailyReport.status.overall)"
        Write-Log "  Report: $DailyReport"

        if ($dailyReport.status.overall -eq "warning") {
            Write-WarningLog "TypeScript error budget exceeded - please review recommendations"
            exit 1
        }
        else {
            Write-SuccessLog "TypeScript error budget within acceptable limits"
            exit 0
        }
    }
    catch {
        Write-ErrorLog "TypeScript Error Tracker failed: $($_.Exception.Message)"
        if ($Verbose) { Write-ErrorLog $_.ScriptStackTrace }
        exit 1
    }
}

# Execute main function
Main