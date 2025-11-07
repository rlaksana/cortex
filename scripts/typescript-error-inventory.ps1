# TypeScript Error Inventory Script (PowerShell Version)
#
# Comprehensive TypeScript error categorization and analysis for daily tracking.
# Generates detailed reports on error patterns, file hotspots, and trends.
#
# Usage: .\scripts\typescript-error-inventory.ps1 [options]
# Options:
#   -Baseline    Set baseline error count
#   -Trend       Show 7-day trend analysis
#   -Export      Export results to JSON file
#   -Help        Show this help message

param(
    [switch]$Baseline,
    [switch]$Trend,
    [switch]$Export,
    [switch]$Help
)

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$ArtifactsDir = Join-Path $ProjectRoot "artifacts"
$BaselineFile = Join-Path $ArtifactsDir "ts-errors-baseline.txt"
$HistoryFile = Join-Path $ArtifactsDir "ts-error-history.json"
$ReportFile = Join-Path $ArtifactsDir "ts-error-inventory-$(Get-Date -Format 'yyyyMMdd').txt"
$JsonReportFile = Join-Path $ArtifactsDir "ts-error-inventory-$(Get-Date -Format 'yyyyMMdd').json"

# Ensure artifacts directory exists
if (!(Test-Path $ArtifactsDir)) {
    New-Item -ItemType Directory -Path $ArtifactsDir -Force | Out-Null
}

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Header {
    param([string]$Message)
    Write-ColorOutput $Message "Blue"
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput $Message "Green"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput $Message "Yellow"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput $Message "Red"
}

# Function to show usage
function Show-Help {
    @"

TypeScript Error Inventory Script (PowerShell)

USAGE:
    .\scripts\typescript-error-inventory.ps1 [OPTIONS]

OPTIONS:
    -Baseline    Set baseline error count
    -Trend       Show 7-day trend analysis
    -Export      Export results to JSON file
    -Help        Show this help message

EXAMPLES:
    .\scripts\typescript-error-inventory.ps1              # Run standard inventory
    .\scripts\typescript-error-inventory.ps1 -Baseline     # Set new baseline
    .\scripts\typescript-error-inventory.ps1 -Trend        # Show trend analysis
    .\scripts\typescript-error-inventory.ps1 -Export       # Export to JSON

"@
}

# Function to run TypeScript compilation and capture errors
function Run-TypeScriptCheck {
    Write-Header "🔍 Running TypeScript Compilation Check..."

    try {
        $tscOutput = & npx tsc --noEmit --pretty false 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "✅ TypeScript compilation passed - no errors found"
            return @{
                Output = ""
                ErrorCount = 0
                Success = $true
            }
        }
    } catch {
        $tscOutput = $_.Exception.Message
    }

    # Extract error count
    $errorCount = 0
    if ($tscOutput -match "Found (\d+) errors?") {
        $errorCount = [int]$matches[1]
    } else {
        # Fallback: count error lines
        $errorCount = ($tscOutput | Select-String "error TS" | Measure-Object).Count
    }

    Write-Warning "⚠️  Found $errorCount TypeScript errors"

    return @{
        Output = $tscOutput
        ErrorCount = $errorCount
        Success = $false
    }
}

# Function to categorize errors by code
function Get-ErrorCategories {
    param([string]$TscOutput)

    Write-Header "📊 Categorizing Errors by Code..."

    # Extract error codes and count them
    $errorCodes = $TscOutput | Select-String "error TS\d+" | ForEach-Object {
        $_.Matches.Value
    } | Group-Object | Sort-Object Count -Descending

    $totalErrors = ($errorCodes | Measure-Object -Property Count -Sum).Sum

    Write-Output "Error Code Distribution (Total: $totalErrors):"
    Write-Output "======================================="
    $errorCodes | ForEach-Object {
        Write-Output ("{0,6} {1}" -f $_.Count, $_.Name)
    }
    Write-Output ""

    return $errorCodes
}

# Function to analyze errors by file
function Get-FileAnalysis {
    param([string]$TscOutput)

    Write-Header "📁 Analyzing Errors by File..."

    # Extract file paths and count errors
    $fileErrors = $TscOutput | Select-String "^[^(:]+" | ForEach-Object {
        $_.Matches.Value.Trim()
    } | Where-Object { $_ -and $_.EndsWith('.ts') } | Group-Object | Sort-Object Count -Descending | Select-Object -First 20

    Write-Output "Top 20 Files with Most Errors:"
    Write-Output "==============================="
    $fileErrors | ForEach-Object {
        Write-Output ("{0,4} {1}" -f $_.Count, $_.Name)
    }
    Write-Output ""

    return $fileErrors
}

# Function to generate detailed report
function New-DetailedReport {
    param(
        [string]$TscOutput,
        [object]$ErrorCategories,
        [object]$FileAnalysis,
        [int]$ErrorCount
    )

    Write-Header "📋 Generating Detailed Error Report..."

    $report = @"
TypeScript Error Inventory Report
==================================
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Project: $(Split-Path -Leaf $ProjectRoot)

Error Summary:
---------------
Total Errors: $ErrorCount

Error Code Distribution:
-----------------------
"@

    $ErrorCategories | ForEach-Object {
        $report += "{0,6} {1}`n" -f $_.Count, $_.Name
    }

    $report += @"

File Analysis:
---------------
"@

    $FileAnalysis | ForEach-Object {
        $report += "{0,4} {1}`n" -f $_.Count, $_.Name
    }

    $report += @"

Error Details (first 100 lines):
--------------
$($TscOutput -split "`n" | Select-Object -First 100 | Out-String)

Generated by: typescript-error-inventory.ps1
"@

    # Save report
    $report | Out-File -FilePath $ReportFile -Encoding UTF8
    Write-Output $report

    Write-Success "📄 Detailed report saved to: $ReportFile"
}

# Function to export to JSON
function Export-ToJson {
    param(
        [object]$ErrorCategories,
        [object]$FileAnalysis,
        [int]$ErrorCount
    )

    Write-Header "💾 Exporting to JSON..."

    # Convert error categories for JSON
    $errorCodesJson = $ErrorCategories | ForEach-Object {
        @{
            code = $_.Name
            count = $_.Count
        }
    }

    # Convert file analysis for JSON
    $filesJson = $FileAnalysis | ForEach-Object {
        @{
            file = $_.Name
            errors = $_.Count
        }
    }

    # Get baseline if exists
    $baseline = $null
    if (Test-Path $BaselineFile) {
        $baselineContent = Get-Content $BaselineFile -Raw
        if ($baselineContent -match "Total: (\d+)") {
            $baseline = [int]$matches[1]
        }
    }

    # Generate JSON report
    $jsonReport = @{
        timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.000Z")
        errorCount = $ErrorCount
        errorCodes = $errorCodesJson
        files = $filesJson
        baseline = $baseline
    } | ConvertTo-Json -Depth 10

    $jsonReport | Out-File -FilePath $JsonReportFile -Encoding UTF8
    Write-Success "📄 JSON report saved to: $JsonReportFile"
}

# Function to set baseline
function Set-Baseline {
    param([int]$ErrorCount)

    Write-Header "📝 Setting TypeScript Error Baseline..."

    $baselineContent = @"
TypeScript Error Baseline
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total: $ErrorCount
"@

    $baselineContent | Out-File -FilePath $BaselineFile -Encoding UTF8
    Write-Success "✅ Baseline set to $ErrorCount errors"
    Write-Success "📄 Baseline saved to: $BaselineFile"
}

# Function to show trend analysis
function Show-Trend {
    Write-Header "📈 7-Day Error Trend Analysis..."

    if (!(Test-Path $HistoryFile)) {
        Write-Warning "⚠️  No history file found. Run script without -Trend to start tracking."
        return
    }

    Write-Output "Recent Error History:"
    Write-Output "===================="

    try {
        $history = Get-Content $HistoryFile -Raw | ConvertFrom-Json
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")

        $history.history | Where-Object { $_.timestamp -ge $sevenDaysAgo } | ForEach-Object {
            Write-Output "$($_.timestamp): $($_.errorCount) errors"
        }
    } catch {
        Write-Warning "⚠️  Error reading history file: $_"
    }
}

# Function to update history
function Update-History {
    param([int]$ErrorCount)

    $today = Get-Date -Format "yyyy-MM-dd"
    $historyEntry = @{
        timestamp = $today
        errorCount = $ErrorCount
    }

    # Create history file if it doesn't exist
    if (!(Test-Path $HistoryFile)) {
        $history = @{
            history = @()
        }
    } else {
        try {
            $history = Get-Content $HistoryFile -Raw | ConvertFrom-Json
        } catch {
            $history = @{
                history = @()
            }
        }
    }

    # Check if today's entry already exists
    $existingEntry = $history.history | Where-Object { $_.timestamp -eq $today }
    if ($existingEntry) {
        $existingEntry.errorCount = $ErrorCount
    } else {
        $history.history += $historyEntry
    }

    # Keep only last 30 days
    $cutoffDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
    $history.history = $history.history | Where-Object { $_.timestamp -ge $cutoffDate }

    $history | ConvertTo-Json -Depth 10 | Out-File -FilePath $HistoryFile -Encoding UTF8
}

# Main execution
Set-Location $ProjectRoot

if ($Help) {
    Show-Help
    exit 0
}

if ($Baseline) {
    $result = Run-TypeScriptCheck
    Set-Baseline -ErrorCount $result.ErrorCount
    exit 0
}

if ($Trend) {
    Show-Trend
    exit 0
}

# Run standard inventory
$result = Run-TypeScriptCheck
$tscOutput = $result.Output
$errorCount = $result.ErrorCount

# Generate analyses
$errorCategories = Get-ErrorCategories -TscOutput $tscOutput
$fileAnalysis = Get-FileAnalysis -TscOutput $tscOutput

# Generate detailed report
New-DetailedReport -TscOutput $tscOutput -ErrorCategories $errorCategories -FileAnalysis $fileAnalysis -ErrorCount $errorCount

# Export to JSON if requested
if ($Export) {
    Export-ToJson -ErrorCategories $errorCategories -FileAnalysis $fileAnalysis -ErrorCount $errorCount
}

# Update history
Update-History -ErrorCount $errorCount

# Show comparison with baseline
if (Test-Path $BaselineFile) {
    $baselineContent = Get-Content $BaselineFile -Raw
    if ($baselineContent -match "Total: (\d+)") {
        $baseline = [int]$matches[1]
        $delta = $errorCount - $baseline

        Write-Output ""
        Write-Header "📊 Baseline Comparison:"
        Write-Output "Current:   $errorCount errors"
        Write-Output "Baseline:  $baseline errors"
        Write-Output "Delta:     $delta"

        if ($delta -gt 0) {
            Write-Error "❌ Error count increased by $delta"
        } elseif ($delta -lt 0) {
            Write-Success "✅ Error count decreased by $(-$delta)"
        } else {
            Write-Success "✅ Error count unchanged"
        }
    }
}

exit 0