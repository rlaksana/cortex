#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Health Check for MCP Cortex Memory System
.DESCRIPTION
    Comprehensive health monitoring for MCP Cortex Memory components including database,
    Docker containers, application services, and system resources.
.PARAMETER Component
    Specific component to check: 'all', 'database', 'docker', 'application', 'system'
.PARAMETER Detailed
    Show detailed health information including performance metrics
.PARAMETER OutputFormat
    Output format: 'console', 'json', 'html'
.PARAMETER Continuous
    Run continuous monitoring with specified interval
.PARAMETER AlertThresholds
    Custom alert thresholds for memory, CPU, and disk usage
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "database", "docker", "application", "system")]
    [string]$Component = "all",

    [Parameter(Mandatory=$false)]
    [switch]$Detailed,

    [Parameter(Mandatory=$false)]
    [ValidateSet("console", "json", "html")]
    [string]$OutputFormat = "console",

    [Parameter(Mandatory=$false)]
    [int]$Continuous,

    [Parameter(Mandatory=$false)]
    [hashtable]$AlertThresholds = @{}
)

$LogPath = "$env:TEMP\cortex-health-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Default alert thresholds
$DefaultThresholds = @{
    memory_warning = 80      # Memory usage percentage for warning
    memory_critical = 90     # Memory usage percentage for critical
    cpu_warning = 75         # CPU usage percentage for warning
    cpu_critical = 90        # CPU usage percentage for critical
    disk_warning = 80        # Disk usage percentage for warning
    disk_critical = 90       # Disk usage percentage for critical
    response_time_warning = 5000  # Response time in milliseconds
    response_time_critical = 10000 # Response time in milliseconds
}

$Thresholds = $DefaultThresholds + $AlertThresholds

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogEntry
}

function Write-HealthStatus {
    param(
        [string]$Component,
        [string]$Status,
        [string]$Message,
        [hashtable]$Metrics = @{}
    )

    $StatusColor = switch ($Status) {
        "HEALTHY" { "Green" }
        "WARNING" { "Yellow" }
        "CRITICAL" { "Red" }
        "UNKNOWN" { "Gray" }
        default { "White" }
    }

    $Icon = switch ($Status) {
        "HEALTHY" { "✅" }
        "WARNING" { "⚠️" }
        "CRITICAL" { "❌" }
        "UNKNOWN" { "❓" }
        default { "ℹ️" }
    }

    if ($OutputFormat -eq "console") {
        Write-Host "$Icon $Component`: $Status" -ForegroundColor $StatusColor
        if ($Message) {
            Write-Host "   $Message" -ForegroundColor White
        }
        if ($Detailed -and $Metrics.Count -gt 0) {
            foreach ($Metric in $Metrics.GetEnumerator()) {
                Write-Host "   • $($Metric.Key): $($Metric.Value)" -ForegroundColor Gray
            }
        }
    }

    Write-Log "$Component - $Status`: $Message"
}

function Test-DockerHealth {
    Write-Host "`n🐳 Docker Health Check" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Gray

    try {
        # Test Docker daemon
        $DockerVersion = docker version --format "{{.Server.Version}}" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-HealthStatus "Docker Daemon" "CRITICAL" "Docker daemon is not running or accessible"
            return @{ Status = "CRITICAL"; Error = "Docker daemon not accessible" }
        }

        Write-HealthStatus "Docker Daemon" "HEALTHY" "Docker daemon v$DockerVersion is running"

        # Check Cortex containers
        $ContainerStatuses = @()
        $CortexContainers = @("cortex-postgres-wsl", "cortex-postgres-desktop", "cortex-pgadmin-wsl", "cortex-pgadmin-desktop")

        foreach ($ContainerName in $CortexContainers) {
            try {
                $ContainerInfo = docker ps -a --filter "name=$ContainerName" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>$null | Select-Object -Skip 1
                if ($ContainerInfo) {
                    $Status = if ($ContainerInfo -match "Up") { "HEALTHY" } elseif ($ContainerInfo -match "Exited") { "WARNING" } else { "CRITICAL" }
                    $StatusMessage = if ($ContainerInfo -match "Up") { "Container is running" } elseif ($ContainerInfo -match "Exited") { "Container is stopped" } else { "Container status unknown" }

                    Write-HealthStatus $ContainerName $Status $StatusMessage
                    $ContainerStatuses += @{ Name = $ContainerName; Status = $Status; Info = $ContainerInfo.Trim() }
                } else {
                    Write-HealthStatus $ContainerName "UNKNOWN" "Container not found"
                    $ContainerStatuses += @{ Name = $ContainerName; Status = "UNKNOWN"; Info = "Container not found" }
                }
            } catch {
                Write-HealthStatus $ContainerName "CRITICAL" "Failed to query container status: $($_.Exception.Message)"
                $ContainerStatuses += @{ Name = $ContainerName; Status = "CRITICAL"; Info = $_.Exception.Message }
            }
        }

        # Check Docker resource usage
        if ($Detailed) {
            $DockerStats = docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>$null
            if ($DockerStats) {
                Write-Host "`n📊 Docker Resource Usage:" -ForegroundColor Cyan
                Write-Host $DockerStats -ForegroundColor Gray
            }
        }

        # Check Docker volumes
        $DockerVolumes = docker volume ls --filter "name=cortex" --format "{{.Name}}" 2>$null
        if ($DockerVolumes) {
            $VolumeCount = ($DockerVolumes | Measure-Object).Count
            Write-HealthStatus "Docker Volumes" "HEALTHY" "$VolumeCount Cortex volumes found"
        }

        # Check Docker networks
        $DockerNetworks = docker network ls --filter "name=cortex" --format "{{.Name}}" 2>$null
        if ($DockerNetworks) {
            $NetworkCount = ($DockerNetworks | Measure-Object).Count
            Write-HealthStatus "Docker Networks" "HEALTHY" "$NetworkCount Cortex networks found"
        }

        return @{
            Status = "HEALTHY"
            DockerVersion = $DockerVersion
            Containers = $ContainerStatuses
            VolumesFound = if ($DockerVolumes) { ($DockerVolumes | Measure-Object).Count } else { 0 }
            NetworksFound = if ($DockerNetworks) { ($DockerNetworks | Measure-Object).Count } else { 0 }
        }
    } catch {
        Write-HealthStatus "Docker" "CRITICAL" "Docker health check failed: $($_.Exception.Message)"
        return @{ Status = "CRITICAL"; Error = $_.Exception.Message }
    }
}

function Test-DatabaseHealth {
    Write-Host "`n🗄️ Database Health Check" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Gray

    try {
        $ActiveContainer = $null
        $DatabaseMetrics = @{}

        # Find running PostgreSQL container
        foreach ($ContainerName in @("cortex-postgres-wsl", "cortex-postgres-desktop")) {
            $ContainerStatus = docker ps --filter "name=$ContainerName" --format "{{.Names}}" -q
            if ($ContainerStatus) {
                $ActiveContainer = $ContainerName
                break
            }
        }

        if (-not $ActiveContainer) {
            Write-HealthStatus "PostgreSQL Container" "CRITICAL" "No running PostgreSQL container found"
            return @{ Status = "CRITICAL"; Error = "No PostgreSQL container running" }
        }

        # Test database connectivity
        $StartTime = Get-Date
        $ConnectionTest = docker exec $ActiveContainer pg_isready -U cortex -d cortex_prod -t 5 2>$null
        $ResponseTime = ((Get-Date) - $StartTime).TotalMilliseconds

        if ($LASTEXITCODE -ne 0) {
            Write-HealthStatus "Database Connection" "CRITICAL" "Cannot connect to cortex_prod database"
            return @{ Status = "CRITICAL"; Error = "Database connection failed" }
        }

        $DatabaseMetrics["ResponseTime"] = "{0:N0}ms" -f $ResponseTime

        # Check response time thresholds
        if ($ResponseTime -gt $Thresholds.response_time_critical) {
            Write-HealthStatus "Database Response Time" "CRITICAL" "Response time is critical: $($DatabaseMetrics.ResponseTime)"
        } elseif ($ResponseTime -gt $Thresholds.response_time_warning) {
            Write-HealthStatus "Database Response Time" "WARNING" "Response time is slow: $($DatabaseMetrics.ResponseTime)"
        } else {
            Write-HealthStatus "Database Connection" "HEALTHY" "Connected to cortex_prod database" $DatabaseMetrics
        }

        if ($Detailed) {
            # Get database size and table counts
            $DbSizeQuery = docker exec $ActiveContainer psql -U cortex -d cortex_prod -t -c "SELECT pg_size_pretty(pg_database_size('cortex_prod'));" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $DbSize = $DbSizeQuery.Trim()
                $DatabaseMetrics["DatabaseSize"] = $DbSize
                Write-Host "   • Database Size: $DbSize" -ForegroundColor Gray
            }

            # Get active connections
            $ConnectionCount = docker exec $ActiveContainer psql -U cortex -d cortex_prod -t -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $ActiveConnections = $ConnectionCount.Trim()
                $DatabaseMetrics["ActiveConnections"] = $ActiveConnections
                Write-Host "   • Active Connections: $ActiveConnections" -ForegroundColor Gray
            }

            # Get table statistics
            $TableStats = docker exec $ActiveContainer psql -U cortex -d cortex_prod -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $TableCount = $TableStats.Trim()
                $DatabaseMetrics["TableCount"] = $TableCount
                Write-Host "   • Tables: $TableCount" -ForegroundColor Gray
            }
        }

        return @{
            Status = "HEALTHY"
            Container = $ActiveContainer
            ResponseTime = $ResponseTime
            Metrics = $DatabaseMetrics
        }
    } catch {
        Write-HealthStatus "Database" "CRITICAL" "Database health check failed: $($_.Exception.Message)"
        return @{ Status = "CRITICAL"; Error = $_.Exception.Message }
    }
}

function Test-ApplicationHealth {
    Write-Host "`n⚡ Application Health Check" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Gray

    try {
        $AppMetrics = @{}
        $OverallStatus = "HEALTHY"

        # Check Node.js installation
        try {
            $NodeVersion = node --version 2>$null
            if ($NodeVersion) {
                Write-HealthStatus "Node.js" "HEALTHY" "Node.js $NodeVersion is installed"
                $AppMetrics["NodeVersion"] = $NodeVersion
            } else {
                Write-HealthStatus "Node.js" "CRITICAL" "Node.js is not installed"
                $OverallStatus = "CRITICAL"
            }
        } catch {
            Write-HealthStatus "Node.js" "CRITICAL" "Node.js is not accessible"
            $OverallStatus = "CRITICAL"
        }

        # Check package.json
        $PackageJsonPath = ".\package.json"
        if (Test-Path $PackageJsonPath) {
            Write-HealthStatus "package.json" "HEALTHY" "package.json exists"

            if ($Detailed) {
                try {
                    $PackageContent = Get-Content -Path $PackageJsonPath -Raw -ErrorAction Stop
                    $PackageData = $PackageContent | ConvertFrom-Json -ErrorAction Stop

                    if ($PackageData.name) {
                        $AppMetrics["AppName"] = $PackageData.name
                    }
                    if ($PackageData.version) {
                        $AppMetrics["AppVersion"] = $PackageData.version
                    }

                    $AppName = if ($PackageData.name) { $PackageData.name } else { "Unknown" }
                    $AppVersion = if ($PackageData.version) { $PackageData.version } else { "Unknown" }
                    Write-Host "   • Application: $AppName v$AppVersion" -ForegroundColor Gray
                } catch {
                    Write-Host "   ⚠️ Could not parse package.json: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        } else {
            Write-HealthStatus "package.json" "CRITICAL" "package.json not found"
            $OverallStatus = "CRITICAL"
        }

        # Check node_modules
        if (Test-Path ".\node_modules") {
            Write-HealthStatus "Dependencies" "HEALTHY" "node_modules directory exists"

            if ($Detailed) {
                try {
                    $ModuleCount = (Get-ChildItem -Path ".\node_modules" -Directory | Measure-Object).Count
                    $AppMetrics["ModuleCount"] = $ModuleCount
                    Write-Host "   • Dependencies installed: $ModuleCount modules" -ForegroundColor Gray
                } catch {
                    Write-Host "   ⚠️ Could not count modules" -ForegroundColor Yellow
                }
            }
        } else {
            Write-HealthStatus "Dependencies" "WARNING" "node_modules not found - run 'npm install'"
            if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
        }

        # Check environment configuration
        $EnvFiles = @(".env", ".env.local", ".env.production")
        $FoundEnvFile = $false
        foreach ($EnvFile in $EnvFiles) {
            if (Test-Path $EnvFile) {
                Write-HealthStatus "Environment" "HEALTHY" "Environment file found: $EnvFile"
                $FoundEnvFile = $true
                break
            }
        }
        if (-not $FoundEnvFile) {
            Write-HealthStatus "Environment" "WARNING" "No environment file found"
            if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
        }

        # Check for compiled application
        $DistPath = ".\dist"
        if (Test-Path $DistPath) {
            Write-HealthStatus "Build Artifacts" "HEALTHY" "dist directory exists"

            if ($Detailed) {
                try {
                    $DistFiles = Get-ChildItem -Path $DistPath -File | Measure-Object
                    $AppMetrics["DistFiles"] = $DistFiles.Count
                    Write-Host "   • Build artifacts: $($DistFiles.Count) files" -ForegroundColor Gray
                } catch {
                    Write-Host "   ⚠️ Could not count dist files" -ForegroundColor Yellow
                }
            }
        } else {
            Write-HealthStatus "Build Artifacts" "WARNING" "dist directory not found - run 'npm run build'"
            if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
        }

        # Test MCP server if possible
        try {
            $IndexPath = ".\dist\index.js"
            if (Test-Path $IndexPath) {
                Write-HealthStatus "MCP Server" "HEALTHY" "MCP server build exists"
            } else {
                Write-HealthStatus "MCP Server" "WARNING" "MCP server build not found"
                if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
            }
        } catch {
            Write-HealthStatus "MCP Server" "UNKNOWN" "Could not verify MCP server status"
        }

        return @{
            Status = $OverallStatus
            Metrics = $AppMetrics
        }
    } catch {
        Write-HealthStatus "Application" "CRITICAL" "Application health check failed: $($_.Exception.Message)"
        return @{ Status = "CRITICAL"; Error = $_.Exception.Message }
    }
}

function Test-SystemHealth {
    Write-Host "`n💻 System Health Check" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Gray

    try {
        $SystemMetrics = @{}
        $OverallStatus = "HEALTHY"

        # Memory usage
        $Memory = Get-CimInstance -ClassName Win32_OperatingSystem
        $TotalMemoryGB = [math]::Round($Memory.TotalVisibleMemorySize / 1MB, 2)
        $FreeMemoryGB = [math]::Round($Memory.FreePhysicalMemory / 1MB, 2)
        $UsedMemoryGB = $TotalMemoryGB - $FreeMemoryGB
        $MemoryUsagePercent = [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 1)

        $SystemMetrics["TotalMemoryGB"] = $TotalMemoryGB
        $SystemMetrics["UsedMemoryGB"] = $UsedMemoryGB
        $SystemMetrics["FreeMemoryGB"] = $FreeMemoryGB
        $SystemMetrics["MemoryUsagePercent"] = $MemoryUsagePercent

        if ($MemoryUsagePercent -gt $Thresholds.memory_critical) {
            Write-HealthStatus "Memory Usage" "CRITICAL" "$MemoryUsagePercent% used ($UsedMemoryGB/$TotalMemoryGB GB)"
            $OverallStatus = "CRITICAL"
        } elseif ($MemoryUsagePercent -gt $Thresholds.memory_warning) {
            Write-HealthStatus "Memory Usage" "WARNING" "$MemoryUsagePercent% used ($UsedMemoryGB/$TotalMemoryGB GB)"
            if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
        } else {
            Write-HealthStatus "Memory Usage" "HEALTHY" "$MemoryUsagePercent% used ($UsedMemoryGB/$TotalMemoryGB GB)"
        }

        # CPU usage
        $CpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue
        if ($CpuUsage) {
            $CpuUsagePercent = [math]::Round($CpuUsage, 1)
            $SystemMetrics["CpuUsagePercent"] = $CpuUsagePercent

            if ($CpuUsagePercent -gt $Thresholds.cpu_critical) {
                Write-HealthStatus "CPU Usage" "CRITICAL" "$CpuUsagePercent% CPU usage"
                $OverallStatus = "CRITICAL"
            } elseif ($CpuUsagePercent -gt $Thresholds.cpu_warning) {
                Write-HealthStatus "CPU Usage" "WARNING" "$CpuUsagePercent% CPU usage"
                if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
            } else {
                Write-HealthStatus "CPU Usage" "HEALTHY" "$CpuUsagePercent% CPU usage"
            }
        }

        # Disk usage for system drive
        $SystemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = 'C:'"
        if ($SystemDrive) {
            $TotalDiskGB = [math]::Round($SystemDrive.Size / 1GB, 2)
            $FreeDiskGB = [math]::Round($SystemDrive.FreeSpace / 1GB, 2)
            $UsedDiskGB = $TotalDiskGB - $FreeDiskGB
            $DiskUsagePercent = [math]::Round(($UsedDiskGB / $TotalDiskGB) * 100, 1)

            $SystemMetrics["TotalDiskGB"] = $TotalDiskGB
            $SystemMetrics["UsedDiskGB"] = $UsedDiskGB
            $SystemMetrics["FreeDiskGB"] = $FreeDiskGB
            $SystemMetrics["DiskUsagePercent"] = $DiskUsagePercent

            if ($DiskUsagePercent -gt $Thresholds.disk_critical) {
                Write-HealthStatus "Disk Usage (C:)" "CRITICAL" "$DiskUsagePercent% used ($UsedDiskGB/$TotalDiskGB GB)"
                $OverallStatus = "CRITICAL"
            } elseif ($DiskUsagePercent -gt $Thresholds.disk_warning) {
                Write-HealthStatus "Disk Usage (C:)" "WARNING" "$DiskUsagePercent% used ($UsedDiskGB/$TotalDiskGB GB)"
                if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
            } else {
                Write-HealthStatus "Disk Usage (C:)" "HEALTHY" "$DiskUsagePercent% used ($UsedDiskGB/$TotalDiskGB GB)"
            }
        }

        # Check for Cortex-specific processes
        try {
            $CortexProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.ProcessName -like "*cortex*" -or
                ($_.CommandLine -and $_.CommandLine -like "*cortex*")
            }
            if ($CortexProcesses) {
                $ProcessCount = $CortexProcesses.Count
                Write-HealthStatus "Cortex Processes" "HEALTHY" "$ProcessCount Cortex processes running"
                $SystemMetrics["CortexProcessCount"] = $ProcessCount

                if ($Detailed) {
                    foreach ($Process in $CortexProcesses) {
                        $ProcessName = $Process.ProcessName
                        $ProcessId = $Process.Id
                        $MemoryUsage = [math]::Round($Process.WorkingSet64 / 1MB, 1)
                        Write-Host "   • $ProcessName (PID: $ProcessId, Memory: ${MemoryUsage}MB)" -ForegroundColor Gray
                    }
                }
            } else {
                Write-HealthStatus "Cortex Processes" "WARNING" "No Cortex processes currently running"
                if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
            }
        } catch {
            Write-HealthStatus "Cortex Processes" "UNKNOWN" "Could not enumerate processes: $($_.Exception.Message)"
            if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
        }

        # Check environment variables
        $CortexEnvVars = Get-ChildItem Env: | Where-Object { $_.Name -match "CORTEX|MCP|DATABASE" }
        if ($CortexEnvVars) {
            $EnvVarCount = $CortexEnvVars.Count
            Write-HealthStatus "Environment Variables" "HEALTHY" "$EnvVarCount Cortex/MCP environment variables set"
            $SystemMetrics["EnvironmentVariableCount"] = $EnvVarCount
        } else {
            Write-HealthStatus "Environment Variables" "WARNING" "No Cortex/MCP environment variables found"
            if ($OverallStatus -eq "HEALTHY") { $OverallStatus = "WARNING" }
        }

        return @{
            Status = $OverallStatus
            Metrics = $SystemMetrics
        }
    } catch {
        Write-HealthStatus "System" "CRITICAL" "System health check failed: $($_.Exception.Message)"
        return @{ Status = "CRITICAL"; Error = $_.Exception.Message }
    }
}

function Generate-HealthReport {
    param(
        [hashtable]$Results,
        [string]$OverallStatus
    )

    if ($OutputFormat -eq "json") {
        $Report = @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            overall_status = $OverallStatus
            components = $Results
            thresholds = $Thresholds
        }
        return $Report | ConvertTo-Json -Depth 10
    } elseif ($OutputFormat -eq "html") {
        $Html = @"
<!DOCTYPE html>
<html>
<head>
    <title>MCP Cortex Memory Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #007acc; color: white; padding: 20px; border-radius: 5px; }
        .healthy { color: #28a745; }
        .warning { color: #ffc107; }
        .critical { color: #dc3545; }
        .component { margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .metrics { background-color: #f8f9fa; padding: 10px; border-radius: 3px; margin-top: 10px; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧠 MCP Cortex Memory Health Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <h2>Overall Status: <span class="$($OverallStatus.ToLower())">$($OverallStatus.ToUpper())</span></h2>
    </div>
"@

        foreach ($Component in $Results.GetEnumerator()) {
            $StatusClass = $Component.Value.Status.ToLower()
            $Html += @"
    <div class="component">
        <h3>$($Component.Key): <span class="$StatusClass">$($Component.Value.Status.ToUpper())</span></h3>
"@
            if ($Component.Value.Error) {
                $Html += "        <p><strong>Error:</strong> $($Component.Value.Error)</p>`n"
            }
            if ($Component.Value.Metrics -and $Component.Value.Metrics.Count -gt 0) {
                $Html += "        <div class='metrics'>`n"
                foreach ($Metric in $Component.Value.Metrics.GetEnumerator()) {
                    $Html += "            <strong>$($Metric.Key):</strong> $($Metric.Value)<br>`n"
                }
                $Html += "        </div>`n"
            }
            $Html += "    </div>`n"
        }

        $Html += @"
</body>
</html>
"@
        return $Html
    }
}

# Main health check execution
function Run-HealthCheck {
    $Results = @{}
    $OverallStatus = "HEALTHY"

    Write-Host "🧠 MCP Cortex Memory Health Monitor" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Gray
    Write-Host "Health check started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""

    try {
        switch ($Component) {
            "all" {
                $Results["System"] = Test-SystemHealth
                $Results["Docker"] = Test-DockerHealth
                $Results["Database"] = Test-DatabaseHealth
                $Results["Application"] = Test-ApplicationHealth
            }
            "system" {
                $Results["System"] = Test-SystemHealth
            }
            "docker" {
                $Results["Docker"] = Test-DockerHealth
            }
            "database" {
                $Results["Database"] = Test-DatabaseHealth
            }
            "application" {
                $Results["Application"] = Test-ApplicationHealth
            }
        }

        # Determine overall status
        foreach ($Result in $Results.Values) {
            if ($Result.Status -eq "CRITICAL") {
                $OverallStatus = "CRITICAL"
                break
            } elseif ($Result.Status -eq "WARNING" -and $OverallStatus -ne "CRITICAL") {
                $OverallStatus = "WARNING"
            }
        }

        Write-Host ""
        Write-Host "🎯 Overall System Status: $OverallStatus" -ForegroundColor $(
            switch ($OverallStatus) {
                "HEALTHY" { "Green" }
                "WARNING" { "Yellow" }
                "CRITICAL" { "Red" }
                default { "White" }
            }
        )

        # Generate report if needed
        if ($OutputFormat -ne "console") {
            $Report = Generate-HealthReport -Results $Results -OverallStatus $OverallStatus

            $ReportPath = "$env:TEMP\cortex-health-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').$($OutputFormat)"
            Set-Content -Path $ReportPath -Value $Report -Force
            Write-Host ""
            Write-Host "📊 Health report generated: $ReportPath" -ForegroundColor Cyan
        }

        # Write log entry
        Write-Log "Health check completed - Overall Status: $OverallStatus"

        return @{
            Status = $OverallStatus
            Results = $Results
            Timestamp = Get-Date
        }
    } catch {
        Write-Host ""
        Write-Host "❌ Health check failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Health check failed: $($_.Exception.Message)" "ERROR"

        return @{
            Status = "CRITICAL"
            Error = $_.Exception.Message
            Timestamp = Get-Date
        }
    }
}

# Execute health check
if ($Continuous) {
    Write-Host "🔄 Continuous monitoring mode (interval: ${Continuous}s)" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Gray
    Write-Host ""

    while ($true) {
        Clear-Host
        Run-HealthCheck
        Write-Host ""
        Write-Host "Next check in $Continuous seconds... (Press Ctrl+C to stop)" -ForegroundColor Gray
        Start-Sleep -Seconds $Continuous
    }
} else {
    $HealthResult = Run-HealthCheck

    # Exit with appropriate code
    switch ($HealthResult.Status) {
        "HEALTHY" { exit 0 }
        "WARNING" { exit 1 }
        "CRITICAL" { exit 2 }
        default { exit 3 }
    }
}