# ============================================================================
# CRITICAL QDRANT AUTO-START SCRIPT FOR CORTEX MEMORY SYSTEM
# ============================================================================
# Purpose: Ensure Qdrant database is always running for memory operations
# Usage: Run this script at system startup or when Qdrant is critical

param(
    [switch]$Force,
    [switch]$Monitor,
    [int]$MonitorInterval = 60
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            "INFO" { "White" }
            default { "White" }
        }
    )
}

function Test-QdrantHealth {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:6333/health" -Method GET -TimeoutSec 10
        if ($response) {
            Write-Log "Qdrant health check passed" "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Qdrant health check failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
    return $false
}

function Start-QdrantContainer {
    Write-Log "Starting Qdrant container with high availability configuration..."

    try {
        # Stop existing container if it exists
        $existingContainer = wsl -d Ubuntu docker ps -aq --filter "name=cortex-qdrant"
        if ($existingContainer) {
            Write-Log "Stopping existing Qdrant container..."
            wsl -d Ubuntu docker stop cortex-qdrant | Out-Null
            wsl -d Ubuntu docker rm cortex-qdrant | Out-Null
        }

        # Start with compose file
        $composeFile = Join-Path $PSScriptRoot "..\docker-compose.qdrant-critical.yml"
        Write-Log "Starting Qdrant using: $composeFile"

        wsl -d Ubuntu bash -c "cd `$(wslpath '$(Split-Path (Get-Location) -Parent)') && docker-compose -f docker-compose.qdrant-critical.yml up -d qdrant"

        # Wait for startup
        Write-Log "Waiting for Qdrant to initialize..."
        Start-Sleep -Seconds 10

        # Verify health
        $retryCount = 0
        $maxRetries = 6
        do {
            if (Test-QdrantHealth) {
                Write-Log "Qdrant is now running and healthy!" "SUCCESS"
                return $true
            }
            Write-Log "Health check failed, retrying in 10 seconds..." "WARN"
            Start-Sleep -Seconds 10
            $retryCount++
        } while ($retryCount -lt $maxRetries)

        throw "Failed to start Qdrant after $maxRetries attempts"
    }
    catch {
        Write-Log "Failed to start Qdrant: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Monitor-Qdrant {
    Write-Log "Starting Qdrant monitoring (interval: ${MonitorInterval}s)..."
    Write-Log "Press Ctrl+C to stop monitoring"

    while ($true) {
        if (-not (Test-QdrantHealth)) {
            Write-Log "Qdrant health check failed, attempting restart..." "WARN"
            if (Start-QdrantContainer) {
                Write-Log "Qdrant successfully restarted" "SUCCESS"
            } else {
                Write-Log "Failed to restart Qdrant - manual intervention required!" "ERROR"
            }
        }

        Start-Sleep -Seconds $MonitorInterval
    }
}

# Main execution
Write-Log "🚀 CORTEX MEMORY SYSTEM - Critical Qdrant Database Manager" "INFO"
Write-Log "Ensuring high availability for memory operations..." "INFO"

if ($Force) {
    Write-Log "Force restart requested" "WARN"
}

# Check if Qdrant is already healthy
if (-not $Force -and (Test-QdrantHealth)) {
    Write-Log "Qdrant is already running and healthy!" "SUCCESS"
} else {
    Write-Log "Qdrant needs to be started or restarted" "INFO"
    if (Start-QdrantContainer) {
        Write-Log "🎯 Critical memory database is now operational!" "SUCCESS"
    } else {
        Write-Log "❌ Failed to start critical memory database!" "ERROR"
        exit 1
    }
}

if ($Monitor) {
    Monitor-Qdrant
}

Write-Log "✅ Qdrant auto-start configuration completed" "SUCCESS"