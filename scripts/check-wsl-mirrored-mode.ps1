#Requires -RunAsAdministrator

<#
.SYNOPSIS
    WSL2 Mirrored Networking Mode Availability Checker

.DESCRIPTION
    Verifies if WSL2 mirrored networking mode is available and functional on Windows Beta Channel.
    Tests system requirements, enables mirrored mode, and validates connectivity.

.NOTES
    Requires: Windows 11 22H2+ (Build 22621+), WSL 2.0.9+, Administrator privileges
    Author: MCP Cortex Installation Team
    Version: 1.0.0
#>

$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"

# Color output functions
function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Failure { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }
function Write-Info { param($Message) Write-Host "🔍 $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "⚠️  $Message" -ForegroundColor Yellow }
function Write-Section { param($Message) Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Magenta; Write-Host " $Message" -ForegroundColor Magenta; Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta }

# Results tracking
$script:Results = @{
    WindowsVersionOK = $false
    WSLVersionOK = $false
    ConfigCreated = $false
    FirewallConfigured = $false
    MirroredModeActive = $false
    IPAddressesMatch = $false
    ConnectivityOK = $false
    OverallSuccess = $false
}

$script:ReportLines = @()

function Add-ReportLine {
    param([string]$Line)
    $script:ReportLines += $Line
    Write-Host $Line
}

# Main verification function
function Test-WSLMirroredMode {
    Write-Section "WSL2 MIRRORED MODE AVAILABILITY CHECK"

    # Step 1: Check Windows Version
    Write-Section "[1] WINDOWS VERSION CHECK"
    try {
        $osInfo = Get-ComputerInfo -Property WindowsVersion, OsBuildNumber, WindowsEditionId
        $buildNumber = [int]$osInfo.OsBuildNumber

        Add-ReportLine "    Windows Edition: $($osInfo.WindowsEditionId)"
        Add-ReportLine "    Build Number: $buildNumber"

        if ($buildNumber -ge 22621) {
            Write-Success "Build greater than or equal to 22621 (Required for mirrored mode)"
            $script:Results.WindowsVersionOK = $true
        } else {
            Write-Failure "Build $buildNumber less than 22621 - Mirrored mode NOT supported"
            return
        }

        # Check if Beta/Dev Channel
        try {
            $flightSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Selection" -ErrorAction SilentlyContinue
            if ($flightSettings) {
                Add-ReportLine "    Insider Channel: $($flightSettings.UIContentType)"
            }
        } catch {
            Add-ReportLine "    Insider Channel: Not detected (Release)"
        }

    } catch {
        Write-Failure "Failed to get Windows version: $_"
        return
    }

    # Step 2: Check WSL Version
    Write-Section "[2] WSL VERSION CHECK"
    try {
        $wslVersionOutput = wsl --version 2>&1 | Out-String
        Add-ReportLine $wslVersionOutput

        # Parse version
        if ($wslVersionOutput -match "WSL version:\s*(\d+\.\d+\.\d+)") {
            $wslVersion = [version]$matches[1]
            $requiredVersion = [version]"2.0.9"

            if ($wslVersion -ge $requiredVersion) {
                Write-Success "WSL version $wslVersion greater than or equal to 2.0.9 (Required)"
                $script:Results.WSLVersionOK = $true
            } else {
                Write-Failure "WSL version $wslVersion less than 2.0.9 - Please run: wsl --update"
                return
            }
        } else {
            Write-Warning "Could not parse WSL version - attempting to continue"
            $script:Results.WSLVersionOK = $true
        }

        # Check for wslinfo command availability
        $wslDistro = wsl -l -q | Select-Object -First 1
        if ($wslDistro) {
            Add-ReportLine "    Default WSL distribution: $wslDistro"
        }

    } catch {
        Write-Failure "Failed to check WSL version: $_"
        return
    }

    # Step 3: Current Configuration Check
    Write-Section "[3] CURRENT CONFIGURATION"
    $wslConfigPath = "$env:USERPROFILE\.wslconfig"

    if (Test-Path $wslConfigPath) {
        Write-Info "Found existing .wslconfig"
        $existingConfig = Get-Content $wslConfigPath -Raw
        Add-ReportLine "    📁 Existing .wslconfig:"
        Add-ReportLine $existingConfig

        # Backup existing config
        $backupPath = "$wslConfigPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item $wslConfigPath $backupPath
        Write-Success "Backed up to: $backupPath"
    } else {
        Write-Info "No existing .wslconfig found"
    }

    # Check current networking mode
    try {
        $currentMode = wsl wslinfo --networking-mode 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-ReportLine "    Current networking mode: $currentMode"
        } else {
            Add-ReportLine "    Current networking mode: Unknown (wslinfo command not available)"
        }
    } catch {
        Add-ReportLine "    Current networking mode: Unable to detect"
    }

    # Step 4: Enable Mirrored Mode
    Write-Section "[4] MIRRORED MODE ENABLEMENT"

    # Create/update .wslconfig
    $mirroredConfig = @"
[wsl2]
networkingMode=mirrored

# Generated by check-wsl-mirrored-mode.ps1
# Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

    try {
        Set-Content -Path $wslConfigPath -Value $mirroredConfig -Force
        Write-Success ".wslconfig created/updated with mirrored mode"
        $script:Results.ConfigCreated = $true
    } catch {
        Write-Failure "Failed to create .wslconfig: $_"
        return
    }

    # Configure Hyper-V Firewall (CRITICAL for mirrored mode)
    try {
        Write-Info "Configuring Hyper-V firewall..."
        Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow -ErrorAction Stop
        Write-Success "Hyper-V firewall configured (DefaultInboundAction: Allow)"
        $script:Results.FirewallConfigured = $true
    } catch {
        Write-Failure "Failed to configure Hyper-V firewall: $_"
        Write-Warning "This may prevent mirrored mode from working correctly"
    }

    # Shutdown WSL to apply changes
    Write-Info "Shutting down WSL to apply changes..."
    wsl --shutdown
    Start-Sleep -Seconds 5
    Write-Success "WSL restarted"

    # Step 5: Verification
    Write-Section "[5] VERIFICATION RESULTS"

    # Start WSL and verify mode
    try {
        Write-Info "Starting WSL and checking networking mode..."
        $newMode = wsl wslinfo --networking-mode 2>&1

        if ($LASTEXITCODE -eq 0 -and $newMode -match "mirrored") {
            Write-Success "Networking mode: $newMode"
            $script:Results.MirroredModeActive = $true
        } else {
            Write-Failure "Networking mode: $newMode (Expected: mirrored)"
            Add-ReportLine "    Note: Mode may still be 'nat' - this indicates mirrored mode is NOT active"
        }
    } catch {
        Write-Failure "Failed to verify networking mode: $_"
    }

    # Step 5a: Network Adapter Detection
    Write-Info "Detecting active network adapters..."
    try {
        # List all network adapters
        $allAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } |
            Select-Object Name, InterfaceDescription, Status, LinkSpeed

        Add-ReportLine "    📡 Active network adapters:"
        foreach ($adapter in $allAdapters) {
            Add-ReportLine "       • $($adapter.Name) ($($adapter.InterfaceDescription)) - $($adapter.Status) - $($adapter.LinkSpeed)"
        }

        # Get primary adapter using default route
        $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($defaultRoute) {
            $primaryAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
            Add-ReportLine ""
            Add-ReportLine "    🎯 Primary adapter (default route): $($primaryAdapter.Name)"
            Add-ReportLine "       Interface: $($primaryAdapter.InterfaceDescription)"
        } else {
            Write-Warning "Could not determine default route - using first active adapter"
            $primaryAdapter = $allAdapters | Select-Object -First 1
        }
    } catch {
        Write-Warning "Network adapter detection error: $_"
    }

    # Compare IP addresses
    try {
        Write-Info "Comparing IP addresses..."

        # Get Windows IP from primary adapter
        if ($primaryAdapter) {
            $windowsIP = (Get-NetIPAddress -InterfaceIndex $primaryAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        } else {
            # Fallback: Get first non-loopback, non-virtual IPv4
            $windowsIP = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
                Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.InterfaceAlias -notmatch "vEthernet" } |
                Select-Object -First 1).IPAddress
        }

        # Get WSL IP
        $wslIP = wsl ip addr show eth0 2>&1 | Select-String "inet " | ForEach-Object {
            if ($_ -match "inet\s+(\d+\.\d+\.\d+\.\d+)") { $matches[1] }
        } | Select-Object -First 1

        Add-ReportLine ""
        Add-ReportLine "    🌐 Windows IP (from $($primaryAdapter.Name)): $windowsIP"
        Add-ReportLine "    🌐 WSL IP: $wslIP"

        if ($windowsIP -and $wslIP -and ($windowsIP -eq $wslIP)) {
            Write-Success "IP ADDRESSES MATCH - Mirrored mode is ACTIVE!"
            $script:Results.IPAddressesMatch = $true
        } else {
            Write-Failure "IP addresses DO NOT match - Mirrored mode is NOT active"
            Add-ReportLine "    This means WSL is still using NAT networking mode"
        }
    } catch {
        Write-Failure "Failed to compare IP addresses: $_"
    }

    # Step 6: Connectivity Test
    Write-Section "[6] CONNECTIVITY TEST"

    try {
        # Test localhost connectivity from WSL
        Write-Info "Testing localhost connectivity from WSL..."
        $localhostTest = wsl curl -s -o /dev/null -w "%{http_code}" http://localhost:80 --connect-timeout 3 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Localhost connectivity: WORKING"
        } else {
            Write-Warning "Localhost connectivity: No service on port 80 (this is OK)"
        }

        # Test if WSL port is accessible from Windows
        if ($windowsIP) {
            Write-Info "Testing WSL accessibility from Windows..."
            $testPort = 8888
            $testServerJob = Start-Job -ScriptBlock {
                wsl bash -c "python3 -m http.server $using:testPort 2>&1 > /dev/null &"
                Start-Sleep -Seconds 2
            }

            Start-Sleep -Seconds 3

            $portTest = Test-NetConnection -ComputerName $windowsIP -Port $testPort -WarningAction SilentlyContinue

            if ($portTest.TcpTestSucceeded) {
                Write-Success "WSL port $testPort accessible from Windows via $windowsIP"
                $script:Results.ConnectivityOK = $true
            } else {
                Write-Warning "WSL port $testPort NOT accessible - may need firewall rules"
            }

            # Cleanup test server
            wsl pkill -f "http.server $testPort" 2>&1 | Out-Null
            Remove-Job $testServerJob -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "No Windows IP detected - skipping connectivity test"
        }

    } catch {
        Write-Warning "Connectivity test inconclusive: $_"
    }

    # Final Result
    Write-Section "FINAL RESULT"

    $script:Results.OverallSuccess = $script:Results.WindowsVersionOK -and
                                      $script:Results.WSLVersionOK -and
                                      $script:Results.MirroredModeActive -and
                                      $script:Results.IPAddressesMatch

    if ($script:Results.OverallSuccess) {
        Write-Host "`n✅✅✅ MIRRORED MODE IS FULLY FUNCTIONAL ✅✅✅`n" -ForegroundColor Green
        Add-ReportLine ""
        Add-ReportLine "📋 IMPLICATIONS FOR USER INSTALLATION:"
        Add-ReportLine "   • No port forwarding needed"
        if ($windowsIP) {
            Add-ReportLine "   • Users connect to: postgresql://cortex:password@$windowsIP:5433/cortex_prod"
        } else {
            Add-ReportLine "   • Users connect to: postgresql://cortex:password@<YOUR-IP>:5433/cortex_prod"
        }
        Add-ReportLine "   • Installation script can be simplified (no netsh commands)"
        Add-ReportLine "   • WSL IP remains stable across restarts"
    } else {
        Write-Host "`n❌❌❌ MIRRORED MODE IS NOT WORKING ❌❌❌`n" -ForegroundColor Red
        Add-ReportLine ""
        Add-ReportLine "📋 FALLBACK PLAN:"
        Add-ReportLine "   • Will use NAT mode with port forwarding"
        Add-ReportLine "   • Installation scripts will include netsh portproxy setup"
        Add-ReportLine "   • Users will need administrator privileges"
        if ($windowsIP) {
            Add-ReportLine "   • Users connect to: postgresql://cortex:password@$windowsIP:5433/cortex_prod"
        } else {
            Add-ReportLine "   • Users connect to: postgresql://cortex:password@<YOUR-IP>:5433/cortex_prod"
        }
        Add-ReportLine "   • More complex but still functional"
    }

    # Save report
    $reportPath = "$PSScriptRoot\wsl-mirrored-mode-report.txt"
    $script:ReportLines | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Success "Report saved to: $reportPath"

    return $script:Results
}

# Rollback function
function Restore-WSLConfig {
    param([string]$BackupPath)

    $wslConfigPath = "$env:USERPROFILE\.wslconfig"

    if (Test-Path $BackupPath) {
        Copy-Item $BackupPath $wslConfigPath -Force
        Write-Success "Restored .wslconfig from backup"
        wsl --shutdown
        Write-Info "WSL restarted with original configuration"
    } else {
        Write-Failure "Backup not found: $BackupPath"
    }
}

# Main execution
try {
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Failure "This script requires Administrator privileges"
        Write-Info "Please run PowerShell as Administrator and try again"
        exit 1
    }

    $results = Test-WSLMirroredMode

    Write-Host "`n"
    Write-Section "RESULTS SUMMARY"
    $results.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $status = if ($_.Value) { "✅" } else { "❌" }
        Add-ReportLine "    $status $($_.Key): $($_.Value)"
    }

    if ($results.OverallSuccess) {
        exit 0
    } else {
        exit 1
    }

} catch {
    Write-Failure "Unexpected error: $_"
    Write-Host $_.ScriptStackTrace
    exit 1
}
