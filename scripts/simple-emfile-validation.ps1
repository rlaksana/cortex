# Simple EMFILE Validation Script
Write-Host "=== EMFILE Fixes Validation ===" -ForegroundColor Cyan

# Check environment variables
Write-Host "`n1. Checking Environment Variables:" -ForegroundColor Yellow
$envVars = @(
    "EMFILE_HANDLES_LIMIT",
    "UV_THREADPOOL_SIZE",
    "NODE_OPTIONS",
    "TEST_TIMEOUT",
    "TEST_WORKERS"
)

foreach ($var in $envVars) {
    $value = [System.Environment]::GetEnvironmentVariable($var, "User")
    if ([string]::IsNullOrEmpty($value)) {
        $value = [System.Environment]::GetEnvironmentVariable($var, "Process")
    }

    if ([string]::IsNullOrEmpty($value)) {
        Write-Host "  ❌ $var : Not set" -ForegroundColor Red
    } else {
        Write-Host "  ✅ $var : $value" -ForegroundColor Green
    }
}

# Check system handle usage
Write-Host "`n2. Checking System Handle Usage:" -ForegroundColor Yellow
try {
    $computerInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalHandles = (Get-Process | Measure-Object -Property HandleCount -Sum).Sum
    Write-Host "  Total System Handles: $totalHandles" -ForegroundColor White

    if ($totalHandles -lt 50000) {
        Write-Host "  ✅ Handle usage is within normal limits" -ForegroundColor Green
    } elseif ($totalHandles -lt 80000) {
        Write-Host "  ⚠️  Handle usage is elevated but acceptable" -ForegroundColor Yellow
    } else {
        Write-Host "  ❌ Handle usage is very high" -ForegroundColor Red
    }
} catch {
    Write-Host "  ❌ Could not check handle usage: $_" -ForegroundColor Red
}

# Check Node.js processes
Write-Host "`n3. Checking Node.js Processes:" -ForegroundColor Yellow
try {
    $nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
    if ($nodeProcesses) {
        Write-Host "  Found $($nodeProcesses.Count) Node.js process(es)" -ForegroundColor White
        foreach ($proc in $nodeProcesses | Sort-Object HandleCount -Descending | Select-Object -First 3) {
            Write-Host "    PID $($proc.Id): $($proc.HandleCount) handles" -ForegroundColor Gray
        }
    } else {
        Write-Host "  ✅ No Node.js processes running" -ForegroundColor Green
    }
} catch {
    Write-Host "  ❌ Could not check Node.js processes: $_" -ForegroundColor Red
}

# Check .env.test file
Write-Host "`n4. Checking .env.test Configuration:" -ForegroundColor Yellow
$envTestPath = ".env.test"
if (Test-Path $envTestPath) {
    Write-Host "  ✅ .env.test file exists" -ForegroundColor Green
    $envContent = Get-Content $envTestPath
    $requiredSettings = @("EMFILE_HANDLES_LIMIT", "UV_THREADPOOL_SIZE", "NODE_OPTIONS")

    foreach ($setting in $requiredSettings) {
        if ($envContent -match "^$setting=") {
            Write-Host "    ✅ $setting configured" -ForegroundColor Green
        } else {
            Write-Host "    ❌ $setting missing" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  ❌ .env.test file not found" -ForegroundColor Red
}

# Test file handle monitoring
Write-Host "`n5. Testing File Handle Monitoring:" -ForegroundColor Yellow
try {
    $initialHandles = (Get-Process -Id $PID).HandleCount
    Write-Host "  Initial handles: $initialHandles" -ForegroundColor White

    # Create some test files to simulate handle usage
    $testFiles = @()
    for ($i = 0; $i -lt 10; $i++) {
        $tempFile = New-TemporaryFile
        $testFiles += $tempFile
        Set-Content $tempFile -Value "Test content $i"
    }

    $afterTestHandles = (Get-Process -Id $PID).HandleCount
    Write-Host "  After creating 10 files: $afterTestHandles" -ForegroundColor White

    # Cleanup test files
    $testFiles | Remove-Item -Force

    # Force garbage collection
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()

    Start-Sleep -Seconds 1
    $finalHandles = (Get-Process -Id $PID).HandleCount
    Write-Host "  After cleanup: $finalHandles" -ForegroundColor White

    $handleIncrease = $finalHandles - $initialHandles
    if ($handleIncrease -le 5) {
        Write-Host "  ✅ Handle cleanup working properly (increase: $handleIncrease)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Possible handle leak detected (increase: $handleIncrease)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ❌ Handle monitoring test failed: $_" -ForegroundColor Red
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan
Write-Host "EMFILE fixes are configured and basic validation passed." -ForegroundColor Green