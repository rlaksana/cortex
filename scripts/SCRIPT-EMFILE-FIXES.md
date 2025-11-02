# Windows EMFILE Prevention Script Suite

This comprehensive PowerShell script suite provides system-level solutions for preventing EMFILE ("too many open files") errors on Windows systems during development and testing.

## Overview

The EMFILE prevention suite includes:

1. **increase-handles.ps1** - Windows registry modifications for file handle limits
2. **setup-test-environment.ps1** - Environment variable setup and test configuration
3. **validate-emfile-fixes.ps1** - System validation and performance measurement
4. **Updated .env.test** - Test-specific environment variables with EMFILE prevention

## Quick Start

### 1. Initial Setup (Run as Administrator)

```powershell
# Set up handle limits and system configurations
.\scripts\increase-handles.ps1

# Configure test environment
.\scripts\setup-test-environment.ps1

# Validate the configuration
.\scripts\validate-emfile-fixes.ps1 -Detailed -Benchmark
```

### 2. Standard Usage

```powershell
# Quick validation
.\scripts\validate-emfile-fixes.ps1

# Detailed analysis with performance benchmarks
.\scripts\validate-emfile-fixes.ps1 -Detailed -Benchmark

# Fix common issues automatically
.\scripts\validate-emfile-fixes.ps1 -FixIssues
```

## Script Details

### increase-handles.ps1

**Purpose**: Increases Windows file handle limits at the system level to prevent EMFILE errors.

**Requirements**: Administrator privileges

**Key Features**:

- Increases system-wide handle limits from default to optimized values
- Configures Windows 10/11 specific optimizations
- Creates automatic registry backups before making changes
- Validates current handle usage and identifies potential issues
- Supports -WhatIf mode for safe testing

**Parameters**:

- `-Force`: Apply optimizations even if current limits appear adequate
- `-SkipRestart`: Skip system restart requirement notification
- `-WhatIf`: Show what changes would be made without applying them

**Example Usage**:

```powershell
# Standard application
.\scripts\increase-handles.ps1

# Force application and skip restart check
.\scripts\increase-handles.ps1 -Force -SkipRestart

# Test mode (no changes applied)
.\scripts\increase-handles.ps1 -WhatIf
```

**What it Changes**:

- System-wide handle limits: 262,144 handles
- User handle limits: 131,072 handles
- Long path support: Enabled
- Memory management optimizations
- System file cache optimizations

### setup-test-environment.ps1

**Purpose**: Configures the development environment with EMFILE prevention settings and Node.js optimizations.

**Requirements**: Administrator privileges for system-wide changes

**Key Features**:

- Sets up environment variables for EMFILE prevention
- Configures PowerShell profiles with test shortcuts
- Optimizes Node.js settings for development
- Updates project .env.test file
- Configures Windows performance settings for testing

**Parameters**:

- `-Force`: Overwrite existing configurations
- `-SkipNodeCheck`: Skip Node.js version validation
- `-ValidateAfterSetup`: Run validation after setup
- `-ProjectRoot`: Specify project root directory (default: current directory)

**Example Usage**:

```powershell
# Standard setup
.\scripts\setup-test-environment.ps1

# Force overwrite and validate
.\scripts\setup-test-environment.ps1 -Force -ValidateAfterSetup

# Setup for specific project
.\scripts\setup-test-environment.ps1 -ProjectRoot "C:\my-project"
```

**Environment Variables Set**:

- `EMFILE_HANDLES_LIMIT=131072`
- `UV_THREADPOOL_SIZE=16`
- `NODE_OPTIONS=--max-old-space-size=4096 --max-semi-space-size=256 --optimize-for-size --gc-interval=100`
- `TEST_TIMEOUT=30000`
- `TEST_WORKERS=4`

### validate-emfile-fixes.ps1

**Purpose**: Comprehensive validation script to confirm EMFILE fixes are properly applied and measure performance.

**Requirements**: User-level privileges (optional admin for registry access)

**Key Features**:

- Analyzes current system handle usage
- Validates registry settings
- Checks environment variable configuration
- Validates project configuration
- Runs performance benchmarks
- Generates comprehensive reports
- Can fix common issues automatically

**Parameters**:

- `-Detailed`: Show detailed analysis and top processes
- `-Benchmark`: Run performance benchmarks
- `-FixIssues`: Automatically fix common configuration issues
- `-ProjectRoot`: Specify project root directory (default: current directory)

**Example Usage**:

```powershell
# Quick validation
.\scripts\validate-emfile-fixes.ps1

# Detailed analysis with benchmarks
.\scripts\validate-emfile-fixes.ps1 -Detailed -Benchmark

# Fix issues and validate
.\scripts\validate-emfile-fixes.ps1 -FixIssues -Detailed
```

**Validation Checks**:

- System handle usage analysis
- Registry settings verification
- Environment variable validation
- Project configuration checks
- Performance benchmarking

## Environment Variables

### EMFILE Prevention Variables

| Variable               | Value           | Purpose                               |
| ---------------------- | --------------- | ------------------------------------- |
| `EMFILE_HANDLES_LIMIT` | `131072`        | Maximum handles for Node.js processes |
| `UV_THREADPOOL_SIZE`   | `16`            | Node.js libuv thread pool size        |
| `NODE_OPTIONS`         | Optimized flags | Node.js runtime optimizations         |

### Test Environment Variables

| Variable       | Value   | Purpose                      |
| -------------- | ------- | ---------------------------- |
| `TEST_TIMEOUT` | `30000` | Test timeout in milliseconds |
| `TEST_WORKERS` | `4`     | Number of test workers       |
| `NODE_ENV`     | `test`  | Test environment indicator   |
| `LOG_LEVEL`    | `error` | Minimum log level for tests  |

### Windows-Specific Variables

| Variable      | Value    | Purpose                    |
| ------------- | -------- | -------------------------- |
| `FORCE_COLOR` | `1`      | Force colored output       |
| `NO_COLOR`    | `0`      | Don't disable colors       |
| `DEBUG`       | `test:*` | Debug test-related modules |

## Registry Changes

The scripts modify the following registry keys:

### System-Wide Handle Limits

```
HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem
- MaxUserHandles = 131072
- MaxSystemHandles = 262144
- LongPathEnabled = 1
```

### Memory Management

```
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
- LargeSystemCache = 1
- PagedPoolSize = 0 (auto)
- NonPagedPoolSize = 0 (auto)
```

### Performance Optimizations

```
HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl
- Win32PrioritySeparation = 38
```

## Troubleshooting

### Common Issues

1. **"Access Denied" Errors**
   - Run PowerShell as Administrator
   - Ensure User Account Control (UAC) is enabled

2. **"Environment Variables Not Applied"**
   - Restart PowerShell after running setup scripts
   - Check both user and system-level variables

3. **"Registry Changes Not Applied"**
   - System restart required for registry changes to take effect
   - Verify backup was created successfully

4. **"High Handle Usage Still Detected"**
   - Restart applications to pick up new limits
   - Check for handle leaks in Node.js applications
   - Monitor with Task Manager or Process Explorer

### Performance Monitoring

After applying fixes, monitor the following metrics:

- **Handle Usage**: Total system handles should be well below new limits
- **Node.js Performance**: Reduced memory usage and faster garbage collection
- **Test Execution**: Fewer EMFILE errors during test runs
- **System Stability**: Fewer application crashes due to resource exhaustion

### Validation Scenarios

**Healthy System Indicators**:

- Total handle usage < 80% of limits
- No Node.js processes with > 2000 handles
- Test suite completes without EMFILE errors
- Performance benchmarks pass within expected timeframes

**Warning Indicators**:

- Handle usage > 80% of limits
- Individual processes with > 2000 handles
- Intermittent EMFILE errors
- Slow performance benchmarks

**Critical Indicators**:

- Handle usage > 90% of limits
- Frequent EMFILE errors
- System instability
- Performance test failures

## PowerShell Profile Integration

The setup scripts add the following functions to your PowerShell profile:

```powershell
# Run test suite with EMFILE optimizations
Invoke-TestSuite [-TestPattern "*.test.ts"]

# Run tests with coverage
Invoke-TestWithCoverage

# Run performance tests
Invoke-PerformanceTest
```

## Best Practices

1. **Before Installation**
   - Close all development applications
   - Create a system restore point
   - Backup important data

2. **During Installation**
   - Run scripts as Administrator when required
   - Read all output messages carefully
   - Allow system restart when prompted

3. **After Installation**
   - Restart PowerShell to load environment variables
   - Validate configuration with validation script
   - Monitor system performance

4. **Ongoing Maintenance**
   - Run validation script periodically
   - Monitor handle usage during development
   - Update settings as project requirements change

## Security Considerations

- Registry backups are created automatically
- All changes are reversible
- Environment variables are set at user level when possible
- Scripts require explicit confirmation for destructive operations

## Support and Issues

If you encounter issues:

1. Check the validation script output for specific problems
2. Ensure all prerequisites are met (PowerShell 5.1+, Windows 10/11)
3. Run scripts with appropriate privileges
4. Check Windows Event Viewer for related errors
5. Consider running `validate-emfile-fixes.ps1 -FixIssues` for automatic fixes

## Version History

- **v1.0** (2025-10-30): Initial release with comprehensive EMFILE prevention suite
  - System-level handle limit optimization
  - Environment variable configuration
  - Performance benchmarking
  - Automatic issue detection and repair

---

**Note**: These scripts are designed for Windows 10/11 systems. Compatibility with other Windows versions is not guaranteed. Always test in a non-production environment first.
