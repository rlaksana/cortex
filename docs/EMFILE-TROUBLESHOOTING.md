# EMFILE Troubleshooting Guide

## Common EMFILE Issues and Solutions

This guide provides troubleshooting steps for common EMFILE ("too many open files") issues that may occur during development and testing.

## Quick Diagnosis

### Check Current System State
```powershell
# Run the simple validation script
.\scripts\simple-emfile-validation.ps1

# Check handle usage manually
Get-Process | Measure-Object -Property HandleCount -Sum | Select-Object Sum
```

### Check Test Environment
```bash
# Verify .env.test has EMFILE settings
cat .env.test | grep EMFILE

# Check if environment variables are loaded
echo $EMFILE_HANDLES_LIMIT
echo $UV_THREADPOOL_SIZE
```

## Common Issues and Solutions

### 1. "EMFILE: too many open files" during testing

**Symptoms:**
- Tests fail with EMFILE errors
- Test suite stops unexpectedly
- Coverage collection fails

**Solutions:**

**Option A: Quick Fix**
```bash
# Set environment variables for current session
export EMFILE_HANDLES_LIMIT=131072
export UV_THREADPOOL_SIZE=16
export TEST_WORKERS=4
npm test
```

**Option B: Full Setup**
```powershell
# Run as Administrator
.\scripts\setup-test-environment.ps1
.\scripts\increase-handles.ps1
```

**Option C: Test-specific Fix**
```bash
# Use conservative test settings
TEST_WORKERS=1 TEST_TIMEOUT=60000 npm test
```

### 2. High handle usage in development

**Symptoms:**
- System feels sluggish
- Applications crash randomly
- Task Manager shows high handle count

**Diagnosis:**
```powershell
# Check handle usage by process
Get-Process | Sort-Object HandleCount -Descending | Select-Object -First 10 Name,Id,HandleCount

# Check Node.js processes specifically
Get-Process -Name "node" | Sort-Object HandleCount -Descending | Select-Object Name,Id,HandleCount
```

**Solutions:**

**Restart Node.js Processes:**
```powershell
# Kill all Node.js processes
Get-Process -Name "node" | Stop-Process -Force

# Restart development server
npm run dev
```

**System Cleanup:**
```powershell
# Restart PowerShell/terminal
# Restart VS Code or other IDEs
# Restart computer if necessary
```

### 3. Test coverage fails with EMFILE errors

**Symptoms:**
- `npm run test:coverage` fails
- Coverage reports incomplete
- Memory errors during coverage collection

**Solutions:**

**Reduce Coverage Scope:**
```bash
# Run coverage for specific files only
npm run test:coverage:unit

# Or run with reduced workers
TEST_WORKERS=2 npm run test:coverage
```

**Use Coverage Report Variants:**
```bash
# Generate JSON report (less resource intensive)
npm run test:coverage:json

# Generate text summary only
npm run test:coverage:summary
```

### 4. Handle leaks in custom code

**Symptoms:**
- Handle count increases over time
- Performance degrades during long-running processes
- EMFILE errors after extended operation

**Diagnosis:**
```javascript
// Add handle monitoring to your code
const handleCount = () => {
  const used = process._getActiveHandles().length;
  console.log(`Active handles: ${used}`);
  return used;
};

// Monitor before and after operations
const before = handleCount();
// Your code here
const after = handleCount();
console.log(`Handle increase: ${after - before}`);
```

**Solutions:**

**Explicit Cleanup:**
```javascript
// Always close file handles
import fs from 'fs';
const handle = fs.openSync('file.txt', 'r');
try {
  // Use the file
} finally {
  fs.closeSync(handle);
}

// Use streams with proper cleanup
import { createReadStream } from 'fs';
const stream = createReadStream('file.txt');
stream.on('end', () => {
  stream.destroy(); // Explicit cleanup
});
```

### 5. PowerShell script errors

**Symptoms:**
- "Access denied" errors
- "Execution policy" errors
- Script syntax errors

**Solutions:**

**Execution Policy:**
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or run with bypass
powershell -ExecutionPolicy Bypass -File "script.ps1"
```

**Administrator Privileges:**
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell -> "Run as Administrator"
```

**Character Encoding:**
```powershell
# Save scripts as UTF-8 with BOM
# Check file encoding
Get-Content "script.ps1" | Select-Object -First 1
```

## Performance Monitoring

### Monitor Handle Usage During Development

**Windows Task Manager:**
1. Open Task Manager
2. Go to "Details" tab
3. Right-click columns -> "Select columns"
4. Check "Handles"
5. Sort by "Handles" to monitor usage

**PowerShell Monitoring:**
```powershell
# Continuous monitoring
while ($true) {
    $handles = (Get-Process | Measure-Object -Property HandleCount -Sum).Sum
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "$timestamp - Total handles: $handles"
    Start-Sleep -Seconds 5
}
```

**Node.js Monitoring:**
```javascript
// Add to your application
setInterval(() => {
  const used = process._getActiveHandles().length;
  const memory = process.memoryUsage();
  console.log(`Handles: ${used}, Memory: ${Math.round(memory.heapUsed / 1024 / 1024)}MB`);
}, 10000);
```

## Prevention Best Practices

### 1. Development Environment

**Regular Cleanup:**
```bash
# Restart development environment daily
# Close unused applications
# Monitor handle usage weekly
```

**Resource Management:**
```bash
# Use conservative test settings during development
TEST_WORKERS=2 npm test

# Use focused tests rather than full suite
npm test -- --grep "specific test"
```

### 2. Code Development

**Handle Management:**
```javascript
// Always use try/finally for cleanup
try {
  const resource = createResource();
  // Use resource
} finally {
  resource.cleanup(); // Always cleanup
}

// Use resource management patterns
import { pipeline } from 'stream';
pipeline(inputStream, transform, outputStream, (err) => {
  // All streams automatically cleaned up
});
```

**Memory Management:**
```javascript
// Force garbage collection in development
if (process.env.NODE_ENV === 'development') {
  setInterval(() => {
    if (global.gc) {
      global.gc();
    }
  }, 60000); // Every minute
}
```

### 3. Testing Strategy

**Test Organization:**
```javascript
// Use beforeEach/afterEach for cleanup
describe('Resource Tests', () => {
  beforeEach(() => {
    // Setup
  });

  afterEach(() => {
    // Explicit cleanup
    cleanupResources();
  });
});
```

**Test Configuration:**
```javascript
// vitest.config.js
export default {
  test: {
    pool: 'threads', // Use threads instead of processes
    poolOptions: {
      threads: {
        maxThreads: 4, // Limit concurrent threads
      }
    },
    setupFiles: ['./test-setup.js'], // Global cleanup
  }
}
```

## Emergency Procedures

### System Handle Limit Reached

**Immediate Actions:**
1. Save all work
2. Close all applications
3. Restart computer
4. Run validation after restart

**After Restart:**
```powershell
# Validate system state
.\scripts\simple-emfile-validation.ps1

# Check if fixes are still applied
.\scripts\validate-emfile-fixes.ps1 -Detailed
```

### Test Suite Completely Fails

**Fallback Strategy:**
```bash
# Run tests with minimal configuration
TEST_WORKERS=1 TEST_TIMEOUT=120000 npm test -- --reporter=verbose

# Or run individual test files
npm test -- tests/unit/services/analytics.service.test.ts
```

**Recovery:**
```bash
# Clean up test artifacts
rm -rf coverage/
rm -rf test-results/
rm -rf node_modules/.cache/

# Reinstall dependencies
npm ci

# Run single test to validate
npm test -- --run
```

## Getting Help

### Check Logs

**Test Logs:**
```bash
# Check test output for EMFILE patterns
npm test 2>&1 | grep -i emfile

# Check coverage logs
npm run test:coverage 2>&1 | grep -i "error\|fail\|emfile"
```

**System Logs:**
```powershell
# Check Windows Event Viewer for system errors
eventvwr.msc

# Look for Application errors related to handle limits
```

### Validation Results

**Healthy System Indicators:**
- Total handles < 50,000
- Individual Node.js processes < 2,000 handles
- Tests complete without EMFILE errors
- Coverage reports generate successfully

**Warning Indicators:**
- Handle usage increasing over time
- Intermittent EMFILE errors
- Slow test execution
- High memory usage

### Support

If issues persist after following this guide:

1. Run `.\scripts\simple-emfile-validation.ps1` and save the output
2. Check [EMFILE-TEST-RESULTS.md](../EMFILE-TEST-RESULTS.md) for known issues
3. Review the validation script logs for specific error patterns
4. Consider system hardware limitations (RAM, disk space)
5. Consult Windows Event Viewer for system-level errors

---

**Last Updated:** 2025-10-30
**Version:** 1.0
**Compatible with:** Windows 10/11, Node.js 20+, PowerShell 5.1+