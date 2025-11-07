# MCP Server Shutdown Testing Guide

This document provides comprehensive guidance for testing the MCP server's graceful shutdown functionality.

## Overview

The MCP server includes robust graceful shutdown mechanisms to ensure:

- Clean termination of all connections
- Completion of in-flight operations
- Proper resource cleanup
- No memory leaks or resource remains

## Test Files

### 1. Unit Tests

- **File**: `tests/integration/mcp-server-graceful-shutdown.test.ts`
- **Framework**: Vitest
- **Coverage**: Signal handling, connection cleanup, resource management

### 2. Simple Test Script

- **File**: `test-mcp-server-shutdown.js`
- **Usage**: Node.js script for basic shutdown validation
- **Features**: Quick validation, JSON report generation

### 3. Comprehensive Test Suite

- **File**: `test-shutdown-comprehensive.mjs`
- **Usage**: Advanced testing with stress scenarios
- **Features**: Resource monitoring, integration tests, stress testing

### 4. Test Utilities

- **File**: `tests/utils/shutdown-test-utils.ts`
- **Content**: Helper classes and functions for shutdown testing
- **Features**: Process management, resource monitoring, test execution

## Quick Start

### Basic Testing

```bash
# Run the simple shutdown test
node test-mcp-server-shutdown.js

# Run with verbose output
node test-mcp-server-shutdown.js --verbose
```

### Comprehensive Testing

```bash
# Run comprehensive test suite
node test-shutdown-comprehensive.mjs

# Run with all options
node test-shutdown-comprehensive.mjs --verbose --integration --stress
```

### Unit Tests

```bash
# Run unit tests (if Vitest is configured)
npm test -- mcp-server-graceful-shutdown

# Run with coverage
npm run test:coverage -- mcp-server-graceful-shutdown
```

## Test Categories

### 1. Signal Handling Tests

- **SIGINT (Ctrl+C)**: Graceful shutdown on interrupt
- **SIGTERM**: Graceful shutdown on termination signal
- **SIGUSR2**: Graceful shutdown on custom signal
- **Multiple signals**: Handling of duplicate/rapid signals
- **Exception handling**: Uncaught exceptions and rejections

### 2. Connection Cleanup Tests

- **Database connections**: Qdrant client cleanup
- **HTTP clients**: Connection pool cleanup
- **WebSocket connections**: Real-time connection cleanup
- **Network resources**: Socket and handle cleanup

### 3. In-flight Operation Tests

- **Active operations**: Waiting for ongoing operations
- **Drain mode**: Stopping new requests while completing existing ones
- **Operation timeout**: Handling stuck operations
- **Grace period**: Allowing time for cleanup

### 4. Resource Management Tests

- **Memory cleanup**: Detecting memory leaks
- **File handles**: Open file descriptor cleanup
- **Timers**: Timeout and interval cleanup
- **Event listeners**: Proper event cleanup

### 5. Error Scenario Tests

- **Operation failures**: Handling cleanup operation errors
- **Critical failures**: Behavior when critical operations fail
- **Timeout scenarios**: Handling extended shutdown times
- **Force shutdown**: Emergency shutdown procedures

### 6. Stress Tests

- **High load**: Shutdown under heavy load
- **Resource pressure**: Memory/CPU pressure during shutdown
- **Rapid cycles**: Quick start/stop sequences
- **Concurrent scenarios**: Multiple shutdown triggers

## Test Results Interpretation

### Success Indicators

- ✅ Clean exit code (0)
- ✅ All signals handled gracefully
- ✅ No resource leaks detected
- ✅ Connections properly closed
- ✅ Memory usage stable

### Failure Indicators

- ❌ Non-zero exit codes
- ❌ Unhandled exceptions
- ❌ Resource leaks (>50MB memory, >5 handles)
- ❌ Connections not closed
- ❌ Timeout during shutdown

### Warnings

- ⚠️ Small resource leaks (<50MB, <5 handles)
- ⚠️ Slow shutdown (>10s)
- ⚠️ Non-critical operation failures
- ⚠️ Incomplete cleanup

## Configuration

### Environment Variables

```bash
NODE_ENV=test                    # Test environment
LOG_LEVEL=debug                  # Verbose logging
SHUTDOWN_TIMEOUT=30000           # Shutdown timeout (ms)
FORCE_SHUTDOWN_TIMEOUT=60000     # Force shutdown timeout (ms)
ENABLE_DRAIN_MODE=true           # Enable drain mode
DRAIN_TIMEOUT=10000              # Drain mode timeout (ms)
```

### Test Options

- `--verbose`: Enable detailed logging
- `--integration`: Run integration tests
- `--stress`: Run stress tests
- `--timeout`: Custom timeout (ms)

## Troubleshooting

### Common Issues

#### Server Not Starting

**Problem**: Test server fails to start
**Solution**:

- Ensure built server exists (`dist/index.js`)
- Check dependencies are installed
- Verify Node.js version compatibility

#### Tests Timing Out

**Problem**: Tests exceed timeout limits
**Solution**:

- Increase timeout with `--timeout` option
- Check for infinite loops in server code
- Verify server is responsive to signals

#### Resource Leaks Detected

**Problem**: Memory or handle leaks found
**Solution**:

- Review connection cleanup code
- Check for missing `clearTimeout`/`clearInterval`
- Verify event listener removal
- Ensure proper error handling

#### Signal Handling Fails

**Problem**: Signals not handled properly
**Solution**:

- Check signal handler registration
- Verify process event listeners
- Ensure no duplicate signal handlers
- Review graceful shutdown logic

### Debug Mode

```bash
# Run with maximum debugging
DEBUG=* node test-shutdown-comprehensive.mjs --verbose

# Run with Node.js debugging
node --inspect test-shutdown-comprehensive.mjs
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Shutdown Tests
on: [push, pull_request]

jobs:
  test-shutdown:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Run shutdown tests
        run: node test-shutdown-comprehensive.mjs

      - name: Upload test reports
        uses: actions/upload-artifact@v3
        with:
          name: shutdown-test-reports
          path: |
            comprehensive-shutdown-test-report.md
            comprehensive-shutdown-test-report.json
```

### CI/CD Pipeline Integration

1. **Pre-deployment**: Run shutdown tests
2. **Canary testing**: Test with real traffic
3. **Production monitoring**: Monitor shutdown behavior
4. **Alerting**: Alert on shutdown failures

## Performance Benchmarks

### Expected Performance

- **Graceful shutdown**: <5 seconds
- **Force shutdown**: <1 second
- **Memory usage**: <50MB increase
- **Handle count**: <5 handles remaining

### Monitoring Metrics

- Shutdown duration
- Memory usage before/after
- Open file handles
- Active connections
- Error counts

## Best Practices

### Development

1. **Test locally** before merging
2. **Use verbose mode** for debugging
3. **Check resource usage** regularly
4. **Update tests** when changing shutdown logic

### Operations

1. **Monitor shutdown behavior** in production
2. **Set appropriate timeouts** for your environment
3. **Configure health checks** to detect issues
4. **Document shutdown procedures** for operations team

### Code Quality

1. **Handle all error cases** in shutdown code
2. **Use timeouts** for all cleanup operations
3. **Log shutdown progress** for debugging
4. **Test with various load conditions**

## Extending Tests

### Adding New Tests

1. Create test method following naming convention
2. Use `ShutdownTestExecutor` for consistency
3. Include resource monitoring
4. Add appropriate assertions
5. Update documentation

### Custom Scenarios

```typescript
// Example: Custom shutdown test
results.push(
  await executor.executeTest(
    'Custom Shutdown Scenario',
    async (server) => {
      await waitForServerReady(server);

      // Your custom test logic here

      await server.stop('SIGINT');
    },
    { logOutput: true, timeout: 15000 }
  )
);
```

## Support

For issues with shutdown testing:

1. Check this documentation first
2. Review test logs for error details
3. Verify server configuration
4. Check system resource availability
5. Consult the main MCP server documentation

---

**Last Updated**: 2025-11-05
**Version**: 1.0.0
**Maintainer**: Cortex Team
