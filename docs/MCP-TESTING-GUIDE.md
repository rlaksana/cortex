# MCP Server Testing Guide

This comprehensive guide covers testing procedures for the Cortex Memory MCP server, including automated tests, manual testing with MCP Inspector, and troubleshooting.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Test Environment Setup](#test-environment-setup)
4. [Automated Testing](#automated-testing)
5. [Manual Testing with MCP Inspector](#manual-testing-with-mcp-inspector)
6. [Test Scenarios](#test-scenarios)
7. [Coverage and Reporting](#coverage-and-reporting)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## Overview

The Cortex Memory MCP server testing suite includes:

- **Unit Tests**: Individual component testing with mocks
- **Integration Tests**: Full MCP protocol communication testing
- **Manual Testing**: Interactive testing with MCP Inspector
- **Performance Tests**: Load and stress testing
- **Error Handling Tests**: Edge cases and failure scenarios

### Test Architecture

```
tests/
├── setup/                    # Test environment setup
│   ├── mcp-test-setup.ts    # Mock Qdrant client and utilities
│   └── global-mcp-setup.ts  # Global test environment
├── mcp-server/              # MCP server specific tests
│   ├── mcp-server-unit.test.ts
│   └── mcp-server-integration.test.ts
└── contract/                # MCP protocol contract tests
```

## Prerequisites

### Required Software

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0
- **Docker** >= 20.0.0
- **Docker Compose** >= 2.0.0

### Optional for Manual Testing

- **MCP Inspector**: `npm install -g @modelcontextprotocol/inspector`
- **Qdrant Instance**: Local or remote (for integration tests)

## Test Environment Setup

### Quick Setup

```bash
# 1. Clone and install dependencies
git clone <repository-url>
cd mcp-cortex
npm install

# 2. Run the automated setup script
node scripts/setup-test-environment.js

# 3. Run tests to verify setup
npm run test:mcp
```

### Manual Setup

#### 1. Start Test Dependencies

```bash
# Start Qdrant and other test services
docker-compose -f docker-compose.test.yml up -d

# Verify services are running
curl http://localhost:6333/health  # Qdrant health check
```

#### 2. Build the Project

```bash
npm run build
```

#### 3. Configure Environment

```bash
# Copy test environment configuration
cp .env.test .env.local

# Edit configuration if needed
nano .env.local
```

#### 4. Verify Setup

```bash
# Check if server starts correctly
npm run start

# Run a quick test
npm run test:mcp:unit
```

## Automated Testing

### Test Categories

#### Unit Tests

Test individual components in isolation with mocks:

```bash
# Run unit tests only
npm run test:mcp:unit

# Run with coverage
npm run test:mcp:unit:coverage

# Run specific test file
npx vitest run tests/mcp-server/mcp-server-unit.test.ts
```

#### Integration Tests

Test full MCP server communication:

```bash
# Run integration tests
npm run test:mcp:integration

# Run with coverage
npm run test:mcp:integration:coverage

# Run integration tests in watch mode
npm run test:mcp:integration:watch
```

#### All MCP Tests

Run the complete MCP test suite:

```bash
# Run all MCP tests
npm run test:mcp

# Run with coverage and reporting
npm run test:mcp:coverage

# Run in CI mode (detailed output)
npm run test:mcp:ci
```

### Test Configuration

The test configuration is defined in `vitest.mcp.config.ts`:

- **Timeout**: 30 seconds per test
- **Retry**: 2 attempts for failed tests
- **Coverage**: 80% threshold
- **Environment**: Node.js with global test setup

### Environment Variables for Testing

Key environment variables in `.env.test`:

```bash
NODE_ENV=test
MCP_TEST_MODE=true
QDRANT_URL=http://localhost:6333
QDRANT_COLLECTION_NAME=test-cortex-memory
MCP_TEST_TIMEOUT=30000
COVERAGE_ENABLED=true
```

## Manual Testing with MCP Inspector

MCP Inspector provides an interactive interface for testing MCP servers.

### Installation

```bash
# Install MCP Inspector globally
npm install -g @modelcontextprotocol/inspector

# Or use npx without installation
npx @modelcontextprotocol/inspector
```

### Starting the Server

```bash
# In Terminal 1: Start the MCP server
npm run start

# In Terminal 2: Start MCP Inspector
mcp-inspector
```

### Connection Configuration

In MCP Inspector, configure the connection to:

- **Transport**: STDIO
- **Command**: `node`
- **Arguments**: `dist/index.js`
- **Working Directory**: Project root

### Test Scenarios

#### 1. Basic Connection Test

Initialize the MCP session:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {
      "tools": {}
    },
    "clientInfo": {
      "name": "inspector",
      "version": "1.0.0"
    }
  }
}
```

#### 2. List Available Tools

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

Expected response: Tools list with `memory_store`, `memory_find`, and `system_status`.

#### 3. Store Memory Items

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "memory_store",
    "arguments": {
      "items": [
        {
          "kind": "entity",
          "data": {
            "title": "Test Entity",
            "description": "A test entity for manual verification",
            "created_at": "2025-01-01T00:00:00.000Z"
          },
          "scope": {
            "project": "test-project",
            "branch": "test-branch",
            "org": "test-org"
          }
        }
      ]
    }
  }
}
```

#### 4. Find Memory Items

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "memory_find",
    "arguments": {
      "query": "test",
      "types": ["entity"],
      "limit": 10
    }
  }
}
```

#### 5. Check System Status

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "system_status",
    "arguments": {}
  }
}
```

### Automated Inspector Tests

For automated testing with MCP Inspector scenarios:

```bash
# Run automated Inspector test scenarios
node test-mcp-inspector.js

# Or use the convenient runner
node scripts/run-mcp-inspector-tests.js

# Run with detailed output
node scripts/run-mcp-inspector-tests.js --verbose
```

## Test Scenarios

### 1. Server Initialization

**Objective**: Verify MCP server starts and initializes correctly.

**Test Steps**:
1. Start MCP server
2. Send initialize request
3. Verify protocol version
4. Check capabilities
5. List available tools

**Expected Results**:
- Server responds to initialization
- Protocol version: `2025-06-18`
- Tools: `memory_store`, `memory_find`, `system_status`

### 2. Memory Storage Operations

**Objective**: Test memory item storage functionality.

**Test Steps**:
1. Store single memory item
2. Store multiple memory items
3. Store items with different types
4. Store items with scope filters
5. Verify storage success

**Expected Results**:
- All items stored successfully
- Correct item counts returned
- Proper error handling for invalid data

### 3. Memory Retrieval Operations

**Objective**: Test memory search and retrieval functionality.

**Test Steps**:
1. Search with simple query
2. Search with type filters
3. Search with scope filters
4. Search with limit parameters
5. Verify search results

**Expected Results**:
- Relevant items returned
- Filters applied correctly
- Limits respected
- Empty results for non-matching queries

### 4. System Status Monitoring

**Objective**: Test system status and health checks.

**Test Steps**:
1. Get system status
2. Check Qdrant connection
3. Verify collection status
4. Monitor performance metrics

**Expected Results**:
- System status returned
- Database connection status
- Performance metrics included
- Error handling for database issues

### 5. Error Handling

**Objective**: Test error handling and edge cases.

**Test Steps**:
1. Test invalid tool names
2. Test missing parameters
3. Test malformed requests
4. Test server resilience
5. Test database connection failures

**Expected Results**:
- Proper error messages
- Appropriate error codes
- Server remains stable
- Graceful degradation

## Coverage and Reporting

### Coverage Reports

Generate coverage reports for MCP tests:

```bash
# Generate coverage report
npm run test:mcp:coverage

# Generate HTML coverage report
npm run test:mcp:coverage:html

# View coverage in browser
open artifacts/coverage/index.html
```

### Coverage Thresholds

Current coverage thresholds:
- **Branches**: 80%
- **Functions**: 80%
- **Lines**: 80%
- **Statements**: 80%

Special thresholds for critical files:
- `src/index.ts`: 90% for all metrics

### Test Reports

Test reports are generated in `artifacts/mcp-tests/`:

- **JSON Results**: `mcp-test-results.json`
- **JUnit XML**: `mcp-test-results.xml`
- **Coverage HTML**: `coverage/index.html`
- **Inspector Tests**: `inspector-test-results.json`

## Troubleshooting

### Common Issues

#### 1. Server Fails to Start

**Symptoms**: Server exits with error or doesn't respond to initialization.

**Solutions**:
```bash
# Check if project is built
ls -la dist/index.js

# Build the project
npm run build

# Check Node.js version
node --version  # Should be >= 18.0.0

# Check environment variables
cat .env.test
```

#### 2. Database Connection Issues

**Symptoms**: Tests fail with Qdrant connection errors.

**Solutions**:
```bash
# Check if Qdrant is running
docker-compose -f docker-compose.test.yml ps

# Restart Qdrant
docker-compose -f docker-compose.test.yml restart qdrant-test

# Check Qdrant health
curl http://localhost:6333/health

# Check logs
docker-compose -f docker-compose.test.yml logs qdrant-test
```

#### 3. Test Timeouts

**Symptoms**: Tests fail with timeout errors.

**Solutions**:
```bash
# Increase test timeout
export MCP_TEST_TIMEOUT=60000

# Run tests with longer timeout
npx vitest run --timeout 60000

# Check for resource constraints
free -h  # Memory usage
df -h    # Disk space
```

#### 4. Port Conflicts

**Symptoms**: Services fail to start due to port conflicts.

**Solutions**:
```bash
# Check port usage
netstat -tulpn | grep :6333

# Kill conflicting processes
sudo kill -9 <PID>

# Use different ports
export QDRANT_URL=http://localhost:6334
```

#### 5. Permission Issues

**Symptoms**: Tests fail with file permission errors.

**Solutions**:
```bash
# Check file permissions
ls -la artifacts/

# Fix permissions
chmod -R 755 artifacts/

# Run as appropriate user
sudo chown -R $USER:$USER artifacts/
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable debug logging
export DEBUG=mcp:*
export MCP_LOG_LEVEL=debug

# Run with debug output
DEBUG=mcp:* npm run test:mcp

# Check logs
tail -f artifacts/test-logs/mcp-test.log
```

### Clean Test Environment

Reset the test environment:

```bash
# Stop Docker services
docker-compose -f docker-compose.test.yml down -v

# Clean artifacts
rm -rf artifacts/

# Reset environment
git checkout .env.test

# Re-run setup
node scripts/setup-test-environment.js
```

## Best Practices

### Test Development

1. **Use Test Utilities**: Leverage `TestUtils` for common operations
2. **Mock External Dependencies**: Use `MockQdrantClient` for unit tests
3. **Test Isolation**: Each test should be independent
4. **Cleanup**: Clean up resources after each test
5. **Error Cases**: Test both success and failure scenarios

### Continuous Integration

1. **Run All Tests**: Ensure complete test suite passes
2. **Coverage Gates**: Maintain coverage thresholds
3. **Parallel Execution**: Run tests in parallel for speed
4. **Artifact Collection**: Save test results and reports
5. **Failure Analysis**: Investigate test failures promptly

### Performance Testing

1. **Load Testing**: Test with concurrent requests
2. **Memory Profiling**: Monitor memory usage
3. **Response Times**: Measure request latency
4. **Resource Limits**: Test under resource constraints
5. **Scalability**: Verify performance under load

### Manual Testing

1. **Use MCP Inspector**: For interactive testing
2. **Test Real Scenarios**: Use realistic test data
3. **Edge Cases**: Test boundary conditions
4. **User Workflows**: Test common user journeys
5. **Documentation**: Document test procedures

## Quick Reference

### Essential Commands

```bash
# Setup test environment
node scripts/setup-test-environment.js

# Run all MCP tests
npm run test:mcp

# Run integration tests
npm run test:mcp:integration

# Run unit tests
npm run test:mcp:unit

# Run with coverage
npm run test:mcp:coverage

# Run Inspector tests
node scripts/run-mcp-inspector-tests.js

# Cleanup test environment
docker-compose -f docker-compose.test.yml down -v
```

### File Locations

- **Test Config**: `vitest.mcp.config.ts`
- **Test Setup**: `tests/setup/mcp-test-setup.ts`
- **Unit Tests**: `tests/mcp-server/mcp-server-unit.test.ts`
- **Integration Tests**: `tests/mcp-server/mcp-server-integration.test.ts`
- **Environment**: `.env.test`
- **Docker Compose**: `docker-compose.test.yml`

### Environment Variables

- `NODE_ENV=test`: Test environment
- `MCP_TEST_MODE=true`: Enable test mode
- `QDRANT_URL`: Database URL
- `MCP_TEST_TIMEOUT`: Test timeout in milliseconds
- `COVERAGE_ENABLED`: Enable coverage collection

### Troubleshooting Commands

```bash
# Check service status
docker-compose -f docker-compose.test.yml ps

# View service logs
docker-compose -f docker-compose.test.yml logs

# Test database connection
curl http://localhost:6333/health

# Check test artifacts
ls -la artifacts/mcp-tests/

# Run tests with debug output
DEBUG=mcp:* npm run test:mcp
```

---

For additional help or to report issues, refer to the project repository or contact the development team.