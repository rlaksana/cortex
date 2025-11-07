# MCP Server Testing - Quick Start Guide

This is a quick reference for setting up and running tests for the Cortex Memory MCP server.

## 🚀 Quick Start

```bash
# 1. Setup test environment (one-time setup)
node scripts/setup-test-environment.js

# 2. Run automated tests
npm run test:mcp

# 3. Run manual tests with MCP Inspector
npm run test:inspector:setup
```

## 📋 Available Test Commands

### Automated Tests
```bash
npm run test:mcp              # Run all MCP tests
npm run test:mcp:unit         # Run unit tests only
npm run test:mcp:integration  # Run integration tests only
npm run test:mcp:coverage     # Run with coverage report
npm run test:mcp:watch        # Run in watch mode
npm run test:mcp:ci           # Run in CI mode
```

### Manual Testing
```bash
npm run test:inspector        # Run Inspector test scenarios
npm run test:inspector:setup  # Run Inspector test runner
```

### Environment Setup
```bash
node scripts/setup-test-environment.js        # Full setup
node scripts/setup-test-environment.js --cleanup # Cleanup
node scripts/setup-test-environment.js --validation-only # Validate setup
```

## 🧪 Test Categories

- **Unit Tests**: Component testing with mocks
- **Integration Tests**: Full MCP protocol testing
- **Inspector Tests**: Manual testing scenarios
- **Coverage Tests**: Code coverage reporting

## 📁 Test Structure

```
tests/
├── setup/                     # Test environment setup
├── mcp-server/               # MCP server tests
│   ├── mcp-server-unit.test.ts
│   └── mcp-server-integration.test.ts
└── contract/                 # Protocol contract tests

artifacts/
├── mcp-tests/               # Test results
├── test-logs/               # Test logs
└── coverage/                # Coverage reports
```

## 🐳 Docker Services

Tests use Docker services defined in `docker-compose.test.yml`:
- **Qdrant**: Vector database (port 6333)
- **Redis**: Caching (port 6379)
- **Prometheus**: Metrics (port 9090)
- **Grafana**: Dashboards (port 3001)

## 🔧 Configuration

Main test configuration files:
- `vitest.mcp.config.ts` - Test runner configuration
- `.env.test` - Test environment variables
- `tsconfig.test.json` - TypeScript test configuration

## 🐛 Troubleshooting

### Server won't start
```bash
npm run build  # Build the project first
```

### Database connection issues
```bash
docker-compose -f docker-compose.test.yml restart qdrant-test
curl http://localhost:6333/health  # Check health
```

### Port conflicts
```bash
docker-compose -f docker-compose.test.yml down  # Stop services
```

### Permission issues
```bash
chmod -R 755 artifacts/  # Fix permissions
```

## 📊 Coverage Reports

Coverage reports are generated in `artifacts/coverage/`:
- Open `artifacts/coverage/index.html` in browser
- Target coverage: 80% overall, 90% for critical files

## 🎯 Manual Testing with MCP Inspector

1. Install MCP Inspector: `npm install -g @modelcontextprotocol/inspector`
2. Start server: `npm run start`
3. Start Inspector: `mcp-inspector`
4. Connect to server and test tools

## 📚 Documentation

For detailed testing instructions, see:
- `docs/MCP-TESTING-GUIDE.md` - Comprehensive testing guide
- `test-mcp-inspector.js` - Inspector test scenarios
- `scripts/run-mcp-inspector-tests.js` - Test runner script

## 🔍 Test Scenarios

Core test scenarios include:
1. **Server Initialization** - MCP protocol handshake
2. **Memory Storage** - Store knowledge items
3. **Memory Retrieval** - Search and find items
4. **System Status** - Health checks
5. **Error Handling** - Edge cases and failures

## 🚨 Important Notes

- Tests require Node.js >= 18.0.0
- Docker and Docker Compose must be installed
- Tests use Qdrant vector database
- All test data is isolated and cleaned up
- Tests can run in parallel for performance

## 📞 Support

For issues:
1. Check the troubleshooting section above
2. Review logs in `artifacts/test-logs/`
3. Consult the comprehensive testing guide
4. Check GitHub issues for known problems