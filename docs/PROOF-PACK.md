# Cortex Memory MCP - Proof Pack Guide

## Overview

This guide helps new engineers run the complete proof pack for the Cortex Memory MCP server, ensuring all quality gates, tests, and validations pass before merging changes.

## Prerequisites

### System Requirements

- **Node.js**: >= 20.0.0 (recommended 22.x)
- **npm**: >= 9.0.0
- **Git**: >= 2.44.0
- **Docker**: >= 20.10.0 (for Qdrant integration tests)
- **Memory**: 8GB+ RAM (for testing and builds)
- **Disk**: 10GB+ free space

### Development Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd mcp-cortex

# Install dependencies
npm install

# Setup Git hooks
npm run prepare
```

## Quick Start Proof Pack

For a fast validation run:

```bash
# Run the complete quality gate
npm run quality:production

# Or run individual components
npm run ci:all
```

## Complete Proof Pack Workflow

### 1. Environment Validation

```bash
# Check Node.js version
node --version  # Should be >= 20.0.0

# Verify npm installation
npm --version

# Check TypeScript compilation
npm run type-check

# Validate package scripts
npm run help
```

### 2. Code Quality Validation

```bash
# Linting (currently bypassed due to TypeScript plugin conflicts)
npm run lint

# Code formatting
npm run format:check  # Validate formatting
npm run format        # Fix formatting issues

# Quality gates
npm run quality-gate:strict
npm run quality-gate:ci
```

### 3. Build Validation

```bash
# Clean build
npm run build

# Validate build output
ls -la dist/

# Test built application
npm run start:raw
```

### 4. Testing Suite

#### Unit Tests

```bash
# Run all unit tests
npm run test:unit

# Run with coverage
npm run test:coverage:unit

# Watch mode for development
npm run test:watch
```

#### Integration Tests

```bash
# Start Qdrant (required for integration tests)
docker run -d --name qdrant -p 6333:6333 qdrant/qdrant:latest

# Run integration tests
npm run test:integration

# Run specific integration test suites
npm run test:integration:happy
npm run test:integration:degraded
npm run test:integration:reassembly
npm run test:integration:performance
```

#### Full Test Suite

```bash
# Run complete test suite
npm run test:all

# CI-optimized test run
npm run test:ci

# Coverage reporting
npm run test:coverage:ci
npm run verify-test-coverage
```

### 5. Security Validation

```bash
# Security audit
npm run security:audit

# Security checks
npm run security:check
npm run security:scan

# Fix security issues (if any)
npm run security:fix
```

### 6. MCP Tool Validation

```bash
# Validate MCP configuration
npm run mcp:check-config

# Test MCP tools
npm run mcp:test-tools

# Validate tool implementations
npm run mcp:validate-tools
```

### 7. Documentation Validation

```bash
# Generate documentation
npm run docs:generate

# Validate documentation
npm run docs:validate

# Create documentation index
npm run docs:index

# Serve documentation locally
npm run docs:serve
```

### 8. Performance Validation

```bash
# Run performance tests
npm run test:performance

# Specific performance tests
npm run test:performance:load
npm run test:performance:memory
npm run test:performance:concurrent
npm run test:performance:stress
npm run test:performance:latency
npm run test:performance:database
npm run test:performance:search
```

## Git Hooks Validation

The project includes automated Git hooks that run on commit and push:

### Pre-commit Hooks

- Type checking
- Linting
- Format validation
- Quality checks
- Unit tests

### Pre-push Hooks

- Full test suite
- Integration tests
- Security audit
- MCP tool validation
- Build verification
- Documentation generation

### Running Hooks Manually

```bash
# Test pre-commit hooks
npm run pre-commit

# Test pre-push hooks
./.husky/pre-push
```

## CI/CD Pipeline Validation

### Local CI Simulation

```bash
# Simulate CI pipeline locally
npm run ci:all

# Run production-ready checks
npm run quality:production

# Test deployment readiness
npm run deploy:validate
```

### Understanding CI Stages

1. **Quality Gates**: Type checking, linting, formatting, builds
2. **Test Suite**: Unit tests, integration tests, coverage
3. **Security & Performance**: Security audit, performance tests
4. **Documentation**: Build and validate docs
5. **Deployment Readiness**: Full validation pipeline

## Known Issues & Troubleshooting

### Current System State (v2.0.1)

**Resolved Issues ✅**:

- Version inconsistency: package.json updated to v2.0.1 to match CHANGELOG.md
- MCP validation script: Fixed regex syntax error in `scripts/validate-mcp-tools.js`
- Coverage configuration: Re-enabled coverage in `vitest.config.ts` with proper thresholds

**Note**: Git tags need to be created for v2.0.0 and v2.0.1 releases

## Troubleshooting Common Issues

### TypeScript Compilation Errors

```bash
# Clear TypeScript cache
rm -rf .tscache/

# Rebuild completely
npm run clean-build
npm run build
```

### Test Failures

```bash
# Clear test cache
rm -rf .vitest/
rm -rf coverage/

# Run tests with verbose output
npm run test:ci -- --reporter=verbose

# Run specific failing test
npm run test:unit -- tests/unit/failing-test.test.ts
```

### Qdrant Connection Issues

```bash
# Reset Qdrant container
docker stop qdrant
docker rm qdrant
docker run -d --name qdrant -p 6333:6333 qdrant/qdrant:latest

# Test connection
npm run test:connection
```

### Memory Issues

```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=8192"

# Run with increased memory
NODE_OPTIONS="--max-old-space-size=8192" npm run test:ci
```

## Success Criteria

The proof pack passes successfully when:

### Quality Gates ✅

- [ ] TypeScript compilation succeeds (`npm run type-check`)
- [ ] Linting passes (`npm run lint`)
- [ ] Code formatting is valid (`npm run format:check`)
- [ ] Quality gate passes (`npm run quality-gate:ci`)

### Testing ✅

- [ ] All unit tests pass (`npm run test:unit`)
- [ ] Integration tests pass (`npm run test:integration`)
- [ ] Coverage thresholds met (`npm run verify-test-coverage`)
  - **Note**: Coverage is enabled with thresholds: Lines ≥90%, Functions ≥90%, Branches ≥85%, Statements ≥90%
- [ ] Security tests pass (`npm run test:security`)

### Build & Deployment ✅

- [ ] Build succeeds (`npm run build`)
- [ ] MCP tools validate (`npm run mcp:validate-tools`)
- [ ] Documentation builds (`npm run docs:all`)
- [ ] Package creation succeeds (`npm pack`)

### Performance ✅

- [ ] Performance tests complete (`npm run test:performance`)
- [ ] Memory usage within limits
- [ ] Response times acceptable

## Automation Scripts

### Complete Proof Pack Script

Create `scripts/run-proof-pack.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Starting Cortex Memory MCP Proof Pack..."

# Environment validation
echo "📋 Validating environment..."
npm run type-check || exit 1
npm run lint || exit 1

# Quality checks
echo "✨ Running quality checks..."
npm run quality-gate:ci || exit 1
npm run format:check || exit 1

# Build validation
echo "🏗️ Building project..."
npm run build || exit 1

# Testing
echo "🧪 Running test suite..."
npm run test:ci || exit 1
npm run test:integration || exit 1

# Security
echo "🔒 Running security checks..."
npm run security:audit || exit 1

# MCP validation
echo "🛠️ Validating MCP tools..."
npm run mcp:validate-tools || exit 1

# Documentation
echo "📚 Building documentation..."
npm run docs:all || exit 1

echo "✅ Proof pack completed successfully!"
```

### Quick Validation Script

Create `scripts/quick-validation.sh`:

```bash
#!/bin/bash
set -e

echo "⚡ Quick validation..."

npm run type-check
npm run lint
npm run test:unit
npm run build

echo "✅ Quick validation passed!"
```

## Next Steps

After successful proof pack completion:

1. **Create Pull Request**: Submit changes for code review
2. **CI Pipeline**: Automated validation will run on GitHub Actions
3. **Code Review**: Team members review and approve changes
4. **Merge**: Changes merged to main branch
5. **Release**: Automated deployment process

## Resources

- [API Documentation](./API-REFERENCE.md)
- [Operations Guide](./OPS-DACKUP-MIGRATION.md)
- [Troubleshooting](./TROUBLESHOOT-ERRORS.md)
- [Architecture Overview](./ARCH-SYSTEM.md)
- [New Engineer Guide](./NEW-ENGINEER-GUIDE.md)

## Support

For proof pack issues:

1. Check this guide first
2. Review troubleshooting section
3. Check GitHub Issues
4. Contact the development team

---

**Last Updated**: 2025-11-04
**Version**: 2.0.0
**Maintainers**: Cortex Team
