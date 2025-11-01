# MCP Cortex Memory Test Profile

## Overview

This document describes the mandatory test profile with mocked embedding service for CI/CD environments. This profile ensures consistent testing across all environments without depending on external services like OpenAI.

## Configuration Files

### 1. `config/test.local.json`
Main test configuration file that defines:
- Environment variables
- Mock service settings
- Database configuration
- Testing parameters
- CI/CD specific settings

### 2. `tests/setup/test-profile-setup.ts`
Test setup script that:
- Loads test configuration
- Sets environment variables
- Validates test profile
- Provides utilities for test reporting

### 3. `.env.test.example`
Example environment file with:
- Database connection settings
- API key placeholders
- Feature flags
- Security configuration

## Key Features

### Mocked Services

1. **Mock Embedding Service**
   - Deterministic vector generation
   - Configurable dimensions (default: 1536)
   - No external API dependencies
   - Consistent results across test runs

2. **Mock Semantic Analyzer**
   - Predefined semantic boundaries
   - Configurable analysis results
   - No embedding service dependency

3. **Test Database**
   - Uses local Qdrant instance
   - Isolated test collection
   - Configurable connection settings

### Environment Variables

```bash
# Core test settings
NODE_ENV=test
LOG_LEVEL=error
MOCK_EXTERNAL_SERVICES=true

# Feature flags
SEMANTIC_CHUNKING_OPTIONAL=true
ENABLE_CACHING=false
ENABLE_METRICS=false
ENABLE_AUTH=false

# Mock service settings
MOCK_EMBEDDING_SERVICE=true
MOCK_EMBEDDING_DETERMINISTIC=true
MOCK_EMBEDDING_DIMENSION=1536
MOCK_EMBEDDING_LATENCY=0
MOCK_EMBEDDING_SHOULD_FAIL=false
```

## Usage

### Running Tests with Test Profile

```bash
# Run tests with mandatory profile
npm run test:profile

# Run tests with profile and validate coverage
npm run test:profile:validate

# CI/CD usage
npm run test:ci  # Uses test profile by default
```

### Manual Test Profile Setup

```typescript
import { setupTestProfile, validateTestProfile } from './tests/setup/test-profile-setup';

// Setup test profile
const config = setupTestProfile();

// Validate configuration
const validation = validateTestProfile();
if (!validation.valid) {
  console.error('Test profile validation failed:', validation.errors);
  process.exit(1);
}
```

## CI/CD Integration

### GitHub Actions

The test profile is automatically used in CI/CD environments:

1. **Feature Branches**: Runs `test:profile:validate`
2. **Pull Requests**: Runs full test suite with coverage
3. **Main Branch**: Runs comprehensive tests including performance

### Requirements for PR Validation

All PRs must pass:
- ✅ Lint checks (`npm run lint`)
- ✅ Type checks (`npm run type-check`)
- ✅ Unit tests with profile (`npm run test:profile`)
- ✅ Coverage validation (`npm run verify-test-coverage`)

## Test Profile Features

### Deterministic Behavior

- **Embedding Generation**: Same input always produces same vector
- **Semantic Analysis**: Consistent boundary detection
- **Test Data**: Predictable test scenarios

### Isolation

- **Database**: Separate test collection
- **Environment**: Isolated environment variables
- **Services**: Mocked external dependencies

### Performance

- **Fast Execution**: No network calls to external services
- **Parallel Testing**: Configurable test parallelism
- **Resource Efficient**: Minimal memory and CPU usage

## Configuration Options

### Mock Embedding Service

```json
{
  "mockServices": {
    "embedding": {
      "enabled": true,
      "deterministic": true,
      "dimension": 1536,
      "latency": 0,
      "shouldFail": false,
      "cacheEnabled": false
    }
  }
}
```

### Testing Parameters

```json
{
  "testing": {
    "timeout": 30000,
    "retries": 3,
    "parallel": true,
    "isolation": true,
    "coverage": true,
    "dryRun": false
  }
}
```

## Troubleshooting

### Common Issues

1. **Test Failures Due to External Dependencies**
   - Ensure `MOCK_EXTERNAL_SERVICES=true`
   - Check `SEMANTIC_CHUNKING_OPTIONAL=true`

2. **Database Connection Issues**
   - Verify Qdrant is running on `http://localhost:6333`
   - Check collection name: `cortex-test`

3. **Timeout Issues**
   - Increase `TEST_TIMEOUT` environment variable
   - Check `TEST_MAX_WORKERS` setting

### Debug Mode

Enable debug logging:

```bash
LOG_LEVEL=debug npm run test:profile
```

### Validation Errors

Run profile validation:

```bash
node -e "
import { validateTestProfile } from './tests/setup/test-profile-setup.js';
const result = validateTestProfile();
console.log('Valid:', result.valid);
if (!result.valid) console.log('Errors:', result.errors);
"
```

## Best Practices

### For Developers

1. **Always use test profile** for unit and integration tests
2. **Mock external dependencies** to ensure reliable tests
3. **Validate test profile** before committing
4. **Use deterministic test data** for consistent results

### For CI/CD

1. **Fail fast** on test profile validation errors
2. **Run tests in parallel** when possible
3. **Generate coverage reports** for all test runs
4. **Use test profile** for all automated testing

## Maintenance

### Updating Mock Services

When updating the main application:
1. Update corresponding mock services
2. Test with both real and mocked services
3. Update test profile configuration if needed
4. Validate all tests pass

### Adding New Tests

1. Import test profile setup in test files
2. Use mocked services for external dependencies
3. Ensure tests work with both mock and real services
4. Add appropriate test coverage

## Security Considerations

- **No API Keys**: Test profile doesn't require real API keys
- **Isolated Data**: Test data doesn't affect production
- **Local Testing**: All services run locally
- **Secure Defaults**: Secure defaults for all settings