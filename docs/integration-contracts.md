# Integration Contracts and Versioning System

This document describes the comprehensive integration contracts and versioning system implemented for the Cortex MCP tools.

## Overview

The integration contracts system provides:

- **Semantic Versioning (SemVer)** for all MCP tools
- **X-Version header support** for client version negotiation
- **Backward compatibility guarantees** across tool versions
- **Enhanced security and quota enforcement** with tenant isolation
- **Comprehensive contract testing** and CI schema drift detection
- **Production-ready middleware** for request validation and security

## Architecture

### Core Components

1. **Versioning Schema** (`src/types/versioning-schema.ts`)
   - SemVer parsing and validation
   - Version compatibility checking
   - Tool contract definitions
   - X-version header support

2. **Enhanced Security Middleware** (`src/middleware/enhanced-security-middleware.ts`)
   - Input validation and sanitization
   - Quota enforcement with multiple dimensions
   - Tenant isolation with multi-level scope validation
   - Rate limiting and security headers

3. **Contract Testing** (`tests/integration/`)
   - Backward compatibility tests
   - MCP tool contract tests
   - Tenant isolation tests

4. **CI Schema Drift Detection** (`scripts/schema-drift-detection.mjs`)
   - Automated detection of breaking changes
   - Schema comparison and validation
   - CI integration with detailed reporting

## Tool Contracts

### Memory Store Tool

**Current Version:** 1.2.0

**Available Versions:**

- 1.0.0 - Basic storage functionality
- 1.1.0 - Added deduplication options
- 1.2.0 - Added processing options and breaking changes

**Rate Limits:**

- 60 requests/minute
- 10,000 tokens/minute
- 10 burst requests
- 5MB max content size
- 100 items per request

**Required Scopes:**

- `memory:write`

**Breaking Changes in 1.2.0:**

- Added required idempotency_key field
- Enhanced processing options

### Memory Find Tool

**Current Version:** 1.3.0

**Available Versions:**

- 1.0.0 - Basic search functionality
- 1.3.0 - Advanced search with graph expansion

**Rate Limits:**

- 120 requests/minute
- 20,000 tokens/minute
- 20 burst requests
- 100KB max content size
- 1 item per request

**Required Scopes:**

- `memory:read`

### System Status Tool

**Current Version:** 1.0.0

**Rate Limits:**

- 30 requests/minute
- 5,000 tokens/minute
- 5 burst requests

**Required Scopes:**

- `system:read`

**Special Notes:**

- No tenant isolation (cross-tenant tool)
- Lower rate limits for system operations

## Version Negotiation

### X-Version Headers

Clients can specify their preferred version using HTTP headers:

```http
x-version: 1.0.0          # Preferred version
x-api-version: 1.1.0      # API version
x-client-version: 1.2.0   # Client version
```

**Priority Order:**

1. `x-version`
2. `x-api-version`
3. Default current version

### Version Resolution

The system uses the following logic to resolve tool versions:

1. **Exact Match:** If requested version exists, use it
2. **Compatible Version:** Find most recent compatible version
3. **Fallback:** Use current version with warning

```typescript
import { resolveToolVersion } from './src/types/versioning-schema.js';

const headers = { 'x-version': '1.0.0' };
const result = resolveToolVersion('memory_store', headers);
// Returns: { version: '1.0.0', warnings: [] }
```

### Backward Compatibility

All new versions maintain backward compatibility with previous minor versions:

- **Patch versions:** Bug fixes only, fully compatible
- **Minor versions:** New features, backward compatible
- **Major versions:** Breaking changes, require client updates

## Security and Quotas

### Input Validation

The system enforces comprehensive input validation:

```typescript
interface InputValidationConfig {
  max_content_length: number; // Max request size
  max_items_per_request: number; // Max items in batch
  allowed_content_types: string[]; // Permitted content types
  sanitize_html: boolean; // XSS protection
  sanitize_sql: boolean; // SQL injection protection
  prevent_code_injection: boolean; // Code injection protection
}
```

### Quota Enforcement

Multi-dimensional quota enforcement:

```typescript
interface SecurityQuota {
  requests_per_minute: number;
  requests_per_hour: number;
  requests_per_day: number;
  tokens_per_minute: number;
  tokens_per_hour: number;
  max_content_length: number;
  max_items_per_request: number;
  burst_requests: number;
  burst_tokens: number;
}
```

### Tenant Isolation

Comprehensive tenant isolation with multiple enforcement levels:

```typescript
interface TenantIsolationConfig {
  enabled: boolean;
  strict_mode: boolean; // Fail closed if tenant ID missing
  cross_tenant_access: string[]; // Tools that can access cross-tenant data
  tenant_id_sources: ('auth' | 'header' | 'query')[];
  default_tenant: string | null;
}
```

**Tenant ID Sources:**

1. **Auth Context:** User's organization ID
2. **Headers:** `x-tenant-id` header
3. **Query:** `tenant_id` parameter
4. **Default:** Configured default tenant

## Implementation Guide

### Setting Up Versioning

1. **Define tool contracts:**

```typescript
export const BUILTIN_TOOL_CONTRACTS: ToolVersionRegistry = {
  your_tool: {
    current_version: '1.0.0',
    available_versions: ['1.0.0'],
    contracts: {
      '1.0.0': {
        name: 'your_tool',
        version: { major: 1, minor: 0, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.0.x',
        },
        input_schema: YourInputSchema,
        output_schema: YourOutputSchema,
        required_scopes: ['your:scope'],
        rate_limits: {
          requests_per_minute: 60,
          tokens_per_minute: 10000,
        },
        input_validation: {
          max_content_length: 1000000,
          max_items_per_request: 100,
        },
        tenant_isolation: true,
      },
    },
  },
};
```

2. **Add security middleware:**

```typescript
import {
  createEnhancedSecurityMiddleware,
  DEFAULT_SECURITY_CONFIG,
} from './middleware/enhanced-security-middleware.js';

const securityMiddleware = createEnhancedSecurityMiddleware({
  ...DEFAULT_SECURITY_CONFIG,
  tool_overrides: {
    your_tool: {
      quotas: {
        requests_per_minute: 120,
        tokens_per_minute: 20000,
      },
    },
  },
});

app.use('/api/your_tool', securityMiddleware.createMiddleware('your_tool'));
```

3. **Implement version resolution:**

```typescript
import { validateInputForVersion, resolveToolVersion } from './types/versioning-schema.js';

export async function handleYourToolRequest(req, res) {
  const headers = req.headers;
  const { version, warnings } = resolveToolVersion('your_tool', headers);

  // Log warnings
  if (warnings.length > 0) {
    logger.warn({ warnings }, 'Version resolution warnings');
  }

  // Validate input
  const validation = validateInputForVersion('your_tool', version, req.body);
  if (!validation.isValid) {
    return res.status(400).json({
      error: 'Invalid input',
      details: validation.error,
    });
  }

  // Process request with validated input
  const result = await processYourTool(validation.validatedInput, version);
  res.json(result);
}
```

### Adding New Tool Versions

1. **Update version in contracts:**

```typescript
export const BUILTIN_TOOL_CONTRACTS: ToolVersionRegistry = {
  your_tool: {
    current_version: '1.1.0', // Update current version
    available_versions: ['1.0.0', '1.1.0'], // Add new version
    contracts: {
      '1.1.0': {
        // New version contract
        compatibility: {
          min_version: '1.0.0', // Backward compatible
          max_version: '1.1.x',
        },
        // ... other contract details
      },
      // ... existing versions
    },
  },
};
```

2. **Add breaking change documentation if needed:**

```typescript
compatibility: {
  min_version: '1.1.0',
  max_version: '1.1.x',
  breaking_changes: [
    {
      version: '1.1.0',
      description: 'Added required field X',
      migration_required: true,
      migration_guide: 'Add field X to all requests',
    },
  ],
},
```

3. **Run schema drift detection:**

```bash
node scripts/schema-drift-detection.mjs
```

## Testing

### Running Tests

```bash
# All contract tests
npm test -- tests/integration/

# Specific test suites
npm test -- tests/integration/backward-compatibility.test.ts
npm test -- tests/integration/mcp-tool-contracts.test.ts
npm test -- tests/integration/tenant-isolation.test.ts
```

### Schema Drift Detection

```bash
# Run locally
node scripts/schema-drift-detection.mjs

# Or via npm script
npm run schema:check
```

The script generates:

- **Console output** with immediate feedback
- **Markdown report** (`schema-drift-report.md`)
- **Baseline schema** (`.schema-baseline.json`) for next comparison

## CI/CD Integration

The system includes comprehensive GitHub Actions workflows:

### Workflow: `.github/workflows/schema-validation.yml`

**Triggers:**

- Push to main/develop branches
- Pull requests

**Jobs:**

1. **schema-validation** - Type checking, drift detection, contract tests
2. **integration-tests** - Full integration test suite
3. **security-scan** - Security audit and code analysis
4. **quality-gate** - Final quality check and reporting

**Artifacts:**

- Schema drift report
- Quality gate report
- Test results

### Quality Gates

The CI pipeline enforces strict quality gates:

- ✅ Schema validation must pass
- ✅ All contract tests must pass
- ✅ No breaking changes without version bump
- ✅ Security audit must pass
- ✅ Integration tests must pass

## Migration Guide

### Upgrading Tool Versions

1. **Check compatibility:**

```typescript
import { isVersionCompatible } from './types/versioning-schema.js';

if (isVersionCompatible('1.0.0', '1.1.0')) {
  // Client can use new version
}
```

2. **Handle deprecation warnings:**

```typescript
const { version, warnings } = resolveToolVersion('memory_store', headers);

if (warnings.some((w) => w.includes('deprecated'))) {
  // Plan migration to newer version
}
```

3. **Update client code for breaking changes:**

```typescript
// Before v1.2.0
const request = { items: [{ kind: 'entity', content: 'test' }] };

// After v1.2.0 (breaking change)
const request = {
  items: [{ kind: 'entity', content: 'test', idempotency_key: 'unique-key' }],
  processing: { enable_validation: true },
};
```

### Handling Schema Drift

If schema drift is detected:

1. **Review the drift report** for breaking changes
2. **Update version numbers** according to SemVer rules
3. **Add migration guides** for breaking changes
4. **Update baseline** after successful deployment
5. **Communicate changes** to API consumers

## Best Practices

### Version Management

- Use semantic versioning consistently
- Document all breaking changes
- Provide migration guides for major versions
- Maintain backward compatibility when possible

### Security

- Enable tenant isolation for data tools
- Use strict validation for all inputs
- Monitor quota usage and adjust as needed
- Log security events for audit trails

### Testing

- Test all version combinations
- Include edge cases in contract tests
- Run schema drift detection in CI
- Monitor test coverage

### Performance

- Validate input size limits
- Monitor quota enforcement overhead
- Optimize tenant isolation lookups
- Cache validation results when appropriate

## Troubleshooting

### Common Issues

1. **Version Resolution Fails**
   - Check x-version header format
   - Verify version exists in contracts
   - Review compatibility matrix

2. **Schema Validation Errors**
   - Check input against version schema
   - Verify required fields are present
   - Review field types and constraints

3. **Tenant Isolation Failures**
   - Verify tenant ID sources are configured
   - Check auth context organization ID
   - Review cross-tenant access rules

4. **Quota Enforcement Issues**
   - Check rate limit configurations
   - Verify quota identifier resolution
   - Review burst allowance settings

### Debug Information

Enable debug logging:

```typescript
import { logger } from './utils/logger.js';

logger.level = 'debug';
```

This will provide detailed information about:

- Version resolution process
- Input validation results
- Tenant isolation decisions
- Quota enforcement actions

## Contributing

When contributing to the integration contracts system:

1. **Update contracts** for any schema changes
2. **Add tests** for new functionality
3. **Run schema drift detection** locally
4. **Update documentation** for new features
5. **Follow SemVer rules** for version changes
6. **Add migration guides** for breaking changes

## Support

For questions or issues with the integration contracts system:

1. Check this documentation
2. Review generated schema drift reports
3. Examine test failures for detailed error information
4. Enable debug logging for troubleshooting
5. Create GitHub issues with detailed reproduction steps
