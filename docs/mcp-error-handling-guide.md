# MCP Error Handling Framework Guide

## Overview

The MCP Error Handling Framework provides comprehensive error handling, response building, correlation tracking, and metrics collection for MCP tool execution. It extends the existing error infrastructure while maintaining compatibility with current `@ts-nocheck` files.

## Key Components

### 1. MCP Error Types (`src/types/mcp-error-types.ts`)

- **McpBaseError**: Base class for all MCP-specific errors
- **McpToolError**: Tool execution failures
- **McpArgumentError**: Argument validation errors
- **McpToolTimeoutError**: Tool timeout errors
- **McpResourceError**: Resource limit errors
- **McpProtocolError**: MCP protocol violations

### 2. Response Builders (`src/utils/mcp-response-builders.ts`)

- **McpResponseBuilder**: Creates standardized success/error responses
- **Correlation ID tracking**: Automatic generation and lifecycle management
- **Argument sanitization**: Data cleaning and size limits
- **Performance tracking**: Built-in timing and metrics

### 3. Enhanced Entry Point (`src/entry-point-factory.ts`)

- **Correlation management**: Automatic ID generation and tracking
- **Tool execution wrapping**: Built-in timeout and error handling
- **Error statistics**: Real-time error counting and threshold monitoring
- **Graceful shutdown**: Cleanup of error handling resources

### 4. Error Metrics (`src/monitoring/mcp-error-metrics.ts`)

- **Real-time monitoring**: Live error tracking and alerting
- **Trend analysis**: Error pattern detection and prediction
- **Cascade detection**: Identifies related error sequences
- **Performance impact**: Response time degradation analysis

### 5. Integration Layer (`src/utils/mcp-error-handler-integration.ts`)

- **Unified interface**: Single entry point for all error handling
- **Convenience functions**: Simplified common patterns
- **Tool wrappers**: Easy tool function decoration
- **Health monitoring**: System-wide error health assessment

## Quick Start

### Basic Tool Implementation

```typescript
import { createMcpToolWrapper, validateMcpArguments } from '@/utils/mcp-error-handler-integration.js';

// Define argument schema
const argumentSchema = {
  query: {
    type: 'string',
    required: true,
    minLength: 1,
    maxLength: 1000
  },
  limit: {
    type: 'number',
    required: false,
    min: 1,
    max: 100
  }
};

// Create tool implementation
async function searchMemory(args: any, context: McpToolContext) {
  // Arguments are already validated by the wrapper
  const { query, limit = 10 } = args;

  // Your tool logic here
  const results = await performSearch(query, limit);

  return {
    results,
    query,
    totalFound: results.length,
    correlationId: context.correlationId
  };
}

// Create wrapped tool function
export const memorySearchTool = createMcpToolWrapper(
  'memory_search',
  searchMemory,
  {
    schema: argumentSchema,
    timeout: 30000
  }
);
```

### Advanced Error Handling

```typescript
import { McpErrorFactory, defaultResponseBuilder } from '@/utils/mcp-error-handler-integration.js';

async function complexOperation(args: any) {
  const correlationId = defaultResponseBuilder.generateCorrelationId();

  try {
    // Custom validation
    if (!args.userId) {
      throw McpErrorFactory.createValidationError(
        'complex_operation',
        'userId',
        'User ID is required for this operation',
        { correlationId }
      );
    }

    // Perform operation with timeout
    const result = await executeWithTimeout(
      () => performComplexOperation(args),
      45000,
      'complex_operation',
      correlationId
    );

    // Build success response
    return defaultResponseBuilder.buildSuccessResponse(
      result,
      {
        toolName: 'complex_operation',
        correlationId,
        executionId: generateExecutionId()
      },
      {
        metadata: {
          userId: args.userId,
          operationComplexity: 'high'
        },
        suggestions: [
          'Cache this result for faster access',
          'Consider using batch processing for multiple items'
        ]
      }
    );

  } catch (error) {
    // Build error response
    const errorResponse = defaultResponseBuilder.buildErrorResponse(
      error,
      {
        toolName: 'complex_operation',
        correlationId,
        executionId: generateExecutionId()
      }
    );

    throw errorResponse;
  }
}
```

### Using the Integration Layer

```typescript
import {
  executeMcpTool,
  getMcpErrorHealth,
  defaultMcpErrorHandler
} from '@/utils/mcp-error-handler-integration.js';

// Execute a tool with full error handling
const result = await executeMcpTool(
  'data_processing',
  async () => {
    const data = await fetchData();
    return processData(data);
  },
  {
    timeout: 60000,
    userId: 'user123',
    onSuccess: (data) => [{
      type: 'text',
      text: `Processed ${data.count} items successfully`
    }],
    onError: (error) => [{
      type: 'text',
      text: `Processing failed: ${error.userMessage}`
    }]
  }
);

// Check system health
const health = getMcpErrorHealth();
if (health.overallHealth === 'critical') {
  console.error('System health is critical:', health.recommendations);
}
```

## Error Handling Patterns

### 1. Validation Errors

```typescript
// Automatic validation with schema
const schema = {
  email: {
    type: 'string',
    required: true,
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  }
};

// Manual validation
if (!isValidEmail(args.email)) {
  throw McpErrorFactory.createValidationError(
    'user_tool',
    'email',
    'Invalid email format',
    {
      correlationId,
      receivedValue: args.email,
      expectedType: 'valid email address'
    }
  );
}
```

### 2. Timeout Handling

```typescript
// Built-in timeout in executeMcpTool
const result = await executeMcpTool(
  'slow_operation',
  () => performSlowOperation(),
  { timeout: 120000 } // 2 minutes
);

// Manual timeout handling
try {
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => {
      reject(new McpToolTimeoutError('slow_operation', 120000));
    }, 120000);
  });

  const result = await Promise.race([
    performSlowOperation(),
    timeoutPromise
  ]);
} catch (error) {
  if (error instanceof McpToolTimeoutError) {
    // Handle timeout
  }
}
```

### 3. Resource Limit Errors

```typescript
if (isQuotaExceeded(userId)) {
  throw McpErrorFactory.createResourceError(
    'api_quota',
    'User quota exceeded',
    {
      correlationId,
      retryable: true
    }
  );
}
```

## Monitoring and Metrics

### Real-time Monitoring

```typescript
import { mcpErrorMetrics } from '@/monitoring/mcp-error-metrics.js';

// Listen to error events
mcpErrorMetrics.on('error:recorded', (data) => {
  console.log(`Error recorded: ${data.toolName} - ${data.error.message}`);
});

mcpErrorMetrics.on('cascade:detected', (cascade) => {
  console.error(`Error cascade detected: ${cascade.cascadeId}`);
});

mcpErrorMetrics.on('alert:created', (alert) => {
  console.warn(`Alert created: ${alert.message}`);
});
```

### Getting Statistics

```typescript
// Overall statistics
const stats = mcpErrorMetrics.getErrorStatistics();
console.log(`Total errors: ${stats.totalErrors}`);
console.log(`Error rate: ${stats.averageErrorRate}`);

// Tool-specific metrics
const toolMetrics = mcpErrorMetrics.getToolMetrics('memory_search');
if (toolMetrics) {
  console.log(`Tool error rate: ${toolMetrics.errorRate}`);
  console.log(`Consecutive errors: ${toolMetrics.consecutiveErrors}`);
}

// Trend analysis
const trends = mcpErrorMetrics.getErrorTrendAnalysis('memory_search');
console.log(`Trend: ${trends.overallTrend}`);
console.log(`Recommendations:`, trends.recommendations);
```

### Performance Impact Analysis

```typescript
const impact = mcpErrorMetrics.getPerformanceImpact('slow_tool');
if (impact) {
  console.log(`Response time degradation: ${impact.responseTimeDegradation}x`);
  console.log(`Throughput impact: ${impact.throughputImpact * 100}%`);
  console.log(`SLA compliance: ${impact.businessImpact.slaCompliance}%`);
}
```

## Migration Guide

### From Existing Error Handling

**Before:**
```typescript
async function toolHandler(args: any) {
  try {
    const result = await performOperation(args);
    return {
      content: [{ type: 'text', text: JSON.stringify(result) }]
    };
  } catch (error) {
    console.error('Tool failed:', error);
    return {
      content: [{ type: 'text', text: 'Operation failed' }]
    };
  }
}
```

**After:**
```typescript
import { createMcpToolWrapper } from '@/utils/mcp-error-handler-integration.js';

const toolHandler = createMcpToolWrapper(
  'tool_name',
  async (args, context) => {
    const result = await performOperation(args);
    return result; // Automatically wrapped in proper response
  },
  {
    schema: argumentSchema,
    timeout: 30000
  }
);
```

### Adding to Existing Tools

1. **Import the integration:**
```typescript
import { executeMcpTool } from '@/utils/mcp-error-handler-integration.js';
```

2. **Wrap your tool logic:**
```typescript
const result = await executeMcpTool('tool_name', () => {
  // Existing tool logic
});
```

3. **Update error handling:**
```typescript
// Replace existing error handling
catch (error) {
  // Remove manual error handling - the framework handles it
  throw error; // Let the framework convert and track
}
```

## Configuration

### Environment Variables

```bash
# Enable/disable real-time alerting
MCP_ERROR_ALERTING=true

# Set default timeout (ms)
MCP_DEFAULT_TIMEOUT=30000

# Configure metrics retention (ms)
MCP_METRICS_RETENTION=86400000  # 24 hours
```

### Custom Configuration

```typescript
import { McpErrorHandlerIntegration } from '@/utils/mcp-error-handler-integration.js';

const customHandler = new McpErrorHandlerIntegration({
  enableMetrics: true,
  enableRealTimeAlerting: true,
  defaultTimeout: 60000,
  customResponseBuilder: new McpResponseBuilder({
    maxResponseSize: 2 * 1024 * 1024, // 2MB
    enablePerformanceTracking: true
  })
});
```

## Best Practices

### 1. Always Use Correlation IDs

```typescript
// Good: Automatic correlation ID handling
const result = await executeMcpTool('tool_name', operation);

// Bad: Manual correlation ID management
const correlationId = generateId(); // Don't do this manually
```

### 2. Define Clear Argument Schemas

```typescript
const schema = {
  // Always define required fields
  userId: { type: 'string', required: true },

  // Use validation patterns
  email: {
    type: 'string',
    required: true,
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },

  // Set reasonable limits
  query: {
    type: 'string',
    required: true,
    minLength: 1,
    maxLength: 1000
  }
};
```

### 3. Handle Timeouts Gracefully

```typescript
// Set appropriate timeouts for your operations
const result = await executeMcpTool(
  'quick_operation', // 10s timeout
  quickOperation,
  { timeout: 10000 }
);

const result = await executeMcpTool(
  'slow_operation', // 2 minute timeout
  slowOperation,
  { timeout: 120000 }
);
```

### 4. Monitor Error Trends

```typescript
// Regularly check error health
setInterval(() => {
  const health = getMcpErrorHealth();
  if (health.overallHealth !== 'healthy') {
    console.error('System health degraded:', health.recommendations);
  }
}, 60000); // Check every minute
```

### 5. Use Specific Error Types

```typescript
// Instead of generic errors
throw new Error('Something went wrong');

// Use specific MCP errors
throw McpErrorFactory.createValidationError(
  'tool_name',
  'field_name',
  'Specific validation message'
);
```

## Troubleshooting

### Common Issues

1. **Missing correlation IDs**: Ensure you're using the integration layer functions
2. **High error rates**: Check error trends and look for cascading failures
3. **Timeout issues**: Review timeout settings and operation performance
4. **Memory leaks**: Ensure proper cleanup of error handling resources

### Debug Mode

```typescript
// Enable debug logging
process.env.DEBUG_MODE = 'true';

// Check error statistics
console.log(getMcpErrorHealth());

// Monitor real-time events
mcpErrorMetrics.on('error:recorded', console.log);
```

## Migration Timeline

### Phase 1 (Current): Foundation
- ✅ MCP error types and hierarchy
- ✅ Response builders with correlation tracking
- ✅ Enhanced entry point factory
- ✅ Error metrics and monitoring

### Phase 2 (Future): Integration
- Migrate existing tool handlers
- Implement custom error types
- Add comprehensive testing
- Update documentation

### Phase 3 (Future): Optimization
- Performance optimizations
- Advanced alerting rules
- Machine learning for error prediction
- Custom dashboard integration

## Support and Contributing

For questions, issues, or contributions to the MCP Error Handling Framework:

1. Check this documentation first
2. Review the existing error types and patterns
3. Look at the integration examples
4. Create issues for bugs or feature requests
5. Follow the established patterns when adding new error types