# Error Handling Guide for Cortex MCP

This guide provides comprehensive documentation for the standardized error handling framework implemented across the Cortex MCP codebase.

## Overview

The unified error handling framework provides:
- **Consistent error classification** with standardized codes and categories
- **Uniform error responses** across all service layers
- **Graceful degradation** and recovery mechanisms
- **Comprehensive logging** with structured context
- **Circuit breaker patterns** for resilience

## Framework Architecture

### Core Components

1. **Base Error Classes** (`src/utils/error-handler.ts`)
   - `BaseError` - Abstract base class for all errors
   - Specialized error classes for different categories
   - Standard error codes and severity levels

2. **Middleware Layer** (`src/middleware/error-middleware.ts`)
   - `ApiErrorHandler` - For MCP tool responses
   - `ServiceErrorHandler` - For service layer operations
   - `DatabaseErrorHandler` - For database operations
   - `AsyncErrorHandler` - For async operations with retry logic
   - `ErrorRecovery` - Graceful degradation and circuit breakers

3. **Error Categories**

| Category | Description | Example Codes |
|----------|-------------|---------------|
| `VALIDATION` | Input validation failures | E1001-E1099 |
| `AUTHENTICATION` | User authentication failures | E1100-E1199 |
| `AUTHORIZATION` | Permission/access failures | E1200-E1299 |
| `DATABASE` | Database operation failures | E1300-E1399 |
| `NETWORK` | Network connectivity issues | E1400-E1499 |
| `EXTERNAL_API` | Third-party service failures | E1500-E1599 |
| `BUSINESS_LOGIC` | Business rule violations | E1600-E1699 |
| `SYSTEM` | System-level failures | E1700-E1799 |
| `CONFIGURATION` | Configuration errors | E1800-E1899 |
| `RATE_LIMIT` | Rate limiting issues | E1900-E1999 |

## Usage Patterns

### 1. API Layer (MCP Tools)

```typescript
// Handle tool calls with standardized error responses
this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    return await this.handleToolCall(name, args);
  } catch (error) {
    // Returns user-friendly error response
    return ApiErrorHandler.handleToolCall(error, name, args);
  }
});

// Validate arguments with structured errors
ApiErrorHandler.validateArguments(args, {
  content: { type: 'string', required: true },
  kind: { type: 'string', required: true }
});
```

### 2. Service Layer

```typescript
// Wrap service methods with consistent error handling
async validateUser(username: string, password: string): Promise<User | null> {
  return ServiceErrorHandler.wrapServiceMethod(
    'validateUser',
    async () => {
      // Your business logic here
      if (!username || !password) {
        throw new ValidationError(
          'Username and password are required',
          'Please provide both username and password'
        );
      }

      // Database operations with retry logic
      const user = await AsyncErrorHandler.retry(
        () => database.findUser(username),
        { maxAttempts: 3, context: { operation: 'findUser' } }
      );

      return user;
    },
    {
      category: ErrorCategory.AUTHENTICATION,
      fallback: () => null
    }
  );
}
```

### 3. Database Layer

```typescript
// Database operations with standardized error handling
async findById(id: string): Promise<User | null> {
  return ServiceErrorHandler.wrapServiceMethod(
    'findById',
    async () => {
      try {
        return await this.database.user.findUnique({ where: { id } });
      } catch (error) {
        DatabaseErrorHandler.handleQueryError(error, 'SELECT', { id });
      }
    },
    { fallback: () => null }
  );
}

// Connection handling with graceful degradation
async initialize(): Promise<void> {
  await ErrorRecovery.gracefulDegradation(
    // Primary connection
    () => this.database.connect(),
    // Fallback options
    [
      () => this.database.connectWithTimeout(10000),
      () => this.database.connectToReplica()
    ],
    { operation: 'database_connect' }
  );
}
```

### 4. External API Calls

```typescript
// External API calls with retry and proper error categorization
async generateEmbedding(text: string): Promise<number[]> {
  try {
    return await AsyncErrorHandler.retry(
      () => this.openai.embeddings.create({ input: text }),
      { maxAttempts: 3, context: { textLength: text.length } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (message.includes('invalid api key')) {
      throw new ConfigurationError('Invalid API key', 'Check your API key');
    } else if (message.includes('rate limit')) {
      throw new ExternalApiError('Rate limit exceeded', 'Try again later');
    } else if (message.includes('network')) {
      throw new NetworkError('Network error', 'Check connection');
    } else {
      throw new ExternalApiError('API error', 'Service unavailable');
    }
  }
}
```

## Error Classes

### Creating Custom Errors

```typescript
// Extend BaseError for custom error types
export class CustomBusinessError extends BaseError {
  constructor(message: string, userMessage: string = 'Business rule violation', context?: Record<string, any>) {
    super({
      code: ErrorCode.BUSINESS_RULE_VIOLATION,
      category: ErrorCategory.BUSINESS_LOGIC,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage,
      context,
      retryable: false
    });
  }
}

// Use in your code
if (!isValidTransition(currentStatus, newStatus)) {
  throw new CustomBusinessError(
    `Invalid status transition: ${currentStatus} -> ${newStatus}`,
    'This status change is not allowed',
    { currentStatus, newStatus, workflow: 'issue_management' }
  );
}
```

### Error Severity Levels

- **LOW**: Informational issues that don't affect functionality
- **MEDIUM**: Issues that affect some functionality but have workarounds
- **HIGH**: Critical issues that significantly impact functionality
- **CRITICAL**: System-level failures that require immediate attention

## Advanced Patterns

### Circuit Breaker Implementation

```typescript
const circuitBreaker = ErrorRecovery.createCircuitBreaker(
  () => externalApiCall(),
  {
    failureThreshold: 5,      // Open after 5 failures
    recoveryTimeout: 60000,    // Try recovery after 1 minute
    monitoringPeriod: 10000    // Monitor for 10 seconds
  }
);

// Use in production
try {
  const result = await circuitBreaker.execute();
  return result;
} catch (error) {
  // Circuit breaker is open or operation failed
  throw error;
}
```

### Async Error Handling

```typescript
// Safe async wrapper that never throws
const result = await AsyncErrorHandler.safe(
  () => riskyOperation(),
  defaultValue  // Fallback value
);

if (result.success) {
  console.log('Operation succeeded:', result.data);
} else {
  console.error('Operation failed:', result.error.userMessage);
  // Use result.data (defaultValue) if provided
}
```

### Global Error Boundary

```typescript
// Check if service should be temporarily disabled
if (globalErrorBoundary.shouldTrip()) {
  throw new Error('Service temporarily unavailable due to high error rate');
}

// Record successful operation
globalErrorBoundary.reset();

// Record errors
globalErrorBoundary.recordError(error);

// Get statistics
const stats = globalErrorBoundary.getStats();
console.log('Error statistics:', stats);
```

## Error Response Format

All errors follow this standardized response format:

```typescript
interface StandardErrorResponse {
  error: {
    code: ErrorCode;           // e.g., 'E1101'
    category: ErrorCategory;  // e.g., 'authentication'
    severity: ErrorSeverity;  // e.g., 'high'
    message: string;          // User-friendly message
    technical_details?: string;  // Technical details
    timestamp: string;        // ISO timestamp
    retryable: boolean;       // Can be retried
    context?: Record<string, any>;  // Additional context
  };
}
```

## Logging and Monitoring

### Structured Logging

All errors are logged with structured context:

```typescript
// Automatic logging when throwing errors
const error = new ValidationError('Invalid input', 'Please check your input', {
  field: 'email',
  value: userInput,
  operation: 'user_registration'
});

error.log();  // Automatically logs with appropriate level
```

### Error Context

Always include relevant context when creating errors:

- **Operation**: What was being attempted
- **Input values**: Relevant input parameters (sanitized)
- **User context**: User ID, session info (if available)
- **System state**: Relevant system information
- **Timestamp**: When the error occurred

## Best Practices

### 1. Error Categories
- Choose the most specific category for your error
- Use business logic errors for domain-specific validations
- Use system errors for infrastructure issues

### 2. User Messages
- Always provide user-friendly messages
- Avoid technical jargon in user messages
- Include actionable guidance when possible

### 3. Context Information
- Include relevant but non-sensitive context
- Never log passwords, tokens, or PII
- Use consistent context structure

### 4. Retry Logic
- Mark retryable errors appropriately
- Use exponential backoff for retries
- Implement circuit breakers for external services

### 5. Graceful Degradation
- Always provide fallback options
- Implement feature flags for critical functionality
- Return simplified responses when services are degraded

## Migration Guide

### Converting Existing Error Handling

1. **Replace generic Error throws**:
   ```typescript
   // Before
   throw new Error('User not found');

   // After
   throw new DatabaseError('User not found', { userId: id });
   ```

2. **Wrap service methods**:
   ```typescript
   // Before
   async getUser(id: string): Promise<User> {
     try {
       return await database.findUser(id);
     } catch (error) {
       console.error('Database error:', error);
       throw error;
     }
   }

   // After
   async getUser(id: string): Promise<User> {
     return ServiceErrorHandler.wrapServiceMethod(
       'getUser',
       () => database.findUser(id),
       { category: ErrorCategory.DATABASE }
     );
   }
   ```

3. **Update API responses**:
   ```typescript
   // Before
   try {
     return await operation();
   } catch (error) {
     return { error: error.message };
   }

   // After
   try {
     return await operation();
   } catch (error) {
     return ApiErrorHandler.handleToolCall(error, toolName, args);
   }
   ```

## Troubleshooting

### Common Issues

1. **Import errors**: Ensure correct import paths for error classes
2. **Type conflicts**: Use proper TypeScript types for error handling
3. **Circular dependencies**: Import error classes, not middleware, from utilities
4. **Missing context**: Always provide meaningful context information

### Debugging

- Enable debug logging to see error details
- Check error boundaries for circuit breaker status
- Monitor error statistics for patterns
- Use structured logs for troubleshooting

This error handling framework provides a robust foundation for building resilient applications with consistent error management across all layers.