# DI Container Migration Guide

## Overview

This guide explains how to migrate from the original DI container (with extensive `any` usage) to the new fully typed DI container with comprehensive type safety and runtime validation.

## Migration Benefits

1. **Complete Type Safety**: Eliminates all `any` usage throughout the DI system
2. **Runtime Validation**: Automatic type checking and validation at runtime
3. **Circular Dependency Detection**: Advanced algorithms to detect and prevent circular dependencies
4. **Enhanced Error Handling**: Detailed error messages with context and resolution paths
5. **Performance Monitoring**: Built-in metrics and performance tracking
6. **Better Developer Experience**: Improved IntelliSense and compile-time checking

## Migration Steps

### Step 1: Update Service Interfaces

Before migrating containers, ensure your service interfaces are properly typed:

```typescript
// Before (any usage)
export interface IConfigService {
  get(key: string): any;
  set(key: string, value: any): void;
}

// After (proper typing)
export interface IConfigService {
  get(key: string): unknown;
  get<T>(key: string, defaultValue: T): T;
  set(key: string, value: unknown): void;
  validate(key: string, validator: (value: unknown) => boolean): boolean;
}
```

### Step 2: Create Runtime Validators

Define validators for your services to enable runtime type checking:

```typescript
import { RuntimeValidator, InstanceValidator, RuntimeTypeChecker } from './runtime-validation';

// Example: Config service validator
const configServiceValidator: RuntimeValidator<IConfigService> = {
  validate(value: unknown): value is IConfigService {
    return value !== null &&
           typeof value === 'object' &&
           'get' in value &&
           'set' in value &&
           typeof (value as any).get === 'function' &&
           typeof (value as any).set === 'function';
  },
  getExpectedType(): string {
    return 'IConfigService';
  },
  getErrorMessage(value: unknown): string {
    return `Expected IConfigService instance, got ${typeof value}`;
  }
};
```

### Step 3: Update Service Registration

Replace old registration patterns with new typed registrations:

```typescript
import { createTypedDIContainer, ServiceLifetime } from './typed-di-container';
import { createServiceId } from '../factories/factory-types';

// Before (original container)
const container = new DIContainer();
container.register('ConfigService', ConfigService, ServiceLifetime.SINGLETON);

// After (typed container)
const container = createTypedDIContainer({
  enableAutoValidation: true,
  enableRuntimeTypeChecking: true,
  enableMetrics: true
});

const CONFIG_SERVICE_ID = createServiceId<IConfigService>('ConfigService');

container.register(
  CONFIG_SERVICE_ID,
  ConfigService,
  ServiceLifetime.SINGLETON,
  [], // dependencies
  configServiceValidator, // runtime validator
  ['core', 'config'], // tags
  1 // priority
);
```

### Step 4: Update Service Resolution

Replace resolution patterns:

```typescript
// Before
const config = container.resolve<IConfigService>('ConfigService');

// After
const config = container.resolve(CONFIG_SERVICE_ID);
```

### Step 5: Handle Dependency Injection

Update constructor injection patterns:

```typescript
// Before
export class MyService {
  constructor(
    @Inject('ConfigService') private config: IConfigService,
    @Inject('LoggerService') private logger: ILoggerService
  ) {}
}

// After (with proper typing)
export class MyService {
  constructor(
    private config: IConfigService,
    private logger: ILoggerService
  ) {}
}

// Registration with dependencies
container.register(
  createServiceId<MyService>('MyService'),
  MyService,
  ServiceLifetime.SINGLETON,
  [CONFIG_SERVICE_ID, LOGGER_SERVICE_ID], // typed dependencies
  myServiceValidator
);
```

## Advanced Features

### Factory Registration

```typescript
container.registerFactory(
  createServiceId<IDatabaseService>('DatabaseService'),
  async (container) => {
    const config = container.resolve(CONFIG_SERVICE_ID);
    const dbConfig = config.getSection<DatabaseConfig>('database');

    const db = new DatabaseManager(dbConfig);
    await db.initialize();
    return new DatabaseServiceAdapter(db);
  },
  ServiceLifetime.SINGLETON,
  [CONFIG_SERVICE_ID],
  databaseServiceValidator
);
```

### Scoped Services

```typescript
// Create a scoped container for request-level services
const scopedContainer = container.createScope('request-123');

// Register scoped service
scopedContainer.register(
  createServiceId<IRequestContext>('RequestContext'),
  RequestContext,
  ServiceLifetime.SCOPED,
  [],
  requestContextValidator
);

// Resolve within scope
const requestContext = scopedContainer.resolve(REQUEST_CONTEXT_ID);
```

### Runtime Validation

```typescript
// Enable comprehensive runtime validation
const container = createTypedDIContainer({
  enableAutoValidation: true,
  enableRuntimeTypeChecking: true,
  enableCircularDependencyDetection: true
});

// Custom validators
const strictValidator: RuntimeValidator<MyService> = {
  validate(value: unknown): value is MyService {
    const instance = value as MyService;
    return instance instanceof MyService &&
           typeof instance.process === 'function' &&
           typeof instance.validate === 'function';
  },
  getExpectedType(): string {
    return 'MyService';
  },
  getErrorMessage(value: unknown): string {
    return `Expected MyService instance with required methods, got ${typeof value}`;
  }
};

container.register(
  SERVICE_ID,
  MyService,
  ServiceLifetime.SINGLETON,
  [],
  strictValidator
);
```

### Monitoring and Metrics

```typescript
// Enable metrics collection
const container = createTypedDIContainer({ enableMetrics: true });

// Get container metrics
const metrics = container.getMetrics();
console.log('Container metrics:', metrics);
/*
{
  totalServices: 15,
  registeredServices: 15,
  resolvedServices: 8,
  failedResolutions: 0,
  averageResolutionTime: 2.5,
  memoryUsage: 2048,
  circularDependencies: 0,
  validationErrors: 0,
  cacheHitRate: 0.85
}
*/

// Listen to service lifecycle events
container.on('service:resolved', ({ serviceId, resolutionTime }) => {
  console.log(`Service ${serviceId} resolved in ${resolutionTime}ms`);
});

container.on('service:resolution-failed', ({ serviceId, error }) => {
  console.error(`Service ${serviceId} resolution failed:`, error);
});
```

## Validation and Diagnostics

### Dependency Graph Validation

```typescript
// Validate entire dependency graph
const validationResult = container.validateDependencyGraph();

if (!validationResult.valid) {
  console.error('Dependency graph issues:', validationResult.errors);
  validationResult.warnings?.forEach(warning => {
    console.warn('Warning:', warning);
  });
}

// Validate all service registrations
const serviceValidation = container.validateAllServices();
if (!serviceValidation.valid) {
  throw new Error(`Service validation failed: ${serviceValidation.errors.join(', ')}`);
}
```

### Circular Dependency Detection

The container automatically detects circular dependencies during resolution:

```typescript
// Example: A -> B -> C -> A
container.register(SERVICE_A, ServiceA, ServiceLifetime.SINGLETON, [SERVICE_B]);
container.register(SERVICE_B, ServiceB, ServiceLifetime.SINGLETON, [SERVICE_C]);
container.register(SERVICE_C, ServiceC, ServiceLifetime.SINGLETON, [SERVICE_A]);

// This will throw a detailed error:
// Error: Circular dependency detected: ServiceA -> ServiceB -> ServiceC -> ServiceA
container.resolve(SERVICE_A);
```

## Error Handling

### Enhanced Error Types

```typescript
import { ServiceRegistrationError, DependencyResolutionError, ServiceValidationError } from './typed-di-container';

try {
  const service = container.resolve(SERVICE_ID);
} catch (error) {
  if (error instanceof ServiceRegistrationError) {
    console.error(`Service registration failed for ${error.serviceId}:`, error.message);
  } else if (error instanceof DependencyResolutionError) {
    console.error(`Dependency resolution failed: ${error.message}`);
    console.error(`Resolution path: ${error.dependencyId} <- ${error.dependentService}`);
  } else if (error instanceof ServiceValidationError) {
    console.error(`Service validation failed for ${error.serviceId}:`);
    error.validationErrors.forEach(err => console.error(`  - ${err}`));
  }
}
```

## Best Practices

### 1. Use Branded Service IDs

```typescript
// Use branded types for service identification
const USER_SERVICE_ID = createServiceId<IUserService>('UserService');
const AUTH_SERVICE_ID = createServiceId<IAuthService>('AuthService');

// This prevents accidental use of wrong service types
container.register(USER_SERVICE_ID, UserService);
const user = container.resolve(USER_SERVICE_ID); // Type-safe
```

### 2. Define Service Dependencies Explicitly

```typescript
// Explicit dependency declaration enables validation
container.register(
  ORDER_SERVICE_ID,
  OrderService,
  ServiceLifetime.SINGLETON,
  [USER_SERVICE_ID, PAYMENT_SERVICE_ID, NOTIFICATION_SERVICE_ID] // explicit deps
);
```

### 3. Use Runtime Validators for Critical Services

```typescript
// Add validators for services that require strict type checking
container.register(
  PAYMENT_SERVICE_ID,
  PaymentService,
  ServiceLifetime.SINGLETON,
  [CONFIG_SERVICE_ID],
  paymentServiceValidator // Runtime validation
);
```

### 4. Enable Auto-Validation in Development

```typescript
const container = createTypedDIContainer({
  enableAutoValidation: process.env.NODE_ENV === 'development',
  enableRuntimeTypeChecking: process.env.NODE_ENV === 'development',
  enableDebugLogging: process.env.NODE_ENV === 'development'
});
```

### 5. Use Scoped Services Appropriately

```typescript
// Use scoped services for request-level or context-specific data
const requestScoped = container.createScope(requestId);
requestScoped.register(
  REQUEST_CONTEXT_ID,
  RequestContext,
  ServiceLifetime.SCOPED
);
```

## Testing Support

### Mock Services

```typescript
// Register mock implementations for testing
const testContainer = createTypedDIContainer();

testContainer.registerInstance(
  CONFIG_SERVICE_ID,
  {
    get: jest.fn().mockReturnValue('test-value'),
    getSection: jest.fn().mockReturnValue({ key: 'value' }),
    set: jest.fn(),
    validate: jest.fn().mockReturnValue(true)
  },
  configServiceValidator
);
```

### Container Reset

```typescript
// Clear container between tests
afterEach(() => {
  testContainer.clear();
});
```

## Performance Considerations

1. **Lazy Loading**: Enable lazy loading for expensive services
2. **Validation Cache**: Runtime validation results are cached
3. **Metrics Overhead**: Disable metrics in production if not needed
4. **Scoped Containers**: Use scoped containers to limit memory usage

## Troubleshooting

### Common Issues

1. **Type Mismatch**: Ensure service implementations match interface definitions
2. **Missing Dependencies**: Check that all declared dependencies are registered
3. **Circular Dependencies**: Use the dependency graph validation to identify cycles
4. **Runtime Validation Failures**: Check validator implementations match expected types

### Debug Mode

```typescript
// Enable debug logging for troubleshooting
const container = createTypedDIContainer({
  enableDebugLogging: true,
  enableAutoValidation: true,
  enableMetrics: true
});

// Listen to all container events
container.on('service:registered', (data) => console.log('Registered:', data));
container.on('service:resolving', (data) => console.log('Resolving:', data));
container.on('service:resolved', (data) => console.log('Resolved:', data));
container.on('service:resolution-failed', (data) => console.error('Failed:', data));
```

This migration guide provides a comprehensive path from the original DI container to the fully typed, validated container with enhanced features and better type safety.