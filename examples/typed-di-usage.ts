/**
 * Example Usage of Typed DI Container
 *
 * This file demonstrates comprehensive usage of the new typed DI container
 * with proper type safety, runtime validation, and advanced features.
 */

import {
  createTypedDIContainer,
  ServiceLifetime,
  type TypedDIContainer,
  type ValidatedServiceRegistration
} from '../src/di/typed-di-container.js';
import { createServiceId, ServiceLifetime as FactoryLifetime } from '../src/factories/factory-types.js';
import {
  RuntimeValidator,
  InstanceValidator,
  RuntimeTypeChecker,
  type ValidationResult
} from '../src/di/runtime-validation.js';

// ============================================================================
// Example Service Interfaces
// ============================================================================

export interface IUserService {
  getUser(id: string): Promise<User | null>;
  createUser(userData: CreateUserRequest): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User>;
  deleteUser(id: string): Promise<boolean>;
}

export interface IEmailService {
  sendEmail(to: string, subject: string, body: string): Promise<EmailResult>;
  sendTemplateEmail(to: string, template: string, data: Record<string, unknown>): Promise<EmailResult>;
}

export interface ICacheService {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
}

export interface ILoggerService {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, error?: Error | unknown, ...args: unknown[]): void;
}

// ============================================================================
// Domain Types
// ============================================================================

export interface User {
  id: string;
  username: string;
  email: string;
  createdAt: Date;
  updatedAt: Date;
  isActive: boolean;
  roles: string[];
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  roles?: string[];
}

export interface EmailResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

// ============================================================================
// Service Implementations
// ============================================================================

export class UserService implements IUserService {
  constructor(
    private readonly cacheService: ICacheService,
    private readonly logger: ILoggerService
  ) {}

  async getUser(id: string): Promise<User | null> {
    this.logger.debug(`Getting user: ${id}`);

    // Try cache first
    const cached = await this.cacheService.get<User>(`user:${id}`);
    if (cached) {
      this.logger.debug(`User ${id} found in cache`);
      return cached;
    }

    // Simulate database fetch
    this.logger.info(`Fetching user ${id} from database`);
    const user: User = {
      id,
      username: `user_${id}`,
      email: `user_${id}@example.com`,
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      roles: ['user']
    };

    // Cache the result
    await this.cacheService.set(`user:${id}`, user, 300); // 5 minutes TTL
    return user;
  }

  async createUser(userData: CreateUserRequest): Promise<User> {
    this.logger.info(`Creating user: ${userData.username}`);

    const user: User = {
      id: crypto.randomUUID(),
      username: userData.username,
      email: userData.email,
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      roles: userData.roles || ['user']
    };

    // Cache the new user
    await this.cacheService.set(`user:${user.id}`, user, 300);

    return user;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    this.logger.info(`Updating user: ${id}`);

    const existingUser = await this.getUser(id);
    if (!existingUser) {
      throw new Error(`User ${id} not found`);
    }

    const updatedUser: User = {
      ...existingUser,
      ...updates,
      updatedAt: new Date()
    };

    // Update cache
    await this.cacheService.set(`user:${id}`, updatedUser, 300);

    return updatedUser;
  }

  async deleteUser(id: string): Promise<boolean> {
    this.logger.info(`Deleting user: ${id}`);

    // Remove from cache
    await this.cacheService.delete(`user:${id}`);

    // Simulate database deletion
    return true;
  }
}

export class EmailService implements IEmailService {
  constructor(private readonly logger: ILoggerService) {}

  async sendEmail(to: string, subject: string, body: string): Promise<EmailResult> {
    this.logger.info(`Sending email to ${to}: ${subject}`);

    // Simulate email sending
    try {
      // In real implementation, this would call an email service API
      const messageId = crypto.randomUUID();

      this.logger.debug(`Email sent successfully with ID: ${messageId}`);

      return {
        success: true,
        messageId
      };
    } catch (error) {
      this.logger.error('Failed to send email', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async sendTemplateEmail(to: string, template: string, data: Record<string, unknown>): Promise<EmailResult> {
    this.logger.info(`Sending template email ${template} to ${to}`);

    // Simulate template processing
    const subject = `Template: ${template}`;
    const body = JSON.stringify(data);

    return this.sendEmail(to, subject, body);
  }
}

export class CacheService implements ICacheService {
  private cache = new Map<string, { value: unknown; expiry: number }>();

  async get<T>(key: string): Promise<T | null> {
    const item = this.cache.get(key);
    if (!item) return null;

    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }

    return item.value as T;
  }

  async set<T>(key: string, value: T, ttl = 300): Promise<void> {
    this.cache.set(key, {
      value,
      expiry: Date.now() + (ttl * 1000)
    });
  }

  async delete(key: string): Promise<boolean> {
    return this.cache.delete(key);
  }

  async clear(): Promise<void> {
    this.cache.clear();
  }
}

export class LoggerService implements ILoggerService {
  constructor(private readonly context: Record<string, unknown> = {}) {}

  debug(message: string, ...args: unknown[]): void {
    console.debug(`[DEBUG] [${this.getContextString()}] ${message}`, ...args);
  }

  info(message: string, ...args: unknown[]): void {
    console.info(`[INFO] [${this.getContextString()}] ${message}`, ...args);
  }

  warn(message: string, ...args: unknown[]): void {
    console.warn(`[WARN] [${this.getContextString()}] ${message}`, ...args);
  }

  error(message: string, error?: Error | unknown, ...args: unknown[]): void {
    console.error(`[ERROR] [${this.getContextString()}] ${message}`, error, ...args);
  }

  child(context: Record<string, unknown>): ILoggerService {
    return new LoggerService({ ...this.context, ...context });
  }

  private getContextString(): string {
    const entries = Object.entries(this.context);
    return entries.length > 0 ? entries.map(([k, v]) => `${k}=${v}`).join(', ') : 'root';
  }
}

// ============================================================================
// Runtime Validators
// ============================================================================

const userServiceValidator: RuntimeValidator<IUserService> = {
  validate(value: unknown): value is IUserService {
    if (typeof value !== 'object' || value === null) return false;

    const service = value as IUserService;
    return (
      typeof service.getUser === 'function' &&
      typeof service.createUser === 'function' &&
      typeof service.updateUser === 'function' &&
      typeof service.deleteUser === 'function'
    );
  },

  getExpectedType(): string {
    return 'IUserService';
  },

  getErrorMessage(value: unknown): string {
    return `Expected IUserService implementation with required methods, got ${typeof value}`;
  }
};

const emailServiceValidator: RuntimeValidator<IEmailService> = {
  validate(value: unknown): value is IEmailService {
    if (typeof value !== 'object' || value === null) return false;

    const service = value as IEmailService;
    return (
      typeof service.sendEmail === 'function' &&
      typeof service.sendTemplateEmail === 'function'
    );
  },

  getExpectedType(): string {
    return 'IEmailService';
  },

  getErrorMessage(value: unknown): string {
    return `Expected IEmailService implementation, got ${typeof value}`;
  }
};

const cacheServiceValidator: RuntimeValidator<ICacheService> = {
  validate(value: unknown): value is ICacheService {
    if (typeof value !== 'object' || value === null) return false;

    const service = value as ICacheService;
    return (
      typeof service.get === 'function' &&
      typeof service.set === 'function' &&
      typeof service.delete === 'function' &&
      typeof service.clear === 'function'
    );
  },

  getExpectedType(): string {
    return 'ICacheService';
  },

  getErrorMessage(value: unknown): string {
    return `Expected ICacheService implementation, got ${typeof value}`;
  }
};

const loggerServiceValidator: RuntimeValidator<ILoggerService> = {
  validate(value: unknown): value is ILoggerService {
    if (typeof value !== 'object' || value === null) return false;

    const service = value as ILoggerService;
    return (
      typeof service.debug === 'function' &&
      typeof service.info === 'function' &&
      typeof service.warn === 'function' &&
      typeof service.error === 'function'
    );
  },

  getExpectedType(): string {
    return 'ILoggerService';
  },

  getErrorMessage(value: unknown): string {
    return `Expected ILoggerService implementation, got ${typeof value}`;
  }
};

// ============================================================================
// Service IDs (Branded Types)
// ============================================================================

export const SERVICE_IDS = {
  USER_SERVICE: createServiceId<IUserService>('UserService'),
  EMAIL_SERVICE: createServiceId<IEmailService>('EmailService'),
  CACHE_SERVICE: createServiceId<ICacheService>('CacheService'),
  LOGGER_SERVICE: createServiceId<ILoggerService>('LoggerService')
} as const;

// ============================================================================
// Container Setup and Configuration
// ============================================================================

export function createContainer(): TypedDIContainer {
  const container = createTypedDIContainer({
    enableAutoValidation: true,
    enableRuntimeTypeChecking: true,
    enableCircularDependencyDetection: true,
    enableMetrics: true,
    enableDebugLogging: true,
    maxResolutionDepth: 20,
    validationCacheTimeout: 60000
  });

  // Register core services
  registerCoreServices(container);

  // Register application services
  registerApplicationServices(container);

  return container;
}

function registerCoreServices(container: TypedDIContainer): void {
  // Logger service (no dependencies)
  container.register(
    SERVICE_IDS.LOGGER_SERVICE,
    LoggerService,
    ServiceLifetime.SINGLETON,
    [], // no dependencies
    loggerServiceValidator,
    ['core', 'logging'], // tags
    1 // priority (highest)
  );

  // Cache service (depends on logger)
  container.register(
    SERVICE_IDS.CACHE_SERVICE,
    CacheService,
    ServiceLifetime.SINGLETON,
    [SERVICE_IDS.LOGGER_SERVICE], // dependency
    cacheServiceValidator,
    ['core', 'caching'],
    2
  );
}

function registerApplicationServices(container: TypedDIContainer): void {
  // Email service (depends on logger)
  container.register(
    SERVICE_IDS.EMAIL_SERVICE,
    EmailService,
    ServiceLifetime.SINGLETON,
    [SERVICE_IDS.LOGGER_SERVICE],
    emailServiceValidator,
    ['application', 'communication'],
    3
  );

  // User service (depends on cache and logger)
  container.register(
    SERVICE_IDS.USER_SERVICE,
    UserService,
    ServiceLifetime.SINGLETON,
    [SERVICE_IDS.CACHE_SERVICE, SERVICE_IDS.LOGGER_SERVICE],
    userServiceValidator,
    ['application', 'business'],
    4
  );
}

// ============================================================================
// Usage Examples
// ============================================================================

export async function basicUsageExample(): Promise<void> {
  console.log('=== Basic Usage Example ===');

  const container = createContainer();

  // Resolve services with full type safety
  const userService = container.resolve(SERVICE_IDS.USER_SERVICE);
  const emailService = container.resolve(SERVICE_IDS.EMAIL_SERVICE);

  // Use services
  const user = await userService.createUser({
    username: 'john_doe',
    email: 'john@example.com',
    password: 'secure_password',
    roles: ['user', 'admin']
  });

  console.log('Created user:', user);

  // Get user (will use cache)
  const retrievedUser = await userService.getUser(user.id);
  console.log('Retrieved user:', retrievedUser);

  // Send email
  const emailResult = await emailService.sendEmail(
    user.email,
    'Welcome!',
    'Welcome to our platform!'
  );
  console.log('Email result:', emailResult);
}

export async function scopedServicesExample(): Promise<void> {
  console.log('\n=== Scoped Services Example ===');

  const rootContainer = createContainer();

  // Create scoped containers for different requests
  const request1Scope = rootContainer.createScope('request-1');
  const request2Scope = rootContainer.createScope('request-2');

  // Each scope gets its own instances
  const logger1 = request1Scope.resolve(SERVICE_IDS.LOGGER_SERVICE);
  const logger2 = request2Scope.resolve(SERVICE_IDS.LOGGER_SERVICE);

  logger1.info('Request 1 started');
  logger2.info('Request 2 started');

  // Clear scopes when done
  rootContainer.clearScope('request-1');
  rootContainer.clearScope('request-2');
}

export async function factoryRegistrationExample(): Promise<void> {
  console.log('\n=== Factory Registration Example ===');

  const container = createTypedDIContainer();

  // Register logger first
  container.register(
    SERVICE_IDS.LOGGER_SERVICE,
    LoggerService,
    ServiceLifetime.SINGLETON,
    [],
    loggerServiceValidator
  );

  // Register cache service with factory
  container.registerFactory(
    SERVICE_IDS.CACHE_SERVICE,
    async (container) => {
      const logger = container.resolve(SERVICE_IDS.LOGGER_SERVICE);
      logger.info('Initializing cache service via factory');

      const cache = new CacheService();
      await cache.set('factory-test', 'initialized via factory', 300);

      return cache;
    },
    ServiceLifetime.SINGLETON,
    [SERVICE_IDS.LOGGER_SERVICE],
    cacheServiceValidator
  );

  // Use the factory-created service
  const cacheService = container.resolve(SERVICE_IDS.CACHE_SERVICE);
  const testValue = await cacheService.get('factory-test');
  console.log('Factory test value:', testValue);
}

export async function validationExample(): Promise<void> {
  console.log('\n=== Validation Example ===');

  const container = createTypedDIContainer();

  // Try to register an invalid instance
  try {
    container.registerInstance(
      SERVICE_IDS.USER_SERVICE,
      { invalid: 'object' } as any, // This will fail validation
      userServiceValidator
    );
  } catch (error) {
    console.error('Expected validation error:', error instanceof Error ? error.message : error);
  }

  // Validate dependency graph
  const graphValidation = container.validateDependencyGraph();
  console.log('Dependency graph validation:', graphValidation);

  // Validate all services
  const serviceValidation = container.validateAllServices();
  console.log('All services validation:', serviceValidation);
}

export async function metricsExample(): Promise<void> {
  console.log('\n=== Metrics Example ===');

  const container = createContainer();

  // Listen to container events
  container.on('service:resolved', ({ serviceId, resolutionTime }) => {
    console.log(`  -> Service ${serviceId} resolved in ${resolutionTime}ms`);
  });

  // Resolve some services to generate metrics
  const userService = container.resolve(SERVICE_IDS.USER_SERVICE);
  const emailService = container.resolve(SERVICE_IDS.EMAIL_SERVICE);

  // Use services
  await userService.getUser('test-user');
  await emailService.sendEmail('test@example.com', 'Test', 'Test body');

  // Get container metrics
  const metrics = container.getMetrics();
  console.log('Container metrics:', {
    totalServices: metrics.totalServices,
    resolvedServices: metrics.resolvedServices,
    averageResolutionTime: metrics.averageResolutionTime,
    memoryUsage: metrics.memoryUsage,
    circularDependencies: metrics.circularDependencies
  });
}

export async function circularDependencyDetectionExample(): Promise<void> {
  console.log('\n=== Circular Dependency Detection Example ===');

  const container = createTypedDIContainer({
    enableCircularDependencyDetection: true
  });

  // Create service IDs for this example
  const SERVICE_A = createServiceId<any>('ServiceA');
  const SERVICE_B = createServiceId<any>('ServiceB');
  const SERVICE_C = createServiceId<any>('ServiceC');

  // Register services with circular dependencies
  container.register(SERVICE_A, class ServiceA {
    constructor(public b: any) {}
  }, ServiceLifetime.SINGLETON, [SERVICE_B]);

  container.register(SERVICE_B, class ServiceB {
    constructor(public c: any) {}
  }, ServiceLifetime.SINGLETON, [SERVICE_C]);

  container.register(SERVICE_C, class ServiceC {
    constructor(public a: any) {}
  }, ServiceLifetime.SINGLETON, [SERVICE_A]);

  // Try to resolve - this should detect the circular dependency
  try {
    container.resolve(SERVICE_A);
  } catch (error) {
    console.error('Expected circular dependency error:', error instanceof Error ? error.message : error);
  }

  // Validate the dependency graph
  const validation = container.validateDependencyGraph();
  console.log('Circular dependency validation:', validation);
}

// ============================================================================
// Main Example Runner
// ============================================================================

export async function runAllExamples(): Promise<void> {
  console.log('🚀 Running Typed DI Container Examples\n');

  try {
    await basicUsageExample();
    await scopedServicesExample();
    await factoryRegistrationExample();
    await validationExample();
    await metricsExample();
    await circularDependencyDetectionExample();

    console.log('\n✅ All examples completed successfully!');
  } catch (error) {
    console.error('\n❌ Example execution failed:', error);
  }
}

// Run examples if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAllExamples();
}