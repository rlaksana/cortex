/**
 * Service Registry Configuration
 *
 * Configures and registers all services in the DI container.
 * Replaces singleton patterns with proper dependency injection.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';

import { AuditServiceAdapter } from './adapters/audit-service-adapter.js';
import { AuthServiceAdapter } from './adapters/auth-service-adapter.js';
import { CircuitBreakerServiceAdapter } from './adapters/circuit-breaker-service-adapter.js';
// Import adapter classes for interface compliance
import { DatabaseServiceAdapter } from './adapters/database-service-adapter.js';
import { DeduplicationServiceAdapter } from './adapters/deduplication-service-adapter.js';
import { EmbeddingServiceAdapter } from './adapters/embedding-service-adapter.js';
import { HealthCheckServiceAdapter } from './adapters/health-check-service-adapter.js';
import { MemoryFindOrchestratorAdapter } from './adapters/memory-find-orchestrator-adapter.js';
import { MemoryStoreOrchestratorAdapter } from './adapters/memory-store-orchestrator-adapter.js';
import { MetricsServiceAdapter } from './adapters/metrics-service-adapter.js';
import { DIContainer, ServiceLifetime } from './di-container.js';
import type {
  IAuditService,
  IAuthService,
  ICacheService,
  ICircuitBreakerService,
  IConfigService,
  IDatabaseService,
  IDeduplicationService,
  IEmbeddingService,
  IEventService,
  IHealthCheckService,
  ILoggerService,
  IMemoryFindOrchestrator,
  IMemoryStoreOrchestrator,
  IMetricsService,
  IPerformanceMonitor,
  IValidationService,
} from './service-interfaces.js';
import { ServiceTokens } from './service-interfaces.js';
import { ConfigService } from './services/config-service.js';
import { LoggerService } from './services/logger-service.js';
import { DatabaseManager } from '../db/database-manager.js';
import { monitoringHealthCheckService } from '../monitoring/health-check-service.js';
import { metricsService } from '../monitoring/metrics-service.js';
import { structuredLogger } from '../monitoring/structured-logger.js';
import { auditService } from '../services/audit/audit-service.js';
import { AuthService } from '../services/auth/auth-service.js';
import { circuitBreakerManager } from '../services/circuit-breaker.service.js';
import { DeduplicationService } from '../services/deduplication/deduplication-service.js';
import { DependencyRegistry } from '../services/deps-registry.js';
import { EmbeddingService } from '../services/embeddings/embedding-service.js';
import { MemoryFindOrchestrator } from '../services/orchestrators/memory-find-orchestrator.js';
// Import existing implementations to be wrapped
import { MemoryStoreOrchestrator } from '../services/orchestrators/memory-store-orchestrator.js';
import { performanceMonitor } from '../utils/performance-monitor.js';

/**
 * Service registry for configuring dependency injection
 */
export class ServiceRegistry {
  private container: DIContainer;

  constructor(container: DIContainer) {
    this.container = container;
  }

  /**
   * Register all core services
   */
  registerCoreServices(): void {
    this.registerConfigService();
    this.registerLoggerService();
    this.registerPerformanceMonitor();
    this.registerEventService();
  }

  /**
   * Register infrastructure services
   */
  registerInfrastructureServices(): void {
    this.registerDatabaseService();
    this.registerCircuitBreakerService();
    this.registerDependencyRegistry();
  }

  /**
   * Register application services
   */
  registerApplicationServices(): void {
    this.registerMemoryServices();
    this.registerSecurityServices();
    this.registerProcessingServices();
    this.registerMonitoringServices();
  }

  /**
   * Register all services in correct order
   */
  registerAll(): void {
    // Core services first (no dependencies)
    this.registerCoreServices();

    // Infrastructure services (depend on core)
    this.registerInfrastructureServices();

    // Application services (depend on infrastructure)
    this.registerApplicationServices();

    console.log('✅ All services registered in DI container');
  }

  /**
   * Register configuration service
   */
  private registerConfigService(): void {
    this.container.registerFactory<IConfigService>(
      ServiceTokens.CONFIG_SERVICE,
      (container) => {
        // Create a temporary logger for config service initialization
        const tempLogger = console;
        return new ConfigService(tempLogger as any);
      },
      ServiceLifetime.SINGLETON
    );
  }

  /**
   * Register logger service
   */
  private registerLoggerService(): void {
    this.container.register<ILoggerService>(
      ServiceTokens.LOGGER_SERVICE,
      LoggerService,
      ServiceLifetime.SINGLETON,
      [ServiceTokens.CONFIG_SERVICE, ServiceTokens.METRICS_SERVICE]
    );
  }

  /**
   * Register performance monitor
   */
  private registerPerformanceMonitor(): void {
    this.container.registerInstance<IPerformanceMonitor>(
      ServiceTokens.PERFORMANCE_MONITOR,
      performanceMonitor as unknown as IPerformanceMonitor
    );
  }

  /**
   * Register event service
   */
  private registerEventService(): void {
    this.container.registerFactory<IEventService>(
      ServiceTokens.EVENT_SERVICE,
      (container) => {
        return new EventEmitter();
      },
      ServiceLifetime.SINGLETON
    );
  }

  /**
   * Register database service
   */
  private registerDatabaseService(): void {
    this.container.registerFactory<IDatabaseService>(
      ServiceTokens.DATABASE_SERVICE,
      (container) => {
        const config = container.resolve<IConfigService>(ServiceTokens.CONFIG_SERVICE);

        // Create DatabaseManager with configuration
        const databaseManager = new DatabaseManager({
          qdrant: {
            url: config.get('QDRANT_URL', 'http://localhost:6333'),
            apiKey: config.get('QDRANT_API_KEY'),
            timeout: config.get('QDRANT_TIMEOUT', 30000),
          },
          enableVectorOperations: config.get('ENABLE_VECTOR_OPERATIONS', true),
          enableFallback: config.get('ENABLE_FALLBACK', true),
        });

        // Wrap with adapter to implement IDatabaseService interface
        return new DatabaseServiceAdapter(databaseManager);
      },
      ServiceLifetime.SINGLETON,
      [ServiceTokens.CONFIG_SERVICE]
    );
  }

  /**
   * Register circuit breaker service
   */
  private registerCircuitBreakerService(): void {
    this.container.registerFactory<ICircuitBreakerService>(
      ServiceTokens.CIRCUIT_BREAKER_SERVICE,
      (container) => {
        // Wrap circuitBreakerManager with adapter to implement ICircuitBreakerService interface
        return new CircuitBreakerServiceAdapter(circuitBreakerManager);
      },
      ServiceLifetime.SINGLETON
    );
  }

  /**
   * Register dependency registry
   */
  private registerDependencyRegistry(): void {
    this.container.registerFactory<DependencyRegistry>(
      ServiceTokens.DEPENDENCY_REGISTRY,
      () => {
        return new DependencyRegistry();
      },
      ServiceLifetime.SINGLETON
    );
  }

  /**
   * Register memory services
   */
  private registerMemoryServices(): void {
    // Memory Store Orchestrator
    this.container.registerFactory<IMemoryStoreOrchestrator>(
      ServiceTokens.MEMORY_STORE_ORCHESTRATOR,
      () => {
        // Create MemoryStoreOrchestrator and wrap with adapter to implement IMemoryStoreOrchestrator interface
        const memoryStoreOrchestrator = new MemoryStoreOrchestrator();
        return new MemoryStoreOrchestratorAdapter(memoryStoreOrchestrator);
      },
      ServiceLifetime.SINGLETON
    );

    // Memory Find Orchestrator
    this.container.registerFactory<IMemoryFindOrchestrator>(
      ServiceTokens.MEMORY_FIND_ORCHESTRATOR,
      () => {
        const memoryFindOrchestrator = new MemoryFindOrchestrator();
        return new MemoryFindOrchestratorAdapter(memoryFindOrchestrator);
      },
      ServiceLifetime.SINGLETON
    );
  }

  /**
   * Register security services
   */
  private registerSecurityServices(): void {
    // Auth Service
    this.container.registerFactory<IAuthService>(
      ServiceTokens.AUTH_SERVICE,
      (container) => {
        const logger = container.resolve<ILoggerService>(ServiceTokens.LOGGER_SERVICE);
        const config = container.resolve<IConfigService>(ServiceTokens.CONFIG_SERVICE);

        const authService = new AuthService({
          jwt_secret: config.get('JWT_SECRET', 'default-secret-key-for-development-only'),
          jwt_refresh_secret: config.get('JWT_REFRESH_SECRET', 'default-refresh-secret'),
          jwt_expires_in: config.get('JWT_EXPIRES_IN', '1h'),
          jwt_refresh_expires_in: config.get('JWT_REFRESH_EXPIRES_IN', '24h'),
          bcrypt_rounds: config.get('BCRYPT_ROUNDS', 12),
          api_key_length: config.get('API_KEY_LENGTH', 32),
          session_timeout_hours: config.get('SESSION_TIMEOUT_HOURS', 24),
          max_sessions_per_user: config.get('MAX_SESSIONS_PER_USER', 5),
          rate_limit_enabled: config.get('RATE_LIMIT_ENABLED', true),
          token_blacklist_backup_path: config.get('TOKEN_BLACKLIST_BACKUP_PATH'),
        });

        return new AuthServiceAdapter(authService);
      },
      ServiceLifetime.SINGLETON,
      [ServiceTokens.LOGGER_SERVICE, ServiceTokens.CONFIG_SERVICE]
    );

    // Validation Service
    this.container.registerFactory<IValidationService>(
      ServiceTokens.VALIDATION_SERVICE,
      (container) => {
        const logger = container.resolve<ILoggerService>(ServiceTokens.LOGGER_SERVICE);
        // TODO: Replace with actual validation service implementation
        return {
          validate: async (data: any, schema: string) => data,
          validateAsync: async (data: any, schema: string) => data,
          addSchema: (name: string, schema: any) => {},
          removeSchema: (name: string) => {},
        };
      },
      ServiceLifetime.SINGLETON,
      [ServiceTokens.LOGGER_SERVICE]
    );
  }

  /**
   * Register processing services
   */
  private registerProcessingServices(): void {
    // Deduplication Service
    this.container.registerInstance<IDeduplicationService>(
      ServiceTokens.DEDUPLICATION_SERVICE,
      new DeduplicationServiceAdapter(new DeduplicationService())
    );

    // Embedding Service
    this.container.registerFactory<IEmbeddingService>(
      ServiceTokens.EMBEDDING_SERVICE,
      (container) => {
        const logger = container.resolve<ILoggerService>(ServiceTokens.LOGGER_SERVICE);
        const config = container.resolve<IConfigService>(ServiceTokens.CONFIG_SERVICE);

        const embeddingService = new EmbeddingService({
          apiKey: config.get('OPENAI_API_KEY'),
          model: config.get('EMBEDDING_MODEL', 'text-embedding-3-small'),
          maxRetries: config.get('EMBEDDING_MAX_RETRIES', 3),
          timeout: config.get('EMBEDDING_TIMEOUT', 30000),
        });

        return new EmbeddingServiceAdapter(embeddingService);
      },
      ServiceLifetime.SINGLETON,
      [ServiceTokens.LOGGER_SERVICE, ServiceTokens.CONFIG_SERVICE]
    );

    // Audit Service
    this.container.registerInstance<IAuditService>(
      ServiceTokens.AUDIT_SERVICE,
      new AuditServiceAdapter()
    );
  }

  /**
   * Register monitoring services
   */
  private registerMonitoringServices(): void {
    // Metrics Service
    this.container.registerInstance<IMetricsService>(
      ServiceTokens.METRICS_SERVICE,
      new MetricsServiceAdapter()
    );

    // Health Check Service
    this.container.registerInstance<IHealthCheckService>(
      ServiceTokens.HEALTH_CHECK_SERVICE,
      new HealthCheckServiceAdapter()
    );

    // Cache Service (simple in-memory implementation)
    this.container.registerFactory<ICacheService>(
      ServiceTokens.CACHE_SERVICE,
      (container) => {
        const logger = container.resolve<ILoggerService>(ServiceTokens.LOGGER_SERVICE);

        // Simple in-memory cache implementation
        const cache = new Map<string, { value: any; expiry: number }>();

        return {
          get: async (key: string) => {
            const item = cache.get(key);
            if (!item) return null;
            if (Date.now() > item.expiry) {
              cache.delete(key);
              return null;
            }
            return item.value;
          },
          set: async (key: string, value: any, ttl = 300000) => {
            cache.set(key, { value, expiry: Date.now() + ttl });
          },
          delete: async (key: string) => {
            cache.delete(key);
          },
          clear: async () => {
            cache.clear();
          },
          has: async (key: string) => {
            const item = cache.get(key);
            if (!item) return false;
            if (Date.now() > item.expiry) {
              cache.delete(key);
              return false;
            }
            return true;
          },
        };
      },
      ServiceLifetime.SINGLETON,
      [ServiceTokens.LOGGER_SERVICE]
    );
  }

  /**
   * Register test services (for testing environment)
   */
  registerTestServices(): void {
    // Mock implementations for testing
    this.container.registerFactory<IConfigService>(
      ServiceTokens.CONFIG_SERVICE,
      (container) => {
        return {
          get: <T>(key: string, defaultValue?: T): T => {
            const testConfig = {
              QDRANT_URL: 'http://localhost:6333',
              QDRANT_COLLECTION_NAME: 'test-cortex-memory',
              LOG_LEVEL: 'debug',
              NODE_ENV: 'test',
            };
            const value = testConfig[key as keyof typeof testConfig];
            return (value !== undefined ? value : defaultValue) as T;
          },
          has: (key: string) => {
            const testConfig = {
              QDRANT_URL: 'http://localhost:6333',
              QDRANT_COLLECTION_NAME: 'test-cortex-memory',
              LOG_LEVEL: 'debug',
              NODE_ENV: 'test',
            };
            return testConfig[key as keyof typeof testConfig] !== undefined;
          },
          reload: async () => {},
        };
      },
      ServiceLifetime.SINGLETON
    );
  }

  /**
   * Get the configured container
   */
  getContainer(): DIContainer {
    return this.container;
  }
}

/**
 * Create and configure service registry with all services
 */
export function createServiceRegistry(): DIContainer {
  const container = new DIContainer();
  const registry = new ServiceRegistry(container);

  const isTest = process.env.NODE_ENV === 'test';
  const isDevelopment = process.env.NODE_ENV === 'development';

  if (isTest) {
    registry.registerTestServices();
  } else {
    registry.registerAll();
  }

  return container;
}
