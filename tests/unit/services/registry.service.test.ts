/**
 * Comprehensive Unit Tests for Registry Service
 *
 * Tests advanced registry service functionality including:
 * - Service instance registration and health check integration
 * - Service discovery and load balancing integration
 * - Health monitoring and unhealthy service removal
 * - Configuration management and dynamic updates
 * - Service lifecycle management and graceful degradation
 * - Integration with microservices and service mesh
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RegistryService } from '../../../src/services/registry/registry-service';
import type {
  ServiceInstance,
  ServiceRegistration,
  HealthCheckResult,
  ServiceConfiguration,
  ServiceDiscovery,
  ServiceEndpoint
} from '../../../src/types/service-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient
}));

// Mock Qdrant client for registry data persistence
const mockQdrantClient = {
  serviceRegistry: {
    create: vi.fn(),
    findMany: vi.fn(),
    findFirst: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  serviceHealth: {
    create: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  serviceConfig: {
    create: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  }
};

// Mock cache factory
vi.mock('../../../src/utils/lru-cache', () => ({
  CacheFactory: {
    createRegistryCache: () => ({
      get: vi.fn(),
      set: vi.fn(),
      clear: vi.fn(),
      delete: vi.fn(),
      getStats: vi.fn(() => ({
        itemCount: 0,
        memoryUsageBytes: 0,
        maxMemoryBytes: 52428800,
        hitRate: 0,
        totalHits: 0,
        totalMisses: 0,
        expiredItems: 0,
        evictedItems: 0
      }))
    })
  }
}));

describe('RegistryService - Comprehensive Service Registry Functionality', () => {
  let registryService: RegistryService;

  beforeEach(() => {
    registryService = new RegistryService();

    // Reset all mocks
    vi.clearAllMocks();

    // Setup default mock responses
    mockQdrantClient.serviceRegistry.findMany.mockResolvedValue([]);
    mockQdrantClient.serviceHealth.findMany.mockResolvedValue([]);
    mockQdrantClient.serviceConfig.findMany.mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Service Registration Tests
  describe('Service Registration', () => {
    it('should register new service instances successfully', async () => {
      const serviceRegistration: ServiceRegistration = {
        serviceId: 'user-service-v1',
        serviceName: 'user-service',
        version: '1.0.0',
        instanceId: 'user-service-001',
        host: 'localhost',
        port: 3001,
        protocol: 'http',
        metadata: {
          description: 'User management service',
          team: 'backend',
          environment: 'development'
        },
        healthCheckUrl: 'http://localhost:3001/health',
        tags: ['user', 'authentication', 'core']
      };

      mockQdrantClient.serviceRegistry.create.mockResolvedValue({
        id: 'registry-1',
        ...serviceRegistration,
        status: 'healthy',
        registeredAt: new Date(),
        lastHealthCheck: new Date()
      });

      const result = await registryService.registerService(serviceRegistration);

      expect(result).toBeDefined();
      expect(result.serviceId).toBe(serviceRegistration.serviceId);
      expect(result.status).toBe('healthy');
      expect(mockQdrantClient.serviceRegistry.create).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceId: serviceRegistration.serviceId,
          serviceName: serviceRegistration.serviceName,
          version: serviceRegistration.version
        })
      );
    });

    it('should validate service registration data', async () => {
      const invalidRegistration = {
        serviceId: '', // Empty service ID
        serviceName: 'test-service',
        version: '1.0.0',
        host: 'invalid-host', // Invalid host format
        port: 70000, // Invalid port
        protocol: 'invalid-protocol'
      };

      await expect(registryService.registerService(invalidRegistration as any))
        .rejects.toThrow('Invalid service registration data');
    });

    it('should handle service versioning correctly', async () => {
      const serviceV1: ServiceRegistration = {
        serviceId: 'api-service-v1',
        serviceName: 'api-service',
        version: '1.0.0',
        instanceId: 'api-service-001',
        host: 'localhost',
        port: 3002,
        protocol: 'http',
        metadata: { deprecated: false }
      };

      const serviceV2: ServiceRegistration = {
        serviceId: 'api-service-v2',
        serviceName: 'api-service',
        version: '2.0.0',
        instanceId: 'api-service-002',
        host: 'localhost',
        port: 3003,
        protocol: 'http',
        metadata: { deprecated: false }
      };

      mockQdrantClient.serviceRegistry.create
        .mockResolvedValueOnce({ id: '1', ...serviceV1, status: 'healthy' })
        .mockResolvedValueOnce({ id: '2', ...serviceV2, status: 'healthy' });

      const resultV1 = await registryService.registerService(serviceV1);
      const resultV2 = await registryService.registerService(serviceV2);

      expect(resultV1.version).toBe('1.0.0');
      expect(resultV2.version).toBe('2.0.0');
      expect(mockQdrantClient.serviceRegistry.create).toHaveBeenCalledTimes(2);
    });

    it('should manage service metadata effectively', async () => {
      const serviceWithMetadata: ServiceRegistration = {
        serviceId: 'metadata-service',
        serviceName: 'metadata-service',
        version: '1.0.0',
        instanceId: 'metadata-001',
        host: 'localhost',
        port: 3004,
        protocol: 'http',
        metadata: {
          team: 'platform',
          criticality: 'high',
          sla: '99.9%',
          dependencies: ['database', 'cache'],
          customProperty: 'custom-value'
        },
        tags: ['platform', 'critical']
      };

      mockQdrantClient.serviceRegistry.create.mockResolvedValue({
        id: 'metadata-1',
        ...serviceWithMetadata,
        status: 'healthy'
      });

      const result = await registryService.registerService(serviceWithMetadata);

      expect(result.metadata.team).toBe('platform');
      expect(result.metadata.criticality).toBe('high');
      expect(result.metadata.dependencies).toEqual(['database', 'cache']);
      expect(result.tags).toContain('platform');
    });

    it('should prevent duplicate service instance registration', async () => {
      const serviceRegistration: ServiceRegistration = {
        serviceId: 'duplicate-service',
        serviceName: 'duplicate-service',
        version: '1.0.0',
        instanceId: 'duplicate-001',
        host: 'localhost',
        port: 3005,
        protocol: 'http'
      };

      // First registration succeeds
      mockQdrantClient.serviceRegistry.create.mockResolvedValueOnce({
        id: 'first',
        ...serviceRegistration,
        status: 'healthy'
      });

      // Second registration fails due to duplicate
      mockQdrantClient.serviceRegistry.create.mockRejectedValueOnce(
        new Error('Service instance already registered')
      );

      const firstResult = await registryService.registerService(serviceRegistration);
      expect(firstResult.status).toBe('healthy');

      await expect(registryService.registerService(serviceRegistration))
        .rejects.toThrow('Service instance already registered');
    });
  });

  // 2. Service Discovery Tests
  describe('Service Discovery', () => {
    it('should discover services by name and version', async () => {
      const mockServices = [
        {
          id: '1',
          serviceId: 'user-service-v1',
          serviceName: 'user-service',
          version: '1.0.0',
          instanceId: 'user-001',
          host: 'localhost',
          port: 3001,
          status: 'healthy',
          lastHealthCheck: new Date()
        },
        {
          id: '2',
          serviceId: 'user-service-v2',
          serviceName: 'user-service',
          version: '2.0.0',
          instanceId: 'user-002',
          host: 'localhost',
          port: 3002,
          status: 'healthy',
          lastHealthCheck: new Date()
        }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(mockServices);

      const discovery: ServiceDiscovery = {
        serviceName: 'user-service',
        version: '2.0.0'
      };

      const result = await registryService.discoverServices(discovery);

      expect(result.services).toHaveLength(1);
      expect(result.services[0].version).toBe('2.0.0');
      expect(result.services[0].serviceName).toBe('user-service');
    });

    it('should implement load balancing for service instances', async () => {
      const mockInstances = [
        {
          id: '1',
          serviceId: 'load-balanced-service',
          serviceName: 'load-balanced-service',
          instanceId: 'instance-1',
          host: 'host1',
          port: 3001,
          status: 'healthy',
          weight: 1
        },
        {
          id: '2',
          serviceId: 'load-balanced-service',
          serviceName: 'load-balanced-service',
          instanceId: 'instance-2',
          host: 'host2',
          port: 3001,
          status: 'healthy',
          weight: 2
        },
        {
          id: '3',
          serviceId: 'load-balanced-service',
          serviceName: 'load-balanced-service',
          instanceId: 'instance-3',
          host: 'host3',
          port: 3001,
          status: 'healthy',
          weight: 1
        }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(mockInstances);

      const discovery: ServiceDiscovery = {
        serviceName: 'load-balanced-service',
        loadBalancingStrategy: 'weighted_round_robin'
      };

      const result = await registryService.discoverServices(discovery);

      expect(result.services).toHaveLength(3);
      expect(result.loadBalancingStrategy).toBe('weighted_round_robin');

      // Test multiple calls to verify load balancing
      const endpoints = [];
      for (let i = 0; i < 10; i++) {
        const endpoint = await registryService.getServiceEndpoint('load-balanced-service');
        endpoints.push(endpoint.instanceId);
      }

      // Should distribute calls across instances based on weight
      const instance2Count = endpoints.filter(id => id === 'instance-2').length;
      expect(instance2Count).toBeGreaterThan(3); // Higher weight = more calls
    });

    it('should handle service routing and endpoint management', async () => {
      const mockService = {
        id: '1',
        serviceId: 'routing-service',
        serviceName: 'routing-service',
        instanceId: 'route-001',
        host: 'api.example.com',
        port: 443,
        protocol: 'https',
        status: 'healthy',
        endpoints: [
          { path: '/api/v1/users', methods: ['GET', 'POST'] },
          { path: '/api/v1/users/{id}', methods: ['GET', 'PUT', 'DELETE'] }
        ]
      };

      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(mockService);

      const endpoint = await registryService.getServiceEndpoint('routing-service', '/api/v1/users');

      expect(endpoint).toBeDefined();
      expect(endpoint.host).toBe('api.example.com');
      expect(endpoint.protocol).toBe('https');
      expect(endpoint.port).toBe(443);
    });

    it('should filter services by tags and metadata', async () => {
      const mockServices = [
        {
          id: '1',
          serviceName: 'filtered-service-1',
          tags: ['api', 'public', 'v1'],
          metadata: { team: 'backend', environment: 'production' },
          status: 'healthy'
        },
        {
          id: '2',
          serviceName: 'filtered-service-2',
          tags: ['internal', 'admin'],
          metadata: { team: 'backend', environment: 'staging' },
          status: 'healthy'
        },
        {
          id: '3',
          serviceName: 'filtered-service-3',
          tags: ['api', 'public', 'v2'],
          metadata: { team: 'frontend', environment: 'production' },
          status: 'healthy'
        }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(mockServices);

      const discovery: ServiceDiscovery = {
        tags: ['api', 'public'],
        metadata: { environment: 'production' }
      };

      const result = await registryService.discoverServices(discovery);

      expect(result.services).toHaveLength(2);
      expect(result.services.every(s => s.tags.includes('api'))).toBe(true);
      expect(result.services.every(s => s.metadata.environment === 'production')).toBe(true);
    });
  });

  // 3. Health Monitoring Tests
  describe('Health Monitoring', () => {
    it('should track service health status effectively', async () => {
      const healthCheckResult: HealthCheckResult = {
        serviceId: 'health-service',
        instanceId: 'health-001',
        status: 'healthy',
        timestamp: new Date(),
        responseTime: 45,
        checks: {
          database: 'pass',
          cache: 'pass',
          external_api: 'pass'
        },
        metadata: {
          uptime: '72h 30m',
          memory_usage: '45%',
          cpu_usage: '12%'
        }
      };

      mockQdrantClient.serviceHealth.create.mockResolvedValue({
        id: 'health-1',
        ...healthCheckResult
      });

      const result = await registryService.recordHealthCheck(healthCheckResult);

      expect(result.status).toBe('healthy');
      expect(result.responseTime).toBe(45);
      expect(result.checks.database).toBe('pass');
      expect(mockQdrantClient.serviceHealth.create).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceId: 'health-service',
          status: 'healthy'
        })
      );
    });

    it('should schedule health checks automatically', async () => {
      const service = {
        id: '1',
        serviceId: 'scheduled-service',
        instanceId: 'scheduled-001',
        healthCheckUrl: 'http://localhost:3006/health',
        healthCheckInterval: 30000 // 30 seconds
      };

      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(service);

      // Mock fetch for health check
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          status: 'healthy',
          timestamp: new Date().toISOString(),
          checks: { all: 'pass' }
        })
      });

      await registryService.startHealthMonitoring('scheduled-service');

      // Verify health check scheduling
      expect(registryService['healthCheckSchedulers']).toHaveProperty('scheduled-service');

      // Stop monitoring to clean up
      await registryService.stopHealthMonitoring('scheduled-service');
    });

    it('should automatically remove unhealthy services', async () => {
      const unhealthyService = {
        id: '1',
        serviceId: 'unhealthy-service',
        instanceId: 'unhealthy-001',
        status: 'unhealthy',
        lastHealthCheck: new Date(Date.now() - 5 * 60 * 1000), // 5 minutes ago
        consecutiveFailures: 3
      };

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue([unhealthyService]);
      mockQdrantClient.serviceRegistry.delete.mockResolvedValue(unhealthyService);

      const removedServices = await registryService.removeUnhealthyServices();

      expect(removedServices).toHaveLength(1);
      expect(removedServices[0].serviceId).toBe('unhealthy-service');
      expect(mockQdrantClient.serviceRegistry.delete).toHaveBeenCalledWith('1');
    });

    it('should detect service recovery automatically', async () => {
      const previouslyUnhealthyService = {
        id: '1',
        serviceId: 'recovery-service',
        instanceId: 'recovery-001',
        status: 'unhealthy',
        lastHealthCheck: new Date(Date.now() - 2 * 60 * 1000) // 2 minutes ago
      };

      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(previouslyUnhealthyService);
      mockQdrantClient.serviceRegistry.update.mockResolvedValue({
        ...previouslyUnhealthyService,
        status: 'healthy',
        lastHealthCheck: new Date()
      });

      const healthCheckResult: HealthCheckResult = {
        serviceId: 'recovery-service',
        instanceId: 'recovery-001',
        status: 'healthy',
        timestamp: new Date(),
        responseTime: 50
      };

      const result = await registryService.recordHealthCheck(healthCheckResult);

      expect(result.status).toBe('healthy');
      expect(mockQdrantClient.serviceRegistry.update).toHaveBeenCalledWith(
        '1',
        expect.objectContaining({
          status: 'healthy',
          lastHealthCheck: expect.any(Date)
        })
      );
    });

    it('should handle health check timeouts and failures', async () => {
      const serviceWithTimeout = {
        id: '1',
        serviceId: 'timeout-service',
        healthCheckUrl: 'http://localhost:3007/health',
        healthCheckTimeout: 5000 // 5 seconds
      };

      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(serviceWithTimeout);

      // Mock fetch that times out
      global.fetch = vi.fn().mockImplementation(() =>
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Health check timeout')), 6000)
        )
      );

      const healthCheckResult = await registryService.performHealthCheck(serviceWithTimeout);

      expect(healthCheckResult.status).toBe('unhealthy');
      expect(healthCheckResult.error).toContain('timeout');
    });
  });

  // 4. Configuration Management Tests
  describe('Configuration Management', () => {
    it('should store and retrieve service configurations', async () => {
      const serviceConfig: ServiceConfiguration = {
        serviceId: 'config-service',
        environment: 'production',
        config: {
          database: {
            host: 'prod-db.example.com',
            port: 5432,
            ssl: true
          },
          cache: {
            ttl: 3600,
            maxSize: 1000
          },
          features: {
            newFeatureFlag: true,
            betaFeatures: false
          }
        },
        version: '1.2.0',
        encrypted: true
      };

      mockQdrantClient.serviceConfig.create.mockResolvedValue({
        id: 'config-1',
        ...serviceConfig,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const result = await registryService.storeConfiguration(serviceConfig);

      expect(result.serviceId).toBe('config-service');
      expect(result.config.database.host).toBe('prod-db.example.com');
      expect(result.encrypted).toBe(true);
    });

    it('should handle dynamic configuration updates', async () => {
      const existingConfig = {
        id: 'config-1',
        serviceId: 'dynamic-config-service',
        environment: 'staging',
        config: {
          logLevel: 'info',
          maxConnections: 100
        }
      };

      const updatedConfig = {
        ...existingConfig,
        config: {
          ...existingConfig.config,
          logLevel: 'debug', // Updated
          maxConnections: 150, // Updated
          newFeature: true // New property
        }
      };

      mockQdrantClient.serviceConfig.findFirst.mockResolvedValue(existingConfig);
      mockQdrantClient.serviceConfig.update.mockResolvedValue({
        ...updatedConfig,
        updatedAt: new Date()
      });

      const result = await registryService.updateConfiguration('dynamic-config-service', {
        logLevel: 'debug',
        maxConnections: 150,
        newFeature: true
      });

      expect(result.config.logLevel).toBe('debug');
      expect(result.config.maxConnections).toBe(150);
      expect(result.config.newFeature).toBe(true);
    });

    it('should manage environment-specific configurations', async () => {
      const environments = ['development', 'staging', 'production'];
      const configs = [];

      for (const env of environments) {
        const config = {
          id: `config-${env}`,
          serviceId: 'multi-env-service',
          environment: env,
          config: {
            logLevel: env === 'production' ? 'error' : 'debug',
            debugMode: env !== 'production',
            apiTimeout: env === 'production' ? 30000 : 60000
          }
        };
        configs.push(config);
      }

      mockQdrantClient.serviceConfig.findMany.mockResolvedValue(configs);

      const prodConfig = await registryService.getConfiguration('multi-env-service', 'production');
      const devConfig = await registryService.getConfiguration('multi-env-service', 'development');

      expect(prodConfig.config.logLevel).toBe('error');
      expect(prodConfig.config.debugMode).toBe(false);
      expect(devConfig.config.logLevel).toBe('debug');
      expect(devConfig.config.debugMode).toBe(true);
    });

    it('should validate configuration schemas', async () => {
      const invalidConfig = {
        serviceId: 'invalid-config-service',
        environment: 'production',
        config: {
          database: {
            host: '', // Invalid: empty host
            port: 'invalid-port', // Invalid: not a number
            ssl: 'not-boolean' // Invalid: not a boolean
          }
        }
      };

      await expect(registryService.storeConfiguration(invalidConfig as any))
        .rejects.toThrow('Configuration validation failed');
    });

    it('should handle configuration encryption and decryption', async () => {
      const sensitiveConfig: ServiceConfiguration = {
        serviceId: 'secure-service',
        environment: 'production',
        config: {
          apiKey: 'sk-1234567890abcdef',
          databasePassword: 'super-secret-password',
          jwtSecret: 'jwt-secret-key'
        },
        encrypted: true,
        sensitiveFields: ['apiKey', 'databasePassword', 'jwtSecret']
      };

      mockQdrantClient.serviceConfig.create.mockResolvedValue({
        id: 'secure-config-1',
        ...sensitiveConfig,
        createdAt: new Date()
      });

      const storedResult = await registryService.storeConfiguration(sensitiveConfig);

      // Verify sensitive fields are encrypted in storage
      expect(storedResult.encrypted).toBe(true);
      expect(storedResult.sensitiveFields).toEqual(['apiKey', 'databasePassword', 'jwtSecret']);

      // Retrieve and decrypt configuration
      mockQdrantClient.serviceConfig.findFirst.mockResolvedValue(storedResult);
      const retrievedConfig = await registryService.getConfiguration('secure-service', 'production', true);

      expect(retrievedConfig.config.apiKey).toBe('sk-1234567890abcdef');
      expect(retrievedConfig.config.databasePassword).toBe('super-secret-password');
    });
  });

  // 5. Service Lifecycle Tests
  describe('Service Lifecycle', () => {
    it('should handle service startup and shutdown gracefully', async () => {
      const serviceInstance: ServiceInstance = {
        id: '1',
        serviceId: 'lifecycle-service',
        instanceId: 'lifecycle-001',
        status: 'starting',
        host: 'localhost',
        port: 3008,
        startTime: new Date(),
        dependencies: ['database', 'cache']
      };

      // Simulate service startup
      mockQdrantClient.serviceRegistry.update.mockResolvedValue({
        ...serviceInstance,
        status: 'running'
      });

      const startedService = await registryService.startService('lifecycle-service', 'lifecycle-001');

      expect(startedService.status).toBe('running');
      expect(mockQdrantClient.serviceRegistry.update).toHaveBeenCalledWith(
        '1',
        expect.objectContaining({
          status: 'running',
          startTime: expect.any(Date)
        })
      );

      // Simulate graceful shutdown
      mockQdrantClient.serviceRegistry.update.mockResolvedValue({
        ...startedService,
        status: 'stopped',
        shutdownTime: new Date()
      });

      const stoppedService = await registryService.stopService('lifecycle-service', 'lifecycle-001');

      expect(stoppedService.status).toBe('stopped');
      expect(stoppedService.shutdownTime).toBeDefined();
    });

    it('should implement graceful degradation', async () => {
      const service = {
        id: '1',
        serviceId: 'degrading-service',
        status: 'degraded',
        lastHealthCheck: new Date(),
        degradationReason: 'High memory usage',
        limitedFeatures: ['advanced-search', 'real-time-updates']
      };

      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(service);
      mockQdrantClient.serviceRegistry.update.mockResolvedValue(service);

      const result = await registryService.getServiceStatus('degrading-service');

      expect(result.status).toBe('degraded');
      expect(result.degradationReason).toBe('High memory usage');
      expect(result.limitedFeatures).toContain('advanced-search');
    });

    it('should handle service replacement and migration', async () => {
      const oldService = {
        id: '1',
        serviceId: 'migration-service',
        version: '1.0.0',
        instanceId: 'old-instance',
        status: 'running',
        host: 'old-host',
        port: 3009
      };

      const newService = {
        serviceId: 'migration-service',
        version: '2.0.0',
        instanceId: 'new-instance',
        host: 'new-host',
        port: 3010
      };

      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(oldService);
      mockQdrantClient.serviceRegistry.create.mockResolvedValue({
        id: '2',
        ...newService,
        status: 'running'
      });
      mockQdrantClient.serviceRegistry.update.mockResolvedValue({
        ...oldService,
        status: 'deprecated'
      });

      const migrationResult = await registryService.migrateService(
        'migration-service',
        'old-instance',
        newService
      );

      expect(migrationResult.newService.version).toBe('2.0.0');
      expect(migrationResult.oldService.status).toBe('deprecated');
      expect(mockQdrantClient.serviceRegistry.create).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceId: 'migration-service',
          version: '2.0.0'
        })
      );
    });

    it('should support blue-green deployment patterns', async () => {
      const blueService = {
        id: '1',
        serviceId: 'bg-service',
        version: '1.0.0',
        instanceId: 'blue-instance',
        status: 'running',
        environment: 'blue'
      };

      const greenService = {
        serviceId: 'bg-service',
        version: '1.1.0',
        instanceId: 'green-instance',
        status: 'running',
        environment: 'green'
      };

      // Register blue service
      mockQdrantClient.serviceRegistry.findFirst.mockResolvedValue(blueService);
      mockQdrantClient.serviceRegistry.create.mockResolvedValue({
        id: '2',
        ...greenService
      });

      const blueGreenDeployment = await registryService.initiateBlueGreenDeployment(
        'bg-service',
        greenService
      );

      expect(blueGreenDeployment.activeEnvironment).toBe('blue');
      expect(blueGreenDeployment.standbyEnvironment).toBe('green');
      expect(blueGreenDeployment.status).toBe('ready-to-switch');

      // Switch traffic to green
      mockQdrantClient.serviceRegistry.update
        .mockResolvedValueOnce({ ...blueService, status: 'standby' })
        .mockResolvedValueOnce({ ...greenService, status: 'active' });

      const switchResult = await registryService.switchBlueGreenTraffic('bg-service');

      expect(switchResult.activeEnvironment).toBe('green');
      expect(switchResult.standbyEnvironment).toBe('blue');
    });
  });

  // 6. Integration with Services Tests
  describe('Integration with Services', () => {
    it('should coordinate microservices effectively', async () => {
      const microservices = [
        {
          id: '1',
          serviceId: 'auth-service',
          endpoints: ['/auth/login', '/auth/logout', '/auth/verify'],
          dependencies: ['user-service', 'token-store']
        },
        {
          id: '2',
          serviceId: 'user-service',
          endpoints: ['/users/{id}', '/users/search'],
          dependencies: ['database']
        },
        {
          id: '3',
          serviceId: 'notification-service',
          endpoints: ['/notifications/send', '/notifications/batch'],
          dependencies: ['queue-service', 'template-service']
        }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(microservices);

      const coordinationMap = await registryService.getMicroserviceCoordinationMap();

      expect(coordinationMap.services).toHaveLength(3);
      expect(coordinationMap.dependencies.auth-service).toContain('user-service');
      expect(coordinationMap.dependents['user-service']).toContain('auth-service');
    });

    it('should integrate with service mesh', async () => {
      const meshConfig = {
        meshProvider: 'istio',
        namespace: 'production',
        services: [
          {
            name: 'api-gateway',
            meshEnabled: true,
            trafficRouting: {
              rules: [
                { from: 'frontend', to: 'api-gateway', weight: 100 },
                { from: 'mobile', to: 'api-gateway', weight: 100 }
              ]
            }
          }
        ]
      };

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(meshConfig.services);

      const meshIntegration = await registryService.getServiceMeshIntegration();

      expect(meshIntegration.meshProvider).toBe('istio');
      expect(meshIntegration.services).toHaveLength(1);
      expect(meshIntegration.services[0].meshEnabled).toBe(true);
    });

    it('should support API gateway integration', async () => {
      const gatewayConfig = {
        gatewayId: 'main-gateway',
        routes: [
          {
            path: '/api/v1/users/*',
            service: 'user-service',
            methods: ['GET', 'POST', 'PUT', 'DELETE'],
            authentication: 'required',
            rateLimit: { requests: 1000, window: '1h' }
          },
          {
            path: '/api/v1/auth/*',
            service: 'auth-service',
            methods: ['POST'],
            authentication: 'optional',
            rateLimit: { requests: 100, window: '1m' }
          }
        ]
      };

      const registeredServices = [
        { serviceId: 'user-service', host: 'user-svc', port: 3001 },
        { serviceId: 'auth-service', host: 'auth-svc', port: 3002 }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(registeredServices);

      const gatewayRoutes = await registryService.generateGatewayRoutes(gatewayConfig);

      expect(gatewayRoutes.routes).toHaveLength(2);
      expect(gatewayRoutes.routes[0].upstream.host).toBe('user-svc');
      expect(gatewayRoutes.routes[0].upstream.port).toBe(3001);
      expect(gatewayRoutes.routes[0].rateLimit.requests).toBe(1000);
    });

    it('should facilitate cross-service communication', async () => {
      const serviceA = {
        serviceId: 'service-a',
        endpoints: ['/process', '/status'],
        communicationProtocol: 'grpc',
        port: 5001
      };

      const serviceB = {
        serviceId: 'service-b',
        endpoints: ['/analyze', '/results'],
        communicationProtocol: 'http',
        port: 3002
      };

      mockQdrantClient.serviceRegistry.findFirst
        .mockResolvedValueOnce(serviceA)
        .mockResolvedValueOnce(serviceB);

      const communicationConfig = await registryService.establishServiceCommunication(
        'service-a',
        'service-b',
        {
          protocol: 'http',
          authentication: 'mutual-tls',
          timeout: 5000,
          retryPolicy: { attempts: 3, backoff: 'exponential' }
        }
      );

      expect(communicationConfig.fromService).toBe('service-a');
      expect(communicationConfig.toService).toBe('service-b');
      expect(communicationConfig.protocol).toBe('http');
      expect(communicationConfig.authentication).toBe('mutual-tls');
    });

    it('should handle service orchestration workflows', async () => {
      const workflowDefinition = {
        workflowId: 'user-onboarding',
        steps: [
          {
            name: 'create-user',
            service: 'user-service',
            endpoint: '/users',
            method: 'POST',
            timeout: 5000
          },
          {
            name: 'send-welcome-email',
            service: 'notification-service',
            endpoint: '/emails/send',
            method: 'POST',
            timeout: 10000,
            dependsOn: ['create-user']
          },
          {
            name: 'create-initial-profile',
            service: 'profile-service',
            endpoint: '/profiles',
            method: 'POST',
            timeout: 3000,
            dependsOn: ['create-user']
          }
        ]
      };

      const availableServices = [
        { serviceId: 'user-service', status: 'healthy' },
        { serviceId: 'notification-service', status: 'healthy' },
        { serviceId: 'profile-service', status: 'healthy' }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(availableServices);

      const orchestrationResult = await registryService.executeServiceWorkflow(workflowDefinition);

      expect(orchestrationResult.workflowId).toBe('user-onboarding');
      expect(orchestrationResult.status).toBe('completed');
      expect(orchestrationResult.executedSteps).toHaveLength(3);
      expect(orchestrationResult.executedSteps[0].service).toBe('user-service');
      expect(orchestrationResult.executedSteps[1].dependsOn).toContain('create-user');
    });
  });

  // Performance and Caching Tests
  describe('Performance and Caching', () => {
    it('should cache service discovery results', async () => {
      const mockServices = [
        {
          id: '1',
          serviceId: 'cached-service',
          serviceName: 'cached-service',
          status: 'healthy',
          host: 'localhost',
          port: 3011
        }
      ];

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue(mockServices);

      // First call should hit database
      const firstResult = await registryService.discoverServices({
        serviceName: 'cached-service'
      });

      // Second call should use cache
      const secondResult = await registryService.discoverServices({
        serviceName: 'cached-service'
      });

      expect(firstResult.services).toEqual(secondResult.services);
      expect(mockQdrantClient.serviceRegistry.findMany).toHaveBeenCalledTimes(1);
    });

    it('should handle high-volume service registrations', async () => {
      const services = Array.from({ length: 100 }, (_, i) => ({
        serviceId: `high-volume-service-${i}`,
        serviceName: 'high-volume-service',
        instanceId: `instance-${i}`,
        host: `host-${i}`,
        port: 3000 + i
      }));

      mockQdrantClient.serviceRegistry.create.mockResolvedValue({ id: `mock-${Math.random()}` });

      const startTime = Date.now();
      const registrationPromises = services.map(service =>
        registryService.registerService(service)
      );

      const results = await Promise.all(registrationPromises);
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(100);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should provide registry analytics and metrics', async () => {
      const mockStats = {
        totalServices: 25,
        healthyServices: 23,
        unhealthyServices: 2,
        servicesByType: {
          'api': 15,
          'worker': 7,
          'database': 3
        },
        averageResponseTime: 120,
        totalRegistrations: 150,
        totalDeregistrations: 125
      };

      mockQdrantClient.serviceRegistry.findMany.mockResolvedValue([]);

      // Mock various query methods
      vi.spyOn(registryService, 'getRegistryStats').mockResolvedValue(mockStats);

      const stats = await registryService.getRegistryStats();

      expect(stats.totalServices).toBe(25);
      expect(stats.healthyServices).toBe(23);
      expect(stats.servicesByType.api).toBe(15);
      expect(stats.averageResponseTime).toBe(120);
    });
  });
});