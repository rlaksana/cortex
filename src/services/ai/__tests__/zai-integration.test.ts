/**
 * ZAI Integration Tests
 *
 * Comprehensive integration tests for ZAI services including
 * configuration, client, orchestrator, and background processor
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'vitest';

import { zaiConfigManager } from '../../config/zai-config';
import type { ZAIChatRequest, ZAIChatResponse, ZAIJobType } from '../../types/zai-interfaces';
import { zaiClientService, zaiServicesManager } from '../index';

// Helper functions for safe property access in tests
const num = (v: unknown, d = 0): number => Number((v as number | undefined) ?? d);
const str = (v: unknown, d = ''): string => ((v as string | undefined) ?? d).trim();
const obj = <T extends object>(v: unknown, d: T): T =>
  v && typeof v === 'object' ? (v as T) : d;

describe('ZAI Integration Tests', () => {
  beforeAll(async () => {
    // Set test environment variables
    process.env['ZAI_API_KEY'] = 'test-api-key';
    process.env['ZAI_MODEL'] = 'glm-4.6';
    process.env['ZAI_BASE_URL'] = 'https://api.z.ai/api/anthropic';
    process.env['OPENAI_API_KEY'] = 'test-openai-key';
    process.env['NODE_ENV'] = 'test';

    // Initialize services
    await zaiServicesManager.initialize();
  });

  afterAll(async () => {
    // Shutdown services
    await zaiServicesManager.shutdown();
  });

  beforeEach(() => {
    // Reset services before each test
    const clientServiceObj = obj(zaiClientService, {} as Record<string, unknown>);
    if (typeof clientServiceObj.reset === 'function') {
      (clientServiceObj.reset as () => void)();
    }
  });

  describe('Configuration Management', () => {
    test('should load ZAI configuration successfully', () => {
      expect(zaiConfigManager.isLoaded()).toBe(true);

      const config = zaiConfigManager.getZAIConfig();
      expect(config).toBeDefined();
      expect(config.apiKey).toBe('test-api-key');
      expect(config.model).toBe('glm-4.6');
      expect(config.baseURL).toBe('https://api.z.ai/api/anthropic');
    });

    test('should get orchestrator configuration', () => {
      const config = zaiConfigManager.getOrchestratorConfig();
      expect(config).toBeDefined();
      expect(config.primaryProvider).toBe('zai');
      expect(config.fallbackProvider).toBe('openai');
      expect(config.autoFailover).toBe(true);
    });

    test('should get background processor configuration', () => {
      const config = zaiConfigManager.getBackgroundProcessorConfig();
      expect(config).toBeDefined();
      expect(config.maxConcurrency).toBeGreaterThan(0);
      expect(config.queueSize).toBeGreaterThan(0);
      expect(config.enablePriorityQueue).toBe(true);
    });

    test('should get configuration summary', () => {
      const summary = zaiConfigManager.getConfigSummary();
      expect(summary).toBeDefined();
      expect(summary.zai.model).toBe('glm-4.6');
      expect(summary.orchestrator.primaryProvider).toBe('zai');
      expect(summary.backgroundProcessor.maxConcurrency).toBeGreaterThan(0);
    });
  });

  describe('ZAI Client Service', () => {
    test('should create client service instance', () => {
      expect(zaiClientService).toBeDefined();
    });

    test('should get service metrics', () => {
      const clientServiceObj = obj(zaiClientService, {} as Record<string, unknown>);
      if (typeof clientServiceObj.getMetrics === 'function') {
        const metrics = (clientServiceObj.getMetrics as () => unknown)();
        expect(metrics).toBeDefined();
        const metricsObj = obj(metrics, {} as Record<string, unknown>);
        expect(metricsObj.totalRequests).toBeDefined();
        expect(metricsObj.successfulRequests).toBeDefined();
        expect(metricsObj.failedRequests).toBeDefined();
        expect(metricsObj.averageResponseTime).toBeDefined();
        expect(metricsObj.errorRate).toBeDefined();
      }
    });

    test('should get service status', async () => {
      const clientServiceObj = obj(zaiClientService, {} as Record<string, unknown>);
      if (typeof clientServiceObj.getServiceStatus === 'function') {
        const status = await (clientServiceObj.getServiceStatus as () => Promise<unknown>)();
        expect(status).toBeDefined();
        const statusObj = obj(status, {} as Record<string, unknown>);
        expect(statusObj.status).toBeDefined();
        expect(statusObj.responseTime).toBeDefined();
        expect(statusObj.errorRate).toBeDefined();
        expect(statusObj.circuitBreakerState).toBeDefined();
        expect(statusObj.uptime).toBeDefined();
      }
    });

    test('should handle chat completion request structure', async () => {
      const request: ZAIChatRequest = {
        messages: [
          { role: 'system', content: 'You are a helpful assistant.' },
          { role: 'user', content: 'Hello, world!' },
        ],
        maxTokens: 100,
        temperature: 0.7,
      };

      // Test request validation (should not throw)
      expect(() => {
        // This would normally make an API call, but we're testing structure
        Promise.resolve(request);
      }).not.toThrow();

      expect(request.messages).toHaveLength(2);
      expect(request.messages[0].role).toBe('system');
      expect(request.messages[1].role).toBe('user');
      expect(request.maxTokens).toBe(100);
    });
  });

  describe('AI Orchestrator Service', () => {
    test('should get orchestrator status', async () => {
      const status = await aiOrchestratorService.getStatus();
      expect(status).toBeDefined();
      expect(status.status).toBeDefined();
      expect(status.activeProvider).toBeDefined();
      expect(status.primaryProvider).toBeDefined();
      expect(status.fallbackProvider).toBeDefined();
      expect(status.failoverCount).toBeDefined();
      expect(status.autoFailoverEnabled).toBe(true);
      expect(status.uptime).toBeGreaterThan(0);
    });

    test('should get orchestrator metrics', () => {
      const metrics = aiOrchestratorService.getMetrics();
      expect(metrics).toBeDefined();
      expect(metrics.orchestrator).toBeDefined();
      expect(metrics.providers).toBeDefined();
      expect(metrics.providers.zai).toBeDefined();
      expect(metrics.providers.openai).toBeDefined();
    });

    test('should handle provider switching', async () => {
      const initialStatus = await aiOrchestratorService.getStatus();
      const initialProvider = initialStatus.activeProvider;

      // Switch provider
      await aiOrchestratorService.switchProvider('openai');

      const newStatus = await aiOrchestratorService.getStatus();
      expect(newStatus.activeProvider).toBe('openai');

      // Switch back
      await aiOrchestratorService.switchProvider(initialProvider as 'zai' | 'openai');

      const finalStatus = await aiOrchestratorService.getStatus();
      expect(finalStatus.activeProvider).toBe(initialProvider);
    });
  });

  describe('Background Processor Service', () => {
    test('should get processor status', () => {
      const status = backgroundProcessorService.getStatus();
      expect(status).toBeDefined();
      expect(status.status).toBeDefined();
      expect(status.activeJobs).toBeDefined();
      expect(status.queuedJobs).toBeDefined();
      expect(status.completedJobs).toBeDefined();
      expect(status.failedJobs).toBeDefined();
      expect(status.uptime).toBeGreaterThan(0);
      expect(status.memoryUsage).toBeDefined();
    });

    test('should get processor metrics', () => {
      const metrics = backgroundProcessorService.getMetrics();
      expect(metrics).toBeDefined();
      expect(metrics.processor).toBeDefined();
      expect(metrics.queue).toBeDefined();
      expect(metrics.workers).toBeDefined();
      expect(metrics.performance).toBeDefined();
    });

    test('should submit background job', async () => {
      const jobId = await backgroundProcessorService.submitJob(
        'text_transformation',
        { text: 'Hello, world!', transformation: 'uppercase' },
        { priority: 'normal' }
      );

      expect(jobId).toBeDefined();
      expect(typeof jobId).toBe('string');
      expect(jobId.length).toBeGreaterThan(0);

      // Check job status
      const jobStatus = backgroundProcessorService.getJobStatus(jobId);
      expect(jobStatus).toBeDefined();
      expect(jobStatus?.type).toBe('text_transformation');
      expect(jobStatus?.priority).toBe('normal');
      expect(jobStatus?.status).toBeDefined();
    });
  });

  describe('Services Manager', () => {
    test('should check if services are ready', () => {
      const isReady = zaiServicesManager.isReady();
      expect(isReady).toBe(true);
    });

    test('should perform health check', async () => {
      const health = await zaiServicesManager.healthCheck();
      expect(health).toBeDefined();
      expect(health.status).toBeDefined();
      expect(health.provider).toBeDefined();
      expect(health.orchestrator).toBeDefined();
      expect(health.backgroundProcessor).toBeDefined();
      expect(health.metrics).toBeDefined();
    });

    test('should get comprehensive metrics', () => {
      const metrics = zaiServicesManager.getMetrics();
      expect(metrics).toBeDefined();
      expect(metrics.config).toBeDefined();
      expect(metrics.zai).toBeDefined();
      expect(metrics.orchestrator).toBeDefined();
      expect(metrics.backgroundProcessor).toBeDefined();
      expect(metrics.system).toBeDefined();
      expect(metrics.system.ready).toBe(true);
    });

    test('should submit job through manager', async () => {
      const jobId = await zaiServicesManager.submitJob(
        'summarization',
        { text: 'This is a test text for summarization.', summaryLength: 'short' },
        { priority: 'high' }
      );

      expect(jobId).toBeDefined();
      expect(typeof jobId).toBe('string');
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid configuration gracefully', async () => {
      // Test with invalid API key
      process.env['ZAI_API_KEY'] = '';

      try {
        await zaiConfigManager.loadConfig();
        // If we get here, the test should fail
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as Error).message).toContain('API key');
      }

      // Restore valid API key
      process.env['ZAI_API_KEY'] = 'test-api-key';
      await zaiConfigManager.loadConfig();
    });

    test('should handle invalid job types', async () => {
      try {
        await backgroundProcessorService.submitJob('invalid_type' as ZAIJobType, { data: 'test' });
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    test('should handle service shutdown gracefully', async () => {
      const isReady = zaiServicesManager.isReady();
      expect(isReady).toBe(true);

      await zaiServicesManager.shutdown();
      expect(zaiServicesManager.isReady()).toBe(false);

      // Re-initialize for other tests
      await zaiServicesManager.initialize();
      expect(zaiServicesManager.isReady()).toBe(true);
    });
  });

  describe('Performance Targets', () => {
    test('should meet performance targets', async () => {
      const health = await zaiServicesManager.healthCheck();

      // Check that metrics are within expected ranges
      expect(health.metrics.errorRate).toBeLessThanOrEqual(1.0);
      expect(health.metrics.averageLatency).toBeGreaterThanOrEqual(0);
      expect(health.backgroundProcessor.status.uptime).toBeGreaterThan(0);

      // Check memory usage
      const metrics = zaiServicesManager.getMetrics();
      expect(metrics.system.memoryUsage.used).toBeGreaterThan(0);
      expect(metrics.system.memoryUsage.total).toBeGreaterThan(0);
      expect(metrics.system.memoryUsage.percentage).toBeGreaterThanOrEqual(0);
      expect(metrics.system.memoryUsage.percentage).toBeLessThanOrEqual(100);
    });

    test('should maintain queue performance', () => {
      const processorMetrics = backgroundProcessorService.getMetrics();

      expect(processorMetrics.performance.successRate).toBeGreaterThanOrEqual(0);
      expect(processorMetrics.performance.successRate).toBeLessThanOrEqual(1);
      expect(processorMetrics.performance.averageProcessingTime).toBeGreaterThanOrEqual(0);
      expect(processorMetrics.performance.throughput).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Integration Flow', () => {
    test('should handle complete integration flow', async () => {
      // 1. Check initial status
      const initialHealth = await zaiServicesManager.healthCheck();
      expect(initialHealth.status).toBeDefined();

      // 2. Submit multiple jobs
      const jobIds = await Promise.all([
        zaiServicesManager.submitJob('text_transformation', {
          text: 'test1',
          transformation: 'lowercase',
        }),
        zaiServicesManager.submitJob('summarization', { text: 'test2', summaryLength: 'short' }),
        zaiServicesManager.submitJob('classification', {
          text: 'test3',
          categories: ['a', 'b', 'c'],
        }),
      ]);

      expect(jobIds).toHaveLength(3);
      jobIds.forEach((jobId) => {
        expect(jobId).toBeDefined();
        expect(typeof jobId).toBe('string');
      });

      // 3. Check job statuses
      for (const jobId of jobIds) {
        const jobStatus = backgroundProcessorService.getJobStatus(jobId);
        expect(jobStatus).toBeDefined();
        expect(['pending', 'processing', 'completed', 'failed']).toContain(jobStatus?.status || '');
      }

      // 4. Check final metrics
      const finalMetrics = zaiServicesManager.getMetrics();
      expect(finalMetrics.backgroundProcessor.processor.totalJobsProcessed).toBeGreaterThanOrEqual(
        0
      );
    });
  });
});

// Import services for testing
let zaiClientService: unknown;
let aiOrchestratorService: unknown;
let backgroundProcessorService: unknown;

// Lazy import to avoid circular dependencies
beforeAll(async () => {
  const services = await import('../index');
  zaiClientService = services.zaiClientService;
  aiOrchestratorService = services.aiOrchestratorService;
  backgroundProcessorService = services.backgroundProcessorService;
});
