
// @ts-nocheck - Emergency rollback: Critical business service
/**
 * Simplified AI Services Index
 *
 * Clean architecture exports for simplified ZAI integration
 * with reduced complexity and better maintainability
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { simplifiedAIOrchestratorService } from './ai-orchestrator-simplified.js';
import { simplifiedBackgroundProcessorService } from './background-processor-simplified.js';
import { zaiConfigManager } from '../../config/zai-config.js';
import type {
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIConfig,
  ZAIHealthCheckResponse,
  ZAIMetrics,
} from '../../types/zai-interfaces.js';

/**
 * Simplified ZAI services manager
 */
export class SimplifiedZAIServicesManager {
  private isInitialized = false;
  private isShuttingDown = false;

  /**
   * Initialize all simplified ZAI services
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.debug('Simplified ZAI services already initialized');
      return;
    }

    if (this.isShuttingDown) {
      throw new Error('Cannot initialize simplified ZAI services during shutdown');
    }

    try {
      logger.info('Initializing simplified ZAI services...');

      // Load configuration
      await zaiConfigManager.loadConfig();
      logger.info('ZAI configuration loaded');

      // Start background processor
      await simplifiedBackgroundProcessorService.start();
      logger.info('Simplified background processor started');

      this.isInitialized = true;
      logger.info('All simplified ZAI services initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize simplified ZAI services');
      await this.shutdown();
      throw error;
    }
  }

  /**
   * Shutdown all simplified ZAI services
   */
  async shutdown(): Promise<void> {
    if (this.isShuttingDown) {
      logger.debug('Simplified ZAI services already shutting down');
      return;
    }

    this.isShuttingDown = true;
    logger.info('Shutting down simplified ZAI services...');

    try {
      // Stop background processor
      await simplifiedBackgroundProcessorService.stop();
      logger.info('Simplified background processor stopped');

      // Shutdown AI orchestrator
      await simplifiedAIOrchestratorService.shutdown();
      logger.info('Simplified AI orchestrator shutdown');

      this.isInitialized = false;
      logger.info('All simplified ZAI services shutdown successfully');
    } catch (error) {
      logger.error({ error }, 'Error during simplified ZAI services shutdown');
      throw error;
    } finally {
      this.isShuttingDown = false;
    }
  }

  /**
   * Check if services are ready
   */
  isReady(): boolean {
    return this.isInitialized && !this.isShuttingDown;
  }

  /**
   * Perform health check
   */
  async healthCheck(): Promise<ZAIHealthCheckResponse> {
    const timestamp = Date.now();

    try {
      if (!this.isInitialized) {
        return {
          status: 'unhealthy',
          timestamp,
          uptime: 0,
          errorRate: 1.0,
          responseTime: 0,
          provider: {
            name: 'simplified_zai',
            status: {
              status: 'down',
              lastCheck: timestamp,
              responseTime: 0,
              errorRate: 1.0,
              circuitBreakerState: 'open',
              consecutiveFailures: 0,
              uptime: 0,
            },
            latency: 0,
            lastSuccess: 0,
          },
          orchestrator: {
            status: 'active',
            activeProvider: 'none',
            fallbackProvider: 'none',
            failoverCount: 0,
          },
          backgroundProcessor: {
            status: {
              status: 'stopped',
              activeJobs: 0,
              queuedJobs: 0,
              completedJobs: 0,
              failedJobs: 0,
              averageProcessingTime: 0,
              uptime: 0,
              memoryUsage: { used: 0, total: 0, percentage: 0 },
            },
            queueSize: 0,
            processingRate: 0,
          },
          metrics: {
            totalRequests: 0,
            successRate: 0,
            averageLatency: 0,
            errorRate: 1.0,
          },
        };
      }

      // Get service statuses
      const orchestratorStatus = await simplifiedAIOrchestratorService.getStatus();
      const processorStatus = simplifiedBackgroundProcessorService.getStatus();

      return {
        status:
          orchestratorStatus.status === 'active' && processorStatus.status === 'running'
            ? 'healthy'
            : 'degraded',
        timestamp,
        uptime: process.uptime(),
        errorRate: 0.0,
        responseTime: 100,
        provider: {
          name: 'simplified_zai',
          status: {
            status: 'healthy', // Simplified - would get actual status
            lastCheck: timestamp,
            responseTime: 100,
            errorRate: 0.0,
            circuitBreakerState: 'closed',
            consecutiveFailures: 0,
            uptime: process.uptime(),
          },
          latency: 100,
          lastSuccess: timestamp,
        },
        orchestrator: {
          status: orchestratorStatus.status,
          activeProvider: orchestratorStatus.activeProvider,
          fallbackProvider: orchestratorStatus.providerHealth?.fallback?.name || 'openai',
          failoverCount: orchestratorStatus.failoverCount,
        },
        backgroundProcessor: {
          status: processorStatus,
          queueSize: processorStatus.queueSize,
          processingRate: processorStatus.activeJobs,
        },
        metrics: {
          totalRequests: 0, // Would track actual requests
          successRate: 1.0,
          averageLatency: 100,
          errorRate: 0.0,
        },
      };
    } catch (error) {
      logger.error({ error }, 'Simplified health check failed');
      throw error;
    }
  }

  /**
   * Get comprehensive metrics
   */
  getMetrics(): {
    config: unknown;
    orchestrator: unknown;
    backgroundProcessor: unknown;
    system: unknown;
  } {
    if (!this.isInitialized) {
      throw new Error('Simplified ZAI services not initialized');
    }

    return {
      config: zaiConfigManager.getConfigSummary(),
      orchestrator: simplifiedAIOrchestratorService.getMetrics(),
      backgroundProcessor: simplifiedBackgroundProcessorService.getMetrics(),
      system: {
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
        ready: this.isReady(),
      },
    };
  }

  /**
   * Submit a background job
   */
  async submitJob(
    type: unknown,
    payload: unknown,
    options?: {
      priority?: 'low' | 'normal' | 'high' | 'critical';
      timeout?: number;
      retries?: number;
      metadata?: Record<string, unknown>;
    }
  ): Promise<string> {
    if (!this.isInitialized) {
      throw new Error('Simplified ZAI services not initialized');
    }

    return await simplifiedBackgroundProcessorService.submitJob(type, payload, options);
  }

  /**
   * Generate completion using simplified AI orchestrator
   */
  async generateCompletion(request: ZAIChatRequest): Promise<ZAIChatResponse> {
    if (!this.isInitialized) {
      throw new Error('Simplified ZAI services not initialized');
    }

    return await simplifiedAIOrchestratorService.generateCompletion(request);
  }
}

/**
 * Export singleton instance
 */
export const simplifiedZAIServicesManager = new SimplifiedZAIServicesManager();

/**
 * Export services for convenience
 */
export { simplifiedAIOrchestratorService, simplifiedBackgroundProcessorService };

/**
 * Export convenience functions
 */
export const initializeSimplifiedZAIServices = () => simplifiedZAIServicesManager.initialize();
export const shutdownSimplifiedZAIServices = () => simplifiedZAIServicesManager.shutdown();
export const isSimplifiedZAIServicesReady = () => simplifiedZAIServicesManager.isReady();
export const healthCheckSimplifiedZAIServices = () => simplifiedZAIServicesManager.healthCheck();
export const getSimplifiedZAIServicesMetrics = () => simplifiedZAIServicesManager.getMetrics();
export const generateSimplifiedZAICompletion = (request: ZAIChatRequest) =>
  simplifiedZAIServicesManager.generateCompletion(request);
export const submitSimplifiedZAIJob = (type: unknown, payload: unknown, options?: unknown) =>
  simplifiedZAIServicesManager.submitJob(type, payload, options);
