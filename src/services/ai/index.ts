
/**
 * ZAI Services Integration Index
 *
 * Central export point for all ZAI services with initialization,
 * health monitoring, and graceful startup/shutdown coordination
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { AIOrchestratorService,aiOrchestratorService } from './ai-orchestrator.service';
import {
  BackgroundProcessorService,
  backgroundProcessorService,
} from './background-processor.service';
import { ZAIClientService,zaiClientService } from './zai-client.service';
import { zaiConfigManager } from '../../config/zai-config.js';
import type {
  AIOrchestratorConfig,
  BackgroundProcessorConfig,
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIConfig,
  ZAIHealthCheckResponse,
  ZAIMetrics,
} from '../../types/zai-interfaces.js';

/**
 * ZAI services manager
 */
export class ZAIServicesManager {
  private static instance: ZAIServicesManager;
  private isInitialized = false;
  private isShuttingDown = false;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  private constructor() {}

  /**
   * Get singleton instance
   */
  static getInstance(): ZAIServicesManager {
    if (!ZAIServicesManager.instance) {
      ZAIServicesManager.instance = new ZAIServicesManager();
    }
    return ZAIServicesManager.instance;
  }

  /**
   * Initialize all ZAI services
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.debug('ZAI services already initialized');
      return;
    }

    if (this.isShuttingDown) {
      throw new Error('Cannot initialize ZAI services during shutdown');
    }

    try {
      logger.info('Initializing ZAI services...');

      // Step 1: Load configuration
      await zaiConfigManager.loadConfig();
      logger.info('ZAI configuration loaded');

      // Step 2: Initialize ZAI client service
      await this.initializeZAIClient();
      logger.info('ZAI client service initialized');

      // Step 3: Initialize AI orchestrator service
      await this.initializeAIOrchestrator();
      logger.info('AI orchestrator service initialized');

      // Step 4: Start background processor
      await this.startBackgroundProcessor();
      logger.info('Background processor started');

      // Step 5: Start health monitoring
      this.startHealthMonitoring();

      this.isInitialized = true;
      logger.info('All ZAI services initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize ZAI services');
      await this.shutdown(); // Cleanup partially initialized services
      throw error;
    }
  }

  /**
   * Shutdown all ZAI services gracefully
   */
  async shutdown(): Promise<void> {
    if (this.isShuttingDown) {
      logger.debug('ZAI services already shutting down');
      return;
    }

    this.isShuttingDown = true;
    logger.info('Shutting down ZAI services...');

    try {
      // Stop health monitoring
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
        this.healthCheckInterval = null;
      }

      // Stop background processor
      try {
        await backgroundProcessorService.stop();
        logger.info('Background processor stopped');
      } catch (error) {
        logger.warn({ error }, 'Error stopping background processor');
      }

      // Shutdown AI orchestrator
      try {
        await aiOrchestratorService.shutdown();
        logger.info('AI orchestrator shutdown');
      } catch (error) {
        logger.warn({ error }, 'Error shutting down AI orchestrator');
      }

      // Reset ZAI client
      try {
        zaiClientService.reset();
        logger.info('ZAI client reset');
      } catch (error) {
        logger.warn({ error }, 'Error resetting ZAI client');
      }

      this.isInitialized = false;
      logger.info('All ZAI services shutdown successfully');
    } catch (error) {
      logger.error({ error }, 'Error during ZAI services shutdown');
      throw error;
    } finally {
      this.isShuttingDown = false;
    }
  }

  /**
   * Check if services are initialized
   */
  isReady(): boolean {
    return this.isInitialized && !this.isShuttingDown;
  }

  /**
   * Perform comprehensive health check
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
            name: 'zai',
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
      const orchestratorStatus = await aiOrchestratorService.getStatus();
      const processorStatus = backgroundProcessorService.getStatus();
      const zaiMetrics = zaiClientService.getMetrics();

      return {
        status:
          orchestratorStatus.status === 'active' && processorStatus.status === 'running'
            ? 'healthy'
            : 'degraded',
        timestamp,
        uptime: process.uptime(),
        errorRate: zaiMetrics.errorRate,
        responseTime: zaiMetrics.averageResponseTime,
        provider: {
          name: 'zai',
          status: await zaiClientService.getServiceStatus(),
          latency: zaiMetrics.averageResponseTime,
          lastSuccess: timestamp,
        },
        orchestrator: {
          status: orchestratorStatus.status,
          activeProvider: orchestratorStatus.activeProvider,
          fallbackProvider: typeof orchestratorStatus.fallbackProvider === 'string'
            ? orchestratorStatus.fallbackProvider
            : orchestratorStatus.fallbackProvider?.name || 'openai',
          failoverCount: orchestratorStatus.failoverCount,
        },
        backgroundProcessor: {
          status: processorStatus,
          queueSize: processorStatus.queuedJobs,
          processingRate: processorStatus.activeJobs,
        },
        metrics: {
          totalRequests: zaiMetrics.totalRequests,
          successRate:
            zaiMetrics.totalRequests > 0
              ? zaiMetrics.successfulRequests / zaiMetrics.totalRequests
              : 0,
          averageLatency: zaiMetrics.averageResponseTime,
          errorRate: zaiMetrics.errorRate,
        },
      } as unknown as ZAIHealthCheckResponse;
    } catch (error) {
      logger.error({ error }, 'Health check failed');
      return {
        status: 'unhealthy',
        timestamp,
        uptime: 0,
        errorRate: 1.0,
        responseTime: 0,
        provider: {
          name: 'zai',
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
          status: 'degraded',
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
  }

  /**
   * Get comprehensive metrics
   */
  getMetrics(): {
    config: any;
    zai: ZAIMetrics;
    orchestrator: any;
    backgroundProcessor: any;
    system: any;
  } {
    if (!this.isInitialized) {
      throw new Error('ZAI services not initialized');
    }

    return {
      config: zaiConfigManager.getConfigSummary(),
      zai: zaiClientService.getMetrics(),
      orchestrator: aiOrchestratorService.getMetrics(),
      backgroundProcessor: backgroundProcessorService.getMetrics(),
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
    type: any,
    payload: any,
    options?: {
      priority?: 'low' | 'normal' | 'high' | 'critical';
      timeout?: number;
      retries?: number;
      metadata?: Record<string, any>;
    }
  ): Promise<string> {
    if (!this.isInitialized) {
      throw new Error('ZAI services not initialized');
    }

    return await backgroundProcessorService.submitJob(type, payload, options);
  }

  /**
   * Generate completion using AI orchestrator
   */
  async generateCompletion(request: ZAIChatRequest): Promise<ZAIChatResponse> {
    if (!this.isInitialized) {
      throw new Error('ZAI services not initialized');
    }

    return await aiOrchestratorService.generateCompletion(request);
  }

  /**
   * Initialize ZAI client service
   */
  private async initializeZAIClient(): Promise<void> {
    // Test ZAI client availability
    const isAvailable = await zaiClientService.isAvailable();
    if (!isAvailable) {
      logger.warn('ZAI client is not available during initialization');
    }
  }

  /**
   * Initialize AI orchestrator service
   */
  private async initializeAIOrchestrator(): Promise<void> {
    // AI orchestrator is already initialized in constructor
    // This method is for future enhancements
  }

  /**
   * Start background processor
   */
  private async startBackgroundProcessor(): Promise<void> {
    await backgroundProcessorService.start();
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(
      async function(this: ZAIServicesManager): Promise<void> {
        try {
          const health = await this.healthCheck();

          // Log health status changes
          if (health.status !== 'healthy') {
            logger.warn({ health }, 'ZAI services health check warning');
          }
        } catch (error) {
          logger.error({ error }, 'ZAI services health check failed');
        }
      }.bind(this),
      60000
    ); // Check every minute

    logger.info('Health monitoring started');
  }
}

/**
 * Export singleton instance
 */
export const zaiServicesManager = ZAIServicesManager.getInstance();

/**
 * Export service classes for testing
 */
export { AIOrchestratorService, BackgroundProcessorService,ZAIClientService };

/**
 * Export convenience functions
 */
export const initializeZAIServices = () => zaiServicesManager.initialize();
export const shutdownZAIServices = () => zaiServicesManager.shutdown();
export const isZAIServicesReady = () => zaiServicesManager.isReady();
export const healthCheckZAIServices = () => zaiServicesManager.healthCheck();
export const getZAIServicesMetrics = () => zaiServicesManager.getMetrics();
export const generateZAICompletion = (request: ZAIChatRequest) =>
  zaiServicesManager.generateCompletion(request);
export const submitZAIJob = (type: any, payload: any, options?: any) =>
  zaiServicesManager.submitJob(type, payload, options);

/**
 * Export services and configuration
 */
export { aiOrchestratorService, backgroundProcessorService, zaiClientService, zaiConfigManager };

/**
 * Export types
 */
export type {
  AIOrchestratorConfig,
  BackgroundProcessorConfig,
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIConfig,
  ZAIHealthCheckResponse,
  ZAIMetrics,
};
