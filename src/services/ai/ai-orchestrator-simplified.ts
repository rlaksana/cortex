/**
 * Simplified AI Orchestrator Service
 *
 * Clean architecture AI orchestrator using provider manager
 * with reduced complexity and clear separation of concerns
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { AIProviderManager } from './provider-manager.js';
import { zaiConfigManager } from '../../config/zai-config.js';
import type {
  AIOrchestratorConfig,
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIEventListener,
  ZAIStreamChunk,
} from '../../types/zai-interfaces.js';

/**
 * Simplified AI orchestrator service with reduced complexity
 */
export class SimplifiedAIOrchestratorService {
  private config: AIOrchestratorConfig;
  private providerManager: AIProviderManager;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metrics = {
    uptime: Date.now(),
    healthChecks: 0,
    lastHealthCheck: 0,
  };

  constructor(config?: AIOrchestratorConfig) {
    this.config = config || zaiConfigManager.getOrchestratorConfig();

    // Transform config to match AIProviderManager expectations
    const providerManagerConfig = {
      primaryProvider: this.config.primaryProvider,
      fallbackProvider: this.config.fallbackProvider,
      providerConfigs: {
        zai: {
          model: this.config.providerConfigs.zai.model,
          ...(this.config.providerConfigs.zai as unknown as Record<string, unknown>)
        } as { model: string; [key: string]: unknown },
        openai: this.config.providerConfigs.openai as { model?: string; [key: string]: unknown } || {}
      }
    };

    this.providerManager = new AIProviderManager(providerManagerConfig);

    // Start health monitoring if enabled
    if (this.config.healthCheckInterval > 0) {
      this.startHealthMonitoring();
    }

    logger.info(
      {
        primaryProvider: this.config.primaryProvider,
        fallbackProvider: this.config.fallbackProvider,
        autoFailover: this.config.autoFailover,
        healthCheckInterval: this.config.healthCheckInterval,
      },
      'Simplified AI Orchestrator initialized'
    );
  }

  /**
   * Generate completion with simplified failover logic
   */
  async generateCompletion(request: ZAIChatRequest): Promise<ZAIChatResponse> {
    return await this.providerManager.generateCompletion(request);
  }

  /**
   * Generate streaming completion
   */
  async *generateStreamingCompletion(request: ZAIChatRequest): AsyncGenerator<ZAIStreamChunk> {
    yield* this.providerManager.generateStreamingCompletion(request);
  }

  /**
   * Get comprehensive status
   */
  async getStatus(): Promise<{
    status: 'active' | 'failed_over' | 'degraded';
    activeProvider: string;
    providerHealth: {
      primary: { name: string; available: boolean };
      fallback: { name: string; available: boolean };
    };
    failoverCount: number;
    uptime: number;
    healthCheckMetrics: {
      totalChecks: number;
      lastCheck: number;
      interval: number;
    };
  }> {
    const providerStatus = await this.providerManager.getStatus();

    return {
      status: this.determineOverallStatus(providerStatus),
      activeProvider: providerStatus.activeProvider,
      providerHealth: {
        primary: providerStatus.primaryProvider,
        fallback: providerStatus.fallbackProvider,
      },
      failoverCount: providerStatus.failoverCount,
      uptime: Date.now() - this.metrics.uptime,
      healthCheckMetrics: {
        totalChecks: this.metrics.healthChecks,
        lastCheck: this.metrics.lastHealthCheck,
        interval: this.config.healthCheckInterval,
      },
    };
  }

  /**
   * Get metrics from all providers
   */
  getMetrics(): {
    providers: Record<string, unknown>;
    orchestrator: {
      totalRequests: number;
      successfulRequests: number;
      failedRequests: number;
      averageLatency: number;
      p95Latency: number;
      circuitBreakerTrips: number;
      activeProviders: number;
    };
  } {
    return {
      providers: this.providerManager.getMetrics() as unknown as Record<string, unknown>,
      orchestrator: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        averageLatency: 0,
        p95Latency: 0,
        circuitBreakerTrips: 0,
        activeProviders: 1,
      },
    };
  }

  /**
   * Manually switch active provider
   */
  async switchProvider(providerName: 'zai' | 'openai'): Promise<void> {
    await this.providerManager.switchProvider(providerName);
  }

  /**
   * Add event listener
   */
  addEventListener(listener: ZAIEventListener): void {
    this.providerManager.addEventListener(listener);
  }

  /**
   * Reset all providers and orchestrator state
   */
  reset(): void {
    this.providerManager.reset();
    this.metrics.healthChecks = 0;
    this.metrics.lastHealthCheck = 0;

    logger.info('Reset simplified AI orchestrator');
  }

  /**
   * Shutdown orchestrator and cleanup
   */
  async shutdown(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    this.providerManager.reset();
    logger.info('Simplified AI orchestrator shutdown complete');
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(
      async function (this: SimplifiedAIOrchestratorService): Promise<void> {
        await this.performHealthCheck();
      }.bind(this),
      this.config.healthCheckInterval
    );

    logger.info(
      {
        interval: this.config.healthCheckInterval,
      },
      'Started simplified AI orchestrator health monitoring'
    );
  }

  /**
   * Perform health check on providers
   */
  private async performHealthCheck(): Promise<void> {
    try {
      this.metrics.healthChecks++;
      this.metrics.lastHealthCheck = Date.now();

      // Check primary provider health and trigger failback if needed
      await this.providerManager.checkPrimaryHealth();

      logger.debug(
        {
          healthChecks: this.metrics.healthChecks,
          lastCheck: this.metrics.lastHealthCheck,
        },
        'Health check completed'
      );
    } catch (error) {
      logger.error({ error }, 'Health check failed');
    }
  }

  /**
   * Determine overall status based on provider health
   */
  private determineOverallStatus(providerStatus: {
    activeProvider: string;
    primaryProvider: { name: string; available: boolean };
    fallbackProvider: { name: string; available: boolean };
  }): 'active' | 'failed_over' | 'degraded' {
    const { activeProvider, primaryProvider, fallbackProvider } = providerStatus;

    if (activeProvider === primaryProvider.name) {
      return primaryProvider.available ? 'active' : 'degraded';
    } else {
      return fallbackProvider.available ? 'failed_over' : 'degraded';
    }
  }
}

/**
 * Export singleton instance
 */
export const simplifiedAIOrchestratorService = new SimplifiedAIOrchestratorService();

/**
 * Export service class for testing
 */
export { SimplifiedAIOrchestratorService as AIOrchestratorService };
