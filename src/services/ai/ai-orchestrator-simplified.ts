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
import { zaiConfigManager } from '../../config/zai-config';
import { AIProviderManager } from './provider-manager';
import type {
  AIOrchestratorConfig,
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIStreamChunk,
  ZAIEvent,
  ZAIEventListener,
} from '../../types/zai-interfaces';

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
    this.providerManager = new AIProviderManager(this.config);

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
    providers: Record<string, any>;
    orchestrator: typeof this.metrics;
  } {
    return {
      providers: this.providerManager.getMetrics(),
      orchestrator: { ...this.metrics },
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
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthCheck();
    }, this.config.healthCheckInterval);

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
  private determineOverallStatus(providerStatus: any): 'active' | 'failed_over' | 'degraded' {
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
