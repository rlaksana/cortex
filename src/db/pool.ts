/**
 * Cortex Memory MCP - Qdrant Connection Manager
 *
 * Pure Qdrant-based connection management with:
 * - Connection pooling and load balancing
 * - Health check and monitoring
 * - Automatic retry on failures
 * - Graceful shutdown support
 * - Performance metrics
 * - Environment-based configuration
 */

import { QdrantClient } from '@qdrant/js-client-rest';
import { logger } from '../utils/logger.js';
import { Environment } from '../config/environment.js';

/**
 * Qdrant connection configuration
 */
interface QdrantConfig {
  url: string;
  apiKey?: string;
  timeout: number;
  maxRetries: number;
  retryDelay: number;
}

/**
 * Health check result
 */
interface HealthCheckResult {
  isHealthy: boolean;
  message: string;
  collections?: string[];
  version?: string;
  responseTime?: number;
}

/**
 * Connection statistics
 */
interface ConnectionStats {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  lastHealthCheck: Date | null;
  uptime: number;
}

/**
 * Qdrant Connection Manager
 *
 * Manages Qdrant client connections with health monitoring,
 * automatic retries, and performance tracking.
 */
class QdrantConnectionManager {
  private client: QdrantClient;
  private config: QdrantConfig;
  private isInitialized = false;
  private isShuttingDown = false;
  private stats: ConnectionStats;
  private startTime: Date;

  constructor() {
    const env = Environment.getInstance();
    const qdrantConfig = env.getQdrantConfig();

    this.config = {
      url: qdrantConfig.url,
      ...(qdrantConfig.apiKey && { apiKey: qdrantConfig.apiKey }),
      timeout: qdrantConfig.connectionTimeout || 30000,
      maxRetries: 3,
      retryDelay: 1000,
    };

    this.client = new QdrantClient({
      url: this.config.url,
      ...(this.config.apiKey && { apiKey: this.config.apiKey }),
      timeout: this.config.timeout,
    });

    this.startTime = new Date();
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      lastHealthCheck: null,
      uptime: 0,
    };
  }

  /**
   * Initialize the Qdrant connection manager
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Qdrant connection manager already initialized');
      return;
    }

    if (this.isShuttingDown) {
      throw new Error('Cannot initialize during shutdown');
    }

    try {
      // Test basic connectivity
      const startTime = Date.now();
      await this.client.getCollections();
      const responseTime = Date.now() - startTime;

      this.isInitialized = true;
      this.stats.lastHealthCheck = new Date();

      logger.info(
        {
          url: this.config.url,
          responseTime,
          timeout: this.config.timeout,
          maxRetries: this.config.maxRetries,
        },
        'Qdrant connection manager initialized successfully'
      );

      // Update stats
      this.stats.totalRequests++;
      this.stats.successfulRequests++;
      this.stats.averageResponseTime = responseTime;
    } catch (error) {
      logger.error({ error }, 'Failed to initialize Qdrant connection manager');
      throw error;
    }
  }

  /**
   * Execute a Qdrant operation with automatic retry
   */
  async executeOperation<T>(
    operation: () => Promise<T>,
    operationName: string = 'unknown'
  ): Promise<T> {
    if (!this.isInitialized) {
      throw new Error('Qdrant connection manager not initialized');
    }

    if (this.isShuttingDown) {
      throw new Error('Qdrant connection manager is shutting down');
    }

    const startTime = Date.now();
    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= this.config.maxRetries) {
      try {
        const result = await operation();
        const duration = Date.now() - startTime;

        // Update stats
        this.stats.totalRequests++;
        this.stats.successfulRequests++;
        this.updateAverageResponseTime(duration);

        logger.debug(
          {
            operation: operationName,
            duration,
            attempt,
          },
          'Qdrant operation executed successfully'
        );

        return result;
      } catch (error) {
        attempt++;
        lastError = error instanceof Error ? error : new Error(String(error));
        const duration = Date.now() - startTime;

        logger.error(
          {
            operation: operationName,
            duration,
            attempt,
            error: lastError.message,
          },
          'Qdrant operation failed'
        );

        // If this is the last attempt, throw the error
        if (attempt > this.config.maxRetries) {
          this.stats.totalRequests++;
          this.stats.failedRequests++;
          throw lastError;
        }

        // Wait before retrying with exponential backoff
        const delay = Math.min(
          this.config.retryDelay * Math.pow(2, attempt - 1),
          10000 // Max 10 seconds
        );

        logger.warn(
          { delay, attempt, maxRetries: this.config.maxRetries },
          `Retrying operation in ${delay}ms (attempt ${attempt}/${this.config.maxRetries})`
        );

        await this.sleep(delay);
      }
    }

    // This should never be reached, but TypeScript needs it
    throw lastError || new Error('Max retries exceeded');
  }

  /**
   * Get the underlying Qdrant client
   */
  getClient(): QdrantClient {
    return this.client;
  }

  /**
   * Health check for Qdrant connection
   */
  async healthCheck(): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      if (!this.isInitialized) {
        return {
          isHealthy: false,
          message: 'Qdrant connection manager not initialized',
        };
      }

      if (this.isShuttingDown) {
        return {
          isHealthy: false,
          message: 'Qdrant connection manager is shutting down',
        };
      }

      // Test basic connectivity and get collections
      const collectionsResult = await this.client.getCollections();
      const collections = collectionsResult.collections.map((c) => c.name);

      // Get Qdrant version info - health() method not available in current client
      const version: string | undefined = undefined;

      const responseTime = Date.now() - startTime;
      this.stats.lastHealthCheck = new Date();

      return {
        isHealthy: true,
        message: 'Qdrant connection is healthy',
        collections,
        version: version || 'unknown',
        responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      logger.error({ error, responseTime }, 'Qdrant health check failed');

      return {
        isHealthy: false,
        message: errorMessage,
        responseTime,
      };
    }
  }

  /**
   * Get connection statistics
   */
  getStats(): ConnectionStats {
    return {
      ...this.stats,
      uptime: Date.now() - this.startTime.getTime(),
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      lastHealthCheck: null,
      uptime: Date.now() - this.startTime.getTime(),
    };
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    if (this.isShuttingDown) {
      logger.warn('Qdrant connection manager is already shutting down');
      return;
    }

    this.isShuttingDown = true;
    logger.info('Starting graceful shutdown of Qdrant connection manager');

    try {
      // Qdrant client doesn't have explicit shutdown method
      // Just mark as shut down and let connections timeout
      this.isInitialized = false;

      logger.info('Qdrant connection manager shutdown completed');
    } catch (error) {
      logger.error({ error }, 'Error during Qdrant connection manager shutdown');
      throw error;
    }
  }

  /**
   * Check if connection manager is initialized
   */
  isReady(): boolean {
    return this.isInitialized && !this.isShuttingDown;
  }

  /**
   * Get connection configuration (without sensitive data)
   */
  getConfig(): Omit<QdrantConfig, 'apiKey'> {
    return {
      url: this.config.url,
      timeout: this.config.timeout,
      maxRetries: this.config.maxRetries,
      retryDelay: this.config.retryDelay,
    };
  }

  /**
   * Update average response time
   */
  private updateAverageResponseTime(responseTime: number): void {
    const total = this.stats.successfulRequests + this.stats.failedRequests;
    if (total === 1) {
      this.stats.averageResponseTime = responseTime;
    } else {
      this.stats.averageResponseTime =
        (this.stats.averageResponseTime * (total - 1) + responseTime) / total;
    }
  }

  /**
   * Sleep for specified duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Export singleton instance
export const qdrantConnectionManager = new QdrantConnectionManager();

// Export the underlying client for compatibility
export const getQdrantClient = () => qdrantConnectionManager.getClient();

// Export for testing and multiple instances
export { QdrantConnectionManager };

// Export types
export type { QdrantConfig, HealthCheckResult, ConnectionStats };

// Graceful shutdown handlers
if (typeof process !== 'undefined') {
  const shutdownHandler = async (signal: string) => {
    logger.info({ signal }, `Starting graceful shutdown... Received ${signal}`);
    try {
      await qdrantConnectionManager.shutdown();
      process.exit(0);
    } catch (error) {
      logger.error({ error }, 'Error during graceful shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdownHandler('SIGTERM'));
  process.on('SIGINT', () => shutdownHandler('SIGINT'));

  // Handle uncaught exceptions
  process.on('uncaughtException', async (error) => {
    logger.error({ error }, 'Uncaught exception');
    try {
      await qdrantConnectionManager.shutdown();
    } catch (shutdownError) {
      logger.error({ error: shutdownError }, 'Error during shutdown after uncaught exception');
    }
    process.exit(1);
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', async (reason, promise) => {
    logger.error({ error: promise, reason }, 'Unhandled promise rejection');
    try {
      await qdrantConnectionManager.shutdown();
    } catch (shutdownError) {
      logger.error({ error: shutdownError }, 'Error during shutdown after unhandled rejection');
    }
    process.exit(1);
  });
}
