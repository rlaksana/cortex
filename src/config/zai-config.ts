/**
 * ZAI Configuration Management
 *
 * Production-ready configuration system for ZAI API integration
 * with comprehensive validation, environment variable support, and defaults
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { getKeyVaultService } from '../services/security/key-vault-service.js';
import type {
  AIOrchestratorConfig,
  BackgroundProcessorConfig,
  CircuitBreakerConfig,
  RequestQueueConfig,
  ZAIConfig,
} from '../types/zai-interfaces.js';

/**
 * Default ZAI configuration
 */
const DEFAULT_ZAI_CONFIG: Omit<ZAIConfig, 'apiKey'> = {
  baseURL: 'https://api.z.ai/api/anthropic',
  model: 'glm-4.6',
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
  circuitBreakerThreshold: 3,
  circuitBreakerTimeout: 60000,
  enableLogging: true,
  rateLimitRPM: 60,
};

/**
 * Default AI orchestrator configuration
 */
const DEFAULT_ORCHESTRATOR_CONFIG: Omit<AIOrchestratorConfig, 'providerConfigs'> = {
  primaryProvider: 'zai',
  fallbackProvider: 'openai',
  autoFailover: true,
  healthCheckInterval: 30000,
  fallbackThreshold: 3,
};

/**
 * Default background processor configuration
 */
const DEFAULT_BACKGROUND_PROCESSOR_CONFIG: BackgroundProcessorConfig = {
  maxConcurrency: 10,
  queueSize: 1000,
  retryAttempts: 3,
  retryDelayMs: 1000,
  timeoutMs: 60000,
  enablePriorityQueue: true,
  persistJobs: false,
  metricsInterval: 30000,
};

/**
 * Default circuit breaker configuration
 */
const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 3,
  timeout: 60000,
  monitoringPeriod: 30000,
  expectedRecoveryTime: 30000,
};

/**
 * Default request queue configuration
 */
const DEFAULT_REQUEST_QUEUE_CONFIG: RequestQueueConfig = {
  maxSize: 1000,
  concurrency: 10,
  timeoutMs: 30000,
  retryAttempts: 3,
  retryDelayMs: 1000,
  priorityQueue: true,
};

/**
 * ZAI configuration manager
 */
export class ZAIConfigManager {
  private static instance: ZAIConfigManager;
  private config: ZAIConfig | null = null;
  private orchestratorConfig: AIOrchestratorConfig | null = null;
  private backgroundProcessorConfig: BackgroundProcessorConfig | null = null;
  private circuitBreakerConfig: CircuitBreakerConfig;
  private requestQueueConfig: RequestQueueConfig;
  private isConfigLoaded = false;

  private constructor() {
    this.circuitBreakerConfig = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG };
    this.requestQueueConfig = { ...DEFAULT_REQUEST_QUEUE_CONFIG };
  }

  /**
   * Get singleton instance
   */
  static getInstance(): ZAIConfigManager {
    if (!ZAIConfigManager.instance) {
      ZAIConfigManager.instance = new ZAIConfigManager();
    }
    return ZAIConfigManager.instance;
  }

  /**
   * Load configuration from environment and key vault
   */
  async loadConfig(): Promise<void> {
    if (this.isConfigLoaded) {
      logger.debug('ZAI configuration already loaded');
      return;
    }

    try {
      logger.info('Loading ZAI configuration...');

      // Load primary ZAI configuration
      await this.loadZAIConfig();

      // Load orchestrator configuration
      await this.loadOrchestratorConfig();

      // Load background processor configuration
      await this.loadBackgroundProcessorConfig();

      // Load circuit breaker configuration
      this.loadCircuitBreakerConfig();

      // Load request queue configuration
      this.loadRequestQueueConfig();

      // Validate configurations
      this.validateConfigurations();

      this.isConfigLoaded = true;
      logger.info('ZAI configuration loaded successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to load ZAI configuration');
      throw error;
    }
  }

  /**
   * Load ZAI configuration
   */
  private async loadZAIConfig(): Promise<void> {
    let apiKey = process.env['ZAI_API_KEY'];

    // Try to get API key from key vault if not in environment
    if (!apiKey) {
      try {
        const keyVault = getKeyVaultService();
        const keyVaultKey = await keyVault.get_key_by_name('zai_api_key');
        if (keyVaultKey) {
          apiKey = keyVaultKey.value;
          logger.info('ZAI API key retrieved from key vault');
        }
      } catch (error) {
        logger.warn({ error }, 'Failed to retrieve ZAI API key from key vault');
      }
    }

    if (!apiKey) {
      throw new Error('ZAI API key is required but not found in environment or key vault');
    }

    this.config = {
      ...DEFAULT_ZAI_CONFIG,
      apiKey,
      // Override with environment variables if present
      baseURL: process.env['ZAI_BASE_URL'] || DEFAULT_ZAI_CONFIG.baseURL,
      model: process.env['ZAI_MODEL'] || DEFAULT_ZAI_CONFIG.model,
      timeout: parseInt(process.env['ZAI_TIMEOUT'] || String(DEFAULT_ZAI_CONFIG.timeout)),
      maxRetries: parseInt(process.env['ZAI_MAX_RETRIES'] || String(DEFAULT_ZAI_CONFIG.maxRetries)),
      retryDelay: parseInt(process.env['ZAI_RETRY_DELAY'] || String(DEFAULT_ZAI_CONFIG.retryDelay)),
      circuitBreakerThreshold: parseInt(
        process.env['ZAI_CIRCUIT_BREAKER_THRESHOLD'] ||
          String(DEFAULT_ZAI_CONFIG.circuitBreakerThreshold)
      ),
      circuitBreakerTimeout: parseInt(
        process.env['ZAI_CIRCUIT_BREAKER_TIMEOUT'] ||
          String(DEFAULT_ZAI_CONFIG.circuitBreakerTimeout)
      ),
      enableLogging: process.env['ZAI_ENABLE_LOGGING'] !== 'false',
      rateLimitRPM: parseInt(
        process.env['ZAI_RATE_LIMIT_RPM'] || String(DEFAULT_ZAI_CONFIG.rateLimitRPM)
      ),
    };
  }

  /**
   * Load AI orchestrator configuration
   */
  private loadOrchestratorConfig(): void {
    const primaryProvider =
      (process.env['ZAI_PRIMARY_PROVIDER'] as unknown) ||
      DEFAULT_ORCHESTRATOR_CONFIG.primaryProvider;
    const fallbackProvider =
      (process.env['ZAI_FALLBACK_PROVIDER'] as unknown) ||
      DEFAULT_ORCHESTRATOR_CONFIG.fallbackProvider;

    this.orchestratorConfig = {
      ...DEFAULT_ORCHESTRATOR_CONFIG,
      primaryProvider: primaryProvider as 'openai' | 'zai',
      fallbackProvider: fallbackProvider as 'openai' | 'zai',
      autoFailover: process.env['ZAI_AUTO_FAILOVER'] !== 'false',
      healthCheckInterval: parseInt(
        process.env['ZAI_HEALTH_CHECK_INTERVAL'] ||
          String(DEFAULT_ORCHESTRATOR_CONFIG.healthCheckInterval)
      ),
      fallbackThreshold: parseInt(
        process.env['ZAI_FALLBACK_THRESHOLD'] ||
          String(DEFAULT_ORCHESTRATOR_CONFIG.fallbackThreshold)
      ),
      providerConfigs: {
        zai: this.config!,
        openai: {
          apiKey: process.env['OPENAI_API_KEY'] || '',
          model: process.env['OPENAI_MODEL'] || 'gpt-4-turbo-preview',
          baseURL: process.env['OPENAI_BASE_URL'],
          timeout: parseInt(process.env['OPENAI_TIMEOUT'] || '30000'),
          maxRetries: parseInt(process.env['OPENAI_MAX_RETRIES'] || '3'),
        },
      },
    };
  }

  /**
   * Load background processor configuration
   */
  private loadBackgroundProcessorConfig(): void {
    this.backgroundProcessorConfig = {
      ...DEFAULT_BACKGROUND_PROCESSOR_CONFIG,
      maxConcurrency: parseInt(
        process.env['ZAI_MAX_CONCURRENCY'] ||
          String(DEFAULT_BACKGROUND_PROCESSOR_CONFIG.maxConcurrency)
      ),
      queueSize: parseInt(
        process.env['ZAI_QUEUE_SIZE'] || String(DEFAULT_BACKGROUND_PROCESSOR_CONFIG.queueSize)
      ),
      retryAttempts: parseInt(
        process.env['ZAI_RETRY_ATTEMPTS'] ||
          String(DEFAULT_BACKGROUND_PROCESSOR_CONFIG.retryAttempts)
      ),
      retryDelayMs: parseInt(
        process.env['ZAI_RETRY_DELAY_MS'] ||
          String(DEFAULT_BACKGROUND_PROCESSOR_CONFIG.retryDelayMs)
      ),
      timeoutMs: parseInt(
        process.env['ZAI_TIMEOUT_MS'] || String(DEFAULT_BACKGROUND_PROCESSOR_CONFIG.timeoutMs)
      ),
      enablePriorityQueue: process.env['ZAI_ENABLE_PRIORITY_QUEUE'] !== 'false',
      persistJobs: process.env['ZAI_PERSIST_JOBS'] === 'true',
      metricsInterval: parseInt(
        process.env['ZAI_METRICS_INTERVAL'] ||
          String(DEFAULT_BACKGROUND_PROCESSOR_CONFIG.metricsInterval)
      ),
    };
  }

  /**
   * Load circuit breaker configuration
   */
  private loadCircuitBreakerConfig(): void {
    this.circuitBreakerConfig = {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      failureThreshold: parseInt(
        process.env['ZAI_CIRCUIT_BREAKER_FAILURE_THRESHOLD'] ||
          String(DEFAULT_CIRCUIT_BREAKER_CONFIG.failureThreshold)
      ),
      timeout: parseInt(
        process.env['ZAI_CIRCUIT_BREAKER_TIMEOUT'] || String(DEFAULT_CIRCUIT_BREAKER_CONFIG.timeout)
      ),
      monitoringPeriod: parseInt(
        process.env['ZAI_CIRCUIT_BREAKER_MONITORING_PERIOD'] ||
          String(DEFAULT_CIRCUIT_BREAKER_CONFIG.monitoringPeriod)
      ),
      expectedRecoveryTime: parseInt(
        process.env['ZAI_CIRCUIT_BREAKER_EXPECTED_RECOVERY_TIME'] ||
          String(DEFAULT_CIRCUIT_BREAKER_CONFIG.expectedRecoveryTime)
      ),
    };
  }

  /**
   * Load request queue configuration
   */
  private loadRequestQueueConfig(): void {
    this.requestQueueConfig = {
      ...DEFAULT_REQUEST_QUEUE_CONFIG,
      maxSize: parseInt(
        process.env['ZAI_QUEUE_MAX_SIZE'] || String(DEFAULT_REQUEST_QUEUE_CONFIG.maxSize)
      ),
      concurrency: parseInt(
        process.env['ZAI_QUEUE_CONCURRENCY'] || String(DEFAULT_REQUEST_QUEUE_CONFIG.concurrency)
      ),
      timeoutMs: parseInt(
        process.env['ZAI_QUEUE_TIMEOUT_MS'] || String(DEFAULT_REQUEST_QUEUE_CONFIG.timeoutMs)
      ),
      retryAttempts: parseInt(
        process.env['ZAI_QUEUE_RETRY_ATTEMPTS'] ||
          String(DEFAULT_REQUEST_QUEUE_CONFIG.retryAttempts)
      ),
      retryDelayMs: parseInt(
        process.env['ZAI_QUEUE_RETRY_DELAY_MS'] || String(DEFAULT_REQUEST_QUEUE_CONFIG.retryDelayMs)
      ),
      priorityQueue: process.env['ZAI_QUEUE_PRIORITY'] !== 'false',
    };
  }

  /**
   * Validate all configurations
   */
  private validateConfigurations(): void {
    if (!this.config) {
      throw new Error('ZAI configuration is not loaded');
    }

    if (!this.orchestratorConfig) {
      throw new Error('AI orchestrator configuration is not loaded');
    }

    if (!this.backgroundProcessorConfig) {
      throw new Error('Background processor configuration is not loaded');
    }

    // Validate ZAI config
    if (!this.config.apiKey) {
      throw new Error('ZAI API key is required');
    }

    if ((this.config.timeout || 0) < 1000 || (this.config.timeout || 0) > 300000) {
      throw new Error('ZAI timeout must be between 1000ms and 300000ms');
    }

    if ((this.config.maxRetries || 0) < 0 || (this.config.maxRetries || 0) > 10) {
      throw new Error('ZAI max retries must be between 0 and 10');
    }

    if ((this.config.rateLimitRPM || 0) < 1 || (this.config.rateLimitRPM || 0) > 1000) {
      throw new Error('ZAI rate limit RPM must be between 1 and 1000');
    }

    // Validate orchestrator config
    if (this.orchestratorConfig.primaryProvider === this.orchestratorConfig.fallbackProvider) {
      throw new Error('Primary and fallback providers cannot be the same');
    }

    // Validate background processor config
    if (
      this.backgroundProcessorConfig.maxConcurrency < 1 ||
      this.backgroundProcessorConfig.maxConcurrency > 100
    ) {
      throw new Error('Max concurrency must be between 1 and 100');
    }

    if (
      this.backgroundProcessorConfig.queueSize < 1 ||
      this.backgroundProcessorConfig.queueSize > 10000
    ) {
      throw new Error('Queue size must be between 1 and 10000');
    }

    logger.info('All ZAI configurations validated successfully');
  }

  /**
   * Get ZAI configuration
   */
  getZAIConfig(): ZAIConfig {
    if (!this.config) {
      throw new Error('ZAI configuration is not loaded. Call loadConfig() first.');
    }
    return { ...this.config }; // Return a copy to prevent modification
  }

  /**
   * Get AI orchestrator configuration
   */
  getOrchestratorConfig(): AIOrchestratorConfig {
    if (!this.orchestratorConfig) {
      throw new Error('AI orchestrator configuration is not loaded. Call loadConfig() first.');
    }
    return JSON.parse(JSON.stringify(this.orchestratorConfig)) as AIOrchestratorConfig; // Deep copy to prevent modification
  }

  /**
   * Get background processor configuration
   */
  getBackgroundProcessorConfig(): BackgroundProcessorConfig {
    if (!this.backgroundProcessorConfig) {
      throw new Error('Background processor configuration is not loaded. Call loadConfig() first.');
    }
    return { ...this.backgroundProcessorConfig }; // Return a copy to prevent modification
  }

  /**
   * Get circuit breaker configuration
   */
  getCircuitBreakerConfig(): CircuitBreakerConfig {
    return { ...this.circuitBreakerConfig }; // Return a copy to prevent modification
  }

  /**
   * Get request queue configuration
   */
  getRequestQueueConfig(): RequestQueueConfig {
    return { ...this.requestQueueConfig }; // Return a copy to prevent modification
  }

  /**
   * Update configuration (for runtime updates)
   */
  updateConfig(updates: Partial<ZAIConfig>): void {
    if (!this.config) {
      throw new Error('ZAI configuration is not loaded. Call loadConfig() first.');
    }

    this.config = { ...this.config, ...updates };

    // Re-validate configuration
    this.validateConfigurations();

    logger.info('ZAI configuration updated successfully');
  }

  /**
   * Update orchestrator configuration (for runtime updates)
   */
  updateOrchestratorConfig(updates: Partial<AIOrchestratorConfig>): void {
    if (!this.orchestratorConfig) {
      throw new Error('AI orchestrator configuration is not loaded. Call loadConfig() first.');
    }

    this.orchestratorConfig = {
      ...this.orchestratorConfig,
      ...updates,
      providerConfigs: { ...this.orchestratorConfig.providerConfigs },
    };

    // Re-validate configuration
    this.validateConfigurations();

    logger.info('AI orchestrator configuration updated successfully');
  }

  /**
   * Get configuration summary (for monitoring)
   */
  getConfigSummary(): {
    zai: { model: string; baseURL: string; rateLimitRPM: number; timeout: number };
    orchestrator: { primaryProvider: string; fallbackProvider: string; autoFailover: boolean };
    backgroundProcessor: { maxConcurrency: number; queueSize: number };
    circuitBreaker: { failureThreshold: number; timeout: number };
    requestQueue: { maxSize: number; concurrency: number };
  } {
    if (!this.config || !this.orchestratorConfig || !this.backgroundProcessorConfig) {
      throw new Error('Configuration is not loaded. Call loadConfig() first.');
    }

    return {
      zai: {
        model: this.config.model,
        baseURL: this.config.baseURL!,
        rateLimitRPM: this.config.rateLimitRPM || 60,
        timeout: this.config.timeout || 30000,
      },
      orchestrator: {
        primaryProvider: this.orchestratorConfig.primaryProvider,
        fallbackProvider: this.orchestratorConfig.fallbackProvider,
        autoFailover: this.orchestratorConfig.autoFailover,
      },
      backgroundProcessor: {
        maxConcurrency: this.backgroundProcessorConfig.maxConcurrency,
        queueSize: this.backgroundProcessorConfig.queueSize,
      },
      circuitBreaker: {
        failureThreshold: this.circuitBreakerConfig.failureThreshold,
        timeout: this.circuitBreakerConfig.timeout,
      },
      requestQueue: {
        maxSize: this.requestQueueConfig.maxSize,
        concurrency: this.requestQueueConfig.concurrency,
      },
    };
  }

  /**
   * Reset configuration to defaults (for testing)
   */
  reset(): void {
    this.config = null;
    this.orchestratorConfig = null;
    this.backgroundProcessorConfig = null;
    this.circuitBreakerConfig = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG };
    this.requestQueueConfig = { ...DEFAULT_REQUEST_QUEUE_CONFIG };
    this.isConfigLoaded = false;
    logger.info('ZAI configuration reset to defaults');
  }

  /**
   * Check if configuration is loaded
   */
  isLoaded(): boolean {
    return this.isConfigLoaded;
  }
}

/**
 * Export singleton instance
 */
export const zaiConfigManager = ZAIConfigManager.getInstance();

/**
 * Export configuration getters for convenience
 */
export const getZAIConfig = () => zaiConfigManager.getZAIConfig();
export const getOrchestratorConfig = () => zaiConfigManager.getOrchestratorConfig();
export const getBackgroundProcessorConfig = () => zaiConfigManager.getBackgroundProcessorConfig();
export const getCircuitBreakerConfig = () => zaiConfigManager.getCircuitBreakerConfig();
export const getRequestQueueConfig = () => zaiConfigManager.getRequestQueueConfig();
