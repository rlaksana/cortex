/**
 * HTTP Configuration
 *
 * Centralized configuration for HTTP timeouts, retries, and other
 * HTTP client settings across the MCP-Cortex system.
 */

export interface HttpTimeoutConfig {
  default: number;
  short: number;
  medium: number;
  long: number;
  upload: number;
  download: number;
}

export interface HttpRetryConfig {
  maxAttempts: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  retryableStatusCodes: number[];
  retryableErrors: string[];
}

export interface HttpConfig {
  timeouts: HttpTimeoutConfig;
  retries: HttpRetryConfig;
  headers: Record<string, string>;
  maxRedirects: number;
  maxRequestSize: number;
  maxResponseSize: number;
  enableCompression: boolean;
  keepAlive: boolean;
  timeout: number; // Default timeout for backward compatibility
}

export interface PartialHttpConfig {
  timeouts?: Partial<HttpTimeoutConfig>;
  retries?: Partial<HttpRetryConfig>;
  headers?: Record<string, string>;
  maxRedirects?: number;
  maxRequestSize?: number;
  maxResponseSize?: number;
  enableCompression?: boolean;
  keepAlive?: boolean;
  timeout?: number;
}

/**
 * Default HTTP configuration
 */
export const DEFAULT_HTTP_CONFIG: HttpConfig = {
  timeouts: {
    default: 30000, // 30 seconds
    short: 5000, // 5 seconds
    medium: 15000, // 15 seconds
    long: 60000, // 1 minute
    upload: 120000, // 2 minutes
    download: 300000, // 5 minutes
  },
  retries: {
    maxAttempts: 3,
    baseDelay: 1000, // 1 second
    maxDelay: 30000, // 30 seconds
    backoffMultiplier: 2,
    retryableStatusCodes: [408, 429, 500, 502, 503, 504],
    retryableErrors: [
      'ECONNRESET',
      'ECONNREFUSED',
      'ETIMEDOUT',
      'ENOTFOUND',
      'EAI_AGAIN',
      'NETWORK_ERROR',
      'TIMEOUT_ERROR',
    ],
  },
  headers: {
    'User-Agent': 'MCP-Cortex/2.0.1',
    Accept: 'application/json',
    'Accept-Encoding': 'gzip, deflate, br',
    Connection: 'keep-alive',
  },
  maxRedirects: 5,
  maxRequestSize: 10 * 1024 * 1024, // 10MB
  maxResponseSize: 50 * 1024 * 1024, // 50MB
  enableCompression: true,
  keepAlive: true,
  timeout: 30000, // Legacy default timeout
};

/**
 * Environment-specific HTTP configurations
 */
export const ENVIRONMENT_HTTP_CONFIGS: Record<string, PartialHttpConfig> = {
  development: {
    timeouts: {
      default: 60000, // Longer timeouts for debugging
      short: 10000,
      medium: 30000,
      long: 120000,
      upload: 300000,
      download: 600000,
    },
    retries: {
      maxAttempts: 5, // More retries for development
      baseDelay: 500,
      maxDelay: 10000,
    },
  },
  test: {
    timeouts: {
      default: 5000, // Short timeouts for tests
      short: 1000,
      medium: 3000,
      long: 10000,
      upload: 15000,
      download: 30000,
    },
    retries: {
      maxAttempts: 1, // Minimal retries for tests
      baseDelay: 100,
      maxDelay: 1000,
    },
  },
  production: {
    timeouts: {
      default: 30000, // Standard production timeouts
      short: 5000,
      medium: 15000,
      long: 60000,
      upload: 120000,
      download: 300000,
    },
    retries: {
      maxAttempts: 3,
      baseDelay: 1000,
      maxDelay: 30000,
    },
    maxRequestSize: 5 * 1024 * 1024, // Smaller for production
    maxResponseSize: 25 * 1024 * 1024, // Smaller for production
  },
};

/**
 * HTTP Configuration Manager
 */
export class HttpConfigManager {
  private config: HttpConfig;
  private environment: string;

  constructor(environment?: string) {
    this.environment = environment || process.env.NODE_ENV || 'development';
    this.config = this.loadConfig();
  }

  /**
   * Load configuration based on environment
   */
  private loadConfig(): HttpConfig {
    const envConfig = ENVIRONMENT_HTTP_CONFIGS[this.environment] || {};
    return {
      ...DEFAULT_HTTP_CONFIG,
      ...envConfig,
      timeouts: {
        ...DEFAULT_HTTP_CONFIG.timeouts,
        ...(envConfig.timeouts || {}),
      },
      retries: {
        ...DEFAULT_HTTP_CONFIG.retries,
        ...(envConfig.retries || {}),
      },
      headers: {
        ...DEFAULT_HTTP_CONFIG.headers,
        ...(envConfig.headers || {}),
      },
    };
  }

  /**
   * Get current configuration
   */
  getConfig(): HttpConfig {
    return { ...this.config };
  }

  /**
   * Get timeout for specific operation type
   */
  getTimeout(type: keyof HttpTimeoutConfig = 'default'): number {
    return this.config.timeouts[type] || this.config.timeouts.default;
  }

  /**
   * Get retry configuration
   */
  getRetryConfig(): HttpRetryConfig {
    return { ...this.config.retries };
  }

  /**
   * Get default headers
   */
  getHeaders(): Record<string, string> {
    return { ...this.config.headers };
  }

  /**
   * Check if status code is retryable
   */
  isRetryableStatusCode(statusCode: number): boolean {
    return this.config.retries.retryableStatusCodes.includes(statusCode);
  }

  /**
   * Check if error is retryable
   */
  isRetryableError(error: Error): boolean {
    return (
      this.config.retries.retryableErrors.includes(error.name) ||
      this.config.retries.retryableErrors.includes(error.message)
    );
  }

  /**
   * Calculate retry delay with exponential backoff
   */
  calculateRetryDelay(attempt: number): number {
    const delay =
      this.config.retries.baseDelay * Math.pow(this.config.retries.backoffMultiplier, attempt - 1);
    return Math.min(delay, this.config.retries.maxDelay);
  }

  /**
   * Update configuration
   */
  updateConfig(updates: Partial<HttpConfig>): void {
    this.config = {
      ...this.config,
      ...updates,
      timeouts: {
        ...this.config.timeouts,
        ...(updates.timeouts || {}),
      },
      retries: {
        ...this.config.retries,
        ...(updates.retries || {}),
      },
      headers: {
        ...this.config.headers,
        ...(updates.headers || {}),
      },
    };
  }

  /**
   * Set timeout for specific operation type
   */
  setTimeout(type: keyof HttpTimeoutConfig, timeout: number): void {
    this.config.timeouts[type] = timeout;
  }

  /**
   * Set retry configuration
   */
  setRetryConfig(retryConfig: Partial<HttpRetryConfig>): void {
    this.config.retries = {
      ...this.config.retries,
      ...retryConfig,
    };
  }

  /**
   * Add default header
   */
  setHeader(name: string, value: string): void {
    this.config.headers[name] = value;
  }

  /**
   * Remove default header
   */
  removeHeader(name: string): void {
    delete this.config.headers[name];
  }

  /**
   * Validate configuration
   */
  validateConfig(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate timeouts
    for (const [key, value] of Object.entries(this.config.timeouts)) {
      if (typeof value !== 'number' || value <= 0) {
        errors.push(`Invalid timeout for ${key}: must be positive number`);
      }
    }

    // Validate retry config
    if (this.config.retries.maxAttempts < 0) {
      errors.push('Max retry attempts must be non-negative');
    }

    if (this.config.retries.baseDelay <= 0) {
      errors.push('Base retry delay must be positive');
    }

    if (this.config.retries.maxDelay <= 0) {
      errors.push('Max retry delay must be positive');
    }

    if (this.config.retries.backoffMultiplier <= 1) {
      errors.push('Backoff multiplier must be greater than 1');
    }

    // Validate other numeric values
    if (this.config.maxRedirects < 0) {
      errors.push('Max redirects must be non-negative');
    }

    if (this.config.maxRequestSize <= 0) {
      errors.push('Max request size must be positive');
    }

    if (this.config.maxResponseSize <= 0) {
      errors.push('Max response size must be positive');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Export configuration to JSON
   */
  exportConfig(): string {
    return JSON.stringify(
      {
        environment: this.environment,
        config: this.config,
        validation: this.validateConfig(),
      },
      null,
      2
    );
  }

  /**
   * Import configuration from JSON
   */
  importConfig(configJson: string): void {
    try {
      const data = JSON.parse(configJson);

      if (data.config) {
        this.updateConfig(data.config);
      }

      if (data.environment) {
        this.environment = data.environment;
      }
    } catch (error) {
      throw new Error(`Failed to import HTTP configuration: ${error}`);
    }
  }

  /**
   * Get configuration summary
   */
  getSummary(): {
    environment: string;
    defaultTimeout: number;
    maxRetries: number;
    headerCount: number;
    compressionEnabled: boolean;
    keepAliveEnabled: boolean;
  } {
    return {
      environment: this.environment,
      defaultTimeout: this.config.timeouts.default,
      maxRetries: this.config.retries.maxAttempts,
      headerCount: Object.keys(this.config.headers).length,
      compressionEnabled: this.config.enableCompression,
      keepAliveEnabled: this.config.keepAlive,
    };
  }
}

// Global HTTP configuration manager instance
export const httpConfigManager = new HttpConfigManager();

/**
 * Get HTTP timeout for operation type
 */
export function getHttpTimeout(type: keyof HttpTimeoutConfig = 'default'): number {
  return httpConfigManager.getTimeout(type);
}

/**
 * Get HTTP retry configuration
 */
export function getHttpRetryConfig(): HttpRetryConfig {
  return httpConfigManager.getRetryConfig();
}

/**
 * Check if HTTP status code is retryable
 */
export function isRetryableHttpStatusCode(statusCode: number): boolean {
  return httpConfigManager.isRetryableStatusCode(statusCode);
}

/**
 * Check if HTTP error is retryable
 */
export function isRetryableHttpError(error: Error): boolean {
  return httpConfigManager.isRetryableError(error);
}

/**
 * Calculate HTTP retry delay
 */
export function calculateHttpRetryDelay(attempt: number): number {
  return httpConfigManager.calculateRetryDelay(attempt);
}
