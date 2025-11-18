/**
 * Configuration Migration System
 *
 * Handles migration of configuration property names to maintain consistency
 * across the MCP-Cortex system while providing backward compatibility.
 *
 * Standardizes all time-related properties to use "Ms" suffix for clarity.
 * Provides validation and migration functions for all configuration objects.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { z } from 'zod';

import type { LegacyConfig } from '../types/config.js';

// ============================================================================
// Migration Schemas and Interfaces
// ============================================================================

/**
 * Legacy health check configuration with old property names
 */
export interface LegacyHealthCheckConfig {
  enabled?: boolean;
  interval?: number;
  intervalMs?: number;
  timeout?: number;
  timeoutMs?: number;
  failureThreshold?: number;
  successThreshold?: number;
  retries?: number;
  retryAttempts?: number;
  retryDelay?: number;
  retryDelayMs?: number;
}

/**
 * Legacy HTTP client configuration
 */
export interface LegacyHttpClientConfig {
  timeout?: number;
  timeoutMs?: number;
  retries?: number;
  retryAttempts?: number;
  retryDelay?: number;
  retryDelayMs?: number;
  headers?: Record<string, string>;
}

/**
 * Standardized health check configuration
 */
export interface StandardHealthCheckConfig {
  enabled: boolean;
  intervalMs: number;
  timeoutMs: number;
  failureThreshold: number;
  successThreshold: number;
  retryAttempts: number;
  retryDelayMs: number;
}

/**
 * Standardized HTTP client configuration
 */
export interface StandardHttpClientConfig {
  timeoutMs: number;
  retryAttempts: number;
  retryDelayMs: number;
  headers?: Record<string, string>;
}

// ============================================================================
// Configuration Migration Functions
// ============================================================================

/**
 * Migrate legacy health check configuration to standard format
 */
export function migrateHealthCheckConfig(
  config: LegacyHealthCheckConfig = {}
): StandardHealthCheckConfig {
  return {
    enabled: config.enabled ?? true,
    intervalMs: normalizeTimeValue(config.intervalMs || config.interval || 30000),
    timeoutMs: normalizeTimeValue(config.timeoutMs || config.timeout || 10000),
    failureThreshold: config.failureThreshold ?? 3,
    successThreshold: config.successThreshold ?? 2,
    retryAttempts: config.retryAttempts ?? config.retries ?? 3,
    retryDelayMs: normalizeTimeValue(config.retryDelayMs || config.retryDelay || 1000),
  };
}

/**
 * Migrate legacy HTTP client configuration to standard format
 */
export function migrateHttpClientConfig(
  config: LegacyHttpClientConfig = {}
): StandardHttpClientConfig {
  return {
    timeoutMs: normalizeTimeValue(config.timeoutMs || config.timeout || 10000),
    retryAttempts: config.retryAttempts ?? config.retries ?? 0,
    retryDelayMs: normalizeTimeValue(config.retryDelayMs || config.retryDelay || 1000),
    headers: config.headers || {},
  };
}

/**
 * Normalize time values to ensure they're in milliseconds
 */
function normalizeTimeValue(value: number | undefined, defaultMs: number = 1000): number {
  if (value === undefined || value === null) {
    return defaultMs;
  }

  // If value is less than 100, assume it's in seconds and convert to ms
  if (value < 100) {
    return value * 1000;
  }

  return value;
}

// ============================================================================
// Configuration Validation Schemas
// ============================================================================

/**
 * Zod schema for standardized health check configuration
 */
export const HealthCheckConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    intervalMs: z.number().min(100).max(300000).default(30000),
    timeoutMs: z.number().min(100).max(300000).default(10000),
    failureThreshold: z.number().min(1).max(10).default(3),
    successThreshold: z.number().min(1).max(10).default(2),
    retryAttempts: z.number().min(0).max(10).default(3),
    retryDelayMs: z.number().min(100).max(60000).default(1000),
  })
  .strict();

/**
 * Zod schema for standardized HTTP client configuration
 */
export const HttpClientConfigSchema = z
  .object({
    timeoutMs: z.number().min(100).max(300000).default(10000),
    retryAttempts: z.number().min(0).max(10).default(0),
    retryDelayMs: z.number().min(100).max(60000).default(1000),
    headers: z.record(z.string()).optional().default({}),
  })
  .strict();

/**
 * Zod schema for legacy health check configuration (for backward compatibility)
 */
export const LegacyHealthCheckConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    interval: z.number().optional(),
    intervalMs: z.number().optional(),
    timeout: z.number().optional(),
    timeoutMs: z.number().optional(),
    failureThreshold: z.number().optional(),
    successThreshold: z.number().optional(),
    retries: z.number().optional(),
    retryAttempts: z.number().optional(),
    retryDelay: z.number().optional(),
    retryDelayMs: z.number().optional(),
  })
  .passthrough(); // Allow additional properties for backward compatibility

// ============================================================================
// Configuration Validators
// ============================================================================

/**
 * Validate standardized health check configuration
 */
export function validateHealthCheckConfig(config: StandardHealthCheckConfig): {
  valid: boolean;
  errors: string[];
} {
  const result = HealthCheckConfigSchema.safeParse(config);

  if (result.success) {
    return { valid: true, errors: [] };
  }

  return {
    valid: false,
    errors: result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`),
  };
}

/**
 * Validate standardized HTTP client configuration
 */
export function validateHttpClientConfig(config: StandardHttpClientConfig): {
  valid: boolean;
  errors: string[];
} {
  const result = HttpClientConfigSchema.safeParse(config);

  if (result.success) {
    return { valid: true, errors: [] };
  }

  return {
    valid: false,
    errors: result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`),
  };
}

/**
 * Validate and migrate legacy configuration in one step
 */
export function validateAndMigrateHealthCheckConfig(config: LegacyHealthCheckConfig): {
  valid: boolean;
  errors: string[];
  migrated?: StandardHealthCheckConfig;
} {
  // First validate the legacy config
  const legacyResult = LegacyHealthCheckConfigSchema.safeParse(config);
  if (!legacyResult.success) {
    return {
      valid: false,
      errors: legacyResult.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`),
    };
  }

  // Migrate to standard format
  const migrated = migrateHealthCheckConfig(config);

  // Validate the migrated config
  const validationResult = validateHealthCheckConfig(migrated);

  return {
    ...validationResult,
    migrated: validationResult.valid ? migrated : undefined,
  };
}

// ============================================================================
// Configuration Builder Classes
// ============================================================================

/**
 * Builder for health check configurations
 */
export class HealthCheckConfigBuilder {
  private config: Partial<StandardHealthCheckConfig> = {};

  /**
   * Enable or disable health checks
   */
  enabled(enabled: boolean): HealthCheckConfigBuilder {
    this.config.enabled = enabled;
    return this;
  }

  /**
   * Set check interval in milliseconds
   */
  intervalMs(intervalMs: number): HealthCheckConfigBuilder {
    this.config.intervalMs = intervalMs;
    return this;
  }

  /**
   * Set timeout in milliseconds
   */
  timeoutMs(timeoutMs: number): HealthCheckConfigBuilder {
    this.config.timeoutMs = timeoutMs;
    return this;
  }

  /**
   * Set failure threshold
   */
  failureThreshold(threshold: number): HealthCheckConfigBuilder {
    this.config.failureThreshold = threshold;
    return this;
  }

  /**
   * Set success threshold
   */
  successThreshold(threshold: number): HealthCheckConfigBuilder {
    this.config.successThreshold = threshold;
    return this;
  }

  /**
   * Set retry attempts
   */
  retryAttempts(attempts: number): HealthCheckConfigBuilder {
    this.config.retryAttempts = attempts;
    return this;
  }

  /**
   * Set retry delay in milliseconds
   */
  retryDelayMs(delayMs: number): HealthCheckConfigBuilder {
    this.config.retryDelayMs = delayMs;
    return this;
  }

  /**
   * Set timeout in seconds (convenience method)
   */
  timeoutSeconds(seconds: number): HealthCheckConfigBuilder {
    this.config.timeoutMs = seconds * 1000;
    return this;
  }

  /**
   * Set retry delay in seconds (convenience method)
   */
  retryDelaySeconds(seconds: number): HealthCheckConfigBuilder {
    this.config.retryDelayMs = seconds * 1000;
    return this;
  }

  /**
   * Set check interval in seconds (convenience method)
   */
  intervalSeconds(seconds: number): HealthCheckConfigBuilder {
    this.config.intervalMs = seconds * 1000;
    return this;
  }

  /**
   * Build the configuration with validation
   */
  build(): StandardHealthCheckConfig {
    const config = migrateHealthCheckConfig(this.config);
    const validation = validateHealthCheckConfig(config);

    if (!validation.valid) {
      throw new Error(`Invalid health check configuration: ${validation.errors.join(', ')}`);
    }

    return config;
  }

  /**
   * Build the configuration without validation (use with caution)
   */
  buildUnsafe(): StandardHealthCheckConfig {
    return migrateHealthCheckConfig(this.config);
  }
}

/**
 * Builder for HTTP client configurations
 */
export class HttpClientConfigBuilder {
  private config: Partial<StandardHttpClientConfig> = {};

  /**
   * Set timeout in milliseconds
   */
  timeoutMs(timeoutMs: number): HttpClientConfigBuilder {
    this.config.timeoutMs = timeoutMs;
    return this;
  }

  /**
   * Set retry attempts
   */
  retryAttempts(attempts: number): HttpClientConfigBuilder {
    this.config.retryAttempts = attempts;
    return this;
  }

  /**
   * Set retry delay in milliseconds
   */
  retryDelayMs(delayMs: number): HttpClientConfigBuilder {
    this.config.retryDelayMs = delayMs;
    return this;
  }

  /**
   * Set headers
   */
  headers(headers: Record<string, string>): HttpClientConfigBuilder {
    this.config.headers = { ...this.config.headers, ...headers };
    return this;
  }

  /**
   * Add a single header
   */
  header(key: string, value: string): HttpClientConfigBuilder {
    if (!this.config.headers) {
      this.config.headers = {};
    }
    this.config.headers[key] = value;
    return this;
  }

  /**
   * Set timeout in seconds (convenience method)
   */
  timeoutSeconds(seconds: number): HttpClientConfigBuilder {
    this.config.timeoutMs = seconds * 1000;
    return this;
  }

  /**
   * Set retry delay in seconds (convenience method)
   */
  retryDelaySeconds(seconds: number): HttpClientConfigBuilder {
    this.config.retryDelayMs = seconds * 1000;
    return this;
  }

  /**
   * Build the configuration with validation
   */
  build(): StandardHttpClientConfig {
    const config = migrateHttpClientConfig(this.config);
    const validation = validateHttpClientConfig(config);

    if (!validation.valid) {
      throw new Error(`Invalid HTTP client configuration: ${validation.errors.join(', ')}`);
    }

    return config;
  }

  /**
   * Build the configuration without validation (use with caution)
   */
  buildUnsafe(): StandardHttpClientConfig {
    return migrateHttpClientConfig(this.config);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a health check configuration builder
 */
export function healthCheckConfig(): HealthCheckConfigBuilder {
  return new HealthCheckConfigBuilder();
}

/**
 * Create an HTTP client configuration builder
 */
export function httpClientConfig(): HttpClientConfigBuilder {
  return new HttpClientConfigBuilder();
}

/**
 * Migrate configuration object recursively
 */
export function migrateConfiguration(
  config: LegacyConfig,
  type: 'health-check' | 'http-client' | 'auto' = 'auto'
): LegacyConfig | StandardHealthCheckConfig | StandardHttpClientConfig {
  if (type === 'auto') {
    // Auto-detect configuration type based on property names
    if (hasHealthCheckProperties(config)) {
      type = 'health-check';
    } else if (hasHttpClientProperties(config)) {
      type = 'http-client';
    }
  }

  switch (type) {
    case 'health-check':
      return migrateHealthCheckConfig(config);
    case 'http-client':
      return migrateHttpClientConfig(config);
    default:
      // Return config as-is if type cannot be determined
      return config;
  }
}

/**
 * Check if configuration object has health check properties
 */
function hasHealthCheckProperties(config: LegacyConfig): boolean {
  const healthCheckProps = [
    'enabled',
    'intervalMs',
    'timeoutMs',
    'failureThreshold',
    'successThreshold',
    'retryAttempts',
    'retryDelayMs',
    'interval',
    'timeout',
    'retries',
    'retryDelay',
  ];

  return healthCheckProps.some((prop) => prop in config);
}

/**
 * Check if configuration object has HTTP client properties
 */
function hasHttpClientProperties(config: LegacyConfig): boolean {
  const httpClientProps = [
    'timeoutMs',
    'retryAttempts',
    'retryDelayMs',
    'timeout',
    'retries',
    'retryDelay',
    'headers',
  ];

  return httpClientProps.some((prop) => prop in config);
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard for legacy health check configuration
 */
export function isLegacyHealthCheckConfig(config: unknown): config is LegacyHealthCheckConfig {
  return typeof config === 'object' && config !== null;
}

/**
 * Type guard for legacy HTTP client configuration
 */
export function isLegacyHttpClientConfig(config: unknown): config is LegacyHttpClientConfig {
  return typeof config === 'object' && config !== null;
}

/**
 * Type guard for standardized health check configuration
 */
export function isStandardHealthCheckConfig(config: unknown): config is StandardHealthCheckConfig {
  return (
    typeof config === 'object' &&
    config !== null &&
    'timeoutMs' in config &&
    'retryAttempts' in config &&
    'retryDelayMs' in config
  );
}

/**
 * Type guard for standardized HTTP client configuration
 */
export function isStandardHttpClientConfig(config: unknown): config is StandardHttpClientConfig {
  return (
    typeof config === 'object' &&
    config !== null &&
    'timeoutMs' in config &&
    'retryAttempts' in config &&
    'retryDelayMs' in config
  );
}
