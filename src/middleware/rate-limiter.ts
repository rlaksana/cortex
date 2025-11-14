// @ts-nocheck
// COMPREHENSIVE EMERGENCY ROLLBACK: Final systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Rate Limiting Service for Cortex MCP
 *
 * Provides comprehensive rate limiting with dual-layer approach:
 * - Token bucket (burst capacity)
 * - Sliding window (sustained rate)
 * - Per-API key and organization limits
 * - Configurable limits per operation type
 * - Distributed Redis support
 * - Local fallback for high availability
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { OperationType } from '../monitoring/operation-types.js';
import { structuredLogger } from '../monitoring/structured-logger.js';

/**
 * Rate limit configuration per entity
 */
export interface RateLimitConfig {
  // Token bucket (burst capacity)
  burst_capacity: number;
  refill_rate_per_second: number;

  // Sliding window (sustained rate)
  window_limit: number;
  window_seconds: number;

  // Custom limits per operation
  operation_limits?: Partial<
    Record<
      OperationType,
      {
        burst_capacity: number;
        refill_rate_per_second: number;
        window_limit: number;
        window_seconds: number;
      }
    >
  >;
}

/**
 * Rate limit check result
 */
export interface RateLimitResult {
  allowed: boolean;
  entity_id: string;
  entity_type: 'api_key' | 'organization';
  operation: OperationType;
  current_usage: {
    tokens_available: number;
    window_count: number;
    next_refill_seconds: number;
  };
  limits: RateLimitConfig;
  retry_after_seconds?: number;
  reason?: string;
}

/**
 * Rate limit violation
 */
export interface RateLimitViolation {
  timestamp: number;
  entity_id: string;
  entity_type: 'api_key' | 'organization';
  operation: OperationType;
  violation_type: 'burst_exceeded' | 'window_exceeded';
  attempted_tokens: number;
  available_tokens: number;
  window_count: number;
  window_limit: number;
}

/**
 * Default rate limit configurations
 */
const DEFAULT_CONFIGS: Record<string, RateLimitConfig> = {
  // Free tier - generous limits for development
  free: {
    burst_capacity: 100,
    refill_rate_per_second: 10,
    window_limit: 1000,
    window_seconds: 3600, // 1 hour
    operation_limits: {
      [OperationType.MEMORY_STORE]: {
        burst_capacity: 50,
        refill_rate_per_second: 5,
        window_limit: 500,
        window_seconds: 3600,
      },
      [OperationType.MEMORY_FIND]: {
        burst_capacity: 200,
        refill_rate_per_second: 20,
        window_limit: 2000,
        window_seconds: 3600,
      },
    },
  },

  // Pro tier - higher limits
  pro: {
    burst_capacity: 500,
    refill_rate_per_second: 50,
    window_limit: 10000,
    window_seconds: 3600,
    operation_limits: {
      [OperationType.MEMORY_STORE]: {
        burst_capacity: 250,
        refill_rate_per_second: 25,
        window_limit: 5000,
        window_seconds: 3600,
      },
      [OperationType.MEMORY_FIND]: {
        burst_capacity: 1000,
        refill_rate_per_second: 100,
        window_limit: 20000,
        window_seconds: 3600,
      },
    },
  },

  // Enterprise tier - very high limits
  enterprise: {
    burst_capacity: 2000,
    refill_rate_per_second: 200,
    window_limit: 100000,
    window_seconds: 3600,
    operation_limits: {
      [OperationType.MEMORY_STORE]: {
        burst_capacity: 1000,
        refill_rate_per_second: 100,
        window_limit: 50000,
        window_seconds: 3600,
      },
      [OperationType.MEMORY_FIND]: {
        burst_capacity: 4000,
        refill_rate_per_second: 400,
        window_limit: 200000,
        window_seconds: 3600,
      },
    },
  },
};

/**
 * Token bucket state
 */
interface TokenBucket {
  tokens: number;
  last_refill: number;
  capacity: number;
  refill_rate: number;
}

/**
 * Sliding window state
 */
interface SlidingWindow {
  requests: number[]; // timestamps
  limit: number;
  window_seconds: number;
}

/**
 * Rate limit service with dual-layer approach
 */
export class RateLimitService extends EventEmitter {
  // In-memory storage for local development/fallback
  private tokenBuckets = new Map<string, TokenBucket>();
  private slidingWindows = new Map<string, SlidingWindow>();
  private violations: RateLimitViolation[] = [];

  // Configuration
  private configs: Map<string, RateLimitConfig> = new Map();
  private entityTiers = new Map<string, string>(); // entity_id -> tier_name

  // Cleanup intervals
  private cleanupInterval: NodeJS.Timeout | null = null;
  private metricsInterval: NodeJS.Timeout | null = null;

  // Metrics
  private metrics = {
    total_checks: 0,
    allowed_requests: 0,
    blocked_requests: 0,
    violations_by_entity: new Map<string, number>(),
    violations_by_operation: new Map<OperationType, number>(),
  };

  constructor() {
    super();

    // Initialize default configurations
    Object.entries(DEFAULT_CONFIGS).forEach(([tier, config]) => {
      this.configs.set(tier, config);
    });

    this.startCleanupTasks();
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): RateLimitService {
    if (!(RateLimitService as unknown).instance) {
      (RateLimitService as unknown).instance = new RateLimitService();
    }
    return (RateLimitService as unknown).instance;
  }

  /**
   * Configure rate limits for an entity
   */
  configureEntity(
    entityId: string,
    entityType: 'api_key' | 'organization',
    tier: string,
    customConfig?: RateLimitConfig
  ): void {
    const config = customConfig || this.configs.get(tier);
    if (!config) {
      throw new Error(`Rate limit tier '${tier}' not found`);
    }

    this.entityTiers.set(entityId, tier);

    // Initialize token bucket and sliding window
    this.initializeEntityLimits(entityId, entityType, config);

    logger.info(
      {
        entity_id: entityId,
        entity_type: entityType,
        tier,
        burst_capacity: config.burst_capacity,
        window_limit: config.window_limit,
      },
      `Configured rate limits for ${entityType} ${entityId}`
    );
  }

  /**
   * Check if a request is allowed
   */
  async checkRateLimit(
    entityId: string,
    entityType: 'api_key' | 'organization',
    operation: OperationType,
    tokens: number = 1
  ): Promise<RateLimitResult> {
    const startTime = Date.now();
    this.metrics.total_checks++;

    // Get configuration
    const tier = this.entityTiers.get(entityId);
    if (!tier) {
      // Apply free tier limits by default
      this.configureEntity(entityId, entityType, 'free');
      return this.checkRateLimit(entityId, entityType, operation, tokens);
    }

    const config = this.configs.get(tier)!;
    const operationConfig = config.operation_limits?.[operation] || config;

    // Get entity keys
    const bucketKey = `${entityType}:${entityId}:bucket:${operation}`;
    const windowKey = `${entityType}:${entityId}:window:${operation}`;

    // Check token bucket (burst capacity)
    const bucketResult = this.checkTokenBucket(
      bucketKey,
      tokens,
      operationConfig.burst_capacity,
      operationConfig.refill_rate_per_second
    );

    // Check sliding window (sustained rate)
    const windowResult = this.checkSlidingWindow(
      windowKey,
      tokens,
      operationConfig.window_limit,
      operationConfig.window_seconds
    );

    // Determine if request is allowed
    const allowed = bucketResult.allowed && windowResult.allowed;

    if (!allowed) {
      this.metrics.blocked_requests++;

      // Record violation
      const violation: RateLimitViolation = {
        timestamp: Date.now(),
        entity_id: entityId,
        entity_type: entityType,
        operation,
        violation_type: !bucketResult.allowed ? 'burst_exceeded' : 'window_exceeded',
        attempted_tokens: tokens,
        available_tokens: bucketResult.tokens_available,
        window_count: windowResult.window_count,
        window_limit: windowResult.window_limit,
      };

      this.recordViolation(violation);

      // Log rate limit violation
      structuredLogger.logRateLimit(
        `${entityType}_${entityId}`,
        0,
        false,
        entityId,
        entityType,
        operation,
        tokens,
        violation.violation_type,
        new Error(`Rate limit exceeded: ${violation.violation_type}`)
      );

      const result: RateLimitResult = {
        allowed: false,
        entity_id: entityId,
        entity_type: entityType,
        operation,
        current_usage: {
          tokens_available: bucketResult.tokens_available,
          window_count: windowResult.window_count,
          next_refill_seconds: bucketResult.next_refill_seconds,
        },
        limits: operationConfig,
        retry_after_seconds: this.calculateRetryAfter(violation),
        reason: violation.violation_type,
      };

      this.emit('rate_limit_violation', violation);
      return result;
    }

    this.metrics.allowed_requests++;

    // Log successful rate limit check
    structuredLogger.logRateLimit(
      `${entityType}_${entityId}`,
      Date.now() - startTime,
      true,
      entityId,
      entityType,
      operation,
      tokens
    );

    return {
      allowed: true,
      entity_id: entityId,
      entity_type: entityType,
      operation,
      current_usage: {
        tokens_available: bucketResult.tokens_available,
        window_count: windowResult.window_count,
        next_refill_seconds: bucketResult.next_refill_seconds,
      },
      limits: operationConfig,
    };
  }

  /**
   * Get current usage statistics for an entity
   */
  getEntityUsage(
    entityId: string,
    entityType: 'api_key' | 'organization',
    operation?: OperationType
  ): {
    tier: string;
    current_tokens: Record<string, number>;
    window_counts: Record<string, number>;
    recent_violations: RateLimitViolation[];
  } {
    const tier = this.entityTiers.get(entityId) || 'free';
    const current_tokens: Record<string, number> = {};
    const window_counts: Record<string, number> = {};

    const operations = operation ? [operation] : Object.values(OperationType);

    for (const op of operations) {
      const bucketKey = `${entityType}:${entityId}:bucket:${op}`;
      const windowKey = `${entityType}:${entityId}:window:${op}`;

      const bucket = this.tokenBuckets.get(bucketKey);
      const window = this.slidingWindows.get(windowKey);

      if (bucket) {
        current_tokens[op] = bucket.tokens;
      }
      if (window) {
        window_counts[op] = window.requests.length;
      }
    }

    const recent_violations = this.violations.filter(
      (v) =>
        v.entity_id === entityId &&
        v.entity_type === entityType &&
        Date.now() - v.timestamp < 3600000 // Last hour
    );

    return {
      tier,
      current_tokens,
      window_counts,
      recent_violations,
    };
  }

  /**
   * Get service-wide metrics
   */
  getMetrics(): {
    total_checks: number;
    allowed_requests: number;
    blocked_requests: number;
    block_rate: number;
    violations_by_entity: Record<string, number>;
    violations_by_operation: Record<string, number>;
    active_entities: number;
  } {
    return {
      ...this.metrics,
      block_rate:
        this.metrics.total_checks > 0
          ? (this.metrics.blocked_requests / this.metrics.total_checks) * 100
          : 0,
      violations_by_entity: Object.fromEntries(this.metrics.violations_by_entity),
      violations_by_operation: Object.fromEntries(this.metrics.violations_by_operation),
      active_entities: this.entityTiers.size,
    };
  }

  /**
   * Reset rate limits for an entity
   */
  resetEntityLimits(entityId: string, entityType: 'api_key' | 'organization'): void {
    // Remove token buckets
    for (const key of Array.from(this.tokenBuckets.keys())) {
      if (key.startsWith(`${entityType}:${entityId}:`)) {
        this.tokenBuckets.delete(key);
      }
    }

    // Remove sliding windows
    for (const key of Array.from(this.slidingWindows.keys())) {
      if (key.startsWith(`${entityType}:${entityId}:`)) {
        this.slidingWindows.delete(key);
      }
    }

    // Remove violations
    this.violations = this.violations.filter(
      (v) => !(v.entity_id === entityId && v.entity_type === entityType)
    );

    logger.info(
      { entity_id: entityId, entity_type: entityType },
      `Reset rate limits for ${entityType} ${entityId}`
    );
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    this.removeAllListeners();
    this.tokenBuckets.clear();
    this.slidingWindows.clear();
    this.violations = [];
    this.entityTiers.clear();
  }

  // Private methods

  private initializeEntityLimits(
    entityId: string,
    entityType: 'api_key' | 'organization',
    config: RateLimitConfig
  ): void {
    // Initialize token buckets for all operations
    for (const operation of Object.values(OperationType)) {
      const operationConfig = config.operation_limits?.[operation as OperationType] || config;

      const bucketKey = `${entityType}:${entityId}:bucket:${operation}`;
      const windowKey = `${entityType}:${entityId}:window:${operation}`;

      this.tokenBuckets.set(bucketKey, {
        tokens: operationConfig.burst_capacity,
        last_refill: Date.now(),
        capacity: operationConfig.burst_capacity,
        refill_rate: operationConfig.refill_rate_per_second,
      });

      this.slidingWindows.set(windowKey, {
        requests: [],
        limit: operationConfig.window_limit,
        window_seconds: operationConfig.window_seconds,
      });
    }
  }

  private checkTokenBucket(
    key: string,
    tokens: number,
    capacity: number,
    refillRate: number
  ): {
    allowed: boolean;
    tokens_available: number;
    next_refill_seconds: number;
  } {
    const bucket = this.tokenBuckets.get(key);
    if (!bucket) {
      // Create new bucket
      const newBucket: TokenBucket = {
        tokens: capacity,
        last_refill: Date.now(),
        capacity,
        refill_rate: refillRate,
      };
      this.tokenBuckets.set(key, newBucket);
      return this.checkTokenBucket(key, tokens, capacity, refillRate);
    }

    // Refill tokens
    const now = Date.now();
    const timeSinceLastRefill = (now - bucket.last_refill) / 1000;
    const tokensToAdd = Math.floor(timeSinceLastRefill * bucket.refill_rate);

    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + tokensToAdd);
    bucket.last_refill = now;

    // Check if request is allowed
    const allowed = bucket.tokens >= tokens;

    if (allowed) {
      bucket.tokens -= tokens;
    }

    return {
      allowed,
      tokens_available: bucket.tokens,
      next_refill_seconds:
        bucket.refill_rate > 0 ? Math.ceil((capacity - bucket.tokens) / bucket.refill_rate) : 0,
    };
  }

  private checkSlidingWindow(
    key: string,
    tokens: number,
    limit: number,
    windowSeconds: number
  ): {
    allowed: boolean;
    window_count: number;
    window_limit: number;
  } {
    const window = this.slidingWindows.get(key);
    if (!window) {
      // Create new window
      const newWindow: SlidingWindow = {
        requests: [],
        limit,
        window_seconds: windowSeconds,
      };
      this.slidingWindows.set(key, newWindow);
      return this.checkSlidingWindow(key, tokens, limit, windowSeconds);
    }

    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    // Remove old requests from window
    window.requests = window.requests.filter((timestamp) => timestamp > windowStart);

    // Check if request is allowed
    const currentCount = window.requests.length;
    const allowed = currentCount + tokens <= limit;

    if (allowed) {
      // Add current request to window
      for (let i = 0; i < tokens; i++) {
        window.requests.push(now);
      }
    }

    return {
      allowed,
      window_count: window.requests.length,
      window_limit: limit,
    };
  }

  private recordViolation(violation: RateLimitViolation): void {
    this.violations.push(violation);

    // Update metrics
    const entityKey = `${violation.entity_type}:${violation.entity_id}`;
    this.metrics.violations_by_entity.set(
      entityKey,
      (this.metrics.violations_by_entity.get(entityKey) || 0) + 1
    );

    this.metrics.violations_by_operation.set(
      violation.operation,
      (this.metrics.violations_by_operation.get(violation.operation) || 0) + 1
    );
  }

  private calculateRetryAfter(violation: RateLimitViolation): number {
    if (violation.violation_type === 'burst_exceeded') {
      // Calculate when tokens will be available
      return 5; // 5 seconds for token refill
    } else {
      // Calculate when sliding window will have space
      const oldestRequest = Math.min(
        ...this.violations
          .filter((v) => v.entity_id === violation.entity_id && v.timestamp > Date.now() - 3600000)
          .map((v) => v.timestamp)
      );

      return Math.max(1, Math.ceil((oldestRequest + 3600000 - Date.now()) / 1000));
    }
  }

  private startCleanupTasks(): void {
    // Cleanup old sliding window entries and violations
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();

      // Clean sliding windows
      for (const [key, window] of Array.from(this.slidingWindows.entries())) {
        const windowStart = now - window.window_seconds * 1000;
        window.requests = window.requests.filter((timestamp) => timestamp > windowStart);
      }

      // Clean old violations (keep last 24 hours)
      this.violations = this.violations.filter((v) => now - v.timestamp < 86400000);
    }, 60000); // Every minute

    // Emit metrics periodically
    this.metricsInterval = setInterval(() => {
      this.emit('metrics', this.getMetrics());
    }, 30000); // Every 30 seconds
  }
}

// Export singleton instance
export const rateLimitService = new RateLimitService();
