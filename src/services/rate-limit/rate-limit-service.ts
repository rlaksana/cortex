/**
 * P8-T8.2: Rate Limiting Service
 *
 * Implements per-actor and per-tool rate limiting for MCP operations.
 * Provides configurable limits with sliding window algorithm for fair usage.
 *
 * Features:
 * - Per-actor rate limiting (identified by API key, session ID, or IP)
 * - Per-tool rate limiting (memory_store, memory_find, etc.)
 * - Sliding window algorithm with configurable time windows
 * - In-memory storage with cleanup for expired entries
 * - Graceful degradation under high load
 * - Detailed metrics and logging
 *
 * @module services/rate-limit
 */

import { logger } from '../../utils/logger.js';

export interface RateLimitConfig {
  /** Maximum requests allowed per window */
  limit: number;
  /** Time window in milliseconds */
  windowMs: number;
  /** Whether to skip successful requests from counting */
  skipSuccessfulRequests?: boolean;
  /** Whether to skip failed requests from counting */
  skipFailedRequests?: boolean;
}

export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Remaining requests in current window */
  remaining: number;
  /** When the window resets (timestamp) */
  resetTime: number;
  /** Total requests in current window */
  total: number;
  /** Request identifier for debugging */
  identifier: string;
}

export interface RateLimitMetrics {
  /** Total requests processed */
  totalRequests: number;
  /** Requests blocked by rate limit */
  blockedRequests: number;
  /** Current active windows */
  activeWindows: number;
  /** Memory usage (approximate) */
  memoryUsage: number;
}

/**
 * Rate limiting entry for tracking requests
 */
interface RateLimitEntry {
  /** Request timestamps in current window */
  timestamps: number[];
  /** Last access time for cleanup */
  lastAccess: number;
}

/**
 * Service for rate limiting MCP operations
 */
export class RateLimitService {
  private windows = new Map<string, RateLimitEntry>();
  private metrics: RateLimitMetrics = {
    totalRequests: 0,
    blockedRequests: 0,
    activeWindows: 0,
    memoryUsage: 0
  };

  // Default configurations
  private readonly DEFAULT_CONFIGS: Record<string, RateLimitConfig> = {
    // Memory operations - higher limits for essential functions
    'memory_store': {
      limit: 100, // 100 requests per minute
      windowMs: 60 * 1000, // 1 minute
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    },
    'memory_find': {
      limit: 200, // 200 requests per minute
      windowMs: 60 * 1000, // 1 minute
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    },
    'database_health': {
      limit: 30, // 30 requests per minute
      windowMs: 60 * 1000, // 1 minute
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    },
    'database_stats': {
      limit: 30, // 30 requests per minute
      windowMs: 60 * 1000, // 1 minute
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    },
    'telemetry_report': {
      limit: 10, // 10 requests per minute
      windowMs: 60 * 1000, // 1 minute
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    }
  };

  // Actor-based limits (per user/session)
  private readonly ACTOR_CONFIG: RateLimitConfig = {
    limit: 500, // 500 requests per minute per actor
    windowMs: 60 * 1000, // 1 minute
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  };

  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Cleanup expired entries every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);

    logger.info('RateLimitService initialized with per-actor and per-tool limits');
  }

  /**
   * Check if a request is allowed based on rate limits
   */
  async checkRateLimit(
    toolName: string,
    actorId: string,
    _config?: Partial<RateLimitConfig>
  ): Promise<RateLimitResult> {
    const now = Date.now();
    this.metrics.totalRequests++;

    // Check tool-specific limit
    const toolKey = `tool:${toolName}`;
    const toolResult = this.checkWindow(toolKey, this.DEFAULT_CONFIGS[toolName] || {
      limit: 100,
      windowMs: 60 * 1000
    }, now);

    // Check actor-specific limit
    const actorKey = `actor:${actorId}`;
    const actorResult = this.checkWindow(actorKey, this.ACTOR_CONFIG, now);

    // Request is allowed only if both limits are satisfied
    const allowed = toolResult.allowed && actorResult.allowed;
    const remaining = Math.min(toolResult.remaining, actorResult.remaining);

    if (!allowed) {
      this.metrics.blockedRequests++;
      logger.warn('Rate limit exceeded', {
        tool: toolName,
        actor: actorId,
        toolRemaining: toolResult.remaining,
        actorRemaining: actorResult.remaining,
        identifier: `${toolKey}:${actorKey}`
      });
    }

    return {
      allowed,
      remaining,
      resetTime: Math.max(toolResult.resetTime, actorResult.resetTime),
      total: toolResult.total + actorResult.total,
      identifier: `${toolKey}:${actorKey}`
    };
  }

  /**
   * Check a specific sliding window
   */
  private checkWindow(key: string, config: RateLimitConfig, now: number): RateLimitResult {
    let entry = this.windows.get(key);

    if (!entry) {
      entry = {
        timestamps: [],
        lastAccess: now
      };
      this.windows.set(key, entry);
    }

    entry.lastAccess = now;

    // Remove timestamps outside the current window
    const windowStart = now - config.windowMs;
    entry.timestamps = entry.timestamps.filter(timestamp => timestamp > windowStart);

    // Check if adding this request would exceed the limit
    const allowed = entry.timestamps.length < config.limit;

    // Add current request timestamp
    if (allowed) {
      entry.timestamps.push(now);
    }

    // Calculate remaining requests and reset time
    const remaining = Math.max(0, config.limit - entry.timestamps.length);
    const resetTime = entry.timestamps.length > 0
      ? Math.min(...entry.timestamps) + config.windowMs
      : now + config.windowMs;

    return {
      allowed,
      remaining,
      resetTime,
      total: entry.timestamps.length,
      identifier: key
    };
  }

  /**
   * Cleanup expired entries to prevent memory leaks
   */
  private cleanup(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.windows.entries()) {
      // Remove entries older than 1 hour
      if (now - entry.lastAccess > 60 * 60 * 1000) {
        keysToDelete.push(key);
      } else {
        // Also clean up old timestamps
        const oldestTimestamp = Math.min(...entry.timestamps);
        if (now - oldestTimestamp > 60 * 60 * 1000) {
          entry.timestamps = entry.timestamps.filter(ts => ts > now - 60 * 60 * 1000);
        }
      }
    }

    // Delete expired entries
    for (const key of keysToDelete) {
      this.windows.delete(key);
    }

    if (keysToDelete.length > 0) {
      logger.debug('Rate limit cleanup completed', {
        entriesDeleted: keysToDelete.length,
        remainingEntries: this.windows.size
      });
    }

    // Update metrics
    this.metrics.activeWindows = this.windows.size;
    this.metrics.memoryUsage = this.estimateMemoryUsage();
  }

  /**
   * Estimate memory usage of rate limit data
   */
  private estimateMemoryUsage(): number {
    let totalTimestamps = 0;
    for (const entry of this.windows.values()) {
      totalTimestamps += entry.timestamps.length;
    }

    // Rough estimation: each entry ~100 bytes + each timestamp ~8 bytes
    return (this.windows.size * 100) + (totalTimestamps * 8);
  }

  /**
   * Get current rate limit metrics
   */
  getMetrics(): RateLimitMetrics {
    return { ...this.metrics };
  }

  /**
   * Get detailed status for debugging
   */
  getStatus(): {
    configs: Record<string, RateLimitConfig>;
    metrics: RateLimitMetrics;
    activeWindows: number;
    memoryUsage: string;
  } {
    return {
      configs: this.DEFAULT_CONFIGS,
      metrics: this.metrics,
      activeWindows: this.windows.size,
      memoryUsage: `${(this.metrics.memoryUsage / 1024).toFixed(2)} KB`
    };
  }

  /**
   * Reset rate limit for a specific identifier (for testing/admin)
   */
  reset(identifier: string): void {
    const deleted = this.windows.delete(identifier);
    if (deleted) {
      logger.info('Rate limit reset', { identifier });
    }
  }

  /**
   * Reset all rate limits (emergency use only)
   */
  resetAll(): void {
    const count = this.windows.size;
    this.windows.clear();
    logger.warn('All rate limits reset', { previousEntries: count });
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.windows.clear();
    logger.info('RateLimitService destroyed');
  }
}

// Singleton instance
export const rateLimitService = new RateLimitService();