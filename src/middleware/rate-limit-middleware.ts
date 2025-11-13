// @ts-nocheck - Emergency rollback: Critical middleware service
/**
 * Rate Limit Middleware for Cortex MCP
 *
 * Provides middleware integration for rate limiting:
 * - Express-style middleware for API endpoints
 * - Orchestrator integration for internal operations
 * - Automatic entity detection from auth context
 * - Graceful error handling and responses
 * - Configurable bypass conditions
 */

import { logger } from '@/utils/logger.js';

import { type RateLimitResult,rateLimitService } from './rate-limiter.js';
import { OperationType } from '../monitoring/operation-types.js';
import type { AuthContext } from '../types/auth-types.js';

/**
 * Rate limit middleware options
 */
export interface RateLimitMiddlewareOptions {
  // Operation type for this middleware
  operation: OperationType;

  // Tokens consumed per request (default: 1)
  tokensPerRequest?: number;

  // Enable bypass for certain conditions
  bypassConditions?: {
    // Bypass rate limiting for internal operations
    internalOperations?: boolean;

    // Bypass for specific user roles
    userRoles?: string[];

    // Bypass for specific organizations
    organizations?: string[];

    // Bypass when system is under low load
    lowLoadBypass?: boolean;
  };

  // Custom error response
  onError?: (_result: RateLimitResult) => unknown;

  // Enable detailed logging
  enableLogging?: boolean;
}

/**
 * Rate limit error response
 */
export interface RateLimitError {
  error: 'rate_limit_exceeded';
  message: string;
  entity_id: string;
  entity_type: 'api_key' | 'organization';
  operation: OperationType;
  retry_after_seconds: number;
  current_usage: {
    tokens_available: number;
    window_count: number;
    next_refill_seconds: number;
  };
  limits: {
    burst_capacity: number;
    window_limit: number;
    window_seconds: number;
  };
}

/**
 * Rate limiting middleware class
 */
export class RateLimitMiddleware {
  private options: RateLimitMiddlewareOptions;

  constructor(options: RateLimitMiddlewareOptions) {
    this.options = {
      tokensPerRequest: 1,
      enableLogging: true,
      bypassConditions: {},
      ...options,
    };
  }

  /**
   * Create middleware function for Express-style usage
   */
  createMiddleware() {
    return async (req: unknown, res: unknown, next: unknown): Promise<void> => {
      try {
        const authContext = req.auth as AuthContext;
        const result = await this.checkRateLimit(authContext, req);

        if (!result.allowed) {
          const errorResponse = this.createErrorResponse(result);

          if (this.options.onError) {
            this.options.onError(result);
            return;
          }

          res.status(429).json(errorResponse);
          return;
        }

        // Add rate limit info to request
        req.rateLimit = {
          allowed: true,
          tokensAvailable: result.current_usage.tokens_available,
          windowCount: result.current_usage.window_count,
        };

        next();
      } catch (error) {
        logger.error({ error, operation: this.options.operation }, 'Rate limit middleware error');

        // Fail open - allow request if rate limiting fails
        req.rateLimit = { allowed: true, error: true };
        next();
      }
    };
  }

  /**
   * Check rate limit for orchestrator operations
   */
  async checkOrchestratorRateLimit(
    authContext?: AuthContext,
    operationOverride?: OperationType,
    tokensOverride?: number
  ): Promise<{
    allowed: boolean;
    tokensAvailable: number;
    windowCount: number;
    error?: RateLimitError;
  }> {
    try {
      const result = await this.checkRateLimit(
        authContext,
        null,
        operationOverride,
        tokensOverride
      );

      if (!result.allowed) {
        return {
          allowed: false,
          tokensAvailable: result.current_usage.tokens_available,
          windowCount: result.current_usage.window_count,
          error: this.createErrorResponse(result),
        };
      }

      return {
        allowed: true,
        tokensAvailable: result.current_usage.tokens_available,
        windowCount: result.current_usage.window_count,
      };
    } catch (error) {
      logger.error(
        { error, operation: this.options.operation },
        'Orchestrator rate limit check error'
      );

      // Fail open
      return {
        allowed: true,
        tokensAvailable: 0,
        windowCount: 0,
      };
    }
  }

  /**
   * Check rate limit with provided context
   */
  private async checkRateLimit(
    authContext?: AuthContext,
    request?: unknown,
    operationOverride?: OperationType,
    tokensOverride?: number
  ): Promise<RateLimitResult> {
    const operation = operationOverride || this.options.operation;
    const tokens = tokensOverride || this.options.tokensPerRequest!;

    // Check bypass conditions
    if (this.shouldBypass(authContext, request)) {
      return {
        allowed: true,
        entity_id: 'bypass',
        entity_type: 'api_key',
        operation,
        current_usage: {
          tokens_available: Number.MAX_SAFE_INTEGER,
          window_count: 0,
          next_refill_seconds: 0,
        },
        limits: {
          burst_capacity: Number.MAX_SAFE_INTEGER,
          refill_rate_per_second: Number.MAX_SAFE_INTEGER,
          window_limit: Number.MAX_SAFE_INTEGER,
          window_seconds: 3600,
        },
      };
    }

    // Extract entity information from auth context
    const { entityId, entityType } = this.extractEntityInfo(authContext);

    if (!entityId) {
      // No auth context - apply anonymous limits
      return await rateLimitService.checkRateLimit('anonymous', 'api_key', operation, tokens);
    }

    // Check rate limits
    return await rateLimitService.checkRateLimit(entityId, entityType, operation, tokens);
  }

  /**
   * Determine if request should bypass rate limiting
   */
  private shouldBypass(authContext?: AuthContext, request?: unknown): boolean {
    if (!this.options.bypassConditions) {
      return false;
    }

    const { internalOperations, userRoles, organizations, lowLoadBypass } =
      this.options.bypassConditions;

    // Bypass internal operations
    if (internalOperations && request?.internal) {
      return true;
    }

    // Bypass specific user roles
    if (userRoles && authContext?.user?.role && userRoles.includes(authContext.user.role)) {
      return true;
    }

    // Bypass specific organizations
    if (
      organizations &&
      authContext?.user?.organizationId &&
      organizations.includes(authContext.user.organizationId)
    ) {
      return true;
    }

    // Bypass under low load conditions
    if (lowLoadBypass && this.isSystemUnderLowLoad()) {
      return true;
    }

    return false;
  }

  /**
   * Extract entity information from auth context
   */
  private extractEntityInfo(authContext?: AuthContext): {
    entityId: string;
    entityType: 'api_key' | 'organization';
  } {
    if (!authContext) {
      return { entityId: 'anonymous', entityType: 'api_key' };
    }

    // Prefer API key rate limiting
    if (authContext.apiKeyId) {
      return {
        entityId: authContext.apiKeyId,
        entityType: 'api_key' as const,
      };
    }

    // Fall back to organization rate limiting
    if (authContext.user?.organizationId) {
      return {
        entityId: authContext.user.organizationId,
        entityType: 'organization' as const,
      };
    }

    // Fall back to user-based rate limiting
    if (authContext.user?.id) {
      return {
        entityId: authContext.user.id,
        entityType: 'api_key' as const,
      };
    }

    return { entityId: 'anonymous', entityType: 'api_key' };
  }

  /**
   * Create standardized error response
   */
  private createErrorResponse(result: RateLimitResult): RateLimitError {
    return {
      error: 'rate_limit_exceeded',
      message: `Rate limit exceeded for ${result.entity_type} ${result.entity_id}. Reason: ${result.reason || 'Unknown'}. Retry after ${result.retry_after_seconds} seconds.`,
      entity_id: result.entity_id,
      entity_type: result.entity_type,
      operation: result.operation,
      retry_after_seconds: result.retry_after_seconds || 60,
      current_usage: result.current_usage,
      limits: {
        burst_capacity: result.limits.burst_capacity,
        window_limit: result.limits.window_limit,
        window_seconds: result.limits.window_seconds,
      },
    };
  }

  /**
   * Check if system is under low load
   */
  private isSystemUnderLowLoad(): boolean {
    // Simple heuristic - could be enhanced with actual metrics
    return false; // Conservative approach - don't bypass by default
  }
}

/**
 * Factory function to create rate limit middleware
 */
export function createRateLimitMiddleware(
  options: RateLimitMiddlewareOptions
): RateLimitMiddleware {
  return new RateLimitMiddleware(options);
}

/**
 * Pre-configured middleware for common operations
 */
export const rateLimitMiddleware = {
  /**
   * Memory store rate limiting
   */
  memoryStore: (options?: Partial<RateLimitMiddlewareOptions>) =>
    createRateLimitMiddleware({
      operation: OperationType.MEMORY_STORE,
      tokensPerRequest: 1,
      enableLogging: true,
      ...options,
    }),

  /**
   * Memory find rate limiting
   */
  memoryFind: (options?: Partial<RateLimitMiddlewareOptions>) =>
    createRateLimitMiddleware({
      operation: OperationType.MEMORY_FIND,
      tokensPerRequest: 1,
      enableLogging: true,
      ...options,
    }),

  /**
   * Embedding generation rate limiting
   */
  embedding: (options?: Partial<RateLimitMiddlewareOptions>) =>
    createRateLimitMiddleware({
      operation: OperationType.EMBEDDING,
      tokensPerRequest: 1,
      enableLogging: true,
      ...options,
    }),

  /**
   * Generic rate limiting for any operation
   */
  custom: (operation: OperationType, options?: Partial<RateLimitMiddlewareOptions>) =>
    createRateLimitMiddleware({
      operation,
      tokensPerRequest: 1,
      enableLogging: true,
      ...options,
    }),
};
