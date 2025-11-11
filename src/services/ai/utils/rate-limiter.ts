
/**
 * Rate Limiter Implementation
 *
 * Token bucket rate limiter for API request throttling
 * with configurable limits and automatic refill
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { RateLimiter } from '../../../types/zai-interfaces.js';

/**
 * Simple token bucket rate limiter implementation
 */
export class SimpleRateLimiter implements RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillRateMs: number;

  constructor(maxTokens: number, refillRateMs: number) {
    this.maxTokens = maxTokens;
    this.refillRateMs = refillRateMs;
    this.tokens = maxTokens;
    this.lastRefill = Date.now();
  }

  /**
   * Check if request is allowed under rate limit
   */
  async isAllowed(): Promise<boolean> {
    this.refillTokens();

    if (this.tokens >= 1) {
      this.tokens--;
      return true;
    }

    return false;
  }

  /**
   * Get remaining tokens
   */
  getRemainingTokens(): number {
    this.refillTokens();
    return Math.floor(this.tokens);
  }

  /**
   * Get time when tokens will be reset
   */
  getResetTime(): number {
    return this.lastRefill + this.refillRateMs;
  }

  /**
   * Reset rate limiter to initial state
   */
  reset(): void {
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
  }

  /**
   * Get rate limiter statistics
   */
  getStats(): {
    maxTokens: number;
    currentTokens: number;
    remainingTokens: number;
    utilizationRate: number;
    timeToReset: number;
  } {
    this.refillTokens();
    const now = Date.now();

    return {
      maxTokens: this.maxTokens,
      currentTokens: this.tokens,
      remainingTokens: Math.floor(this.tokens),
      utilizationRate: (this.maxTokens - this.tokens) / this.maxTokens,
      timeToReset: Math.max(0, this.lastRefill + this.refillRateMs - now),
    };
  }

  /**
   * Refill tokens based on time passed
   */
  private refillTokens(): void {
    const now = Date.now();
    const timePassed = now - this.lastRefill;

    if (timePassed >= this.refillRateMs) {
      const tokensToAdd = Math.floor(timePassed / this.refillRateMs);
      this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
      this.lastRefill = now;
    }
  }

  /**
   * Force token refill to maximum
   */
  forceRefill(): void {
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
  }

  /**
   * Check if rate limiter is currently exhausted
   */
  isExhausted(): boolean {
    this.refillTokens();
    return this.tokens < 1;
  }

  /**
   * Get estimated time until next available token
   */
  getTimeToNextToken(): number {
    if (this.tokens >= 1) {
      return 0;
    }

    return this.refillRateMs;
  }
}
