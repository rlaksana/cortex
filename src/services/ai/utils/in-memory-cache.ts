/**
 * In-Memory Cache Implementation
 *
 * Simple thread-safe in-memory cache with TTL support
 * for ZAI responses and other cached data
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { ZAICache, ZAIChatResponse } from '../../../types/zai-interfaces';

/**
 * Simple in-memory cache implementation with TTL support
 */
export class InMemoryCache implements ZAICache {
  private cache = new Map<string, { data: ZAIChatResponse; expiry: number }>();
  private statsData = { hits: 0, misses: 0 };

  /**
   * Get value from cache
   */
  async get(key: string): Promise<ZAIChatResponse | null> {
    const entry = this.cache.get(key);
    if (!entry) {
      this.statsData.misses++;
      return null;
    }

    // Check if entry has expired
    if (Date.now() > entry.expiry) {
      this.cache.delete(key);
      this.statsData.misses++;
      return null;
    }

    this.statsData.hits++;
    return entry.data;
  }

  /**
   * Set value in cache with optional TTL
   */
  async set(key: string, value: ZAIChatResponse, ttlMs: number = 3600000): Promise<void> {
    const expiry = Date.now() + ttlMs;
    this.cache.set(key, { data: value, expiry });
  }

  /**
   * Delete value from cache
   */
  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }

  /**
   * Clear all cache entries
   */
  async clear(): Promise<void> {
    this.cache.clear();
    this.statsData.hits = 0;
    this.statsData.misses = 0;
  }

  /**
   * Get number of cached items
   */
  async size(): Promise<number> {
    return this.cache.size;
  }

  /**
   * Get cache statistics
   */
  async stats(): Promise<{ hits: number; misses: number; hitRate: number }> {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.statsData,
      hitRate: total > 0 ? this.stats.hits / total : 0,
    };
  }

  /**
   * Clean up expired entries
   */
  async cleanup(): Promise<number> {
    const now = Date.now();
    let cleanedCount = 0;
    const keysToDelete: string[] = [];

    // Collect expired keys first
    this.cache.forEach((entry, key) => {
      if (now > entry.expiry) {
        keysToDelete.push(key);
      }
    });

    // Delete expired entries
    keysToDelete.forEach((key) => {
      this.cache.delete(key);
      cleanedCount++;
    });

    return cleanedCount;
  }

  /**
   * Reset cache statistics
   */
  async resetStats(): Promise<void> {
    this.statsData.hits = 0;
    this.statsData.misses = 0;
  }
}
