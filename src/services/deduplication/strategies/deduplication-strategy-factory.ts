
/**
 * Deduplication Strategy Factory
 *
 * Factory for creating deduplication strategy instances.
 * Supports creating strategies by name and with custom configurations.
 */

import { logger } from '@/utils/logger.js';

import type { DeduplicationStrategy,DeduplicationStrategyConfig } from './base-strategy.js';
import { CombineStrategy, type CombineStrategyConfig } from './combine-strategy.js';
import { IntelligentStrategy, type IntelligentStrategyConfig } from './intelligent-strategy.js';
import {
  PreferExistingStrategy,
  type PreferExistingStrategyConfig,
} from './prefer-existing-strategy.js';
import { PreferNewerStrategy, type PreferNewerStrategyConfig } from './prefer-newer-strategy.js';
import { SkipStrategy, type SkipStrategyConfig } from './skip-strategy.js';
import type { MergeStrategy } from '../../../config/deduplication-config.js';

// Re-export strategy types for convenience
export type {
  DeduplicationResult,
  DeduplicationStrategy,
  DeduplicationStrategyConfig,
  DuplicateAnalysis,
} from './base-strategy.js';
export type { CombineStrategyConfig } from './combine-strategy.js';
export type { IntelligentStrategyConfig } from './intelligent-strategy.js';
export type { PreferExistingStrategyConfig } from './prefer-existing-strategy.js';
export type { PreferNewerStrategyConfig } from './prefer-newer-strategy.js';
export type { SkipStrategyConfig } from './skip-strategy.js';

// Strategy class union type
export type StrategyClass =
  | typeof SkipStrategy
  | typeof PreferExistingStrategy
  | typeof PreferNewerStrategy
  | typeof CombineStrategy
  | typeof IntelligentStrategy;

/**
 * Factory class for creating deduplication strategies
 */
export class DeduplicationStrategyFactory {
  private static strategyRegistry = new Map<string, StrategyClass>([
    ['skip', SkipStrategy],
    ['prefer_existing', PreferExistingStrategy],
    ['prefer_newer', PreferNewerStrategy],
    ['combine', CombineStrategy],
    ['intelligent', IntelligentStrategy],
  ]);

  /**
   * Create a deduplication strategy instance
   * @param name Name of the strategy to create
   * @param config Configuration options for the strategy
   * @returns Instance of the requested strategy
   */
  static createDedupStrategy(
    name: MergeStrategy | string,
    config?: DeduplicationStrategyConfig
  ): DeduplicationStrategy {
    const normalized = this.normalizeStrategyName(name);
    const StrategyClass = this.strategyRegistry.get(normalized);

    if (!StrategyClass) {
      const available = Array.from(this.strategyRegistry.keys());
      throw new Error(
        `Unknown deduplication strategy: '${name}'. Available strategies: ${available.join(', ')}`
      );
    }

    try {
      return new StrategyClass(config || {}) as DeduplicationStrategy;
    } catch (error) {
      logger.error(
        { error, strategyName: name, config },
        'Failed to create deduplication strategy'
      );
      throw new Error(
        `Failed to create ${name} strategy: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Get all available strategy names
   */
  static getAvailableStrategies(): string[] {
    return Array.from(this.strategyRegistry.keys());
  }

  /**
   * Check if a strategy is available
   * @param name Strategy name to check
   * @returns True if strategy exists
   */
  static isStrategyAvailable(name: string): boolean {
    const normalized = this.normalizeStrategyName(name);
    return this.strategyRegistry.has(normalized);
  }

  /**
   * Register a custom strategy class
   * @param name Name to register the strategy under
   * @param strategyClass Strategy constructor class
   */
  static registerStrategy(name: string, strategyClass: StrategyClass): void {
    const normalized = this.normalizeStrategyName(name);

    if (this.strategyRegistry.has(normalized)) {
      logger.warn({ strategyName: name }, 'Overriding existing deduplication strategy');
    }

    this.strategyRegistry.set(normalized, strategyClass);
    logger.info({ strategyName: name }, 'Registered custom deduplication strategy');
  }

  /**
   * Unregister a strategy
   * @param name Name of the strategy to unregister
   */
  static unregisterStrategy(name: string): boolean {
    const normalized = this.normalizeStrategyName(name);
    const removed = this.strategyRegistry.delete(normalized);

    if (removed) {
      logger.info({ strategyName: name }, 'Unregistered deduplication strategy');
    } else {
      logger.warn({ strategyName: name }, 'Attempted to unregister non-existent strategy');
    }

    return removed;
  }

  /**
   * Get default configuration for a strategy
   * @param name Strategy name
   * @returns Default configuration object
   */
  static getDefaultConfig(name: MergeStrategy | string): DeduplicationStrategyConfig {
    const normalized = this.normalizeStrategyName(name);

    switch (normalized) {
      case 'skip':
        return {
          logSkippedItems: false,
          performBasicValidation: true,
        };

      case 'prefer_existing':
        return {
          similarityThreshold: 0.85,
          checkWithinScopeOnly: true,
          respectTimestamps: true,
        };

      case 'prefer_newer':
        return {
          similarityThreshold: 0.85,
          checkWithinScopeOnly: true,
          respectUpdateTimestamps: true,
          timeWindowHours: 24 * 7, // 1 week
        };

      case 'combine':
        return {
          similarityThreshold: 0.8,
          checkWithinScopeOnly: true,
          mergeConflictResolution: 'prefer_newer',
          preserveMergeHistory: true,
          maxMergeHistoryEntries: 10,
        };

      case 'intelligent':
        return {
          similarityThreshold: 0.75,
          semanticThreshold: 0.8,
          contentThreshold: 0.6,
          enableSemanticAnalysis: true,
          enableKeywordExtraction: true,
          weightingFactors: {
            title: 2.0,
            content: 1.0,
            metadata: 0.5,
          },
          maxHistoryHours: 24 * 7, // 1 week
          crossScopeDeduplication: false,
          prioritizeSameScope: true,
        };

      default:
        throw new Error(`No default configuration available for strategy: '${name}'`);
    }
  }

  /**
   * Validate configuration for a strategy
   * @param name Strategy name
   * @param config Configuration to validate
   * @returns Validation result with any errors
   */
  static validateConfig(
    name: MergeStrategy | string,
    config: DeduplicationStrategyConfig
  ): { valid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];
    const normalized = this.normalizeStrategyName(name);

    // Common validations
    if (config.similarityThreshold !== undefined) {
      if (
        typeof config.similarityThreshold !== 'number' ||
        config.similarityThreshold < 0 ||
        config.similarityThreshold > 1
      ) {
        errors.push('similarityThreshold must be a number between 0 and 1');
      } else if (config.similarityThreshold < 0.5) {
        warnings.push('Low similarity threshold may cause false positives');
      }
    }

    // Strategy-specific validations
    switch (normalized) {
      case 'prefer_newer':
        if (config.timeWindowHours !== undefined && config.timeWindowHours < 0) {
          errors.push('timeWindowHours must be non-negative');
        }
        break;

      case 'intelligent':
        if (
          config.semanticThreshold !== undefined &&
          config.contentThreshold !== undefined &&
          config.semanticThreshold <= config.contentThreshold
        ) {
          warnings.push(
            'semanticThreshold should be higher than contentThreshold for better results'
          );
        }
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Create a strategy with environment variable configuration
   * @param name Strategy name
   * @returns Strategy instance configured from environment
   */
  static createFromEnvironment(name: MergeStrategy | string): DeduplicationStrategy {
    const envConfig = this.loadConfigFromEnvironment(name);
    return this.createDedupStrategy(name, envConfig);
  }

  /**
   * Load strategy configuration from environment variables
   * @param name Strategy name
   * @returns Configuration object from environment variables
   */
  private static loadConfigFromEnvironment(name: string): DeduplicationStrategyConfig {
    const config: DeduplicationStrategyConfig = {};
    const normalized = this.normalizeStrategyName(name);
    const prefix = `DEDUPE_${normalized.toUpperCase()}`;

    // Load common configuration
    if (process.env[`${prefix}_ENABLED`] !== undefined) {
      config.enabled = process.env[`${prefix}_ENABLED`] === 'true';
    }

    if (process.env[`${prefix}_SIMILARITY_THRESHOLD`] !== undefined) {
      const threshold = parseFloat(process.env[`${prefix}_SIMILARITY_THRESHOLD`]!);
      if (!isNaN(threshold)) {
        config.similarityThreshold = threshold;
      }
    }

    if (process.env[`${prefix}_CHECK_WITHIN_SCOPE_ONLY`] !== undefined) {
      config.checkWithinScopeOnly = process.env[`${prefix}_CHECK_WITHIN_SCOPE_ONLY`] === 'true';
    }

    // Load strategy-specific configuration
    switch (normalized) {
      case 'intelligent':
        if (process.env[`${prefix}_SEMANTIC_THRESHOLD`] !== undefined) {
          const threshold = parseFloat(process.env[`${prefix}_SEMANTIC_THRESHOLD`]!);
          if (!isNaN(threshold)) {
            (config as IntelligentStrategyConfig).semanticThreshold = threshold;
          }
        }
        break;

      case 'prefer_newer':
        if (process.env[`${prefix}_TIME_WINDOW_HOURS`] !== undefined) {
          const hours = parseInt(process.env[`${prefix}_TIME_WINDOW_HOURS`]!, 10);
          if (!isNaN(hours)) {
            (config as PreferNewerStrategyConfig).timeWindowHours = hours;
          }
        }
        break;
    }

    return config;
  }

  /**
   * Normalize strategy name for consistent lookup
   * @param name Strategy name to normalize
   * @returns Normalized strategy name
   */
  private static normalizeStrategyName(name: string): string {
    return name.toLowerCase().replace(/[-_]/g, '_');
  }
}

/**
 * Export factory function for convenience
 */
export function createDedupStrategy(
  name: MergeStrategy | string,
  config?: DeduplicationStrategyConfig
): DeduplicationStrategy {
  return DeduplicationStrategyFactory.createDedupStrategy(name, config);
}
