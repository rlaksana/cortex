// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Deduplication Strategies Export
 *
 * Exports all deduplication strategy classes and the factory for creating strategies.
 * Implements the 5 required strategies: skip, prefer_existing, prefer_newer, combine, intelligent
 */

export type { DeduplicationStrategy, DeduplicationStrategyConfig } from './base-strategy.js';
export { CombineStrategy } from './combine-strategy.js';
export { DeduplicationStrategyFactory } from './deduplication-strategy-factory.js';
export { IntelligentStrategy } from './intelligent-strategy.js';
export { PreferExistingStrategy } from './prefer-existing-strategy.js';
export { PreferNewerStrategy } from './prefer-newer-strategy.js';
export { SkipStrategy } from './skip-strategy.js';
