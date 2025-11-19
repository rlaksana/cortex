// ABSOLUTELY FINAL EMERGENCY ROLLBACK: Complete ALL systematic type issues

/**
 * Discriminated Union Utilities
 *
 * Utility functions and types for working with discriminated unions
 * to provide better type safety and exhaustive checking
 */

export type SearchStrategyType =
  | 'semantic'
  | 'keyword'
  | 'hybrid'
  | 'expanded'
  | 'graph'
  | 'fallback'
  | 'auto';

export interface BaseSearchStrategy {
  type: SearchStrategyType;
}

export interface SemanticSearchStrategy extends BaseSearchStrategy {
  type: 'semantic';
  vectorEnabled: boolean;
  similarityThreshold: number;
  maxResults: number;
}

export interface KeywordSearchStrategy extends BaseSearchStrategy {
  type: 'keyword';
  exactMatch: boolean;
  caseSensitive: boolean;
  includeContext: boolean;
}

export interface HybridSearchStrategy extends BaseSearchStrategy {
  type: 'hybrid';
  semanticWeight: number;
  keywordWeight: number;
  vectorEnabled: boolean;
}

export interface ExpandedSearchStrategy extends BaseSearchStrategy {
  type: 'expanded';
  expansionTerms: string[];
  maxExpansions: number;
}

export interface GraphSearchStrategy extends BaseSearchStrategy {
  type: 'graph';
  depth: number;
  includeRelated: boolean;
}

export interface FallbackSearchStrategy extends BaseSearchStrategy {
  type: 'fallback';
  originalStrategy: SearchStrategyType;
  fallbackReason: string;
}

export interface AutoSearchStrategy extends BaseSearchStrategy {
  type: 'auto';
  confidenceThreshold: number;
  enableFallback: boolean;
}

export type SearchStrategy =
  | SemanticSearchStrategy
  | KeywordSearchStrategy
  | HybridSearchStrategy
  | ExpandedSearchStrategy
  | GraphSearchStrategy
  | FallbackSearchStrategy
  | AutoSearchStrategy;

/**
 * Helper function for exhaustive switch statements
 * Ensures all cases are handled at compile time
 */
export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${value}`);
}

/**
 * Type Guards
 */
function hasKey<K extends PropertyKey>(value: unknown, key: K): value is Record<K, unknown> {
  return !!value && typeof value === 'object' && key in value;
}

export function isZAIProvider(provider: unknown): provider is { type: 'zai' } {
  return hasKey(provider, 'type') && (provider as Record<string, unknown>).type === 'zai';
}

export function isOpenAIProvider(provider: unknown): provider is { type: 'openai' } {
  return hasKey(provider, 'type') && (provider as Record<string, unknown>).type === 'openai';
}

export function isAutoMode(mode: unknown): mode is { mode: 'auto' } {
  return hasKey(mode, 'mode') && (mode as Record<string, unknown>).mode === 'auto';
}

export function isFastMode(mode: unknown): mode is { mode: 'fast' } {
  return hasKey(mode, 'mode') && (mode as Record<string, unknown>).mode === 'fast';
}

export function isDeepMode(mode: unknown): mode is { mode: 'deep' } {
  return hasKey(mode, 'mode') && (mode as Record<string, unknown>).mode === 'deep';
}

export function isSemanticStrategy(strategy: unknown): strategy is { strategy: 'semantic' } {
  return hasKey(strategy, 'strategy') && (strategy as Record<string, unknown>).strategy === 'semantic';
}

export function isKeywordStrategy(strategy: unknown): strategy is { strategy: 'keyword' } {
  return hasKey(strategy, 'strategy') && (strategy as Record<string, unknown>).strategy === 'keyword';
}

export function isHybridStrategy(strategy: unknown): strategy is { strategy: 'hybrid' } {
  return hasKey(strategy, 'strategy') && (strategy as Record<string, unknown>).strategy === 'hybrid';
}

export function isHealthyStatus(status: unknown): status is { status: 'healthy' } {
  return hasKey(status, 'status') && (status as Record<string, unknown>).status === 'healthy';
}

export function isDegradedStatus(status: unknown): status is { status: 'degraded' } {
  return hasKey(status, 'status') && (status as Record<string, unknown>).status === 'degraded';
}

export function isUnhealthyStatus(status: unknown): status is { status: 'unhealthy' } {
  return hasKey(status, 'status') && (status as Record<string, unknown>).status === 'unhealthy';
}
