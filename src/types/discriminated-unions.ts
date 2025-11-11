/**
 * Discriminated Union Utilities
 *
 * Utility functions and types for working with discriminated unions
 * to provide better type safety and exhaustive checking
 */

export type SearchStrategyType = 'semantic' | 'keyword' | 'hybrid' | 'expanded' | 'graph' | 'fallback' | 'auto';

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
export function isZAIProvider(provider: any): provider is { type: 'zai' } {
  return provider.type === 'zai';
}

export function isOpenAIProvider(provider: any): provider is { type: 'openai' } {
  return provider.type === 'openai';
}

export function isAutoMode(mode: any): mode is { mode: 'auto' } {
  return mode.mode === 'auto';
}

export function isFastMode(mode: any): mode is { mode: 'fast' } {
  return mode.mode === 'fast';
}

export function isDeepMode(mode: any): mode is { mode: 'deep' } {
  return mode.mode === 'deep';
}

export function isSemanticStrategy(strategy: any): strategy is { strategy: 'semantic' } {
  return strategy.strategy === 'semantic';
}

export function isKeywordStrategy(strategy: any): strategy is { strategy: 'keyword' } {
  return strategy.strategy === 'keyword';
}

export function isHybridStrategy(strategy: any): strategy is { strategy: 'hybrid' } {
  return strategy.strategy === 'hybrid';
}

export function isHealthyStatus(status: any): status is { status: 'healthy' } {
  return status.status === 'healthy';
}

export function isDegradedStatus(status: any): status is { status: 'degraded' } {
  return status.status === 'degraded';
}

export function isUnhealthyStatus(status: any): status is { status: 'unhealthy' } {
  return status.status === 'unhealthy';
}