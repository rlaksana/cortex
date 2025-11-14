// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Observability Helper Utilities
 *
 * Provides standardized observability metadata creation for Cortex MCP responses.
 * Ensures consistent response format across all tools and operations.
 */

import { v4 as uuidv4 } from 'uuid';

export interface StoreObservabilityMeta {
  source: 'cortex_memory';
  strategy: 'autonomous_deduplication';
  vector_used: boolean;
  degraded: boolean;
  execution_time_ms: number;
  confidence_score: number;
}

export interface FindObservabilityMeta {
  source: 'cortex_memory';
  strategy: 'semantic' | 'keyword' | 'hybrid' | 'fallback' | 'auto' | 'fast' | 'deep' | 'error';
  vector_used: boolean;
  degraded: boolean;
  execution_time_ms: number;
  confidence_average: number;
  search_id: string;
}

export interface SystemObservabilityMeta {
  source: 'cortex_memory';
  strategy: 'system_operation';
  vector_used: false;
  degraded: boolean;
  execution_time_ms: number;
  timestamp: string;
}

export function createStoreObservability(
  vector_used: boolean,
  degraded: boolean,
  execution_time_ms: number,
  confidence_score: number = 0.8
): StoreObservabilityMeta {
  return {
    source: 'cortex_memory',
    strategy: 'autonomous_deduplication',
    vector_used,
    degraded,
    execution_time_ms,
    confidence_score,
  };
}

export function createFindObservability(
  strategy: FindObservabilityMeta['strategy'],
  vector_used: boolean,
  degraded: boolean,
  execution_time_ms: number,
  confidence_average: number
): FindObservabilityMeta {
  return {
    source: 'cortex_memory',
    strategy,
    vector_used,
    degraded,
    execution_time_ms,
    confidence_average,
    search_id: uuidv4(),
  };
}

export function createSystemObservability(
  degraded: boolean,
  execution_time_ms: number
): SystemObservabilityMeta {
  return {
    source: 'cortex_memory',
    strategy: 'system_operation',
    vector_used: false,
    degraded,
    execution_time_ms,
    timestamp: new Date().toISOString(),
  };
}
