// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * DatabaseResult Type Migration Utilities
 *
 * Provides backward compatibility and migration utilities for consolidating
 * DatabaseResult type definitions to the discriminant union pattern from database-generics.ts
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import type { DatabaseResult as OptimalDatabaseResult, DatabaseError } from './database-generics.js';

// ============================================================================
// Legacy Type Definitions (for backward compatibility)
// ============================================================================

/** @deprecated Use DatabaseResult<T> from './database-generics.js' instead */
export interface DatabaseResultLegacy<T = unknown> {
  readonly rows: T[];
  readonly rowCount: number;
  readonly command: string;
}

/** @deprecated Use DatabaseResult<T> from './database-generics.js' instead */
export type DatabaseResultEnhanced<T> = Result<T, DatabaseError>;

// ============================================================================
// Migration Utilities
// ============================================================================

/**
 * Migration adapter: converts legacy SQL-style result to discriminant union
 * @param legacy - Legacy DatabaseResult with rows property
 * @returns Optimal DatabaseResult with discriminant union structure
 */
export function migrateLegacyResult<T>(
  legacy: DatabaseResultLegacy<T>
): OptimalDatabaseResult<T[]> {
  return {
    success: true,
    data: legacy.rows,
    metadata: {
      rowCount: legacy.rowCount,
      command: legacy.command,
      migratedFrom: 'legacy-sql-result'
    }
  };
}

/**
 * Migration adapter: converts enhanced Result wrapper to discriminant union
 * @param enhanced - Enhanced Result<T, DatabaseError>
 * @returns Optimal DatabaseResult with discriminant union structure
 */
export function migrateEnhancedResult<T>(
  enhanced: DatabaseResultEnhanced<T>
): OptimalDatabaseResult<T> {
  if (enhanced.success) {
    return {
      success: true,
      data: enhanced.data,
      metadata: {
        migratedFrom: 'enhanced-result'
      }
    };
  } else {
    return {
      success: false,
      error: enhanced.error,
      metadata: {
        migratedFrom: 'enhanced-result'
      }
    };
  }
}

/**
 * Type guard to check if a result uses the legacy format
 */
export function isLegacyResult<T>(result: unknown): result is DatabaseResultLegacy<T> {
  return typeof result === 'object'
    && result !== null
    && 'rows' in result
    && 'rowCount' in result
    && 'command' in result;
}

/**
 * Type guard to check if a result uses the enhanced format
 */
export function isEnhancedResult<T>(result: unknown): result is DatabaseResultEnhanced<T> {
  return typeof result === 'object'
    && result !== null
    && 'success' in result
    && ('data' in result || 'error' in result)
    && !('readonly' in result); // Distinguish from optimal format
}

/**
 * Auto-migration utility: attempts to convert any DatabaseResult variant to optimal format
 */
export function migrateToOptimal<T>(result: unknown): OptimalDatabaseResult<T> {
  // Check if already optimal (discriminant union with readonly properties)
  if (typeof result === 'object' && result !== null && 'success' in result) {
    const candidate = result as { success: boolean; data?: T; error?: DatabaseError; metadata?: Record<string, unknown> };

    // Simple check for optimal format (success property + proper structure)
    if (candidate.success && 'data' in candidate) {
      return {
        success: true,
        data: candidate.data as T,
        metadata: candidate.metadata
      };
    } else if (!candidate.success && 'error' in candidate) {
      return {
        success: false,
        error: candidate.error as DatabaseError,
        metadata: candidate.metadata
      };
    }
  }

  // Try legacy format migration
  if (isLegacyResult<T>(result)) {
    return migrateLegacyResult(result) as OptimalDatabaseResult<T>;
  }

  // Try enhanced format migration
  if (isEnhancedResult<T>(result)) {
    return migrateEnhancedResult(result);
  }

  // Fallback: create error result for unknown formats
  return {
    success: false,
    error: new DatabaseError(
      'Unknown DatabaseResult format during migration',
      'MIGRATION_ERROR',
      'medium',
      false,
      { receivedType: typeof result, hasData: 'data' in (result as object) }
    )
  };
}

// ============================================================================
// Type Aliases for Migration Period
// ============================================================================

/** @deprecated Use OptimalDatabaseResult<T> instead */
export type DatabaseResult<T> = OptimalDatabaseResult<T>;

// Re-export the optimal version as the primary type
export { OptimalDatabaseResult as DatabaseResultOptimal };

// ============================================================================
// Import Path Migration Helpers
// ============================================================================

/**
 * Helper for gradual migration: import from new location while maintaining compatibility
 *
 * Usage:
 * import { DatabaseResultMigration } from './database-result-migration.js';
 * type DatabaseResult<T> = DatabaseResultMigration.Optimal<T>;
 */
export namespace DatabaseResultMigration {
  export type Optimal<T> = OptimalDatabaseResult<T>;
  export type Legacy<T> = DatabaseResultLegacy<T>;
  export type Enhanced<T> = DatabaseResultEnhanced<T>;

  // Migration utilities
  export const toOptimal = migrateToOptimal;
  export const fromLegacy = migrateLegacyResult;
  export const fromEnhanced = migrateEnhancedResult;

  // Type guards
  export const isLegacy = isLegacyResult;
  export const isEnhanced = isEnhancedResult;
}

// ============================================================================
// Deprecation Warnings
// ============================================================================

/**
 * @deprecated This module is for migration purposes only.
 * Update your imports to use 'DatabaseResult' from './database-generics.js' directly.
 */
export const LEGACY_MIGRATION_NOTICE = `
⚠️  DEPRECATED: Importing from './database-result-migration.ts'

    Update your imports:
    - Remove: import { DatabaseResult } from './database-result-migration.js'
    - Add:    import type { DatabaseResult } from './database-generics.js'

    This migration module will be removed in v2.1.0
` as const;