/**
 * Enhanced configuration system for deduplication
 *
 * Provides configurable deduplication behavior with:
 * - Similarity thresholds
 * - Time windows
 * - Scope rules
 * - Merge strategies
 */

export interface DeduplicationConfig {
  // Basic deduplication settings
  enabled: boolean;
  contentSimilarityThreshold: number;
  checkWithinScopeOnly: boolean;
  maxHistoryHours: number;
  dedupeWindowDays: number;
  allowNewerVersions: boolean;
  enableAuditLogging: boolean;

  // Enhanced merge strategies
  mergeStrategy: MergeStrategy;
  enableIntelligentMerging: boolean;
  preserveMergeHistory: boolean;
  maxMergeHistoryEntries: number;

  // Scope filtering rules
  scopeFilters: ScopeFilters;
  crossScopeDeduplication: boolean;
  prioritizeSameScope: boolean;

  // Time-based deduplication
  timeBasedDeduplication: boolean;
  maxAgeForDedupeDays: number;
  respectUpdateTimestamps: boolean;

  // Content analysis settings
  contentAnalysisSettings: ContentAnalysisSettings;
  enableSemanticAnalysis: boolean;

  // Performance settings
  maxItemsToCheck: number;
  batchSize: number;
  enableParallelProcessing: boolean;
}

export type MergeStrategy = 'skip' | 'prefer_existing' | 'prefer_newer' | 'combine' | 'intelligent';

export interface ScopeFilters {
  org: {
    enabled: boolean;
    priority: number;
  };
  project: {
    enabled: boolean;
    priority: number;
  };
  branch: {
    enabled: boolean;
    priority: number;
  };
}

export interface ContentAnalysisSettings {
  minLengthForAnalysis: number;
  enableSemanticAnalysis: boolean;
  enableKeywordExtraction: boolean;
  ignoreCommonWords: boolean;
  customStopWords: string[];
  weightingFactors: {
    title: number;
    content: number;
    metadata: number;
  };
}

export interface DeduplicationResult {
  action: 'stored' | 'skipped' | 'merged' | 'updated';
  similarityScore: number;
  matchType: 'none' | 'exact' | 'content' | 'semantic' | 'partial';
  reason: string;
  existingId?: string;
  mergeDetails?: MergeDetails;
  auditLog?: AuditLogEntry;
}

export interface MergeDetails {
  strategy: MergeStrategy;
  fieldsMerged: string[];
  conflictsResolved: string[];
  newFieldsAdded: string[];
  mergeDuration: number;
}

export interface AuditLogEntry {
  timestamp: string;
  itemId: string;
  action: string;
  similarityScore: number;
  strategy: MergeStrategy;
  matchType: string;
  scope: {
    org?: string;
    project?: string;
    branch?: string;
  };
  existingId?: string;
  reason: string;
  mergeDetails?: MergeDetails;
  configSnapshot: Partial<DeduplicationConfig>;
}

/**
 * Default configuration for deduplication
 */
export const DEFAULT_DEDUPLICATION_CONFIG: DeduplicationConfig = {
  // Basic settings
  enabled: true,
  contentSimilarityThreshold: 0.85,
  checkWithinScopeOnly: true,
  maxHistoryHours: 24 * 7, // 1 week
  dedupeWindowDays: 7,
  allowNewerVersions: true,
  enableAuditLogging: true,

  // Enhanced merge strategies
  mergeStrategy: 'intelligent',
  enableIntelligentMerging: true,
  preserveMergeHistory: true,
  maxMergeHistoryEntries: 10,

  // Scope filtering rules
  scopeFilters: {
    org: { enabled: true, priority: 3 },
    project: { enabled: true, priority: 2 },
    branch: { enabled: false, priority: 1 },
  },
  crossScopeDeduplication: false,
  prioritizeSameScope: true,

  // Time-based deduplication
  timeBasedDeduplication: true,
  maxAgeForDedupeDays: 30,
  respectUpdateTimestamps: true,

  // Content analysis settings
  contentAnalysisSettings: {
    minLengthForAnalysis: 10,
    enableSemanticAnalysis: true,
    enableKeywordExtraction: true,
    ignoreCommonWords: true,
    customStopWords: [],
    weightingFactors: {
      title: 1.5,
      content: 1.0,
      metadata: 0.5,
    },
  },

  // Performance settings
  maxItemsToCheck: 50,
  batchSize: 10,
  enableParallelProcessing: false,

  // Analysis settings
  enableSemanticAnalysis: true,
};

/**
 * Configuration presets for different use cases
 */
export const DEDUPE_PRESETS: Record<string, Partial<DeduplicationConfig>> = {
  strict: {
    contentSimilarityThreshold: 0.95,
    checkWithinScopeOnly: true,
    mergeStrategy: 'skip',
    crossScopeDeduplication: false,
  },

  aggressive: {
    contentSimilarityThreshold: 0.7,
    checkWithinScopeOnly: false,
    mergeStrategy: 'combine',
    crossScopeDeduplication: true,
  },

  time_sensitive: {
    timeBasedDeduplication: true,
    maxAgeForDedupeDays: 1,
    respectUpdateTimestamps: true,
    mergeStrategy: 'prefer_newer',
  },

  content_focused: {
    contentSimilarityThreshold: 0.9,
    enableSemanticAnalysis: true,
    contentAnalysisSettings: {
      minLengthForAnalysis: 5,
      enableSemanticAnalysis: true,
      enableKeywordExtraction: true,
      ignoreCommonWords: true,
      customStopWords: [],
      weightingFactors: {
        title: 2.0,
        content: 1.5,
        metadata: 0.3,
      },
    },
  },
};

/**
 * Configuration validation
 */
export function validateDeduplicationConfig(config: Partial<DeduplicationConfig>): {
  valid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate similarity threshold
  if (config.contentSimilarityThreshold !== undefined) {
    if (
      typeof config.contentSimilarityThreshold !== 'number' ||
      config.contentSimilarityThreshold < 0 ||
      config.contentSimilarityThreshold > 1
    ) {
      errors.push('contentSimilarityThreshold must be a number between 0 and 1');
    }
    if (config.contentSimilarityThreshold < 0.5) {
      warnings.push('Very low similarity threshold may cause false positives');
    }
    if (config.contentSimilarityThreshold > 0.95) {
      warnings.push('Very high similarity threshold may miss similar items');
    }
  }

  // Validate time windows
  if (config.maxHistoryHours !== undefined && config.maxHistoryHours < 0) {
    errors.push('maxHistoryHours must be non-negative');
  }
  if (config.dedupeWindowDays !== undefined && config.dedupeWindowDays < 0) {
    errors.push('dedupeWindowDays must be non-negative');
  }
  if (config.maxAgeForDedupeDays !== undefined && config.maxAgeForDedupeDays < 0) {
    errors.push('maxAgeForDedupeDays must be non-negative');
  }

  // Validate performance settings
  if (config.maxItemsToCheck !== undefined && config.maxItemsToCheck <= 0) {
    errors.push('maxItemsToCheck must be positive');
  }
  if (config.batchSize !== undefined && config.batchSize <= 0) {
    errors.push('batchSize must be positive');
  }

  // Validate merge strategy
  if (config.mergeStrategy !== undefined) {
    const validStrategies: MergeStrategy[] = [
      'skip',
      'prefer_existing',
      'prefer_newer',
      'combine',
      'intelligent',
    ];
    if (!validStrategies.includes(config.mergeStrategy)) {
      errors.push(
        `Invalid merge strategy: ${config.mergeStrategy}. Must be one of: ${validStrategies.join(', ')}`
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Merge configurations with validation
 */
export function mergeDeduplicationConfig(
  base: DeduplicationConfig,
  override: Partial<DeduplicationConfig>
): DeduplicationConfig {
  const validation = validateDeduplicationConfig(override);
  if (!validation.valid) {
    throw new Error(`Invalid deduplication configuration: ${validation.errors.join(', ')}`);
  }

  if (validation.warnings.length > 0) {
    console.warn(`Deduplication configuration warnings: ${validation.warnings.join(', ')}`);
  }

  return { ...base, ...override };
}

/**
 * Load configuration from environment variables
 */
export function loadDeduplicationConfigFromEnv(): Partial<DeduplicationConfig> {
  const config: Partial<DeduplicationConfig> = {};

  if (process.env.DEDUPE_ENABLED !== undefined) {
    config.enabled = process.env.DEDUPE_ENABLED === 'true';
  }

  if (process.env.DEDUPE_SIMILARITY_THRESHOLD !== undefined) {
    const threshold = parseFloat(process.env.DEDUPE_SIMILARITY_THRESHOLD);
    if (!isNaN(threshold)) {
      config.contentSimilarityThreshold = threshold;
    }
  }

  if (process.env.DEDUPE_MERGE_STRATEGY !== undefined) {
    const strategy = process.env.DEDUPE_MERGE_STRATEGY as MergeStrategy;
    if (['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'].includes(strategy)) {
      config.mergeStrategy = strategy;
    }
  }

  if (process.env.DEDUPE_WINDOW_DAYS !== undefined) {
    const days = parseInt(process.env.DEDUPE_WINDOW_DAYS, 10);
    if (!isNaN(days)) {
      config.dedupeWindowDays = days;
    }
  }

  if (process.env.DEDUPE_MAX_HISTORY_HOURS !== undefined) {
    const hours = parseInt(process.env.DEDUPE_MAX_HISTORY_HOURS, 10);
    if (!isNaN(hours)) {
      config.maxHistoryHours = hours;
    }
  }

  if (process.env.DEDUPE_CROSS_SCOPE !== undefined) {
    config.crossScopeDeduplication = process.env.DEDUPE_CROSS_SCOPE === 'true';
  }

  if (process.env.DEDUPE_TIME_BASED !== undefined) {
    config.timeBasedDeduplication = process.env.DEDUPE_TIME_BASED === 'true';
  }

  if (process.env.DEDUPE_MAX_AGE_DAYS !== undefined) {
    const days = parseInt(process.env.DEDUPE_MAX_AGE_DAYS, 10);
    if (!isNaN(days)) {
      config.maxAgeForDedupeDays = days;
    }
  }

  return config;
}
