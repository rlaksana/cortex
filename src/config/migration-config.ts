/**
 * Migration Configuration Manager
 *
 * Comprehensive migration configuration system for qdrant to Qdrant
 * data migration with safety controls, performance optimization, and progress tracking.
 *
 * Features:
 * - Migration mode configuration (one-way, two-way, sync)
 * - Batch processing and concurrency control
 * - Progress tracking and resume capability
 * - Data validation and integrity checking
 * - Performance optimization and monitoring
 * - Safety controls and rollback mechanisms
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../utils/logger.js';
import type { MigrationConfig } from './database-config.js';

export type MigrationMode = 'pg-to-qdrant' | 'qdrant-to-pg' | 'sync' | 'validate' | 'cleanup';

export interface MigrationStrategy {
  mode: MigrationMode;
  description: string;
  requiresSource: boolean;
  requiresTarget: boolean;
  destructive: boolean;
  reversible: boolean;
  estimatedDuration: 'fast' | 'medium' | 'slow';
}

export interface DataTransformationConfig {
  generateEmbeddings: 'always' | 'if-missing' | 'never';
  embeddingModel: string;
  batchSize: number;
  contentFields: string[];
  metadataFields: string[];
  filterRules: FilterRule[];
  transformationRules: TransformationRule[];
}

export interface FilterRule {
  name: string;
  field: string;
  operator:
    | 'equals'
    | 'contains'
    | 'startsWith'
    | 'endsWith'
    | 'regex'
    | 'exists'
    | 'greaterThan'
    | 'lessThan';
  value: any;
  negate?: boolean;
}

export interface TransformationRule {
  name: string;
  type: 'field' | 'value' | 'structure';
  sourceField?: string;
  targetField?: string;
  transformation: string;
  parameters?: Record<string, any>;
}

export interface ValidationConfig {
  enabled: boolean;
  level: 'basic' | 'comprehensive' | 'exhaustive';
  sampleSize: number;
  timeout: number;
  checkSum: boolean;
  checkEmbeddings: boolean;
  checkMetadata: boolean;
  toleranceThreshold: number;
}

export interface ProgressTrackingConfig {
  enabled: boolean;
  filePath: string;
  checkpointInterval: number;
  saveInterval: number;
  maxRetries: number;
  resumeOnError: boolean;
  compressionEnabled: boolean;
}

export interface PerformanceConfig {
  maxConcurrency: number;
  memoryLimitMB: number;
  rateLimitRPS: number;
  chunkSize: number;
  prefetchSize: number;
  gcInterval: number;
  monitoringEnabled: boolean;
}

export interface SafetyConfig {
  dryRun: boolean;
  preserveSource: boolean;
  requireConfirmation: boolean;
  backupEnabled: boolean;
  backupPath?: string;
  maxErrors: number;
  errorThreshold: number;
  rollbackOnFailure: boolean;
  criticalOperations: string[];
}

export interface MigrationEnvironmentConfig {
  mode: MigrationMode;
  strategy: MigrationStrategy;
  dataTransformation: DataTransformationConfig;
  validation: ValidationConfig;
  progressTracking: ProgressTrackingConfig;
  performance: PerformanceConfig;
  safety: SafetyConfig;
  source: {
    type: 'qdrant' | 'qdrant';
    config: any;
  };
  target: {
    type: 'qdrant' | 'qdrant';
    config: any;
  };
}

/**
 * Migration strategy definitions
 */
export const MIGRATION_STRATEGIES: Record<MigrationMode, MigrationStrategy> = {
  'pg-to-qdrant': {
    mode: 'pg-to-qdrant',
    description: 'Migrate data from qdrant to Qdrant with vector embeddings',
    requiresSource: true,
    requiresTarget: true,
    destructive: false,
    reversible: true,
    estimatedDuration: 'slow',
  },
  'qdrant-to-pg': {
    mode: 'qdrant-to-pg',
    description: 'Migrate data from Qdrant back to qdrant (vector data as metadata)',
    requiresSource: true,
    requiresTarget: true,
    destructive: false,
    reversible: true,
    estimatedDuration: 'medium',
  },
  sync: {
    mode: 'sync',
    description: 'Synchronize data bidirectionally between qdrant and Qdrant',
    requiresSource: true,
    requiresTarget: true,
    destructive: false,
    reversible: true,
    estimatedDuration: 'slow',
  },
  validate: {
    mode: 'validate',
    description: 'Validate data integrity between qdrant and Qdrant without migration',
    requiresSource: true,
    requiresTarget: true,
    destructive: false,
    reversible: true,
    estimatedDuration: 'medium',
  },
  cleanup: {
    mode: 'cleanup',
    description: 'Clean up orphaned data and optimize storage',
    requiresSource: true,
    requiresTarget: false,
    destructive: true,
    reversible: false,
    estimatedDuration: 'fast',
  },
};

/**
 * Default transformation configurations
 */
export const DEFAULT_TRANSFORMATIONS: Record<MigrationMode, DataTransformationConfig> = {
  'pg-to-qdrant': {
    generateEmbeddings: 'always',
    embeddingModel: 'text-embedding-3-small',
    batchSize: 100,
    contentFields: ['content', 'text', 'description', 'title'],
    metadataFields: ['kind', 'scope', 'created_at', 'updated_at', 'id'],
    filterRules: [
      {
        name: 'exclude-empty-content',
        field: 'content',
        operator: 'exists',
        value: true,
      },
    ],
    transformationRules: [
      {
        name: 'flatten-metadata',
        type: 'structure',
        transformation: 'flatten',
        parameters: { separator: '_' },
      },
    ],
  },
  'qdrant-to-pg': {
    generateEmbeddings: 'never',
    embeddingModel: 'text-embedding-3-small',
    batchSize: 50,
    contentFields: ['content'],
    metadataFields: ['kind', 'scope', 'created_at'],
    filterRules: [],
    transformationRules: [
      {
        name: 'extract-vector-metadata',
        type: 'field',
        sourceField: 'vector',
        targetField: 'embedding_data',
        transformation: 'serialize',
      },
    ],
  },
  sync: {
    generateEmbeddings: 'if-missing',
    embeddingModel: 'text-embedding-3-small',
    batchSize: 75,
    contentFields: ['content', 'text'],
    metadataFields: ['kind', 'scope', 'created_at', 'updated_at'],
    filterRules: [
      {
        name: 'exclude-system-records',
        field: 'kind',
        operator: 'exists',
        value: true,
      },
    ],
    transformationRules: [
      {
        name: 'merge-metadata',
        type: 'structure',
        transformation: 'merge',
        parameters: { strategy: 'target-priority' },
      },
    ],
  },
  validate: {
    generateEmbeddings: 'never',
    embeddingModel: 'text-embedding-3-small',
    batchSize: 200,
    contentFields: ['content'],
    metadataFields: ['id', 'kind', 'scope'],
    filterRules: [],
    transformationRules: [],
  },
  cleanup: {
    generateEmbeddings: 'never',
    embeddingModel: 'text-embedding-3-small',
    batchSize: 500,
    contentFields: [],
    metadataFields: ['id', 'kind', 'created_at'],
    filterRules: [
      {
        name: 'old-records',
        field: 'created_at',
        operator: 'lessThan',
        value: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      },
    ],
    transformationRules: [],
  },
};

/**
 * Migration configuration manager
 */
export class MigrationConfigManager {
  private config: MigrationEnvironmentConfig;
  private environment: 'development' | 'production' | 'test';

  constructor(
    baseConfig: MigrationConfig,
    environment: 'development' | 'production' | 'test' = 'production'
  ) {
    this.environment = environment;
    this.config = this.buildCompleteConfig(baseConfig);
    this.validateConfiguration();
  }

  /**
   * Build complete migration configuration
   */
  private buildCompleteConfig(baseConfig: MigrationConfig): MigrationEnvironmentConfig {
    const mode = baseConfig.mode || 'validate';
    const strategy = MIGRATION_STRATEGIES[mode];

    if (!strategy) {
      throw new Error(`Unsupported migration mode: ${mode}`);
    }

    const defaultTransformation = DEFAULT_TRANSFORMATIONS[mode];

    return {
      mode,
      strategy,
      dataTransformation: {
        generateEmbeddings: defaultTransformation.generateEmbeddings,
        embeddingModel: baseConfig.mode === 'pg-to-qdrant' ? 'text-embedding-3-small' : 'none',
        batchSize: baseConfig.batchSize,
        contentFields: defaultTransformation.contentFields,
        metadataFields: defaultTransformation.metadataFields,
        filterRules: defaultTransformation.filterRules,
        transformationRules: defaultTransformation.transformationRules,
      },
      validation: {
        enabled: baseConfig.validationEnabled,
        level: this.environment === 'production' ? 'comprehensive' : 'basic',
        sampleSize: this.environment === 'production' ? 1000 : 100,
        timeout: 30000,
        checkSum: true,
        checkEmbeddings: mode === 'pg-to-qdrant' || mode === 'sync',
        checkMetadata: true,
        toleranceThreshold: 0.95,
      },
      progressTracking: {
        enabled: true,
        filePath: baseConfig.progressFile,
        checkpointInterval: Math.min(baseConfig.batchSize, 100),
        saveInterval: 1000,
        maxRetries: 3,
        resumeOnError: true,
        compressionEnabled: this.environment === 'production',
      },
      performance: {
        maxConcurrency: baseConfig.concurrency,
        memoryLimitMB: this.environment === 'production' ? 1024 : 512,
        rateLimitRPS: this.environment === 'production' ? 100 : 50,
        chunkSize: Math.min(baseConfig.batchSize / 2, 50),
        prefetchSize: Math.min(baseConfig.batchSize, 100),
        gcInterval: 10000,
        monitoringEnabled: true,
      },
      safety: {
        dryRun: baseConfig.dryRun,
        preserveSource: baseConfig.preservePg,
        requireConfirmation: !baseConfig.dryRun,
        backupEnabled: !baseConfig.dryRun && this.environment === 'production',
        backupPath: baseConfig.progressFile.replace('.json', '-backup.json'),
        maxErrors: 10,
        errorThreshold: 0.05,
        rollbackOnFailure: baseConfig.preservePg,
        criticalOperations: ['delete', 'truncate', 'drop', 'cleanup'],
      },
      source: { type: 'qdrant', config: {} }, // Will be populated later
      target: { type: 'qdrant', config: {} }, // Will be populated later
    };
  }

  /**
   * Validate configuration
   */
  private validateConfiguration(): void {
    const errors: string[] = [];

    // Validate mode compatibility
    if (this.config.strategy.requiresSource && !this.config.source.config) {
      errors.push('Source database configuration is required for this migration mode');
    }

    if (this.config.strategy.requiresTarget && !this.config.target.config) {
      errors.push('Target database configuration is required for this migration mode');
    }

    // Validate safety constraints
    if (this.config.safety.dryRun && this.config.validation.enabled) {
      logger.warn('Running in dry-run mode with validation enabled - validation will be simulated');
    }

    if (
      !this.config.safety.dryRun &&
      this.config.strategy.destructive &&
      !this.config.safety.backupEnabled
    ) {
      errors.push('Backup is required for destructive migration operations');
    }

    // Validate performance constraints
    if (this.config.performance.maxConcurrency > 10 && this.environment === 'production') {
      logger.warn('High concurrency may impact production system performance');
    }

    if (this.config.performance.memoryLimitMB < 256) {
      errors.push('Memory limit is too low for migration operations (minimum 256MB)');
    }

    if (errors.length > 0) {
      throw new Error(`Migration configuration validation failed:\n${errors.join('\n')}`);
    }

    logger.info(
      {
        mode: this.config.mode,
        environment: this.environment,
        dryRun: this.config.safety.dryRun,
        batchSize: this.config.dataTransformation.batchSize,
        concurrency: this.config.performance.maxConcurrency,
      },
      'Migration configuration validated'
    );
  }

  /**
   * Get complete migration configuration
   */
  getConfiguration(): MigrationEnvironmentConfig {
    return { ...this.config };
  }

  /**
   * Get migration strategy
   */
  getStrategy(): MigrationStrategy {
    return { ...this.config.strategy };
  }

  /**
   * Get data transformation configuration
   */
  getDataTransformationConfig(): DataTransformationConfig {
    return { ...this.config.dataTransformation };
  }

  /**
   * Get validation configuration
   */
  getValidationConfig(): ValidationConfig {
    return { ...this.config.validation };
  }

  /**
   * Get progress tracking configuration
   */
  getProgressTrackingConfig(): ProgressTrackingConfig {
    return { ...this.config.progressTracking };
  }

  /**
   * Get performance configuration
   */
  getPerformanceConfig(): PerformanceConfig {
    return { ...this.config.performance };
  }

  /**
   * Get safety configuration
   */
  getSafetyConfig(): SafetyConfig {
    return { ...this.config.safety };
  }

  /**
   * Set source database configuration
   */
  setSourceConfig(_type: 'qdrant' | 'qdrant', config: any): void {
    this.config.source = { type: _type, config };
  }

  /**
   * Set target database configuration
   */
  setTargetConfig(_type: 'qdrant' | 'qdrant', config: any): void {
    this.config.target = { type: _type, config };
  }

  /**
   * Apply environment-specific optimizations
   */
  applyEnvironmentOptimizations(): void {
    switch (this.environment) {
      case 'development':
        // Development optimizations
        this.config.safety.dryRun = true;
        this.config.validation.level = 'basic';
        this.config.performance.maxConcurrency = Math.min(
          this.config.performance.maxConcurrency,
          2
        );
        this.config.dataTransformation.batchSize = Math.min(
          this.config.dataTransformation.batchSize,
          10
        );
        break;

      case 'production':
        // Production optimizations
        this.config.validation.level = 'comprehensive';
        this.config.safety.backupEnabled = true;
        this.config.safety.requireConfirmation = true;
        this.config.performance.monitoringEnabled = true;
        this.config.progressTracking.compressionEnabled = true;
        break;

      case 'test':
        // Test optimizations
        this.config.safety.dryRun = true;
        this.config.validation.enabled = false;
        this.config.performance.maxConcurrency = 1;
        this.config.dataTransformation.batchSize = 5;
        this.config.progressTracking.enabled = false;
        break;
    }
  }

  /**
   * Estimate migration duration
   */
  estimateMigrationDuration(recordCount: number): {
    estimatedMinutes: number;
    confidence: 'low' | 'medium' | 'high';
    factors: string[];
  } {
    const batchSize = this.config.dataTransformation.batchSize;
    const concurrency = this.config.performance.maxConcurrency;
    const batchesNeeded = Math.ceil(recordCount / batchSize);
    const estimatedMsPerBatch = 5000; // Rough estimate
    let totalMs = (batchesNeeded / concurrency) * estimatedMsPerBatch;

    const factors: string[] = [];
    let confidence: 'low' | 'medium' | 'high' = 'medium';

    // Adjust based on strategy
    switch (this.config.strategy.estimatedDuration) {
      case 'fast':
        factors.push('Fast migration strategy');
        break;
      case 'slow':
        totalMs *= 2;
        factors.push('Slow migration strategy');
        confidence = 'low';
        break;
    }

    // Adjust based on embeddings
    if (this.config.dataTransformation.generateEmbeddings !== 'never') {
      totalMs *= 1.5;
      factors.push('Embedding generation required');
    }

    // Adjust based on validation
    if (this.config.validation.enabled && this.config.validation.level !== 'basic') {
      totalMs *= 1.3;
      factors.push('Comprehensive validation enabled');
    }

    // Adjust based on environment
    if (this.environment === 'production') {
      totalMs *= 1.2;
      factors.push('Production safety measures');
      confidence = 'high';
    }

    const estimatedMinutes = Math.ceil(totalMs / (1000 * 60));

    return {
      estimatedMinutes,
      confidence,
      factors,
    };
  }

  /**
   * Create migration checkpoint configuration
   */
  createCheckpointConfig(_checkpointId: string): {
    id: string;
    timestamp: Date;
    config: Partial<MigrationEnvironmentConfig>;
    metadata: Record<string, any>;
  } {
    return {
      id: _checkpointId,
      timestamp: new Date(),
      config: {
        mode: this.config.mode,
        dataTransformation: { ...this.config.dataTransformation },
        validation: { ...this.config.validation },
        performance: { ...this.config.performance },
      },
      metadata: {
        environment: this.environment,
        strategy: this.config.strategy.description,
        estimatedDuration: this.config.strategy.estimatedDuration,
      },
    };
  }

  /**
   * Export configuration for persistence
   */
  exportForPersistence(): Record<string, any> {
    return {
      version: '2.0.0',
      timestamp: new Date().toISOString(),
      environment: this.environment,
      config: this.config,
    };
  }

  /**
   * Import configuration from persistence
   */
  static importFromPersistence(_data: Record<string, any>): MigrationConfigManager {
    if (_data.version !== '2.0.0') {
      throw new Error(`Unsupported migration configuration version: ${_data.version}`);
    }

    const baseConfig: MigrationConfig = {
      mode: _data.config.mode,
      batchSize: _data.config.dataTransformation.batchSize,
      concurrency: _data.config.performance.maxConcurrency,
      dryRun: _data.config.safety.dryRun,
      preservePg: _data.config.safety.preserveSource,
      validationEnabled: _data.config.validation.enabled,
      skipValidation: !_data.config.validation.enabled,
      progressFile: _data.config.progressTracking.filePath,
    };

    return new MigrationConfigManager(baseConfig, _data.environment);
  }
}

/**
 * Migration configuration factory
 */
export class MigrationConfigFactory {
  /**
   * Create migration configuration manager
   */
  static create(
    baseConfig: MigrationConfig,
    environment: 'development' | 'production' | 'test' = 'production'
  ): MigrationConfigManager {
    return new MigrationConfigManager(baseConfig, environment);
  }

  /**
   * Create configuration for specific migration mode
   */
  static createForMode(
    mode: MigrationMode,
    environment: 'development' | 'production' | 'test' = 'production',
    overrides: Partial<MigrationConfig> = {}
  ): MigrationConfigManager {
    const baseConfig: MigrationConfig = {
      mode,
      batchSize: environment === 'production' ? 1000 : 100,
      concurrency: environment === 'production' ? 2 : 1,
      dryRun: environment !== 'production',
      preservePg: true,
      validationEnabled: true,
      skipValidation: false,
      progressFile: `./migration-${mode}-progress.json`,
      ...overrides,
    };

    return new MigrationConfigManager(baseConfig, environment);
  }

  /**
   * Get available migration strategies
   */
  static getAvailableStrategies(): MigrationStrategy[] {
    return Object.values(MIGRATION_STRATEGIES);
  }

  /**
   * Get strategy by mode
   */
  static getStrategy(mode: MigrationMode): MigrationStrategy | undefined {
    return MIGRATION_STRATEGIES[mode];
  }
}

// Export utility functions
export function createMigrationConfig(
  baseConfig: MigrationConfig,
  environment: 'development' | 'production' | 'test' = 'production'
): MigrationConfigManager {
  return MigrationConfigFactory.create(baseConfig, environment);
}

export function createMigrationConfigForMode(
  mode: MigrationMode,
  environment: 'development' | 'production' | 'test' = 'production',
  overrides?: Partial<MigrationConfig>
): MigrationConfigManager {
  return MigrationConfigFactory.createForMode(mode, environment, overrides);
}

