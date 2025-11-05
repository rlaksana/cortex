/**
 * Memory Optimization Configuration
 *
 * Central configuration for all memory optimization features in the MCP Cortex system.
 * This file provides tunable parameters for memory management, monitoring,
 * and cleanup strategies.
 */

export interface MemoryOptimizationConfig {
  // Memory Manager Configuration
  memoryManager: {
    warningThreshold: number;    // Percentage (0-100)
    criticalThreshold: number;   // Percentage (0-100)
    emergencyThreshold: number;  // Percentage (0-100)
    checkInterval: number;       // Milliseconds
    trendWindow: number;         // Milliseconds
    enableAutoCleanup: boolean;
    maxCleanupRetries: number;
  };

  // Embedding Service Configuration
  embeddingService: {
    cacheEnabled: boolean;
    cacheMaxSize: number;        // Number of entries
    cacheMaxMemoryMB: number;    // Memory limit in MB
    cacheEvictionPolicy: 'lru' | 'lfu' | 'priority';
    batchSize: number;           // Reduced batch size for memory
    enableCircuitBreaker: boolean;
    circuitBreakerTimeout: number; // Milliseconds
    enableMemoryMonitoring: boolean;
    memoryThresholdMB: number;   // Memory threshold for cleanup
  };

  // Memory Monitor Configuration
  memoryMonitor: {
    checkInterval: number;       // Milliseconds
    historySize: number;         // Number of data points
    trendWindowSize: number;     // Number of points for trend analysis
    enablePredictions: boolean;
    enableAutoCleanup: boolean;
    alertCooldowns: {
      info: number;      // Milliseconds
      warning: number;   // Milliseconds
      critical: number;  // Milliseconds
      emergency: number; // Milliseconds
    };
  };

  // Store Orchestrator Configuration
  storeOrchestrator: {
    enableMemoryOptimization: boolean;
    maxBatchSize: number;        // Maximum batch size
    memoryPressureThresholds: {
      low: number;       // Percentage
      medium: number;    // Percentage
      high: number;      // Percentage
      critical: number;  // Percentage
    };
    poolConfig: {
      itemResultPoolSize: number;
      batchSummaryPoolSize: number;
      contextPoolSize: number;
    };
    enableBatchSplitting: boolean;
    interBatchCleanupDelay: number; // Milliseconds
  };

  // Find Orchestrator Configuration
  findOrchestrator: {
    enableMemoryOptimization: boolean;
    maxResultSize: number;       // Maximum number of results
    resultCacheSize: number;     // Number of cached results
    enableResultStreaming: boolean;
    memoryPressureHandling: {
      reduceBatchSize: boolean;
      enableEarlyTermination: boolean;
      maxProcessingTime: number; // Milliseconds
    };
  };

  // Global Memory Settings
  global: {
    enableGarbageCollection: boolean;
    gcTriggerThreshold: number;  // Percentage
    maxHeapSizeMB: number;      // Maximum heap size
    enableMemoryProfiling: boolean;
    profilingInterval: number;   // Milliseconds
    logMemoryUsage: boolean;
    memoryLogInterval: number;   // Milliseconds
  };
}

/**
 * Default memory optimization configuration
 */
export const defaultMemoryOptimizationConfig: MemoryOptimizationConfig = {
  memoryManager: {
    warningThreshold: 80,
    criticalThreshold: 90,
    emergencyThreshold: 95,
    checkInterval: 30000,       // 30 seconds
    trendWindow: 300000,         // 5 minutes
    enableAutoCleanup: true,
    maxCleanupRetries: 3,
  },

  embeddingService: {
    cacheEnabled: true,
    cacheMaxSize: 5000,          // Reduced from 10000
    cacheMaxMemoryMB: 100,       // 100MB limit
    cacheEvictionPolicy: 'lru',
    batchSize: 50,               // Reduced from 100
    enableCircuitBreaker: true,
    circuitBreakerTimeout: 30000, // 30 seconds
    enableMemoryMonitoring: true,
    memoryThresholdMB: 200,      // 200MB threshold
  },

  memoryMonitor: {
    checkInterval: 15000,        // 15 seconds
    historySize: 240,            // 1 hour at 15-second intervals
    trendWindowSize: 20,          // 5 minutes for trend analysis
    enablePredictions: true,
    enableAutoCleanup: true,
    alertCooldowns: {
      info: 300000,      // 5 minutes
      warning: 180000,   // 3 minutes
      critical: 60000,   // 1 minute
      emergency: 30000,  // 30 seconds
    },
  },

  storeOrchestrator: {
    enableMemoryOptimization: true,
    maxBatchSize: 100,
    memoryPressureThresholds: {
      low: 60,      // 60%
      medium: 75,   // 75%
      high: 85,     // 85%
      critical: 95, // 95%
    },
    poolConfig: {
      itemResultPoolSize: 100,
      batchSummaryPoolSize: 50,
      contextPoolSize: 50,
    },
    enableBatchSplitting: true,
    interBatchCleanupDelay: 100, // 100ms
  },

  findOrchestrator: {
    enableMemoryOptimization: true,
    maxResultSize: 1000,
    resultCacheSize: 500,
    enableResultStreaming: true,
    memoryPressureHandling: {
      reduceBatchSize: true,
      enableEarlyTermination: true,
      maxProcessingTime: 30000, // 30 seconds
    },
  },

  global: {
    enableGarbageCollection: true,
    gcTriggerThreshold: 85,      // 85%
    maxHeapSizeMB: 2048,        // 2GB
    enableMemoryProfiling: true,
    profilingInterval: 60000,    // 1 minute
    logMemoryUsage: true,
    memoryLogInterval: 60000,    // 1 minute
  },
};

/**
 * Production memory optimization configuration
 * More conservative settings for production environment
 */
export const productionMemoryOptimizationConfig: MemoryOptimizationConfig = {
  ...defaultMemoryOptimizationConfig,
  memoryManager: {
    ...defaultMemoryOptimizationConfig.memoryManager,
    warningThreshold: 75,        // Lower threshold for production
    criticalThreshold: 85,
    emergencyThreshold: 92,
    checkInterval: 15000,        // More frequent checks
  },

  embeddingService: {
    ...defaultMemoryOptimizationConfig.embeddingService,
    cacheMaxSize: 3000,          // Smaller cache for production
    cacheMaxMemoryMB: 75,        // Smaller memory limit
    batchSize: 25,               // Smaller batches
  },

  storeOrchestrator: {
    ...defaultMemoryOptimizationConfig.storeOrchestrator,
    maxBatchSize: 50,            // Smaller batches
    memoryPressureThresholds: {
      low: 50,      // More conservative
      medium: 65,
      high: 80,
      critical: 90,
    },
  },

  global: {
    ...defaultMemoryOptimizationConfig.global,
    gcTriggerThreshold: 80,      // Earlier GC trigger
    maxHeapSizeMB: 1536,        // 1.5GB limit
  },
};

/**
 * Development memory optimization configuration
 * More relaxed settings for development environment
 */
export const developmentMemoryOptimizationConfig: MemoryOptimizationConfig = {
  ...defaultMemoryOptimizationConfig,
  memoryManager: {
    ...defaultMemoryOptimizationConfig.memoryManager,
    warningThreshold: 85,        // Higher threshold for development
    criticalThreshold: 92,
    emergencyThreshold: 97,
    checkInterval: 60000,        // Less frequent checks
  },

  embeddingService: {
    ...defaultMemoryOptimizationConfig.embeddingService,
    cacheMaxSize: 10000,         // Larger cache for development
    cacheMaxMemoryMB: 200,       // Larger memory limit
    batchSize: 100,              // Larger batches
  },

  storeOrchestrator: {
    ...defaultMemoryOptimizationConfig.storeOrchestrator,
    maxBatchSize: 200,           // Larger batches
    memoryPressureThresholds: {
      low: 70,
      medium: 80,
      high: 90,
      critical: 95,
    },
  },

  global: {
    ...defaultMemoryOptimizationConfig.global,
    gcTriggerThreshold: 90,      // Later GC trigger
    maxHeapSizeMB: 4096,        // 4GB limit
  },
};

/**
 * Get memory optimization configuration based on environment
 */
export function getMemoryOptimizationConfig(): MemoryOptimizationConfig {
  const nodeEnv = process.env.NODE_ENV || 'development';

  switch (nodeEnv) {
    case 'production':
      return productionMemoryOptimizationConfig;
    case 'development':
      return developmentMemoryOptimizationConfig;
    default:
      return defaultMemoryOptimizationConfig;
  }
}

/**
 * Validate memory optimization configuration
 */
export function validateMemoryConfig(config: MemoryOptimizationConfig): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Validate threshold ranges
  if (config.memoryManager.warningThreshold < 0 || config.memoryManager.warningThreshold > 100) {
    errors.push('Memory manager warning threshold must be between 0 and 100');
  }

  if (config.memoryManager.criticalThreshold <= config.memoryManager.warningThreshold) {
    errors.push('Critical threshold must be greater than warning threshold');
  }

  if (config.memoryManager.emergencyThreshold <= config.memoryManager.criticalThreshold) {
    errors.push('Emergency threshold must be greater than critical threshold');
  }

  // Validate cache sizes
  if (config.embeddingService.cacheMaxSize <= 0) {
    errors.push('Embedding cache max size must be positive');
  }

  if (config.embeddingService.cacheMaxMemoryMB <= 0) {
    errors.push('Embedding cache max memory must be positive');
  }

  // Validate intervals
  if (config.memoryManager.checkInterval < 1000) {
    errors.push('Memory manager check interval must be at least 1000ms');
  }

  if (config.memoryMonitor.checkInterval < 5000) {
    errors.push('Memory monitor check interval must be at least 5000ms');
  }

  // Validate batch sizes
  if (config.storeOrchestrator.maxBatchSize <= 0) {
    errors.push('Store orchestrator max batch size must be positive');
  }

  if (config.embeddingService.batchSize <= 0) {
    errors.push('Embedding service batch size must be positive');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Merge user configuration with defaults
 */
export function mergeMemoryConfig(
  userConfig: Partial<MemoryOptimizationConfig>
): MemoryOptimizationConfig {
  const baseConfig = getMemoryOptimizationConfig();

  return {
    memoryManager: { ...baseConfig.memoryManager, ...userConfig.memoryManager },
    embeddingService: { ...baseConfig.embeddingService, ...userConfig.embeddingService },
    memoryMonitor: { ...baseConfig.memoryMonitor, ...userConfig.memoryMonitor },
    storeOrchestrator: { ...baseConfig.storeOrchestrator, ...userConfig.storeOrchestrator },
    findOrchestrator: { ...baseConfig.findOrchestrator, ...userConfig.findOrchestrator },
    global: { ...baseConfig.global, ...userConfig.global },
  };
}

/**
 * Environment-specific configuration loader
 */
export function loadMemoryOptimizationConfig(): MemoryOptimizationConfig {
  // Load from environment variables
  const envConfig: Partial<MemoryOptimizationConfig> = {
    memoryManager: {
      warningThreshold: parseInt(process.env.MEMORY_WARNING_THRESHOLD || '80'),
      criticalThreshold: parseInt(process.env.MEMORY_CRITICAL_THRESHOLD || '90'),
      emergencyThreshold: parseInt(process.env.MEMORY_EMERGENCY_THRESHOLD || '95'),
      checkInterval: parseInt(process.env.MEMORY_CHECK_INTERVAL || '30000'),
      trendWindow: parseInt(process.env.MEMORY_TREND_WINDOW || '300000'), // 5 minutes
      enableAutoCleanup: process.env.MEMORY_AUTO_CLEANUP !== 'false',
      maxCleanupRetries: parseInt(process.env.MEMORY_CLEANUP_RETRIES || '3'),
    },
    embeddingService: {
      cacheEnabled: process.env.EMBEDDING_CACHE_ENABLED !== 'false',
      cacheMaxSize: parseInt(process.env.EMBEDDING_CACHE_SIZE || '5000'),
      cacheMaxMemoryMB: parseInt(process.env.EMBEDDING_CACHE_MEMORY_MB || '100'),
      cacheEvictionPolicy: (process.env.EMBEDDING_CACHE_EVICTION as 'lru' | 'lfu' | 'priority') || 'lru',
      batchSize: parseInt(process.env.EMBEDDING_BATCH_SIZE || '50'),
      enableCircuitBreaker: process.env.EMBEDDING_CIRCUIT_BREAKER !== 'false',
      circuitBreakerTimeout: parseInt(process.env.EMBEDDING_CIRCUIT_BREAKER_TIMEOUT || '30000'),
      enableMemoryMonitoring: process.env.EMBEDDING_MEMORY_MONITORING !== 'false',
      memoryThresholdMB: parseInt(process.env.EMBEDDING_MEMORY_THRESHOLD_MB || '200'),
    },
    global: {
      enableGarbageCollection: process.env.GC_ENABLED !== 'false',
      gcTriggerThreshold: parseInt(process.env.GC_TRIGGER_THRESHOLD || '1024'),
      maxHeapSizeMB: parseInt(process.env.MAX_HEAP_SIZE_MB || '2048'),
      enableMemoryProfiling: process.env.MEMORY_PROFILING === 'true',
      profilingInterval: parseInt(process.env.MEMORY_PROFILING_INTERVAL || '60000'),
      logMemoryUsage: process.env.MEMORY_LOG_USAGE !== 'false',
      memoryLogInterval: parseInt(process.env.MEMORY_LOG_INTERVAL || '30000'),
    },
  };

  // Merge with base configuration
  const config = mergeMemoryConfig(envConfig);

  // Validate configuration
  const validation = validateMemoryConfig(config);
  if (!validation.valid) {
    throw new Error(`Invalid memory configuration: ${validation.errors.join(', ')}`);
  }

  return config;
}