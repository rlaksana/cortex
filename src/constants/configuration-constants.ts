/**
 * Typed Configuration Constants
 *
 * Centralized, type-safe configuration constants to replace `any` usage
 * throughout the configuration system. All constants use proper types
 * and provide runtime validation capabilities.
 *
 * @version 2.0.0
 * @since 2025
 */

import type { Dict, JSONValue, MutableDict } from '../types/index.js';

// ============================================================================
// Database Configuration Constants
// ============================================================================

/**
 * Supported database types with type safety
 */
export const SUPPORTED_DATABASE_TYPES = ['qdrant'] as const;
export type DatabaseType = (typeof SUPPORTED_DATABASE_TYPES)[number];

/**
 * Default Qdrant configuration
 */
export const DEFAULT_QDRANT_CONFIG: {
  host: string;
  port: number;
  timeout: number;
  maxRetries: number;
  distance: 'Cosine' | 'Euclidean' | 'Dot';
} = {
  host: 'localhost',
  port: 6333,
  timeout: 30000,
  maxRetries: 3,
  distance: 'Cosine',
};

/**
 * Default vector configuration
 */
export const DEFAULT_VECTOR_CONFIG: {
  size: number;
  distance: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  model: string;
} = {
  size: 1536,
  distance: 'Cosine',
  model: 'text-embedding-3-small',
};

// ============================================================================
// Migration Configuration Constants
// ============================================================================

/**
 * Migration modes with type safety
 */
export const MIGRATION_MODES = [
  'pg-to-qdrant',
  'qdrant-to-pg',
  'sync',
  'validate',
  'cleanup',
] as const;
export type MigrationMode = (typeof MIGRATION_MODES)[number];

/**
 * Default migration settings
 */
export const DEFAULT_MIGRATION_CONFIG: {
  mode: MigrationMode;
  batchSize: number;
  concurrency: number;
  dryRun: boolean;
  preservePg: boolean;
  validationEnabled: boolean;
  skipValidation: boolean;
  progressFile: string;
} = {
  mode: 'validate',
  batchSize: 1000,
  concurrency: 2,
  dryRun: true,
  preservePg: true,
  validationEnabled: true,
  skipValidation: false,
  progressFile: './migration-progress.json',
};

/**
 * Migration strategies configuration
 */
export const MIGRATION_STRATEGIES: Dict<{
  mode: MigrationMode;
  description: string;
  requiresSource: boolean;
  requiresTarget: boolean;
  destructive: boolean;
  reversible: boolean;
  estimatedDuration: 'fast' | 'medium' | 'slow';
}> = {
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

// ============================================================================
// Validation Configuration Constants
// ============================================================================

/**
 * Validation levels with type safety
 */
export const VALIDATION_LEVELS = ['basic', 'comprehensive', 'exhaustive'] as const;
export type ValidationLevel = (typeof VALIDATION_LEVELS)[number];

/**
 * Default validation configuration
 */
export const DEFAULT_VALIDATION_CONFIG: {
  enabled: boolean;
  level: ValidationLevel;
  sampleSize: number;
  timeout: number;
  checkSum: boolean;
  checkEmbeddings: boolean;
  checkMetadata: boolean;
  toleranceThreshold: number;
} = {
  enabled: true,
  level: 'comprehensive',
  sampleSize: 1000,
  timeout: 30000,
  checkSum: true,
  checkEmbeddings: true,
  checkMetadata: true,
  toleranceThreshold: 0.95,
};

// ============================================================================
// Performance Configuration Constants
// ============================================================================

/**
 * Default performance configuration
 */
export const DEFAULT_PERFORMANCE_CONFIG: {
  maxConcurrency: number;
  memoryLimitMB: number;
  rateLimitRPS: number;
  chunkSize: number;
  prefetchSize: number;
  gcInterval: number;
  monitoringEnabled: boolean;
} = {
  maxConcurrency: 10,
  memoryLimitMB: 1024,
  rateLimitRPS: 100,
  chunkSize: 100,
  prefetchSize: 200,
  gcInterval: 10000,
  monitoringEnabled: true,
};

// ============================================================================
// Security Configuration Constants
// ============================================================================

/**
 * Default security configuration
 */
export const DEFAULT_SECURITY_CONFIG: {
  corsOrigin: string[];
  rateLimitEnabled: boolean;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  helmetEnabled: boolean;
  requireApiKey: boolean;
  maxRequestSizeMb: number;
  enableCompression: boolean;
} = {
  corsOrigin: ['http://localhost:3000'],
  rateLimitEnabled: true,
  rateLimitWindowMs: 900000, // 15 minutes
  rateLimitMaxRequests: 1000,
  helmetEnabled: true,
  requireApiKey: false,
  maxRequestSizeMb: 10,
  enableCompression: true,
};

/**
 * Password validation patterns
 */
export const PASSWORD_VALIDATION_PATTERNS: {
  placeholder: RegExp[];
  minLength: number;
  patterns: Array<{
    name: string;
    pattern: RegExp;
    description: string;
  }>;
} = {
  placeholder: [
    /your_.*_password/i,
    /your_.*_key/i,
    /placeholder/i,
    /example/i,
    /test/i,
    /change.*me/i,
    /cortex_pg18_secure_2025_key/i,
  ],
  minLength: 12,
  patterns: [
    {
      name: 'uppercase',
      pattern: /[A-Z]/,
      description: 'At least one uppercase letter',
    },
    {
      name: 'lowercase',
      pattern: /[a-z]/,
      description: 'At least one lowercase letter',
    },
    {
      name: 'number',
      pattern: /\d/,
      description: 'At least one number',
    },
    {
      name: 'special',
      pattern: /[!@#$%^&*(),.?":{}|<>]/,
      description: 'At least one special character',
    },
  ],
};

// ============================================================================
// API Key Validation Constants
// ============================================================================

/**
 * API key validation patterns
 */
export const API_KEY_VALIDATION: {
  openai: {
    patterns: RegExp[];
    minLength: number;
    validPrefixes: string[];
    placeholder: RegExp[];
  };
} = {
  openai: {
    patterns: [
      // Additional patterns can be added here if needed
    ],
    minLength: 20,
    validPrefixes: ['sk-', 'sk-proj-'],
    placeholder: [/your_.*_api_key/i, /sk-.*\.\.\./, /placeholder/i, /example/i, /test/i],
  },
};

// ============================================================================
// Environment Configuration Constants
// ============================================================================

/**
 * Supported environments
 */
export const SUPPORTED_ENVIRONMENTS = ['development', 'production', 'test', 'staging'] as const;
export type Environment = (typeof SUPPORTED_ENVIRONMENTS)[number];

/**
 * Environment-specific settings
 */
export const ENVIRONMENT_SETTINGS: Dict<{
  validation: {
    level: ValidationLevel;
    strictMode: boolean;
    enableWarnings: boolean;
  };
  performance: {
    maxConcurrency: number;
    memoryLimitMB: number;
    monitoring: boolean;
  };
  security: {
    requireHttps: boolean;
    enableCsp: boolean;
    strictCors: boolean;
  };
}> = {
  development: {
    validation: {
      level: 'basic',
      strictMode: false,
      enableWarnings: true,
    },
    performance: {
      maxConcurrency: 2,
      memoryLimitMB: 512,
      monitoring: false,
    },
    security: {
      requireHttps: false,
      enableCsp: false,
      strictCors: false,
    },
  },
  production: {
    validation: {
      level: 'comprehensive',
      strictMode: true,
      enableWarnings: true,
    },
    performance: {
      maxConcurrency: 10,
      memoryLimitMB: 2048,
      monitoring: true,
    },
    security: {
      requireHttps: true,
      enableCsp: true,
      strictCors: true,
    },
  },
  test: {
    validation: {
      level: 'basic',
      strictMode: false,
      enableWarnings: false,
    },
    performance: {
      maxConcurrency: 1,
      memoryLimitMB: 256,
      monitoring: false,
    },
    security: {
      requireHttps: false,
      enableCsp: false,
      strictCors: false,
    },
  },
  staging: {
    validation: {
      level: 'comprehensive',
      strictMode: true,
      enableWarnings: true,
    },
    performance: {
      maxConcurrency: 5,
      memoryLimitMB: 1024,
      monitoring: true,
    },
    security: {
      requireHttps: true,
      enableCsp: true,
      strictCors: true,
    },
  },
};

// ============================================================================
// Error Code Constants
// ============================================================================

/**
 * Standardized error codes
 */
export const ERROR_CODES: Dict<{
  message: string;
  category: 'security' | 'performance' | 'validation' | 'connectivity' | 'compatibility';
  severity: 'error' | 'warning' | 'info';
}> = {
  // Security errors
  SEC001: {
    message: 'Database password appears to be a placeholder value',
    category: 'security',
    severity: 'error',
  },
  SEC002: {
    message: 'Database password should be at least 12 characters long for security',
    category: 'security',
    severity: 'warning',
  },
  SEC003: {
    message: 'OpenAI API key appears to be a placeholder value',
    category: 'security',
    severity: 'error',
  },
  SEC004: {
    message: 'OpenAI API key format is invalid',
    category: 'security',
    severity: 'error',
  },
  SEC005: {
    message: 'JWT secret appears to be a placeholder value',
    category: 'security',
    severity: 'error',
  },
  SEC006: {
    message: 'JWT secret must be at least 32 characters long',
    category: 'security',
    severity: 'error',
  },

  // Performance errors
  PERF001: {
    message: 'Large batch size may cause memory issues',
    category: 'performance',
    severity: 'warning',
  },
  PERF002: {
    message: 'High memory usage detected',
    category: 'performance',
    severity: 'warning',
  },
  PERF003: {
    message: 'Slow query detected',
    category: 'performance',
    severity: 'warning',
  },

  // Validation errors
  VAL001: {
    message: 'Invalid configuration value',
    category: 'validation',
    severity: 'error',
  },
  VAL002: {
    message: 'Missing required configuration field',
    category: 'validation',
    severity: 'error',
  },
  VAL003: {
    message: 'Configuration type mismatch',
    category: 'validation',
    severity: 'error',
  },

  // Connectivity errors
  CONN001: {
    message: 'Database connection failed',
    category: 'connectivity',
    severity: 'error',
  },
  CONN002: {
    message: 'Service unavailable',
    category: 'connectivity',
    severity: 'error',
  },
  CONN003: {
    message: 'Connection timeout',
    category: 'connectivity',
    severity: 'warning',
  },

  // Compatibility errors
  COMP001: {
    message: 'Vector model compatibility issue',
    category: 'compatibility',
    severity: 'error',
  },
  COMP002: {
    message: 'Version compatibility issue',
    category: 'compatibility',
    severity: 'warning',
  },
};

// ============================================================================
// Utility Functions for Constants
// ============================================================================

/**
 * Check if a database type is supported
 */
export function isSupportedDatabaseType(type: string): type is DatabaseType {
  return SUPPORTED_DATABASE_TYPES.includes(type as DatabaseType);
}

/**
 * Check if a migration mode is supported
 */
export function isSupportedMigrationMode(mode: string): mode is MigrationMode {
  return MIGRATION_MODES.includes(mode as MigrationMode);
}

/**
 * Check if a validation level is supported
 */
export function isSupportedValidationLevel(level: string): level is ValidationLevel {
  return VALIDATION_LEVELS.includes(level as ValidationLevel);
}

/**
 * Check if an environment is supported
 */
export function isSupportedEnvironment(env: string): env is Environment {
  return SUPPORTED_ENVIRONMENTS.includes(env as Environment);
}

/**
 * Get error code information
 */
export function getErrorCode(code: string): {
  message: string;
  category: string;
  severity: string;
} | null {
  return ERROR_CODES[code] || null;
}

/**
 * Validate password against security requirements
 */
export function validatePassword(password: string): {
  valid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check for placeholder patterns
  for (const pattern of PASSWORD_VALIDATION_PATTERNS.placeholder) {
    if (pattern.test(password)) {
      errors.push('Password appears to be a placeholder value');
      break;
    }
  }

  // Check minimum length
  if (password.length < PASSWORD_VALIDATION_PATTERNS.minLength) {
    errors.push(
      `Password must be at least ${PASSWORD_VALIDATION_PATTERNS.minLength} characters long`
    );
  }

  // Check for character patterns
  for (const { name, pattern, description } of PASSWORD_VALIDATION_PATTERNS.patterns) {
    if (!pattern.test(password)) {
      warnings.push(description);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Validate API key format
 */
export function validateApiKey(
  apiKey: string,
  service: 'openai'
): {
  valid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  const validation = API_KEY_VALIDATION[service];
  if (!validation) {
    errors.push(`Unsupported API key service: ${service}`);
    return { valid: false, errors, warnings };
  }

  // Check for placeholder patterns
  for (const pattern of validation.placeholder) {
    if (pattern.test(apiKey)) {
      errors.push('API key appears to be a placeholder value');
      break;
    }
  }

  // Check minimum length
  if (apiKey.length < validation.minLength) {
    errors.push(`API key must be at least ${validation.minLength} characters long`);
  }

  // Check for valid prefixes
  const hasValidPrefix = validation.validPrefixes.some((prefix) => apiKey.startsWith(prefix));
  if (!hasValidPrefix) {
    errors.push(`API key must start with one of: ${validation.validPrefixes.join(', ')}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Get environment-specific configuration
 */
export function getEnvironmentConfig(environment: Environment): Dict<JSONValue> {
  const settings = ENVIRONMENT_SETTINGS[environment];
  if (!settings) {
    throw new Error(`Unsupported environment: ${environment}`);
  }

  return {
    environment,
    ...settings,
  } as Dict<JSONValue>;
}

/**
 * Create typed configuration object from environment variables
 */
export function createConfigFromEnvironment(env: NodeJS.ProcessEnv): Dict<JSONValue> {
  const config: MutableDict<JSONValue> = {};

  // Database configuration
  if (env.QDRANT_URL) {
    config.qdrantUrl = env.QDRANT_URL;
  }
  if (env.QDRANT_API_KEY) {
    config.qdrantApiKey = env.QDRANT_API_KEY;
  }

  // Vector configuration
  if (env.OPENAI_API_KEY) {
    config.openaiApiKey = env.OPENAI_API_KEY;
  }
  if (env.VECTOR_SIZE) {
    config.vectorSize = parseInt(env.VECTOR_SIZE, 10);
  }
  if (env.VECTOR_DISTANCE) {
    config.vectorDistance = env.VECTOR_DISTANCE;
  }

  // Security configuration
  if (env.JWT_SECRET) {
    config.jwtSecret = env.JWT_SECRET;
  }
  if (env.JWT_REFRESH_SECRET) {
    config.jwtRefreshSecret = env.JWT_REFRESH_SECRET;
  }
  if (env.ENCRYPTION_KEY) {
    config.encryptionKey = env.ENCRYPTION_KEY;
  }

  // Performance configuration
  if (env.MAX_OLD_SPACE_SIZE) {
    config.maxOldSpaceSize = parseInt(env.MAX_OLD_SPACE_SIZE, 10);
  }
  if (env.NODE_OPTIONS) {
    config.nodeOptions = env.NODE_OPTIONS;
  }

  // Environment
  if (env.NODE_ENV) {
    config.environment = env.NODE_ENV;
  }

  return config;
}
