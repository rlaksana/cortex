/**
 * Configuration Test Helper
 *
 * Utility functions for testing environment configuration validation
 * across the entire system.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { Environment } from '../../src/config/environment.js';
import { configValidator, ValidationResult } from '../../src/config/validation.js';

/**
 * Complete configuration validation result
 */
export interface CompleteValidationResult {
  environment: ValidationResult;
  requiredConfig: { valid: boolean; errors: string[] };
  environmentSpecific: { valid: boolean; errors: string[]; warnings: string[] };
  allValid: boolean;
  summary: {
    totalErrors: number;
    totalWarnings: number;
    criticalErrors: string[];
  };
}

/**
 * Environment variable usage tracker
 */
export interface EnvironmentVariableUsage {
  variable: string;
  files: string[];
  required: boolean;
  defaultValue?: string;
  validation?: string;
  category: 'database' | 'security' | 'performance' | 'testing' | 'cicd' | 'general';
}

/**
 * Configuration test helper class
 */
export class ConfigTestHelper {
  private static instance: ConfigTestHelper;
  private trackedVariables: Map<string, EnvironmentVariableUsage> = new Map();

  private constructor() {
    this.initializeTrackedVariables();
  }

  static getInstance(): ConfigTestHelper {
    if (!ConfigTestHelper.instance) {
      ConfigTestHelper.instance = new ConfigTestHelper();
    }
    return ConfigTestHelper.instance;
  }

  /**
   * Initialize tracked environment variables based on codebase analysis
   */
  private initializeTrackedVariables(): void {
    const variables: EnvironmentVariableUsage[] = [
      // Database variables
      { variable: 'QDRANT_URL', files: ['src/db/unified-database-layer.ts', 'src/index-claude.ts'], required: false, defaultValue: 'http://localhost:6333', category: 'database' },
      { variable: 'QDRANT_URL', files: ['src/db/unified-database-layer.ts', 'src/index-qdrant.ts'], required: true, defaultValue: 'http://localhost:6333', category: 'database' },
      { variable: 'QDRANT_API_KEY', files: ['src/db/unified-database-layer.ts', 'src/index-qdrant.ts'], required: false, category: 'database' },
      { variable: 'DB_HOST', files: ['src/db/pool.ts', 'start-cortex.js'], required: false, defaultValue: 'localhost', category: 'database' },
      { variable: 'DB_PORT', files: ['src/db/pool.ts', 'start-cortex.js'], required: false, defaultValue: '5433', category: 'database' },
      { variable: 'DB_NAME', files: ['scripts/setup-database.sh', 'tests/integration/migration-integration.test.ts'], required: false, defaultValue: 'cortex_prod', category: 'database' },
      { variable: 'DB_USER', files: ['src/db/pool.ts', 'scripts/setup-database.sh'], required: false, defaultValue: 'cortex', category: 'database' },
      { variable: 'DB_PASSWORD', files: ['src/db/pool.ts', 'start-cortex.js'], required: false, category: 'database' },

      // Database performance variables
      { variable: 'DB_POOL_MIN', files: ['src/db/pool.ts'], required: false, defaultValue: '5', category: 'performance' },
      { variable: 'DB_POOL_MAX', files: ['src/db/pool.ts'], required: false, defaultValue: '20', category: 'performance' },
      { variable: 'DB_IDLE_TIMEOUT_MS', files: ['src/db/pool.ts'], required: false, defaultValue: '30000', category: 'performance' },
      { variable: 'DB_CONNECTION_TIMEOUT_MS', files: ['src/db/pool.ts'], required: false, defaultValue: '10000', category: 'performance' },
      { variable: 'DB_CONNECTION_TIMEOUT', files: ['src/index-qdrant.ts', 'src/db/database-factory.ts'], required: false, defaultValue: '30000', category: 'performance' },
      { variable: 'DB_MAX_CONNECTIONS', files: ['src/index-qdrant.ts', 'src/db/database-factory.ts'], required: false, defaultValue: '10', category: 'performance' },
      { variable: 'DB_QUERY_TIMEOUT', files: ['src/db/pool.ts'], required: false, defaultValue: '30000', category: 'performance' },
      { variable: 'DB_STATEMENT_TIMEOUT', files: ['src/db/pool.ts'], required: false, defaultValue: '30000', category: 'performance' },
      { variable: 'DB_MAX_USES', files: ['src/db/pool.ts'], required: false, defaultValue: '7500', category: 'performance' },
      { variable: 'DB_SSL', files: ['src/db/pool.ts'], required: false, defaultValue: 'false', category: 'database' },
      { variable: 'DB_RETRY_ATTEMPTS', files: ['src/config/environment.ts'], required: false, defaultValue: '3', category: 'performance' },
      { variable: 'DB_RETRY_DELAY', files: ['src/config/environment.ts'], required: false, defaultValue: '1000', category: 'performance' },

      // Vector/Embedding variables
      { variable: 'OPENAI_API_KEY', files: ['src/index-claude.ts', 'src/db/adapters/qdrant-adapter.ts'], required: true, category: 'database' },
      { variable: 'VECTOR_SIZE', files: ['src/index-qdrant.ts', 'src/db/database-factory.ts'], required: false, defaultValue: '1536', validation: '[384, 768, 1024, 1536, 2048, 3072]', category: 'database' },
      { variable: 'VECTOR_DISTANCE', files: ['src/index-qdrant.ts', 'src/db/database-factory.ts'], required: false, defaultValue: 'Cosine', validation: '[Cosine, Euclidean, DotProduct]', category: 'database' },
      { variable: 'EMBEDDING_MODEL', files: ['src/config/environment.ts'], required: false, defaultValue: 'text-embedding-ada-002', category: 'database' },
      { variable: 'EMBEDDING_BATCH_SIZE', files: ['src/config/environment.ts'], required: false, defaultValue: '10', category: 'performance' },
      { variable: 'QDRANT_COLLECTION_NAME', files: ['src/db/database-factory.ts'], required: false, defaultValue: 'cortex-memory', category: 'database' },
      { variable: 'QDRANT_COLLECTION_PREFIX', files: ['src/config/environment.ts'], required: false, defaultValue: 'cortex', category: 'database' },
      { variable: 'QDRANT_TIMEOUT', files: ['src/config/environment.ts'], required: false, defaultValue: '30000', category: 'performance' },

      // Security variables
      { variable: 'JWT_SECRET', files: ['src/config/auth-config.ts'], required: false, validation: 'min 32 chars', category: 'security' },
      { variable: 'JWT_REFRESH_SECRET', files: ['src/config/auth-config.ts'], required: false, validation: 'min 32 chars', category: 'security' },
      { variable: 'ENCRYPTION_KEY', files: ['src/config/environment.ts'], required: false, validation: 'min 32 chars', category: 'security' },

      // General configuration
      { variable: 'NODE_ENV', files: ['src/utils/mcp-logger.ts', 'src/db/database-factory.ts'], required: false, defaultValue: 'development', validation: '[development, production, test]', category: 'general' },
      { variable: 'LOG_LEVEL', files: ['src/utils/mcp-logger.ts', 'start-cortex.js'], required: false, defaultValue: 'info', validation: '[error, warn, info, debug, trace]', category: 'general' },
      { variable: 'APP_NAME', files: ['src/config/environment.ts'], required: false, defaultValue: 'Cortex Memory MCP', category: 'general' },
      { variable: 'APP_VERSION', files: ['src/config/environment.ts'], required: false, defaultValue: '2.0.0', category: 'general' },

      // MCP configuration
      { variable: 'MCP_TRANSPORT', files: ['src/utils/mcp-logger.ts'], required: false, defaultValue: 'stdio', validation: '[stdio, http]', category: 'general' },
      { variable: 'MCP_SERVER_NAME', files: ['src/config/environment.ts'], required: false, defaultValue: 'cortex-qdrant', category: 'general' },
      { variable: 'MCP_SERVER_VERSION', files: ['src/config/environment.ts'], required: false, defaultValue: '2.0.0', category: 'general' },

      // Performance configuration
      { variable: 'CACHE_TTL', files: ['src/config/environment.ts'], required: false, defaultValue: '3600', category: 'performance' },
      { variable: 'CACHE_MAX_SIZE', files: ['src/config/environment.ts'], required: false, defaultValue: '1000', category: 'performance' },
      { variable: 'SEARCH_LIMIT', files: ['src/config/environment.ts'], required: false, defaultValue: '50', category: 'performance' },
      { variable: 'SEARCH_THRESHOLD', files: ['src/config/environment.ts'], required: false, defaultValue: '0.7', category: 'performance' },
      { variable: 'BATCH_SIZE', files: ['src/config/environment.ts'], required: false, defaultValue: '50', category: 'performance' },
      { variable: 'BATCH_TIMEOUT', files: ['src/config/environment.ts'], required: false, defaultValue: '30000', category: 'performance' },
      { variable: 'METRICS_ENABLED', files: ['src/config/environment.ts'], required: false, defaultValue: 'true', category: 'performance' },
      { variable: 'HEALTH_CHECK_INTERVAL', files: ['src/config/environment.ts'], required: false, defaultValue: '60000', category: 'performance' },
      { variable: 'API_RATE_LIMIT', files: ['src/config/environment.ts'], required: false, defaultValue: '100', category: 'performance' },
      { variable: 'API_TIMEOUT', files: ['src/config/environment.ts'], required: false, defaultValue: '30000', category: 'performance' },

      // Feature flags
      { variable: 'ENABLE_AUTH', files: ['src/config/environment.ts'], required: false, defaultValue: 'false', category: 'general' },
      { variable: 'ENABLE_CACHING', files: ['src/config/environment.ts'], required: false, defaultValue: 'true', category: 'performance' },
      { variable: 'ENABLE_METRICS', files: ['src/config/environment.ts'], required: false, defaultValue: 'true', category: 'performance' },
      { variable: 'ENABLE_LOGGING', files: ['src/config/environment.ts'], required: false, defaultValue: 'true', category: 'general' },

      // Development configuration
      { variable: 'DEV_MODE', files: ['src/config/environment.ts'], required: false, defaultValue: 'false', category: 'general' },
      { variable: 'DEBUG_MODE', files: ['src/config/environment.ts'], required: false, defaultValue: 'false', category: 'general' },
      { variable: 'HOT_RELOAD', files: ['src/config/environment.ts'], required: false, defaultValue: 'false', category: 'general' },

      // Testing configuration
      { variable: 'TEST_MODE', files: ['src/config/environment.ts'], required: false, defaultValue: 'false', category: 'testing' },
      { variable: 'TEST_QDRANT_URL', files: ['tests/e2e/*.test.ts', 'tests/integration/*.test.ts'], required: false, category: 'testing' },
      { variable: 'MOCK_EXTERNAL_SERVICES', files: ['src/config/environment.ts'], required: false, defaultValue: 'false', category: 'testing' },

      // CI/CD configuration
      { variable: 'CODECOV_TOKEN', files: ['scripts/upload-coverage-reports.js'], required: false, category: 'cicd' },
      { variable: 'GITHUB_SHA', files: ['scripts/upload-coverage-reports.js'], required: false, category: 'cicd' },
      { variable: 'GITHUB_REF_NAME', files: ['scripts/upload-coverage-reports.js'], required: false, category: 'cicd' },
      { variable: 'GITHUB_ACTIONS', files: ['scripts/upload-coverage-reports.js'], required: false, defaultValue: 'false', category: 'cicd' },

      // Scope inference
      { variable: 'CORTEX_ORG', files: ['src/config/environment.ts'], required: false, category: 'general' },
      { variable: 'CORTEX_PROJECT', files: ['src/config/environment.ts'], required: false, category: 'general' },
      { variable: 'CORTEX_BRANCH', files: ['src/config/environment.ts'], required: false, category: 'general' }
    ];

    variables.forEach(variable => {
      this.trackedVariables.set(variable.variable, variable);
    });
  }

  /**
   * Get all tracked environment variables
   */
  getAllTrackedVariables(): EnvironmentVariableUsage[] {
    return Array.from(this.trackedVariables.values());
  }

  /**
   * Get variables by category
   */
  getVariablesByCategory(category: EnvironmentVariableUsage['category']): EnvironmentVariableUsage[] {
    return Array.from(this.trackedVariables.values()).filter(v => v.category === category);
  }

  /**
   * Get required variables
   */
  getRequiredVariables(): EnvironmentVariableUsage[] {
    return Array.from(this.trackedVariables.values()).filter(v => v.required);
  }

  /**
   * Check if environment variable is properly configured
   */
  validateVariable(variable: string, value?: string): { valid: boolean; error?: string } {
    const trackedVar = this.trackedVariables.get(variable);
    if (!trackedVar) {
      return { valid: false, error: `Variable ${variable} is not tracked` };
    }

    const actualValue = value !== undefined ? value : process.env[variable];

    if (trackedVar.required && !actualValue) {
      return { valid: false, error: `Required variable ${variable} is not set` };
    }

    if (actualValue && trackedVar.validation) {
      // Apply validation based on the validation string
      if (trackedVar.validation === 'min 32 chars' && actualValue.length < 32) {
        return { valid: false, error: `${variable} must be at least 32 characters` };
      }

      if (trackedVar.validation.startsWith('[') && trackedVar.validation.endsWith(']')) {
        const validValues = trackedVar.validation.slice(1, -1).split(', ').map(v => v.trim());
        if (!validValues.includes(actualValue)) {
          return { valid: false, error: `${variable} must be one of: ${trackedVar.validation}` };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Perform complete configuration validation
   */
  async performCompleteValidation(): Promise<CompleteValidationResult> {
    const env = Environment.getInstance();

    // Get all validation results
    const environmentValidation = await configValidator.validateConfiguration(env.exportForMcp() as any);
    const requiredConfigValidation = env.validateRequiredConfig();
    const environmentSpecificValidation = env.validateEnvironmentSpecificRequirements();

    // Count total errors and warnings
    const totalErrors = environmentValidation.errors.length +
                       requiredConfigValidation.errors.length +
                       environmentSpecificValidation.errors.length;
    const totalWarnings = environmentValidation.warnings.length +
                         environmentSpecificValidation.warnings.length;

    // Identify critical errors
    const criticalErrors = [
      ...requiredConfigValidation.errors.filter(e => e.includes('required')),
      ...environmentSpecificValidation.errors.filter(e => e.includes('required')),
      ...environmentValidation.errors.filter(e => e.severity === 'error').map(e => e.message)
    ];

    return {
      environment: environmentValidation,
      requiredConfig: requiredConfigValidation,
      environmentSpecific: environmentSpecificValidation,
      allValid: environmentValidation.valid &&
                requiredConfigValidation.valid &&
                environmentSpecificValidation.valid,
      summary: {
        totalErrors,
        totalWarnings,
        criticalErrors
      }
    };
  }

  /**
   * Generate environment variable coverage report
   */
  generateCoverageReport(): {
    total: number;
    configured: number;
    missing: number;
    byCategory: Record<string, { total: number; configured: number; missing: number }>;
    missingVariables: string[];
  } {
    const allVars = this.getAllTrackedVariables();
    const categories = ['database', 'security', 'performance', 'testing', 'cicd', 'general'];

    let totalConfigured = 0;
    const missingVariables: string[] = [];
    const byCategory: Record<string, { total: number; configured: number; missing: number }> = {};

    categories.forEach(category => {
      const categoryVars = this.getVariablesByCategory(category);
      const configured = categoryVars.filter(v => process.env[v.variable]).length;
      const missing = categoryVars.filter(v => !process.env[v.variable] && v.required).length;

      byCategory[category] = {
        total: categoryVars.length,
        configured,
        missing
      };

      totalConfigured += configured;
      missingVariables.push(...categoryVars.filter(v => !process.env[v.variable] && v.required).map(v => v.variable));
    });

    return {
      total: allVars.length,
      configured: totalConfigured,
      missing: missingVariables.length,
      byCategory,
      missingVariables
    };
  }

  /**
   * Validate that all tracked variables are properly defined in environment.ts
   */
  validateEnvironmentTsCoverage(): {
    valid: boolean;
    missingInEnvironmentTs: string[];
    extraInEnvironmentTs: string[];
  } {
    const env = Environment.getInstance();
    const rawConfig = env.getRawConfig();

    const trackedVars = new Set(this.getAllTrackedVariables().map(v => v.variable));
    const definedVars = new Set(Object.keys(rawConfig));

    const missingInEnvironmentTs = Array.from(trackedVars).filter(v => !definedVars.has(v));
    const extraInEnvironmentTs = Array.from(definedVars).filter(v => !trackedVars.has(v) && !v.startsWith('_'));

    return {
      valid: missingInEnvironmentTs.length === 0,
      missingInEnvironmentTs,
      extraInEnvironmentTs
    };
  }
}

/**
 * Export singleton instance
 */
export const configTestHelper = ConfigTestHelper.getInstance();

/**
 * Convenience functions for testing
 */
export async function validateCompleteConfiguration(): Promise<CompleteValidationResult> {
  return await configTestHelper.performCompleteValidation();
}

export function generateEnvironmentCoverageReport() {
  return configTestHelper.generateCoverageReport();
}

export function validateEnvironmentTsCoverage() {
  return configTestHelper.validateEnvironmentTsCoverage();
}

export function validateVariable(variable: string, value?: string) {
  return configTestHelper.validateVariable(variable, value);
}