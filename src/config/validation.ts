/**
 * Configuration Validation System
 *
 * Comprehensive validation system for environment variables, database configurations,
 * and migration settings with detailed error reporting and suggestions.
 *
 * Features:
 * - Schema-based validation with Zod
 * - Environment-specific validation rules
 * - Dependency validation
 * - Security validation
 * - Performance validation
 * - Detailed error reporting with suggestions
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { z } from 'zod';
import { logger } from '../utils/logger.js';
import type { CompleteDatabaseConfig } from './database-config.js';

export interface ValidationError {
  field: string;
  message: string;
  severity: 'error' | 'warning' | 'info';
  suggestion?: string;
  code?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
  info: ValidationError[];
  summary: {
    total: number;
    errors: number;
    warnings: number;
    info: number;
  };
}

export interface ValidationRule {
  name: string;
  validator: (config: any) => ValidationError[];
  enabled: boolean;
  category: 'security' | 'performance' | 'connectivity' | 'compatibility' | 'best-practices';
}

/**
 * Configuration validation engine with comprehensive rule system
 */
export class ConfigurationValidator {
  private rules: Map<string, ValidationRule> = new Map();
  private schemas: Map<string, z.ZodSchema> = new Map();

  constructor() {
    this.initializeSchemas();
    this.initializeRules();
  }

  /**
   * Initialize Zod schemas for type validation
   */
  private initializeSchemas(): void {
    // Database type validation schema - fixed duplicate enum
    this.schemas.set('databaseType', z.enum(['postgresql', 'qdrant', 'hybrid']));

    // PostgreSQL URL validation schema
    this.schemas.set('qdrantUrl', z.string().url().refine(
      (url) => {
        try {
          const parsed = new URL(url);
          return parsed.protocol === 'postgresql:' || parsed.protocol === 'postgres:';
        } catch {
          return false;
        }
      },
      { message: 'PostgreSQL URL must start with postgresql:// or postgres://' }
    ));

    // Qdrant URL validation schema - fixed duplicate schema key
    this.schemas.set('qdrantServiceUrl', z.string().url().refine(
      (url) => {
        try {
          const parsed = new URL(url);
          return ['http:', 'https:'].includes(parsed.protocol);
        } catch {
          return false;
        }
      },
      { message: 'Qdrant URL must be a valid HTTP/HTTPS URL' }
    ));

    // Vector configuration validation
    this.schemas.set('vectorSize', z.number().refine(
      (size) => [384, 768, 1024, 1536, 2048, 3072].includes(size),
      { message: 'Vector size must be one of: 384, 768, 1024, 1536, 2048, 3072' }
    ));

    this.schemas.set('vectorDistance', z.enum(['Cosine', 'Euclidean', 'DotProduct']));

    // Pool configuration validation
    this.schemas.set('poolSize', z.object({
      min: z.number().min(1),
      max: z.number().min(1).max(100),
      idleTimeout: z.number().min(1000),
      connectionTimeout: z.number().min(1000).max(300000),
      retryAttempts: z.number().min(0).max(10),
      retryDelay: z.number().min(100)
    }).refine(
      (pool) => pool.min <= pool.max,
      { message: 'Minimum pool size must be less than or equal to maximum pool size' }
    ));

    // Migration configuration validation
    this.schemas.set('migrationConfig', z.object({
      batchSize: z.number().min(1).max(10000),
      concurrency: z.number().min(1).max(10),
      dryRun: z.boolean(),
      preservePg: z.boolean(),
      validationEnabled: z.boolean()
    }));
  }

  /**
   * Initialize validation rules
   */
  private initializeRules(): void {
    // Security validation rules
    this.addRule({
      name: 'secure-connection-strings',
      category: 'security',
      enabled: true,
      validator: (config: CompleteDatabaseConfig): ValidationError[] => {
        const errors: ValidationError[] = [];

        // Check for placeholder/invalid credentials in connection strings
        if (config.qdrant.databaseUrl) {
          const url = new URL(config.qdrant.databaseUrl);

          // Check for obvious placeholder passwords
          const placeholderPatterns = [
            'your_.*_password',
            'your_.*_key',
            'placeholder',
            'example',
            'test',
            'change.*me',
            'cortex_pg18_secure_2025_key'
          ];

          if (url.password) {
            for (const pattern of placeholderPatterns) {
              if (new RegExp(pattern, 'i').test(url.password)) {
                errors.push({
                  field: 'qdrant.databaseUrl',
                  message: 'Database password appears to be a placeholder value',
                  severity: 'error',
                  suggestion: 'Set a strong, unique password for production use',
                  code: 'SEC001'
                });
                break;
              }
            }

            if (url.password.length < 12) {
              errors.push({
                field: 'qdrant.databaseUrl',
                message: 'Database password should be at least 12 characters long for security',
                severity: 'warning',
                suggestion: 'Use a strong password with mixed characters',
                code: 'SEC002'
              });
            }
          }
        }

        // Validate OpenAI API key format and reject placeholders
        if (config.vector.openaiApiKey) {
          // Check for placeholder patterns
          const placeholderPatterns = [
            'your_.*_api_key',
            'sk-.*\\.\\.\\.',
            'placeholder',
            'example',
            'test'
          ];

          for (const pattern of placeholderPatterns) {
            if (new RegExp(pattern, 'i').test(config.vector.openaiApiKey)) {
              errors.push({
                field: 'vector.openaiApiKey',
                message: 'OpenAI API key appears to be a placeholder value',
                severity: 'error',
                suggestion: 'Use a valid OpenAI API key from your OpenAI dashboard',
                code: 'SEC003'
              });
              break;
            }
          }

          // Validate OpenAI API key format
          if (!config.vector.openaiApiKey.startsWith('sk-') || config.vector.openaiApiKey.length < 20) {
            errors.push({
              field: 'vector.openaiApiKey',
              message: 'OpenAI API key format is invalid',
              severity: 'error',
              suggestion: 'OpenAI API keys must start with "sk-" and be at least 20 characters long',
              code: 'SEC004'
            });
          }
        }

        // Validate JWT secrets for placeholder patterns
        const checkJwtSecret = (secret: string | undefined, fieldName: string) => {
          if (secret) {
            const placeholderPatterns = [
              'your.*super.*secret',
              'your.*very.*long.*secure',
              'change.*in.*production',
              'placeholder',
              'example.*secret',
              'test.*secret'
            ];

            for (const pattern of placeholderPatterns) {
              if (new RegExp(pattern, 'i').test(secret)) {
                errors.push({
                  field: fieldName,
                  message: `${fieldName} appears to be a placeholder value`,
                  severity: 'error',
                  suggestion: `Generate a secure random ${fieldName} using 'openssl rand -hex 32'`,
                  code: 'SEC005'
                });
                break;
              }
            }

            if (secret.length < 32) {
              errors.push({
                field: fieldName,
                message: `${fieldName} must be at least 32 characters long`,
                severity: 'error',
                suggestion: `Generate a longer ${fieldName} for better security`,
                code: 'SEC006'
              });
            }
          }
        };

        // Check JWT secrets (these would come from environment config)
        const env = (global as any).environment; // Access to environment if available
        if (env) {
          checkJwtSecret(env.config?.JWT_SECRET, 'JWT_SECRET');
          checkJwtSecret(env.config?.JWT_REFRESH_SECRET, 'JWT_REFRESH_SECRET');
          checkJwtSecret(env.config?.ENCRYPTION_KEY, 'ENCRYPTION_KEY');
        }

        return errors;
      }
    });

    // Performance validation rules
    this.addRule({
      name: 'pool-optimization',
      category: 'performance',
      enabled: true,
      validator: (config: CompleteDatabaseConfig): ValidationError[] => {
        const errors: ValidationError[] = [];
        const pool = config.qdrant.pool;

        // Check pool size recommendations
        if (pool.max > 50) {
          errors.push({
            field: 'qdrant.pool.max',
            message: 'Large connection pool may impact performance',
            severity: 'warning',
            suggestion: 'Consider reducing pool size or using connection pooling middleware',
            code: 'PERF001'
          });
        }

        if (pool.connectionTimeout > 60000) {
          errors.push({
            field: 'qdrant.pool.connectionTimeout',
            message: 'Connection timeout is very high, may cause slow failure detection',
            severity: 'warning',
            suggestion: 'Consider reducing timeout to 30-45 seconds for better responsiveness',
            code: 'PERF002'
          });
        }

        // Migration performance checks
        if (config.migration.batchSize > 5000) {
          errors.push({
            field: 'migration.batchSize',
            message: 'Large batch size may cause memory issues',
            severity: 'warning',
            suggestion: 'Consider reducing batch size to 1000-2000 for better memory management',
            code: 'PERF003'
          });
        }

        return errors;
      }
    });

    // Connectivity validation rules
    this.addRule({
      name: 'connectivity-checks',
      category: 'connectivity',
      enabled: true,
      validator: (config: CompleteDatabaseConfig): ValidationError[] => {
        const errors: ValidationError[] = [];

        // Check database type requirements for hybrid architecture
        switch (config.selection.type) {
          case 'postgresql':
            // PostgreSQL mode requires PostgreSQL connection
            if (!config.qdrant.databaseUrl) {
              errors.push({
                field: 'qdrant.databaseUrl',
                message: 'PostgreSQL connection string is required for PostgreSQL database type',
                severity: 'error',
                suggestion: 'Set DATABASE_URL or individual DB_* environment variables',
                code: 'CONN001'
              });
            }
            break;

          case 'qdrant':
            // Qdrant mode requires Qdrant service URL and OpenAI API key
            if (!config.qdrant.url) {
              errors.push({
                field: 'qdrant.url',
                message: 'Qdrant service URL is required for Qdrant database type',
                severity: 'error',
                suggestion: 'Set QDRANT_URL environment variable',
                code: 'CONN002'
              });
            }

            if (!config.vector.openaiApiKey) {
              errors.push({
                field: 'vector.openaiApiKey',
                message: 'OpenAI API key is required for vector operations',
                severity: 'error',
                suggestion: 'Set OPENAI_API_KEY environment variable',
                code: 'CONN003'
              });
            }
            break;

          case 'hybrid':
            // Hybrid mode requires both PostgreSQL and Qdrant
            if (!config.qdrant.databaseUrl) {
              errors.push({
                field: 'qdrant.databaseUrl',
                message: 'PostgreSQL connection string is required for hybrid database type',
                severity: 'error',
                suggestion: 'Set DATABASE_URL or individual DB_* environment variables',
                code: 'CONN004'
              });
            }

            if (!config.qdrant.url) {
              errors.push({
                field: 'qdrant.url',
                message: 'Qdrant service URL is required for hybrid database type',
                severity: 'error',
                suggestion: 'Set QDRANT_URL environment variable',
                code: 'CONN005'
              });
            }

            if (!config.vector.openaiApiKey) {
              errors.push({
                field: 'vector.openaiApiKey',
                message: 'OpenAI API key is required for vector operations in hybrid mode',
                severity: 'error',
                suggestion: 'Set OPENAI_API_KEY environment variable',
                code: 'CONN006'
              });
            }

            // Hybrid mode specific validations
            if (!config.features.migrationMode) {
              errors.push({
                field: 'features.migrationMode',
                message: 'Migration mode should be enabled for hybrid deployments',
                severity: 'info',
                suggestion: 'Consider enabling migration mode for hybrid database deployments',
                code: 'CONN007'
              });
            }
            break;
        }

        return errors;
      }
    });

    // Compatibility validation rules
    this.addRule({
      name: 'compatibility-checks',
      category: 'compatibility',
      enabled: true,
      validator: (config: CompleteDatabaseConfig): ValidationError[] => {
        const errors: ValidationError[] = [];

        // Check vector model compatibility
        if (config.vector.embeddingModel === 'text-embedding-ada-002' && config.vector.size !== 1536) {
          errors.push({
            field: 'vector.size',
            message: 'text-embedding-ada-002 model produces 1536-dimensional vectors',
            severity: 'error',
            suggestion: 'Set VECTOR_SIZE to 1536 for text-embedding-ada-002 model',
            code: 'COMP001'
          });
        }

        // Check hybrid mode requirements
        if (config.selection.type === 'hybrid' && !config.features.migrationMode) {
          errors.push({
            field: 'features.migrationMode',
            message: 'Hybrid mode typically requires migration mode to be enabled',
            severity: 'info',
            suggestion: 'Consider enabling migration mode for hybrid deployments',
            code: 'COMP002'
          });
        }

        return errors;
      }
    });

    // Production security validation rules
    this.addRule({
      name: 'production-security',
      category: 'security',
      enabled: true,
      validator: (config: CompleteDatabaseConfig): ValidationError[] => {
        const errors: ValidationError[] = [];

        // Check if we're in production environment
        const isProduction = process.env.NODE_ENV === 'production';

        if (isProduction) {
          // Require all security settings in production
          const requiredSecurityFields = [
            { envVar: 'JWT_SECRET', minLength: 32 },
            { envVar: 'JWT_REFRESH_SECRET', minLength: 32 },
            { envVar: 'ENCRYPTION_KEY', minLength: 32 }
          ];

          for (const field of requiredSecurityFields) {
            const value = process.env[field.envVar];
            if (!value) {
              errors.push({
                field: field.envVar,
                message: `${field.envVar} is required in production environment`,
                severity: 'error',
                suggestion: `Set ${field.envVar} as an environment variable with at least ${field.minLength} random characters`,
                code: 'PROD_SEC001'
              });
            } else if (value.length < field.minLength) {
              errors.push({
                field: field.envVar,
                message: `${field.envVar} must be at least ${field.minLength} characters in production`,
                severity: 'error',
                suggestion: `Regenerate ${field.envVar} with more characters for better security`,
                code: 'PROD_SEC002'
              });
            }
          }

          // Production should not use development defaults
          if (process.env.LOG_LEVEL === 'debug' || process.env.LOG_LEVEL === 'trace') {
            errors.push({
              field: 'LOG_LEVEL',
              message: 'Debug logging should not be enabled in production',
              severity: 'warning',
              suggestion: 'Set LOG_LEVEL to "info", "warn", or "error" in production',
              code: 'PROD_SEC003'
            });
          }

          // Check for development URLs in production
          const devUrls = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1'
          ];

          const checkUrl = (url: string | undefined, fieldName: string) => {
            if (url) {
              for (const devUrl of devUrls) {
                if (url.includes(devUrl)) {
                  errors.push({
                    field: fieldName,
                    message: `${fieldName} contains development URL (${devUrl}) in production`,
                    severity: 'warning',
                    suggestion: `Use production URLs for ${fieldName} in production environment`,
                    code: 'PROD_SEC004'
                  });
                  break;
                }
              }
            }
          };

          checkUrl(process.env.QDRANT_URL, 'QDRANT_URL');
          checkUrl(process.env.DATABASE_URL, 'DATABASE_URL');
          checkUrl(process.env.CORS_ORIGIN, 'CORS_ORIGIN');

          // Require SSL in production for database connections
          if (process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('sslmode=require')) {
            errors.push({
              field: 'DATABASE_URL',
              message: 'Database connections should use SSL in production',
              severity: 'warning',
              suggestion: 'Add "?sslmode=require" to your DATABASE_URL for secure connections',
              code: 'PROD_SEC005'
            });
          }
        }

        return errors;
      }
    });

    // Best practices validation rules
    this.addRule({
      name: 'best-practices',
      category: 'best-practices',
      enabled: true,
      validator: (config: CompleteDatabaseConfig): ValidationError[] => {
        const errors: ValidationError[] = [];

        // Migration safety checks
        if (config.migration.mode && !config.migration.dryRun) {
          errors.push({
            field: 'migration.dryRun',
            message: 'Running migration without dry-run mode',
            severity: 'warning',
            suggestion: 'Consider running with dry-run=true first to validate migration',
            code: 'PRACTICE001'
          });
        }

        if (config.migration.mode && !config.migration.preservePg) {
          errors.push({
            field: 'migration.preservePg',
            message: 'Migration will not preserve qdrant data',
            severity: 'warning',
            suggestion: 'Consider enabling preservePg for safety during migration',
            code: 'PRACTICE002'
          });
        }

        // Feature flag recommendations
        if (config.selection.type === 'hybrid' && !config.features.metricsCollection) {
          errors.push({
            field: 'features.metricsCollection',
            message: 'Metrics collection recommended for hybrid deployments',
            severity: 'info',
            suggestion: 'Enable metrics collection to monitor hybrid system performance',
            code: 'PRACTICE003'
          });
        }

        return errors;
      }
    });
  }

  /**
   * Add a validation rule
   */
  addRule(rule: ValidationRule): void {
    this.rules.set(rule.name, rule);
  }

  /**
   * Remove a validation rule
   */
  removeRule(name: string): void {
    this.rules.delete(name);
  }

  /**
   * Enable/disable a validation rule
   */
  toggleRule(name: string, enabled: boolean): void {
    const rule = this.rules.get(name);
    if (rule) {
      rule.enabled = enabled;
    }
  }

  /**
   * Validate complete configuration
   */
  async validateConfiguration(config: CompleteDatabaseConfig): Promise<ValidationResult> {
    const allErrors: ValidationError[] = [];
    const allWarnings: ValidationError[] = [];
    const allInfo: ValidationError[] = [];

    // Run schema validation
    const schemaValidation = this.validateSchemas(config);
    allErrors.push(...schemaValidation.errors);
    allWarnings.push(...schemaValidation.warnings);

    // Run rule-based validation
    for (const [name, rule] of this.rules) {
      if (rule.enabled) {
        try {
          const ruleResults = rule.validator(config);
          for (const result of ruleResults) {
            switch (result.severity) {
              case 'error':
                allErrors.push(result);
                break;
              case 'warning':
                allWarnings.push(result);
                break;
              case 'info':
                allInfo.push(result);
                break;
            }
          }
        } catch (error) {
          logger.error({ rule: name, error }, 'Validation rule failed');
          allErrors.push({
            field: 'validation',
            message: `Validation rule '${name}' failed: ${error instanceof Error ? error.message : String(error)}`,
            severity: 'error',
            code: 'VALID001'
          });
        }
      }
    }

    const summary = {
      total: allErrors.length + allWarnings.length + allInfo.length,
      errors: allErrors.length,
      warnings: allWarnings.length,
      info: allInfo.length
    };

    // Log validation results
    if (summary.errors > 0) {
      logger.error({ summary, errors: allErrors }, 'Configuration validation failed');
    } else if (summary.warnings > 0) {
      logger.warn({ summary, warnings: allWarnings }, 'Configuration validation completed with warnings');
    } else {
      logger.info({ summary }, 'Configuration validation passed');
    }

    return {
      valid: summary.errors === 0,
      errors: allErrors,
      warnings: allWarnings,
      info: allInfo,
      summary
    };
  }

  /**
   * Validate configuration against schemas
   */
  private validateSchemas(config: CompleteDatabaseConfig): {
    errors: ValidationError[];
    warnings: ValidationError[];
  } {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];

    // Validate database type
    const dbTypeResult = this.schemas.get('databaseType')?.safeParse(config.selection.type);
    if (!dbTypeResult?.success) {
      errors.push({
        field: 'selection.type',
        message: `Invalid database type: ${config.selection.type}`,
        severity: 'error',
        suggestion: 'Use one of: qdrant, qdrant, hybrid',
        code: 'SCHEMA001'
      });
    }

    // Validate PostgreSQL URL (for postgresql and hybrid modes)
    if (config.qdrant.databaseUrl) {
      const pgUrlResult = this.schemas.get('qdrantUrl')?.safeParse(config.qdrant.databaseUrl);
      if (!pgUrlResult?.success) {
        errors.push({
          field: 'qdrant.databaseUrl',
          message: 'Invalid PostgreSQL connection string',
          severity: 'error',
          suggestion: 'Use format: postgresql://user:password@host:port/database',
          code: 'SCHEMA002'
        });
      }
    }

    // Validate Qdrant service URL (for qdrant and hybrid modes)
    if (config.qdrant.url) {
      const qdrantUrlResult = this.schemas.get('qdrantServiceUrl')?.safeParse(config.qdrant.url);
      if (!qdrantUrlResult?.success) {
        errors.push({
          field: 'qdrant.url',
          message: 'Invalid Qdrant service URL',
          severity: 'error',
          suggestion: 'Use format: http://localhost:6333 or https://your-qdrant-instance.com',
          code: 'SCHEMA003'
        });
      }
    }

    // Validate vector configuration
    const vectorSizeResult = this.schemas.get('vectorSize')?.safeParse(config.vector.size);
    if (!vectorSizeResult?.success) {
      errors.push({
        field: 'vector.size',
        message: 'Invalid vector size',
        severity: 'error',
        suggestion: 'Use one of: 384, 768, 1024, 1536, 2048, 3072',
        code: 'SCHEMA004'
      });
    }

    const vectorDistanceResult = this.schemas.get('vectorDistance')?.safeParse(config.vector.distance);
    if (!vectorDistanceResult?.success) {
      errors.push({
        field: 'vector.distance',
        message: 'Invalid vector distance metric',
        severity: 'error',
        suggestion: 'Use one of: Cosine, Euclidean, DotProduct',
        code: 'SCHEMA005'
      });
    }

    // Validate pool configuration
    const poolResult = this.schemas.get('poolSize')?.safeParse(config.qdrant.pool);
    if (!poolResult?.success) {
      poolResult?.error.issues.forEach((issue) => {
        errors.push({
          field: `qdrant.pool.${issue.path.join('.')}`,
          message: issue.message,
          severity: 'error',
          code: 'SCHEMA006'
        });
      });
    }

    return { errors, warnings };
  }

  /**
   * Get validation rules by category
   */
  getRulesByCategory(category: ValidationRule['category']): ValidationRule[] {
    return Array.from(this.rules.values()).filter(rule => rule.category === category);
  }

  /**
   * Get all validation rules
   */
  getAllRules(): ValidationRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Validate specific rule
   */
  validateRule(ruleName: string, config: CompleteDatabaseConfig): ValidationError[] {
    const rule = this.rules.get(ruleName);
    if (!rule || !rule.enabled) {
      return [];
    }

    try {
      return rule.validator(config);
    } catch (error) {
      logger.error({ rule: ruleName, error }, 'Rule validation failed');
      return [{
        field: 'validation',
        message: `Rule '${ruleName}' failed: ${error instanceof Error ? error.message : String(error)}`,
        severity: 'error',
        code: 'RULE001'
      }];
    }
  }
}

// Export singleton instance
export const configValidator = new ConfigurationValidator();

// Export utility functions
export async function validateConfig(config: CompleteDatabaseConfig): Promise<ValidationResult> {
  return await configValidator.validateConfiguration(config);
}

export function addValidationRule(rule: ValidationRule): void {
  configValidator.addRule(rule);
}

export function removeValidationRule(name: string): void {
  configValidator.removeRule(name);
}