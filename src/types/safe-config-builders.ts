/**
 * Safe Configuration Builders with Validation
 *
 * This module provides fluent, type-safe builders for creating configuration objects
 * with comprehensive validation, default values, and detailed error reporting.
 */

import type { Config } from './base-types.js';
import type { Environment, Version } from './branded-types.js';
import {
  arrayGuard,
  booleanGuard,
  enumGuard,
  guard,
  numberGuard,
  objectGuard,
  optionalGuard,
  patternGuard,
  rangeGuard,
  stringGuard,
  type TypeGuard,
  type ValidationContext,
  type ValidationError,
  type ValidationWarning,
} from './runtime-type-guard-framework.js';
import { safeGetNestedProperty, safeSetNestedProperty } from './safe-property-access.js';

// ============================================================================
// Configuration Builder Types
// ============================================================================

/**
 * Configuration property definition
 */
export interface ConfigProperty<T = unknown> {
  /** Property name */
  readonly name: string;
  /** Property description */
  readonly description?: string;
  /** Whether property is required */
  readonly required: boolean;
  /** Default value */
  readonly defaultValue?: T;
  /** Type guard for validation */
  readonly validator: TypeGuard<T>;
  /** Environment-specific overrides */
  readonly environmentOverrides?: Map<Environment, ConfigPropertyOverride<T>>;
  /** Property metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /** Property deprecation information */
  readonly deprecated?: DeprecationInfo;
}

/**
 * Configuration property override for specific environments
 */
export interface ConfigPropertyOverride<T = unknown> {
  /** Override value */
  readonly value?: T;
  /** Override default value */
  readonly defaultValue?: T;
  /** Override required flag */
  readonly required?: boolean;
  /** Override validator */
  readonly validator?: TypeGuard<T>;
  /** Override description */
  readonly description?: string;
}

/**
 * Deprecation information for configuration properties
 */
export interface DeprecationInfo {
  /** Deprecation message */
  readonly message: string;
  /** Version when deprecated */
  readonly since: Version;
  /** Version when property will be removed */
  readonly removalVersion?: Version;
  /** Migration path to new property */
  readonly migrationPath?: string;
  /** Automatic migration function */
  readonly autoMigrate?: (value: unknown) => unknown;
}

/**
 * Configuration schema definition
 */
export interface ConfigSchema {
  /** Schema name */
  readonly name: string;
  /** Schema version */
  readonly version: Version;
  /** Schema description */
  readonly description?: string;
  /** Schema properties */
  readonly properties: Map<string, ConfigProperty>;
  /** Required environments */
  readonly requiredEnvironments?: Set<Environment>;
  /** Schema metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Configuration build result
 */
export interface ConfigBuildResult {
  /** Whether build was successful */
  readonly success: boolean;
  /** Built configuration object */
  readonly config?: Config;
  /** Validation errors */
  readonly errors: ValidationError[];
  /** Validation warnings */
  readonly warnings: ValidationWarning[];
  /** Build statistics */
  readonly stats: ConfigBuildStats;
}

/**
 * Configuration build statistics
 */
export interface ConfigBuildStats {
  /** Number of properties processed */
  propertiesProcessed: number;
  /** Number of properties successfully validated */
  propertiesValidated: number;
  /** Number of default values used */
  defaultsUsed: number;
  /** Number of environment overrides applied */
  overridesApplied: number;
  /** Number of deprecated properties encountered */
  deprecatedProperties: number;
  /** Build duration in milliseconds */
  durationMs: number;
}

/**
 * Configuration builder context
 */
export interface ConfigBuilderContext {
  /** Target environment */
  environment?: Environment;
  /** Strict validation mode */
  strict?: boolean;
  /** Allow any properties */
  allowUnknown?: boolean;
  /** Collect detailed statistics */
  collectStats?: boolean;
  /** Custom property resolvers */
  propertyResolvers?: Map<string, (context: ConfigBuilderContext) => unknown>;
  /** Environment variable mappings */
  envMappings?: Map<string, string>;
  /** Configuration sources */
  sources?: ConfigSource[];
}

/**
 * Configuration source interface
 */
export interface ConfigSource {
  /** Source name */
  readonly name: string;
  /** Source priority (higher number = higher priority) */
  readonly priority: number;
  /** Get value from source */
  readonly getValue: (path: string, context: ConfigBuilderContext) => unknown;
  /** Check if source has value */
  readonly hasValue: (path: string, context: ConfigBuilderContext) => boolean;
}

// ============================================================================
// Configuration Builder Class
// ============================================================================

/**
 * Fluent configuration builder with validation
 */
export class ConfigBuilder {
  private schema: ConfigSchema;
  private context: ConfigBuilderContext;
  private intermediate: Record<string, unknown> = {};

  constructor(
    name: string,
    version: Version,
    description?: string,
    context?: Partial<ConfigBuilderContext>
  ) {
    this.schema = {
      name,
      version,
      description,
      properties: new Map(),
      metadata: {},
    };

    this.context = {
      environment: undefined,
      strict: false,
      allowUnknown: false,
      collectStats: false,
      propertyResolvers: new Map(),
      envMappings: new Map(),
      sources: [],
      ...context,
    };
  }

  /**
   * Add a string property
   */
  string(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      minLength?: number;
      maxLength?: number;
      pattern?: RegExp;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = options.pattern
      ? patternGuard(options.pattern, { description: options.description })
      : stringGuard;

    if (options.minLength !== undefined || options.maxLength !== undefined) {
      // Add length validation logic here
    }

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'string',
        minLength: options.minLength,
        maxLength: options.maxLength,
        pattern: options.pattern?.toString(),
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a number property
   */
  number(
    name: string,
    options: {
      required?: boolean;
      default?: number;
      min?: number;
      max?: number;
      integer?: boolean;
      positive?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    let validator = numberGuard;

    if (options.min !== undefined || options.max !== undefined) {
      validator = rangeGuard(options.min ?? -Infinity, options.max ?? Infinity, {
        integer: options.integer,
        inclusive: true,
      });
    }

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'number',
        min: options.min,
        max: options.max,
        integer: options.integer,
        positive: options.positive,
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a boolean property
   */
  boolean(
    name: string,
    options: {
      required?: boolean;
      default?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator: booleanGuard,
      metadata: {
        type: 'boolean',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add an enum property
   */
  enum<T extends readonly string[]>(
    name: string,
    values: T,
    options: {
      required?: boolean;
      default?: T[number];
      caseSensitive?: boolean;
      allowCoercion?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = enumGuard(values, {
      caseSensitive: options.caseSensitive,
      allowCoercion: options.allowCoercion,
    });

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'enum',
        values,
        caseSensitive: options.caseSensitive,
        allowCoercion: options.allowCoercion,
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add an array property
   */
  array<T>(
    name: string,
    itemValidator: TypeGuard<T>,
    options: {
      required?: boolean;
      default?: T[];
      minLength?: number;
      maxLength?: number;
      uniqueItems?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = arrayGuard(itemValidator, {
      minLength: options.minLength,
      maxLength: options.maxLength,
      uniqueItems: options.uniqueItems,
    });

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'array',
        itemType: itemValidator.typeName,
        minLength: options.minLength,
        maxLength: options.maxLength,
        uniqueItems: options.uniqueItems,
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add an object property
   */
  object<T extends Record<string, unknown>>(
    name: string,
    shape: { [K in keyof T]: TypeGuard<T[K]> },
    options: {
      required?: boolean;
      default?: T;
      strict?: boolean;
      allowExtra?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = objectGuard(shape, {
      strict: options.strict,
      allowExtra: options.allowExtra,
    });

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'object',
        shape: Object.keys(shape).map((k) => `${k}: ${shape[k as keyof T].typeName}`),
        strict: options.strict,
        allowExtra: options.allowExtra,
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a configuration key property
   */
  configKey(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('configKey').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'configKey',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add an environment property
   */
  environmentProperty(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('environment').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'environment',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a service name property
   */
  serviceName(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('serviceName').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'serviceName',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a connection string property
   */
  connectionString(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('connectionString').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'connectionString',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a secret property
   */
  secret(
    name: string,
    options: {
      required?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('secret').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      validator,
      metadata: {
        type: 'secret',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a hostname property
   */
  hostname(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('hostname').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'hostname',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a port property
   */
  port(
    name: string,
    options: {
      required?: boolean;
      default?: number;
      min?: number;
      max?: number;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = rangeGuard(options.min ?? 1, options.max ?? 65535, { integer: true }).name(
      'port'
    );

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'port',
        min: options.min,
        max: options.max,
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a version property
   */
  version(
    name: string,
    options: {
      required?: boolean;
      default?: string;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(stringGuard).name('version').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'version',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Add a feature flag property
   */
  featureFlag(
    name: string,
    options: {
      required?: boolean;
      default?: boolean;
      description?: string;
      envVar?: string;
      deprecated?: DeprecationInfo;
    } = {}
  ): this {
    const validator = guard(booleanGuard).name('featureFlag').build();

    this.addProperty(name, {
      name,
      description: options.description,
      required: options.required ?? false,
      defaultValue: options.default,
      validator,
      metadata: {
        type: 'featureFlag',
        envVar: options.envVar,
      },
      deprecated: options.deprecated,
    });

    return this;
  }

  /**
   * Set the target environment
   */
  environment(env: Environment): this {
    this.context.environment = env;
    return this;
  }

  /**
   * Enable strict validation mode
   */
  strict(strict: boolean = true): this {
    this.context.strict = strict;
    return this;
  }

  /**
   * Allow any properties
   */
  allowUnknown(allow: boolean = true): this {
    this.context.allowUnknown = allow;
    return this;
  }

  /**
   * Enable statistics collection
   */
  collectStats(collect: boolean = true): this {
    this.context.collectStats = collect;
    return this;
  }

  /**
   * Add an environment variable mapping
   */
  envMapping(propertyPath: string, envVar: string): this {
    this.context.envMappings!.set(propertyPath, envVar);
    return this;
  }

  /**
   * Add a property resolver
   */
  resolve(propertyPath: string, resolver: (context: ConfigBuilderContext) => unknown): this {
    this.context.propertyResolvers!.set(propertyPath, resolver);
    return this;
  }

  /**
   * Add a configuration source
   */
  source(source: ConfigSource): this {
    this.context.sources!.push(source);
    // Sort sources by priority (highest first)
    this.context.sources!.sort((a, b) => b.priority - a.priority);
    return this;
  }

  /**
   * Set an intermediate value (for programmatic configuration)
   */
  set(path: string, value: unknown): this {
    safeSetNestedProperty(this.intermediate, path.split('.'), value, {
      createPath: true,
    });
    return this;
  }

  /**
   * Build the configuration
   */
  build(): ConfigBuildResult {
    const startTime = Date.now();
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const stats: ConfigBuildStats = {
      propertiesProcessed: 0,
      propertiesValidated: 0,
      defaultsUsed: 0,
      overridesApplied: 0,
      deprecatedProperties: 0,
      durationMs: 0,
    };

    const config: Record<string, unknown> = {};

    // Process each property in the schema
    for (const [propertyName, property] of Array.from(this.schema.properties.entries())) {
      stats.propertiesProcessed++;

      const propertyResult = this.buildProperty(property, propertyName);
      errors.push(...propertyResult.errors);
      warnings.push(...propertyResult.warnings);

      if (propertyResult.success && propertyResult.value !== undefined) {
        config[propertyName] = propertyResult.value;
        stats.propertiesValidated++;

        if (propertyResult.usedDefault) {
          stats.defaultsUsed++;
        }

        if (propertyResult.usedOverride) {
          stats.overridesApplied++;
        }
      }

      if (property.deprecated) {
        stats.deprecatedProperties++;
        warnings.push({
          code: 'DEPRECATED_PROPERTY',
          message: `Property '${propertyName}' is deprecated: ${property.deprecated.message}`,
          path: propertyName,
          value: config[propertyName],
          severity: 'medium',
        });

        // Handle automatic migration
        if (property.deprecated.autoMigrate && property.deprecated.migrationPath) {
          const migratedValue = property.deprecated.autoMigrate(config[propertyName]);
          if (property.deprecated.migrationPath) {
            safeSetNestedProperty(
              config,
              property.deprecated.migrationPath.split('.'),
              migratedValue
            );
            warnings.push({
              code: 'AUTO_MIGRATED',
              message: `Deprecated property '${propertyName}' automatically migrated to '${property.deprecated.migrationPath}'`,
              path: property.deprecated.migrationPath,
              value: migratedValue,
              severity: 'low',
            });
          }
        }
      }
    }

    // Add intermediate values that aren't in the schema
    if (this.context.allowUnknown) {
      this.mergeIntermediateValues(config, stats);
    }

    stats.durationMs = Date.now() - startTime;

    return {
      success: errors.length === 0,
      config,
      errors,
      warnings,
      stats,
    };
  }

  /**
   * Build configuration from an object
   */
  fromObject(obj: Record<string, unknown>): this {
    for (const [key, value] of Object.entries(obj)) {
      this.set(key, value);
    }
    return this;
  }

  /**
   * Build configuration from environment variables
   */
  fromEnvironment(prefix: string = ''): this {
    if (typeof process === 'undefined' || !process.env) {
      return this;
    }

    for (const [propertyName, property] of Array.from(this.schema.properties.entries())) {
      const envVar =
        (property.metadata?.envVar as string) ||
        this.context.envMappings!.get(propertyName) ||
        `${prefix}${propertyName.toUpperCase().replace('.', '_')}`;

      if (envVar in process.env) {
        const envValue = process.env[envVar];
        this.set(propertyName, this.parseEnvironmentValue(envValue, property));
      }
    }

    return this;
  }

  /**
   * Build configuration from command line arguments
   */
  fromArguments(argv: string[] = process.argv): this {
    const args = argv.slice(2); // Remove node and script name

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];

      if (arg.startsWith('--')) {
        const key = arg.slice(2);
        const nextArg = args[i + 1];

        // Handle --key=value format
        if (key.includes('=')) {
          const [k, v] = key.split('=', 2);
          this.set(k, v);
        }
        // Handle --key value format (if next arg doesn't start with --)
        else if (nextArg && !nextArg.startsWith('--')) {
          this.set(key, nextArg);
          i++; // Skip the next arg as it's the value
        }
        // Handle --key (boolean flag)
        else {
          this.set(key, true);
        }
      }
    }

    return this;
  }

  /**
   * Build configuration from a JSON file
   */
  fromJSON(filePath: string): this {
    try {
      // In a real implementation, you would read the file here
      // For now, we'll just note that this would be implemented
      console.log(`Would load JSON from: ${filePath}`);
    } catch (error) {
      throw new Error(`Failed to load JSON from ${filePath}: ${error}`);
    }

    return this;
  }

  // Private helper methods

  private addProperty<T>(name: string, property: ConfigProperty<T>): void {
    this.schema.properties.set(name, property);
  }

  private buildProperty(
    property: ConfigProperty,
    propertyName: string
  ): {
    success: boolean;
    value?: unknown;
    errors: ValidationError[];
    warnings: ValidationWarning[];
    usedDefault?: boolean;
    usedOverride?: boolean;
  } {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Get value from sources in priority order
    let value = this.getValueFromSources(propertyName);
    let usedOverride = false;

    // Apply environment-specific overrides
    if (this.context.environment && property.environmentOverrides?.has(this.context.environment)) {
      const override = property.environmentOverrides.get(this.context.environment)!;
      if (override.value !== undefined) {
        value = override.value;
        usedOverride = true;
      }
    }

    // Use default value if no value provided
    let usedDefault = false;
    if (value === undefined && property.defaultValue !== undefined) {
      value = property.defaultValue;
      usedDefault = true;
    }

    // Check if required property is missing
    if (property.required && value === undefined) {
      errors.push({
        code: 'REQUIRED_PROPERTY',
        message: `Required property '${propertyName}' is missing`,
        path: propertyName,
        value: undefined,
        expected: property.validator.typeName || 'value',
        actual: 'undefined',
        suggestions: ['Provide a value for this property', 'Add a default value if appropriate'],
      });
      return { success: false, errors, warnings };
    }

    // Skip validation if value is undefined and not required
    if (value === undefined) {
      return { success: true, errors, warnings };
    }

    // Validate the value
    const validator = property.validator;
    const validationContext: ValidationContext = {
      path: propertyName,
      root: this.intermediate,
      config: this.intermediate as unknown, // JSONObject compatibility
      strict: this.context.strict ?? false,
      mode: 'lenient',
      errors: [],
      warnings: [],
      options: {
        strict: this.context.strict,
        collectMetrics: this.context.collectStats,
      },
    };

    const validationResult = validator.validate(value, validationContext);
    errors.push(...validationResult.errors);
    warnings.push(...validationResult.warnings);

    if (!validationResult.success) {
      return { success: false, errors, warnings };
    }

    return {
      success: true,
      value: validationResult.value,
      errors,
      warnings,
      usedDefault,
      usedOverride,
    };
  }

  private getValueFromSources(propertyName: string): unknown {
    // Check intermediate values first
    const intermediateResult = safeGetNestedProperty(this.intermediate, propertyName.split('.'));
    if (intermediateResult.found) {
      return intermediateResult.value;
    }

    // Check property resolvers
    const resolver = this.context.propertyResolvers!.get(propertyName);
    if (resolver) {
      return resolver(this.context);
    }

    // Check configuration sources
    for (const source of this.context.sources!) {
      if (source.hasValue(propertyName, this.context)) {
        return source.getValue(propertyName, this.context);
      }
    }

    return undefined;
  }

  private mergeIntermediateValues(config: Record<string, unknown>, stats: ConfigBuildStats): void {
    for (const [key, value] of Object.entries(this.intermediate)) {
      if (!(key in config)) {
        config[key] = value;
        stats.propertiesValidated++;
      }
    }
  }

  private parseEnvironmentValue(envValue: string, property: ConfigProperty): unknown {
    // Basic parsing logic - in a real implementation, this would be more sophisticated
    const type = property.metadata?.type as string;

    switch (type) {
      case 'boolean':
        return envValue.toLowerCase() === 'true' || envValue === '1';
      case 'number':
        const num = Number(envValue);
        return isNaN(num) ? envValue : num;
      case 'array':
        try {
          return JSON.parse(envValue);
        } catch {
          return envValue.split(',').map((s) => s.trim());
        }
      case 'object':
        try {
          return JSON.parse(envValue);
        } catch {
          return envValue;
        }
      default:
        return envValue;
    }
  }
}

// ============================================================================
// Pre-built Configuration Builders
// ============================================================================

/**
 * Create a basic application configuration builder
 */
export function createAppConfigBuilder(
  version: Version,
  context?: Partial<ConfigBuilderContext>
): ConfigBuilder {
  return new ConfigBuilder('application', version, 'Basic application configuration', context)
    .environmentProperty('environment', {
      required: true,
      description: 'Application environment',
      envVar: 'NODE_ENV',
    })
    .boolean('debug', {
      default: false,
      description: 'Enable debug mode',
      envVar: 'DEBUG',
    })
    .enum('logLevel', ['error', 'warn', 'info', 'debug', 'trace'] as const, {
      default: 'info',
      description: 'Logging level',
      envVar: 'LOG_LEVEL',
    })
    .port('port', {
      default: 3000,
      min: 1000,
      max: 65535,
      description: 'Server port',
      envVar: 'PORT',
    })
    .hostname('host', {
      default: 'localhost',
      description: 'Server host',
      envVar: 'HOST',
    });
}

/**
 * Create a database configuration builder
 */
export function createDatabaseConfigBuilder(
  version: Version,
  context?: Partial<ConfigBuilderContext>
): ConfigBuilder {
  return new ConfigBuilder('database', version, 'Database configuration', context)
    .object(
      'qdrant',
      {
        host: guard(stringGuard).name('hostname'),
        port: rangeGuard(1, 65535, { integer: true }).name('port'),
        apiKey: guard(stringGuard).name('secret'),
        timeout: (guard(numberGuard) as unknown).build().name('timeout'),
        maxRetries: rangeGuard(0, 10, { integer: true }).name('maxRetries'),
        retryDelay: (guard(numberGuard) as unknown).build().name('retryDelay'),
        useHttps: (guard(booleanGuard) as unknown).build().name('useHttps'),
        collectionPrefix: optionalGuard(stringGuard).build().name('collectionPrefix'),
        enableHealthChecks: (guard(booleanGuard) as unknown).build().name('enableHealthChecks'),
        connectionPoolSize: rangeGuard(1, 100, { integer: true }).name('connectionPoolSize'),
        requestTimeout: (guard(numberGuard) as unknown).build().name('requestTimeout'),
        connectTimeout: (guard(numberGuard) as unknown).build().name('connectTimeout'),
      },
      {
        required: true,
        description: 'Qdrant vector database configuration',
      }
    )
    .boolean('fallbackEnabled', {
      default: true,
      description: 'Enable fallback storage',
      envVar: 'DB_FALLBACK_ENABLED',
    })
    .boolean('backupEnabled', {
      default: false,
      description: 'Enable database backups',
      envVar: 'DB_BACKUP_ENABLED',
    })
    .boolean('migrationEnabled', {
      default: true,
      description: 'Enable database migrations',
      envVar: 'DB_MIGRATION_ENABLED',
    });
}

/**
 * Create a monitoring configuration builder
 */
export function createMonitoringConfigBuilder(
  version: Version,
  context?: Partial<ConfigBuilderContext>
): ConfigBuilder {
  return new ConfigBuilder('monitoring', version, 'Monitoring configuration', context)
    .object(
      'metrics',
      {
        enabled: (guard(booleanGuard) as unknown).build().name('enabled'),
        interval: (guard(numberGuard) as unknown).build().name('interval'),
        prefix: guard(stringGuard).name('prefix'),
        labels: objectGuard({}, { allowExtra: true }).build().name('labels'),
        defaultBuckets: arrayGuard(numberGuard).build().name('defaultBuckets'),
      },
      {
        description: 'Metrics collection configuration',
      }
    )
    .object(
      'healthCheck',
      {
        enabled: (guard(booleanGuard) as unknown).build().name('enabled'),
        interval: (guard(numberGuard) as unknown).build().name('interval'),
        timeout: (guard(numberGuard) as unknown).build().name('timeout'),
        retries: (guard(numberGuard) as unknown).build().name('retries'),
        endpoints: arrayGuard(
          objectGuard({
            name: stringGuard,
            path: stringGuard,
            method: enumGuard(['GET', 'POST', 'PUT', 'DELETE'] as const),
            expectedStatus: rangeGuard(200, 299),
            timeout: numberGuard,
          })
        ),
      },
      {
        description: 'Health check configuration',
      }
    )
    .object(
      'tracing',
      {
        enabled: (guard(booleanGuard) as unknown).build().name('enabled'),
        samplingRate: rangeGuard(0, 1).build().name('samplingRate'),
        serviceName: guard(stringGuard).name('serviceName'),
        version: guard(stringGuard).name('version'),
      },
      {
        description: 'Distributed tracing configuration',
      }
    );
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a configuration builder with default sources
 */
export function createConfigBuilder(
  name: string,
  version: Version,
  description?: string,
  context?: Partial<ConfigBuilderContext>
): ConfigBuilder {
  const builder = new ConfigBuilder(name, version, description, context);

  // Add default sources (environment variables, command line, etc.)
  builder
    .source({
      name: 'environment',
      priority: 10,
      hasValue: (path, ctx) => {
        const envVar = ctx.envMappings?.get(path) || path.toUpperCase().replace('.', '_');
        return typeof process !== 'undefined' && process.env && envVar in process.env;
      },
      getValue: (path, ctx) => {
        const envVar = ctx.envMappings?.get(path) || path.toUpperCase().replace('.', '_');
        return typeof process !== 'undefined' && process.env ? process.env[envVar] : undefined;
      },
    })
    .source({
      name: 'command-line',
      priority: 20,
      hasValue: (path, ctx) => {
        // Check if path exists in command line arguments
        return false; // Implementation would check argv
      },
      getValue: (path, ctx) => {
        // Get value from command line arguments
        return undefined; // Implementation would parse argv
      },
    });

  return builder as unknown;
}

/**
 * Build configuration with sensible defaults
 */
export function buildConfig(
  name: string,
  version: Version,
  options?: {
    description?: string;
    environment?: Environment;
    strict?: boolean;
    allowUnknown?: boolean;
    envPrefix?: string;
  }
): ConfigBuildResult {
  const builder = createConfigBuilder(name, version, options?.description, {
    environment: options?.environment,
    strict: options?.strict,
    allowUnknown: options?.allowUnknown,
  });

  if (options?.envPrefix) {
    builder.fromEnvironment(options.envPrefix);
  }

  return builder.build();
}

/**
 * Validate existing configuration against a schema
 */
export function validateConfig(
  config: Record<string, unknown>,
  schema: ConfigSchema,
  options?: {
    strict?: boolean;
    environment?: Environment;
  }
): ConfigBuildResult {
  const builder = new ConfigBuilder(schema.name, schema.version, schema.description, {
    environment: options?.environment,
    strict: options?.strict,
    allowUnknown: false,
  });

  // Copy schema properties to builder
  for (const [name, property] of schema.properties) {
    builder['addProperty'](name, property);
  }

  // Load existing config
  builder.fromObject(config);

  return builder.build();
}
