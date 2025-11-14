/**
 * Generic Configuration Validation Schema with Runtime Checks
 *
 * This module provides a comprehensive schema-based validation framework
 * for configuration objects with runtime type safety and detailed error reporting.
 */

import type {
  Dict,
  JSONObject,
  JSONValue,
  ValidationError,
  ValidationResult,
  ValidationWarning
} from './base-types.js';
import type {
  ConfigKey,
  ConnectionString,
  createConfigKey,
  createConnectionString,
  createEnvironment,
  createFeatureFlag,
  createHostname,
  createMetricName,
  createPort,
  createSecret,
  createServiceName,
  createTagKey,
  createTagValue,
  createVersion,
  Environment,
  FeatureFlag,
  Hostname,
  MetricName,
  Port,
  Secret,
  ServiceName,
  TagKey,
  TagValue,
  Version} from './branded-types.js';
import type {
  Config,
  ConfigPath,
  ConfigTransformer,
  ConfigValidator,
  ConfigValue,
  DeepPartial} from './config.js';

// ============================================================================
// Validation Schema Types
// ============================================================================

/**
 * Base validation rule interface
 */
export interface ValidationRule<T = unknown> {
  /** Rule identifier for error reporting */
  readonly name: string;
  /** Rule description */
  readonly description?: string;
  /** Whether this rule is required */
  readonly required: boolean;
  /** Default value if not provided */
  readonly default?: T;
  /** Transform function applied before validation */
  readonly transform?: (value: unknown) => unknown;
  /** Validate function */
  readonly validate: (value: unknown, context: ValidationContext) => ValidationResult;
}

/**
 * Validation context for rule execution
 */
export interface ValidationContext {
  /** Current path being validated */
  readonly path: ConfigPath;
  /** Full configuration object */
  readonly config: JSONObject;
  /** Environment-specific context */
  readonly environment?: Environment;
  /** Strict mode (fail on unknown properties) */
  readonly strict: boolean;
  /** Validation mode */
  readonly mode: ValidationMode;
  /** Parent object context */
  readonly parent?: ValidationContext;
  /** Accumulated errors */
  readonly errors: ValidationError[];
  /** Accumulated warnings */
  readonly warnings: ValidationWarning[];
}

/**
 * Validation execution modes
 */
export type ValidationMode =
  | 'strict'    // Fail on any issue
  | 'lenient'   // Allow warnings, fail on errors
  | 'permissive'; // Allow both warnings and errors

/**
 * Schema definition interface
 */
export interface ConfigSchema {
  /** Schema name */
  readonly name: string;
  /** Schema version */
  readonly version: Version;
  /** Schema description */
  readonly description?: string;
  /** Validation rules by path */
  readonly rules: Map<ConfigPath, ValidationRule[]>;
  /** Environment-specific overrides */
  readonly environmentOverrides?: Map<Environment, Partial<ConfigSchema>>;
  /** Required environments */
  readonly requiredEnvironments?: Environment[];
  /** Deprecated paths with migration info */
  readonly deprecatedPaths?: Map<ConfigPath, DeprecatedPathInfo>;
}

/**
 * Deprecated path information
 */
export interface DeprecatedPathInfo {
  /** Deprecation message */
  readonly message: string;
  /** Since version */
  readonly since: Version;
  /** Removal version */
  readonly removalVersion?: Version;
  /** Migration path */
  readonly migrationPath?: ConfigPath;
  /** Automatic migration function */
  readonly autoMigrate?: (value: unknown) => unknown;
}

/**
 * Property validation options
 */
export interface PropertyValidationOptions<T = unknown> {
  /** Property is required */
  readonly required?: boolean;
  /** Default value */
  readonly default?: T;
  /** Description for documentation */
  readonly description?: string;
  /** Validation rules */
  readonly rules?: ValidationRule<T>[];
  /** Environment-specific overrides */
  readonly environmentOverrides?: Partial<Record<string, PropertyValidationOptions<T>>>;
  /** Deprecation info */
  readonly deprecated?: DeprecatedPathInfo;
}

// ============================================================================
// Built-in Validation Rules
// ============================================================================

/**
 * String validation rule
 */
export function stringRule(options: {
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  trim?: boolean;
  transform?: (value: string) => string;
} = {}): ValidationRule<string> {
  const { minLength, maxLength, pattern, trim = true, transform } = options;

  return {
    name: 'string',
    description: 'Validates string values',
    required: false,
    validate: (value: unknown, context): ValidationResult => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      // Transform to string if possible
      let strValue: string;
      if (typeof value === 'string') {
        strValue = trim ? value.trim() : value;
      } else if (value === null || value === undefined) {
        return { valid: true, errors: [], warnings: [] };
      } else {
        strValue = String(value);
        warnings.push({
          code: 'TYPE_COERCION',
          message: `Value at ${context.path} was coerced to string`,
          path: context.path,
          value
        });
      }

      // Apply custom transform
      if (transform) {
        strValue = transform(strValue);
      }

      // Length validation
      if (minLength !== undefined && strValue.length < minLength) {
        errors.push({
          code: 'MIN_LENGTH',
          message: `String at ${context.path} must be at least ${minLength} characters long`,
          path: context.path,
          value: strValue
        });
      }

      if (maxLength !== undefined && strValue.length > maxLength) {
        errors.push({
          code: 'MAX_LENGTH',
          message: `String at ${context.path} must be at most ${maxLength} characters long`,
          path: context.path,
          value: strValue
        });
      }

      // Pattern validation
      if (pattern && !pattern.test(strValue)) {
        errors.push({
          code: 'PATTERN_MISMATCH',
          message: `String at ${context.path} does not match required pattern`,
          path: context.path,
          value: strValue
        });
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
        data: strValue
      };
    }
  };
}

/**
 * Number validation rule
 */
export function numberRule(options: {
  min?: number;
  max?: number;
  integer?: boolean;
  positive?: boolean;
  transform?: (value: number) => number;
} = {}): ValidationRule<number> {
  const { min, max, integer = false, positive = false, transform } = options;

  return {
    name: 'number',
    description: 'Validates numeric values',
    required: false,
    validate: (value: unknown, context): ValidationResult => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      // Convert to number
      let numValue: number;
      if (typeof value === 'number') {
        numValue = value;
      } else if (typeof value === 'string') {
        const parsed = parseFloat(value);
        if (isNaN(parsed)) {
          errors.push({
            code: 'INVALID_NUMBER',
            message: `Value at ${context.path} is not a valid number`,
            path: context.path,
            value
          });
          return { valid: false, errors, warnings };
        }
        numValue = parsed;
        warnings.push({
          code: 'TYPE_COERCION',
          message: `String value at ${context.path} was parsed as number`,
          path: context.path,
          value
        });
      } else if (value === null || value === undefined) {
        return { valid: true, errors: [], warnings: [] };
      } else {
        errors.push({
          code: 'INVALID_TYPE',
          message: `Value at ${context.path} must be a number`,
          path: context.path,
          value
        });
        return { valid: false, errors, warnings };
      }

      // Apply custom transform
      if (transform) {
        numValue = transform(numValue);
      }

      // NaN/Infinity check
      if (!isFinite(numValue)) {
        errors.push({
          code: 'INVALID_NUMBER',
          message: `Value at ${context.path} must be a finite number`,
          path: context.path,
          value: numValue
        });
      }

      // Integer check
      if (integer && !Number.isInteger(numValue)) {
        errors.push({
          code: 'NOT_INTEGER',
          message: `Value at ${context.path} must be an integer`,
          path: context.path,
          value: numValue
        });
      }

      // Positive check
      if (positive && numValue <= 0) {
        errors.push({
          code: 'NOT_POSITIVE',
          message: `Value at ${context.path} must be positive`,
          path: context.path,
          value: numValue
        });
      }

      // Range validation
      if (min !== undefined && numValue < min) {
        errors.push({
          code: 'MIN_VALUE',
          message: `Value at ${context.path} must be at least ${min}`,
          path: context.path,
          value: numValue
        });
      }

      if (max !== undefined && numValue > max) {
        errors.push({
          code: 'MAX_VALUE',
          message: `Value at ${context.path} must be at most ${max}`,
          path: context.path,
          value: numValue
        });
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
        data: numValue
      };
    }
  };
}

/**
 * Boolean validation rule
 */
export function booleanRule(options: {
  allowStringBoolean?: boolean;
  truthyValues?: unknown[];
  falsyValues?: unknown[];
} = {}): ValidationRule<boolean> {
  const { allowStringBoolean = true, truthyValues = [true, 1, 'true', '1'], falsyValues = [false, 0, 'false', '0'] } = options;

  return {
    name: 'boolean',
    description: 'Validates boolean values',
    required: false,
    validate: (value: unknown, context): ValidationResult => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (typeof value === 'boolean') {
        return { valid: true, errors: [], warnings: [], data: value };
      }

      if (value === null || value === undefined) {
        return { valid: true, errors: [], warnings: [] };
      }

      // String boolean conversion
      if (allowStringBoolean && typeof value === 'string') {
        const lower = value.toLowerCase();
        if (lower === 'true') {
          warnings.push({
            code: 'TYPE_COERCION',
            message: `String 'true' at ${context.path} was converted to boolean`,
            path: context.path,
            value
          });
          return { valid: true, errors: [], warnings, data: true };
        }
        if (lower === 'false') {
          warnings.push({
            code: 'TYPE_COERCION',
            message: `String 'false' at ${context.path} was converted to boolean`,
            path: context.path,
            value
          });
          return { valid: true, errors: [], warnings, data: false };
        }
      }

      // Truthy/falsy conversion
      if (truthyValues.includes(value)) {
        warnings.push({
          code: 'TYPE_COERCION',
          message: `Value at ${context.path} was converted to boolean (true)`,
          path: context.path,
          value
        });
        return { valid: true, errors: [], warnings, data: true };
      }

      if (falsyValues.includes(value)) {
        warnings.push({
          code: 'TYPE_COERCION',
          message: `Value at ${context.path} was converted to boolean (false)`,
          path: context.path,
          value
        });
        return { valid: true, errors: [], warnings, data: false };
      }

      errors.push({
        code: 'INVALID_BOOLEAN',
        message: `Value at ${context.path} must be a boolean or convertible to boolean`,
        path: context.path,
        value
      });

      return { valid: false, errors, warnings };
    }
  };
}

/**
 * Array validation rule
 */
export function arrayRule<T>(
  itemType: ValidationRule<T>,
  options: {
    minLength?: number;
    maxLength?: number;
    uniqueItems?: boolean;
    allowEmpty?: boolean;
  } = {}
): ValidationRule<T[]> {
  const { minLength, maxLength, uniqueItems = false, allowEmpty = true } = options;

  return {
    name: 'array',
    description: 'Validates array values',
    required: false,
    validate: (value: unknown, context): ValidationResult => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (value === null || value === undefined) {
        return { valid: true, errors: [], warnings: [] };
      }

      if (!Array.isArray(value)) {
        errors.push({
          code: 'INVALID_ARRAY',
          message: `Value at ${context.path} must be an array`,
          path: context.path,
          value
        });
        return { valid: false, errors, warnings };
      }

      // Empty array check
      if (!allowEmpty && value.length === 0) {
        errors.push({
          code: 'EMPTY_ARRAY',
          message: `Array at ${context.path} cannot be empty`,
          path: context.path,
          value
        });
      }

      // Length validation
      if (minLength !== undefined && value.length < minLength) {
        errors.push({
          code: 'MIN_LENGTH',
          message: `Array at ${context.path} must have at least ${minLength} items`,
          path: context.path,
          value
        });
      }

      if (maxLength !== undefined && value.length > maxLength) {
        errors.push({
          code: 'MAX_LENGTH',
          message: `Array at ${context.path} must have at most ${maxLength} items`,
          path: context.path,
          value
        });
      }

      // Validate each item
      const validatedItems: T[] = [];
      for (let i = 0; i < value.length; i++) {
        const itemPath = `${context.path}[${i}]`;
        const itemContext = { ...context, path: itemPath };
        const itemResult = itemType.validate(value[i], itemContext);

        errors.push(...itemResult.errors);
        warnings.push(...itemResult.warnings);

        if (itemResult.valid && itemResult.data !== undefined) {
          validatedItems.push(itemResult.data);
        }
      }

      // Unique items check
      if (uniqueItems) {
        const seen = new Set();
        for (const item of validatedItems) {
          const key = JSON.stringify(item);
          if (seen.has(key)) {
            errors.push({
              code: 'DUPLICATE_ITEM',
              message: `Array at ${context.path} contains duplicate items`,
              path: context.path,
              value: item
            });
          }
          seen.add(key);
        }
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
        data: validatedItems
      };
    }
  };
}

/**
 * Object validation rule
 */
export function objectRule<T extends Record<string, unknown>>(
  schema: Record<string, ValidationRule<unknown>>,
  options: {
    allowUnknownProperties?: boolean;
    strict?: boolean;
  } = {}
): ValidationRule<T> {
  const { allowUnknownProperties = false, strict = false } = options;

  return {
    name: 'object',
    description: 'Validates object values',
    required: false,
    validate: (value: unknown, context): ValidationResult => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (value === null || value === undefined) {
        return { valid: true, errors: [], warnings: [] };
      }

      if (typeof value !== 'object' || Array.isArray(value)) {
        errors.push({
          code: 'INVALID_OBJECT',
          message: `Value at ${context.path} must be an object`,
          path: context.path,
          value
        });
        return { valid: false, errors, warnings };
      }

      const obj = value as Record<string, unknown>;
      const validatedObj: Record<string, unknown> = {};

      // Check for unknown properties
      if (strict && !allowUnknownProperties) {
        const knownProperties = new Set(Object.keys(schema));
        for (const key of Object.keys(obj)) {
          if (!knownProperties.has(key)) {
            warnings.push({
              code: 'UNKNOWN_PROPERTY',
              message: `Unknown property '${key}' at ${context.path}`,
              path: `${context.path}.${key}`,
              value: obj[key]
            });
          }
        }
      }

      // Validate each property
      for (const [propertyName, rule] of Object.entries(schema)) {
        const propertyPath = context.path ? `${context.path}.${propertyName}` : propertyName;
        const propertyContext = { ...context, path: propertyPath };
        const propertyValue = obj[propertyName];

        // Handle required properties
        if (rule.required && (propertyValue === undefined || propertyValue === null)) {
          errors.push({
            code: 'REQUIRED_PROPERTY',
            message: `Required property '${propertyName}' is missing at ${context.path}`,
            path: propertyPath,
            value: propertyValue
          });
          continue;
        }

        // Use default value if available
        const valueToValidate = propertyValue !== undefined ? propertyValue : rule.default;

        const result = rule.validate(valueToValidate, propertyContext);
        errors.push(...result.errors);
        warnings.push(...result.warnings);

        if (result.valid && result.data !== undefined) {
          validatedObj[propertyName] = result.data;
        }
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings,
        data: validatedObj as T
      };
    }
  };
}

/**
 * Enum validation rule
 */
export function enumRule<T extends string>(
  allowedValues: readonly T[],
  options: {
    caseSensitive?: boolean;
    allowCoercion?: boolean;
  } = {}
): ValidationRule<T> {
  const { caseSensitive = true, allowCoercion = false } = options;

  const valueSet = new Set(caseSensitive ? allowedValues : allowedValues.map(v => v.toLowerCase()));

  return {
    name: 'enum',
    description: `Validates enum values (${allowedValues.join(', ')})`,
    required: false,
    validate: (value: unknown, context): ValidationResult => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (value === null || value === undefined) {
        return { valid: true, errors: [], warnings: [] };
      }

      let strValue = String(value);
      const originalValue = strValue;

      if (!caseSensitive) {
        strValue = strValue.toLowerCase();
      }

      if (valueSet.has(strValue as T)) {
        const finalValue = caseSensitive ? strValue : (allowedValues.find(v => v.toLowerCase() === strValue) as T);
        if (allowCoercion && originalValue !== finalValue) {
          warnings.push({
            code: 'ENUM_COERCION',
            message: `Value '${originalValue}' at ${context.path} was coerced to '${finalValue}'`,
            path: context.path,
            value
          });
        }
        return { valid: true, errors: [], warnings, data: finalValue };
      }

      errors.push({
        code: 'INVALID_ENUM',
        message: `Value at ${context.path} must be one of: ${allowedValues.join(', ')}`,
        path: context.path,
        value
      });

      return { valid: false, errors, warnings };
    }
  };
}

/**
 * Branded type validation rules
 */

export const configKeyRule: ValidationRule<ConfigKey> = {
  name: 'configKey',
  description: 'Validates configuration key',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const configKey = createConfigKey(String(value));
      return { valid: true, errors: [], warnings: [], data: configKey };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_CONFIG_KEY',
          message: `Invalid configuration key at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const environmentRule: ValidationRule<Environment> = {
  name: 'environment',
  description: 'Validates environment value',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const env = createEnvironment(String(value));
      return { valid: true, errors: [], warnings: [], data: env };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_ENVIRONMENT',
          message: `Invalid environment at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const serviceNameRule: ValidationRule<ServiceName> = {
  name: 'serviceName',
  description: 'Validates service name',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const serviceName = createServiceName(String(value));
      return { valid: true, errors: [], warnings: [], data: serviceName };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_SERVICE_NAME',
          message: `Invalid service name at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const connectionStringRule: ValidationRule<ConnectionString> = {
  name: 'connectionString',
  description: 'Validates connection string',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const connectionString = createConnectionString(String(value));
      return { valid: true, errors: [], warnings: [], data: connectionString };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_CONNECTION_STRING',
          message: `Invalid connection string at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const secretRule: ValidationRule<Secret> = {
  name: 'secret',
  description: 'Validates secret value',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const secret = createSecret(String(value));
      return { valid: true, errors: [], warnings: [], data: secret };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_SECRET',
          message: `Invalid secret at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const hostnameRule: ValidationRule<Hostname> = {
  name: 'hostname',
  description: 'Validates hostname',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const hostname = createHostname(String(value));
      return { valid: true, errors: [], warnings: [], data: hostname };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_HOSTNAME',
          message: `Invalid hostname at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const portRule: ValidationRule<Port> = {
  name: 'port',
  description: 'Validates port number',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const port = createPort(Number(value));
      return { valid: true, errors: [], warnings: [], data: port };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_PORT',
          message: `Invalid port at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const versionRule: ValidationRule<Version> = {
  name: 'version',
  description: 'Validates version string',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const version = createVersion(String(value));
      return { valid: true, errors: [], warnings: [], data: version };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_VERSION',
          message: `Invalid version at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const featureFlagRule: ValidationRule<FeatureFlag> = {
  name: 'featureFlag',
  description: 'Validates feature flag name',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const flag = createFeatureFlag(String(value));
      return { valid: true, errors: [], warnings: [], data: flag };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_FEATURE_FLAG',
          message: `Invalid feature flag at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const metricNameRule: ValidationRule<MetricName> = {
  name: 'metricName',
  description: 'Validates metric name',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const metricName = createMetricName(String(value));
      return { valid: true, errors: [], warnings: [], data: metricName };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_METRIC_NAME',
          message: `Invalid metric name at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const tagKeyRule: ValidationRule<TagKey> = {
  name: 'tagKey',
  description: 'Validates tag key',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const tagKey = createTagKey(String(value));
      return { valid: true, errors: [], warnings: [], data: tagKey };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_TAG_KEY',
          message: `Invalid tag key at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

export const tagValueRule: ValidationRule<TagValue> = {
  name: 'tagValue',
  description: 'Validates tag value',
  required: false,
  validate: (value: unknown, context): ValidationResult => {
    try {
      const tagValue = createTagValue(String(value));
      return { valid: true, errors: [], warnings: [], data: tagValue };
    } catch (error) {
      return {
        valid: false,
        errors: [{
          code: 'INVALID_TAG_VALUE',
          message: `Invalid tag value at ${context.path}: ${error instanceof Error ? error.message : String(error)}`,
          path: context.path,
          value
        }],
        warnings: []
      };
    }
  }
};

// ============================================================================
// Schema Builder
// ============================================================================

/**
 * Schema builder for creating configuration schemas
 */
export class ConfigSchemaBuilder {
  private rules: Map<ConfigPath, ValidationRule[]> = new Map();
  private environmentOverrides: Map<Environment, Partial<ConfigSchema>> = new Map();
  private deprecatedPaths: Map<ConfigPath, DeprecatedPathInfo> = new Map();

  constructor(
    private readonly name: string,
    private readonly version: Version,
    private readonly description?: string
  ) {}

  /**
   * Add a validation rule for a configuration path
   */
  addRule(path: ConfigPath, rule: ValidationRule): this {
    const existing = this.rules.get(path) || [];
    this.rules.set(path, [...existing, rule]);
    return this;
  }

  /**
   * Add multiple validation rules for a configuration path
   */
  addRules(path: ConfigPath, rules: ValidationRule[]): this {
    const existing = this.rules.get(path) || [];
    this.rules.set(path, [...existing, ...rules]);
    return this;
  }

  /**
   * Add a property with validation options
   */
  addProperty<T>(path: ConfigPath, options: PropertyValidationOptions<T>): this {
    const rules: ValidationRule<T>[] = [];

    // Add required validation if needed
    if (options.required) {
      rules.push({
        name: 'required',
        description: 'Property is required',
        required: true,
        validate: (value: unknown, context): ValidationResult => {
          if (value === undefined || value === null) {
            return {
              valid: false,
              errors: [{
                code: 'REQUIRED_PROPERTY',
                message: `Required property '${path}' is missing`,
                path: context.path,
                value
              }],
              warnings: []
            };
          }
          return { valid: true, errors: [], warnings: [] };
        }
      });
    }

    // Add custom rules
    if (options.rules) {
      rules.push(...options.rules);
    }

    // Add default value rule
    if (options.default !== undefined) {
      rules.push({
        name: 'default',
        description: 'Default value',
        required: false,
        default: options.default,
        validate: (value: unknown): ValidationResult => {
          return { valid: true, errors: [], warnings: [], data: value ?? options.default };
        }
      });
    }

    // Add deprecated path info
    if (options.deprecated) {
      this.deprecatedPaths.set(path, options.deprecated);
    }

    this.addRules(path, rules);
    return this;
  }

  /**
   * Add environment-specific overrides
   */
  addEnvironmentOverride(environment: Environment, overrides: Partial<ConfigSchema>): this {
    this.environmentOverrides.set(environment, overrides);
    return this;
  }

  /**
   * Mark a path as deprecated
   */
  deprecatePath(path: ConfigPath, info: DeprecatedPathInfo): this {
    this.deprecatedPaths.set(path, info);
    return this;
  }

  /**
   * Build the final schema
   */
  build(): ConfigSchema {
    return {
      name: this.name,
      version: this.version,
      description: this.description,
      rules: this.rules,
      environmentOverrides: this.environmentOverrides.size > 0 ? this.environmentOverrides : undefined,
      deprecatedPaths: this.deprecatedPaths.size > 0 ? this.deprecatedPaths : undefined
    };
  }
}

// ============================================================================
// Schema Validation Engine
// ============================================================================

/**
 * Configuration validation engine
 */
export class ConfigValidationEngine {
  private schemas: Map<string, ConfigSchema> = new Map();

  /**
   * Register a configuration schema
   */
  registerSchema(schema: ConfigSchema): void {
    this.schemas.set(schema.name, schema);
  }

  /**
   * Get a registered schema
   */
  getSchema(name: string): ConfigSchema | undefined {
    return this.schemas.get(name);
  }

  /**
   * Validate configuration against a schema
   */
  validate(
    config: JSONObject,
    schemaName: string,
    options: {
      environment?: Environment;
      mode?: ValidationMode;
      strict?: boolean;
    } = {}
  ): ValidationResult {
    const schema = this.getSchema(schemaName);
    if (!schema) {
      return {
        valid: false,
        errors: [{
          code: 'SCHEMA_NOT_FOUND',
          message: `Schema '${schemaName}' not found`,
          path: '',
          value: config
        }],
        warnings: []
      };
    }

    const { environment, mode = 'lenient', strict = false } = options;
    const context: ValidationContext = {
      path: '',
      config,
      environment,
      strict,
      mode,
      errors: [],
      warnings: []
    };

    // Apply environment-specific overrides if present
    let schemaToUse = schema;
    if (environment && schema.environmentOverrides?.has(environment)) {
      const override = schema.environmentOverrides.get(environment)!;
      schemaToUse = {
        ...schema,
        rules: new Map([...schema.rules, ...(override.rules || new Map())])
      };
    }

    return this.validateAgainstSchema(config, schemaToUse, context);
  }

  /**
   * Validate configuration against a specific schema
   */
  private validateAgainstSchema(
    config: JSONObject,
    schema: ConfigSchema,
    context: ValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Check deprecated paths
    for (const [path, info] of schema.deprecatedPaths || []) {
      if (this.hasProperty(config, path)) {
        warnings.push({
          code: 'DEPRECATED_PATH',
          message: `Configuration path '${path}' is deprecated: ${info.message}`,
          path,
          value: this.getProperty(config, path)
        });

        // Auto-migrate if possible
        if (info.autoMigrate && info.migrationPath) {
          const currentValue = this.getProperty(config, path);
          const migratedValue = info.autoMigrate(currentValue);
          this.setProperty(config, info.migrationPath, migratedValue);
          warnings.push({
            code: 'AUTO_MIGRATED',
            message: `Deprecated path '${path}' was automatically migrated to '${info.migrationPath}'`,
            path: info.migrationPath,
            value: migratedValue
          });
        }
      }
    }

    // Validate all rules
    for (const [path, rules] of schema.rules) {
      const value = this.getProperty(config, path);
      const pathContext = { ...context, path };

      for (const rule of rules) {
        const result = rule.validate(value, pathContext);
        errors.push(...result.errors);
        warnings.push(...result.warnings);

        // Update config with transformed/validated data
        if (result.valid && result.data !== undefined) {
          this.setProperty(config, path, result.data);
        }
      }
    }

    // Strict mode: check for unknown properties
    if (context.strict) {
      const knownPaths = new Set(schema.rules.keys());
      for (const path of this.getAllPaths(config)) {
        if (!knownPaths.has(path)) {
          warnings.push({
            code: 'UNKNOWN_PROPERTY',
            message: `Unknown configuration property: ${path}`,
            path,
            value: this.getProperty(config, path)
          });
        }
      }
    }

    // Determine overall validity based on mode
    let valid = errors.length === 0;
    if (context.mode === 'permissive') {
      valid = true; // Always valid in permissive mode
    } else if (context.mode === 'lenient') {
      valid = errors.length === 0; // Valid if no errors (warnings allowed)
    } else {
      valid = errors.length === 0 && warnings.length === 0; // Strict mode
    }

    return {
      valid,
      errors,
      warnings,
      data: config
    };
  }

  /**
   * Check if object has a property at the given path
   */
  private hasProperty(obj: JSONObject, path: string): boolean {
    const parts = path.split('.');
    let current: unknown = obj;

    for (const part of parts) {
      if (current === null || typeof current !== 'object' || !(part in current)) {
        return false;
      }
      current = (current as Record<string, unknown>)[part];
    }

    return true;
  }

  /**
   * Get property value at the given path
   */
  private getProperty(obj: JSONObject, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;

    for (const part of parts) {
      if (current === null || typeof current !== 'object' || !(part in current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }

    return current;
  }

  /**
   * Set property value at the given path
   */
  private setProperty(obj: JSONObject, path: string, value: unknown): void {
    const parts = path.split('.');
    let current: unknown = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current) || current[part] === null || typeof current[part] !== 'object') {
        current[part] = {};
      }
      current = current[part];
    }

    current[parts[parts.length - 1]] = value;
  }

  /**
   * Get all paths in an object
   */
  private getAllPaths(obj: JSONObject, prefix: string = ''): string[] {
    const paths: string[] = [];

    for (const [key, value] of Object.entries(obj)) {
      const currentPath = prefix ? `${prefix}.${key}` : key;
      paths.push(currentPath);

      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        paths.push(...this.getAllPaths(value as JSONObject, currentPath));
      }
    }

    return paths;
  }
}

// ============================================================================
// Pre-built Common Schemas
// ============================================================================

/**
 * Create a basic application configuration schema
 */
export function createAppConfigSchema(version: Version): ConfigSchema {
  return new ConfigSchemaBuilder('application', version, 'Basic application configuration')
    .addProperty('environment', {
      required: true,
      rules: [environmentRule]
    })
    .addProperty('debug', {
      required: false,
      default: false,
      rules: [booleanRule()]
    })
    .addProperty('logLevel', {
      required: false,
      default: 'info',
      rules: [enumRule(['error', 'warn', 'info', 'debug', 'trace'] as const)]
    })
    .addProperty('port', {
      required: false,
      default: 3000,
      rules: [portRule]
    })
    .addProperty('host', {
      required: false,
      default: 'localhost',
      rules: [hostnameRule]
    })
    .build();
}

/**
 * Create a database configuration schema
 */
export function createDatabaseConfigSchema(version: Version): ConfigSchema {
  return new ConfigSchemaBuilder('database', version, 'Database configuration')
    .addProperty('qdrant', {
      required: true,
      rules: [objectRule({
        host: hostnameRule,
        port: portRule,
        apiKey: secretRule,
        timeout: numberRule({ min: 1000, max: 300000 }),
        maxRetries: numberRule({ min: 0, max: 10, integer: true }),
        retryDelay: numberRule({ min: 100, max: 10000 }),
        useHttps: booleanRule(),
        collectionPrefix: stringRule({ maxLength: 50 }),
        enableHealthChecks: booleanRule(),
        connectionPoolSize: numberRule({ min: 1, max: 100, integer: true }),
        requestTimeout: numberRule({ min: 1000, max: 300000 }),
        connectTimeout: numberRule({ min: 1000, max: 300000 })
      })]
    })
    .addProperty('fallbackEnabled', {
      required: false,
      default: true,
      rules: [booleanRule()]
    })
    .addProperty('backupEnabled', {
      required: false,
      default: false,
      rules: [booleanRule()]
    })
    .addProperty('migrationEnabled', {
      required: false,
      default: true,
      rules: [booleanRule()]
    })
    .build();
}

/**
 * Create a monitoring configuration schema
 */
export function createMonitoringConfigSchema(version: Version): ConfigSchema {
  return new ConfigSchemaBuilder('monitoring', version, 'Monitoring configuration')
    .addProperty('metrics', {
      required: false,
      rules: [objectRule({
        enabled: booleanRule(),
        interval: numberRule({ min: 1000, max: 300000 }),
        prefix: stringRule({ maxLength: 50 }),
        labels: objectRule({}, { allowUnknownProperties: true }),
        defaultBuckets: arrayRule(numberRule({ positive: true }), { minLength: 1 })
      })]
    })
    .addProperty('healthCheck', {
      required: false,
      rules: [objectRule({
        enabled: booleanRule(),
        interval: numberRule({ min: 5000, max: 300000 }),
        timeout: numberRule({ min: 1000, max: 30000 }),
        retries: numberRule({ min: 0, max: 10, integer: true }),
        endpoints: arrayRule(objectRule({
          name: stringRule({ minLength: 1 }),
          path: stringRule({ minLength: 1 }),
          method: enumRule(['GET', 'POST', 'PUT', 'DELETE'] as const),
          expectedStatus: numberRule({ min: 200, max: 299 }),
          timeout: numberRule({ min: 100, max: 30000 })
        }), { minLength: 1 })
      })]
    })
    .addProperty('tracing', {
      required: false,
      rules: [objectRule({
        enabled: booleanRule(),
        samplingRate: numberRule({ min: 0, max: 1 }),
        serviceName: serviceNameRule,
        version: versionRule
      })]
    })
    .build();
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a default validation engine with common schemas
 */
export function createDefaultValidationEngine(): ConfigValidationEngine {
  const engine = new ConfigValidationEngine();

  // Register common schemas with default version
  const defaultVersion = createVersion('1.0.0');
  engine.registerSchema(createAppConfigSchema(defaultVersion));
  engine.registerSchema(createDatabaseConfigSchema(defaultVersion));
  engine.registerSchema(createMonitoringConfigSchema(defaultVersion));

  return engine;
}

/**
 * Validate configuration using default engine
 */
export function validateConfig(
  config: JSONObject,
  schemaName: string,
  options?: {
    environment?: Environment;
    mode?: ValidationMode;
    strict?: boolean;
  }
): ValidationResult {
  const engine = createDefaultValidationEngine();
  return engine.validate(config, schemaName, options);
}

/**
 * Type guard for validation result
 */
export function isValidValidationResult(value: unknown): value is ValidationResult {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const result = value as Record<string, unknown>;

  return typeof result.valid === 'boolean' &&
         Array.isArray(result.errors) &&
         Array.isArray(result.warnings);
}

/**
 * Extract error messages from validation result
 */
export function getErrorMessages(result: ValidationResult): string[] {
  return result.errors.map(error => `${error.code}: ${error.message}`);
}

/**
 * Extract warning messages from validation result
 */
export function getWarningMessages(result: ValidationResult): string[] {
  return result.warnings.map(warning => `${warning.code}: ${warning.message}`);
}

/**
 * Format validation result for logging
 */
export function formatValidationResult(result: ValidationResult): string {
  const lines = [`Validation ${result.valid ? 'passed' : 'failed'}`];

  if (result.errors.length > 0) {
    lines.push('Errors:');
    result.errors.forEach(error => {
      lines.push(`  - ${error.path}: ${error.message} (${error.code})`);
    });
  }

  if (result.warnings.length > 0) {
    lines.push('Warnings:');
    result.warnings.forEach(warning => {
      lines.push(`  - ${warning.path}: ${warning.message} (${warning.code})`);
    });
  }

  return lines.join('\n');
}