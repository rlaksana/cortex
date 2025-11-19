/**
 * Configuration Validation Decorators
 *
 * TypeScript decorators for automatic configuration validation,
 * property validation, and class-level validation rules.
 */

import {
  type ValidationContext,
  type ValidationResult,
  type ValidationError,
  type ValidationWarning,
  type ValidationOptions
} from './runtime-type-guard-framework';
import { TypeDebugger } from './type-debug-helpers';

import 'reflect-metadata';

// Enhanced ValidationContext for decorator usage with full compatibility
interface DecoratorValidationContext extends Omit<ValidationContext, 'options'> {
  property?: string;
  options?: ValidationOptions & {
    groups?: string[];
    skipOnUpdate?: boolean;
  };
}

// Enhanced ValidationResult for decorator usage with full compatibility
interface DecoratorValidationResult extends ValidationResult {
  // Extend base ValidationResult with decorator-specific properties
}

// Type alias for compatibility
type ValidationContextCompat = ValidationContext & DecoratorValidationContext;

// Extended ValidationError interface for decorator compatibility
interface ExtendedValidationError extends ValidationError {
  timestamp?: string;
  severity?: 'low' | 'medium' | 'high';
  constraint?: string;
}

// Extended ValidationWarning interface for decorator compatibility
interface ExtendedValidationWarning extends ValidationWarning {
  timestamp?: string;
  category?: string;
}

/**
 * Metadata key for storing validation rules
 */
const VALIDATION_RULES_KEY = Symbol('validation_rules');
const CLASS_VALIDATION_KEY = Symbol('class_validation');

/**
 * Validation decorator options
 */
export interface ValidationDecoratorOptions {
  required?: boolean;
  default?: unknown;
  error?: string;
  groups?: string[];
  skipOnUpdate?: boolean;
  transform?: (value: unknown) => unknown;
}

/**
 * String validation options
 */
export interface StringValidationOptions extends ValidationDecoratorOptions {
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  email?: boolean;
  url?: boolean;
  uuid?: boolean;
  trim?: boolean;
  normalize?: boolean;
}

/**
 * Number validation options
 */
export interface NumberValidationOptions extends ValidationDecoratorOptions {
  min?: number;
  max?: number;
  integer?: boolean;
  positive?: boolean;
  negative?: boolean;
  finite?: boolean;
  step?: number;
}

/**
 * Array validation options
 */
export interface ArrayValidationOptions extends ValidationDecoratorOptions {
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  itemsType?: unknown;
  contains?: unknown;
}

/**
 * Object validation options
 */
export interface ObjectValidationOptions extends ValidationDecoratorOptions {
  strict?: boolean;
  allowExtra?: boolean;
  forbidExtra?: boolean;
  minProperties?: number;
  maxProperties?: number;
  propertyNames?: unknown;
  additionalProperties?: unknown;
}

/**
 * Custom validation function
 */
export type CustomValidatorFunction = (
  value: unknown,
  context?: ValidationContextCompat
) => boolean | ValidationResult;

/**
 * Class validation metadata
 */
export interface ClassValidationMetadata {
  className?: string;
  validateOnConstruction?: boolean;
  validateOnUpdate?: boolean;
  groups?: string[];
  strictMode?: boolean;
  stopOnFirstError?: boolean;
}

/**
 * Property validation metadata
 */
export interface PropertyValidationMetadata {
  propertyName: string;
  rule: {
    name: string;
    required: boolean;
    validate: (value: unknown, context: ValidationContextCompat) => ValidationResult;
  };
  options: ValidationDecoratorOptions;
}

/**
 * Base validation decorator factory
 */
function createValidationDecorator(
  ruleFactory: (options: ValidationDecoratorOptions) => {
    name: string;
    required: boolean;
    validate: (value: unknown, context: ValidationContextCompat) => ValidationResult;
  },
  defaultOptions: ValidationDecoratorOptions = {}
) {
  return function (options: ValidationDecoratorOptions = {}) {
    return function (target: unknown, propertyKey: string | symbol) {
      const validationOptions = { ...defaultOptions, ...options };
      const rule = ruleFactory(validationOptions);

      // Get existing validation rules
      const existingRules = Reflect.getMetadata(VALIDATION_RULES_KEY, target) || [];

      // Add new rule
      existingRules.push({
        propertyName: propertyKey.toString(),
        rule,
        options: validationOptions,
      });

      // Store updated rules
      Reflect.defineMetadata(VALIDATION_RULES_KEY, existingRules, target);
    };
  };
}

/**
 * Required property decorator
 */
export function Required(options: ValidationDecoratorOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'required',
      required: true,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        const success = value !== null && value !== undefined && value !== '';
        return {
          success,
          value: success ? value : undefined,
          errors: success
            ? []
            : [
                {
                  code: 'REQUIRED',
                  message: opts?.error || `Property is required`,
                  path: context.path,
                  value,
                },
              ],
          warnings: [],
        };
      },
    }),
    { required: true, ...options }
  );
}

/**
 * Optional property decorator
 */
export function Optional(options: ValidationDecoratorOptions = {}) {
  return createValidationDecorator(
    () => ({
      name: 'optional',
      required: false,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        return { success: true, value, errors: [], warnings: [], suggestions: [], context };
      },
    }),
    { required: false, ...options }
  );
}

/**
 * String validation decorator
 */
export function IsString(options: StringValidationOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'string',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        const errors: ValidationError[] = [];
        const warnings: ValidationWarning[] = [];

        // Check if value is string or should be skipped
        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              code: 'REQUIRED',
              message: opts?.error || 'String value is required',
              path: context.path,
              value,
              expected: 'string',
              actual: typeof value,
                          });
          }
          return { success: errors.length === 0, value: undefined, errors, warnings, suggestions: [], context };
        }

        // Transform value if needed
        let stringValue = String(value);
        if ((opts as any).trim) stringValue = stringValue.trim();
        if ((opts as any).normalize) stringValue = stringValue.normalize();

        // Type check
        if (typeof stringValue !== 'string') {
          errors.push({
            code: 'INVALID_TYPE',
            message: opts?.error || 'Value must be a string',
            path: context.path,
            value: stringValue,
            expected: 'string',
            actual: typeof stringValue,
                      });
        }

        // Length validations
        if ((opts as any).minLength !== undefined && stringValue.length < (opts as any).minLength) {
          errors.push({
            code: 'MIN_LENGTH',
            message: opts?.error || `String must be at least ${(opts as any).minLength} characters long`,
            path: context.path,
            value: stringValue,
            expected: `length >= ${(opts as any).minLength}`,
            actual: `length = ${stringValue.length}`,
                      });
        }

        if ((opts as any).maxLength !== undefined && stringValue.length > (opts as any).maxLength) {
          errors.push({
            code: 'MAX_LENGTH',
            message: opts?.error || `String must be at most ${(opts as any).maxLength} characters long`,
            path: context.path,
            value: stringValue,
            expected: `length <= ${(opts as any).maxLength}`,
            actual: `length = ${stringValue.length}`,
                      });
        }

        // Pattern validation
        if ((opts as any).pattern && !(opts as any).pattern.test(stringValue)) {
          errors.push({
            code: 'PATTERN_MISMATCH',
            message: opts?.error || 'String does not match required pattern',
            path: context.path,
            value: stringValue,
            expected: `pattern: ${(opts as any).pattern.toString()}`,
            actual: stringValue,
                      });
        }

        // Email validation
        if ((opts as any).email) {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(stringValue)) {
            errors.push({
              code: 'INVALID_EMAIL',
              message: opts?.error || 'Invalid email format',
              path: context.path,
              value: stringValue,
              expected: 'email format',
              actual: stringValue,
                          });
          }
        }

        // URL validation
        if ((opts as any).url) {
          try {
            new URL(stringValue);
          } catch {
            errors.push({
              code: 'INVALID_URL',
              message: opts?.error || 'Invalid URL format',
              path: context.path,
              value: stringValue,
              expected: 'valid URL',
              actual: stringValue,
                          });
          }
        }

        // UUID validation
        if ((opts as any).uuid) {
          const uuidRegex =
            /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
          if (!uuidRegex.test(stringValue)) {
            errors.push({
              code: 'INVALID_UUID',
              message: opts?.error || 'Invalid UUID format',
              path: context.path,
              value: stringValue,
              expected: 'UUID format',
              actual: stringValue,
                          });
          }
        }

        return {
          success: errors.length === 0,
          value: errors.length === 0 ? stringValue : undefined,
          errors,
          warnings,
                    context,
        };
      },
    }),
    options
  );
}

/**
 * Number validation decorator
 */
export function IsNumber(options: NumberValidationOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'number',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        const errors: ValidationError[] = [];
        const warnings: ValidationWarning[] = [];

        // Check if value should be skipped
        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              code: 'REQUIRED',
              message: opts?.error || 'Number value is required',
              path: context.path,
              value,
              expected: 'number',
              actual: typeof value,
                          });
          }
          return { success: errors.length === 0, value: undefined, errors, warnings, suggestions: [], context };
        }

        // Convert to number
        const numValue = Number(value);

        // Type check
        if (typeof numValue !== 'number' || isNaN(numValue)) {
          errors.push({
            code: 'INVALID_TYPE',
            message: opts?.error || 'Value must be a valid number',
            path: context.path,
            value,
            expected: 'number',
            actual: typeof value,
                      });
          return { success: false, value: undefined, errors, warnings, suggestions: [], context };
        }

        // Finite check
        if ((opts as NumberValidationOptions).finite !== false && !isFinite(numValue)) {
          errors.push({
            code: 'NOT_FINITE',
            message: opts?.error || 'Number must be finite',
            path: context.path,
            value: numValue,
            expected: 'finite number',
            actual: 'infinite or NaN',
                      });
        }

        // Integer check
        if ((opts as NumberValidationOptions).integer && !Number.isInteger(numValue)) {
          errors.push({
            code: 'NOT_INTEGER',
            message: opts?.error || 'Number must be an integer',
            path: context.path,
            value: numValue,
            expected: 'integer',
            actual: 'float',
                      });
        }

        // Positive/negative checks
        if ((opts as NumberValidationOptions).positive && numValue <= 0) {
          errors.push({
            code: 'NOT_POSITIVE',
            message: opts?.error || 'Number must be positive',
            path: context.path,
            value: numValue,
            expected: '> 0',
            actual: String(numValue),
                      });
        }

        if ((opts as NumberValidationOptions).negative && numValue >= 0) {
          errors.push({
            code: 'NOT_NEGATIVE',
            message: opts?.error || 'Number must be negative',
            path: context.path,
            value: numValue,
            expected: '< 0',
            actual: String(numValue),
                      });
        }

        // Range checks
        if ((opts as NumberValidationOptions).min !== undefined && numValue < (opts as NumberValidationOptions).min) {
          errors.push({
            code: 'MIN_VALUE',
            message: opts?.error || `Number must be at least ${(opts as NumberValidationOptions).min}`,
            path: context.path,
            value: numValue,
            expected: `>= ${(opts as NumberValidationOptions).min}`,
            actual: String(numValue),
                      });
        }

        if ((opts as NumberValidationOptions).max !== undefined && numValue > (opts as NumberValidationOptions).max) {
          errors.push({
            code: 'MAX_VALUE',
            message: opts?.error || `Number must be at most ${(opts as NumberValidationOptions).max}`,
            path: context.path,
            value: numValue,
            expected: `<= ${(opts as NumberValidationOptions).max}`,
            actual: String(numValue),
                      });
        }

        // Step validation
        if ((opts as NumberValidationOptions).step !== undefined) {
          const remainder = numValue % (opts as NumberValidationOptions).step!;
          if (Math.abs(remainder) > Number.EPSILON) {
            errors.push({
              code: 'INVALID_STEP',
              message: opts?.error || `Number must be a multiple of ${(opts as NumberValidationOptions).step}`,
              path: context.path,
              value: numValue,
              expected: `multiple of ${(opts as NumberValidationOptions).step}`,
              actual: String(numValue),
                          });
          }
        }

        return {
          success: errors.length === 0,
          value: errors.length === 0 ? numValue : undefined,
          errors,
          warnings,
                    context
        };
      },
    }),
    options
  );
}

/**
 * Boolean validation decorator
 */
export function IsBoolean(options: ValidationDecoratorOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'boolean',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        const errors: ValidationError[] = [];
        const warnings: ValidationWarning[] = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              code: 'REQUIRED',
              message: opts?.error || 'Boolean value is required',
              path: context.path,
              value,
              expected: 'boolean',
              actual: typeof value,
                          });
          }
          return { success: errors.length === 0, value: undefined, errors, warnings, suggestions: [], context };
        }

        if (typeof value !== 'boolean') {
          errors.push({
            code: 'INVALID_TYPE',
            message: opts?.error || 'Value must be a boolean',
            path: context.path,
            value,
            expected: 'boolean',
            actual: typeof value,
                      });
        }

        return {
          success: errors.length === 0,
          value: errors.length === 0 ? value : undefined,
          errors,
          warnings,
                    context
        };
      },
    }),
    options
  );
}

/**
 * Array validation decorator
 */
export function IsArray(options: ArrayValidationOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'array',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        const errors: ValidationError[] = [];
        const warnings: ValidationWarning[] = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              code: 'REQUIRED',
              message: opts?.error || 'Array value is required',
              path: context.path,
              value,
              expected: 'array',
              actual: typeof value,
                          });
          }
          return { success: errors.length === 0, value: undefined, errors, warnings, suggestions: [], context };
        }

        if (!Array.isArray(value)) {
          errors.push({
            code: 'INVALID_TYPE',
            message: opts?.error || 'Value must be an array',
            path: context.path,
            value,
            expected: 'array',
            actual: typeof value,
                      });
          return { success: false, value: undefined, errors, warnings, suggestions: [], context };
        }

        // Length validations
        if ((opts as ArrayValidationOptions).minItems !== undefined && value.length < (opts as ArrayValidationOptions).minItems) {
          errors.push({
            code: 'MIN_ITEMS',
            message: opts?.error || `Array must have at least ${(opts as ArrayValidationOptions).minItems} items`,
            path: context.path,
            value,
            expected: `length >= ${(opts as ArrayValidationOptions).minItems}`,
            actual: `length = ${value.length}`,
                      });
        }

        if ((opts as ArrayValidationOptions).maxItems !== undefined && value.length > (opts as ArrayValidationOptions).maxItems) {
          errors.push({
            code: 'MAX_ITEMS',
            message: opts?.error || `Array must have at most ${(opts as ArrayValidationOptions).maxItems} items`,
            path: context.path,
            value,
            expected: `length <= ${(opts as ArrayValidationOptions).maxItems}`,
            actual: `length = ${value.length}`,
                      });
        }

        // Unique items validation
        if ((opts as ArrayValidationOptions).uniqueItems) {
          const uniqueValues = new Set(value);
          if (uniqueValues.size !== value.length) {
            errors.push({
              code: 'DUPLICATE_ITEMS',
              message: opts?.error || 'Array items must be unique',
              path: context.path,
              value,
              expected: 'unique items',
              actual: `${value.length} items with ${uniqueValues.size} unique values`,
                          });
          }
        }

        // Item type validation - skip for now as it needs proper type handling
        // This would require more complex type system integration

        // Contains validation - skip for now as it needs proper type handling
        // This would require more complex type system integration

        return {
          success: errors.length === 0,
          value: errors.length === 0 ? value : undefined,
          errors,
          warnings,
                    context
        };
      },
    }),
    options
  );
}

/**
 * Object validation decorator
 */
export function IsObject(options: ObjectValidationOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'object',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): ValidationResult => {
        const errors: ValidationError[] = [];
        const warnings: ValidationWarning[] = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              code: 'REQUIRED',
              message: opts?.error || 'Object value is required',
              path: context.path,
              value,
              expected: 'object',
              actual: typeof value,
                          });
          }
          return { success: errors.length === 0, value: undefined, errors, warnings, suggestions: [], context };
        }

        if (typeof value !== 'object' || Array.isArray(value)) {
          errors.push({
            code: 'INVALID_TYPE',
            message: opts?.error || 'Value must be an object',
            path: context.path,
            value,
            expected: 'object',
            actual: typeof value,
                      });
          return { success: false, value: undefined, errors, warnings, suggestions: [], context };
        }

        const obj = value as Record<string, unknown>;

        // Property count validations
        const propertyCount = Object.keys(obj).length;
        if ((opts as ObjectValidationOptions).minProperties !== undefined && propertyCount < (opts as ObjectValidationOptions).minProperties) {
          errors.push({
            code: 'MIN_PROPERTIES',
            message: opts?.error || `Object must have at least ${(opts as ObjectValidationOptions).minProperties} properties`,
            path: context.path,
            value,
            expected: `properties >= ${(opts as ObjectValidationOptions).minProperties}`,
            actual: `properties = ${propertyCount}`,
                      });
        }

        if ((opts as ObjectValidationOptions).maxProperties !== undefined && propertyCount > (opts as ObjectValidationOptions).maxProperties) {
          errors.push({
            code: 'MAX_PROPERTIES',
            message: opts?.error || `Object must have at most ${(opts as ObjectValidationOptions).maxProperties} properties`,
            path: context.path,
            value,
            expected: `properties <= ${(opts as ObjectValidationOptions).maxProperties}`,
            actual: `properties = ${propertyCount}`,
                      });
        }

        // Property names validation - skip for now as it needs proper type handling
        // Additional properties validation - skip for now as it needs proper type handling

        return {
          success: errors.length === 0,
          value: errors.length === 0 ? value : undefined,
          errors,
          warnings,
                    context
        };
      },
    }),
    options
  );
}

/**
 * Enum validation decorator
 */
export function IsEnum<T extends Record<string, unknown>>(
  enumObj: T,
  options: ValidationDecoratorOptions = {}
) {
  const enumValues = Object.values(enumObj);

  return createValidationDecorator(
    (opts) => ({
      name: 'enum',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): DecoratorValidationResult => {
        const errors: Array<{ path: string; error: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              error: opts?.error || 'Enum value is required',
              code: 'REQUIRED',
              value,
            });
          }
          return { success: errors.length === 0, errors };
        }

        if (!enumValues.includes(value)) {
          errors.push({
            path: context.path,
            error: opts?.error || `Value must be one of: ${enumValues.join(', ')}`,
            code: 'INVALID_ENUM',
            value,
          });
        }

        return { success: errors.length === 0, errors };
      },
    }),
    options
  );
}

/**
 * Custom validation decorator
 */
export function Validate(
  validator: CustomValidatorFunction,
  options: ValidationDecoratorOptions = {}
) {
  return createValidationDecorator(
    (opts) => ({
      name: 'custom',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContextCompat): DecoratorValidationResult => {
        if (value === null || (value === undefined && !opts.required)) {
          return { success: true as unknown, errors: [] };
        }

        const result = validator(value, context);

        if (typeof result === 'boolean') {
          return {
            success: result,
            errors: result
              ? []
              : [
                  {
                    path: context.path,
                    error: opts?.error || 'Custom validation failed',
                    code: 'CUSTOM_VALIDATION',
                    value,
                  },
                ],
          };
        }

        return result;
      },
    }),
    options
  );
}

/**
 * Class validation decorator
 */
export function ValidateClass(options: ClassValidationMetadata = {}) {
  return function <T extends { new (...args: any[]): object }>(constructor: T) {
    const metadata: ClassValidationMetadata = {
      className: constructor.name,
      validateOnConstruction: true,
      validateOnUpdate: true,
      strictMode: false,
      stopOnFirstError: false,
      groups: [],
      ...options,
    };

    Reflect.defineMetadata(CLASS_VALIDATION_KEY, metadata, constructor);

    return class extends constructor {
      constructor(...args: any[]) {
        super(...args);

        if (metadata.validateOnConstruction) {
          const validationResult = this.validate();
          if (!validationResult.success) {
            const errorMessages = validationResult?.errors.map((e) => e?.error).join(', ');
            throw new Error(`Validation failed for ${constructor.name}: ${errorMessages}`);
          }
        }
      }

      /**
       * Validate all decorated properties
       */
      validate(groups: string[] = []): DecoratorValidationResult {
        const typeDebugger = TypeDebugger.getInstance();
        const errors: Array<{ path: string; error: string; code: string; value?: unknown }> = [];

        // Get all property validation rules
        const propertyRules = Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];

        for (const { propertyName, rule, options: propOptions } of propertyRules) {
          // Skip if group is specified and not in requested groups
          if (propOptions.groups && propOptions.groups.length > 0) {
            if (!propOptions.groups.some((group) => groups.includes(group))) {
              continue;
            }
          }

          // Skip on update if specified
          if (propOptions.skipOnUpdate) {
            continue;
          }

          const value = (this as unknown)[propertyName];
          const result = rule.validate(value, {
            path: propertyName,
            property: propertyName,
            root: this,
            parent: this,
          });

          if (!result.success) {
            errors.push(...result?.errors);

            if (metadata.stopOnFirstError) {
              break;
            }
          }
        }

        // Log validation errors to debugger
        if (errors.length > 0) {
          typeDebugger.logIssue({
            level: 'error' as unknown,
            category: 'validation' as unknown,
            title: 'Class Validation Failed',
            description: `Validation failed for ${constructor.name}`,
            context: {
              className: constructor.name,
              errors,
              groups,
            },
          });
        }

        return { success: errors.length === 0, errors };
      }

      /**
       * Validate specific property
       */
      validateProperty(propertyName: string, groups: string[] = []): DecoratorValidationResult {
        const propertyRules = Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];
        const propertyRule = propertyRules.find(
          (rule: unknown) => rule.propertyName === propertyName
        );

        if (!propertyRule) {
          return { success: true as unknown, errors: [] };
        }

        const value = (this as unknown)[propertyName];
        const result = propertyRule.rule.validate(value, {
          path: propertyName,
          property: propertyName,
          root: this,
          parent: this,
        });

        return result;
      }

      /**
       * Get validation rules for debugging
       */
      getValidationRules(): PropertyValidationMetadata[] {
        return Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];
      }

      /**
       * Legacy method for backward compatibility
       */
      getanys(): PropertyValidationMetadata[] {
        return this.getValidationRules();
      }
    };
  };
}

/**
 * Configuration class base with built-in validation
 */
export class ValidatedConfig {
  /**
   * Validate all decorated properties
   */
  validate(groups: string[] = []): DecoratorValidationResult {
    // Default implementation - should be overridden by decorator
    return { success: true, errors: [] };
  }

  /**
   * Validate specific property
   */
  validateProperty(propertyName: string, groups: string[] = []): DecoratorValidationResult {
    // Default implementation - should be overridden by decorator
    return { success: true, errors: [] };
  }

  /**
   * Get validation rules for debugging
   */
  getValidationRules(): PropertyValidationMetadata[] {
    // Default implementation - get from reflection metadata
    return Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];
  }

  /**
   * Legacy method for backward compatibility
   */
  getanys(): PropertyValidationMetadata[] {
    return this.getValidationRules();
  }

  /**
   * Validate and get configuration as plain object
   */
  toPlainObject<T = Record<string, unknown>>(): T {
    const validationResult = this.validate();
    if (!validationResult.success) {
      const errorMessages = validationResult?.errors.map((e) => e?.error).join(', ');
      throw new Error(`Cannot export invalid configuration: ${errorMessages}`);
    }

    const result: Record<string, unknown> = {};
    const rules = this.getValidationRules();

    for (const { propertyName } of rules) {
      if ((this as unknown)[propertyName] !== undefined) {
        result[propertyName] = (this as unknown)[propertyName];
      }
    }

    return result as T;
  }

  /**
   * Load configuration from object
   */
  static fromObject<T extends ValidatedConfig>(this: new () => T, obj: Record<string, unknown>): T {
    const instance = new this();
    const rules = instance.getValidationRules();

    for (const { propertyName, options } of rules) {
      if (obj[propertyName] !== undefined) {
        (instance as unknown)[propertyName] = obj[propertyName];
      } else if (options.default !== undefined) {
        (instance as unknown)[propertyName] = options.default;
      }
    }

    return instance;
  }

  /**
   * Validate configuration object without creating instance
   */
  static validateObject(
    obj: Record<string, unknown>,
    rules: PropertyValidationMetadata[]
  ): DecoratorValidationResult {
    const errors: Array<{ path: string; error: string; code: string; value?: unknown }> = [];

    for (const { propertyName, rule, options } of rules) {
      const value = obj[propertyName];

      // Apply default if value is missing and default is provided
      const valueToValidate = value === undefined ? options.default : value;

      const result = rule.validate(valueToValidate, {
        path: propertyName,
        property: propertyName,
        root: obj,
        parent: obj,
      });

      if (!result.success) {
        errors.push(...result?.errors);
      }
    }

    return { success: errors.length === 0, errors };
  }
}

/**
 * Utility functions for decorator usage
 */

/**
 * Extract validation rules from a class
 */
export function extractanys(target: unknown): PropertyValidationMetadata[] {
  // For backward compatibility
  if (typeof target.getValidationRules === 'function') {
    return target.getValidationRules();
  }
  return Reflect.getMetadata(VALIDATION_RULES_KEY, target) || [];
}

/**
 * Extract class validation metadata
 */
export function extractClassValidationMetadata(
  target: unknown
): ClassValidationMetadata | undefined {
  return Reflect.getMetadata(CLASS_VALIDATION_KEY, target);
}

/**
 * Validate object using class decorators
 */
export function validateObjectUsingClass<T>(
  obj: Record<string, unknown>,
  classConstructor: new () => T
): DecoratorValidationResult {
  const tempInstance = new classConstructor();
  const rules = extractanys(tempInstance);
  return ValidatedConfig.validateObject(obj, rules);
}

/**
 * Configuration validation schema builder using decorators
 */
export class ConfigSchemaBuilder {
  private rules: Map<string, unknown> = new Map();

  string(name: string, options: StringValidationOptions = {}): this {
    this.rules.set(name, {
      name: 'string',
      required: options.required || false,
      default: options.default,
      validate: (value: unknown, context: ValidationContextCompat): DecoratorValidationResult => {
        // Implementation similar to IsString decorator
        const errors: Array<{ path: string; error: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (options.required) {
            errors.push({
              path: context.path,
              error: options?.error || 'String value is required',
              code: 'REQUIRED',
              value,
            });
          }
          return { success: errors.length === 0, errors };
        }

        const stringValue = String(value);
        if (typeof stringValue !== 'string') {
          errors.push({
            path: context.path,
            error: options?.error || 'Value must be a string',
            code: 'INVALID_TYPE',
            value: stringValue,
          });
        }

        if (options.minLength !== undefined && stringValue.length < options.minLength) {
          errors.push({
            path: context.path,
            error: options?.error || `String must be at least ${options.minLength} characters long`,
            code: 'MIN_LENGTH',
            value: stringValue,
          });
        }

        if (options.maxLength !== undefined && stringValue.length > options.maxLength) {
          errors.push({
            path: context.path,
            error: options?.error || `String must be at most ${options.maxLength} characters long`,
            code: 'MAX_LENGTH',
            value: stringValue,
          });
        }

        return { success: errors.length === 0, errors };
      },
    });
    return this;
  }

  number(name: string, options: NumberValidationOptions = {}): this {
    this.rules.set(name, {
      name: 'number',
      required: options.required || false,
      default: options.default,
      validate: (value: unknown, context: ValidationContextCompat): DecoratorValidationResult => {
        // Implementation similar to IsNumber decorator
        const errors: Array<{ path: string; error: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (options.required) {
            errors.push({
              path: context.path,
              error: options?.error || 'Number value is required',
              code: 'REQUIRED',
              value,
            });
          }
          return { success: errors.length === 0, errors };
        }

        const numValue = Number(value);
        if (typeof numValue !== 'number' || isNaN(numValue)) {
          errors.push({
            path: context.path,
            error: options?.error || 'Value must be a valid number',
            code: 'INVALID_TYPE',
            value,
          });
          return { success: false, errors };
        }

        if (options.min !== undefined && numValue < options.min) {
          errors.push({
            path: context.path,
            error: options?.error || `Number must be at least ${options.min}`,
            code: 'MIN_VALUE',
            value: numValue,
          });
        }

        if (options.max !== undefined && numValue > options.max) {
          errors.push({
            path: context.path,
            error: options?.error || `Number must be at most ${options.max}`,
            code: 'MAX_VALUE',
            value: numValue,
          });
        }

        return { success: errors.length === 0, errors };
      },
    });
    return this;
  }

  build(): Record<string, unknown> {
    return Object.fromEntries(this.rules);
  }
}
