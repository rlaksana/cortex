/**
 * Configuration Validation Decorators
 *
 * TypeScript decorators for automatic configuration validation,
 * property validation, and class-level validation rules.
 */

import { ConfigKey } from './branded-types';
import { type ValidationContext, type ValidationResult,type ValidationRule } from './runtime-type-guard-framework';
import { TypeDebugger } from './type-debug-helpers';

import 'reflect-metadata';

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
  message?: string;
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
  itemsType?: ValidationRule;
  contains?: ValidationRule;
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
  propertyNames?: ValidationRule;
  additionalProperties?: ValidationRule;
}

/**
 * Custom validation function
 */
export type CustomValidatorFunction = (value: unknown, context?: ValidationContext) => boolean | ValidationResult;

/**
 * Class validation metadata
 */
export interface ClassValidationMetadata {
  className: string;
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
  rules: ValidationRule[];
  options: ValidationDecoratorOptions;
}

/**
 * Base validation decorator factory
 */
function createValidationDecorator(
  ruleFactory: (options: unknown) => ValidationRule,
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
        options: validationOptions
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const isValid = value !== null && value !== undefined && value !== '';
        return {
          isValid,
          errors: isValid ? [] : [{
            path: context.path,
            message: opts.message || `Property is required`,
            code: 'REQUIRED',
            value
          }]
        };
      }
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        return { isValid: true, errors: [] };
      }
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        // Check if value is string or should be skipped
        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              message: opts.message || 'String value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        // Transform value if needed
        let stringValue = String(value);
        if (opts.trim) stringValue = stringValue.trim();
        if (opts.normalize) stringValue = stringValue.normalize();

        // Type check
        if (typeof stringValue !== 'string') {
          errors.push({
            path: context.path,
            message: opts.message || 'Value must be a string',
            code: 'INVALID_TYPE',
            value: stringValue
          });
        }

        // Length validations
        if (opts.minLength !== undefined && stringValue.length < opts.minLength) {
          errors.push({
            path: context.path,
            message: opts.message || `String must be at least ${opts.minLength} characters long`,
            code: 'MIN_LENGTH',
            value: stringValue
          });
        }

        if (opts.maxLength !== undefined && stringValue.length > opts.maxLength) {
          errors.push({
            path: context.path,
            message: opts.message || `String must be at most ${opts.maxLength} characters long`,
            code: 'MAX_LENGTH',
            value: stringValue
          });
        }

        // Pattern validation
        if (opts.pattern && !opts.pattern.test(stringValue)) {
          errors.push({
            path: context.path,
            message: opts.message || 'String does not match required pattern',
            code: 'PATTERN_MISMATCH',
            value: stringValue
          });
        }

        // Email validation
        if (opts.email) {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(stringValue)) {
            errors.push({
              path: context.path,
              message: opts.message || 'Invalid email format',
              code: 'INVALID_EMAIL',
              value: stringValue
            });
          }
        }

        // URL validation
        if (opts.url) {
          try {
            new URL(stringValue);
          } catch {
            errors.push({
              path: context.path,
              message: opts.message || 'Invalid URL format',
              code: 'INVALID_URL',
              value: stringValue
            });
          }
        }

        // UUID validation
        if (opts.uuid) {
          const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
          if (!uuidRegex.test(stringValue)) {
            errors.push({
              path: context.path,
              message: opts.message || 'Invalid UUID format',
              code: 'INVALID_UUID',
              value: stringValue
            });
          }
        }

        return { isValid: errors.length === 0, errors };
      }
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        // Check if value should be skipped
        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              message: opts.message || 'Number value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        // Convert to number
        const numValue = Number(value);

        // Type check
        if (typeof numValue !== 'number' || isNaN(numValue)) {
          errors.push({
            path: context.path,
            message: opts.message || 'Value must be a valid number',
            code: 'INVALID_TYPE',
            value
          });
          return { isValid: false, errors };
        }

        // Finite check
        if (opts.finite !== false && !isFinite(numValue)) {
          errors.push({
            path: context.path,
            message: opts.message || 'Number must be finite',
            code: 'NOT_FINITE',
            value: numValue
          });
        }

        // Integer check
        if (opts.integer && !Number.isInteger(numValue)) {
          errors.push({
            path: context.path,
            message: opts.message || 'Number must be an integer',
            code: 'NOT_INTEGER',
            value: numValue
          });
        }

        // Positive/negative checks
        if (opts.positive && numValue <= 0) {
          errors.push({
            path: context.path,
            message: opts.message || 'Number must be positive',
            code: 'NOT_POSITIVE',
            value: numValue
          });
        }

        if (opts.negative && numValue >= 0) {
          errors.push({
            path: context.path,
            message: opts.message || 'Number must be negative',
            code: 'NOT_NEGATIVE',
            value: numValue
          });
        }

        // Range checks
        if (opts.min !== undefined && numValue < opts.min) {
          errors.push({
            path: context.path,
            message: opts.message || `Number must be at least ${opts.min}`,
            code: 'MIN_VALUE',
            value: numValue
          });
        }

        if (opts.max !== undefined && numValue > opts.max) {
          errors.push({
            path: context.path,
            message: opts.message || `Number must be at most ${opts.max}`,
            code: 'MAX_VALUE',
            value: numValue
          });
        }

        // Step validation
        if (opts.step !== undefined) {
          const remainder = numValue % opts.step;
          if (Math.abs(remainder) > Number.EPSILON) {
            errors.push({
              path: context.path,
              message: opts.message || `Number must be a multiple of ${opts.step}`,
              code: 'INVALID_STEP',
              value: numValue
            });
          }
        }

        return { isValid: errors.length === 0, errors };
      }
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              message: opts.message || 'Boolean value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        if (typeof value !== 'boolean') {
          errors.push({
            path: context.path,
            message: opts.message || 'Value must be a boolean',
            code: 'INVALID_TYPE',
            value
          });
        }

        return { isValid: errors.length === 0, errors };
      }
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              message: opts.message || 'Array value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        if (!Array.isArray(value)) {
          errors.push({
            path: context.path,
            message: opts.message || 'Value must be an array',
            code: 'INVALID_TYPE',
            value
          });
          return { isValid: false, errors };
        }

        // Length validations
        if (opts.minItems !== undefined && value.length < opts.minItems) {
          errors.push({
            path: context.path,
            message: opts.message || `Array must have at least ${opts.minItems} items`,
            code: 'MIN_ITEMS',
            value
          });
        }

        if (opts.maxItems !== undefined && value.length > opts.maxItems) {
          errors.push({
            path: context.path,
            message: opts.message || `Array must have at most ${opts.maxItems} items`,
            code: 'MAX_ITEMS',
            value
          });
        }

        // Unique items validation
        if (opts.uniqueItems) {
          const uniqueValues = new Set(value);
          if (uniqueValues.size !== value.length) {
            errors.push({
              path: context.path,
              message: opts.message || 'Array items must be unique',
              code: 'DUPLICATE_ITEMS',
              value
            });
          }
        }

        // Item type validation
        if (opts.itemsType) {
          for (let i = 0; i < value.length; i++) {
            const itemResult = opts.itemsType.validate(value[i], {
              ...context,
              path: `${context.path}[${i}]`
            });
            if (!itemResult.isValid) {
              errors.push(...itemResult.errors);
            }
          }
        }

        // Contains validation
        if (opts.contains) {
          const hasValidItem = value.some(item => {
            const result = opts.contains!.validate(item, context);
            return result.isValid;
          });
          if (!hasValidItem) {
            errors.push({
              path: context.path,
              message: opts.message || 'Array must contain at least one item matching the required condition',
              code: 'CONTAINS_VALIDATION',
              value
            });
          }
        }

        return { isValid: errors.length === 0, errors };
      }
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
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              message: opts.message || 'Object value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        if (typeof value !== 'object' || Array.isArray(value)) {
          errors.push({
            path: context.path,
            message: opts.message || 'Value must be an object',
            code: 'INVALID_TYPE',
            value
          });
          return { isValid: false, errors };
        }

        const obj = value as Record<string, unknown>;

        // Property count validations
        const propertyCount = Object.keys(obj).length;
        if (opts.minProperties !== undefined && propertyCount < opts.minProperties) {
          errors.push({
            path: context.path,
            message: opts.message || `Object must have at least ${opts.minProperties} properties`,
            code: 'MIN_PROPERTIES',
            value
          });
        }

        if (opts.maxProperties !== undefined && propertyCount > opts.maxProperties) {
          errors.push({
            path: context.path,
            message: opts.message || `Object must have at most ${opts.maxProperties} properties`,
            code: 'MAX_PROPERTIES',
            value
          });
        }

        // Property names validation
        if (opts.propertyNames) {
          for (const propertyName of Object.keys(obj)) {
            const nameResult = opts.propertyNames.validate(propertyName, context);
            if (!nameResult.isValid) {
              errors.push(...nameResult.errors);
            }
          }
        }

        // Additional properties validation
        if (opts.additionalProperties) {
          // This would need the schema to know which properties are allowed
          // For now, we'll just validate all properties
          for (const [propertyName, propertyValue] of Object.entries(obj)) {
            const result = opts.additionalProperties.validate(propertyValue, {
              ...context,
              path: `${context.path}.${propertyName}`
            });
            if (!result.isValid) {
              errors.push(...result.errors);
            }
          }
        }

        return { isValid: errors.length === 0, errors };
      }
    }),
    options
  );
}

/**
 * Enum validation decorator
 */
export function IsEnum<T extends Record<string, unknown>>(enumObj: T, options: ValidationDecoratorOptions = {}) {
  const enumValues = Object.values(enumObj);

  return createValidationDecorator(
    (opts) => ({
      name: 'enum',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (opts.required) {
            errors.push({
              path: context.path,
              message: opts.message || 'Enum value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        if (!enumValues.includes(value)) {
          errors.push({
            path: context.path,
            message: opts.message || `Value must be one of: ${enumValues.join(', ')}`,
            code: 'INVALID_ENUM',
            value
          });
        }

        return { isValid: errors.length === 0, errors };
      }
    }),
    options
  );
}

/**
 * Custom validation decorator
 */
export function Validate(validator: CustomValidatorFunction, options: ValidationDecoratorOptions = {}) {
  return createValidationDecorator(
    (opts) => ({
      name: 'custom',
      required: opts.required || false,
      default: opts.default,
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        if (value === null || value === undefined && !opts.required) {
          return { isValid: true, errors: [] };
        }

        const result = validator(value, context);

        if (typeof result === 'boolean') {
          return {
            isValid: result,
            errors: result ? [] : [{
              path: context.path,
              message: opts.message || 'Custom validation failed',
              code: 'CUSTOM_VALIDATION',
              value
            }]
          };
        }

        return result;
      }
    }),
    options
  );
}

/**
 * Class validation decorator
 */
export function ValidateClass(options: ClassValidationMetadata = {}) {
  return function <T extends { new(...args: any[]): object }>(constructor: T) {
    const metadata: ClassValidationMetadata = {
      className: constructor.name,
      validateOnConstruction: true,
      validateOnUpdate: true,
      strictMode: false,
      stopOnFirstError: false,
      ...options
    };

    Reflect.defineMetadata(CLASS_VALIDATION_KEY, metadata, constructor);

    return class extends constructor {
      constructor(...args: any[]) {
        super(...args);

        if (metadata.validateOnConstruction) {
          const validationResult = this.validate();
          if (!validationResult.isValid) {
            const errorMessages = validationResult.errors.map(e => e.message).join(', ');
            throw new Error(`Validation failed for ${constructor.name}: ${errorMessages}`);
          }
        }
      }

      /**
       * Validate all decorated properties
       */
      validate(groups: string[] = []): ValidationResult {
        const typeDebugger = TypeDebugger.getInstance();
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        // Get all property validation rules
        const propertyRules = Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];

        for (const { propertyName, rule, options: propOptions } of propertyRules) {
          // Skip if group is specified and not in requested groups
          if (propOptions.groups && propOptions.groups.length > 0) {
            if (!propOptions.groups.some(group => groups.includes(group))) {
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
            parent: this
          });

          if (!result.isValid) {
            errors.push(...result.errors);

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
              groups
            }
          });
        }

        return { isValid: errors.length === 0, errors };
      }

      /**
       * Validate specific property
       */
      validateProperty(propertyName: string, groups: string[] = []): ValidationResult {
        const propertyRules = Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];
        const propertyRule = propertyRules.find((rule: unknown) => rule.propertyName === propertyName);

        if (!propertyRule) {
          return { isValid: true, errors: [] };
        }

        const value = (this as unknown)[propertyName];
        const result = propertyRule.rule.validate(value, {
          path: propertyName,
          property: propertyName,
          root: this,
          parent: this
        });

        return result;
      }

      /**
       * Get validation rules for debugging
       */
      getValidationRules(): PropertyValidationMetadata[] {
        return Reflect.getMetadata(VALIDATION_RULES_KEY, this) || [];
      }
    };
  };
}

/**
 * Configuration class base with built-in validation
 */
@ValidateClass()
export abstract class ValidatedConfig {
  /**
   * Validate and get configuration as plain object
   */
  toPlainObject<T = Record<string, unknown>>(): T {
    const validationResult = this.validate();
    if (!validationResult.isValid) {
      const errorMessages = validationResult.errors.map(e => e.message).join(', ');
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
  static fromObject<T extends ValidatedConfig>(
    this: new () => T,
    obj: Record<string, unknown>
  ): T {
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
  ): ValidationResult {
    const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

    for (const { propertyName, rule, options } of rules) {
      const value = obj[propertyName];

      // Apply default if value is missing and default is provided
      const valueToValidate = value === undefined ? options.default : value;

      const result = rule.validate(valueToValidate, {
        path: propertyName,
        property: propertyName,
        root: obj,
        parent: obj
      });

      if (!result.isValid) {
        errors.push(...result.errors);
      }
    }

    return { isValid: errors.length === 0, errors };
  }
}

/**
 * Utility functions for decorator usage
 */

/**
 * Extract validation rules from a class
 */
export function extractValidationRules(target: unknown): PropertyValidationMetadata[] {
  return Reflect.getMetadata(VALIDATION_RULES_KEY, target) || [];
}

/**
 * Extract class validation metadata
 */
export function extractClassValidationMetadata(target: unknown): ClassValidationMetadata | undefined {
  return Reflect.getMetadata(CLASS_VALIDATION_KEY, target);
}

/**
 * Validate object using class decorators
 */
export function validateObjectUsingClass<T>(
  obj: Record<string, unknown>,
  classConstructor: new () => T
): ValidationResult {
  const tempInstance = new classConstructor();
  const rules = extractValidationRules(tempInstance);
  return ValidatedConfig.validateObject(obj, rules);
}

/**
 * Configuration validation schema builder using decorators
 */
export class ConfigSchemaBuilder {
  private rules: Map<string, ValidationRule> = new Map();

  string(name: string, options: StringValidationOptions = {}): this {
    this.rules.set(name, {
      name: 'string',
      required: options.required || false,
      default: options.default,
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        // Implementation similar to IsString decorator
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (options.required) {
            errors.push({
              path: context.path,
              message: options.message || 'String value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        const stringValue = String(value);
        if (typeof stringValue !== 'string') {
          errors.push({
            path: context.path,
            message: options.message || 'Value must be a string',
            code: 'INVALID_TYPE',
            value: stringValue
          });
        }

        if (options.minLength !== undefined && stringValue.length < options.minLength) {
          errors.push({
            path: context.path,
            message: options.message || `String must be at least ${options.minLength} characters long`,
            code: 'MIN_LENGTH',
            value: stringValue
          });
        }

        if (options.maxLength !== undefined && stringValue.length > options.maxLength) {
          errors.push({
            path: context.path,
            message: options.message || `String must be at most ${options.maxLength} characters long`,
            code: 'MAX_LENGTH',
            value: stringValue
          });
        }

        return { isValid: errors.length === 0, errors };
      }
    });
    return this;
  }

  number(name: string, options: NumberValidationOptions = {}): this {
    this.rules.set(name, {
      name: 'number',
      required: options.required || false,
      default: options.default,
      validate: (value: unknown, context: ValidationContext): ValidationResult => {
        // Implementation similar to IsNumber decorator
        const errors: Array<{ path: string; message: string; code: string; value?: unknown }> = [];

        if (value === null || value === undefined) {
          if (options.required) {
            errors.push({
              path: context.path,
              message: options.message || 'Number value is required',
              code: 'REQUIRED',
              value
            });
          }
          return { isValid: errors.length === 0, errors };
        }

        const numValue = Number(value);
        if (typeof numValue !== 'number' || isNaN(numValue)) {
          errors.push({
            path: context.path,
            message: options.message || 'Value must be a valid number',
            code: 'INVALID_TYPE',
            value
          });
          return { isValid: false, errors };
        }

        if (options.min !== undefined && numValue < options.min) {
          errors.push({
            path: context.path,
            message: options.message || `Number must be at least ${options.min}`,
            code: 'MIN_VALUE',
            value: numValue
          });
        }

        if (options.max !== undefined && numValue > options.max) {
          errors.push({
            path: context.path,
            message: options.message || `Number must be at most ${options.max}`,
            code: 'MAX_VALUE',
            value: numValue
          });
        }

        return { isValid: errors.length === 0, errors };
      }
    });
    return this;
  }

  build(): Record<string, ValidationRule> {
    return Object.fromEntries(this.rules);
  }
}