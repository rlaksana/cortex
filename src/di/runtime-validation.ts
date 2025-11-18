// EMERGENCY ROLLBACK: Final batch of type compatibility issues

/**
 * Runtime Type Validation System for DI Container
 *
 * Provides comprehensive runtime validation for service registration,
 * dependency resolution, and type checking to ensure type safety at runtime.
 */

import type { ValidationResult } from '../factories/factory-types';

// Runtime type validation interfaces
export interface RuntimeValidator<T = unknown> {
  validate(value: unknown): value is T;
  getExpectedType(): string;
  getErrorMessage(value: unknown): string;
}

export interface ServiceTypeDescriptor {
  readonly name: string;
  readonly validator: RuntimeValidator;
  readonly dependencies: ReadonlyArray<string>;
  readonly optionalDependencies: ReadonlyArray<string>;
}

export interface ResolutionContext {
  readonly path: ReadonlyArray<string>;
  readonly scope?: string;
  readonly depth: number;
  readonly maxDepth: number;
}

export interface ServiceResolutionPlan {
  readonly serviceId: string;
  readonly dependencies: ReadonlyArray<ServiceResolutionPlan>;
  readonly circular: boolean;
  readonly estimatedCost: number;
}

export interface ValidationCache {
  readonly valid: boolean;
  readonly timestamp: number;
  readonly ttl: number;
}

// Type validator implementations
export class PrimitiveValidator<T> implements RuntimeValidator<T> {
  constructor(
    private readonly expectedType:
      | 'string'
      | 'number'
      | 'boolean'
      | 'object'
      | 'function'
      | 'symbol'
      | 'undefined',
    private readonly typeName: string
  ) {}

  validate(value: unknown): value is T {
    return typeof value === this.expectedType;
  }

  getExpectedType(): string {
    return this.typeName;
  }

  getErrorMessage(value: unknown): string {
    return `Expected ${this.typeName}, got ${typeof value}`;
  }
}

export class InstanceValidator<T> implements RuntimeValidator<T> {
  constructor(
    private readonly expectedClass: new (...args: any[]) => T,
    private readonly className: string
  ) {}

  validate(value: unknown): value is T {
    return value instanceof this.expectedClass;
  }

  getExpectedType(): string {
    return this.className;
  }

  getErrorMessage(value: unknown): string {
    return `Expected instance of ${this.className}, got ${typeof value}`;
  }
}

export class UnionValidator<T> implements RuntimeValidator<T> {
  constructor(private readonly validators: RuntimeValidator[]) {}

  validate(value: unknown): value is T {
    return this.validators.some((validator) => validator.validate(value));
  }

  getExpectedType(): string {
    return this.validators.map((v) => v.getExpectedType()).join(' | ');
  }

  getErrorMessage(value: unknown): string {
    const errors = this.validators.map((v) => v.getErrorMessage(value));
    return `Expected one of: ${errors.join(', ')}`;
  }
}

export class ArrayValidator<T> implements RuntimeValidator<T[]> {
  constructor(private readonly itemValidator: RuntimeValidator<T>) {}

  validate(value: unknown): value is T[] {
    if (!Array.isArray(value)) return false;
    return value.every((item) => this.itemValidator.validate(item));
  }

  getExpectedType(): string {
    return `${this.itemValidator.getExpectedType()}[]`;
  }

  getErrorMessage(value: unknown): string {
    if (!Array.isArray(value)) {
      return `Expected array, got ${typeof value}`;
    }
    return `Array contains invalid items: ${this.itemValidator.getExpectedType()}`;
  }
}

export class RecordValidator<T> implements RuntimeValidator<Record<string, T>> {
  constructor(private readonly valueValidator: RuntimeValidator<T>) {}

  validate(value: unknown): value is Record<string, T> {
    if (typeof value !== 'object' || value === null) return false;

    const record = value as Record<string, unknown>;
    return Object.values(record).every((v) => this.valueValidator.validate(v));
  }

  getExpectedType(): string {
    return `Record<string, ${this.valueValidator.getExpectedType()}>`;
  }

  getErrorMessage(value: unknown): string {
    if (typeof value !== 'object' || value === null) {
      return `Expected object, got ${typeof value}`;
    }
    return `Record contains invalid values: ${this.valueValidator.getExpectedType()}`;
  }
}

export class OptionalValidator<T> implements RuntimeValidator<T | undefined> {
  constructor(private readonly baseValidator: RuntimeValidator<T>) {}

  validate(value: unknown): value is T | undefined {
    return value === undefined || this.baseValidator.validate(value);
  }

  getExpectedType(): string {
    return `${this.baseValidator.getExpectedType()} | undefined`;
  }

  getErrorMessage(value: unknown): string {
    if (value === undefined) return ''; // undefined is always valid
    return this.baseValidator.getErrorMessage(value);
  }
}

// Service registry with runtime validation
export class ValidatedServiceRegistry {
  private serviceDescriptors = new Map<string | symbol, ServiceTypeDescriptor>();
  private validationCache = new Map<string, ValidationCache>();
  private readonly cacheTimeout = 30000; // 30 seconds

  registerService<T>(token: string | symbol, descriptor: ServiceTypeDescriptor): void {
    this.serviceDescriptors.set(token, descriptor);
    this.clearValidationCache(token);
  }

  unregisterService(token: string | symbol): void {
    this.serviceDescriptors.delete(token);
    this.clearValidationCache(token);
  }

  validateService<T>(token: string | symbol, instance: unknown): ValidationResult {
    const descriptor = this.serviceDescriptors.get(token);
    if (!descriptor) {
      return {
        valid: false,
        errors: [`Service ${String(token)} is not registered`],
      };
    }

    // Check cache first
    const cacheKey = `${String(token)}_${typeof instance}`;
    const cached = this.validationCache.get(cacheKey);
    if (cached && this.isCacheValid(cached)) {
      return {
        valid: cached.valid,
        errors: cached.valid ? [] : ['Cached validation failed'],
      };
    }

    const result = this.validateInstance(descriptor, instance);

    // Update cache
    this.validationCache.set(cacheKey, {
      valid: result.valid,
      timestamp: Date.now(),
      ttl: this.cacheTimeout,
    });

    return result;
  }

  private validateInstance(descriptor: ServiceTypeDescriptor, instance: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!descriptor.validator.validate(instance)) {
      errors.push(descriptor.validator.getErrorMessage(instance));
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  private isCacheValid(cache: ValidationCache): boolean {
    return Date.now() - cache.timestamp < cache.ttl;
  }

  private clearValidationCache(token?: string | symbol): void {
    if (token) {
      // Clear specific token entries
      for (const [key] of this.validationCache) {
        if (key.startsWith(String(token))) {
          this.validationCache.delete(key);
        }
      }
    } else {
      // Clear all cache
      this.validationCache.clear();
    }
  }

  getServiceDescriptor(token: string | symbol): ServiceTypeDescriptor | undefined {
    return this.serviceDescriptors.get(token);
  }

  getAllServices(): ReadonlyMap<string | symbol, ServiceTypeDescriptor> {
    return new Map(this.serviceDescriptors);
  }
}

// Dependency resolution validator
export class DependencyResolutionValidator {
  constructor(private readonly serviceRegistry: ValidatedServiceRegistry) {}

  validateResolutionPlan(serviceId: string | symbol, context: ResolutionContext): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check depth
    if (context.depth > context.maxDepth) {
      errors.push(`Maximum resolution depth exceeded: ${context.depth} > ${context.maxDepth}`);
    }

    // Check for circular dependencies
    if (context.path.length > 1) {
      const serviceIndex = context.path.indexOf(String(serviceId));
      if (serviceIndex !== -1) {
        const cycle = context.path.slice(serviceIndex).concat(String(serviceId));
        errors.push(`Circular dependency detected: ${cycle.join(' -> ')}`);
      }
    }

    // Check if service exists
    const descriptor = this.serviceRegistry.getServiceDescriptor(serviceId);
    if (!descriptor) {
      errors.push(`Service ${String(serviceId)} is not registered`);
      return { valid: false, errors, warnings };
    }

    // Validate dependencies
    for (const depId of descriptor.dependencies) {
      const depContext: ResolutionContext = {
        ...context,
        path: [...context.path, String(serviceId)],
        depth: context.depth + 1,
      };

      const depResult = this.validateResolutionPlan(depId, depContext);
      errors.push(...depResult.errors);
      warnings.push(...depResult.warnings);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  createResolutionPlan(
    serviceId: string | symbol,
    visited = new Set<string | symbol>()
  ): ServiceResolutionPlan {
    if (visited.has(serviceId)) {
      return {
        serviceId: String(serviceId),
        dependencies: [],
        circular: true,
        estimatedCost: 0,
      };
    }

    visited.add(serviceId);
    const descriptor = this.serviceRegistry.getServiceDescriptor(serviceId);

    if (!descriptor) {
      visited.delete(serviceId);
      return {
        serviceId: String(serviceId),
        dependencies: [],
        circular: false,
        estimatedCost: 0,
      };
    }

    const dependencies = descriptor.dependencies.map((dep) =>
      this.createResolutionPlan(dep, new Set(visited))
    );

    const circular = dependencies.some((dep) => dep.circular);
    const estimatedCost = 1 + dependencies.reduce((sum, dep) => sum + dep.estimatedCost, 0);

    visited.delete(serviceId);

    return {
      serviceId: String(serviceId),
      dependencies,
      circular,
      estimatedCost,
    };
  }

  validateDependencyGraph(): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const services = Array.from(this.serviceRegistry.getAllServices().keys());

    // Check each service
    for (const serviceId of services) {
      const plan = this.createResolutionPlan(serviceId);

      if (plan.circular) {
        const cycle = this.extractCycle(serviceId, plan);
        errors.push(`Circular dependency: ${cycle.join(' -> ')}`);
      }

      if (plan.estimatedCost > 50) {
        warnings.push(
          `Service ${String(serviceId)} has high dependency cost: ${plan.estimatedCost}`
        );
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  private extractCycle(startId: string | symbol, plan: ServiceResolutionPlan): string[] {
    const visited = new Set<string>();
    const path: string[] = [];

    const findCycle = (serviceId: string, currentPlan: ServiceResolutionPlan): string[] | null => {
      if (visited.has(serviceId)) {
        const index = path.indexOf(serviceId);
        return index !== -1 ? path.slice(index) : null;
      }

      visited.add(serviceId);
      path.push(serviceId);

      for (const dep of currentPlan.dependencies) {
        const cycle = findCycle(dep.serviceId, dep);
        if (cycle) return cycle;
      }

      path.pop();
      return null;
    };

    return findCycle(String(startId), plan) || [String(startId)];
  }
}

// Runtime type checking utilities
export class RuntimeTypeChecker {
  private static validators = new Map<string, RuntimeValidator>();

  static registerValidator<T>(name: string, validator: RuntimeValidator<T>): void {
    this.validators.set(name, validator);
  }

  static getValidator<T>(name: string): RuntimeValidator<T> | undefined {
    return this.validators.get(name) as RuntimeValidator<T>;
  }

  static validateType<T>(value: unknown, validatorName: string): ValidationResult {
    const validator = this.getValidator(validatorName);
    if (!validator) {
      return {
        valid: false,
        errors: [`Validator '${validatorName}' not found`],
      };
    }

    const isValid = validator.validate(value);
    return {
      valid: isValid,
      errors: isValid ? [] : [validator.getErrorMessage(value)],
    };
  }

  // Built-in validators
  static readonly string = new PrimitiveValidator<string>('string', 'string');
  static readonly number = new PrimitiveValidator<number>('number', 'number');
  static readonly boolean = new PrimitiveValidator<boolean>('boolean', 'boolean');
  static readonly object = new PrimitiveValidator<object>('object', 'object');
  static readonly function = new PrimitiveValidator<(...args: unknown[]) => unknown>(
    'function',
    'function'
  );

  static stringArray(): ArrayValidator<string> {
    return new ArrayValidator(this.string);
  }

  static numberArray(): ArrayValidator<number> {
    return new ArrayValidator(this.number);
  }

  static stringRecord(): RecordValidator<string> {
    return new RecordValidator(this.string);
  }

  static optional<T>(validator: RuntimeValidator<T>): OptionalValidator<T> {
    return new OptionalValidator(validator);
  }

  static union<T>(...validators: RuntimeValidator[]): UnionValidator<T> {
    return new UnionValidator(validators);
  }
}

// Error types specific to validation
export class ServiceValidationError extends Error {
  constructor(
    message: string,
    public readonly serviceId: string,
    public readonly validationErrors: ReadonlyArray<string>
  ) {
    super(message);
    this.name = 'ServiceValidationError';
  }
}

export class TypeValidationError extends Error {
  constructor(
    message: string,
    public readonly expectedType: string,
    public readonly actualValue: unknown
  ) {
    super(message);
    this.name = 'TypeValidationError';
  }
}

// Initialize built-in validators
RuntimeTypeChecker.registerValidator('string', RuntimeTypeChecker.string);
RuntimeTypeChecker.registerValidator('number', RuntimeTypeChecker.number);
RuntimeTypeChecker.registerValidator('boolean', RuntimeTypeChecker.boolean);
RuntimeTypeChecker.registerValidator('object', RuntimeTypeChecker.object);
RuntimeTypeChecker.registerValidator('function', RuntimeTypeChecker.function);
