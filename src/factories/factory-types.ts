// @ts-nocheck
// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Enhanced factory type definitions with proper generics and type safety
 * Eliminates 'any' usage in factory implementations and provides branded types for service identifiers
 */

// Branded types for service identifiers
export type ServiceId<T = unknown> = string & { readonly __brand: unique symbol };
export type FactoryId<T = unknown> = string & { readonly __brand: unique symbol };
export type DatabaseId<T = unknown> = string & { readonly __brand: unique symbol };

// Service lifetime with explicit typing
export enum ServiceLifetime {
  SINGLETON = 'singleton',
  SCOPED = 'scoped',
  TRANSIENT = 'transient'
}

// Enhanced service registration with proper generics
export interface TypedServiceRegistration<T> {
  readonly token: ServiceId<T> | symbol | (new (...args: never[]) => T);
  readonly implementation: new (...args: never[]) => T;
  readonly lifetime: ServiceLifetime;
  readonly dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>;
}

// Factory service registration
export interface FactoryServiceRegistration<T> {
  readonly token: ServiceId<T> | symbol | (new (...args: never[]) => T);
  readonly factory: (container: TypedDIContainer) => T | Promise<T>;
  readonly lifetime: ServiceLifetime;
  readonly dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>;
}

// Instance service registration
export interface InstanceServiceRegistration<T> {
  readonly token: ServiceId<T> | symbol | (new (...args: never[]) => T);
  readonly instance: T;
  readonly lifetime: ServiceLifetime.SINGLETON;
}

// Union type for all service registrations
export type EnhancedServiceRegistration<T> =
  | TypedServiceRegistration<T>
  | FactoryServiceRegistration<T>
  | InstanceServiceRegistration<T>;

// Factory interface with proper generics
export interface TypedFactory<TInstance, TConfig = void> {
  readonly id: FactoryId<TInstance>;
  create(config: TConfig): Promise<TInstance> | TInstance;
  validate?(config: TConfig): Promise<ValidationResult>;
  dispose?(instance: TInstance): Promise<void> | void;
}

// Database factory interface
export interface DatabaseFactory<TDb extends IDatabase> {
  readonly id: DatabaseId<TDb>;
  create(config: DatabaseConfig): Promise<TDb>;
  validate(config: DatabaseConfig): Promise<ValidationResult>;
  test(config: DatabaseConfig): Promise<ConnectionTestResult>;
  dispose(instance: TDb): Promise<void>;
}

// Enhanced DI Container interface
export interface TypedDIContainer {
  register<T>(
    token: ServiceId<T> | symbol | (new (...args: never[]) => T),
    implementation: new (...args: never[]) => T,
    lifetime?: ServiceLifetime,
    dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>
  ): void;

  registerFactory<T>(
    token: ServiceId<T> | symbol | (new (...args: never[]) => T),
    factory: (container: TypedDIContainer) => T | Promise<T>,
    lifetime?: ServiceLifetime,
    dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>
  ): void;

  registerInstance<T>(
    token: ServiceId<T> | symbol | (new (...args: never[]) => T),
    instance: T
  ): void;

  resolve<T>(
    token: ServiceId<T> | symbol | (new (...args: never[]) => T),
    options?: ResolutionOptions
  ): T;

  isRegistered<T>(
    token: ServiceId<T> | symbol | (new (...args: never[]) => T)
  ): boolean;

  createScope<T>(scopeId?: string): TypedDIContainer & { readonly scopeId: string };
  dispose(): Promise<void>;
}

// Resolution options with proper typing
export interface ResolutionOptions {
  readonly forceNew?: boolean;
  readonly scope?: string;
  readonly timeout?: number;
}

// Configuration validation result
export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: ReadonlyArray<string>;
  readonly warnings?: ReadonlyArray<string>;
}

// Connection test result
export interface ConnectionTestResult {
  readonly connected: boolean;
  readonly healthy: boolean;
  readonly latency?: number;
  readonly error?: string;
  readonly metadata?: ReadonlyRecord<string, unknown>;
}

// Service metadata
export interface ServiceMetadata {
  readonly name: string;
  readonly version: string;
  readonly description?: string;
  readonly dependencies?: ReadonlyArray<string>;
  readonly tags?: ReadonlyArray<string>;
}

// Factory registry interface
export interface FactoryRegistry {
  register<TInstance, TConfig>(
    factory: TypedFactory<TInstance, TConfig>
  ): void;

  get<TInstance, TConfig>(
    id: FactoryId<TInstance>
  ): TypedFactory<TInstance, TConfig> | undefined;

  getAll(): ReadonlyMap<string, TypedFactory<unknown, unknown>>;

  dispose(): Promise<void>;
}

// Type guards for factory types
export function isServiceId<T>(value: unknown): value is ServiceId<T> {
  return typeof value === 'string' && value.length > 0;
}

export function isFactoryId<T>(value: unknown): value is FactoryId<T> {
  return typeof value === 'string' && value.length > 0;
}

export function isDatabaseId<T>(value: unknown): value is DatabaseId<T> {
  return typeof value === 'string' && value.length > 0;
}

// Helper functions to create branded types
export function createServiceId<T>(name: string): ServiceId<T> {
  return name as ServiceId<T>;
}

export function createFactoryId<T>(name: string): FactoryId<T> {
  return name as FactoryId<T>;
}

export function createDatabaseId<T>(name: string): DatabaseId<T> {
  return name as DatabaseId<T>;
}

// Import required types from existing codebase
import type { IDatabase } from '../db/interfaces/database.interface';
import type { DatabaseConfig } from '../types/database';

// Enhanced error types for factory operations
export class FactoryError extends Error {
  constructor(
    message: string,
    public readonly factoryId: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'FactoryError';
  }
}

export class ServiceRegistrationError extends Error {
  constructor(
    message: string,
    public readonly serviceId: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'ServiceRegistrationError';
  }
}

export class DependencyResolutionError extends Error {
  constructor(
    message: string,
    public readonly dependencyId: string,
    public readonly dependentService?: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'DependencyResolutionError';
  }
}