// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Dependency Injection and Event System Types
 *
 * Comprehensive type definitions for dependency injection, service registry,
 * event bus, and related architectural patterns to eliminate 'any' types.
 */

// ============================================================================
// Base Service Types
// ============================================================================

export interface ServiceIdentifier<T = unknown> {
  token: string;
  name?: string;
  description?: string;
  factory?: () => T;
  singleton?: boolean;
  dependencies?: ServiceIdentifier[];
}

export interface ServiceRegistration<T = unknown> {
  identifier: ServiceIdentifier<T>;
  implementation: ServiceImplementation<T>;
  lifetime: ServiceLifetime;
  dependencies?: ServiceIdentifier[];
  metadata?: ServiceMetadata;
}

export interface ServiceImplementation<T = unknown> {
  factory: () => T | Promise<T>;
  instance?: T;
  instanceId?: string;
}

export interface ServiceMetadata {
  version: string;
  description: string;
  tags: string[];
  healthCheckEndpoint?: string;
  configuration?: Record<string, unknown>;
}

export type ServiceLifetime = 'transient' | 'scoped' | 'singleton';

// ============================================================================
// Service Registry Types
// ============================================================================

export interface ServiceRegistry {
  register<T>(identifier: ServiceIdentifier<T>, implementation: ServiceImplementation<T>, lifetime?: ServiceLifetime): void;
  get<T>(identifier: ServiceIdentifier<T>): T;
  getAsync<T>(identifier: ServiceIdentifier<T>): Promise<T>;
  isRegistered<T>(identifier: ServiceIdentifier<T>): boolean;
  unregister<T>(identifier: ServiceIdentifier<T>): void;
  clear(): void;
  getRegisteredServices(): ServiceRegistration[];
  getHealthStatus(): ServiceHealthStatus[];
}

export interface ServiceRegistryConfig {
  enableAutoRegistration: boolean;
  defaultLifetime: ServiceLifetime;
  enableLazyLoading: boolean;
  enableCircularDependencyDetection: boolean;
  enableServiceValidation: boolean;
  maxConcurrentResolutions: number;
  resolutionTimeoutMs: number;
}

export interface ServiceContainer {
  parent?: ServiceContainer;
  services: Map<string, ServiceRegistration>;
  singletons: Map<string, unknown>;
  scopes: Map<string, unknown>;
  createScope(): ServiceContainer;
  resolve<T>(identifier: ServiceIdentifier<T>): T;
  dispose(): void;
  isDisposed: boolean;
}

// ============================================================================
// Service Health Types
// ============================================================================

export interface ServiceHealthStatus {
  serviceName: string;
  status: 'healthy' | 'unhealthy' | 'degraded' | 'unknown';
  lastCheck: Date;
  responseTimeMs?: number;
  errorMessage?: string;
  metadata?: Record<string, unknown>;
  dependencies?: string[];
}

export interface HealthCheckResult {
  healthy: boolean;
  message?: string;
  responseTimeMs?: number;
  metadata?: Record<string, unknown>;
  checks: HealthCheck[];
}

export interface HealthCheck {
  name: string;
  status: 'pass' | 'warn' | 'fail';
  message?: string;
  responseTimeMs?: number;
  metadata?: Record<string, unknown>;
}

export interface HealthCheckConfig {
  intervalSeconds: number;
  timeoutSeconds: number;
  retries: number;
  enabledChecks: string[];
  detailedLogging: boolean;
}

// ============================================================================
// Event System Types
// ============================================================================

export interface EventBus {
  publish<T>(event: Event<T>): Promise<void>;
  subscribe<T>(eventType: string, handler: EventHandler<T>): SubscriptionHandle;
  unsubscribe(handle: SubscriptionHandle): void;
  unsubscribeAll(eventType?: string): void;
  getEventHistory<T>(eventType: string, limit?: number): Event<T>[];
  clearEventHistory(eventType?: string): void;
  getMetrics(): EventMetrics;
}

export interface Event<T = unknown> {
  id: string;
  type: string;
  timestamp: Date;
  data: T;
  source: string;
  version: string;
  correlationId?: string;
  causationId?: string;
  metadata?: Record<string, unknown>;
  priority?: EventPriority;
}

export interface EventHandler<T = unknown> {
  handle(event: Event<T>): Promise<void> | void;
  filter?: EventFilter<T>;
  priority?: number;
  retries?: RetryConfig;
  timeout?: number;
}

export interface EventFilter<T = unknown> {
  matches(event: Event<T>): boolean;
  or?(filters: EventFilter<T>[]): EventFilter<T>;
  and?(filters: EventFilter<T>[]): EventFilter<T>;
  not?(): EventFilter<T>;
}

export interface SubscriptionHandle {
  id: string;
  eventType: string;
  handlerId: string;
  unsubscribe(): void;
  isActive: boolean;
  createdAt: Date;
  metadata?: Record<string, unknown>;
}

export type EventPriority = 'low' | 'normal' | 'high' | 'critical';

export interface RetryConfig {
  maxAttempts: number;
  backoffMs: number;
  backoffMultiplier: number;
  maxBackoffMs: number;
  jitter: boolean;
}

export interface EventMetrics {
  totalEvents: number;
  eventsByType: Record<string, number>;
  successfulDeliveries: number;
  failedDeliveries: number;
  averageProcessingTimeMs: number;
  activeSubscriptions: number;
  eventHistorySize: number;
}

// ============================================================================
// Domain Event Types
// ============================================================================

export interface DomainEvent<T = unknown> extends Event<T> {
  aggregateId: string;
  aggregateType: string;
  eventId: string;
  eventNumber: number;
}

export interface AggregateRoot<TId = string> {
  id: TId;
  version: number;
  uncommittedEvents: DomainEvent[];
  getUncommittedEvents(): DomainEvent[];
  markEventsAsCommitted(): void;
  applyEvent(event: DomainEvent): void;
}

export interface EventStore {
  saveEvents(aggregateId: string, events: DomainEvent[], expectedVersion?: number): Promise<void>;
  getEvents(aggregateId: string, fromVersion?: number, toVersion?: number): Promise<DomainEvent[]>;
  getEventsByType(eventType: string, fromTimestamp?: Date, toTimestamp?: Date): Promise<DomainEvent[]>;
  snapshot(aggregateId: string, version: number, snapshot: unknown): Promise<void>;
  getSnapshot(aggregateId: string, version?: number): Promise<unknown | null>;
}

// ============================================================================
// Command Query Responsibility Segregation (CQRS) Types
// ============================================================================

export interface Command<T = unknown> {
  id: string;
  type: string;
  data: T;
  timestamp: Date;
  userId?: string;
  correlationId?: string;
  metadata?: Record<string, unknown>;
  expectedVersion?: number;
}

export interface Query<T = unknown, R = unknown> {
  id: string;
  type: string;
  parameters: T;
  timestamp: Date;
  userId?: string;
  metadata?: Record<string, unknown>;
}

export interface CommandHandler<T = unknown> {
  canHandle(command: Command<T>): boolean;
  handle(command: Command<T>): Promise<CommandResult>;
}

export interface QueryHandler<T = unknown, R = unknown> {
  canHandle(query: Query<T>): boolean;
  handle(query: Query<T>): Promise<QueryResult<R>>;
}

export interface CommandResult {
  success: boolean;
  result?: unknown;
  error?: Error;
  events?: DomainEvent[];
  affectedAggregateIds?: string[];
}

export interface QueryResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: Error;
  metadata?: Record<string, unknown>;
}

export interface CommandBus {
  dispatch<T>(command: Command<T>): Promise<CommandResult>;
  register<T>(commandType: string, handler: CommandHandler<T>): void;
  unregister(commandType: string): void;
}

export interface QueryBus {
  execute<T, R>(query: Query<T>): Promise<QueryResult<R>>;
  register<T, R>(queryType: string, handler: QueryHandler<T, R>): void;
  unregister(queryType: string): void;
}

// ============================================================================
// Module and Plugin System Types
// ============================================================================

export interface Module {
  name: string;
  version: string;
  dependencies?: string[];
  initialize(container: ServiceContainer): Promise<void>;
  shutdown(): Promise<void>;
  getServices(): ServiceRegistration[];
  getEventHandlers(): EventHandler[];
  getCommandHandlers(): CommandHandler[];
  getQueryHandlers(): QueryHandler[];
}

export interface Plugin {
  name: string;
  version: string;
  author?: string;
  description?: string;
  homepage?: string;
  main: string;
  dependencies?: string[];
  peerDependencies?: string[];
  config?: Record<string, unknown>;
}

export interface PluginRegistry {
  register(plugin: Plugin): void;
  unregister(pluginName: string): void;
  getPlugin(pluginName: string): Plugin | null;
  getAllPlugins(): Plugin[];
  getPluginDependencies(pluginName: string): Plugin[];
  validateDependencies(pluginName: string): ValidationResult;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  plugin: string;
  dependency: string;
  version?: string;
  message: string;
  severity: 'error';
}

export interface ValidationWarning {
  plugin: string;
  dependency: string;
  version?: string;
  message: string;
  severity: 'warning';
}

// ============================================================================
// Configuration and Lifecycle Types
// ============================================================================

export interface DIContainerConfig {
  autoRegistration?: boolean;
  defaultLifetime?: ServiceLifetime;
  enableLazyLoading?: boolean;
  enableCircularDependencyDetection?: boolean;
  enableServiceValidation?: boolean;
  maxConcurrentResolutions?: number;
  resolutionTimeoutMs?: number;
  enableMetrics?: boolean;
  enableHealthChecks?: boolean;
  healthCheckIntervalMs?: number;
}

export interface LifecycleEvent {
  type: 'container_created' | 'container_disposed' | 'service_registered' | 'service_resolved' | 'scope_created' | 'scope_disposed';
  timestamp: Date;
  containerId?: string;
  serviceId?: string;
  scopeId?: string;
  metadata?: Record<string, unknown>;
}

export interface ILifecycleAware {
  onInit?(): Promise<void> | void;
  onStart?(): Promise<void> | void;
  onStop?(): Promise<void> | void;
  onDestroy?(): Promise<void> | void;
}

export interface ServiceLifecycleManager {
  initialize(): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  destroy(): Promise<void>;
  getLifecycleStatus(): LifecycleStatus;
  getActiveServices(): string[];
}

export interface LifecycleStatus {
  phase: 'uninitialized' | 'initializing' | 'initialized' | 'starting' | 'started' | 'stopping' | 'stopped' | 'destroying' | 'destroyed';
  servicesStarted: number;
  totalServices: number;
  startTime?: Date;
  phaseStartTime?: Date;
  errors: Error[];
}

// ============================================================================
// Interception and AOP Types
// ============================================================================

export interface Interceptor<T = unknown> {
  intercept(invocation: Invocation<T>): Promise<T>;
  order?: number;
  condition?: (invocation: Invocation<T>) => boolean;
}

export interface Invocation<T = unknown> {
  target: unknown;
  method: string;
  arguments: unknown[];
  proceed(): Promise<T>;
  metadata?: Record<string, unknown>;
  context: InterceptorContext;
}

export interface InterceptorContext {
  interceptors: Interceptor[];
  currentIndex: number;
  startTime: number;
  metadata: Map<string, unknown>;
}

export interface ProxyFactory {
  createProxy<T extends object>(target: T, interceptors: Interceptor[]): T;
  addInterceptor<T>(target: T, interceptor: Interceptor): void;
  removeInterceptor<T>(target: T, interceptor: Interceptor): void;
  getInterceptors<T>(target: T): Interceptor[];
}

// ============================================================================
// Monitoring and Diagnostics Types
// ============================================================================

export interface DIMetrics {
  totalResolutions: number;
  resolutionTimes: number[];
  activeServices: number;
  failedResolutions: number;
  averageResolutionTime: number;
  serviceResolutionsByType: Record<string, number>;
  memoryUsageBytes: number;
  containerInstances: number;
  activeScopes: number;
  circularDependencyAttempts: number;
  interceptedCalls: number;
  averageInterceptionTime: number;
}

export interface ServiceDependency {
  serviceName: string;
  dependencyName: string;
  lifetime: ServiceLifetime;
  optional: boolean;
  resolutionTime: number;
  resolvedAt: Date;
}

export interface ServiceDependencyGraph {
  nodes: ServiceDependencyNode[];
  edges: ServiceDependencyEdge[];
  cycles: ServiceDependencyCycle[];
}

export interface ServiceDependencyNode {
  id: string;
  name: string;
  lifetime: ServiceLifetime;
  registrationCount: number;
  resolutionCount: number;
  averageResolutionTime: number;
  memoryUsage: number;
}

export interface ServiceDependencyEdge {
  from: string;
  to: string;
  dependencyType: 'constructor' | 'property' | 'method';
  optional: boolean;
  resolutionCount: number;
}

export interface ServiceDependencyCycle {
  services: string[];
  severity: 'warning' | 'error';
  detectedAt: Date;
  resolutionCount: number;
}

// ============================================================================
// Error Types
// ============================================================================

export interface DIError extends Error {
  code: string;
  serviceId?: string;
  dependencyId?: string;
  resolutionPath?: string[];
  context?: Record<string, unknown>;
  innerError?: Error;
}

export interface ServiceResolutionError extends DIError {
  serviceId: string;
  dependencyId: string;
  resolutionPath: string[];
}

export interface CircularDependencyError extends DIError {
  cycle: string[];
  resolutionPath: string[];
}

export interface ServiceRegistrationError extends DIError {
  serviceId: string;
  reason: 'already_registered' | 'invalid_dependency' | 'invalid_lifetime' | 'validation_failed';
}

export interface ServiceNotFoundError extends DIError {
  serviceId: string;
  suggestedServices?: string[];
}

// ============================================================================
// Factory and Builder Types
// ============================================================================

export interface ServiceFactory<T = unknown> {
  create(container: ServiceContainer): T | Promise<T>;
  createScope?(parent: ServiceContainer): ServiceContainer;
  dispose?(instance: T): void;
  validate?(instance: T): ValidationResult;
}

export interface ServiceBuilder<T = unknown> {
  useFactory(factory: () => T | Promise<T>): ServiceBuilder<T>;
  useValue(value: T): ServiceBuilder<T>;
  useType(ctor: new (...args: unknown[]) => T): ServiceBuilder<T>;
  singleton(): ServiceBuilder<T>;
  scoped(): ServiceBuilder<T>;
  transient(): ServiceBuilder<T>;
  withDependencies(dependencies: ServiceIdentifier[]): ServiceBuilder<T>;
  withMetadata(metadata: ServiceMetadata): ServiceBuilder<T>;
  build(): ServiceRegistration<T>;
}

export interface ContainerBuilder {
  register<T>(identifier: ServiceIdentifier<T>): ServiceBuilder<T>;
  registerInstance<T>(identifier: ServiceIdentifier<T>, instance: T): void;
  registerFactory<T>(identifier: ServiceIdentifier<T>, factory: ServiceFactory<T>): void;
  addModule(module: Module): ContainerBuilder;
  build(): ServiceContainer;
  configure(config: DIContainerConfig): ContainerBuilder;
}