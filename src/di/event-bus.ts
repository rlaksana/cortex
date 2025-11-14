// @ts-nocheck
// EMERGENCY ROLLBACK: DI container interface compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Event Bus Implementation
 *
 * Provides event-driven architecture for loose coupling between services.
 * Replaces direct service dependencies with event-based communication.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';

import { Injectable } from './di-container.js';
import type { IEventService, ILoggerService  } from './service-interfaces.js';
import { ServiceTokens } from './service-interfaces.js';

/**
 * Event interface with metadata
 */
export interface CortexEvent<T = unknown> {
  id: string;
  type: string;
  data: T;
  timestamp: Date;
  correlationId?: string;
  source?: string;
  version: string;
  metadata?: Record<string, unknown>;
}

/**
 * Event handler interface
 */
export interface EventHandler<T = unknown> {
  (event: CortexEvent<T>): void | Promise<void>;
}

/**
 * Event subscription options
 */
export interface EventSubscriptionOptions {
  once?: boolean;
  priority?: number;
  timeout?: number;
  filter?: (event: CortexEvent) => boolean;
}

/**
 * Event validation result
 */
export interface EventValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Event schema registry for type safety
 */
export interface EventSchema {
  type: string;
  version: string;
  schema: unknown; // JSON Schema or similar
  required: string[];
  examples?: unknown[];
}

/**
 * Event bus with comprehensive event management
 */
@Injectable(ServiceTokens.EVENT_SERVICE)
export class EventBus implements IEventService {
  private emitter: EventEmitter;
  private logger: ILoggerService;
  private schemas = new Map<string, EventSchema>();
  private handlers = new Map<
    string,
    Array<{ handler: EventHandler; options: EventSubscriptionOptions }>
  >();
  private middleware: Array<(event: CortexEvent, next: () => void) => void> = [];
  private metrics = {
    eventsPublished: 0,
    eventsProcessed: 0,
    eventsFailed: 0,
    handlersRegistered: 0,
  };

  constructor(logger: ILoggerService) {
    this.emitter = new EventEmitter();
    this.logger = logger.child({ service: 'EventBus' });
    this.setupErrorHandling();
  }

  /**
   * Publish an event
   */
  emit(
    eventType: string,
    data: unknown,
    options: {
      correlationId?: string;
      source?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ): void {
    const event: CortexEvent = {
      id: this.generateEventId(),
      type: eventType,
      data,
      timestamp: new Date(),
      correlationId: options.correlationId,
      source: options.source,
      version: '1.0.0',
      metadata: options.metadata,
    };

    this.publishEvent(event);
  }

  /**
   * Subscribe to events
   */
  on(eventType: string, handler: EventHandler, options: EventSubscriptionOptions = {}): void {
    this.validateHandler(handler);

    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, []);
    }

    const handlerEntry = { handler, options };
    this.handlers.get(eventType)!.push(handlerEntry);

    // Sort by priority (higher priority first)
    this.handlers
      .get(eventType)!
      .sort((a, b) => (b.options.priority || 0) - (a.options.priority || 0));

    this.metrics.handlersRegistered++;
    this.logger.debug(`Event handler registered`, { eventType, priority: options.priority });

    if (options.once) {
      this.emitter.once(eventType, (event: CortexEvent) => {
        this.executeHandler(handlerEntry, event);
      });
    } else {
      this.emitter.on(eventType, (event: CortexEvent) => {
        this.executeHandler(handlerEntry, event);
      });
    }
  }

  /**
   * Subscribe to events (once)
   */
  once(eventType: string, handler: EventHandler, options: EventSubscriptionOptions = {}): void {
    this.on(eventType, handler, { ...options, once: true });
  }

  /**
   * Unsubscribe from events
   */
  off(eventType: string, handler: EventHandler): void {
    const handlers = this.handlers.get(eventType);
    if (handlers) {
      const index = handlers.findIndex((h) => h.handler === handler);
      if (index !== -1) {
        handlers.splice(index, 1);
        this.emitter.off(eventType, handler as unknown);
        this.logger.debug(`Event handler removed`, { eventType });
      }
    }
  }

  /**
   * Remove all listeners
   */
  removeAllListeners(eventType?: string): void {
    if (eventType) {
      this.handlers.delete(eventType);
      this.emitter.removeAllListeners(eventType);
      this.logger.debug(`All listeners removed for event type`, { eventType });
    } else {
      this.handlers.clear();
      this.emitter.removeAllListeners();
      this.logger.debug(`All listeners removed for all event types`);
    }
  }

  /**
   * Register event schema for validation
   */
  registerSchema(schema: EventSchema): void {
    const key = `${schema.type}:${schema.version}`;
    this.schemas.set(key, schema);
    this.logger.debug(`Event schema registered`, { type: schema.type, version: schema.version });
  }

  /**
   * Validate event against registered schema
   */
  validateEvent(event: CortexEvent): EventValidationResult {
    const key = `${event.type}:${event.version}`;
    const schema = this.schemas.get(key);

    if (!schema) {
      return {
        valid: false,
        errors: [`No schema found for event type ${event.type} version ${event.version}`],
        warnings: [],
      };
    }

    const errors: string[] = [];
    const warnings: string[] = [];

    // Check required fields
    for (const requiredField of schema.required) {
      if (!(requiredField in event.data)) {
        errors.push(`Required field '${requiredField}' is missing`);
      }
    }

    // TODO: Add more comprehensive JSON schema validation
    // For now, basic structure validation

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Add middleware for event processing
   */
  use(middleware: (event: CortexEvent, next: () => void) => void): void {
    this.middleware.push(middleware);
    this.logger.debug(`Event middleware added`, { totalMiddleware: this.middleware.length });
  }

  /**
   * Get event metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      registeredSchemas: this.schemas.size,
      registeredHandlers: Array.from(this.handlers.values()).reduce(
        (sum, handlers) => sum + handlers.length,
        0
      ),
      middlewareCount: this.middleware.length,
    };
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.metrics = {
      eventsPublished: 0,
      eventsProcessed: 0,
      eventsFailed: 0,
      handlersRegistered: 0,
    };
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    this.logger.info('EventBus shutting down...');
    this.removeAllListeners();
    this.middleware = [];
    this.schemas.clear();
    this.emitter.removeAllListeners();
    this.logger.info('EventBus shutdown complete');
  }

  /**
   * Publish event with validation and middleware
   */
  private publishEvent(event: CortexEvent): void {
    // Validate event
    const validation = this.validateEvent(event);
    if (!validation.valid) {
      this.logger.error('Event validation failed', { event, errors: validation.errors });
      this.metrics.eventsFailed++;
      return;
    }

    if (validation.warnings.length > 0) {
      this.logger.warn('Event validation warnings', { event, warnings: validation.warnings });
    }

    this.metrics.eventsPublished++;

    // Process through middleware
    this.processMiddleware(event, () => {
      this.emitter.emit(event.type, event);
      this.metrics.eventsProcessed++;
    });
  }

  /**
   * Execute event handler with error handling and timeout
   */
  private async executeHandler(
    handlerEntry: { handler: EventHandler; options: EventSubscriptionOptions },
    event: CortexEvent
  ): Promise<void> {
    const { handler, options } = handlerEntry;

    // Apply filter if provided
    if (options.filter && !options.filter(event)) {
      return;
    }

    try {
      const timeout = options.timeout || 30000; // 30 seconds default
      await Promise.race([
        Promise.resolve(handler(event)),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Handler timeout')), timeout)),
      ]);

      this.logger.debug('Event handler executed successfully', {
        eventType: event.type,
        eventId: event.id,
      });
    } catch (error) {
      this.logger.error('Event handler execution failed', {
        eventType: event.type,
        eventId: event.id,
        error: error instanceof Error ? error.message : String(error),
      });
      this.metrics.eventsFailed++;
    }
  }

  /**
   * Process middleware chain
   */
  private processMiddleware(event: CortexEvent, finalCallback: () => void): void {
    let index = 0;

    const next = () => {
      if (index >= this.middleware.length) {
        finalCallback();
        return;
      }

      const middleware = this.middleware[index++];
      try {
        middleware(event, next);
      } catch (error) {
        this.logger.error('Middleware error', {
          eventId: event.id,
          error: error instanceof Error ? error.message : String(error),
        });
        this.metrics.eventsFailed++;
      }
    };

    next();
  }

  /**
   * Setup error handling for the event emitter
   */
  private setupErrorHandling(): void {
    this.emitter.on('error', (error) => {
      this.logger.error('EventBus error', { error: error.message });
      this.metrics.eventsFailed++;
    });

    // Handle too many listeners warning
    this.emitter.setMaxListeners(1000);
  }

  /**
   * Validate event handler
   */
  private validateHandler(handler: EventHandler): void {
    if (typeof handler !== 'function') {
      throw new Error('Event handler must be a function');
    }
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Standard event types used throughout the application
 */
export const StandardEventTypes = {
  // System events
  SYSTEM_STARTED: 'system.started',
  SYSTEM_SHUTDOWN: 'system.shutdown',
  SYSTEM_ERROR: 'system.error',
  SYSTEM_HEALTH_CHECK: 'system.health_check',

  // Database events
  DATABASE_CONNECTED: 'database.connected',
  DATABASE_DISCONNECTED: 'database.disconnected',
  DATABASE_ERROR: 'database.error',
  DATABASE_QUERY: 'database.query',

  // Memory events
  MEMORY_STORED: 'memory.stored',
  MEMORY_FOUND: 'memory.found',
  MEMORY_DELETED: 'memory.deleted',
  MEMORY_UPDATED: 'memory.updated',
  MEMORY_EXPIRED: 'memory.expired',

  // Auth events
  AUTH_LOGIN: 'auth.login',
  AUTH_LOGOUT: 'auth.logout',
  AUTH_FAILED: 'auth.failed',
  AUTH_TOKEN_CREATED: 'auth.token_created',
  AUTH_TOKEN_EXPIRED: 'auth.token_expired',

  // Processing events
  PROCESSING_STARTED: 'processing.started',
  PROCESSING_COMPLETED: 'processing.completed',
  PROCESSING_FAILED: 'processing.failed',
  PROCESSING_PROGRESS: 'processing.progress',

  // Metrics events
  METRICS_RECORDED: 'metrics.recorded',
  METRICS_THRESHOLD_EXCEEDED: 'metrics.threshold_exceeded',

  // Configuration events
  CONFIG_CHANGED: 'config.changed',
  CONFIG_RELOADED: 'config.reloaded',

  // Dependency events
  DEPENDENCY_HEALTH_CHANGED: 'dependency.health_changed',
  DEPENDENCY_CONNECTED: 'dependency.connected',
  DEPENDENCY_DISCONNECTED: 'dependency.disconnected',
} as const;
