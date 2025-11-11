/**
 * Logger Service Implementation
 *
 * Provides structured logging with context, correlation, and performance
 * monitoring. Replaces the global logger singleton.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { Injectable } from '../di-container.js';
import type { IConfigService , ILoggerService, IMetricsService  } from '../service-interfaces.js';
import { ServiceTokens } from '../service-interfaces.js';

/**
 * Log levels in order of severity
 */
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
  TRACE = 4,
}

/**
 * Log entry interface
 */
export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: Date;
  context?: Record<string, any>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  correlationId?: string;
  duration?: number;
  service?: string;
}

/**
 * Logger service with structured logging and correlation
 */
@Injectable(ServiceTokens.LOGGER_SERVICE)
export class LoggerService implements ILoggerService {
  private config: IConfigService;
  private metrics?: IMetricsService;
  private context: Record<string, any>;
  private correlationId?: string;

  constructor(
    config: IConfigService,
    metrics?: IMetricsService,
    context: Record<string, any> = {}
  ) {
    this.config = config;
    this.metrics = metrics;
    this.context = { ...context };
    this.correlationId = this.generateCorrelationId();
  }

  /**
   * Log debug message
   */
  debug(message: string, ...args: any[]): void {
    this.log(LogLevel.DEBUG, message, ...args);
  }

  /**
   * Log info message
   */
  info(message: string, ...args: any[]): void {
    this.log(LogLevel.INFO, message, ...args);
  }

  /**
   * Log warning message
   */
  warn(message: string, ...args: any[]): void {
    this.log(LogLevel.WARN, message, ...args);
  }

  /**
   * Log error message
   */
  error(message: string, error?: any, ...args: any[]): void {
    this.log(LogLevel.ERROR, message, error, ...args);
  }

  /**
   * Create child logger with additional context
   */
  child(context: Record<string, any>): ILoggerService {
    const mergedContext = { ...this.context, ...context };
    return new LoggerService(this.config, this.metrics, mergedContext);
  }

  /**
   * Set correlation ID for request tracing
   */
  setCorrelationId(correlationId: string): void {
    this.correlationId = correlationId;
  }

  /**
   * Get current correlation ID
   */
  getCorrelationId(): string | undefined {
    return this.correlationId;
  }

  /**
   * Create logger with service context
   */
  withService(serviceName: string): ILoggerService {
    return this.child({ service: serviceName });
  }

  /**
   * Create logger with operation context
   */
  withOperation(operation: string): ILoggerService {
    return this.child({ operation });
  }

  /**
   * Create logger with user context
   */
  withUser(userId: string): ILoggerService {
    return this.child({ userId });
  }

  /**
   * Create logger with request context
   */
  withRequest(requestId: string, method?: string, url?: string): ILoggerService {
    const context: any = { requestId };
    if (method) context.method = method;
    if (url) context.url = url;
    return this.child(context);
  }

  /**
   * Performance measurement
   */
  startTimer(label: string): () => void {
    const start = Date.now();
    return () => {
      const duration = Date.now() - start;
      this.debug(`Performance: ${label} completed`, { duration, label });

      if (this.metrics) {
        this.metrics.timing('operation.duration', duration, { label });
      }
    };
  }

  /**
   * Log operation start
   */
  logOperationStart(operation: string, context?: Record<string, any>): void {
    this.info(`Starting operation: ${operation}`, { operation, phase: 'start', ...context });
  }

  /**
   * Log operation completion
   */
  logOperationComplete(operation: string, duration: number, context?: Record<string, any>): void {
    this.info(`Completed operation: ${operation}`, {
      operation,
      phase: 'complete',
      duration,
      ...context,
    });

    if (this.metrics) {
      this.metrics.timing('operation.duration', duration, { operation });
      this.metrics.increment('operation.completed', 1, { operation });
    }
  }

  /**
   * Log operation failure
   */
  logOperationFailure(operation: string, error: Error, context?: Record<string, any>): void {
    this.error(`Failed operation: ${operation}`, error, {
      operation,
      phase: 'failed',
      errorMessage: error.message,
      errorName: error.name,
      ...context,
    });

    if (this.metrics) {
      this.metrics.increment('operation.failed', 1, { operation, errorType: error.name });
    }
  }

  /**
   * Core logging implementation
   */
  private log(level: LogLevel, message: string, ...args: any[]): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const entry = this.createLogEntry(level, message, ...args);
    this.outputLog(entry);
    this.recordMetrics(level);
  }

  /**
   * Check if message should be logged based on configured level
   */
  private shouldLog(level: LogLevel): boolean {
    const configuredLevel = this.getLogLevelFromString(this.config.get('LOG_LEVEL', 'info'));
    return level <= configuredLevel;
  }

  /**
   * Create structured log entry
   */
  private createLogEntry(level: LogLevel, message: string, ...args: any[]): LogEntry {
    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date(),
      context: { ...this.context },
      correlationId: this.correlationId,
    };

    // Handle error argument
    if (args.length > 0 && this.isError(args[0])) {
      const error = args[0];
      entry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };

      // Add additional context from remaining args
      if (args.length > 1) {
        Object.assign(entry.context!, args[1]);
      }
    } else if (args.length > 0 && typeof args[0] === 'object') {
      // Add context object
      Object.assign(entry.context!, args[0]);
    }

    return entry;
  }

  /**
   * Output log entry to appropriate destination
   */
  private outputLog(entry: LogEntry): void {
    const logMessage = this.formatLogMessage(entry);

    switch (entry.level) {
      case LogLevel.ERROR:
        console.error(logMessage);
        break;
      case LogLevel.WARN:
        console.warn(logMessage);
        break;
      case LogLevel.INFO:
        console.info(logMessage);
        break;
      case LogLevel.DEBUG:
        if (typeof console.debug === 'function') {
          console.debug(logMessage);
        } else {
          console.log(logMessage);
        }
        break;
      case LogLevel.TRACE:
        if (typeof console.trace === 'function') {
          console.trace(logMessage);
        } else if (typeof console.debug === 'function') {
          console.debug(logMessage);
        } else {
          console.log(logMessage);
        }
        break;
    }
  }

  /**
   * Format log message for console output
   */
  private formatLogMessage(entry: LogEntry): string {
    const timestamp = entry.timestamp.toISOString();
    const level = LogLevel[entry.level].padEnd(5);
    const correlation = entry.correlationId ? `[${entry.correlationId}] ` : '';
    const context =
      entry.context && Object.keys(entry.context).length > 0
        ? ` ${JSON.stringify(entry.context)}`
        : '';
    const error = entry.error ? ` ${entry.error.name}: ${entry.error.message}` : '';
    const duration = entry.duration ? ` (${entry.duration}ms)` : '';

    return `${timestamp} ${level} ${correlation}${entry.message}${duration}${context}${error}`;
  }

  /**
   * Record logging metrics
   */
  private recordMetrics(level: LogLevel): void {
    if (!this.metrics) return;

    const levelName = LogLevel[level].toLowerCase();
    this.metrics.increment('log.entries', 1, { level: levelName });
  }

  /**
   * Convert string log level to enum
   */
  private getLogLevelFromString(level: string): LogLevel {
    switch (level.toLowerCase()) {
      case 'error':
        return LogLevel.ERROR;
      case 'warn':
        return LogLevel.WARN;
      case 'info':
        return LogLevel.INFO;
      case 'debug':
        return LogLevel.DEBUG;
      case 'trace':
        return LogLevel.TRACE;
      default:
        return LogLevel.INFO;
    }
  }

  /**
   * Check if value is an Error
   */
  private isError(value: any): value is Error {
    return (
      value instanceof Error || (value && typeof value === 'object' && value.message && value.name)
    );
  }

  /**
   * Generate correlation ID
   */
  private generateCorrelationId(): string {
    return `cortex_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
