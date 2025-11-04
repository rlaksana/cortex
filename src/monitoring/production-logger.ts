/**
 * Production Logger
 *
 * Structured logging system optimized for production environments.
 * Provides JSON-formatted logs with correlation IDs, performance metrics,
 * and security event tracking.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

export interface LogEntry {
  timestamp: string;
  level: string;
  service: string;
  message: string;
  requestId?: string;
  userId?: string;
  error?: {
    name: string;
    message: string;
    stack?: string;
    code?: string;
  };
  metadata?: Record<string, any>;
  performance?: {
    duration?: number;
    memory?: NodeJS.MemoryUsage;
    cpu?: NodeJS.CpuUsage;
  };
  security?: {
    event: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    ip?: string;
    userAgent?: string;
    action?: string;
  };
}

export interface LoggerConfig {
  level: string;
  format: 'json' | 'text';
  includeTimestamp: boolean;
  includeRequestId: boolean;
  enablePerformanceLogging: boolean;
  enableSecurityLogging: boolean;
  service: string;
}

export class ProductionLogger {
  private config: LoggerConfig;
  private static instance: ProductionLogger;
  private readonly LOG_LEVELS = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3
  };

  constructor(service: string = 'cortex-memory') {
    this.config = {
      level: process.env.LOG_LEVEL || 'info',
      format: process.env.LOG_FORMAT === 'text' ? 'text' : 'json',
      includeTimestamp: process.env.LOG_TIMESTAMP !== 'false',
      includeRequestId: process.env.LOG_REQUEST_ID !== 'false',
      enablePerformanceLogging: process.env.ENABLE_PERFORMANCE_MONITORING === 'true',
      enableSecurityLogging: process.env.ENABLE_SECURITY_LOGGING === 'true',
      service
    };
  }

  /**
   * Get singleton logger instance
   */
  static getInstance(service?: string): ProductionLogger {
    if (!ProductionLogger.instance) {
      ProductionLogger.instance = new ProductionLogger(service);
    }
    return ProductionLogger.instance;
  }

  /**
   * Log error message
   */
  error(message: string, metadata?: Record<string, any>, error?: Error): void {
    this.log('error', message, metadata, error);
  }

  /**
   * Log warning message
   */
  warn(message: string, metadata?: Record<string, any>): void {
    this.log('warn', message, metadata);
  }

  /**
   * Log info message
   */
  info(message: string, metadata?: Record<string, any>): void {
    this.log('info', message, metadata);
  }

  /**
   * Log debug message
   */
  debug(message: string, metadata?: Record<string, any>): void {
    this.log('debug', message, metadata);
  }

  /**
   * Log security event
   */
  security(event: string, severity: 'low' | 'medium' | 'high' | 'critical', metadata?: Record<string, any>): void {
    if (!this.config.enableSecurityLogging) return;

    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: 'info',
      service: this.config.service,
      message: `Security event: ${event}`,
      security: {
        event,
        severity,
        ip: metadata?.ip,
        userAgent: metadata?.userAgent,
        action: metadata?.action
      },
      metadata: this.sanitizeMetadata(metadata)
    };

    this.writeLog(logEntry);
  }

  /**
   * Log performance metrics
   */
  performance(operation: string, duration: number, metadata?: Record<string, any>): void {
    if (!this.config.enablePerformanceLogging) return;

    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: 'info',
      service: this.config.service,
      message: `Performance: ${operation}`,
      performance: {
        duration,
        memory: process.memoryUsage(),
        cpu: process.cpuUsage()
      },
      metadata: this.sanitizeMetadata(metadata)
    };

    this.writeLog(logEntry);
  }

  /**
   * Core logging method
   */
  private log(level: string, message: string, metadata?: Record<string, any>, error?: Error): void {
    if (!this.shouldLog(level)) return;

    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      service: this.config.service,
      message,
      metadata: this.sanitizeMetadata(metadata)
    };

    // Add error information if provided
    if (error) {
      logEntry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: (error as any).code
      };
    }

    this.writeLog(logEntry);
  }

  /**
   * Write log entry to output
   */
  private writeLog(logEntry: LogEntry): void {
    try {
      if (this.config.format === 'json') {
        console.log(JSON.stringify(logEntry));
      } else {
        // Text format for development/debugging
        const textLog = this.formatTextLog(logEntry);
        console.log(textLog);
      }
    } catch (error) {
      // Fallback logging if JSON serialization fails
      console.error('Logger error:', error);
      console.error('Original log:', logEntry.message);
    }
  }

  /**
   * Format log entry as text
   */
  private formatTextLog(logEntry: LogEntry): string {
    const timestamp = this.config.includeTimestamp ? `[${logEntry.timestamp}] ` : '';
    const level = logEntry.level.toUpperCase().padEnd(5);
    const service = `[${logEntry.service}] `;
    const requestId = logEntry.requestId ? `[${logEntry.requestId}] ` : '';

    let message = `${timestamp}${level}${service}${requestId}${logEntry.message}`;

    if (logEntry.error) {
      message += `\nError: ${logEntry.error.message}`;
      if (logEntry.error.stack) {
        message += `\nStack: ${logEntry.error.stack}`;
      }
    }

    if (logEntry.metadata && Object.keys(logEntry.metadata).length > 0) {
      message += `\nMetadata: ${JSON.stringify(logEntry.metadata, null, 2)}`;
    }

    return message;
  }

  /**
   * Check if log level should be logged
   */
  private shouldLog(level: string): boolean {
    const configLevel = this.LOG_LEVELS[this.config.level as keyof typeof this.LOG_LEVELS];
    const messageLevel = this.LOG_LEVELS[level as keyof typeof this.LOG_LEVELS];
    return messageLevel <= configLevel;
  }

  /**
   * Sanitize metadata to remove sensitive information
   */
  private sanitizeMetadata(metadata?: Record<string, any>): Record<string, any> | undefined {
    if (!metadata) return undefined;

    const sensitiveFields = [
      'password',
      'secret',
      'token',
      'key',
      'authorization',
      'api_key',
      'openai_api_key',
      'jwt_secret',
      'encryption_key'
    ];

    const sanitized = { ...metadata };

    for (const [key, value] of Object.entries(sanitized)) {
      if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeMetadata(value);
      }
    }

    return sanitized;
  }

  /**
   * Create child logger with additional context
   */
  child(context: Record<string, any>): ProductionLogger {
    const childLogger = new ProductionLogger(this.config.service);
    childLogger.config = { ...this.config };

    // Store context for use in log entries
    (childLogger as any).context = context;

    return childLogger;
  }

  /**
   * Update log level at runtime
   */
  setLevel(level: string): void {
    if (level in this.LOG_LEVELS) {
      this.config.level = level;
    } else {
      throw new Error(`Invalid log level: ${level}. Valid levels: ${Object.keys(this.LOG_LEVELS).join(', ')}`);
    }
  }

  /**
   * Get current log level
   */
  getLevel(): string {
    return this.config.level;
  }

  /**
   * Enable or disable performance logging
   */
  setPerformanceLogging(enabled: boolean): void {
    this.config.enablePerformanceLogging = enabled;
  }

  /**
   * Enable or disable security logging
   */
  setSecurityLogging(enabled: boolean): void {
    this.config.enableSecurityLogging = enabled;
  }

  /**
   * Flush any pending log entries (if buffering is implemented)
   */
  async flush(): Promise<void> {
    // In a more advanced implementation, this would flush buffered logs
    // For now, it's a no-op since we're writing directly to console
  }

  /**
   * Close logger and cleanup resources
   */
  async close(): Promise<void> {
    await this.flush();
    // Additional cleanup if needed
  }
}

// Export a default logger instance
export const logger = ProductionLogger.getInstance();
export default ProductionLogger;