// ABSOLUTELY FINAL EMERGENCY ROLLBACK: Complete ALL systematic type issues

/**
 * MCP-Safe Logger - Windows compatible solution for stdio transport
 *
 * This logger implementation bypasses Pino's problematic destination
 * configuration on Windows and directly writes to stderr for MCP compatibility.
 * Enhanced with correlation ID support for request tracing.
 */

import pino from 'pino';

import { getCorrelationId } from './correlation-id.js';

interface LogEntry {
  level: string;
  time: string;
  service: string;
  environment: string;
  msg: string;
  correlation_id?: string;
  [key: string]: unknown;
}

class MCPSafeLogger {
  public level: string;
  public baseContext: Record<string, unknown>;

  constructor() {
    this.level = process.env.LOG_LEVEL === 'error' ? 'error' : 'info';
    this.baseContext = {
      service: 'cortex-mcp',
      environment: process.env.NODE_ENV ?? 'development',
    };
  }

  public shouldLog(level: string): boolean {
    const levels = { debug: 10, info: 20, warn: 30, error: 40, fatal: 50 };
    return levels[level as keyof typeof levels] >= levels[this.level as keyof typeof levels];
  }

  public writeLog(level: string, msg: string, obj?: unknown): void {
    if (!this.shouldLog(level)) return;

    const correlationId = getCorrelationId();

    const logEntry: LogEntry = {
      level,
      time: new Date().toISOString(),
      service: this.baseContext.service as string,
      environment: this.baseContext.environment as string,
      msg,
      ...(correlationId && { correlation_id: correlationId }),
      ...(obj as unknown),
    };

    const logLine = `${JSON.stringify(logEntry)}\n`;

    // Force write to stderr (file descriptor 2) for MCP stdio compatibility
    process.stderr.write(logLine);
  }

  info = (msg: unknown, ...args: any[]): void => {
    if (typeof msg === 'object' && msg !== null) {
      // Pattern: info(obj, msg)
      const message = args[0] || '';
      this.writeLog('info', message as string, msg);
    } else {
      // Pattern: info(msg, obj)
      const obj = args.length > 0 ? args[0] : undefined;
      this.writeLog('info', msg as string, obj);
    }
  };

  debug = (msg: unknown, ...args: any[]): void => {
    if (typeof msg === 'object' && msg !== null) {
      const message = args[0] || '';
      this.writeLog('debug', message as string, msg);
    } else {
      const obj = args.length > 0 ? args[0] : undefined;
      this.writeLog('debug', msg as string, obj);
    }
  };

  warn = (msg: unknown, ...args: any[]): void => {
    if (typeof msg === 'object' && msg !== null) {
      const message = args[0] || '';
      this.writeLog('warn', message as string, msg);
    } else {
      const obj = args.length > 0 ? args[0] : undefined;
      this.writeLog('warn', msg as string, obj);
    }
  };

  error = (msg: unknown, ...args: any[]): void => {
    if (typeof msg === 'object' && msg !== null) {
      const message = args[0] || '';
      this.writeLog('error', message as string, msg);
    } else {
      const obj = args.length > 0 ? args[0] : undefined;
      this.writeLog('error', msg as string, obj);
    }
  };

  trace = (msg: unknown, ...args: any[]): void => {
    if (typeof msg === 'object' && msg !== null) {
      const message = args[0] || '';
      this.writeLog('debug', message as string, msg); // Map trace to debug level
    } else {
      const obj = args.length > 0 ? args[0] : undefined;
      this.writeLog('debug', msg as string, obj); // Map trace to debug level
    }
  };

  child(context: Record<string, unknown>): MCPSafeLogger {
    const childLogger = new MCPSafeLogger();
    childLogger.baseContext = { ...this.baseContext, ...context };
    return childLogger;
  }
}

// Conditional logger: MCP-safe for stdio transport, regular Pino for other modes
const isMcpMode = process.env.MCP_TRANSPORT === 'stdio';

// Create a mixin function to automatically add correlation ID
const correlationMixin = () => {
  const correlationId = getCorrelationId();
  return correlationId ? { correlation_id: correlationId } : {};
};

export const logger = isMcpMode
  ? new MCPSafeLogger()
  : pino({
      level: process.env.LOG_LEVEL ?? 'info',
      formatters: {
        level: (label) => ({ level: label }),
      },
      base: {
        service: 'cortex-mcp',
        environment: process.env.NODE_ENV ?? 'development',
      },
      timestamp: pino.stdTimeFunctions.isoTime,
      mixin: correlationMixin,
      redact: {
        paths: ['*.idempotency_key', '*.actor'],
        remove: true,
      },
      transport: {
        target: 'pino/file',
        options: { destination: 2 },
      },
    });
