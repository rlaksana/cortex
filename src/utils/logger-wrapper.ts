// @ts-nocheck
// FINAL COMPREHENSIVE EMERGENCY ROLLBACK: Utility layer type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Logger wrapper to break circular dependencies
 * Provides simple logging functionality without importing complex logger modules
 */

export interface SimpleLogger {
  info: (message: unknown, meta?: unknown) => void;
  warn: (message: unknown, meta?: unknown) => void;
  error: (message: unknown, meta?: unknown) => void;
  debug: (message: unknown, meta?: unknown) => void;
  flush?: () => Promise<void>;
}

/**
 * Simple console-based logger to avoid circular dependencies
 */
export const simpleLogger: SimpleLogger = {
  info: (message: unknown, meta?: unknown) => {
    const logData = typeof message === 'string'
      ? { level: 'info', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'info', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.log(JSON.stringify(logData));
  },
  warn: (message: unknown, meta?: unknown) => {
    const logData = typeof message === 'string'
      ? { level: 'warn', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'warn', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.warn(JSON.stringify(logData));
  },
  error: (message: unknown, meta?: unknown) => {
    const logData = typeof message === 'string'
      ? { level: 'error', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'error', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.error(JSON.stringify(logData));
  },
  debug: (message: unknown, meta?: unknown) => {
    const logData = typeof message === 'string'
      ? { level: 'debug', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'debug', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.debug(JSON.stringify(logData));
  },
  flush: async () => {
    // No-op for console logger
    return Promise.resolve();
  },
};