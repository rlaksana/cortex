/**
 * Logger wrapper to break circular dependencies
 * Provides simple logging functionality without importing complex logger modules
 */

export interface SimpleLogger {
  info: (message: any, meta?: any) => void;
  warn: (message: any, meta?: any) => void;
  error: (message: any, meta?: any) => void;
  debug: (message: any, meta?: any) => void;
  flush?: () => Promise<void>;
}

/**
 * Simple console-based logger to avoid circular dependencies
 */
export const simpleLogger: SimpleLogger = {
  info: (message: any, meta?: any) => {
    const logData = typeof message === 'string'
      ? { level: 'info', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'info', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.log(JSON.stringify(logData));
  },
  warn: (message: any, meta?: any) => {
    const logData = typeof message === 'string'
      ? { level: 'warn', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'warn', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.warn(JSON.stringify(logData));
  },
  error: (message: any, meta?: any) => {
    const logData = typeof message === 'string'
      ? { level: 'error', message, timestamp: new Date().toISOString(), ...meta }
      : { level: 'error', message: 'Log entry', timestamp: new Date().toISOString(), ...message, ...meta };
    console.error(JSON.stringify(logData));
  },
  debug: (message: any, meta?: any) => {
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