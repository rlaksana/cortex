// FINAL COMPREHENSIVE EMERGENCY ROLLBACK: Utility layer type issues

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
    const baseData = {
      level: 'info' as const,
      timestamp: new Date().toISOString(),
    };

    if (typeof message === 'string') {
      const logData = {
        ...baseData,
        message,
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.log(JSON.stringify(logData));
    } else {
      const logData = {
        ...baseData,
        message: 'Log entry',
        ...(message && typeof message === 'object' ? (message as Record<string, unknown>) : {}),
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.log(JSON.stringify(logData));
    }
  },
  warn: (message: unknown, meta?: unknown) => {
    const baseData = {
      level: 'warn' as const,
      timestamp: new Date().toISOString(),
    };

    if (typeof message === 'string') {
      const logData = {
        ...baseData,
        message,
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.warn(JSON.stringify(logData));
    } else {
      const logData = {
        ...baseData,
        message: 'Log entry',
        ...(message && typeof message === 'object' ? (message as Record<string, unknown>) : {}),
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.warn(JSON.stringify(logData));
    }
  },
  error: (message: unknown, meta?: unknown) => {
    const baseData = {
      level: 'error' as const,
      timestamp: new Date().toISOString(),
    };

    if (typeof message === 'string') {
      const logData = {
        ...baseData,
        message,
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.error(JSON.stringify(logData));
    } else {
      const logData = {
        ...baseData,
        message: 'Log entry',
        ...(message && typeof message === 'object' ? (message as Record<string, unknown>) : {}),
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.error(JSON.stringify(logData));
    }
  },
  debug: (message: unknown, meta?: unknown) => {
    const baseData = {
      level: 'debug' as const,
      timestamp: new Date().toISOString(),
    };

    if (typeof message === 'string') {
      const logData = {
        ...baseData,
        message,
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.debug(JSON.stringify(logData));
    } else {
      const logData = {
        ...baseData,
        message: 'Log entry',
        ...(message && typeof message === 'object' ? (message as Record<string, unknown>) : {}),
        ...(meta && typeof meta === 'object' ? (meta as Record<string, unknown>) : {}),
      };
      console.debug(JSON.stringify(logData));
    }
  },
  flush: async () => {
    // No-op for console logger
    return Promise.resolve();
  },
};
