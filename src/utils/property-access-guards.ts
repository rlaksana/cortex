// TypeScript Recovery: Phase 2 - Type Guard Utilities
//
// Systematic type guard patterns for safe property access on unknown types
// Provides comprehensive type checking and narrowing for common patterns

/**
 * Type guard for object with specific property
 */
export function hasProperty<T extends object, K extends string>(
  obj: unknown,
  prop: K
): obj is T & Record<K, unknown> {
  return typeof obj === 'object' && obj !== null && prop in obj;
}

/**
 * Type guard for object with multiple properties
 */
export function hasProperties<T extends object>(
  obj: unknown,
  props: string[]
): obj is T {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }
  return props.every(prop => prop in obj);
}

/**
 * Type guard for string property
 */
export function hasStringProperty(obj: unknown, prop: string): obj is Record<string, string> {
  return hasProperty(obj, prop) && typeof (obj as any)[prop] === 'string';
}

/**
 * Type guard for number property
 */
export function hasNumberProperty(obj: unknown, prop: string): obj is Record<string, number> {
  return hasProperty(obj, prop) && typeof (obj as any)[prop] === 'number';
}

/**
 * Type guard for boolean property
 */
export function hasBooleanProperty(obj: unknown, prop: string): obj is Record<string, boolean> {
  return hasProperty(obj, prop) && typeof (obj as any)[prop] === 'boolean';
}

/**
 * Type guard for array property
 */
export function hasArrayProperty<T = unknown>(
  obj: unknown,
  prop: string,
  itemGuard?: (item: unknown) => item is T
): obj is Record<string, T[]> {
  if (!hasProperty(obj, prop)) {
    return false;
  }
  const value = (obj as any)[prop];
  if (!Array.isArray(value)) {
    return false;
  }
  if (itemGuard) {
    return value.every(itemGuard);
  }
  return true;
}

/**
 * Type guard for object property
 */
export function hasObjectProperty(
  obj: unknown,
  prop: string
): obj is Record<string, Record<string, unknown>> {
  if (!hasProperty(obj, prop)) {
    return false;
  }
  const value = (obj as any)[prop];
  return typeof value === 'object' && value !== null;
}

/**
 * Safe property getter with fallback
 */
export function safeGetProperty<T>(
  obj: unknown,
  prop: string,
  fallback: T
): T {
  if (typeof obj !== 'object' || obj === null || !(prop in obj)) {
    return fallback;
  }
  return (obj as any)[prop] ?? fallback;
}

/**
 * Type guard for performance metric structure
 */
export function isPerformanceMetric(obj: unknown): obj is {
  timestamp: string | number;
  operation: string;
  operationType: string;
  duration: number;
  success: boolean;
  metadata?: Record<string, unknown>;
  error?: string;
} {
  return typeof obj === 'object' &&
         obj !== null &&
         typeof (obj as any).timestamp !== 'undefined' &&
         typeof (obj as any).operation === 'string' &&
         typeof (obj as any).operationType === 'string' &&
         typeof (obj as any).duration === 'number' &&
         typeof (obj as any).success === 'boolean';
}

/**
 * Type guard for alert structure
 */
export function isAlertData(obj: unknown): obj is {
  title: string;
  description: string;
  tags: string[];
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  data?: Record<string, unknown>;
} {
  return typeof obj === 'object' &&
         obj !== null &&
         typeof (obj as any).title === 'string' &&
         typeof (obj as any).description === 'string' &&
         Array.isArray((obj as any).tags) &&
         (obj as any).tags.every((tag: unknown) => typeof tag === 'string') &&
         typeof (obj as any).source === 'string' &&
         ['low', 'medium', 'high', 'critical'].includes((obj as any).severity);
}

/**
 * Type guard for incident declaration
 */
export function isIncidentDeclaration(obj: unknown): obj is {
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  declaredBy: string;
  disasterType: string;
  affectedSystems: string[];
  impact: string;
  estimatedDuration?: string;
} {
  return typeof obj === 'object' &&
         obj !== null &&
         typeof (obj as any).description === 'string' &&
         typeof (obj as any).declaredBy === 'string' &&
         typeof (obj as any).disasterType === 'string' &&
         Array.isArray((obj as any).affectedSystems) &&
         typeof (obj as any).impact === 'string' &&
         ['low', 'medium', 'high', 'critical'].includes((obj as any).severity);
}

/**
 * Type guard for backup configuration
 */
export function isBackupConfig(obj: unknown): obj is {
  schedule: string;
  retention: {
    daily: number;
    weekly: number;
    monthly: number;
  };
  storage: {
    type: string;
    location: string;
    credentials?: Record<string, unknown>;
  };
  targets: string[];
  performance: {
    maxConcurrentBackups: number;
    compressionEnabled: boolean;
    encryptionEnabled: boolean;
  };
} {
  return typeof obj === 'object' &&
         obj !== null &&
         typeof (obj as any).schedule === 'string' &&
         typeof (obj as any).storage === 'object' &&
         Array.isArray((obj as any).targets) &&
         typeof (obj as any).performance === 'object';
}

/**
 * Type guard for operation result with performance details
 */
export function hasPerformanceDetails(obj: unknown): obj is {
  performanceDetails: {
    duration: number;
    throughput: number;
    errors: number;
    retries: number;
  };
} {
  return hasObjectProperty(obj, 'performanceDetails') &&
         typeof (obj as any).performanceDetails.duration === 'number' &&
         typeof (obj as any).performanceDetails.throughput === 'number';
}

/**
 * Type guard for data integrity information
 */
export function hasDataIntegrity(obj: unknown): obj is {
  dataIntegrity: {
    checksum: string;
    recordCount: number;
    validationPassed: boolean;
    inconsistencies: string[];
  };
} {
  return hasObjectProperty(obj, 'dataIntegrity') &&
         typeof (obj as any).dataIntegrity.checksum === 'string' &&
         typeof (obj as any).dataIntegrity.recordCount === 'number' &&
         typeof (obj as any).dataIntegrity.validationPassed === 'boolean' &&
         Array.isArray((obj as any).dataIntegrity.inconsistencies);
}

/**
 * Safe object accessor with comprehensive error handling
 */
export function safeObjectAccess<T = unknown>(
  obj: unknown,
  accessor: (safeObj: Record<string, unknown>) => T,
  fallback: T
): T {
  try {
    if (typeof obj !== 'object' || obj === null) {
      return fallback;
    }
    return accessor(obj as Record<string, unknown>);
  } catch {
    return fallback;
  }
}

/**
 * Create a typed proxy for unknown objects with safe property access
 */
export function createSafeProxy<T extends Record<string, unknown>>(
  obj: unknown,
  defaults: Partial<T> = {}
): T {
  if (typeof obj !== 'object' || obj === null) {
    return defaults as T;
  }

  return new Proxy({ ...defaults, ...(obj as T) }, {
    get: (target, prop: string | symbol) => {
      if (prop in target) {
        return target[prop as keyof T];
      }
      if (typeof prop === 'string' && prop in defaults) {
        return defaults[prop as keyof T];
      }
      return undefined;
    }
  });
}