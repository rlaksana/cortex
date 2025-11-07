// @ts-nocheck
/**
 * Result Type Definitions for Dependency Registry
 *
 * Provides consistent Result<T> pattern for dependency operations
 * with proper error handling and type safety.
 */

import { DependencyStatus, HealthCheckResult } from './deps-registry.js';

/**
 * Standard result type for dependency operations
 */
export interface DependencyResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  timestamp: Date;
}

/**
 * Result type for dependency connection operations
 */
export interface ConnectionResult extends DependencyResult<boolean> {
  dependency: string;
  connectionTime?: number;
  retryAttempts?: number;
}

/**
 * Result type for dependency disconnection operations
 */
export interface DisconnectionResult extends DependencyResult<boolean> {
  dependency: string;
  graceful: boolean;
}

/**
 * Result type for health check operations
 */
export interface HealthCheckResultExtended extends DependencyResult<HealthCheckResult> {
  dependency: string;
  responseTime: number;
  previousStatus?: DependencyStatus;
}

/**
 * Result type for dependency registration operations
 */
export interface RegistrationResult extends DependencyResult<string> {
  dependency: string;
  type: string;
  autoConnected: boolean;
}

/**
 * Result type for dependency unregistration operations
 */
export interface UnregistrationResult extends DependencyResult<string> {
  dependency: string;
  wasConnected: boolean;
  cleanedUpResources: string[];
}

/**
 * Promise-wrapped result types for async operations
 */
export type DependencyPromiseResult<T = unknown> = Promise<DependencyResult<T>>;
export type ConnectionPromiseResult = Promise<ConnectionResult>;
export type DisconnectionPromiseResult = Promise<DisconnectionResult>;
export type HealthCheckPromiseResult = Promise<HealthCheckResultExtended>;
export type RegistrationPromiseResult = Promise<RegistrationResult>;
export type UnregistrationPromiseResult = Promise<UnregistrationResult>;

/**
 * Error codes for dependency operations
 */
export enum DependencyErrorCode {
  CONNECTION_FAILED = 'CONNECTION_FAILED',
  DISCONNECTION_FAILED = 'DISCONNECTION_FAILED',
  HEALTH_CHECK_FAILED = 'HEALTH_CHECK_FAILED',
  DEPENDENCY_NOT_FOUND = 'DEPENDENCY_NOT_FOUND',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  TIMEOUT_ERROR = 'TIMEOUT_ERROR',
  CONFIGURATION_ERROR = 'CONFIGURATION_ERROR',
  CIRCUIT_BREAKER_OPEN = 'CIRCUIT_BREAKER_OPEN',
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  NETWORK_ERROR = 'NETWORK_ERROR',
}

/**
 * Factory functions for creating results
 */
export class DependencyResultFactory {
  static success<T>(data: T): DependencyResult<T> {
    return {
      success: true,
      data,
      timestamp: new Date(),
    };
  }

  static failure<T>(code: string, message: string, details?: unknown): DependencyResult<T> {
    return {
      success: false,
      error: {
        code,
        message,
        details,
      },
      timestamp: new Date(),
    };
  }

  static connectionSuccess(
    dependency: string,
    connectionTime?: number,
    retryAttempts?: number
  ): ConnectionResult {
    return {
      success: true,
      data: true,
      dependency,
      connectionTime,
      retryAttempts,
      timestamp: new Date(),
    };
  }

  static connectionFailure(
    dependency: string,
    code: string,
    message: string,
    details?: unknown
  ): ConnectionResult {
    return {
      success: false,
      data: false,
      dependency,
      error: { code, message, details },
      timestamp: new Date(),
    };
  }

  static disconnectionSuccess(dependency: string, graceful: boolean = true): DisconnectionResult {
    return {
      success: true,
      data: true,
      dependency,
      graceful,
      timestamp: new Date(),
    };
  }

  static disconnectionFailure(
    dependency: string,
    code: string,
    message: string,
    graceful: boolean = false
  ): DisconnectionResult {
    return {
      success: false,
      data: false,
      dependency,
      graceful,
      error: { code, message },
      timestamp: new Date(),
    };
  }

  static healthCheckSuccess(
    dependency: string,
    result: HealthCheckResult,
    previousStatus?: DependencyStatus
  ): HealthCheckResultExtended {
    return {
      success: true,
      data: result,
      dependency,
      responseTime: result.responseTime,
      previousStatus,
      timestamp: new Date(),
    };
  }

  static healthCheckFailure(
    dependency: string,
    code: string,
    message: string,
    responseTime?: number,
    details?: unknown
  ): HealthCheckResultExtended {
    return {
      success: false,
      dependency,
      responseTime: responseTime || 0,
      error: { code, message, details },
      timestamp: new Date(),
    };
  }

  static registrationSuccess(
    dependency: string,
    type: string,
    autoConnected: boolean = false
  ): RegistrationResult {
    return {
      success: true,
      data: dependency,
      dependency,
      type,
      autoConnected,
      timestamp: new Date(),
    };
  }

  static registrationFailure(
    dependency: string,
    type: string,
    code: string,
    message: string,
    details?: unknown
  ): RegistrationResult {
    return {
      success: false,
      dependency,
      type,
      autoConnected: false,
      error: { code, message, details },
      timestamp: new Date(),
    };
  }

  static unregistrationSuccess(
    dependency: string,
    wasConnected: boolean = false,
    cleanedUpResources: string[] = []
  ): UnregistrationResult {
    return {
      success: true,
      data: dependency,
      dependency,
      wasConnected,
      cleanedUpResources,
      timestamp: new Date(),
    };
  }

  static unregistrationFailure(
    dependency: string,
    code: string,
    message: string,
    details?: unknown
  ): UnregistrationResult {
    return {
      success: false,
      dependency,
      wasConnected: false,
      cleanedUpResources: [],
      error: { code, message, details },
      timestamp: new Date(),
    };
  }
}
