/**
 * Service Integration Validator
 *
 * Validates service layer integration and provides comprehensive testing
 * utilities for the ServiceResponse<T> pattern implementation.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type {
  IBaseService,
  IMemoryFindOrchestrator,
  IMemoryStoreOrchestrator,
  ServiceResponse,
} from '../interfaces/service-interfaces.js';
import { ServiceResponseValidator, TypeValidators } from './service-response-builders.js';
import { logger } from './logger.js';

/**
 * Service integration validation result
 */
export interface ServiceValidationResult {
  serviceName: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  metrics: {
    interfaceCompliance: number; // 0-100%
    typeSafetyScore: number; // 0-100%
    responseFormatCompliance: number; // 0-100%
  };
}

/**
 * Comprehensive service integration validator
 */
export class ServiceIntegrationValidator {
  /**
   * Validate a single service implementation
   */
  static async validateService<T = unknown>(
    service: IBaseService,
    serviceType: 'knowledge' | 'orchestrator' | 'find' | 'store' | 'general'
  ): Promise<ServiceValidationResult> {
    const result: ServiceValidationResult = {
      serviceName: service.constructor.name,
      valid: true,
      errors: [],
      warnings: [],
      metrics: {
        interfaceCompliance: 0,
        typeSafetyScore: 0,
        responseFormatCompliance: 0,
      },
    };

    try {
      // Test interface compliance
      await this.validateInterfaceCompliance(service, serviceType, result);

      // Test type safety
      await this.validateTypeSafety(service, result);

      // Test response format compliance
      await this.validateResponseFormat(service, result);

      // Calculate overall metrics
      result.metrics.interfaceCompliance = this.calculateInterfaceCompliance(result);
      result.metrics.typeSafetyScore = this.calculateTypeSafetyScore(result);
      result.metrics.responseFormatCompliance = this.calculateResponseFormatCompliance(result);

      // Determine overall validity
      result.valid = result.errors.length === 0;

      logger.info(
        {
          serviceName: result.serviceName,
          valid: result.valid,
          errors: result.errors.length,
          warnings: result.warnings.length,
          metrics: result.metrics,
        },
        'Service validation completed'
      );
    } catch (error) {
      result.valid = false;
      result.errors.push(`Validation failed: ${(error as Error).message}`);

      logger.error(
        {
          serviceName: result.serviceName,
          error,
        },
        'Service validation error'
      );
    }

    return result;
  }

  /**
   * Validate multiple services
   */
  static async validateServices(
    services: Array<{ service: IBaseService; type: 'knowledge' | 'orchestrator' | 'find' | 'store' | 'general' }>
  ): Promise<ServiceValidationResult[]> {
    const results: ServiceValidationResult[] = [];

    for (const { service, type } of services) {
      const result = await this.validateService(service, type);
      results.push(result);
    }

    return results;
  }

  /**
   * Test service interface compliance
   */
  private static async validateInterfaceCompliance(
    service: IBaseService,
    serviceType: string,
    result: ServiceValidationResult
  ): Promise<void> {
    // Check if service implements required methods
    const requiredMethods = this.getRequiredMethods(serviceType);

    for (const methodName of requiredMethods) {
      if (!(service as any)[methodName] || typeof (service as any)[methodName] !== 'function') {
        result.errors.push(`Missing required method: ${methodName}`);
      }
    }

    // Test health check if available
    if (typeof service.healthCheck === 'function') {
      try {
        const healthResponse = await service.healthCheck();

        if (!ServiceResponseValidator.isValid(healthResponse)) {
          result.errors.push('healthCheck() returns invalid ServiceResponse format');
        } else if (!healthResponse.success || !healthResponse.data) {
          result.errors.push('healthCheck() should return successful response with status data');
        }
      } catch (error) {
        result.errors.push(`healthCheck() failed: ${(error as Error).message}`);
      }
    }

    // Test getStatus if available
    if (typeof service.getStatus === 'function') {
      try {
        const statusResponse = await service.getStatus();

        if (!ServiceResponseValidator.isValid(statusResponse)) {
          result.errors.push('getStatus() returns invalid ServiceResponse format');
        }
      } catch (error) {
        result.warnings.push(`getStatus() failed: ${(error as Error).message}`);
      }
    }
  }

  /**
   * Test service type safety
   */
  private static async validateTypeSafety(
    service: IBaseService,
    result: ServiceValidationResult
  ): Promise<void> {
    // Test method signatures and return types
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(service))
      .filter(name => name !== 'constructor' && typeof (service as any)[name] === 'function');

    for (const methodName of methods) {
      try {
        const method = (service as any)[methodName];

        // Skip private methods
        if (methodName.startsWith('_')) {
          continue;
        }

        // Check if method returns ServiceResponse (basic signature validation)
        // Note: We can't easily test this without knowing expected parameters
        if (this.shouldReturnServiceResponse(methodName)) {
          result.warnings.push(`Method ${methodName} should return ServiceResponse<T> - verify manually`);
        }
      } catch (error) {
        result.warnings.push(`Cannot validate method ${methodName}: ${(error as Error).message}`);
      }
    }
  }

  /**
   * Test response format compliance
   */
  private static async validateResponseFormat(
    service: IBaseService,
    result: ServiceValidationResult
  ): Promise<void> {
    // Test service methods that should return ServiceResponse
    const testableMethods = ['healthCheck', 'getStatus'];

    for (const methodName of testableMethods) {
      if (typeof (service as any)[methodName] === 'function') {
        try {
          const response = await (service as any)[methodName]();

          if (response && !ServiceResponseValidator.isValid(response)) {
            result.errors.push(`Method ${methodName} returns invalid response format`);
          }
        } catch (error) {
          // Expected for some methods, just log as warning
          result.warnings.push(`Method ${methodName} threw error during testing: ${(error as Error).message}`);
        }
      }
    }
  }

  /**
   * Get required methods for different service types
   */
  private static getRequiredMethods(serviceType: string): string[] {
    const baseMethods = ['healthCheck'];

    switch (serviceType) {
      case 'knowledge':
        return [...baseMethods, 'store', 'get', 'update', 'delete', 'search', 'list', 'count'];
      case 'orchestrator':
      case 'store':
        return [...baseMethods, 'storeItems', 'getBatchStorageStatus', 'cancelBatchOperation'];
      case 'find':
        return [...baseMethods, 'findItems', 'findSimilarItems', 'getFindMetrics'];
      default:
        return baseMethods;
    }
  }

  /**
   * Determine if method should return ServiceResponse
   */
  private static shouldReturnServiceResponse(methodName: string): boolean {
    const serviceResponseMethods = [
      'store', 'get', 'update', 'delete', 'search', 'list', 'count',
      'storeItems', 'findItems', 'findSimilarItems', 'getFindMetrics',
      'getBatchStorageStatus', 'cancelBatchOperation', 'healthCheck', 'getStatus'
    ];

    return serviceResponseMethods.includes(methodName);
  }

  /**
   * Calculate interface compliance score
   */
  private static calculateInterfaceCompliance(result: ServiceValidationResult): number {
    const totalChecks = 3; // healthCheck, getStatus, required methods
    const passedChecks = totalChecks - result.errors.filter(e =>
      e.includes('Missing required method') || e.includes('healthCheck') || e.includes('getStatus')
    ).length;

    return Math.round((passedChecks / totalChecks) * 100);
  }

  /**
   * Calculate type safety score
   */
  private static calculateTypeSafetyScore(result: ServiceValidationResult): number {
    // Type safety is harder to quantify automatically
    // Base score reduced by warnings and errors
    let score = 100;
    score -= result.errors.length * 20;
    score -= result.warnings.length * 5;

    return Math.max(0, score);
  }

  /**
   * Calculate response format compliance score
   */
  private static calculateResponseFormatCompliance(result: ServiceValidationResult): number {
    const responseErrors = result.errors.filter(e =>
      e.includes('invalid ServiceResponse format') || e.includes('returns invalid response format')
    );

    const totalTests = 2; // healthCheck and getStatus
    const passedTests = totalTests - responseErrors.length;

    return Math.round((passedTests / totalTests) * 100);
  }
}

/**
 * Service integration test runner
 */
export class ServiceIntegrationTestRunner {
  /**
   * Run comprehensive integration tests
   */
  static async runIntegrationTests(
    services: Array<{ service: IBaseService; type: 'knowledge' | 'orchestrator' | 'find' | 'store' | 'general' }>
  ): Promise<{
    summary: {
      totalServices: number;
      validServices: number;
      invalidServices: number;
      averageCompliance: number;
    };
    results: ServiceValidationResult[];
  }> {
    const results = await ServiceIntegrationValidator.validateServices(services);

    const validServices = results.filter(r => r.valid).length;
    const invalidServices = results.length - validServices;
    const averageCompliance = Math.round(
      results.reduce((sum, r) => sum + r.metrics.interfaceCompliance, 0) / results.length
    );

    const summary = {
      totalServices: results.length,
      validServices,
      invalidServices,
      averageCompliance,
    };

    logger.info(
      {
        summary,
        results: results.map(r => ({
          serviceName: r.serviceName,
          valid: r.valid,
          errors: r.errors.length,
          warnings: r.warnings.length,
          metrics: r.metrics,
        })),
      },
      'Service integration tests completed'
    );

    return { summary, results };
  }

  /**
   * Generate validation report
   */
  static generateReport(results: ServiceValidationResult[]): string {
    const lines: string[] = [];

    lines.push('# Service Integration Validation Report');
    lines.push(`Generated: ${new Date().toISOString()}`);
    lines.push('');

    const totalServices = results.length;
    const validServices = results.filter(r => r.valid).length;
    const invalidServices = totalServices - validServices;

    lines.push('## Summary');
    lines.push(`- Total Services: ${totalServices}`);
    lines.push(`- Valid Services: ${validServices}`);
    lines.push(`- Invalid Services: ${invalidServices}`);
    lines.push(`- Success Rate: ${Math.round((validServices / totalServices) * 100)}%`);
    lines.push('');

    lines.push('## Detailed Results');
    lines.push('');

    for (const result of results) {
      lines.push(`### ${result.serviceName}`);
      lines.push(`- Status: ${result.valid ? '✅ Valid' : '❌ Invalid'}`);
      lines.push(`- Interface Compliance: ${result.metrics.interfaceCompliance}%`);
      lines.push(`- Type Safety Score: ${result.metrics.typeSafetyScore}%`);
      lines.push(`- Response Format Compliance: ${result.metrics.responseFormatCompliance}%`);

      if (result.errors.length > 0) {
        lines.push('- Errors:');
        result.errors.forEach(error => lines.push(`  - ${error}`));
      }

      if (result.warnings.length > 0) {
        lines.push('- Warnings:');
        result.warnings.forEach(warning => lines.push(`  - ${warning}`));
      }

      lines.push('');
    }

    return lines.join('\n');
  }
}