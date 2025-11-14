/**
 * MCP Response Envelope System - Index
 *
 * Centralized exports for the MCP response envelope system.
 * This provides a single entry point for all envelope-related types,
 * utilities, and validators.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

// Core envelope types
export type {
  BaseResponseEnvelope,
  ErrorEnvelope,
  PaginatedEnvelope,
  ResponseEnvelope,
  StreamingEnvelope,
  SuccessEnvelope} from './response-envelope.types';
export type {
  ExtractErrorData,
  ExtractPaginatedData,
  ExtractSuccessData} from './response-envelope.types';

// Response data types
export type {
  DatabaseErrorDetails,
  MemoryFindResult,
  MemoryStoreResult,
  RateLimitErrorDetails,
  SystemStatusResult,
  ValidationErrorDetails} from './mcp-response-data.types';

// Type guards
export {
  isErrorEnvelope,
  isPaginatedEnvelope,
  isStreamingEnvelope,
  isSuccessEnvelope} from './response-envelope.types';

// Response builders
export {
  ErrorCode,
  ResponseEnvelopeBuilder} from '../utils/response-envelope-builder';
export {
  createResponseEnvelopeBuilder,
  extractErrorInfo,
  extractSuccessData,
  isErrorResponse,
  isSuccessfulResponse} from '../utils/response-envelope-builder';

// Response validators
export type {
  ValidationResult
} from '../utils/response-envelope-validator';
export {
  ResponseEnvelopeValidator
} from '../utils/response-envelope-validator';
export {
  validateEnvelopeOrThrow,
  validateOperationResponseOrThrow
} from '../utils/response-envelope-validator';

// Response type guards
export {
  createResponseMatcher,
  extractDatabaseErrorDetails,
  extractMemoryFindData,
  extractMemoryStoreData,
  extractRateLimitErrorDetails,
  extractSystemStatusData,
  extractValidationErrorDetails,
  getOperationStatus,
  isDatabaseErrorResponse,
  isMemoryFindResponse,
  isMemoryStoreResponse,
  isOperationFailed,
  isOperationSuccessful,
  isRateLimitErrorResponse,
  isSystemStatusResponse,
  isValidationErrorResponse,
  ResponseProcessor,
  safeExtractResponseData} from '../utils/mcp-response-guards';

// Re-export unified response interface for compatibility
export type {
  SearchStrategy,
  UnifiedResponseMeta,
  UnifiedToolResponse} from './unified-response.interface';
export {
  createMcpResponse,
  createResponseMeta} from './unified-response.interface';