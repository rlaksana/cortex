/**
 * Middleware Module Index for Cortex MCP
 * Exports all middleware components
 */

export { AuthMiddleware, AuthenticatedRequest } from './auth-middleware.js';
export { SecurityMiddleware, securityMiddleware, commonSchemas } from './security-middleware.js';

export type {
  AuthContext,
  AuthError,
  AuthMiddlewareConfig,
  AuthScope,
  SecurityAuditLog,
  UserRole,
} from '../types/auth-types.js';

export type { SecurityConfig, ValidationError } from './security-middleware.js';
