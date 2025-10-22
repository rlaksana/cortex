#!/usr/bin/env node
// Test service initialization specifically

import { config } from 'dotenv';
import { logger } from './dist/utils/logger.js';
import { loadEnv } from './dist/config/env.js';
import { AUTH_CONFIG } from './dist/config/auth-config.js';

// Load environment
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);
config();
console.log = originalConsoleLog;

loadEnv();

// Test service constructors one by one
console.error('Testing service constructors...');

try {
  console.error('Step 1: Importing AuthService...');
  const { AuthService } = await import('./dist/services/auth/auth-service.js');

  console.error('Step 2: Creating AuthService...');
  const authService = new AuthService({
    jwt_secret: AUTH_CONFIG.JWT_SECRET,
    jwt_refresh_secret: AUTH_CONFIG.JWT_REFRESH_SECRET,
    jwt_expires_in: AUTH_CONFIG.JWT_EXPIRES_IN,
    jwt_refresh_expires_in: AUTH_CONFIG.JWT_REFRESH_EXPIRES_IN,
    bcrypt_rounds: AUTH_CONFIG.BCRYPT_ROUNDS,
    api_key_length: AUTH_CONFIG.API_KEY_LENGTH,
    session_timeout_hours: AUTH_CONFIG.SESSION_TIMEOUT_HOURS,
    max_sessions_per_user: AUTH_CONFIG.MAX_SESSIONS_PER_USER,
    rate_limit_enabled: AUTH_CONFIG.RATE_LIMIT_ENABLED
  });
  console.error('Step 2: AuthService created successfully');

  console.error('Step 3: Creating AuthorizationService...');
  const { AuthorizationService } = await import('./dist/services/auth/authorization-service.js');
  const authorizationService = new AuthorizationService();
  console.error('Step 3: AuthorizationService created successfully');

  console.error('Step 4: Creating AuditService...');
  const { AuditService } = await import('./dist/services/audit/audit-service.js');
  const auditService = new AuditService();
  console.error('Step 4: AuditService created successfully');

  console.error('Step 5: Creating ApiKeyService...');
  const { ApiKeyService } = await import('./dist/services/auth/api-key-service.js');
  const apiKeyService = new ApiKeyService(authService, auditService);
  console.error('Step 5: ApiKeyService created successfully');

  console.error('Step 6: Creating MCPAuthHelper...');
  const { MCPAuthHelper } = await import('./dist/services/auth/auth-middleware-helper.js');
  const authHelper = new MCPAuthHelper(authService, authorizationService, auditService);
  console.error('Step 6: MCPAuthHelper created successfully');

  console.error('All services created successfully!');

} catch (error) {
  console.error('Service creation failed:', error);
  process.exit(1);
}