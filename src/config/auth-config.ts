// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Authentication Configuration
 * Configuration constants and utilities for the authentication system
 *
 * Updated to use unified environment configuration system
 */

import { Environment } from './environment.js';

/**
 * Get authentication configuration from unified environment system
 */
export function getAuthConfig() {
  const _env = Environment.getInstance();
  const securityConfig = _env.getSecurityConfig();
  const apiConfig = _env.getApiConfig();

  return {
    // JWT configuration from unified environment
    JWT_SECRET: securityConfig.jwtSecret,
    JWT_REFRESH_SECRET: securityConfig.jwtRefreshSecret,
    JWT_EXPIRES_IN: '15m',
    JWT_REFRESH_EXPIRES_IN: '7d',

    // Security configuration
    ENCRYPTION_KEY: securityConfig.encryptionKey,
    BCRYPT_ROUNDS: 12,
    API_KEY_LENGTH: 32,
    SESSION_TIMEOUT_HOURS: 24,
    MAX_SESSIONS_PER_USER: 5,

    // Rate limiting from unified environment
    RATE_LIMIT_ENABLED: apiConfig.authEnabled,
    RATE_LIMIT_WINDOW_MS: 60 * 1000, // 1 minute
    RATE_LIMIT_MAX_REQUESTS: apiConfig.rateLimit,

    // Security settings
    PASSWORD_MIN_LENGTH: 12,
    PASSWORD_REQUIRE_UPPERCASE: true,
    PASSWORD_REQUIRE_LOWERCASE: true,
    PASSWORD_REQUIRE_NUMBERS: true,
    PASSWORD_REQUIRE_SYMBOLS: true,

    // Login attempt tracking
    MAX_LOGIN_ATTEMPTS: 5,
    LOGIN_ATTEMPT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    ACCOUNT_LOCKOUT_DURATION_MS: 30 * 60 * 1000, // 30 minutes
  };
}
