/**
 * Standardized Authentication Service
 *
 * Refactored authentication service that uses the standardized database layer
 * instead of direct Qdrant access. Follows the service layer patterns established
 * in the codebase for consistency and maintainability.
 *
 * Key improvements:
 * - Uses DatabaseManager interface instead of direct Qdrant access
 * - Consistent error handling and logging
 * - Standardized service patterns
 * - Better testability and modularity
 * - Circuit breaker pattern for database failures
 */

import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'node:crypto';
import { logger } from '../../utils/logger.js';
import type { DatabaseManager } from '../../db/database-manager.js';
import {
  ConfigurationError,
  AuthenticationError,
  ValidationError,
  ErrorCategory,
} from '../../utils/error-handler.js';
import {
  User,
  ApiKey,
  AuthToken,
  TokenPayload,
  AuthSession,
  UserRole,
  AuthScope,
  AuthContext,
  DEFAULT_ROLE_PERMISSIONS,
} from '../../types/auth-types.js';

export interface AuthServiceConfig {
  jwt_secret: string;
  jwt_refresh_secret: string;
  jwt_expires_in: string;
  jwt_refresh_expires_in: string;
  bcrypt_rounds: number;
  api_key_length: number;
  session_timeout_hours: number;
  max_sessions_per_user: number;
  rate_limit_enabled: boolean;
  token_blacklist_backup_path?: string;
}

interface SecurityEvent {
  type: string;
  jti?: string;
  userId?: string;
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, any>;
}

interface DatabaseUser {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  role: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
  last_login?: Date;
}

export class StandardizedAuthService {
  private config: AuthServiceConfig;
  private databaseManager: DatabaseManager;
  private tokenBlacklist: Set<string> = new Set();
  private tokenBlacklistCache: Map<string, { revoked: boolean; timestamp: number }> = new Map();
  private activeSessions: Map<string, AuthSession> = new Map();
  private databaseCircuitBreaker: {
    isOpen: boolean;
    failureCount: number;
    lastFailureTime: number;
    recoveryTimeout: number;
  } = {
    isOpen: false,
    failureCount: 0,
    lastFailureTime: 0,
    recoveryTimeout: 60000,
  };

  constructor(databaseManager: DatabaseManager, config: AuthServiceConfig) {
    this.databaseManager = databaseManager;
    this.config = config;
    this.validateConfig();
    this.loadTokenBlacklistFromBackup();
    this.startSessionCleanup();
  }

  private validateConfig(): void {
    if (!this.config.jwt_secret || this.config.jwt_secret.length < 32) {
      throw new ConfigurationError(
        'JWT_SECRET must be at least 32 characters long',
        'Invalid JWT secret configuration',
        { secretLength: this.config.jwt_secret?.length || 0 }
      );
    }
    if (!this.config.jwt_refresh_secret || this.config.jwt_refresh_secret.length < 32) {
      throw new ConfigurationError(
        'JWT_REFRESH_SECRET must be at least 32 characters long',
        'Invalid JWT refresh secret configuration',
        { secretLength: this.config.jwt_refresh_secret?.length || 0 }
      );
    }
  }

  // Password operations
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.config.bcrypt_rounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Database-backed user authentication using standardized database layer
   */
  async validateUserWithDatabase(username: string, password: string): Promise<User | null> {
    try {
      // Validate input
      if (!username || !password) {
        throw new ValidationError(
          'Username and password are required',
          'Please provide both username and password',
          { username: !!username, password: !!password }
        );
      }

      // Check circuit breaker
      if (this.databaseCircuitBreaker.isOpen) {
        logger.warn({ username }, 'Database circuit breaker is open');
        return null;
      }

      // Fetch user from database using standardized interface
      const userRecord = await this.databaseManager.findOne('users', {
        where: { username },
        select: {
          id: true,
          username: true,
          email: true,
          password_hash: true,
          role: true,
          is_active: true,
          created_at: true,
          updated_at: true,
          last_login: true,
        },
      });

      if (!userRecord) {
        logger.warn({ username }, 'User not found in database');
        return null;
      }

      // Check if user account is active
      if (!userRecord.is_active) {
        throw new AuthenticationError(
          `User account ${username} is inactive`,
          'Account is disabled',
          { userId: userRecord.id, username }
        );
      }

      // Verify password
      const isValidPassword = await this.verifyPassword(password, userRecord.password_hash);
      if (!isValidPassword) {
        throw new AuthenticationError(
          'Invalid password provided',
          'Invalid username or password',
          { userId: userRecord.id, username }
        );
      }

      // Update last login timestamp
      await this.databaseManager.updateOne('users', userRecord.id, {
        last_login: new Date(),
      });

      // Convert database user to User interface
      const user: User = {
        id: userRecord.id,
        username: userRecord.username,
        email: userRecord.email,
        password_hash: userRecord.password_hash,
        role: userRecord.role as UserRole,
        is_active: userRecord.is_active,
        created_at: userRecord.created_at.toISOString(),
        updated_at: userRecord.updated_at.toISOString(),
      };

      if (userRecord.last_login) {
        user.last_login = userRecord.last_login.toISOString();
      }

      logger.info(
        {
          userId: user.id,
          username: user.username,
          role: user.role,
        },
        'User authenticated successfully via database'
      );

      // Reset circuit breaker on success
      this.databaseCircuitBreaker.failureCount = 0;

      return user;
    } catch (error) {
      if (error instanceof AuthenticationError || error instanceof ValidationError) {
        throw error;
      }

      // Handle database failure
      this.handleDatabaseFailure(error instanceof Error ? error : new Error(String(error)));
      logger.error({ error, username }, 'Database user validation failed');
      return null;
    }
  }

  // JWT token operations
  generateAccessToken(user: User, sessionId: string, scopes: AuthScope[]): string {
    const payload: TokenPayload = {
      sub: user.id,
      username: user.username,
      role: user.role,
      scopes,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.parseExpiration(this.config.jwt_expires_in),
      jti: crypto.randomUUID(),
      session_id: sessionId,
    };

    return jwt.sign(payload, this.config.jwt_secret, {
      algorithm: 'HS256',
      issuer: 'cortex-mcp',
      audience: 'cortex-client',
    });
  }

  generateRefreshToken(user: User, sessionId: string): string {
    const payload = {
      sub: user.id,
      session_id: sessionId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.parseExpiration(this.config.jwt_refresh_expires_in),
      jti: crypto.randomUUID(),
    };

    return jwt.sign(payload, this.config.jwt_refresh_secret, {
      algorithm: 'HS256',
      issuer: 'cortex-mcp',
    });
  }

  async verifyAccessToken(token: string): Promise<TokenPayload> {
    try {
      const decoded = jwt.verify(token, this.config.jwt_secret, {
        algorithms: ['HS256'],
        issuer: 'cortex-mcp',
        audience: 'cortex-client',
      }) as TokenPayload;

      const isRevoked = await this.checkTokenRevocationWithFailSafe(decoded.jti);

      if (isRevoked) {
        logger.warn(
          {
            jti: decoded.jti,
            userId: decoded.sub,
            username: decoded.username,
            reason: 'token_revoked',
          },
          'Access denied: Token has been revoked'
        );

        await this.storeSecurityEvent({
          type: 'revoked_token_access_attempt',
          jti: decoded.jti,
          userId: decoded.sub,
          timestamp: new Date(),
          severity: 'high',
        }).catch((err) => logger.error({ err }, 'Failed to store security event'));

        throw new Error('TOKEN_REVOKED');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('EXPIRED_TOKEN');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('INVALID_TOKEN');
      } else if (error instanceof Error && error.message === 'TOKEN_REVOKED') {
        throw error;
      } else {
        logger.error(
          {
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
            context: 'token_verification',
          },
          'Unexpected error during token verification'
        );
        throw new Error('TOKEN_VERIFICATION_FAILED');
      }
    }
  }

  /**
   * Fail-safe token revocation check using standardized database layer
   */
  private async checkTokenRevocationWithFailSafe(jti: string): Promise<boolean> {
    const now = Date.now();

    // Layer 1: Enhanced in-memory cache
    const cached = this.tokenBlacklistCache.get(jti);
    if (cached) {
      if (now - cached.timestamp < 5 * 60 * 1000) {
        return cached.revoked;
      } else {
        this.tokenBlacklistCache.delete(jti);
        this.tokenBlacklist.delete(jti);
      }
    }

    // Layer 2: Check circuit breaker
    if (this.databaseCircuitBreaker.isOpen) {
      if (
        now - this.databaseCircuitBreaker.lastFailureTime >
        this.databaseCircuitBreaker.recoveryTimeout
      ) {
        this.databaseCircuitBreaker.isOpen = false;
        this.databaseCircuitBreaker.failureCount = 0;
        logger.info('Database circuit breaker attempting recovery');
      } else {
        logger.warn({ jti }, 'Database circuit breaker open - defaulting to secure verification');
        this.tokenBlacklistCache.set(jti, { revoked: true, timestamp: now });
        this.tokenBlacklist.add(jti);
        return true;
      }
    }

    // Layer 3: Database check using standardized interface
    try {
      const revokedToken = await this.databaseManager.findOne('tokenRevocationList', {
        where: {
          jti,
          expires_at: { gt: new Date() },
        },
      });

      const isRevoked = !!revokedToken;

      this.tokenBlacklistCache.set(jti, { revoked: isRevoked, timestamp: now });
      if (isRevoked) {
        this.tokenBlacklist.add(jti);
      }

      this.databaseCircuitBreaker.failureCount = 0;
      return isRevoked;
    } catch (dbError) {
      this.handleDatabaseFailure(dbError instanceof Error ? dbError : new Error(String(dbError)));
      logger.error({ jti, error: dbError }, 'Database token revocation check failed');

      this.tokenBlacklistCache.set(jti, { revoked: true, timestamp: now });
      this.tokenBlacklist.add(jti);
      return true;
    }
  }

  /**
   * Handle database failures and manage circuit breaker
   */
  private handleDatabaseFailure(error: Error): void {
    this.databaseCircuitBreaker.failureCount++;
    this.databaseCircuitBreaker.lastFailureTime = Date.now();

    if (this.databaseCircuitBreaker.failureCount >= 3) {
      this.databaseCircuitBreaker.isOpen = true;
      logger.error(
        {
          failureCount: this.databaseCircuitBreaker.failureCount,
          error: error.message,
        },
        'Database circuit breaker opened due to consecutive failures'
      );
    }
  }

  async revokeToken(jti: string, reason?: string): Promise<void> {
    const now = Date.now();

    // Layer 1: Add to in-memory cache
    this.tokenBlacklist.add(jti);
    this.tokenBlacklistCache.set(jti, { revoked: true, timestamp: now });

    // Layer 2: Persist to backup storage
    await this.persistTokenRevocationToBackup(jti, now);

    // Layer 3: Persist to database using standardized interface
    let databasePersisted = false;
    try {
      await this.databaseManager.createOne('tokenRevocationList', {
        jti,
        revoked_at: new Date(),
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        reason: reason || 'manual_revocation',
      });
      databasePersisted = true;
    } catch (error) {
      logger.error({ jti, error }, 'Failed to persist token revocation to database');
    }

    logger.info(
      {
        jti,
        reason,
        databasePersisted,
        timestamp: new Date(now).toISOString(),
      },
      'Token revoked with multi-layer persistence'
    );

    await this.storeSecurityEvent({
      type: 'token_revoked',
      jti,
      timestamp: new Date(now),
      severity: reason?.includes('security') ? 'high' : 'medium',
      metadata: {
        reason,
        databasePersisted,
        layers: ['memory', 'backup', databasePersisted ? 'database' : 'database_failed'],
      },
    }).catch((err) => logger.error({ err }, 'Failed to store token revocation security event'));
  }

  /**
   * Store security event using standardized database interface
   */
  private async storeSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      await this.databaseManager.createOne('securityEvents', {
        type: event.type,
        jti: event.jti,
        user_id: event.userId,
        timestamp: event.timestamp,
        severity: event.severity,
        metadata: event.metadata || {},
      });
    } catch (error) {
      logger.warn({ event, error }, 'Failed to store security event in database');
      // Fallback to file storage could be implemented here
    }
  }

  // Session management
  createSession(user: User, ipAddress: string, userAgent: string): AuthSession {
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + this.config.session_timeout_hours * 60 * 60 * 1000);

    this.cleanupUserSessions(user.id);

    const session: AuthSession = {
      id: sessionId,
      user_id: user.id,
      session_token: sessionId,
      ip_address: ipAddress,
      user_agent: userAgent,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
      is_active: true,
    };

    this.activeSessions.set(sessionId, session);
    return session;
  }

  getSession(sessionId: string): AuthSession | null {
    const session = this.activeSessions.get(sessionId);
    if (!session || !session.is_active) {
      return null;
    }

    if (new Date() > new Date(session.expires_at)) {
      this.activeSessions.delete(sessionId);
      return null;
    }

    return session;
  }

  revokeSession(sessionId: string): void {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.is_active = false;
      this.activeSessions.delete(sessionId);
      logger.info({ sessionId, userId: session.user_id }, 'Session revoked');
    }
  }

  private cleanupUserSessions(userId: string): void {
    const userSessions = Array.from(this.activeSessions.entries()).filter(
      ([_, session]) => session.user_id === userId
    );

    if (userSessions.length >= this.config.max_sessions_per_user) {
      const sortedSessions = userSessions.sort(
        (a, b) => new Date(b[1].created_at).getTime() - new Date(a[1].created_at).getTime()
      );

      const sessionsToRemove = sortedSessions.slice(this.config.max_sessions_per_user);
      sessionsToRemove.forEach(([sessionId]) => {
        this.revokeSession(sessionId);
      });
    }
  }

  private startSessionCleanup(): void {
    setInterval(
      async () => {
        const now = Date.now();
        const nowDate = new Date(now);

        // Clean up expired sessions
        for (const [sessionId, session] of Array.from(this.activeSessions.entries())) {
          if (nowDate > new Date(session.expires_at)) {
            this.activeSessions.delete(sessionId);
          }
        }

        // Clean up expired token revocations
        const expiryMs = 7 * 24 * 60 * 60 * 1000;
        let cacheCleanupCount = 0;

        for (const [jti, entry] of Array.from(this.tokenBlacklistCache.entries())) {
          if (now - entry.timestamp > expiryMs) {
            this.tokenBlacklistCache.delete(jti);
            this.tokenBlacklist.delete(jti);
            cacheCleanupCount++;
          }
        }

        if (cacheCleanupCount > 0) {
          logger.debug({ cacheCleanupCount }, 'Cleaned up expired entries from token blacklist cache');
        }

        // Clean up expired token revocations from database
        try {
          await this.databaseManager.deleteMany('tokenRevocationList', {
            where: { expires_at: { lt: nowDate } },
          });
        } catch (error) {
          logger.error({ error }, 'Failed to cleanup expired token revocations from database');
        }

        // Circuit breaker recovery attempt
        if (
          this.databaseCircuitBreaker.isOpen &&
          now - this.databaseCircuitBreaker.lastFailureTime > this.databaseCircuitBreaker.recoveryTimeout
        ) {
          try {
            await this.databaseManager.findOne('tokenRevocationList', {
              where: { jti: 'circuit-breaker-test' },
            });

            this.databaseCircuitBreaker.isOpen = false;
            this.databaseCircuitBreaker.failureCount = 0;
            logger.info('Database circuit breaker recovered - connection restored');
          } catch (error) {
            this.databaseCircuitBreaker.lastFailureTime = now;
            logger.debug(
              { error: error instanceof Error ? error.message : String(error) },
              'Database circuit breaker test failed, keeping open'
            );
          }
        }
      },
      5 * 60 * 1000
    );
  }

  /**
   * Load token blacklist from backup storage
   */
  private async loadTokenBlacklistFromBackup(): Promise<void> {
    if (!this.config.token_blacklist_backup_path) {
      return;
    }

    try {
      const fs = await import('fs/promises');
      const path = await import('path');

      const backupFile = path.join(
        this.config.token_blacklist_backup_path,
        'token-blacklist-backup.json'
      );

      const data = await fs.readFile(backupFile, 'utf-8');
      const backup: Record<string, number> = JSON.parse(data);

      const now = Date.now();
      const expiryMs = 7 * 24 * 60 * 60 * 1000;
      let loadedCount = 0;
      let expiredCount = 0;

      for (const [jti, timestamp] of Object.entries(backup)) {
        if (now - timestamp < expiryMs) {
          this.tokenBlacklist.add(jti);
          this.tokenBlacklistCache.set(jti, { revoked: true, timestamp });
          loadedCount++;
        } else {
          expiredCount++;
        }
      }

      logger.info(
        {
          backupFile,
          loadedCount,
          expiredCount,
          totalEntries: Object.keys(backup).length,
        },
        'Token blacklist loaded from backup storage'
      );
    } catch (error) {
      logger.info(
        {
          error: error instanceof Error ? error.message : String(error),
          backupPath: this.config.token_blacklist_backup_path,
        },
        'No backup token blacklist found or failed to load, starting fresh'
      );
    }
  }

  /**
   * Persist token revocation to backup storage
   */
  private async persistTokenRevocationToBackup(jti: string, timestamp: number): Promise<void> {
    if (!this.config.token_blacklist_backup_path) {
      return;
    }

    try {
      const fs = await import('fs/promises');
      const path = await import('path');

      const backupFile = path.join(
        this.config.token_blacklist_backup_path,
        'token-blacklist-backup.json'
      );

      await fs.mkdir(path.dirname(backupFile), { recursive: true });

      let backup: Record<string, number> = {};
      try {
        const data = await fs.readFile(backupFile, 'utf-8');
        backup = JSON.parse(data);
      } catch {
        backup = {};
      }

      backup[jti] = timestamp;

      const tempFile = `${backupFile}.tmp`;
      await fs.writeFile(tempFile, JSON.stringify(backup, null, 2));
      await fs.rename(tempFile, backupFile);

      logger.debug({ jti, backupFile }, 'Token revocation persisted to backup storage');
    } catch (error) {
      logger.error(
        {
          jti,
          error: error instanceof Error ? error.message : String(error),
          backupPath: this.config.token_blacklist_backup_path,
        },
        'Failed to persist token revocation to backup storage'
      );
    }
  }

  // Utility methods
  private parseExpiration(expiration: string): number {
    const match = expiration.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid expiration format: ${expiration}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 24 * 60 * 60;
      default:
        throw new Error(`Invalid time unit: ${unit}`);
    }
  }

  // Health check
  getHealthStatus(): { status: 'healthy' | 'degraded'; details: any } {
    const now = Date.now();
    const expiredSessions = Array.from(this.activeSessions.values()).filter(
      (session) => new Date(session.expires_at) < new Date(now)
    ).length;

    const details = {
      active_sessions: this.activeSessions.size,
      expired_sessions: expiredSessions,
      blacklisted_tokens: this.tokenBlacklist.size,
      enhanced_cache_size: this.tokenBlacklistCache.size,
      circuit_breaker_open: this.databaseCircuitBreaker.isOpen,
      database_failures: this.databaseCircuitBreaker.failureCount,
    };

    const isDegraded =
      expiredSessions > 100 ||
      this.databaseCircuitBreaker.isOpen;

    return {
      status: isDegraded ? 'degraded' : 'healthy',
      details,
    };
  }
}

// Export factory function
export function createStandardizedAuthService(
  databaseManager: DatabaseManager,
  config: AuthServiceConfig
): StandardizedAuthService {
  return new StandardizedAuthService(databaseManager, config);
}