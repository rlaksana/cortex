/**
 * Authentication Service for Cortex MCP
 * Implements JWT-based authentication with RBAC and scope-based authorization
 */

import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { logger } from '../../utils/logger.js';
import { qdrant } from '../../db/qdrant-client.js';
import {
  ConfigurationError,
  AuthenticationError,
  ValidationError,
  ServiceErrorHandler,
  AsyncErrorHandler
} from '../../middleware/error-middleware.js';
import { BaseError, ErrorCode, ErrorCategory, ErrorSeverity } from '../../utils/error-handler.js';
import {
  User,
  ApiKey,
  AuthToken,
  TokenPayload,
  AuthSession,
  UserRole,
  AuthScope,
  AuthContext,
  AuthError,
  TokenRevocationList,
  DEFAULT_ROLE_PERMISSIONS
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
  token_blacklist_backup_path?: string; // Optional backup path for token blacklist
}

interface SecurityEvent {
  type: string;
  jti?: string;
  userId?: string;
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, any>;
}

export class AuthService {
  private config: AuthServiceConfig;
  private tokenBlacklist: Set<string> = new Set(); // In-memory cache for performance
  private tokenBlacklistCache: Map<string, { revoked: boolean; timestamp: number }> = new Map(); // Enhanced cache with metadata
  private activeSessions: Map<string, AuthSession> = new Map();
  private databaseCircuitBreaker: { isOpen: boolean; failureCount: number; lastFailureTime: number; recoveryTimeout: number } = {
    isOpen: false,
    failureCount: 0,
    lastFailureTime: 0,
    recoveryTimeout: 60000 // 1 minute recovery timeout
  };
  private distributedSync: { lastSyncTime: number; syncInterval: number; instanceId: string } = {
    lastSyncTime: 0,
    syncInterval: 30000, // 30 seconds
    instanceId: crypto.randomUUID()
  };

  constructor(config: AuthServiceConfig) {
    this.config = config;
    this.validateConfig();
    this.loadTokenBlacklistFromBackup();
    this.startSessionCleanup();
    this.startDistributedSync();
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
   * Database-backed user authentication
   */
  async validateUserWithDatabase(username: string, password: string): Promise<User | null> {
    return ServiceErrorHandler.wrapServiceMethod(
      'validateUserWithDatabase',
      async () => {
        // Validate input
        if (!username || !password) {
          throw new ValidationError(
            'Username and password are required',
            'Please provide both username and password',
            { username: !!username, password: !!password }
          );
        }

        // Fetch user from database
        const userRecord = await AsyncErrorHandler.retry(
          () => qdrant.getClient().user.findUnique({
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
              last_login: true
            }
          }),
          {
            maxAttempts: 3,
            context: { operation: 'findUser', username }
          }
        );

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
        await AsyncErrorHandler.retry(
          () => qdrant.getClient().user.update({
            where: { id: userRecord.id },
            data: { last_login: new Date() }
          }),
          {
            maxAttempts: 2,
            context: { operation: 'updateLastLogin', userId: userRecord.id }
          }
        );

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
          last_login: userRecord.last_login?.toISOString()
        };

        logger.info({
          userId: user.id,
          username: user.username,
          role: user.role
        }, 'User authenticated successfully via database');

        return user;
      },
      {
        category: ErrorCategory.AUTHENTICATION,
        fallback: () => null
      }
    );
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
      session_id: sessionId
    };

    return jwt.sign(payload, this.config.jwt_secret, {
      algorithm: 'HS256',
      issuer: 'cortex-mcp',
      audience: 'cortex-client'
    });
  }

  generateRefreshToken(user: User, sessionId: string): string {
    const payload = {
      sub: user.id,
      session_id: sessionId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + this.parseExpiration(this.config.jwt_refresh_expires_in),
      jti: crypto.randomUUID()
    };

    return jwt.sign(payload, this.config.jwt_refresh_secret, {
      algorithm: 'HS256',
      issuer: 'cortex-mcp'
    });
  }

  async verifyAccessToken(token: string): Promise<TokenPayload> {
    try {
      const decoded = jwt.verify(token, this.config.jwt_secret, {
        algorithms: ['HS256'],
        issuer: 'cortex-mcp',
        audience: 'cortex-client'
      }) as TokenPayload;

      // Multi-layered token revocation check with fail-safe defaults
      const isRevoked = await this.checkTokenRevocationWithFailSafe(decoded.jti);

      if (isRevoked) {
        // Audit log for security monitoring
        logger.warn({
          jti: decoded.jti,
          userId: decoded.sub,
          username: decoded.username,
          reason: 'token_revoked'
        }, 'Access denied: Token has been revoked');

        // Store security event
        await this.storeSecurityEvent({
          type: 'revoked_token_access_attempt',
          jti: decoded.jti,
          userId: decoded.sub,
          timestamp: new Date(),
          severity: 'high'
        }).catch(err => logger.error({ err }, 'Failed to store security event'));

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
        // Log unexpected errors for security monitoring
        logger.error({
          error: error.message,
          stack: error.stack,
          context: 'token_verification'
        }, 'Unexpected error during token verification');
        throw new Error('TOKEN_VERIFICATION_FAILED');
      }
    }
  }

  /**
   * Fail-safe token revocation check with multiple persistence layers
   * Defaults to SECURE behavior (returns true for revoked) when any layer is unavailable
   */
  private async checkTokenRevocationWithFailSafe(jti: string): Promise<boolean> {
    const now = Date.now();

    // Layer 1: Enhanced in-memory cache with metadata
    const cached = this.tokenBlacklistCache.get(jti);
    if (cached) {
      // Cache entry is valid for 5 minutes
      if (now - cached.timestamp < 5 * 60 * 1000) {
        return cached.revoked;
      } else {
        // Expired cache entry, remove it
        this.tokenBlacklistCache.delete(jti);
        this.tokenBlacklist.delete(jti);
      }
    }

    // Layer 2: Check circuit breaker status
    if (this.databaseCircuitBreaker.isOpen) {
      if (now - this.databaseCircuitBreaker.lastFailureTime > this.databaseCircuitBreaker.recoveryTimeout) {
        // Attempt to close circuit breaker
        this.databaseCircuitBreaker.isOpen = false;
        this.databaseCircuitBreaker.failureCount = 0;
        logger.info('Database circuit breaker attempting recovery');
      } else {
        // Circuit breaker is still open - default to secure behavior
        logger.warn({ jti }, 'Database circuit breaker open - defaulting to secure token verification');

        // Store temporary revocation entry
        this.tokenBlacklistCache.set(jti, {
          revoked: true,
          timestamp: now
        });
        this.tokenBlacklist.add(jti);

        return true;
      }
    }

    // Layer 3: Database check with exponential backoff retry
    try {
      const isRevoked = await this.checkDatabaseTokenRevocationWithRetry(jti);

      // Cache the result
      this.tokenBlacklistCache.set(jti, {
        revoked: isRevoked,
        timestamp: now
      });

      if (isRevoked) {
        this.tokenBlacklist.add(jti);
      }

      // Reset circuit breaker on success
      this.databaseCircuitBreaker.failureCount = 0;

      return isRevoked;

    } catch (dbError) {
      // Handle database failure with fail-safe default
      this.handleDatabaseFailure(dbError);

      logger.error({
        jti,
        error: dbError.message,
        circuitBreakerOpen: this.databaseCircuitBreaker.isOpen
      }, 'Database token revocation check failed - applying fail-safe security');

      // FAIL-SAFE: When database is unavailable, assume token might be revoked
      // This is the critical security fix - default to secure behavior
      this.tokenBlacklistCache.set(jti, {
        revoked: true,
        timestamp: now
      });
      this.tokenBlacklist.add(jti);

      return true;
    }
  }

  /**
   * Database token revocation check with exponential backoff retry
   */
  private async checkDatabaseTokenRevocationWithRetry(jti: string, attempt: number = 1): Promise<boolean> {
    const maxAttempts = 3;
    const baseDelay = 100; // 100ms base delay

    try {
      const revokedToken = await qdrant.getClient().tokenRevocationList.findFirst({
        where: {
          jti: jti,
          expires_at: {
            gt: new Date()
          }
        }
      });

      return !!revokedToken;

    } catch (error) {
      if (attempt < maxAttempts) {
        const delay = baseDelay * Math.pow(2, attempt - 1); // Exponential backoff
        logger.warn({
          jti,
          attempt,
          maxAttempts,
          delay,
          error: error.message
        }, 'Database token revocation check failed, retrying...');

        await new Promise(resolve => setTimeout(resolve, delay));
        return this.checkDatabaseTokenRevocationWithRetry(jti, attempt + 1);
      }

      throw error;
    }
  }

  /**
   * Handle database failures and manage circuit breaker state
   */
  private handleDatabaseFailure(error: Error): void {
    this.databaseCircuitBreaker.failureCount++;
    this.databaseCircuitBreaker.lastFailureTime = Date.now();

    // Open circuit breaker after 3 consecutive failures
    if (this.databaseCircuitBreaker.failureCount >= 3) {
      this.databaseCircuitBreaker.isOpen = true;
      logger.error({
        failureCount: this.databaseCircuitBreaker.failureCount,
        error: error.message
      }, 'Database circuit breaker opened due to consecutive failures');
    }
  }

  verifyRefreshToken(token: string): any {
    try {
      return jwt.verify(token, this.config.jwt_refresh_secret, {
        algorithms: ['HS256'],
        issuer: 'cortex-mcp'
      });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('EXPIRED_REFRESH_TOKEN');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('INVALID_REFRESH_TOKEN');
      } else {
        throw error;
      }
    }
  }

  async revokeToken(jti: string, reason?: string): Promise<void> {
    const now = Date.now();

    // Layer 1: Add to in-memory cache for immediate effect
    this.tokenBlacklist.add(jti);
    this.tokenBlacklistCache.set(jti, {
      revoked: true,
      timestamp: now
    });

    // Layer 2: Persist to backup storage
    await this.persistTokenRevocationToBackup(jti, now);

    // Layer 3: Persist to database for distributed consistency with retry logic
    let databasePersisted = false;
    try {
      databasePersisted = await this.persistTokenRevocationToDatabaseWithRetry(jti, reason);
    } catch (error) {
      logger.error({ jti, error }, 'Failed to persist token revocation to database after retries');
    }

    // Log comprehensive audit trail
    logger.info({
      jti,
      reason,
      databasePersisted,
      timestamp: new Date(now).toISOString()
    }, 'Token revoked with multi-layer persistence');

    // Store security event for monitoring
    await this.storeSecurityEvent({
      type: 'token_revoked',
      jti,
      timestamp: new Date(now),
      severity: reason?.includes('security') ? 'high' : 'medium',
      metadata: {
        reason,
        databasePersisted,
        layers: ['memory', 'backup', databasePersisted ? 'database' : 'database_failed']
      }
    }).catch(err => logger.error({ err }, 'Failed to store token revocation security event'));
  }

  /**
   * Persist token revocation to database with exponential backoff retry
   */
  private async persistTokenRevocationToDatabaseWithRetry(jti: string, reason?: string, attempt: number = 1): Promise<boolean> {
    const maxAttempts = 3;
    const baseDelay = 200; // 200ms base delay

    try {
      await qdrant.getClient().tokenRevocationList.create({
        data: {
          jti,
          revoked_at: new Date(),
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          reason: reason || 'manual_revocation'
        }
      });

      return true;

    } catch (error) {
      if (attempt < maxAttempts) {
        const delay = baseDelay * Math.pow(2, attempt - 1); // Exponential backoff
        logger.warn({
          jti,
          attempt,
          maxAttempts,
          delay,
          error: error.message
        }, 'Database token revocation persistence failed, retrying...');

        await new Promise(resolve => setTimeout(resolve, delay));
        return this.persistTokenRevocationToDatabaseWithRetry(jti, reason, attempt + 1);
      }

      logger.error({
        jti,
        error: error.message,
        finalAttempt: attempt
      }, 'Failed to persist token revocation to database after all retries');

      throw error;
    }
  }

  /**
   * Persist token revocation to backup storage (filesystem)
   */
  private async persistTokenRevocationToBackup(jti: string, timestamp: number): Promise<void> {
    if (!this.config.token_blacklist_backup_path) {
      return; // Skip if no backup path configured
    }

    try {
      const fs = await import('fs/promises');
      const path = await import('path');

      const backupFile = path.join(this.config.token_blacklist_backup_path, 'token-blacklist-backup.json');

      // Ensure directory exists
      await fs.mkdir(path.dirname(backupFile), { recursive: true });

      // Read existing backup
      let backup: Record<string, number> = {};
      try {
        const data = await fs.readFile(backupFile, 'utf-8');
        backup = JSON.parse(data);
      } catch (error) {
        // File doesn't exist or is invalid, start fresh
        backup = {};
      }

      // Add revocation entry
      backup[jti] = timestamp;

      // Write backup atomically
      const tempFile = backupFile + '.tmp';
      await fs.writeFile(tempFile, JSON.stringify(backup, null, 2));
      await fs.rename(tempFile, backupFile);

      logger.debug({ jti, backupFile }, 'Token revocation persisted to backup storage');

    } catch (error) {
      logger.error({
        jti,
        error: error.message,
        backupPath: this.config.token_blacklist_backup_path
      }, 'Failed to persist token revocation to backup storage');
    }
  }

  /**
   * Load token blacklist from backup storage on startup
   */
  private async loadTokenBlacklistFromBackup(): Promise<void> {
    if (!this.config.token_blacklist_backup_path) {
      return; // Skip if no backup path configured
    }

    try {
      const fs = await import('fs/promises');
      const path = await import('path');

      const backupFile = path.join(this.config.token_blacklist_backup_path, 'token-blacklist-backup.json');

      const data = await fs.readFile(backupFile, 'utf-8');
      const backup: Record<string, number> = JSON.parse(data);

      const now = Date.now();
      const expiryMs = 7 * 24 * 60 * 60 * 1000; // 7 days
      let loadedCount = 0;
      let expiredCount = 0;

      for (const [jti, timestamp] of Object.entries(backup)) {
        if (now - timestamp < expiryMs) {
          this.tokenBlacklist.add(jti);
          this.tokenBlacklistCache.set(jti, {
            revoked: true,
            timestamp
          });
          loadedCount++;
        } else {
          expiredCount++;
        }
      }

      logger.info({
        backupFile,
        loadedCount,
        expiredCount,
        totalEntries: Object.keys(backup).length
      }, 'Token blacklist loaded from backup storage');

    } catch (error) {
      logger.info({
        error: error.message,
        backupPath: this.config.token_blacklist_backup_path
      }, 'No backup token blacklist found or failed to load, starting fresh');
    }
  }

  /**
   * Store security event for audit and monitoring
   */
  private async storeSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      // Store in database if available
      await qdrant.getClient().securityEvent.create({
        data: {
          type: event.type,
          jti: event.jti,
          user_id: event.userId,
          timestamp: event.timestamp,
          severity: event.severity,
          metadata: event.metadata || {}
        }
      });

    } catch (error) {
      // If database storage fails, log to file as fallback
      logger.warn({
        event,
        error: error.message
      }, 'Failed to store security event in database, logging to file');

      try {
        const fs = await import('fs/promises');
        const path = await import('path');

        const logFile = path.join(
          this.config.token_blacklist_backup_path || process.cwd(),
          'security-events.log'
        );

        const logEntry = {
          timestamp: event.timestamp.toISOString(),
          ...event
        };

        await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');

      } catch (fileError) {
        logger.error({ fileError }, 'Failed to write security event to file');
      }
    }
  }

  // Session management
  createSession(user: User, ipAddress: string, userAgent: string): AuthSession {
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + this.config.session_timeout_hours * 60 * 60 * 1000);

    // Clean up old sessions for this user
    this.cleanupUserSessions(user.id);

    const session: AuthSession = {
      id: sessionId,
      user_id: user.id,
      session_token: sessionId,
      ip_address: ipAddress,
      user_agent: userAgent,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
      is_active: true
    };

    this.activeSessions.set(sessionId, session);
    return session;
  }

  getSession(sessionId: string): AuthSession | null {
    const session = this.activeSessions.get(sessionId);
    if (!session || !session.is_active) {
      return null;
    }

    // Check if session has expired
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

  revokeAllUserSessions(userId: string): void {
    for (const [sessionId, session] of this.activeSessions) {
      if (session.user_id === userId) {
        this.revokeSession(sessionId);
      }
    }
  }

  private cleanupUserSessions(userId: string): void {
    const userSessions = Array.from(this.activeSessions.entries())
      .filter(([_, session]) => session.user_id === userId);

    // Keep only the most recent sessions up to the limit
    if (userSessions.length >= this.config.max_sessions_per_user) {
      const sortedSessions = userSessions.sort((a, b) =>
        new Date(b[1].created_at).getTime() - new Date(a[1].created_at).getTime()
      );

      const sessionsToRemove = sortedSessions.slice(this.config.max_sessions_per_user);
      sessionsToRemove.forEach(([sessionId]) => {
        this.revokeSession(sessionId);
      });
    }
  }

  private startSessionCleanup(): void {
    setInterval(async () => {
      const now = Date.now();
      const nowDate = new Date(now);

      // Clean up expired sessions
      for (const [sessionId, session] of this.activeSessions) {
        if (nowDate > new Date(session.expires_at)) {
          this.activeSessions.delete(sessionId);
        }
      }

      // Clean up expired token revocations from enhanced cache
      const expiryMs = 7 * 24 * 60 * 60 * 1000; // 7 days
      let cacheCleanupCount = 0;

      for (const [jti, entry] of this.tokenBlacklistCache.entries()) {
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
        const result = await qdrant.getClient().tokenRevocationList.deleteMany({
          where: {
            expires_at: {
              lt: nowDate
            }
          }
        });

        if (result.count > 0) {
          logger.info({ deletedCount: result.count }, 'Cleaned up expired token revocations from database');
        }

      } catch (error) {
        logger.error({ error }, 'Failed to cleanup expired token revocations from database');
      }

      // Clean up backup storage
      await this.cleanupBackupStorage(now);

      // Aggressive cache cleanup if memory usage is high
      if (this.tokenBlacklistCache.size > 10000) {
        // Keep only recent entries (last 1 hour)
        const oneHourMs = 60 * 60 * 1000;
        const beforeCount = this.tokenBlacklistCache.size;

        for (const [jti, entry] of this.tokenBlacklistCache.entries()) {
          if (now - entry.timestamp > oneHourMs) {
            this.tokenBlacklistCache.delete(jti);
            this.tokenBlacklist.delete(jti);
          }
        }

        const afterCount = this.tokenBlacklistCache.size;
        logger.info({
          beforeCount,
          afterCount,
          clearedCount: beforeCount - afterCount
        }, 'Performed aggressive token blacklist cache cleanup');
      }

      // Circuit breaker recovery attempt
      if (this.databaseCircuitBreaker.isOpen &&
          now - this.databaseCircuitBreaker.lastFailureTime > this.databaseCircuitBreaker.recoveryTimeout) {

        // Test database connection
        try {
          await qdrant.getClient().tokenRevocationList.findFirst({
            where: { jti: 'circuit-breaker-test' }
          });

          this.databaseCircuitBreaker.isOpen = false;
          this.databaseCircuitBreaker.failureCount = 0;
          logger.info('Database circuit breaker recovered - connection restored');

        } catch (error) {
          this.databaseCircuitBreaker.lastFailureTime = now;
          logger.debug({ error: error.message }, 'Database circuit breaker test failed, keeping open');
        }
      }

    }, 5 * 60 * 1000); // Clean up every 5 minutes
  }

  /**
   * Clean up expired entries from backup storage
   */
  private async cleanupBackupStorage(now: number): Promise<void> {
    if (!this.config.token_blacklist_backup_path) {
      return;
    }

    try {
      const fs = await import('fs/promises');
      const path = await import('path');

      const backupFile = path.join(this.config.token_blacklist_backup_path, 'token-blacklist-backup.json');

      try {
        const data = await fs.readFile(backupFile, 'utf-8');
        const backup: Record<string, number> = JSON.parse(data);

        const expiryMs = 7 * 24 * 60 * 60 * 1000; // 7 days
        const cleanedBackup: Record<string, number> = {};
        let removedCount = 0;

        for (const [jti, timestamp] of Object.entries(backup)) {
          if (now - timestamp < expiryMs) {
            cleanedBackup[jti] = timestamp;
          } else {
            removedCount++;
          }
        }

        if (removedCount > 0) {
          // Write cleaned backup atomically
          const tempFile = backupFile + '.tmp';
          await fs.writeFile(tempFile, JSON.stringify(cleanedBackup, null, 2));
          await fs.rename(tempFile, backupFile);

          logger.debug({ removedCount, backupFile }, 'Cleaned up expired entries from backup storage');
        }

      } catch (error) {
        // Backup file doesn't exist or is invalid
        logger.debug({ error: error.message }, 'Backup file cleanup skipped - file not accessible');
      }

    } catch (error) {
      logger.error({ error }, 'Failed to cleanup backup storage');
    }
  }

  // API Key operations
  generateApiKey(): { keyId: string; key: string } {
    const keyId = `ck_${crypto.randomBytes(8).toString('hex')}`;
    const key = `ck_${crypto.randomBytes(32).toString('hex')}`;

    return { keyId, key };
  }

  async hashApiKey(key: string): Promise<string> {
    return bcrypt.hash(key, this.config.bcrypt_rounds);
  }

  async verifyApiKey(key: string, hashedKey: string): Promise<boolean> {
    return bcrypt.compare(key, hashedKey);
  }

  /**
   * Database-backed API key validation
   */
  async validateApiKeyWithDatabase(apiKey: string): Promise<{ user: User; scopes: AuthScope[]; apiKeyInfo: ApiKey } | null> {
    try {
      // Extract key ID from API key format (ck_live_... or ck_test_...)
      const keyIdMatch = apiKey.match(/^(ck_[^_]+)_([a-f0-9]+)/);
      if (!keyIdMatch) {
        logger.warn({ apiKeyPrefix: apiKey.substring(0, 10) }, 'Invalid API key format');
        return null;
      }

      const keyId = `${keyIdMatch[1]}_${keyIdMatch[2]}`;

      // Fetch API key from database with user information
      const apiKeyRecord = await qdrant.getClient().apiKey.findFirst({
        where: {
          key_id: keyId,
          is_active: true
        },
        include: {
          user: {
            select: {
              id: true,
              username: true,
              email: true,
              role: true,
              is_active: true,
              created_at: true,
              updated_at: true,
              last_login: true
            }
          }
        }
      });

      if (!apiKeyRecord) {
        logger.warn({ keyId }, 'API key not found or inactive');
        return null;
      }

      // Check if API key has expired
      if (apiKeyRecord.expires_at && new Date() > apiKeyRecord.expires_at) {
        logger.warn({ keyId, expiresAt: apiKeyRecord.expires_at }, 'API key has expired');
        return null;
      }

      // Check if user is active
      if (!apiKeyRecord.user.is_active) {
        logger.warn({ keyId, userId: apiKeyRecord.user.id }, 'User account is inactive');
        return null;
      }

      // Verify the API key hash
      const isValidKey = await this.verifyApiKey(apiKey, apiKeyRecord.key_hash);
      if (!isValidKey) {
        logger.warn({ keyId }, 'API key hash verification failed');
        return null;
      }

      // Parse scopes from JSON
      const scopes: AuthScope[] = Array.isArray(apiKeyRecord.scopes)
        ? apiKeyRecord.scopes as AuthScope[]
        : [];

      // Update last used timestamp
      await qdrant.getClient().apiKey.update({
        where: { id: apiKeyRecord.id },
        data: { last_used: new Date() }
      });

      // Convert database user to User interface
      const user: User = {
        id: apiKeyRecord.user.id,
        username: apiKeyRecord.user.username,
        email: apiKeyRecord.user.email,
        password_hash: '', // Not included for security
        role: apiKeyRecord.user.role as UserRole,
        is_active: apiKeyRecord.user.is_active,
        created_at: apiKeyRecord.user.created_at.toISOString(),
        updated_at: apiKeyRecord.user.updated_at.toISOString(),
        last_login: apiKeyRecord.user.last_login?.toISOString()
      };

      // Convert database API key to ApiKey interface
      const apiKeyInfo: ApiKey = {
        id: apiKeyRecord.id,
        key_id: apiKeyRecord.key_id,
        key_hash: apiKeyRecord.key_hash,
        user_id: apiKeyRecord.user_id,
        name: apiKeyRecord.name,
        description: apiKeyRecord.description || undefined,
        scopes,
        is_active: apiKeyRecord.is_active,
        expires_at: apiKeyRecord.expires_at?.toISOString(),
        created_at: apiKeyRecord.created_at.toISOString(),
        last_used: apiKeyRecord.last_used?.toISOString(),
        updated_at: apiKeyRecord.updated_at.toISOString()
      };

      logger.info({
        keyId,
        userId: user.id,
        scopes: scopes.length,
        lastUsed: apiKeyRecord.last_used
      }, 'API key validated successfully');

      return { user, scopes, apiKeyInfo };

    } catch (error) {
      logger.error({ error, apiKeyPrefix: apiKey.substring(0, 10) }, 'API key validation failed');
      return null;
    }
  }

  /**
   * Create a new API key in the database
   */
  async createApiKeyInDatabase(
    userId: string,
    name: string,
    scopes: AuthScope[],
    expiresAt?: Date,
    description?: string
  ): Promise<{ keyId: string; key: string }> {
    try {
      const { keyId, key } = this.generateApiKey();
      const keyHash = await this.hashApiKey(key);

      await qdrant.getClient().apiKey.create({
        data: {
          key_id: keyId,
          key_hash: keyHash,
          user_id: userId,
          name,
          description,
          scopes: scopes as any[], // Qdrant Json field
          expires_at: expiresAt,
          is_active: true
        }
      });

      logger.info({ keyId, userId, scopes: scopes.length }, 'API key created in database');
      return { keyId, key };

    } catch (error) {
      logger.error({ error, userId, name }, 'Failed to create API key in database');
      throw error;
    }
  }

  /**
   * Revoke an API key
   */
  async revokeApiKey(keyId: string, userId?: string): Promise<boolean> {
    try {
      const whereClause: any = { key_id: keyId };
      if (userId) {
        whereClause.user_id = userId;
      }

      const result = await qdrant.getClient().apiKey.updateMany({
        where: whereClause,
        data: { is_active: false }
      });

      const success = result.count > 0;
      if (success) {
        logger.info({ keyId, userId }, 'API key revoked successfully');
      } else {
        logger.warn({ keyId, userId }, 'API key not found for revocation');
      }

      return success;

    } catch (error) {
      logger.error({ error, keyId, userId }, 'Failed to revoke API key');
      return false;
    }
  }

  /**
   * List API keys for a user
   */
  async listApiKeysForUser(userId: string): Promise<ApiKey[]> {
    try {
      const apiKeys = await qdrant.getClient().apiKey.findMany({
        where: { user_id: userId },
        select: {
          id: true,
          key_id: true,
          key_hash: true,
          user_id: true,
          name: true,
          description: true,
          scopes: true,
          is_active: true,
          expires_at: true,
          created_at: true,
          last_used: true,
          updated_at: true
        },
        orderBy: { created_at: 'desc' }
      });

      return apiKeys.map(key => ({
        id: key.id,
        key_id: key.key_id,
        key_hash: key.key_hash,
        user_id: key.user_id,
        name: key.name,
        description: key.description || undefined,
        scopes: Array.isArray(key.scopes) ? key.scopes as AuthScope[] : [],
        is_active: key.is_active,
        expires_at: key.expires_at?.toISOString(),
        created_at: key.created_at.toISOString(),
        last_used: key.last_used?.toISOString(),
        updated_at: key.updated_at.toISOString()
      }));

    } catch (error) {
      logger.error({ error, userId }, 'Failed to list API keys for user');
      return [];
    }
  }

  // Authorization operations
  getUserScopes(user: User): AuthScope[] {
    const roleConfig = DEFAULT_ROLE_PERMISSIONS[user.role];
    return roleConfig ? roleConfig.default_scopes : [];
  }

  getUserMaxScopes(user: User): AuthScope[] {
    const roleConfig = DEFAULT_ROLE_PERMISSIONS[user.role];
    return roleConfig ? roleConfig.max_scopes : [];
  }

  validateScopes(userScopes: AuthScope[], requiredScopes: AuthScope[]): boolean {
    return requiredScopes.every(scope => userScopes.includes(scope));
  }

  canAccessResource(user: User, resource: string, action: string, apiKeyScopes?: AuthScope[]): boolean {
    const userScopes = this.getUserScopes(user);
    const effectiveScopes = apiKeyScopes ? [...userScopes, ...apiKeyScopes] : userScopes;

    // Resource-based scope mapping
    const resourceScopes = this.getResourceScopes(resource, action);

    return this.validateScopes(effectiveScopes, resourceScopes);
  }

  private getResourceScopes(resource: string, action: string): AuthScope[] {
    const resourceMap: Record<string, Record<string, AuthScope[]>> = {
      'memory_store': {
        'read': [AuthScope.MEMORY_READ],
        'write': [AuthScope.MEMORY_WRITE],
        'delete': [AuthScope.MEMORY_DELETE]
      },
      'memory_find': {
        'read': [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC],
        'deep': [AuthScope.SEARCH_DEEP],
        'advanced': [AuthScope.SEARCH_ADVANCED]
      },
      'knowledge': {
        'read': [AuthScope.KNOWLEDGE_READ],
        'write': [AuthScope.KNOWLEDGE_WRITE],
        'delete': [AuthScope.KNOWLEDGE_DELETE]
      },
      'audit': {
        'read': [AuthScope.AUDIT_READ],
        'write': [AuthScope.AUDIT_WRITE]
      },
      'system': {
        'read': [AuthScope.SYSTEM_READ],
        'manage': [AuthScope.SYSTEM_MANAGE]
      }
    };

    return resourceMap[resource]?.[action] || [];
  }

  // Authentication context creation
  async createAuthContext(token: string, ipAddress: string, userAgent: string): Promise<AuthContext> {
    const payload = await this.verifyAccessToken(token);
    const session = payload.session_id ? this.getSession(payload.session_id) : null;

    if (!session) {
      throw new Error('SESSION_EXPIRED');
    }

    return {
      user: {
        id: payload.sub,
        username: payload.username,
        role: payload.role
      },
      session: {
        id: session.id,
        ip_address: session.ip_address,
        user_agent: session.user_agent
      },
      scopes: payload.scopes as AuthScope[],
      token_jti: payload.jti
    };
  }

  // Token refresh
  async refreshToken(refreshToken: string): Promise<AuthToken> {
    const decoded = this.verifyRefreshToken(refreshToken);
    const session = this.getSession(decoded.session_id);

    if (!session || !session.is_active) {
      throw new Error('SESSION_EXPIRED');
    }

    // Revoke old access token if it exists
    if (session.refresh_token) {
      try {
        const oldTokenPayload = await this.verifyAccessToken(session.refresh_token);
        await this.revokeToken(oldTokenPayload.jti);
      } catch {
        // Old token might be invalid, ignore
      }
    }

    // Create new tokens
    const user: User = {
      id: decoded.sub,
      username: '', // Will be populated from database
      email: '',
      password_hash: '',
      role: UserRole.USER,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const scopes: AuthScope[] = this.getUserScopes(user);
    const accessToken = this.generateAccessToken(user, session.id, scopes);
    const newRefreshToken = this.generateRefreshToken(user, session.id);

    // Update session
    session.refresh_token = newRefreshToken;
    this.activeSessions.set(session.id, session);

    return {
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: 'Bearer',
      expires_in: this.parseExpiration(this.config.jwt_expires_in),
      scope: scopes
    };
  }

  // Utility methods
  private parseExpiration(expiration: string): number {
    // Parse time strings like '15m', '1h', '7d', '30d'
    const match = expiration.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid expiration format: ${expiration}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 60 * 60;
      case 'd': return value * 24 * 60 * 60;
      default: throw new Error(`Invalid time unit: ${unit}`);
    }
  }

  // Rate limiting (simple implementation)
  private rateLimitMap: Map<string, { count: number; resetTime: number }> = new Map();

  checkRateLimit(identifier: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    const record = this.rateLimitMap.get(identifier);

    if (!record || now > record.resetTime) {
      // New window
      this.rateLimitMap.set(identifier, {
        count: 1,
        resetTime: now + windowMs
      });
      return true;
    }

    if (record.count >= limit) {
      return false;
    }

    record.count++;
    return true;
  }

  /**
   * Start distributed synchronization for multi-instance deployments
   */
  private startDistributedSync(): void {
    // Sync every 30 seconds to ensure consistency across instances
    setInterval(async () => {
      await this.performDistributedSync();
    }, this.distributedSync.syncInterval);
  }

  /**
   * Perform distributed synchronization with other instances
   */
  private async performDistributedSync(): Promise<void> {
    const now = Date.now();

    // Skip if circuit breaker is open
    if (this.databaseCircuitBreaker.isOpen) {
      return;
    }

    try {
      // Get recent token revocations from database (last 5 minutes)
      const fiveMinutesAgo = new Date(now - 5 * 60 * 1000);

      const recentRevocations = await qdrant.getClient().tokenRevocationList.findMany({
        where: {
          revoked_at: {
            gt: fiveMinutesAgo
          }
        },
        select: {
          jti: true,
          revoked_at: true
        },
        orderBy: {
          revoked_at: 'desc'
        }
      });

      let syncCount = 0;

      for (const revocation of recentRevocations) {
        const revocationTime = revocation.revoked_at.getTime();

        // Only add if not already cached or if our cache is older
        const cached = this.tokenBlacklistCache.get(revocation.jti);
        if (!cached || cached.timestamp < revocationTime) {
          this.tokenBlacklist.add(revocation.jti);
          this.tokenBlacklistCache.set(revocation.jti, {
            revoked: true,
            timestamp: revocationTime
          });
          syncCount++;
        }
      }

      this.distributedSync.lastSyncTime = now;

      if (syncCount > 0) {
        logger.info({
          instanceId: this.distributedSync.instanceId,
          syncCount,
          totalRevocations: recentRevocations.length
        }, 'Distributed token blacklist sync completed');
      }

      // Update instance heartbeat
      await this.updateInstanceHeartbeat();

    } catch (error) {
      logger.error({
        instanceId: this.distributedSync.instanceId,
        error: error.message
      }, 'Distributed sync failed');

      // Don't treat this as a database circuit breaker issue
      // Sync failures shouldn't affect normal token verification
    }
  }

  /**
   * Update instance heartbeat for distributed coordination
   */
  private async updateInstanceHeartbeat(): Promise<void> {
    try {
      await qdrant.getClient().authInstance.upsert({
        where: { instance_id: this.distributedSync.instanceId },
        update: {
          last_heartbeat: new Date(),
          token_blacklist_size: this.tokenBlacklist.size,
          circuit_breaker_open: this.databaseCircuitBreaker.isOpen
        },
        create: {
          instance_id: this.distributedSync.instanceId,
          last_heartbeat: new Date(),
          token_blacklist_size: this.tokenBlacklist.size,
          circuit_breaker_open: this.databaseCircuitBreaker.isOpen,
          created_at: new Date()
        }
      });

    } catch (error) {
      logger.debug({
        instanceId: this.distributedSync.instanceId,
        error: error.message
      }, 'Failed to update instance heartbeat');
    }
  }

  /**
   * Force immediate distributed sync (useful for testing or manual triggers)
   */
  async forceDistributedSync(): Promise<void> {
    logger.info({ instanceId: this.distributedSync.instanceId }, 'Forcing immediate distributed sync');
    await this.performDistributedSync();
  }

  // Health check
  getHealthStatus(): { status: 'healthy' | 'degraded'; details: any } {
    const now = Date.now();
    const expiredSessions = Array.from(this.activeSessions.values())
      .filter(session => new Date(session.expires_at) < new Date(now)).length;

    const details = {
      active_sessions: this.activeSessions.size,
      expired_sessions: expiredSessions,
      blacklisted_tokens: this.tokenBlacklist.size,
      enhanced_cache_size: this.tokenBlacklistCache.size,
      rate_limit_entries: this.rateLimitMap.size,
      circuit_breaker_open: this.databaseCircuitBreaker.isOpen,
      database_failures: this.databaseCircuitBreaker.failureCount,
      instance_id: this.distributedSync.instanceId,
      last_distributed_sync: this.distributedSync.lastSyncTime ? new Date(this.distributedSync.lastSyncTime).toISOString() : 'never'
    };

    const isDegraded = expiredSessions > 100 ||
                      this.databaseCircuitBreaker.isOpen ||
                      (now - this.distributedSync.lastSyncTime > 5 * 60 * 1000); // No sync for 5 minutes

    return {
      status: isDegraded ? 'degraded' : 'healthy',
      details
    };
  }
}