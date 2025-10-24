/**
 * Authentication Service for Cortex MCP
 * Implements JWT-based authentication with RBAC and scope-based authorization
 */

import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { logger } from '../../utils/logger.js';
import { prisma } from '../../db/prisma-client.js';
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
}

export class AuthService {
  private config: AuthServiceConfig;
  private tokenBlacklist: Set<string> = new Set();
  private activeSessions: Map<string, AuthSession> = new Map();

  constructor(config: AuthServiceConfig) {
    this.config = config;
    this.validateConfig();
    this.startSessionCleanup();
  }

  private validateConfig(): void {
    if (!this.config.jwt_secret || this.config.jwt_secret.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters long');
    }
    if (!this.config.jwt_refresh_secret || this.config.jwt_refresh_secret.length < 32) {
      throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
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
    try {
      // Fetch user from database
      const userRecord = await prisma.getClient().user.findUnique({
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
      });

      if (!userRecord) {
        logger.warn({ username }, 'User not found in database');
        return null;
      }

      // Check if user account is active
      if (!userRecord.is_active) {
        logger.warn({ username, userId: userRecord.id }, 'User account is inactive');
        return null;
      }

      // Verify password
      const isValidPassword = await this.verifyPassword(password, userRecord.password_hash);
      if (!isValidPassword) {
        logger.warn({ username, userId: userRecord.id }, 'Invalid password provided');
        return null;
      }

      // Update last login timestamp
      await prisma.getClient().user.update({
        where: { id: userRecord.id },
        data: { last_login: new Date() }
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
        last_login: userRecord.last_login?.toISOString()
      };

      logger.info({
        userId: user.id,
        username: user.username,
        role: user.role
      }, 'User authenticated successfully via database');

      return user;

    } catch (error) {
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

  verifyAccessToken(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, this.config.jwt_secret, {
        algorithms: ['HS256'],
        issuer: 'cortex-mcp',
        audience: 'cortex-client'
      }) as TokenPayload;

      // Check if token is blacklisted
      if (this.tokenBlacklist.has(decoded.jti)) {
        throw new Error('Token has been revoked');
      }

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('EXPIRED_TOKEN');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('INVALID_TOKEN');
      } else {
        throw error;
      }
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

  revokeToken(jti: string): void {
    this.tokenBlacklist.add(jti);
    logger.info({ jti }, 'Token revoked');
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
    setInterval(() => {
      const now = new Date();
      for (const [sessionId, session] of this.activeSessions) {
        if (now > new Date(session.expires_at)) {
          this.activeSessions.delete(sessionId);
        }
      }
    }, 5 * 60 * 1000); // Clean up every 5 minutes
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
      const apiKeyRecord = await prisma.getClient().apiKey.findFirst({
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
      await prisma.getClient().apiKey.update({
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

      await prisma.getClient().apiKey.create({
        data: {
          key_id: keyId,
          key_hash: keyHash,
          user_id: userId,
          name,
          description,
          scopes: scopes as any[], // Prisma Json field
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

      const result = await prisma.getClient().apiKey.updateMany({
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
      const apiKeys = await prisma.getClient().apiKey.findMany({
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
  createAuthContext(token: string, ipAddress: string, userAgent: string): AuthContext {
    const payload = this.verifyAccessToken(token);
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
        const oldTokenPayload = this.verifyAccessToken(session.refresh_token);
        this.revokeToken(oldTokenPayload.jti);
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

  // Health check
  getHealthStatus(): { status: 'healthy' | 'degraded'; details: any } {
    const now = Date.now();
    const expiredSessions = Array.from(this.activeSessions.values())
      .filter(session => new Date(session.expires_at) < new Date(now)).length;

    const details = {
      active_sessions: this.activeSessions.size,
      expired_sessions: expiredSessions,
      blacklisted_tokens: this.tokenBlacklist.size,
      rate_limit_entries: this.rateLimitMap.size
    };

    return {
      status: expiredSessions > 100 ? 'degraded' : 'healthy',
      details
    };
  }
}