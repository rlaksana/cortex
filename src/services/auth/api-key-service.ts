/**
 * API Key Management Service for Cortex MCP
 * Handles creation, validation, and management of API keys for MCP clients
 */

import crypto from 'crypto';
import { logger } from '../../utils/logger.js';
import { AuthService } from './auth-service.js';
import { AuditService } from '../audit/audit-service.js';
import { ApiKey, User, AuthScope, SecurityAuditLog, AuthContext } from '../../types/auth-types.js';

export interface CreateApiKeyRequest {
  name: string;
  scopes: AuthScope[];
  expires_at?: string;
  description?: string;
  project_scopes?: string[];
}

export interface ApiKeyResponse {
  id: string;
  key_id: string;
  name: string;
  scopes: AuthScope[];
  expires_at?: string;
  created_at: string;
  last_used?: string;
  is_active: boolean;
  description?: string;
  project_scopes?: string[];
}

export interface ApiKeyValidationResult {
  valid: boolean;
  api_key?: ApiKey;
  user?: User;
  scopes?: AuthScope[];
  error?: string;
  error_code?: string;
}

export class ApiKeyService {
  private apiKeys: Map<string, ApiKey> = new Map(); // key_id -> ApiKey
  private keyHashes: Map<string, string> = new Map(); // key_hash -> key_id

  constructor(
    private authService: AuthService,
    private auditService: AuditService
  ) {}

  /**
   * Create a new API key for a user
   */
  async createApiKey(
    user: User,
    request: CreateApiKeyRequest,
    context?: { ip_address: string; user_agent: string }
  ): Promise<{ api_key: string; key_info: ApiKeyResponse }> {
    // Validate user permissions
    const userMaxScopes = this.authService.getUserMaxScopes(user);
    const invalidScopes = request.scopes.filter((scope) => !userMaxScopes.includes(scope));

    if (invalidScopes.length > 0) {
      throw new Error(
        `User not allowed to create API key with scopes: ${invalidScopes.join(', ')}`
      );
    }

    // Generate API key
    const { keyId, key } = this.authService.generateApiKey();
    const keyHash = await this.authService.hashApiKey(key);

    // Create API key record
    const apiKey: ApiKey = {
      id: crypto.randomUUID(),
      key_id: keyId,
      key_hash: keyHash,
      user_id: user.id,
      name: request.name,
      scopes: request.scopes,
      is_active: true,
      expires_at: request.expires_at,
      created_at: new Date().toISOString(),
    };

    // Store API key
    this.apiKeys.set(keyId, apiKey);
    this.keyHashes.set(keyHash, keyId);

    // Log API key creation
    await this.logApiKeyEvent({
      event_type: 'api_key_created',
      user_id: user.id,
      api_key_id: apiKey.id,
      ip_address: context?.ip_address || 'unknown',
      user_agent: context?.user_agent || 'unknown',
      details: {
        key_id: keyId,
        name: request.name,
        scopes: request.scopes,
        expires_at: request.expires_at,
        description: request.description,
      },
      severity: 'medium',
    });

    logger.info(
      {
        keyId,
        userId: user.id,
        name: request.name,
        scopes: request.scopes,
      },
      'API key created'
    );

    return {
      api_key: key,
      key_info: this.mapToApiKeyResponse(apiKey),
    };
  }

  /**
   * Validate an API key and return user context
   */
  async validateApiKey(
    apiKey: string,
    context?: { ip_address: string; user_agent: string }
  ): Promise<ApiKeyValidationResult> {
    try {
      // Basic format validation
      if (!apiKey.startsWith('ck_') || apiKey.length < 35) {
        return {
          valid: false,
          error: 'Invalid API key format',
          error_code: 'INVALID_FORMAT',
        };
      }

      // Find key by trying to match against stored hashes
      let foundApiKey: ApiKey | null = null;
      let keyId: string | null = null;

      for (const [keyIdCandidate, apiKeyRecord] of this.apiKeys) {
        const isValid = await this.authService.verifyApiKey(apiKey, apiKeyRecord.key_hash);
        if (isValid) {
          foundApiKey = apiKeyRecord;
          keyId = keyIdCandidate;
          break;
        }
      }

      if (!foundApiKey || !keyId) {
        await this.logApiKeyEvent({
          event_type: 'auth_failure',
          ip_address: context?.ip_address || 'unknown',
          user_agent: context?.user_agent || 'unknown',
          details: {
            reason: 'Invalid API key',
            key_prefix: apiKey.substring(0, 10),
          },
          severity: 'medium',
        });

        return {
          valid: false,
          error: 'Invalid API key',
          error_code: 'INVALID_KEY',
        };
      }

      // Check if key is active
      if (!foundApiKey.is_active) {
        await this.logApiKeyEvent({
          event_type: 'auth_failure',
          user_id: foundApiKey.user_id,
          api_key_id: foundApiKey.id,
          ip_address: context?.ip_address || 'unknown',
          user_agent: context?.user_agent || 'unknown',
          details: {
            reason: 'API key is inactive',
            key_id: keyId,
          },
          severity: 'medium',
        });

        return {
          valid: false,
          error: 'API key is inactive',
          error_code: 'INACTIVE_KEY',
        };
      }

      // Check expiration
      if (foundApiKey.expires_at && new Date(foundApiKey.expires_at) < new Date()) {
        await this.logApiKeyEvent({
          event_type: 'auth_failure',
          user_id: foundApiKey.user_id,
          api_key_id: foundApiKey.id,
          ip_address: context?.ip_address || 'unknown',
          user_agent: context?.user_agent || 'unknown',
          details: {
            reason: 'API key expired',
            key_id: keyId,
            expires_at: foundApiKey.expires_at,
          },
          severity: 'medium',
        });

        return {
          valid: false,
          error: 'API key has expired',
          error_code: 'EXPIRED_KEY',
        };
      }

      // Update last used timestamp
      foundApiKey.last_used = new Date().toISOString();
      this.apiKeys.set(keyId, foundApiKey);

      // Log successful usage
      await this.logApiKeyEvent({
        event_type: 'auth_success',
        user_id: foundApiKey.user_id,
        api_key_id: foundApiKey.id,
        ip_address: context?.ip_address || 'unknown',
        user_agent: context?.user_agent || 'unknown',
        details: {
          key_id: keyId,
          scopes: foundApiKey.scopes as AuthScope[],
        },
        severity: 'low',
      });

      // Mock user data (in real implementation, fetch from database)
      const user: User = {
        id: foundApiKey.user_id,
        username: 'api-user',
        email: 'api-user@cortex.local',
        password_hash: '',
        role: 'user' as any,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      return {
        valid: true,
        api_key: foundApiKey,
        user,
        scopes: foundApiKey.scopes as AuthScope[],
      };
    } catch (error) {
      logger.error({ error }, 'API key validation error');

      await this.logApiKeyEvent({
        event_type: 'auth_failure',
        ip_address: context?.ip_address || 'unknown',
        user_agent: context?.user_agent || 'unknown',
        details: {
          reason: 'Validation error',
          error: error instanceof Error ? error.message : String(error),
        },
        severity: 'high',
      });

      return {
        valid: false,
        error: 'Validation failed',
        error_code: 'VALIDATION_ERROR',
      };
    }
  }

  /**
   * List all API keys for a user
   */
  async listApiKeys(user: User): Promise<ApiKeyResponse[]> {
    const userApiKeys = Array.from(this.apiKeys.values()).filter((key) => key.user_id === user.id);

    return userApiKeys.map((key) => this.mapToApiKeyResponse(key));
  }

  /**
   * Get details of a specific API key
   */
  async getApiKey(user: User, keyId: string): Promise<ApiKeyResponse | null> {
    const apiKey = this.apiKeys.get(keyId);

    if (!apiKey || apiKey.user_id !== user.id) {
      return null;
    }

    return this.mapToApiKeyResponse(apiKey);
  }

  /**
   * Revoke an API key
   */
  async revokeApiKey(
    user: User,
    keyId: string,
    context?: { ip_address: string; user_agent: string }
  ): Promise<boolean> {
    const apiKey = this.apiKeys.get(keyId);

    if (!apiKey || apiKey.user_id !== user.id) {
      return false;
    }

    // Mark as inactive
    apiKey.is_active = false;
    this.apiKeys.set(keyId, apiKey);

    // Log revocation
    await this.logApiKeyEvent({
      event_type: 'api_key_revoked',
      user_id: user.id,
      api_key_id: apiKey.id,
      ip_address: context?.ip_address || 'unknown',
      user_agent: context?.user_agent || 'unknown',
      details: {
        key_id: keyId,
        name: apiKey.name,
        revoked_at: new Date().toISOString(),
      },
      severity: 'medium',
    });

    logger.info(
      {
        keyId,
        userId: user.id,
        name: apiKey.name,
      },
      'API key revoked'
    );

    return true;
  }

  /**
   * Update an API key
   */
  async updateApiKey(
    user: User,
    keyId: string,
    updates: {
      name?: string;
      scopes?: AuthScope[];
      expires_at?: string;
      description?: string;
      is_active?: boolean;
    },
    context?: { ip_address: string; user_agent: string }
  ): Promise<ApiKeyResponse | null> {
    const apiKey = this.apiKeys.get(keyId);

    if (!apiKey || apiKey.user_id !== user.id) {
      return null;
    }

    // Validate scope updates
    if (updates.scopes) {
      const userMaxScopes = this.authService.getUserMaxScopes(user);
      const invalidScopes = updates.scopes.filter((scope) => !userMaxScopes.includes(scope));

      if (invalidScopes.length > 0) {
        throw new Error(`User not allowed to assign scopes: ${invalidScopes.join(', ')}`);
      }
    }

    // Apply updates
    const updatedKey: ApiKey = {
      ...apiKey,
      ...updates,
      updated_at: new Date().toISOString(),
    };

    this.apiKeys.set(keyId, updatedKey);

    // Log update
    await this.logApiKeyEvent({
      event_type: 'api_key_updated',
      user_id: user.id,
      api_key_id: apiKey.id,
      ip_address: context?.ip_address || 'unknown',
      user_agent: context?.user_agent || 'unknown',
      details: {
        key_id: keyId,
        updates,
        updated_at: updatedKey.updated_at,
      },
      severity: 'low',
    });

    return this.mapToApiKeyResponse(updatedKey);
  }

  /**
   * Get usage statistics for API keys
   */
  async getApiKeyUsageStats(user: User): Promise<{
    total_keys: number;
    active_keys: number;
    expired_keys: number;
    keys_by_scope: Record<string, number>;
    recent_usage: Array<{ key_id: string; name: string; last_used?: string; usage_count: number }>;
  }> {
    const userApiKeys = Array.from(this.apiKeys.values()).filter((key) => key.user_id === user.id);

    const now = new Date();
    const activeKeys = userApiKeys.filter(
      (key) => key.is_active && (!key.expires_at || new Date(key.expires_at) > now)
    );

    const expiredKeys = userApiKeys.filter(
      (key) => key.expires_at && new Date(key.expires_at) <= now
    );

    // Count keys by scope
    const keysByScope: Record<string, number> = {};
    userApiKeys.forEach((key) => {
      key.scopes.forEach((scope) => {
        keysByScope[scope] = (keysByScope[scope] || 0) + 1;
      });
    });

    // Recent usage (mock implementation - in real system, track usage count)
    const recentUsage = userApiKeys
      .filter((key) => key.last_used)
      .sort((a, b) => new Date(b.last_used!).getTime() - new Date(a.last_used!).getTime())
      .slice(0, 10)
      .map((key) => ({
        key_id: key.key_id,
        name: key.name,
        last_used: key.last_used,
        usage_count: Math.floor(Math.random() * 100), // Mock usage count
      }));

    return {
      total_keys: userApiKeys.length,
      active_keys: activeKeys.length,
      expired_keys: expiredKeys.length,
      keys_by_scope: keysByScope,
      recent_usage: recentUsage,
    };
  }

  /**
   * Cleanup expired and inactive API keys
   */
  async cleanupExpiredKeys(): Promise<number> {
    const now = new Date();
    let cleanedCount = 0;

    for (const [keyId, apiKey] of this.apiKeys) {
      const isExpired = apiKey.expires_at && new Date(apiKey.expires_at) <= now;
      const isInactive = !apiKey.is_active;
      const isOld =
        new Date(apiKey.created_at) < new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000); // 1 year old

      if ((isExpired || isInactive) && isOld) {
        this.apiKeys.delete(keyId);
        // Also remove from keyHashes if it exists
        for (const [hash, id] of this.keyHashes) {
          if (id === keyId) {
            this.keyHashes.delete(hash);
            break;
          }
        }
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.info({ count: cleanedCount }, 'Cleaned up expired API keys');
    }

    return cleanedCount;
  }

  /**
   * Create authentication context from API key validation result
   */
  createAuthContextFromApiKey(
    validation: ApiKeyValidationResult,
    context: { ip_address: string; user_agent: string }
  ): AuthContext {
    if (!validation.valid || !validation.user || !validation.api_key) {
      throw new Error('Invalid API key validation result');
    }

    return {
      user: {
        id: validation.user.id,
        username: validation.user.username,
        role: validation.user.role,
      },
      session: {
        id: `api-key-${validation.api_key.id}`,
        ip_address: context.ip_address,
        user_agent: context.user_agent,
      },
      scopes: validation.scopes || [],
      token_jti: validation.api_key.id,
    };
  }

  /**
   * Map ApiKey to ApiKeyResponse (excluding sensitive data)
   */
  private mapToApiKeyResponse(apiKey: ApiKey): ApiKeyResponse {
    return {
      id: apiKey.id,
      key_id: apiKey.key_id,
      name: apiKey.name,
      scopes: apiKey.scopes,
      expires_at: apiKey.expires_at,
      created_at: apiKey.created_at,
      last_used: apiKey.last_used,
      is_active: apiKey.is_active,
      description: apiKey.description,
    };
  }

  /**
   * Log API key events
   */
  private async logApiKeyEvent(event: Omit<SecurityAuditLog, 'id' | 'created_at'>): Promise<void> {
    try {
      await this.auditService.logSecurityAuditEvent(event as SecurityAuditLog);
    } catch (error) {
      logger.error({ error, event }, 'Failed to log API key event');
    }
  }

  /**
   * Get health status of API key service
   */
  getHealthStatus(): { status: 'healthy' | 'degraded'; details: any } {
    const now = new Date();
    const expiredKeys = Array.from(this.apiKeys.values()).filter(
      (key) => key.expires_at && new Date(key.expires_at) <= now
    ).length;

    const inactiveKeys = Array.from(this.apiKeys.values()).filter((key) => !key.is_active).length;

    const details = {
      total_keys: this.apiKeys.size,
      active_keys: this.apiKeys.size - inactiveKeys,
      expired_keys: expiredKeys,
      inactive_keys: inactiveKeys,
      key_hashes_stored: this.keyHashes.size,
    };

    return {
      status: expiredKeys > this.apiKeys.size * 0.2 ? 'degraded' : 'healthy',
      details,
    };
  }
}
