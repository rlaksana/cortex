/**
 * Security utilities for Cortex MCP
 * Provides password hashing, token validation, session management, and security helpers
 */

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { logger } from '@/utils/logger.js';
import { AuthScope, UserRole } from '../types/auth-types.js';

export interface SecurityConfig {
  password_min_length: number;
  password_require_uppercase: boolean;
  password_require_lowercase: boolean;
  password_require_numbers: boolean;
  password_require_symbols: boolean;
  max_login_attempts: number;
  login_attempt_window_ms: number;
  account_lockout_duration_ms: number;
  session_timeout_ms: number;
  secure_cookie: boolean;
  rate_limit_window_ms: number;
  rate_limit_max_requests: number;
}

export class SecurityUtils {
  private static instance: SecurityUtils;
  private loginAttempts: Map<string, Array<{ timestamp: number; success: boolean }>> = new Map();
  private lockedAccounts: Map<string, { until: number; reason: string }> = new Map();
  private config: SecurityConfig;

  constructor(config: SecurityConfig) {
    this.config = config;
    this.startCleanupTimer();
  }

  static getInstance(config?: SecurityConfig): SecurityUtils {
    if (!SecurityUtils.instance) {
      if (!config) {
        throw new Error('Security config required for first initialization');
      }
      SecurityUtils.instance = new SecurityUtils(config);
    }
    return SecurityUtils.instance;
  }

  // Password utilities
  async hashPassword(password: string, rounds?: number): Promise<string> {
    const saltRounds = rounds || 12;
    return bcrypt.hash(password, saltRounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return bcrypt.compare(password, hash);
    } catch (error) {
      logger.error({ error }, 'Password verification error');
      return false;
    }
  }

  validatePassword(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (password.length < this.config.password_min_length) {
      errors.push(`Password must be at least ${this.config.password_min_length} characters long`);
    }

    if (this.config.password_require_uppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (this.config.password_require_lowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (this.config.password_require_numbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (
      this.config.password_require_symbols &&
      !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)
    ) {
      errors.push('Password must contain at least one special character');
    }

    // Check for common weak passwords
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein'];
    if (commonPasswords.some((common) => password.toLowerCase().includes(common))) {
      errors.push('Password contains common patterns');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  generateSecurePassword(length: number = 16): string {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let password = '';
    const allChars = uppercase + lowercase + numbers + symbols;

    // Ensure at least one character from each required category
    if (this.config.password_require_uppercase) {
      password += uppercase[crypto.randomInt(uppercase.length)];
    }
    if (this.config.password_require_lowercase) {
      password += lowercase[crypto.randomInt(lowercase.length)];
    }
    if (this.config.password_require_numbers) {
      password += numbers[crypto.randomInt(numbers.length)];
    }
    if (this.config.password_require_symbols) {
      password += symbols[crypto.randomInt(symbols.length)];
    }

    // Fill remaining length with random characters
    for (let i = password.length; i < length; i++) {
      password += allChars[crypto.randomInt(allChars.length)];
    }

    // Shuffle the password
    return password
      .split('')
      .sort(() => crypto.randomInt(0, 1) - 0.5)
      .join('');
  }

  // Token utilities
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  generateApiKey(): { keyId: string; key: string } {
    const keyId = `ck_${crypto.randomBytes(8).toString('hex')}`;
    const key = `ck_${crypto.randomBytes(32).toString('hex')}`;
    return { keyId, key };
  }

  generateSessionToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  verifyTokenHash(token: string, hash: string): boolean {
    const tokenHash = this.hashToken(token);
    return crypto.timingSafeEqual(Buffer.from(tokenHash), Buffer.from(hash));
  }

  // Input sanitization
  sanitizeInput(input: string): string {
    if (typeof input !== 'string') {
      return '';
    }

    // Remove potentially dangerous characters
    return input
      .replace(/[<>]/g, '') // Remove HTML tags
      .replace(/javascript:/gi, '') // Remove JavaScript protocol
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .trim();
  }

  sanitizeEmail(email: string): string {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const sanitized = email.toLowerCase().trim();
    return emailRegex.test(sanitized) ? sanitized : '';
  }

  sanitizeUsername(username: string): string {
    // Allow only alphanumeric characters, underscores, and hyphens
    return username.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
  }

  // Login attempt tracking
  recordLoginAttempt(identifier: string, success: boolean, ip?: string): void {
    const now = Date.now();
    const attempts = this.loginAttempts.get(identifier) || [];

    attempts.push({ timestamp: now, success });

    // Keep only attempts within the window
    const windowStart = now - this.config.login_attempt_window_ms;
    const recentAttempts = attempts.filter((attempt) => attempt.timestamp > windowStart);

    this.loginAttempts.set(identifier, recentAttempts);

    // Check for account lockout
    if (!success) {
      const failedAttempts = recentAttempts.filter((attempt) => !attempt.success);
      if (failedAttempts.length >= this.config.max_login_attempts) {
        this.lockAccount(identifier, 'Too many failed login attempts');
        logger.warn(
          {
            identifier,
            ip,
            attempts: failedAttempts.length,
          },
          'Account locked due to failed attempts'
        );
      }
    }
  }

  isAccountLocked(identifier: string): { locked: boolean; reason?: string; until?: Date } {
    const lockInfo = this.lockedAccounts.get(identifier);
    if (!lockInfo) {
      return { locked: false };
    }

    const now = Date.now();
    if (now > lockInfo.until) {
      this.lockedAccounts.delete(identifier);
      return { locked: false };
    }

    return {
      locked: true,
      reason: lockInfo.reason,
      until: new Date(lockInfo.until),
    };
  }

  lockAccount(identifier: string, reason: string, duration?: number): void {
    const lockDuration = duration || this.config.account_lockout_duration_ms;
    this.lockedAccounts.set(identifier, {
      until: Date.now() + lockDuration,
      reason,
    });
  }

  unlockAccount(identifier: string): void {
    this.lockedAccounts.delete(identifier);
    this.loginAttempts.delete(identifier);
  }

  // Rate limiting
  private rateLimitMap: Map<string, { count: number; resetTime: number }> = new Map();

  checkRateLimit(identifier: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    const record = this.rateLimitMap.get(identifier);

    if (!record || now > record.resetTime) {
      // New window
      this.rateLimitMap.set(identifier, {
        count: 1,
        resetTime: now + windowMs,
      });
      return true;
    }

    if (record.count >= limit) {
      return false;
    }

    record.count++;
    return true;
  }

  getRateLimitStatus(identifier: string): { remaining: number; resetTime: Date } | null {
    const record = this.rateLimitMap.get(identifier);
    if (!record) {
      return null;
    }

    const now = Date.now();
    if (now > record.resetTime) {
      return null;
    }

    return {
      remaining: Math.max(0, this.config.rate_limit_max_requests - record.count),
      resetTime: new Date(record.resetTime),
    };
  }

  // Security headers
  getSecurityHeaders(): Record<string, string> {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy': "default-src 'self'",
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    };
  }

  // Input validation
  isValidScope(scope: string): scope is AuthScope {
    return Object.values(AuthScope).includes(scope as AuthScope);
  }

  isValidRole(role: string): role is UserRole {
    return Object.values(UserRole).includes(role as UserRole);
  }

  validateScopes(scopes: string[]): { valid: boolean; invalid: string[] } {
    const invalid = scopes.filter((scope) => !this.isValidScope(scope));
    return {
      valid: invalid.length === 0,
      invalid,
    };
  }

  validateId(id: string): boolean {
    // Check if ID is a valid UUID or has valid format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const cortexIdRegex = /^ck_[a-f0-9]{16}$/i;

    return uuidRegex.test(id) || cortexIdRegex.test(id);
  }

  // Cryptographic utilities
  generateSecureId(): string {
    return crypto.randomUUID();
  }

  encryptSensitiveData(data: string, key: string): string {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return `${iv.toString('hex')}:${encrypted}`;
    } catch (error) {
      logger.error({ error }, 'Encryption failed');
      throw new Error('Encryption failed');
    }
  }

  decryptSensitiveData(encryptedData: string, key: string): string {
    try {
      const parts = encryptedData.split(':');
      const iv = Buffer.from(parts[0], 'hex');
      const encrypted = parts[1];
      const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      logger.error({ error }, 'Decryption failed');
      throw new Error('Decryption failed');
    }
  }

  // Timing-safe comparison
  timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  }

  // Cleanup expired data
  private startCleanupTimer(): void {
    setInterval(
      () => {
        this.cleanupExpiredData();
      },
      5 * 60 * 1000
    ); // Run every 5 minutes
  }

  private cleanupExpiredData(): void {
    const now = Date.now();
    let cleanedCount = 0;

    // Clean up old login attempts
    for (const [identifier, attempts] of this.loginAttempts) {
      const windowStart = now - this.config.login_attempt_window_ms;
      const recentAttempts = attempts.filter((attempt) => attempt.timestamp > windowStart);

      if (recentAttempts.length === 0) {
        this.loginAttempts.delete(identifier);
        cleanedCount++;
      } else if (recentAttempts.length < attempts.length) {
        this.loginAttempts.set(identifier, recentAttempts);
      }
    }

    // Clean up expired account locks
    for (const [identifier, lockInfo] of this.lockedAccounts) {
      if (now > lockInfo.until) {
        this.lockedAccounts.delete(identifier);
        cleanedCount++;
      }
    }

    // Clean up expired rate limit records
    for (const [identifier, record] of this.rateLimitMap) {
      if (now > record.resetTime) {
        this.rateLimitMap.delete(identifier);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug({ cleanedCount }, 'Security cleanup completed');
    }
  }

  // Security metrics
  getSecurityMetrics(): {
    login_attempts: number;
    locked_accounts: number;
    active_rate_limits: number;
    failed_logins_last_hour: number;
  } {
    const now = Date.now();
    const oneHourAgo = now - 60 * 60 * 1000;

    let failedLoginsLastHour = 0;
    for (const attempts of this.loginAttempts.values()) {
      const recentFailures = attempts.filter(
        (attempt) => !attempt.success && attempt.timestamp > oneHourAgo
      );
      failedLoginsLastHour += recentFailures.length;
    }

    return {
      login_attempts: Array.from(this.loginAttempts.values()).reduce(
        (sum, attempts) => sum + attempts.length,
        0
      ),
      locked_accounts: this.lockedAccounts.size,
      active_rate_limits: this.rateLimitMap.size,
      failed_logins_last_hour: failedLoginsLastHour,
    };
  }

  // Security audit helpers
  auditLog(
    action: string,
    details: Record<string, any>,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ): void {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      action,
      details,
      severity,
    };

    logger.info(auditEntry, 'Security audit log');
  }

  // IP address utilities
  isValidIP(ip: string): boolean {
    const ipv4Regex =
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }

  isPrivateIP(ip: string): boolean {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/,
    ];

    return privateRanges.some((range) => range.test(ip));
  }

  extractIPFromRequest(headers: Record<string, string>): string {
    return (
      headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      headers['x-real-ip'] ||
      headers['cf-connecting-ip'] ||
      'unknown'
    );
  }
}
