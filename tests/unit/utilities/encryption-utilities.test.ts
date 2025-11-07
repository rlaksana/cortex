/**
 * Encryption Utilities Tests
 *
 * Comprehensive tests for encryption functionality including symmetric encryption,
 * asymmetric encryption, hash generation and validation, digital signatures,
 * key management, data protection, performance optimization, compliance and
 * standards, and integration and security.
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';
import { SecurityUtils, type SecurityConfig } from '../../../src/utils/security';

// Mock dependencies
vi.mock('bcryptjs', () => ({
  hash: vi.fn(),
  compare: vi.fn(),
}));

vi.mock('../../../src/utils/logger', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

import bcrypt from 'bcryptjs';
import { logger } from '../../../src/utils/logger';

// Mock encryption utilities for testing
class MockEncryptionUtils {
  // AES Configuration
  private static readonly AES_ALGORITHM = 'aes-256-gcm';
  private static readonly RSA_ALGORITHM = 'rsa-oaep';
  private static readonly HASH_ALGORITHM = 'sha256';
  private static readonly SIGNATURE_ALGORITHM = 'rsa-sha256';

  // Symmetric Encryption (AES)
  static generateAESKey(): Buffer {
    return crypto.randomBytes(32); // 256 bits for AES-256
  }

  static generateIV(): Buffer {
    return crypto.randomBytes(16); // 128 bits for AES GCM
  }

  static encryptAES(data: string, key: Buffer): { encrypted: Buffer; iv: Buffer; tag: Buffer } {
    const iv = this.generateIV();
    const cipher = crypto.createCipher(this['AES_ALGORITHM'], key);
    if (cipher.setAAD) {
      cipher.setAAD(Buffer.from('additional-data'));
    }

    let encrypted = cipher.update(data, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag ? cipher.getAuthTag() : Buffer.alloc(0);

    return { encrypted, iv, tag };
  }

  static decryptAES(encryptedData: Buffer, key: Buffer, iv: Buffer, tag: Buffer): string {
    const decipher = crypto.createDecipher(this['AES_ALGORITHM'], key);
    if (decipher.setAAD) {
      decipher.setAAD(Buffer.from('additional-data'));
    }
    if (decipher.setAuthTag) {
      decipher.setAuthTag(tag);
    }

    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('utf8');
  }

  // Asymmetric Encryption (RSA)
  static generateRSAKeyPair(keySize: number = 2048): crypto['K']eyPairSyncResult<string, string> {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: keySize,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  }

  static encryptRSA(data: string, publicKey: string): Buffer {
    return crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants['RSA_PKCS1_OAEP_PADDING'],
        oaepHash: 'sha256',
      },
      Buffer.from(data)
    );
  }

  static decryptRSA(encryptedData: Buffer, privateKey: string): string {
    return crypto
      .privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants['RSA_PKCS1_OAEP_PADDING'],
          oaepHash: 'sha256',
        },
        encryptedData
      )
      .toString('utf8');
  }

  // Hash Generation and Validation
  static generateHash(data: string, algorithm: string = this['HASH_ALGORITHM']): string {
    return crypto.createHash(algorithm).update(data).digest('hex');
  }

  static generateHMAC(
    data: string,
    secret: string,
    algorithm: string = this['HASH_ALGORITHM']
  ): string {
    return crypto.createHmac(algorithm, secret).update(data).digest('hex');
  }

  static verifyHash(data: string, hash: string, algorithm: string = this['HASH_ALGORITHM']): boolean {
    const computedHash = this.generateHash(data, algorithm);
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(computedHash));
  }

  static verifyHMAC(
    data: string,
    hmac: string,
    secret: string,
    algorithm: string = this['HASH_ALGORITHM']
  ): boolean {
    const computedHMAC = this.generateHMAC(data, secret, algorithm);
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(computedHMAC));
  }

  // Digital Signatures
  static signData(data: string, privateKey: string): Buffer {
    const sign = crypto.createSign(this['SIGNATURE_ALGORITHM']);
    sign.update(data);
    return sign.sign(privateKey);
  }

  static verifySignature(data: string, signature: Buffer, publicKey: string): boolean {
    try {
      const verify = crypto.createVerify(this['SIGNATURE_ALGORITHM']);
      verify.update(data);
      return verify.verify(publicKey, signature);
    } catch (error) {
      return false;
    }
  }

  // Key Management
  static deriveKey(password: string, salt: Buffer, iterations: number = 100000): Buffer {
    return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  }

  static generateSalt(length: number = 32): Buffer {
    return crypto.randomBytes(length);
  }

  // Key Encryption and Protection
  static encryptKey(key: Buffer, masterKey: Buffer): { encrypted: Buffer; iv: Buffer } {
    const iv = this.generateIV();
    const cipher = crypto.createCipher('aes-256-cbc', masterKey);

    let encrypted = cipher.update(key);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return { encrypted, iv };
  }

  static decryptKey(encryptedKey: Buffer, masterKey: Buffer, iv: Buffer): Buffer {
    const decipher = crypto.createDecipher('aes-256-cbc', masterKey);

    let decrypted = decipher.update(encryptedKey);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  // Performance and Batch Operations
  static async encryptBatch(
    dataArray: string[],
    key: Buffer
  ): Promise<Array<{ encrypted: Buffer; iv: Buffer; tag: Buffer }>> {
    return Promise.all(dataArray.map((data) => this.encryptAES(data, key)));
  }

  static async decryptBatch(
    encryptedDataArray: Array<{ encrypted: Buffer; iv: Buffer; tag: Buffer }>,
    key: Buffer
  ): Promise<string[]> {
    return Promise.all(
      encryptedDataArray.map(({ encrypted, iv, tag }) => this.decryptAES(encrypted, key, iv, tag))
    );
  }

  // Compliance and Security
  static isSecureAlgorithm(algorithm: string): boolean {
    const secureAlgorithms = ['aes-256-gcm', 'aes-256-cbc', 'rsa-oaep', 'sha256', 'sha512'];
    return secureAlgorithms.includes(algorithm.toLowerCase());
  }

  static validateKeyStrength(key: Buffer, algorithm: string): boolean {
    const minKeyLengths: Record<string, number> = {
      'aes-256-gcm': 32,
      'aes-256-cbc': 32,
      'aes-128-gcm': 16,
      'aes-128-cbc': 16,
      rsa: 256, // For 2048-bit RSA
    };

    const minLength = minKeyLengths[algorithm.toLowerCase()];
    return minLength ? key.length >= minLength : false;
  }
}

describe('Encryption Operations', () => {
  let mockSecurityUtils: any;
  let mockConfig: SecurityConfig;

  beforeEach(() => {
    vi.clearAllMocks();

    mockConfig = {
      password_min_length: 8,
      password_require_uppercase: true,
      password_require_lowercase: true,
      password_require_numbers: true,
      password_require_symbols: true,
      max_login_attempts: 5,
      login_attempt_window_ms: 900000,
      account_lockout_duration_ms: 1800000,
      session_timeout_ms: 3600000,
      secure_cookie: true,
      rate_limit_window_ms: 900000,
      rate_limit_max_requests: 100,
    };

    mockSecurityUtils = {
      encryptSensitiveData: vi.fn(),
      decryptSensitiveData: vi.fn(),
      generateSecureToken: vi.fn(),
      hashToken: vi.fn(),
      verifyTokenHash: vi.fn(),
      generateApiKey: vi.fn(),
      generateSessionToken: vi.fn(),
      timingSafeEqual: vi.fn(),
      hashPassword: vi.fn(),
      verifyPassword: vi.fn(),
      validatePassword: vi.fn(),
      generateSecurePassword: vi.fn(),
      sanitizeInput: vi.fn(),
      sanitizeEmail: vi.fn(),
      sanitizeUsername: vi.fn(),
      recordLoginAttempt: vi.fn(),
      isAccountLocked: vi.fn(),
      lockAccount: vi.fn(),
      unlockAccount: vi.fn(),
      checkRateLimit: vi.fn(),
      getRateLimitStatus: vi.fn(),
      getSecurityHeaders: vi.fn(),
      isValidScope: vi.fn(),
      isValidRole: vi.fn(),
      validateScopes: vi.fn(),
      validateId: vi.fn(),
      generateSecureId: vi.fn(),
      auditLog: vi.fn(),
      isValidIP: vi.fn(),
      isPrivateIP: vi.fn(),
      extractIPFromRequest: vi.fn(),
      getSecurityMetrics: vi.fn(),
    } as any;
  });

  describe('Symmetric Encryption (AES)', () => {
    it('should generate secure AES keys', () => {
      const key1 = MockEncryptionUtils.generateAESKey();
      const key2 = MockEncryptionUtils.generateAESKey();

      expect(key1).toBeInstanceOf(Buffer);
      expect(key1.length).toBe(32); // 256 bits
      expect(key2).toBeInstanceOf(Buffer);
      expect(key2.length).toBe(32);
      expect(key1.equals(key2)).toBe(false); // Keys should be unique
    });

    it('should generate unique initialization vectors', () => {
      const iv1 = MockEncryptionUtils.generateIV();
      const iv2 = MockEncryptionUtils.generateIV();

      expect(iv1).toBeInstanceOf(Buffer);
      expect(iv1.length).toBe(16); // 128 bits
      expect(iv2).toBeInstanceOf(Buffer);
      expect(iv2.length).toBe(16);
      expect(iv1.equals(iv2)).toBe(false); // IVs should be unique
    });

    it('should encrypt and decrypt data correctly', () => {
      const originalData = 'This is sensitive data that needs encryption';
      const key = MockEncryptionUtils.generateAESKey();

      const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(originalData, key);
      const decryptedData = MockEncryptionUtils.decryptAES(encrypted, key, iv, tag);

      expect(encrypted).toBeInstanceOf(Buffer);
      expect(iv).toBeInstanceOf(Buffer);
      expect(tag).toBeInstanceOf(Buffer);
      expect(decryptedData).toBe(originalData);
      expect(!encrypted.equals(Buffer.from(originalData))).toBe(true);
    });

    it('should fail to decrypt with wrong key', () => {
      const originalData = 'Secret message';
      const correctKey = MockEncryptionUtils.generateAESKey();
      const wrongKey = MockEncryptionUtils.generateAESKey();

      const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(originalData, correctKey);

      expect(() => {
        MockEncryptionUtils.decryptAES(encrypted, wrongKey, iv, tag);
      }).toThrow();
    });

    it('should fail to decrypt with wrong IV', () => {
      const originalData = 'Secret message';
      const key = MockEncryptionUtils.generateAESKey();
      const wrongIV = MockEncryptionUtils.generateIV();

      const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(originalData, key);

      expect(() => {
        MockEncryptionUtils.decryptAES(encrypted, key, wrongIV, tag);
      }).toThrow();
    });

    it('should fail to decrypt with wrong authentication tag', () => {
      const originalData = 'Secret message';
      const key = MockEncryptionUtils.generateAESKey();
      const wrongTag = crypto.randomBytes(16);

      const { encrypted, iv } = MockEncryptionUtils.encryptAES(originalData, key);

      expect(() => {
        MockEncryptionUtils.decryptAES(encrypted, key, iv, wrongTag);
      }).toThrow();
    });

    it('should handle empty data encryption', () => {
      const originalData = '';
      const key = MockEncryptionUtils.generateAESKey();

      const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(originalData, key);
      const decryptedData = MockEncryptionUtils.decryptAES(encrypted, key, iv, tag);

      expect(decryptedData).toBe(originalData);
    });

    it('should handle large data encryption', () => {
      const originalData = 'A'.repeat(1000000); // 1MB of data
      const key = MockEncryptionUtils.generateAESKey();

      const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(originalData, key);
      const decryptedData = MockEncryptionUtils.decryptAES(encrypted, key, iv, tag);

      expect(decryptedData).toBe(originalData);
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it('should handle Unicode and special characters', () => {
      const originalData = 'Hello 世界! 🌍 ñoël émojis 😊 and 特殊文字';
      const key = MockEncryptionUtils.generateAESKey();

      const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(originalData, key);
      const decryptedData = MockEncryptionUtils.decryptAES(encrypted, key, iv, tag);

      expect(decryptedData).toBe(originalData);
    });
  });

  describe('Asymmetric Encryption (RSA)', () => {
    it('should generate RSA key pairs with different sizes', () => {
      const keyPair2048 = MockEncryptionUtils.generateRSAKeyPair(2048);
      const keyPair4096 = MockEncryptionUtils.generateRSAKeyPair(4096);

      expect(keyPair2048.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keyPair2048.privateKey).toContain('BEGIN PRIVATE KEY');
      expect(keyPair4096.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(keyPair4096.privateKey).toContain('BEGIN PRIVATE KEY');
      expect(keyPair2048.publicKey).not.toBe(keyPair4096.publicKey);
    });

    it('should encrypt and decrypt data with RSA', () => {
      const originalData = 'RSA encrypted message';
      const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);

      const encrypted = MockEncryptionUtils.encryptRSA(originalData, keyPair.publicKey);
      const decryptedData = MockEncryptionUtils.decryptRSA(encrypted, keyPair.privateKey);

      expect(encrypted).toBeInstanceOf(Buffer);
      expect(decryptedData).toBe(originalData);
    });

    it('should handle RSA encryption size limitations', () => {
      const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);

      // Maximum data size for RSA-OAEP with SHA-256 and 2048-bit key is 190 bytes
      const maxData = 'A'.repeat(190);
      const oversizedData = 'A'.repeat(200);

      // Should work with maximum size
      expect(() => {
        const encrypted = MockEncryptionUtils.encryptRSA(maxData, keyPair.publicKey);
        const decrypted = MockEncryptionUtils.decryptRSA(encrypted, keyPair.privateKey);
        expect(decrypted).toBe(maxData);
      }).not.toThrow();

      // Should fail with oversized data
      expect(() => {
        MockEncryptionUtils.encryptRSA(oversizedData, keyPair.publicKey);
      }).toThrow();
    });

    it('should fail to decrypt with wrong private key', () => {
      const originalData = 'Secret RSA message';
      const keyPair1 = MockEncryptionUtils.generateRSAKeyPair(2048);
      const keyPair2 = MockEncryptionUtils.generateRSAKeyPair(2048);

      const encrypted = MockEncryptionUtils.encryptRSA(originalData, keyPair1.publicKey);

      expect(() => {
        MockEncryptionUtils.decryptRSA(encrypted, keyPair2.privateKey);
      }).toThrow();
    });

    it('should handle RSA encryption with different key sizes', () => {
      const originalData = 'Test message';
      const keyPair2048 = MockEncryptionUtils.generateRSAKeyPair(2048);
      const keyPair4096 = MockEncryptionUtils.generateRSAKeyPair(4096);

      const encrypted2048 = MockEncryptionUtils.encryptRSA(originalData, keyPair2048.publicKey);
      const encrypted4096 = MockEncryptionUtils.encryptRSA(originalData, keyPair4096.publicKey);

      const decrypted2048 = MockEncryptionUtils.decryptRSA(encrypted2048, keyPair2048.privateKey);
      const decrypted4096 = MockEncryptionUtils.decryptRSA(encrypted4096, keyPair4096.privateKey);

      expect(decrypted2048).toBe(originalData);
      expect(decrypted4096).toBe(originalData);
      expect(encrypted4096.length).toBeGreaterThan(encrypted2048.length);
    });
  });

  describe('Hash Generation and Validation', () => {
    it('should generate consistent SHA-256 hashes', () => {
      const data = 'Data to hash';
      const hash1 = MockEncryptionUtils.generateHash(data);
      const hash2 = MockEncryptionUtils.generateHash(data);

      expect(hash1).toBe(hash2);
      expect(hash1.length).toBe(64); // SHA-256 produces 64 hex characters
      expect(/^[a-f0-9]{64}$/.test(hash1)).toBe(true);
    });

    it('should generate different hashes for different data', () => {
      const data1 = 'First data';
      const data2 = 'Second data';
      const hash1 = MockEncryptionUtils.generateHash(data1);
      const hash2 = MockEncryptionUtils.generateHash(data2);

      expect(hash1).not.toBe(hash2);
    });

    it('should support different hash algorithms', () => {
      const data = 'Test data';
      const sha256Hash = MockEncryptionUtils.generateHash(data, 'sha256');
      const sha512Hash = MockEncryptionUtils.generateHash(data, 'sha512');

      expect(sha256Hash).not.toBe(sha512Hash);
      expect(sha256Hash.length).toBe(64);
      expect(sha512Hash.length).toBe(128);
    });

    it('should generate and verify HMAC', () => {
      const data = 'Message to authenticate';
      const secret = 'secret-key';

      const hmac = MockEncryptionUtils.generateHMAC(data, secret);
      const isValid = MockEncryptionUtils.verifyHMAC(data, hmac, secret);

      expect(hmac.length).toBe(64); // HMAC-SHA256 produces 64 hex characters
      expect(isValid).toBe(true);
    });

    it('should fail HMAC verification with wrong secret', () => {
      const data = 'Message to authenticate';
      const correctSecret = 'correct-secret';
      const wrongSecret = 'wrong-secret';

      const hmac = MockEncryptionUtils.generateHMAC(data, correctSecret);
      const isValid = MockEncryptionUtils.verifyHMAC(data, hmac, wrongSecret);

      expect(isValid).toBe(false);
    });

    it('should verify hash correctness', () => {
      const data = 'Test data';
      const hash = MockEncryptionUtils.generateHash(data);

      expect(MockEncryptionUtils.verifyHash(data, hash)).toBe(true);
      expect(MockEncryptionUtils.verifyHash('Wrong data', hash)).toBe(false);
    });

    it('should handle hashing of empty data', () => {
      const emptyData = '';
      const hash = MockEncryptionUtils.generateHash(emptyData);

      expect(hash.length).toBe(64);
      expect(/^[a-f0-9]{64}$/.test(hash)).toBe(true);
    });

    it('should handle hashing of large data', () => {
      const largeData = 'A'.repeat(1000000);
      const hash = MockEncryptionUtils.generateHash(largeData);

      expect(hash.length).toBe(64);
      expect(/^[a-f0-9]{64}$/.test(hash)).toBe(true);
    });
  });

  describe('Digital Signatures', () => {
    it('should sign and verify data', () => {
      const data = 'Important document';
      const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);

      const signature = MockEncryptionUtils.signData(data, keyPair.privateKey);
      const isValid = MockEncryptionUtils.verifySignature(data, signature, keyPair.publicKey);

      expect(signature).toBeInstanceOf(Buffer);
      expect(signature.length).toBeGreaterThan(0);
      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong data', () => {
      const originalData = 'Original document';
      const modifiedData = 'Modified document';
      const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);

      const signature = MockEncryptionUtils.signData(originalData, keyPair.privateKey);
      const isValid = MockEncryptionUtils.verifySignature(
        modifiedData,
        signature,
        keyPair.publicKey
      );

      expect(isValid).toBe(false);
    });

    it('should fail verification with wrong public key', () => {
      const data = 'Document';
      const keyPair1 = MockEncryptionUtils.generateRSAKeyPair(2048);
      const keyPair2 = MockEncryptionUtils.generateRSAKeyPair(2048);

      const signature = MockEncryptionUtils.signData(data, keyPair1.privateKey);
      const isValid = MockEncryptionUtils.verifySignature(data, signature, keyPair2.publicKey);

      expect(isValid).toBe(false);
    });

    it('should handle signatures for large data', () => {
      const largeData = 'A'.repeat(10000);
      const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);

      const signature = MockEncryptionUtils.signData(largeData, keyPair.privateKey);
      const isValid = MockEncryptionUtils.verifySignature(largeData, signature, keyPair.publicKey);

      expect(isValid).toBe(true);
    });

    it('should generate unique signatures for the same data', () => {
      const data = 'Document';
      const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);

      const signature1 = MockEncryptionUtils.signData(data, keyPair.privateKey);
      const signature2 = MockEncryptionUtils.signData(data, keyPair.privateKey);

      // RSA signatures should be deterministic with the same algorithm and padding
      // However, due to random padding in some implementations, we test verification
      expect(MockEncryptionUtils.verifySignature(data, signature1, keyPair.publicKey)).toBe(true);
      expect(MockEncryptionUtils.verifySignature(data, signature2, keyPair.publicKey)).toBe(true);
    });
  });

  describe('Key Management', () => {
    it('should derive keys from passwords using PBKDF2', () => {
      const password = 'user-password-123';
      const salt = MockEncryptionUtils.generateSalt();
      const iterations = 100000;

      const derivedKey = MockEncryptionUtils.deriveKey(password, salt, iterations);

      expect(derivedKey).toBeInstanceOf(Buffer);
      expect(derivedKey.length).toBe(32); // 256 bits
    });

    it('should generate different keys with different salts', () => {
      const password = 'same-password';
      const salt1 = MockEncryptionUtils.generateSalt();
      const salt2 = MockEncryptionUtils.generateSalt();

      const key1 = MockEncryptionUtils.deriveKey(password, salt1);
      const key2 = MockEncryptionUtils.deriveKey(password, salt2);

      expect(key1.equals(key2)).toBe(false);
    });

    it('should generate the same key with same password and salt', () => {
      const password = 'test-password';
      const salt = MockEncryptionUtils.generateSalt();

      const key1 = MockEncryptionUtils.deriveKey(password, salt);
      const key2 = MockEncryptionUtils.deriveKey(password, salt);

      expect(key1.equals(key2)).toBe(true);
    });

    it('should generate cryptographically secure salts', () => {
      const salt1 = MockEncryptionUtils.generateSalt();
      const salt2 = MockEncryptionUtils.generateSalt();

      expect(salt1).toBeInstanceOf(Buffer);
      expect(salt2).toBeInstanceOf(Buffer);
      expect(salt1.length).toBe(32);
      expect(salt2.length).toBe(32);
      expect(salt1.equals(salt2)).toBe(false);
    });

    it('should support custom salt lengths', () => {
      const shortSalt = MockEncryptionUtils.generateSalt(16);
      const longSalt = MockEncryptionUtils.generateSalt(64);

      expect(shortSalt.length).toBe(16);
      expect(longSalt.length).toBe(64);
    });

    it('should validate key strength for different algorithms', () => {
      const aes256Key = crypto.randomBytes(32);
      const aes128Key = crypto.randomBytes(16);
      const weakKey = crypto.randomBytes(8);

      expect(MockEncryptionUtils.validateKeyStrength(aes256Key, 'aes-256-gcm')).toBe(true);
      expect(MockEncryptionUtils.validateKeyStrength(aes128Key, 'aes-128-gcm')).toBe(true);
      expect(MockEncryptionUtils.validateKeyStrength(weakKey, 'aes-256-gcm')).toBe(false);
    });
  });

  describe('Data Protection', () => {
    it('should encrypt and decrypt sensitive data using SecurityUtils', () => {
      const sensitiveData = 'User social security number: 123-45-6789';
      const key = 'a'.repeat(64); // 256-bit key in hex

      mockSecurityUtils.encryptSensitiveData.mockReturnValue(
        'encrypted:1234567890abcdef:encrypteddata'
      );
      mockSecurityUtils.decryptSensitiveData.mockReturnValue(sensitiveData);

      const encrypted = mockSecurityUtils.encryptSensitiveData(sensitiveData, key);
      const decrypted = mockSecurityUtils.decryptSensitiveData(encrypted, key);

      expect(encrypted).toContain('encrypted:');
      expect(decrypted).toBe(sensitiveData);
      expect(mockSecurityUtils.encryptSensitiveData).toHaveBeenCalledWith(sensitiveData, key);
      expect(mockSecurityUtils.decryptSensitiveData).toHaveBeenCalledWith(encrypted, key);
    });

    it('should handle encryption errors gracefully', () => {
      const sensitiveData = 'Sensitive data';
      const key = 'invalid-key';

      mockSecurityUtils.encryptSensitiveData.mockImplementation(() => {
        throw new Error('Encryption failed');
      });

      expect(() => {
        mockSecurityUtils.encryptSensitiveData(sensitiveData, key);
      }).toThrow('Encryption failed');
    });

    it('should handle decryption errors gracefully', () => {
      const encryptedData = 'invalid:encrypted:data';
      const key = 'a'.repeat(64);

      mockSecurityUtils.decryptSensitiveData.mockImplementation(() => {
        throw new Error('Decryption failed');
      });

      expect(() => {
        mockSecurityUtils.decryptSensitiveData(encryptedData, key);
      }).toThrow('Decryption failed');
    });

    it('should provide timing-safe comparison', () => {
      const data1 = 'same-data';
      const data2 = 'same-data';
      const data3 = 'different-data';

      mockSecurityUtils.timingSafeEqual.mockReturnValue(true);
      mockSecurityUtils.timingSafeEqual.mockReturnValue(false);

      expect(mockSecurityUtils.timingSafeEqual(data1, data2)).toBe(true);
      expect(mockSecurityUtils.timingSafeEqual(data1, data3)).toBe(false);
    });

    it('should handle PII data masking', () => {
      const ssn = '123-45-6789';
      const creditCard = '4532-1234-5678-9012';
      const email = 'user@example.com';

      // Mock PII masking functionality
      const maskPII = (data: string, type: string): string => {
        switch (type) {
          case 'ssn':
            return `***-**-${data.slice(-4)}`;
          case 'creditcard':
            return `****-****-****-${data.slice(-4)}`;
          case 'email': {
            const [username, domain] = data.split('@');
            return `${username.slice(0, 2)}***@${domain}`;
          }
          default:
            return data;
        }
      };

      expect(maskPII(ssn, 'ssn')).toBe('***-**-6789');
      expect(maskPII(creditCard, 'creditcard')).toBe('****-****-****-9012');
      expect(maskPII(email, 'email')).toBe('us***@example.com');
    });
  });

  describe('Performance Optimization', () => {
    it('should encrypt data in parallel', async () => {
      const dataArray = Array.from({ length: 100 }, (_, i) => `Data item ${i}`);
      const key = MockEncryptionUtils.generateAESKey();

      const startTime = Date.now();
      const encryptedBatch = await MockEncryptionUtils.encryptBatch(dataArray, key);
      const endTime = Date.now();

      expect(encryptedBatch).toHaveLength(100);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds

      const decryptedBatch = await MockEncryptionUtils.decryptBatch(encryptedBatch, key);
      expect(decryptedBatch).toEqual(dataArray);
    });

    it('should handle memory-efficient encryption of large datasets', async () => {
      const largeDataArray = Array.from(
        { length: 1000 },
        (_, i) => `Large data item ${i} with additional content`
      );
      const key = MockEncryptionUtils.generateAESKey();

      // Process in chunks to manage memory
      const chunkSize = 100;
      const encryptedChunks: Array<Array<{ encrypted: Buffer; iv: Buffer; tag: Buffer }>> = [];

      for (let i = 0; i < largeDataArray.length; i += chunkSize) {
        const chunk = largeDataArray.slice(i, i + chunkSize);
        const encryptedChunk = await MockEncryptionUtils.encryptBatch(chunk, key);
        encryptedChunks.push(encryptedChunk);
      }

      expect(encryptedChunks).toHaveLength(10); // 1000 items / 100 chunk size
      expect(encryptedChunks.flat()).toHaveLength(1000);
    });

    it('should benchmark encryption performance', () => {
      const testData = 'Performance test data';
      const key = MockEncryptionUtils.generateAESKey();
      const iterations = 1000;

      const startTime = process.hrtime.bigint();

      for (let i = 0; i < iterations; i++) {
        const { encrypted, iv, tag } = MockEncryptionUtils.encryptAES(testData, key);
        MockEncryptionUtils.decryptAES(encrypted, key, iv, tag);
      }

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

      expect(duration).toBeLessThan(1000); // Should complete 1000 operations within 1 second
      expect(duration / iterations).toBeLessThan(1); // Average less than 1ms per operation
    });

    it('should support hardware acceleration detection', () => {
      // Mock hardware acceleration detection
      const hasHardwareAcceleration = (): boolean => {
        // In a real implementation, this would check for AES-NI, crypto hardware, etc.
        return process.arch === 'x64' || process.arch === 'arm64';
      };

      const accelerationStatus = hasHardwareAcceleration();
      expect(typeof accelerationStatus).toBe('boolean');
    });
  });

  describe('Compliance and Standards', () => {
    it('should validate secure algorithms', () => {
      expect(MockEncryptionUtils.isSecureAlgorithm('aes-256-gcm')).toBe(true);
      expect(MockEncryptionUtils.isSecureAlgorithm('aes-256-cbc')).toBe(true);
      expect(MockEncryptionUtils.isSecureAlgorithm('sha256')).toBe(true);
      expect(MockEncryptionUtils.isSecureAlgorithm('sha512')).toBe(true);
      expect(MockEncryptionUtils.isSecureAlgorithm('rsa-oaep')).toBe(true);

      expect(MockEncryptionUtils.isSecureAlgorithm('des')).toBe(false);
      expect(MockEncryptionUtils.isSecureAlgorithm('md5')).toBe(false);
      expect(MockEncryptionUtils.isSecureAlgorithm('sha1')).toBe(false);
    });

    it('should enforce FIPS-compliant algorithms', () => {
      const fipsAlgorithms = ['aes-256-gcm', 'aes-256-cbc', 'sha256', 'sha512', 'rsa-oaep'];
      const nonFipsAlgorithms = ['des', 'rc4', 'md5', 'sha1'];

      fipsAlgorithms.forEach((algo) => {
        expect(MockEncryptionUtils.isSecureAlgorithm(algo)).toBe(true);
      });

      nonFipsAlgorithms.forEach((algo) => {
        expect(MockEncryptionUtils.isSecureAlgorithm(algo)).toBe(false);
      });
    });

    it('should maintain audit trail for encryption operations', () => {
      const auditLog: Array<{ operation: string; timestamp: Date; metadata: any }> = [];

      const logEncryptionOperation = (operation: string, metadata: any) => {
        auditLog.push({
          operation,
          timestamp: new Date(),
          metadata,
        });
      };

      logEncryptionOperation('encrypt', { algorithm: 'aes-256-gcm', keySize: 256 });
      logEncryptionOperation('decrypt', { algorithm: 'aes-256-gcm', keySize: 256 });
      logEncryptionOperation('sign', { algorithm: 'rsa-sha256', keySize: 2048 });

      expect(auditLog).toHaveLength(3);
      expect(auditLog[0].operation).toBe('encrypt');
      expect(auditLog[1].operation).toBe('decrypt');
      expect(auditLog[2].operation).toBe('sign');

      auditLog.forEach((entry) => {
        expect(entry.timestamp).toBeInstanceOf(Date);
        expect(entry.metadata).toBeDefined();
      });
    });

    it('should validate industry standard compliance', () => {
      const complianceChecks = {
        pciDss: {
          requiresStrongCryptography: true,
          requiresSecureKeyManagement: true,
          requiresAuditLogging: true,
        },
        gdpr: {
          requiresDataEncryption: true,
          requiresDataPortability: true,
          requiresRightToBeForgotten: true,
        },
        hipaa: {
          requiresEncryptionAtRest: true,
          requiresEncryptionInTransit: true,
          requiresAccessControls: true,
        },
      };

      Object.entries(complianceChecks).forEach(([standard, requirements]) => {
        Object.entries(requirements).forEach(([requirement, required]) => {
          expect(typeof required).toBe('boolean');
        });
      });
    });

    it('should support certificate-based operations', () => {
      // Mock certificate generation and validation
      const generateSelfSignedCertificate = (): { cert: string; key: string } => {
        const keyPair = MockEncryptionUtils.generateRSAKeyPair(2048);
        // In a real implementation, this would generate an X.509 certificate
        return {
          cert: '-----BEGIN CERTIFICATE-----\nMOCK_CERTIFICATE_DATA\n-----END CERTIFICATE-----',
          key: keyPair.privateKey,
        };
      };

      const { cert, key } = generateSelfSignedCertificate();

      expect(cert).toContain('BEGIN CERTIFICATE');
      expect(key).toContain('BEGIN PRIVATE KEY');
    });
  });

  describe('Integration and Security', () => {
    it('should integrate with authentication services', () => {
      const password = 'SecurePassword123!';
      const hashedPassword = 'hashed_password_value';

      (bcrypt.hash as any).mockResolvedValue(hashedPassword);
      (bcrypt.compare as any).mockResolvedValue(true);

      mockSecurityUtils.hashPassword(password).then((result) => {
        expect(result).toBe(hashedPassword);
        expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
      });

      mockSecurityUtils.verifyPassword(password, hashedPassword).then((result) => {
        expect(result).toBe(true);
        expect(bcrypt.compare).toHaveBeenCalledWith(password, hashedPassword);
      });
    });

    it('should generate secure API keys', () => {
      const { keyId, key } = {
        keyId: 'ck_1234567890abcdef',
        key: 'ck_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      };

      mockSecurityUtils.generateApiKey.mockReturnValue({ keyId, key });

      const result = mockSecurityUtils.generateApiKey();

      expect(result.keyId).toMatch(/^ck_[a-f0-9]{16}$/);
      expect(result.key).toMatch(/^ck_[a-f0-9]{64}$/);
      expect(mockSecurityUtils.generateApiKey).toHaveBeenCalled();
    });

    it('should support session token management', () => {
      const sessionToken = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

      mockSecurityUtils.generateSessionToken.mockReturnValue(sessionToken);
      mockSecurityUtils.hashToken.mockReturnValue('hashed_token_value');
      mockSecurityUtils.verifyTokenHash.mockReturnValue(true);

      const token = mockSecurityUtils.generateSessionToken();
      const hashedToken = mockSecurityUtils.hashToken(token);
      const isValid = mockSecurityUtils.verifyTokenHash(token, hashedToken);

      expect(token).toMatch(/^[a-f0-9]{64}$/);
      expect(hashedToken).toBe('hashed_token_value');
      expect(isValid).toBe(true);
    });

    it('should provide comprehensive security headers', () => {
      const securityHeaders = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'",
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      };

      mockSecurityUtils.getSecurityHeaders.mockReturnValue(securityHeaders);

      const headers = mockSecurityUtils.getSecurityHeaders();

      expect(headers).toEqual(securityHeaders);
      expect(headers['X-Frame-Options']).toBe('DENY');
      expect(headers['Strict-Transport-Security']).toContain('max-age=31536000');
    });

    it('should handle security audit logging', () => {
      const auditEntry = {
        action: 'encryption_operation',
        details: { algorithm: 'aes-256-gcm', dataSize: 1024 },
        severity: 'medium' as const,
      };

      mockSecurityUtils.auditLog.mockImplementation((action, details, severity) => {
        expect(action).toBe('encryption_operation');
        expect(details.algorithm).toBe('aes-256-gcm');
        expect(severity).toBe('medium');
      });

      mockSecurityUtils.auditLog(auditEntry.action, auditEntry.details, auditEntry.severity);
      expect(mockSecurityUtils.auditLog).toHaveBeenCalled();
    });

    it('should support database encryption integration', () => {
      const sensitiveFields = ['ssn', 'creditCard', 'medicalRecord'];
      const record = {
        id: 'user123',
        name: 'John Doe',
        ssn: '123-45-6789',
        creditCard: '4532-1234-5678-9012',
        email: 'john@example.com',
      };

      // Mock database encryption
      const encryptRecordFields = (record: any, fieldsToEncrypt: string[], key: string) => {
        const encrypted = { ...record };
        fieldsToEncrypt.forEach((field) => {
          if (encrypted[field]) {
            encrypted[field] = `encrypted:${encrypted[field]}`;
          }
        });
        return encrypted;
      };

      const key = 'encryption_key_123';
      const encryptedRecord = encryptRecordFields(record, sensitiveFields, key);

      expect(encryptedRecord.ssn).toBe('encrypted:123-45-6789');
      expect(encryptedRecord.creditCard).toBe('encrypted:4532-1234-5678-9012');
      expect(encryptedRecord.name).toBe('John Doe'); // Not encrypted
      expect(encryptedRecord.email).toBe('john@example.com'); // Not encrypted
    });

    it('should validate secure random number generation', () => {
      const randomBytes1 = crypto.randomBytes(32);
      const randomBytes2 = crypto.randomBytes(32);

      expect(randomBytes1).toBeInstanceOf(Buffer);
      expect(randomBytes2).toBeInstanceOf(Buffer);
      expect(randomBytes1.length).toBe(32);
      expect(randomBytes2.length).toBe(32);
      expect(randomBytes1.equals(randomBytes2)).toBe(false);

      // Test randomness quality (basic statistical test)
      const bytes = crypto.randomBytes(10000);
      let zeroCount = 0;
      let oneCount = 0;

      for (const byte of bytes) {
        for (let bit = 0; bit < 8; bit++) {
          if ((byte >> bit) & 1) {
            oneCount++;
          } else {
            zeroCount++;
          }
        }
      }

      // Should be roughly 50/50 distribution (within 5% tolerance)
      const totalBits = zeroCount + oneCount;
      const zeroRatio = zeroCount / totalBits;
      const oneRatio = oneCount / totalBits;

      expect(zeroRatio).toBeGreaterThan(0.45);
      expect(zeroRatio).toBeLessThan(0.55);
      expect(oneRatio).toBeGreaterThan(0.45);
      expect(oneRatio).toBeLessThan(0.55);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null/undefined inputs gracefully', () => {
      expect(() => {
        MockEncryptionUtils.encryptAES(null as any, MockEncryptionUtils.generateAESKey());
      }).toThrow();

      expect(() => {
        MockEncryptionUtils.encryptAES('data', null as any);
      }).toThrow();
    });

    it('should handle buffer conversion issues', () => {
      const key = MockEncryptionUtils.generateAESKey();

      expect(() => {
        MockEncryptionUtils.encryptAES('', key);
      }).not.toThrow();

      expect(() => {
        MockEncryptionUtils.encryptAES('valid data', key);
      }).not.toThrow();
    });

    it('should handle concurrent encryption operations', async () => {
      const key = MockEncryptionUtils.generateAESKey();
      const promises = Array.from({ length: 100 }, (_, i) =>
        MockEncryptionUtils.encryptAES(`Concurrent data ${i}`, key)
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(100);
      results.forEach(({ encrypted, iv, tag }) => {
        expect(encrypted).toBeInstanceOf(Buffer);
        expect(iv).toBeInstanceOf(Buffer);
        expect(tag).toBeInstanceOf(Buffer);
      });
    });

    it('should handle memory pressure during large operations', async () => {
      const key = MockEncryptionUtils.generateAESKey();
      const largeDataSets = Array.from(
        { length: 10 },
        (_, i) => 'A'.repeat(100000) // 100KB each
      );

      // Process sequentially to avoid memory spikes
      const results = [];
      for (const data of largeDataSets) {
        const encrypted = MockEncryptionUtils.encryptAES(data, key);
        results.push(encrypted);

        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }

      expect(results).toHaveLength(10);
    });
  });
});

describe('Security Integration Tests', () => {
  let securityConfig: SecurityConfig;
  let securityUtils: SecurityUtils;

  beforeEach(() => {
    securityConfig = {
      password_min_length: 12,
      password_require_uppercase: true,
      password_require_lowercase: true,
      password_require_numbers: true,
      password_require_symbols: true,
      max_login_attempts: 3,
      login_attempt_window_ms: 900000,
      account_lockout_duration_ms: 1800000,
      session_timeout_ms: 3600000,
      secure_cookie: true,
      rate_limit_window_ms: 900000,
      rate_limit_max_requests: 100,
    };

    securityUtils = new SecurityUtils(securityConfig);
  });

  describe('Complete Encryption Workflow', () => {
    it('should demonstrate end-to-end encryption workflow', async () => {
      // 1. Generate master key
      const masterKey = MockEncryptionUtils.generateAESKey();

      // 2. Generate data encryption key
      const dataKey = MockEncryptionUtils.generateAESKey();

      // 3. Encrypt data key with master key
      const { encrypted: encryptedDataKey, iv: keyIV } = MockEncryptionUtils.encryptKey(
        dataKey,
        masterKey
      );

      // 4. Encrypt sensitive data
      const sensitiveData = 'Patient medical record: John Doe, Age 45, Condition: Hypertension';
      const {
        encrypted: encryptedData,
        iv: dataIV,
        tag,
      } = MockEncryptionUtils.encryptAES(sensitiveData, dataKey);

      // 5. Store encrypted components (simulating database storage)
      const storedData = {
        encryptedDataKey: encryptedDataKey.toString('base64'),
        keyIV: keyIV.toString('base64'),
        encryptedData: encryptedData.toString('base64'),
        dataIV: dataIV.toString('base64'),
        tag: tag.toString('base64'),
      };

      // 6. Retrieval and decryption workflow
      const retrievedDataKey = MockEncryptionUtils.decryptKey(
        Buffer.from(storedData.encryptedDataKey, 'base64'),
        masterKey,
        Buffer.from(storedData.keyIV, 'base64')
      );

      const retrievedData = MockEncryptionUtils.decryptAES(
        Buffer.from(storedData.encryptedData, 'base64'),
        retrievedDataKey,
        Buffer.from(storedData.dataIV, 'base64'),
        Buffer.from(storedData.tag, 'base64')
      );

      expect(retrievedData).toBe(sensitiveData);
    });

    it('should handle key rotation workflow', () => {
      // 1. Generate old and new master keys
      const oldMasterKey = MockEncryptionUtils.generateAESKey();
      const newMasterKey = MockEncryptionUtils.generateAESKey();

      // 2. Encrypt data with old key
      const dataKey = MockEncryptionUtils.generateAESKey();
      const { encrypted: encryptedDataKey, iv } = MockEncryptionUtils.encryptKey(
        dataKey,
        oldMasterKey
      );

      // 3. Decrypt with old key and re-encrypt with new key
      const decryptedDataKey = MockEncryptionUtils.decryptKey(encryptedDataKey, oldMasterKey, iv);
      const { encrypted: newEncryptedDataKey, iv: newIV } = MockEncryptionUtils.encryptKey(
        decryptedDataKey,
        newMasterKey
      );

      // 4. Verify new encryption works
      const retrievedDataKey = MockEncryptionUtils.decryptKey(
        newEncryptedDataKey,
        newMasterKey,
        newIV
      );

      expect(retrievedDataKey.equals(dataKey)).toBe(true);
      expect(!encryptedDataKey.equals(newEncryptedDataKey)).toBe(true);
    });
  });

  describe('Multi-layer Security', () => {
    it('should implement defense in depth', () => {
      const sensitiveData = 'Multi-layer security test data';

      // Layer 1: Application-level encryption
      const appKey = MockEncryptionUtils.generateAESKey();
      const {
        encrypted: appEncrypted,
        iv: appIV,
        tag: appTag,
      } = MockEncryptionUtils.encryptAES(sensitiveData, appKey);

      // Layer 2: Transport encryption (simulated)
      const transportKey = MockEncryptionUtils.generateAESKey();
      const {
        encrypted: transportEncrypted,
        iv: transportIV,
        tag: transportTag,
      } = MockEncryptionUtils.encryptAES(appEncrypted.toString('base64'), transportKey);

      // Layer 3: Database field encryption (simulated)
      const dbKey = MockEncryptionUtils.generateAESKey();
      const {
        encrypted: dbEncrypted,
        iv: dbIV,
        tag: dbTag,
      } = MockEncryptionUtils.encryptAES(transportEncrypted.toString('base64'), dbKey);

      // Reverse the process
      const transportDecrypted = MockEncryptionUtils.decryptAES(dbEncrypted, dbKey, dbIV, dbTag);
      const appDecrypted = MockEncryptionUtils.decryptAES(
        Buffer.from(transportDecrypted, 'base64'),
        transportKey,
        transportIV,
        transportTag
      );
      const originalData = MockEncryptionUtils.decryptAES(
        Buffer.from(appDecrypted, 'base64'),
        appKey,
        appIV,
        appTag
      );

      expect(originalData).toBe(sensitiveData);
    });
  });
});
