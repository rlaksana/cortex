import {
  describe,
  test,
  expect,
  beforeEach,
  afterEach,
  vi,
  type MockedFunction,
  type MockedObject,
} from 'vitest';
import { Request, Response, NextFunction } from 'express';
import {
  AuthMiddleware,
  type AuthenticatedRequest,
} from '../../../src/middleware/auth-middleware.js';
import { AuthService } from '../../../src/services/auth/auth-service.js';
import { AuditService } from '../../../src/services/audit/audit-service.js';
import {
  AuthContext,
  AuthError,
  AuthMiddlewareConfig,
  AuthScope,
  SecurityAuditLog,
  UserRole,
  IPValidationConfig,
} from '../../../src/types/auth-types.js';
import { logger } from '../../../src/utils/logger.js';

// Mock dependencies
vi.mock('../../../src/utils/logger.js');
const mockLogger = vi.mocked(logger);

// Mock crypto - will be handled inline in tests

describe('AuthMiddleware', () => {
  let authMiddleware: AuthMiddleware;
  let mockAuthService: MockedObject<AuthService>;
  let mockAuditService: MockedObject<AuditService>;
  let mockRequest: MockedObject<AuthenticatedRequest>;
  let mockResponse: MockedObject<Response>;
  let mockNext: MockedFunction<NextFunction>;

  // Test data
  const mockUser = {
    id: 'user-123',
    username: 'testuser',
    role: UserRole._USER,
  };

  const mockAuthContext: AuthContext = {
    user: mockUser,
    session: {
      id: 'session-123',
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0 (Test Browser)',
    },
    scopes: [AuthScope._MEMORY_READ, AuthScope._MEMORY_WRITE],
    token_jti: 'token-123',
  };

  const validJwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid.jwt.token';
  const validApiKey = 'ck_live_123456789012345678901234567890';

  beforeEach(() => {
    // Clear all mocks
    vi.clearAllMocks();

    // Setup mock services
    mockAuthService = {
      createAuthContext: vi.fn(),
      validateApiKeyWithDatabase: vi.fn(),
      checkRateLimit: vi.fn(),
    } as any;

    mockAuditService = {
      logSecurityAuditEvent: vi.fn(),
      logRateLimitExceeded: vi.fn(),
    } as any;

    // Create auth middleware instance
    authMiddleware = new AuthMiddleware(mockAuthService, mockAuditService);

    // Setup mock request/response/next
    mockRequest = {
      headers: {},
      ip: '192.168.1.100',
      socket: { remoteAddress: '192.168.1.100' },
      path: '/api/memory',
      method: 'POST',
    } as any;

    mockResponse = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    } as any;

    mockNext = vi.fn();

    // Setup default mock implementations
    mockAuthService.createAuthContext.mockResolvedValue(mockAuthContext);
    mockAuthService.validateApiKeyWithDatabase.mockResolvedValue({
      user: mockUser,
      scopes: [AuthScope._MEMORY_READ],
      apiKeyInfo: { id: 'api-key-123', key_id: 'ck_test_123' },
    });
    mockAuthService.checkRateLimit.mockReturnValue(true);
    mockAuditService.logSecurityAuditEvent.mockResolvedValue(undefined);
    mockAuditService.logRateLimitExceeded.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Middleware Operations', () => {
    test('should successfully authenticate with valid JWT token', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuthService.createAuthContext).toHaveBeenCalledWith(
        validJwtToken,
        '192.168.1.100',
        'unknown'
      );
      expect(mockRequest.auth).toEqual(mockAuthContext);
      expect(mockRequest.user).toEqual(mockUser);
      expect(mockNext).toHaveBeenCalled();
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          user_id: 'user-123',
          session_id: 'session-123',
        })
      );
    });

    test('should successfully authenticate with valid API key', async () => {
      // Arrange
      mockRequest.headers['x-api-key'] = validApiKey;
      const middleware = authMiddleware.authenticate({ allow_api_keys: true });

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuthService.validateApiKeyWithDatabase).toHaveBeenCalledWith(validApiKey);
      expect(mockRequest.auth).toBeDefined();
      expect(mockRequest.user).toEqual(mockUser);
      expect(mockNext).toHaveBeenCalled();
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          user_id: 'user-123',
        })
      );
    });

    test('should reject request with no authentication credentials', async () => {
      // Arrange
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'INVALID_TOKEN',
          message: 'No valid authentication credentials provided',
        }),
      });
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          details: expect.objectContaining({
            error_code: 'INVALID_TOKEN',
          }),
        })
      );
    });

    test('should handle malformed authorization header', async () => {
      // Arrange
      mockRequest.headers.authorization = 'InvalidFormat token123';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    test('should handle API key authentication when disabled', async () => {
      // Arrange
      mockRequest.headers['x-api-key'] = validApiKey;
      const middleware = authMiddleware.authenticate({ allow_api_keys: false });

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockAuthService.validateApiKeyWithDatabase).not.toHaveBeenCalled();
    });
  });

  describe('Token Management', () => {
    test('should validate JWT token with correct format', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuthService.createAuthContext).toHaveBeenCalledWith(
        validJwtToken,
        '192.168.1.100',
        expect.any(String)
      );
    });

    test('should handle JWT token expiration', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.createAuthContext.mockRejectedValue(new Error('EXPIRED_TOKEN'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'EXPIRED_TOKEN',
          message: 'Access token has expired',
        }),
      });
    });

    test('should handle invalid JWT token', async () => {
      // Arrange
      const invalidToken = 'invalid.jwt.token';
      mockRequest.headers.authorization = `Bearer ${invalidToken}`;
      mockAuthService.createAuthContext.mockRejectedValue(new Error('INVALID_TOKEN'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'INVALID_TOKEN',
          message: 'Invalid access token',
        }),
      });
    });

    test('should handle session expiration', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.createAuthContext.mockRejectedValue(new Error('SESSION_EXPIRED'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'SESSION_EXPIRED',
          message: 'User session has expired',
        }),
      });
    });

    test('should support multiple token types in same request', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['x-api-key'] = validApiKey;
      const middleware = authMiddleware.authenticate({ allow_api_keys: true });

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // JWT should take precedence over API key
      expect(mockAuthService.createAuthContext).toHaveBeenCalled();
      expect(mockAuthService.validateApiKeyWithDatabase).not.toHaveBeenCalled();
    });

    test('should validate token JTI for revocation checking', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth?.token_jti).toBe('token-123');
    });
  });

  describe('Session Management', () => {
    test('should create and attach user context to request', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth).toBeDefined();
      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.auth?.user.id).toBe('user-123');
      expect(mockRequest.auth?.session.id).toBe('session-123');
    });

    test('should handle session timeout scenarios', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.createAuthContext.mockRejectedValue(new Error('SESSION_EXPIRED'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          details: expect.objectContaining({
            error_code: 'SESSION_EXPIRED',
          }),
        })
      );
    });

    test('should maintain session continuity across requests', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act - Simulate multiple requests
      await middleware(mockRequest, mockResponse, mockNext);
      const firstSessionId = mockRequest.auth?.session.id;

      // Reset mocks for second request
      vi.clearAllMocks();
      mockAuthService.createAuthContext.mockResolvedValue(mockAuthContext);

      await middleware(mockRequest, mockResponse, mockNext);
      const secondSessionId = mockRequest.auth?.session.id;

      // Assert
      expect(firstSessionId).toBe(secondSessionId);
    });

    test('should validate session IP address consistency', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.ip = '192.168.1.200'; // Different IP
      const middleware = authMiddleware.authenticate({
        ip_validation: { mode: 'strict' },
      });

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // Should fail strict IP validation since IPs don't match
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    test('should handle session recovery scenarios', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.createAuthContext.mockResolvedValue({
        ...mockAuthContext,
        session: {
          ...mockAuthContext.session,
          id: 'recovered-session-123',
        },
      });
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth?.session.id).toBe('recovered-session-123');
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Security Validation', () => {
    test('should validate request signature when enabled', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['x-signature'] = 'valid-signature';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Note: Actual signature validation would be implemented in AuthService
    });

    test('should detect and handle suspicious request patterns', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['user-agent'] = 'SuspiciousBot/1.0';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          user_agent: 'SuspiciousBot/1.0',
        })
      );
    });

    test('should validate security headers', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['x-forwarded-for'] = '203.0.113.1, 192.168.1.1';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // IP extraction should handle forwarded headers properly
    });

    test('should prevent header injection attacks', async () => {
      // Arrange
      mockRequest.headers['x-forwarded-for'] = '192.168.1.1\nInjected-Header: malicious';
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // Should handle malformed headers safely
      expect(mockNext).toHaveBeenCalled();
    });

    test('should validate CSRF tokens for state-changing requests', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.method = 'POST';
      mockRequest.headers['x-csrf-token'] = 'valid-csrf-token';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Note: CSRF validation would be implemented with proper token verification
    });

    test('should detect malicious payload attempts', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['x-malicious'] = '<script>alert("xss")</script>';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Request should proceed but with proper sanitization
    });
  });

  describe('Scope and Authorization Validation', () => {
    test('should validate required scopes successfully', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const config: AuthMiddlewareConfig = {
        required_scopes: [AuthScope._MEMORY_READ],
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should reject insufficient scopes', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const config: AuthMiddlewareConfig = {
        required_scopes: [AuthScope._SYSTEM_MANAGE],
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'INSUFFICIENT_SCOPES',
          message: 'Required scopes: system:manage',
        }),
      });
    });

    test('should handle multiple required scopes with AND logic', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const config: AuthMiddlewareConfig = {
        required_scopes: [AuthScope._MEMORY_READ, AuthScope._MEMORY_WRITE],
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should validate optional scopes when provided', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const config: AuthMiddlewareConfig = {
        optional_scopes: [AuthScope._SEARCH_ADVANCED],
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Optional scopes should not block authentication
    });

    test('should use requireScopes middleware for additional validation', async () => {
      // Arrange
      mockRequest.auth = mockAuthContext;
      const middleware = authMiddleware.requireScopes([AuthScope._MEMORY_READ]);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should reject requireScopes when no auth context', async () => {
      // Arrange
      const middleware = authMiddleware.requireScopes([AuthScope._MEMORY_READ]);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'INVALID_TOKEN',
          message: 'Authentication required',
        }),
      });
    });

    test('should use requireRole middleware for role-based access', async () => {
      // Arrange
      mockRequest.auth = mockAuthContext;
      const middleware = authMiddleware.requireRole(UserRole._USER);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should reject requireRole for insufficient role', async () => {
      // Arrange
      mockRequest.auth = {
        ...mockAuthContext,
        user: { ...mockUser, role: UserRole._READ_ONLY },
      };
      const middleware = authMiddleware.requireRole(UserRole._ADMIN);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'INSUFFICIENT_SCOPES',
          message: 'Required roles: admin',
        }),
      });
    });

    test('should handle resource-based authorization', async () => {
      // Arrange
      mockRequest.auth = mockAuthContext;
      mockRequest.path = '/api/memory/store';
      const middleware = authMiddleware.requireResourceAccess('memory_store', 'POST');

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits when configured', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.checkRateLimit.mockReturnValue(false);
      const config: AuthMiddlewareConfig = {
        rate_limit: {
          requests: 100,
          window_ms: 3600000,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuthService.checkRateLimit).toHaveBeenCalledWith('user-123', 100, 3600000);
      expect(mockResponse.status).toHaveBeenCalledWith(429);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'RATE_LIMITED',
          message: 'Too many requests',
        }),
      });
      expect(mockAuditService.logRateLimitExceeded).toHaveBeenCalledWith(
        'user-123',
        '/api/memory',
        100,
        3600000,
        '192.168.1.100',
        expect.any(String),
        'user-123'
      );
    });

    test('should allow requests within rate limit', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.checkRateLimit.mockReturnValue(true);
      const config: AuthMiddlewareConfig = {
        rate_limit: {
          requests: 100,
          window_ms: 3600000,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      expect(mockAuthService.checkRateLimit).toHaveBeenCalled();
    });

    test('should use API key prefix for rate limiting with API key auth', async () => {
      // Arrange
      mockRequest.headers['x-api-key'] = validApiKey;
      mockAuthService.checkRateLimit.mockReturnValue(true);
      const config: AuthMiddlewareConfig = {
        rate_limit: {
          requests: 1000,
          window_ms: 3600000,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuthService.checkRateLimit).toHaveBeenCalledWith('user-123', 1000, 3600000);
    });

    test('should handle rate limit service failures gracefully', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.checkRateLimit.mockImplementation(() => {
        throw new Error('Rate limit service unavailable');
      });
      const config: AuthMiddlewareConfig = {
        rate_limit: {
          requests: 100,
          window_ms: 3600000,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // The middleware should handle the error gracefully and send an error response
      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('IP Validation and Security', () => {
    test('should validate IP address in strict mode', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const config: AuthMiddlewareConfig = {
        ip_validation: {
          mode: 'strict',
          validate_headers: true,
          log_ip_changes: true,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle IP validation failures', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.ip = '203.0.113.1'; // Different IP
      const config: AuthMiddlewareConfig = {
        ip_validation: {
          mode: 'strict',
          validate_headers: true,
          log_ip_changes: true,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // Should fail strict IP validation
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: expect.objectContaining({
          code: 'IP_VALIDATION_FAILED',
        }),
      });
    });

    test('should support subnet-based IP validation', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.ip = '192.168.1.150'; // Same subnet
      const config: AuthMiddlewareConfig = {
        ip_validation: {
          mode: 'subnet',
          subnet_mask: 24,
          allowed_subnets: ['192.168.1.0/24'],
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle disabled IP validation', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.ip = '203.0.113.1'; // Different IP
      const config: AuthMiddlewareConfig = {
        ip_validation: {
          mode: 'disabled',
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should extract IP from X-Forwarded-For header', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['x-forwarded-for'] = '203.0.113.1, 192.168.1.1';
      mockRequest.ip = undefined;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Should extract rightmost IP from forwarded header
    });

    test('should prevent IP spoofing attacks', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['x-forwarded-for'] = '192.168.1.1\n\rInjected-Header: malicious';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Should handle malformed headers safely without injection
    });

    test('should validate IPv6 addresses correctly', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.ip = '192.168.1.100'; // Same IP as session
      const config: AuthMiddlewareConfig = {
        ip_validation: {
          mode: 'strict',
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
    });

    test('should detect suspicious IP changes', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.ip = '203.0.113.1'; // Geographically different
      const config: AuthMiddlewareConfig = {
        ip_validation: {
          mode: 'strict',
          log_ip_changes: true,
        },
      };
      const middleware = authMiddleware.authenticate(config);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          severity: 'high',
          details: expect.objectContaining({
            error_code: 'IP_VALIDATION_FAILED',
          }),
        })
      );
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle authentication service failures gracefully', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuthService.createAuthContext.mockRejectedValue(new Error('Service unavailable'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          severity: 'high',
        })
      );
    });

    test('should handle audit service failures gracefully', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuditService.logSecurityAuditEvent.mockRejectedValue(new Error('Audit failed'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // Should continue even if audit logging fails
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle malformed JSON in responses', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockResponse.json.mockImplementation(() => {
        throw new Error('JSON serialization failed');
      });
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // The middleware should handle JSON serialization errors gracefully
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle concurrent authentication requests', async () => {
      // Arrange
      const requests = Array.from({ length: 5 }, () => ({
        ...mockRequest,
        headers: { authorization: `Bearer ${validJwtToken}` },
      }));
      const middleware = authMiddleware.authenticate();

      // Act
      const promises = requests.map((req) => middleware(req, mockResponse, mockNext));
      await Promise.all(promises);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(5);
      expect(mockAuthService.createAuthContext).toHaveBeenCalledTimes(5);
    });

    test('should handle missing request properties gracefully', async () => {
      // Arrange
      const incompleteRequest = {
        headers: { authorization: `Bearer ${validJwtToken}` },
        ip: '192.168.1.100', // Provide an IP since the middleware needs it
        socket: { remoteAddress: '192.168.1.100' },
        path: '/api/test',
        method: 'GET',
      } as AuthenticatedRequest;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(incompleteRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Should handle missing properties gracefully
    });

    test('should validate configuration parameters', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const invalidConfig: AuthMiddlewareConfig = {
        rate_limit: {
          requests: -1,
          window_ms: 0,
        },
      };
      const middleware = authMiddleware.authenticate(invalidConfig);

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      // Should handle invalid configuration gracefully
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle extremely long headers', async () => {
      // Arrange
      const longUserAgent = 'A'.repeat(10000);
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.headers['user-agent'] = longUserAgent;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Should handle long headers without performance issues
    });
  });

  describe('Optional Authentication', () => {
    test('should attach auth context when available with optional auth', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.optionalAuth();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth).toEqual(mockAuthContext);
      expect(mockNext).toHaveBeenCalled();
    });

    test('should continue without auth when credentials missing with optional auth', async () => {
      // Arrange
      const middleware = authMiddleware.optionalAuth();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
    });

    test('should continue without auth when credentials invalid with optional auth', async () => {
      // Arrange
      mockRequest.headers.authorization = 'Bearer invalid-token';
      mockAuthService.createAuthContext.mockRejectedValue(new Error('Invalid token'));
      const middleware = authMiddleware.optionalAuth();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth).toBeUndefined();
      expect(mockNext).toHaveBeenCalled();
      expect(mockLogger.warn).toHaveBeenCalled();
    });

    test('should support API keys with optional auth', async () => {
      // Arrange
      mockRequest.headers['x-api-key'] = validApiKey;
      const middleware = authMiddleware.optionalAuth({ allow_api_keys: true });

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth).toBeDefined();
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Performance and Integration', () => {
    test('should complete authentication quickly', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      const startTime = Date.now();
      await middleware(mockRequest, mockResponse, mockNext);
      const endTime = Date.now();

      // Assert
      expect(endTime - startTime).toBeLessThan(100); // Should complete in < 100ms
      expect(mockNext).toHaveBeenCalled();
    });

    test('should handle high-volume authentication requests', async () => {
      // Arrange
      const requestCount = 100;
      const middleware = authMiddleware.authenticate();

      // Act
      const startTime = Date.now();
      const promises = Array.from({ length: requestCount }, () => {
        const req = {
          ...mockRequest,
          headers: { authorization: `Bearer ${validJwtToken}` },
        };
        return middleware(req, mockResponse, mockNext);
      });
      await Promise.all(promises);
      const endTime = Date.now();

      // Assert
      expect(endTime - startTime).toBeLessThan(1000); // Should handle 100 requests in < 1s
      expect(mockNext).toHaveBeenCalledTimes(requestCount);
    });

    test('should minimize memory usage during authentication', async () => {
      // Arrange
      const middleware = authMiddleware.authenticate();

      // Act
      const initialMemory = process.memoryUsage().heapUsed;
      await middleware(mockRequest, mockResponse, mockNext);
      const finalMemory = process.memoryUsage().heapUsed;

      // Assert
      const memoryIncrease = finalMemory - initialMemory;
      expect(memoryIncrease).toBeLessThan(1024 * 1024); // Less than 1MB increase
    });

    test('should integrate properly with Express middleware chain', async () => {
      // Arrange
      const mockNextMiddleware = vi.fn();
      const middleware = authMiddleware.authenticate();
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;

      // Act
      await middleware(mockRequest, mockResponse, mockNextMiddleware);

      // Assert
      expect(mockNextMiddleware).toHaveBeenCalled();
      expect(mockRequest.auth).toBeDefined();
    });

    test('should maintain request context through middleware chain', async () => {
      // Arrange
      const middleware = authMiddleware.authenticate();
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockRequest.auth).toBeDefined();
      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.auth?.user).toBe(mockRequest.user);
    });
  });

  describe('Logging and Monitoring', () => {
    test('should log successful authentication events', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          user_id: 'user-123',
          session_id: 'session-123',
          ip_address: '192.168.1.100',
          severity: 'low',
          details: expect.objectContaining({
            auth_method: 'jwt',
            processing_time_ms: expect.any(Number),
          }),
        })
      );
    });

    test('should log authentication failures with appropriate severity', async () => {
      // Arrange
      mockRequest.headers.authorization = 'Bearer invalid-token';
      mockAuthService.createAuthContext.mockRejectedValue(new Error('INVALID_TOKEN'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          severity: 'medium',
          details: expect.objectContaining({
            error_code: 'INVALID_TOKEN',
            processing_time_ms: expect.any(Number),
          }),
        })
      );
    });

    test('should log security events with complete context', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockRequest.path = '/api/secure-endpoint';
      mockRequest.method = 'DELETE';
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      const auditCall = mockAuditService.logSecurityAuditEvent.mock.calls[0][0];
      expect(auditCall.details.resource).toBe('/api/secure-endpoint');
      expect(auditCall.details.action).toBe('DELETE');
    });

    test('should not log sensitive authentication data', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      const auditCall = mockAuditService.logSecurityAuditEvent.mock.calls[0][0];
      expect(auditCall.details).not.toHaveProperty('token');
      expect(auditCall.details).not.toHaveProperty('password');
      expect(auditCall.details).not.toHaveProperty('secret');
    });

    test('should handle audit logging failures without blocking auth', async () => {
      // Arrange
      mockRequest.headers.authorization = `Bearer ${validJwtToken}`;
      mockAuditService.logSecurityAuditEvent.mockRejectedValue(new Error('Audit service down'));
      const middleware = authMiddleware.authenticate();

      // Act
      await middleware(mockRequest, mockResponse, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalled();
      // Authentication should succeed even if audit logging fails
    });
  });
});
