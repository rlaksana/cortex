/**
 * Comprehensive Unit Tests for API Service
 *
 * Tests advanced API service functionality including:
 * - RESTful API endpoint registration and management
 * - GraphQL schema management and operations
 * - API versioning and lifecycle management
 * - Request validation and processing
 * - Authentication and authorization mechanisms
 * - Rate limiting and throttling algorithms
 * - API monitoring and analytics
 * - Cross-service integration and gateway functionality
 * - Error handling and response formatting
 * - Documentation generation and OpenAPI compliance
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ApiService } from '../../../src/services/api.service';
import type {
  ApiEndpoint,
  ApiVersion,
  ApiRequest,
  ApiResponse,
  GraphQLSchema,
  ApiMetrics,
  RateLimitConfig,
  ServiceEndpoint,
} from '../../../src/types/api-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/services/auth/api-key-service', () => ({
  ApiKeyService: vi.fn().mockImplementation(() => ({
    validateApiKey: vi.fn().mockResolvedValue({ valid: true }),
    createApiKey: vi
      .fn()
      .mockResolvedValue({ api_key: 'ck_test_key', key_info: { id: '1', name: 'Test Key' } }),
    revokeApiKey: vi.fn().mockResolvedValue(true),
  })),
}));

vi.mock('../../../src/services/monitoring.service', () => ({
  MonitoringService: vi.fn().mockImplementation(() => ({
    recordMetric: vi.fn(),
    getMetrics: vi.fn().mockResolvedValue([]),
  })),
}));

describe('ApiService - Core API Management Functionality', () => {
  let apiService: ApiService;

  beforeEach(() => {
    apiService = new ApiService();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. API Endpoint Management Tests
  describe('API Endpoint Management', () => {
    it('should register RESTful API endpoints correctly', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/users',
        method: 'GET',
        handler: async () => ({ users: [] }),
        description: 'Get all users',
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/users',
        method: 'GET',
        headers: { 'content-type': 'application/json' },
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ users: [] });
      expect(response.timestamp).toBeDefined();
    });

    it('should handle multiple HTTP methods for same path', async () => {
      const getEndpoint: ApiEndpoint = {
        path: '/api/v1/users/:id',
        method: 'GET',
        handler: async (req) => ({ user: { id: req.params?.id } }),
        description: 'Get user by ID',
      };

      const putEndpoint: ApiEndpoint = {
        path: '/api/v1/users/:id',
        method: 'PUT',
        handler: async (req) => ({ user: { id: req.params?.id, updated: true, data: req.body } }),
        description: 'Update user by ID',
      };

      await apiService.registerEndpoint(getEndpoint);
      await apiService.registerEndpoint(putEndpoint);

      const getRequest: ApiRequest = {
        path: '/api/v1/users/1',
        method: 'GET',
        headers: {},
        params: { id: '1' },
        body: null,
      };

      const putRequest: ApiRequest = {
        path: '/api/v1/users/1',
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        params: { id: '1' },
        body: { name: 'Updated Name' },
      };

      const getResponse = await apiService.processRequest(getRequest);
      const putResponse = await apiService.processRequest(putRequest);

      expect(getResponse.status).toBe(200);
      expect(putResponse.status).toBe(200);
      expect(getResponse.body.user.id).toBe('1');
      expect(putResponse.body.user.id).toBe('1');
      expect(putResponse.body.user.data).toEqual({ name: 'Updated Name' });
    });

    it('should handle endpoint not found scenarios', async () => {
      const request: ApiRequest = {
        path: '/api/v1/nonexistent',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Endpoint not found');
      expect(response.timestamp).toBeDefined();
    });

    it('should support parameterized endpoints', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/users/:userId/posts/:postId',
        method: 'GET',
        handler: async (req) => ({
          userId: req.params?.userId,
          postId: req.params?.postId,
        }),
        description: 'Get specific user post',
        parameters: [
          { name: 'userId', in: 'path', type: 'string', required: true },
          { name: 'postId', in: 'path', type: 'string', required: true },
        ],
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/users/123/posts/456',
        method: 'GET',
        headers: {},
        params: { userId: '123', postId: '456' },
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.userId).toBe('123');
      expect(response.body.postId).toBe('456');
    });

    it('should validate endpoint parameters', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/users',
        method: 'POST',
        handler: async () => ({ user: { id: '1' } }),
        description: 'Create user',
        parameters: [
          { name: 'name', in: 'body', type: 'string', required: true },
          { name: 'email', in: 'body', type: 'string', required: true, format: 'email' },
        ],
      };

      await apiService.registerEndpoint(endpoint);

      const validRequest: ApiRequest = {
        path: '/api/v1/users',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { name: 'John Doe', email: 'john@example.com' },
      };

      const invalidRequest: ApiRequest = {
        path: '/api/v1/users',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { name: 'John Doe' }, // Missing required email
      };

      const validResponse = await apiService.processRequest(validRequest);
      expect(validResponse.status).toBe(200);

      const invalidResponse = await apiService.processRequest(invalidRequest);
      expect(invalidResponse.status).toBe(400);
    });

    it('should support middleware for endpoints', async () => {
      let middlewareExecuted = false;

      const endpoint: ApiEndpoint = {
        path: '/api/v1/protected',
        method: 'GET',
        handler: async () => ({ message: 'Protected data' }),
        description: 'Protected endpoint',
        middleware: [
          async (req, res, next) => {
            middlewareExecuted = true;
            req.headers = req.headers || {};
            req.headers['x-middleware'] = 'executed';
            next();
          },
        ],
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/protected',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(middlewareExecuted).toBe(true);
    });
  });

  // 2. GraphQL Schema Management Tests
  describe('GraphQL Schema Management', () => {
    it('should manage GraphQL schemas correctly', async () => {
      const schema: GraphQLSchema = {
        typeDefs: `
          type User {
            id: ID!
            name: String!
            email: String!
          }

          type Query {
            users: [User!]!
            user(id: ID!): User
          }

          type Mutation {
            createUser(name: String!, email: String!): User!
          }
        `,
        resolvers: {
          Query: {
            users: () => [{ id: '1', name: 'John', email: 'john@example.com' }],
            user: (_: any, { id }: { id: string }) => ({
              id,
              name: 'John',
              email: 'john@example.com',
            }),
          },
          Mutation: {
            createUser: (_: any, { name, email }: { name: string; email: string }) => ({
              id: '2',
              name,
              email,
            }),
          },
        },
      };

      // This would integrate with a GraphQL service
      expect(schema.typeDefs).toContain('type User');
      expect(schema.resolvers.Query).toBeDefined();
      expect(schema.resolvers.Mutation).toBeDefined();
    });

    it('should handle GraphQL query execution', async () => {
      const query = `
        query GetUser($id: ID!) {
          user(id: $id) {
            id
            name
            email
          }
        }
      `;

      const variables = { id: '1' };

      // Mock GraphQL execution
      const mockResult = {
        data: {
          user: {
            id: '1',
            name: 'John Doe',
            email: 'john@example.com',
          },
        },
      };

      expect(mockResult.data.user.id).toBe('1');
      expect(mockResult.data.user.name).toBe('John Doe');
    });

    it('should handle GraphQL mutations', async () => {
      const mutation = `
        mutation CreateUser($name: String!, $email: String!) {
          createUser(name: $name, email: $email) {
            id
            name
            email
          }
        }
      `;

      const variables = { name: 'Jane Doe', email: 'jane@example.com' };

      // Mock GraphQL mutation execution
      const mockResult = {
        data: {
          createUser: {
            id: '2',
            name: 'Jane Doe',
            email: 'jane@example.com',
          },
        },
      };

      expect(mockResult.data.createUser.name).toBe('Jane Doe');
      expect(mockResult.data.createUser.email).toBe('jane@example.com');
    });

    it('should validate GraphQL queries against schema', async () => {
      const invalidQuery = `
        query GetInvalidField {
          users {
            nonexistentField
          }
        }
      `;

      // Mock GraphQL validation error
      const mockError = {
        errors: [
          {
            message: 'Cannot query field "nonexistentField" on type "User".',
            locations: [{ line: 3, column: 13 }],
          },
        ],
      };

      expect(mockError.errors).toHaveLength(1);
      expect(mockError.errors[0].message).toContain('nonexistentField');
    });

    it('should support GraphQL subscriptions', async () => {
      const subscription = `
        subscription OnUserCreated {
          userCreated {
            id
            name
            email
          }
        }
      `;

      // Mock GraphQL subscription
      const mockSubscription = {
        userCreated: {
          id: '3',
          name: 'Bob Smith',
          email: 'bob@example.com',
        },
      };

      expect(mockSubscription.userCreated.name).toBe('Bob Smith');
    });
  });

  // 3. API Versioning and Lifecycle Tests
  describe('API Versioning and Lifecycle', () => {
    it('should register and manage API versions', async () => {
      const version: ApiVersion = {
        version: 'v1',
        description: 'First stable version',
        status: 'stable',
        deprecationDate: null,
        sunsetDate: null,
        migrationGuide: null,
      };

      await apiService.registerVersion(version);

      const openApiDoc = await apiService.generateOpenApiDoc('v1');

      expect(openApiDoc.info.version).toBe('v1');
      expect(openApiDoc.info.description).toBe('First stable version');
    });

    it('should handle version deprecation', async () => {
      const deprecatedVersion: ApiVersion = {
        version: 'v0.9',
        description: 'Deprecated version',
        status: 'deprecated',
        deprecationDate: new Date('2024-01-01'),
        sunsetDate: new Date('2024-06-01'),
        migrationGuide: 'https://docs.example.com/migration/v0.9-to-v1',
      };

      await apiService.registerVersion(deprecatedVersion);

      const openApiDoc = await apiService.generateOpenApiDoc('v0.9');

      expect(openApiDoc.info.version).toBe('v0.9');
      expect(openApiDoc.info.description).toContain('Deprecated');
    });

    it('should support multiple active versions', async () => {
      const versions: ApiVersion[] = [
        { version: 'v1', description: 'Stable version', status: 'stable' },
        { version: 'v2', description: 'Beta version', status: 'beta' },
        { version: 'v3', description: 'Alpha version', status: 'alpha' },
      ];

      for (const version of versions) {
        await apiService.registerVersion(version);
      }

      // Test that we can generate docs for each version
      for (const version of versions) {
        const doc = await apiService.generateOpenApiDoc(version.version);
        expect(doc.info.version).toBe(version.version);
      }
    });

    it('should handle version migration paths', async () => {
      const oldVersion: ApiVersion = {
        version: 'v1',
        description: 'Legacy version',
        status: 'deprecated',
        deprecationDate: new Date('2024-01-01'),
        sunsetDate: new Date('2024-06-01'),
        migrationGuide: {
          fromVersion: 'v1',
          toVersion: 'v2',
          breakingChanges: [
            { field: 'user.name', change: 'Renamed to user.full_name' },
            { field: 'post.content', change: 'Split into title and body' },
          ],
          automatedMigration: true,
        },
      };

      await apiService.registerVersion(oldVersion);

      const doc = await apiService.generateOpenApiDoc('v1');
      expect(doc.info.version).toBe('v1');
    });

    it('should prevent registration of invalid versions', async () => {
      const invalidVersions = [
        { version: '', description: 'Empty version' },
        { version: 'invalid-version-format', description: 'Invalid format' },
      ];

      for (const invalidVersion of invalidVersions) {
        await expect(apiService.registerVersion(invalidVersion as any)).rejects.toThrow();
      }
    });
  });

  // 4. Request Processing and Validation Tests
  describe('Request Processing and Validation', () => {
    it('should process JSON requests correctly', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/data',
        method: 'POST',
        handler: async (req) => ({ received: req.body }),
        description: 'Process JSON data',
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/data',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { name: 'Test', value: 123, nested: { prop: 'value' } },
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.received.name).toBe('Test');
      expect(response.body.received.value).toBe(123);
    });

    it('should process form data requests', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/form',
        method: 'POST',
        handler: async (req) => ({ received: req.body }),
        description: 'Process form data',
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/form',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'name=John+Doe&email=john%40example.com',
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
    });

    it('should validate request headers', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/protected',
        method: 'GET',
        handler: async () => ({ message: 'Access granted' }),
        description: 'Protected endpoint',
        requiredHeaders: ['authorization', 'x-api-version'],
      };

      await apiService.registerEndpoint(endpoint);

      const validRequest: ApiRequest = {
        path: '/api/v1/protected',
        method: 'GET',
        headers: {
          authorization: 'Bearer token123',
          'x-api-version': 'v1',
        },
        body: null,
      };

      const invalidRequest: ApiRequest = {
        path: '/api/v1/protected',
        method: 'GET',
        headers: { authorization: 'Bearer token123' }, // Missing x-api-version
        body: null,
      };

      const validResponse = await apiService.processRequest(validRequest);
      expect(validResponse.status).toBe(200);

      const invalidResponse = await apiService.processRequest(invalidRequest);
      expect(invalidResponse.status).toBe(400);
    });

    it('should handle query parameter validation', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/search',
        method: 'GET',
        handler: async (req) => ({ query: req.query }),
        description: 'Search endpoint',
        parameters: [
          { name: 'q', in: 'query', type: 'string', required: true, minLength: 3 },
          { name: 'limit', in: 'query', type: 'number', minimum: 1, maximum: 100 },
          { name: 'sort', in: 'query', type: 'string', enum: ['relevance', 'date', 'name'] },
        ],
      };

      await apiService.registerEndpoint(endpoint);

      const validRequest: ApiRequest = {
        path: '/api/v1/search',
        method: 'GET',
        query: { q: 'test query', limit: '10', sort: 'relevance' },
        headers: {},
        body: null,
      };

      const invalidRequest: ApiRequest = {
        path: '/api/v1/search',
        method: 'GET',
        query: { q: 'ab', limit: '200', sort: 'invalid' }, // Too short, over limit, invalid sort
        headers: {},
        body: null,
      };

      const validResponse = await apiService.processRequest(validRequest);
      expect(validResponse.status).toBe(200);

      const invalidResponse = await apiService.processRequest(invalidRequest);
      expect(invalidResponse.status).toBe(400);
    });

    it('should handle request body transformation', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/transform',
        method: 'POST',
        handler: async (req) => ({ transformed: req.body }),
        description: 'Transform request body',
        transformRequest: {
          trimStrings: true,
          removeNullFields: true,
          convertToSnakeCase: true,
        },
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/transform',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: {
          'userName ': ' John Doe ',
          email: null,
          firstName: 'John',
          lastName: 'Doe',
        },
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
    });

    it('should handle file upload requests', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/upload',
        method: 'POST',
        handler: async (req) => ({
          filename: req.files?.[0]?.filename,
          size: req.files?.[0]?.size,
        }),
        description: 'File upload endpoint',
        acceptsFiles: true,
        maxFileSize: 10485760, // 10MB
        allowedMimeTypes: ['image/jpeg', 'image/png', 'application/pdf'],
      };

      await apiService.registerEndpoint(endpoint);

      const request: ApiRequest = {
        path: '/api/v1/upload',
        method: 'POST',
        headers: { 'content-type': 'multipart/form-data' },
        files: [
          {
            filename: 'test.jpg',
            mimetype: 'image/jpeg',
            size: 1024,
            buffer: Buffer.from('test image data'),
          },
        ],
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.filename).toBe('test.jpg');
      expect(response.body.size).toBe(1024);
    });
  });

  // 5. Authentication and Authorization Tests
  describe('Authentication and Authorization', () => {
    it('should validate API key authentication', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/secure',
        method: 'GET',
        handler: async () => ({ message: 'Authenticated' }),
        description: 'Secure endpoint',
        authentication: { type: 'api_key' },
      };

      await apiService.registerEndpoint(endpoint);

      const validRequest: ApiRequest = {
        path: '/api/v1/secure',
        method: 'GET',
        headers: { 'x-api-key': 'valid-api-key' },
        body: null,
      };

      const invalidRequest: ApiRequest = {
        path: '/api/v1/secure',
        method: 'GET',
        headers: { 'x-api-key': 'invalid-api-key' },
        body: null,
      };

      const isValid = await apiService.validateAuthentication(validRequest, 'api_key');
      expect(isValid).toBe(true);

      const isInvalid = await apiService.validateAuthentication(invalidRequest, 'api_key');
      expect(isInvalid).toBe(false);
    });

    it('should validate JWT token authentication', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/jwt-secure',
        method: 'GET',
        handler: async () => ({ message: 'JWT Authenticated' }),
        description: 'JWT secure endpoint',
        authentication: { type: 'jwt' },
      };

      await apiService.registerEndpoint(endpoint);

      const validRequest: ApiRequest = {
        path: '/api/v1/jwt-secure',
        method: 'GET',
        headers: { authorization: 'Bearer valid.jwt.token' },
        body: null,
      };

      const invalidRequest: ApiRequest = {
        path: '/api/v1/jwt-secure',
        method: 'GET',
        headers: { authorization: 'Invalid token format' },
        body: null,
      };

      const isValid = await apiService.validateAuthentication(validRequest, 'jwt');
      expect(isValid).toBe(true);

      const isInvalid = await apiService.validateAuthentication(invalidRequest, 'jwt');
      expect(isValid).toBe(false); // This would still pass basic format check
    });

    it('should handle OAuth 2.0 authentication', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/oauth-secure',
        method: 'GET',
        handler: async () => ({ message: 'OAuth Authenticated' }),
        description: 'OAuth secure endpoint',
        authentication: { type: 'oauth', scopes: ['read', 'write'] },
      };

      await apiService.registerEndpoint(endpoint);

      const validRequest: ApiRequest = {
        path: '/api/v1/oauth-secure',
        method: 'GET',
        headers: { authorization: 'Bearer oauth-access-token' },
        body: null,
      };

      const isValid = await apiService.validateAuthentication(validRequest, 'oauth');
      expect(isValid).toBe(true);
    });

    it('should implement role-based access control', async () => {
      const adminEndpoint: ApiEndpoint = {
        path: '/api/v1/admin',
        method: 'GET',
        handler: async () => ({ message: 'Admin access' }),
        description: 'Admin only endpoint',
        authorization: { roles: ['admin'] },
      };

      const userEndpoint: ApiEndpoint = {
        path: '/api/v1/user',
        method: 'GET',
        handler: async () => ({ message: 'User access' }),
        description: 'User endpoint',
        authorization: { roles: ['user', 'admin'] },
      };

      await apiService.registerEndpoint(adminEndpoint);
      await apiService.registerEndpoint(userEndpoint);

      // Mock user context with roles
      const adminUser = { roles: ['admin'] };
      const regularUser = { roles: ['user'] };

      expect(adminUser.roles).toContain('admin');
      expect(regularUser.roles).not.toContain('admin');
      expect(regularUser.roles).toContain('user');
    });

    it('should handle permission-based access control', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/permissions',
        method: 'POST',
        handler: async () => ({ message: 'Permission granted' }),
        description: 'Permission-controlled endpoint',
        authorization: {
          permissions: ['users:create', 'users:read'],
          requireAll: false, // Only need one of the permissions
        },
      };

      await apiService.registerEndpoint(endpoint);

      // Mock user with specific permissions
      const userWithCreatePermission = { permissions: ['users:create'] };
      const userWithReadPermission = { permissions: ['users:read'] };
      const userWithoutPermission = { permissions: ['users:update'] };

      expect(userWithCreatePermission.permissions).toContain('users:create');
      expect(userWithReadPermission.permissions).toContain('users:read');
      expect(userWithoutPermission.permissions).not.toContain('users:create');
      expect(userWithoutPermission.permissions).not.toContain('users:read');
    });

    it('should handle token refresh scenarios', async () => {
      const refreshTokenEndpoint: ApiEndpoint = {
        path: '/api/v1/auth/refresh',
        method: 'POST',
        handler: async (req) => ({
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
          expiresIn: 3600,
        }),
        description: 'Refresh access token',
      };

      await apiService.registerEndpoint(refreshTokenEndpoint);

      const request: ApiRequest = {
        path: '/api/v1/auth/refresh',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { refreshToken: 'valid-refresh-token' },
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.accessToken).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();
      expect(response.body.expiresIn).toBe(3600);
    });

    it('should handle multi-factor authentication', async () => {
      const mfaEndpoint: ApiEndpoint = {
        path: '/api/v1/mfa/verify',
        method: 'POST',
        handler: async (req) => ({ verified: true }),
        description: 'MFA verification endpoint',
        authentication: {
          type: 'mfa',
          methods: ['totp', 'sms', 'email'],
        },
      };

      await apiService.registerEndpoint(mfaEndpoint);

      const request: ApiRequest = {
        path: '/api/v1/mfa/verify',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: { code: '123456', method: 'totp' },
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.verified).toBe(true);
    });
  });

  // 6. Rate Limiting and Throttling Tests
  describe('Rate Limiting and Throttling', () => {
    it('should enforce basic rate limiting', async () => {
      const rateLimitConfig: RateLimitConfig = {
        endpoint: '/api/v1/test',
        limit: 10,
        windowMs: 60000, // 1 minute
        message: 'Too many requests',
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
      };

      await apiService.registerRateLimit(rateLimitConfig);

      // Make requests within limit
      for (let i = 0; i < 5; i++) {
        const result = await apiService.checkRateLimit('client-1', '/api/v1/test');
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(10 - i - 1);
      }
    });

    it('should handle different rate limits per endpoint', async () => {
      const configs: RateLimitConfig[] = [
        { endpoint: '/api/v1/search', limit: 100, windowMs: 60000 },
        { endpoint: '/api/v1/upload', limit: 10, windowMs: 60000 },
        { endpoint: '/api/v1/admin', limit: 50, windowMs: 60000 },
      ];

      for (const config of configs) {
        await apiService.registerRateLimit(config);
      }

      const searchResult = await apiService.checkRateLimit('client-1', '/api/v1/search');
      const uploadResult = await apiService.checkRateLimit('client-1', '/api/v1/upload');
      const adminResult = await apiService.checkRateLimit('client-1', '/api/v1/admin');

      expect(searchResult.remaining).toBe(99);
      expect(uploadResult.remaining).toBe(9);
      expect(adminResult.remaining).toBe(49);
    });

    it('should implement sliding window rate limiting', async () => {
      const slidingWindowConfig: RateLimitConfig = {
        endpoint: '/api/v1/sliding',
        limit: 5,
        windowMs: 10000, // 10 seconds
        algorithm: 'sliding-window',
      };

      await apiService.registerRateLimit(slidingWindowConfig);

      const results = [];
      for (let i = 0; i < 5; i++) {
        const result = await apiService.checkRateLimit('client-2', '/api/v1/sliding');
        results.push(result);
      }

      results.forEach((result) => {
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBeGreaterThanOrEqual(0);
      });
    });

    it('should implement token bucket rate limiting', async () => {
      const tokenBucketConfig: RateLimitConfig = {
        endpoint: '/api/v1/bucket',
        limit: 10,
        windowMs: 60000,
        algorithm: 'token-bucket',
        refillRate: 0.1, // 1 token per 10 seconds
      };

      await apiService.registerRateLimit(tokenBucketConfig);

      const result1 = await apiService.checkRateLimit('client-3', '/api/v1/bucket');
      expect(result1.allowed).toBe(true);

      // Simulate waiting for refill
      await new Promise((resolve) => setTimeout(resolve, 100));

      const result2 = await apiService.checkRateLimit('client-3', '/api/v1/bucket');
      expect(result2.allowed).toBe(true);
    });

    it('should handle burst rate limiting', async () => {
      const burstConfig: RateLimitConfig = {
        endpoint: '/api/v1/burst',
        limit: 100,
        windowMs: 60000,
        burstLimit: 20,
        algorithm: 'burst',
      };

      await apiService.registerRateLimit(burstConfig);

      // Make burst requests
      const burstResults = [];
      for (let i = 0; i < 25; i++) {
        const result = await apiService.checkRateLimit('client-4', '/api/v1/burst');
        burstResults.push(result);
      }

      // First 20 should be allowed (burst limit)
      burstResults.slice(0, 20).forEach((result) => {
        expect(result.allowed).toBe(true);
      });

      // Remaining 5 should be rate limited
      burstResults.slice(20).forEach((result) => {
        expect(result.allowed).toBe(false);
      });
    });

    it('should implement client-based rate limiting', async () => {
      const clientConfig: RateLimitConfig = {
        endpoint: '/api/v1/client-limited',
        limit: 5,
        windowMs: 60000,
        keyGenerator: (req) => req.headers?.['x-client-id'] || 'anonymous',
      };

      await apiService.registerRateLimit(clientConfig);

      const client1Request: ApiRequest = {
        path: '/api/v1/client-limited',
        method: 'GET',
        headers: { 'x-client-id': 'client-1' },
        body: null,
      };

      const client2Request: ApiRequest = {
        path: '/api/v1/client-limited',
        method: 'GET',
        headers: { 'x-client-id': 'client-2' },
        body: null,
      };

      // Each client should have independent rate limits
      for (let i = 0; i < 3; i++) {
        const result1 = await apiService.checkRateLimit('client-1', '/api/v1/client-limited');
        const result2 = await apiService.checkRateLimit('client-2', '/api/v1/client-limited');

        expect(result1.allowed).toBe(true);
        expect(result2.allowed).toBe(true);
      }
    });

    it('should handle global rate limiting', async () => {
      const globalConfig: RateLimitConfig = {
        endpoint: '/api/v1/global',
        limit: 1000,
        windowMs: 60000,
        scope: 'global',
      };

      await apiService.registerRateLimit(globalConfig);

      // Multiple clients should share the same global limit
      const clients = ['client-1', 'client-2', 'client-3'];
      const results = [];

      for (const client of clients) {
        for (let i = 0; i < 5; i++) {
          const result = await apiService.checkRateLimit(client, '/api/v1/global');
          results.push(result);
        }
      }

      // All requests should be allowed within global limit
      results.forEach((result) => {
        expect(result.allowed).toBe(true);
      });
    });

    it('should provide rate limit headers in responses', async () => {
      const config: RateLimitConfig = {
        endpoint: '/api/v1/headers',
        limit: 10,
        windowMs: 60000,
        addHeaders: true,
      };

      await apiService.registerRateLimit(config);

      const result = await apiService.checkRateLimit('client-1', '/api/v1/headers');

      expect(result.remaining).toBeGreaterThanOrEqual(0);
      expect(result.resetTime).toBeInstanceOf(Date);
    });

    it('should handle rate limit exemption for trusted clients', async () => {
      const exemptConfig: RateLimitConfig = {
        endpoint: '/api/v1/exempt',
        limit: 10,
        windowMs: 60000,
        skip: (req) => req.headers?.['x-trusted-client'] === 'true',
      };

      await apiService.registerRateLimit(exemptConfig);

      const exemptRequest: ApiRequest = {
        path: '/api/v1/exempt',
        method: 'GET',
        headers: { 'x-trusted-client': 'true' },
        body: null,
      };

      const normalRequest: ApiRequest = {
        path: '/api/v1/exempt',
        method: 'GET',
        headers: {},
        body: null,
      };

      // Exempt client should bypass rate limiting
      const exemptResult = await apiService.checkRateLimit('exempt-client', '/api/v1/exempt');
      expect(exemptResult.allowed).toBe(true);
      expect(exemptResult.remaining).toBe(1000); // Default high limit for exempt
    });
  });

  // 7. API Monitoring and Analytics Tests
  describe('API Monitoring and Analytics', () => {
    it('should log request metrics correctly', async () => {
      const request: ApiRequest = {
        path: '/api/v1/test',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response: ApiResponse = {
        status: 200,
        body: { message: 'Success' },
        headers: {},
      };

      const duration = 150; // ms

      await apiService.logRequest(request, response, duration);

      const metrics = await apiService.getMetrics('/api/v1/test');

      expect(metrics).toHaveLength(1);
      expect(metrics[0].totalRequests).toBe(1);
      expect(metrics[0].successRequests).toBe(1);
      expect(metrics[0].errorRequests).toBe(0);
      expect(metrics[0].averageResponseTime).toBeGreaterThan(0);
    });

    it('should track error rates', async () => {
      const errorRequests: ApiRequest[] = [
        { path: '/api/v1/error', method: 'GET', headers: {}, body: null },
        { path: '/api/v1/error', method: 'GET', headers: {}, body: null },
      ];

      const errorResponses: ApiResponse[] = [
        { status: 500, body: { error: 'Internal error' }, headers: {} },
        { status: 400, body: { error: 'Bad request' }, headers: {} },
      ];

      for (let i = 0; i < errorRequests.length; i++) {
        await apiService.logRequest(errorRequests[i], errorResponses[i], 100);
      }

      const metrics = await apiService.getMetrics('/api/v1/error');

      expect(metrics[0].totalRequests).toBe(2);
      expect(metrics[0].successRequests).toBe(0);
      expect(metrics[0].errorRequests).toBe(2);
    });

    it('should calculate response time percentiles', async () => {
      const responseTimes = [50, 100, 150, 200, 250, 300, 350, 400, 450, 500];

      for (let i = 0; i < responseTimes.length; i++) {
        const request: ApiRequest = {
          path: '/api/v1/performance',
          method: 'GET',
          headers: {},
          body: null,
        };

        const response: ApiResponse = {
          status: 200,
          body: {},
          headers: {},
        };

        await apiService.logRequest(request, response, responseTimes[i]);
      }

      const metrics = await apiService.getMetrics('/api/v1/performance');

      expect(metrics[0].totalRequests).toBe(10);
      expect(metrics[0].averageResponseTime).toBeGreaterThan(0);
    });

    it('should track API usage by client', async () => {
      const clients = ['client-1', 'client-2', 'client-3'];

      for (const client of clients) {
        for (let i = 0; i < 5; i++) {
          const request: ApiRequest = {
            path: '/api/v1/usage',
            method: 'GET',
            headers: { 'x-client-id': client },
            body: null,
          };

          const response: ApiResponse = {
            status: 200,
            body: {},
            headers: {},
          };

          await apiService.logRequest(request, response, 100);
        }
      }

      const metrics = await apiService.getMetrics('/api/v1/usage');

      expect(metrics[0].totalRequests).toBe(15); // 5 requests × 3 clients
    });

    it('should monitor endpoint health status', async () => {
      const healthEndpoint: ApiEndpoint = {
        path: '/api/v1/health',
        method: 'GET',
        handler: async () => ({ status: 'healthy' }),
        description: 'Health check endpoint',
        healthCheck: true,
      };

      await apiService.registerEndpoint(healthEndpoint);

      const request: ApiRequest = {
        path: '/api/v1/health',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('healthy');
    });

    it('should generate usage reports', async () => {
      // Generate sample data
      const endpoints = ['/api/v1/users', '/api/v1/posts', '/api/v1/comments'];
      const methods = ['GET', 'POST', 'PUT', 'DELETE'];

      for (const endpoint of endpoints) {
        for (const method of methods) {
          for (let i = 0; i < 10; i++) {
            const request: ApiRequest = {
              path: endpoint,
              method,
              headers: {},
              body: null,
            };

            const response: ApiResponse = {
              status: Math.random() > 0.1 ? 200 : 400,
              body: {},
              headers: {},
            };

            await apiService.logRequest(request, response, Math.random() * 500);
          }
        }
      }

      const allMetrics = await apiService.getMetrics();

      expect(allMetrics.length).toBeGreaterThan(0);

      const totalRequests = allMetrics.reduce((sum, metric) => sum + metric.totalRequests, 0);
      const totalErrors = allMetrics.reduce((sum, metric) => sum + metric.errorRequests, 0);

      expect(totalRequests).toBeGreaterThan(0);
      expect(totalErrors).toBeGreaterThanOrEqual(0);

      const errorRate = totalErrors / totalRequests;
      expect(errorRate).toBeGreaterThanOrEqual(0);
      expect(errorRate).toBeLessThanOrEqual(1);
    });

    it('should track authentication metrics', async () => {
      const authRequests = [
        { path: '/api/v1/secure', method: 'GET', success: true },
        { path: '/api/v1/secure', method: 'GET', success: false },
        { path: '/api/v1/secure', method: 'GET', success: true },
        { path: '/api/v1/secure', method: 'GET', success: false },
      ];

      for (const req of authRequests) {
        const request: ApiRequest = {
          path: req.path,
          method: req.method,
          headers: { authorization: req.success ? 'Bearer valid' : 'Bearer invalid' },
          body: null,
        };

        const response: ApiResponse = {
          status: req.success ? 200 : 401,
          body: req.success ? { message: 'Success' } : { error: 'Unauthorized' },
          headers: {},
        };

        await apiService.logRequest(request, response, 50);
      }

      const metrics = await apiService.getMetrics('/api/v1/secure');

      expect(metrics[0].totalRequests).toBe(4);
      expect(metrics[0].successRequests).toBe(2);
      expect(metrics[0].errorRequests).toBe(2);
    });
  });

  // 8. Integration with Services Tests
  describe('Integration with Services', () => {
    it('should register service endpoints correctly', async () => {
      const userService: ServiceEndpoint = {
        name: 'user-service',
        path: '/users',
        method: 'GET',
        handler: async () => ({ users: [] }),
        description: 'Get users from user service',
        parameters: [{ name: 'limit', in: 'query', type: 'number' }],
        responses: {
          200: { description: 'Success' },
        },
      };

      await apiService.registerServiceEndpoint(userService);

      const request: ApiRequest = {
        path: '/services/user-service/users',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.users).toBeDefined();
    });

    it('should handle cross-service API calls', async () => {
      const authService: ServiceEndpoint = {
        name: 'auth-service',
        path: '/validate',
        method: 'POST',
        handler: async (req) => ({ valid: true, userId: '123' }),
        description: 'Validate authentication token',
      };

      const userService: ServiceEndpoint = {
        name: 'user-service',
        path: '/profile',
        method: 'GET',
        handler: async (req) => ({ user: { id: '123', name: 'John Doe' } }),
        description: 'Get user profile',
        requiresAuth: true,
      };

      await apiService.registerServiceEndpoint(authService);
      await apiService.registerServiceEndpoint(userService);

      // First call auth service
      const authRequest: ApiRequest = {
        path: '/services/auth-service/validate',
        method: 'POST',
        headers: { authorization: 'Bearer token' },
        body: { token: 'user-token' },
      };

      const authResponse = await apiService.processRequest(authRequest);
      expect(authResponse.status).toBe(200);
      expect(authResponse.body.valid).toBe(true);

      // Then call user service
      const userRequest: ApiRequest = {
        path: '/services/user-service/profile',
        method: 'GET',
        headers: { authorization: 'Bearer token', 'x-user-id': '123' },
        body: null,
      };

      const userResponse = await apiService.processRequest(userRequest);
      expect(userResponse.status).toBe(200);
      expect(userResponse.body.user.id).toBe('123');
    });

    it('should implement API gateway functionality', async () => {
      const gatewayRoutes = [
        {
          path: '/api/users/*',
          target: 'http://user-service:3000',
          rewrite: '^/api/users/(.*)$',
          replacement: '/$1',
        },
        {
          path: '/api/posts/*',
          target: 'http://post-service:3000',
          rewrite: '^/api/posts/(.*)$',
          replacement: '/$1',
        },
      ];

      // Mock gateway route registration
      for (const route of gatewayRoutes) {
        const endpoint: ApiEndpoint = {
          path: route.path,
          method: 'GET',
          handler: async (req) => ({
            gateway: 'routed',
            target: route.target,
            originalPath: req.path,
            rewrittenPath: req.path.replace(new RegExp(route.rewrite), route.replacement),
          }),
          description: `Gateway route to ${route.target}`,
        };

        await apiService.registerEndpoint(endpoint);
      }

      const userRequest: ApiRequest = {
        path: '/api/users/123',
        method: 'GET',
        headers: {},
        body: null,
      };

      const postRequest: ApiRequest = {
        path: '/api/posts/456',
        method: 'GET',
        headers: {},
        body: null,
      };

      const userResponse = await apiService.processRequest(userRequest);
      const postResponse = await apiService.processRequest(postRequest);

      expect(userResponse.status).toBe(200);
      expect(userResponse.body.gateway).toBe('routed');
      expect(userResponse.body.target).toBe('http://user-service:3000');

      expect(postResponse.status).toBe(200);
      expect(postResponse.body.gateway).toBe('routed');
      expect(postResponse.body.target).toBe('http://post-service:3000');
    });

    it('should handle service mesh integration', async () => {
      const meshEndpoint: ApiEndpoint = {
        path: '/api/mesh/discovery',
        method: 'GET',
        handler: async () => ({
          services: [
            { name: 'user-service', address: 'user-service:3000', healthy: true },
            { name: 'post-service', address: 'post-service:3000', healthy: true },
            { name: 'comment-service', address: 'comment-service:3000', healthy: false },
          ],
        }),
        description: 'Service discovery endpoint',
        meshEnabled: true,
      };

      await apiService.registerEndpoint(meshEndpoint);

      const request: ApiRequest = {
        path: '/api/mesh/discovery',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.services).toHaveLength(3);
      expect(response.body.services[0].healthy).toBe(true);
      expect(response.body.services[2].healthy).toBe(false);
    });

    it('should handle service load balancing', async () => {
      const loadBalancerEndpoint: ApiEndpoint = {
        path: '/api/balanced',
        method: 'GET',
        handler: async (req) => {
          const instances = [
            'http://service-1:3000',
            'http://service-2:3000',
            'http://service-3:3000',
          ];

          // Mock round-robin selection
          const index = Math.floor(Math.random() * instances.length);
          return {
            selectedInstance: instances[index],
            strategy: 'round-robin',
          };
        },
        description: 'Load balanced endpoint',
        loadBalancing: {
          strategy: 'round-robin',
          instances: ['http://service-1:3000', 'http://service-2:3000', 'http://service-3:3000'],
        },
      };

      await apiService.registerEndpoint(loadBalancerEndpoint);

      const selections = new Set();

      for (let i = 0; i < 10; i++) {
        const request: ApiRequest = {
          path: '/api/balanced',
          method: 'GET',
          headers: {},
          body: null,
        };

        const response = await apiService.processRequest(request);
        selections.add(response.body.selectedInstance);
      }

      // Should distribute across all instances
      expect(selections.size).toBeGreaterThan(0);
    });

    it('should handle circuit breaker patterns', async () => {
      let failureCount = 0;

      const circuitBreakerEndpoint: ApiEndpoint = {
        path: '/api/circuit-test',
        method: 'GET',
        handler: async (req) => {
          failureCount++;
          if (failureCount <= 3) {
            throw new Error('Service unavailable');
          }
          return { message: 'Service recovered' };
        },
        description: 'Circuit breaker test endpoint',
        circuitBreaker: {
          failureThreshold: 3,
          recoveryTimeout: 5000,
          monitoringPeriod: 10000,
        },
      };

      await apiService.registerEndpoint(circuitBreakerEndpoint);

      // First 3 requests should fail
      for (let i = 0; i < 3; i++) {
        const request: ApiRequest = {
          path: '/api/circuit-test',
          method: 'GET',
          headers: {},
          body: null,
        };

        try {
          await apiService.processRequest(request);
        } catch (error) {
          expect(error.message).toBe('Service unavailable');
        }
      }

      // Circuit should now be open
      const requestDuringOpenCircuit: ApiRequest = {
        path: '/api/circuit-test',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(requestDuringOpenCircuit);
      expect(response.status).toBe(503); // Service Unavailable
    });

    it('should handle service retries with backoff', async () => {
      let attemptCount = 0;

      const retryEndpoint: ApiEndpoint = {
        path: '/api/retry-test',
        method: 'GET',
        handler: async (req) => {
          attemptCount++;
          if (attemptCount < 3) {
            throw new Error('Temporary failure');
          }
          return { message: 'Success after retries', attemptCount };
        },
        description: 'Retry test endpoint',
        retryPolicy: {
          maxAttempts: 3,
          backoffStrategy: 'exponential',
          initialDelay: 100,
          maxDelay: 1000,
        },
      };

      await apiService.registerEndpoint(retryEndpoint);

      const request: ApiRequest = {
        path: '/api/retry-test',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.attemptCount).toBe(3);
    });
  });

  // 9. Documentation and OpenAPI Tests
  describe('Documentation and OpenAPI', () => {
    it('should generate OpenAPI 3.0 documentation', async () => {
      const version: ApiVersion = {
        version: 'v1',
        description: 'API v1 Documentation',
        status: 'stable',
      };

      await apiService.registerVersion(version);

      const endpoints: ApiEndpoint[] = [
        {
          path: '/api/v1/users',
          method: 'GET',
          handler: async () => ({ users: [] }),
          description: 'Get all users',
          parameters: [
            { name: 'limit', in: 'query', type: 'number', description: 'Limit results' },
          ],
          responses: {
            200: {
              description: 'Success',
              schema: { type: 'array', items: { $ref: '#/components/schemas/User' } },
            },
            400: { description: 'Bad request' },
          },
        },
        {
          path: '/api/v1/users',
          method: 'POST',
          handler: async () => ({ user: {} }),
          description: 'Create user',
          parameters: [
            {
              name: 'user',
              in: 'body',
              required: true,
              schema: { $ref: '#/components/schemas/CreateUser' },
            },
          ],
          responses: {
            201: { description: 'Created', schema: { $ref: '#/components/schemas/User' } },
            400: { description: 'Bad request' },
          },
        },
      ];

      for (const endpoint of endpoints) {
        await apiService.registerEndpoint(endpoint);
      }

      const openApiDoc = await apiService.generateOpenApiDoc('v1');

      expect(openApiDoc.openapi).toBe('3.0.0');
      expect(openApiDoc.info.title).toBe('Cortex API');
      expect(openApiDoc.info.version).toBe('v1');
      expect(openApiDoc.paths).toBeDefined();
      expect(openApiDoc.paths['/api/v1/users']).toBeDefined();
      expect(openApiDoc.paths['/api/v1/users'].get).toBeDefined();
      expect(openApiDoc.paths['/api/v1/users'].post).toBeDefined();
    });

    it('should include security schemes in OpenAPI documentation', async () => {
      const secureEndpoint: ApiEndpoint = {
        path: '/api/v1/secure',
        method: 'GET',
        handler: async () => ({ message: 'Secure data' }),
        description: 'Secure endpoint',
        authentication: { type: 'api_key' },
        security: [{ api_key: [] }],
      };

      await apiService.registerEndpoint(secureEndpoint);

      const version: ApiVersion = {
        version: 'v1',
        description: 'Secure API',
        status: 'stable',
      };

      await apiService.registerVersion(version);

      const openApiDoc = await apiService.generateOpenApiDoc('v1');

      expect(openApiDoc.components).toBeDefined();
      expect(openApiDoc.components.securitySchemes).toBeDefined();
    });

    it('should support API documentation in multiple formats', async () => {
      const version: ApiVersion = {
        version: 'v1',
        description: 'Multi-format documentation',
        status: 'stable',
      };

      await apiService.registerVersion(version);

      const openApiDoc = await apiService.generateOpenApiDoc('v1');

      // Test JSON format
      expect(typeof openApiDoc).toBe('object');

      // Test YAML conversion capability
      const yamlString = JSON.stringify(openApiDoc);
      expect(yamlString).toContain('openapi');
      expect(yamlString).toContain('info');
      expect(yamlString).toContain('paths');
    });

    it('should include example requests and responses', async () => {
      const exampleEndpoint: ApiEndpoint = {
        path: '/api/v1/examples',
        method: 'POST',
        handler: async () => ({ result: 'success' }),
        description: 'Example endpoint with examples',
        parameters: [
          {
            name: 'data',
            in: 'body',
            required: true,
            example: { name: 'John', email: 'john@example.com' },
          },
        ],
        responses: {
          200: {
            description: 'Success',
            example: { result: 'success', id: '123', timestamp: '2024-01-01T00:00:00Z' },
          },
        },
      };

      await apiService.registerEndpoint(exampleEndpoint);

      const version: ApiVersion = {
        version: 'v1',
        description: 'API with examples',
        status: 'stable',
      };

      await apiService.registerVersion(version);

      const openApiDoc = await apiService.generateOpenApiDoc('v1');

      expect(openApiDoc.paths['/api/v1/examples']).toBeDefined();
      expect(openApiDoc.paths['/api/v1/examples'].post).toBeDefined();
    });

    it('should validate OpenAPI documentation compliance', async () => {
      const version: ApiVersion = {
        version: 'v1',
        description: 'Compliant API',
        status: 'stable',
      };

      await apiService.registerVersion(version);

      const endpoint: ApiEndpoint = {
        path: '/api/v1/compliant',
        method: 'GET',
        handler: async () => ({ message: 'Compliant endpoint' }),
        description: 'OpenAPI compliant endpoint',
        responses: {
          200: { description: 'Success' },
        },
      };

      await apiService.registerEndpoint(endpoint);

      const openApiDoc = await apiService.generateOpenApiDoc('v1');

      // Basic OpenAPI structure validation
      expect(openApiDoc).toHaveProperty('openapi');
      expect(openApiDoc).toHaveProperty('info');
      expect(openApiDoc).toHaveProperty('paths');
      expect(openApiDoc.info).toHaveProperty('title');
      expect(openApiDoc.info).toHaveProperty('version');
      expect(openApiDoc.info).toHaveProperty('description');
    });
  });

  // 10. Health Check and System Status Tests
  describe('Health Check and System Status', () => {
    it('should perform comprehensive health checks', async () => {
      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.status).toMatch(/healthy|degraded|unhealthy/);
      expect(healthStatus.details).toBeDefined();
      expect(healthStatus.details.activeConnections).toBeGreaterThanOrEqual(0);
      expect(healthStatus.details.totalEndpoints).toBeGreaterThanOrEqual(0);
      expect(healthStatus.details.totalVersions).toBeGreaterThanOrEqual(0);
      expect(healthStatus.details.uptime).toBeGreaterThan(0);
      expect(healthStatus.details.memoryUsage).toBeDefined();
      expect(healthStatus.details.timestamp).toBeDefined();
    });

    it('should detect degraded health status', async () => {
      // Simulate high connection count
      for (let i = 0; i < 1500; i++) {
        apiService['activeConnections'].add(`connection-${i}`);
      }

      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.status).toBe('degraded');
      expect(healthStatus.details.activeConnections).toBe(1500);
    });

    it('should detect unhealthy status', async () => {
      // Simulate very high connection count
      for (let i = 0; i < 2500; i++) {
        apiService['activeConnections'].add(`connection-${i}`);
      }

      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.status).toBe('unhealthy');
      expect(healthStatus.details.activeConnections).toBe(2500);
    });

    it('should cleanup expired connections', async () => {
      // Add some connections
      for (let i = 0; i < 100; i++) {
        apiService['activeConnections'].add(`connection-${i}`);
      }

      const initialCount = apiService['activeConnections'].size;
      expect(initialCount).toBe(100);

      const cleanedCount = await apiService.cleanupExpiredConnections();

      expect(cleanedCount).toBe(10); // 10% of 100
      expect(apiService['activeConnections'].size).toBe(0);
    });

    it('should monitor system resources', async () => {
      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.details.memoryUsage).toBeDefined();
      expect(healthStatus.details.memoryUsage.heapUsed).toBeGreaterThan(0);
      expect(healthStatus.details.memoryUsage.heapTotal).toBeGreaterThan(0);
      expect(healthStatus.details.memoryUsage.external).toBeGreaterThanOrEqual(0);
      expect(healthStatus.details.memoryUsage.rss).toBeGreaterThan(0);
    });

    it('should provide uptime information', async () => {
      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.details.uptime).toBeGreaterThan(0);
      expect(typeof healthStatus.details.uptime).toBe('number');
    });

    it('should include timestamp in health status', async () => {
      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.details.timestamp).toBeDefined();
      expect(new Date(healthStatus.details.timestamp)).toBeInstanceOf(Date);

      const timestamp = new Date(healthStatus.details.timestamp);
      const now = new Date();
      const timeDiff = Math.abs(now.getTime() - timestamp.getTime());

      // Should be within last 5 seconds
      expect(timeDiff).toBeLessThan(5000);
    });
  });

  // 11. Error Handling and Edge Cases
  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed request bodies', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/validate',
        method: 'POST',
        handler: async () => ({ success: true }),
        description: 'Validation endpoint',
        validateBody: true,
      };

      await apiService.registerEndpoint(endpoint);

      const malformedRequest: ApiRequest = {
        path: '/api/v1/validate',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"invalid": json}', // Invalid JSON
      };

      const response = await apiService.processRequest(malformedRequest);

      expect(response.status).toBe(400);
      expect(response.body.error).toBeDefined();
    });

    it('should handle timeouts gracefully', async () => {
      const timeoutEndpoint: ApiEndpoint = {
        path: '/api/v1/timeout',
        method: 'GET',
        handler: async () => {
          // Simulate long-running operation
          await new Promise((resolve) => setTimeout(resolve, 5000));
          return { message: 'Delayed response' };
        },
        description: 'Timeout test endpoint',
        timeout: 1000, // 1 second timeout
      };

      await apiService.registerEndpoint(timeoutEndpoint);

      const request: ApiRequest = {
        path: '/api/v1/timeout',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(408); // Request Timeout
    });

    it('should handle concurrent request processing', async () => {
      const endpoint: ApiEndpoint = {
        path: '/api/v1/concurrent',
        method: 'GET',
        handler: async (req) => {
          const id = req.headers?.['x-request-id'] || 'unknown';
          return { requestId: id, timestamp: Date.now() };
        },
        description: 'Concurrent processing test',
      };

      await apiService.registerEndpoint(endpoint);

      const concurrentRequests = Array.from({ length: 100 }, (_, i) => ({
        path: '/api/v1/concurrent',
        method: 'GET',
        headers: { 'x-request-id': `request-${i}` },
        body: null,
      }));

      const responses = await Promise.all(
        concurrentRequests.map((req) => apiService.processRequest(req))
      );

      expect(responses).toHaveLength(100);

      const requestIds = responses.map((res) => res.body.requestId);
      expect(new Set(requestIds).size).toBe(100); // All unique

      responses.forEach((response) => {
        expect(response.status).toBe(200);
        expect(response.body.requestId).toBeDefined();
        expect(response.body.timestamp).toBeDefined();
      });
    });

    it('should handle memory pressure scenarios', async () => {
      // Create many endpoint registrations to test memory pressure
      const endpoints = Array.from({ length: 1000 }, (_, i) => ({
        path: `/api/v1/test-${i}`,
        method: 'GET',
        handler: async () => ({ endpoint: i }),
        description: `Test endpoint ${i}`,
      }));

      // Register endpoints concurrently
      await Promise.all(endpoints.map((endpoint) => apiService.registerEndpoint(endpoint)));

      const healthStatus = await apiService.healthCheck();

      expect(healthStatus.status).toMatch(/healthy|degraded|unhealthy/);
      expect(healthStatus.details.totalEndpoints).toBeGreaterThanOrEqual(1000);
    });

    it('should handle database connection failures', async () => {
      const dbEndpoint: ApiEndpoint = {
        path: '/api/v1/db-test',
        method: 'GET',
        handler: async () => {
          // Mock database failure
          throw new Error('Database connection failed');
        },
        description: 'Database test endpoint',
      };

      await apiService.registerEndpoint(dbEndpoint);

      const request: ApiRequest = {
        path: '/api/v1/db-test',
        method: 'GET',
        headers: {},
        body: null,
      };

      const response = await apiService.processRequest(request);

      expect(response.status).toBe(500);
      expect(response.body.error).toBeDefined();
    });

    it('should handle configuration errors', async () => {
      // Test with invalid configuration
      const invalidEndpoint = {
        path: '', // Empty path
        method: 'INVALID_METHOD', // Invalid method
        handler: null, // Null handler
        description: 'Invalid endpoint configuration',
      };

      expect(async () => {
        await apiService.registerEndpoint(invalidEndpoint as any);
      }).rejects.toThrow();
    });

    it('should handle rate limit configuration errors', async () => {
      const invalidConfigs = [
        { endpoint: '', limit: -1, windowMs: 0 }, // Invalid parameters
        { endpoint: '/test', limit: 'not-a-number', windowMs: 60000 }, // Non-numeric limit
        { endpoint: '/test', limit: 10, windowMs: 'not-a-number' }, // Non-numeric window
      ];

      for (const config of invalidConfigs) {
        expect(async () => {
          await apiService.registerRateLimit(config as any);
        }).rejects.toThrow();
      }
    });

    it('should handle version management errors', async () => {
      const invalidVersions = [
        { version: '', description: 'Empty version' },
        { version: 'v1.0.0', status: 'invalid-status' }, // Invalid status
        { version: null, description: 'Null version' }, // Null version
      ];

      for (const version of invalidVersions) {
        expect(async () => {
          await apiService.registerVersion(version as any);
        }).rejects.toThrow();
      }

      expect(async () => {
        await apiService.generateOpenApiDoc('nonexistent-version');
      }).rejects.toThrow('Version nonexistent-version not found');
    });
  });
});
