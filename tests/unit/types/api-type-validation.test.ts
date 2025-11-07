/**
 * Comprehensive Unit Tests for API Type Validation Functionality
 *
 * Tests API type validation functionality including:
 * - REST API interface contracts validation
 * - GraphQL schema validation types
 * - HTTP request/response type safety
 * - OpenAPI specification type validation
 * - Client SDK type safety
 * - API versioning type validation
 * - Integration and performance type validation
 * - Error handling type validation
 *
 * Follows established test patterns from configuration and core interfaces tests.
 * Comprehensive coverage with 20+ test cases covering all API type validation functionality.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

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
// AbortController is globally available in Node.js 16+
// No need to import from node:abort_controller for compatibility

// Import API types for validation
import type {
  // REST API interface contracts
  RestApiContract,
  HttpMethod,
  AuthRequirement,
  OAuthConfig,
  RateLimitConfig,
  ValidationSchema,

  // HTTP request/response types
  HttpRequest,
  HttpResponse,
  HttpStatus,
  ApiError,
  ValidationError,

  // GraphQL schema types
  GraphQLSchema,
  GraphQLType,
  GraphQLField,
  GraphQLArgument,
  GraphQLDirective,
  GraphQLRequest,
  GraphQLResponse,
  GraphQLError,
  GraphQLErrorLocation,

  // OpenAPI specification types
  OpenAPIDocument,
  OpenAPIInfo,
  OpenAPIServer,
  OpenAPIPaths,
  OpenAPIPathItem,
  OpenAPIOperation,
  OpenAPIParameter,
  OpenAPIRequestBody,
  OpenAPIResponses,
  OpenAPIResponse,
  OpenAPIComponents,
  OpenAPISchema,
  OpenAPIRequirement,
  OpenAPITag,
  OpenAPISecurityScheme,
  OAuthFlows,
  OAuthFlow,

  // Client SDK types
  ApiClientConfig,
  AuthConfig,
  ApiKeyCredentials,
  BearerCredentials,
  BasicCredentials,
  OAuthCredentials,
  InterceptorConfig,
  ApiClient,
  RequestOptions,
  ApiResponse,
  SdkMethod,
  SdkParameter,
  ValidationRule,

  // API versioning types
  ApiVersion,
  BreakingChange,
  VersionedEndpoint,
  VersionedEndpointConfig,
  DeprecationInfo,
  MigrationInfo,
  MigrationChange,

  // Integration and performance types
  ServiceIntegration,
  IntegrationEndpoint,
  HealthCheckConfig,
  CircuitBreakerConfig,
  PerformanceMetrics,
  ApiMonitoring,
  MonitoringAlert,
  AlertChannel,
  MonitoringDashboard,
  DashboardWidget,

  // Error handling types
  ApiErrorHandler,
  ErrorContext,
  ApiErrorResponse,
  ErrorCategory,
  ErrorMapping,

  // Utility types
  ApiResponseData,
  ApiRequestBody,
  ApiResponseBody,
  ExtractEndpoints,
  EndpointMethod,
  EndpointPath,
} from '../../../src/types/api-types.js';

// Mock logger to avoid console output during tests
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('API Type Validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ========================================================================
  // REST API Interface Contracts Validation
  // ========================================================================

  describe('REST API Interface Contracts', () => {
    test('should validate complete REST API contract structure', () => {
      const contract: RestApiContract = {
        endpoint: '/api/v1/users',
        method: 'POST',
        pathParams: { id: 'String' },
        queryParams: { page: 'number', limit: 'number' },
        requestBody: { name: 'String', email: 'String' },
        responseType: { id: 'String', name: 'String', email: 'String', createdAt: 'String' },
        headers: { 'Content-Type': 'application/json' },
        auth: {
          required: true,
          scopes: ['users:write'],
          apiKey: true,
        },
        rateLimit: {
          requests: 100,
          windowMs: 60000,
          skipSuccessfulRequests: false,
        },
        validation: {
          body: { name: 'String', email: 'String' },
          params: { id: 'String' },
          query: { page: 'number', limit: 'number' },
        },
      };

      expect(contract.endpoint).toBe('/api/v1/users');
      expect(contract.method).toBe('POST');
      expect(contract.auth?.required).toBe(true);
      expect(contract.auth?.scopes).toContain('users:write');
      expect(contract.rateLimit?.requests).toBe(100);
      expect(contract.validation?.body).toBeDefined();
    });

    test('should validate minimal REST API contract', () => {
      const contract: RestApiContract = {
        endpoint: '/api/v1/status',
        method: 'GET',
        responseType: { status: 'String', timestamp: 'String' },
      };

      expect(contract.endpoint).toBe('/api/v1/status');
      expect(contract.method).toBe('GET');
      expect(contract.auth).toBeUndefined();
      expect(contract.rateLimit).toBeUndefined();
    });

    test('should validate HTTP method types', () => {
      const validMethods: HttpMethod[] = [
        'GET',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'HEAD',
        'OPTIONS',
      ];

      validMethods.forEach((method) => {
        const contract: RestApiContract = {
          endpoint: '/api/v1/test',
          method,
          responseType: {},
        };
        expect(contract.method).toBe(method);
      });
    });

    test('should validate authentication requirements', () => {
      const authWithOAuth: AuthRequirement = {
        required: true,
        scopes: ['read', 'write'],
        oauth: {
          provider: 'google',
          scopes: ['profile', 'email'],
          flow: 'authorization_code',
        },
      };

      const authWithApiKey: AuthRequirement = {
        required: true,
        apiKey: true,
      };

      const noAuth: AuthRequirement = {
        required: false,
      };

      expect(authWithOAuth.oauth?.provider).toBe('google');
      expect(authWithOAuth.oauth?.flow).toBe('authorization_code');
      expect(authWithApiKey.apiKey).toBe(true);
      expect(noAuth.required).toBe(false);
    });

    test('should validate rate limiting configuration', () => {
      const rateLimit: RateLimitConfig = {
        requests: 1000,
        windowMs: 900000,
        skipSuccessfulRequests: true,
        skipFailedRequests: false,
      };

      expect(rateLimit.requests).toBe(1000);
      expect(rateLimit.windowMs).toBe(900000);
      expect(rateLimit.skipSuccessfulRequests).toBe(true);
      expect(rateLimit.skipFailedRequests).toBe(false);
    });
  });

  // ========================================================================
  // HTTP Request/Response Type Safety
  // ========================================================================

  describe('HTTP Request/Response Type Safety', () => {
    test('should validate complete HTTP request structure', () => {
      const request: HttpRequest<{ name: string }> = {
        method: 'POST',
        url: 'https://api.example.com/users',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer token123',
        },
        params: { id: '123' },
        query: { verbose: 'true' },
        body: { name: 'John Doe' },
        timestamp: Date.now(),
        id: 'req-123',
        userAgent: 'Mozilla/5.0...',
        ip: '192.168.1.1',
      };

      expect(request.method).toBe('POST');
      expect(request.url).toBe('https://api.example.com/users');
      expect(request.headers['Content-Type']).toBe('application/json');
      expect(request.body?.name).toBe('John Doe');
      expect(request.timestamp).toBeTypeOf('number');
      expect(request.id).toBe('req-123');
    });

    test('should validate HTTP response structure', () => {
      const response: HttpResponse<{ id: string; name: string }> = {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': 'req-123',
        },
        body: { id: '123', name: 'John Doe' },
        timestamp: Date.now(),
        requestId: 'req-123',
        duration: 150,
        size: 1024,
      };

      expect(response.status).toBe(200);
      expect(response.body?.id).toBe('123');
      expect(response.duration).toBe(150);
      expect(response.size).toBe(1024);
      expect(response.requestId).toBe('req-123');
    });

    test('should validate HTTP status codes', () => {
      const validStatuses: HttpStatus[] = [
        200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504,
      ];

      validStatuses.forEach((status) => {
        const response: HttpResponse = {
          status,
          headers: {},
          timestamp: Date.now(),
          requestId: 'test',
          duration: 100,
          size: 0,
        };
        expect(response.status).toBe(status);
      });
    });

    test('should validate API error structure', () => {
      const apiError: ApiError = {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: {
          field: 'email',
          value: 'invalid-email',
          constraint: 'must be a valid email',
        },
        timestamp: new Date().toISOString(),
        requestId: 'req-123',
        stack: 'Error: Validation failed\n    at ...',
        errors: [
          {
            field: 'email',
            message: 'Invalid email format',
            value: 'invalid-email',
            constraint: 'email',
          },
        ],
      };

      expect(apiError.code).toBe('VALIDATION_ERROR');
      expect(apiError.message).toBe('Request validation failed');
      expect(apiError.details?.field).toBe('email');
      expect(apiError.errors).toHaveLength(1);
      expect(apiError.errors[0].field).toBe('email');
    });

    test('should validate validation error details', () => {
      const validationError: ValidationError = {
        field: 'username',
        message: 'Username must be at least 3 characters',
        value: 'ab',
        constraint: 'minLength',
      };

      expect(validationError.field).toBe('username');
      expect(validationError.value).toBe('ab');
      expect(validationError.constraint).toBe('minLength');
    });
  });

  // ========================================================================
  // GraphQL Schema Validation Types
  // ========================================================================

  describe('GraphQL Schema Validation Types', () => {
    test('should validate complete GraphQL schema structure', () => {
      const schema: GraphQLSchema = {
        query: 'type Query { user(id: ID!): User }',
        mutation: 'type Mutation { createUser(input: CreateUserInput!): User }',
        subscription: 'type Subscription { userCreated: User }',
        types: [
          {
            name: 'User',
            kind: 'OBJECT',
            fields: [
              {
                name: 'id',
                type: 'ID!',
                description: 'User unique identifier',
              },
              {
                name: 'name',
                type: 'String!',
                description: 'User full name',
              },
            ],
          },
        ],
        directives: [
          {
            name: 'deprecated',
            locations: ['FIELD_DEFINITION'],
            args: [
              {
                name: 'reason',
                type: 'String',
                description: 'Reason for deprecation',
              },
            ],
          },
        ],
      };

      expect(schema.query).toBeDefined();
      expect(schema.mutation).toBeDefined();
      expect(schema.subscription).toBeDefined();
      expect(schema.types).toHaveLength(1);
      expect(schema.types[0].name).toBe('User');
      expect(schema.directives).toHaveLength(1);
    });

    test('should validate GraphQL request structure', () => {
      const request: GraphQLRequest = {
        query: `
          query GetUser($id: ID!) {
            user(id: $id) {
              id
              name
              email
            }
          }
        `,
        variables: { id: '123' },
        operationName: 'GetUser',
        extensions: {
          persistedQuery: {
            version: 1,
            sha256Hash: 'abc123',
          },
        },
      };

      expect(request.query).toContain('query GetUser');
      expect(request.variables?.id).toBe('123');
      expect(request.operationName).toBe('GetUser');
      expect(request.extensions?.persistedQuery).toBeDefined();
    });

    test('should validate GraphQL response structure', () => {
      const response: GraphQLResponse<{ user: { id: string; name: string } }> = {
        data: {
          user: {
            id: '123',
            name: 'John Doe',
          },
        },
        errors: [
          {
            message: 'Field not found',
            locations: [{ line: 2, column: 3 }],
            path: ['user', 'email'],
            extensions: { code: 'FIELD_NOT_FOUND' },
          },
        ],
        extensions: {
          cost: 1,
          complexity: 10,
        },
      };

      expect(response.data?.user.id).toBe('123');
      expect(response.errors).toHaveLength(1);
      expect(response.errors[0].message).toBe('Field not found');
      expect(response.errors[0].locations).toHaveLength(1);
      expect(response.extensions?.cost).toBe(1);
    });

    test('should validate GraphQL error structure', () => {
      const graphQLError: GraphQLError = {
        message: 'Cannot query field "nonexistent" on type "User"',
        locations: [
          { line: 3, column: 5 },
          { line: 7, column: 10 },
        ],
        path: ['user', 'nonexistent'],
        extensions: {
          code: 'GRAPHQL_VALIDATION_FAILED',
          exception: { stacktrace: ['Error: ...'] },
        },
      };

      expect(graphQLError.message).toContain('Cannot query field');
      expect(graphQLError.locations).toHaveLength(2);
      expect(graphQLError.path).toEqual(['user', 'nonexistent']);
      expect(graphQLError.extensions?.code).toBe('GRAPHQL_VALIDATION_FAILED');
    });
  });

  // ========================================================================
  // OpenAPI Specification Types
  // ========================================================================

  describe('OpenAPI Specification Types', () => {
    test('should validate complete OpenAPI document structure', () => {
      const openApiDoc: OpenAPIDocument = {
        openapi: '3.0.3',
        info: {
          title: 'User Management API',
          description: 'API for managing users',
          version: '1.0.0',
          termsOfService: 'https://example.com/terms',
          contact: {
            name: 'API Support',
            url: 'https://example.com/support',
            email: 'support@example.com',
          },
          license: {
            name: 'MIT',
            url: 'https://opensource.org/licenses/MIT',
          },
        },
        servers: [
          {
            url: 'https://api.example.com/v1',
            description: 'Production server',
            variables: {
              version: {
                enum: ['v1', 'v2'],
                default: 'v1',
                description: 'API version',
              },
            },
          },
        ],
        paths: {
          '/users': {
            get: {
              tags: ['users'],
              summary: 'List users',
              operationId: 'listUsers',
              parameters: [
                {
                  name: 'page',
                  in: 'query',
                  description: 'Page number',
                  schema: { type: 'integer', default: 1 },
                },
              ],
              responses: {
                '200': {
                  description: 'List of users',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          users: { type: 'array', items: { $ref: '#/components/schemas/User' } },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        components: {
          schemas: {
            User: {
              type: 'object',
              required: ['id', 'name'],
              properties: {
                id: { type: 'String', format: 'uuid' },
                name: { type: 'String', minLength: 1 },
                email: { type: 'String', format: 'email' },
              },
            },
          },
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
            },
          },
        },
        security: [
          {
            bearerAuth: [],
          },
        ],
        tags: [
          {
            name: 'users',
            description: 'User management operations',
          },
        ],
      };

      expect(openApiDoc.openapi).toBe('3.0.3');
      expect(openApiDoc.info.title).toBe('User Management API');
      expect(openApiDoc.servers).toHaveLength(1);
      expect(openApiDoc.paths['/users']).toBeDefined();
      expect(openApiDoc.components?.schemas?.User).toBeDefined();
      expect(openApiDoc.security).toHaveLength(1);
    });

    test('should validate OpenAPI operation with request body', () => {
      const operation: OpenAPIOperation = {
        tags: ['users'],
        summary: 'Create user',
        operationId: 'createUser',
        requestBody: {
          description: 'User data to create',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateUserRequest' },
              example: {
                name: 'John Doe',
                email: 'john@example.com',
              },
            },
          },
          required: true,
        },
        responses: {
          '201': {
            description: 'User created successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/User' },
              },
            },
          },
          '400': {
            description: 'Invalid request',
          },
        },
        deprecated: false,
      };

      expect(operation.requestBody?.required).toBe(true);
      expect(operation.responses['201']).toBeDefined();
      expect(operation.responses['400']).toBeDefined();
      expect(operation.deprecated).toBe(false);
    });

    test('should validate OpenAPI schema with validation rules', () => {
      const schema: OpenAPISchema = {
        type: 'object',
        title: 'User Registration',
        description: 'User registration data',
        required: ['username', 'email', 'password'],
        properties: {
          username: {
            type: 'String',
            minLength: 3,
            maxLength: 20,
            pattern: '^[a-zA-Z0-9_]+$',
            description: 'Unique username',
          },
          email: {
            type: 'String',
            format: 'email',
            description: 'Valid email address',
          },
          password: {
            type: 'String',
            minLength: 8,
            pattern: '^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d@$!%*?&]{8,}$',
            description: 'Strong password',
          },
          age: {
            type: 'integer',
            minimum: 18,
            maximum: 120,
            description: 'User age',
          },
        },
        additionalProperties: false,
      };

      expect(schema.required).toContain('username');
      expect(schema.properties?.username.minLength).toBe(3);
      expect(schema.properties?.password.pattern).toBeDefined();
      expect(schema.additionalProperties).toBe(false);
    });

    test('should validate OAuth security scheme', () => {
      const oauthScheme: OpenAPISecurityScheme = {
        type: 'oauth2',
        description: 'OAuth2 authentication',
        flows: {
          authorizationCode: {
            authorizationUrl: 'https://example.com/oauth/authorize',
            tokenUrl: 'https://example.com/oauth/token',
            refreshUrl: 'https://example.com/oauth/refresh',
            scopes: {
              'read:users': 'Read user information',
              'write:users': 'Create and update users',
            },
          },
        },
      };

      expect(oauthScheme.type).toBe('oauth2');
      expect(oauthScheme.flows?.authorizationCode).toBeDefined();
      expect(oauthScheme.flows?.authorizationCode?.scopes['read:users']).toBe(
        'Read user information'
      );
    });
  });

  // ========================================================================
  // Client SDK Types
  // ========================================================================

  describe('Client SDK Types', () => {
    test('should validate complete API client configuration', () => {
      const config: ApiClientConfig = {
        baseUrl: 'https://api.example.com/v1',
        apiKey: 'sk-1234567890abcdef',
        timeout: 30000,
        retries: 3,
        retryDelay: 1000,
        headers: {
          'User-Agent': 'MyApp/1.0.0',
          Accept: 'application/json',
        },
        auth: {
          type: 'bearer',
          credentials: {
            token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          },
        },
        interceptors: [
          {
            type: 'request',
            handler: 'authInterceptor',
            options: { addTimestamp: true },
          },
          {
            type: 'response',
            handler: 'errorInterceptor',
            options: { logErrors: true },
          },
        ],
      };

      expect(config.baseUrl).toBe('https://api.example.com/v1');
      expect(config.apiKey).toBe('sk-1234567890abcdef');
      expect(config.timeout).toBe(30000);
      expect(config.auth?.type).toBe('bearer');
      expect(config.interceptors).toHaveLength(2);
    });

    test('should validate different authentication credential types', () => {
      const apiKeyCreds: ApiKeyCredentials = {
        key: 'api-key-123',
        headerName: 'X-API-Key',
        queryParam: 'api_key',
      };

      const bearerCreds: BearerCredentials = {
        token: 'jwt-token-123',
      };

      const basicCreds: BasicCredentials = {
        username: 'user123',
        password: 'pass123',
      };

      const oauthCreds: OAuthCredentials = {
        clientId: 'client123',
        clientSecret: 'secret123',
        accessToken: 'access123',
        refreshToken: 'refresh123',
        expiresAt: Date.now() + 3600000,
      };

      expect(apiKeyCreds.headerName).toBe('X-API-Key');
      expect(bearerCreds.token).toBe('jwt-token-123');
      expect(basicCreds.username).toBe('user123');
      expect(oauthCreds.expiresAt).toBeGreaterThan(Date.now());
    });

    test('should validate API request options', () => {
      const options: RequestOptions = {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': 'req-123',
        },
        params: { userId: '123' },
        query: { verbose: 'true', page: '1' },
        timeout: 15000,
        retries: 2,
        signal: new AbortController().signal,
      };

      expect(options.headers?.['X-Request-ID']).toBe('req-123');
      expect(options.params?.userId).toBe('123');
      expect(options.query?.page).toBe('1');
      expect(options.timeout).toBe(15000);
      expect(options.signal).toBeInstanceOf(AbortSignal);
    });

    test('should validate API response structure', () => {
      const response: ApiResponse<{ id: string; name: string }> = {
        data: { id: '123', name: 'John Doe' },
        status: 200,
        statusText: 'OK',
        headers: {
          'content-type': 'application/json',
          'x-request-id': 'req-123',
        },
        config: {
          headers: { Accept: 'application/json' },
          timeout: 30000,
        },
        request: {
          url: 'https://api.example.com/users/123',
          method: 'GET',
        },
      };

      expect(response['data.id']).toBe('123');
      expect(response.status).toBe(200);
      expect(response.statusText).toBe('OK');
      expect(response.headers['x-request-id']).toBe('req-123');
      expect(response.config.timeout).toBe(30000);
    });

    test('should validate SDK method definition', () => {
      const method: SdkMethod<{ name: string }, { id: string; name: string }> = {
        name: 'createUser',
        description: 'Creates a new user',
        parameters: [
          {
            name: 'userData',
            type: 'CreateUserRequest',
            required: true,
            description: 'User data to create',
            validation: [
              { type: 'required', constraint: true, message: 'User data is required' },
              { type: 'min', constraint: 1, message: 'At least one field is required' },
            ],
          },
        ],
        returnType: { id: 'String', name: String },
        requestType: { name: 'String' },
        exampleRequest: { name: 'John Doe' },
        exampleResponse: { id: '123', name: 'John Doe' },
      };

      expect(method.name).toBe('createUser');
      expect(method.parameters).toHaveLength(1);
      expect(method.parameters[0].validation).toHaveLength(2);
      expect(method.exampleRequest?.name).toBe('John Doe');
    });
  });

  // ========================================================================
  // API Versioning Types
  // ========================================================================

  describe('API Versioning Types', () => {
    test('should validate API version information', () => {
      const version: ApiVersion = {
        version: '2.1.0',
        status: 'active',
        releasedAt: '2024-01-15T10:00:00Z',
        sunsetAt: '2025-01-15T10:00:00Z',
        deprecationMessage: 'Version 2.1.0 will be deprecated in favor of 3.0.0',
        migrationGuide: 'https://docs.example.com/migration/2.1-to-3.0',
        breakingChanges: [
          {
            type: 'field_removed',
            description: 'Removed deprecated "legacyId" field',
            migrationPath: 'Use "id" field instead',
          },
          {
            type: 'response_type_changed',
            description: 'User endpoint now returns paginated results',
            migrationPath: 'Update client to handle pagination',
          },
        ],
      };

      expect(version.version).toBe('2.1.0');
      expect(version.status).toBe('active');
      expect(version.breakingChanges).toHaveLength(2);
      expect(version.breakingChanges[0].type).toBe('field_removed');
    });

    test('should validate versioned endpoint structure', () => {
      const versionedEndpoint: VersionedEndpoint = {
        endpoint: '/users',
        defaultVersion: 'v2',
        versions: {
          v1: {
            version: 'v1',
            contract: {
              endpoint: '/users',
              method: 'GET',
              responseType: { users: 'array' },
            },
            deprecationInfo: {
              deprecatedAt: '2024-01-01T00:00:00Z',
              sunsetAt: '2024-06-01T00:00:00Z',
              reason: 'Replaced by more efficient v2',
              replacementEndpoint: '/v2/users',
              migrationGuide: 'https://docs.example.com/migration/users-v1-to-v2',
            },
          },
          v2: {
            version: 'v2',
            contract: {
              endpoint: '/users',
              method: 'GET',
              responseType: { data: 'array', pagination: 'object' },
            },
          },
        },
      };

      expect(versionedEndpoint.defaultVersion).toBe('v2');
      expect(versionedEndpoint.versions['v1'].deprecationInfo).toBeDefined();
      expect(versionedEndpoint.versions['v1'].deprecationInfo?.sunsetAt).toBe(
        '2024-06-01T00:00:00Z'
      );
    });

    test('should validate migration information', () => {
      const migrationInfo: MigrationInfo = {
        fromVersion: '1.0.0',
        toVersion: '2.0.0',
        changes: [
          {
            type: 'add',
            path: 'users.email',
            newValue: 'String',
            breaking: false,
          },
          {
            type: 'remove',
            path: 'users.legacyId',
            oldValue: 'String',
            breaking: true,
          },
          {
            type: 'modify',
            path: 'users.name',
            oldValue: 'String',
            newValue: 'object',
            breaking: true,
          },
        ],
        automatedMigration: true,
        migrationScript: 'migrate-users-1-to-2.js',
      };

      expect(migrationInfo.changes).toHaveLength(3);
      expect(migrationInfo.changes.filter((c) => c.breaking)).toHaveLength(2);
      expect(migrationInfo.automatedMigration).toBe(true);
      expect(migrationInfo.migrationScript).toBe('migrate-users-1-to-2.js');
    });
  });

  // ========================================================================
  // Integration and Performance Types
  // ========================================================================

  describe('Integration and Performance Types', () => {
    test('should validate service integration configuration', () => {
      const integration: ServiceIntegration = {
        name: 'Payment Service',
        version: '2.0.0',
        endpoints: [
          {
            name: 'createPayment',
            method: 'POST',
            path: '/payments',
            timeout: 10000,
            retries: 2,
            circuitBreaker: {
              failureThreshold: 5,
              recoveryTimeout: 30000,
            },
          },
          {
            name: 'getPayment',
            method: 'GET',
            path: '/payments/{id}',
            timeout: 5000,
            retries: 1,
          },
        ],
        authentication: {
          required: true,
          scopes: ['payments:write'],
          apiKey: true,
        },
        rateLimit: {
          requests: 100,
          windowMs: 60000,
        },
        healthCheck: {
          endpoint: '/health',
          interval: 30000,
          timeout: 5000,
          expectedStatus: 200,
          healthyThreshold: 2,
          unhealthyThreshold: 3,
        },
        circuitBreaker: {
          enabled: true,
          failureThreshold: 10,
          recoveryTimeout: 60000,
          monitoringPeriod: 120000,
          expectedRecoveryTime: 30000,
        },
      };

      expect(integration.name).toBe('Payment Service');
      expect(integration.endpoints).toHaveLength(2);
      expect(integration.healthCheck?.interval).toBe(30000);
      expect(integration.circuitBreaker?.enabled).toBe(true);
    });

    test('should validate performance metrics', () => {
      const metrics: PerformanceMetrics = {
        requestCount: 10000,
        errorCount: 50,
        averageResponseTime: 150.5,
        p50ResponseTime: 120,
        p95ResponseTime: 300,
        p99ResponseTime: 800,
        throughput: 166.67,
        errorRate: 0.005,
        timestamp: '2024-01-15T10:30:00Z',
      };

      expect(metrics.requestCount).toBe(10000);
      expect(metrics.errorRate).toBe(0.005);
      expect(metrics.p95ResponseTime).toBe(300);
      expect(metrics.throughput).toBeCloseTo(166.67);
      expect(metrics.timestamp).toBe('2024-01-15T10:30:00Z');
    });

    test('should validate API monitoring configuration', () => {
      const monitoring: ApiMonitoring = {
        endpoint: '/api/v1/users',
        method: 'POST',
        metrics: [
          {
            requestCount: 1000,
            errorCount: 10,
            averageResponseTime: 200,
            p50ResponseTime: 150,
            p95ResponseTime: 400,
            p99ResponseTime: 900,
            throughput: 50,
            errorRate: 0.01,
            timestamp: '2024-01-15T10:00:00Z',
          },
        ],
        alerts: [
          {
            name: 'High Error Rate',
            type: 'error_rate',
            threshold: 0.05,
            condition: 'greater_than',
            enabled: true,
            channels: [
              {
                type: 'slack',
                destination: '#api-alerts',
                enabled: true,
              },
              {
                type: 'email',
                destination: 'alerts@example.com',
                enabled: true,
              },
            ],
          },
          {
            name: 'Slow Response Time',
            type: 'response_time',
            threshold: 500,
            condition: 'greater_than',
            enabled: true,
            channels: [
              {
                type: 'webhook',
                destination: 'https://hooks.example.com/alerts',
                enabled: false,
              },
            ],
          },
        ],
        dashboards: [
          {
            name: 'API Performance',
            description: 'Real-time API performance metrics',
            refreshInterval: 30000,
            widgets: [
              {
                type: 'metric',
                title: 'Request Rate',
                query: 'rate(requests_total[5m])',
                config: { unit: 'req/s' },
              },
              {
                type: 'chart',
                title: 'Response Time Trend',
                query: 'avg(response_time)',
                config: { type: 'line', timespan: '1h' },
              },
            ],
          },
        ],
      };

      expect(monitoring.alerts).toHaveLength(2);
      expect(monitoring.alerts[0].channels).toHaveLength(2);
      expect(monitoring.dashboards).toHaveLength(1);
      expect(monitoring.dashboards[0].widgets).toHaveLength(2);
    });

    test('should validate circuit breaker configuration', () => {
      const circuitBreaker: CircuitBreakerConfig = {
        enabled: true,
        failureThreshold: 5,
        recoveryTimeout: 30000,
        monitoringPeriod: 60000,
        expectedRecoveryTime: 15000,
      };

      expect(circuitBreaker.enabled).toBe(true);
      expect(circuitBreaker.failureThreshold).toBe(5);
      expect(circuitBreaker.recoveryTimeout).toBe(30000);
      expect(circuitBreaker.expectedRecoveryTime).toBe(15000);
    });
  });

  // ========================================================================
  // Error Handling Types
  // ========================================================================

  describe('Error Handling Types', () => {
    test('should validate error context information', () => {
      const context: ErrorContext = {
        request: {
          method: 'POST',
          url: 'https://api.example.com/users',
          headers: { 'Content-Type': 'application/json' },
          body: { name: 'John' },
          timestamp: Date.now(),
          id: 'req-123',
        },
        endpoint: 'createUser',
        userId: 'user-123',
        sessionId: 'session-456',
        correlationId: 'corr-789',
        timestamp: Date.now(),
      };

      expect(context.request.method).toBe('POST');
      expect(context.endpoint).toBe('createUser');
      expect(context.userId).toBe('user-123');
      expect(context.correlationId).toBe('corr-789');
    });

    test('should validate API error response structure', () => {
      const errorResponse: ApiErrorResponse = {
        error: {
          code: 'VALIDATION_FAILED',
          message: 'Request validation failed',
          timestamp: '2024-01-15T10:30:00Z',
          requestId: 'req-123',
        },
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': 'req-123',
        },
        correlationId: 'corr-789',
        timestamp: '2024-01-15T10:30:00Z',
      };

      expect(errorResponse.error.code).toBe('VALIDATION_FAILED');
      expect(errorResponse.statusCode).toBe(400);
      expect(errorResponse.correlationId).toBe('corr-789');
      expect(errorResponse.headers['X-Request-ID']).toBe('req-123');
    });

    test('should validate error categories', () => {
      const clientError: ErrorCategory = {
        type: 'client_error',
        severity: 'medium',
        actionable: true,
        retryable: false,
      };

      const serverError: ErrorCategory = {
        type: 'server_error',
        severity: 'high',
        actionable: true,
        retryable: true,
      };

      const networkError: ErrorCategory = {
        type: 'network_error',
        severity: 'low',
        actionable: false,
        retryable: true,
      };

      expect(clientError.type).toBe('client_error');
      expect(clientError.severity).toBe('medium');
      expect(clientError.actionable).toBe(true);
      expect(serverError.retryable).toBe(true);
      expect(networkError.actionable).toBe(false);
    });

    test('should validate error mapping configuration', () => {
      const errorMapping: ErrorMapping = {
        VALIDATION_ERROR: {
          category: {
            type: 'client_error',
            severity: 'medium',
            actionable: true,
            retryable: false,
          },
          httpStatus: 400,
          message: 'Request validation failed',
          userMessage: 'Please check your input and try again',
          resolution: 'Fix the validation errors in your request',
        },
        RATE_LIMIT_EXCEEDED: {
          category: {
            type: 'client_error',
            severity: 'low',
            actionable: true,
            retryable: true,
          },
          httpStatus: 429,
          message: 'Rate limit exceeded',
          userMessage: 'Too many requests. Please try again later.',
          resolution: 'Wait before making more requests or upgrade your plan',
        },
        INTERNAL_SERVER_ERROR: {
          category: {
            type: 'server_error',
            severity: 'high',
            actionable: true,
            retryable: true,
          },
          httpStatus: 500,
          message: 'Internal server error',
          userMessage: 'Something went wrong. Please try again.',
          resolution: 'Contact support if the problem persists',
        },
      };

      expect(errorMapping['VALIDATION_ERROR'].httpStatus).toBe(400);
      expect(errorMapping['RATE_LIMIT_EXCEEDED'].category.retryable).toBe(true);
      expect(errorMapping['INTERNAL_SERVER_ERROR'].severity).toBe('high');
      expect(errorMapping['VALIDATION_ERROR'].userMessage).toBeDefined();
    });
  });

  // ========================================================================
  // Utility Types Validation
  // ========================================================================

  describe('Utility Types Validation', () => {
    test('should validate ApiResponseData utility type', () => {
      // This test validates that the utility type correctly extracts the data type
      type ApiResponsePromise = Promise<{ id: string; name: string }>;
      type ExtractedData = ApiResponseData<ApiResponsePromise>; // Should be { id: String; name: String }

      const testData: ExtractedData = { id: '123', name: 'test' };
      expect(testData.id).toBe('123');
      expect(testData.name).toBe('test');
    });

    test('should validate request/response body extraction types', () => {
      type UserContract = RestApiContract<{ name: string }, { id: string; name: string }>;

      // ApiRequestBody should extract { name: String }
      type RequestBodyType = ApiRequestBody<UserContract>;
      const requestBody: RequestBodyType = { name: 'John' };
      expect(requestBody.name).toBe('John');

      // ApiResponseBody should extract { id: String; name: String }
      type ResponseBodyType = ApiResponseBody<UserContract>;
      const responseBody: ResponseBodyType = { id: '123', name: 'John' };
      expect(responseBody.id).toBe('123');
    });

    test('should validate endpoint extraction utilities', () => {
      type Endpoints = {
        getUsers: RestApiContract<null, { users: any[] }>;
        createUser: RestApiContract<{ name: string }, { id: string; name: string }>;
      };

      // ExtractEndpoints should preserve the structure
      type ExtractedEndpoints = ExtractEndpoints<Endpoints>;
      const endpoints: ExtractedEndpoints = {
        getUsers: {
          endpoint: '/users',
          method: 'GET',
          responseType: { users: [] },
        },
        createUser: {
          endpoint: '/users',
          method: 'POST',
          requestBody: { name: 'test' },
          responseType: { id: '123', name: 'test' },
        },
      };

      expect(endpoints.getUsers.method).toBe('GET');
      expect(endpoints.createUser.method).toBe('POST');
    });

    test('should validate endpoint method/path extraction', () => {
      type GetUserEndpoint = RestApiContract<null, { id: string; name: string }>;
      type CreateUserEndpoint = RestApiContract<{ name: string }, { id: string; name: string }>;

      // EndpointMethod should extract 'GET'
      type GetUserMethod = EndpointMethod<GetUserEndpoint>;
      const getUserMethod: GetUserMethod = 'GET';
      expect(getUserMethod).toBe('GET');

      // EndpointPath should extract the endpoint String
      type GetUserPath = EndpointPath<GetUserEndpoint>;
      const getUserPath: GetUserPath = '/users/{id}';
      expect(getUserPath).toBe('/users/{id}');
    });
  });

  // ========================================================================
  // Integration Tests - Type Safety Across Boundaries
  // ========================================================================

  describe('Integration Type Safety', () => {
    test('should validate end-to-end type flow from request to response', () => {
      // Define a complete API contract
      const userApiContract: RestApiContract<
        { name: string; email: string },
        { id: string; name: string; email: string; createdAt: string }
      > = {
        endpoint: '/api/v2/users',
        method: 'POST',
        requestBody: { name: 'String', email: 'String' },
        responseType: { id: 'String', name: 'String', email: 'String', createdAt: 'String' },
        auth: {
          required: true,
          scopes: ['users:write'],
        },
      };

      // Create request
      const request: HttpRequest<typeof userApiContract.requestBody> = {
        method: userApiContract.method,
        url: `https://api.example.com${userApiContract.endpoint}`,
        headers: { 'Content-Type': 'application/json' },
        body: { name: 'John Doe', email: 'john@example.com' },
        timestamp: Date.now(),
        id: 'req-123',
      };

      // Create response
      const response: HttpResponse<typeof userApiContract.responseType> = {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
        body: {
          id: 'user-123',
          name: 'John Doe',
          email: 'john@example.com',
          createdAt: new Date().toISOString(),
        },
        timestamp: Date.now(),
        requestId: request.id,
        duration: 150,
        size: 256,
      };

      expect(request.body?.name).toBe('John Doe');
      expect(response.body?.id).toBe('user-123');
      expect(response.status).toBe(201);
    });

    test('should validate OpenAPI to TypeScript type mapping consistency', () => {
      // OpenAPI schema definition
      const userSchema: OpenAPISchema = {
        type: 'object',
        required: ['id', 'name', 'email'],
        properties: {
          id: { type: 'String', format: 'uuid' },
          name: { type: 'String', minLength: 1 },
          email: { type: 'String', format: 'email' },
          age: { type: 'integer', minimum: 0, maximum: 150 },
          isActive: { type: 'boolean', default: true },
        },
        additionalProperties: false,
      };

      // Corresponding TypeScript type
      type UserType = {
        id: string;
        name: string;
        email: string;
        age?: number;
        isActive?: boolean;
      };

      // Test that the types are compatible
      const user: UserType = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'John Doe',
        email: 'john@example.com',
        age: 30,
        isActive: true,
      };

      expect(userSchema.required).toContain('id');
      expect(userSchema.required).toContain('name');
      expect(userSchema.required).toContain('email');
      expect(user.name).toBe('John Doe');
      expect(user.email).toBe('john@example.com');
    });

    test('should validate GraphQL schema to TypeScript type consistency', () => {
      // GraphQL type definition
      const graphQLType: GraphQLType = {
        name: 'User',
        kind: 'OBJECT',
        fields: [
          { name: 'id', type: 'ID!', description: 'User ID' },
          { name: 'name', type: 'String!', description: 'User name' },
          { name: 'email', type: 'String', description: 'User email' },
          { name: 'posts', type: '[Post!]!', description: 'User posts' },
        ],
      };

      // Corresponding TypeScript type
      type GraphQLUser = {
        id: string;
        name: string;
        email?: string;
        posts: Array<{
          id: string;
          title: string;
          content: string;
        }>;
      };

      // Test GraphQL request/response
      const gqlRequest: GraphQLRequest = {
        query: `
          query GetUser($id: ID!) {
            user(id: $id) {
              id
              name
              email
              posts {
                id
                title
                content
              }
            }
          }
        `,
        variables: { id: '123' },
      };

      const gqlResponse: GraphQLResponse<{ user: GraphQLUser }> = {
        data: {
          user: {
            id: '123',
            name: 'John Doe',
            email: 'john@example.com',
            posts: [{ id: 'post1', title: 'First Post', content: 'Hello World' }],
          },
        },
      };

      expect(graphQLType.name).toBe('User');
      expect(gqlResponse.data?.user.id).toBe('123');
      expect(gqlResponse.data?.user.posts).toHaveLength(1);
      expect(gqlRequest.variables?.id).toBe('123');
    });
  });
});
