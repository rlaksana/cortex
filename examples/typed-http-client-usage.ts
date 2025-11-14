/**
 * Typed HTTP Client Usage Examples
 *
 * Comprehensive examples demonstrating how to use the new typed HTTP client
 * with proper type safety, validation, and error handling.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025-11-12
 */

import { z } from 'zod';

import {
  createTypedHttpClient,
  TypedHttpClientBuilder,
  type TypedHttpClient,
  type TypedHttpResponse,
} from '../src/http-client/typed-http-client.js';
import {
  ZodRequestValidator,
  ZodResponseValidator,
  createCrudValidator,
  createRestApiValidator,
  PaginationRequestSchema,
  PaginationResponseSchema,
} from '../src/http-client/http-validation.js';
import {
  createHttpErrorHandler,
  type ErrorCategory,
  type ErrorSeverity,
} from '../src/http-client/http-error-handler.js';

// ============================================================================
// Example 1: Basic Typed HTTP Requests
// ============================================================================

/**
 * Define data schemas for type safety
 */
const UserSchema = z.object({
  id: z.number(),
  name: z.string(),
  email: z.string().email(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

const CreateUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  role: z.enum(['user', 'admin']).default('user'),
});

const UpdateUserSchema = CreateUserSchema.partial();

type User = z.infer<typeof UserSchema>;
type CreateUser = z.infer<typeof CreateUserSchema>;
type UpdateUser = z.infer<typeof UpdateUserSchema>;

/**
 * Create a typed HTTP client for user management
 */
function createUserApiClient(): TypedHttpClient {
  return new TypedHttpClientBuilder()
    .baseURL('https://api.example.com')
    .timeout(10000)
    .retries(3)
    .retryDelay(1000)
    .headers({
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    })
    .responseValidation({
      enabled: true,
      strictMode: false,
      schemaValidationEnabled: true,
      typeValidationEnabled: true,
    })
    .addInterceptor({
      type: 'request',
      handler: async (context) => {
        console.log('Request interceptor:', context.request.method, context.request.url);
      },
      priority: 1,
    })
    .addInterceptor({
      type: 'response',
      handler: async (context) => {
        console.log('Response interceptor:', context.response?.status);
      },
      priority: 1,
    })
    .build();
}

/**
 * User service with typed HTTP operations
 */
class UserService {
  private client: TypedHttpClient;
  private errorHandler = createHttpErrorHandler({
    enableRetry: true,
    maxRetries: 3,
    baseRetryDelay: 1000,
    logLevel: 'info',
  });

  constructor() {
    this.client = createUserApiClient();
  }

  /**
   * Get all users with pagination
   */
  async getUsers(page: number = 1, limit: number = 50): Promise<{
    users: User[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }> {
    try {
      const response = await this.client.get<{
        data: User[];
        pagination: z.infer<typeof PaginationResponseSchema>['pagination'];
      }>(`/users`, {
        query: { page, limit },
      });

      return {
        users: response.data.data,
        pagination: response.data.pagination,
      };
    } catch (error) {
      await this.errorHandler.handleError(error, {
        url: '/users',
        method: 'GET',
        query: { page, limit },
      } as any);
      throw error;
    }
  }

  /**
   * Get user by ID
   */
  async getUserById(id: number): Promise<User> {
    try {
      const response = await this.client.get<User>(`/users/${id}`);
      return response.data;
    } catch (error) {
      await this.errorHandler.handleError(error, {
        url: `/users/${id}`,
        method: 'GET',
      } as any);
      throw error;
    }
  }

  /**
   * Create new user with validation
   */
  async createUser(userData: CreateUser): Promise<User> {
    try {
      const validator = new ZodRequestValidator(CreateUserSchema);

      const response = await this.client.post<User, CreateUser>(
        '/users',
        userData,
        {
          validator,
        }
      );

      return response.data;
    } catch (error) {
      await this.errorHandler.handleError(error, {
        url: '/users',
        method: 'POST',
        body: userData,
      } as any);
      throw error;
    }
  }

  /**
   * Update user with partial data
   */
  async updateUser(id: number, updateData: UpdateUser): Promise<User> {
    try {
      const validator = new ZodRequestValidator(UpdateUserSchema);

      const response = await this.client.patch<User, UpdateUser>(
        `/users/${id}`,
        updateData,
        {
          validator,
        }
      );

      return response.data;
    } catch (error) {
      await this.errorHandler.handleError(error, {
        url: `/users/${id}`,
        method: 'PATCH',
        body: updateData,
      } as any);
      throw error;
    }
  }

  /**
   * Delete user
   */
  async deleteUser(id: number): Promise<void> {
    try {
      await this.client.delete(`/users/${id}`);
    } catch (error) {
      await this.errorHandler.handleError(error, {
        url: `/users/${id}`,
        method: 'DELETE',
      } as any);
      throw error;
    }
  }
}

// ============================================================================
// Example 2: CRUD Operations with Generated Validators
// ============================================================================

/**
 * Define product schemas
 */
const ProductSchema = z.object({
  id: z.number(),
  name: z.string(),
  description: z.string(),
  price: z.number().positive(),
  category: z.string(),
  inStock: z.boolean(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

const CreateProductSchema = z.object({
  name: z.string().min(1),
  description: z.string(),
  price: z.number().positive(),
  category: z.string(),
  inStock: z.boolean().default(true),
});

type Product = z.infer<typeof ProductSchema>;
type CreateProduct = z.infer<typeof CreateProductSchema>;

/**
 * Product service using generated CRUD validators
 */
class ProductService {
  private client: TypedHttpClient;
  private validators = createCrudValidator(CreateProductSchema, ProductSchema.partial());

  constructor() {
    this.client = createUserApiClient(); // Reuse client for simplicity
  }

  async createProduct(productData: CreateProduct): Promise<Product> {
    const response = await this.client.post<Product, CreateProduct>(
      '/products',
      productData,
      {
        validator: this.validators.create,
      }
    );

    return response.data;
  }

  async getProduct(id: number): Promise<Product> {
    const response = await this.client.get<Product>(`/products/${id}`);
    return response.data;
  }

  async updateProduct(id: number, updateData: Partial<CreateProduct>): Promise<Product> {
    const response = await this.client.patch<Product, Partial<CreateProduct>>(
      `/products/${id}`,
      updateData,
      {
        validator: this.validators.update,
      }
    );

    return response.data;
  }

  async deleteProduct(id: number): Promise<void> {
    await this.client.delete(`/products/${id}`);
  }

  async listProducts(): Promise<Product[]> {
    const response = await this.client.get<Product[]>('/products');
    return response.data;
  }
}

// ============================================================================
// Example 3: Error Handling with Type Discrimination
// ============================================================================

/**
 * Advanced error handling example
 */
async function demonstrateErrorHandling() {
  const client = createUserApiClient();
  const errorHandler = createHttpErrorHandler({
    enableRetry: true,
    maxRetries: 3,
    baseRetryDelay: 1000,
    logLevel: 'debug',
    errorMappings: {
      network_error: {
        category: ErrorCategory.NETWORK,
        severity: ErrorSeverity.HIGH,
        retryable: true,
        recoveryStrategy: 'backoff' as any,
        maxRetries: 5,
        retryDelay: 2000,
        userMessage: 'Network connection lost. Retrying...',
        technicalDetails: 'Network connectivity issues detected.',
      },
      authentication_error: {
        category: ErrorCategory.AUTHENTICATION,
        severity: ErrorSeverity.CRITICAL,
        retryable: false,
        recoveryStrategy: 'manual_intervention' as any,
        userMessage: 'Authentication failed. Please log in again.',
        technicalDetails: 'Invalid or expired authentication credentials.',
      },
    },
  });

  try {
    // This might fail with various error types
    const response = await client.get('/protected-resource');
    console.log('Success:', response.data);
  } catch (error) {
    // Handle with type discrimination
    try {
      await errorHandler.handleError(error, {
        url: '/protected-resource',
        method: 'GET',
      } as any);
    } catch (handledError) {
      console.error('Final error after handling:', handledError);

      // You can still check error types for specific handling
      if (handledError.type === 'authentication_error') {
        // Redirect to login
        console.log('Redirecting to login...');
      } else if (handledError.type === 'rate_limit_error') {
        // Show rate limit message
        console.log('Rate limited. Please wait...');
      }
    }
  }
}

// ============================================================================
// Example 4: Streaming API with Typed Responses
// ============================================================================

/**
 * Streaming API example
 */
class StreamingService {
  private client: TypedHttpClient;

  constructor() {
    this.client = createUserApiClient();
  }

  /**
   * Stream data from API
   */
  async *streamData(endpoint: string): AsyncGenerator<unknown> {
    try {
      const response = await this.client.get<ReadableStream>(
        endpoint,
        {
          headers: {
            'Accept': 'text/event-stream',
          },
        }
      );

      const reader = (response.data as ReadableStream).getReader();
      const decoder = new TextDecoder();

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split('\n').filter(line => line.trim());

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              try {
                const parsed = JSON.parse(data);
                yield parsed;
              } catch {
                yield { raw: data };
              }
            }
          }
        }
      } finally {
        reader.releaseLock();
      }
    } catch (error) {
      console.error('Streaming error:', error);
      throw error;
    }
  }
}

// ============================================================================
// Example 5: File Upload with Validation
// ============================================================================

/**
 * File upload service with validation
 */
class FileUploadService {
  private client: TypedHttpClient;

  constructor() {
    this.client = createUserApiClient();
  }

  /**
   * Upload file with type validation
   */
  async uploadFile(file: File, metadata: Record<string, string>): Promise<{
    id: string;
    filename: string;
    size: number;
    url: string;
  }> {
    const formData = new FormData();
    formData.append('file', file);

    // Add metadata
    Object.entries(metadata).forEach(([key, value]) => {
      formData.append(key, value);
    });

    try {
      const response = await this.client.post<{
        id: string;
        filename: string;
        size: number;
        url: string;
      }>('/upload', formData as any, {
        headers: {
          // Don't set Content-Type for FormData - browser sets it with boundary
        },
      });

      return response.data;
    } catch (error) {
      console.error('File upload failed:', error);
      throw error;
    }
  }

  /**
   * Validate file before upload
   */
  validateFile(file: File): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    const maxSize = 10 * 1024 * 1024; // 10MB
    const allowedTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'text/plain',
    ];

    if (file.size > maxSize) {
      errors.push(`File size ${file.size} exceeds maximum ${maxSize}`);
    }

    if (!allowedTypes.includes(file.type)) {
      errors.push(`File type ${file.type} not allowed`);
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

// ============================================================================
// Example 6: GraphQL API with Typed Operations
// ============================================================================

/**
 * GraphQL service with typed queries and mutations
 */
class GraphQLService {
  private client: TypedHttpClient;

  constructor() {
    this.client = new TypedHttpClientBuilder()
      .baseURL('https://api.example.com/graphql')
      .headers({
        'Content-Type': 'application/json',
      })
      .build();
  }

  /**
   * Execute GraphQL query with typed response
   */
  async query<TData = unknown, TVariables = Record<string, unknown>>(
    query: string,
    variables?: TVariables
  ): Promise<{
    data: TData;
    errors?: Array<{ message: string; path?: Array<string | number> }>;
  }> {
    try {
      const response = await this.client.post<{
        data: TData;
        errors?: Array<{ message: string; path?: Array<string | number> }>;
      }, {
        query: string;
        variables?: TVariables;
      }>('', {
        query,
        variables,
      });

      return response.data;
    } catch (error) {
      console.error('GraphQL query failed:', error);
      throw error;
    }
  }

  /**
   * Execute GraphQL mutation with typed response
   */
  async mutation<TData = unknown, TVariables = Record<string, unknown>>(
    mutation: string,
    variables: TVariables
  ): Promise<TData> {
    const result = await this.query<TData, TVariables>(mutation, variables);

    if (result.errors && result.errors.length > 0) {
      throw new Error(`GraphQL mutation failed: ${result.errors[0].message}`);
    }

    return result.data;
  }
}

// ============================================================================
// Usage Examples
// ============================================================================

/**
 * Demonstrate all examples
 */
async function demonstrateUsage() {
  console.log('=== Typed HTTP Client Usage Examples ===\n');

  // Example 1: Basic operations
  console.log('1. Basic CRUD Operations:');
  const userService = new UserService();

  try {
    // Create user
    const newUser = await userService.createUser({
      name: 'John Doe',
      email: 'john@example.com',
      role: 'user',
    });
    console.log('Created user:', newUser);

    // Get user
    const user = await userService.getUserById(newUser.id);
    console.log('Retrieved user:', user);

    // List users
    const users = await userService.getUsers(1, 10);
    console.log('Users list:', users);
  } catch (error) {
    console.error('User operation failed:', error);
  }

  // Example 2: Error handling
  console.log('\n2. Error Handling:');
  await demonstrateErrorHandling();

  // Example 3: Streaming
  console.log('\n3. Streaming API:');
  const streamingService = new StreamingService();

  try {
    for await (const chunk of streamingService.streamData('/events')) {
      console.log('Received chunk:', chunk);
      // Break after a few chunks for demo
      break;
    }
  } catch (error) {
    console.error('Streaming failed:', error);
  }

  console.log('\n=== Examples Complete ===');
}

// Export for use in other modules
export {
  UserService,
  ProductService,
  StreamingService,
  FileUploadService,
  GraphQLService,
  demonstrateUsage,
  type User,
  type CreateUser,
  type Product,
  type CreateProduct,
};