/**
 * Comprehensive Type Guards Usage Examples
 *
 * This file demonstrates how to use the enhanced type guards system
 * to replace `any` usage with runtime type safety throughout the application.
 */

import {
  // Basic Guards
  isString,
  isNumber,
  isBoolean,
  isNonEmptyString,
  isValidUUID,
  isValidISODate,

  // API Response Guards
  isSuccessResponse,
  isErrorResponse,
  isStandardApiResponse,
  isMCPToolResponse,

  // Knowledge Item Guards
  isKnowledgeItem,
  isSearchQuery,
  isSearchResult,
  isKnowledgeScope,

  // Configuration Guards
  isDatabaseConfig,
  isServiceConfig,
  isQdrantConfig,
  isAuthConfig,

  // Error Guards
  isValidationError,
  isSystemError,
  isDatabaseError,
  isNetworkError,

  // Guard Composition Utilities
  and,
  or,
  optional,
  arrayOf,
  hasProperty,
  hasProperties,
  partialShape,
  exactShape,
  discriminatedUnion,
  oneOf,
  oneOfValues,
  numberRange,
  stringPattern,
  stringLength,

  // Schema-Based Guards
  nestedObject,
  collectionSchema,
  conditionalGuard,

  // Performance Optimization
  memoized,
  fastFail,
  GuardPerformance,
} from '../src/utils/type-guards.js';

// =============================================================================
// Example 1: API Response Validation
// =============================================================================

function handleApiResponse(response: unknown) {
  // Basic success/error response handling
  if (isSuccessResponse(response, isString)) {
    console.log('Success:', response.data);
    return response.data; // TypeScript knows this is string
  }

  if (isErrorResponse(response)) {
    console.error('Error:', response.error.message);
    throw new Error(response.error.message);
  }

  throw new Error('Invalid response format');
}

// =============================================================================
// Example 2: Knowledge Item Processing
// =============================================================================

function processKnowledgeItem(item: unknown) {
  if (!isKnowledgeItem(item)) {
    throw new Error('Invalid KnowledgeItem format');
  }

  // TypeScript now knows item is a valid KnowledgeItem
  console.log(`Processing ${item.kind} from ${item.scope.project || 'unknown'}`);

  // Optional properties are properly typed
  if (item.content) {
    console.log(`Content length: ${item.content.length}`);
  }

  if (item.created_at) {
    const createdDate = new Date(item.created_at);
    console.log(`Created: ${createdDate.toISOString()}`);
  }
}

// =============================================================================
// Example 3: Configuration Validation
// =============================================================================

function validateDatabaseConfig(config: unknown) {
  // Use composition for complex validation
  const isCompleteConfig = and(
    isDatabaseConfig,
    hasProperty('qdrant', isQdrantConfig),
    hasProperty('fallbackEnabled', isBoolean)
  );

  if (!isCompleteConfig(config)) {
    throw new Error('Invalid database configuration');
  }

  // Safe to use config with proper typing
  console.log(`Database host: ${config.qdrant.host}`);
  console.log(`Fallback enabled: ${config.fallbackEnabled}`);
}

// =============================================================================
// Example 4: Error Handling with Type Guards
// =============================================================================

function handleError(error: unknown) {
  if (isValidationError(error)) {
    console.log(`Validation failed at ${error.path || 'unknown path'}: ${error.message}`);
    return;
  }

  if (isDatabaseError(error)) {
    console.log(`Database error in ${error.database}: ${error.message}`);
    if (error.retryable) {
      console.log('This error can be retried');
    }
    return;
  }

  if (isNetworkError(error)) {
    console.log(`Network error: ${error.message}`);
    if (error.statusCode) {
      console.log(`HTTP Status: ${error.statusCode}`);
    }
    return;
  }

  // Fallback for unknown errors
  console.error('Unknown error:', error);
}

// =============================================================================
// Example 5: Advanced Guard Composition
// =============================================================================

// Create a specialized guard for user objects
const isUser = exactShape({
  id: isString,
  name: isString,
  email: (value: unknown): value is string =>
    typeof value === 'string' && value.includes('@'),
  age: (value: unknown): value is number =>
    typeof value === 'number' && value >= 0 && value <= 150,
  isActive: optional(isBoolean),
  tags: optional(arrayOf(isString, { maxLength: 10 })),
});

// Create a guard for user search results
const isUserSearchResult = hasProperties({
  users: arrayOf(isUser),
  total: isNumber,
  page: isNumber,
});

function processUserSearchResults(data: unknown) {
  if (!isUserSearchResult(data)) {
    throw new Error('Invalid user search results');
  }

  console.log(`Found ${data.total} users on page ${data.page}`);
  data.users.forEach(user => {
    console.log(`- ${user.name} (${user.email})`);
  });
}

// =============================================================================
// Example 6: Discriminated Union Handling
// =============================================================================

type TextContent = { type: 'text'; content: string };
type ImageContent = { type: 'image'; url: string; alt?: string };
type VideoContent = { type: 'video'; url: string; duration: number };

// Create guards for each type
const isTextContent = discriminatedUnion('type', 'text',
  hasProperties({ content: isNonEmptyString })
);

const isImageContent = discriminatedUnion('type', 'image',
  hasProperties({ url: isValidURL })
);

const isVideoContent = discriminatedUnion('type', 'video',
  hasProperties({
    url: isValidURL,
    duration: numberRange(1, 3600) // 1 second to 1 hour
  })
);

// Create a union guard
const isContent = oneOf('type', {
  text: isTextContent,
  image: isImageContent,
  video: isVideoContent,
});

function processContent(content: unknown) {
  if (!isContent(content)) {
    throw new Error('Invalid content format');
  }

  switch (content.type) {
    case 'text':
      console.log(`Text: ${content.content.substring(0, 50)}...`);
      break;
    case 'image':
      console.log(`Image: ${content.url} (${content.alt || 'no alt text'})`);
      break;
    case 'video':
      console.log(`Video: ${content.url} (${content.duration}s)`);
      break;
  }
}

// =============================================================================
// Example 7: Schema-Based Validation
// =============================================================================

// Define a complex schema with nested validation
const userSchema = nestedObject({
  id: { validate: isValidUUID, required: true },
  profile: {
    validate: nestedObject({
      name: { validate: stringLength(1, 100), required: true },
      bio: { validate: stringLength(0, 500), required: false },
      avatar: { validate: isValidURL, required: false },
    }),
    required: true,
  },
  preferences: {
    validate: nestedObject({
      theme: { validate: oneOfValues(['light', 'dark', 'auto']), required: true },
      notifications: { validate: isBoolean, required: true },
      language: { validate: stringPattern(/^[a-z]{2}-[A-Z]{2}$/), required: false },
    }),
    required: false,
  },
  roles: {
    validate: collectionSchema(
      { validate: oneOfValues(['admin', 'user', 'guest']) },
      { minLength: 1, maxLength: 5 }
    ),
    required: true,
  },
}, { strict: true });

function validateUserWithSchema(user: unknown) {
  if (!userSchema(user)) {
    throw new Error('Invalid user schema');
  }

  // TypeScript knows the structure
  console.log(`User ${user.profile.name} has roles: ${user.roles.join(', ')}`);
  if (user.preferences) {
    console.log(`Theme: ${user.preferences.theme}`);
  }
}

// =============================================================================
// Example 8: Performance Optimization
// =============================================================================

// Create a memoized guard for expensive validations
const isExpensiveUser = memoized(isUser, (user) => (user as any).id);

// Create a fast-fail guard for common invalid inputs
const isUserFast = fastFail(isUser, ['null', 'undefined', 'string', 'number', 'boolean']);

// Wrap guard with performance monitoring
const isUserWithMetrics = GuardPerformance.wrap('user-validation', isUser);

function processUsersOptimized(users: unknown[]) {
  const validUsers = [];

  for (const user of users) {
    // Use fast-fail guard first
    if (!isUserFast(user)) {
      console.log('Fast-fail: invalid user type');
      continue;
    }

    // Use memoized guard for expensive validation
    if (isExpensiveUser(user)) {
      validUsers.push(user);
    }
  }

  // Check performance metrics
  const metrics = GuardPerformance.getMetrics('user-validation');
  console.log(`Validation metrics:`, metrics);

  return validUsers;
}

// =============================================================================
// Example 9: Conditional Validation
// =============================================================================

// Create conditional guards based on context
const isExternalUser = conditionalGuard(
  (value) => typeof value === 'object' && value !== null && 'source' in value && (value as any).source === 'external',
  hasProperties({ externalId: isString, provider: isString }),
  hasProperties({ internalId: isString })
);

function processUserBySource(user: unknown) {
  if (isExternalUser(user)) {
    if (user.source === 'external') {
      console.log(`Processing external user from ${user.provider}: ${user.externalId}`);
    } else {
      console.log(`Processing internal user: ${user.internalId}`);
    }
  }
}

// =============================================================================
// Example 10: Collection Validation with Constraints
// =============================================================================

// Validate a paginated response with constraints
const isPaginatedUsers = hasProperties({
  users: arrayOf(isUser, { minLength: 0, maxLength: 100 }),
  pagination: hasProperties({
    page: numberRange(1, Infinity),
    pageSize: numberRange(1, 100),
    total: numberRange(0, Infinity),
    hasNext: isBoolean,
    hasPrev: isBoolean,
  }),
  filters: optional(partialShape({
    role: oneOfValues(['admin', 'user', 'guest']),
    active: isBoolean,
    search: isString,
  })),
});

function processPaginatedUsers(response: unknown) {
  if (!isPaginatedUsers(response)) {
    throw new Error('Invalid paginated users response');
  }

  console.log(`Page ${response.pagination.page} of ${response.users.length} users`);
  console.log(`Total: ${response.pagination.total} users`);

  if (response.pagination.hasNext) {
    console.log('Next page available');
  }

  if (response.filters) {
    console.log('Applied filters:', response.filters);
  }
}

// =============================================================================
// Export examples for testing
// =============================================================================

export {
  handleApiResponse,
  processKnowledgeItem,
  validateDatabaseConfig,
  handleError,
  processUserSearchResults,
  processContent,
  validateUserWithSchema,
  processUsersOptimized,
  processUserBySource,
  processPaginatedUsers,
};

// Example usage in tests
export const examples = {
  validUser: {
    id: '123e4567-e89b-12d3-a456-426614174000',
    name: 'John Doe',
    email: 'john@example.com',
    age: 30,
    isActive: true,
    tags: ['developer', 'javascript'],
  },

  validKnowledgeItem: {
    id: 'item-123',
    kind: 'decision',
    content: 'This is a decision record',
    scope: { project: 'my-project', branch: 'main' },
    data: { decision: 'Use TypeScript', rationale: 'Type safety' },
    metadata: { version: '1.0' },
    created_at: '2024-01-01T00:00:00.000Z',
  },

  validApiResponse: {
    success: true,
    data: 'Operation completed successfully',
    message: 'Success',
  },

  validErrorResponse: {
    success: false,
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Invalid input data',
      details: { field: 'email', value: 'invalid-email' },
    },
  },
};