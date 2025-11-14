/**
 * Safe Types Usage Examples - Consolidated Type System
 *
 * This file demonstrates the new consolidated and enhanced type system
 * that eliminates all `any` usage and provides comprehensive type safety
 * throughout the Cortex MCP system.
 *
 * Key Features:
 * - Zero `any` usage
 * - Comprehensive type guards
 * - Unified type exports
 * - Runtime validation
 * - Enhanced error handling
 */

import type {
  // Base types (safe alternatives to `any`)
  JSONValue,
  Metadata,
} from '../src/types/index.js';

import {
  // Enhanced type guards for runtime validation
  isJSONValue,
  isMetadata,
} from '../src/types/index.js';

// =============================================================================
// Example 1: API Response Handling
// =============================================================================

interface ApiResponse {
  success: boolean;
  data: JSONValue;
  metadata?: Metadata;
}

function handleApiResponse(response: unknown): string {
  // Validate the response structure
  if (!response || typeof response !== 'object') {
    throw new Error('Invalid response: must be an object');
  }

  const apiResponse = response as Record<string, unknown>;

  if (apiResponse.success !== true) {
    throw new Error('API call failed');
  }

  if (!isJSONValue(apiResponse.data)) {
    throw new Error('Invalid response data format');
  }

  // Now we have type-safe access to the data
  const data = apiResponse.data;
  return JSON.stringify(data, null, 2);
}

// =============================================================================
// Example 2: Configuration Management
// =============================================================================

interface ServiceConfig {
  database: Config;
  cache: Config;
  logging: {
    level: string;
    enabled: boolean;
  };
}

function loadServiceConfig(configData: unknown): ServiceConfig {
  if (!configData || typeof configData !== 'object') {
    throw new Error('Configuration must be an object');
  }

  const config = configData as Record<string, unknown>;

  // Validate required sections
  if (!isDict(config.database, isJSONValue)) {
    throw new Error('Invalid database configuration');
  }

  if (!isDict(config.cache, isJSONValue)) {
    throw new Error('Invalid cache configuration');
  }

  if (!config.logging || typeof config.logging !== 'object') {
    throw new Error('Invalid logging configuration');
  }

  const logging = config.logging as Record<string, unknown>;
  if (typeof logging.level !== 'string' || typeof logging.enabled !== 'boolean') {
    throw new Error('Invalid logging settings');
  }

  return {
    database: config.database,
    cache: config.cache,
    logging: {
      level: logging.level,
      enabled: logging.enabled,
    },
  };
}

// =============================================================================
// Example 3: Tag Management System
// =============================================================================

class EntityTagManager {
  private tags: Tags = {};

  addTag(key: string, value: string): void {
    // Validate tag format
    if (!isTagsStrict({ [key]: value }, {
      maxTagLength: 100,
      tagKeyPattern: /^[a-z0-9-]+$/,
      tagValuePattern: /^[a-zA-Z0-9._\s-]+$/
    })) {
      throw new Error(`Invalid tag format: ${key} = ${value}`);
    }

    this.tags[key] = value;
  }

  getTags(): Tags {
    return { ...this.tags };
  }

  hasTag(key: string): boolean {
    return key in this.tags;
  }

  removeTag(key: string): boolean {
    if (key in this.tags) {
      delete this.tags[key];
      return true;
    }
    return false;
  }

  mergeTags(newTags: unknown): void {
    if (!isTags(newTags)) {
      throw new Error('Invalid tags format');
    }

    this.tags = { ...this.tags, ...newTags };
  }
}

// Helper function for strict tag validation
function isTagsStrict(
  tags: unknown,
  options: {
    maxTagLength?: number;
    tagKeyPattern?: RegExp;
    tagValuePattern?: RegExp;
  } = {}
): tags is Tags {
  const { maxTagLength = 200, tagKeyPattern, tagValuePattern } = options;

  if (!isDict(tags, isString)) {
    return false;
  }

  return Object.entries(tags).every(([key, value]) => {
    if (tagKeyPattern && !tagKeyPattern.test(key)) {
      return false;
    }

    if (tagValuePattern && !tagValuePattern.test(value)) {
      return false;
    }

    if (value.length > maxTagLength) {
      return false;
    }

    return true;
  });
}

// =============================================================================
// Example 4: Event Processing
// =============================================================================

interface UserActionEvent extends BaseEvent {
  type: 'USER_ACTION';
  data: {
    userId: string;
    action: string;
    timestamp: string;
    metadata?: Record<string, JSONValue>;
  };
}

class EventProcessor {
  private handlers: Dict<EventHandler> = {};

  registerHandler<T extends BaseEvent>(
    eventType: string,
    handler: EventHandler<T>
  ): void {
    this.handlers[eventType] = handler;
  }

  processEvent(eventData: unknown): void {
    if (!isBaseEvent(eventData)) {
      throw new Error('Invalid event format');
    }

    const handler = this.handlers[eventData.type];
    if (handler) {
      handler(eventData);
    } else {
      console.warn(`No handler registered for event type: ${eventData.type}`);
    }
  }
}

// =============================================================================
// Example 5: Query Parameter Processing
// =============================================================================

function buildUrlWithQuery(
  baseUrl: string,
  queryParams: unknown
): string {
  if (!isQueryParams(queryParams)) {
    throw new Error('Invalid query parameters');
  }

  const url = new URL(baseUrl);
  Object.entries(queryParams).forEach(([key, value]) => {
    url.searchParams.append(key, String(value));
  });

  return url.toString();
}

// =============================================================================
// Example 6: Custom Type Guard Composition
// =============================================================================

// Create specialized guards using composition utilities
const isPositiveInteger = and(
  (value: unknown): value is number => typeof value === 'number',
  (value: number): value is number => Number.isInteger(value) && value > 0
);

const isEmailOrPhone = or(
  (value: unknown): value is string => {
    if (typeof value !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  },
  (value: unknown): value is string => {
    if (typeof value !== 'string') return false;
    return /^\+?[\d\s-()]+$/.test(value);
  }
);

const isValidUserId = transform(
  (value: unknown) => String(value),
  (value: string): value is string => {
    // User ID should be a UUID or alphanumeric string
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) ||
           /^[a-zA-Z0-9_-]+$/.test(value);
  }
);

// Example usage of custom guards
function validateUserData(userData: unknown): { userId: string; contact: string; age: number } {
  if (!userData || typeof userData !== 'object') {
    throw new Error('User data must be an object');
  }

  const data = userData as Record<string, unknown>;

  if (!isValidUserId(data.userId)) {
    throw new Error('Invalid user ID');
  }

  if (!isEmailOrPhone(data.contact)) {
    throw new Error('Invalid contact information');
  }

  if (!isPositiveInteger(data.age)) {
    throw new Error('Invalid age');
  }

  return {
    userId: data.userId,
    contact: data.contact,
    age: data.age,
  };
}

// =============================================================================
// Example 7: Result Pattern Implementation
// =============================================================================

function safeParseJSON(jsonString: string): Result<JSONValue, Error> {
  try {
    const parsed = JSON.parse(jsonString);
    if (isJSONValue(parsed)) {
      return { success: true, data: parsed };
    } else {
      return { success: false, error: new Error('Invalid JSON structure') };
    }
  } catch (error) {
    return { success: false, error: error as Error };
  }
}

function processJSONResult(result: Result<JSONValue, Error>): string {
  if (result.success) {
    return JSON.stringify(result.data, null, 2);
  } else {
    throw result.error;
  }
}

// =============================================================================
// Example 8: Metadata Enrichment
// =============================================================================

function enrichMetadata(
  baseMetadata: unknown,
  additionalData: Record<string, JSONValue>
): Metadata {
  let metadata: Metadata = {};

  // Validate base metadata
  if (baseMetadata && isMetadata(baseMetadata)) {
    metadata = { ...baseMetadata };
  } else if (baseMetadata && typeof baseMetadata === 'object') {
    // Try to convert to valid metadata
    const converted = toMetadata(baseMetadata);
    if (converted) {
      metadata = converted;
    }
  }

  // Add timestamp and version if not present
  metadata.timestamp = metadata.timestamp || new Date().toISOString();
  metadata.version = metadata.version || '1.0.0';

  // Merge additional data
  Object.entries(additionalData).forEach(([key, value]) => {
    metadata[key] = value;
  });

  return metadata;
}

function toMetadata(data: unknown): Metadata | null {
  if (!data || typeof data !== 'object') {
    return null;
  }

  const metadata: Metadata = {};
  const obj = data as Record<string, unknown>;

  Object.entries(obj).forEach(([key, value]) => {
    if (key === 'tags' && isTags(value)) {
      metadata.tags = value;
    } else if (key === 'version' && typeof value === 'string') {
      metadata.version = value;
    } else if (key === 'source' && typeof value === 'string') {
      metadata.source = value;
    } else if (key === 'timestamp' && typeof value === 'string') {
      metadata.timestamp = value;
    } else if (isJSONValue(value)) {
      metadata[key] = value;
    }
  });

  return metadata;
}

// =============================================================================
// Example Usage
// =============================================================================

export function demonstrateSafeTypes(): void {
  console.log('=== Safe Types Usage Examples ===\n');

  // Example 1: API Response
  try {
    const mockResponse = {
      success: true,
      data: { userId: '123', name: 'John Doe', active: true },
      metadata: { version: '1.0', source: 'api' }
    };

    const result = handleApiResponse(mockResponse);
    console.log('1. API Response Handling:');
    console.log(result);
    console.log();
  } catch (error) {
    console.error('API Response Error:', error);
  }

  // Example 2: Configuration
  try {
    const mockConfig = {
      database: { host: 'localhost', port: 5432, ssl: true },
      cache: { ttl: 3600, maxSize: 1000 },
      logging: { level: 'info', enabled: true }
    };

    const config = loadServiceConfig(mockConfig);
    console.log('2. Configuration Loading:');
    console.log('Database host:', config.database.host);
    console.log('Cache TTL:', config.cache.ttl);
    console.log();
  } catch (error) {
    console.error('Config Error:', error);
  }

  // Example 3: Tag Management
  try {
    const tagManager = new EntityTagManager();
    tagManager.addTag('environment', 'production');
    tagManager.addTag('service', 'api-gateway');
    tagManager.addTag('version', '2.1.0');

    console.log('3. Tag Management:');
    console.log('Tags:', tagManager.getTags());
    console.log('Has environment tag:', tagManager.hasTag('environment'));
    console.log();
  } catch (error) {
    console.error('Tag Error:', error);
  }

  // Example 4: Event Processing
  try {
    const processor = new EventProcessor();
    processor.registerHandler('USER_ACTION', (event) => {
      console.log(`Processing user action: ${event.id}`);
    });

    const mockEvent: UserActionEvent = {
      type: 'USER_ACTION',
      id: 'evt-123',
      timestamp: new Date().toISOString(),
      data: {
        userId: 'user-456',
        action: 'login',
        timestamp: new Date().toISOString()
      }
    };

    console.log('4. Event Processing:');
    processor.processEvent(mockEvent);
    console.log();
  } catch (error) {
    console.error('Event Error:', error);
  }

  // Example 5: Query Parameters
  try {
    const params = { userId: '123', active: true, limit: 10 };
    const url = buildUrlWithQuery('https://api.example.com/users', params);
    console.log('5. Query Parameters:');
    console.log('Built URL:', url);
    console.log();
  } catch (error) {
    console.error('Query Error:', error);
  }

  // Example 6: Custom Validation
  try {
    const userData = {
      userId: 'user-abc123',
      contact: 'user@example.com',
      age: 25
    };

    const validated = validateUserData(userData);
    console.log('6. Custom Validation:');
    console.log('Validated user:', validated);
    console.log();
  } catch (error) {
    console.error('Validation Error:', error);
  }

  // Example 7: Result Pattern
  try {
    const jsonString = '{"name": "Alice", "age": 30, "active": true}';
    const result = safeParseJSON(jsonString);
    const processed = processJSONResult(result);
    console.log('7. Result Pattern:');
    console.log('Processed JSON:', processed);
    console.log();
  } catch (error) {
    console.error('Result Error:', error);
  }

  // Example 8: Metadata Enrichment
  try {
    const baseData = { tags: { environment: 'staging' } };
    const additional = { service: 'auth', version: '1.2.3' };
    const enriched = enrichMetadata(baseData, additional);
    console.log('8. Metadata Enrichment:');
    console.log('Enriched metadata:', JSON.stringify(enriched, null, 2));
    console.log();
  } catch (error) {
    console.error('Metadata Error:', error);
  }
}

// Run demonstration if this file is executed directly
if (require.main === module) {
  demonstrateSafeTypes();
}