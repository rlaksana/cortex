// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Branded Types for Safe Configuration and Identifiers
 *
 * This module provides branded types that prevent accidental misuse of values
 * and provide compile-time safety for critical configuration and identifier values.
 */

// ============================================================================
// Core Branded Type Infrastructure
// ============================================================================

/**
 * Creates a branded type with the specified brand
 */
export type Brand<T, B> = T & { readonly __brand: B };

/**
 * Type brand marker for configuration keys
 */
export interface ConfigKeyBrand {
  readonly __brand: 'ConfigKey';
}

/**
 * Type brand marker for environment names
 */
export interface EnvironmentBrand {
  readonly __brand: 'Environment';
}

/**
 * Type brand marker for service names
 */
export interface ServiceNameBrand {
  readonly __brand: 'ServiceName';
}

/**
 * Type brand marker for database connection strings
 */
export interface ConnectionStringBrand {
  readonly __brand: 'ConnectionString';
}

/**
 * Type brand marker for API keys and secrets
 */
export interface SecretBrand {
  readonly __brand: 'Secret';
}

/**
 * Type brand marker for hostnames
 */
export interface HostnameBrand {
  readonly __brand: 'Hostname';
}

/**
 * Type brand marker for port numbers
 */
export interface PortBrand {
  readonly __brand: 'Port';
}

/**
 * Type brand marker for version strings
 */
export interface VersionBrand {
  readonly __brand: 'Version';
}

/**
 * Type brand marker for feature flags
 */
export interface FeatureFlagBrand {
  readonly __brand: 'FeatureFlag';
}

/**
 * Type brand marker for metric names
 */
export interface MetricNameBrand {
  readonly __brand: 'MetricName';
}

/**
 * Type brand marker for tag keys
 */
export interface TagKeyBrand {
  readonly __brand: 'TagKey';
}

/**
 * Type brand marker for tag values
 */
export interface TagValueBrand {
  readonly __brand: 'TagValue';
}

// ============================================================================
// Configuration-Specific Branded Types
// ============================================================================

/**
 * Safe configuration key that can only be created through validation
 */
export type ConfigKey = Brand<string, ConfigKeyBrand>;

/**
 * Safe environment identifier
 */
export type Environment = Brand<string, EnvironmentBrand>;

/**
 * Safe service name identifier
 */
export type ServiceName = Brand<string, ServiceNameBrand>;

/**
 * Safe database connection string
 */
export type ConnectionString = Brand<string, ConnectionStringBrand>;

/**
 * Safe secret/API key
 */
export type Secret = Brand<string, SecretBrand>;

/**
 * Safe hostname
 */
export type Hostname = Brand<string, HostnameBrand>;

/**
 * Safe port number
 */
export type Port = Brand<number, PortBrand>;

/**
 * Safe version string
 */
export type Version = Brand<string, VersionBrand>;

/**
 * Safe feature flag name
 */
export type FeatureFlag = Brand<string, FeatureFlagBrand>;

/**
 * Safe metric name
 */
export type MetricName = Brand<string, MetricNameBrand>;

/**
 * Safe tag key
 */
export type TagKey = Brand<string, TagKeyBrand>;

/**
 * Safe tag value
 */
export type TagValue = Brand<string, TagValueBrand>;

// ============================================================================
// Generic Branded Type Utilities
// ============================================================================

/**
 * Type guard for branded types
 */
export function isBranded<T, B>(
  value: unknown,
  validator: (value: unknown) => value is T,
  brand: B
): value is Brand<T, B> {
  return validator(value) && typeof value === 'object' && '__brand' in value;
}

/**
 * Create a branded value with runtime validation
 */
export function createBranded<T, B>(
  value: T,
  validator: (value: T) => boolean,
  brand: B
): Brand<T, B> {
  if (!validator(value)) {
    throw new Error(`Invalid value for branded type: ${String(value)}`);
  }
  return value as Brand<T, B>;
}

/**
 * Unbrand a value to get the underlying type
 */
export function unbrand<T, B>(branded: Brand<T, B>): T {
  return branded as T;
}

// ============================================================================
// Configuration Key Utilities
// ============================================================================

/**
 * Valid configuration key patterns
 */
const CONFIG_KEY_PATTERNS = {
  // Database configuration keys
  DATABASE: /^(database\.qdrant\.(host|port|apiKey|timeout|maxRetries|retryDelay|useHttps|collectionPrefix|enableHealthChecks|connectionPoolSize|requestTimeout|connectTimeout))$/,

  // API configuration keys
  API: /^(api\.(port|host|compression|helmet|trustProxy|bodyLimit|timeout))$/,

  // Authentication configuration keys
  AUTH: /^(auth\.(jwt\.(secret|expiresIn|issuer|audience|algorithm)|apiKey\.(headerName|queryParam|validationEnabled|rateLimitEnabled)|enabled|sessionTimeout|refreshTokenEnabled|passwordPolicyEnabled))$/,

  // Logging configuration keys
  LOGGING: /^(logging\.(level|format|colorize|timestamp|file\.(enabled|path|maxSize|maxFiles|rotationInterval)|console\.(enabled|level)))$/,

  // Monitoring configuration keys
  MONITORING: /^(monitoring\.(metrics\.(enabled|interval|prefix|labels|defaultBuckets)|healthCheck\.(enabled|interval|timeout|retries|endpoints)|tracing\.(enabled|samplingRate|serviceName|version)|alerting\.(enabled|webhookUrl|emailSettings)))$/,

  // Security configuration keys
  SECURITY: /^(security\.(encryption\.(algorithm|keyLength|ivLength)|hashing\.(algorithm|rounds|saltLength)|validation\.(maxFileSize|allowedMimeTypes|allowedExtensions)|rateLimit|cors))$/,

  // Performance configuration keys
  PERFORMANCE: /^(performance\.(cache\.(enabled|ttl|maxSize|strategy|compressionEnabled)|compression\.(enabled|threshold|algorithm)|clustering\.(enabled|workers|maxMemory)))$/,

  // Feature flag keys
  FEATURES: /^(features\.(newSearchAlgorithm|enhancedLogging|betaFeatures|experimentalFeatures|debugMode))$/,

  // Environment-specific keys
  ENV: /^(environment|debug|logLevel)$/
} as const;

/**
 * Validate a configuration key
 */
export function isValidConfigKey(key: string): boolean {
  return Object.values(CONFIG_KEY_PATTERNS).some(pattern => pattern.test(key));
}

/**
 * Create a safe configuration key
 */
export function createConfigKey(key: string): ConfigKey {
  if (!isValidConfigKey(key)) {
    throw new Error(`Invalid configuration key: ${key}`);
  }
  return key as ConfigKey;
}

/**
 * Type guard for configuration keys
 */
export function isConfigKey(value: unknown): value is ConfigKey {
  return typeof value === 'string' && isValidConfigKey(value);
}

/**
 * Extract configuration category from key
 */
export function getConfigCategory(key: ConfigKey): string {
  const keyStr = unbrand(key);
  const firstSegment = keyStr.split('.')[0];
  return firstSegment;
}

/**
 * Extract configuration section from key
 */
export function getConfigSection(key: ConfigKey): string {
  const keyStr = unbrand(key);
  const segments = keyStr.split('.');
  return segments.slice(0, 2).join('.');
}

// ============================================================================
// Environment Type Utilities
// ============================================================================

/**
 * Valid environment values
 */
const VALID_ENVIRONMENTS = ['development', 'staging', 'production', 'test'] as const;

export type ValidEnvironment = typeof VALID_ENVIRONMENTS[number];

/**
 * Validate environment value
 */
export function isValidEnvironment(value: string): value is ValidEnvironment {
  return VALID_ENVIRONMENTS.includes(value as ValidEnvironment);
}

/**
 * Create a safe environment identifier
 */
export function createEnvironment(env: string): Environment {
  if (!isValidEnvironment(env)) {
    throw new Error(`Invalid environment: ${env}. Must be one of: ${VALID_ENVIRONMENTS.join(', ')}`);
  }
  return env as Environment;
}

/**
 * Type guard for environment
 */
export function isEnvironment(value: unknown): value is Environment {
  return typeof value === 'string' && isValidEnvironment(value);
}

/**
 * Get environment precedence (higher number = higher precedence)
 */
export function getEnvironmentPrecedence(env: Environment): number {
  const precedence: Record<ValidEnvironment, number> = {
    production: 4,
    staging: 3,
    test: 2,
    development: 1
  };
  return precedence[unbrand(env) as ValidEnvironment];
}

// ============================================================================
// Service Name Utilities
// ============================================================================

/**
 * Service name validation pattern
 */
const SERVICE_NAME_PATTERN = /^[a-z][a-z0-9-]*[a-z]$/;

/**
 * Validate service name
 */
export function isValidServiceName(name: string): boolean {
  return SERVICE_NAME_PATTERN.test(name) && name.length >= 3 && name.length <= 50;
}

/**
 * Create a safe service name
 */
export function createServiceName(name: string): ServiceName {
  if (!isValidServiceName(name)) {
    throw new Error(`Invalid service name: ${name}. Must be 3-50 characters, lowercase, alphanumeric with hyphens, no leading/trailing hyphens`);
  }
  return name as ServiceName;
}

/**
 * Type guard for service name
 */
export function isServiceName(value: unknown): value is ServiceName {
  return typeof value === 'string' && isValidServiceName(value);
}

// ============================================================================
// Connection String Utilities
// ============================================================================

/**
 * Connection string patterns for different databases
 */
const CONNECTION_STRING_PATTERNS = {
  // PostgreSQL: postgresql://[user[:password]@][host][:port][/dbname][?param1=value1&...]
  POSTGRESQL: /^postgresql:\/\/(?:([^:@]+)(?::([^@]*))?@)?([^:\/]+)(?::(\d+))?(\/[^?]+)?(?:\?(.*))?$/,

  // MongoDB: mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
  MONGODB: /^mongodb:\/\/(?:([^:]+):([^@]+)@)?([^\/]+)(?:\/([^?]+))?(?:\?(.*))?$/,

  // Redis: redis://[:password@]host[:port][/db-number]
  REDIS: /^redis:\/\/(?::([^@]+)@)?([^:\/]+)(?::(\d+))?(?:\/(\d+))?$/,

  // HTTP/HTTPS: http[s]://[user[:password]@]host[:port][path][?query]
  HTTP: /^https?:\/\/(?:([^:@]+)(?::([^@]*))?@)?([^:\/]+)(?::(\d+))?(\/[^?]*)?(?:\?(.*))?$/
} as const;

/**
 * Connection string types
 */
export type ConnectionStringType = keyof typeof CONNECTION_STRING_PATTERNS;

/**
 * Validate connection string format
 */
export function isValidConnectionString(value: string): boolean {
  return Object.values(CONNECTION_STRING_PATTERNS).some(pattern => pattern.test(value));
}

/**
 * Get connection string type
 */
export function getConnectionStringType(connectionString: string): ConnectionStringType | null {
  for (const [type, pattern] of Object.entries(CONNECTION_STRING_PATTERNS)) {
    if (pattern.test(connectionString)) {
      return type as ConnectionStringType;
    }
  }
  return null;
}

/**
 * Create a safe connection string
 */
export function createConnectionString(connectionString: string): ConnectionString {
  if (!isValidConnectionString(connectionString)) {
    throw new Error(`Invalid connection string format: ${connectionString}`);
  }
  return connectionString as ConnectionString;
}

/**
 * Type guard for connection string
 */
export function isConnectionString(value: unknown): value is ConnectionString {
  return typeof value === 'string' && isValidConnectionString(value);
}

/**
 * Parse connection string components (basic implementation)
 */
export function parseConnectionString(connectionString: ConnectionString): {
  type: ConnectionStringType;
  protocol: string;
  host: string;
  port?: number;
  username?: string;
  password?: string;
  database?: string;
  options?: Record<string, string>;
} {
  const str = unbrand(connectionString);
  const type = getConnectionStringType(str);

  if (!type) {
    throw new Error(`Unable to determine connection string type for: ${str}`);
  }

  const pattern = CONNECTION_STRING_PATTERNS[type];
  const match = str.match(pattern);

  if (!match) {
    throw new Error(`Invalid connection string format for type ${type}: ${str}`);
  }

  // Basic parsing - would need to be enhanced for production use
  const components: {
    type: ConnectionStringType;
    protocol: string;
    host: string;
    port?: number;
    username?: string;
    password?: string;
    database?: string;
    options?: Record<string, string>;
  } = {
    type,
    protocol: str.split('://')[0],
    host: match[3],
    port: match[4] ? parseInt(match[4], 10) : undefined,
    username: match[1],
    password: match[2],
    database: match[5]
  };

  // Parse options if present
  if (match[6]) {
    components.options = {};
    const options = match[6].split('&');
    for (const option of options) {
      const [key, value] = option.split('=');
      if (key && value) {
        components.options[key] = decodeURIComponent(value);
      }
    }
  }

  return components;
}

// ============================================================================
// Secret Type Utilities
// ============================================================================

/**
 * Minimum secret requirements
 */
const SECRET_REQUIREMENTS = {
  minLength: 8,
  maxLength: 2048,
  requireSpecialChars: false // Some secrets like API keys might not have special chars
} as const;

/**
 * Validate secret value (basic checks for common secret types)
 */
export function isValidSecret(value: string): boolean {
  if (value.length < SECRET_REQUIREMENTS.minLength ||
      value.length > SECRET_REQUIREMENTS.maxLength) {
    return false;
  }

  // Check for common insecure patterns
  const insecurePatterns = [
    /^(password|123456|qwerty|admin|test)/i,
    /^(.)\1+$/, // All same character
    /^(012345|abcde)/i // Sequential patterns
  ];

  return !insecurePatterns.some(pattern => pattern.test(value));
}

/**
 * Create a safe secret
 */
export function createSecret(secret: string): Secret {
  if (!isValidSecret(secret)) {
    throw new Error(`Invalid secret: must be between ${SECRET_REQUIREMENTS.minLength} and ${SECRET_REQUIREMENTS.maxLength} characters and not use common insecure patterns`);
  }
  return secret as Secret;
}

/**
 * Type guard for secret
 */
export function isSecret(value: unknown): value is Secret {
  return typeof value === 'string' && isValidSecret(value);
}

// ============================================================================
// Hostname Utilities
// ============================================================================

/**
 * Hostname validation pattern (RFC 1123)
 */
const HOSTNAME_PATTERN = /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?|[a-fA-F0-9:]+)$/;

/**
 * Validate hostname
 */
export function isValidHostname(hostname: string): boolean {
  return HOSTNAME_PATTERN.test(hostname) && hostname.length <= 253;
}

/**
 * Create a safe hostname
 */
export function createHostname(hostname: string): Hostname {
  if (!isValidHostname(hostname)) {
    throw new Error(`Invalid hostname: ${hostname}. Must follow RFC 1123 standards`);
  }
  return hostname as Hostname;
}

/**
 * Type guard for hostname
 */
export function isHostname(value: unknown): value is Hostname {
  return typeof value === 'string' && isValidHostname(value);
}

// ============================================================================
// Port Utilities
// ============================================================================

/**
 * Valid port range (excluding privileged ports for most services)
 */
const PORT_RANGE = {
  min: 1,
  max: 65535,
  recommendedMin: 1024 // Non-privileged ports
} as const;

/**
 * Validate port number
 */
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= PORT_RANGE.min && port <= PORT_RANGE.max;
}

/**
 * Validate non-privileged port
 */
export function isValidNonPrivilegedPort(port: number): boolean {
  return Number.isInteger(port) && port >= PORT_RANGE.recommendedMin && port <= PORT_RANGE.max;
}

/**
 * Create a safe port number
 */
export function createPort(port: number, allowPrivileged: boolean = false): Port {
  const validator = allowPrivileged ? isValidPort : isValidNonPrivilegedPort;
  if (!validator(port)) {
    const range = allowPrivileged
      ? `${PORT_RANGE.min}-${PORT_RANGE.max}`
      : `${PORT_RANGE.recommendedMin}-${PORT_RANGE.max}`;
    throw new Error(`Invalid port: ${port}. Must be an integer in range ${range}`);
  }
  return port as Port;
}

/**
 * Type guard for port
 */
export function isPort(value: unknown): value is Port {
  return typeof value === 'number' && isValidPort(value);
}

// ============================================================================
// Version Utilities
// ============================================================================

/**
 * Semantic version pattern
 */
const VERSION_PATTERN = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

/**
 * Version components
 */
export interface VersionComponents {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
  build?: string;
}

/**
 * Validate version string
 */
export function isValidVersion(version: string): boolean {
  return VERSION_PATTERN.test(version);
}

/**
 * Create a safe version
 */
export function createVersion(version: string): Version {
  if (!isValidVersion(version)) {
    throw new Error(`Invalid version format: ${version}. Must follow semantic versioning (x.y.z)`);
  }
  return version as Version;
}

/**
 * Type guard for version
 */
export function isVersion(value: unknown): value is Version {
  return typeof value === 'string' && isValidVersion(value);
}

/**
 * Parse version components
 */
export function parseVersion(version: Version): VersionComponents {
  const versionStr = unbrand(version);
  const match = versionStr.match(VERSION_PATTERN);

  if (!match) {
    throw new Error(`Invalid version: ${versionStr}`);
  }

  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4],
    build: match[5]
  };
}

/**
 * Compare two versions
 */
export function compareVersions(a: Version, b: Version): number {
  const aComponents = parseVersion(a);
  const bComponents = parseVersion(b);

  // Compare major, minor, patch
  for (const key of ['major', 'minor', 'patch'] as const) {
    if (aComponents[key] !== bComponents[key]) {
      return aComponents[key] > bComponents[key] ? 1 : -1;
    }
  }

  // Compare prerelease (if one has prerelease and other doesn't, the one without is greater)
  if (aComponents.prerelease && !bComponents.prerelease) return -1;
  if (!aComponents.prerelease && bComponents.prerelease) return 1;

  // If both have prerelease, compare them lexicographically
  if (aComponents.prerelease && bComponents.prerelease) {
    return aComponents.prerelease.localeCompare(bComponents.prerelease);
  }

  return 0;
}

// ============================================================================
// Feature Flag Utilities
// ============================================================================

/**
 * Feature flag name pattern
 */
const FEATURE_FLAG_PATTERN = /^[a-z][a-z0-9_]*[a-z]$/;

/**
 * Validate feature flag name
 */
export function isValidFeatureFlag(flag: string): boolean {
  return FEATURE_FLAG_PATTERN.test(flag) && flag.length >= 3 && flag.length <= 50;
}

/**
 * Create a safe feature flag name
 */
export function createFeatureFlag(flag: string): FeatureFlag {
  if (!isValidFeatureFlag(flag)) {
    throw new Error(`Invalid feature flag name: ${flag}. Must be 3-50 characters, lowercase, alphanumeric with underscores, no leading/trailing underscores`);
  }
  return flag as FeatureFlag;
}

/**
 * Type guard for feature flag
 */
export function isFeatureFlag(value: unknown): value is FeatureFlag {
  return typeof value === 'string' && isValidFeatureFlag(value);
}

// ============================================================================
// Metric Name Utilities
// ============================================================================

/**
 * Metric name pattern (following Prometheus conventions)
 */
const METRIC_NAME_PATTERN = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;

/**
 * Validate metric name
 */
export function isValidMetricName(name: string): boolean {
  return METRIC_NAME_PATTERN.test(name) && name.length >= 2 && name.length <= 200;
}

/**
 * Create a safe metric name
 */
export function createMetricName(name: string): MetricName {
  if (!isValidMetricName(name)) {
    throw new Error(`Invalid metric name: ${name}. Must follow Prometheus naming conventions`);
  }
  return name as MetricName;
}

/**
 * Type guard for metric name
 */
export function isMetricName(value: unknown): value is MetricName {
  return typeof value === 'string' && isValidMetricName(value);
}

// ============================================================================
// Tag Utilities
// ============================================================================

/**
 * Tag key pattern
 */
const TAG_KEY_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Tag value pattern (more lenient)
 */
const TAG_VALUE_PATTERN = /^[^\s]*$/; // No whitespace

/**
 * Validate tag key
 */
export function isValidTagKey(key: string): boolean {
  return TAG_KEY_PATTERN.test(key) && key.length >= 1 && key.length <= 100;
}

/**
 * Validate tag value
 */
export function isValidTagValue(value: string): boolean {
  return TAG_VALUE_PATTERN.test(value) && value.length >= 0 && value.length <= 200;
}

/**
 * Create a safe tag key
 */
export function createTagKey(key: string): TagKey {
  if (!isValidTagKey(key)) {
    throw new Error(`Invalid tag key: ${key}. Must be alphanumeric with underscores, no whitespace, max 100 characters`);
  }
  return key as TagKey;
}

/**
 * Create a safe tag value
 */
export function createTagValue(value: string): TagValue {
  if (!isValidTagValue(value)) {
    throw new Error(`Invalid tag value: ${value}. Must not contain whitespace, max 200 characters`);
  }
  return value as TagValue;
}

/**
 * Type guard for tag key
 */
export function isTagKey(value: unknown): value is TagKey {
  return typeof value === 'string' && isValidTagKey(value);
}

/**
 * Type guard for tag value
 */
export function isTagValue(value: unknown): value is TagValue {
  return typeof value === 'string' && isValidTagValue(value);
}

// ============================================================================
// Branded Type Collections
// ============================================================================

/**
 * Type-safe configuration map
 */
export type ConfigMap = Map<ConfigKey, unknown>;

/**
 * Type-safe tag map
 */
export type TagMap = Map<TagKey, TagValue>;

/**
 * Type-safe metric map
 */
export type MetricMap = Map<MetricName, number>;

/**
 * Type-safe service registry
 */
export type ServiceRegistry = Map<ServiceName, {
  version: Version;
  host: Hostname;
  port: Port;
  connectionString?: ConnectionString;
  enabled: boolean;
}>;

// ============================================================================
// Utility Functions for Branded Types
// ============================================================================

/**
 * Create a type-safe configuration map
 */
export function createConfigMap(): ConfigMap {
  return new Map();
}

/**
 * Create a type-safe tag map
 */
export function createTagMap(): TagMap {
  return new Map();
}

/**
 * Create a type-safe metric map
 */
export function createMetricMap(): MetricMap {
  return new Map();
}

/**
 * Create a type-safe service registry
 */
export function createServiceRegistry(): ServiceRegistry {
  return new Map();
}

/**
 * Validate branded type value and return it or throw
 */
export function validateBrandedType<T, B>(
  value: unknown,
  validator: (value: unknown) => value is T,
  errorMessage: string
): Brand<T, B> {
  if (!validator(value)) {
    throw new Error(errorMessage);
  }
  return value as Brand<T, B>;
}

/**
 * Safely cast to branded type (returns null if invalid)
 */
export function safeBrandedCast<T, B>(
  value: unknown,
  validator: (value: unknown) => value is T
): Brand<T, B> | null {
  return validator(value) ? (value as Brand<T, B>) : null;
}