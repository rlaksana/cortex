/**
 * HTTP Client Utility with Timeout Handling
 *
 * Provides centralized HTTP request functionality with consistent timeout,
 * abort controller, and error handling across the application.
 */

import {
  httpClientConfig,
  type LegacyHttpClientConfig,
  migrateHttpClientConfig,
  type StandardHttpClientConfig,
  validateHttpClientConfig,
} from '../config/configuration-migration.js';

/**
 * Legacy HttpClientConfig interface for backward compatibility
 * @deprecated Use StandardHttpClientConfig instead
 */
export interface HttpClientConfig {
  timeout?: number;
  timeoutMs?: number;
  headers?: Record<string, string>;
  retries?: number;
  retryAttempts?: number;
  retryDelay?: number;
  retryDelayMs?: number;
}

export interface HttpClientResponse<T = any> {
  data: T;
  status: number;
  statusText: string;
  headers: Headers;
  ok: boolean;
  url: string;
}

export class HttpClient {
  private config: StandardHttpClientConfig;

  constructor(config: HttpClientConfig = {}) {
    // Migrate legacy configuration to standard format
    const legacyConfig: LegacyHttpClientConfig = {
      timeout: 10000,
      timeoutMs: 10000,
      retries: 0,
      retryAttempts: 0,
      retryDelay: 1000,
      retryDelayMs: 1000,
      headers: {},
      ...config,
    };

    // Migrate to standard configuration
    this.config = migrateHttpClientConfig(legacyConfig);

    // Validate the migrated configuration
    const validation = validateHttpClientConfig(this.config);
    if (!validation.valid) {
      console.warn(
        `[http-client] Configuration validation failed: ${validation.errors.join(', ')}`
      );
    }
  }

  /**
   * Create an HttpClient with builder pattern
   */
  static builder(): HttpClientBuilder {
    return new HttpClientBuilder();
  }

  /**
   * Get the current configuration (read-only)
   */
  public getConfiguration(): Readonly<StandardHttpClientConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration with migration and validation
   */
  public updateConfiguration(config: Partial<HttpClientConfig>): void {
    const legacyConfig: LegacyHttpClientConfig = {
      ...this.config,
      ...config,
    };

    const standardConfig = migrateHttpClientConfig(legacyConfig);
    const validation = validateHttpClientConfig(standardConfig);

    if (!validation.valid) {
      throw new Error(`Invalid configuration update: ${validation.errors.join(', ')}`);
    }

    this.config = standardConfig;
  }

  /**
   * Perform HTTP request with timeout handling
   */
  async request<T = any>(
    url: string,
    options: RequestInit & {
      timeout?: number;
      timeoutMs?: number;
      retries?: number;
      retryAttempts?: number;
      retryDelay?: number;
      retryDelayMs?: number;
    } = {}
  ): Promise<HttpClientResponse<T>> {
    // Merge request-specific config with default config
    const { headers: optionsHeaders, ...otherOptions } = options;
    const requestConfig: LegacyHttpClientConfig = {
      timeout: this.config.timeoutMs,
      timeoutMs: this.config.timeoutMs,
      retries: this.config.retryAttempts,
      retryAttempts: this.config.retryAttempts,
      retryDelay: this.config.retryDelayMs,
      retryDelayMs: this.config.retryDelayMs,
      headers: this.config.headers,
      ...otherOptions,
    };

    // Migrate to standard format for this request
    const standardConfig = migrateHttpClientConfig(requestConfig);

    const timeout = standardConfig.timeoutMs;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= standardConfig.retryAttempts; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
          headers: this.convertHeadersToRecord({
            ...this.config.headers,
            ...standardConfig.headers,
            ...options.headers,
          }),
        });

        clearTimeout(timeoutId);

        // Handle HTTP errors
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        // Parse response based on content type
        const contentType = response.headers.get('content-type');
        let data: T;

        if (contentType?.includes('application/json')) {
          data = await response.json();
        } else if (contentType?.includes('text/')) {
          data = (await response.text()) as unknown as T;
        } else {
          data = (await response.blob()) as unknown as T;
        }

        return {
          data,
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
          ok: response.ok,
          url: response.url,
        };
      } catch (error) {
        clearTimeout(timeoutId);
        lastError = error as Error;

        // Don't retry on abort (timeout) or 4xx errors
        if (error instanceof Error && error.name === 'AbortError') {
          throw new Error(`Request timeout after ${timeout}ms`);
        }

        // Wait before retry (except on last attempt)
        if (attempt < standardConfig.retryAttempts) {
          await this.delay(standardConfig.retryDelayMs);
        }
      }
    }

    throw lastError || new Error('Request failed');
  }

  /**
   * Convenience method for GET requests
   */
  async get<T = any>(
    url: string,
    options: Omit<RequestInit, 'method'> & { timeout?: number } = {}
  ): Promise<HttpClientResponse<T>> {
    return this.request<T>(url, { ...options, method: 'GET' });
  }

  /**
   * Convenience method for POST requests
   */
  async post<T = any>(
    url: string,
    data?: any,
    options: Omit<RequestInit, 'method' | 'body'> & { timeout?: number } = {}
  ): Promise<HttpClientResponse<T>> {
    return this.request<T>(url, {
      ...options,
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
  }

  /**
   * Convenience method for PUT requests
   */
  async put<T = any>(
    url: string,
    data?: any,
    options: Omit<RequestInit, 'method' | 'body'> & { timeout?: number } = {}
  ): Promise<HttpClientResponse<T>> {
    return this.request<T>(url, {
      ...options,
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
  }

  /**
   * Convenience method for DELETE requests
   */
  async delete<T = any>(
    url: string,
    options: Omit<RequestInit, 'method'> & { timeout?: number } = {}
  ): Promise<HttpClientResponse<T>> {
    return this.request<T>(url, { ...options, method: 'DELETE' });
  }

  /**
   * Simple fetch wrapper with timeout for compatibility
   */
  async fetchWithTimeout(
    url: string,
    options: RequestInit & { timeout?: number; timeoutMs?: number } = {}
  ): Promise<Response> {
    // Handle both old and new timeout properties
    const timeout = options.timeoutMs || options.timeout || this.config.timeoutMs;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }

      throw error;
    }
  }

  /**
   * Helper method for delays
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Convert headers from HeadersInit to Record<string, string>
   */
  private convertHeaders(headers?: HeadersInit): Record<string, string> | undefined {
    if (!headers) {
      return undefined;
    }

    // If headers are already a Record, return as-is
    if (typeof headers === 'object' && !Array.isArray(headers) && !(headers instanceof Headers)) {
      return headers as Record<string, string>;
    }

    // Convert Headers object or array to Record
    const record: Record<string, string> = {};

    if (headers instanceof Headers) {
      headers.forEach((value, key) => {
        record[key] = value;
      });
    } else if (Array.isArray(headers)) {
      headers.forEach(([key, value]) => {
        record[key] = value;
      });
    }

    return record;
  }

  /**
   * Convert headers to Record<string, string> with guaranteed return type
   */
  private convertHeadersToRecord(
    headers?: HeadersInit | Record<string, string>
  ): Record<string, string> {
    if (!headers) return {};

    // If headers are already a Record, return as-is
    if (typeof headers === 'object' && !Array.isArray(headers) && !(headers instanceof Headers)) {
      return headers as Record<string, string>;
    }

    // Convert Headers object to Record
    if (headers instanceof Headers) {
      const record: Record<string, string> = {};
      headers.forEach((value, key) => {
        record[key] = value;
      });
      return record;
    }

    if (Array.isArray(headers)) {
      return Object.fromEntries(headers);
    }

    return headers as Record<string, string>;
  }
}

// Default HTTP client instance
export const httpClient = new HttpClient();

// Export convenience functions
export const { get, post, put, delete: del, fetchWithTimeout } = httpClient;

/**
 * Builder for HttpClient
 */
export class HttpClientBuilder {
  private config: Partial<HttpClientConfig> = {};

  /**
   * Set timeout in milliseconds
   */
  timeoutMs(timeoutMs: number): HttpClientBuilder {
    this.config.timeoutMs = timeoutMs;
    return this;
  }

  /**
   * Set timeout in seconds (convenience method)
   */
  timeoutSeconds(seconds: number): HttpClientBuilder {
    this.config.timeoutMs = seconds * 1000;
    return this;
  }

  /**
   * Set timeout (legacy property for backward compatibility)
   */
  timeout(timeout: number): HttpClientBuilder {
    this.config.timeout = timeout;
    return this;
  }

  /**
   * Set retry attempts
   */
  retryAttempts(attempts: number): HttpClientBuilder {
    this.config.retryAttempts = attempts;
    return this;
  }

  /**
   * Set retry attempts (legacy property for backward compatibility)
   */
  retries(retries: number): HttpClientBuilder {
    this.config.retries = retries;
    return this;
  }

  /**
   * Set retry delay in milliseconds
   */
  retryDelayMs(delayMs: number): HttpClientBuilder {
    this.config.retryDelayMs = delayMs;
    return this;
  }

  /**
   * Set retry delay in seconds (convenience method)
   */
  retryDelaySeconds(seconds: number): HttpClientBuilder {
    this.config.retryDelayMs = seconds * 1000;
    return this;
  }

  /**
   * Set retry delay (legacy property for backward compatibility)
   */
  retryDelay(delay: number): HttpClientBuilder {
    this.config.retryDelay = delay;
    return this;
  }

  /**
   * Set headers
   */
  headers(headers: Record<string, string>): HttpClientBuilder {
    this.config.headers = { ...this.config.headers, ...headers };
    return this;
  }

  /**
   * Add a single header
   */
  header(key: string, value: string): HttpClientBuilder {
    if (!this.config.headers) {
      this.config.headers = {};
    }
    this.config.headers[key] = value;
    return this;
  }

  /**
   * Build the HttpClient instance
   */
  build(): HttpClient {
    return new HttpClient(this.config);
  }
}

/**
 * Utility function to create a request with AbortSignal.timeout (modern approach)
 */
export function createTimeoutFetchRequest(
  url: string,
  options: RequestInit & { timeout?: number; timeoutMs?: number } = {}
): Promise<Response> {
  // Handle both old and new timeout properties
  const timeout = options.timeoutMs || options.timeout || 10000;

  return fetch(url, {
    ...options,
    signal: AbortSignal.timeout(timeout),
  });
}
