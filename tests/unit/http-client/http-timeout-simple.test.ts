/**
 * Simple HTTP Client Timeout Tests
 *
 * Tests core timeout functionality
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  HttpClient,
  fetchWithTimeout,
  createTimeoutFetchRequest,
} from '../../../src/http-client/index.js';

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('HTTP Client Timeout Handling - Simple Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should create HTTP client with default configuration', () => {
    const client = new HttpClient();
    expect(client).toBeDefined();
  });

  it('should handle successful requests with timeout', async () => {
    const mockResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers({ 'content-type': 'application/json' }),
      url: 'https://example.com/api/test',
      json: vi.fn().mockResolvedValue({ data: 'test' }),
      text: vi.fn().mockResolvedValue('{"data": "test"}'),
      blob: vi.fn().mockResolvedValue(new Blob()),
    };

    mockFetch.mockResolvedValue(mockResponse);

    const client = new HttpClient({ timeout: 5000 });
    const result = await client.get('https://example.com/api/test');

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ data: 'test' });
    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/api/test',
      expect.objectContaining({
        method: 'GET',
        signal: expect.any(AbortSignal),
      })
    );
  });

  it('should handle AbortError properly', async () => {
    const abortError = new Error('Request aborted');
    abortError.name = 'AbortError';
    mockFetch.mockRejectedValue(abortError);

    const client = new HttpClient({ timeout: 1000 });

    await expect(client.get('https://example.com/api/test')).rejects.toThrow(
      'Request timeout after 1000ms'
    );
  });

  it('should handle HTTP error responses', async () => {
    const mockResponse = {
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: new Headers(),
      url: 'https://example.com/api/notfound',
    };

    mockFetch.mockResolvedValue(mockResponse);

    const client = new HttpClient();

    await expect(client.get('https://example.com/api/notfound')).rejects.toThrow(
      'HTTP 404: Not Found'
    );
  });

  describe('fetchWithTimeout', () => {
    it('should add timeout to fetch request', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        url: 'https://example.com/api/test',
      };

      mockFetch.mockResolvedValue(mockResponse);

      const result = await fetchWithTimeout('https://example.com/api/test', { timeout: 5000 });

      expect(result).toBe(mockResponse);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api/test',
        expect.objectContaining({
          signal: expect.any(AbortSignal),
        })
      );
    });
  });

  describe('createTimeoutFetchRequest', () => {
    it('should create request with AbortSignal.timeout', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        url: 'https://example.com/api/test',
      };

      mockFetch.mockResolvedValue(mockResponse);

      const result = await createTimeoutFetchRequest('https://example.com/api/test', {
        timeout: 5000,
      });

      expect(result).toBe(mockResponse);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api/test',
        expect.objectContaining({
          signal: expect.any(AbortSignal),
        })
      );
    });
  });
});
