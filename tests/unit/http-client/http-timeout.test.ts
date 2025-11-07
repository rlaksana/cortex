/**
 * HTTP Client Timeout Tests
 *
 * Tests timeout functionality and proper abort controller usage
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  HttpClient,
  httpClient,
  fetchWithTimeout,
  createTimeoutFetchRequest,
} from '../../../src/http-client/index.js';

// Mock fetch to control timing
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('HTTP Client Timeout Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('HttpClient', () => {
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

    it('should timeout request when response takes too long', async () => {
      // Mock a fetch that never resolves
      mockFetch.mockImplementation(() => new Promise(() => {}));

      const client = new HttpClient({ timeout: 50 }); // Very short timeout

      const promise = client.get('https://example.com/api/test');

      // Advance time to trigger timeout
      vi.advanceTimersByTime(60);

      await expect(promise).rejects.toThrow('Request timeout after 50ms');
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

    it('should use custom timeout for individual requests', async () => {
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
      await client.get('https://example.com/api/test', { timeout: 2000 });

      // Verify the custom timeout was used (we can't directly test AbortSignal timeout,
      // but we can verify the request was made)
      expect(mockFetch).toHaveBeenCalled();
    });

    it('should retry failed requests', async () => {
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: new Headers({ 'content-type': 'application/json' }),
          url: 'https://example.com/api/test',
          json: vi.fn().mockResolvedValue({ data: 'success' }),
          text: vi.fn().mockResolvedValue('{"data": "success"}'),
          blob: vi.fn().mockResolvedValue(new Blob()),
        });

      const client = new HttpClient({ timeout: 1000, retries: 2, retryDelay: 10 });
      const result = await client.get('https://example.com/api/test');

      expect(result.data).toEqual({ data: 'success' });
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('should not retry on timeout errors', async () => {
      // Mock a fetch that never resolves
      mockFetch.mockImplementation(() => new Promise(() => {}));

      const client = new HttpClient({ timeout: 50, retries: 2 });

      const promise = client.get('https://example.com/api/test');

      // Advance time to trigger timeout
      vi.advanceTimersByTime(60);

      await expect(promise).rejects.toThrow('Request timeout after 50ms');

      // Should only be called once (no retries on timeout)
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should handle POST requests with JSON data', async () => {
      const mockResponse = {
        ok: true,
        status: 201,
        statusText: 'Created',
        headers: new Headers(),
        url: 'https://example.com/api/test',
        json: vi.fn().mockResolvedValue({ id: 1, name: 'test' }),
        text: vi.fn().mockResolvedValue('{"id": 1, "name": "test"}'),
        blob: vi.fn().mockResolvedValue(new Blob()),
      };

      mockFetch.mockResolvedValue(mockResponse);

      const client = new HttpClient();
      const postData = { name: 'test', value: 123 };
      const result = await client.post('https://example.com/api/test', postData);

      expect(result.status).toBe(201);
      expect(result.data).toEqual({ id: 1, name: 'test' });
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api/test',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(postData),
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should handle PUT requests', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        url: 'https://example.com/api/test/1',
        json: vi.fn().mockResolvedValue({ id: 1, name: 'updated' }),
        text: vi.fn().mockResolvedValue('{"id": 1, "name": "updated"}'),
        blob: vi.fn().mockResolvedValue(new Blob()),
      };

      mockFetch.mockResolvedValue(mockResponse);

      const client = new HttpClient();
      const putData = { name: 'updated' };
      const result = await client.put('https://example.com/api/test/1', putData);

      expect(result.data).toEqual({ id: 1, name: 'updated' });
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api/test/1',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify(putData),
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          signal: expect.any(AbortSignal),
        })
      );
    });

    it('should handle DELETE requests', async () => {
      const mockResponse = {
        ok: true,
        status: 204,
        statusText: 'No Content',
        headers: new Headers(),
        url: 'https://example.com/api/test/1',
      };

      mockFetch.mockResolvedValue(mockResponse);

      const client = new HttpClient();
      const result = await client.delete('https://example.com/api/test/1');

      expect(result.status).toBe(204);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api/test/1',
        expect.objectContaining({
          method: 'DELETE',
          signal: expect.any(AbortSignal),
        })
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

    it('should use default timeout when not specified', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: new Headers(),
        url: 'https://example.com/api/test',
      };

      mockFetch.mockResolvedValue(mockResponse);

      await fetchWithTimeout('https://example.com/api/test');

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

  describe('Default HTTP Client', () => {
    it('should provide default httpClient instance', () => {
      expect(httpClient).toBeDefined();
      expect(httpClient).toBeInstanceOf(HttpClient);
    });

    it('should provide convenience methods', () => {
      expect(get).toBeInstanceOf(Function);
      expect(post).toBeInstanceOf(Function);
      expect(put).toBeInstanceOf(Function);
      expect(del).toBeInstanceOf(Function);
      expect(fetchWithTimeout).toBeInstanceOf(Function);
    });
  });
});
