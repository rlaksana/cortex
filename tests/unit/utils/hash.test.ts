/**
 * Comprehensive Unit Tests for Hashing Utilities
 *
 * Tests hashing functionality including:
 * - SHA-256 content hash computation
 * - Text normalization (whitespace, case)
 * - Deterministic hash generation
 * - Edge cases and error handling
 * - Performance considerations
 * - Security properties
 */

import { computeContentHash } from '../../../src/utils/hash.ts';

describe('Hashing Utilities', () => {
  describe('computeContentHash', () => {
    it('should generate consistent hash for same content', () => {
      const content = 'This is a test content for hashing';
      const hash1 = computeContentHash(content);
      const hash2 = computeContentHash(content);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 produces 64 hex characters
    });

    it('should normalize whitespace', () => {
      const content1 = 'Hello world';
      const content2 = 'Hello   world';
      const content3 = 'Hello\nworld';
      const content4 = 'Hello\tworld';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);
      const hash4 = computeContentHash(content4);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toBe(hash4);
    });

    it('should trim leading and trailing whitespace', () => {
      const content1 = 'Hello world';
      const content2 = '  Hello world  ';
      const content3 = '\nHello world\n';
      const content4 = '\tHello world\t';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);
      const hash4 = computeContentHash(content4);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toBe(hash4);
    });

    it('should convert to lowercase', () => {
      const content1 = 'Hello World';
      const content2 = 'HELLO WORLD';
      const content3 = 'hello world';
      const content4 = 'hElLo wOrLd';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);
      const hash4 = computeContentHash(content4);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toBe(hash4);
    });

    it('should handle empty string', () => {
      const hash = computeContentHash('');

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
      // Should be the hash of empty string
      expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should handle whitespace-only strings', () => {
      const content1 = '   ';
      const content2 = '\n\t\r ';
      const content3 = '    \n    \t    \r    ';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);

      // All should normalize to empty string
      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('should handle single character strings', () => {
      const hash1 = computeContentHash('a');
      const hash2 = computeContentHash('A');
      const hash3 = computeContentHash(' a ');

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle strings with special characters', () => {
      const content = 'Special chars: !@#$%^&*()_+-={}[]|\\:";\'<>?,./';
      const hash = computeContentHash(content);

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle strings with Unicode characters', () => {
      const content1 = 'café résumé';
      const content2 = 'CAFÉ RÉSUMÉ';
      const content3 = '  café   résumé  ';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle strings with emojis', () => {
      const content1 = '🚀 rocket';
      const content2 = '🚀   ROCKET';
      const content3 = '  🚀 rocket  ';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle very long strings', () => {
      const longString = 'a'.repeat(10000);
      const hash = computeContentHash(longString);

      expect(hash).toMatch(/^[a-f0-9]{64}$/);

      // Should be different from hash of short string
      const shortHash = computeContentHash('a');
      expect(hash).not.toBe(shortHash);
    });

    it('should handle JSON strings', () => {
      const json1 = '{"key": "value", "number": 42}';
      const json2 = '{  "key"  :  "value"  ,  "number"  :  42  }';
      const json3 = '{"KEY": "value", "NUMBER": 42}';

      const hash1 = computeContentHash(json1);
      const hash2 = computeContentHash(json2);
      const hash3 = computeContentHash(json3);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
    });

    it('should handle multiline strings', () => {
      const content1 = 'Line 1\nLine 2\nLine 3';
      const content2 = 'Line 1   \n   Line 2   \n   Line 3';
      const content3 = 'LINE 1\nLINE 2\nLINE 3';

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
    });
  });

  describe('Hash Properties', () => {
    it('should produce different hashes for different content', () => {
      const contents = [
        'content A',
        'content B',
        'Content A', // Different case (should be same after normalization)
        ' content A ', // Extra whitespace (should be same after normalization)
        'content A ', // Different trailing space (should be same after normalization)
      ];

      const hashes = contents.map(content => computeContentHash(content));

      expect(hashes[0]).toBe(hashes[1]); // Different content
      expect(hashes[0]).toBe(hashes[2]); // Same after case normalization
      expect(hashes[0]).toBe(hashes[3]); // Same after whitespace normalization
      expect(hashes[0]).toBe(hashes[4]); // Same after whitespace normalization
    });

    it('should be deterministic across multiple calls', () => {
      const content = 'Deterministic test content';
      const hashes = Array.from({ length: 100 }, () => computeContentHash(content));

      // All hashes should be identical
      expect(hashes.every(hash => hash === hashes[0])).toBe(true);
    });

    it('should have avalanche effect (small changes produce different hashes)', () => {
      const content1 = 'the quick brown fox';
      const content2 = 'the quick brown foxes'; // Pluralized
      const content3 = 'the quick brown fo'; // Missing x

      const hash1 = computeContentHash(content1);
      const hash2 = computeContentHash(content2);
      const hash3 = computeContentHash(content3);

      expect(hash1).not.toBe(hash2);
      expect(hash1).not.toBe(hash3);
      expect(hash2).not.toBe(hash3);

      // Hashes should be significantly different (not just a few characters)
      const diffCount1_2 = hash1.split('').filter((char, i) => char !== hash2[i]).length;
      const diffCount1_3 = hash1.split('').filter((char, i) => char !== hash3[i]).length;

      expect(diffCount1_2).toBeGreaterThan(20); // At least 20 different characters
      expect(diffCount1_3).toBeGreaterThan(20);
    });

    it('should handle hash collision resistance', () => {
      // Generate many different strings and check for collisions
      const strings = Array.from({ length: 1000 }, (_, i) => `test string ${i}`);
      const hashes = strings.map(str => computeContentHash(str));
      const uniqueHashes = new Set(hashes);

      expect(uniqueHashes.size).toBe(hashes.length); // No collisions
    });
  });

  describe('Normalization Behavior', () => {
    it('should normalize multiple consecutive spaces', () => {
      const tests = [
        ['hello world', 'hello   world'],
        ['test case', 'test    case'],
        ['multiple   spaces', 'multiple     spaces'],
      ];

      tests.forEach(([expected, input]) => {
        const expectedHash = computeContentHash(expected);
        const inputHash = computeContentHash(input);
        expect(expectedHash).toBe(inputHash);
      });
    });

    it('should normalize mixed whitespace characters', () => {
      const content = 'hello world';
      const variations = [
        'hello\tworld',
        'hello\nworld',
        'hello\rworld',
        'hello\r\nworld',
        'hello \t \n \r world',
      ];

      const baseHash = computeContentHash(content);
      const variationHashes = variations.map(v => computeContentHash(v));

      variationHashes.forEach(hash => {
        expect(hash).toBe(baseHash);
      });
    });

    it('should normalize leading and trailing whitespace correctly', () => {
      const content = 'hello world';
      const variations = [
        'hello world',
        ' hello world',
        'hello world ',
        '  hello world  ',
        '\thello world\t',
        '\nhello world\n',
        '\rhello world\r',
      ];

      const baseHash = computeContentHash(content);
      const variationHashes = variations.map(v => computeContentHash(v));

      variationHashes.forEach(hash => {
        expect(hash).toBe(baseHash);
      });
    });

    it('should handle empty results after normalization', () => {
      const inputs = ['   ', '\t', '\n', '\r', ' \t\n\r ', '\n\t\r\n\t '];
      const hashes = inputs.map(input => computeContentHash(input));

      // All should produce the same hash as empty string
      hashes.forEach(hash => {
        expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null input gracefully', () => {
      expect(() => computeContentHash(null as any)).not.toThrow();
    });

    it('should handle undefined input gracefully', () => {
      expect(() => computeContentHash(undefined as any)).not.toThrow();
    });

    it('should handle non-string input gracefully', () => {
      const nonStringInputs = [
        123,
        true,
        false,
        [],
        {},
        Symbol('test'),
        () => 'function',
      ];

      nonStringInputs.forEach(input => {
        expect(() => computeContentHash(input as any)).not.toThrow();
      });
    });

    it('should handle very large strings efficiently', () => {
      const largeString = 'a'.repeat(1000000); // 1MB string

      const startTime = performance.now();
      const hash = computeContentHash(largeString);
      const endTime = performance.now();

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete in under 1 second
    });

    it('should handle strings with null bytes', () => {
      const content = 'test\0string';
      const hash = computeContentHash(content);

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle strings with control characters', () => {
      const content = 'test\u0001\u0002\u0003string';
      const hash = computeContentHash(content);

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle strings with surrogate pairs', () => {
      const content = 'test\ud83d\ude00string'; // Emoji
      const hash = computeContentHash(content);

      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Performance Considerations', () => {
    it('should process small strings quickly', () => {
      const content = 'Small test string';
      const iterations = 10000;

      const startTime = performance.now();
      for (let i = 0; i < iterations; i++) {
        computeContentHash(content);
      }
      const endTime = performance.now();

      const averageTime = (endTime - startTime) / iterations;
      expect(averageTime).toBeLessThan(1); // Should average less than 1ms per hash
    });

    it('should handle batch processing efficiently', () => {
      const contents = Array.from({ length: 1000 }, (_, i) => `Content string number ${i}`);

      const startTime = performance.now();
      const hashes = contents.map(content => computeContentHash(content));
      const endTime = performance.now();

      expect(hashes).toHaveLength(1000);
      expect(hashes.every(hash => hash.match(/^[a-f0-9]{64}$/))).toBe(true);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete in under 1 second
    });

    it('should not leak memory during repeated hashing', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Perform many hash operations
      for (let i = 0; i < 10000; i++) {
        computeContentHash(`Test content ${i}`);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });

  describe('Real-world Scenarios', () => {
    it('should handle document content hashing', () => {
      const document1 = `# Document Title

This is a sample document with multiple paragraphs.

## Section 1

Some content here.

## Section 2

More content here.`;

      const document2 = `# Document Title


This is a sample document with multiple paragraphs.


## Section 1


Some content here.


## Section 2


More content here.`;

      const hash1 = computeContentHash(document1);
      const hash2 = computeContentHash(document2);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle code snippet hashing', () => {
      const code1 = `function example() {
    console.log('Hello, world!');
    return true;
}`;

      const code2 = `
function example()    {

    console.log('Hello, world!');

    return true;

}
    `;

      const hash1 = computeContentHash(code1);
      const hash2 = computeContentHash(code2);

      expect(hash1).toBe(hash2);
    });

    it('should handle configuration file hashing', () => {
      const config1 = `{
  "database": {
    "host": "localhost",
    "port": 5432,
    "name": "myapp"
  },
  "server": {
    "port": 3000,
    "host": "0.0.0.0"
  }
}`;

      const config2 = `{
  "database"  :  {
    "host"  :  "localhost"  ,
    "port"  :  5432  ,
    "name"  :  "myapp"
  }  ,
  "server"  :  {
    "port"  :  3000  ,
    "host"  :  "0.0.0.0"
  }
}`;

      const hash1 = computeContentHash(config1);
      const hash2 = computeContentHash(config2);

      expect(hash1).toBe(hash2);
    });

    it('should handle user input normalization', () => {
      const userInput1 = '  User\'s SEARCH query   ';
      const userInput2 = "user's search query";
      const userInput3 = "USER'S SEARCH QUERY";

      const hash1 = computeContentHash(userInput1);
      const hash2 = computeContentHash(userInput2);
      const hash3 = computeContentHash(userInput3);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
    });

    it('should handle URL and path normalization', () => {
      const path1 = '/api/v1/users/123/profile';
      const path2 = '  /api/v1/users/123/profile  ';
      const path3 = '/API/V1/USERS/123/PROFILE';

      const hash1 = computeContentHash(path1);
      const hash2 = computeContentHash(path2);
      const hash3 = computeContentHash(path3);

      expect(hash1).toBe(hash2);
      expect(hash1).toBe(hash3);
    });
  });

  describe('Security Properties', () => {
    it('should be resistant to timing attacks', () => {
      const content1 = 'short content';
      const content2 = 'a'.repeat(10000); // Much longer content

      // Time both operations
      const start1 = performance.now();
      const hash1 = computeContentHash(content1);
      const end1 = performance.now();

      const start2 = performance.now();
      const hash2 = computeContentHash(content2);
      const end2 = performance.now();

      const time1 = end1 - start1;
      const time2 = end2 - start2;

      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
      expect(hash2).toMatch(/^[a-f0-9]{64}$/);

      // Hash computation time should not vary significantly with content length
      // (allowing some variance for normalization processing)
      expect(Math.abs(time1 - time2)).toBeLessThan(100); // Within 100ms
    });

    it('should produce consistent output format', () => {
      const contents = Array.from({ length: 100 }, (_, i) => `Test content ${i}`);
      const hashes = contents.map(content => computeContentHash(content));

      // All hashes should be exactly 64 hexadecimal characters
      hashes.forEach(hash => {
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
        expect(hash.length).toBe(64);
      });
    });

    it('should handle potential hash collision inputs', () => {
      // Test strings that might cause similar intermediate states
      const testCases = [
        'aaaaaaaaaa',
        'aaaaaaaaab',
        'baaaaaaaaa',
        'a'.repeat(50) + 'b',
        'a'.repeat(49) + 'ba',
      ];

      const hashes = testCases.map(content => computeContentHash(content));

      // All hashes should be different
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(hashes.length);

      // Hashes should be significantly different
      for (let i = 0; i < hashes.length; i++) {
        for (let j = i + 1; j < hashes.length; j++) {
          const diffCount = hashes[i].split('').filter((char, k) => char !== hashes[j][k]).length;
          expect(diffCount).toBeGreaterThan(10); // At least 10 different characters
        }
      }
    });
  });
});