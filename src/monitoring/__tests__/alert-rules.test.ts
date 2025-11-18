import { evaluateCondition, withHysteresis, debounceSignal } from '../alert-rules';

// Type assertion for Jest globals
declare const describe: any;
declare const beforeEach: any;
declare const test: any;
declare const expect: any;
declare const beforeAll: any;
declare const afterAll: any;
declare const afterEach: any;
declare const it: any;

describe('alert-rules', () => {
  describe('evaluateCondition', () => {
    test('evaluates gt', () => {
      expect(evaluateCondition(5, 'gt', 3)).toBe(true);
      expect(evaluateCondition(2, 'gt', 3)).toBe(false);
    });

    test('evaluates lt', () => {
      expect(evaluateCondition(2, 'lt', 5)).toBe(true);
      expect(evaluateCondition(5, 'lt', 2)).toBe(false);
    });

    test('evaluates gte', () => {
      expect(evaluateCondition(5, 'gte', 5)).toBe(true);
      expect(evaluateCondition(4, 'gte', 5)).toBe(false);
    });

    test('evaluates lte', () => {
      expect(evaluateCondition(3, 'lte', 3)).toBe(true);
      expect(evaluateCondition(4, 'lte', 3)).toBe(false);
    });

    test('evaluates eq', () => {
      expect(evaluateCondition('foo', 'eq', 'foo')).toBe(true);
      expect(evaluateCondition('bar', 'eq', 'baz')).toBe(false);
      expect(evaluateCondition(5, 'eq', 5)).toBe(true);
      expect(evaluateCondition(5, 'eq', 6)).toBe(false);
    });

    test('evaluates ne', () => {
      expect(evaluateCondition('a', 'ne', 'b')).toBe(true);
      expect(evaluateCondition('x', 'ne', 'x')).toBe(false);
    });

    test('evaluates in', () => {
      expect(evaluateCondition('a', 'in', ['a', 'b'])).toBe(true);
      expect(evaluateCondition('c', 'in', ['a', 'b'])).toBe(false);
    });
  });
});
