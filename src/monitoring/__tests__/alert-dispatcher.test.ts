import { AlertDispatcher } from '../alert-dispatcher';

// Type assertion for Jest globals
declare const describe: any;
declare const beforeEach: any;
declare const test: any;
declare const expect: any;
declare const beforeAll: any;
declare const afterAll: any;
declare const afterEach: any;
declare const it: any;

describe('AlertDispatcher', () => {
  let dispatcher: AlertDispatcher;

  beforeEach(() => {
    dispatcher = new AlertDispatcher();
  });

  test('accepts valid types', async () => {
    // Ensure no error when dispatching to supported types
    await expect(dispatcher.dispatch('slack', 'test', {})).resolves.not.toThrow();
    await expect(dispatcher.dispatch('email', 'test', {})).resolves.not.toThrow();
    await expect(dispatcher.dispatch('pagerduty', 'test', {})).resolves.not.toThrow();
    await expect(dispatcher.dispatch('webhook', 'test', {})).resolves.not.toThrow();
    await expect(dispatcher.dispatch('sns', 'test', {})).resolves.not.toThrow();
    await expect(dispatcher.dispatch('teams', 'test', {})).resolves.not.toThrow();
  });
});
