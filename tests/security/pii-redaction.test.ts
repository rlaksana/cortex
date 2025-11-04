import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStoreService } from '../../src/services/memory-store-service.js';
import { DatabaseManager } from '../../src/db/database-manager.js';

describe('Security Tests - PII Redaction and Data Privacy', () => {
  let memoryStore: MemoryStoreService;
  let dbManager: DatabaseManager;
  let testUserId: string;

  beforeEach(async () => {
    dbManager = new DatabaseManager();
    await dbManager.initialize();
    memoryStore = new MemoryStoreService(dbManager);
    testUserId = 'test-user-id';
  });

  afterEach(async () => {
    await dbManager.cleanup();
  });

  describe('PII Detection and Redaction', () => {
    it('should detect and redact email addresses', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithPII = `
        User contact information:
        Email: john.doe@example.com
        Work email: john.doe@company.org
        Support: support@helpdesk.net
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithPII,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('john.doe@example.com');
      expect(result.storedContent).not.toContain('john.doe@company.org');
      expect(result.storedContent).not.toContain('support@helpdesk.net');
      expect(result.storedContent).toContain('[REDACTED_EMAIL]');
    });

    it('should detect and redact phone numbers', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithPhoneNumbers = `
        Contact details:
        Mobile: +1-555-123-4567
        Office: (555) 987-6543
        International: +44 20 7946 0958
        Fax: 555.555.0123
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithPhoneNumbers,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('+1-555-123-4567');
      expect(result.storedContent).not.toContain('(555) 987-6543');
      expect(result.storedContent).not.toContain('+44 20 7946 0958');
      expect(result.storedContent).toContain('[REDACTED_PHONE]');
    });

    it('should detect and redact social security numbers', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithSSN = `
        Employee records:
        John Doe - SSN: 123-45-6789
        Jane Smith - SSN: 987-65-4321
        ID Format: 123456789
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithSSN,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('123-45-6789');
      expect(result.storedContent).not.toContain('987-65-4321');
      expect(result.storedContent).not.toContain('123456789');
      expect(result.storedContent).toContain('[REDACTED_SSN]');
    });

    it('should detect and redact credit card numbers', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithCreditCards = `
        Payment methods:
        Visa: 4111 1111 1111 1111
        Mastercard: 5500-0000-0000-0004
        Amex: 378282246310005
        Discover: 6011111111111117
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithCreditCards,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('4111 1111 1111 1111');
      expect(result.storedContent).not.toContain('5500-0000-0000-0004');
      expect(result.storedContent).not.toContain('378282246310005');
      expect(result.storedContent).toContain('[REDACTED_CREDIT_CARD]');
    });

    it('should detect and redact IP addresses', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithIPs = `
        Network logs:
        Source IP: 192.168.1.100
        Destination: 10.0.0.1
        External: 203.0.113.1
        IPv6: 2001:db8::1
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithIPs,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('192.168.1.100');
      expect(result.storedContent).not.toContain('10.0.0.1');
      expect(result.storedContent).not.toContain('203.0.113.1');
      expect(result.storedContent).not.toContain('2001:db8::1');
      expect(result.storedContent).toContain('[REDACTED_IP]');
    });
  });

  describe('Address and Location Redaction', () => {
    it('should detect and redact physical addresses', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithAddresses = `
        Contact information:
        Home: 123 Main St, Springfield, IL 62701
        Office: 456 Oak Avenue, Suite 200, New York, NY 10001
        International: 10 Downing Street, London SW1A 2AA, UK
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithAddresses,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('123 Main St');
      expect(result.storedContent).not.toContain('456 Oak Avenue');
      expect(result.storedContent).not.toContain('10 Downing Street');
      expect(result.storedContent).toContain('[REDACTED_ADDRESS]');
    });

    it('should detect and redact geographic coordinates', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithCoordinates = `
        Location data:
        GPS: 40.7128° N, 74.0060° W
        Decimal: 51.5074, -0.1278
        DMS: 37°46'31.2"N 122°25'07.5"W
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithCoordinates,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('40.7128');
      expect(result.storedContent).not.toContain('51.5074');
      expect(result.storedContent).not.toContain('37°46\'31.2');
      expect(result.storedContent).toContain('[REDACTED_COORDINATES]');
    });
  });

  describe 'Medical and Health Information Redaction', () => {
    it('should detect and redact medical record numbers', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithMedical = `
        Patient records:
        MRN: MRN-12345678
        Patient ID: PAT-987654321
        Medical Record: MED-0011223344
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithMedical,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('MRN-12345678');
      expect(result.storedContent).not.toContain('PAT-987654321');
      expect(result.storedContent).toContain('[REDACTED_MEDICAL_ID]');
    });

    it('should detect and redact sensitive health conditions', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithHealthInfo = `
        Health information:
        Diagnosis: Type 2 Diabetes, Hypertension
        Medications: Metformin 500mg, Lisinopril 10mg
        Allergies: Penicillin, Peanuts
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithHealthInfo,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('Type 2 Diabetes');
      expect(result.storedContent).not.toContain('Hypertension');
      expect(result.storedContent).not.toContain('Metformin');
      expect(result.storedContent).toContain('[REDACTED_HEALTH_INFO]');
    });
  });

  describe('Custom PII Patterns', () => {
    it('should detect and redact API keys and secrets', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithSecrets = `
        Configuration:
        AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE
        API_SECRET: sk-1234567890abcdef
        Database password: p@ssw0rd123!
        JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithSecrets,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(result.storedContent).not.toContain('sk-1234567890abcdef');
      expect(result.storedContent).not.toContain('p@ssw0rd123!');
      expect(result.storedContent).toContain('[REDACTED_SECRET]');
    });

    it('should detect and redact financial account numbers', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithAccounts = `
        Banking information:
        Account: 123456789
        Routing: 021000021
        IBAN: GB29NWBK60161331926819
        SWIFT: BOFAUS3NXXX
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithAccounts,
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.storedContent).not.toContain('123456789');
      expect(result.storedContent).not.toContain('021000021');
      expect(result.storedContent).not.toContain('GB29NWBK60161331926819');
      expect(result.storedContent).toContain('[REDACTED_ACCOUNT]');
    });
  });

  describe('PII Redaction Configuration', () => {
    it('should allow configurable redaction levels', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithMixedPII = `
        Contact: john.doe@example.com, Phone: 555-123-4567
        Address: 123 Main St, Anytown, USA
        Credit: 4111111111111111
      `;

      // Test strict redaction level
      const strictResult = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithMixedPII,
        scope: { tenant: 'test-tenant', org: 'test-org' },
        redactionLevel: 'strict'
      }, userContext);

      expect(strictResult.success).toBe(true);
      expect(strictResult.storedContent).not.toContain('john.doe@example.com');
      expect(strictResult.storedContent).not.toContain('555-123-4567');
      expect(strictResult.storedContent).not.toContain('123 Main St');
      expect(strictResult.storedContent).not.toContain('4111111111111111');

      // Test minimal redaction level
      const minimalResult = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithMixedPII,
        scope: { tenant: 'test-tenant', org: 'test-org' },
        redactionLevel: 'minimal'
      }, userContext);

      expect(minimalResult.success).toBe(true);
      // Should only redact the most sensitive information
      expect(minimalResult.storedContent).not.toContain('4111111111111111');
      expect(minimalResult.storedContent).not.toContain('123 Main St');
      // But might allow less sensitive info
    });

    it('should provide PII detection report', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      const contentWithPII = `
        User data: john.doe@example.com
        Phone: 555-123-4567
        SSN: 123-45-6789
        Address: 123 Main St, Anytown
      `;

      const result = await memoryStore.store({
        kind: 'entity' as const,
        content: contentWithPII,
        scope: { tenant: 'test-tenant', org: 'test-org' },
        includePIIReport: true
      }, userContext);

      expect(result.success).toBe(true);
      expect(result.piiReport).toBeDefined();
      expect(result.piiReport.detectedTypes).toContain('email');
      expect(result.piiReport.detectedTypes).toContain('phone');
      expect(result.piiReport.detectedTypes).toContain('ssn');
      expect(result.piiReport.detectedTypes).toContain('address');
      expect(result.piiReport.redactionCount).toBeGreaterThan(0);
    });
  });

  describe('Search and Retrieval Privacy', () => {
    it('should redact PII in search results', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      // Store content with PII
      await memoryStore.store({
        kind: 'entity' as const,
        content: 'Contact john.doe@example.com at 555-123-4567',
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      // Search for the content
      const searchResult = await memoryStore.find({
        query: 'Contact john.doe@example.com',
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      expect(searchResult.items).toHaveLength(1);
      expect(searchResult.items[0].content).not.toContain('john.doe@example.com');
      expect(searchResult.items[0].content).not.toContain('555-123-4567');
      expect(searchResult.items[0].content).toContain('[REDACTED_EMAIL]');
    });

    it('should not allow PII search bypass through wildcards', async () => {
      const userContext = {
        userId: testUserId,
        tenant: 'test-tenant',
        org: 'test-org'
      };

      // Store content with PII
      await memoryStore.store({
        kind: 'entity' as const,
        content: 'Email: john.doe@example.com',
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      // Try to search for partial PII
      const partialSearchResult = await memoryStore.find({
        query: 'john.doe@',
        scope: { tenant: 'test-tenant', org: 'test-org' }
      }, userContext);

      // Should not return results or should redact
      expect(partialSearchResult.items.length).toBeLessThanOrEqual(1);
      if (partialSearchResult.items.length > 0) {
        expect(partialSearchResult.items[0].content).not.toContain('john.doe@example.com');
      }
    });
  });
});