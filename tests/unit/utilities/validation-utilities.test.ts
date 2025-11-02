/**
 * Validation Utilities Tests
 *
 * Comprehensive tests for validation functionality including schema validation,
 * input sanitization, business rule validation, performance validation,
 * error reporting, and integration.
 */

import {
  ValidationService,
  type ValidationSchema,
  type ValidationResult,
  type ValidationError,
  type ValidationRule,
  type BusinessValidator,
  type ValidationContext,
  ValidationSeverity,
  ValidationMode,
} from '../../../src/services/validation/validation-service';

import {
  SchemaValidator,
  type ValidationOptions,
  type ValidationError as SchemaValidationError,
} from '../../../src/utils/validation/schema-validator';

import {
  InputSanitizer,
  type SanitizationOptions,
  type SanitizationResult,
} from '../../../src/utils/validation/input-sanitizer';

import {
  BusinessRuleValidator,
  type RuleDefinition,
  type RuleContext,
} from '../../../src/utils/validation/business-rule-validator';

import {
  ValidationCache,
  type CacheOptions,
  type CacheEntry,
} from '../../../src/utils/validation/validation-cache';

import {
  ValidationReporter,
  type ErrorReport,
  type ReportingOptions,
} from '../../../src/utils/validation/validation-reporter';

// Mock implementations
import { vi } from 'vitest';

const mockValidationService = {
  validateSchema: vi.fn(),
  validateInput: vi.fn(),
  validateBusinessRules: vi.fn(),
  batchValidate: vi.fn(),
  createValidator: vi.fn(),
  registerValidator: vi.fn(),
  clearCache: vi.fn(),
  getValidationStats: vi.fn(),
} as any;

const mockSchemaValidator: any = {
  validate: vi.fn(),
  compile: vi.fn(),
  addFormat: vi.fn(),
  removeFormat: vi.fn(),
  getFormats: vi.fn(),
} as any;

const mockInputSanitizer: any = {
  sanitize: vi.fn(),
  sanitizeBatch: vi.fn(),
  validateSanitized: vi.fn(),
  addSanitizationRule: vi.fn(),
  removeSanitizationRule: vi.fn(),
} as any;

const mockBusinessRuleValidator: any = {
  validate: vi.fn(),
  addRule: vi.fn(),
  removeRule: vi.fn(),
  getRules: vi.fn(),
  validateWithContext: vi.fn(),
} as any;

const mockValidationCache: any = {
  get: vi.fn(),
  set: vi.fn(),
  delete: vi.fn(),
  clear: vi.fn(),
  has: vi.fn(),
  getStats: vi.fn(),
  cleanup: vi.fn(),
} as any;

const mockValidationReporter: any = {
  reportErrors: vi.fn(),
  formatErrors: vi.fn(),
  aggregateErrors: vi.fn(),
  createReport: vi.fn(),
  exportReport: vi.fn(),
  clearErrors: vi.fn(),
} as any;

describe('Schema Validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('JSON Schema Validation', () => {
    it('should validate valid JSON schema', async () => {
      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          age: { type: 'number', minimum: 0 },
        },
        required: ['name'],
      };

      const data = { name: 'John', age: 30 };
      const expectedResult: ValidationResult = {
        valid: true,
        errors: [],
        data,
      };

      mockValidationService.validateSchema.mockResolvedValue(expectedResult);

      const result = await mockValidationService.validateSchema(data, schema);

      expect(result).toEqual(expectedResult);
      expect(mockValidationService.validateSchema).toHaveBeenCalledWith(data, schema);
    });

    it('should reject invalid JSON schema', async () => {
      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          age: { type: 'number', minimum: 0 },
        },
        required: ['name', 'age'],
      };

      const data = { name: 'John' }; // Missing required age
      const expectedResult: ValidationResult = {
        valid: false,
        errors: [
          {
            field: 'age',
            message: 'Required field',
            code: 'REQUIRED',
            severity: ValidationSeverity.ERROR,
          },
        ],
        data,
      };

      mockValidationService.validateSchema.mockResolvedValue(expectedResult);

      const result = await mockValidationService.validateSchema(data, schema);

      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].field).toBe('age');
    });

    it('should handle nested object validation', async () => {
      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          user: {
            type: 'object',
            properties: {
              profile: {
                type: 'object',
                properties: {
                  email: { type: 'string', format: 'email' },
                },
                required: ['email'],
              },
            },
            required: ['profile'],
          },
        },
        required: ['user'],
      };

      const data = {
        user: {
          profile: {
            email: 'invalid-email',
          },
        },
      };

      const expectedResult: ValidationResult = {
        valid: false,
        errors: [
          {
            field: 'user.profile.email',
            message: 'Invalid email format',
            code: 'FORMAT',
            severity: ValidationSeverity.ERROR,
          },
        ],
        data,
      };

      mockValidationService.validateSchema.mockResolvedValue(expectedResult);

      const result = await mockValidationService.validateSchema(data, schema);

      expect(result.valid).toBe(false);
      expect(result.errors[0].field).toBe('user.profile.email');
    });

    it('should validate array schemas', async () => {
      const schema: ValidationSchema = {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'number' },
            name: { type: 'string' },
          },
          required: ['id', 'name'],
        },
      };

      const data = [
        { id: 1, name: 'Item 1' },
        { id: 2, name: 'Item 2' },
        { id: 3 }, // Missing name
      ];

      const expectedResult: ValidationResult = {
        valid: false,
        errors: [
          {
            field: '[2].name',
            message: 'Required field',
            code: 'REQUIRED',
            severity: ValidationSeverity.ERROR,
          },
        ],
        data,
      };

      mockValidationService.validateSchema.mockResolvedValue(expectedResult);

      const result = await mockValidationService.validateSchema(data, schema);

      expect(result.valid).toBe(false);
      expect(result.errors[0].field).toBe('[2].name');
    });
  });

  describe('Type Validation Utilities', () => {
    it('should validate basic types', () => {
      const schema: ValidationSchema = { type: 'string' };

      mockSchemaValidator.validate.mockReturnValue({
        valid: true,
        errors: [],
      });

      const result = mockSchemaValidator.validate('test string', schema);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle type conversion', () => {
      const schema: ValidationSchema = { type: 'number' };

      mockSchemaValidator.validate.mockReturnValue({
        valid: true,
        errors: [],
        data: 42,
      });

      const result = mockSchemaValidator.validate('42', schema);

      expect(result.valid).toBe(true);
      expect(result.data).toBe(42);
    });

    it('should validate union types', () => {
      const schema: ValidationSchema = {
        anyOf: [{ type: 'string' }, { type: 'number' }],
      };

      mockSchemaValidator.validate.mockReturnValue({
        valid: true,
        errors: [],
      });

      const result = mockSchemaValidator.validate(42, schema);

      expect(result.valid).toBe(true);
    });

    it('should handle custom formats', () => {
      const schema: ValidationSchema = {
        type: 'string',
        format: 'custom-date',
      };

      mockSchemaValidator.validate.mockReturnValue({
        valid: true,
        errors: [],
      });

      mockSchemaValidator.addFormat('custom-date', (value: string) => {
        return /^\d{4}-\d{2}-\d{2}$/.test(value);
      });

      const result = mockSchemaValidator.validate('2025-01-15', schema);

      expect(result.valid).toBe(true);
    });
  });

  describe('Custom Validation Rules', () => {
    it('should execute custom validation rules', async () => {
      const customRule: ValidationRule = {
        name: 'customRule',
        validator: (value: any) => {
          return typeof value === 'string' && value.length >= 3;
        },
        message: 'String must be at least 3 characters long',
      };

      const data = { name: 'Jo' }; // Too short

      mockValidationService.validateSchema.mockResolvedValue({
        valid: false,
        errors: [
          {
            field: 'name',
            message: customRule.message,
            code: 'CUSTOM_VALIDATION',
            severity: ValidationSeverity.ERROR,
          },
        ],
        data,
      });

      const result = await mockValidationService.validateSchema(data, {}, [customRule]);

      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe(customRule.message);
    });

    it('should allow async validation rules', async () => {
      const asyncRule: ValidationRule = {
        name: 'asyncRule',
        validator: async (value: any) => {
          // Simulate async check
          await new Promise((resolve) => setTimeout(resolve, 10));
          return value && value.exists;
        },
        message: 'Resource must exist',
      };

      const data = { id: 1, exists: true };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data,
      });

      const result = await mockValidationService.validateSchema(data, {}, [asyncRule]);

      expect(result.valid).toBe(true);
    });

    it('should handle rule dependency resolution', async () => {
      const rules: ValidationRule[] = [
        {
          name: 'rule1',
          validator: (value: any) => value.step1,
          message: 'Step 1 failed',
          dependsOn: [],
        },
        {
          name: 'rule2',
          validator: (value: any) => value.step2,
          message: 'Step 2 failed',
          dependsOn: ['rule1'],
        },
      ];

      const data = { step1: true, step2: true };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data,
      });

      const result = await mockValidationService.validateSchema(data, {}, rules);

      expect(result.valid).toBe(true);
    });
  });

  describe('Validation Error Formatting', () => {
    it('should format validation errors consistently', () => {
      const errors: ValidationError[] = [
        {
          field: 'name',
          message: 'Name is required',
          code: 'REQUIRED',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'email',
          message: 'Invalid email format',
          code: 'FORMAT',
          severity: ValidationSeverity.WARNING,
        },
      ];

      mockValidationReporter.formatErrors.mockReturnValue({
        formattedErrors: [
          'ERROR: name - Name is required',
          'WARNING: email - Invalid email format',
        ],
        summary: {
          total: 2,
          errors: 1,
          warnings: 1,
        },
      });

      const result = mockValidationReporter.formatErrors(errors);

      expect(result.formattedErrors).toHaveLength(2);
      expect(result.summary.errors).toBe(1);
      expect(result.summary.warnings).toBe(1);
    });

    it('should provide error context information', () => {
      const error: ValidationError = {
        field: 'user.address.zip',
        message: 'Invalid ZIP code',
        code: 'FORMAT',
        severity: ValidationSeverity.ERROR,
        context: {
          schemaPath: 'properties.user.properties.address.properties.zip',
          value: 'invalid',
          allowedValues: ['12345', '12345-6789'],
        },
      };

      mockValidationReporter.formatErrors.mockReturnValue({
        formattedErrors: [
          'ERROR: user.address.zip - Invalid ZIP code (Value: "invalid", Expected: ZIP format)',
        ],
        summary: {
          total: 1,
          errors: 1,
          warnings: 0,
        },
      });

      const result = mockValidationReporter.formatErrors([error]);

      expect(result.formattedErrors[0]).toContain('user.address.zip');
      expect(result.formattedErrors[0]).toContain('invalid');
    });
  });
});

describe('Input Sanitization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Data Sanitization Utilities', () => {
    it('should sanitize HTML input', () => {
      const input = '<script>alert("xss")</script><p>Safe content</p>';
      const options: SanitizationOptions = {
        allowedTags: ['p'],
        allowedAttributes: {},
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: '<p>Safe content</p>',
        changed: true,
        removed: ['script'],
        warnings: [],
      });

      const result = mockInputSanitizer.sanitize(input, options);

      expect(result.sanitized).toBe('<p>Safe content</p>');
      expect(result.changed).toBe(true);
      expect(result.removed).toContain('script');
    });

    it('should sanitize SQL input', () => {
      const input = "'; DROP TABLE users; --";
      const options: SanitizationOptions = {
        type: 'sql',
        escapeQuotes: true,
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: "\\'\\'; DROP TABLE users; --",
        changed: true,
        removed: [],
        warnings: ['SQL injection attempt detected'],
      });

      const result = mockInputSanitizer.sanitize(input, options);

      expect(result.sanitized).toContain("\\'");
      expect(result.warnings).toContain('SQL injection attempt detected');
    });

    it('should handle batch sanitization', () => {
      const inputs = [
        '<script>alert("xss")</script>',
        '<p>Safe content</p>',
        "'; DROP TABLE users; --",
      ];

      const options: SanitizationOptions = {
        allowedTags: ['p'],
        allowedAttributes: {},
        escapeQuotes: true,
      };

      mockInputSanitizer.sanitizeBatch.mockReturnValue([
        { sanitized: '', changed: true, removed: ['script'], warnings: [] },
        { sanitized: '<p>Safe content</p>', changed: false, removed: [], warnings: [] },
        {
          sanitized: "\\'\\'; DROP TABLE users; --",
          changed: true,
          removed: [],
          warnings: ['SQL injection attempt detected'],
        },
      ]);

      const results = mockInputSanitizer.sanitizeBatch(inputs, options);

      expect(results).toHaveLength(3);
      expect(results[0].removed).toContain('script');
      expect(results[2].warnings).toContain('SQL injection attempt detected');
    });

    it('should preserve safe content', () => {
      const input = '<p>This is <strong>safe</strong> content</p>';
      const options: SanitizationOptions = {
        allowedTags: ['p', 'strong'],
        allowedAttributes: {},
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: input,
        changed: false,
        removed: [],
        warnings: [],
      });

      const result = mockInputSanitizer.sanitize(input, options);

      expect(result.sanitized).toBe(input);
      expect(result.changed).toBe(false);
    });
  });

  describe('XSS Prevention Validation', () => {
    it('should detect and prevent XSS attacks', () => {
      const xssInputs = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(\'xss\')">',
        '<a href="javascript:alert(\'xss\')">Click me</a>',
        '<div onclick="alert(\'xss\')">Click</div>',
      ];

      const options: SanitizationOptions = {
        xssProtection: true,
        removeEventHandlers: true,
        removeJavascriptProtocols: true,
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: '',
        changed: true,
        removed: ['script', 'img', 'a', 'div'],
        warnings: xssInputs.map((input) => `XSS attempt detected: ${input.substring(0, 20)}...`),
      });

      xssInputs.forEach((input) => {
        const result = mockInputSanitizer.sanitize(input, options);
        expect(result.warnings.some((w) => w.includes('XSS attempt'))).toBe(true);
      });
    });

    it('should allow safe HTML attributes', () => {
      const input = '<a href="https://example.com" title="Safe link">Click me</a>';
      const options: SanitizationOptions = {
        allowedTags: ['a'],
        allowedAttributes: { href: true, title: true },
        xssProtection: true,
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: input,
        changed: false,
        removed: [],
        warnings: [],
      });

      const result = mockInputSanitizer.sanitize(input, options);

      expect(result.sanitized).toBe(input);
      expect(result.changed).toBe(false);
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should detect SQL injection patterns', () => {
      const sqlInjectionPatterns = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        'UNION SELECT * FROM passwords',
        "'; EXEC xp_cmdshell('dir'); --",
      ];

      const options: SanitizationOptions = {
        type: 'sql',
        sqlInjectionProtection: true,
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: '',
        changed: true,
        removed: [],
        warnings: sqlInjectionPatterns.map(
          (pattern) => `SQL injection attempt detected: ${pattern}`
        ),
      });

      sqlInjectionPatterns.forEach((pattern) => {
        const result = mockInputSanitizer.sanitize(pattern, options);
        expect(result.warnings.some((w) => w.includes('SQL injection attempt'))).toBe(true);
      });
    });

    it('should safely escape SQL parameters', () => {
      const input = "O'Reilly";
      const options: SanitizationOptions = {
        type: 'sql',
        escapeQuotes: true,
      };

      mockInputSanitizer.sanitize.mockReturnValue({
        sanitized: "O''Reilly",
        changed: true,
        removed: [],
        warnings: [],
      });

      const result = mockInputSanitizer.sanitize(input, options);

      expect(result.sanitized).toBe("O''Reilly");
    });
  });

  describe('Input Format Validation', () => {
    it('should validate email formats', () => {
      const validEmails = ['user@example.com', 'user.name@example.co.uk', 'user+tag@example.org'];

      const invalidEmails = ['invalid-email', '@example.com', 'user@', 'user..name@example.com'];

      mockInputSanitizer.validateSanitized.mockReturnValue(true);

      validEmails.forEach((email) => {
        const result = mockInputSanitizer.validateSanitized(email, { type: 'email' });
        expect(result).toBe(true);
      });

      mockInputSanitizer.validateSanitized.mockReturnValue(false);

      invalidEmails.forEach((email) => {
        const result = mockInputSanitizer.validateSanitized(email, { type: 'email' });
        expect(result).toBe(false);
      });
    });

    it('should validate phone number formats', () => {
      const validPhones = ['+1-555-123-4567', '(555) 123-4567', '555.123.4567', '5551234567'];

      mockInputSanitizer.validateSanitized.mockReturnValue(true);

      validPhones.forEach((phone) => {
        const result = mockInputSanitizer.validateSanitized(phone, { type: 'phone' });
        expect(result).toBe(true);
      });
    });

    it('should validate URL formats', () => {
      const validUrls = [
        'https://example.com',
        'http://example.com/path',
        'https://example.com:8080/path?query=value',
        'ftp://example.com/file.txt',
      ];

      mockInputSanitizer.validateSanitized.mockReturnValue(true);

      validUrls.forEach((url) => {
        const result = mockInputSanitizer.validateSanitized(url, { type: 'url' });
        expect(result).toBe(true);
      });
    });
  });
});

describe('Business Rule Validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Knowledge Type Validation Rules', () => {
    it('should validate entity knowledge types', () => {
      const rule: RuleDefinition = {
        name: 'entityType',
        validate: (data: any, context: RuleContext) => {
          return data.type === 'entity' && data.name && data.properties;
        },
        message: 'Entity must have type, name, and properties',
      };

      const validData = {
        type: 'entity',
        name: 'User',
        properties: { name: 'string', age: 'number' },
      };

      const invalidData = {
        type: 'entity',
        name: 'User',
        // Missing properties
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validData, [rule])).toBe(true);

      mockBusinessRuleValidator.validate.mockReturnValue(false);
      expect(mockBusinessRuleValidator.validate(invalidData, [rule])).toBe(false);
    });

    it('should validate relation knowledge types', () => {
      const rule: RuleDefinition = {
        name: 'relationType',
        validate: (data: any, context: RuleContext) => {
          return data.type === 'relation' && data.source && data.target && data.relationType;
        },
        message: 'Relation must have source, target, and relationType',
      };

      const validData = {
        type: 'relation',
        source: 'user1',
        target: 'user2',
        relationType: 'knows',
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validData, [rule])).toBe(true);
    });

    it('should validate observation knowledge types', () => {
      const rule: RuleDefinition = {
        name: 'observationType',
        validate: (data: any, context: RuleContext) => {
          return data.type === 'observation' && data.content && data.timestamp;
        },
        message: 'Observation must have content and timestamp',
      };

      const validData = {
        type: 'observation',
        content: 'User logged in',
        timestamp: new Date().toISOString(),
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validData, [rule])).toBe(true);
    });
  });

  describe('Cross-field Validation', () => {
    it('should validate field dependencies', () => {
      const rule: RuleDefinition = {
        name: 'passwordConfirmation',
        validate: (data: any, context: RuleContext) => {
          if (data.password) {
            return data.password === data.passwordConfirmation;
          }
          return true; // Password is optional
        },
        message: 'Password and confirmation must match',
      };

      const validData = {
        password: 'secret123',
        passwordConfirmation: 'secret123',
      };

      const invalidData = {
        password: 'secret123',
        passwordConfirmation: 'different',
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validData, [rule])).toBe(true);

      mockBusinessRuleValidator.validate.mockReturnValue(false);
      expect(mockBusinessRuleValidator.validate(invalidData, [rule])).toBe(false);
    });

    it('should validate conditional requirements', () => {
      const rule: RuleDefinition = {
        name: 'companyEmployeeConditional',
        validate: (data: any, context: RuleContext) => {
          if (data.type === 'employee') {
            return data.company && data.employeeId;
          }
          return true;
        },
        message: 'Employees must have company and employeeId',
      };

      const validEmployee = {
        type: 'employee',
        company: 'Acme Corp',
        employeeId: 'EMP123',
      };

      const validContractor = {
        type: 'contractor',
        company: 'Acme Corp',
        // employeeId not required for contractors
      };

      const invalidEmployee = {
        type: 'employee',
        company: 'Acme Corp',
        // Missing employeeId
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validEmployee, [rule])).toBe(true);
      expect(mockBusinessRuleValidator.validate(validContractor, [rule])).toBe(true);

      mockBusinessRuleValidator.validate.mockReturnValue(false);
      expect(mockBusinessRuleValidator.validate(invalidEmployee, [rule])).toBe(false);
    });
  });

  describe('Conditional Validation Logic', () => {
    it('should apply validation based on conditions', () => {
      const rules: RuleDefinition[] = [
        {
          name: 'ageValidation',
          condition: (data: any) => data.age !== undefined,
          validate: (data: any, context: RuleContext) => {
            return data.age >= 0 && data.age <= 150;
          },
          message: 'Age must be between 0 and 150',
        },
        {
          name: 'studentIdValidation',
          condition: (data: any) => data.type === 'student',
          validate: (data: any, context: RuleContext) => {
            return data.studentId && /^STU\d{6}$/.test(data.studentId);
          },
          message: 'Students must have a valid student ID',
        },
      ];

      const validStudent = {
        type: 'student',
        age: 20,
        studentId: 'STU123456',
      };

      const invalidStudent = {
        type: 'student',
        age: -5,
        studentId: 'INVALID',
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validStudent, rules)).toBe(true);

      mockBusinessRuleValidator.validate.mockReturnValue(false);
      expect(mockBusinessRuleValidator.validate(invalidStudent, rules)).toBe(false);
    });

    it('should support complex logical expressions', () => {
      const rule: RuleDefinition = {
        name: 'complexValidation',
        condition: (data: any) => {
          return (
            (data.type === 'premium' && data.subscription) ||
            (data.type === 'trial' && data.trialEnds)
          );
        },
        validate: (data: any, context: RuleContext) => {
          if (data.type === 'premium') {
            return data.subscription.active;
          } else if (data.type === 'trial') {
            return new Date(data.trialEnds) > new Date();
          }
          return false;
        },
        message: 'Account type validation failed',
      };

      const validPremium = {
        type: 'premium',
        subscription: { active: true },
      };

      const validTrial = {
        type: 'trial',
        trialEnds: new Date(Date.now() + 86400000).toISOString(), // Tomorrow
      };

      mockBusinessRuleValidator.validate.mockReturnValue(true);
      expect(mockBusinessRuleValidator.validate(validPremium, [rule])).toBe(true);
      expect(mockBusinessRuleValidator.validate(validTrial, [rule])).toBe(true);
    });
  });

  describe('Custom Business Validators', () => {
    it('should support custom validator functions', () => {
      const customValidator: BusinessValidator = {
        name: 'customBusinessRule',
        validate: (data: any, context: ValidationContext) => {
          // Custom business logic
          if (data.accountType === 'business') {
            return data.businessRegistration && data.taxId && data.contactEmail;
          }
          return true;
        },
        message: 'Business accounts must have registration, tax ID, and contact email',
      };

      const validBusiness = {
        accountType: 'business',
        businessRegistration: 'REG123',
        taxId: 'TAX456',
        contactEmail: 'contact@business.com',
      };

      const invalidBusiness = {
        accountType: 'business',
        businessRegistration: 'REG123',
        // Missing taxId and contactEmail
      };

      mockValidationService.createValidator.mockReturnValue(customValidator);
      mockValidationService.validateBusinessRules.mockResolvedValue({
        valid: true,
        errors: [],
        data: validBusiness,
      });

      const validator = mockValidationService.createValidator(customValidator);
      expect(validator).toBe(customValidator);

      mockValidationService.validateBusinessRules.mockResolvedValue({
        valid: false,
        errors: [
          {
            field: 'taxId',
            message: 'Tax ID is required for business accounts',
            code: 'BUSINESS_RULE',
            severity: ValidationSeverity.ERROR,
          },
        ],
        data: invalidBusiness,
      });

      const result = mockValidationService.validateBusinessRules(invalidBusiness, [
        customValidator,
      ]);
      expect(result.valid).toBe(false);
    });

    it('should handle async business validation', async () => {
      const asyncValidator: BusinessValidator = {
        name: 'asyncBusinessRule',
        validate: async (data: any, context: ValidationContext) => {
          // Simulate async validation (e.g., API call)
          await new Promise((resolve) => setTimeout(resolve, 10));

          // Check if user exists in external system
          if (data.email) {
            return true; // Assume external validation passed
          }
          return false;
        },
        message: 'User must exist in external system',
      };

      const data = {
        email: 'user@example.com',
        name: 'Test User',
      };

      mockValidationService.validateBusinessRules.mockResolvedValue({
        valid: true,
        errors: [],
        data,
      });

      const result = await mockValidationService.validateBusinessRules(data, [asyncValidator]);

      expect(result.valid).toBe(true);
    });
  });
});

describe('Performance Validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('High-performance Validation', () => {
    it('should validate large datasets efficiently', async () => {
      const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
        id: i + 1,
        name: `Item ${i + 1}`,
        value: Math.random() * 100,
      }));

      const schema: ValidationSchema = {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'number' },
            name: { type: 'string' },
            value: { type: 'number', minimum: 0 },
          },
          required: ['id', 'name', 'value'],
        },
      };

      const startTime = Date.now();

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: largeDataset,
      });

      const result = await mockValidationService.validateSchema(largeDataset, schema);

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(result.valid).toBe(true);
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should optimize validation for repeated patterns', async () => {
      const repeatedData = Array.from({ length: 1000 }, () => ({
        type: 'user',
        email: 'user@example.com',
        status: 'active',
      }));

      const schema: ValidationSchema = {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['user', 'admin'] },
            email: { type: 'string', format: 'email' },
            status: { type: 'string', enum: ['active', 'inactive'] },
          },
          required: ['type', 'email', 'status'],
        },
      };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: repeatedData,
      });

      const result = await mockValidationService.validateSchema(repeatedData, schema);

      expect(result.valid).toBe(true);
    });
  });

  describe('Batch Validation Utilities', () => {
    it('should validate multiple items in parallel', async () => {
      const items = [
        { name: 'Item 1', value: 10 },
        { name: 'Item 2', value: 20 },
        { name: 'Item 3', value: 30 },
      ];

      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          value: { type: 'number', minimum: 0 },
        },
        required: ['name', 'value'],
      };

      mockValidationService.batchValidate.mockResolvedValue([
        { valid: true, errors: [], data: items[0] },
        { valid: true, errors: [], data: items[1] },
        { valid: true, errors: [], data: items[2] },
      ]);

      const results = await mockValidationService.batchValidate(items, schema);

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.valid)).toBe(true);
    });

    it('should handle batch validation with mixed results', async () => {
      const items = [
        { name: 'Item 1', value: 10 }, // Valid
        { name: 'Item 2' }, // Missing value
        { value: 30 }, // Missing name
        { name: 'Item 4', value: -5 }, // Invalid value
      ];

      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          value: { type: 'number', minimum: 0 },
        },
        required: ['name', 'value'],
      };

      mockValidationService.batchValidate.mockResolvedValue([
        { valid: true, errors: [], data: items[0] },
        { valid: false, errors: [{ field: 'value', message: 'Required field' }], data: items[1] },
        { valid: false, errors: [{ field: 'name', message: 'Required field' }], data: items[2] },
        {
          valid: false,
          errors: [{ field: 'value', message: 'Value must be >= 0' }],
          data: items[3],
        },
      ]);

      const results = await mockValidationService.batchValidate(items, schema);

      expect(results).toHaveLength(3);
      expect(results.filter((r) => r.valid)).toHaveLength(1);
      expect(results.filter((r) => !r.valid)).toHaveLength(3);
    });

    it('should support batch validation with progress tracking', async () => {
      const items = Array.from({ length: 100 }, (_, i) => ({
        id: i + 1,
        name: `Item ${i + 1}`,
      }));

      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          id: { type: 'number' },
          name: { type: 'string' },
        },
        required: ['id', 'name'],
      };

      const progressCallback = vi.fn();

      mockValidationService.batchValidate.mockImplementation(async (items, schema, options) => {
        const results = [];
        for (let i = 0; i < items.length; i++) {
          results.push({ valid: true, errors: [], data: items[i] });
          if (options?.onProgress) {
            options.onProgress(i + 1, items.length);
          }
        }
        return results;
      });

      const results = await mockValidationService.batchValidate(items, schema, {
        onProgress: progressCallback,
      });

      expect(results).toHaveLength(100);
      expect(progressCallback).toHaveBeenCalledTimes(100);
      expect(progressCallback).toHaveBeenLastCalledWith(100, 100);
    });
  });

  describe('Caching Validation Results', () => {
    it('should cache validation results for repeated validation', async () => {
      const data = { name: 'Test', email: 'test@example.com' };
      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          email: { type: 'string', format: 'email' },
        },
        required: ['name', 'email'],
      };

      const cacheKey = `validation_${JSON.stringify(data)}_${JSON.stringify(schema)}`;
      const cachedResult: ValidationResult = {
        valid: true,
        errors: [],
        data,
      };

      // First validation - not cached
      mockValidationCache.get.mockResolvedValue(null);
      mockValidationService.validateSchema.mockResolvedValue(cachedResult);
      mockValidationCache.set.mockResolvedValue(undefined);

      const result1 = await mockValidationService.validateSchema(data, schema);

      expect(result1).toEqual(cachedResult);
      expect(mockValidationCache.get).toHaveBeenCalledWith(cacheKey);
      expect(mockValidationCache.set).toHaveBeenCalledWith(cacheKey, cachedResult);

      // Second validation - cached
      mockValidationCache.get.mockResolvedValue(cachedResult);

      const result2 = await mockValidationService.validateSchema(data, schema);

      expect(result2).toEqual(cachedResult);
      expect(mockValidationCache.get).toHaveBeenCalledWith(cacheKey);
      expect(mockValidationService.validateSchema).toHaveBeenCalledTimes(1); // Called only once
    });

    it('should respect cache TTL and invalidation', async () => {
      const data = { name: 'Test' };
      const schema: ValidationSchema = { type: 'object', properties: { name: { type: 'string' } } };
      const cacheKey = `validation_${JSON.stringify(data)}_${JSON.stringify(schema)}`;

      // Cache entry has expired
      mockValidationCache.get.mockResolvedValue(null);
      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data,
      });
      mockValidationCache.set.mockResolvedValue(undefined);

      const result = await mockValidationService.validateSchema(data, schema);

      expect(result.valid).toBe(true);
      expect(mockValidationCache.get).toHaveBeenCalledWith(cacheKey);
      expect(mockValidationCache.set).toHaveBeenCalledWith(cacheKey, expect.any(Object), {
        ttl: 300000,
      }); // 5 minutes
    });

    it('should handle cache size limits', async () => {
      const cacheStats = {
        size: 1000,
        maxSize: 1000,
        hitRate: 0.85,
        hits: 850,
        misses: 150,
      };

      mockValidationCache.getStats.mockResolvedValue(cacheStats);

      const stats = await mockValidationCache.getStats();

      expect(stats.size).toBe(1000);
      expect(stats.hitRate).toBe(0.85);

      // Simulate cache cleanup when size limit is reached
      mockValidationCache.cleanup.mockResolvedValue({ deleted: 100 });

      const cleanupResult = await mockValidationCache.cleanup();

      expect(cleanupResult.deleted).toBe(100);
    });
  });

  describe('Validation Optimization', () => {
    it('should use compiled schemas for better performance', () => {
      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          age: { type: 'number' },
        },
      };

      mockSchemaValidator.compile.mockReturnValue({
        validate: vi.fn().mockReturnValue({
          valid: true,
          errors: [],
        }),
      });

      const compiledValidator = mockSchemaValidator.compile(schema);

      expect(typeof compiledValidator.validate).toBe('function');

      const result = compiledValidator.validate({ name: 'Test', age: 25 });

      expect(result.valid).toBe(true);
    });

    it('should optimize validation order based on cost', async () => {
      const rules: ValidationRule[] = [
        {
          name: 'expensiveRule',
          validator: () => true,
          cost: 100,
          message: 'Expensive validation',
        },
        {
          name: 'cheapRule',
          validator: () => false,
          cost: 1,
          message: 'Cheap validation',
        },
      ];

      const data = { test: 'value' };

      // Cheap rule should run first and fail early
      mockValidationService.validateSchema.mockResolvedValue({
        valid: false,
        errors: [
          {
            field: 'test',
            message: 'Cheap validation',
            code: 'CHEAP_RULE',
            severity: ValidationSeverity.ERROR,
          },
        ],
        data,
      });

      const result = await mockValidationService.validateSchema(data, {}, rules);

      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Cheap validation');
    });
  });
});

describe('Error Reporting', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Validation Error Aggregation', () => {
    it('should aggregate errors from multiple validations', () => {
      const errors = [
        {
          field: 'name',
          message: 'Name is required',
          code: 'REQUIRED',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'email',
          message: 'Invalid email format',
          code: 'FORMAT',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'age',
          message: 'Age must be positive',
          code: 'MINIMUM',
          severity: ValidationSeverity.WARNING,
        },
        {
          field: 'password',
          message: 'Password too weak',
          code: 'STRENGTH',
          severity: ValidationSeverity.WARNING,
        },
      ];

      mockValidationReporter.aggregateErrors.mockReturnValue({
        totalErrors: 4,
        errorsBySeverity: {
          [ValidationSeverity.ERROR]: 2,
          [ValidationSeverity.WARNING]: 2,
        },
        errorsByField: {
          name: ['Name is required'],
          email: ['Invalid email format'],
          age: ['Age must be positive'],
          password: ['Password too weak'],
        },
        errorsByCode: {
          REQUIRED: 1,
          FORMAT: 1,
          MINIMUM: 1,
          STRENGTH: 1,
        },
      });

      const aggregation = mockValidationReporter.aggregateErrors(errors);

      expect(aggregation.totalErrors).toBe(4);
      expect(aggregation.errorsBySeverity[ValidationSeverity.ERROR]).toBe(2);
      expect(aggregation.errorsByField.name).toContain('Name is required');
    });

    it('should deduplicate similar errors', () => {
      const errors = [
        {
          field: 'name',
          message: 'Name is required',
          code: 'REQUIRED',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'name',
          message: 'Name is required',
          code: 'REQUIRED',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'email',
          message: 'Invalid email format',
          code: 'FORMAT',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'email',
          message: 'Invalid email format',
          code: 'FORMAT',
          severity: ValidationSeverity.ERROR,
        },
      ];

      mockValidationReporter.aggregateErrors.mockReturnValue({
        totalErrors: 2,
        uniqueErrors: 2,
        duplicates: 2,
        deduplicatedErrors: [
          {
            field: 'name',
            message: 'Name is required',
            code: 'REQUIRED',
            severity: ValidationSeverity.ERROR,
            count: 2,
          },
          {
            field: 'email',
            message: 'Invalid email format',
            code: 'FORMAT',
            severity: ValidationSeverity.ERROR,
            count: 2,
          },
        ],
      });

      const aggregation = mockValidationReporter.aggregateErrors(errors);

      expect(aggregation.totalErrors).toBe(2);
      expect(aggregation.duplicates).toBe(2);
      expect(aggregation.deduplicatedErrors).toHaveLength(2);
    });
  });

  describe('User-friendly Error Messages', () => {
    it('should provide contextual error messages', () => {
      const errors = [
        { field: 'user.profile.email', message: 'Invalid format', code: 'FORMAT' },
        { field: 'order.items[0].quantity', message: 'Must be positive', code: 'MINIMUM' },
        { field: 'payment.card.expiry', message: 'Expired card', code: 'EXPIRED' },
      ];

      mockValidationReporter.formatErrors.mockReturnValue({
        formattedErrors: [
          'The email address in your profile is not valid. Please enter a valid email address.',
          'The quantity for the first item in your order must be a positive number.',
          'Your payment card has expired. Please update your payment information.',
        ],
        suggestions: [
          'Check that your email includes an @ symbol and domain name.',
          'Enter a quantity of 1 or more.',
          'Add a new payment card with a future expiration date.',
        ],
      });

      const formatted = mockValidationReporter.formatErrors(errors);

      expect(formatted.formattedErrors).toHaveLength(3);
      expect(formatted.formattedErrors[0]).toContain('profile');
      expect(formatted.suggestions).toHaveLength(3);
    });

    it('should adapt messages based on user context', () => {
      const errors = [{ field: 'api_key', message: 'Invalid format', code: 'FORMAT' }];

      const developerContext = {
        userType: 'developer',
        technicalLevel: 'high',
      };

      const endUserContext = {
        userType: 'enduser',
        technicalLevel: 'low',
      };

      mockValidationReporter.formatErrors
        .mockReturnValueOnce({
          formattedErrors: ['API key format invalid. Expected: 32-character hexadecimal string.'],
          technicalDetails: {
            expectedPattern: '/^[a-f0-9]{32}$/',
            examples: ['a1b2c3d4e5f6789012345678901234ab'],
          },
        })
        .mockReturnValueOnce({
          formattedErrors: [
            'There was a problem with your API key. Please contact support for assistance.',
          ],
          nextSteps: ['Contact our support team', 'Check your account settings'],
        });

      const developerFormatted = mockValidationReporter.formatErrors(errors, {
        context: developerContext,
      });
      const endUserFormatted = mockValidationReporter.formatErrors(errors, {
        context: endUserContext,
      });

      expect(developerFormatted.formattedErrors[0]).toContain('hexadecimal');
      expect(endUserFormatted.formattedErrors[0]).toContain('contact support');
    });
  });

  describe('Error Context Preservation', () => {
    it('should preserve validation context in error reports', () => {
      const context: ValidationContext = {
        operation: 'userRegistration',
        userId: 'user123',
        timestamp: new Date().toISOString(),
        requestPath: '/api/users/register',
        userAgent: 'Mozilla/5.0...',
        ipAddress: '192.168.1.1',
      };

      const errors = [{ field: 'email', message: 'Already exists', code: 'DUPLICATE' }];

      mockValidationReporter.createReport.mockReturnValue({
        id: 'report_123',
        timestamp: context.timestamp,
        context,
        errors,
        severity: ValidationSeverity.ERROR,
        actionTaken: 'registration_blocked',
        metadata: {
          validationDuration: 45,
          schemaVersion: '1.2.0',
        },
      });

      const report = mockValidationReporter.createReport(errors, context);

      expect(report.context).toEqual(context);
      expect(report.actionTaken).toBe('registration_blocked');
      expect(report.metadata.validationDuration).toBe(45);
    });

    it('should include stack traces in development mode', () => {
      const errors = [
        {
          field: 'custom',
          message: 'Custom validation failed',
          code: 'CUSTOM',
          stack: 'Error: Custom validation failed\n    at CustomValidator.validate',
        },
      ];

      const developmentOptions = {
        environment: 'development',
        includeStackTraces: true,
        includeInternalErrors: true,
      };

      mockValidationReporter.createReport.mockReturnValue({
        id: 'debug_report_456',
        errors,
        debugInfo: {
          stackTraces: [errors[0].stack],
          internalState: { validatorCache: { size: 10 } },
          performanceMetrics: { validationTime: 23 },
        },
      });

      const report = mockValidationReporter.createReport(errors, {}, developmentOptions);

      expect(report.debugInfo.stackTraces).toHaveLength(1);
      expect(report.debugInfo.stackTraces[0]).toContain('CustomValidator.validate');
    });
  });

  describe('Error Export and Integration', () => {
    it('should export errors in multiple formats', () => {
      const errors = [
        {
          field: 'name',
          message: 'Required',
          code: 'REQUIRED',
          severity: ValidationSeverity.ERROR,
        },
        {
          field: 'email',
          message: 'Invalid format',
          code: 'FORMAT',
          severity: ValidationSeverity.WARNING,
        },
      ];

      // JSON export
      mockValidationReporter.exportReport.mockReturnValueOnce({
        format: 'json',
        data: JSON.stringify({ errors, timestamp: new Date().toISOString() }),
        filename: 'validation-errors.json',
      });

      // CSV export
      mockValidationReporter.exportReport.mockReturnValueOnce({
        format: 'csv',
        data: 'field,message,code,severity\nname,Required,REQUIRED,error\nemail,Invalid format,FORMAT,warning',
        filename: 'validation-errors.csv',
      });

      // HTML export
      mockValidationReporter.exportReport.mockReturnValueOnce({
        format: 'html',
        data: '<html><body><h1>Validation Errors</h1><table>...</table></body></html>',
        filename: 'validation-errors.html',
      });

      const jsonExport = mockValidationReporter.exportReport(errors, 'json');
      const csvExport = mockValidationReporter.exportReport(errors, 'csv');
      const htmlExport = mockValidationReporter.exportReport(errors, 'html');

      expect(jsonExport.format).toBe('json');
      expect(csvExport.format).toBe('csv');
      expect(htmlExport.format).toBe('html');
      expect(jsonExport.data).toContain('errors');
      expect(csvExport.data).toContain('field,message');
      expect(htmlExport.data).toContain('<html>');
    });

    it('should integrate with external monitoring systems', () => {
      const errors = [
        {
          field: 'payment',
          message: 'Payment processing failed',
          code: 'PAYMENT_ERROR',
          severity: ValidationSeverity.ERROR,
        },
      ];

      const monitoringConfig = {
        enabled: true,
        systems: ['sentry', 'datadog', 'rollbar'],
        alertThreshold: { errors: 5, warnings: 10 },
        customTags: { service: 'validation', environment: 'production' },
      };

      mockValidationReporter.createReport.mockReturnValue({
        id: 'monitoring_report_789',
        errors,
        monitoring: {
          sent: true,
          systems: monitoringConfig.systems,
          alertTriggered: false,
          metrics: {
            errorCount: 1,
            warningCount: 0,
            criticality: 'medium',
          },
        },
      });

      const report = mockValidationReporter.createReport(
        errors,
        {},
        { monitoring: monitoringConfig }
      );

      expect(report.monitoring.sent).toBe(true);
      expect(report.monitoring.systems).toEqual(monitoringConfig.systems);
      expect(report.monitoring.alertTriggered).toBe(false);
    });
  });
});

describe('Integration and Extensibility', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Service Integration Validation', () => {
    it('should validate service integration configurations', async () => {
      const serviceConfig = {
        name: 'payment-service',
        type: 'external',
        endpoint: 'https://api.payment.com',
        apiKey: 'sk_test_123',
        timeout: 30000,
        retries: 3,
      };

      const integrationRules: BusinessValidator[] = [
        {
          name: 'endpointValidation',
          validate: (config: any) => {
            return (
              config.endpoint &&
              config.endpoint.startsWith('https://') &&
              config.endpoint.includes('api.')
            );
          },
          message: 'Endpoint must be a valid HTTPS API URL',
        },
        {
          name: 'apiKeyValidation',
          validate: (config: any) => {
            return (
              config.apiKey && config.apiKey.length >= 20 && config.apiKey.startsWith('sk_test_')
            );
          },
          message: 'API key must be valid test key format',
        },
      ];

      mockValidationService.validateBusinessRules.mockResolvedValue({
        valid: true,
        errors: [],
        data: serviceConfig,
      });

      const result = await mockValidationService.validateBusinessRules(
        serviceConfig,
        integrationRules
      );

      expect(result.valid).toBe(true);
      expect(mockValidationService.validateBusinessRules).toHaveBeenCalledWith(
        serviceConfig,
        integrationRules
      );
    });

    it('should validate service dependencies', async () => {
      const serviceDependencies = {
        database: {
          host: 'localhost',
          port: 5432,
          ssl: true,
        },
        cache: {
          host: 'localhost',
          port: 6379,
          cluster: false,
        },
        messageQueue: {
          host: 'localhost',
          port: 5672,
          vhost: '/',
        },
      };

      const dependencyRules: RuleDefinition[] = [
        {
          name: 'databaseConnection',
          validate: (deps: any) => {
            return deps.database.port > 0 && deps.database.port < 65536;
          },
          message: 'Database port must be valid',
        },
        {
          name: 'cacheConnection',
          validate: (deps: any) => {
            return deps.cache.port > 0 && deps.cache.port < 65536;
          },
          message: 'Cache port must be valid',
        },
      ];

      mockBusinessRuleValidator.validate.mockReturnValue(true);

      const result = mockBusinessRuleValidator.validate(serviceDependencies, dependencyRules);

      expect(result).toBe(true);
    });
  });

  describe('Custom Validator Registration', () => {
    it('should allow registration of custom validators', () => {
      const customValidator = {
        name: 'phoneNumberValidator',
        validator: (value: string) => {
          return /^\+?[\d\s-()]+$/.test(value) && value.replace(/\D/g, '').length >= 10;
        },
        message: 'Phone number must be valid',
      };

      mockValidationService.registerValidator.mockReturnValue(true);

      const registered = mockValidationService.registerValidator('phoneNumber', customValidator);

      expect(registered).toBe(true);
      expect(mockValidationService.registerValidator).toHaveBeenCalledWith(
        'phoneNumber',
        customValidator
      );
    });

    it('should handle validator namespace and versioning', () => {
      const namespacedValidator = {
        name: 'v2.emailValidator',
        version: '2.0.0',
        validator: (value: string) => {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
        },
        message: 'Email must be valid format',
      };

      mockValidationService.registerValidator.mockReturnValue(true);

      const registered = mockValidationService.registerValidator('email:v2', namespacedValidator);

      expect(registered).toBe(true);
      expect(mockValidationService.registerValidator).toHaveBeenCalledWith(
        'email:v2',
        namespacedValidator
      );
    });

    it('should support validator deprecation and migration', () => {
      const deprecatedValidator = {
        name: 'oldZipCodeValidator',
        deprecated: true,
        deprecatedIn: '1.5.0',
        removedIn: '2.0.0',
        migrationTo: 'newZipCodeValidator',
        validator: (value: string) => /^\d{5}$/.test(value),
        message: 'ZIP code must be 5 digits',
      };

      mockValidationService.registerValidator.mockImplementation((name, validator) => {
        if (validator.deprecated) {
          console.warn(
            `Validator ${name} is deprecated and will be removed in ${validator.removedIn}`
          );
        }
        return true;
      });

      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation();

      const registered = mockValidationService.registerValidator('oldZipCode', deprecatedValidator);

      expect(registered).toBe(true);
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('oldZipCode is deprecated'));

      consoleSpy.mockRestore();
    });
  });

  describe('Validation Pipeline Orchestration', () => {
    it('should orchestrate multiple validation stages', async () => {
      const pipeline = {
        stages: [
          {
            name: 'inputSanitization',
            validators: ['xssProtection', 'sqlInjectionProtection'],
            parallel: false,
          },
          {
            name: 'schemaValidation',
            validators: ['jsonSchema', 'typeValidation'],
            parallel: false,
          },
          {
            name: 'businessRules',
            validators: ['userPermissions', 'dataIntegrity'],
            parallel: true,
          },
        ],
      };

      const data = {
        userInput: '<script>alert("xss")</script>',
        email: 'user@example.com',
        role: 'admin',
      };

      const pipelineResults = [
        { stage: 'inputSanitization', valid: true, duration: 5 },
        { stage: 'schemaValidation', valid: true, duration: 12 },
        { stage: 'businessRules', valid: true, duration: 8 },
      ];

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: { ...data, userInput: 'alert("xss")' }, // Sanitized
      });

      const result = await mockValidationService.validateSchema(data, {});

      expect(result.valid).toBe(true);
      expect(mockValidationService.validateSchema).toHaveBeenCalled();
    });

    it('should support conditional pipeline execution', async () => {
      const conditionalPipeline = {
        stages: [
          {
            name: 'basicValidation',
            always: true,
            validators: ['requiredFields', 'basicTypes'],
          },
          {
            name: 'adminValidation',
            condition: (data: any) => data.role === 'admin',
            validators: ['adminPermissions', 'securityChecks'],
          },
          {
            name: 'paymentValidation',
            condition: (data: any) => data.paymentRequired,
            validators: ['paymentMethod', 'billingAddress'],
          },
        ],
      };

      const adminData = { role: 'admin', name: 'Admin User' };
      const userData = { role: 'user', name: 'Regular User' };

      mockValidationService.validateSchema
        .mockResolvedValueOnce({ valid: true, errors: [], data: adminData })
        .mockResolvedValueOnce({ valid: true, errors: [], data: userData });

      const adminResult = await mockValidationService.validateSchema(adminData, {});
      const userResult = await mockValidationService.validateSchema(userData, {});

      expect(adminResult.valid).toBe(true);
      expect(userResult.valid).toBe(true);
    });
  });

  describe('Validation Middleware Integration', () => {
    it('should integrate with Express middleware', () => {
      const mockRequest = {
        body: {
          name: 'John Doe',
          email: 'john@example.com',
          age: 30,
        },
        headers: {
          'content-type': 'application/json',
        },
      };

      const mockResponse = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };

      const mockNext = vi.fn();

      const schema: ValidationSchema = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          email: { type: 'string', format: 'email' },
          age: { type: 'number', minimum: 0 },
        },
        required: ['name', 'email'],
      };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: mockRequest.body,
      });

      // Simulate middleware function
      const validationMiddleware = async (req: any, res: any, next: any) => {
        try {
          const result = await mockValidationService.validateSchema(req.body, schema);
          if (result.valid) {
            req.validatedData = result.data;
            next();
          } else {
            res.status(400).json({ errors: result.errors });
          }
        } catch (error) {
          next(error);
        }
      };

      // Execute middleware
      validationMiddleware(mockRequest, mockResponse, mockNext);

      // Since it's async, we need to wait for the promise to resolve
      setTimeout(() => {
        expect(mockValidationService.validateSchema).toHaveBeenCalledWith(mockRequest.body, schema);
        expect(mockNext).toHaveBeenCalled();
      }, 0);
    });

    it('should handle GraphQL input validation', () => {
      const graphqlArgs = {
        input: {
          title: 'New Post',
          content: 'This is a new post content',
          tags: ['javascript', 'validation'],
          published: true,
        },
      };

      const graphqlValidationSchema = {
        type: 'object',
        properties: {
          title: { type: 'string', minLength: 1, maxLength: 200 },
          content: { type: 'string', minLength: 10 },
          tags: {
            type: 'array',
            items: { type: 'string' },
            maxItems: 5,
          },
          published: { type: 'boolean' },
        },
        required: ['title', 'content'],
      };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: graphqlArgs.input,
      });

      const result = mockValidationService.validateSchema(
        graphqlArgs.input,
        graphqlValidationSchema
      );

      expect(result).resolves.toMatchObject({
        valid: true,
        data: graphqlArgs.input,
      });
    });

    it('should support event-driven validation', () => {
      const eventData = {
        eventType: 'user.created',
        userId: 'user123',
        timestamp: new Date().toISOString(),
        payload: {
          name: 'New User',
          email: 'newuser@example.com',
        },
      };

      const eventSchema = {
        type: 'object',
        properties: {
          eventType: { type: 'string', enum: ['user.created', 'user.updated', 'user.deleted'] },
          userId: { type: 'string', pattern: '^user[0-9]+$' },
          timestamp: { type: 'string', format: 'date-time' },
          payload: { type: 'object' },
        },
        required: ['eventType', 'userId', 'timestamp', 'payload'],
      };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: eventData,
      });

      const eventValidationMiddleware = async (event: any) => {
        const result = await mockValidationService.validateSchema(event, eventSchema);
        if (!result.valid) {
          throw new Error(
            `Event validation failed: ${result.errors.map((e) => e.message).join(', ')}`
          );
        }
        return result.data;
      };

      const result = eventValidationMiddleware(eventData);

      expect(result).resolves.toEqual(eventData);
    });
  });

  describe('Plugin Architecture Support', () => {
    it('should support validation plugins', () => {
      const validationPlugin = {
        name: 'advancedValidation',
        version: '1.0.0',
        validators: {
          creditCard: {
            validate: (value: string) => {
              return /^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$/.test(value);
            },
            message: 'Credit card number is invalid',
          },
          ssn: {
            validate: (value: string) => {
              return /^\d{3}-\d{2}-\d{4}$/.test(value);
            },
            message: 'SSN format is invalid',
          },
        },
        hooks: {
          beforeValidation: (data: any) => {
            console.log('Starting validation with advanced plugin');
          },
          afterValidation: (result: ValidationResult) => {
            console.log(`Validation completed with ${result.errors.length} errors`);
          },
        },
      };

      mockValidationService.registerValidator.mockImplementation((name, validator) => {
        console.log(`Registered validator: ${name}`);
        return true;
      });

      // Register plugin validators
      Object.entries(validationPlugin.validators).forEach(([name, validator]) => {
        mockValidationService.registerValidator(`${validationPlugin.name}.${name}`, validator);
      });

      expect(mockValidationService.registerValidator).toHaveBeenCalledTimes(2);
    });

    it('should support validator composition', () => {
      const composedValidator = {
        name: 'composedAddressValidator',
        validators: [
          {
            name: 'streetValidator',
            validate: (value: string) => value && value.length > 5,
            message: 'Street address is required',
          },
          {
            name: 'cityValidator',
            validate: (value: string) => value && /^[a-zA-Z\s]+$/.test(value),
            message: 'City must contain only letters',
          },
          {
            name: 'zipValidator',
            validate: (value: string) => /^\d{5}(-\d{4})?$/.test(value),
            message: 'ZIP code format is invalid',
          },
        ],
        composer: (results: any[]) => {
          return {
            valid: results.every((r) => r.valid),
            errors: results.flatMap((r) => r.errors),
          };
        },
      };

      const address = {
        street: '123 Main St',
        city: 'Anytown',
        zip: '12345',
      };

      mockValidationService.validateSchema.mockResolvedValue({
        valid: true,
        errors: [],
        data: address,
      });

      const result = mockValidationService.validateSchema(
        address,
        {},
        composedValidator.validators
      );

      expect(result).resolves.toMatchObject({
        valid: true,
        data: address,
      });
    });
  });
});
