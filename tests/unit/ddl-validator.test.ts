import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DDLValidator } from '../../src/services/validation/business-validators';
import type { KnowledgeItem } from '../../src/types/core-interfaces';

// Mock the logger to avoid noise in tests
vi.mock('../../src/utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('DDLValidator - P5-T5.1 Business Rules', () => {
  let validator: DDLValidator;

  beforeEach(() => {
    validator = new DDLValidator();
    vi.clearAllMocks();
  });

  describe('DDL Checksum Requirement Rule', () => {
    it('should REJECT DDL without checksum when checksum is required', async () => {
      // Arrange: Create a DDL that requires checksum but doesn't have one
      const ddlWithoutChecksum: KnowledgeItem = {
        id: 'ddl-123',
        kind: 'ddl',
        content: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE);',
        data: {
          title: 'Create users table',
          sql: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE);',
          database: 'production_db',
          migration_id: '001_create_users_table',
          checksum_required: true, // Checksum is required
          // Missing checksum - this should cause validation failure
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(ddlWithoutChecksum);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('DDL requires checksum verification');
    });

    it('should ACCEPT DDL with valid checksum when checksum is required', async () => {
      // Arrange: Create a DDL with proper checksum
      const ddlWithChecksum: KnowledgeItem = {
        id: 'ddl-456',
        kind: 'ddl',
        content: 'ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT NOW();',
        data: {
          title: 'Add created_at column to users table',
          sql: 'ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT NOW();',
          database: 'production_db',
          migration_id: '002_add_created_at_to_users',
          checksum_required: true,
          checksum: 'sha256:abc123def4567890fedcba0987654321abcdef1234567890', // Valid checksum
        },
        metadata: { created_at: '2024-01-20T11:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T11:00:00Z'),
        updated_at: new Date('2024-01-20T11:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(ddlWithChecksum);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT DDL without checksum when checksum is not required', async () => {
      // Arrange: Create a DDL that doesn't require checksum
      const ddlNoChecksumRequired: KnowledgeItem = {
        id: 'ddl-789',
        kind: 'ddl',
        content: "COMMENT ON TABLE users IS 'User accounts table';",
        data: {
          title: 'Add comment to users table',
          sql: "COMMENT ON TABLE users IS 'User accounts table';",
          database: 'production_db',
          migration_id: '003_comment_users_table',
          checksum_required: false, // Checksum not required
          // No checksum provided - should be acceptable
        },
        metadata: { created_at: '2024-01-20T12:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T12:00:00Z'),
        updated_at: new Date('2024-01-20T12:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(ddlNoChecksumRequired);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT DDL with invalid checksum format', async () => {
      // Arrange: Create a DDL with malformed checksum
      const ddlInvalidChecksum: KnowledgeItem = {
        id: 'ddl-999',
        kind: 'ddl',
        content: 'CREATE INDEX idx_users_email ON users(email);',
        data: {
          title: 'Create email index on users table',
          sql: 'CREATE INDEX idx_users_email ON users(email);',
          database: 'production_db',
          migration_id: '004_create_users_email_index',
          checksum_required: true,
          checksum: 'invalid-checksum-format', // Invalid format
        },
        metadata: { created_at: '2024-01-20T13:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T13:00:00Z'),
        updated_at: new Date('2024-01-20T13:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(ddlInvalidChecksum);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Invalid checksum format: must be in format "algorithm:hash"'
      );
    });
  });

  describe('Migration ID Uniqueness Rule', () => {
    it('should REJECT DDL with duplicate migration_id in same scope', async () => {
      // Arrange: Create a DDL with duplicate migration_id (simulating existing check)
      const duplicateMigrationDDL: KnowledgeItem = {
        id: 'ddl-duplicate',
        kind: 'ddl',
        content: 'CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(255));',
        data: {
          title: 'Create products table',
          sql: 'CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(255));',
          database: 'production_db',
          migration_id: '001_create_users_table', // Duplicate migration_id
          checksum_required: true,
          checksum: 'sha256:different7890abcdef1234567890abcdef1234567890',
          duplicate_migration_id_detected: true, // Flag to simulate duplicate detection
          existing_ddl_id: 'ddl-original',
        },
        metadata: { created_at: '2024-01-20T14:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T14:00:00Z'),
        updated_at: new Date('2024-01-20T14:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(duplicateMigrationDDL);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Duplicate migration_id "001_create_users_table" detected in scope "test-project:production_db". Existing DDL ID: ddl-original'
      );
    });

    it('should ACCEPT DDL with unique migration_id in same scope', async () => {
      // Arrange: Create a DDL with unique migration_id
      const uniqueMigrationDDL: KnowledgeItem = {
        id: 'ddl-unique',
        kind: 'ddl',
        content:
          'CREATE TABLE orders (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id));',
        data: {
          title: 'Create orders table',
          sql: 'CREATE TABLE orders (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id));',
          database: 'production_db',
          migration_id: '005_create_orders_table', // Unique migration_id
          checksum_required: true,
          checksum: 'sha256:unique1234567890abcdef1234567890abcdef',
          duplicate_migration_id_detected: false, // No duplicate
        },
        metadata: { created_at: '2024-01-20T15:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T15:00:00Z'),
        updated_at: new Date('2024-01-20T15:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(uniqueMigrationDDL);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT DDL with same migration_id in different database scope', async () => {
      // Arrange: Create a DDL with same migration_id but different database
      const sameIdDifferentDB: KnowledgeItem = {
        id: 'ddl-different-db',
        kind: 'ddl',
        content: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE);',
        data: {
          title: 'Create users table in staging',
          sql: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE);',
          database: 'staging_db', // Different database
          migration_id: '001_create_users_table', // Same migration_id, different scope
          checksum_required: true,
          checksum: 'sha256:staging7890abcdef1234567890abcdef1234567890',
          duplicate_migration_id_detected: false, // Different scope, so not a duplicate
        },
        metadata: { created_at: '2024-01-20T16:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T16:00:00Z'),
        updated_at: new Date('2024-01-20T16:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(sameIdDifferentDB);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT DDL with same migration_id in different project scope', async () => {
      // Arrange: Create a DDL with same migration_id but different project
      const sameIdDifferentProject: KnowledgeItem = {
        id: 'ddl-different-project',
        kind: 'ddl',
        content: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE);',
        data: {
          title: 'Create users table in another project',
          sql: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE);',
          database: 'production_db',
          migration_id: '001_create_users_table', // Same migration_id
          checksum_required: true,
          checksum: 'sha256:anotherproject7890abcdef1234567890abcdef',
          duplicate_migration_id_detected: false, // Different project scope
        },
        metadata: { created_at: '2024-01-20T17:00:00Z' },
        scope: { project: 'different-project' }, // Different project
        created_at: new Date('2024-01-20T17:00:00Z'),
        updated_at: new Date('2024-01-20T17:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(sameIdDifferentProject);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('DDL Safety Rules', () => {
    it('should WARN about destructive migration without backup requirement', async () => {
      // Arrange: Create a destructive DDL without backup requirement
      const destructiveDDL: KnowledgeItem = {
        id: 'ddl-destructive',
        kind: 'ddl',
        content: 'DROP TABLE users;',
        data: {
          title: 'Drop users table',
          sql: 'DROP TABLE users;',
          database: 'production_db',
          migration_id: '999_drop_users_table',
          checksum_required: true,
          checksum: 'sha256:destructive1234567890abcdef1234567890',
          migration_type: 'destructive', // Destructive migration
          backup_required: false, // No backup required - should warn
        },
        metadata: { created_at: '2024-01-20T18:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T18:00:00Z'),
        updated_at: new Date('2024-01-20T18:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(destructiveDDL);

      // Assert: Should pass with warning
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toContain('Destructive migrations should require backup');
    });

    it('should REJECT DDL with rollback requirement but no rollback SQL', async () => {
      // Arrange: Create a DDL that requires rollback but doesn't have rollback SQL
      const ddlWithRollbackRequirement: KnowledgeItem = {
        id: 'ddl-rollback-required',
        kind: 'ddl',
        content: "DELETE FROM users WHERE created_at < '2023-01-01';",
        data: {
          title: 'Delete old user data',
          sql: "DELETE FROM users WHERE created_at < '2023-01-01';",
          database: 'production_db',
          migration_id: '010_delete_old_users',
          checksum_required: true,
          checksum: 'sha256:rollback7890abcdef1234567890abcdef123456',
          rollback_required: true, // Rollback required
          // Missing rollback_sql - this should cause validation failure
        },
        metadata: { created_at: '2024-01-20T19:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T19:00:00Z'),
        updated_at: new Date('2024-01-20T19:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(ddlWithRollbackRequirement);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('DDL requires rollback SQL when rollback is required');
    });

    it('should ACCEPT DDL with proper rollback SQL when rollback is required', async () => {
      // Arrange: Create a DDL with proper rollback SQL
      const ddlWithRollback: KnowledgeItem = {
        id: 'ddl-with-rollback',
        kind: 'ddl',
        content: "UPDATE users SET status = 'inactive' WHERE last_login < '2023-01-01';",
        data: {
          title: 'Deactivate old users',
          sql: "UPDATE users SET status = 'inactive' WHERE last_login < '2023-01-01';",
          database: 'production_db',
          migration_id: '011_deactivate_old_users',
          checksum_required: true,
          checksum: 'sha256:rollback1234567890abcdef1234567890abcdef',
          rollback_required: true,
          rollback_sql: "UPDATE users SET status = 'active' WHERE last_login < '2023-01-01';", // Proper rollback
        },
        metadata: { created_at: '2024-01-20T20:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T20:00:00Z'),
        updated_at: new Date('2024-01-20T20:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(ddlWithRollback);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Basic DDL Validation', () => {
    it('should REJECT DDL without SQL content', async () => {
      const ddlWithoutSQL: KnowledgeItem = {
        id: 'ddl-123',
        kind: 'ddl',
        content: 'DDL content',
        data: {
          title: 'Some DDL',
          database: 'test_db',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(ddlWithoutSQL);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('DDL requires SQL content');
    });

    it('should REJECT DDL without database name', async () => {
      const ddlWithoutDB: KnowledgeItem = {
        id: 'ddl-123',
        kind: 'ddl',
        content: 'DDL content',
        data: {
          title: 'Some DDL',
          sql: 'CREATE TABLE test (id INTEGER);',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(ddlWithoutDB);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('DDL requires database name');
    });
  });
});
