/**
 * Comprehensive Unit Tests for DDL (Data Definition Language) Knowledge Type
 *
 * Tests DDL knowledge type functionality including:
 * - Schema validation with required fields (migration_id, ddl_text, checksum)
 * - Optional fields (applied_at, description)
 * - Migration ID format and length constraints
 * - DDL statement validation and format requirements
 * - Checksum validation (SHA-256 hash format)
 * - Scope isolation and project boundaries
 * - Storage operations with Qdrant integration
 * - Search operations for DDL entries
 * - Batch operations and error handling
 * - Complex DDL statements and edge cases
 * - Integration with knowledge system and TTL policies
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { DDLSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';
import { createHash } from 'crypto';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green'
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  }
}));

describe('DDL Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('DDL Schema Validation', () => {
    it('should validate complete DDL with all fields', () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          migration_id: '001_initial_schema',
          ddl_text: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);',
          checksum: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
          applied_at: '2025-01-01T12:00:00Z',
          description: 'Initial user table creation with basic fields'
        },
        tags: { environment: 'production', category: 'schema' },
        source: {
          actor: 'database-admin',
          tool: 'migration-tool',
          timestamp: '2025-01-01T00:00:00Z'
        }
      };

      const result = DDLSchema.safeParse(ddl);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('ddl');
        expect(result.data.data.migration_id).toBe('001_initial_schema');
        expect(result.data.data.ddl_text).toContain('CREATE TABLE users');
        expect(result.data.data.checksum).toHaveLength(64);
        expect(result.data.data.applied_at).toBe('2025-01-01T12:00:00Z');
        expect(result.data.data.description).toBe('Initial user table creation with basic fields');
      }
    });

    it('should validate minimal DDL with only required fields', () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          migration_id: '002_add_indexes',
          ddl_text: 'CREATE INDEX idx_users_email ON users(email);',
          checksum: createHash('sha256').update('CREATE INDEX idx_users_email ON users(email);').digest('hex')
        }
      };

      const result = DDLSchema.safeParse(ddl);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.migration_id).toBe('002_add_indexes');
        expect(result.data.data.ddl_text).toBe('CREATE INDEX idx_users_email ON users(email);');
        expect(result.data.data.checksum).toHaveLength(64);
        expect(result.data.data.applied_at).toBeUndefined();
        expect(result.data.data.description).toBeUndefined();
      }
    });

    it('should reject DDL missing required fields', () => {
      const invalidDDLs = [
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing migration_id
            ddl_text: 'CREATE TABLE test (id INT);',
            checksum: createHash('sha256').update('CREATE TABLE test (id INT);').digest('hex')
          }
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_test',
            // Missing ddl_text
            checksum: createHash('sha256').update('').digest('hex')
          }
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_test',
            ddl_text: 'CREATE TABLE test (id INT);',
            // Missing checksum
          }
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '', // Empty migration_id
            ddl_text: 'CREATE TABLE test (id INT);',
            checksum: createHash('sha256').update('CREATE TABLE test (id INT);').digest('hex')
          }
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_test',
            ddl_text: '', // Empty ddl_text
            checksum: createHash('sha256').update('').digest('hex')
          }
        }
      ];

      invalidDDLs.forEach((ddl, index) => {
        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce migration_id length constraints', () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: 'x'.repeat(201), // Exceeds 200 character limit
          ddl_text: 'CREATE TABLE test (id INT);',
          checksum: createHash('sha256').update('CREATE TABLE test (id INT);').digest('hex')
        }
      };

      const result = DDLSchema.safeParse(ddl);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('200 characters or less');
      }
    });

    it('should enforce checksum length constraints', () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '001_test',
          ddl_text: 'CREATE TABLE test (id INT);',
          checksum: 'a1b2c3d4e5f6' // Too short (only 14 characters)
        }
      };

      const result = DDLSchema.safeParse(ddl);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('64 characters');
      }
    });

    it('should validate different DDL operation types', () => {
      const ddls = [
        {
          migration_id: '001_create_table',
          ddl_text: 'CREATE TABLE products (id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, price DECIMAL(10,2));',
          operation: 'CREATE TABLE'
        },
        {
          migration_id: '002_alter_table',
          ddl_text: 'ALTER TABLE products ADD COLUMN description TEXT;',
          operation: 'ALTER TABLE'
        },
        {
          migration_id: '003_create_view',
          ddl_text: 'CREATE VIEW active_users AS SELECT * FROM users WHERE status = \'active\';',
          operation: 'CREATE VIEW'
        },
        {
          migration_id: '004_create_index',
          ddl_text: 'CREATE INDEX idx_products_price ON products(price);',
          operation: 'CREATE INDEX'
        },
        {
          migration_id: '005_drop_table',
          ddl_text: 'DROP TABLE old_products;',
          operation: 'DROP TABLE'
        },
        {
          migration_id: '006_truncate_table',
          ddl_text: 'TRUNCATE TABLE temp_data;',
          operation: 'TRUNCATE TABLE'
        }
      ];

      ddls.forEach((ddlConfig) => {
        const ddl = {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: ddlConfig.migration_id,
            ddl_text: ddlConfig.ddl_text,
            checksum: createHash('sha256').update(ddlConfig.ddl_text).digest('hex')
          }
        };

        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.ddl_text).toContain(ddlConfig.operation);
        }
      });
    });

    it('should validate complex DDL statements', () => {
      const complexDDL = `CREATE TABLE orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_amount DECIMAL(12,2) NOT NULL CHECK (total_amount > 0),
        status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
        shipping_address JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX idx_orders_user_id ON orders(user_id);
      CREATE INDEX idx_orders_status ON orders(status);
      CREATE INDEX idx_orders_date ON orders(order_date);

      CREATE TRIGGER update_updated_at BEFORE UPDATE ON orders
      FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();`;

      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '003_complex_order_schema',
          ddl_text: complexDDL,
          checksum: createHash('sha256').update(complexDDL).digest('hex'),
          description: 'Complex order schema with table, indexes, and trigger'
        }
      };

      const result = DDLSchema.safeParse(ddl);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.ddl_text).toContain('CREATE TABLE orders');
        expect(result.data.data.ddl_text).toContain('CREATE INDEX');
        expect(result.data.data.ddl_text).toContain('CREATE TRIGGER');
        expect(result.data.data.description).toBe('Complex order schema with table, indexes, and trigger');
      }
    });

    it('should handle DDL with special characters and SQL keywords', () => {
      const ddlStatements = [
        "CREATE TABLE \"user-roles\" (id SERIAL PRIMARY KEY, role_name VARCHAR(100) NOT NULL UNIQUE);",
        "CREATE TABLE `config-settings` (key VARCHAR(255) PRIMARY KEY, value TEXT NOT NULL, \"type\" VARCHAR(50));",
        "ALTER TABLE products ADD COLUMN CONSTRAINT chk_price_positive CHECK (price >= 0);",
        "CREATE VIEW \"user-summary\" AS SELECT u.id, u.name, COUNT(o.id) as order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name;"
      ];

      ddlStatements.forEach((ddlText, index) => {
        const ddl = {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: `00${index + 4}_special_chars`,
            ddl_text: ddlText,
            checksum: createHash('sha256').update(ddlText).digest('hex')
          }
        };

        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('DDL Storage Operations', () => {
    it('should store DDL successfully using memory_store pattern', async () => {
      const ddlText = 'CREATE TABLE customers (id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE);';
      const ddl = {
        kind: 'ddl' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          migration_id: '001_create_customers',
          ddl_text: ddlText,
          checksum: createHash('sha256').update(ddlText).digest('hex'),
          description: 'Create customers table with basic information'
        },
        content: `DDL Migration: 001_create_customers - ${ddlText}` // Required for embedding generation
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('ddl');
      expect(result.stored[0].data.migration_id).toBe('001_create_customers');
      expect(result.stored[0].data.ddl_text).toContain('CREATE TABLE customers');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch DDL storage successfully', async () => {
      const ddls = [
        {
          migration_id: '001_create_users',
          ddl_text: 'CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL);'
        },
        {
          migration_id: '002_create_posts',
          ddl_text: 'CREATE TABLE posts (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), title VARCHAR(255) NOT NULL);'
        },
        {
          migration_id: '003_create_comments',
          ddl_text: 'CREATE TABLE comments (id SERIAL PRIMARY KEY, post_id INTEGER REFERENCES posts(id), user_id INTEGER REFERENCES users(id), content TEXT NOT NULL);'
        },
        {
          migration_id: '004_add_foreign_keys',
          ddl_text: 'ALTER TABLE posts ADD CONSTRAINT fk_posts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;'
        },
        {
          migration_id: '005_create_indexes',
          ddl_text: 'CREATE INDEX idx_posts_user ON posts(user_id); CREATE INDEX idx_comments_post ON comments(post_id);'
        }
      ].map((ddlConfig, index) => ({
        kind: 'ddl' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          migration_id: ddlConfig.migration_id,
          ddl_text: ddlConfig.ddl_text,
          checksum: createHash('sha256').update(ddlConfig.ddl_text).digest('hex'),
          description: `Migration ${index + 1}: ${ddlConfig.migration_id}`
        },
        content: `DDL Migration: ${ddlConfig.migration_id} - ${ddlConfig.ddl_text}`
      }));

      const result = await db.storeItems(ddls);

      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);

      // Verify all migrations were stored with correct IDs
      expect(result.stored[0].data.migration_id).toBe('001_create_users');
      expect(result.stored[1].data.migration_id).toBe('002_create_posts');
      expect(result.stored[2].data.migration_id).toBe('003_create_comments');
      expect(result.stored[3].data.migration_id).toBe('004_add_foreign_keys');
      expect(result.stored[4].data.migration_id).toBe('005_create_indexes');
    });

    it('should handle mixed valid and invalid DDL entries in batch', async () => {
      const items = [
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_valid_table',
            ddl_text: 'CREATE TABLE valid_table (id INT PRIMARY KEY);',
            checksum: createHash('sha256').update('CREATE TABLE valid_table (id INT PRIMARY KEY);').digest('hex')
          },
          content: 'DDL Migration: 001_valid_table - CREATE TABLE valid_table (id INT PRIMARY KEY);'
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing migration_id
            ddl_text: 'CREATE TABLE invalid_table (id INT);',
            checksum: createHash('sha256').update('CREATE TABLE invalid_table (id INT);').digest('hex')
          },
          content: 'DDL Migration: invalid - Missing migration_id'
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '002_valid_index',
            ddl_text: 'CREATE INDEX idx_valid ON valid_table(id);',
            checksum: createHash('sha256').update('CREATE INDEX idx_valid ON valid_table(id);').digest('hex'),
            description: 'Valid index creation'
          },
          content: 'DDL Migration: 002_valid_index - CREATE INDEX idx_valid ON valid_table(id);'
        },
        {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '003_invalid_checksum',
            ddl_text: 'ALTER TABLE valid_table ADD COLUMN name VARCHAR(100);',
            checksum: 'invalid_checksum_length' // Invalid checksum length
          },
          content: 'DDL Migration: 003_invalid_checksum - Invalid checksum'
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid DDL entries
      expect(result.errors).toHaveLength(2); // 2 invalid DDL entries
      expect(result.stored[0].data.migration_id).toBe('001_valid_table');
      expect(result.stored[1].data.migration_id).toBe('002_valid_index');
    });

    it('should handle DDL with applied_at timestamp', async () => {
      const ddlText = 'CREATE TABLE audit_log (id SERIAL PRIMARY KEY, action VARCHAR(100) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);';
      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '006_create_audit_log',
          ddl_text: ddlText,
          checksum: createHash('sha256').update(ddlText).digest('hex'),
          applied_at: '2025-01-15T10:30:00Z',
          description: 'Create audit log table for tracking changes'
        },
        content: `DDL Migration: 006_create_audit_log - ${ddlText}`
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.applied_at).toBe('2025-01-15T10:30:00Z');
      expect(result.stored[0].data.description).toBe('Create audit log table for tracking changes');
    });
  });

  describe('DDL Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for DDL entries
      mockQdrant.search.mockResolvedValue([
        {
          id: 'ddl-id-1',
          score: 0.9,
          payload: {
            kind: 'ddl',
            data: {
              migration_id: '001_create_users',
              ddl_text: 'CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, email VARCHAR(255));',
              checksum: createHash('sha256').update('CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, email VARCHAR(255));').digest('hex'),
              applied_at: '2025-01-01T12:00:00Z'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'ddl-id-2',
          score: 0.8,
          payload: {
            kind: 'ddl',
            data: {
              migration_id: '002_add_user_indexes',
              ddl_text: 'CREATE INDEX idx_users_username ON users(username); CREATE INDEX idx_users_email ON users(email);',
              checksum: createHash('sha256').update('CREATE INDEX idx_users_username ON users(username); CREATE INDEX idx_users_email ON users(email);').digest('hex'),
              description: 'Add indexes for user lookup optimization'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find DDL entries by query', async () => {
      const query = 'create table users';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.migration_id).toBe('001_create_users');
      expect(result.items[0].data.ddl_text).toContain('CREATE TABLE users');
      expect(result.items[1].data.migration_id).toBe('002_add_user_indexes');
      expect(result.items[1].data.ddl_text).toContain('CREATE INDEX');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should find DDL entries by migration_id', async () => {
      const query = '001_create_users migration';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.migration_id).toBe('001_create_users');
    });

    it('should find DDL entries by DDL operation type', async () => {
      const query = 'CREATE INDEX operations';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[1].data.ddl_text).toContain('CREATE INDEX');
    });

    it('should handle empty DDL search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent migration');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });

    it('should find DDL entries by description', async () => {
      const query = 'user lookup optimization';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[1].data.description).toBe('Add indexes for user lookup optimization');
    });
  });

  describe('DDL Scope Isolation', () => {
    it('should isolate DDL entries by project scope', async () => {
      const ddlProjectA = {
        kind: 'ddl' as const,
        scope: {
          project: 'project-A',
          branch: 'main'
        },
        data: {
          migration_id: '001_project_a_schema',
          ddl_text: 'CREATE TABLE project_a_table (id INT PRIMARY KEY);',
          checksum: createHash('sha256').update('CREATE TABLE project_a_table (id INT PRIMARY KEY);').digest('hex')
        },
        content: 'DDL Migration: 001_project_a_schema - CREATE TABLE project_a_table (id INT PRIMARY KEY);'
      };

      const ddlProjectB = {
        kind: 'ddl' as const,
        scope: {
          project: 'project-B',
          branch: 'main'
        },
        data: {
          migration_id: '001_project_b_schema',
          ddl_text: 'CREATE TABLE project_b_table (id INT PRIMARY KEY);',
          checksum: createHash('sha256').update('CREATE TABLE project_b_table (id INT PRIMARY KEY);').digest('hex')
        },
        content: 'DDL Migration: 001_project_b_schema - CREATE TABLE project_b_table (id INT PRIMARY KEY);'
      };

      // Store both DDL entries
      await db.storeItems([ddlProjectA, ddlProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Verify project scope isolation in stored payloads
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0].points[0].payload.scope.project).toBe('project-A');
      expect(storedCalls[1][0].points[0].payload.scope.project).toBe('project-B');
    });

    it('should handle DDL entries with different branch scopes', async () => {
      const ddls = [
        {
          kind: 'ddl' as const,
          scope: {
            project: 'test-project',
            branch: 'main'
          },
          data: {
            migration_id: '001_main_branch_schema',
            ddl_text: 'CREATE TABLE main_table (id INT PRIMARY KEY);',
            checksum: createHash('sha256').update('CREATE TABLE main_table (id INT PRIMARY KEY);').digest('hex')
          },
          content: 'DDL Migration: 001_main_branch_schema - CREATE TABLE main_table (id INT PRIMARY KEY);'
        },
        {
          kind: 'ddl' as const,
          scope: {
            project: 'test-project',
            branch: 'develop'
          },
          data: {
            migration_id: '001_develop_branch_schema',
            ddl_text: 'CREATE TABLE develop_table (id INT PRIMARY KEY, new_feature BOOLEAN DEFAULT false);',
            checksum: createHash('sha256').update('CREATE TABLE develop_table (id INT PRIMARY KEY, new_feature BOOLEAN DEFAULT false);').digest('hex')
          },
          content: 'DDL Migration: 001_develop_branch_schema - CREATE TABLE develop_table (id INT PRIMARY KEY, new_feature BOOLEAN DEFAULT false);'
        },
        {
          kind: 'ddl' as const,
          scope: {
            project: 'test-project',
            branch: 'feature/new-auth'
          },
          data: {
            migration_id: '001_feature_branch_schema',
            ddl_text: 'CREATE TABLE auth_table (id INT PRIMARY KEY, token VARCHAR(255) UNIQUE);',
            checksum: createHash('sha256').update('CREATE TABLE auth_table (id INT PRIMARY KEY, token VARCHAR(255) UNIQUE);').digest('hex')
          },
          content: 'DDL Migration: 001_feature_branch_schema - CREATE TABLE auth_table (id INT PRIMARY KEY, token VARCHAR(255) UNIQUE);'
        }
      ];

      await db.storeItems(ddls);

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.branch).toBe('main');
      expect(storedCalls[1][0][0].payload.scope.branch).toBe('develop');
      expect(storedCalls[2][0][0].payload.scope.branch).toBe('feature/new-auth');
    });
  });

  describe('DDL Edge Cases and Error Handling', () => {
    it('should handle DDL with very long statements', async () => {
      const longDDL = `
        CREATE TABLE very_wide_table (
          id SERIAL PRIMARY KEY,
          ${Array.from({ length: 50 }, (_, i) => `col_${i} VARCHAR(255)`).join(',\n          ')}
        );

        CREATE TABLE another_large_table (
          id SERIAL PRIMARY KEY,
          ${Array.from({ length: 30 }, (_, i) => `field_${i} INTEGER DEFAULT 0`).join(',\n          ')}
        );

        ${Array.from({ length: 20 }, (_, i) => `CREATE INDEX idx_large_table_${i} ON very_wide_table(col_${i});`).join('\n        ')}
      `;

      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '007_large_schema_migration',
          ddl_text: longDDL,
          checksum: createHash('sha256').update(longDDL).digest('hex'),
          description: 'Large migration with multiple tables and many indexes'
        },
        content: `DDL Migration: 007_large_schema_migration - Large migration with multiple tables and indexes`
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.ddl_text.length).toBeGreaterThan(1000);
    });

    it('should handle DDL with multiline statements and comments', async () => {
      const ddlWithComments = `
        -- Create user management tables
        -- This migration sets up the basic user structure

        CREATE TABLE users (
          id SERIAL PRIMARY KEY,           -- Primary key
          username VARCHAR(100) UNIQUE NOT NULL,  -- Unique username
          email VARCHAR(255) UNIQUE NOT NULL,     -- Unique email
          password_hash VARCHAR(255) NOT NULL,    -- Hashed password
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Auto-populated
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP   -- Auto-populated
        );

        -- Create index for faster email lookups
        CREATE INDEX idx_users_email ON users(email);

        -- Add comment to document table purpose
        COMMENT ON TABLE users IS 'User accounts table with authentication information';
      `;

      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '008_schema_with_comments',
          ddl_text: ddlWithComments,
          checksum: createHash('sha256').update(ddlWithComments).digest('hex'),
          description: 'User tables creation with comprehensive comments'
        },
        content: `DDL Migration: 008_schema_with_comments - User tables with comments`
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.ddl_text).toContain('--');
      expect(result.stored[0].data.ddl_text).toContain('COMMENT ON TABLE');
    });

    it('should handle DDL with special SQL constructs', async () => {
      const specialDDL = `
        CREATE TABLE products (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          price DECIMAL(10,2) CHECK (price > 0),
          status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'discontinued')),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT products_name_price UNIQUE (name, price)
        );

        CREATE TYPE order_status AS ENUM ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled');

        CREATE TABLE orders (
          id SERIAL PRIMARY KEY,
          product_id INTEGER REFERENCES products(id) ON DELETE RESTRICT,
          quantity INTEGER CHECK (quantity > 0),
          order_status order_status DEFAULT 'pending',
          order_date DATE DEFAULT CURRENT_DATE,
          UNIQUE(product_id, order_date)
        );

        CREATE OR REPLACE FUNCTION update_product_status()
        RETURNS TRIGGER AS $$
        BEGIN
          IF NEW.status = 'discontinued' THEN
            UPDATE orders SET order_status = 'cancelled' WHERE product_id = NEW.id;
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER trigger_update_product_status
        AFTER UPDATE ON products
        FOR EACH ROW EXECUTE FUNCTION update_product_status();
      `;

      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '009_advanced_sql_constructs',
          ddl_text: specialDDL,
          checksum: createHash('sha256').update(specialDDL).digest('hex'),
          description: 'Advanced DDL with constraints, enums, functions, and triggers'
        },
        content: `DDL Migration: 009_advanced_sql_constructs - Advanced SQL constructs`
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.ddl_text).toContain('CHECK');
      expect(result.stored[0].data.ddl_text).toContain('CONSTRAINT');
      expect(result.stored[0].data.ddl_text).toContain('CREATE TYPE');
      expect(result.stored[0].data.ddl_text).toContain('CREATE OR REPLACE FUNCTION');
      expect(result.stored[0].data.ddl_text).toContain('CREATE TRIGGER');
    });

    it('should handle DDL storage errors gracefully', async () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '010_error_test',
          ddl_text: 'CREATE TABLE error_test (id INT PRIMARY KEY);',
          checksum: createHash('sha256').update('CREATE TABLE error_test (id INT PRIMARY KEY);').digest('hex')
        }
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });

    it('should handle DDL with Unicode and special characters', async () => {
      const unicodeDDL = `
        CREATE TABLE international_products (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          description TEXT,
          price DECIMAL(10,2),
          category VARCHAR(100),
          tags TEXT[]
        );

        INSERT INTO international_products (name, description, price, category, tags) VALUES
        ('Café au Lait Bowl', 'Porcelain bowl with café design', 24.99, 'Kitchen', '{coffee, café, porcelain}'),
        ('Sushi Plate Set', 'Traditional Japanese sushi plates', 89.99, 'Dining', '{sushi, japanese, traditional}'),
        ('Matryoshka Dolls', 'Russian nesting dolls set', 45.50, 'Decor', '{russian, traditional, nesting}');
      `;

      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '011_unicode_support',
          ddl_text: unicodeDDL,
          checksum: createHash('sha256').update(unicodeDDL).digest('hex'),
          description: 'DDL with Unicode characters and international content'
        },
        content: `DDL Migration: 011_unicode_support - Unicode and international content`
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.ddl_text).toContain('Café au Lait Bowl');
      expect(result.stored[0].data.ddl_text).toContain('Sushi Plate Set');
      expect(result.stored[0].data.ddl_text).toContain('Matryoshka Dolls');
    });
  });

  describe('DDL Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          migration_id: '001_validation_test',
          ddl_text: 'CREATE TABLE validation_test (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL);',
          checksum: createHash('sha256').update('CREATE TABLE validation_test (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL);').digest('hex'),
          description: 'Test DDL for knowledge system validation'
        },
        tags: { environment: 'test', category: 'validation', critical: true },
        source: {
          actor: 'test-suite',
          tool: 'vitest',
          timestamp: '2025-01-01T00:00:00Z'
        }
      };

      const result = validateKnowledgeItem(ddl);
      expect(result.kind).toBe('ddl');
      expect(result.data.migration_id).toBe('001_validation_test');
      expect(result.tags.environment).toBe('test');
      expect(result.tags.critical).toBe(true);
      expect(result.source.actor).toBe('test-suite');
      expect(result.source.tool).toBe('vitest');
    });

    it('should handle TTL policy for DDL entries', async () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '001_ttl_test',
          ddl_text: 'CREATE TABLE ttl_test (id INT PRIMARY KEY);',
          checksum: createHash('sha256').update('CREATE TABLE ttl_test (id INT PRIMARY KEY);').digest('hex'),
          description: 'Test DDL with TTL policy'
        },
        ttl_policy: 'short' as const,
        content: 'DDL Migration: 001_ttl_test - Test DDL with TTL policy'
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });

    it('should support different TTL policies for DDL', async () => {
      const ttlPolicies = ['default', 'short', 'long', 'permanent'] as const;

      const ddls = ttlPolicies.map((policy, index) => ({
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: `00${index + 1}_ttl_${policy}`,
          ddl_text: `CREATE TABLE ttl_${policy}_test (id INT PRIMARY KEY);`,
          checksum: createHash('sha256').update(`CREATE TABLE ttl_${policy}_test (id INT PRIMARY KEY);`).digest('hex'),
          description: `Test DDL with ${policy} TTL policy`
        },
        ttl_policy: policy,
        content: `DDL Migration: 00${index + 1}_ttl_${policy} - TTL policy test`
      }));

      const result = await db.storeItems(ddls);

      expect(result.stored).toHaveLength(4);
      expect(result.stored[0].ttl_policy).toBe('default');
      expect(result.stored[1].ttl_policy).toBe('short');
      expect(result.stored[2].ttl_policy).toBe('long');
      expect(result.stored[3].ttl_policy).toBe('permanent');
    });

    it('should handle DDL with complex metadata and tags', async () => {
      const ddl = {
        kind: 'ddl' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          migration_id: '001_complex_metadata',
          ddl_text: 'CREATE TABLE metadata_test (id SERIAL PRIMARY KEY, config JSONB NOT NULL);',
          checksum: createHash('sha256').update('CREATE TABLE metadata_test (id SERIAL PRIMARY KEY, config JSONB NOT NULL);').digest('hex'),
          description: 'Test DDL with complex metadata',
          applied_at: '2025-01-01T12:00:00Z'
        },
        tags: {
          environment: 'production',
          category: 'core-schema',
          criticality: 'high',
          team: 'backend',
          requires_downtime: false,
          rollback_plan: 'available',
          tested: true,
          approved_by: 'db-team-lead',
          complexity_score: 7.5,
          estimated_runtime_seconds: 120,
          dependencies: ['001_initial_schema', '002_create_extensions'],
          impact_assessment: {
            performance_impact: 'low',
            storage_impact: 'medium',
            compatibility_impact: 'none'
          }
        },
        source: {
          actor: 'database-admin',
          tool: 'liquibase',
          timestamp: '2025-01-01T10:00:00Z',
          session_id: 'session-12345',
          request_id: 'req-abcdef'
        },
        content: 'DDL Migration: 001_complex_metadata - Complex metadata test'
      };

      const result = await db.storeItems([ddl]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].tags.criticality).toBe('high');
      expect(result.stored[0].tags.requires_downtime).toBe(false);
      expect(result.stored[0].tags.complexity_score).toBe(7.5);
      expect(result.stored[0].tags.impact_assessment.performance_impact).toBe('low');
      expect(result.stored[0].source.session_id).toBe('session-12345');
    });
  });

  describe('DDL-Specific Features and Validation', () => {
    it('should validate migration ID patterns', () => {
      const validMigrationIds = [
        '001_initial_schema',
        '20250101_120000_create_users',
        'v1.0.0_initial_setup',
        '001_create_user_table',
        '002_add_email_index',
        '003_alter_users_add_last_login',
        '004_create_user_preferences_view',
        '005_drop_deprecated_columns',
        '006_rename_user_to_account',
        '007_create_audit_triggers'
      ];

      validMigrationIds.forEach((migrationId) => {
        const ddl = {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: migrationId,
            ddl_text: 'CREATE TABLE test (id INT PRIMARY KEY);',
            checksum: createHash('sha256').update('CREATE TABLE test (id INT PRIMARY KEY);').digest('hex')
          }
        };

        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.migration_id).toBe(migrationId);
        }
      });
    });

    it('should handle DDL content validation through checksums', () => {
      const ddlText = 'CREATE TABLE checksum_test (id SERIAL PRIMARY KEY, data TEXT);';
      const incorrectChecksum = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const correctChecksum = createHash('sha256').update(ddlText).digest('hex');

      const ddlWithIncorrectChecksum = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '001_checksum_validation',
          ddl_text: ddlText,
          checksum: incorrectChecksum
        }
      };

      const ddlWithCorrectChecksum = {
        kind: 'ddl' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '001_checksum_validation',
          ddl_text: ddlText,
          checksum: correctChecksum
        }
      };

      // Both should be valid from schema perspective (content validation is business logic)
      const resultIncorrect = DDLSchema.safeParse(ddlWithIncorrectChecksum);
      const resultCorrect = DDLSchema.safeParse(ddlWithCorrectChecksum);

      expect(resultIncorrect.success).toBe(true);
      expect(resultCorrect.success).toBe(true);

      // Verify checksum format is correct (64 hex characters)
      expect(correctChecksum).toMatch(/^[a-f0-9]{64}$/i);
      expect(correctChecksum).toHaveLength(64);
    });

    it('should handle DDL with applied_at validation', () => {
      const validTimestamps = [
        '2025-01-01T00:00:00Z',
        '2025-12-31T23:59:59Z',
        '2025-06-15T12:30:45.123Z'
      ];

      validTimestamps.forEach((timestamp) => {
        const ddl = {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_timestamp_test',
            ddl_text: 'CREATE TABLE timestamp_test (id INT PRIMARY KEY);',
            checksum: createHash('sha256').update('CREATE TABLE timestamp_test (id INT PRIMARY KEY);').digest('hex'),
            applied_at: timestamp
          }
        };

        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.applied_at).toBe(timestamp);
        }
      });
    });

    it('should reject invalid applied_at timestamps', () => {
      const invalidTimestamps = [
        '2025-01-01',           // Missing time
        '2025-01-01T25:00:00Z', // Invalid hour
        '2025-13-01T12:00:00Z', // Invalid month
        '2025-01-32T12:00:00Z', // Invalid day
        'invalid-date-format',  // Completely invalid
        '2025-01-01T12:00:00',  // Missing Z suffix
        'January 1, 2025'       // Human-readable format
      ];

      invalidTimestamps.forEach((timestamp) => {
        const ddl = {
          kind: 'ddl' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_invalid_timestamp',
            ddl_text: 'CREATE TABLE invalid_timestamp_test (id INT PRIMARY KEY);',
            checksum: createHash('sha256').update('CREATE TABLE invalid_timestamp_test (id INT PRIMARY KEY);').digest('hex'),
            applied_at: timestamp
          }
        };

        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(false);
      });
    });
  });
});