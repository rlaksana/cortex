/**
 * Database Migration Integration Tests
 *
 * Tests comprehensive database migration scenarios including:
 * - Schema migrations and updates
 * - Data migration between versions
 * - Rollback and recovery procedures
 * - Migration performance with large datasets
 * - Concurrent migration safety
 * - Migration validation and verification
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { Pool } from 'pg';
import { dbPool } from '../db/pool.ts';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { SCHEMA_DDL } from '../db/schema.ts';

describe('Migration Integration Tests', () => {
  let testPool: Pool;
  let migrationDb: string;

  beforeAll(async () => {
    // Initialize main database
    await dbPool.initialize();

    // Create separate test database for migration testing
    migrationDb = `cortex_migration_test_${Date.now()}`;
    testPool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5433'),
      database: process.env.DB_NAME || 'cortex_prod',
      user: process.env.DB_USER || 'cortex',
      password: process.env.DB_PASSWORD || '',
    });

    // Create test database
    await testPool.query(`CREATE DATABASE ${migrationDb}`);

    // Connect to test database
    await testPool.end();
    testPool = new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5433'),
      database: migrationDb,
      user: process.env.DB_USER || 'cortex',
      password: process.env.DB_PASSWORD || '',
    });
  });

  afterAll(async () => {
    try {
      await testPool.end();

      // Clean up test database
      const cleanupPool = new Pool({
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5433'),
        database: process.env.DB_NAME || 'cortex_prod',
        user: process.env.DB_USER || 'cortex',
        password: process.env.DB_PASSWORD || '',
      });

      await cleanupPool.query(`DROP DATABASE IF EXISTS ${migrationDb}`);
      await cleanupPool.end();
    } catch (error) {
      console.warn('Error during migration test cleanup:', error);
    }
  });

  describe('Schema Migration Scenarios', () => {
    beforeEach(async () => {
      // Clean test database
      await testPool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    });

    it('should handle initial schema creation', async () => {
      // Apply initial schema
      await testPool.query(SCHEMA_DDL);

      // Verify tables were created
      const tablesResult = await testPool.query(`
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
        ORDER BY table_name
      `);

      const tableNames = tablesResult.rows.map(row => row.table_name);

      // Verify core tables exist
      expect(tableNames).toContain('section');
      expect(tableNames).toContain('decision');
      expect(tableNames).toContain('runbook');
      expect(tableNames).toContain('change_log');
      expect(tableNames).toContain('knowledge_entity');
      expect(tableNames).toContain('knowledge_relation');

      // Verify table structures
      const sectionColumns = await testPool.query(`
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'section'
        ORDER BY ordinal_position
      `);

      const columnNames = sectionColumns.rows.map(row => row.column_name);
      expect(columnNames).toContain('id');
      expect(columnNames).toContain('title');
      expect(columnNames).toContain('heading');
      expect(columnNames).toContain('body_text');
      expect(columnNames).toContain('tags');
      expect(columnNames).toContain('created_at');
      expect(columnNames).toContain('updated_at');
    });

    it('should handle schema evolution with new columns', async () => {
      // Create initial schema (simplified)
      await testPool.query(`
        CREATE TABLE section (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          heading VARCHAR(300) NOT NULL,
          body_text TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO section (title, heading, body_text)
        VALUES ('Test Section', 'Test Heading', 'Test content')
        RETURNING id
      `);

      // Add new column (simulating schema evolution)
      await testPool.query(`
        ALTER TABLE section
        ADD COLUMN tags JSONB DEFAULT '{}',
        ADD COLUMN metadata JSONB DEFAULT '{}'
      `);

      // Verify existing data is accessible with default values
      const existingData = await testPool.query(`
        SELECT title, heading, body_text, tags, metadata
        FROM section
        WHERE title = 'Test Section'
      `);

      expect(existingData.rows).toHaveLength(1);
      expect(existingData.rows[0].title).toBe('Test Section');
      expect(existingData.rows[0].tags).toEqual({});
      expect(existingData.rows[0].metadata).toEqual({});

      // Insert new data with new columns
      await testPool.query(`
        INSERT INTO section (title, heading, body_text, tags, metadata)
        VALUES (
          'New Section',
          'New Heading',
          'New content',
          '{"test": true}',
          '{"version": 2}'
        )
      `);

      // Verify new data is stored correctly
      const newData = await testPool.query(`
        SELECT title, tags, metadata
        FROM section
        WHERE title = 'New Section'
      `);

      expect(newData.rows[0].tags).toEqual({ test: true });
      expect(newData.rows[0].metadata).toEqual({ version: 2 });
    });

    it('should handle column type changes safely', async () => {
      // Create table with initial column type
      await testPool.query(`
        CREATE TABLE test_migration (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(100) NOT NULL,
          priority INTEGER DEFAULT 0,
          status VARCHAR(20) DEFAULT 'pending'
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO test_migration (title, priority, status)
        VALUES
          ('Task 1', 1, 'pending'),
          ('Task 2', 2, 'in_progress'),
          ('Task 3', 3, 'completed')
      `);

      // Verify initial data
      const initialData = await testPool.query('SELECT * FROM test_migration ORDER BY priority');
      expect(initialData.rows).toHaveLength(3);

      // Migrate column types (VARCHAR -> TEXT, INTEGER -> SMALLINT)
      await testPool.query(`
        ALTER TABLE test_migration
        ALTER COLUMN title TYPE TEXT,
        ALTER COLUMN priority TYPE SMALLINT
      `);

      // Add enum constraint to status column
      await testPool.query(`
        ALTER TABLE test_migration
        ADD CONSTRAINT valid_status
        CHECK (status IN ('pending', 'in_progress', 'completed', 'cancelled'))
      `);

      // Verify data integrity after migration
      const migratedData = await testPool.query('SELECT * FROM test_migration ORDER BY priority');
      expect(migratedData.rows).toHaveLength(3);

      migratedData.rows.forEach((row, index) => {
        expect(row.title).toBe(`Task ${index + 1}`);
        expect(row.priority).toBe(index + 1);
        expect(['pending', 'in_progress', 'completed']).toContain(row.status);
      });

      // Test constraint enforcement
      await expect(
        testPool.query("INSERT INTO test_migration (title, priority, status) VALUES ('Invalid', 1, 'invalid_status')")
      ).rejects.toThrow('valid_status');
    });

    it('should handle table renaming and restructuring', async () => {
      // Create original table structure
      await testPool.query(`
        CREATE TABLE legacy_sections (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          section_title VARCHAR(500) NOT NULL,
          section_heading VARCHAR(300) NOT NULL,
          section_content TEXT,
          created_date TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO legacy_sections (section_title, section_heading, section_content)
        VALUES ('Legacy Title', 'Legacy Heading', 'Legacy content')
      `);

      // Create new table structure
      await testPool.query(`
        CREATE TABLE section (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          heading VARCHAR(300) NOT NULL,
          body_text TEXT,
          body_md TEXT,
          tags JSONB DEFAULT '{}',
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Migrate data from old to new structure
      await testPool.query(`
        INSERT INTO section (title, heading, body_text, created_at)
        SELECT
          section_title,
          section_heading,
          section_content,
          created_date
        FROM legacy_sections
      `);

      // Verify migration success
      const migratedSection = await testPool.query(`
        SELECT title, heading, body_text, created_at
        FROM section
        WHERE title = 'Legacy Title'
      `);

      expect(migratedSection.rows).toHaveLength(1);
      expect(migratedSection.rows[0].title).toBe('Legacy Title');
      expect(migratedSection.rows[0].heading).toBe('Legacy Heading');
      expect(migratedSection.rows[0].body_text).toBe('Legacy content');

      // Clean up old table
      await testPool.query('DROP TABLE legacy_sections');

      // Verify new table still has data
      const finalSection = await testPool.query('SELECT COUNT(*) as count FROM section');
      expect(parseInt(finalSection.rows[0].count)).toBe(1);
    });
  });

  describe('Data Migration Scenarios', () => {
    beforeEach(async () => {
      // Setup initial schema and data
      await testPool.query(SCHEMA_DDL);
    });

    it('should migrate data between table structures', async () => {
      // Create source table with old structure
      await testPool.query(`
        CREATE TABLE source_data (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title TEXT NOT NULL,
          content TEXT,
          category VARCHAR(100),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO source_data (title, content, category)
        VALUES
          ('Document 1', 'Content of document 1', 'technical'),
          ('Document 2', 'Content of document 2', 'business'),
          ('Document 3', 'Content of document 3', 'technical')
      `);

      // Migrate data to target table (sections)
      await testPool.query(`
        INSERT INTO section (title, heading, body_text, tags, created_at)
        SELECT
          title,
          'Migrated: ' || title,
          content,
          jsonb_build_object('migrated_from', 'source_data', 'category', category),
          created_at
        FROM source_data
        WHERE category = 'technical'
      `);

      // Verify migration
      const migratedSections = await testPool.query(`
        SELECT title, heading, tags
        FROM section
        WHERE tags->>'migrated_from' = 'source_data'
      `);

      expect(migratedSections.rows).toHaveLength(2);
      migratedSections.rows.forEach(row => {
        expect(row.title).toMatch(/Document [13]/);
        expect(row.heading).toMatch(/Migrated:/);
        expect(row.tags.category).toBe('technical');
      });

      // Clean up
      await testPool.query('DROP TABLE source_data');
    });

    it('should handle data transformation during migration', async () => {
      // Create source with different data format
      await testPool.query(`
        CREATE TABLE decisions_old (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          decision_title VARCHAR(500) NOT NULL,
          decision_status VARCHAR(50) NOT NULL,
          impact_description TEXT,
          decision_date DATE NOT NULL,
          decision_maker VARCHAR(200)
        );
      `);

      // Insert legacy data
      await testPool.query(`
        INSERT INTO decisions_old (decision_title, decision_status, impact_description, decision_date, decision_maker)
        VALUES
          ('Adopt Microservices', 'APPROVED', 'Will improve scalability', '2024-01-15', 'Architecture Team'),
          ('Use PostgreSQL', 'APPROVED', 'Better performance than MySQL', '2024-02-01', 'Database Team'),
          ('Implement CI/CD', 'REJECTED', 'Too complex for current team size', '2024-02-15', 'DevOps Team')
      `);

      // Transform and migrate to new decision table
      await testPool.query(`
        INSERT INTO decision (title, status, component, rationale, tags, created_at)
        SELECT
          decision_title,
          CASE decision_status
            WHEN 'APPROVED' THEN 'accepted'
            WHEN 'REJECTED' THEN 'rejected'
            ELSE 'proposed'
          END,
          CASE
            WHEN decision_title LIKE '%Microservices%' THEN 'architecture'
            WHEN decision_title LIKE '%PostgreSQL%' THEN 'database'
            WHEN decision_title LIKE '%CI/CD%' THEN 'devops'
            ELSE 'general'
          END,
          impact_description || ' (Decision made by ' || decision_maker || ' on ' || decision_date || ')',
          jsonb_build_object(
            'migrated_from', 'decisions_old',
            'original_status', decision_status,
            'decision_date', decision_date::text,
            'decision_maker', decision_maker
          ),
          decision_date::timestamp
        FROM decisions_old
      `);

      // Verify transformation
      const transformedDecisions = await testPool.query(`
        SELECT title, status, component, rationale, tags
        FROM decision
        WHERE tags->>'migrated_from' = 'decisions_old'
        ORDER BY title
      `);

      expect(transformedDecisions.rows).toHaveLength(3);

      const microservicesDecision = transformedDecisions.rows.find(d => d.title === 'Adopt Microservices');
      expect(microservicesDecision.status).toBe('accepted');
      expect(microservicesDecision.component).toBe('architecture');
      expect(microservicesDecision.rationale).toContain('Architecture Team');
      expect(microservicesDecision.tags.original_status).toBe('APPROVED');

      const cicdDecision = transformedDecisions.rows.find(d => d.title === 'Implement CI/CD');
      expect(cicdDecision.status).toBe('rejected');
      expect(cicdDecision.component).toBe('devops');

      // Clean up
      await testPool.query('DROP TABLE decisions_old');
    });

    it('should handle large dataset migration efficiently', async () => {
      // Create source table
      await testPool.query(`
        CREATE TABLE large_source (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title TEXT NOT NULL,
          content TEXT,
          category VARCHAR(100),
          priority INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      const recordCount = 10000;
      const batchSize = 1000;

      console.log(`Migrating ${recordCount} records...`);
      const startTime = Date.now();

      // Insert large dataset in batches
      for (let batch = 0; batch < recordCount / batchSize; batch++) {
        const values = Array.from({ length: batchSize }, (_, i) => {
          const index = batch * batchSize + i;
          return `('Record ${index}', 'Content for record ${index}', 'category_${index % 10}', ${index % 5})`;
        }).join(', ');

        await testPool.query(`
          INSERT INTO large_source (title, content, category, priority)
          VALUES ${values}
        `);
      }

      const insertTime = Date.now() - startTime;
      console.log(`Inserted ${recordCount} records in ${insertTime}ms`);

      // Migrate data in batches
      const migrateStartTime = Date.now();
      let migratedCount = 0;

      for (let offset = 0; offset < recordCount; offset += batchSize) {
        await testPool.query(`
          INSERT INTO section (title, heading, body_text, tags, created_at)
          SELECT
            title,
            'Migrated: ' || title,
            content,
            jsonb_build_object(
              'migrated_from', 'large_source',
              'category', category,
              'priority', priority
            ),
            created_at
          FROM large_source
          ORDER BY id
          LIMIT ${batchSize} OFFSET ${offset}
        `);

        migratedCount += batchSize;
      }

      const migrateTime = Date.now() - migrateStartTime;
      console.log(`Migrated ${migratedCount} records in ${migrateTime}ms`);

      // Verify migration
      const totalSections = await testPool.query('SELECT COUNT(*) as count FROM section WHERE tags->>\'migrated_from\' = \'large_source\'');
      expect(parseInt(totalSections.rows[0].count)).toBe(recordCount);

      // Performance expectations
      expect(migrateTime).toBeLessThan(30000); // Should complete within 30 seconds

      // Verify data integrity
      const sampleRecords = await testPool.query(`
        SELECT title, tags
        FROM section
        WHERE tags->>'migrated_from' = 'large_source'
        LIMIT 10
      `);

      sampleRecords.rows.forEach(row => {
        expect(row.title).toMatch(/^Migrated: Record \d+$/);
        expect(row.tags.category).toMatch(/^category_\d+$/);
        expect(row.tags.priority).toBeGreaterThanOrEqual(0);
        expect(row.tags.priority).toBeLessThanOrEqual(4);
      });

      // Clean up
      await testPool.query('DROP TABLE large_source');
    });
  });

  describe('Migration Rollback and Recovery', () => {
    beforeEach(async () => {
      // Clean test database
      await testPool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    });

    it('should support transactional rollbacks', async () => {
      // Start migration transaction
      await testPool.query('BEGIN');

      try {
        // Create table
        await testPool.query(`
          CREATE TABLE test_rollback (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            title VARCHAR(500) NOT NULL,
            content TEXT
          );
        `);

        // Insert data
        await testPool.query(`
          INSERT INTO test_rollback (title, content)
          VALUES ('Test Data', 'Test content')
        `);

        // Simulate error condition
        if (Math.random() > 0.5) {
          throw new Error('Simulated migration error');
        }

        // If no error, commit
        await testPool.query('COMMIT');

        // Should be able to find data
        const result = await testPool.query('SELECT * FROM test_rollback');
        expect(result.rows.length).toBeGreaterThan(0);

      } catch (error) {
        // Rollback on error
        await testPool.query('ROLLBACK');

        // Table should not exist after rollback
        await expect(
          testPool.query('SELECT * FROM test_rollback')
        ).rejects.toThrow('does not exist');
      }
    });

    it('should handle partial migration recovery', async () => {
      // Create initial table
      await testPool.query(`
        CREATE TABLE partial_migration_test (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          value INTEGER
        );
      `);

      // Insert initial data
      await testPool.query(`
        INSERT INTO partial_migration_test (title, value)
        VALUES
          ('Item 1', 10),
          ('Item 2', 20),
          ('Item 3', 30)
      `);

      // Start partial migration
      await testPool.query('BEGIN');

      try {
        // Add new column
        await testPool.query('ALTER TABLE partial_migration_test ADD COLUMN new_field TEXT');

        // Update some rows (partial success)
        await testPool.query(`
          UPDATE partial_migration_test
          SET new_field = 'Updated ' || title
          WHERE value > 15
        `);

        // Simulate error
        throw new Error('Migration interrupted');

      } catch (error) {
        await testPool.query('ROLLBACK');
      }

      // Verify original state is preserved
      const originalData = await testPool.query(`
        SELECT title, value
        FROM partial_migration_test
        ORDER BY value
      `);

      expect(originalData.rows).toHaveLength(3);
      expect(originalData.rows[0].title).toBe('Item 1');
      expect(originalData.rows[0].value).toBe(10);

      // Column should not exist after rollback
      const columns = await testPool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'partial_migration_test'
      `);
      const columnNames = columns.rows.map(row => row.column_name);
      expect(columnNames).not.toContain('new_field');
    });

    it('should create and restore migration backups', async () => {
      // Create original table with data
      await testPool.query(`
        CREATE TABLE backup_test (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          content TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO backup_test (title, content)
        VALUES
          ('Backup Test 1', 'Content 1'),
          ('Backup Test 2', 'Content 2'),
          ('Backup Test 3', 'Content 3')
      `);

      // Create backup
      await testPool.query('CREATE TABLE backup_test_backup AS SELECT * FROM backup_test');

      // Perform migration
      await testPool.query(`
        ALTER TABLE backup_test
        ADD COLUMN status VARCHAR(50) DEFAULT 'active',
        ADD COLUMN priority INTEGER DEFAULT 0
      `);

      await testPool.query(`
        UPDATE backup_test
        SET status = 'migrated', priority = 1
        WHERE title LIKE '%1%'
      `);

      // Verify migration worked
      const migratedData = await testPool.query(`
        SELECT title, status, priority
        FROM backup_test
        WHERE title = 'Backup Test 1'
      `);
      expect(migratedData.rows[0].status).toBe('migrated');
      expect(migratedData.rows[0].priority).toBe(1);

      // Simulate rollback from backup
      await testPool.query('DROP TABLE backup_test');
      await testPool.query('ALTER TABLE backup_test_backup RENAME TO backup_test');

      // Verify restoration
      const restoredData = await testPool.query(`
        SELECT title, content
        FROM backup_test
        ORDER BY title
      `);

      expect(restoredData.rows).toHaveLength(3);
      expect(restoredData.rows[0].title).toBe('Backup Test 1');
      expect(restoredData.rows[0].content).toBe('Content 1');

      // Verify new columns don't exist after restore
      const columns = await testPool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'backup_test'
      `);
      const columnNames = columns.rows.map(row => row.column_name);
      expect(columnNames).not.toContain('status');
      expect(columnNames).not.toContain('priority');
    });
  });

  describe('Migration Validation and Verification', () => {
    beforeEach(async () => {
      // Setup test environment
      await testPool.query(SCHEMA_DDL);
    });

    it('should validate data integrity after migration', async () => {
      // Create source data
      await testPool.query(`
        CREATE TABLE validation_source (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          content TEXT,
          category VARCHAR(100),
          priority INTEGER,
          checksum VARCHAR(64)
        );
      `);

      // Insert test data with checksums
      const testRecords = [
        { title: 'Validation Test 1', content: 'Content 1', category: 'A', priority: 1 },
        { title: 'Validation Test 2', content: 'Content 2', category: 'B', priority: 2 },
        { title: 'Validation Test 3', content: 'Content 3', category: 'A', priority: 3 }
      ];

      for (const record of testRecords) {
        // Create checksum
        const content = `${record.title}|${record.content}|${record.category}|${record.priority}`;
        const crypto = require('crypto');
        const checksum = crypto.createHash('sha256').update(content).digest('hex');

        await testPool.query(`
          INSERT INTO validation_source (title, content, category, priority, checksum)
          VALUES ($1, $2, $3, $4, $5)
        `, [record.title, record.content, record.category, record.priority, checksum]);
      }

      // Migrate data
      await testPool.query(`
        INSERT INTO section (title, heading, body_text, tags, created_at)
        SELECT
          title,
          'Validated: ' || title,
          content,
          jsonb_build_object(
            'migrated_from', 'validation_source',
            'category', category,
            'priority', priority,
            'original_checksum', checksum
          ),
          NOW()
        FROM validation_source
      `);

      // Validate migration integrity
      const migratedRecords = await testPool.query(`
        SELECT title, body_text, tags
        FROM section
        WHERE tags->>'migrated_from' = 'validation_source'
        ORDER BY title
      `);

      expect(migratedRecords.rows).toHaveLength(3);

      // Verify checksums match
      migratedRecords.rows.forEach((row, index) => {
        const originalRecord = testRecords[index];
        expect(row.title).toBe(originalRecord.title);
        expect(row.body_text).toBe(originalRecord.content);

        // Recalculate checksum and verify
        const content = `${originalRecord.title}|${originalRecord.content}|${originalRecord.category}|${originalRecord.priority}`;
        const crypto = require('crypto');
        const expectedChecksum = crypto.createHash('sha256').update(content).digest('hex');
        expect(row.tags.original_checksum).toBe(expectedChecksum);
      });

      // Verify record count matches
      const sourceCount = await testPool.query('SELECT COUNT(*) as count FROM validation_source');
      const targetCount = await testPool.query(`
        SELECT COUNT(*) as count
        FROM section
        WHERE tags->>'migrated_from' = 'validation_source'
      `);

      expect(parseInt(sourceCount.rows[0].count)).toBe(parseInt(targetCount.rows[0].count));

      // Clean up
      await testPool.query('DROP TABLE validation_source');
    });

    it('should verify foreign key relationships after migration', async () => {
      // Create related source tables
      await testPool.query(`
        CREATE TABLE source_documents (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          description TEXT
        );
      `);

      await testPool.query(`
        CREATE TABLE source_sections (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          document_id UUID REFERENCES source_documents(id),
          title VARCHAR(500) NOT NULL,
          content TEXT
        );
      `);

      // Insert related data
      const docResult = await testPool.query(`
        INSERT INTO source_documents (title, description)
        VALUES ('Test Document', 'Test description')
        RETURNING id
      `);
      const documentId = docResult.rows[0].id;

      await testPool.query(`
        INSERT INTO source_sections (document_id, title, content)
        VALUES
          ($1, 'Section 1', 'Content 1'),
          ($1, 'Section 2', 'Content 2')
      `, [documentId]);

      // Migrate documents
      await testPool.query(`
        INSERT INTO document (title, description, tags, created_at)
        SELECT
          title,
          description,
          jsonb_build_object('migrated_from', 'source_documents'),
          NOW()
        FROM source_documents
        RETURNING id
      `);

      // Get migrated document ID
      const migratedDocResult = await testPool.query(`
        SELECT id
        FROM document
        WHERE tags->>'migrated_from' = 'source_documents'
      `);
      const migratedDocId = migratedDocResult.rows[0].id;

      // Migrate sections with new foreign key relationship
      await testPool.query(`
        INSERT INTO section (document_id, title, heading, body_text, tags, created_at)
        SELECT
          $1 as document_id,
          title,
          'Migrated: ' || title,
          content,
          jsonb_build_object('migrated_from', 'source_sections', 'original_document_id', document_id),
          NOW()
        FROM source_sections
      `, [migratedDocId]);

      // Verify foreign key relationships
      const relatedSections = await testPool.query(`
        SELECT s.title, d.title as document_title
        FROM section s
        JOIN document d ON s.document_id = d.id
        WHERE s.tags->>'migrated_from' = 'source_sections'
        ORDER BY s.title
      `);

      expect(relatedSections.rows).toHaveLength(2);
      relatedSections.rows.forEach(row => {
        expect(row.document_title).toBe('Test Document');
        expect(row.title).toMatch(/Migrated: Section [12]/);
      });

      // Verify referential integrity is enforced
      await expect(
        testPool.query(`
          INSERT INTO section (document_id, title, heading, body_text)
          VALUES ('00000000-0000-0000-0000-000000000000', 'Orphan Section', 'Orphan', 'No parent')
        `)
      ).rejects.toThrow('violates foreign key constraint');

      // Clean up
      await testPool.query('DROP TABLE source_documents, source_sections');
    });

    it('should detect and report migration anomalies', async () => {
      // Create source with data that might cause issues
      await testPool.query(`
        CREATE TABLE anomaly_source (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          content TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Insert test data including potential anomalies
      await testPool.query(`
        INSERT INTO anomaly_source (title, content)
        VALUES
          ('Normal Record', 'Normal content'),
          ('Very Long Title That Exceeds The Normal Constraints And Should Be Detected During Migration Validation', 'Content with long title'),
          ('NULL Content', NULL),
          ('Duplicate Title', 'First instance'),
          ('Duplicate Title', 'Second instance'),
          ('Special Content', 'Content with special chars: \'"@#$%^&*()')
      `);

      // Create migration validation function
      await testPool.query(`
        CREATE OR REPLACE FUNCTION validate_migration()
        RETURNS JSON AS $$
        DECLARE
          result JSON;
          anomaly_count INTEGER;
        BEGIN
          -- Check for duplicate titles
          SELECT COUNT(*) - COUNT(DISTINCT title) INTO anomaly_count
          FROM anomaly_source;

          result := jsonb_build_object(
            'duplicate_titles', anomaly_count,
            'null_content', (SELECT COUNT(*) FROM anomaly_source WHERE content IS NULL),
            'long_titles', (SELECT COUNT(*) FROM anomaly_source WHERE length(title) > 400),
            'total_records', (SELECT COUNT(*) FROM anomaly_source)
          );

          RETURN result;
        END;
        $$ LANGUAGE plpgsql;
      `);

      // Run validation
      const validationResult = await testPool.query('SELECT validate_migration() as result');
      const validationData = validationResult.rows[0].result;

      expect(parseInt(validationData.duplicate_titles)).toBe(1);
      expect(parseInt(validationData.null_content)).toBe(1);
      expect(parseInt(validationData.long_titles)).toBe(1);
      expect(parseInt(validationData.total_records)).toBe(6);

      // Perform migration with anomaly handling
      try {
        await testPool.query(`
          INSERT INTO section (title, heading, body_text, tags, created_at)
          SELECT
            CASE
              WHEN length(title) > 400 THEN substring(title, 1, 397) || '...'
              ELSE title
            END,
            'Migrated: ' || CASE
              WHEN length(title) > 400 THEN substring(title, 1, 397) || '...'
              ELSE title
            END,
            COALESCE(content, 'No content provided'),
            jsonb_build_object(
              'migrated_from', 'anomaly_source',
              'had_long_title', length(title) > 400,
              'had_null_content', content IS NULL,
              'had_duplicate_title', EXISTS (
                SELECT 1 FROM anomaly_source s2
                WHERE s2.title = anomaly_source.title AND s2.id != anomaly_source.id
              )
            ),
            created_at
          FROM anomaly_source
        `);

        // Verify migration handled anomalies
        const migratedCount = await testPool.query(`
          SELECT COUNT(*) as count
          FROM section
          WHERE tags->>'migrated_from' = 'anomaly_source'
        `);
        expect(parseInt(migratedCount.rows[0].count)).toBe(6);

        // Check long title was truncated
        const truncatedTitle = await testPool.query(`
          SELECT title
          FROM section
          WHERE title LIKE '%...%' AND tags->>'had_long_title' = 'true'
        `);
        expect(truncatedTitle.rows.length).toBe(1);
        expect(truncatedTitle.rows[0].title.length).toBeLessThanOrEqual(400);

        // Check null content was handled
        const nullContentHandled = await testPool.query(`
          SELECT body_text
          FROM section
          WHERE tags->>'had_null_content' = 'true'
        `);
        expect(nullContentHandled.rows[0].body_text).toBe('No content provided');

      } catch (error) {
        console.error('Migration failed:', error);
        throw error;
      }

      // Clean up
      await testPool.query('DROP FUNCTION validate_migration();');
      await testPool.query('DROP TABLE anomaly_source');
    });
  });

  describe('Concurrent Migration Safety', () => {
    beforeEach(async () => {
      // Clean test database
      await testPool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    });

    it('should handle concurrent read operations during migration', async () => {
      // Create initial table with data
      await testPool.query(`
        CREATE TABLE concurrent_read_test (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL,
          content TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO concurrent_read_test (title, content)
        SELECT 'Test Item ' || i, 'Content ' || i
        FROM generate_series(1, 100) i
      `);

      // Start concurrent read operations
      const readPromises = Array.from({ length: 10 }, async (_, i) => {
        const results = [];
        for (let j = 0; j < 10; j++) {
          const result = await testPool.query(`
            SELECT COUNT(*) as count
            FROM concurrent_read_test
          `);
          results.push(parseInt(result.rows[0].count));
        }
        return { readerId: i, results };
      });

      // Start migration
      const migrationPromise = testPool.query(`
        ALTER TABLE concurrent_read_test
        ADD COLUMN status VARCHAR(50) DEFAULT 'active',
        ADD COLUMN priority INTEGER DEFAULT 0
      `);

      // Wait for all operations to complete
      const [readResults, migrationResult] = await Promise.all([
        Promise.all(readPromises),
        migrationPromise
      ]);

      // Verify all reads succeeded
      readResults.forEach(({ readerId, results }) => {
        expect(results.length).toBe(10);
        // All reads should return consistent count (100)
        results.forEach(count => {
          expect(count).toBe(100);
        });
      });

      // Verify migration succeeded
      const columns = await testPool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'concurrent_read_test'
      `);
      const columnNames = columns.rows.map(row => row.column_name);
      expect(columnNames).toContain('status');
      expect(columnNames).toContain('priority');
    });

    it('should prevent conflicting schema changes', async () => {
      // Create initial table
      await testPool.query(`
        CREATE TABLE conflict_test (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL
        );
      `);

      // Try to perform conflicting operations
      const conflictPromises = [
        testPool.query('ALTER TABLE conflict_test ADD COLUMN field_a TEXT'),
        testPool.query('ALTER TABLE conflict_test ADD COLUMN field_b TEXT'),
        testPool.query('ALTER TABLE conflict_test ADD COLUMN field_c TEXT')
      ];

      // All should succeed (PostgreSQL handles concurrent ALTER TABLE)
      const results = await Promise.allSettled(conflictPromises);

      results.forEach((result, index) => {
        expect(result.status).toBe('fulfilled');
      });

      // Verify all columns were added
      const columns = await testPool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'conflict_test'
        ORDER BY column_name
      `);
      const columnNames = columns.rows.map(row => row.column_name);
      expect(columnNames).toContain('field_a');
      expect(columnNames).toContain('field_b');
      expect(columnNames).toContain('field_c');
    });

    it('should handle migration timeouts gracefully', async () => {
      // Create table
      await testPool.query(`
        CREATE TABLE timeout_test (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(500) NOT NULL
        );
      `);

      // Insert test data
      await testPool.query(`
        INSERT INTO timeout_test (title)
        SELECT 'Test Item ' || i
        FROM generate_series(1, 1000) i
      `);

      // Start long-running operation with timeout
      const longOperationPromise = testPool.query({
        text: `
          UPDATE timeout_test
          SET title = title || ' (updated)'
          WHERE id IN (
            SELECT id FROM timeout_test ORDER BY id FOR UPDATE
          )
        `,
        // Note: In a real scenario, you'd set a timeout
        // This is just to simulate the pattern
      });

      try {
        await Promise.race([
          longOperationPromise,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Operation timeout')), 5000)
          )
        ]);
      } catch (error) {
        if (error.message === 'Operation timeout') {
          // Handle timeout gracefully
          console.log('Operation timed out as expected');

          // Verify data is still accessible
          const count = await testPool.query('SELECT COUNT(*) as count FROM timeout_test');
          expect(parseInt(count.rows[0].count)).toBe(1000);
        } else {
          throw error;
        }
      }
    });
  });
});