/**
 * Database Test Helper
 *
 * Provides database setup, cleanup, and test data management
 * for isolated test environments.
 */

import type { Pool } from 'pg';
import { getPool } from '../../../database/connection.js';

/**
 * Database test helper for managing test databases and data
 */
export class DatabaseTestHelper {
  private static testDatabases: Set<string> = new Set();

  /**
   * Setup test environment with all required tables and indexes
   */
  static async setupTestEnvironment(pool: Pool): Promise<void> {
    // Create all tables for the 16 knowledge types
    await this.createKnowledgeTables(pool);

    // Create indexes for performance
    await this.createPerformanceIndexes(pool);

    // Create triggers and constraints
    await this.createDatabaseConstraints(pool);

    // Insert basic test data
    await this.seedBasicTestData(pool);
  }

  /**
   * Create isolated test database
   */
  static async setupTestDatabase(dbName: string): Promise<Pool> {
    const adminPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 1,
    });

    try {
      // Create the test database
      await adminPool.query(`CREATE DATABASE "${dbName}"`);
      this.testDatabases.add(dbName);

      // Connect to the test database
      const testDbUrl = process.env.DATABASE_URL?.replace(/\/[^\/]*$/, `/${dbName}`);
      const testPool = new Pool({
        connectionString: testDbUrl,
        max: 5,
      });

      // Run migrations and setup
      await this.setupTestEnvironment(testPool);

      return testPool;

    } finally {
      await adminPool.end();
    }
  }

  /**
   * Clean up test database
   */
  static async cleanupTestDatabase(dbName: string): Promise<void> {
    const adminPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 1,
    });

    try {
      // Kill all connections to the test database
      await adminPool.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${dbName}'
      `);

      // Drop the test database
      await adminPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
      this.testDatabases.delete(dbName);

    } finally {
      await adminPool.end();
    }
  }

  /**
   * Clean up all test databases
   */
  static async cleanupAllTestDatabases(): Promise<void> {
    const adminPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 1,
    });

    try {
      for (const dbName of this.testDatabases) {
        await this.cleanupTestDatabase(dbName);
      }
    } finally {
      await adminPool.end();
    }
  }

  /**
   * Create knowledge tables for all 16 types
   */
  private static async createKnowledgeTables(pool: Pool): Promise<void> {
    // Core knowledge tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS section (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        heading TEXT NOT NULL,
        title TEXT NOT NULL,
        body_md TEXT,
        body_text TEXT,
        body_jsonb JSONB,
        tags JSONB DEFAULT '{}',
        citation_count INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS adr_decision (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        component TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('proposed', 'accepted', 'deprecated', 'superseded')),
        rationale TEXT NOT NULL,
        alternatives_considered JSONB DEFAULT '[]',
        consequences TEXT,
        supersedes TEXT,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS issue_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        status TEXT DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
        assignee TEXT,
        labels JSONB DEFAULT '[]',
        reported_by TEXT,
        reported_at TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS todo_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        text TEXT NOT NULL,
        scope TEXT,
        status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'cancelled')),
        priority TEXT CHECK (priority IN ('low', 'medium', 'high', 'critical')),
        assignee TEXT,
        due_date TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS runbook (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        service TEXT NOT NULL,
        title TEXT,
        description TEXT,
        steps_jsonb JSONB NOT NULL,
        prerequisites JSONB DEFAULT '[]',
        rollback_procedure TEXT,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS change_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        subject_ref TEXT NOT NULL,
        summary TEXT,
        details TEXT,
        author TEXT,
        change_type TEXT,
        impact TEXT,
        risk_level TEXT,
        test_results TEXT,
        deployment_notes TEXT,
        rollback_plan TEXT,
        approved_by TEXT,
        approved_at TIMESTAMP WITH TIME ZONE,
        deployed_at TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS release_note (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        version TEXT NOT NULL,
        summary TEXT,
        features JSONB DEFAULT '[]',
        bug_fixes JSONB DEFAULT '[]',
        breaking_changes JSONB DEFAULT '[]',
        migration_notes TEXT,
        security_notes TEXT,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS ddl_history (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        migration_id TEXT NOT NULL UNIQUE,
        description TEXT,
        sql_content TEXT,
        checksum TEXT,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        applied_by TEXT,
        rollback_sql TEXT,
        dependencies JSONB DEFAULT '[]',
        impact TEXT,
        risk_level TEXT
      );

      CREATE TABLE IF NOT EXISTS pr_context (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        description TEXT,
        pr_number INTEGER,
        author TEXT,
        reviewers JSONB DEFAULT '[]',
        status TEXT,
        merge_commit TEXT,
        base_branch TEXT,
        head_branch TEXT,
        files_changed INTEGER,
        additions INTEGER,
        deletions INTEGER,
        tests_added INTEGER,
        tests_passed BOOLEAN,
        coverage_change DECIMAL(5,2),
        performance_impact TEXT,
        security_review TEXT,
        documentation_updated BOOLEAN,
        breaking_change BOOLEAN,
        migration_required BOOLEAN,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      // Graph extension tables
      CREATE TABLE IF NOT EXISTS knowledge_entity (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        entity_type TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        data JSONB DEFAULT '{}',
        properties JSONB DEFAULT '{}',
        status TEXT DEFAULT 'active',
        owner TEXT,
        created_by TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}'
      );

      CREATE TABLE IF NOT EXISTS knowledge_relation (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        from_entity_type TEXT NOT NULL,
        from_entity_id UUID NOT NULL,
        to_entity_type TEXT NOT NULL,
        to_entity_id UUID NOT NULL,
        relation_type TEXT NOT NULL,
        description TEXT,
        properties JSONB DEFAULT '{}',
        strength DECIMAL(3,2) DEFAULT 0.5,
        bidirectional BOOLEAN DEFAULT FALSE,
        created_by TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}'
      );

      CREATE TABLE IF NOT EXISTS knowledge_observation (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        entity_type TEXT NOT NULL,
        entity_id UUID NOT NULL,
        observation_type TEXT NOT NULL,
        key TEXT NOT NULL,
        value JSONB NOT NULL,
        unit TEXT,
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        source TEXT,
        context JSONB DEFAULT '{}',
        confidence DECIMAL(3,2) DEFAULT 1.0,
        verified BOOLEAN DEFAULT FALSE,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      // Additional log tables for the 8-LOG system
      CREATE TABLE IF NOT EXISTS incident_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        impact TEXT,
        status TEXT DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
        detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        resolved_at TIMESTAMP WITH TIME ZONE,
        duration_minutes INTEGER,
        affected_services JSONB DEFAULT '[]',
        affected_users INTEGER,
        root_cause_analysis TEXT,
        resolution TEXT,
        prevention_measures JSONB DEFAULT '[]',
        lessons_learned JSONB DEFAULT '[]',
        post_mortem_link TEXT,
        coordinator TEXT,
        participants JSONB DEFAULT '[]',
        communication_channels JSONB DEFAULT '[]',
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS release_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        version TEXT NOT NULL,
        release_type TEXT CHECK (release_type IN ('patch', 'minor', 'major')),
        status TEXT DEFAULT 'planned' CHECK (status IN ('planned', 'in_progress', 'deployed', 'rolled_back')),
        scope TEXT,
        planned_date TIMESTAMP WITH TIME ZONE,
        actual_date TIMESTAMP WITH TIME ZONE,
        description TEXT,
        features JSONB DEFAULT '[]',
        bug_fixes JSONB DEFAULT '[]',
        breaking_changes JSONB DEFAULT '[]',
        rollback_procedure TEXT,
        deployment_strategy TEXT,
        testing_summary TEXT,
        performance_impact TEXT,
        security_review TEXT,
        approved_by TEXT,
        deployment_notes TEXT,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS risk_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        category TEXT,
        risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
        impact_description TEXT,
        probability TEXT CHECK (probability IN ('low', 'medium', 'high')),
        impact_score INTEGER CHECK (impact_score BETWEEN 1 AND 10),
        probability_score INTEGER CHECK (probability_score BETWEEN 1 AND 10),
        risk_score INTEGER,
        identified_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        status TEXT DEFAULT 'identified' CHECK (status IN ('identified', 'assessed', 'mitigated', 'accepted', 'closed')),
        mitigation_strategies JSONB DEFAULT '[]',
        mitigation_status TEXT,
        residual_risk TEXT,
        owner TEXT,
        reviewer TEXT,
        review_date TIMESTAMP WITH TIME ZONE,
        next_review_date TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS assumption_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        description TEXT,
        category TEXT,
        validation_status TEXT DEFAULT 'unvalidated' CHECK (validation_status IN ('unvalidated', 'in_progress', 'validated', 'invalidated')),
        impact_if_invalid TEXT,
        validation_method TEXT,
        validation_date TIMESTAMP WITH TIME ZONE,
        validator TEXT,
        confidence_level DECIMAL(3,2) DEFAULT 0.5,
        dependencies JSONB DEFAULT '[]',
        expiry_date TIMESTAMP WITH TIME ZONE,
        tags JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        deleted_at TIMESTAMP WITH TIME ZONE
      );
    `);
  }

  /**
   * Create performance indexes
   */
  private static async createPerformanceIndexes(pool: Pool): Promise<void> {
    await pool.query(`
      -- FTS index for sections
      CREATE INDEX IF NOT EXISTS idx_section_fts ON section USING gin(to_tsvector('english', heading || ' ' || COALESCE(body_md, '')));

      -- General performance indexes
      CREATE INDEX IF NOT EXISTS idx_section_updated_at ON section(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_section_tags ON section USING gin(tags);
      CREATE INDEX IF NOT EXISTS idx_section_deleted_at ON section(deleted_at);

      CREATE INDEX IF NOT EXISTS idx_decision_updated_at ON adr_decision(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_decision_component ON adr_decision(component);
      CREATE INDEX IF NOT EXISTS idx_decision_status ON adr_decision(status);
      CREATE INDEX IF NOT EXISTS idx_decision_deleted_at ON adr_decision(deleted_at);

      CREATE INDEX IF NOT EXISTS idx_issue_updated_at ON issue_log(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_issue_status ON issue_log(status);
      CREATE INDEX IF NOT EXISTS idx_issue_severity ON issue_log(severity);
      CREATE INDEX IF NOT EXISTS idx_issue_deleted_at ON issue_log(deleted_at);

      CREATE INDEX IF NOT EXISTS idx_todo_updated_at ON todo_log(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_todo_status ON todo_log(status);
      CREATE INDEX IF NOT EXISTS idx_todo_priority ON todo_log(priority);
      CREATE INDEX IF NOT EXISTS idx_todo_deleted_at ON todo_log(deleted_at);

      -- Graph indexes
      CREATE INDEX IF NOT EXISTS idx_entity_type_name ON knowledge_entity(entity_type, name);
      CREATE INDEX IF NOT EXISTS idx_entity_updated_at ON knowledge_entity(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_entity_deleted_at ON knowledge_entity(deleted_at);

      CREATE INDEX IF NOT EXISTS idx_relation_from ON knowledge_relation(from_entity_type, from_entity_id);
      CREATE INDEX IF NOT EXISTS idx_relation_to ON knowledge_relation(to_entity_type, to_entity_id);
      CREATE INDEX IF NOT EXISTS idx_relation_type ON knowledge_relation(relation_type);
      CREATE INDEX IF NOT EXISTS idx_relation_deleted_at ON knowledge_relation(deleted_at);

      CREATE INDEX IF NOT EXISTS idx_observation_entity ON knowledge_observation(entity_type, entity_id);
      CREATE INDEX IF NOT EXISTS idx_observation_type_key ON knowledge_observation(observation_type, key);
      CREATE INDEX IF NOT EXISTS idx_observation_timestamp ON knowledge_observation(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_observation_deleted_at ON knowledge_observation(deleted_at);
    `);
  }

  /**
   * Create database constraints and triggers
   */
  private static async createDatabaseConstraints(pool: Pool): Promise<void> {
    await pool.query(`
      -- Update timestamps trigger
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ language 'plpgsql';

      -- Apply the trigger to all tables with updated_at columns
      DO $$
      DECLARE
        table_name TEXT;
      BEGIN
        FOR table_name IN
          SELECT tablename FROM pg_tables WHERE schemaname = 'public'
          AND EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE table_name = tablename AND column_name = 'updated_at')
        LOOP
          EXECUTE format('CREATE TRIGGER update_%I_updated_at
                         BEFORE UPDATE ON %I
                         FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()',
                         table_name, table_name);
        END LOOP;
      END $$;
    `);
  }

  /**
   * Seed basic test data
   */
  private static async seedBasicTestData(pool: Pool): Promise<void> {
    await pool.query(`
      -- Insert some basic test sections
      INSERT INTO section (heading, title, body_md, tags) VALUES
      ('Test Section 1', 'Test Section 1', '# Test Section 1\nThis is a test section.', '{"category": "test", "priority": "medium"}'),
      ('Test Section 2', 'Test Section 2', '# Test Section 2\nAnother test section.', '{"category": "test", "priority": "low"}')
      ON CONFLICT DO NOTHING;

      -- Insert a test decision
      INSERT INTO adr_decision (title, component, status, rationale, alternatives_considered) VALUES
      ('Test Decision', 'test-component', 'proposed', 'This is a test decision for testing purposes.', '["Alternative 1", "Alternative 2"]')
      ON CONFLICT DO NOTHING;

      -- Insert a test issue
      INSERT INTO issue_log (title, description, severity, status) VALUES
      ('Test Issue', 'This is a test issue', 'medium', 'open')
      ON CONFLICT DO NOTHING;
    `);
  }

  /**
   * Clear all test data from tables
   */
  static async clearTestData(pool: Pool): Promise<void> {
    await pool.query(`
      TRUNCATE TABLE knowledge_observation CASCADE;
      TRUNCATE TABLE knowledge_relation CASCADE;
      TRUNCATE TABLE knowledge_entity CASCADE;
      TRUNCATE TABLE assumption_log CASCADE;
      TRUNCATE TABLE risk_log CASCADE;
      TRUNCATE TABLE release_log CASCADE;
      TRUNCATE TABLE incident_log CASCADE;
      TRUNCATE TABLE pr_context CASCADE;
      TRUNCATE TABLE ddl_history CASCADE;
      TRUNCATE TABLE release_note CASCADE;
      TRUNCATE TABLE change_log CASCADE;
      TRUNCATE TABLE runbook CASCADE;
      TRUNCATE TABLE todo_log CASCADE;
      TRUNCATE TABLE issue_log CASCADE;
      TRUNCATE TABLE adr_decision CASCADE;
      TRUNCATE TABLE section CASCADE;
    `);
  }

  /**
   * Get table row counts for verification
   */
  static async getTableRowCounts(pool: Pool): Promise<Record<string, number>> {
    const result = await pool.query(`
      SELECT
        'section' as table_name, COUNT(*) as row_count FROM section
      UNION ALL
      SELECT 'adr_decision' as table_name, COUNT(*) as row_count FROM adr_decision
      UNION ALL
      SELECT 'issue_log' as table_name, COUNT(*) as row_count FROM issue_log
      UNION ALL
      SELECT 'todo_log' as table_name, COUNT(*) as row_count FROM todo_log
      UNION ALL
      SELECT 'runbook' as table_name, COUNT(*) as row_count FROM runbook
      UNION ALL
      SELECT 'change_log' as table_name, COUNT(*) as row_count FROM change_log
      UNION ALL
      SELECT 'release_note' as table_name, COUNT(*) as row_count FROM release_note
      UNION ALL
      SELECT 'ddl_history' as table_name, COUNT(*) as row_count FROM ddl_history
      UNION ALL
      SELECT 'pr_context' as table_name, COUNT(*) as row_count FROM pr_context
      UNION ALL
      SELECT 'knowledge_entity' as table_name, COUNT(*) as row_count FROM knowledge_entity
      UNION ALL
      SELECT 'knowledge_relation' as table_name, COUNT(*) as row_count FROM knowledge_relation
      UNION ALL
      SELECT 'knowledge_observation' as table_name, COUNT(*) as row_count FROM knowledge_observation
      UNION ALL
      SELECT 'incident_log' as table_name, COUNT(*) as row_count FROM incident_log
      UNION ALL
      SELECT 'release_log' as table_name, COUNT(*) as row_count FROM release_log
      UNION ALL
      SELECT 'risk_log' as table_name, COUNT(*) as row_count FROM risk_log
      UNION ALL
      SELECT 'assumption_log' as table_name, COUNT(*) as row_count FROM assumption_log
    `);

    const counts: Record<string, number> = {};
    for (const row of result.rows) {
      counts[row.table_name] = parseInt(row.row_count, 10);
    }

    return counts;
  }

  /**
   * Verify database schema
   */
  static async verifySchema(pool: Pool): Promise<{
    tables: string[];
    indexes: string[];
    constraints: string[];
  }> {
    const tables = await pool.query(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);

    const indexes = await pool.query(`
      SELECT indexname FROM pg_indexes
      WHERE schemaname = 'public' AND indexname NOT LIKE '%_pkey'
      ORDER BY indexname
    `);

    const constraints = await pool.query(`
      SELECT constraint_name, table_name
      FROM information_schema.table_constraints
      WHERE constraint_schema = 'public'
      ORDER BY table_name, constraint_name
    `);

    return {
      tables: tables.rows.map(r => r.table_name),
      indexes: indexes.rows.map(r => r.indexname),
      constraints: constraints.rows.map(r => `${r.table_name}.${r.constraint_name}`),
    };
  }

  /**
   * Execute a query and return the result
   */
  static async executeQuery<T = any>(
    pool: Pool,
    query: string,
    params: any[] = []
  ): Promise<T[]> {
    const result = await pool.query(query, params);
    return result.rows;
  }

  /**
   * Wait for database to be ready
   */
  static async waitForDatabase(pool: Pool, maxAttempts: number = 10): Promise<void> {
    for (let i = 0; i < maxAttempts; i++) {
      try {
        await pool.query('SELECT 1');
        return;
      } catch (error) {
        if (i === maxAttempts - 1) {
          throw error;
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }
}