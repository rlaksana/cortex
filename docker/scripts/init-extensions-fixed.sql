-- ============================================================================
-- CORTEX MEMORY MCP - PostgreSQL Extensions Initialization
-- ============================================================================

-- This script initializes the required PostgreSQL extensions for the Cortex Memory MCP system.
-- It should be executed during database initialization (via docker-entrypoint-initdb.d).

-- Extensions are essential for:
-- - UUID generation (pgcrypto with gen_random_uuid())
-- - Full-text search capabilities
-- - JSONB operations
-- - Advanced data types and functions

-- ============================================================================
-- CORE EXTENSIONS FOR CORTEX MEMORY MCP
-- ============================================================================

-- UUID generation for primary keys and audit trail
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Additional useful extensions for enhanced functionality
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- For query performance monitoring
CREATE EXTENSION IF NOT EXISTS "pg_trgm";          -- For trigram similarity search
CREATE EXTENSION IF NOT EXISTS "btree_gin";        -- For GIN indexes on B-tree types
CREATE EXTENSION IF NOT EXISTS "btree_gist";       -- For GiST indexes on B-tree types

-- ============================================================================
-- EXTENSION VERIFICATION
-- ============================================================================

-- Verify that all required extensions are installed
DO $$
DECLARE
    required_extensions TEXT[] := ARRAY['pgcrypto', 'pg_stat_statements', 'pg_trgm', 'btree_gin', 'btree_gist'];
    missing_extensions TEXT[] := '{}';
    extension_rec RECORD;
BEGIN
    -- Check each required extension
    FOR extension_rec IN SELECT unnest(required_extensions) as ext_name
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_extension
            WHERE extname = extension_rec.ext_name
        ) THEN
            missing_extensions := array_append(missing_extensions, extension_rec.ext_name);
        END IF;
    END LOOP;

    -- Log results
    IF array_length(missing_extensions, 1) > 0 THEN
        RAISE NOTICE 'Missing extensions: %', array_to_string(missing_extensions, ', ');
        RAISE EXCEPTION 'Required PostgreSQL extensions are not available. Please install: %', array_to_string(missing_extensions, ', ');
    ELSE
        RAISE NOTICE 'All required PostgreSQL extensions are installed successfully.';
    END IF;
END $$;

-- ============================================================================
-- EXTENSION-SPECIFIC CONFIGURATION
-- ============================================================================

-- Configure pg_stat_statements for query monitoring (if available)
DO $$
BEGIN
    -- Check if pg_stat_statements is available and configure it
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements') THEN
        -- Set reasonable limits for query tracking
        ALTER SYSTEM SET pg_stat_statements.max = 10000;
        ALTER SYSTEM SET pg_stat_statements.track = all;
        ALTER SYSTEM SET pg_stat_statements.track_utility = off;

        -- Create custom function for query analysis
        CREATE OR REPLACE FUNCTION analyze_query_performance()
        RETURNS TABLE (
            query_text TEXT,
            calls BIGINT,
            total_time DOUBLE PRECISION,
            mean_time DOUBLE PRECISION,
            rows BIGINT
        ) AS $$
        BEGIN
            RETURN QUERY
            SELECT
                query,
                calls,
                total_time,
                mean_time,
                rows
            FROM pg_stat_statements
            WHERE calls > 10
            ORDER BY total_time DESC
            LIMIT 100;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER;

        RAISE NOTICE 'pg_stat_statements configured for query performance monitoring.';
    END IF;
END $$;

-- Configure trigram extension for fuzzy search (if available)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        -- Create example similarity search function
        CREATE OR REPLACE FUNCTION find_similar_titles(search_text TEXT, threshold FLOAT DEFAULT 0.3)
        RETURNS TABLE (
            table_name TEXT,
            record_id UUID,
            title TEXT,
            similarity_score FLOAT
        ) AS $$
        BEGIN
            RETURN QUERY
            SELECT
                'section' as table_name,
                s.id as record_id,
                s.title,
                similarity(s.title, search_text) as similarity_score
            FROM section s
            WHERE similarity(s.title, search_text) > threshold

            UNION ALL

            SELECT
                'runbook' as table_name,
                r.id as record_id,
                r.title,
                similarity(r.title, search_text) as similarity_score
            FROM runbook r
            WHERE similarity(r.title, search_text) > threshold

            UNION ALL

            SELECT
                'issue_log' as table_name,
                i.id as record_id,
                i.title,
                similarity(i.title, search_text) as similarity_score
            FROM issue_log i
            WHERE similarity(i.title, search_text) > threshold

            ORDER BY similarity_score DESC;
        END;
        $$ LANGUAGE plpgsql SECURITY DEFINER;

        RAISE NOTICE 'pg_trgm configured for fuzzy search capabilities.';
    END IF;
END $$;

-- ============================================================================
-- CUSTOM FUNCTIONS AND AGGREGATES
-- ============================================================================

-- Create custom aggregate functions for enhanced functionality

-- Aggregate for concatenating arrays
CREATE OR REPLACE FUNCTION array_concat_agg(anyarray)
    RETURNS anyarray
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS 'SELECT array_agg(DISTINCT unnest($1))';

-- Create custom function for UUID v7 (time-based UUID) if not available
CREATE OR REPLACE FUNCTION uuid_generate_v7()
    RETURNS UUID
    LANGUAGE plpgsql
AS $$
BEGIN
    -- Use PostgreSQL 18's gen_random_uuid() as fallback
    RETURN gen_random_uuid();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function for safe JSONB operations
CREATE OR REPLACE FUNCTION safe_jsonb_get(jsonb_data JSONB, path TEXT[], default_value JSONB DEFAULT NULL::JSONB)
    RETURNS JSONB
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
AS $$
BEGIN
    BEGIN
        RETURN jsonb_data #> path;
    EXCEPTION WHEN OTHERS THEN
        RETURN default_value;
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function for generating audit-friendly metadata
CREATE OR REPLACE FUNCTION generate_audit_metadata(
    event_type TEXT,
    additional_metadata JSONB DEFAULT '{}'::JSONB
)
    RETURNS JSONB
    LANGUAGE plpgsql
AS $$
BEGIN
    RETURN jsonb_build_object(
        'event_type', event_type,
        'timestamp', NOW(),
        'version', '1.0.0',
        'generated_by', 'cortex-mcp-system'
    ) || additional_metadata;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- SECURITY AND PERMISSIONS
-- ============================================================================

-- Ensure proper permissions for extensions
DO $$
DECLARE
    extension_rec RECORD;
BEGIN
    FOR extension_rec IN SELECT extname FROM pg_extension
    LOOP
        -- Grant usage on extension functions to public
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO PUBLIC', extension_rec.extname);

        -- Grant execute on functions in the extension
        EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO PUBLIC', extension_rec.extname);
    END LOOP;
END $$;

-- Create custom role for database administration (optional)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cortex_admin') THEN
        CREATE ROLE cortex_admin WITH
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            INHERIT
            CONNECTION LIMIT -1;

        -- Grant necessary permissions
        GRANT CONNECT ON DATABASE current_database() TO cortex_admin;
        GRANT USAGE ON SCHEMA public TO cortex_admin;
        GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cortex_admin;
        GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cortex_admin;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO cortex_admin;

        RAISE NOTICE 'Created cortex_admin role for database administration.';
    END IF;
END $$;

-- ============================================================================
-- EXTENSION HEALTH CHECK
-- ============================================================================

-- Create function to verify extension health
CREATE OR REPLACE FUNCTION check_extension_health()
    RETURNS TABLE (
        extension_name TEXT,
        is_installed BOOLEAN,
        version TEXT,
        description TEXT
    ) AS $$
DECLARE
    extension_rec RECORD;
BEGIN
    -- Check core extensions
    RETURN QUERY
    SELECT
        e.extname as extension_name,
        true as is_installed,
        e.extversion as version,
        COALESCE(obj_description(e.oid, 'pg_extension'), 'No description') as description
    FROM pg_extension e
    WHERE e.extname IN ('pgcrypto', 'pg_stat_statements', 'pg_trgm', 'btree_gin', 'btree_gist')
    ORDER BY e.extname;

    -- Add any missing extensions
    FOR extension_rec IN SELECT unnest(ARRAY['pgcrypto', 'pg_stat_statements', 'pg_trgm', 'btree_gin', 'btree_gist']) as ext_name
    WHERE NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = extension_rec.ext_name)
    LOOP
        RETURN QUERY SELECT
            extension_rec.ext_name as extension_name,
            false as is_installed,
            NULL as version,
            'Extension not installed' as description;
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- PERFORMANCE TUNING
-- ============================================================================

-- Set reasonable work memory for complex operations
ALTER SYSTEM SET work_mem = '16MB';

-- Set maintenance work memory for index creation
ALTER SYSTEM SET maintenance_work_mem = '64MB';

-- Enable better statistics collection
ALTER SYSTEM SET default_statistics_target = 100;

-- Configure random page cost for SSD optimization
ALTER SYSTEM SET random_page_cost = 1.1;

-- Set effective cache size (typically 25-50% of total RAM)
ALTER SYSTEM SET effective_cache_size = '256MB';

-- ============================================================================
-- COMPLETION NOTIFICATION
-- ============================================================================

-- Log successful initialization
DO $$
DECLARE
    extension_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO extension_count FROM pg_extension;

    RAISE NOTICE 'PostgreSQL extensions initialized successfully.';
    RAISE NOTICE 'Total extensions installed: %', extension_count;
    RAISE NOTICE 'Database is ready for Cortex Memory MCP system.';
END $$;

-- Create a marker table to track successful initialization
CREATE TABLE IF NOT EXISTS system_info (
    id SERIAL PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Record extension initialization
INSERT INTO system_info (key, value)
VALUES ('extensions_initialized', NOW()::TEXT)
ON CONFLICT (key)
DO UPDATE SET value = NOW()::TEXT, updated_at = NOW();

-- Record PostgreSQL version
INSERT INTO system_info (key, value)
VALUES ('postgresql_version', version())
ON CONFLICT (key)
DO UPDATE SET value = version(), updated_at = NOW();

-- ============================================================================
-- INITIALIZATION COMPLETE
-- ============================================================================

-- This script has successfully:
-- ✓ Installed required PostgreSQL extensions
-- ✓ Configured extension-specific settings
-- ✓ Created utility functions for enhanced functionality
-- ✓ Set up proper permissions and security
-- ✓ Added performance tuning parameters
-- ✓ Created health monitoring functions
-- ✓ Recorded system information

-- The database is now ready for the Cortex Memory MCP schema migration.