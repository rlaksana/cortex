-- Standardize Timestamp Types
-- Priority 3: HIGH - Essential for consistency across timezones

-- Convert all legacy tables from TIMESTAMP to TIMESTAMPTZ
-- Execute these SQL statements after adding foreign keys

-- STANDARDIZE LEGACY TABLES TO TIMESTAMPTZ
-- =============================================

-- Table: section
DO $$
BEGIN
    -- Check if columns are already TIMESTAMPTZ
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'section'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE section
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE section
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized section timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  section timestamps already standardized';
    END IF;
END $$;

-- Table: adr_decision
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'adr_decision'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE adr_decision
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE adr_decision
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        -- Also standardize accepted_at if it exists
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'adr_decision'
            AND column_name = 'accepted_at'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE adr_decision
            ALTER COLUMN accepted_at TYPE TIMESTAMPTZ USING accepted_at AT TIME ZONE 'UTC';
        END IF;

        RAISE NOTICE '✅ Standardized adr_decision timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  adr_decision timestamps already standardized';
    END IF;
END $$;

-- Table: issue_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'issue_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE issue_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE issue_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized issue_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  issue_log timestamps already standardized';
    END IF;
END $$;

-- Table: todo_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'todo_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE todo_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE todo_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        -- Also standardize other timestamp columns
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'todo_log'
            AND column_name = 'due_date'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE todo_log
            ALTER COLUMN due_date TYPE TIMESTAMPTZ USING due_date AT TIME ZONE 'UTC';
        END IF;

        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'todo_log'
            AND column_name = 'closed_at'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE todo_log
            ALTER COLUMN closed_at TYPE TIMESTAMPTZ USING closed_at AT TIME ZONE 'UTC';
        END IF;

        RAISE NOTICE '✅ Standardized todo_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  todo_log timestamps already standardized';
    END IF;
END $$;

-- Table: runbook
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'runbook'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE runbook
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE runbook
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized runbook timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  runbook timestamps already standardized';
    END IF;
END $$;

-- Table: change_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'change_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE change_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE change_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized change_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  change_log timestamps already standardized';
    END IF;
END $$;

-- Table: release_note
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'release_note'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE release_note
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE release_note
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized release_note timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  release_note timestamps already standardized';
    END IF;
END $$;

-- Table: ddl_history
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'ddl_history'
        AND column_name = 'applied_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE ddl_history
        ALTER COLUMN applied_at TYPE TIMESTAMPTZ USING applied_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized ddl_history timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  ddl_history timestamps already standardized';
    END IF;
END $$;

-- Table: pr_context
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'pr_context'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE pr_context
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE pr_context
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        -- Also standardize merged_at if it exists
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'pr_context'
            AND column_name = 'merged_at'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE pr_context
            ALTER COLUMN merged_at TYPE TIMESTAMPTZ USING merged_at AT TIME ZONE 'UTC';
        END IF;

        RAISE NOTICE '✅ Standardized pr_context timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  pr_context timestamps already standardized';
    END IF;
END $$;

-- Table: knowledge_entity
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'knowledge_entity'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE knowledge_entity
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE knowledge_entity
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        -- Also standardize deleted_at if it exists
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'knowledge_entity'
            AND column_name = 'deleted_at'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE knowledge_entity
            ALTER COLUMN deleted_at TYPE TIMESTAMPTZ USING deleted_at AT TIME ZONE 'UTC';
        END IF;

        RAISE NOTICE '✅ Standardized knowledge_entity timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  knowledge_entity timestamps already standardized';
    END IF;
END $$;

-- Table: knowledge_observation
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'knowledge_observation'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE knowledge_observation
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE knowledge_observation
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        -- Also standardize deleted_at if it exists
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'knowledge_observation'
            AND column_name = 'deleted_at'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE knowledge_observation
            ALTER COLUMN deleted_at TYPE TIMESTAMPTZ USING deleted_at AT TIME ZONE 'UTC';
        END IF;

        RAISE NOTICE '✅ Standardized knowledge_observation timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  knowledge_observation timestamps already standardized';
    END IF;
END $$;

-- Table: knowledge_relation
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'knowledge_relation'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE knowledge_relation
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE knowledge_relation
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        -- Also standardize deleted_at if it exists
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'knowledge_relation'
            AND column_name = 'deleted_at'
            AND data_type = 'timestamp without time zone'
            AND table_schema = 'public'
        ) THEN
            ALTER TABLE knowledge_relation
            ALTER COLUMN deleted_at TYPE TIMESTAMPTZ USING deleted_at AT TIME ZONE 'UTC';
        END IF;

        RAISE NOTICE '✅ Standardized knowledge_relation timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  knowledge_relation timestamps already standardized';
    END IF;
END $$;

-- Table: incident_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'incident_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE incident_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE incident_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized incident_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  incident_log timestamps already standardized';
    END IF;
END $$;

-- Table: release_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'release_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE release_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE release_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized release_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  release_log timestamps already standardized';
    END IF;
END $$;

-- Table: risk_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'risk_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE risk_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE risk_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized risk_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  risk_log timestamps already standardized';
    END IF;
END $$;

-- Table: assumption_log
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'assumption_log'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE assumption_log
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE assumption_log
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized assumption_log timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  assumption_log timestamps already standardized';
    END IF;
END $$;

-- Table: purge_metadata
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'purge_metadata'
        AND column_name = 'last_purge_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE purge_metadata
        ALTER COLUMN last_purge_at TYPE TIMESTAMPTZ USING last_purge_at AT TIME ZONE 'UTC';

        ALTER TABLE purge_metadata
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        ALTER TABLE purge_metadata
        ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized purge_metadata timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  purge_metadata timestamps already standardized';
    END IF;
END $$;

-- Table: event_audit
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'event_audit'
        AND column_name = 'created_at'
        AND data_type = 'timestamp without time zone'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE event_audit
        ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';

        RAISE NOTICE '✅ Standardized event_audit timestamps to TIMESTAMPTZ';
    ELSE
        RAISE NOTICE '⚠️  event_audit timestamps already standardized';
    END IF;
END $$;

RAISE NOTICE '✅ Timestamp standardization complete - all tables now use TIMESTAMPTZ';

-- VERIFICATION QUERY
-- Run this to verify all timestamp columns are now TIMESTAMPTZ:
/*
SELECT
    table_name,
    column_name,
    data_type
FROM information_schema.columns
WHERE data_type LIKE '%timestamp%'
    AND table_schema = 'public'
    AND table_name NOT LIKE '_%'
ORDER BY table_name, column_name;
*/