-- Migration: Align Database Schema with Prisma Models
-- This migration fixes the schema mismatches discovered during comprehensive testing

-- Ensure section table has all required columns with proper constraints
DO $$
BEGIN
    -- Add content_hash column if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'content_hash') THEN
        ALTER TABLE section ADD COLUMN content_hash TEXT;
        CREATE INDEX idx_section_content_hash ON section(content_hash);
    END IF;

    -- Ensure title column exists and is properly constrained
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'title') THEN
        ALTER TABLE section ADD COLUMN title VARCHAR(500) NOT NULL DEFAULT '';
    ELSE
        -- Ensure title column is NOT NULL
        ALTER TABLE section ALTER COLUMN title SET NOT NULL;
        ALTER TABLE section ALTER COLUMN title SET DEFAULT '';
    END IF;

    -- Ensure heading column exists and is properly constrained
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'heading') THEN
        ALTER TABLE section ADD COLUMN heading VARCHAR(300) NOT NULL DEFAULT '';
    ELSE
        -- Ensure heading column is NOT NULL
        ALTER TABLE section ALTER COLUMN heading SET NOT NULL;
        ALTER TABLE section ALTER COLUMN heading SET DEFAULT '';
    END IF;

    -- Ensure body_jsonb column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'body_jsonb') THEN
        ALTER TABLE section ADD COLUMN body_jsonb JSONB
        GENERATED ALWAYS AS (
            jsonb_build_object(
                'text', COALESCE(body_text, ''),
                'markdown', COALESCE(body_md, '')
            )
        ) STORED;
    END IF;

    -- Add proper indexes for section table
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'section' AND indexname = 'idx_section_title') THEN
        CREATE INDEX idx_section_title ON section(title);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'section' AND indexname = 'idx_section_tags') THEN
        CREATE INDEX idx_section_tags ON section USING GIN(tags);
    END IF;

    -- Fix any existing rows with empty title or heading
    UPDATE section
    SET title = COALESCE(NULLIF(TRIM(title), ''), 'Untitled Section'),
        heading = COALESCE(NULLIF(TRIM(heading), ''), title)
    WHERE title = '' OR heading = '' OR title IS NULL OR heading IS NULL;
END $$;

-- Ensure ADR decision table has proper structure
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'adr_decision' AND column_name = 'alternatives_considered') THEN
        ALTER TABLE adr_decision ADD COLUMN alternatives_considered TEXT[];
    END IF;

    -- Add indexes for ADR decision table
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'adr_decision' AND indexname = 'idx_adr_decision_status') THEN
        CREATE INDEX idx_adr_decision_status ON adr_decision(status);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'adr_decision' AND indexname = 'idx_adr_decision_component') THEN
        CREATE INDEX idx_adr_decision_component ON adr_decision(component);
    END IF;
END $$;

-- Ensure issue_log table has proper structure
DO $$
BEGIN
    -- Add unique constraint if missing
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'unique_issue_tracker_external') THEN
        ALTER TABLE issue_log ADD CONSTRAINT unique_issue_tracker_external
        UNIQUE (tracker, external_id);
    END IF;

    -- Add indexes for issue_log table
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'issue_log' AND indexname = 'idx_issue_status') THEN
        CREATE INDEX idx_issue_status ON issue_log(status);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'issue_log' AND indexname = 'idx_issue_severity') THEN
        CREATE INDEX idx_issue_severity ON issue_log(severity);
    END IF;
END $$;

-- Ensure todo_log table has proper structure
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'todo_log' AND indexname = 'idx_todo_status') THEN
        CREATE INDEX idx_todo_status ON todo_log(status);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'todo_log' AND indexname = 'idx_todo_priority') THEN
        CREATE INDEX idx_todo_priority ON todo_log(priority);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'todo_log' AND indexname = 'idx_todo_due_date') THEN
        CREATE INDEX idx_todo_due_date ON todo_log(due_date);
    END IF;
END $$;

-- Ensure change_log table has proper structure
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'change_log' AND column_name = 'affected_files') THEN
        ALTER TABLE change_log ADD COLUMN affected_files TEXT[];
    END IF;

    -- Add indexes for change_log table
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'change_log' AND indexname = 'idx_change_type') THEN
        CREATE INDEX idx_change_type ON change_log(change_type);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'change_log' AND indexname = 'idx_change_commit_sha') THEN
        CREATE INDEX idx_change_commit_sha ON change_log(commit_sha);
    END IF;
END $$;

-- Update existing data to ensure consistency
DO $$
BEGIN
    -- Fix any sections with missing titles by using heading as fallback
    UPDATE section
    SET title = heading
    WHERE title = '' OR title IS NULL;

    -- Fix any sections with missing headings by using title as fallback
    UPDATE section
    SET heading = title
    WHERE heading = '' OR heading IS NULL;

    -- Ensure all sections have both title and heading
    UPDATE section
    SET title = 'Generated Section ' || EXTRACT(EPOCH FROM NOW())::text,
        heading = 'Generated Section ' || EXTRACT(EPOCH FROM NOW())::text
    WHERE (title = '' OR title IS NULL) OR (heading = '' OR heading IS NULL);

    -- Generate content hashes for existing sections
    UPDATE section
    SET content_hash = ENCODE(SHA256(title::bytea || COALESCE(body_md, '')::bytea || COALESCE(body_text, '')::bytea), 'hex')
    WHERE content_hash IS NULL;
END $$;

-- Add validation comments for documentation
COMMENT ON TABLE section IS 'Documentation sections with proper title/heading constraints';
COMMENT ON COLUMN section.title IS 'Required title field (max 500 chars) - validated by application';
COMMENT ON COLUMN section.heading IS 'Required heading field (max 300 chars) - validated by application';
COMMENT ON COLUMN section.content_hash IS 'Content hash for deduplication and similarity detection';
COMMENT ON COLUMN section.body_jsonb IS 'Generated JSONB column containing structured content';