-- Fix Section Table - Critical for MCP Cortex functionality
-- This migration fixes the title/heading constraint violation discovered during testing

-- Check current state and add missing columns safely
DO $$
BEGIN
    -- Add content_hash column if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'content_hash') THEN
        ALTER TABLE section ADD COLUMN content_hash TEXT;
        CREATE INDEX idx_section_content_hash ON section(content_hash);
        RAISE NOTICE 'Added content_hash column';
    END IF;

    -- Ensure title column exists and is properly set
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'title') THEN
        ALTER TABLE section ADD COLUMN title VARCHAR(500);
        RAISE NOTICE 'Added title column';
    END IF;

    -- Update any NULL titles to have default values
    UPDATE section SET title = COALESCE(title, heading, 'Untitled Section') WHERE title IS NULL OR title = '';
    ALTER TABLE section ALTER COLUMN title SET NOT NULL;
    RAISE NOTICE 'Fixed title column constraints';

    -- Ensure heading column exists and is properly set
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'heading') THEN
        ALTER TABLE section ADD COLUMN heading VARCHAR(300);
        RAISE NOTICE 'Added heading column';
    END IF;

    -- Update any NULL headings to have default values
    UPDATE section SET heading = COALESCE(heading, title, 'Untitled Section') WHERE heading IS NULL OR heading = '';
    ALTER TABLE section ALTER COLUMN heading SET NOT NULL;
    RAISE NOTICE 'Fixed heading column constraints';

    -- Ensure body_jsonb column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'section' AND column_name = 'body_jsonb') THEN
        ALTER TABLE section ADD COLUMN body_jsonb JSONB DEFAULT '{}';
        RAISE NOTICE 'Added body_jsonb column';
    END IF;

    -- Generate content hashes for existing records
    UPDATE section
    SET content_hash = ENCODE(SHA256(title::bytea || COALESCE(body_md, '')::bytea || COALESCE(body_text, '')::bytea), 'hex')
    WHERE content_hash IS NULL;
    RAISE NOTICE 'Generated content hashes';

    -- Add essential indexes
    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'section' AND indexname = 'idx_section_title') THEN
        CREATE INDEX idx_section_title ON section(title);
        RAISE NOTICE 'Added title index';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes
                   WHERE tablename = 'section' AND indexname = 'idx_section_tags') THEN
        CREATE INDEX idx_section_tags ON section USING GIN(tags);
        RAISE NOTICE 'Added tags index';
    END IF;
END $$;

-- Verify the changes
SELECT
    column_name,
    data_type,
    is_nullable,
    character_maximum_length
FROM information_schema.columns
WHERE table_name = 'section'
AND column_name IN ('id', 'title', 'heading', 'content_hash', 'body_jsonb', 'tags')
ORDER BY column_name;