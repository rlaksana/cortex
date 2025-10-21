-- Add Missing Foreign Key Constraints
-- Priority 2: HIGH - Critical for data integrity

-- Execute these SQL statements after fixing Prisma mappings

-- FOREIGN KEY CONSTRAINT: observation.entity_id -> entity.id
DO $$
BEGIN
    -- Check if constraint already exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_observation_entity'
        AND table_name = 'observation'
        AND table_schema = 'public'
    ) THEN
        -- Add the foreign key constraint
        ALTER TABLE observation
        ADD CONSTRAINT fk_observation_entity
        FOREIGN KEY (entity_id) REFERENCES entity(id) ON DELETE CASCADE;

        RAISE NOTICE '✅ Added foreign key constraint: observation.entity_id -> entity.id';
    ELSE
        RAISE NOTICE '⚠️  Foreign key constraint already exists: observation.entity_id -> entity.id';
    END IF;
END $$;

-- FOREIGN KEY CONSTRAINT: relation.source_entity_id -> entity.id
DO $$
BEGIN
    -- Check if constraint already exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_relation_source_entity'
        AND table_name = 'relation'
        AND table_schema = 'public'
    ) THEN
        -- Add the foreign key constraint
        ALTER TABLE relation
        ADD CONSTRAINT fk_relation_source_entity
        FOREIGN KEY (source_entity_id) REFERENCES entity(id) ON DELETE CASCADE;

        RAISE NOTICE '✅ Added foreign key constraint: relation.source_entity_id -> entity.id';
    ELSE
        RAISE NOTICE '⚠️  Foreign key constraint already exists: relation.source_entity_id -> entity.id';
    END IF;
END $$;

-- FOREIGN KEY CONSTRAINT: relation.target_entity_id -> entity.id
DO $$
BEGIN
    -- Check if constraint already exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_relation_target_entity'
        AND table_name = 'relation'
        AND table_schema = 'public'
    ) THEN
        -- Add the foreign key constraint
        ALTER TABLE relation
        ADD CONSTRAINT fk_relation_target_entity
        FOREIGN KEY (target_entity_id) REFERENCES entity(id) ON DELETE CASCADE;

        RAISE NOTICE '✅ Added foreign key constraint: relation.target_entity_id -> entity.id';
    ELSE
        RAISE NOTICE '⚠️  Foreign key constraint already exists: relation.target_entity_id -> entity.id';
    END IF;
END $$;

-- ADD INDEXES for foreign key performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_observation_entity_id
ON observation (entity_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_relation_source_entity_id
ON relation (source_entity_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_relation_target_entity_id
ON relation (target_entity_id);

RAISE NOTICE '✅ Added foreign key indexes for performance';

-- VERIFICATION QUERIES
-- Run these to verify the foreign key constraints were added correctly:

-- 1. Check foreign key constraints on observation table
/*
SELECT
    tc.constraint_name,
    tc.constraint_type,
    kcu.column_name,
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name,
    rc.update_rule,
    rc.delete_rule
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
    ON tc.constraint_name = kcu.constraint_name
    AND tc.table_schema = kcu.table_schema
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = tc.constraint_name
    AND ccu.table_schema = tc.table_schema
JOIN information_schema.referential_constraints AS rc
    ON tc.constraint_name = rc.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY'
    AND tc.table_name = 'observation'
    AND tc.table_schema = 'public';
*/

-- 2. Check foreign key constraints on relation table
/*
SELECT
    tc.constraint_name,
    tc.constraint_type,
    kcu.column_name,
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name,
    rc.update_rule,
    rc.delete_rule
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
    ON tc.constraint_name = kcu.constraint_name
    AND tc.table_schema = kcu.table_schema
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = tc.constraint_name
    AND ccu.table_schema = tc.table_schema
JOIN information_schema.referential_constraints AS rc
    ON tc.constraint_name = rc.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY'
    AND tc.table_name = 'relation'
    AND tc.table_schema = 'public';
*/

-- 3. Test foreign key integrity
/*
-- Test: Try to insert observation with non-existent entity_id (should fail)
BEGIN;
INSERT INTO observation (entity_id, fact) VALUES ('00000000-0000-0000-0000-000000000000', 'test');
ROLLBACK;

-- Test: Insert valid entity and observation (should succeed)
BEGIN;
INSERT INTO entity (id, name, type) VALUES ('123e4567-e89b-12d3-a456-426614174000', 'test-entity', 'test');
INSERT INTO observation (entity_id, fact) VALUES ('123e4567-e89b-12d3-a456-426614174000', 'test-observation');
ROLLBACK;
*/

RAISE NOTICE '✅ Foreign key constraints setup complete';