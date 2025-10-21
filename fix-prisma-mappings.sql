-- Fix Prisma Schema Mappings
-- CRITICAL: These corrections must be applied to prisma/schema.prisma

-- This file contains the corrected Prisma model mappings
-- Apply these changes to prisma/schema.prisma file

-- CORRECTION 1: Update AdrDecision model
-- CURRENT (incorrect):
-- @@map("adrdecision")
-- CORRECT:
-- @@map("adr_decision")

-- CORRECTION 2: Update IssueLog model
-- CURRENT (incorrect):
-- @@map("issuelog")
-- CORRECT:
-- @@map("issue_log")

-- CORRECTION 3: Update TodoLog model
-- CURRENT (incorrect):
-- @@map("todolog")
-- CORRECT:
-- @@map("todo_log")

-- CORRECTION 4: Update ChangeLog model
-- CURRENT (incorrect):
-- @@map("changelog")
-- CORRECT:
-- @@map("change_log")

-- CORRECTION 5: Update ReleaseNote model
-- CURRENT (incorrect):
-- @@map("releasenote")
-- CORRECT:
-- @@map("release_note")

-- CORRECTION 6: Update DdlHistory model
-- CURRENT (incorrect):
-- @@map("ddlhistory")
-- CORRECT:
-- @@map("ddl_history")

-- CORRECTION 7: Update PrContext model
-- CURRENT (incorrect):
-- @@map("prcontext")
-- CORRECT:
-- @@map("pr_context")

-- CORRECTION 8: Update KnowledgeEntity model
-- CURRENT (incorrect):
-- @@map("knowledgeentity")
-- CORRECT:
-- @@map("knowledge_entity")

-- CORRECTION 9: Update KnowledgeRelation model
-- CURRENT (incorrect):
-- @@map("knowledgerelation")
-- CORRECT:
-- @@map("knowledge_relation")

-- CORRECTION 10: Update KnowledgeObservation model
-- CURRENT (incorrect):
-- @@map("knowledgeobservation")
-- CORRECT:
-- @@map("knowledge_observation")

-- CORRECTION 11: Update IncidentLog model
-- CURRENT (incorrect):
-- @@map("incidentlog")
-- CORRECT:
-- @@map("incident_log")

-- CORRECTION 12: Update ReleaseLog model
-- CURRENT (incorrect):
-- @@map("releaselog")
-- CORRECT:
-- @@map("release_log")

-- CORRECTION 13: Update RiskLog model
-- CURRENT (incorrect):
-- @@map("risklog")
-- CORRECT:
-- @@map("risk_log")

-- CORRECTION 14: Update AssumptionLog model
-- CURRENT (incorrect):
-- @@map("assumptionlog")
-- CORRECT:
-- @@map("assumption_log")

-- CORRECTION 15: Update PurgeMetadata model
-- CURRENT (incorrect):
-- @@map("purgemetadata")
-- CORRECT:
-- @@map("purge_metadata")

-- CORRECTION 16: Update EventAudit model
-- CURRENT (incorrect):
-- @@map("eventaudit")
-- CORRECT:
-- @@map("event_audit")

-- SESSION-LOGS TABLES: Ensure these are correctly mapped (lowercase)
-- These should remain as they are since the tables exist with these names:
-- @@map("assumption")     - CORRECT
-- @@map("ddl_log")        - CORRECT
-- @@map("entity")         - CORRECT
-- @@map("incident")       - CORRECT
-- @@map("observation")    - CORRECT
-- @@map("relation")       - CORRECT
-- @@map("release")        - CORRECT
-- @@map("risk")           - CORRECT

-- IMPLEMENTATION STEPS:
-- 1. Apply these corrections to prisma/schema.prisma
-- 2. Run: npx prisma generate
-- 3. Run: npx prisma db pull (to verify mappings)
-- 4. Test basic CRUD operations

-- VERIFICATION QUERY:
-- After applying fixes, run this to verify all models map to existing tables:
/*
SELECT
    pm.model_name,
    pm.table_name,
    CASE
        WHEN t.table_name IS NOT NULL THEN '✅ EXISTS'
        ELSE '❌ MISSING'
    END as status
FROM (
    -- Extract model mappings from corrected Prisma schema
    SELECT 'AdrDecision' as model_name, 'adr_decision' as table_name
    UNION ALL SELECT 'IssueLog', 'issue_log'
    UNION ALL SELECT 'TodoLog', 'todo_log'
    UNION ALL SELECT 'ChangeLog', 'change_log'
    UNION ALL SELECT 'ReleaseNote', 'release_note'
    UNION ALL SELECT 'DdlHistory', 'ddl_history'
    UNION ALL SELECT 'PrContext', 'pr_context'
    UNION ALL SELECT 'KnowledgeEntity', 'knowledge_entity'
    UNION ALL SELECT 'KnowledgeRelation', 'knowledge_relation'
    UNION ALL SELECT 'KnowledgeObservation', 'knowledge_observation'
    UNION ALL SELECT 'IncidentLog', 'incident_log'
    UNION ALL SELECT 'ReleaseLog', 'release_log'
    UNION ALL SELECT 'RiskLog', 'risk_log'
    UNION ALL SELECT 'AssumptionLog', 'assumption_log'
    UNION ALL SELECT 'PurgeMetadata', 'purge_metadata'
    UNION ALL SELECT 'EventAudit', 'event_audit'
    UNION ALL SELECT 'assumption', 'assumption'
    UNION ALL SELECT 'ddl_log', 'ddl_log'
    UNION ALL SELECT 'entity', 'entity'
    UNION ALL SELECT 'incident', 'incident'
    UNION ALL SELECT 'observation', 'observation'
    UNION ALL SELECT 'relation', 'relation'
    UNION ALL SELECT 'release', 'release'
    UNION ALL SELECT 'risk', 'risk'
) pm
LEFT JOIN information_schema.tables t ON t.table_name = pm.table_name AND t.table_schema = 'public'
ORDER BY pm.model_name;
*/