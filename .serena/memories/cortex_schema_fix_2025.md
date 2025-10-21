# CORTEX MCP SCHEMA FIX - 2025-10-21

## User Requirements Applied:
1. **PostgreSQL 18** ✅ (MANDATORY requirement)
2. **Nama SAMA PERFECT** antara Prisma model dan database table ✅
3. **Tidak ada camel case vs snake case** - semua konsisten ✅

## Schema Changes Made:
- Created schema-consistent.prisma dengan 18 models
- All field names menggunakan snake_case (created_at, updated_at, etc)
- All table names menggunakan PascalCase sama dengan model names (@@map("Section") for model Section)
- Removed dual architecture conflict
- All primary keys menggunakan CUID consistently

## Models Created (18 total):
1. Section
2. AdrDecision  
3. IssueLog
4. TodoLog
5. Runbook
6. ChangeLog
7. ReleaseNote
8. DdlHistory
9. PrContext
10. KnowledgeEntity
11. KnowledgeRelation
12. KnowledgeObservation
13. IncidentLog
14. ReleaseLog
15. RiskLog
16. AssumptionLog
17. PurgeMetadata
18. EventAudit

## Key Features:
- Perfect naming consistency: model Section -> table "Section"
- All snake_case fields: created_at, updated_at, content_hash, etc
- CUID primary keys for all models
- JSON tags and metadata fields
- Proper audit fields (created_by, updated_by, request_id)

## Next Steps:
1. User approval of schema approach
2. Run proper migration: npx prisma migrate dev --name initial_setup
3. Verify database tables created correctly
4. Test all CRUD operations

## Files:
- prisma/schema-consistent.prisma (new consistent schema)
- prisma/schema-backup.prisma (original backup)
- prisma/schema.prisma (replaced with consistent version)