# Schema Alignment Implementation Guide
## Agent 2: Complete Fix Implementation

**Date:** 2025-10-21
**Status:** Ready for Implementation
**Criticality:** BLOCKS ALL FUNCTIONALITY

---

## 🚨 IMMEDIATE ACTION REQUIRED

The Cortex MCP system is **completely non-functional** due to Prisma schema mapping issues. Follow this implementation guide **exactly** to restore functionality.

---

## Implementation Order (CRITICAL)

### Phase 1: Emergency Fixes (30 minutes)
**This will restore basic functionality**

#### 1.1 Fix Prisma Schema Mappings
```bash
# Edit prisma/schema.prisma file
# Update ALL 16 model mappings from lowercase to snake_case:

# BEFORE (INCORRECT):
model AdrDecision {
  # ... fields ...
  @@map("adrdecision")  # ❌ WRONG
}

# AFTER (CORRECT):
model AdrDecision {
  # ... fields ...
  @@map("adr_decision")  # ✅ CORRECT
}

# Apply to ALL these models:
- AdrDecision -> "adr_decision"
- IssueLog -> "issue_log"
- TodoLog -> "todo_log"
- ChangeLog -> "change_log"
- ReleaseNote -> "release_note"
- DdlHistory -> "ddl_history"
- PrContext -> "pr_context"
- KnowledgeEntity -> "knowledge_entity"
- KnowledgeRelation -> "knowledge_relation"
- KnowledgeObservation -> "knowledge_observation"
- IncidentLog -> "incident_log"
- ReleaseLog -> "release_log"
- RiskLog -> "risk_log"
- AssumptionLog -> "assumption_log"
- PurgeMetadata -> "purge_metadata"
- EventAudit -> "event_audit"
```

#### 1.2 Regenerate Prisma Client
```bash
cd "D:\WORKSPACE\tools-node\mcp-cortex"
npx prisma generate
```

#### 1.3 Verify Schema Alignment
```bash
npx prisma db pull
# Should show "No changes" if mappings are correct
```

#### 1.4 Test Basic Functionality
```bash
# Test database connection
npm run dev

# Run basic test
node -e "
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
prisma.section.findMany().then(r => console.log('✅ Database connection works:', r.length, 'sections'));
"
```

### Phase 2: Data Integrity (45 minutes)
**Critical for production stability**

#### 2.1 Add Foreign Key Constraints
```bash
# Execute the foreign key SQL script
psql "postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod" -f add-foreign-keys.sql
```

#### 2.2 Standardize Timestamps
```bash
# Execute timestamp standardization script
psql "postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod" -f standardize-timestamps.sql
```

### Phase 3: Performance Optimization (15 minutes)
**Important for scalability**

#### 3.1 Add Performance Indexes
```bash
# Execute performance indexes script
psql "postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod" -f add-performance-indexes.sql
```

#### 3.2 Create Database Triggers (Optional)
```bash
# Execute triggers script for automation
psql "postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod" -f create-triggers.sql
```

---

## Verification Checklist

### ✅ Phase 1 Verification
- [ ] Prisma schema updated with correct table mappings
- [ ] `npx prisma generate` completes without errors
- [ ] `npx prisma db pull` shows "No changes"
- [ ] Basic database queries work
- [ ] No "table does not exist" errors

### ✅ Phase 2 Verification
- [ ] Foreign key constraints created successfully
- [ ] All timestamps converted to TIMESTAMPTZ
- [ ] No data integrity constraint violations

### ✅ Phase 3 Verification
- [ ] Performance indexes created
- [ ] Query performance improved
- [ ] Database triggers functioning (if applied)

---

## Critical Success Indicators

### Before Fix (❌ BROKEN)
```
Error: Table "adrdecision" doesn't exist
Error: Table "issuelog" doesn't exist
Error: Table "todolog" doesn't exist
```

### After Fix (✅ WORKING)
```
✅ Database connection established
✅ Found X sections
✅ Found X issues
✅ Found X todos
✅ All CRUD operations working
```

---

## Rollback Plan

If something goes wrong during implementation:

### 1. Prisma Schema Rollback
```bash
git checkout HEAD -- prisma/schema.prisma
npx prisma generate
```

### 2. Database Changes Rollback
```bash
# Foreign key constraints can be safely dropped later if needed
# Timestamp changes are backward compatible
# Indexes can be dropped if performance issues occur
```

---

## Testing Requirements

### 1. Basic Functionality Tests
```bash
# Test each major table type
node -e "
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

Promise.all([
  prisma.section.count(),
  prisma.adrDecision.count(),
  prisma.issueLog.count(),
  prisma.todoLog.count(),
  prisma.entity.count(),
  prisma.relation.count(),
  prisma.observation.count(),
  prisma.incident.count(),
  prisma.release.count(),
  prisma.risk.count(),
  prisma.assumption.count()
]).then(([sections, decisions, issues, todos, entities, relations, observations, incidents, releases, risks, assumptions]) => {
  console.log('✅ All tables accessible:');
  console.log('  Sections:', sections);
  console.log('  Decisions:', decisions);
  console.log('  Issues:', issues);
  console.log('  Todos:', todos);
  console.log('  Entities:', entities);
  console.log('  Relations:', relations);
  console.log('  Observations:', observations);
  console.log('  Incidents:', incidents);
  console.log('  Releases:', releases);
  console.log('  Risks:', risks);
  console.log('  Assumptions:', assumptions);
}).catch(console.error);
"
```

### 2. Relationship Tests
```bash
# Test foreign key constraints work
node -e "
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient');

async function testRelationships() {
  try {
    // Create entity
    const entity = await prisma.entity.create({
      data: {
        name: 'Test Entity',
        type: 'test'
      }
    });

    // Create observation for that entity
    const observation = await prisma.observation.create({
      data: {
        entityId: entity.id,
        fact: 'Test observation'
      }
    });

    console.log('✅ Foreign key relationships working');

    // Cleanup
    await prisma.observation.delete({ where: { id: observation.id } });
    await prisma.entity.delete({ where: { id: entity.id } });
  } catch (error) {
    console.error('❌ Relationship test failed:', error);
  }
}

testRelationships();
"
```

### 3. MCP Server Tests
```bash
# Start the MCP server
npm start

# Test basic memory operations
# (Use your MCP client to test)
```

---

## Post-Implementation Monitoring

### 1. Database Performance
```sql
-- Monitor index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;

-- Monitor slow queries
SELECT query, mean_time, calls
FROM pg_stat_statements
WHERE mean_time > 100
ORDER BY mean_time DESC;
```

### 2. Application Logs
```bash
# Monitor for database errors
tail -f logs/app.log | grep -i "database\|prisma\|error"
```

### 3. MCP Functionality
- Test all memory operations (store, find, update, delete)
- Test relationship creation and retrieval
- Test scope isolation (project/branch/org)
- Test search functionality

---

## Success Metrics

### ✅ Functionality Restored
- [ ] All 26 database tables accessible via Prisma
- [ ] Basic CRUD operations work on all tables
- [ ] Foreign key relationships enforced
- [ ] MCP server responds to all requests

### ✅ Performance Optimized
- [ ] Query response times < 100ms for simple queries
- [ ] Content hash deduplication working
- [ ] Branch isolation performing efficiently

### ✅ Data Integrity Ensured
- [ ] No orphaned records
- [ ] Consistent timestamp handling
- [ ] Proper scope isolation working

---

## Emergency Contact

If implementation fails:
1. **Stop immediately** - Don't proceed to next phase
2. **Rollback** using the rollback plan above
3. **Document** what failed and where
4. **Contact** the development team with specific error messages

**DO NOT** proceed with Phase 2 until Phase 1 is working perfectly.
**DO NOT** proceed with Phase 3 until Phase 2 is working perfectly.

---

## Implementation Status

- [ ] Phase 1: Emergency Fixes - **CRITICAL BLOCKER**
- [ ] Phase 2: Data Integrity - **HIGH PRIORITY**
- [ ] Phase 3: Performance Optimization - **MEDIUM PRIORITY**

**Current Status:** 🚨 **SYSTEM NON-FUNCTIONAL** - Phase 1 must be completed immediately

---

**Next Steps:** Execute Phase 1 immediately, then proceed to Phase 2 and 3 only after verification.