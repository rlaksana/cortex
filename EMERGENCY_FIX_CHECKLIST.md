# CORTEX MCP EMERGENCY FIX CHECKLIST

## STATUS: CRITICAL SYSTEM FAILURE
## Root Cause: Prisma Schema vs Database Mismatch

## IMMEDIATE ACTION ITEMS:

### 1. DATABASE RESET (IN PROGRESS)
- [x] Stop existing container: `wsl -d Ubuntu docker stop cortex-postgres`
- [x] Remove container: `wsl -d Ubuntu docker rm cortex-postgres`
- [x] Create fresh container: `wsl -d Ubuntu docker run -d --name cortex-postgres -e POSTGRES_DB=cortex_prod -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:15-alpine`
- [x] Verify container is running
- [x] Test database connection

### 2. SCHEMA FIXES (REQUIREMENT: NAMA SAMA DI PRISMA DAN DB)
- [ ] Fix schema to ensure table names identical between Prisma and database
- [ ] Remove dual model architecture - use single consistent approach
- [ ] Verify ALL field types and constraints match exactly
- [ ] User requirement: nama harus sama di Prisma dan database

### 3. PROPER MIGRATION WORKFLOW
- [ ] Delete any existing migration files
- [ ] Use `npx prisma migrate dev --name initial_setup` (NOT db push!)
- [ ] Run `npx prisma generate`
- [ ] Verify migration success

### 4. VALIDATION
- [ ] Check all tables exist with correct names
- [ ] Test basic CRUD operations
- [ ] Verify all 16 knowledge types work
- [ ] Test UUID validation
- [ ] Test relationships

### 5. SYSTEM TESTING
- [ ] Run Agent 1: Core functionality test
- [ ] Run Agent 2: Performance test
- [ ] Run Agent 3: Integration test
- [ ] Run Agent 4: Security test
- [ ] Run Agent 5: Documentation test

## CRITICAL ISSUES IDENTIFIED:
- 18 Prisma models with wrong @@map annotations
- Dual model architecture conflict (CUID vs UUID)
- 27 instances of raw SQL bypassing Prisma
- Type safety violations with `as any` casting
- Session-logs integration failures

## BEST PRACTICES TO IMPLEMENT:
- Always use `migrate dev` not `db push` for proper migrations
- Never mix raw SQL with Prisma operations
- Maintain schema consistency between database and Prisma
- Use proper TypeScript types, avoid `as any`
- Test schema changes in isolation

## NEXT STEPS AFTER FIXES:
1. Build system: `npm run build`
2. Restart Claude Code
3. Comprehensive testing with 5 agents
4. Document lessons learned

## DELETE THIS FILE WHEN ALL COMPLETED
## Created: 2025-10-21 (Emergency Fix Session)