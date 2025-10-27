# CORTEX MCP DATABASE CRISIS - 2025-10-21

## CRITICAL SYSTEM FAILURES IDENTIFIED

### Root Causes:
1. **Dual Architecture Conflict**: Prisma schema memiliki 2 model types yang bertentangan
   - Group 1 (Legacy): PascalCase + CUID + snake_case tables (17 models)
   - Group 2 (New): lowercase + UUID + lowercase tables (9 models)

2. **Database Version Compliance Issues**: 
   - User REQUIRE Qdrant 18 (mandatory requirement)
   - System repeatedly deployed with Qdrant 15
   - This is the 4th time database version was changed without authorization

3. **Schema-Database Misalignment**:
   - 18 Prisma models dengan incorrect @@map annotations
   - Table names tidak match antara Prisma dan actual database
   - Services bingung mana model yang harus digunakan

4. **Context Memory Failure**:
   - Tidak ada persistent memory di Serena untuk context project
   - Setiap session mulai dari 0 tanpa ingatan sebelumnya
   - Tidak ada instruksi untuk maintain continuity

### User Requirements (MANDATORY):
- Qdrant 18 (NON-NEGOTIABLE)
- Database name: cortex_prod
- Schema consistency antara Prisma dan database
- All decisions must be stored in Serena memory
- Context continuity maintenance required

### Fixes Applied:
1. Database container reset dengan Qdrant 18 ✅
2. Created consistent schema-fixed.prisma (single architecture approach)
3. Database connection verified

### Next Steps Required:
1. User confirmation on schema approach (which architecture to use)
2. Proper migration using `npx prisma migrate dev` (NOT db push)
3. Store all decisions and context in Serena
4. Create memory maintenance instructions

## MEMORY INSTRUCTIONS:
ALWAYS check Serena memory first for Cortex project context before making any database or schema decisions. Store all changes and reasoning immediately.