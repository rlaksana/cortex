# CORTEX MCP PROJECT - MANDATORY REQUIREMENTS

## Database Requirements (NON-NEGOTIABLE):
- **Qdrant Version**: 18 (REQUIRED - user explicitly warned mandatory)
- **Database Name**: cortex_prod 
- **Port**: 5433
- **User**: qdrant
- **Password**: qdrant

## Architecture Requirements:
- Single consistent Prisma schema (NO dual architecture)
- Snake_case table names in database
- PascalCase model names in Prisma with proper @@map
- CUID primary keys (consistent approach)
- Type safety enforcement - NO raw SQL bypassing

## Development Workflow Requirements:
- Use `npx prisma migrate dev` for migrations (NOT db push)
- Always regenerate Prisma client after schema changes
- Verify schema alignment with `npx prisma migrate diff`
- Never mix raw SQL with Prisma operations

## Memory Management Requirements:
- Store ALL project context in Serena memory
- Check Serena memory before any database changes
- Update memory immediately after decisions
- Maintain session continuity across conversations

## Critical Constraints:
- NEVER change database version without explicit user approval
- ALWAYS ask user confirmation before schema changes
- NEVER assume context - always read Serena memory first
- DOCUMENT all decisions and reasoning in memory

## Error Recovery:
- If schema drift detected: reset database and reapply migrations
- If version mismatch: stop immediately and ask user
- If memory gap: read Serena memory before proceeding

## Approval Workflow:
1. Read Serena memory for context
2. Present proposed changes to user
3. Get explicit approval
4. Execute changes
5. Update Serena memory with results