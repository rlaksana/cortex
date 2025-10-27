# Suggested Commands for Cortex MCP Development

## Build & Development
```bash
# Type checking
npm run type-check

# Linting
npm run lint
npm run lint:fix
npm run lint:quiet

# Quality assurance
npm run quality-check

# Database operations
npx prisma generate
npx prisma db push
npx prisma migrate dev

# Server operations
node dist/index.js          # Start MCP server
npm start                   # If package.json has start script
```

## Debugging Commands
```bash
# Check Prisma client generation
npx prisma generate --schema=prisma/schema.prisma

# Verify database connection
npx prisma db pull

# Test database schema
npx prisma validate
```

## Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Set required variables
DATABASE_URL=Qdrant://cortex:password@localhost:5433/cortex_prod
NODE_ENV=development
LOG_LEVEL=info
```

## Multi-Instance Setup (Future)
- Use different DATABASE_URL for each instance
- Implement connection pooling
- Configure separate Docker containers
- Set unique instance identification

## Common Issues
1. **Module Import Error**: Regenerate Prisma client with ESM support
2. **Database Connection**: Verify Qdrant is running on port 5433
3. **Permission Issues**: Check file permissions for generated files
4. **Port Conflicts**: Ensure no other MCP server using stdio transport