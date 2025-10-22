#!/bin/bash

# Database Setup Script for mcp-cortex
# This script configures PostgreSQL in WSL2 for the mcp-cortex project

set -e

echo "🚀 Setting up mcp-cortex database configuration..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DB_USER="cortex"
DB_PASSWORD="cortex_pg18_secure_2025_key"
DB_NAME="cortex_prod"
DB_HOST="localhost"
DB_PORT="5432"

echo -e "${YELLOW}Checking WSL2 PostgreSQL service...${NC}"

# Check if PostgreSQL is running in WSL2
if ! wsl -d Ubuntu bash -c "systemctl is-active --quiet postgresql"; then
    echo -e "${YELLOW}Starting PostgreSQL service...${NC}"
    wsl -d Ubuntu bash -c "sudo systemctl start postgresql"
    wsl -d Ubuntu bash -c "sudo systemctl enable postgresql"
fi

echo -e "${GREEN}✅ PostgreSQL service is running${NC}"

# Check if user exists
USER_EXISTS=$(wsl -d Ubuntu bash -c "sudo -u postgres psql -tAc \"SELECT 1 FROM pg_user WHERE usename = '$DB_USER'\"")

if [ -z "$USER_EXISTS" ]; then
    echo -e "${YELLOW}Creating database user: $DB_USER${NC}"
    wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';\""
    echo -e "${GREEN}✅ User $DB_USER created${NC}"
else
    echo -e "${GREEN}✅ User $DB_USER already exists${NC}"
fi

# Check if database exists
DB_EXISTS=$(wsl -d Ubuntu bash -c "sudo -u postgres psql -tAc \"SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'\"")

if [ -z "$DB_EXISTS" ]; then
    echo -e "${YELLOW}Creating database: $DB_NAME${NC}"
    wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\""
    wsl -d Ubuntu bash -c "sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;\""
    echo -e "${GREEN}✅ Database $DB_NAME created${NC}"
else
    echo -e "${GREEN}✅ Database $DB_NAME already exists${NC}"
fi

# Update .env file
echo -e "${YELLOW}Updating .env configuration...${NC}"

# Backup existing .env file
if [ -f ".env" ]; then
    cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
fi

# Create new .env file
cat > .env << EOF
# Database Connection (Local PostgreSQL Development)
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD

# Application Configuration
LOG_LEVEL=info
NODE_ENV=development
MCP_TRANSPORT=stdio

# Scope Inference (optional, falls back to git)
CORTEX_ORG=local-dev
CORTEX_PROJECT=mcp-cortex
CORTEX_BRANCH=master

# Performance Tuning (Optimized for local development)
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_IDLE_TIMEOUT_MS=30000
DB_CONNECTION_TIMEOUT_MS=10000
DB_QUERY_TIMEOUT=30000
DB_STATEMENT_TIMEOUT=30000

# MCP Server Configuration (Local execution)
MCP_SERVER_NAME=cortex-memory
MCP_SERVER_VERSION=1.1.0
MCP_MAX_BATCH_SIZE=100

# Security - Development Values
ENCRYPTION_KEY=dev_encryption_key_32_chars_long_123456
JWT_SECRET=dev_jwt_secret_key_for_development_123456
API_KEY_SECRET=dev_api_key_secret_for_development_123456
EOF

echo -e "${GREEN}✅ .env configuration updated${NC}"

# Clear cached environment variables
unset DB_PORT DATABASE_URL

# Test database connection
echo -e "${YELLOW}Testing database connection...${NC}"

# Test with Node.js
node -e "
require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});
pool.query('SELECT current_user as user, current_database() as database')
  .then(result => {
    console.log('✅ Database connection successful!');
    console.log('User:', result.rows[0].user);
    console.log('Database:', result.rows[0].database);
    return pool.end();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  });
"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Database connection test passed${NC}"
else
    echo -e "${RED}❌ Database connection test failed${NC}"
    exit 1
fi

# Setup Prisma
echo -e "${YELLOW}Setting up Prisma...${NC}"

# Generate Prisma client
npx prisma generate

# Push schema to database
npx prisma db push

# Test Prisma connection
npm run db:health

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Prisma setup successful${NC}"
else
    echo -e "${RED}❌ Prisma setup failed${NC}"
    exit 1
fi

echo -e "${GREEN}🎉 Database setup completed successfully!${NC}"
echo ""
echo "Database Configuration Summary:"
echo "  Host: $DB_HOST"
echo "  Port: $DB_PORT"
echo "  Database: $DB_NAME"
echo "  User: $DB_USER"
echo ""
echo "Next steps:"
echo "  1. Start the application: npm start"
echo "  2. Test the MCP server: npm test"
echo "  3. View troubleshooting guide: DATABASE_CONNECTION_TROUBLESHOOTING.md"
echo ""
echo "If you encounter any issues, check the troubleshooting guide or run:"
echo "  npm run test:connection  # Test database pool connection"
echo "  npm run db:health        # Test Prisma connection"