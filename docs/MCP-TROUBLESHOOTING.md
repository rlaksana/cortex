# MCP Server Troubleshooting Guide

## Overview

This comprehensive troubleshooting guide covers common issues, diagnostic procedures, and solutions for the Cortex Memory MCP Server v2.0. The guide is organized by symptom severity and includes step-by-step resolution procedures.

**🚀 Quick Reference**:

- ✅ **MCP Protocol Version**: 2024-11-05 (100% compliant)
- ✅ **Production Status**: Fully operational with comprehensive monitoring
- ⚠️ **Most Common Issues**: Configuration, database connectivity, and environment setup

## Table of Contents

1. [Emergency Quick Fixes](#emergency-quick-fixes)
2. [Connection & Startup Issues](#connection--startup-issues)
3. [Database & Qdrant Issues](#database--qdrant-issues)
4. [MCP Protocol Issues](#mcp-protocol-issues)
5. [Performance & Memory Issues](#performance--memory-issues)
6. [Configuration Issues](#configuration-issues)
7. [Search & Deduplication Issues](#search--deduplication-issues)
8. [Monitoring & Health Issues](#monitoring--health-issues)
9. [Production Deployment Issues](#production-deployment-issues)
10. [Diagnostic Tools & Commands](#diagnostic-tools--commands)

---

## Emergency Quick Fixes

### Server Won't Start

**Symptoms**:

- Server fails to start or crashes immediately
- MCP tools not registering
- Database connection errors

**Immediate Actions**:

1. **Check Environment Variables**:

```bash
# Verify required environment variables
echo "OPENAI_API_KEY: $OPENAI_API_KEY"
echo "QDRANT_URL: $QDRANT_URL"
echo "NODE_ENV: $NODE_ENV"

# If OPENAI_API_KEY is missing, set it:
export OPENAI_API_KEY=your-api-key-here
```

2. **Verify Qdrant is Running**:

```bash
# Check if Qdrant is accessible
curl -f http://localhost:6333/health || echo "Qdrant not accessible"

# If using Docker, check container status
docker ps | grep qdrant
docker logs qdrant-container
```

3. **Check Port Availability**:

```bash
# Check if MCP port is available
netstat -an | grep :3000 || echo "Port 3000 is free"

# Kill any process using the port
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
```

4. **Quick Reset**:

```bash
# Clear caches and restart
rm -rf .cache node_modules/.cache
npm run build
npm start
```

### Tools Not Responding

**Symptoms**:

- MCP tools registered but not responding
- Timeout errors when calling tools
- Empty responses

**Immediate Actions**:

1. **Check MCP Server Status**:

```bash
# Test MCP server directly
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

2. **Verify Tool Registration**:

```bash
# Check if tools are properly registered
npm run mcp:check-tools || echo "Tool registration issue"
```

3. **Restart with Debug Logging**:

```bash
# Enable debug mode
DEBUG=cortex:* npm start
```

---

## Connection & Startup Issues

### MCP Server Fails to Initialize

**Error Messages**:

- `Failed to initialize MCP server`
- `Transport connection failed`
- `Server startup timeout`

**Diagnosis**:

1. **Check System Resources**:

```bash
# Check available memory
free -h || echo "Memory check"

# Check disk space
df -h || echo "Disk space check"

# Check Node.js version
node --version  # Should be 20+
```

2. **Verify Dependencies**:

```bash
# Check if all dependencies are installed
npm list --depth=0

# Reinstall if needed
npm ci --force
```

3. **Check Configuration Files**:

```bash
# Verify .env file exists and is readable
test -f .env && echo ".env exists" || echo ".env missing"
cat .env | grep -E "^(OPENAI_API_KEY|QDRANT_URL)" || echo "Check .env configuration"
```

**Solutions**:

1. **Rebuild Project**:

```bash
# Clean rebuild
rm -rf dist
npm run build
npm start
```

2. **Reset Environment**:

```bash
# Reset to known good state
git checkout HEAD -- package-lock.json
npm ci
cp .env.example .env
# Edit .env with correct values
```

### Database Connection Failures

**Error Messages**:

- `Failed to connect to Qdrant`
- `Connection timeout`
- `Database not responding`

**Diagnosis**:

1. **Test Qdrant Connection**:

```bash
# Basic connectivity test
curl -f http://localhost:6333/collections || echo "Qdrant collections endpoint failed"

# Health check
curl -f http://localhost:6333/health || echo "Qdrant health check failed"

# Detailed status
curl http://localhost:6333/cluster
```

2. **Check Qdrant Configuration**:

```bash
# Verify Qdrant configuration
docker ps | grep qdrant
docker logs qdrant-container | tail -20

# If using standalone Qdrant:
ps aux | grep qdrant
```

**Solutions**:

1. **Restart Qdrant**:

```bash
# Docker restart
docker restart qdrant-container

# Wait for startup
sleep 5
curl http://localhost:6333/health
```

2. **Reset Qdrant Collection**:

```bash
# Delete and recreate collection (CAUTION: data loss)
curl -X DELETE http://localhost:6333/collections/cortex-memory
# Server will recreate on next start
```

---

## Database & Qdrant Issues

### Collection Creation Failures

**Error Messages**:

- `Failed to create collection`
- `Collection already exists with different schema`
- `Invalid collection configuration`

**Diagnosis**:

```bash
# Check existing collections
curl http://localhost:6333/collections

# Check collection details
curl http://localhost:6333/collections/cortex-memory

# Look for schema conflicts
curl http://localhost:6333/collections/cortex-memory | jq '.result.config.params'
```

**Solutions**:

1. **Reset Collection**:

```bash
# Backup existing data (if needed)
curl -X POST http://localhost:6333/collections/cortex-memory/points/scroll \
  -H "Content-Type: application/json" \
  -d '{"limit": 1000}' > backup.json

# Delete and recreate
curl -X DELETE http://localhost:6333/collections/cortex-memory
npm restart  # Will recreate with correct schema
```

2. **Verify Vector Configuration**:

```bash
# Check vector size matches OpenAI embeddings (1536)
curl http://localhost:6333/collections/cortex-memory | \
  jq '.result.config.params.vectors.size'
# Should return 1536
```

### Search Performance Issues

**Symptoms**:

- Slow search responses (>5 seconds)
- Timeouts during search operations
- High memory usage during searches

**Diagnosis**:

```bash
# Monitor Qdrant performance
curl http://localhost:6333/telemetry

# Check collection statistics
curl -X POST http://localhost:6333/collections/cortex-memory/points/count \
  -H "Content-Type: application/json" \
  -d '{}'

# Monitor system resources
top -p $(pgrep -f qdrant)
```

**Solutions**:

1. **Optimize Search Parameters**:

```javascript
// Use more targeted searches
await client.callTool('memory_find', {
  query: 'specific terms',
  limit: 10, // Reduce limit
  search_strategy: 'fast', // Use fast mode for quick results
  scope: { project: 'specific-project' }, // Narrow scope
});
```

2. **Add Search Indexes**:

```bash
# Qdrant automatically creates HNSW index
# Monitor index performance
curl http://localhost:6333/collections/cortex-memory/indexes
```

---

## MCP Protocol Issues

### Tool Registration Failures

**Error Messages**:

- `Failed to register tools`
- `Invalid tool schema`
- `MCP protocol version mismatch`

**Diagnosis**:

```bash
# Check MCP protocol version
npm run mcp:version || echo "MCP version check failed"

# Verify tool schemas
npm run mcp:validate-schemas || echo "Schema validation failed"

# Test MCP protocol compliance
npm run mcp:test-protocol || echo "Protocol compliance test failed"
```

**Solutions**:

1. **Verify MCP Configuration**:

```bash
# Check MCP client configuration
cat ~/.claude/claude_desktop_config.json

# Verify only one Cortex configuration exists
grep -c "cortex" ~/.claude/claude_desktop_config.json
# Should return 1
```

2. **Reset MCP Connection**:

```bash
# Restart Claude Desktop or MCP client
# Clear MCP cache
rm -rf ~/.claude/cache
# Restart client
```

### JSON-RPC Errors

**Error Messages**:

- `Invalid JSON-RPC request`
- `Method not found`
- `Invalid params`

**Diagnosis**:

```bash
# Test JSON-RPC directly
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "memory_store",
      "arguments": {"items": []}
    }
  }'
```

**Solutions**:

1. **Validate Request Format**:

```javascript
// Ensure proper JSON-RPC 2.0 format
const request = {
  jsonrpc: '2.0',
  id: Date.now(),
  method: 'tools/call',
  params: {
    name: 'memory_store',
    arguments: {
      items: [
        /* valid items */
      ],
    },
  },
};
```

---

## Performance & Memory Issues

### High Memory Usage

**Symptoms**:

- Memory usage continuously increasing
- Node.js process using >1GB RAM
- System becoming unresponsive

**Diagnosis**:

```bash
# Monitor Node.js memory usage
ps aux | grep node
top -p $(pgrep -f node)

# Check for memory leaks
npm run debug:memory-leak

# Monitor garbage collection
DEBUG=cortex:gc npm start
```

**Solutions**:

1. **Configure Node.js Memory Limits**:

```bash
# Set appropriate memory limits
export NODE_OPTIONS="--max-old-space-size=2048 --max-semi-space-size=256"
npm start
```

2. **Enable Memory Monitoring**:

```bash
# Add memory monitoring to environment
export NODE_OPTIONS="--max-old-space-size=2048 --inspect"
npm start

# Monitor with Chrome DevTools
# Open chrome://inspect and connect to Node.js process
```

3. **Batch Processing Optimization**:

```javascript
// Process items in smaller batches
const batchSize = 10;
for (let i = 0; i < items.length; i += batchSize) {
  const batch = items.slice(i, i + batchSize);
  await client.callTool('memory_store', { items: batch });
  // Small delay between batches
  await new Promise((resolve) => setTimeout(resolve, 100));
}
```

### Slow Response Times

**Symptoms**:

- Tool calls taking >10 seconds
- Search operations timing out
- System becoming sluggish

**Diagnosis**:

```bash
# Monitor response times
npm run monitor:performance

# Check database performance
curl -w "@curl-format.txt" -s -o /dev/null http://localhost:3000/health

# Profile Node.js performance
npm run profile:cpu
```

**Solutions**:

1. **Enable Caching**:

```javascript
// Use search caching
await client.callTool('memory_find', {
  query: 'frequently searched term',
  optimization: {
    enable_caching: true,
    cache_ttl_seconds: 3600,
  },
});
```

2. **Optimize Search Strategy**:

```javascript
// Use appropriate search modes
await client.callTool('memory_find', {
  query: 'quick lookup',
  search_strategy: 'fast', // For quick results
  limit: 5, // Reduce result set
  optimization: {
    timeout_ms: 5000, // Set reasonable timeout
  },
});
```

---

## Configuration Issues

### Environment Configuration Problems

**Symptoms**:

- Server starts but features not working
- Missing or incorrect configuration values
- Features using default values instead of custom settings

**Diagnosis**:

```bash
# Check environment variables
env | grep -E "^(OPENAI_API_KEY|QDRANT_URL|NODE_ENV|LOG_LEVEL)"

# Validate .env file
npm run config:validate

# Check configuration loading
DEBUG=cortex:config npm start
```

**Solutions**:

1. **Create Complete .env File**:

```bash
# Copy example configuration
cp .env.example .env

# Edit with required values
nano .env
```

2. **Required Minimum Configuration**:

```bash
# Minimum required environment variables
export OPENAI_API_KEY=sk-...
export QDRANT_URL=http://localhost:6333
export QDRANT_COLLECTION_NAME=cortex-memory
export NODE_ENV=production
export LOG_LEVEL=info
```

### Database Configuration Issues

**Symptoms**:

- Qdrant connection failures
- Collection creation errors
- Search operations failing

**Diagnosis**:

```bash
# Test Qdrant configuration
curl -f $QDRANT_URL/health || echo "Qdrant URL incorrect"

# Check collection configuration
curl $QDRANT_URL/collections/$QDRANT_COLLECTION_NAME

# Verify vector configuration
curl $QDRANT_URL/collections/$QDRANT_COLLECTION_NAME | \
  jq '.result.config.params.vectors'
```

**Solutions**:

1. **Standard Qdrant Configuration**:

```bash
# Default production configuration
export QDRANT_URL=http://localhost:6333
export QDRANT_API_KEY=  # Leave empty if no auth
export QDRANT_COLLECTION_NAME=cortex-memory
export VECTOR_SIZE=1536  # OpenAI ada-002
export VECTOR_DISTANCE=Cosine
```

---

## Search & Deduplication Issues

### Search Not Returning Results

**Symptoms**:

- Empty search results
- No matches for known content
- All confidence scores are 0

**Diagnosis**:

```bash
# Check if data exists in database
curl -X POST http://localhost:6333/collections/cortex-memory/points/count \
  -H "Content-Type: application/json" \
  -d '{}'

# Test basic search
npm run test:search-basic

# Check embedding generation
npm run test:embeddings
```

**Solutions**:

1. **Verify Data Storage**:

```javascript
// Check if items were actually stored
const result = await client.callTool('memory_find', {
  query: 'test',
  search_strategy: 'deep',
  limit: 10,
});
console.log(`Found ${result.results.length} items`);
```

2. **Check Embedding Generation**:

```bash
# Test OpenAI API connectivity
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models

# Test embedding generation
npm run test:openai-embeddings
```

### Deduplication Not Working

**Symptoms**:

- Duplicate entries being stored
- No deduplication warnings
- Similar items not being detected

**Diagnosis**:

```bash
# Check deduplication configuration
npm run config:deduplication

# Test similarity detection
npm run test:similarity

# Check merge history
npm run debug:merge-history
```

**Solutions**:

1. **Configure Deduplication**:

```javascript
// Enable intelligent deduplication
await client.callTool('memory_store', {
  items: [newItem],
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent',
    similarity_threshold: 0.85,
    enable_intelligent_merging: true,
    enable_audit_logging: true,
  },
});
```

2. **Verify Similarity Threshold**:

```javascript
// Adjust similarity threshold if too strict/lenient
await client.callTool('memory_store', {
  items: [item],
  deduplication: {
    similarity_threshold: 0.7, // Lower if no duplicates detected
  },
});
```

---

## Monitoring & Health Issues

### Health Check Failures

**Symptoms**:

- Health endpoint returning errors
- System showing unhealthy status
- Monitoring alerts firing

**Diagnosis**:

```bash
# Run comprehensive health check
npm run health:comprehensive

# Check individual components
npm run health:database
npm run health:mcp-server
npm run health:memory-services

# Check system metrics
npm run metrics:system
```

**Solutions**:

1. **Manual Health Check**:

```bash
# Test each component manually
curl http://localhost:3000/health
curl http://localhost:6333/health
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models
```

2. **Enable Detailed Monitoring**:

```javascript
// Get detailed system status
const health = await client.callTool('system_status', {
  operation: 'health',
  include_detailed_metrics: true,
  response_formatting: {
    verbose: true,
    include_raw_data: false,
  },
});
```

### Performance Monitoring Issues

**Symptoms**:

- Missing performance metrics
- Monitoring data not updating
- Graphs showing flat lines

**Diagnosis**:

```bash
# Check metrics collection
npm run metrics:test

# Verify telemetry data
npm run telemetry:check

# Monitor system resources
npm run monitor:resources
```

**Solutions**:

1. **Enable Metrics Collection**:

```javascript
// Enable performance tracking
await client.callTool('memory_find', {
  query: 'test search',
  analytics: {
    track_search_metrics: true,
    include_performance_metrics: true,
  },
});
```

---

## Production Deployment Issues

### Docker Deployment Problems

**Symptoms**:

- Container fails to start
- Health checks failing
- Environment variables not loading

**Diagnosis**:

```bash
# Check container logs
docker logs cortex-mcp-container

# Check container status
docker ps -a | grep cortex-mcp

# Test container health
docker exec cortex-mcp-container curl http://localhost:3000/health
```

**Solutions**:

1. **Fix Docker Configuration**:

```yaml
# docker-compose.yml
version: '3.8'
services:
  cortex-mcp:
    build: .
    ports:
      - '3000:3000'
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - QDRANT_URL=http://qdrant:6333
      - NODE_ENV=production
    depends_on:
      - qdrant
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:3000/health']
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
```

2. **Environment Variable Management**:

```bash
# Create .env file for production
cat > .env.production << EOF
OPENAI_API_KEY=sk-...
QDRANT_URL=http://qdrant:6333
NODE_ENV=production
LOG_LEVEL=info
EOF

# Use production env file
docker-compose --env-file .env.production up -d
```

### Load Balancer Issues

**Symptoms**:

- Requests not being distributed
- Health checks failing
- SSL/TLS errors

**Diagnosis**:

```bash
# Check load balancer configuration
nginx -t && nginx -s reload

# Test upstream servers
curl http://localhost:3000/health

# Check SSL certificates
openssl x509 -in /path/to/cert.crt -text -noout
```

**Solutions**:

1. **Configure Nginx Load Balancer**:

```nginx
# /etc/nginx/sites-available/cortex-mcp
upstream cortex_mcp {
    server 127.0.0.1:3000 weight=1 max_fails=3 fail_timeout=30s;
    # Add more instances as needed
    server 127.0.0.1:3001 weight=1 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name cortex.example.com;

    location / {
        proxy_pass http://cortex_mcp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    location /health {
        proxy_pass http://cortex_mcp/health;
        access_log off;
    }
}
```

---

## Diagnostic Tools & Commands

### Quick Diagnostics

```bash
# Run all diagnostic checks
npm run diagnose:all

# Check system health
npm run health:check

# Validate configuration
npm run config:validate

# Test MCP connectivity
npm run mcp:test-connectivity
```

### Performance Diagnostics

```bash
# Benchmark system performance
npm run benchmark:performance

# Test search performance
npm run test:search-performance

# Monitor memory usage
npm run monitor:memory

# Profile CPU usage
npm run profile:cpu
```

### Database Diagnostics

```bash
# Check Qdrant status
npm run db:status

# Test database operations
npm run test:database-operations

# Verify collection schema
npm run db:schema-check

# Monitor database performance
npm run monitor:database
```

### MCP Protocol Diagnostics

```bash
# Test MCP protocol compliance
npm run mcp:test-protocol

# Validate tool schemas
npm run mcp:validate-schemas

# Test tool registration
npm run mcp:test-tools

# Monitor MCP traffic
npm run monitor:mcp
```

### Log Analysis

```bash
# View recent logs
npm run logs:recent

# Filter error logs
npm run logs:errors

# Monitor logs in real-time
npm run logs:follow

# Analyze log patterns
npm run logs:analyze
```

---

## Getting Help

### Support Channels

1. **Documentation**: Check [API Reference](docs/API-REFERENCE.md)
2. **GitHub Issues**: [Report issues](https://github.com/your-org/cortex-memory-mcp/issues)
3. **Community**: [Discussions](https://github.com/your-org/cortex-memory-mcp/discussions)

### Before Requesting Help

1. **Run Diagnostics**: `npm run diagnose:all`
2. **Check Logs**: `npm run logs:recent`
3. **Verify Configuration**: `npm run config:validate`
4. **Test Connectivity**: `npm run health:check`

### Include in Support Requests

- System information (`npm run info:system`)
- Error messages and logs
- Configuration file (redacted sensitive data)
- Steps to reproduce the issue
- Expected vs actual behavior

---

## Preventive Maintenance

### Regular Maintenance Tasks

```bash
# Weekly maintenance
npm run maintenance:weekly

# Monthly cleanup
npm run maintenance:monthly

# Performance optimization
npm run maintenance:optimize

# Security updates
npm run maintenance:security-update
```

### Monitoring Setup

```bash
# Set up monitoring
npm run monitoring:setup

# Configure alerts
npm run monitoring:alerts

# Create dashboard
npm run monitoring:dashboard
```

### Backup and Recovery

```bash
# Create backup
npm run backup:create

# Verify backup
npm run backup:verify

# Test recovery
npm run backup:test-recovery
```

---

**Last Updated**: 2025-11-05
**Version**: v2.0.0
**MCP Protocol Version**: 2024-11-05
