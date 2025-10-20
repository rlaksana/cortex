# MCP Cortex Memory User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Core Concepts](#core-concepts)
4. [Daily Operations](#daily-operations)
5. [Memory Management](#memory-management)
6. [Search and Retrieval](#search-and-retrieval)
7. [Advanced Features](#advanced-features)
8. [Configuration](#configuration)
9. [Integration](#integration)
10. [Best Practices](#best-practices)
11. [FAQ](#faq)

## Introduction

MCP Cortex Memory is a sophisticated knowledge management system designed to enhance your development workflow with intelligent memory storage, retrieval, and decision support capabilities. It works as an MCP (Model Context Protocol) server, seamlessly integrating with AI assistants like Claude Desktop.

### What Can MCP Cortex Memory Do?

- **Knowledge Storage**: Store and organize development knowledge, decisions, and observations
- **Smart Search**: Intelligent search across all stored knowledge with context-aware retrieval
- **Decision Support**: Get AI-powered recommendations based on historical decisions and patterns
- **Session Persistence**: Maintain conversation context across multiple sessions
- **Automated Logging**: Track changes, decisions, and observations automatically
- **Integration Ready**: Works with Claude Desktop and other MCP-compatible applications

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Host System                      │
├─────────────────────┬───────────────────────────────────────┤
│   MCP Server        │        Docker Container                │
│   (Native Windows)  │    (PostgreSQL Database)              │
│                     │                                        │
│ ┌─────────────────┐ │ ┌─────────────────────────────────────┐ │
│ │ Cortex API      │ │ │ PostgreSQL 18                      │ │
│ │ Search Engine   │ │ │ Knowledge Graph                    │ │
│ │ Memory Manager  │ │ │ Decision Support                   │ │
│ │ Session Logger  │ │ │ Change Tracking                    │ │
│ └─────────────────┘ │ └─────────────────────────────────────┘ │
└─────────────────────┴───────────────────────────────────────┘
```

## Getting Started

### First-Time Setup

After completing installation (see [Installation Guide](INSTALLATION.md)):

1. **Verify Installation**:
   ```powershell
   .\health-check.ps1
   ```

2. **Start MCP Server**:
   ```powershell
   # Development mode
   npm start

   # Production mode
   npm run start:prod

   # Background service
   npm run service
   ```

3. **Test Basic Functionality**:
   ```powershell
   # Test server connectivity
   curl http://localhost:3000/health

   # Check database connection
   docker exec cortex-postgres-wsl pg_isready -U cortex -d cortex_prod
   ```

### Claude Desktop Integration

1. **Configure Claude Desktop**:
   ```json
   // %APPDATA%\Claude\claude_desktop_config.json
   {
     "mcpServers": {
       "cortex-memory": {
         "command": "node",
         "args": ["C:\\cortex-memory\\dist\\index.js"],
         "env": {
           "DATABASE_URL": "postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod"
         }
       }
     }
   }
   ```

2. **Restart Claude Desktop**:
   - Close Claude Desktop completely
   - Reopen the application
   - Verify Cortex Memory appears in the connections panel

3. **Test Integration**:
   - Start a conversation with Claude
   - Ask: "What can you tell me about my current project?"
   - Claude should access your stored project knowledge

## Core Concepts

### Knowledge Types

MCP Cortex Memory stores 16 different types of knowledge:

| Type | Purpose | Example |
|------|---------|---------|
| **Entity** | Core objects, components, people | "User authentication module" |
| **Decision** | Technical decisions and rationale | "Use OAuth 2.0 for authentication" |
| **Observation** | Facts, measurements, findings | "Database query takes 200ms" |
| **Section** | Documentation, explanations | "API endpoint documentation" |
| **Runbook** | Procedures, step-by-step guides | "Database backup procedure" |
| **Change** | Code changes, modifications | "Updated authentication logic" |
| **Issue** | Problems, bugs, incidents | "Login page crashes on Safari" |
| **Todo** | Tasks, action items | "Implement password reset" |
| **Release** | Software releases, deployments | "Version 1.2.0 deployment" |
| **DDL** | Database schema changes | "Added user preferences table" |
| **PR Context** | Pull request metadata | "Pull request #123 discussion" |
| **Incident** | Outages, critical events | "Database outage on 2024-01-15" |
| **Risk** | Risk assessments, mitigations | "Security vulnerability in auth module" |
| **Assumption** | Assumptions, constraints | "Users will have modern browsers" |
| **Relation** | Relationships between entities | "User has many preferences" |

### Knowledge Graph

All knowledge types are interconnected in a graph structure:

```
[Decision] ──resolves_issue──► [Issue]
    │                           │
    │                           └───documents_incident──► [Incident]
    │
    └───mitigates_risk──► [Risk]
```

This graph structure enables:
- **Contextual Search**: Find related knowledge automatically
- **Impact Analysis**: Understand how changes affect other components
- **Decision Traceability**: Track the rationale behind technical choices

### Scope and Context

Knowledge is organized by scope for better organization:

- **Project**: All knowledge within a specific project
- **Branch**: Knowledge specific to a git branch
- **Organization**: Knowledge shared across projects
- **Global**: Universal knowledge and patterns

## Daily Operations

### Starting the System

1. **Manual Start**:
   ```powershell
   # Navigate to installation directory
   cd C:\cortex-memory

   # Start the server
   npm start
   ```

2. **Service Mode**:
   ```powershell
   # Install as Windows service (optional)
   npm run service-install

   # Start service
   Start-Service cortex-memory
   ```

3. **Verify Running Status**:
   ```powershell
   .\health-check.ps1
   ```

### Basic Memory Operations

#### Storing Information

When working with Claude Desktop, information is stored automatically:

```
User: "I decided to use React for the frontend because of its component-based architecture."

System: Automatically stores:
- Decision: "Use React for frontend"
- Observation: "React provides component-based architecture"
- Entity: "Frontend module"
```

#### Manual Storage (Advanced)

For direct API interaction:

```javascript
// Store a decision
const decision = {
  kind: "decision",
  scope: { project: "my-app", branch: "main" },
  data: {
    title: "Use PostgreSQL for primary database",
    rationale: "PostgreSQL provides better JSON support and ACID compliance",
    alternatives: ["MySQL", "MongoDB", "SQLite"],
    impact: "Medium"
  }
};

// Store an observation
const observation = {
  kind: "observation",
  scope: { project: "my-app" },
  data: {
    title: "Database query performance issue",
    details: "User login query takes 2.5 seconds",
    metrics: { query_time: 2500, records_returned: 1 },
    severity: "high"
  }
};
```

#### Retrieving Information

Search and retrieval happens automatically in conversations:

```
User: "What database did we decide to use?"

System: Retrieves relevant decisions and provides context about the PostgreSQL choice, including rationale and alternatives considered.
```

### Health Monitoring

Regular health checks ensure optimal performance:

```powershell
# Quick health check
.\health-check.ps1

# Detailed monitoring
.\health-check.ps1 -Detailed

# Continuous monitoring (every 60 seconds)
.\health-check.ps1 -Continuous 60

# Generate health report
.\health-check.ps1 -OutputFormat json > health-report.json
```

## Memory Management

### Organizing Knowledge

#### Project Structure

```
MyProject/
├── Decisions/
│   ├── Database choice (PostgreSQL)
│   ├── Frontend framework (React)
│   └── Authentication method (JWT)
├── Issues/
│   ├── Login page performance
│   └── Mobile responsiveness
├── Observations/
│   ├── API response times
│   └── User behavior patterns
└── Runbooks/
    ├── Database backup procedure
    └── Deployment process
```

#### Tagging and Categorization

Knowledge is automatically tagged based on:

- **Component**: Related software components
- **Technology**: Technologies and frameworks mentioned
- **Priority**: Implicit priority based on context
- **Time**: Timestamps for temporal queries

#### Manual Organization

```javascript
// Create a structured knowledge entry
const structuredEntry = {
  kind: "section",
  scope: { project: "my-app", branch: "main" },
  data: {
    title: "Authentication System Architecture",
    content: "Detailed explanation of authentication flow...",
    tags: ["security", "jwt", "oauth", "user-management"],
    related_components: ["auth-service", "user-model", "jwt-handler"],
    importance: "high"
  }
};
```

### Data Management

#### Backup Strategies

```powershell
# Daily backup
.\backup.ps1 -BackupType full -Compression

# Configuration-only backup
.\backup.ps1 -BackupType config

# Database backup
.\backup.ps1 -BackupType database

# Scheduled backup (Windows Task Scheduler)
# Create task to run: .\backup.ps1 -BackupType incremental
```

#### Data Retention

Configure retention policies in `.env`:

```bash
# Backup retention (days)
BACKUP_RETENTION_DAYS=30

# Auto-cleanup old observations
AUTO_CLEANUP_ENABLED=true
AUTO_CLEANUP_DAYS=90

# Log retention
LOG_RETENTION_DAYS=7
```

#### Data Purging

```powershell
# Purge old data
.\scripts\cleanup-old-data.ps1 -Days 365

# Purge specific project data
.\scripts\cleanup-project.ps1 -Project "old-project"

# Compact database
docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "VACUUM ANALYZE;"
```

## Search and Retrieval

### Natural Language Search

Search using natural language queries:

```
User queries:
- "What decisions did we make about the database?"
- "Show me all issues related to authentication"
- "What's the backup procedure for the database?"
- "Tell me about the frontend architecture decisions"
```

### Advanced Search Patterns

#### Specific Knowledge Types

```
- "Find all decisions about security"          # Search decisions only
- "List open issues in the user module"        # Search issues only
- "Show me runbooks for deployment"            # Search procedures only
- "What observations did we make about performance?"  # Search observations only
```

#### Time-Based Queries

```
- "What decisions did we make last week?"
- "Show me issues from this month"
- "What changed since our last release?"
- "Find all recent observations about the API"
```

#### Context-Aware Search

The system automatically considers:
- **Current project context**
- **Recent conversation history**
- **User preferences and patterns**
- **Relationships between knowledge items**

### Search Optimization

#### Improving Search Results

1. **Use Specific Terms**:
   ```
   Better: "PostgreSQL connection pooling decisions"
   Poor: "database stuff"
   ```

2. **Include Context**:
   ```
   Better: "How do we handle user authentication in the mobile app?"
   Poor: "authentication"
   ```

3. **Reference Timeframes**:
   ```
   Better: "What frontend framework did we choose in March?"
   Poor: "frontend framework"
   ```

#### Search Results Format

Results are ranked by relevance and include:

```javascript
{
  "query": "database decisions",
  "results": [
    {
      "type": "decision",
      "title": "Use PostgreSQL for primary database",
      "relevance_score": 0.95,
      "context": {
        "project": "my-app",
        "branch": "main",
        "timestamp": "2024-01-15T10:30:00Z"
      },
      "excerpt": "Chose PostgreSQL for its JSON support and ACID compliance...",
      "related_items": ["database_schema_ddl", "performance_observation"]
    }
  ]
}
```

## Advanced Features

### Decision Support

The system provides intelligent recommendations based on historical decisions:

```
User: "I need to choose a caching solution for our API"

System provides:
- Historical caching decisions and their outcomes
- Performance observations from previous implementations
- Related issues and how they were resolved
- Recommendations based on project context
```

### Pattern Recognition

Automatically identifies patterns across your knowledge base:

- **Recurring Issues**: Problems that appear multiple times
- **Successful Solutions**: Approaches that worked well
- **Technology Choices**: Patterns in technology selection
- **Decision Rationale**: Common reasons for decisions

### Impact Analysis

Understand the potential impact of changes:

```
User: "I'm thinking of changing our authentication system"

System analyzes:
- Components that depend on authentication
- Previous authentication changes and their impact
- Related issues and risks
- Migration procedures and considerations
```

### Knowledge Visualization

Generate visual representations of your knowledge graph:

```powershell
# Generate knowledge graph visualization
.\scripts\generate-graph-viz.ps1 -Project "my-app" -Format svg

# Component dependency diagram
.\scripts\generate-dependency-diagram.ps1 -Component "auth-service"

# Decision timeline
.\scripts\generate-decision-timeline.ps1 -Project "my-app" -Months 6
```

## Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Database Configuration
DATABASE_URL=postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod
DB_POOL_MIN=5
DB_POOL_MAX=20

# MCP Server Configuration
MCP_SERVER_NAME=cortex-memory
MCP_TRANSPORT=stdio
MCP_MAX_BATCH_SIZE=100

# Performance Tuning
DB_QUERY_TIMEOUT=30000
DB_STATEMENT_TIMEOUT=30000

# Logging Configuration
LOG_LEVEL=info            # error, warn, info, debug
NODE_ENV=production

# Scope Configuration
CORTEX_ORG=my-org
CORTEX_PROJECT=cortex
CORTEX_BRANCH=main

# Feature Flags
ENABLE_METRICS=false
DEBUG_MODE=false
ENABLE_HEALTH_CHECKS=true
```

### Advanced Configuration

#### Performance Tuning

For high-load scenarios:

```bash
# Increase connection pool
DB_POOL_MIN=10
DB_POOL_MAX=50

# Optimize timeouts
DB_CONNECTION_TIMEOUT_MS=15000
DB_QUERY_TIMEOUT=60000

# Enable connection caching
ENABLE_CONNECTION_CACHE=true
CACHE_TTL_MS=300000
```

#### Development Configuration

For development environments:

```bash
# Enable debug mode
DEBUG_MODE=true
LOG_LEVEL=debug

# Development database
DEV_DATABASE_URL=postgresql://cortex:dev_key@localhost:5432/cortex_dev

# Hot reload
HOT_RELOAD=true
```

### Custom Configuration Files

Create custom configurations for different environments:

```powershell
# Development configuration
copy config\env-template.env .env.development

# Production configuration
copy config\env-template.env .env.production

# Test configuration
copy config\env-template.env .env.test
```

## Integration

### Claude Desktop Integration

#### Basic Setup

1. **Install Claude Desktop**:
   - Download from Anthropic
   - Sign in with your account

2. **Configure MCP Server**:
   ```json
   // %APPDATA%\Claude\claude_desktop_config.json
   {
     "mcpServers": {
       "cortex-memory": {
         "command": "node",
         "args": ["C:\\cortex-memory\\dist\\index.js"],
         "env": {
           "NODE_ENV": "production",
           "LOG_LEVEL": "info"
         }
       }
     }
   }
   ```

3. **Verify Connection**:
   - Open Claude Desktop
   - Check that Cortex Memory appears in connections
   - Test with a simple query

#### Advanced Integration

```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": ["C:\\cortex-memory\\dist\\index.js"],
      "env": {
        "DATABASE_URL": "postgresql://cortex:password@localhost:5433/cortex_prod",
        "CORTEX_ORG": "my-company",
        "CORTEX_PROJECT": "current-project",
        "LOG_LEVEL": "debug",
        "ENABLE_METRICS": "true"
      },
      "disabled": false,
      "autoApprove": [
        "memory.find",
        "memory.store"
      ]
    }
  }
}
```

### IDE Integration

#### VS Code Extension

Install the Cortex Memory VS Code extension for:

- **Inline search**: Search knowledge without leaving VS Code
- **Context suggestions**: Get relevant knowledge while coding
- **Code annotations**: Link code to stored decisions

#### Git Integration

Configure Git hooks to automatically capture knowledge:

```bash
# .git/hooks/pre-commit
#!/bin/bash
node .\scripts\git-commit-hook.js $1

# Captures:
# - Commit messages as decisions
# - Changed files as observations
# - Branch context
```

### API Integration

For custom application integration:

```javascript
// Node.js client example
const CortexMemoryClient = require('@cortex/memory-client');

const client = new CortexMemoryClient({
  databaseUrl: process.env.DATABASE_URL,
  scope: {
    org: 'my-org',
    project: 'my-project',
    branch: 'main'
  }
});

// Store knowledge
await client.store({
  kind: 'decision',
  data: {
    title: 'Use REST API for external integration',
    rationale: 'REST provides better compatibility with existing systems'
  }
});

// Search knowledge
const results = await client.find('API integration decisions');
```

## Best Practices

### Knowledge Organization

#### Consistent Naming

- Use clear, descriptive titles
- Follow consistent naming conventions
- Include relevant technology names
- Specify affected components

**Good examples**:
- "Decision: Use PostgreSQL for user authentication data"
- "Issue: Login API timeouts under high load"
- "Observation: Database query performance improved by 40% after indexing"

**Poor examples**:
- "DB decision"
- "Login problem"
- "Performance thing"

#### Regular Knowledge Capture

1. **During Development**:
   - Capture architectural decisions as they're made
   - Document workarounds and temporary solutions
   - Record performance observations

2. **During Reviews**:
   - Document review feedback and decisions
   - Capture alternative approaches considered
   - Record rationale for final choices

3. **During Incidents**:
   - Create incident records with timelines
   - Document root cause analysis
   - Store resolution procedures as runbooks

#### Knowledge Quality

- **Specificity**: Be specific about what, why, and how
- **Context**: Include project context and constraints
- **Alternatives**: Document alternatives considered and rejected
- **Impact**: Note the impact and scope of decisions

### Performance Optimization

#### Database Optimization

```powershell
# Monitor database performance
docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;"

# Optimize database settings
# Edit docker-compose.*.yml to increase shared_buffers, work_mem
```

#### Search Optimization

- Use specific search terms
- Include time context in queries
- Reference specific components or technologies
- Use natural language rather than technical jargon

#### Memory Management

```powershell
# Regular cleanup
.\scripts\cleanup-old-data.ps1 -Days 365

# Database maintenance
docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "VACUUM ANALYZE;"

# Monitor growth
.\health-check.ps1 -Detailed
```

### Security Best Practices

#### Database Security

- Change default passwords
- Use strong, unique passwords
- Enable database connection encryption
- Regular database backups

#### Application Security

- Keep Node.js and dependencies updated
- Use environment variables for sensitive data
- Enable request logging for monitoring
- Regular security audits

#### Access Control

- Limit database access to authorized users
- Use read-only users where possible
- Implement proper authentication
- Regular access reviews

## FAQ

### General Questions

**Q: How much data can MCP Cortex Memory store?**
A: The system is designed to handle large-scale knowledge bases. With PostgreSQL 18 and proper indexing, it can efficiently manage millions of knowledge entries. Practical limits depend on your hardware, but 100GB+ databases are common.

**Q: Can I use MCP Cortex Memory without Claude Desktop?**
A: Yes! The system has a REST API and can be integrated with any application. Claude Desktop integration is optional but provides the most seamless experience.

**Q: How secure is my data?**
A: Data is stored locally in your PostgreSQL database. All data stays on your machine unless you configure external backups. The database supports encryption for additional security.

### Technical Questions

**Q: Why does Docker Desktop use more memory than WSL Docker?**
A: Docker Desktop includes a GUI application and additional management tools, while WSL Docker runs only the essential Docker engine with minimal overhead.

**Q: Can I run multiple projects with the same MCP Cortex Memory instance?**
A: Yes! The system supports project-based scoping. Each project's knowledge is isolated but you can search across projects if needed.

**Q: How do I migrate from WSL Docker to Docker Desktop (or vice versa)?**
A: Create a backup with `.\\backup.ps1`, then switch deployment options using `.\\install.ps1`, and restore with `.\\restore.ps1`.

### Troubleshooting

**Q: The MCP server won't start. What should I do?**
A: Run `.\\health-check.ps1` to diagnose the issue. Common problems include database connection issues or missing dependencies.

**Q: Search results are not relevant. How can I improve them?**
A: Use more specific search terms, include context and timeframes, and ensure your knowledge entries have clear, descriptive titles.

**Q: The system is running slowly. How can I improve performance?**
A: Check memory usage with `.\\health-check.ps1 -Detailed`, consider increasing database memory limits, and ensure your system meets the recommended requirements.

### Integration Questions

**Q: Can I integrate MCP Cortex Memory with other AI assistants?**
A: Yes! Any application that supports the MCP protocol can integrate with Cortex Memory. The system also has a REST API for custom integrations.

**Q: How do I backup my knowledge to the cloud?**
A: Use `.\\backup.ps1 -Compression` to create compressed backups, then manually upload to your preferred cloud storage. Cloud integration features are planned for future releases.

---

## Quick Reference

### Essential Commands

```powershell
# Start system
npm start

# Health check
.\health-check.ps1

# Backup data
.\backup.ps1 -BackupType full

# Search (via Claude Desktop)
"What decisions did we make about the database?"

# Stop system
Ctrl+C (if running in console)
# OR
Stop-Service cortex-memory (if running as service)
```

### Common Tasks

| Task | Command/Action |
|------|----------------|
| **Check system health** | `.\\health-check.ps1` |
| **Create backup** | `.\\backup.ps1 -BackupType full` |
| **Restore from backup** | `.\\restore.ps1 -BackupPath "backup-path"` |
| **View logs** | `Get-Content logs\\cortex.log -Tail 50` |
| **Update configuration** | Edit `.env` file |
| **Restart services** | `docker-compose restart` |

For technical support or additional help, refer to the [Troubleshooting Guide](TROUBLESHOOTING.md) or [Installation Guide](INSTALLATION.md).