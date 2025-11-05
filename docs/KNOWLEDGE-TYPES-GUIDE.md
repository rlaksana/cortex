# Complete Knowledge Types Guide

## Overview

Cortex Memory MCP Server supports 16 comprehensive knowledge types designed to cover all aspects of software development, operations, and business decision-making. Each knowledge type has specific validation rules, business logic, and optimal use cases.

**🎯 This Guide Covers**:
- Detailed examples for each knowledge type
- Best practices and usage patterns
- Validation rules and required fields
- Real-world use cases and scenarios
- Integration patterns and workflows

## Table of Contents

1. [Core Knowledge Types](#core-knowledge-types)
2. [Development & Tracking Types](#development--tracking-types)
3. [Release & Deployment Types](#release--deployment-types)
4. [Risk & Planning Types](#risk--planning-types)
5. [Advanced Usage Patterns](#advanced-usage-patterns)

---

## Core Knowledge Types

### 1. Entity (`entity`)

**Purpose**: Represent concepts, objects, components, or any discrete item in your system.

**Use Cases**:
- System components and services
- Users, teams, and organizations
- Physical or logical resources
- Products and features
- Configurations and settings

**Required Fields**:
- `entity_type` (string, max 100 chars): Type classification
- `name` (string, max 500 chars): Unique identifier

**Optional Fields**:
- `data` (object): Flexible data structure
- `description` (string): Detailed description
- `status` (string): Current state
- `metadata` (object): Additional properties

#### Examples

**Basic Entity Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'entity',
    data: {
      entity_type: 'user',
      name: 'john_doe',
      data: {
        email: 'john@example.com',
        role: 'senior_developer',
        department: 'engineering',
        skills: ['TypeScript', 'Node.js', 'PostgreSQL'],
        join_date: '2023-01-15',
        employee_id: 'EMP001'
      }
    },
    scope: { project: 'hr-system', branch: 'main' }
  }]
});
```

**Service Component Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'entity',
    data: {
      entity_type: 'microservice',
      name: 'user-service',
      data: {
        version: '2.1.0',
        repository: 'github.com/company/user-service',
        language: 'TypeScript',
        framework: 'Express.js',
        database: 'PostgreSQL',
        endpoints: ['GET /users', 'POST /users', 'PUT /users/:id'],
        dependencies: ['auth-service', 'notification-service'],
        health_check_url: 'https://api.example.com/users/health'
      }
    },
    scope: { project: 'microservices', branch: 'production' }
  }]
});
```

**Configuration Entity Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'entity',
    data: {
      entity_type: 'configuration',
      name: 'database-connection-pool',
      data: {
        max_connections: 20,
        min_connections: 5,
        idle_timeout: 30000,
        connection_timeout: 10000,
        host: 'db.example.com',
        port: 5432,
        database: 'production',
        ssl_enabled: true
      }
    },
    scope: { project: 'infrastructure', branch: 'main' }
  }]
});
```

**Best Practices**:
- Use descriptive `entity_type` values that follow your domain model
- Keep names unique and consistent across your system
- Store related entities in the same scope for better organization
- Use the `data` field for flexible, extensible properties

---

### 2. Relation (`relation`)

**Purpose**: Define relationships and connections between entities.

**Use Cases**:
- System dependencies and integrations
- Team structures and reporting lines
- Workflow connections and process flows
- Data relationships and associations
- Component interactions

**Required Fields**:
- `relation_type` (string): Type of relationship
- `source_entity` (string): Origin entity identifier
- `target_entity` (string): Destination entity identifier

**Optional Fields**:
- `metadata` (object): Additional relationship properties
- `strength` (number): Relationship strength (0-1)
- `bidirectional` (boolean): Whether relation is two-way

#### Examples

**System Dependency Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'relation',
    data: {
      relation_type: 'depends_on',
      source_entity: 'user-service',
      target_entity: 'database-service',
      metadata: {
        dependency_type: 'runtime',
        criticality: 'high',
        impact_if_unavailable: 'Users cannot authenticate or access data'
      },
      strength: 0.9
    },
    scope: { project: 'system-architecture', branch: 'main' }
  }]
});
```

**Team Structure Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'relation',
    data: {
      relation_type: 'reports_to',
      source_entity: 'sarah_developer',
      target_entity: 'john_team_lead',
      metadata: {
        department: 'engineering',
        team: 'frontend',
        direct_report: true,
        start_date: '2024-01-15'
      },
      bidirectional: false
    },
    scope: { project: 'team-structure', branch: 'main' }
  }]
});
```

**Workflow Connection Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'relation',
    data: {
      relation_type: 'triggers',
      source_entity: 'code-deploy',
      target_entity: 'automated-tests',
      metadata: {
        trigger_condition: 'on_merge_to_main',
        test_suite: 'integration-tests',
        failure_action: 'rollback_deployment'
      },
      strength: 1.0
    },
    scope: { project: 'cicd-pipeline', branch: 'main' }
  }]
});
```

**Best Practices**:
- Create entity references first before defining relations
- Use consistent naming for entities across relations
- Include clear metadata explaining the relationship context
- Use `strength` to indicate relationship importance
- Consider bidirectional relations for mutual dependencies

---

### 3. Observation (`observation`)

**Purpose**: Capture fine-grained data, events, or measurements attached to entities.

**Use Cases**:
- User behavior analytics
- System metrics and measurements
- Event logs and incidents
- Performance data points
- Quality assurance findings

**Required Fields**:
- `observation_type` (string): Category of observation
- `details` (object): Observation data

**Optional Fields**:
- `entity_ref` (string): Related entity identifier
- `timestamp` (string): When observation occurred
- `source` (string): Observation source
- `confidence` (number): Confidence level (0-1)

#### Examples

**User Behavior Observation**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'observation',
    data: {
      observation_type: 'user_behavior',
      details: {
        action: 'login_attempt',
        user_id: 'user_123',
        timestamp: '2025-01-15T10:30:00Z',
        success: true,
        ip_address: '192.168.1.100',
        user_agent: 'Mozilla/5.0...',
        location: 'New York, NY',
        device_type: 'mobile',
        session_duration: 1800
      },
      entity_ref: 'user_123',
      source: 'authentication-service',
      confidence: 0.95
    },
    scope: { project: 'user-analytics', branch: 'production' }
  }]
});
```

**System Performance Observation**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'observation',
    data: {
      observation_type: 'performance_metric',
      details: {
        metric_name: 'api_response_time',
        service: 'user-service',
        endpoint: '/api/users',
        method: 'GET',
        response_time_ms: 245,
        status_code: 200,
        timestamp: '2025-01-15T10:30:00Z',
        memory_usage_mb: 128,
        cpu_usage_percent: 45,
        database_query_time_ms: 120
      },
      source: 'monitoring-system',
      confidence: 0.99
    },
    scope: { project: 'performance-monitoring', branch: 'main' }
  }]
});
```

**Quality Assurance Observation**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'observation',
    data: {
      observation_type: 'qa_finding',
      details: {
        test_type: 'integration_test',
        test_suite: 'user-registration-flow',
        test_name: 'user_registration_with_invalid_email',
        result: 'failed',
        error_message: 'Email validation not working for international domains',
        timestamp: '2025-01-15T14:22:00Z',
        test_environment: 'staging',
        severity: 'medium',
        reproducible: true
      },
      source: 'qa-automation',
      confidence: 0.9
    },
    scope: { project: 'quality-assurance', branch: 'main' }
  }]
});
```

**Best Practices**:
- Include precise timestamps for temporal analysis
- Use structured data in `details` field for easy querying
- Reference related entities when applicable
- Include confidence levels for uncertain observations
- Use descriptive observation_type values for categorization

---

### 4. Section (`section`)

**Purpose**: Organize and structure larger documents, knowledge bases, or content collections.

**Use Cases**:
- Documentation chapters and sections
- Knowledge base articles
- Policy and procedure documents
- Technical specifications
- Training materials

**Required Fields**:
- `section_type` (string): Type of section
- `title` (string): Section title
- `content` (string): Section content

**Optional Fields**:
- `parent_section` (string): Parent section reference
- `order` (number): Section order within parent
- `tags` (array): Categorization tags
- `author` (string): Content author
- `last_updated` (string): Last modification time

#### Examples

**Documentation Section Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'section',
    data: {
      section_type: 'documentation',
      title: 'API Authentication Guide',
      content: `
# API Authentication Guide

## Overview
This guide covers authentication methods for accessing our API endpoints.

## Authentication Methods

### OAuth 2.0 (Recommended)
- Use industry-standard OAuth 2.0 flow
- Supports access tokens and refresh tokens
- Implement proper token management

### API Key Authentication
- Simple key-based authentication
- Suitable for server-to-server communication
- Include API key in Authorization header

## Code Examples
\`\`\`javascript
const response = await fetch('/api/users', {
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN_HERE'
  }
});
\`\`\`
      `.trim(),
      parent_section: 'api-documentation',
      order: 2,
      tags: ['authentication', 'security', 'api'],
      author: 'technical-writer',
      last_updated: '2025-01-15T10:00:00Z'
    },
    scope: { project: 'documentation', branch: 'main' }
  }]
});
```

**Policy Document Section**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'section',
    data: {
      section_type: 'policy',
      title: 'Data Retention Policy',
      content: `
# Data Retention Policy

## Purpose
This policy defines how long different types of data are retained and when they are deleted.

## Retention Periods

### User Data
- Personal information: 2 years after account closure
- Activity logs: 90 days
- Support tickets: 3 years after resolution

### System Data
- Performance metrics: 1 year
- Error logs: 90 days
- Security logs: 5 years

## Compliance
- GDPR compliant
- SOX compliant
- Industry regulations
      `.trim(),
      tags: ['policy', 'compliance', 'security'],
      author: 'compliance-officer',
      last_updated: '2025-01-10T15:30:00Z'
    },
    scope: { project: 'company-policies', branch: 'main' }
  }]
});
```

**Training Material Section**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'section',
    data: {
      section_type: 'training',
      title: 'Onboarding Module 1: System Overview',
      content: `
# System Overview

## Learning Objectives
After completing this module, you will understand:
- System architecture and components
- Key workflows and processes
- Tools and resources available

## System Architecture
Our system consists of:
- Frontend applications (React, Vue.js)
- Backend services (Node.js, Python)
- Database layer (PostgreSQL, Redis)
- Message queue (RabbitMQ)
- Monitoring and logging

## Key Workflows
1. User registration and authentication
2. Data processing and analysis
3. Report generation and distribution
4. System maintenance and updates

## Resources
- System documentation
- Video tutorials
- Practice environments
      `.trim(),
      parent_section: 'developer-onboarding',
      order: 1,
      tags: ['training', 'onboarding', 'system'],
      author: 'training-team',
      last_updated: '2025-01-12T09:00:00Z'
    },
    scope: { project: 'training', branch: 'main' }
  }]
});
```

**Best Practices**:
- Use structured content format (Markdown works well)
- Keep sections focused on a single topic
- Use hierarchical organization with parent/child relationships
- Include order field for logical sequencing
- Tag content for easy categorization and search

---

## Development & Tracking Types

### 5. Runbook (`runbook`)

**Purpose**: Document step-by-step procedures for operations, troubleshooting, and maintenance.

**Use Cases**:
- Incident response procedures
- System deployment guides
- Troubleshooting checklists
- Backup and recovery procedures
- Maintenance operations

**Required Fields**:
- `title` (string): Procedure title
- `purpose` (string): Objective description
- `steps` (array): Step-by-step instructions

**Optional Fields**:
- `prerequisites` (array): Requirements before starting
- `troubleshooting` (object): Common issues and solutions
- `estimated_time` (string): Expected duration
- `complexity` (string): Difficulty level
- `author` (string): Procedure author
- `last_updated` (string): Last modification time

#### Examples

**Database Backup Runbook**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'runbook',
    data: {
      title: 'Database Backup and Restoration',
      purpose: 'Perform regular database backups and restore data when needed',
      prerequisites: [
        'Database access credentials',
        'Sufficient disk space for backup files',
        'Database connection tools installed',
        'Backup verification procedures'
      ],
      steps: [
        'Stop application services to prevent data inconsistency',
        'Create database backup using pg_dump or similar tool',
        'Verify backup file integrity',
        'Compress backup file to save storage space',
        'Upload backup to secure storage location',
        'Test backup restoration in staging environment',
        'Document backup details and retention period'
      ],
      troubleshooting: {
        common_issues: [
          'Insufficient disk space for backup',
          'Database connection timeouts',
          'Backup file corruption'
        ],
        solutions: [
          'Clean up old backup files before starting',
          'Check database connectivity and network',
          'Verify backup file integrity with checksum'
        ]
      },
      estimated_time: '45 minutes',
      complexity: 'medium',
      author: 'database-admin',
      last_updated: '2025-01-15T08:30:00Z'
    },
    scope: { project: 'operations', branch: 'main' }
  }]
});
```

**Incident Response Runbook**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'runbook',
    data: {
      title: 'P0 Incident Response Procedure',
      purpose: 'Respond to critical production incidents affecting service availability',
      prerequisites: [
        'Incident management system access',
        'Communication tools ready (Slack, email)',
        'System monitoring dashboard access',
        'Escalation contact list',
        'Service owner contact information'
      ],
      steps: [
        'Acknowledge incident within 5 minutes',
        'Form incident response team (IRT)',
        'Assess incident impact and scope',
        'Establish communication channels',
        'Identify root cause quickly',
        'Implement immediate workaround if available',
        'Coordinate with relevant teams',
        'Communicate status updates regularly',
        'Resolve root cause',
        'Verify system recovery',
        'Create postmortem documentation',
        'Update monitoring and alerting'
      ],
      troubleshooting: {
        common_issues: [
          'Team members not responding',
          'Root cause unclear',
          'Multiple systems affected',
          'Communication channels down'
        ],
        solutions: [
          'Use multiple communication methods',
          'Escalate to management if needed',
          'Check for related incidents',
          'Use backup communication systems'
        ]
      },
      estimated_time: '2-6 hours depending on severity',
      complexity: 'high',
      author: 'incident-commander',
      last_updated: '2025-01-10T14:00:00Z'
    },
    scope: { project: 'incident-management', branch: 'main' }
  }]
});
```

**Deployment Runbook**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'runbook',
    data: {
      title: 'Blue-Green Deployment Procedure',
      purpose: 'Deploy application updates with zero downtime using blue-green strategy',
      prerequisites: [
        'Load balancer configured for blue-green',
        'Two identical production environments',
        'Database migration scripts prepared',
        'Health check endpoints implemented',
        'Rollback plan documented'
      ],
      steps: [
        'Verify current (blue) environment health',
        'Deploy new version to green environment',
        'Run smoke tests on green environment',
        'Run comprehensive integration tests',
        'Update load balancer to route to green',
        'Monitor green environment for issues',
        'Verify user experience and performance',
        'Update blue environment with new version',
        'Complete cutover to blue environment',
        'Decommission old green environment'
      ],
      troubleshooting: {
        common_issues: [
          'Health check failures on green environment',
          'Load balancer configuration errors',
          'Database migration issues',
          'Performance degradation during switchover'
        ],
        solutions: [
          'Debug application logs for errors',
          'Verify load balancer configuration',
          'Check database migration logs',
          'Monitor system metrics during deployment'
        ]
      },
      estimated_time: '30-45 minutes',
      complexity: 'high',
      author: 'devops-team',
      last_updated: '2025-01-12T11:30:00Z'
    },
    scope: { project: 'deployment', branch: 'main' }
  }]
});
```

**Best Practices**:
- Write clear, unambiguous step instructions
- Include prerequisites to avoid missing dependencies
- Document expected outcomes and verification steps
- Include troubleshooting for common issues
- Estimate realistic timeframes
- Regularly test and update runbooks
- Include contact information for escalation

---

### 6. Change (`change`)

**Purpose**: Track code changes, system modifications, and configuration updates.

**Use Cases**:
- Code commits and pull requests
- Configuration changes
- Infrastructure modifications
- Database schema changes
- Feature implementations

**Required Fields**:
- `change_type` (string): Category of change
- `description` (string): Detailed description

**Optional Fields**:
- `files_modified` (array): List of changed files
- `impact` (object): Change impact assessment
- `metadata` (object): Additional change details
- `author` (string): Change author
- `timestamp` (string): Change timestamp

#### Examples

**Code Change Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'change',
    data: {
      change_type: 'feature',
      title: 'Add Two-Factor Authentication',
      description: 'Implement TFA for enhanced security',
      files_modified: [
        'src/auth/two-factor.service.ts',
        'src/middleware/auth.middleware.ts',
        'src/routes/auth.routes.ts',
        'tests/auth/two-factor.test.ts',
        'frontend/components/auth/two-factor.tsx'
      ],
      impact: {
        breaking_changes: false,
        api_changes: true,
        database_changes: true,
        user_experience: 'minor'
      },
      metadata: {
        pull_request: '#1234',
        commit_hash: 'abc123def456',
        reviewer: 'security-team',
        approval_status: 'approved'
      },
      author: 'backend-developer',
      timestamp: '2025-01-15T14:30:00Z'
    },
    scope: { project: 'user-service', branch: 'feature/two-factor' }
  }]
});
```

**Infrastructure Change Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'change',
    data: {
      change_type: 'infrastructure',
      title: 'Upgrade Database Cluster to v15',
      description: 'Upgrade PostgreSQL from version 14 to version 15 with new features',
      files_modified: [
        'infrastructure/docker-compose.yml',
        'infrastructure/postgresql.conf',
        'infrastructure/backup-scripts.sh'
      ],
      impact: {
        breaking_changes: true,
        database_changes: true,
        downtime_required: true,
        user_impact: 'high'
      },
      metadata: {
        change_request: 'INF-2025-015',
        approved_by: 'infrastructure-team',
        maintenance_window: '2025-01-20 02:00-04:00 UTC',
        rollback_plan: 'Documented'
      },
      author: 'infrastructure-admin',
      timestamp: '2025-01-15T09:00:00Z'
    },
    scope: { project: 'infrastructure', branch: 'main' }
  }]
});
```

**Configuration Change Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'change',
    data: {
      change_type: 'configuration',
      title: 'Update Rate Limiting Policies',
      description: 'Adjust API rate limits to handle increased traffic',
      files_modified: [
        'config/rate-limits.yml',
        'src/middleware/rate-limiter.ts'
      ],
      impact: {
        breaking_changes: false,
        api_changes: true,
        user_impact: 'neutral'
      },
      metadata: {
        reason: 'Traffic increased 300% after marketing campaign',
        new_limits: {
          'api/users': 1000,
          'api/orders': 500,
          'api/products': 2000
        },
        old_limits: {
          'api/users': 250,
          'api/orders': 125,
          'api/products': 500
        }
      },
      author: 'platform-engineer',
      timestamp: '2025-01-15T16:45:00Z'
    },
    scope: { project: 'api-platform', branch: 'main' }
  }]
});
```

**Best Practices**:
- Clearly describe the purpose and impact of changes
- List all affected files for traceability
- Include impact assessment for risk evaluation
- Reference related pull requests or change requests
- Document breaking changes for communication
- Include rollback information when applicable

---

### 7. Issue (`issue`)

**Purpose**: Track bugs, problems, incidents, and tasks requiring resolution.

**Use Cases**:
- Bug reports and defects
- Performance issues
- Security vulnerabilities
- User reported problems
- System outages

**Required Fields**:
- `title` (string): Issue description
- `severity` (string): Issue severity level
- `status` (string): Current status

**Optional Fields**:
- `description` (string): Detailed problem description
- `steps_to_reproduce` (array): Reproduction steps
- `expected_behavior` (string): Expected outcome
- `actual_behavior` (string): Actual observed behavior
- `priority` (string): Priority level
- `assignee` (string): Assigned person/team
- `category` (string): Issue category
- `environment` (string): Where issue occurs

#### Examples

**Bug Report Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'issue',
    data: {
      title: 'Memory leak in batch processing module',
      description: 'Memory usage increases continuously when processing large datasets',
      severity: 'high',
      priority: 'P1',
      status: 'open',
      category: 'performance',
      steps_to_reproduce: [
        'Navigate to batch processing page',
        'Select large dataset (>100k records)',
        'Click "Start Processing"',
        'Monitor memory usage in task manager'
      ],
      expected_behavior: 'Memory usage should remain stable during processing',
      actual_behavior: 'Memory usage increases by ~50MB per batch until application crashes',
      environment: 'production',
      affected_users: 'all users with batch access',
      reported_by: 'monitoring-system',
      assignee: 'backend-team',
      discovered_at: '2025-01-15T10:30:00Z'
    },
    scope: { project: 'data-processing', branch: 'main' }
  }]
});
```

**Security Issue Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'issue',
    data: {
      title: 'SQL Injection Vulnerability in Search API',
      description: 'Search API endpoint vulnerable to SQL injection attacks',
      severity: 'critical',
      priority: 'P0',
      status: 'in_progress',
      category: 'security',
      steps_to_reproduce: [
        'Access search endpoint: /api/search',
        'Enter malicious payload: \'; DROP TABLE users; --',
        'Execute search request'
      ],
      expected_behavior: 'Input should be sanitized and rejected',
      actual_behavior: 'Malicious SQL code executes successfully',
      environment: 'staging',
      cve_reference: 'CVE-2025-12345',
      security_team_notified: true,
      assignee: 'security-team',
      discovered_at: '2025-01-15T09:15:00Z'
    },
    scope: { project: 'security-audit', branch: 'main' }
  }]
});
```

**User Interface Issue Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'issue',
    data: {
      title: 'Mobile menu not accessible on iOS devices',
      description: 'Navigation menu cannot be opened on iPhone and iPad',
      severity: 'medium',
      priority: 'P2',
      status: 'confirmed',
      category: 'ui/ux',
      steps_to_reproduce: [
        'Open application on iPhone 14',
        'Tap menu button in top-left corner',
        'Observe that menu does not appear'
      ],
      expected_behavior: 'Menu should open and display navigation options',
      actual_behavior: 'Menu button is unresponsive',
      environment: 'production',
      affected_devices: ['iPhone', 'iPad'],
      user_reports: 15,
      browser_safari_version: '17.2',
      assignee: 'frontend-team',
      discovered_at: '2025-01-14T16:20:00Z'
    },
    scope: { project: 'mobile-app', branch: 'main' }
  }]
});
```

**Best Practices**:
- Include detailed reproduction steps for debugging
- Clearly differentiate expected vs actual behavior
- Use appropriate severity and priority levels
- Assign issues to responsible teams
- Track issue status changes over time
- Include environment and version information
- Reference related documentation or tickets

---

### 8. Decision (`decision`)

**Purpose**: Document important decisions, architecture choices, and business determinations.

**Use Cases**:
- Architecture Decision Records (ADRs)
- Technical tool selections
- Business strategy decisions
- Process changes
- Policy decisions

**Required Fields**:
- `title` (string): Decision title
- `rationale` (string): Reasoning behind decision

**Optional Fields**:
- `alternatives` (array): Considered options
- `decision` (string): Chosen option
- `impact` (object): Decision impact assessment
- `status` (string): Decision status
- `decision_date` (string): When decision was made
- `decision_maker` (string): Who made the decision
- `review_date` (string): When decision should be reviewed

#### Examples

**Architecture Decision Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'decision',
    data: {
      title: 'Use Microservices Architecture for New Platform',
      rationale: 'Microservices architecture provides better scalability, independent team autonomy, and technology diversity compared to monolithic approach. Enables faster development cycles and easier maintenance.',
      alternatives: [
        {
          option: 'Monolithic Architecture',
          pros: ['Simpler deployment', 'Easier initial development', 'Single codebase'],
          cons: ['Scalability limitations', 'Tight coupling', 'Technology lock-in']
        },
        {
          option: 'Modular Monolith',
          pros: ['Better than pure monolith', 'Clear module boundaries', 'Single deployment'],
          cons: ['Still scaling challenges', 'Shared database', 'Coordinated deployments']
        },
        {
          option: 'Service-Oriented Architecture (SOA)',
          pros: ['Service reusability', 'Technology diversity', 'Enterprise integration'],
          cons: ['Complex infrastructure', 'Overhead of ESB', 'Tight coupling through ESB']
        }
      ],
      decision: 'Microservices Architecture',
      impact: {
        level: 'high',
        affected_components: ['deployment', 'monitoring', 'team-structure'],
        migration_effort: 'high',
        timeline: '12-18 months',
        budget_impact: 'significant'
      },
      status: 'accepted',
      decision_date: '2025-01-10',
      decision_maker: 'architecture-committee',
      review_date: '2025-07-10',
      implementation_notes: 'Start with user and order services, gradually migrate other components'
    },
    scope: { project: 'platform-architecture', branch: 'main' }
  }]
});
```

**Technology Selection Decision**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'decision',
    data: {
      title: 'Select React Native for Mobile Application Development',
      rationale: 'React Native provides code sharing between iOS and Android, faster development cycles, access to native APIs, and strong ecosystem support. Team has existing React expertise.',
      alternatives: [
        {
          option: 'Flutter',
          pros: ['Single codebase for all platforms', 'Fast development', 'Google support'],
          cons: ['Smaller ecosystem', 'Limited third-party libraries', 'Team lacks experience']
        },
        {
          option: 'Native iOS/Android',
          pros: ['Best performance', 'Full access to platform features', 'Most stable'],
          cons: ['Separate codebases', 'Higher development cost', 'Slower time to market']
        },
        {
          option: 'Progressive Web App',
          pros: ['Single codebase', 'No app store deployment', 'Easy updates'],
          cons: ['Limited offline functionality', 'Performance limitations', 'No app store presence']
        }
      ],
      decision: 'React Native',
      impact: {
        level: 'medium',
        affected_components: ['mobile-app', 'team-training'],
        migration_effort: 'low',
        timeline: '6-8 months',
        budget_impact: 'moderate'
      },
      status: 'accepted',
      decision_date: '2025-01-12',
      decision_maker: 'mobile-team-lead',
      review_date: '2025-04-12'
    },
    scope: { project: 'mobile-application', branch: 'main' }
  }]
});
```

**Business Process Decision**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'decision',
    data: {
      title: 'Implement Code Review Process for All Teams',
      rationale: 'Code reviews improve code quality, knowledge sharing, and reduce defects. Creates culture of collective ownership and continuous improvement.',
      alternatives: [
        {
          option: 'No Code Reviews',
          pros: ['Faster development', 'No coordination overhead'],
          cons: ['Lower quality', 'Knowledge silos', 'More defects in production']
        },
        {
          option: 'Lightweight Code Reviews',
          pros: ['Faster than comprehensive reviews', 'Less process overhead'],
          cons: ['Limited effectiveness', 'Still missing some issues']
        },
        {
          option: 'Comprehensive Code Reviews',
          pros: ['Highest quality', 'Thorough coverage', 'Best learning'],
          cons: ['Time consuming', 'Potential bottlenecks']
        }
      ],
      decision: 'Comprehensive Code Reviews',
      impact: {
        level: 'medium',
        affected_components: ['development-process', 'team-collaboration'],
        migration_effort: 'medium',
        timeline: '1-2 months',
        budget_impact: 'development-time-investment'
      },
      status: 'accepted',
      decision_date: '2025-01-08',
      decision_maker: 'engineering-management',
      review_date: '2025-04-08',
      implementation_details: {
        'review_tools': ['GitHub PR reviews', 'SonarQube integration'],
        'review_requirements': ['At least one reviewer per PR', 'All comments addressed', 'CI/CD pipeline passes'],
        'team_training': 'GitHub workshops and best practices documentation'
      }
    },
    scope: { project: 'development-process', branch: 'main' }
  }]
});
```

**Best Practices**:
- Document the decision-making process thoroughly
- Include specific alternatives considered
- Clearly articulate reasoning and trade-offs
- Assess impact on different stakeholders
- Set review dates for important decisions
- Link to related issues or documents
- Document implementation details and next steps

---

## Risk & Planning Types

### 14. Risk (`risk`)

**Purpose**: Identify, assess, and manage risks that could impact projects or operations.

**Use Cases**:
- Technical risk assessment
- Business risk identification
- Project risk tracking
- Compliance risk management
- Operational risk planning

**Required Fields**:
- `title` (string): Risk description
- `probability` (string): Likelihood of occurrence
- `impact` (string): Potential impact level

**Optional Fields**:
- `risk_score` (number): Calculated risk priority (1-16)
- `description` (string): Detailed risk description
- `triggers` (array): Events that could trigger risk
- `mitigations` (array): Risk mitigation strategies
- `contingency_plans` (array): Backup plans
- `owner` (string): Risk owner
- `status` (string): Current risk status
- `review_date` (string): Next review date

#### Examples

**Technical Risk Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'risk',
    data: {
      title: 'Database Vendor Lock-in Risk',
      category: 'technical',
      probability: 'medium',
      impact: 'high',
      risk_score: 12, // probability (3) x impact (4)
      description: 'Heavy reliance on PostgreSQL-specific features may limit future database flexibility and increase migration costs if requirements change.',
      triggers: [
        'Need to migrate to different database vendor',
        'PostgreSQL licensing changes',
        'Performance requirements exceed PostgreSQL capabilities',
        'Cloud provider changes database offerings'
      ],
      mitigations: [
        {
          strategy: 'Database Abstraction Layer',
          implementation: 'Implement repository pattern with database-agnostic interfaces',
          owner: 'architecture-team',
          due_date: '2025-03-01',
          status: 'in_progress'
        },
        {
          strategy: 'Multi-Database Testing',
          implementation: 'Set up testing environments with MySQL and MongoDB alternatives',
          owner: 'qa-team',
          due_date: '2025-04-01',
          status: 'planned'
        },
        {
          strategy: 'Documentation and Standards',
          implementation: 'Document PostgreSQL-specific features and create migration guides',
          owner: 'technical-writers',
          due_date: '2025-02-15',
          status: 'in_progress'
        }
      ],
      contingency_plans: [
        'Develop migration scripts for PostgreSQL alternatives',
        'Document PostgreSQL-specific features used in current implementation',
        'Evaluate cloud database services as migration targets',
        'Create budget for potential migration project'
      ],
      owner: 'cto',
      status: 'active',
      created_date: '2025-01-15',
      review_date: '2025-06-15'
    },
    scope: { project: 'platform-architecture', branch: 'main' }
  }]
});
```

**Business Risk Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'risk',
    data: {
      title: 'Key Developer Attrition Risk',
      category: 'business',
      probability: 'high',
      impact: 'high',
      risk_score: 16, // probability (4) x impact (4)
      description: 'Critical team members are considering leaving for better opportunities, potentially causing project delays and knowledge loss.',
      triggers: [
        'Competitor offers with better compensation',
        'Burnout from overwork',
        'Limited career advancement opportunities',
        'Better work-life balance elsewhere'
      ],
      mitigations: [
        {
          strategy: 'Competitive Compensation Review',
          implementation: 'Conduct market salary analysis and adjust compensation packages',
          owner: 'hr-manager',
          due_date: '2025-02-01',
          status: 'in_progress'
        },
        {
          'strategy': 'Career Development Program',
          implementation: 'Create clear career paths and skill development opportunities',
          owner: 'engineering-manager',
          due_date: '2025-03-01',
          status: 'planned'
        },
        {
          'strategy': 'Work-Life Balance Improvement',
          implementation: 'Implement flexible working hours and reduced overtime expectations',
          owner: 'team-leads',
          due_date: '2025-01-30',
          status: 'in_progress'
        }
      ],
      contingency_plans: [
        'Cross-train backup team members',
        'Document critical knowledge and processes',
        'Engage contractors as temporary coverage',
        'Accelerate hiring for critical positions'
      ],
      owner: 'engineering-director',
      status: 'active',
      created_date: '2025-01-12',
      review_date: '2025-02-12'
    },
    scope: { project: 'team-management', branch: 'main' }
  }]
});
```

**Security Risk Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'risk',
    data: {
      title: 'Insufficient Security Monitoring',
      category: 'security',
      probability: 'medium',
      impact: 'high',
      risk_score: 12,
      description: 'Current security monitoring systems lack comprehensive coverage of all attack vectors and may not detect sophisticated attacks in time.',
      triggers: [
        'Advanced persistent threats (APTs)',
        'Zero-day vulnerabilities',
        'Insider threats',
        'Supply chain attacks'
      ],
      mitigations: [
        {
          strategy: 'Enhanced Security Monitoring',
          implementation: 'Deploy SIEM system with comprehensive threat detection',
          owner: 'security-team',
          due_date: '2025-03-15',
          status: 'planned'
        },
        {
          strategy: 'Regular Security Audits',
          implementation: 'Quarterly penetration testing and security assessments',
          owner: 'external-auditors',
          due_date: '2025-01-31',
          status: 'scheduled'
        },
        {
          strategy: 'Security Awareness Training',
          implementation: 'Monthly security training for all employees',
          owner: 'hr-department',
          due_date: '2025-02-01',
          status: 'ongoing'
        }
      ],
      contingency_plans: [
        'Incident response plan for security breaches',
        'Emergency communication procedures',
        'Legal and compliance notification requirements',
        'Public relations crisis management plan'
      ],
      owner: 'ciso',
      status: 'active',
      created_date: '2025-01-18',
      review_date: '2025-04-18'
    },
    scope: { project: 'security-posture', branch: 'main' }
  }]
});
```

**Best Practices**:
- Use consistent risk scoring methodology (probability x impact)
- Regularly review and update risk assessments
- Assign clear ownership and accountability
- Create specific, actionable mitigation strategies
- Develop concrete contingency plans
- Track risk status changes over time
- Involve stakeholders in risk assessment process

---

### 15. Assumption (`assumption`)

**Purpose**: Document business and technical assumptions that underlie planning and decisions.

**Use Cases**:
- Business case assumptions
- Technical feasibility assumptions
- Market condition assumptions
- Resource availability assumptions
- Timeline and dependency assumptions

**Required Fields**:
- `title` (string): Assumption description
- `description` (string): Detailed assumption details
- `impact_level` (string): Impact if assumption is invalid
- `confidence_level` (string): Confidence in assumption validity

**Optional Fields**:
- `validation_method` (string): How to validate assumption
- `validation_date` (string): When validation will occur
- `made_by` (string): Who made the assumption
- `made_date` (string): When assumption was made
- `supporting_evidence` (array): Evidence supporting assumption
- `risks_if_invalid` (array): Consequences if assumption is wrong
- `status` (string): Current assumption status

#### Examples

**Business Case Assumption Example**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'assumption',
    data: {
      title: 'High Market Demand for New Product Features',
      description: 'Assumes customers will rapidly adopt new features based on initial positive feedback from beta testing and competitive analysis',
      impact_level: 'high',
      confidence_level: 'medium',
      validation_method: 'Customer feedback surveys and usage analytics',
      validation_date: '2025-03-01',
      made_by: 'product-manager',
      made_date: '2025-01-15',
      supporting_evidence: [
        'Beta testing showed 80% positive feedback',
        'Similar features in competitors have high adoption rates',
        'User requests indicate high demand for upcoming features',
        'Market research confirms unmet needs'
      ],
      risks_if_invalid: [
        'Lower than expected revenue and user adoption',
        'Feature development resources wasted',
        'Need to pivot product strategy',
        'Budget shortfalls and timeline delays'
      ],
      monitoring_plan: [
        'Track feature adoption rates weekly',
        'Monitor user feedback channels',
        'Analyze usage patterns and drop-off points',
        'Review competitive landscape changes'
      ],
      status: 'active'
    },
    scope: { project: 'product-development', branch: 'main' }
  }]
});
```

**Technical Feasibility Assumption**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'assumption',
    data: {
      title: 'Current Infrastructure Can Support 10x Traffic Growth',
      description: 'Assumes current server infrastructure and database capacity can handle 10x increase in traffic without major architectural changes',
      impact_level: 'high',
      confidence_level: 'medium',
      validation_method: 'Load testing and capacity planning',
      validation_date: '2025-02-15',
      made_by: 'infrastructure-team',
      made_date: '2025-01-20',
      supporting_evidence: [
        'Current server utilization at 30%',
        'Database performance testing shows good headroom',
        'Cloud provider auto-scaling configured',
        'Monitoring indicates healthy performance under load'
      ],
      risks_if_invalid: [
        'System performance degradation under load',
        'User experience issues during peak traffic',
        'Revenue loss from poor performance',
        'Emergency infrastructure upgrades required',
        'Customer dissatisfaction and churn'
      ],
      mitigation_strategies: [
        'Implement proactive monitoring and alerting',
        'Prepare emergency scaling procedures',
        'Document infrastructure upgrade requirements',
        'Budget for cloud service scaling'
      ],
      status: 'active'
    },
    scope: { project: 'infrastructure-planning', branch: 'main' }
  }]
});
```

**Timeline Assumption**:
```javascript
await call_tool('memory_store', {
  items: [{
    kind: 'assumption',
    data: {
      title: 'Project Timeline Assumes No Major Blockers',
      description: 'Assumes 6-month project timeline can be achieved without encountering major technical or business blockers',
      impact_level: 'high',
      confidence_level: 'low',
      validation_method: 'Weekly risk assessment and timeline reviews',
      validation_date: '2025-01-30',
      made_by: 'project-manager',
      made_date: '2025-01-10',
      supporting_evidence: [
        'Team availability confirmed through project duration',
        'Similar projects completed on schedule',
        'Key dependencies appear stable',
        'Initial requirements appear complete'
      ],
      risks_if_invalid: [
        'Project delays and budget overruns',
        'Missed market windows or deadlines',
        'Increased costs due to extended timeline',
        'Resource conflicts with other projects',
        'Stakeholder confidence and trust issues'
      ],
      early_warning_indicators: [
        'Team member availability changes',
        'Technical complexity increases significantly',
        'Dependencies become unstable',
        'Scope creep or requirement changes'
      ],
      status: 'active'
    },
    scope: { project: 'new-product-launch', branch: 'main' }
  }]
});
```

**Best Practices**:
- Be specific and measurable in assumptions
- Assign realistic confidence levels based on available evidence
- Create concrete validation methods and dates
- Document supporting evidence thoroughly
- Consider the full impact if assumptions prove invalid
- Establish early warning indicators for potential issues
- Regularly review and update assumption validity

---

## Advanced Usage Patterns

### Knowledge Graph Relationships

```javascript
// Create a network of related knowledge items
const architectureDecision = {
  kind: 'decision',
  data: {
    title: 'Use Microservices Architecture'
  }
};

const serviceA = {
  kind: 'entity',
  data: { entity_type: 'service', name: 'user-service' }
};

const serviceB = {
  kind: 'entity',
  data: { entity_type: 'service', name: 'order-service' }
};

const dependency = {
  kind: 'relation',
  data: {
    relation_type: 'depends_on',
    source_entity: 'order-service',
    target_entity: 'user-service'
  }
};

// Store related items
await call_tool('memory_store', {
  items: [architectureDecision, serviceA, serviceB, dependency],
  deduplication: {
    enabled: true,
    merge_strategy: 'intelligent'
  }
});

// Search with graph expansion
const relatedKnowledge = await call_tool('memory_find', {
  query: 'microservices architecture decision',
  graph_expansion: {
    enabled: true,
    expansion_type: 'relations',
    max_depth: 3
  }
});
```

### Cross-Project Knowledge Sharing

```javascript
// Share knowledge across projects with scope management
const sharedKnowledge = {
  kind: 'decision',
  data: {
    title: 'Database Security Best Practices',
    rationale: 'Comprehensive security guidelines applicable across all projects'
  },
  scope: {
    org: 'company-name',
    project: 'shared-knowledge'  // Cross-project scope
  }
};

const projectSpecific = {
  kind: 'decision',
  data: {
    title: 'Project-Specific Database Configuration',
    rationale: 'Tailored configuration for specific project needs'
  },
  scope: {
    org: 'company-name',
    project: 'user-service'
  }
};

// Search across organization scope
const orgResults = await call_tool('memory_find', {
  query: 'database security best practices',
  scope: {
    org: 'company-name'
  }
});
```

### Automated Knowledge Workflows

```javascript
// Automated decision capture from code reviews
async function captureDecisionFromPR(prContext) {
  const decision = {
    kind: 'decision',
    data: {
      title: prContext.title,
      rationale: `Decision made during PR review: ${prContext.description}`,
      alternatives: [],
      decision: prContext.status === 'approved' ? 'Accepted' : 'Rejected',
      impact: {
        level: prContext.impact_level || 'medium',
        affected_components: prContext.files_modified
      },
      status: prContext.status === 'approved' ? 'accepted' : 'rejected',
      decision_date: new Date().toISOString(),
      decision_maker: 'review-team'
    },
    source: {
      tool: 'ci-cd-pipeline',
      timestamp: new Date().toISOString()
    },
    scope: {
      project: prContext.project,
      branch: prContext.branch
    }
  };

  await call_tool('memory_store', {
    items: [decision],
    deduplication: {
      enabled: true,
      enable_audit_logging: true
    }
  });
}
```

---

## Integration Examples

### Development Workflow Integration

```javascript
// Complete development workflow with knowledge tracking
class DevelopmentWorkflow {
  async startWork(workItem) {
    // Record initial task
    await call_tool('memory_store', {
      items: [{
        kind: 'todo',
        data: {
          title: workItem.title,
          status: 'in_progress',
          assignee: workItem.assignee,
          estimated_hours: workItem.estimatedHours
        },
        scope: {
          project: getCurrentProject(),
          branch: getCurrentBranch()
        }
      }]
    });
  }

  async makeDecision(decision) {
    await call_tool('memory_store', {
      items: [{
        kind: 'decision',
        data: {
          title: decision.title,
          rationale: decision.rationale,
          alternatives: decision.alternatives,
          status: 'proposed'
        },
        scope: { project: getCurrentProject() }
      }]
    });
  }

  async logObservation(observation) {
    await call_tool('memory_store', {
      items: [{
        kind: 'observation',
        data: {
          observation_type: observation.type,
          details: observation.details,
          confidence: observation.confidence
        },
        scope: { project: getCurrentProject() }
      }]
    });
  }

  async completeWork(workItemId) {
    await call_tool('memory_store', {
      items: [{
        kind: 'change',
        data: {
          change_type: 'feature',
          title: `Completed: ${workItemId}`,
          description: 'Feature successfully implemented and tested'
        },
        scope: { project: getCurrentProject() }
      }]
    });

    // Update todo status
    // Implementation would find and update the todo item
  }
}
```

### Incident Management Workflow

```javascript
class IncidentManager {
  async createIncident(incident) {
    await call_tool('memory_store', {
      items: [{
        kind: 'incident',
        data: {
          incident_id: incident.id,
          title: incident.title,
          severity: incident.severity,
          status: 'detected',
          impact: incident.impact
        },
        scope: { project: 'incident-management' }
      }]
    });

    // Send initial notifications
    await this.sendNotifications(incident);
  }

  async updateIncident(incidentId, update) {
    // Implementation would find and update the incident
    await call_tool('memory_store', {
      items: [{
        kind: 'observation',
        data: {
          observation_type: 'incident_update',
          details: {
            incident_id: incidentId,
            update_type: update.type,
            update_details: update.details,
            timestamp: new Date().toISOString()
          }
        },
        scope: { project: 'incident-management' }
      }]
    });
  }

  async resolveIncident(incidentId, resolution) {
    await call_tool('memory_store', {
      items: [{
        kind: 'incident',
        data: {
          incident_id: incidentId,
          status: 'resolved',
          resolution: resolution
        },
        scope: { project: 'incident-management' }
      }]
    });

    // Create postmortem
    await this.createPostmortem(incidentId, resolution);
  }

  async createPostmortem(incidentId, resolution) {
    await call_tool('memory_store', {
      items: [{
        kind: 'section',
        data: {
          section_type: 'postmortem',
          title: `Postmortem: ${incidentId}`,
          content: `
# Incident Postmortem: ${incidentId}

## Summary
${resolution.summary}

## Timeline
${resolution.timeline}

## Root Cause Analysis
${resolution.rootCause}

## Resolution Steps
${resolution.resolutionSteps}

## Lessons Learned
${resolution.lessonsLearned}

## Preventive Measures
${resolution.preventiveMeasures}
          `.trim()
        },
        scope: { project: 'incident-management' }
      }]
    });
  }
}
```

This comprehensive guide provides detailed coverage of all 16 knowledge types with practical examples, best practices, and integration patterns. Use this as a reference for effective knowledge management in your Cortex Memory MCP implementation.