# Relation Knowledge Type Test

## Test Relations Between System Components

### Relation 1: Service Dependency
**Source Entity:** authentication-service  
**Target Entity:** user-database-service  
**Relation Type:** depends_on  
**Strength:** strong (critical dependency)  
**Description:** Authentication service requires user database for credential validation and profile management

**Connection Details:**
- Protocol: PostgreSQL connection
- Database: user_data_prod
- Connection pool: 20 connections max
- Timeout: 5 seconds
- Retry policy: 3 attempts with exponential backoff

### Relation 2: Data Flow
**Source Entity:** authentication-service  
**Target Entity:** session-cache-service  
**Relation Type:** writes_to  
**Strength:** medium (performance optimization)  
**Description:** Authentication service writes session data to Redis cache for fast subsequent lookups

**Connection Details:**
- Protocol: Redis connection
- Cache TTL: 24 hours
- Session format: JSON Web Token + metadata
- Cache key pattern: session:{user_id}:{session_id}

### Relation 3: Event Publishing
**Source Entity:** authentication-service  
**Target Entity:** audit-log-service  
**Relation Type:** publishes_to  
**Strength:** strong (security requirement)  
**Description:** All authentication events must be logged for security audit trails

**Event Types:**
- login_success
- login_failure  
- password_change
- account_locked
- multi_factor_enabled
- session_expired

### Relation 4: API Communication
**Source Entity:** authentication-service  
**Target Entity:** notification-service  
**Relation Type:** calls  
**Strength:** weak (optional feature)  
**Description:** Authentication service calls notification service for email/SMS alerts

**Use Cases:**
- New user registration welcome emails
- Password reset notifications
- Suspicious login alerts
- Multi-factor authentication setup