# Monitoring and Security Enhancements

This document describes the comprehensive monitoring and security enhancements implemented for the Cortex MCP system.

## 🚀 Performance Monitoring

### Overview

The performance monitoring system provides real-time insights into application performance, operation metrics, and system health. It includes automatic metrics collection, alerting, and a dashboard for visualization.

### Components

#### 1. Performance Collector (`src/monitoring/performance-collector.ts`)

The core metrics collection engine that tracks:
- Operation timing and success rates
- Memory usage and system resources
- Custom metrics for business operations
- Automatic alerting based on thresholds

**Key Features:**
- Real-time metric collection
- Percentile calculations (P95, P99)
- Memory usage monitoring
- Alert generation for performance issues
- Prometheus metrics export

**Usage:**
```typescript
import { performanceCollector, PerformanceMiddleware } from './monitoring/index.js';

// Start automated collection
performanceCollector.startCollection(60000); // 1 minute intervals

// Manual metric tracking
const endMetric = performanceCollector.startMetric('custom_operation', { userId: '123' });
// ... perform operation
endMetric();

// Using decorator
@PerformanceMiddleware.trackOperation('database_query')
async function queryDatabase(sql: string) {
  // Database operation
}
```

#### 2. Performance Middleware (`src/monitoring/performance-middleware.ts`)

Provides automatic performance tracking for HTTP requests and operations.

**Key Features:**
- HTTP request timing
- Request/response metadata collection
- Slow query detection
- Operation-specific tracking decorators

**Usage:**
```typescript
import { httpPerformance, PerformanceMiddleware } from './monitoring/index.js';

// Express middleware
app.use(httpPerformance);

// Database query tracking
const endMetric = PerformanceMiddleware.trackDatabaseQuery('SELECT * FROM users', []);
// ... execute query
endMetric();

// Function tracking decorator
class UserService {
  @PerformanceMiddleware.trackOperation('user_creation')
  async createUser(userData: any) {
    // User creation logic
  }
}
```

#### 3. Performance Dashboard (`src/monitoring/performance-dashboard.ts`)

HTTP API endpoints for monitoring and alerting.

**Endpoints:**
- `GET /monitoring/metrics` - Get performance metrics
- `GET /monitoring/alerts` - Get performance alerts
- `GET /monitoring/trends` - Get performance trends
- `GET /monitoring/health` - Health check with performance metrics
- `GET /monitoring/system` - System information

**Usage:**
```typescript
import { performanceDashboard } from './monitoring/index.js';

// Mount dashboard routes
app.use('/monitoring', performanceDashboard.getRouter());
```

### Configuration

The performance monitoring system can be configured with custom thresholds and collection intervals:

```typescript
import { performanceCollector } from './monitoring/index.js';

// Set custom alert thresholds
performanceCollector.setAlertThreshold('api_operation', 500, 2); // 500ms, 2% error rate
performanceCollector.setAlertThreshold('database_query', 200, 1); // 200ms, 1% error rate

// Configure collection intervals
performanceCollector.startCollection(30000); // 30 seconds
```

### Dashboard Integration

The dashboard can be integrated with external monitoring tools:

**Prometheus:**
```bash
curl http://localhost:3000/monitoring/metrics?format=prometheus
```

**JSON API:**
```bash
curl http://localhost:3000/monitoring/metrics
curl http://localhost:3000/monitoring/trends?timeWindow=60
curl http://localhost:3000/monitoring/alerts?severity=high
```

## 🔒 Security Enhancements

### Overview

The security middleware provides comprehensive protection against common web vulnerabilities and implements modern security best practices.

### Components

#### Security Middleware (`src/middleware/security-middleware.ts`)

A comprehensive security suite that includes:
- Rate limiting and DDoS protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- Security headers
- CORS configuration
- API key authentication

**Key Features:**
- Configurable rate limiting per IP/endpoint
- Input validation using Zod schemas
- Automatic SQL injection detection
- XSS payload sanitization
- Comprehensive security headers
- IP blocking capabilities

**Usage:**
```typescript
import { security, rateLimit, validateInput, commonSchemas } from './middleware/index.js';

// Apply comprehensive security
app.use(security);

// Apply rate limiting with custom settings
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests from this IP'
}));

// Input validation
app.post('/api/memory',
  validateInput(commonSchemas.memoryStore),
  (req, res) => {
    // Request is validated and sanitized
  }
);

// SQL injection prevention
app.use('/api/', preventSQLInjection());

// XSS protection
app.use('/api/', preventXSS());
```

#### Validation Schemas

Predefined validation schemas for common operations:

```typescript
// Memory store validation
const memoryStoreSchema = z.object({
  content: z.string().min(1).max(1000000),
  kind: z.enum(['entity', 'relation', 'observation', 'section', 'runbook', 'change', 'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption']),
  items: z.array(z.any()).optional()
});

// Memory find validation
const memoryFindSchema = z.object({
  query: z.string().min(1).max(1000),
  limit: z.number().min(1).max(1000).optional(),
  scope: z.object({
    project: z.string().optional(),
    branch: z.string().optional(),
    organization: z.string().optional()
  }).optional(),
  types: z.array(z.string()).optional()
});
```

### Security Configuration

Configure security settings based on your requirements:

```typescript
import { SecurityMiddleware } from './middleware/index.js';

const security = new SecurityMiddleware({
  enableRateLimit: true,
  enableInputValidation: true,
  enableSecurityHeaders: true,
  enableCORS: true,
  rateLimitWindowMs: 15 * 60 * 1000, // 15 minutes
  rateLimitMax: 100, // 100 requests per window
  maxRequestSize: 10 * 1024 * 1024, // 10MB
  allowedOrigins: ['https://yourdomain.com'],
  blockedIPs: ['192.168.1.100'] // Block malicious IPs
});
```

### Security Headers

The middleware automatically applies security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- Removes `X-Powered-By` header

### Rate Limiting

Configurable rate limiting with multiple strategies:

```typescript
// Global rate limiting
app.use(rateLimit());

// Endpoint-specific rate limiting
app.use('/api/auth/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 login attempts per 15 minutes
  message: 'Too many login attempts'
}));

// API key rate limiting
app.use('/api/premium/', rateLimit({
  windowMs: 60 * 1000,
  max: 1000, // Higher limit for premium users
  keyGenerator: (req) => req.apiKey // Use API key for rate limiting
}));
```

## 📊 Dependency Management

### Audit Script (`scripts/audit-dependencies.js`)

Automated dependency auditing for security vulnerabilities, outdated packages, and unused dependencies.

**Features:**
- Security vulnerability detection
- Outdated package identification
- Unused dependency analysis
- License compliance checking
- Package health analysis
- Automated fixes where possible

**Usage:**
```bash
# Run dependency audit
node scripts/audit-dependencies.js

# Generate detailed report
node scripts/audit-dependencies.js > audit-report.json

# Auto-fix common issues
npm audit fix
npm update
```

**Report Sections:**
- Outdated dependencies with severity levels
- Security vulnerabilities with fix availability
- Unused dependencies
- License compliance issues
- Package health recommendations

## 🏗️ Code Organization

### Analysis Script (`scripts/improve-code-organization.js`)

Automated code organization analysis and improvement tools.

**Features:**
- Directory structure analysis
- Circular dependency detection
- Large file identification
- Orphan file detection
- Deep nesting analysis
- Naming convention validation
- Automated refactoring

**Usage:**
```bash
# Analyze code organization
node scripts/improve-code-organization.js

# Auto-fix organizational issues
node scripts/improve-code-organization.js --fix

# Generate detailed report
node scripts/improve-code-organization.js > organization-report.json
```

**Analysis Areas:**
- Directory structure consistency
- Module dependency graph
- Circular dependencies
- File size and complexity
- Naming convention adherence
- Index file usage

## 🔧 Integration Examples

### Complete Security and Monitoring Setup

```typescript
import express from 'express';
import { performanceDashboard, httpPerformance } from './monitoring/index.js';
import { security, rateLimit, validateInput, commonSchemas } from './middleware/index.js';
import { AuthMiddleware } from './middleware/auth-middleware.js';

const app = express();
const authMiddleware = new AuthMiddleware(authService, auditService);

// Security middleware
app.use(security);
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Performance monitoring
app.use(httpPerformance);

// API routes with security
app.post('/api/memory',
  authMiddleware.authenticate({ required_scopes: [AuthScope.MEMORY_WRITE] }),
  validateInput(commonSchemas.memoryStore),
  preventSQLInjection(),
  preventXSS(),
  async (req, res) => {
    // Business logic with automatic performance tracking
  }
);

// Monitoring endpoints
app.use('/monitoring', performanceDashboard.getRouter());

// Health check
app.get('/health', performanceDashboard.getHealth.bind(performanceDashboard));
```

### Custom Performance Tracking

```typescript
import { performanceCollector, PerformanceMiddleware } from './monitoring/index.js';

class DatabaseService {
  @PerformanceMiddleware.trackOperation('database_query')
  async query(sql: string, params: any[]) {
    const endMetric = PerformanceMiddleware.trackDatabaseQuery(sql, params);

    try {
      const result = await this.pool.query(sql, params);
      endMetric();
      return result;
    } catch (error) {
      performanceCollector.recordError('database_query', error, { sql });
      throw error;
    }
  }

  @PerformanceMiddleware.trackOperation('embedding_generation')
  async generateEmbedding(text: string) {
    const endMetric = PerformanceMiddleware.trackEmbeddingGeneration(
      text.length,
      'text-embedding-ada-002'
    );

    try {
      const embedding = await this.openai.embeddings.create({
        input: text,
        model: 'text-embedding-ada-002'
      });
      endMetric();
      return embedding;
    } catch (error) {
      performanceCollector.recordError('embedding_generation', error);
      throw error;
    }
  }
}
```

## 📈 Monitoring Dashboards

### Grafana Integration

1. Add Prometheus data source
2. Import the Cortex MCP dashboard configuration
3. Set up alerts for critical metrics

### Key Metrics to Monitor

**Performance:**
- Operation duration percentiles (P50, P95, P99)
- Error rates by operation
- Request throughput
- Memory usage trends

**Security:**
- Failed authentication attempts
- Rate limit violations
- Suspicious activity patterns
- IP block events

**System:**
- Memory usage
- CPU utilization
- Database connection pool status
- Active sessions

### Alert Configuration

Configure alerts for:

1. **High Error Rate** (>5%): `cortex_operation_success_rate < 95`
2. **Slow Operations** (>2s): `cortex_operation_duration_seconds{quantile="p95"} > 2`
3. **Memory Usage** (>90%): `nodejs_memory_usage_bytes{type="heap_used"} / nodejs_memory_usage_bytes{type="heap_total"} > 0.9`
4. **Failed Logins** (>10/min): Rate of auth failures

## 🛡️ Security Best Practices

### Recommended Configuration

```typescript
const security = new SecurityMiddleware({
  // Enable all security features
  enableRateLimit: true,
  enableInputValidation: true,
  enableSecurityHeaders: true,
  enableCORS: true,

  // Strict rate limiting
  rateLimitWindowMs: 15 * 60 * 1000, // 15 minutes
  rateLimitMax: 100, // 100 requests per window

  // Reasonable request size limit
  maxRequestSize: 10 * 1024 * 1024, // 10MB

  // Restrict CORS origins
  allowedOrigins: [
    'https://yourdomain.com',
    'https://app.yourdomain.com'
  ],

  // Block known malicious IPs
  blockedIPs: []
});
```

### Security Headers

All applications should use the comprehensive security headers provided by the middleware. This protects against:

- Clickjacking (`X-Frame-Options`)
- MIME type sniffing (`X-Content-Type-Options`)
- XSS attacks (`X-XSS-Protection`)
- Referrer leakage (`Referrer-Policy`)
- Camera/microphone access (`Permissions-Policy`)

### Input Validation

Always validate input using the provided schemas:

```typescript
// Always validate request bodies
app.post('/api/endpoint',
  validateInput(commonSchemas.appropriateSchema),
  (req, res) => {
    // req.body is now validated and sanitized
  }
);

// Prevent SQL injection
app.use('/api/', preventSQLInjection());

// Prevent XSS
app.use('/api/', preventXSS());
```

## 🔍 Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check for memory leaks in the dashboard
   - Monitor large file operations
   - Review embedding generation batches

2. **Slow Operations**
   - Use the performance dashboard to identify bottlenecks
   - Check database query performance
   - Review external API call timings

3. **Security Alerts**
   - Review blocked IP addresses
   - Check rate limit violations
   - Monitor failed authentication attempts

### Debug Information

Enable debug logging for troubleshooting:

```typescript
import { logger } from './utils/logger.js';

// Set debug level
logger.level = 'debug';

// Monitor specific operations
performanceCollector.on('alert', (alert) => {
  logger.warn(alert, 'Performance alert');
});

performanceCollector.on('metric', (metric) => {
  if (metric.duration > 1000) { // Log slow operations
    logger.info(metric, 'Slow operation detected');
  }
});
```

## 📚 Additional Resources

- [Express Security Best Practices](https://expressjs.com/en/advanced/security-best-practices.html)
- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)
- [Prometheus Node.js Exporter](https://github.com/prometheus/node_exporter)
- [Grafana Dashboard Examples](https://grafana.com/grafana/dashboards/)

---

For questions or issues with the monitoring and security features, please refer to the troubleshooting section or create an issue in the project repository.