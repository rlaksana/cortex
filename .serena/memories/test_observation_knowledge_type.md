# Observation Knowledge Type Test

## Technical Observations

### Observation 1: Database Performance Issue
**Observed Fact:** PostgreSQL query performance degradation during peak hours (2-4 PM)
**Measurement:** Average query response time increased from 50ms to 450ms
**Timestamp:** 2025-10-25 14:30:00 UTC
**Observer:** database-monitoring-system
**Impact:** High - affecting user authentication latency

**Supporting Data:**
- Database: user_data_prod
- Table: user_credentials (index scan)
- Query type: SELECT with JOIN operations
- Concurrent connections: 185/200 (92.5% utilization)
- CPU usage: 78% on database server

### Observation 2: Memory Usage Pattern
**Observed Fact:** Authentication service memory usage shows gradual increase over 7-day period
**Measurement:** Memory usage grew from 512MB to 1.2GB (134% increase)
**Timestamp:** 2025-10-18 09:00:00 UTC - 2025-10-25 09:00:00 UTC
**Observer:** application-performance-monitor
**Impact:** Medium - potential memory leak investigation needed

**Memory Analysis:**
- Heap usage: 890MB (74% of total)
- Cached sessions: 45,000 objects
- JWT token cache: 234MB
- Connection pool buffers: 156MB

### Observation 3: Security Event Pattern
**Observed Fact:** Increased failed login attempts from specific IP ranges
**Measurement:** 15,000 failed attempts from 3 IP ranges over 24 hours
**Timestamp:** 2025-10-24 00:00:00 UTC - 2025-10-25 00:00:00 UTC
**Observer:** security-monitoring-system
**Impact:** High - potential brute force attack

**Attack Pattern:**
- IP ranges: 192.168.1.0/24, 10.0.0.0/24, 172.16.0.0/24
- Target accounts: admin@company.com (85% of attempts)
- Attack method: password spraying
- Rate limit triggers: 1,247 blocks automatically applied

### Observation 4: API Usage Statistics
**Observed Fact:** Mobile app API usage increased by 300% after new feature release
**Measurement:** API calls increased from 1,000/hour to 4,000/hour
**Timestamp:** 2025-10-23 16:00:00 UTC - 2025-10-25 16:00:00 UTC
**Observer:** api-gateway-metrics
**Impact:** Low - positive usage growth, scaling considerations needed

**Usage Breakdown:**
- Mobile refresh tokens: 60%
- Profile updates: 25%
- Password changes: 10%
- Multi-factor setup: 5%