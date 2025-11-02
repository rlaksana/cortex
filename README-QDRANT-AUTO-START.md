# Qdrant Critical Memory Database - Auto-Start Configuration

## Overview

This configuration ensures the Qdrant vector database (critical for Cortex Memory operations) maintains high availability with automatic restart capabilities.

## Configuration Files

### 1. Docker Compose Configuration

- **File**: `docker-compose.qdrant-critical.yml`
- **Features**:
  - `restart: always` policy for maximum availability
  - Health checks with automatic retry logic
  - Resource limits and reservations
  - Persistent data storage
  - Network isolation

### 2. Health Check Script

- **File**: `health-check/qdrant-health.sh`
- **Features**:
  - Comprehensive health monitoring
  - Multiple retry attempts with delays
  - Collection existence verification
  - Clear success/failure reporting

### 3. PowerShell Management Script

- **File**: `scripts/start-qdrant-critical.ps1`
- **Features**:
  - Automatic container management
  - Health verification
  - Force restart capabilities
  - Continuous monitoring mode
  - Detailed logging with timestamps

## Usage

### Quick Start

```powershell
# Ensure Qdrant is running (auto-start if needed)
.\scripts\start-qdrant-critical.ps1

# Force restart (if needed)
.\scripts\start-qdrant-critical.ps1 -Force

# Continuous monitoring
.\scripts\start-qdrant-critical.ps1 -Monitor -MonitorInterval 60
```

### Docker Compose Commands

```bash
# Start with high availability configuration
wsl -d Ubuntu bash -c 'cd /mnt/d/WORKSPACE/tools-node/mcp-cortex && docker compose -f docker-compose.qdrant-critical.yml up -d qdrant'

# Check status
wsl -d Ubuntu docker ps

# View logs
wsl -d Ubuntu docker logs cortex-qdrant --tail 50
```

## High Availability Features

### 1. Restart Policy

- **Policy**: `always`
- **Behavior**: Container automatically restarts on any failure or system reboot
- **Maximum Retries**: Unlimited (continuous attempts)

### 2. Health Monitoring

- **Interval**: Every 30 seconds
- **Timeout**: 10 seconds per check
- **Retries**: 3 consecutive failures before marking unhealthy
- **Startup Grace Period**: 40 seconds initial wait

### 3. Resource Management

- **Memory Limit**: 1GB maximum
- **Memory Reservation**: 512MB minimum
- **CPU**: Shared host resources

### 4. Data Persistence

- **Volume**: `qdrant_data` with local driver
- **Location**: Docker managed volume space
- **Backup**: Volume persists across container restarts

## Monitoring and Verification

### Health Endpoints

- **Main API**: `http://localhost:6333/`
- **Info**: `http://localhost:6333/info`
- **Collections**: `http://localhost:6333/collections`

### Manual Health Check

```bash
# Basic connectivity
curl -s http://localhost:6333/ | jq .

# Detailed system info
curl -s http://localhost:6333/info | jq .
```

### Container Status

```bash
# Check running status
wsl -d Ubuntu docker ps

# Check all containers (including stopped)
wsl -d Ubuntu docker ps -a

# Inspect restart policy
wsl -d Ubuntu docker inspect cortex-qdrant | grep -A 5 RestartPolicy
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 6333/6334 are available
2. **Permission issues**: Check Docker daemon permissions
3. **Resource limits**: Monitor memory usage on constrained systems

### Recovery Commands

```powershell
# Full reset (last resort)
wsl -d Ubuntu docker stop cortex-qdrant
wsl -d Ubuntu docker rm cortex-qdrant
wsl -d Ubuntu volume rm mcp-cortex_qdrant_data
.\scripts\start-qdrant-critical.ps1 -Force
```

### Log Analysis

```bash
# Real-time logs
wsl -d Ubuntu docker logs -f cortex-qdrant

# Error filtering
wsl -d Ubuntu docker logs cortex-qdrant 2>&1 | grep -i error
```

## Integration with Cortex Memory

### Application Configuration

The Cortex Memory system should be configured to connect to:

- **HTTP Endpoint**: `http://localhost:6333`
- **gRPC Endpoint**: `localhost:6334`
- **Timeout**: 30 seconds (with retry logic)

### Failure Handling

- Application should implement exponential backoff retry
- Monitor container health before attempting operations
- Graceful degradation when database is unavailable

## Security Considerations

### Network Security

- Container runs in isolated bridge network
- Only necessary ports exposed to host
- Consider firewall rules for production environments

### Data Security

- Volumes use local driver (host filesystem access)
- Consider encryption for sensitive data
- Regular backup recommendations for critical memory data

## Performance Tuning

### Memory Optimization

- Monitor memory usage with `docker stats`
- Adjust limits based on actual usage patterns
- Consider memory-mapped storage for large datasets

### I/O Optimization

- Use SSD storage for better performance
- Monitor disk I/O during heavy operations
- Consider volume optimization for production workloads
