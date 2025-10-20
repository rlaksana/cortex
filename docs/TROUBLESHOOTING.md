# MCP Cortex Memory Troubleshooting Guide

## Table of Contents
1. [Quick Diagnostics](#quick-diagnostics)
2. [Common Issues](#common-issues)
3. [Docker Issues](#docker-issues)
4. [Database Issues](#database-issues)
5. [Application Issues](#application-issues)
6. [Performance Issues](#performance-issues)
7. [Network Issues](#network-issues)
8. [System Issues](#system-issues)
9. [Recovery Procedures](#recovery-procedures)
10. [Log Analysis](#log-analysis)
11. [Contact Support](#contact-support)

## Quick Diagnostics

### Health Check Commands

Always start with a comprehensive health check:

```powershell
# Basic health check
.\health-check.ps1

# Detailed diagnostics
.\health-check.ps1 -Detailed

# Check specific component
.\health-check.ps1 -Component database

# Continuous monitoring
.\health-check.ps1 -Continuous 60

# Generate JSON report for support
.\health-check.ps1 -OutputFormat json
```

### Log Locations

Key log files for troubleshooting:

```
# Installation logs
%TEMP%\cortex-install-*.log
%TEMP%\cortex-wsl-install-*.log
%TEMP%\cortex-docker-desktop-install-*.log

# Application logs
%TEMP%\cortex-*.log
logs\cortex.log
logs\database.log

# System logs
Windows Event Viewer -> Application
Windows Event Viewer -> System
```

## Common Issues

### Installation Fails Mid-Process

**Symptoms**: Installation stops or errors out during setup

**Solutions**:
1. **Run as Administrator**:
   ```powershell
   # Ensure PowerShell is running as Administrator
   Start-Process PowerShell -Verb RunAs
   ```

2. **Check Internet Connection**:
   ```powershell
   # Test connectivity
   Test-NetConnection google.com -Port 443
   ```

3. **Clear Temp Files and Retry**:
   ```powershell
   # Clear temp files
   Get-ChildItem $env:TEMP -Filter "cortex-*" | Remove-Item -Recurse -Force
   # Retry installation
   .\install.ps1
   ```

4. **Check Disk Space**:
   ```powershell
   # Verify sufficient disk space
   Get-PSDrive C | Select-Object Name, @{Name="FreeGB";Expression={[math]::Round($_.Free/1GB,2)}}
   ```

### "Access Denied" Errors

**Symptoms**: Permission errors during installation or operation

**Solutions**:
1. **Verify Administrator Privileges**:
   ```powershell
   # Check current user privileges
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   ```

2. **Check File Permissions**:
   ```powershell
   # Check installation directory permissions
   Get-Acl . | Format-List
   ```

3. **Reset Permissions**:
   ```powershell
   # Take ownership of installation directory
   takeown /f "C:\cortex-memory" /r /d y
   icacls "C:\cortex-memory" /grant Administrators:F /t
   ```

### Port Conflicts

**Symptoms**: Database or service fails to start due to port conflicts

**Solutions**:
1. **Check Port Usage**:
   ```powershell
   # Check if port 5433 is in use
   netstat -an | findstr 5433
   ```

2. **Identify Conflicting Process**:
   ```powershell
   # Find process using the port
   Get-NetTCPConnection -LocalPort 5433 -ErrorAction SilentlyContinue | Select-ProcessId
   Get-Process -Id <ProcessId>
   ```

3. **Stop Conflicting Service**:
   ```powershell
   # Stop conflicting PostgreSQL service
   Stop-Service postgresql* -ErrorAction SilentlyContinue
   ```

## Docker Issues

### Docker Daemon Not Running

**Symptoms**: "Cannot connect to Docker daemon" errors

**Solutions**:
1. **Start Docker Service**:
   ```powershell
   # For Docker Desktop
   Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

   # Wait for Docker to start
   Start-Sleep -Seconds 30

   # Verify Docker is running
   docker version
   ```

2. **Restart Docker**:
   ```powershell
   # Restart Docker Desktop
   Stop-Process -Name "Docker Desktop" -Force
   Start-Sleep -Seconds 10
   Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
   ```

3. **Check WSL Backend**:
   ```powershell
   # Verify WSL is running
   wsl --list --verbose

   # Restart WSL if needed
   wsl --shutdown
   wsl
   ```

### Container Fails to Start

**Symptoms**: PostgreSQL container exits immediately or fails to start

**Solutions**:
1. **Check Container Logs**:
   ```powershell
   # View container logs
   docker logs cortex-postgres-wsl
   docker logs cortex-postgres-desktop
   ```

2. **Check Container Status**:
   ```powershell
   # List all containers with status
   docker ps -a --filter "name=cortex"
   ```

3. **Remove and Recreate Container**:
   ```powershell
   # Remove failed container
   docker rm -f cortex-postgres-wsl

   # Recreate using docker-compose
   docker-compose -f docker/docker-compose.wsl.yml up -d
   ```

4. **Check Volume Issues**:
   ```powershell
   # List Docker volumes
   docker volume ls --filter "name=cortex"

   # Inspect volume
   docker volume inspect cortex_data
   ```

### Out of Memory Errors

**Symptoms**: Docker containers restart due to memory pressure

**Solutions**:
1. **Check Memory Usage**:
   ```powershell
   # Check system memory
   Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory

   # Check Docker memory usage
   docker stats --no-stream
   ```

2. **Configure Docker Memory Limits**:
   ```powershell
   # For WSL, create .wslconfig file
   @"
[wsl2]
memory=4GB
processors=2
swap=2GB
"@ | Out-File -FilePath "$env:USERPROFILE\.wslconfig" -Encoding UTF8
   ```

3. **Restart WSL**:
   ```powershell
   wsl --shutdown
   wsl
   ```

## Database Issues

### Database Connection Failed

**Symptoms**: Cannot connect to PostgreSQL database

**Solutions**:
1. **Check Database Container Status**:
   ```powershell
   # Verify container is running
   docker ps --filter "name=cortex-postgres"

   # Check container health
   docker exec cortex-postgres-wsl pg_isready -U cortex -d cortex_prod
   ```

2. **Test Connection from Host**:
   ```powershell
   # Install PostgreSQL client tools or use Docker
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT version();"
   ```

3. **Verify Database Configuration**:
   ```powershell
   # Check environment variables
   Get-ChildItem Env: | Where-Object { $_.Name -match "DATABASE|POSTGRES" }

   # Test connection string
   $env:DATABASE_URL
   ```

### Database Schema Issues

**Symptoms**: Database tables missing or schema errors

**Solutions**:
1. **Check Schema Existence**:
   ```powershell
   # List tables in database
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "\dt"
   ```

2. **Run Schema Migration**:
   ```powershell
   # Apply schema if missing
   docker exec -i cortex-postgres-wsl psql -U cortex -d cortex_prod < migrations/001_complete_schema.sql
   ```

3. **Check Extensions**:
   ```powershell
   # Verify required extensions
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "\dx"
   ```

### Database Performance Issues

**Symptoms**: Slow queries or timeouts

**Solutions**:
1. **Check Active Connections**:
   ```powershell
   # View active connections
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"
   ```

2. **Check Query Statistics**:
   ```powershell
   # Enable pg_stat_statements if not already enabled
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
   ```

3. **Optimize Configuration**:
   ```powershell
   # Check current configuration
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SHOW ALL;"

   # Update configuration if needed
   # Edit docker/docker-compose.*.yml files
   ```

## Application Issues

### MCP Server Fails to Start

**Symptoms**: Node.js application crashes or won't start

**Solutions**:
1. **Check Node.js Installation**:
   ```powershell
   # Verify Node.js version
   node --version
   npm --version

   # Should be Node.js 18+
   ```

2. **Check Dependencies**:
   ```powershell
   # Verify node_modules exists
   Test-Path .\node_modules

   # Reinstall if needed
   npm install
   ```

3. **Check Build Status**:
   ```powershell
   # Verify dist directory exists
   Test-Path .\dist

   # Rebuild if needed
   npm run build
   ```

4. **Test Application Manually**:
   ```powershell
   # Run application directly
   node .\dist\index.js

   # Check for specific error messages
   ```

### Environment Variable Issues

**Symptoms**: Configuration not loaded properly

**Solutions**:
1. **Check .env File**:
   ```powershell
   # Verify .env file exists
   Test-Path .\.env

   # Check file contents
   Get-Content .\.env
   ```

2. **Verify Environment Variables**:
   ```powershell
   # Check required variables
   $RequiredVars = @("DATABASE_URL", "MCP_SERVER_NAME", "NODE_ENV")
   foreach ($Var in $RequiredVars) {
       $Value = [System.Environment]::GetEnvironmentVariable($Var, "User")
       Write-Host "$Var = $Value"
   }
   ```

3. **Set Environment Variables**:
   ```powershell
   # Set DATABASE_URL if missing
   [System.Environment]::SetEnvironmentVariable("DATABASE_URL", "postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod", "User")
   ```

### Memory Leaks or High Memory Usage

**Symptoms**: Application memory usage increases over time

**Solutions**:
1. **Monitor Memory Usage**:
   ```powershell
   # Monitor Node.js process memory
   Get-Process | Where-Object { $_.ProcessName -eq "node" } | Select-Object ProcessName, Id, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}
   ```

2. **Restart Application**:
   ```powershell
   # Graceful restart
   # If running as service, restart service
   Restart-Service cortex-memory
   ```

3. **Check for Memory Leaks**:
   ```powershell
   # Enable Node.js heap dump
   $env:NODE_OPTIONS = "--max-old-space-size=4096"

   # Generate heap dump if needed
   # Manual intervention required
   ```

## Performance Issues

### Slow Response Times

**Symptoms**: High latency in database or application responses

**Solutions**:
1. **Benchmark Current Performance**:
   ```powershell
   # Test database response time
   $StartTime = Get-Date
   docker exec cortex-postgres-wsl pg_isready -U cortex -d cortex_prod
   $ResponseTime = (Get-Date) - $StartTime
   Write-Host "Database response time: $($ResponseTime.TotalMilliseconds)ms"
   ```

2. **Check System Resources**:
   ```powershell
   # Comprehensive system check
   .\health-check.ps1 -Detailed
   ```

3. **Optimize Database Settings**:
   ```powershell
   # Check PostgreSQL configuration
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SHOW shared_buffers;"
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SHOW effective_cache_size;"
   ```

### High CPU Usage

**Symptoms**: System CPU usage consistently high

**Solutions**:
1. **Identify High CPU Processes**:
   ```powershell
   # Get top CPU consuming processes
   Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU
   ```

2. **Check Database Queries**:
   ```powershell
   # Find long-running queries
   docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
   ```

3. **Resource Optimization**:
   ```powershell
   # Optimize Docker resource limits
   # Edit docker-compose files to adjust CPU/memory limits
   ```

## Network Issues

### Firewall Blocking Connections

**Symptoms**: Cannot connect to services despite them running

**Solutions**:
1. **Check Firewall Rules**:
   ```powershell
   # Check firewall rules for PostgreSQL
   Get-NetFirewallRule | Where-Object { $_.DisplayName -match "PostgreSQL|5433" }
   ```

2. **Allow Database Port**:
   ```powershell
   # Create firewall rule for PostgreSQL
   New-NetFirewallRule -DisplayName "PostgreSQL Cortex" -Direction Inbound -Protocol TCP -LocalPort 5433 -Action Allow
   ```

3. **Test Connectivity**:
   ```powershell
   # Test local connection
   Test-NetConnection localhost -Port 5433

   # Test connection to database
   docker exec cortex-postgres-wsl pg_isready -U cortex -d cortex_prod
   ```

### DNS Resolution Issues

**Symptoms**: Cannot resolve container names or external services

**Solutions**:
1. **Check DNS Resolution**:
   ```powershell
   # Test DNS resolution
   Resolve-DName google.com

   # Check container DNS
   docker exec cortex-postgres-wsl nslookup google.com
   ```

2. **Flush DNS Cache**:
   ```powershell
   # Clear DNS cache
   Clear-DnsClientCache
   ```

## System Issues

### Insufficient Disk Space

**Symptoms**: Services fail to start or write operations fail

**Solutions**:
1. **Check Disk Usage**:
   ```powershell
   # Check disk space usage
   Get-PSDrive C | Select-Object Name, @{Name="UsedGB";Expression={[math]::Round($_.Used/1GB,2)}}, @{Name="FreeGB";Expression={[math]::Round($_.Free/1GB,2)}}

   # Check Docker disk usage
   docker system df
   ```

2. **Clean Up Docker Resources**:
   ```powershell
   # Remove unused Docker objects
   docker system prune -a -f

   # Remove unused volumes (cautious!)
   docker volume prune -f
   ```

3. **Clean Temporary Files**:
   ```powershell
   # Clear temp files
   Get-ChildItem $env:TEMP -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
   ```

### Windows Update Interference

**Symptoms**: Services stop working after Windows updates

**Solutions**:
1. **Check Service Status**:
   ```powershell
   # Check Windows services
   Get-Service | Where-Object { $_.Name -match "docker|wsl|postgres" }
   ```

2. **Restart Services**:
   ```powershell
   # Restart Docker Desktop
   Stop-Process -Name "Docker Desktop" -Force
   Start-Sleep -Seconds 10
   Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
   ```

3. **Check for Windows Update Conflicts**:
   ```powershell
   # Check recent updates
   Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
   ```

## Recovery Procedures

### Complete System Reset

**For complete reinstallation**:

1. **Backup Current Data**:
   ```powershell
   # Create backup before reset
   .\backup.ps1 -BackupType full -Compression
   ```

2. **Complete Uninstall**:
   ```powershell
   # Remove everything
   .\uninstall.ps1 -RemoveData -RemoveBackups -Force
   ```

3. **Clean System**:
   ```powershell
   # Clear all Cortex-related data
   Get-ChildItem $env:TEMP -Filter "cortex-*" | Remove-Item -Recurse -Force
   ```

4. **Reinstall Fresh**:
   ```powershell
   # Fresh installation
   .\install.ps1
   ```

### Partial Recovery

**For component-specific recovery**:

1. **Database Recovery**:
   ```powershell
   # Recreate database container
   docker-compose -f docker/docker-compose.wsl.yml down
   docker volume rm cortex_cortex_data
   docker-compose -f docker/docker-compose.wsl.yml up -d

   # Restore from backup if needed
   .\restore.ps1 -BackupPath "backup-path" -RestoreType database
   ```

2. **Application Recovery**:
   ```powershell
   # Rebuild application
   npm run clean
   npm install
   npm run build
   ```

### Disaster Recovery

**For critical data recovery**:

1. **Locate Latest Backup**:
   ```powershell
   # Find recent backups
   Get-ChildItem $env:TEMP -Filter "cortex-backup-*" -Directory | Sort-Object Name -Descending | Select-Object -First 5
   ```

2. **System Restore Point**:
   ```powershell
   # Check for Windows restore points
   Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 5
   ```

3. **Restore from Backup**:
   ```powershell
   # Full system restore
   .\restore.ps1 -BackupPath "path-to-backup" -RestoreType full -CreateRestoreBackup
   ```

## Log Analysis

### Interpreting Health Check Results

**Status Levels**:
- **HEALTHY**: Component is functioning normally
- **WARNING**: Component works but has performance or configuration issues
- **CRITICAL**: Component is not functioning or has serious issues
- **UNKNOWN**: Component status cannot be determined

**Key Metrics**:
- **Response Time**: Database connection latency
- **Memory Usage**: RAM consumption percentage
- **CPU Usage**: Processor utilization percentage
- **Disk Usage**: Storage consumption percentage

### Reading Application Logs

**Log File Locations**:
- Main application: `logs/cortex.log`
- Database: `logs/database.log`
- System: `logs/system.log`

**Log Levels**:
- **ERROR**: Critical errors requiring immediate attention
- **WARN**: Warning conditions that should be investigated
- **INFO**: Informational messages about normal operation
- **DEBUG**: Detailed debugging information

### Database Log Analysis

**PostgreSQL Logs Location**:
```powershell
# View PostgreSQL logs
docker exec cortex-postgres-wsl tail -f /var/log/postgresql/postgresql-18-main.log
```

**Common Database Errors**:
- **Connection refused**: Database not accepting connections
- **FATAL: password authentication failed**: Incorrect credentials
- **Out of memory**: Insufficient memory allocation
- **Disk full**: Insufficient disk space

## Contact Support

### Before Contacting Support

1. **Run Health Check**:
   ```powershell
   .\health-check.ps1 -OutputFormat json > health-report.json
   ```

2. **Collect Logs**:
   ```powershell
   # Collect recent log files
   $LogDir = "support-logs-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
   New-Item -Path $LogDir -ItemType Directory -Force

   # Copy log files
   Copy-Item $env:TEMP\cortex-*.log $LogDir\
   Copy-Item logs\*.log $LogDir\ -ErrorAction SilentlyContinue
   ```

3. **Document Issue**:
   - Steps to reproduce
   - Expected vs actual behavior
   - Time when issue occurred
   - Recent changes to system

### Support Information

**What to Include in Support Request**:
- Health check JSON report
- Relevant log files
- System specifications
- Error messages
- Steps already tried

**Support Channels**:
- **GitHub Issues**: [Create New Issue](https://github.com/your-org/mcp-cortex/issues)
- **Documentation**: [Online Docs](https://docs.your-org.com/mcp-cortex)
- **Community**: [Discord/Forum Link]

### Emergency Procedures

**For Production Outages**:
1. **Immediate Backup**:
   ```powershell
   .\backup.ps1 -BackupType full -Force
   ```

2. **Fallback Plan**:
   - Use last known good backup
   - Switch to manual mode if available
   - Document all actions taken

3. **Escalation**:
   - Contact emergency support
   - Provide detailed status information
   - Follow incident response procedures

---

## Quick Reference Commands

```powershell
# Essential troubleshooting commands
.\health-check.ps1 -Detailed
docker logs cortex-postgres-wsl
Get-Process | Where-Object {$_.Name -match "node|cortex"}
Get-ChildItem $env:TEMP -Filter "cortex-*.log"

# Recovery commands
.\backup.ps1 -BackupType full
.\restore.ps1 -BackupPath "backup-path" -RestoreType full
.\uninstall.ps1 -Force
.\install.ps1

# Service management
docker-compose -f docker/docker-compose.wsl.yml restart
docker-compose -f docker/docker-compose.wsl.yml logs -f
```

For additional help, refer to the [Installation Guide](INSTALLATION.md) or [User Guide](USER_GUIDE.md).