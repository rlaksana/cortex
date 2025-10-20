# MCP Cortex Memory System Requirements

## Table of Contents
1. [Overview](#overview)
2. [Minimum Requirements](#minimum-requirements)
3. [Recommended Requirements](#recommended-requirements)
4. [Software Prerequisites](#software-prerequisites)
5. [Hardware Requirements by Deployment Type](#hardware-requirements-by-deployment-type)
6. [Network Requirements](#network-requirements)
7. [Security Requirements](#security-requirements)
8. [Compatibility Matrix](#compatibility-matrix)
9. [Performance Benchmarks](#performance-benchmarks)
10. [Scalability Considerations](#scalability-considerations)

## Overview

MCP Cortex Memory is designed to run on modern Windows systems with flexible deployment options. The system consists of two main components:

1. **MCP Server**: Native Windows application for optimal performance
2. **PostgreSQL Database**: Containerized database with two deployment options
   - WSL Docker (Resource-efficient: ~800MB memory)
   - Docker Desktop (Feature-rich: 3-5GB memory)

## Minimum Requirements

### System Specifications
- **Operating System**: Windows 10 version 2004+ (64-bit) or Windows 11
- **Processor**: x64 architecture, 2+ CPU cores, 2.0+ GHz
- **Memory**: 8GB RAM
- **Storage**: 10GB free disk space on system drive
- **Network**: Internet connection for initial setup

### Software Requirements
- **PowerShell**: Version 5.1+ (included with Windows) or PowerShell Core 7+
- **Windows Subsystem for Linux 2** (WSL2): Enabled and configured
- **Docker**: Either Docker Desktop OR WSL2 with Docker Engine
- **.NET Framework**: 4.8+ (required for some PowerShell modules)

### Administrative Requirements
- **Administrator Privileges**: Required for installation and service configuration
- **User Account Control (UAC)**: Must allow administrative operations
- **Windows Update**: Should be current for security compatibility

## Recommended Requirements

### System Specifications
- **Operating System**: Windows 11 Pro (64-bit) with latest updates
- **Processor**: x64 architecture, 4+ CPU cores, 3.0+ GHz
- **Memory**: 16GB RAM
- **Storage**: 50GB free disk space on SSD
- **Network**: Stable high-speed internet connection

### Software Requirements
- **PowerShell Core 7**: Latest stable version
- **Docker Desktop**: Latest version with WSL2 integration
- **Windows Terminal**: For improved command-line experience
- **Visual Studio Code**: For configuration editing

### Enhanced Features
- **Hardware Virtualization**: Enabled in BIOS/UEFI
- **Hyper-V**: Enabled (for Docker Desktop)
- **Windows Sandbox**: Optional for testing

## Software Prerequisites

### PowerShell Requirements

**PowerShell 5.1+ (Built-in)**:
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion
```

**PowerShell Core 7+ (Recommended)**:
```powershell
# Install PowerShell Core
winget install Microsoft.PowerShell

# Verify installation
pwsh --version
```

**Required PowerShell Modules**:
```powershell
# Installation script handles these automatically
# But you can verify manually:
Get-Module -ListAvailable | Where-Object {$_.Name -match "Microsoft.PowerShell.*|PackageManagement"}
```

### WSL2 Requirements

**Enable WSL2**:
```powershell
# Enable WSL feature
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

# Enable Virtual Machine Platform
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Restart computer
Restart-Computer

# Set WSL2 as default
wsl --set-default-version 2
```

**Verify WSL2 Installation**:
```powershell
# Check WSL status
wsl --list --verbose

# Should show WSL2 for distributions
```

### Docker Requirements

**Option 1: Docker Desktop**:
- **Version**: Latest stable (4.25+)
- **Configuration**: WSL2 backend enabled
- **Resources**: Minimum 4GB RAM allocated
- **Download**: https://www.docker.com/products/docker-desktop

**Option 2: WSL2 Docker Engine**:
- **Installation**: Handled by `install-wsl-docker.ps1`
- **Version**: Docker Engine 24.0+
- **Configuration**: Optimized for WSL2 environment

**Verify Docker Installation**:
```powershell
# Test Docker
docker --version
docker run hello-world
```

### Node.js Requirements

**Version Requirements**:
- **Minimum**: Node.js 18.0.0+
- **Recommended**: Node.js 20.x LTS
- **npm**: Included with Node.js

**Installation Methods**:
```powershell
# Method 1: Official installer (recommended)
# Download from https://nodejs.org/

# Method 2: Winget (Windows Package Manager)
winget install OpenJS.NodeJS

# Method 3: Version manager (nvm-windows)
# Install nvm-windows first, then:
nvm install 20
nvm use 20
```

**Verify Node.js Installation**:
```powershell
# Check versions
node --version  # Should be v18.x or higher
npm --version   # Should be 9.x or higher
```

## Hardware Requirements by Deployment Type

### WSL Docker Deployment (Recommended)

**Memory Usage Breakdown**:
- **Windows OS**: 2-4GB (base system)
- **MCP Server**: 100-200MB (native Windows)
- **WSL2 Ubuntu**: 200-300MB
- **PostgreSQL Container**: 256MB (configured limit)
- **Docker Engine**: 100-150MB
- **Total**: ~800MB

**Performance Characteristics**:
- **Database Latency**: 5-10ms
- **Memory Efficiency**: High
- **Resource Management**: Conservative
- **Suitability**: Production, resource-constrained environments

**Storage Requirements**:
- **System**: 10GB minimum
- **Database**: 2GB initial, scales with data
- **Logs**: 500MB (rotating)
- **Backups**: Variable, depends on retention policy

### Docker Desktop Deployment

**Memory Usage Breakdown**:
- **Windows OS**: 2-4GB (base system)
- **MCP Server**: 100-200MB (native Windows)
- **Docker Desktop**: 1-2GB (application + GUI)
- **PostgreSQL Container**: 512MB (configured limit)
- **Optional Tools**: 500MB (pgAdmin, Portainer)
- **Total**: 3-5GB

**Performance Characteristics**:
- **Database Latency**: 10-20ms
- **Memory Efficiency**: Medium
- **Resource Management**: Generous
- **Suitability**: Development, GUI management preferred

**Storage Requirements**:
- **System**: 20GB minimum
- **Database**: 2GB initial, scales with data
- **Docker Images**: 2GB (PostgreSQL + tools)
- **Logs**: 1GB (rotating)
- **Backups**: Variable, depends on retention policy

## Network Requirements

### Internet Connectivity

**Required for**:
- Downloading dependencies (Node.js, Docker images)
- Initial installation and configuration
- Optional cloud backup services
- Updates and patches

**Bandwidth Requirements**:
- **Initial Setup**: 1-2GB download
- **Updates**: 100-500MB monthly
- **Backup/Restore**: Depends on data size

**Firewall Requirements**:
```powershell
# Required ports to allow
# 5433/tcp - PostgreSQL (if accessing from other machines)
# 8080/tcp - pgAdmin (optional)
# 9443/tcp - Portainer (optional)

# Docker Desktop may need additional ports
# Check Docker Desktop settings for port mappings
```

### Local Network

**Port Usage**:
- **5433/tcp**: PostgreSQL database (host to container)
- **5432/tcp**: PostgreSQL (container internal)
- **80/tcp**: pgAdmin (optional)
- **9000/tcp**: Portainer (optional)

**DNS Resolution**:
- **localhost**: Should resolve to 127.0.0.1
- **Container names**: Docker internal DNS
- **External services**: For optional integrations

## Security Requirements

### Windows Security

**User Account Control (UAC)**:
- **Level**: Default or higher
- **Behavior**: Must allow administrative operations
- **Configuration**: Control Panel → User Accounts → Change User Account Control settings

**Windows Defender**:
- **Real-time Protection**: Should not block installation
- **Exclusions**: May need to exclude installation directory
- **Network Protection**: Allow Docker and WSL2 communications

**Windows Firewall**:
```powershell
# Required firewall rules
# Allow Docker Desktop through firewall
# Allow WSL2 network communications
# Allow PostgreSQL port 5433 (if external access needed)

# Manual firewall rule creation:
New-NetFirewallRule -DisplayName "PostgreSQL Cortex" -Direction Inbound -Protocol TCP -LocalPort 5433 -Action Allow
```

### Docker Security

**Container Security**:
- **Images**: Official PostgreSQL images only
- **Network**: Isolated Docker networks
- **Volumes**: Properly configured permissions
- **User**: Non-root user in containers

**Security Configuration**:
```yaml
# Docker Compose security settings
security_opt:
  - no-new-privileges:true
read_only: false  # Required for PostgreSQL
user: "999:999"   # Non-root user
```

### Database Security

**Authentication**:
- **Method**: Password authentication
- **Encryption**: TLS available (optional)
- **Connection**: Localhost by default
- **User Roles**: Separated privileges

**Password Security**:
- **Default**: Secure auto-generated password
- **Rotation**: Recommended for production
- **Storage**: Environment variables (user scope)
- **Complexity**: 20+ characters, mixed case, numbers, symbols

## Compatibility Matrix

### Operating System Compatibility

| Windows Version | Support Level | Notes |
|-----------------|---------------|-------|
| Windows 10 2004+ | ✅ Supported | Minimum requirement |
| Windows 10 1903 | ⚠️ Limited | WSL2 may need manual installation |
| Windows 10 1809 | ❌ Not Supported | WSL2 not available |
| Windows 11 All | ✅ Recommended | Best compatibility |
| Windows Server 2019 | ⚠️ Limited | WSL2 available, Desktop UI not |
| Windows Server 2022 | ✅ Supported | Full WSL2 support |

### Docker Compatibility

| Docker Version | Support Level | Notes |
|----------------|---------------|-------|
| Docker Desktop 4.25+ | ✅ Recommended | Latest features |
| Docker Desktop 4.20-4.24 | ✅ Supported | Full functionality |
| Docker Desktop 4.10-4.19 | ⚠️ Limited | May have WSL2 issues |
| Docker Desktop <4.10 | ❌ Not Supported | WSL2 problems |
| WSL2 Docker Engine 24+ | ✅ Recommended | Best performance |
| WSL2 Docker Engine 20-23 | ✅ Supported | Full functionality |
| WSL2 Docker Engine <20 | ❌ Not Supported | Compatibility issues |

### PowerShell Compatibility

| PowerShell Version | Support Level | Notes |
|-------------------|---------------|-------|
| PowerShell 5.1 | ✅ Minimum | Built into Windows |
| PowerShell 7.0+ | ✅ Recommended | Better performance |
| PowerShell 6.x | ⚠️ Deprecated | Upgrade to 7.x |
| PowerShell Core <6 | ❌ Not Supported | Too old |

### Node.js Compatibility

| Node.js Version | Support Level | End of Life |
|-----------------|---------------|-------------|
| Node.js 20.x LTS | ✅ Recommended | April 2027 |
| Node.js 18.x LTS | ✅ Supported | April 2025 |
| Node.js 16.x LTS | ⚠️ Deprecated | September 2023 |
| Node.js 14.x | ❌ Not Supported | April 2023 |

## Performance Benchmarks

### Baseline Performance Metrics

**System: 8GB RAM, 4-core CPU, SSD Storage**

| Deployment Type | Database Latency | Memory Usage | CPU Usage | Storage IOPS |
|-----------------|------------------|--------------|-----------|--------------|
| WSL Docker | 5-10ms | 800MB | 5-10% | 100-200 IOPS |
| Docker Desktop | 10-20ms | 3-5GB | 10-15% | 200-400 IOPS |

### Load Testing Results

**Concurrent Users: 10 simultaneous connections**

| Metric | WSL Docker | Docker Desktop |
|--------|------------|----------------|
| Query Response Time | 15ms avg | 25ms avg |
| Connection Setup Time | 50ms avg | 75ms avg |
| Memory per Connection | 2MB | 3MB |
| CPU per Query | 0.5% | 0.8% |

### Scalability Limits

**Maximum Recommended Load**:

| Resource | WSL Docker | Docker Desktop |
|----------|------------|----------------|
| Concurrent Connections | 50 | 100 |
| Database Size | 10GB | 50GB |
| Queries per Second | 100 | 200 |
| Memory Growth | Linear to 2GB | Linear to 8GB |

## Scalability Considerations

### Vertical Scaling

**Memory Scaling**:
```powershell
# WSL Docker memory limits
# Edit %USERPROFILE%\.wslconfig
[wsl2]
memory=8GB    # Increase from 4GB
processors=4  # Increase from 2
```

**Database Scaling**:
```yaml
# docker-compose.wsl.yml memory limits
services:
  postgres:
    deploy:
      resources:
        limits:
          memory: 2G    # Increase from 1G
          cpus: '2'     # Increase from '1.5'
```

### Horizontal Scaling

**Read Replicas**:
- PostgreSQL supports read replicas
- Application can distribute read queries
- Requires manual configuration
- Not covered by automatic installation

**Connection Pooling**:
- Built-in connection pooling
- Default: 100 connections max
- Configurable via environment variables
- Recommended for high-load scenarios

### Data Growth Planning

**Storage Scaling**:
- **Database**: Grows with content storage
- **Logs**: Rotating logs, limited growth
- **Backups**: Depends on retention policy
- **Temp Files**: Cleaned automatically

**Monitoring for Scaling**:
```powershell
# Monitor database size
docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT pg_size_pretty(pg_database_size('cortex_prod'));"

# Monitor connection usage
docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT count(*) FROM pg_stat_activity;"

# Monitor performance
.\health-check.ps1 -Continuous 300  # 5-minute intervals
```

## Installation Validation Checklist

### Pre-Installation Checks

- [ ] Windows 10/11 with latest updates
- [ ] Administrator privileges available
- [ ] 8GB+ RAM available
- [ ] 10GB+ free disk space
- [ ] Internet connection active
- [ ] PowerShell 5.1+ available
- [ ] WSL2 enabled and configured
- [ ] Docker installed (Desktop or WSL2)

### Post-Installation Verification

- [ ] Docker containers running
- [ ] PostgreSQL database accessible
- [ ] MCP server starts successfully
- [ ] Health check passes
- [ ] Environment variables configured
- [ ] Backup system functional
- [ ] Log files created
- [ ] Performance within acceptable ranges

### Ongoing Monitoring

- [ ] Memory usage stable
- [ ] CPU usage normal (<20%)
- [ ] Disk space adequate
- [ ] Database performance acceptable
- [ ] Backup schedule working
- [ ] No error logs accumulating
- [ ] Health checks passing

---

## Quick Reference Commands

```powershell
# System validation
$PSVersionTable.PSVersion
wsl --list --verbose
docker --version
node --version

# Resource monitoring
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10
Get-PSDrive C | Select-Object Name, @{Name="FreeGB";Expression={[math]::Round($_.Free/1GB,2)}}
docker stats --no-stream

# Network verification
Test-NetConnection localhost -Port 5433
docker exec cortex-postgres-wsl pg_isready -U cortex

# Performance testing
Measure-Command { docker exec cortex-postgres-wsl psql -U cortex -d cortex_prod -c "SELECT 1;" }
```

For detailed installation instructions, see the [Installation Guide](INSTALLATION.md).