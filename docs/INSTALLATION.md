# MCP Cortex Memory Installation Guide

## Table of Contents
1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation Options](#installation-options)
4. [Quick Start Installation](#quick-start-installation)
5. [Manual Installation](#manual-installation)
6. [Post-Installation Configuration](#post-installation-configuration)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

## Overview

MCP Cortex Memory is a comprehensive knowledge management system with autonomous decision support capabilities. This guide will walk you through the installation process on Windows systems.

### Architecture
- **MCP Server**: Runs natively on Windows for optimal performance
- **PostgreSQL Database**: Runs in Docker containers (WSL2 or Docker Desktop)
- **Resource Usage**:
  - WSL Docker: ~800MB total memory (recommended)
  - Docker Desktop: 3-5GB total memory (with GUI management)

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11 (64-bit) with WSL2 support
- **Memory**: 8GB RAM (16GB recommended)
- **Storage**: 10GB free disk space
- **Processor**: x64 architecture, 2+ cores

### Software Requirements
- **PowerShell**: Windows PowerShell 5.1+ or PowerShell Core 7+
- **Docker**: Either Docker Desktop or WSL2 with Docker Engine
- **Node.js**: Version 18+ (auto-installed)
- **Git**: For version control operations (optional)

### Network Requirements
- Internet connection for downloading dependencies
- Administrative privileges for installation

## Installation Options

### Option 1: WSL Docker (Recommended)
- **Memory Usage**: ~800MB
- **Performance**: 5-10ms latency
- **Management**: Command-line interface
- **Resource Efficiency**: Optimized for minimal resource usage

### Option 2: Docker Desktop
- **Memory Usage**: 3-5GB
- **Performance**: 10-20ms latency
- **Management**: GUI interface with visual tools
- **Resource Usage**: Higher but includes management tools

## Quick Start Installation

### One-Click Installation

1. **Download and extract** the MCP Cortex Memory package to your desired location.

2. **Open PowerShell as Administrator**:
   ```powershell
   # Right-click Start menu and select "Windows PowerShell (Admin)"
   # OR
   Start-Process PowerShell -Verb RunAs
   ```

3. **Navigate to installation directory**:
   ```powershell
   cd C:\path\to\mcp-cortex
   ```

4. **Run the installer**:
   ```powershell
   .\install.ps1
   ```

5. **Follow the interactive prompts**:
   - Choose your Docker deployment option (WSL or Docker Desktop)
   - Review system requirements
   - Confirm installation settings
   - Wait for completion

6. **Verify installation**:
   ```powershell
   .\health-check.ps1
   ```

### What the Installer Does

The one-click installer performs the following steps:

1. **System Validation**
   - Checks administrator privileges
   - Validates system requirements
   - Verifies PowerShell version

2. **Docker Environment Setup**
   - Installs and configures Docker (WSL or Desktop)
   - Creates Docker networks and volumes
   - Optimizes performance settings

3. **Database Deployment**
   - Deploys PostgreSQL 18 in Docker container
   - Configures database with optimal settings
   - Creates necessary schemas and extensions

4. **Application Setup**
   - Installs Node.js and dependencies
   - Builds MCP server application
   - Configures environment variables

5. **Service Configuration**
   - Sets up automatic startup
   - Creates health monitoring
   - Configures backup system

## Manual Installation

If you prefer manual installation or need to customize the setup:

### Step 1: Docker Environment Setup

#### For WSL Docker:
```powershell
# Install WSL2
wsl --install

# Install Docker in WSL2 Ubuntu
.\install-wsl-docker.ps1
```

#### For Docker Desktop:
```powershell
# Install Docker Desktop
.\install-docker-desktop.ps1
```

### Step 2: Database Deployment

```powershell
# Deploy using WSL configuration
docker-compose -f docker/docker-compose.wsl.yml up -d

# OR deploy using Docker Desktop configuration
docker-compose -f docker/docker-compose.desktop.yml up -d
```

### Step 3: Application Installation

```powershell
# Install Node.js (if not already installed)
# Download from https://nodejs.org/

# Install dependencies
npm install

# Build application
npm run build

# Copy environment configuration
copy config\env-template.env .env

# Edit .env file with your settings
notepad .env
```

### Step 4: Service Configuration

```powershell
# Test MCP server
node dist/index.js

# Configure for automatic startup (optional)
# Follow instructions in USER_GUIDE.md
```

## Post-Installation Configuration

### Environment Variables

Key environment variables in `.env`:

```bash
# Database Connection
DATABASE_URL=postgresql://cortex:cortex_pg18_secure_2025_key@localhost:5433/cortex_prod

# MCP Server Configuration
MCP_SERVER_NAME=cortex-memory
MCP_TRANSPORT=stdio

# Logging
LOG_LEVEL=info
NODE_ENV=production

# Scope Inference
CORTEX_ORG=my-org
CORTEX_PROJECT=cortex
CORTEX_BRANCH=main
```

### Database Configuration

PostgreSQL is automatically configured with optimal settings:

- **Shared Buffers**: 256MB (WSL) / 512MB (Desktop)
- **Connection Pool**: 100 (WSL) / 150 (Desktop)
- **Performance Tuning**: Optimized for respective environments

### Backup Configuration

Automatic backup system includes:

- **Frequency**: Daily (configurable)
- **Retention**: 30 days (configurable)
- **Compression**: Enabled by default
- **Storage**: Local with cloud option

## Verification

### Health Check

Run comprehensive health check:

```powershell
# Check all components
.\health-check.ps1

# Check specific component
.\health-check.ps1 -Component database

# Detailed output
.\health-check.ps1 -Detailed

# Continuous monitoring
.\health-check.ps1 -Continuous 60
```

### Manual Verification Steps

1. **Database Connectivity**:
   ```powershell
   docker exec cortex-postgres-wsl pg_isready -U cortex -d cortex_prod
   ```

2. **MCP Server Test**:
   ```powershell
   node dist/index.js --test
   ```

3. **Service Status**:
   ```powershell
   Get-Service | Where-Object { $_.Name -like "*cortex*" }
   ```

### Expected Results

Successful installation should show:

- ✅ All health checks passing
- ✅ Database container running
- ✅ MCP server accessible
- ✅ Environment variables configured
- ✅ Backup system operational

## Troubleshooting

### Common Issues

#### Docker Issues
```powershell
# Docker not starting
Restart-Service docker

# Permission denied
# Run PowerShell as Administrator

# Container not running
docker ps -a
docker logs cortex-postgres-wsl
```

#### Database Issues
```powershell
# Connection refused
# Check port 5433 availability
netstat -an | findstr 5433

# Database not ready
docker exec cortex-postgres-wsl pg_isready -U cortex
```

#### Application Issues
```powershell
# Node modules missing
npm install

# Build errors
npm run clean
npm run build

# Environment issues
Get-ChildItem Env: | Where-Object { $_.Name -match "CORTEX|MCP" }
```

### Recovery Procedures

#### Complete Reinstall
```powershell
# Uninstall completely
.\uninstall.ps1 -RemoveData -Force

# Reinstall fresh
.\install.ps1
```

#### Restore from Backup
```powershell
# Restore last backup
.\restore.ps1 -BackupPath "C:\path\to\backup" -RestoreType full
```

### Support Resources

- **Log Files**: Check `%TEMP%\cortex-*.log` for detailed logs
- **Health Reports**: Run health check with `-OutputFormat json`
- **Documentation**: See `docs/` directory for detailed guides
- **Community**: [GitHub Issues](https://github.com/your-org/mcp-cortex/issues)

### Performance Optimization

#### WSL Docker Optimization
```powershell
# Configure WSL memory limits
# Create %USERPROFILE%\.wslconfig file:
[wsl2]
memory=4GB
processors=2
swap=2GB
```

#### Docker Desktop Optimization
- Allocate 4GB+ RAM to Docker Desktop
- Enable WSL2 integration
- Configure resource limits in Docker settings

## Next Steps

After successful installation:

1. **Read the User Guide**: `docs/USER_GUIDE.md`
2. **Configure Memory Settings**: Customize for your use case
3. **Set Up Backups**: Configure backup schedule and destinations
4. **Integrate with Claude Desktop**: Follow integration guide
5. **Explore Features**: Check `docs/FEATURES.md`

---

## Installation Script Reference

### Main Installer
- **File**: `install.ps1`
- **Purpose**: One-click installation with Docker choice
- **Options**: Interactive prompts, system validation, backup creation

### Setup Scripts
- **File**: `install-wsl-docker.ps1`
- **Purpose**: WSL2 Docker installation and configuration
- **Resource**: ~800MB memory usage

- **File**: `install-docker-desktop.ps1`
- **Purpose**: Docker Desktop installation and configuration
- **Resource**: 3-5GB memory usage

### Management Scripts
- **backup.ps1**: Comprehensive system backup
- **restore.ps1**: System restore from backup
- **health-check.ps1**: Health monitoring and diagnostics
- **uninstall.ps1**: Complete system removal with rollback

For detailed script options and parameters, refer to individual script documentation.