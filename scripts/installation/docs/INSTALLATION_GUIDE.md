# MCP Cortex Installation Guide

Complete installation guide for deploying MCP Cortex in a multi-user environment with NAT mode and port forwarding.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Server Setup](#server-setup)
3. [Client Installation](#client-installation)
4. [Testing & Verification](#testing--verification)
5. [Maintenance](#maintenance)
6. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Network Topology

```
┌─────────────────────────────────────────────────┐
│  Server Computer (e.g., 10.10.254.177)          │
│  ├─ Windows: 10.10.254.177 (Primary IP)         │
│  ├─ WSL (NAT): 172.29.227.247 (Internal)        │
│  │  └─ Docker PostgreSQL :5433                  │
│  └─ Port Forward:                                │
│     10.10.254.177:5433 → 172.29.227.247:5433   │
└─────────────────────────────────────────────────┘
              ↑ ↑ ↑
   Users connect to: 10.10.254.177:5433
              │ │ │
    ┌─────────┘ │ └─────────┐
    │           │           │
┌───┴────┐  ┌──┴───┐  ┌───┴────┐
│ User 1 │  │User 2│  │ User N │
│Windows │  │ Mac  │  │ Linux  │
└────────┘  └──────┘  └────────┘
```

### Why NAT Mode?

**Mirrored mode is NOT supported** on systems with:
- Active VPN connections (NordVPN, etc.)
- Complex Hyper-V virtual network configurations
- Enterprise network policies

**NAT mode with port forwarding** is the reliable alternative that works in all environments.

---

## Server Setup

### Prerequisites

- ✅ Windows 10/11 with WSL2
- ✅ Docker installed in WSL2
- ✅ Administrator privileges
- ✅ Stable local network connection

### Step 1: Prepare Server

1. **Clone/Download MCP Cortex:**
   ```bash
   cd /path/to/projects
   git clone https://github.com/your-org/mcp-cortex
   cd mcp-cortex
   ```

2. **Ensure Docker is running in WSL:**
   ```bash
   wsl
   docker --version
   sudo service docker start  # if not running
   ```

### Step 2: Run Server Setup

1. **Open PowerShell as Administrator**
   - Right-click PowerShell → "Run as Administrator"

2. **Navigate to installation scripts:**
   ```powershell
   cd D:\path\to\mcp-cortex\scripts\installation\server
   ```

3. **Run setup script:**
   ```powershell
   .\setup-server.ps1
   ```

   Or with custom password:
   ```powershell
   .\setup-server.ps1 -DbPassword "your-secure-password"
   ```

### Step 3: Note Connection Info

The script will output connection information:

```
═══════════════════════════════════════════════════════════
 CONNECTION DETAILS FOR YOUR 20 USERS
═══════════════════════════════════════════════════════════

Server IP:        10.10.254.177
Port:             5433
Database:         cortex_prod
Username:         cortex
Password:         [generated-password]

Connection String:
postgresql://cortex:[password]@10.10.254.177:5433/cortex_prod
```

**Save this information!** You'll need to share it with your users.

### What the Setup Script Does

1. ✅ Detects your Windows IP address
2. ✅ Detects WSL IP address
3. ✅ Starts PostgreSQL Docker container
4. ✅ Configures Windows port forwarding (netsh)
5. ✅ Creates Windows Firewall rule
6. ✅ Tests connectivity
7. ✅ Generates CONNECTION_INFO.txt file

---

## Client Installation

### For Windows Users

1. **Download installation package**
   - Receive `install-windows.ps1` from administrator

2. **Open PowerShell** (no admin needed)

3. **Run installer:**
   ```powershell
   .\install-windows.ps1 -ServerIP 10.10.254.177 -Password "your-password"
   ```

4. **Restart Claude Desktop**

### For Mac Users

1. **Download installation package**
   - Receive `install-mac.sh` from administrator

2. **Open Terminal**

3. **Make executable and run:**
   ```bash
   chmod +x install-mac.sh
   ./install-mac.sh 10.10.254.177 5433 your-password
   ```

4. **Restart Claude Desktop**

### For Linux Users

1. **Download installation package**
   - Receive `install-linux.sh` from administrator

2. **Open Terminal**

3. **Make executable and run:**
   ```bash
   chmod +x install-linux.sh
   ./install-linux.sh 10.10.254.177 5433 your-password
   ```

4. **Restart Claude Desktop**

### What the Client Installer Does

1. ✅ Locates Claude Desktop configuration
2. ✅ Backs up existing configuration
3. ✅ Adds MCP Cortex server configuration
4. ✅ Tests connectivity to server
5. ✅ Displays next steps

---

## Testing & Verification

### Server-Side Testing

**Check PostgreSQL is running:**
```bash
wsl docker-compose ps
```

**Check port forwarding:**
```powershell
netsh interface portproxy show v4tov4
```

**Test local connectivity:**
```powershell
Test-NetConnection -ComputerName 10.10.254.177 -Port 5433
```

### Client-Side Testing

**Use the connection tester:**
```bash
node test-connection.js 10.10.254.177 5433 your-password
```

Expected output:
```
═══════════════════════════════════════════════════════════
 TEST SUMMARY
═══════════════════════════════════════════════════════════

TCP Connection:        ✅ PASS
Database Connection:   ✅ PASS
Query Execution:       ✅ PASS

✅✅✅ ALL TESTS PASSED ✅✅✅
```

### In Claude Desktop

1. Open Claude Desktop
2. Start a new conversation
3. Claude will show available MCP tools
4. On first use, Claude will prompt for tool approval (click "Allow")
5. Test with: "Store this to memory: Test entry"

---

## Maintenance

### If WSL Restarts

When WSL restarts, its IP address may change. You'll need to update port forwarding:

```powershell
cd D:\path\to\mcp-cortex\scripts\installation\server
.\refresh-forwarding.ps1
```

This script:
- Detects new WSL IP
- Removes old port forwarding
- Creates new port forwarding
- Tests connectivity

### Regular Maintenance Tasks

**View PostgreSQL logs:**
```bash
wsl docker-compose logs -f postgres
```

**Restart PostgreSQL:**
```bash
wsl docker-compose restart
```

**Stop PostgreSQL:**
```bash
wsl docker-compose down
```

**Start PostgreSQL:**
```bash
wsl docker-compose up -d
```

**Check disk usage:**
```bash
wsl docker system df
```

### Backup Database

**Create backup:**
```bash
wsl docker-compose exec postgres pg_dump -U cortex cortex_prod > backup-$(date +%Y%m%d).sql
```

**Restore backup:**
```bash
cat backup-20250114.sql | wsl docker-compose exec -T postgres psql -U cortex cortex_prod
```

---

## Troubleshooting

### Users Cannot Connect

**1. Verify server is running:**
```powershell
Test-NetConnection -ComputerName 10.10.254.177 -Port 5433
```

**2. Check port forwarding:**
```powershell
netsh interface portproxy show v4tov4
```

**3. Check firewall:**
```powershell
Get-NetFirewallRule -DisplayName "MCP Cortex PostgreSQL"
```

**4. Verify WSL networking:**
```bash
wsl ip addr show eth0
wsl ping google.com
```

### Port Forwarding Not Working

**Remove and recreate:**
```powershell
# Remove
netsh interface portproxy delete v4tov4 listenport=5433 listenaddress=0.0.0.0

# Get WSL IP
wsl ip addr show eth0 | findstr "inet "

# Recreate (replace WSL_IP)
netsh interface portproxy add v4tov4 listenport=5433 listenaddress=0.0.0.0 connectport=5433 connectaddress=<WSL_IP>
```

### Claude Desktop Not Showing MCP Tools

**1. Check configuration file exists:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Mac: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/claude/claude_desktop_config.json`

**2. Verify JSON syntax:**
```bash
# Mac/Linux
cat ~/.config/claude/claude_desktop_config.json | python -m json.tool

# Windows
Get-Content "$env:APPDATA\Claude\claude_desktop_config.json" | ConvertFrom-Json
```

**3. Restart Claude Desktop completely:**
- Quit Claude Desktop
- Kill any remaining processes
- Start Claude Desktop again

### Database Connection Errors

**Authentication failed (28P01):**
- Verify password is correct
- Check CONNECTION_INFO.txt on server

**Database does not exist (3D000):**
- Run migrations: `wsl docker-compose exec postgres psql -U cortex -c "CREATE DATABASE cortex_prod;"`

**Connection timeout:**
- Check network connectivity
- Verify server IP is correct
- Ensure you're on the same network

---

## Security Considerations

### Password Management

- Use strong, random passwords (generated by setup script)
- Don't share passwords in plain text (use password manager)
- Rotate passwords periodically

### Network Security

- MCP Cortex is designed for **LAN use only**
- Do NOT expose to public internet without VPN
- Consider using firewall rules to restrict access to known IP ranges

### Firewall Configuration

**Allow specific IPs only:**
```powershell
New-NetFirewallRule -DisplayName "MCP Cortex (Restricted)" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5433 `
    -Action Allow `
    -RemoteAddress 192.168.1.0/24
```

---

## Advanced Configuration

### Custom Port

If port 5433 is already in use, specify a different port:

**Server:**
```powershell
.\setup-server.ps1 -Port 5434
```

**Client:**
```powershell
.\install-windows.ps1 -ServerIP 10.10.254.177 -Port 5434 -Password "pass"
```

### Multiple Databases

To support multiple projects, create additional databases:

```bash
wsl docker-compose exec postgres psql -U cortex -c "CREATE DATABASE project2_db;"
```

Update connection strings accordingly.

---

## Support

For issues or questions:

1. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
2. Run connection tester: `node test-connection.js`
3. Contact system administrator
4. Check GitHub issues: [github.com/your-org/mcp-cortex/issues]

---

## Changelog

- **v1.0.0** (2025-01-14): Initial release with NAT mode support
