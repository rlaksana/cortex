# MCP Cortex Troubleshooting Guide

Quick solutions to common problems.

---

## Quick Diagnostic Checklist

Run through this checklist first:

- [ ] Server is running (`Test-NetConnection -ComputerName <IP> -Port 5433`)
- [ ] PostgreSQL container is up (`wsl docker-compose ps`)
- [ ] Port forwarding is configured (`netsh interface portproxy show v4tov4`)
- [ ] Firewall allows port 5433
- [ ] Claude Desktop is restarted after config changes
- [ ] Password is correct

---

## Common Issues

### 1. "Cannot connect to server" (Client)

**Symptoms:**
- Connection test fails
- Claude Desktop shows MCP error
- Timeout errors

**Solutions:**

**A. Test basic connectivity:**
```bash
# Windows
Test-NetConnection -ComputerName 10.10.254.177 -Port 5433

# Mac/Linux
nc -zv 10.10.254.177 5433
```

**B. Verify server IP:**
```powershell
# On server, check Windows IP
ipconfig
```

**C. Check same network:**
- Both client and server must be on same LAN
- Check Wi-Fi/Ethernet connection
- Ping server: `ping 10.10.254.177`

**D. Firewall:**
```powershell
# On server, check firewall rule
Get-NetFirewallRule -DisplayName "MCP Cortex PostgreSQL"
```

---

### 2. "Port forwarding not working" (Server)

**Symptoms:**
- Server can access PostgreSQL locally
- Clients cannot connect from network

**Solutions:**

**A. Check port forwarding exists:**
```powershell
netsh interface portproxy show v4tov4
```

Should show:
```
Listen on ipv4:      Connect to ipv4:

0.0.0.0:5433         172.29.x.x:5433
```

**B. WSL IP changed after restart:**
```powershell
# Run refresh script
.\refresh-forwarding.ps1
```

**C. Manually recreate:**
```powershell
# Get WSL IP
wsl ip addr show eth0

# Remove old forwarding
netsh interface portproxy delete v4tov4 listenport=5433 listenaddress=0.0.0.0

# Add new forwarding (replace WSL_IP)
netsh interface portproxy add v4tov4 listenport=5433 listenaddress=0.0.0.0 connectport=5433 connectaddress=<WSL_IP>
```

---

### 3. "Authentication failed" (Client)

**Symptoms:**
- TCP connection works
- Database auth fails
- Error: `password authentication failed`

**Solutions:**

**A. Verify password:**
- Check `CONNECTION_INFO.txt` on server
- Password is case-sensitive

**B. Test with connection tester:**
```bash
node test-connection.js 10.10.254.177 5433 correct-password
```

**C. Reset password:**
```bash
# On server
wsl docker-compose exec postgres psql -U postgres -c "ALTER USER cortex PASSWORD 'new-password';"
```

Then update all client configs.

---

### 4. "WSL has no network" (Server)

**Symptoms:**
- WSL cannot ping internet
- Docker cannot pull images
- `ip addr show eth0` shows no IP

**Solutions:**

**A. Check .wslconfig:**
```powershell
cat $env:USERPROFILE\.wslconfig
```

Should NOT have `networkingMode=mirrored` (causes issues).

**B. Restart WSL:**
```powershell
wsl --shutdown
wsl
```

**C. Check WSL version:**
```powershell
wsl --version
```

Should be 2.0.9 or higher.

**D. Reset networking:**
```powershell
wsl --shutdown
netsh winsock reset
netsh int ip reset
wsl
```

---

### 5. "Docker container not starting" (Server)

**Symptoms:**
- `docker-compose up` fails
- Container exits immediately
- Port already in use

**Solutions:**

**A. Check Docker logs:**
```bash
wsl docker-compose logs postgres
```

**B. Port conflict:**
```bash
# Check if port 5433 is in use
wsl netstat -tlnp | grep 5433

# Or change port in docker-compose.yml
ports:
  - "5434:5432"  # Use 5434 instead
```

**C. Permissions issue:**
```bash
# Fix volume permissions
wsl sudo chown -R 999:999 ./data
```

**D. Restart Docker:**
```bash
wsl sudo service docker restart
wsl docker-compose up -d
```

---

### 6. "Claude Desktop doesn't show MCP tools" (Client)

**Symptoms:**
- Installation succeeded
- Claude Desktop restarted
- No MCP tools visible

**Solutions:**

**A. Verify config location:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Mac: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/claude/claude_desktop_config.json`

**B. Check JSON syntax:**
```powershell
# Windows
Get-Content "$env:APPDATA\Claude\claude_desktop_config.json" | ConvertFrom-Json

# Mac/Linux
cat ~/.config/claude/claude_desktop_config.json | python -m json.tool
```

**C. Verify mcpServers section exists:**
```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": ["path/to/dist/index.js"],
      "env": {
        "DATABASE_URL": "postgresql://..."
      }
    }
  }
}
```

**D. Completely restart Claude:**
- Quit Claude Desktop
- Kill processes: `taskkill /F /IM claude.exe` (Windows)
- Start Claude Desktop

**E. Check Claude Desktop version:**
- Ensure Claude Desktop is up to date
- MCP support requires recent version

---

### 7. "MCP tool calls timing out" (Client)

**Symptoms:**
- Claude shows loading spinner
- Eventually timeout error
- Connection test passes

**Solutions:**

**A. Check server load:**
```bash
wsl docker stats
```

**B. Increase timeout in config:**
```json
{
  "mcpServers": {
    "cortex-memory": {
      "command": "node",
      "args": ["path/to/dist/index.js"],
      "env": {
        "DATABASE_URL": "postgresql://...",
        "DB_POOL_MAX": "20",
        "DB_IDLE_TIMEOUT_MS": "60000"
      }
    }
  }
}
```

**C. Check database performance:**
```bash
wsl docker-compose exec postgres psql -U cortex -c "SELECT COUNT(*) FROM pg_stat_activity;"
```

---

## Error Code Reference

### Database Errors

| Code | Meaning | Solution |
|------|---------|----------|
| 28P01 | Authentication failed | Check password |
| 3D000 | Database does not exist | Create database or check name |
| 08006 | Connection failure | Check network/firewall |
| 08001 | Cannot connect | Server not running |
| 53300 | Too many connections | Increase connection pool |

### Network Errors

| Error | Meaning | Solution |
|-------|---------|----------|
| ECONNREFUSED | Connection refused | Server not listening |
| ETIMEDOUT | Connection timeout | Check firewall/network |
| EHOSTUNREACH | Host unreachable | Check IP address |
| ENETUNREACH | Network unreachable | Check network connection |

---

## Diagnostic Commands

### Server Diagnostics

```powershell
# Windows IP
ipconfig | findstr IPv4

# WSL IP
wsl ip addr show eth0

# Port forwarding rules
netsh interface portproxy show v4tov4

# Firewall rules
Get-NetFirewallRule -DisplayName "*Cortex*"

# Test local connection
Test-NetConnection -ComputerName localhost -Port 5433

# Docker status
wsl docker ps
wsl docker-compose ps

# PostgreSQL logs
wsl docker-compose logs -f postgres

# Database connections
wsl docker-compose exec postgres psql -U cortex -c "SELECT * FROM pg_stat_activity;"
```

### Client Diagnostics

```bash
# Connection test
node test-connection.js 10.10.254.177 5433 password

# Ping server
ping 10.10.254.177

# TCP connection test
# Windows
Test-NetConnection -ComputerName 10.10.254.177 -Port 5433

# Mac/Linux
nc -zv 10.10.254.177 5433

# Traceroute
tracert 10.10.254.177  # Windows
traceroute 10.10.254.177  # Mac/Linux

# Check Claude config
cat ~/.config/claude/claude_desktop_config.json | jq .mcpServers
```

---

## Performance Tuning

### Slow Queries

**Check query performance:**
```sql
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
```

**Enable pg_stat_statements:**
```bash
wsl docker-compose exec postgres psql -U cortex -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
```

### Connection Pooling

**Increase pool size:**
```json
"env": {
  "DATABASE_URL": "postgresql://...",
  "DB_POOL_MIN": "2",
  "DB_POOL_MAX": "20"
}
```

### Database Maintenance

```bash
# Vacuum database
wsl docker-compose exec postgres psql -U cortex -c "VACUUM ANALYZE;"

# Reindex
wsl docker-compose exec postgres psql -U cortex -c "REINDEX DATABASE cortex_prod;"

# Check table sizes
wsl docker-compose exec postgres psql -U cortex -c "SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;"
```

---

## Getting Help

If you've tried everything above:

1. **Gather diagnostic info:**
   ```powershell
   # On server
   .\scripts\collect-diagnostics.ps1 > diagnostics.txt
   ```

2. **Check logs:**
   - Server: `wsl docker-compose logs postgres`
   - Client: Claude Desktop logs (location varies by platform)

3. **Contact administrator** with:
   - Diagnostic info
   - Error messages
   - Steps to reproduce

4. **Create GitHub issue:**
   - Include diagnostic info
   - Redact passwords
   - Describe expected vs actual behavior

---

## Prevention Tips

### Regular Maintenance

- **Weekly:** Check disk space, review logs
- **Monthly:** Vacuum database, rotate logs
- **Quarterly:** Update passwords, review firewall rules

### Monitoring

Set up basic monitoring:

```bash
# Cron job to check server health
0 * * * * Test-NetConnection -ComputerName 10.10.254.177 -Port 5433 || echo "MCP Cortex down" | mail -s "Alert" admin@example.com
```

### Backup Strategy

- **Daily:** Automated database backups
- **Weekly:** Full system backup
- **Monthly:** Test restore procedure

---

## Advanced Troubleshooting

### Enable Debug Logging

```json
"env": {
  "DATABASE_URL": "postgresql://...",
  "LOG_LEVEL": "debug"
}
```

### Packet Capture

```powershell
# Windows
netsh trace start capture=yes tracefile=C:\temp\mcp-cortex.etl

# Reproduce issue

netsh trace stop
```

### Database Query Logging

```bash
# Enable query logging
wsl docker-compose exec postgres psql -U postgres -c "ALTER SYSTEM SET log_statement = 'all';"
wsl docker-compose restart postgres

# View logs
wsl docker-compose logs -f postgres | grep "LOG:  statement:"
```

---

**Last Updated:** 2025-01-14
