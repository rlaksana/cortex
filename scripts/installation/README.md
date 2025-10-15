# MCP Cortex Installation Package

Complete installation package for deploying MCP Cortex to multiple users with NAT mode and port forwarding.

---

## Quick Start

### For Server Administrator

1. **Run server setup:**
   ```powershell
   cd server
   .\setup-server.ps1
   ```

2. **Share connection info with users:**
   - Provide `CONNECTION_INFO.txt`
   - Distribute client installer scripts

### For Users (Clients)

**Windows:**
```powershell
cd client
.\install-windows.ps1 -ServerIP 10.10.254.177 -Password "your-password"
```

**Mac:**
```bash
cd client
chmod +x install-mac.sh
./install-mac.sh 10.10.254.177 5433 your-password
```

**Linux:**
```bash
cd client
chmod +x install-linux.sh
./install-linux.sh 10.10.254.177 5433 your-password
```

---

## Package Contents

```
installation/
├── server/                      # Server setup scripts
│   ├── setup-server.ps1         # Main server setup (run once)
│   ├── refresh-forwarding.ps1   # Update port forwarding (run after WSL restart)
│   └── README-SERVER.md         # Server documentation
│
├── client/                      # Client installer scripts
│   ├── install-windows.ps1      # Windows installer
│   ├── install-mac.sh           # Mac installer
│   ├── install-linux.sh         # Linux installer
│   ├── test-connection.js       # Connection diagnostic tool
│   └── README-CLIENT.md         # Client documentation
│
└── docs/                        # Documentation
    ├── INSTALLATION_GUIDE.md    # Complete installation guide
    └── TROUBLESHOOTING.md       # Troubleshooting guide
```

---

## Architecture

**NAT Mode with Port Forwarding:**
- Server runs PostgreSQL in WSL2 Docker
- Windows port forwarding exposes PostgreSQL to LAN
- Clients connect via server's Windows IP

**Why NAT Mode?**
- WSL2 mirrored mode is NOT supported with VPNs and complex networks
- NAT mode with port forwarding works in all environments
- Proven reliability for multi-user deployments

---

## Documentation

- **[Installation Guide](docs/INSTALLATION_GUIDE.md)** - Complete setup instructions
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[Server README](server/README-SERVER.md)** - Server administration
- **[Client README](client/README-CLIENT.md)** - Client installation

---

## System Requirements

### Server Requirements
- Windows 10/11 with WSL2
- Docker in WSL2
- Administrator privileges
- Stable network connection
- Minimum 4GB RAM, 10GB disk space

### Client Requirements
- Claude Desktop installed
- Network access to server
- Node.js (for connection testing)

---

## Support

1. Check [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
2. Run connection tester: `node client/test-connection.js`
3. Contact system administrator
4. GitHub issues: [github.com/your-org/mcp-cortex/issues]

---

## Version

**v1.0.0** - Initial release with NAT mode support

**Tested on:**
- Windows 11 Enterprise (Build 26200)
- WSL 2.6.1.0
- PostgreSQL 18 Alpine
- Claude Desktop (latest)

---

## License

[Your License Here]

---

## Credits

MCP Cortex Installation Package
Generated: 2025-01-14
