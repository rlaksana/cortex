# Cortex MCP Configuration Rules

**🔒 CRITICAL CONFIGURATION RESTRICTIONS**

---

## **STRICTLY PROHIBITED: Multiple Cortex Configurations**

⚠️ **WARNING**: Only ONE Cortex MCP configuration allowed per Claude Desktop setup

### **MANDATORY RULE**
✅ Use only `[mcp_servers.cortex]` - no alternatives, backups, or multiples

### **FORBIDDEN CONFIGURATIONS**
❌ `[mcp_servers.cortex_backup]`
❌ `[mcp_servers.cortex_alt]`
❌ `[mcp_servers.cortex_test]`
❌ Any configuration with "cortex" in the name other than the primary

### **VALID CONFIGURATION**
```toml
[mcp_servers.cortex]
command = "cortex"
args = []
env = {}
```

### **VERIFICATION**
Run this command to verify compliance:
```bash
npm run mcp:check-config
```

---

## **Why This Restriction Exists**

1. **Memory Integrity**: Multiple Cortex instances can cause memory corruption
2. **Performance**: Duplicate services impact Claude Desktop performance
3. **Data Consistency**: Prevents conflicting knowledge stores
4. **Resource Management**: Avoids database connection conflicts

---

## **Configuration Validation**

### **Check Your Current Configuration**
```bash
# Check Claude Desktop configuration
npm run mcp:check-config

# Expected output: ✅ Configuration compliant
```

### **Fix Non-Compliant Configurations**
1. Open your Claude Desktop configuration file
2. Remove all `[mcp_servers.cortex_*]` sections except the primary
3. Keep only `[mcp_servers.cortex]`
4. Restart Claude Desktop

---

## **Troubleshooting**

### **Multiple Configuration Detected**
- **Error**: "Multiple Cortex configurations found"
- **Solution**: Remove duplicate Cortex configurations
- **Verify**: Run `npm run mcp:check-config` again

### **Configuration Not Found**
- **Error**: "Cortex configuration not found"
- **Solution**: Add the valid configuration shown above
- **Verify**: Restart Claude Desktop

---

## **Additional Guidelines**

### **Environment Variables**
```toml
[mcp_servers.cortex]
command = "cortex"
args = []
env = {
  "OPENAI_API_KEY": "your-key-here",
  "QDRANT_URL": "http://localhost:6333"
}
```

### **Custom Arguments**
```toml
[mcp_servers.cortex]
command = "cortex"
args = ["--log-level", "debug"]
env = {}
```

---

## **Support**

If you encounter configuration issues:
1. Run `npm run mcp:check-config` first
2. Check the [Troubleshooting Guide](docs/TROUBLESHOOT-ERRORS.md)
3. Review [Configuration Guide](docs/SETUP-CONFIGURATION.md)

---

**Last Updated: 2025-11-03**
**Version: v2.0.0**