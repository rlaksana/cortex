# Clone Setup Guide

## 🚀 Quick Setup After Clone

### **Step 1: Install Dependencies**
```bash
npm install
```

### **Step 2: Build Project**
```bash
npm run build
```

### **Step 3: Update Paths (One-time)**
Setelah clone ke lokasi baru, jalankan script untuk update paths:

**Windows:**
```cmd
cd D:\your\new\location\mcp-cortex
scripts\update-paths.bat
```

**Linux/Mac:**
```bash
cd /your/new/location/mcp-cortex
chmod +x scripts/update-paths.sh
./scripts/update-paths.sh
```

### **Step 4: Update MCP Configuration**
Copy hasil config dari `config/simple-mcp-config.json` ke MCP configuration Anda:

```json
{
  "cortex": {
    "type": "stdio",
    "command": "node",
    "args": [
      "PATH_ANDA_KE_LOKASI_BARU\dist\index.js"
    ],
    "env": {
      "OPENAI_API_KEY": "your-openai-api-key-here"
    }
  }
}
```

### **Step 5: Start Qdrant**
```bash
docker run -p 6333:6333 -d --name cortex-qdrant qdrant/qdrant:latest
```

### **Step 6: Test MCP Server**
```bash
node dist/index.js
```

## 🔧 Manual Path Update (Jika Script gagal)

Jika automated script tidak berjalan, update secara manual:

### **Critical File: MCP Configuration**
Ganti path di MCP config Anda:
```
D:\WORKSPACE\tools-node\mcp-cortex\dist\index.js
```
Menjadi:
```
D:\YOUR_NEW_LOCATION\mcp-cortex\dist\index.js
```

### **Optional: Documentation Files**
Update examples di file ini (opsional, untuk reference saja):
- `DEVELOPMENT-POLICY.md`
- `config/mcp-config-guide.md`
- `.ai-assistant-guidelines.md`

## ✅ Verification

Setelah setup, verifikasi dengan:

1. **Build successful:**
   ```bash
   npm run build
   ```

2. **File exists:**
   ```bash
   ls -la dist/index.js
   ```

3. **MCP server starts:**
   ```bash
   node dist/index.js
   ```

4. **Qdrant connection:**
   ```bash
   curl http://localhost:6333/health
   ```

## 🎯 Summary

**Hanya 1 file yang critical:** MCP configuration Anda
**File lain:** Optional documentation (bisa diabaikan)

**Keuntungan hardcoded setup:**
- ✅ Simple dan langsung jalan
- ✅ Tidak perlu environment variables
- ❌ Perlu update 1 path saat clone

It's a fair trade-off untuk simplicity!