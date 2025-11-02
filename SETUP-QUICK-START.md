# 🚀 Cortex Memory MCP - Quick Start Guide

**Get from "just cloned" to "working Cortex MCP server" in 15-30 minutes**

This guide helps you set up the Cortex Memory MCP server from scratch. No prior knowledge required.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Steps](#installation-steps)
- [Configuration](#configuration)
- [Build & Run](#build--run)
- [Basic Usage](#basic-usage)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

---

## ⚡ Prerequisites

**Required Software:**

- **Node.js** 20.0.0 or higher
- **Git** (for cloning)
- **Docker** (for Qdrant database)
- **OpenAI API Key** (MANDATORY - system will not start without it)

**Check if you have prerequisites:**

```bash
# Check Node.js version
node --version
# Expected: v20.0.0 or higher

# Check Git
git --version
# Expected: git version 2.x.x or higher

# Check Docker
docker --version
# Expected: Docker version 20.x.x or higher

# Test OpenAI API key (replace with your key)
curl -H "Authorization: Bearer YOUR_API_KEY" https://api.openai.com/v1/models
# Expected: List of available models
```

**Estimated setup time:** 2-5 minutes

---

## 📦 Installation Steps

### Step 1: Clone and Navigate

```bash
# Clone the repository
git clone https://github.com/your-org/cortex-memory-mcp.git
cd cortex-memory-mcp

# Expected: You're now in the project root directory
ls
# Should show: package.json, src/, README.md, etc.
```

### Step 2: Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Expected output:
# ✓ Dependencies installed successfully
# ✓ 200+ packages installed
```

### Step 3: Start Qdrant Database

```bash
# Start Qdrant with Docker
docker run -d --name cortex-qdrant -p 6333:6333 qdrant/qdrant:latest

# Expected output:
# (container ID)
# Verify Qdrant is running
curl http://localhost:6333/health
# Expected: {"ok":true,"version":"..."}
```

**Time estimate:** 3-8 minutes (depends on internet speed)

---

## ⚙️ Configuration

### Step 4: Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit the .env file with your configuration
# On Windows: notepad .env
# On Mac/Linux: nano .env
```

**REQUIRED: Edit `.env` and set your OpenAI API key:**

```bash
# ⚠️ MANDATORY - Replace with your actual OpenAI API key
OPENAI_API_KEY=your-openai-api-key-here

# Keep other settings as defaults for quick start
QDRANT_URL=http://localhost:6333
SEARCH_LIMIT=50
LOG_LEVEL=info
```

**What you MUST change:**

- `OPENAI_API_KEY` - Get from https://platform.openai.com/api-keys

**Optional settings (keep defaults for now):**

- `QDRANT_URL` - Keep `http://localhost:6333`
- `SEARCH_LIMIT` - Keep `50`
- `LOG_LEVEL` - Keep `info`

**Time estimate:** 2-3 minutes

---

## 🔨 Build & Run

### Step 5: Build the Project

```bash
# Build TypeScript to JavaScript
npm run build

# Expected output:
# ✓ TypeScript compilation completed
# ✓ Generated dist/ folder with compiled code
```

### Step 6: Start the Server

```bash
# Start the Cortex MCP server
npm start

# Expected output:
# 🚀 Cortex Memory MCP Server v2.0.0
# ✅ Connected to Qdrant at localhost:6333
# ✅ OpenAI embeddings configured
# 🎯 Server running on stdio
# 📊 Memory system ready
```

**Alternative: Development mode**

```bash
# For development with auto-restart
npm run dev
```

**Time estimate:** 1-2 minutes

---

## 🎯 Basic Usage

### Test Your Setup

**Step 7A: Test Database Health**

```bash
# In a NEW terminal window (keep server running)

# Test database connection
npm run db:health

# Expected output:
# ✅ Qdrant DB healthy
# ✅ Connection: localhost:6333
# ✅ Collections: cortex-memory
```

**Step 7B: Test API Connection**

```bash
# Test OpenAI connection
npm run test:connection

# Expected output:
# ✅ Qdrant connection OK
# ✅ OpenAI API working
```

### Step 8: Your First Memory Operations

Create a test file `test-memory.js`:

```javascript
import { CortexMemoryMCP } from './dist/index.js';

// Create a memory item
const testItem = {
  kind: 'entity',
  data: {
    title: 'My First Test Entity',
    description: 'Testing the Cortex Memory system',
    content: 'This is my first knowledge item stored in Cortex',
  },
  scope: {
    project: 'my-test-project',
  },
};

// Store the item
console.log('Storing memory item...');
// (In real usage, this would be called via MCP protocol)
console.log('✅ Item stored successfully');
```

**Expected outcome:**

- ✅ Server starts without errors
- ✅ Database health check passes
- ✅ OpenAI API connection works
- ✅ Ready to receive memory operations

**Time estimate:** 2-3 minutes

---

## 🔧 Troubleshooting

### Common Issues & Solutions

**❌ Issue: "OPENAI_API_KEY is required"**

```bash
# Solution: Verify your .env file
cat .env | grep OPENAI_API_KEY
# Should show: OPENAI_API_KEY=sk-... (not the placeholder)
```

**❌ Issue: "Qdrant connection failed"**

```bash
# Check if Qdrant is running
docker ps | grep qdrant
# Should show cortex-qdrant container

# If not running, restart it:
docker start cortex-qdrant
```

**❌ Issue: "Node.js version too old"**

```bash
# Check version
node --version
# If < 20.0.0, upgrade Node.js from nodejs.org
```

**❌ Issue: "Port 6333 already in use"**

```bash
# Find what's using the port
netstat -tulpn | grep 6333
# Stop conflicting service or use different port in .env
```

**❌ Issue: Build errors**

```bash
# Clean and rebuild
rm -rf dist/ node_modules/
npm install
npm run build
```

### Get Help

**Quick diagnostic commands:**

```bash
# Check everything at once
npm run quality-check
npm run db:health
npm run test:connection
```

**Expected outputs:**

- ✅ All linters pass
- ✅ Database healthy
- ✅ Connections working

**Time estimate for troubleshooting:** 2-10 minutes

---

## ✅ Verification Checklist

**You're successful if you see:**

- [ ] `npm install` completed without errors
- [ ] Docker container `cortex-qdrant` is running
- [ ] `npm run build` created `dist/` folder
- [ ] `npm start` shows server startup messages
- [ ] `npm run db:health` returns "✅ Qdrant DB healthy"
- [ ] No error messages about missing API keys

**Total time estimate:** 10-15 minutes (experienced) or 30 minutes (beginners)

---

## 🎉 Next Steps

**You did it! Your Cortex MCP server is running. Now explore:**

1. **Read the Full Documentation:** [Developer Guide](docs/SETUP-DEVELOPER.md)
2. **API Reference:** [API Documentation](docs/API-REFERENCE.md)
3. **Advanced Configuration:** [Configuration Guide](docs/SETUP-CONFIGURATION.md)
4. **Testing:** `npm test` (run the test suite)
5. **Production Deployment:** [Deployment Guide](docs/CONFIG-DEPLOYMENT.md)

**Example next commands:**

```bash
# Run comprehensive tests
npm test

# Check code quality
npm run quality-check

# Explore API documentation
cat docs/API-REFERENCE.md
```

---

## 🆘 Still Need Help?

**Check these resources:**

- 📖 [Full Documentation Index](README.md) - 38 comprehensive guides
- 🔧 [Troubleshooting Guide](docs/TROUBLESHOOT-EMFILE.md) - Detailed problem solving
- 🐛 [GitHub Issues](https://github.com/your-org/cortex-memory-mcp/issues)
- 💬 [GitHub Discussions](https://github.com/your-org/cortex-memory-mcp/discussions)

**Quick diagnostic:**

```bash
# Generate system report
echo "=== System Info ===" && \
node --version && \
docker --version && \
echo "=== Docker Status ===" && \
docker ps && \
echo "=== Project Status ===" && \
npm run db:health
```

---

## 📚 Quick Reference

**Essential Commands:**

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript
npm start           # Start server
npm run dev         # Development mode
npm run db:health   # Check database
npm test           # Run tests
npm run lint       # Code quality
```

**File Locations:**

- Configuration: `.env`
- Main code: `src/index.ts`
- Documentation: `docs/`
- Docker files: `docker/`

**Ports Used:**

- 6333: Qdrant database
- 3000: Optional HTTP API

---

**🎯 Congratulations! You have a working Cortex Memory MCP server ready for intelligent knowledge management!**

_Last updated: 2025-10-30 | Version: 2.0.0 | Architecture: Qdrant-only_
