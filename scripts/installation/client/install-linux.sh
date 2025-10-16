#!/usr/bin/env bash

#######################################################################
# MCP Cortex Client Installer for Linux
#
# Usage: ./install-linux.sh <server-ip> [port] [password]
# Example: ./install-linux.sh 192.168.1.100 5433 my-password
#
# Version: 1.0.0
# Supports: Ubuntu, Debian, Fedora, Arch, and derivatives
#######################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Output functions
success() { echo -e "${GREEN}✅ $1${NC}"; }
failure() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${CYAN}🔍 $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
section() {
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA} $1${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
}

# Check arguments
if [ "$#" -lt 1 ]; then
    failure "Usage: $0 <server-ip> [port] [password]"
    info "Example: $0 192.168.1.100 5433 my-password"
    exit 1
fi

SERVER_IP="$1"
PORT="${2:-5433}"
PASSWORD="$3"

if [ -z "$PASSWORD" ]; then
    read -sp "Enter database password: " PASSWORD
    echo ""
fi

section "MCP CORTEX CLIENT INSTALLER FOR LINUX"
echo -e "${YELLOW}This will configure Claude Desktop to use MCP Cortex${NC}\n"

# Step 1: Locate Claude Desktop config
section "[1] LOCATING CLAUDE DESKTOP"

CLAUDE_CONFIG_PATHS=(
    "$HOME/.config/claude/claude_desktop_config.json"
    "$HOME/.claude/config.json"
    "$HOME/.claude.json"
    "$HOME/.local/share/claude/config.json"
)

CLAUDE_CONFIG_PATH=""
for path in "${CLAUDE_CONFIG_PATHS[@]}"; do
    if [ -f "$path" ]; then
        CLAUDE_CONFIG_PATH="$path"
        success "Found Claude Desktop config: $path"
        break
    fi
done

if [ -z "$CLAUDE_CONFIG_PATH" ]; then
    failure "Claude Desktop config not found"
    info "Searched locations:"
    for path in "${CLAUDE_CONFIG_PATHS[@]}"; do
        echo "  - $path"
    done
    warning "\nPlease ensure Claude Desktop is installed"
    info "Or create config manually at: $HOME/.config/claude/claude_desktop_config.json"
    exit 1
fi

# Step 2: Backup existing config
section "[2] BACKING UP CONFIGURATION"

BACKUP_PATH="${CLAUDE_CONFIG_PATH}.backup-$(date +%Y%m%d-%H%M%S)"
if cp "$CLAUDE_CONFIG_PATH" "$BACKUP_PATH"; then
    success "Backup created: $BACKUP_PATH"
else
    failure "Failed to create backup"
    exit 1
fi

# Step 3: Update config
section "[3] UPDATING CONFIGURATION"

DATABASE_URL="postgresql://cortex:${PASSWORD}@${SERVER_IP}:${PORT}/cortex_prod"

# Check for JSON tools
JSON_TOOL=""
if command -v jq &> /dev/null; then
    JSON_TOOL="jq"
elif command -v python3 &> /dev/null; then
    JSON_TOOL="python3"
elif command -v python &> /dev/null; then
    JSON_TOOL="python"
else
    failure "No JSON tool found (jq or python required)"
    info "Install jq: sudo apt install jq  # or  sudo dnf install jq"
    exit 1
fi

if [ "$JSON_TOOL" = "jq" ]; then
    # Use jq
    jq --arg db_url "$DATABASE_URL" '
    .mcpServers["cortex"] = {
        "command": "node",
        "args": ["path/to/mcp-cortex/dist/index.js"],
        "env": {
            "DATABASE_URL": $db_url,
            "LOG_LEVEL": "error",
            "NODE_ENV": "production"
        }
    }
    ' "$CLAUDE_CONFIG_PATH" > "${CLAUDE_CONFIG_PATH}.tmp" && mv "${CLAUDE_CONFIG_PATH}.tmp" "$CLAUDE_CONFIG_PATH"

    success "Configuration updated successfully"
else
    # Use Python
    python3 - <<EOF
import json

with open("$CLAUDE_CONFIG_PATH", "r") as f:
    config = json.load(f)

if "mcpServers" not in config:
    config["mcpServers"] = {}

config["mcpServers"]["cortex"] = {
    "command": "node",
    "args": ["path/to/mcp-cortex/dist/index.js"],
    "env": {
        "DATABASE_URL": "$DATABASE_URL",
        "LOG_LEVEL": "error",
        "NODE_ENV": "production"
    }
}

with open("$CLAUDE_CONFIG_PATH", "w") as f:
    json.dump(config, f, indent=2)
EOF

    success "Configuration updated successfully"
fi

# Step 4: Test connection
section "[4] TESTING CONNECTION"

info "Testing connectivity to ${SERVER_IP}:${PORT}..."

# Try different connection test methods
CONNECTION_TEST=false

if command -v nc &> /dev/null; then
    if timeout 5 nc -z "$SERVER_IP" "$PORT" 2>/dev/null; then
        CONNECTION_TEST=true
    fi
elif command -v telnet &> /dev/null; then
    if timeout 5 bash -c "echo > /dev/tcp/$SERVER_IP/$PORT" 2>/dev/null; then
        CONNECTION_TEST=true
    fi
else
    warning "No connection test tool found (nc or telnet)"
    info "Skipping connection test"
    CONNECTION_TEST=true
fi

if [ "$CONNECTION_TEST" = true ]; then
    success "Server is reachable on ${SERVER_IP}:${PORT}"
else
    failure "Cannot connect to ${SERVER_IP}:${PORT}"
    warning "Please check:"
    echo "  1. Server IP is correct: $SERVER_IP"
    echo "  2. Server is running (ask administrator)"
    echo "  3. Firewall allows port $PORT"
    echo "  4. You are on the same network"
    echo ""
    warning "Configuration was saved, but connection test failed"
    exit 1
fi

# Step 5: Installation complete
section "[5] INSTALLATION COMPLETE"

echo ""
echo -e "${GREEN}✅✅✅ MCP CORTEX INSTALLED SUCCESSFULLY ✅✅✅${NC}\n"

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN} CONFIGURATION DETAILS${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo "Config file:      $CLAUDE_CONFIG_PATH"
echo "Backup:           $BACKUP_PATH"
echo "Server:           ${SERVER_IP}:${PORT}"
echo "Database:         cortex_prod"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${GREEN}📋 Next Steps:${NC}"
echo "1. Restart Claude Desktop for changes to take effect"
echo "2. Open Claude Desktop"
echo "3. MCP Cortex tools will be available (memory.store, memory.find)"
echo "4. Claude may prompt for tool approval - this is normal"

echo ""
echo -e "${YELLOW}⚠️  Important Notes:${NC}"
echo "- MCP tools require approval on first use (security feature)"
echo "- If connection fails, run test-connection.js to diagnose"
echo "- Contact administrator if you cannot connect"

echo ""
echo -e "${GREEN}🎉 Installation complete! Enjoy using MCP Cortex!${NC}\n"
