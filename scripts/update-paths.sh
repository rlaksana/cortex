#!/bin/bash

echo "Updating project paths for new location..."

# Get current directory
CURRENT_DIR=$(pwd)

# Update simple MCP config
echo "Updating config/simple-mcp-config.json..."
sed -i "s|D:\\\\WORKSPACE\\\\tools-node\\\\mcp-cortex|$CURRENT_DIR|g" config/simple-mcp-config.json

# Update development policy examples
echo "Updating DEVELOPMENT-POLICY.md examples..."
sed -i "s|D:\\\\WORKSPACE\\\\tools-node\\\\mcp-cortex|$CURRENT_DIR|g" DEVELOPMENT-POLICY.md

# Update AI assistant guidelines
echo "Updating .ai-assistant-guidelines.md..."
sed -i "s|D:\\\\WORKSPACE\\\\tools-node\\\\mcp-cortex|$CURRENT_DIR|g" .ai-assistant-guidelines.md

echo ""
echo "✅ All paths updated to: $CURRENT_DIR"
echo ""
echo "Your MCP config now points to:"
echo "$CURRENT_DIR/dist/index.js"
echo ""