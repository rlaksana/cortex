#!/usr/bin/env node

/**
 * Simple MCP test - tests initialization and tool discovery
 */

const { spawn } = require("child_process");

async function testMCPServer() {
  console.log("🧪 Testing MCP Cortex Server\n");

  // Start the server
  const server = spawn("node", ["dist/index.js"], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: process.cwd()
  });

  let outputBuffer = "";
  let initialized = false;

  server.stdout.on("data", (data) => {
    const output = data.toString();
    outputBuffer += output;

    // Look for JSON-RPC responses
    const lines = output.split('\n').filter(line => line.trim().startsWith('{'));
    lines.forEach(line => {
      try {
        const response = JSON.parse(line);
        console.log("📨 Received:", JSON.stringify(response, null, 2));

        if (response.result && response.result.serverInfo) {
          initialized = true;
          console.log("✅ Server initialized successfully");

          // Test tools/list
          setTimeout(() => {
            console.log("\n🔍 Testing tools/list...");
            server.stdin.write(JSON.stringify({
              jsonrpc: "2.0",
              id: 2,
              method: "tools/list",
              params: {}
            }) + "\n");
          }, 1000);
        }

        if (response.result && response.result.tools) {
          console.log("✅ Tools discovered:");
          response.result.tools.forEach(tool => {
            console.log(`   - ${tool.name}: ${tool.description.substring(0, 80)}...`);
          });

          // Test memory_store
          setTimeout(() => {
            console.log("\n💾 Testing memory_store...");
            server.stdin.write(JSON.stringify({
              jsonrpc: "2.0",
              id: 3,
              method: "tools/call",
              params: {
                name: "memory_store",
                arguments: {
                  items: [{
                    kind: "entity",
                    data: {
                      name: "Test Entity",
                      type: "test",
                      description: "Test entity created during MCP compliance testing"
                    }
                  }]
                }
              }
            }) + "\n");
          }, 1000);
        }

        if (response.result && response.result.content) {
          console.log("✅ Tool call successful");
          console.log("📤 Response:", response.result.content[0].text.substring(0, 200) + "...");

          setTimeout(() => {
            console.log("\n🎉 All tests completed successfully!");
            server.kill();
            process.exit(0);
          }, 1000);
        }

        if (response.error) {
          console.log("❌ Error response:", response.error);
        }
      } catch (e) {
        // Not JSON, ignore
      }
    });
  });

  server.stderr.on("data", (data) => {
    const output = data.toString();
    if (output.includes("ready and accepting requests")) {
      console.log("🚀 Server is ready, sending initialization...");

      // Send initialization request
      server.stdin.write(JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          clientInfo: {
            name: "test-client",
            version: "1.0.0"
          }
        }
      }) + "\n");
    }
  });

  server.on("error", (error) => {
    console.error("❌ Server error:", error);
    process.exit(1);
  });

  // Timeout after 30 seconds
  setTimeout(() => {
    console.log("⏰ Test timeout");
    server.kill();
    process.exit(1);
  }, 30000);
}

testMCPServer().catch(console.error);