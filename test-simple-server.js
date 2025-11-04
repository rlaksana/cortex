#!/usr/bin/env node

/**
 * Test script for the simple MCP server with tools/list fix
 */

import { spawn } from 'child_process';

console.error('=== Testing Simple MCP Server with tools/list fix ===');

async function testSimpleServer() {
    return new Promise((resolve, reject) => {
        console.error('Starting simple MCP server...');

        // Spawn the simple MCP server process
        const child = spawn('node', ['dist/simple-mcp-server.js'], {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: process.cwd()
        });

        let responseData = '';
        let isHandshakeComplete = false;
        let requestId = 1;

        // Timeout for entire test
        const timeout = setTimeout(() => {
            if (!isHandshakeComplete) {
                child.kill('SIGTERM');
                reject(new Error('Test timeout after 10 seconds'));
            }
        }, 10000);

        // Send initialize request
        const initializeRequest = {
            jsonrpc: "2.0",
            id: `test-${requestId++}`,
            method: "initialize",
            params: {
                protocolVersion: "2024-11-05",
                capabilities: {
                    tools: {}
                },
                clientInfo: {
                    name: "test-client",
                    version: "1.0.0"
                }
            }
        };

        console.error('Sending initialize request...');
        child.stdin.write(JSON.stringify(initializeRequest) + '\n');

        // Listen for responses
        child.stdout.on('data', (data) => {
            const chunk = data.toString();
            responseData += chunk;

            console.error('Received data:', chunk);

            // Try to parse complete JSON-RPC response
            try {
                const lines = responseData.split('\n').filter(line => line.trim());
                for (const line of lines) {
                    if (line.startsWith('{') && line.endsWith('}')) {
                        const response = JSON.parse(line);
                        console.error('Parsed response:', response);

                        if (response.result) {
                            if (!isHandshakeComplete && response.result.protocolVersion) {
                                console.error('✅ Initialize SUCCESS!');
                                isHandshakeComplete = true;

                                // Send tools/list request
                                const toolsListRequest = {
                                    jsonrpc: "2.0",
                                    id: `test-${requestId++}`,
                                    method: "tools/list",
                                    params: {}
                                };

                                console.error('Sending tools/list request...');
                                child.stdin.write(JSON.stringify(toolsListRequest) + '\n');
                            } else if (response.result.tools) {
                                console.error('✅ tools/list SUCCESS!');
                                console.error('Tools returned:', response.result.tools.length);
                                clearTimeout(timeout);
                                child.kill('SIGTERM');
                                resolve({
                                    success: true,
                                    toolsCount: response.result.tools.length,
                                    serverType: 'simple-mcp-server'
                                });
                            }
                        } else if (response.error) {
                            console.error('❌ Request FAILED!');
                            console.error('Error:', response.error);
                            clearTimeout(timeout);
                            child.kill('SIGTERM');
                            reject(new Error(`MCP Error: ${response.error.message}`));
                        }
                    }
                }
            } catch (e) {
                // Not complete JSON yet, continue accumulating
            }
        });

        child.stderr.on('data', (data) => {
            console.error('Server stderr:', data.toString());
        });

        child.on('error', (error) => {
            clearTimeout(timeout);
            console.error('❌ Child process error:', error);
            reject(error);
        });

        child.on('close', (code, signal) => {
            clearTimeout(timeout);
            if (!isHandshakeComplete) {
                console.error(`❌ Server closed before completion. Code: ${code}, Signal: ${signal}`);
                reject(new Error(`Server closed before completion. Code: ${code}, Signal: ${signal}`));
            }
        });
    });
}

// Run the test
testSimpleServer()
    .then((result) => {
        console.error('\n✅ Test completed successfully!');
        console.error('Result:', result);
        process.exit(0);
    })
    .catch((error) => {
        console.error('\n❌ Test failed:', error.message);
        process.exit(1);
    });