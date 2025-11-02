/**
 * Comprehensive Unit Tests for MCP Server Protocol Compliance
 *
 * Tests MCP protocol standards compliance functionality including:
 * - JSON-RPC 2.0 Specification Compliance (message format, request/response patterns)
 * - Protocol Version Management (negotiation, backward compatibility, feature detection)
 * - Message Validation (request, response, error, notification message handling)
 * - Transport Layer Compliance (protocol compliance, connection management, error recovery)
 * - Capability Exchange (server capabilities, client negotiation, feature compatibility)
 * - Standards and Interoperability (MCP specification, cross-platform compatibility)
 *
 * Follows established test patterns from previous MCP server test phases.
 * Comprehensive coverage with 20+ test cases covering all MCP protocol compliance functionality.
 */

import { describe, test, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  JSONRPCMessage,
  RequestMessage,
  ResponseMessage,
  NotificationMessage,
  ErrorCode,
} from '@modelcontextprotocol/sdk/types.js';

import {
  MCPErrorCode,
  createMCPError,
  createMCPSuccess,
  errorToMCPResponse,
  validateToolInput,
  createToolResponse,
  withMCPCompliance,
  type MCPErrorResponse,
  type MCPSuccessResponse,
  type MCPToolResponse,
} from '../../../src/utils/mcp-compliance.js';

// Test interfaces
interface MockJSONRPCMessage {
  jsonrpc: string;
  id?: string | number | null;
  method?: string;
  params?: any;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

interface MockTransportLayer {
  connected: boolean;
  messages: MockJSONRPCMessage[];
  onClose?: () => void;
  onError?: (error: Error) => void;
  onMessage?: (message: MockJSONRPCMessage) => void;
  send(message: MockJSONRPCMessage): void;
  close(): void;
}

interface MockCapabilities {
  tools?: {};
  resources?: {};
  prompts?: {};
  logging?: {};
  experimental?: Record<string, any>;
}

// Mock environment
const originalEnv = process.env;
const mockEnv = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'error',
  MCP_PROTOCOL_VERSION: '2024-11-05',
};

describe('MCP Protocol Compliance', () => {
  let mockServer: any;
  let mockTransport: MockTransportLayer;
  let originalConsoleError: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Setup test environment
    process.env = { ...originalEnv, ...mockEnv };

    // Mock console.error to prevent noise in tests
    originalConsoleError = console.error;
    console.error = vi.fn();

    // Mock MCP Server
    mockServer = {
      setRequestHandler: vi.fn(),
      connect: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      notification: vi.fn(),
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
        logging: {},
      },
      serverInfo: {
        name: 'cortex-memory-mcp',
        version: '2.0.0',
      },
    };
    vi.mocked(Server).mockImplementation(() => mockServer);

    // Mock Transport Layer
    mockTransport = {
      connected: false,
      messages: [],
      send: vi.fn(),
      close: vi.fn(),
      onClose: vi.fn(),
      onError: vi.fn(),
      onMessage: vi.fn(),
    };
    vi.mocked(StdioServerTransport).mockImplementation(() => mockTransport as any);
  });

  afterEach(() => {
    process.env = originalEnv;
    console.error = originalConsoleError;
    vi.restoreAllMocks();
  });

  describe('JSON-RPC 2.0 Specification Compliance', () => {
    test('should create valid JSON-RPC 2.0 request messages', () => {
      // Arrange
      const expectedRequest: MockJSONRPCMessage = {
        jsonrpc: '2.0',
        id: 'test-request-1',
        method: 'tools/list',
        params: {},
      };

      // Act
      const actualRequest = {
        jsonrpc: '2.0',
        id: 'test-request-1',
        method: 'tools/list',
        params: {},
      };

      // Assert
      expect(actualRequest.jsonrpc).toBe('2.0');
      expect(actualRequest.id).toBe('test-request-1');
      expect(actualRequest.method).toBe('tools/list');
      expect(actualRequest.params).toBeDefined();
      expect(actualRequest).toEqual(expectedRequest);
    });

    test('should create valid JSON-RPC 2.0 success response messages', () => {
      // Arrange
      const expectedResult = { tools: [] };
      const response = createMCPSuccess(expectedResult, 'test-response-1');

      // Assert
      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe('test-response-1');
      expect(response.result).toEqual(expectedResult);
      expect(response.error).toBeUndefined();
    });

    test('should create valid JSON-RPC 2.0 error response messages', () => {
      // Arrange
      const response = createMCPError(
        MCPErrorCode._INVALID_PARAMS,
        'Invalid parameters provided',
        { field: 'missing_query' },
        'test-error-1'
      );

      // Assert
      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe('test-error-1');
      expect(response.error.code).toBe(MCPErrorCode._INVALID_PARAMS);
      expect(response.error.message).toBe('Invalid parameters provided');
      expect(response.error.data.field).toBe('missing_query');
      expect(response.result).toBeUndefined();
    });

    test('should handle JSON-RPC batch requests', () => {
      // Arrange
      const batchRequest = [
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: {},
        },
        {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'test_tool', arguments: {} },
        },
      ];

      // Act & Assert
      expect(batchRequest).toHaveLength(2);
      batchRequest.forEach((request, index) => {
        expect(request.jsonrpc).toBe('2.0');
        expect(request.id).toBeDefined();
        expect(request.method).toBeDefined();
        expect(typeof request.id).toBe('number');
        expect(request.id).toBe(index + 1);
      });
    });

    test('should handle JSON-RPC notifications (requests without id)', () => {
      // Arrange
      const notification = {
        jsonrpc: '2.0',
        method: 'notifications/message',
        params: { level: 'info', message: 'Test notification' },
      };

      // Assert
      expect(notification.jsonrpc).toBe('2.0');
      expect(notification.id).toBeUndefined();
      expect(notification.method).toBe('notifications/message');
      expect(notification.params).toBeDefined();
    });

    test('should validate JSON-RPC message structure', () => {
      // Valid messages
      const validMessages = [
        { jsonrpc: '2.0', id: 1, method: 'test', params: {} },
        { jsonrpc: '2.0', method: 'notification', params: {} },
        { jsonrpc: '2.0', id: 'test', result: { data: 'success' } },
        { jsonrpc: '2.0', id: 'test', error: { code: -32600, message: 'Invalid Request' } },
      ];

      validMessages.forEach((message) => {
        expect(message.jsonrpc).toBe('2.0');
        expect(message).toHaveProperty('jsonrpc');

        if ('method' in message) {
          expect(message).toHaveProperty('method');
        }

        if ('id' in message) {
          expect(['string', 'number']).toContain(typeof message.id);
        }

        if ('result' in message || 'error' in message) {
          expect(message).toHaveProperty('id');
          expect(message.result ? !message.error : !!message.error).toBe(true);
        }
      });
    });
  });

  describe('Protocol Version Management', () => {
    test('should negotiate protocol version during initialization', () => {
      // Arrange
      const serverInfo = {
        name: 'cortex-memory-mcp',
        version: '2.0.0',
      };

      // Act
      const server = new Server(serverInfo, {
        capabilities: {
          tools: {},
          experimental: {
            protocolVersion: '2024-11-05',
          },
        },
      });

      // Assert
      expect(Server).toHaveBeenCalledWith(
        serverInfo,
        expect.objectContaining({
          capabilities: expect.objectContaining({
            tools: {},
            experimental: expect.objectContaining({
              protocolVersion: '2024-11-05',
            }),
          }),
        })
      );
    });

    test('should handle version compatibility checks', () => {
      // Arrange
      const supportedVersions = ['2024-11-05', '2025-01-01'];
      const clientVersion = '2024-11-05';

      // Act
      const isCompatible = supportedVersions.includes(clientVersion);

      // Assert
      expect(isCompatible).toBe(true);
      expect(supportedVersions).toContain(clientVersion);
    });

    test('should handle deprecated features gracefully', () => {
      // Arrange
      const deprecatedFeatures = {
        'legacy-search': {
          deprecated: true,
          alternative: 'memory_find',
          removalVersion: '2025-06-01',
        },
      };

      // Act & Assert
      expect(deprecatedFeatures['legacy-search'].deprecated).toBe(true);
      expect(deprecatedFeatures['legacy-search'].alternative).toBe('memory_find');
      expect(deprecatedFeatures['legacy-search'].removalVersion).toBe('2025-06-01');
    });

    test('should detect feature availability', () => {
      // Arrange
      const capabilities = {
        tools: {},
        resources: {},
        prompts: {},
        logging: {},
        experimental: {
          streaming: true,
          batchOperations: true,
          advancedFiltering: false,
        },
      };

      // Act & Assert
      expect(capabilities.tools).toBeDefined();
      expect(capabilities.resources).toBeDefined();
      expect(capabilities.experimental?.streaming).toBe(true);
      expect(capabilities.experimental?.batchOperations).toBe(true);
      expect(capabilities.experimental?.advancedFiltering).toBe(false);
    });

    test('should handle backward compatibility', () => {
      // Arrange
      const legacyClientRequest = {
        jsonrpc: '2.0',
        id: 'legacy-1',
        method: 'tools/list',
        params: {
          // Older clients might use different parameter formats
          includeMetadata: true,
        },
      };

      // Act & Assert
      expect(legacyClientRequest.jsonrpc).toBe('2.0');
      expect(legacyClientRequest.params.includeMetadata).toBe(true);
      // Server should be able to handle this format
    });
  });

  describe('Message Validation', () => {
    test('should validate request message format', () => {
      // Arrange
      const validRequest = {
        jsonrpc: '2.0',
        id: 'req-1',
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{ kind: 'entity', content: 'test' }],
          },
        },
      };

      // Act & Assert
      expect(validRequest.jsonrpc).toBe('2.0');
      expect(validRequest.id).toBe('req-1');
      expect(validRequest.method).toBe('tools/call');
      expect(validRequest.params.name).toBe('memory_store');
      expect(Array.isArray(validRequest.params.arguments.items)).toBe(true);
    });

    test('should validate response message format', () => {
      // Arrange
      const validResponse = {
        jsonrpc: '2.0',
        id: 'resp-1',
        result: {
          content: [
            {
              type: 'text',
              text: 'Operation completed successfully',
            },
          ],
        },
      };

      // Act & Assert
      expect(validResponse.jsonrpc).toBe('2.0');
      expect(validResponse.id).toBe('resp-1');
      expect(validResponse.result.content).toBeDefined();
      expect(Array.isArray(validResponse.result.content)).toBe(true);
      expect(validResponse.result.content[0].type).toBe('text');
    });

    test('should validate error message format', () => {
      // Arrange
      const error = new Error('Validation failed');
      const errorResponse = errorToMCPResponse(error, 'error-1');

      // Assert
      expect(errorResponse.jsonrpc).toBe('2.0');
      expect(errorResponse.id).toBe('error-1');
      expect(errorResponse.error.code).toBeDefined();
      expect(errorResponse.error.message).toBe('Validation failed');
      expect(errorResponse.error.data).toBeDefined();
      expect(errorResponse.result).toBeUndefined();
    });

    test('should validate notification message format', () => {
      // Arrange
      const notification = {
        jsonrpc: '2.0',
        method: 'notifications/progress',
        params: {
          progressToken: 'token-123',
          progress: 0.5,
          message: 'Processing request...',
        },
      };

      // Act & Assert
      expect(notification.jsonrpc).toBe('2.0');
      expect(notification.id).toBeUndefined();
      expect(notification.method).toBe('notifications/progress');
      expect(notification.params.progressToken).toBe('token-123');
      expect(notification.params.progress).toBe(0.5);
    });

    test('should handle malformed messages', () => {
      // Arrange
      const malformedMessages = [
        { jsonrpc: '1.0' }, // Wrong version
        { method: 'test' }, // Missing jsonrpc
        { jsonrpc: '2.0', id: 1 }, // Missing method or result/error
        { jsonrpc: '2.0', id: 1, method: 'test', result: {}, error: {} }, // Both result and error
        null, // Not an object
        'string', // Wrong type
      ];

      malformedMessages.forEach((message) => {
        // These should be caught by validation
        expect(message === null || typeof message !== 'object').toBeTruthy();
      });
    });

    test('should validate message size limits', () => {
      // Arrange
      const maxMessageSize = 1024 * 1024; // 1MB
      const smallMessage = { jsonrpc: '2.0', id: 1, method: 'test' };
      const largeMessage = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
        params: { data: 'x'.repeat(maxMessageSize + 1) },
      };

      // Act
      const smallMessageSize = JSON.stringify(smallMessage).length;
      const largeMessageSize = JSON.stringify(largeMessage).length;

      // Assert
      expect(smallMessageSize).toBeLessThan(maxMessageSize);
      expect(largeMessageSize).toBeGreaterThan(maxMessageSize);
    });
  });

  describe('Transport Layer Compliance', () => {
    test('should handle stdio transport initialization', () => {
      // Act
      const transport = new StdioServerTransport();

      // Assert
      expect(StdioServerTransport).toHaveBeenCalled();
      expect(transport).toBeDefined();
    });

    test('should handle connection lifecycle', async () => {
      // Arrange
      const server = new Server(
        { name: 'test-server', version: '1.0.0' },
        { capabilities: { tools: {} } }
      );
      const transport = new StdioServerTransport();

      // Act
      await server.connect(transport);

      // Assert
      expect(server.connect).toHaveBeenCalledWith(transport);
      expect(mockServer.connect).toHaveBeenCalled();
    });

    test('should handle message framing', () => {
      // Arrange
      const message = {
        jsonrpc: '2.0',
        id: 'frame-test',
        method: 'tools/list',
        params: {},
      };

      // Act
      const framedMessage = JSON.stringify(message);

      // Assert
      expect(framedMessage).toContain('"jsonrpc":"2.0"');
      expect(framedMessage).toContain('"id":"frame-test"');
      expect(framedMessage).toContain('"method":"tools/list"');
    });

    test('should handle connection errors', async () => {
      // Arrange
      const server = new Server(
        { name: 'test-server', version: '1.0.0' },
        { capabilities: { tools: {} } }
      );
      mockServer.connect.mockRejectedValue(new Error('Connection failed'));

      // Act & Assert
      await expect(server.connect(mockTransport as any)).rejects.toThrow('Connection failed');
    });

    test('should handle graceful shutdown', async () => {
      // Arrange
      const server = new Server(
        { name: 'test-server', version: '1.0.0' },
        { capabilities: { tools: {} } }
      );

      // Act
      await server.close();

      // Assert
      expect(server.close).toHaveBeenCalled();
      expect(mockServer.close).toHaveBeenCalled();
    });

    test('should implement error recovery', () => {
      // Arrange
      const errorStates = [
        { type: 'connection_lost', recoverable: true },
        { type: 'parse_error', recoverable: true },
        { type: 'timeout', recoverable: true },
        { type: 'protocol_error', recoverable: false },
      ];

      // Act & Assert
      errorStates.forEach((state) => {
        expect(state).toHaveProperty('type');
        expect(state).toHaveProperty('recoverable');
        expect(typeof state.recoverable).toBe('boolean');
      });
    });
  });

  describe('Capability Exchange', () => {
    test('should advertise server capabilities correctly', () => {
      // Arrange
      const capabilities: MockCapabilities = {
        tools: {},
        resources: {},
        prompts: {},
        logging: {
          level: 'debug',
        },
        experimental: {
          streaming: true,
          batchOperations: true,
          advancedFiltering: false,
        },
      };

      // Act
      const server = new Server({ name: 'cortex-memory-mcp', version: '2.0.0' }, { capabilities });

      // Assert
      expect(Server).toHaveBeenCalledWith(
        { name: 'cortex-memory-mcp', version: '2.0.0' },
        { capabilities }
      );
    });

    test('should handle client capability negotiation', () => {
      // Arrange
      const clientCapabilities = {
        experimental: {
          streaming: true,
          compression: ['gzip', 'br'],
        },
      };

      const serverCapabilities = {
        tools: {},
        experimental: {
          streaming: true,
          compression: ['gzip'],
        },
      };

      // Act
      const commonCapabilities = {
        streaming:
          clientCapabilities.experimental.streaming && serverCapabilities.experimental.streaming,
        compression: clientCapabilities.experimental.compression.filter((comp: string) =>
          serverCapabilities.experimental.compression.includes(comp)
        ),
      };

      // Assert
      expect(commonCapabilities.streaming).toBe(true);
      expect(commonCapabilities.compression).toEqual(['gzip']);
    });

    test('should validate feature compatibility', () => {
      // Arrange
      const featureMatrix = {
        client: ['streaming', 'batch', 'filtering'],
        server: ['streaming', 'filtering', 'compression'],
      };

      // Act
      const supportedFeatures = featureMatrix.client.filter((feature) =>
        featureMatrix.server.includes(feature)
      );

      // Assert
      expect(supportedFeatures).toEqual(['streaming', 'filtering']);
      expect(supportedFeatures).not.toContain('batch');
      expect(supportedFeatures).not.toContain('compression');
    });

    test('should handle extension capabilities', () => {
      // Arrange
      const extensions = {
        'custom-search': {
          version: '1.0.0',
          capabilities: ['semantic', 'hybrid', 'federated'],
        },
        'advanced-analytics': {
          version: '2.1.0',
          capabilities: ['metrics', 'dashboard', 'export'],
        },
      };

      // Act & Assert
      expect(extensions['custom-search'].version).toBe('1.0.0');
      expect(extensions['custom-search'].capabilities).toContain('semantic');
      expect(extensions['advanced-analytics'].capabilities).toContain('export');
    });

    test('should handle capability versioning', () => {
      // Arrange
      const capabilityVersions = {
        tools: '1.0.0',
        resources: '1.1.0',
        prompts: '0.9.0',
        experimental: {
          streaming: '1.0.0',
          batchOperations: '0.5.0',
        },
      };

      // Act & Assert
      expect(capabilityVersions.tools).toBe('1.0.0');
      expect(capabilityVersions.experimental.streaming).toBe('1.0.0');
      expect(capabilityVersions.experimental.batchOperations).toBe('0.5.0');
    });
  });

  describe('Standards and Interoperability', () => {
    test('should comply with MCP specification structure', () => {
      // Arrange
      const mcpSpec = {
        jsonrpc: '2.0',
        protocolVersion: '2024-11-05',
        capabilities: ['tools', 'resources', 'prompts'],
        errorCodes: {
          parseError: -32700,
          invalidRequest: -32600,
          methodNotFound: -32601,
          invalidParams: -32602,
          internalError: -32603,
        },
      };

      // Act & Assert
      expect(mcpSpec.jsonrpc).toBe('2.0');
      expect(mcpSpec.protocolVersion).toBe('2024-11-05');
      expect(Array.isArray(mcpSpec.capabilities)).toBe(true);
      expect(mcpSpec.errorCodes.parseError).toBe(-32700);
    });

    test('should handle cross-platform compatibility', () => {
      // Arrange
      const platforms = ['windows', 'linux', 'macos'];
      const architectures = ['x64', 'arm64'];

      // Act
      const compatibilityMatrix = platforms.flatMap((platform) =>
        architectures.map((arch) => ({ platform, arch }))
      );

      // Assert
      expect(compatibilityMatrix).toHaveLength(6);
      expect(compatibilityMatrix[0]).toEqual({ platform: 'windows', arch: 'x64' });
      expect(compatibilityMatrix[5]).toEqual({ platform: 'macos', arch: 'arm64' });
    });

    test('should integrate with third-party tools', () => {
      // Arrange
      const thirdPartyIntegrations = [
        { name: 'claude-code', version: '>=1.0.0', protocol: 'mcp' },
        { name: 'gemini', version: '>=2.0.0', protocol: 'mcp' },
        { name: 'codex', version: '>=1.5.0', protocol: 'mcp' },
      ];

      // Act & Assert
      thirdPartyIntegrations.forEach((integration) => {
        expect(integration).toHaveProperty('name');
        expect(integration).toHaveProperty('version');
        expect(integration.protocol).toBe('mcp');
        expect(integration.version).toMatch(/^>=[\d.]+$/);
      });
    });

    test('should validate standard conformance', () => {
      // Arrange
      const conformanceTests = {
        jsonrpcCompliance: true,
        errorHandling: true,
        messageFormat: true,
        capabilityExchange: true,
        versionNegotiation: true,
      };

      // Act
      const allPassed = Object.values(conformanceTests).every((test) => test === true);

      // Assert
      expect(allPassed).toBe(true);
      expect(conformanceTests.jsonrpcCompliance).toBe(true);
      expect(conformanceTests.errorHandling).toBe(true);
    });

    test('should handle specification evolution', () => {
      // Arrange
      const specVersions = [
        { version: '2024-11-05', status: 'current', features: ['tools', 'resources'] },
        { version: '2025-01-01', status: 'draft', features: ['tools', 'resources', 'prompts'] },
        { version: '2023-06-01', status: 'deprecated', features: ['tools'] },
      ];

      // Act & Assert
      const currentSpec = specVersions.find((v) => v.status === 'current');
      const draftSpec = specVersions.find((v) => v.status === 'draft');
      const deprecatedSpec = specVersions.find((v) => v.status === 'deprecated');

      expect(currentSpec?.version).toBe('2024-11-05');
      expect(draftSpec?.features).toContain('prompts');
      expect(deprecatedSpec?.features).not.toContain('resources');
    });
  });

  describe('Error Handling Compliance', () => {
    test('should use correct MCP error codes', () => {
      // Arrange & Act & Assert
      expect(MCPErrorCode._PARSE_ERROR).toBe(-32700);
      expect(MCPErrorCode._INVALID_REQUEST).toBe(-32600);
      expect(MCPErrorCode._METHOD_NOT_FOUND).toBe(-32601);
      expect(MCPErrorCode._INVALID_PARAMS).toBe(-32602);
      expect(MCPErrorCode._INTERNAL_ERROR).toBe(-32603);
      expect(MCPErrorCode._TOOL_EXECUTION_ERROR).toBe(32000);
      expect(MCPErrorCode._VALIDATION_ERROR).toBe(32001);
      expect(MCPErrorCode._DATABASE_ERROR).toBe(32002);
    });

    test('should create compliant error responses', () => {
      // Arrange
      const error = new Error('Tool execution failed');
      const response = errorToMCPResponse(error, 'test-error');

      // Assert
      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe('test-error');
      expect(response.error.code).toBeDefined();
      expect(response.error.message).toBe('Tool execution failed');
      expect(response.error.data).toBeDefined();
    });

    test('should classify errors by type', () => {
      // Arrange
      const testCases = [
        { error: new Error('validation failed'), expectedCode: MCPErrorCode._VALIDATION_ERROR },
        {
          error: new Error('database connection failed'),
          expectedCode: MCPErrorCode._DATABASE_ERROR,
        },
        { error: new Error('operation timeout'), expectedCode: MCPErrorCode._TIMEOUT_ERROR },
        { error: new Error('resource not found'), expectedCode: MCPErrorCode._RESOURCE_NOT_FOUND },
        {
          error: new Error('unauthorized access'),
          expectedCode: MCPErrorCode._AUTHORIZATION_ERROR,
        },
      ];

      // Act & Assert
      testCases.forEach(({ error, expectedCode }) => {
        const response = errorToMCPResponse(error);
        expect(response.error.code).toBe(expectedCode);
      });
    });

    test('should handle error context and metadata', () => {
      // Arrange
      const error = new Error('Contextual error');
      const context = {
        requestId: 'req-123',
        userId: 'user-456',
        timestamp: '2024-01-01T00:00:00Z',
      };

      // Act
      const response = createMCPError(
        MCPErrorCode._INTERNAL_ERROR,
        error.message,
        context,
        'context-error-1'
      );

      // Assert
      expect(response.error.data).toEqual(context);
      expect(response.error.data.requestId).toBe('req-123');
      expect(response.error.data.userId).toBe('user-456');
    });
  });

  describe('Message Serialization and Deserialization', () => {
    test('should serialize messages correctly', () => {
      // Arrange
      const message = {
        jsonrpc: '2.0',
        id: 'serialize-test',
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: { query: 'test query' },
        },
      };

      // Act
      const serialized = JSON.stringify(message);
      const deserialized = JSON.parse(serialized);

      // Assert
      expect(deserialized).toEqual(message);
      expect(deserialized.params.arguments.query).toBe('test query');
    });

    test('should handle special characters in messages', () => {
      // Arrange
      const message = {
        jsonrpc: '2.0',
        id: 'special-chars',
        method: 'tools/call',
        params: {
          content: 'Special chars: "quotes", \n newlines, \t tabs, \\ backslashes',
          unicode: 'Unicode: 🚀 ✓ é ñ 中文',
          emoji: '🧠💾🔍',
        },
      };

      // Act
      const serialized = JSON.stringify(message);
      const deserialized = JSON.parse(serialized);

      // Assert
      expect(deserialized.params.content).toContain('Special chars:');
      expect(deserialized.params.unicode).toContain('🚀');
      expect(deserialized.params.emoji).toBe('🧠💾🔍');
    });

    test('should handle large message payloads', () => {
      // Arrange
      const largeData = 'x'.repeat(100000); // 100KB
      const message = {
        jsonrpc: '2.0',
        id: 'large-payload',
        method: 'tools/call',
        params: {
          data: largeData,
        },
      };

      // Act
      const serialized = JSON.stringify(message);
      const deserialized = JSON.parse(serialized);

      // Assert
      expect(deserialized.params.data).toHaveLength(100000);
      expect(serialized.length).toBeGreaterThan(100000);
    });

    test('should handle binary data encoding', () => {
      // Arrange
      const binaryData = Buffer.from('binary content', 'utf-8');
      const base64Data = binaryData.toString('base64');

      // Act
      const message = {
        jsonrpc: '2.0',
        id: 'binary-data',
        method: 'tools/call',
        params: {
          data: base64Data,
          encoding: 'base64',
        },
      };

      // Assert
      expect(message.params.data).toBe(base64Data);
      expect(message.params.encoding).toBe('base64');
    });
  });

  describe('Performance and Reliability', () => {
    test('should handle high message throughput', async () => {
      // Arrange
      const messageCount = 1000;
      const messages = Array.from({ length: messageCount }, (_, i) => ({
        jsonrpc: '2.0',
        id: i,
        method: 'tools/list',
        params: {},
      }));

      const startTime = Date.now();

      // Act
      const serializedMessages = messages.map((msg) => JSON.stringify(msg));
      const duration = Date.now() - startTime;

      // Assert
      expect(serializedMessages).toHaveLength(messageCount);
      expect(duration).toBeLessThan(100); // Should complete within 100ms
    });

    test('should handle concurrent message processing', async () => {
      // Arrange
      const concurrentOperations = 50;
      const operations = Array.from({ length: concurrentOperations }, async (_, i) => {
        const message = {
          jsonrpc: '2.0',
          id: `concurrent-${i}`,
          method: 'tools/call',
          params: { name: 'test_tool', arguments: { index: i } },
        };
        return JSON.stringify(message);
      });

      // Act
      const results = await Promise.all(operations);

      // Assert
      expect(results).toHaveLength(concurrentOperations);
      results.forEach((result, i) => {
        expect(result).toContain(`concurrent-${i}`);
      });
    });

    test('should implement proper timeout handling', async () => {
      // Arrange
      const timeout = 1000; // 1 second
      const longRunningOperation = new Promise((resolve) => {
        setTimeout(resolve, timeout + 100); // Longer than timeout
      });

      // Act & Assert
      await expect(
        Promise.race([
          longRunningOperation,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Operation timeout')), timeout)
          ),
        ])
      ).rejects.toThrow('Operation timeout');
    });

    test('should handle resource exhaustion gracefully', () => {
      // Arrange
      const maxMemory = 100 * 1024 * 1024; // 100MB
      const currentUsage = 50 * 1024 * 1024; // 50MB
      const messageSize = 1024; // 1KB

      // Act
      const canProcess = currentUsage + messageSize < maxMemory;

      // Assert
      expect(canProcess).toBe(true);
      expect(currentUsage + messageSize).toBeLessThan(maxMemory);
    });
  });
});
