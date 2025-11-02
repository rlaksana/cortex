# Key Vault Service Setup and Configuration

## Overview

The Cortex Memory MCP Server includes a comprehensive server-side key vault service for secure storage and management of API keys and sensitive credentials. The key vault provides encryption at rest, access logging, and seamless fallback to environment variables.

## Features

- **AES-256-GCM Encryption**: Military-grade encryption for keys at rest
- **Key Rotation Support**: Secure key rotation without service interruption
- **Access Logging**: Comprehensive audit trails for key access
- **Environment Fallback**: Graceful fallback to environment variables
- **Memory-Only Decryption**: Raw keys never persisted to disk
- **Caching**: Performance optimization with 5-minute cache TTL
- **Health Monitoring**: Built-in health checks and status reporting

## Quick Start

### 1. Environment Setup

Create a master key for the key vault:

```bash
# Generate a secure master key (Base64 encoded)
openssl rand -base64 32

# Set the master key environment variable
export KEY_VAULT_MASTER_KEY="your-generated-master-key-here"
```

### 2. Configure API Keys

Set your API keys as environment variables (used as fallback):

```bash
# OpenAI API Key
export OPENAI_API_KEY="sk-your-openai-api-key"

# Qdrant API Key (optional)
export QDRANT_API_KEY="your-qdrant-api-key"

# JWT Secrets
export JWT_SECRET="your-jwt-secret-at-least-32-characters"
export JWT_REFRESH_SECRET="your-jwt-refresh-secret"

# Encryption Key
export ENCRYPTION_KEY="your-encryption-key-32-chars-minimum"
```

### 3. Using the Key Vault

```typescript
import { getKeyVaultService } from './services/security/key-vault-service.js';

// Get the singleton instance
const keyVault = getKeyVaultService();

// Retrieve a key
const openaiKey = await keyVault.get_key_by_name('openai_api_key');
if (openaiKey) {
  console.log('API key retrieved securely:', openaiKey.value);
}

// Store a new key (encrypted)
const keyId = await keyVault.storeKey({
  name: 'new_service_api_key',
  type: 'custom',
  encrypted_value: 'encrypted-value-here',
  iv: 'initialization-vector',
  salt: 'salt-value',
  algorithm: 'aes-256-gcm',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  access_count: 0,
  is_active: true,
  description: 'New service API key',
  environment: 'production',
  tags: ['api', 'external-service'],
});
```

## Configuration Options

### KeyVaultService Configuration

```typescript
interface KeyVaultConfig {
  masterKeyEnv?: string; // Environment variable containing master key
  fallbackToEnv?: boolean; // Fall back to environment variables if vault key missing
  enableAccessLogging?: boolean; // Enable access logging and audit trails
  encryptionAlgorithm?: string; // Encryption algorithm (default: 'aes-256-gcm')
  keyDerivationRounds?: number; // Key derivation rounds (default: 32768)
}
```

### Default Configuration

```typescript
const defaultConfig = {
  masterKeyEnv: 'KEY_VAULT_MASTER_KEY',
  fallbackToEnv: true,
  enableAccessLogging: true,
  encryptionAlgorithm: 'aes-256-gcm',
  keyDerivationRounds: 32768,
};
```

## Supported Key Types

The key vault supports these predefined key types:

- `openai_api_key`: OpenAI API keys
- `qdrant_api_key`: Qdrant vector database API keys
- `jwt_secret`: JWT signing secrets
- `encryption_key`: General encryption keys
- `custom`: User-defined keys

## Service Integration

### Authentication Service

```typescript
import { getAuthService } from './services/auth/auth-service.js';

// The auth service automatically retrieves JWT secrets from key vault
const authService = await getAuthService();
```

### Embedding Service

```typescript
import { EmbeddingService } from './services/embeddings/embedding-service.js';

// Embedding service automatically retrieves OpenAI API key from key vault
const embeddingService = new EmbeddingService();
const embeddings = await embeddingService.generateEmbedding('text to embed');
```

### Database Adapters

```typescript
import { QdrantAdapter } from './db/adapters/qdrant-adapter.js';

// Database adapters automatically retrieve API keys from key vault
const adapter = new QdrantAdapter({
  url: 'http://localhost:6333',
  // API key will be retrieved from key vault
});
```

## Environment Variables

### Required Variables

- `KEY_VAULT_MASTER_KEY`: Base64-encoded master key for encryption (recommended)
- `OPENAI_API_KEY`: OpenAI API key (fallback)

### Optional Variables

- `QDRANT_API_KEY`: Qdrant API key
- `JWT_SECRET`: JWT signing secret
- `JWT_REFRESH_SECRET`: JWT refresh secret
- `ENCRYPTION_KEY`: General encryption key

### Service Configuration

- `JWT_EXPIRES_IN`: JWT token expiration (default: '1h')
- `JWT_REFRESH_EXPIRES_IN`: JWT refresh token expiration (default: '7d')
- `BCRYPT_ROUNDS`: Password hashing rounds (default: '12')
- `RATE_LIMIT_ENABLED`: Enable rate limiting (default: 'true')

## Production Deployment

### Docker Environment

```dockerfile
# Generate master key
RUN openssl rand -base64 32 > /tmp/master_key

# Set environment variables
ENV KEY_VAULT_MASTER_KEY_FILE=/tmp/master_key
ENV OPENAI_API_KEY=${OPENAI_API_KEY}
ENV QDRANT_API_KEY=${QDRANT_API_KEY}
ENV JWT_SECRET=${JWT_SECRET}

# Load master key from file
CMD ["sh", "-c", "export KEY_VAULT_MASTER_KEY=$(cat $KEY_VAULT_MASTER_KEY_FILE) && node dist/index.js"]
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cortex-secrets
type: Opaque
data:
  key-vault-master-key: <base64-encoded-master-key>
  openai-api-key: <base64-encoded-openai-key>
  qdrant-api-key: <base64-encoded-qdrant-key>
  jwt-secret: <base64-encoded-jwt-secret>

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cortex-server
spec:
  template:
    spec:
      containers:
        - name: cortex
          image: cortex-server:latest
          env:
            - name: KEY_VAULT_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: cortex-secrets
                  key: key-vault-master-key
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: cortex-secrets
                  key: openai-api-key
            - name: QDRANT_API_KEY
              valueFrom:
                secretKeyRef:
                  name: cortex-secrets
                  key: qdrant-api-key
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: cortex-secrets
                  key: jwt-secret
```

## Security Best Practices

### 1. Master Key Security

- Generate a unique master key for each deployment
- Store master keys in secure secret management systems
- Rotate master keys regularly (recommended: every 90 days)
- Never commit master keys to version control

### 2. API Key Management

- Use the principle of least privilege for API keys
- Rotate API keys regularly
- Monitor key usage through access logs
- Revoke compromised keys immediately

### 3. Environment Configuration

```bash
# Production environment
export NODE_ENV=production
export KEY_VAULT_MASTER_KEY="your-secure-master-key"
export OPENAI_API_KEY="your-production-openai-key"
export LOG_LEVEL=info

# Development environment
export NODE_ENV=development
export KEY_VAULT_MASTER_KEY="your-dev-master-key"
export OPENAI_API_KEY="your-dev-openai-key"
export LOG_LEVEL=debug
```

## Troubleshooting

### Common Issues

#### 1. Master Key Not Found

**Error**: `Master key environment variable KEY_VAULT_MASTER_KEY is required`

**Solution**: Set the `KEY_VAULT_MASTER_KEY` environment variable or enable fallback mode.

```bash
export KEY_VAULT_MASTER_KEY="your-base64-encoded-master-key"
```

#### 2. Key Vault Degraded Mode

**Warning**: `Master key not found, using environment fallback mode`

**Solution**: This is expected behavior in development. In production, ensure the master key is properly configured.

#### 3. API Key Not Found

**Error**: `OpenAI API key is required but not found in config, key vault, or environment`

**Solution**: Set the required API key as an environment variable:

```bash
export OPENAI_API_KEY="sk-your-openai-api-key"
```

### Health Checks

Monitor the key vault health:

```typescript
const keyVault = getKeyVaultService();
const health = await keyVault.healthCheck();

console.log('Key Vault Status:', health.status);
console.log('Details:', health.details);
```

### Debug Logging

Enable debug logging for troubleshooting:

```bash
export LOG_LEVEL=debug
```

## API Reference

### KeyVaultService

#### Methods

- `get_key_by_name(name: string): Promise<DecryptedKey | null>`
- `storeKey(entry: Omit<KeyEntry, 'id' | 'created_at' | 'updated_at' | 'access_count'>): Promise<string>`
- `deleteKey(id: string): Promise<boolean>`
- `rotateKey(id: string, newValue: string): Promise<string>`
- `listKeys(): Promise<Omit<KeyEntry, 'encrypted_value' | 'iv' | 'salt'>[]>`
- `clearCache(): void`
- `healthCheck(): Promise<{ status: 'healthy' | 'degraded' | 'unhealthy'; details: any }>`

#### Types

```typescript
interface DecryptedKey {
  id: string;
  name: string;
  type: KeyEntry['type'];
  value: string;
  description?: string;
  environment?: string;
  tags?: string[];
}

interface KeyEntry {
  id: string;
  name: string;
  type: 'openai_api_key' | 'qdrant_api_key' | 'jwt_secret' | 'encryption_key' | 'custom';
  encrypted_value: string;
  iv: string;
  salt: string;
  algorithm: string;
  created_at: string;
  updated_at: string;
  last_accessed?: string;
  access_count: number;
  description?: string;
  environment?: string;
  tags?: string[];
  is_active: boolean;
}
```

## Migration Guide

### From Environment Variables

1. Generate a master key
2. Set up the key vault configuration
3. Update service initialization to use key vault
4. Test fallback behavior
5. Deploy with key vault enabled

### Migration Steps

```typescript
// Before: Direct environment access
const apiKey = process.env.OPENAI_API_KEY;

// After: Key vault integration
const keyVault = getKeyVaultService();
const key = await keyVault.get_key_by_name('openai_api_key');
const apiKey = key?.value || process.env.OPENAI_API_KEY;
```

## Testing

Run the key vault tests:

```bash
# Run all key vault tests
npm test -- --testPathPattern=key-vault

# Run specific test
npm test -- key-vault-service.test.ts

# Run with coverage
npm test -- --coverage --testPathPattern=key-vault
```

## Support

For issues related to the key vault service:

1. Check the health status: `await keyVault.healthCheck()`
2. Review the logs for error messages
3. Verify environment variables are set correctly
4. Ensure master key is properly configured
5. Test fallback mechanisms

## License

This key vault service is part of the Cortex Memory MCP Server and follows the same license terms.
