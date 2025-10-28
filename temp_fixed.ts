/**
 * Database Factory
 *
 * Creates and manages database adapters based on configuration.
 * Supports Qdrant with proper
 * dependency injection and error handling.
 *
 * Features:
 * - Factory pattern for adapter creation
 * - Configuration validation
 * - Support for Qdrant database
 * - Fallback and error recovery
 * - Type-safe adapter instantiation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '../../utils/logger';
import { Environment } from '../../config/environment';
import { QdrantAdapter } from '../adapters/qdrant-adapter';
import type {
  IDatabaseFactory,
  DatabaseFactoryConfig,
  DatabaseType,
  DatabaseAdapters,
  AdapterCapabilities,
} from '../interfaces/database-factory.interface';
import {
  DatabaseFactoryError,
  ConfigurationError,
  AdapterCreationError,
  UnsupportedDatabaseError,
} from '../interfaces/database-factory.interface';
import type { IVectorAdapter, VectorConfig } from '../interfaces/vector-adapter.interface';
