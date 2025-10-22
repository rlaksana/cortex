// Temporary stub to get basic compilation working
import type { MemoryStoreRequest } from '../../types/core-interfaces.js';

export class ValidationService {
  validateStoreRequest(_request: MemoryStoreRequest): { valid: boolean; errors: string[] } {
    return { valid: true, errors: [] };
  }
}