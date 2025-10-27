/**
 * Array Serialization Utilities for qdrant
 *
 * Handles conversion between JavaScript arrays and qdrant array format.
 * qdrant expects arrays in format: {"item1","item2","item3"}
 * while JSON.stringify produces: ["item1","item2","item3"]
 */

/**
 * Convert JavaScript array to qdrant array string format
 * @param arr - JavaScript array to convert
 * @returns qdrant array string literal
 */
export function serializeArray(arr: string[] | null | undefined): string[] | null {
  if (!arr || arr.length === 0) {
    return null;
  }

  // Escape any single quotes and backslashes in array elements
  const escapedElements = arr.map(item => {
    return item.replace(/'/g, "''").replace(/\\/g, "\\\\");
  });

  return escapedElements;
}

/**
 * Convert qdrant array string back to JavaScript array
 * @param pgArray - qdrant array string
 * @returns JavaScript array
 */
export function deserializeArray(pgArray: string[] | null): string[] {
  if (!pgArray || pgArray.length === 0) {
    return [];
  }

  return pgArray.map(item => {
    // Unescape qdrant array elements
    return item.replace(/''/g, "'").replace(/\\\\/g, "\\");
  });
}

/**
 * Handle array serialization for database storage
 * Converts arrays to qdrant format, keeps other types unchanged
 * @param value - Value to serialize
 * @returns Serialized value ready for qdrant
 */
export function serializeForDatabase(value: any): any {
  if (Array.isArray(value)) {
    return serializeArray(value);
  }

  if (value && typeof value === 'object') {
    // Handle objects with array properties
    const result: any = {};
    for (const [key, val] of Object.entries(value)) {
      result[key] = serializeForDatabase(val);
    }
    return result;
  }

  return value;
}

/**
 * Convert database value back to JavaScript format
 * @param value - Value from database
 * @returns Deserialized JavaScript value
 */
export function deserializeFromDatabase(value: any): any {
  // qdrant arrays come back as arrays, no conversion needed
  return value;
}