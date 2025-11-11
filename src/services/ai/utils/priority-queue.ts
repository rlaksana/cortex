
/**
 * Priority Queue Implementation
 *
 * Thread-safe priority queue for background job processing
 * with configurable priorities and efficient operations
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

/**
 * Priority queue implementation with configurable priority levels
 */
export class PriorityQueue<T> {
  private queues: Map<string, T[]> = new Map();
  private priorities: string[] = ['critical', 'high', 'normal', 'low'];

  constructor(customPriorities?: string[]) {
    if (customPriorities) {
      this.priorities = customPriorities;
    }

    // Initialize queues for each priority level
    for (const priority of this.priorities) {
      this.queues.set(priority, []);
    }
  }

  /**
   * Add item to queue with specified priority
   */
  enqueue(item: T, priority: string): void {
    const queue = this.queues.get(priority);
    if (queue) {
      queue.push(item);
    } else {
      // Default to normal priority if unknown priority
      this.queues.get('normal')?.push(item);
    }
  }

  /**
   * Get next item from highest priority queue
   */
  dequeue(): T | undefined {
    for (const priority of this.priorities) {
      const queue = this.queues.get(priority);
      if (queue && queue.length > 0) {
        return queue.shift();
      }
    }
    return undefined;
  }

  /**
   * Peek at next item without removing it
   */
  peek(): T | undefined {
    for (const priority of this.priorities) {
      const queue = this.queues.get(priority);
      if (queue && queue.length > 0) {
        return queue[0];
      }
    }
    return undefined;
  }

  /**
   * Get total size of all queues
   */
  size(): number {
    return Array.from(this.queues.values()).reduce((total, queue) => total + queue.length, 0);
  }

  /**
   * Get size by priority level
   */
  sizeByPriority(): Record<string, number> {
    const sizes: Record<string, number> = {};
    for (const [priority, queue] of this.queues) {
      sizes[priority] = queue.length;
    }
    return sizes;
  }

  /**
   * Check if all queues are empty
   */
  isEmpty(): boolean {
    return this.size() === 0;
  }

  /**
   * Clear all queues
   */
  clear(): void {
    for (const queue of this.queues.values()) {
      queue.length = 0;
    }
  }

  /**
   * Get all items from all queues (for debugging/testing)
   */
  getAll(): T[] {
    const allItems: T[] = [];
    for (const queue of this.queues.values()) {
      allItems.push(...queue);
    }
    return allItems;
  }

  /**
   * Remove items that match a predicate
   */
  removeWhere(predicate: (item: T) => boolean): number {
    let removedCount = 0;

    for (const queue of this.queues.values()) {
      const originalLength = queue.length;
      for (let i = queue.length - 1; i >= 0; i--) {
        if (predicate(queue[i])) {
          queue.splice(i, 1);
          removedCount++;
        }
      }
    }

    return removedCount;
  }

  /**
   * Get queue statistics
   */
  getStats(): {
    totalSize: number;
    sizeByPriority: Record<string, number>;
    priorities: string[];
    isEmpty: boolean;
  } {
    return {
      totalSize: this.size(),
      sizeByPriority: this.sizeByPriority(),
      priorities: [...this.priorities],
      isEmpty: this.isEmpty(),
    };
  }

  /**
   * Reorder an existing item to a new priority
   */
  reprioritize(item: T, newPriority: string): boolean {
    // Remove from current queue
    const removed = this.removeWhere((currentItem) => currentItem === item);

    if (removed > 0) {
      // Add to new priority queue
      this.enqueue(item, newPriority);
      return true;
    }

    return false;
  }

  /**
   * Get items from a specific priority without removing them
   */
  getItemsByPriority(priority: string): T[] {
    const queue = this.queues.get(priority);
    return queue ? [...queue] : [];
  }

  /**
   * Check if queue contains an item
   */
  contains(item: T): boolean {
    for (const queue of this.queues.values()) {
      if (queue.includes(item)) {
        return true;
      }
    }
    return false;
  }
}
