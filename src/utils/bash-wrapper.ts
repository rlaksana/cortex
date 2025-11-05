/**
 * Bash wrapper utility for runbook execution
 * This is a simplified wrapper that uses child_process for command execution
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Execute a bash command
 */
export async function Bash(options: {
  command: string;
  description?: string;
  timeout?: number;
}): Promise<string> {
  try {
    const timeout = options.timeout || 30000;
    const { stdout, stderr } = await execAsync(options.command, {
      timeout,
      shell: '/bin/bash',
    });

    if (stderr) {
      throw new Error(stderr);
    }

    return stdout.trim();
  } catch (error) {
    throw new Error(`Command execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}