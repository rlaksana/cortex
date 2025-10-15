#!/usr/bin/env node

// Test script to debug environment variables
console.log('=== Environment Variables ===');
console.log('DATABASE_URL:', process.env.DATABASE_URL || '(not set)');
console.log('NODE_ENV:', process.env.NODE_ENV || '(not set)');
console.log('LOG_LEVEL:', process.env.LOG_LEVEL || '(not set)');
console.log('CWD:', process.cwd());
console.log('===========================');

// Try to extract password from DATABASE_URL
if (process.env.DATABASE_URL) {
  const url = new URL(process.env.DATABASE_URL);
  console.log('Parsed URL:');
  console.log('  Protocol:', url.protocol);
  console.log('  Username:', url.username);
  console.log('  Password:', url.password);
  console.log('  Host:', url.hostname);
  console.log('  Port:', url.port);
  console.log('  Database:', url.pathname);
}
