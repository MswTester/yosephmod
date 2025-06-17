/**
 * @version 1.0.0
 * @description Simple hello world agent for testing
 * @author Yongsan SexMaster Team
 * @target Any process
 */

console.log('👋 Hello World Agent Loaded');

// Simple process information
console.log(`📱 Process: ${Process.id} (${Process.platform}/${Process.arch})`);

// Send hello message to host
send({
  type: 'hello',
  pid: Process.id,
  platform: Process.platform,
  arch: Process.arch,
  timestamp: Date.now()
});

console.log('✨ Hello World Agent ready');