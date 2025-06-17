📦
337 /src/agents/hello-world.js
✄
// src/agents/hello-world.ts
console.log("\u{1F44B} Hello World Agent Loaded");
console.log(`\u{1F4F1} Process: ${Process.id} (${Process.platform}/${Process.arch})`);
send({
  type: "hello",
  pid: Process.id,
  platform: Process.platform,
  arch: Process.arch,
  timestamp: Date.now()
});
console.log("\u2728 Hello World Agent ready");
