📦
2723 /src/agents/example-agent.js
✄
// src/agents/example-agent.ts
console.log("\u{1F680} Example Frida Agent Loaded");
try {
  if (typeof Java !== "undefined") {
    Java.perform(() => {
      console.log("\u{1F4F1} Java.perform started");
      try {
        const Log = Java.use("android.util.Log");
        Log.d.overload("java.lang.String", "java.lang.String").implementation = function(tag, msg) {
          console.log(`[LOG.D] ${tag}: ${msg}`);
          return this.d(tag, msg);
        };
        console.log("\u2705 Successfully hooked android.util.Log.d");
      } catch (error) {
        console.log("\u26A0\uFE0F Could not hook android.util.Log.d:", error);
      }
    });
  } else {
    console.log("\u26A0\uFE0F Java runtime not available (not Android)");
  }
} catch (error) {
  console.log("\u26A0\uFE0F Java runtime check failed:", error);
}
try {
  const functions = ["open", "fopen", "_open"];
  let hooked = false;
  for (const funcName of functions) {
    try {
      const funcPtr = Module.findExportByName(null, funcName);
      if (funcPtr) {
        Interceptor.attach(funcPtr, {
          onEnter(args) {
            if (funcName === "open" || funcName === "_open") {
              const path = args[0].readUtf8String();
              console.log(`[NATIVE] ${funcName}() called with: ${path}`);
            } else if (funcName === "fopen") {
              const path = args[0].readUtf8String();
              const mode = args[1].readUtf8String();
              console.log(`[NATIVE] ${funcName}() called with: ${path}, mode: ${mode}`);
            }
          },
          onLeave(retval) {
            console.log(`[NATIVE] ${funcName}() returned: ${retval}`);
          }
        });
        console.log(`\u2705 Successfully hooked ${funcName}()`);
        hooked = true;
        break;
      }
    } catch (e) {
    }
  }
  if (!hooked) {
    console.log("\u26A0\uFE0F Could not hook any file operation functions");
  }
} catch (error) {
  console.log("\u26A0\uFE0F Could not hook native functions:", error);
}
try {
  const ranges = Process.enumerateRanges("r--");
  console.log(`\u{1F4CA} Found ${ranges.length} readable memory ranges`);
  if (ranges.length > 0) {
    console.log(`\u{1F4CD} First range: ${ranges[0].base} - ${ranges[0].base.add(ranges[0].size)} (${ranges[0].size} bytes)`);
  }
} catch (error) {
  console.log("\u26A0\uFE0F Could not enumerate memory ranges:", error);
}
function sendUpdate(data) {
  send({
    type: "agent-update",
    timestamp: Date.now(),
    data
  });
}
sendUpdate({
  status: "initialized",
  capabilities: ["native-hooking", "memory-scanning"],
  pid: Process.id,
  platform: Process.platform,
  arch: Process.arch
});
console.log("\u2728 Example Agent initialization complete");
