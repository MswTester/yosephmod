/**
 * @version 1.0.0
 * @description Example Frida agent demonstrating hooking capabilities
 * @author Yongsan SexMaster Team
 * @target Any process (Android/Desktop)
 */

console.log('🚀 Example Frida Agent Loaded');

// Check if Java runtime is available (Android)
try {
  // @ts-ignore - Java is a global available in Frida context
  if (typeof Java !== 'undefined') {
    // @ts-ignore
    Java.perform(() => {
      console.log('📱 Java.perform started');
      
      try {
        // @ts-ignore
        const Log = Java.use('android.util.Log');
        
        Log.d.overload('java.lang.String', 'java.lang.String').implementation = function(tag: string, msg: string) {
          console.log(`[LOG.D] ${tag}: ${msg}`);
          return this.d(tag, msg);
        };
        
        console.log('✅ Successfully hooked android.util.Log.d');
      } catch (error) {
        console.log('⚠️ Could not hook android.util.Log.d:', error);
      }
    });
  } else {
    console.log('⚠️ Java runtime not available (not Android)');
  }
} catch (error) {
  console.log('⚠️ Java runtime check failed:', error);
}

// Example: Native function hooking
try {
  // Try different common function names depending on platform
  const functions = ['open', 'fopen', '_open'];
  let hooked = false;
  
  for (const funcName of functions) {
    try {
      // @ts-ignore - Module.findExportByName exists in Frida
      const funcPtr = Module.findExportByName(null, funcName);
      if (funcPtr) {
        Interceptor.attach(funcPtr, {
          onEnter(args) {
            if (funcName === 'open' || funcName === '_open') {
              const path = args[0].readUtf8String();
              console.log(`[NATIVE] ${funcName}() called with: ${path}`);
            } else if (funcName === 'fopen') {
              const path = args[0].readUtf8String();
              const mode = args[1].readUtf8String();
              console.log(`[NATIVE] ${funcName}() called with: ${path}, mode: ${mode}`);
            }
          },
          onLeave(retval) {
            console.log(`[NATIVE] ${funcName}() returned: ${retval}`);
          }
        });
        console.log(`✅ Successfully hooked ${funcName}()`);
        hooked = true;
        break;
      }
    } catch (e) {
      // Continue to next function
    }
  }
  
  if (!hooked) {
    console.log('⚠️ Could not hook any file operation functions');
  }
} catch (error) {
  console.log('⚠️ Could not hook native functions:', error);
}

// Example: Memory scanning
try {
  const ranges = Process.enumerateRanges('r--');
  console.log(`📊 Found ${ranges.length} readable memory ranges`);
  
  if (ranges.length > 0) {
    console.log(`📍 First range: ${ranges[0].base} - ${ranges[0].base.add(ranges[0].size)} (${ranges[0].size} bytes)`);
  }
} catch (error) {
  console.log('⚠️ Could not enumerate memory ranges:', error);
}

// Example: Send data to host application
function sendUpdate(data: any) {
  send({
    type: 'agent-update',
    timestamp: Date.now(),
    data: data
  });
}

// Send initial status
sendUpdate({
  status: 'initialized',
  capabilities: ['native-hooking', 'memory-scanning'],
  pid: Process.id,
  platform: Process.platform,
  arch: Process.arch
});

console.log('✨ Example Agent initialization complete');