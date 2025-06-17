/**
 * @version 1.0.0
 * @description Cheat Agent for Android Game Hacking
 * @author Yongsan SexMaster Team
 * @target Android Games
 */

console.log('🎮 Cheat Agent Loaded');

// Cheat state management
let cheatsEnabled = false;
let healthValue = 100;
let coinValue = 1000;
let speedMultiplier = 1.0;

// Memory scanning utilities
class MemoryScanner {
  static scanForValue(value: number, type: 'i8' | 'i16' | 'i32' | 'i64' | 'float' | 'double' = 'i32'): NativePointer[] {
    const results: NativePointer[] = [];
    const ranges = Process.enumerateRanges('rw-');
    
    for (const range of ranges) {
      try {
        Memory.scan(range.base, range.size, this.getPattern(value, type), {
          onMatch: (address, size) => {
            results.push(address);
          },
          onComplete: () => {}
        });
      } catch (error) {
        // Continue scanning other ranges
      }
    }
    
    return results;
  }
  
  private static getPattern(value: number, type: string): string {
    let buffer: ArrayBuffer;
    let view: DataView;
    
    switch (type) {
      case 'i8':
        buffer = new ArrayBuffer(1);
        view = new DataView(buffer);
        view.setInt8(0, value);
        break;
      case 'i16':
        buffer = new ArrayBuffer(2);
        view = new DataView(buffer);
        view.setInt16(0, value, true);
        break;
      case 'i32':
        buffer = new ArrayBuffer(4);
        view = new DataView(buffer);
        view.setInt32(0, value, true);
        break;
      case 'float':
        buffer = new ArrayBuffer(4);
        view = new DataView(buffer);
        view.setFloat32(0, value, true);
        break;
      case 'double':
        buffer = new ArrayBuffer(8);
        view = new DataView(buffer);
        view.setFloat64(0, value, true);
        break;
      default:
        buffer = new ArrayBuffer(4);
        view = new DataView(buffer);
        view.setInt32(0, value, true);
    }
    
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
  }
}

// Hook Java runtime if available (Android)
// @ts-ignore
if (typeof Java !== 'undefined') {
  // @ts-ignore
  Java.perform(() => {
    console.log('📱 Java.perform started - Android environment detected');
    
    try {
      // Common Android game classes to hook
      hookUnityPlayer();
      hookPlayerPrefs();
      hookCommonGameMethods();
    } catch (error) {
      console.log('⚠️ Some hooks failed:', error);
    }
  });
}

function hookUnityPlayer() {
  try {
    // @ts-ignore
    const UnityPlayer = Java.use('com.unity3d.player.UnityPlayer');
    
    // Hook Unity messages
    const originalUnitySendMessage = UnityPlayer.UnitySendMessage;
    UnityPlayer.UnitySendMessage = function(gameObject: string, methodName: string, message: string) {
      console.log(`[UNITY] ${gameObject}.${methodName}(${message})`);
      
      // Intercept specific messages
      if (cheatsEnabled) {
        if (methodName === 'TakeDamage' || methodName === 'OnDamage') {
          console.log('🛡️ Damage blocked by cheat');
          return; // Block damage
        }
        
        if (methodName === 'SpendCoins' || methodName === 'DeductCoins') {
          console.log('💰 Coin spending blocked by cheat');
          return; // Block coin spending
        }
      }
      
      return originalUnitySendMessage.call(this, gameObject, methodName, message);
    };
    
    console.log('✅ Unity Player hooked');
  } catch (error) {
    console.log('⚠️ Unity Player not found');
  }
}

function hookPlayerPrefs() {
  try {
    // @ts-ignore
    const PlayerPrefs = Java.use('com.unity3d.player.UnityPlayerPrefs');
    
    // Hook getInt
    PlayerPrefs.getInt.overload('java.lang.String', 'int').implementation = function(key: string, defaultValue: number) {
      const originalValue = this.getInt(key, defaultValue);
      
      if (cheatsEnabled) {
        if (key.toLowerCase().includes('coin') || key.toLowerCase().includes('money')) {
          console.log(`💰 PlayerPrefs.getInt(${key}) -> ${coinValue} (modified)`);
          return coinValue;
        }
        
        if (key.toLowerCase().includes('health') || key.toLowerCase().includes('hp')) {
          console.log(`❤️ PlayerPrefs.getInt(${key}) -> ${healthValue} (modified)`);
          return healthValue;
        }
      }
      
      return originalValue;
    };
    
    // Hook setInt to prevent saving modified values
    PlayerPrefs.setInt.overload('java.lang.String', 'int').implementation = function(key: string, value: number) {
      if (cheatsEnabled && (key.toLowerCase().includes('coin') || key.toLowerCase().includes('money'))) {
        console.log(`💰 Prevented saving ${key} = ${value}`);
        return;
      }
      
      return this.setInt(key, value);
    };
    
    console.log('✅ PlayerPrefs hooked');
  } catch (error) {
    console.log('⚠️ PlayerPrefs not found');
  }
}

function hookCommonGameMethods() {
  try {
    // Hook common game class patterns
    const gameClasses = [
      'GameManager',
      'PlayerController', 
      'Player',
      'Character',
      'GameController'
    ];
    
    for (const className of gameClasses) {
      try {
        // @ts-ignore
        Java.enumerateLoadedClasses({
          onMatch: (name: string) => {
            if (name.includes(className)) {
              try {
                // @ts-ignore
                const GameClass = Java.use(name);
                console.log(`🎯 Found potential game class: ${name}`);
                
                // Try to hook common method names
                const methods = ['takeDamage', 'TakeDamage', 'OnDamage', 'damage'];
                methods.forEach(methodName => {
                  try {
                    const originalMethod = GameClass[methodName];
                    if (originalMethod) {
                      GameClass[methodName].implementation = function(...args: any[]) {
                        if (cheatsEnabled) {
                          console.log(`🛡️ Blocked ${name}.${methodName}()`);
                          return;
                        }
                        return originalMethod.apply(this, args);
                      };
                      console.log(`✅ Hooked ${name}.${methodName}`);
                    }
                  } catch (e) {
                    // Method not found, continue
                  }
                });
              } catch (e) {
                // Class loading failed
              }
            }
          },
          onComplete: () => {}
        });
      } catch (error) {
        // Continue with next class
      }
    }
  } catch (error) {
    console.log('⚠️ Common game method hooking failed:', error);
  }
}

// Exported RPC functions for UI
function toggleCheats(): boolean {
  cheatsEnabled = !cheatsEnabled;
  console.log(`🎮 Cheats ${cheatsEnabled ? 'ENABLED' : 'DISABLED'}`);
  
  send({
    type: 'cheat-status',
    enabled: cheatsEnabled,
    timestamp: Date.now()
  });
  
  return cheatsEnabled;
}

function setHealth(value: number): boolean {
  healthValue = Math.max(0, Math.min(999999, value));
  console.log(`❤️ Health set to ${healthValue}`);
  
  send({
    type: 'health-updated',
    value: healthValue,
    timestamp: Date.now()
  });
  
  return true;
}

function setCoins(value: number): boolean {
  coinValue = Math.max(0, Math.min(999999999, value));
  console.log(`💰 Coins set to ${coinValue}`);
  
  send({
    type: 'coins-updated',
    value: coinValue,
    timestamp: Date.now()
  });
  
  return true;
}

function setSpeedMultiplier(multiplier: number): boolean {
  speedMultiplier = Math.max(0.1, Math.min(10.0, multiplier));
  console.log(`🏃 Speed multiplier set to ${speedMultiplier}x`);
  
  send({
    type: 'speed-updated',
    multiplier: speedMultiplier,
    timestamp: Date.now()
  });
  
  return true;
}

function scanMemoryForValue(value: number, type: string = 'i32'): number {
  console.log(`🔍 Scanning memory for ${type} value: ${value}`);
  
  const results = MemoryScanner.scanForValue(value, type as any);
  console.log(`Found ${results.length} matches`);
  
  send({
    type: 'memory-scan-result',
    value,
    dataType: type,
    matches: results.length,
    addresses: results.slice(0, 10).map(addr => addr.toString()),
    timestamp: Date.now()
  });
  
  return results.length;
}

function getCheatStatus(): any {
  return {
    enabled: cheatsEnabled,
    health: healthValue,
    coins: coinValue,
    speedMultiplier,
    platform: Process.platform,
    arch: Process.arch,
    pid: Process.id
  };
}

function freezeValue(address: string, value: number, type: string = 'i32'): boolean {
  try {
    const memPtr = ptr(address);
    
    // Write the value initially
    switch (type) {
      case 'i8':
        memPtr.writeS8(value);
        break;
      case 'i16':
        memPtr.writeS16(value);
        break;
      case 'i32':
        memPtr.writeS32(value);
        break;
      case 'float':
        memPtr.writeFloat(value);
        break;
      case 'double':
        memPtr.writeDouble(value);
        break;
      default:
        memPtr.writeS32(value);
    }
    
    console.log(`🧊 Freezing ${address} to ${value} (${type})`);
    
    // Set up memory protection change callback
    const intervalId = setInterval(() => {
      try {
        switch (type) {
          case 'i8':
            memPtr.writeS8(value);
            break;
          case 'i16':
            memPtr.writeS16(value);
            break;
          case 'i32':
            memPtr.writeS32(value);
            break;
          case 'float':
            memPtr.writeFloat(value);
            break;
          case 'double':
            memPtr.writeDouble(value);
            break;
          default:
            memPtr.writeS32(value);
        }
      } catch (error) {
        console.log(`❄️ Freeze failed for ${address}, stopping`);
        clearInterval(intervalId);
      }
    }, 100);
    
    // Store interval ID for later cleanup
    (globalThis as any).freezeIntervals = (globalThis as any).freezeIntervals || [];
    (globalThis as any).freezeIntervals.push(intervalId);
    
    return true;
  } catch (error) {
    console.log(`❌ Failed to freeze ${address}:`, error);
    return false;
  }
}

// Export functions for RPC calls
rpc.exports = {
  toggleCheats,
  setHealth,
  setCoins,
  setSpeedMultiplier,
  scanMemoryForValue,
  getCheatStatus,
  freezeValue
};

// Send initial status
send({
  type: 'agent-initialized',
  agent: 'cheat-agent',
  capabilities: [
    'memory-scanning',
    'value-freezing', 
    'unity-hooking',
    'playerprefs-hooking',
    'damage-blocking',
    'coin-hacking'
  ],
  status: getCheatStatus(),
  timestamp: Date.now()
});

console.log('🎮 Cheat Agent initialization complete');