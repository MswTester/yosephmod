# YSSM - Complete Application Development Guide

> 🎓 **Educational Purposes Only** - A comprehensive guide for application development and reverse engineering learning

## 🚀 Quick Start (5 Minutes)

### 1. Prerequisites Installation
```bash
# Install Node.js 18+ (https://nodejs.org)
# Install Git (https://git-scm.com)
# Android Device + USB Debugging Enabled
```

### 2. Project Download and Setup
```bash
git clone https://github.com/MswTester/yongsan-sexmaster.git
cd yongsan-sexmaster
npm install
```

### 3. Run Development Mode
```bash
npm run dev
```

---

## 🏗️ Understanding System Architecture

### 📋 Overall Structure Overview
YSSM operates through **3 independent parts** communicating with each other:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Renderer     │◄──►│   Main Process  │◄──►│     Agent       │
│   (UI Layer)    │    │  (Relay Server) │    │ (Core Logic)    │
│                 │    │                 │    │                 │
│ • React-based   │    │ • Electron Main │    │ • Frida Scripts │
│ • User Input    │    │ • Communication │    │ • Memory Access │
│ • State Display │    │ • State Mgmt    │    │ • Function Hook │
└─────────────────┘    └─────────────────┘    └─────────────────┘
    Browser Environment    Node.js Environment   Target App Environment
```

### 🎯 Detailed Component Descriptions

#### 1️⃣ **Agent** - `src/agents/`
- **Role**: Core component that performs actual functionality
- **Location**: Runs inside target game/app process
- **Technology**: Frida JavaScript Engine
- **Features**:
  - Memory read/write operations
  - Function hooking and patching
  - Game logic manipulation
  - Real-time data collection

```typescript
// src/agents/main-agent.ts example
on('change-health', (newValue: number) => {
    const healthAddress = findHealthAddress();
    if (healthAddress) {
        Memory.protect(healthAddress, 4, 'rw-');
        healthAddress.writeInt(newValue);
        setState('current-health', newValue); // Auto-send to UI
    }
});
```

#### 2️⃣ **Main Process** - `src/main/`
- **Role**: Communication relay between Agent and Renderer
- **Location**: Runs in desktop environment (Electron)
- **Technology**: Node.js + Electron + Frida Node.js bindings
- **Features**:
  - Agent management via FridaManager
  - Global state management via StateManager
  - UI connection via IPC communication
  - File system access

```typescript
// src/main/main_logic.ts example
ipcMain.on('from-renderer', (event, channel, ...args) => {
    console.log(`UI -> Agent: ${channel}`, args);
    fridaManager.send(channel, ...args); // Forward to Agent
});

fridaManager.on('scan-complete', (address, value) => {
    sendRenderer('scan-complete', address, value); // Forward to UI
});
```

#### 3️⃣ **Renderer** - `src/renderer/`
- **Role**: Provides user interface
- **Location**: Browser environment inside Electron window
- **Technology**: React + TypeScript + Styled Components
- **Features**:
  - Control panel for features
  - Real-time status monitoring
  - Settings management UI
  - Log console display

```typescript
// src/renderer/Main.tsx example
const handleChangeHealth = () => {
    const value = parseInt(targetValue);
    send('change-health', value); // Auto-send to Agent
};

const currentHealth = getState('current-health'); // Auto-update from Agent
```

---

## ⚙️ Initial Configuration and State Management System

### 🔧 Using config_initial.ts

All application settings and initial values are managed in `src/main/config_initial.ts`.

#### Understanding Configuration Structure
```typescript
interface setupConfig {
    key: string;        // Unique key name
    default: any;       // Default value (any type allowed)
    store: boolean;     // true: persist after restart, false: reset after restart
}
```

#### Real Configuration Examples
```typescript
const init_config: setupConfig[] = [
    // Window settings (auto-saved)
    {key: "main-bounds", default: {x: 0, y: 0, width: 400, height: 600}, store: true},
    
    // Target app settings
    {key: "target-app", default: "com.example.app", store: true},
    
    // Basic feature settings
    {key: "auto-mode", default: false, store: true},
    {key: "speed-multiplier", default: 1.0, store: true},
    {key: "god-mode", default: false, store: true},
    
    // Game-related settings
    {key: "default-health", default: 1000, store: true},
    {key: "default-gold", default: 999999, store: true},
    
    // Runtime state (not saved)
    {key: "device", default: null, store: false},
    {key: "session", default: null, store: false},
    {key: "last-scan-results", default: [], store: false},
];
```

#### How to Add New Settings
```typescript
// Step 1: Add setting to config_initial.ts
{key: "my-custom-setting", default: "default-value", store: true},

// Step 2: Use in Agent
const mySetting = state['my-custom-setting'];

// Step 3: Use in UI
const { getState, setState } = useGlobal();
const value = getState('my-custom-setting');
setState('my-custom-setting', 'new-value');
```

### 📊 StateManager Operation Principles

StateManager automatically handles state synchronization between the 3 parts:

```typescript
// State change in Agent
setState('player-health', 1000);

// ⬇️ Automatically sent to Main Process

// ⬇️ Main Process relays to Renderer

// ⬇️ Immediately available in UI
const health = getState('player-health'); // 1000
```

---

## 🔄 Complete Communication System Guide

### 📡 Understanding Communication Flow

#### Pattern 1: UI → Agent (Command Transmission)
```typescript
// 1. Button click in UI
const handleClick = () => {
    send('do-something', param1, param2);
};

// 2. Main Process auto-relay (this code is written in main.ts)
ipcMain.on('send-to-agent', (event, channel, ...args) => {
    fridaManager.send(channel, ...args);
});

// 3. Processing in Agent
on('do-something', (param1, param2) => {
    log("Task in progress...");
    // Execute actual logic
    setState('task-result', 'success');
});
```

#### Pattern 2: Agent → UI (State Updates)
```typescript
// 1. State change in Agent
setState('health', newValue);

// 2. Main Process auto-detect and relay (this code is written in main.ts)
fridaManager.on('state-update', (key, value) => {
    sendRenderer('state-changed', key, value);
});

// 3. Auto-update in UI
const currentHealth = getState('health'); // Automatically latest value
```

### 🎛️ Event Handling System

#### Registering Event Listeners in Agent
```typescript
// src/agents/main-agent.ts
import { on, setState, log } from './module';

// Health change event
on('change-health', (newValue: number) => {
    try {
        const address = findHealthAddress();
        if (address) {
            Memory.protect(address, 4, 'rw-');
            address.writeInt(newValue);
            setState('current-health', newValue);
            log(`✅ Health changed to ${newValue}`);
        }
    } catch (error) {
        log("❌ Health change failed:", error);
        setState('last-error', error.message);
    }
});

// State change detection
onStateChanged((key: string, value: any) => {
    if (key === 'auto-mode' && value) {
        startAutoMode();
    }
});
```

#### Sending Events from UI
```typescript
// src/renderer/Main.tsx
import { useGlobal } from './contexts/globalContext';

const Main = () => {
    const { send, exec, getState, setState } = useGlobal();
    
    // Simple command transmission
    const handleHealthChange = () => {
        send('change-health', 1000);
    };
    
    // Direct code execution
    const executeCustomCode = () => {
        exec('log("Hello from UI!")');
    };
    
    // State checking
    const currentHealth = getState('current-health');
    
    return (
        <Button onClick={handleHealthChange}>
            Change Health (Current: {currentHealth})
        </Button>
    );
};
```

---

## 🎨 UI Components and State Integration Guide

### 🧩 Primitive Component System

YSSM provides reusable UI components:

#### Basic Layout Components
```typescript
import { Container, Row, Col, Button, Input, Text } from './components/ui/primitive';

// Basic layout
<Container h="100%" p="1rem" gap="1rem">
    <Row justify="space-between" items="center">
        <Text size="lg">Title</Text>
        <Button variant="outline">Button</Button>
    </Row>
    
    <Col gap="0.5rem">
        <Input placeholder="Enter value" />
        <Button variant="default">Execute</Button>
    </Col>
</Container>
```

#### State-Integrated UI Components
```typescript
// src/renderer/Main.tsx
import React, { useState, useEffect } from 'react';
import { useGlobal } from './contexts/globalContext';
import { Switch, Slider, Text } from './components/ui/primitive';

const Panel = () => {
    const { getState, setState, send } = useGlobal();
    
    // Local state
    const [inputValue, setInputValue] = useState('1000');
    
    // Sync with global state
    const autoMode = getState('auto-mode') || false;
    const speedMultiplier = getState('speed-multiplier') || 1.0;
    
    // Toggle auto mode
    const toggleAutoMode = () => {
        const newState = !autoMode;
        setState('auto-mode', newState);
        send('toggle-auto-mode', newState);
    };
    
    // Change speed
    const handleSpeedChange = (value: number) => {
        setState('speed-multiplier', value);
        send('set-speed-multiplier', value);
    };
    
    return (
        <Col gap="1rem" p="1rem">
            {/* Auto mode switch */}
            <Row justify="space-between" items="center">
                <Text>Auto Mode</Text>
                <Switch 
                    checked={autoMode}
                    onChange={toggleAutoMode}
                />
            </Row>
            
            {/* Speed slider */}
            <Col gap="0.5rem">
                <Text>Speed Multiplier: {speedMultiplier}x</Text>
                <Slider
                    min={0.1}
                    max={5}
                    step={0.1}
                    value={speedMultiplier}
                    onChange={handleSpeedChange}
                />
            </Col>
            
            {/* Input and button */}
            <Row gap="0.5rem">
                <Input 
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder="Health value"
                />
                <Button 
                    onClick={() => send('change-health', parseInt(inputValue))}
                    disabled={isNaN(parseInt(inputValue))}
                >
                    Change
                </Button>
            </Row>
        </Col>
    );
};
```

### 📱 Building Configuration UI in Config.tsx
```typescript
// src/renderer/Config.tsx
import { Switch, Select, Input, Row, Col, Text, Button } from './components/ui/primitive';

const Config = () => {
    const { getState, setState } = useGlobal();
    
    return (
        <Container p="1rem" gap="1rem">
            {/* Basic settings */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text size="lg" weight="medium">Basic Settings</Text>
                
                <Row justify="space-between" items="center">
                    <Text>Auto Start</Text>
                    <Switch 
                        checked={getState('auto-start')}
                        onChange={(checked) => setState('auto-start', checked)}
                    />
                </Row>
                
                <Row justify="space-between" items="center">
                    <Text>Target App</Text>
                    <Input 
                        value={getState('target-app')}
                        onChange={(e) => setState('target-app', e.target.value)}
                        placeholder="com.example.app"
                    />
                </Row>
            </Col>
            
            {/* Performance settings */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text size="lg" weight="medium">Performance Settings</Text>
                
                <Row justify="space-between" items="center">
                    <Text>Update Interval (ms)</Text>
                    <Select 
                        value={getState('update-interval')}
                        onChange={(e) => setState('update-interval', parseInt(e.target.value))}
                    >
                        <option value="100">100ms</option>
                        <option value="500">500ms</option>
                        <option value="1000">1 second</option>
                        <option value="5000">5 seconds</option>
                    </Select>
                </Row>
            </Col>
        </Container>
    );
};
```

---

## 🔧 FridaManager Usage and Real Application Examples

### 🎯 FridaManager Core Methods

#### Device Connection and Script Loading
```typescript
// src/main/main_logic.ts
const init = async (fridaManager: FridaManager, stateManager: StateManager) => {
    try {
        // Select USB device
        await fridaManager.selectDeviceByType('usb');
        console.log('✅ USB device connected');
        
        // Load script to target app
        const targetApp = stateManager.getState("target-app");
        const result = await fridaManager.loadScript("main-agent", targetApp);
        
        if (result.success) {
            console.log('✅ Script loading successful');
        } else {
            console.error('❌ Script loading failed:', result.error);
        }
    } catch (error) {
        console.error('❌ Initialization failed:', error);
    }
};
```

#### Agent Communication Setup
```typescript
// Send message to Agent
fridaManager.send('channel-name', data1, data2);

// Receive message from Agent
fridaManager.on('message-from-agent', (data) => {
    console.log('Data received from Agent:', data);
});

// Monitor script status
fridaManager.on('script-destroyed', () => {
    console.log('Script connection lost');
});
```

### 🎮 Complete Application Example

#### Scenario: Creating RPG Game Health/Gold Modification Tool

**Step 1: Implement Logic in Agent**
```typescript
// src/agents/main-agent.ts
import { state, log, on, emit, setState } from './module';

let gameModuleBase: NativePointer | null = null;
let healthAddress: NativePointer | null = null;
let goldAddress: NativePointer | null = null;

// Initialization
on('init', () => {
    log("🚀 RPG modification agent started!");
    findGameAddresses();
});

// Find game memory addresses
function findGameAddresses() {
    try {
        // Find game main module
        const gameModule = Process.getModuleByName("libgame.so");
        if (gameModule) {
            gameModuleBase = gameModule.base;
            log(`🎯 Game module found: ${gameModuleBase}`);
            
            // Calculate addresses using known offsets
            healthAddress = gameModuleBase.add(0x123456);
            goldAddress = gameModuleBase.add(0x789ABC);
            
            setState('addresses-found', true);
            log("✅ Memory address search complete");
        }
    } catch (error) {
        log("❌ Address search failed:", error);
        setState('addresses-found', false);
    }
}

// Change health
on('change-health', (newValue: number) => {
    if (!healthAddress) {
        log("❌ Health address not found");
        return;
    }
    
    try {
        Memory.protect(healthAddress, 4, 'rw-');
        healthAddress.writeInt(newValue);
        
        // Verify actual value
        const currentValue = healthAddress.readInt();
        setState('current-health', currentValue);
        
        log(`✅ Health changed: ${currentValue}`);
    } catch (error) {
        log("❌ Health change failed:", error);
    }
});

// Change gold
on('change-gold', (newValue: number) => {
    if (!goldAddress) {
        log("❌ Gold address not found");
        return;
    }
    
    try {
        Memory.protect(goldAddress, 4, 'rw-');
        goldAddress.writeInt(newValue);
        
        const currentValue = goldAddress.readInt();
        setState('current-gold', currentValue);
        
        log(`✅ Gold changed: ${currentValue}`);
    } catch (error) {
        log("❌ Gold change failed:", error);
    }
});

// Auto mode
let autoInterval: any = null;
on('toggle-auto-mode', (enabled: boolean) => {
    if (enabled) {
        autoInterval = setInterval(() => {
            if (healthAddress && goldAddress) {
                // Maintain health and gold at maximum
                const maxHealth = state['default-health'] || 9999;
                const maxGold = state['default-gold'] || 999999;
                
                healthAddress.writeInt(maxHealth);
                goldAddress.writeInt(maxGold);
                
                setState('current-health', maxHealth);
                setState('current-gold', maxGold);
            }
        }, state['update-interval'] || 1000);
        
        log("🤖 Auto mode enabled");
    } else {
        if (autoInterval) {
            clearInterval(autoInterval);
            autoInterval = null;
        }
        log("🤖 Auto mode disabled");
    }
});
```

**Step 2: Implement Control Panel in UI**
```typescript
// src/renderer/Main.tsx
import React, { useState } from 'react';
import { useGlobal } from './contexts/globalContext';
import { Container, Row, Col, Button, Input, Text, Switch, Badge } from './components/ui/primitive';

const RPGPanel = () => {
    const { getState, setState, send } = useGlobal();
    
    const [healthInput, setHealthInput] = useState('9999');
    const [goldInput, setGoldInput] = useState('999999');
    
    // Current state
    const addressesFound = getState('addresses-found');
    const currentHealth = getState('current-health');
    const currentGold = getState('current-gold');
    const autoMode = getState('auto-mode') || false;
    
    return (
        <Container h="100%" p="1rem" gap="1rem">
            {/* Status display */}
            <Row justify="space-between" items="center">
                <Text size="lg" weight="medium">RPG Panel</Text>
                <Badge variant={addressesFound ? 'default' : 'destructive'}>
                    {addressesFound ? 'Connected' : 'Disconnected'}
                </Badge>
            </Row>
            
            {/* Current values display */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text weight="medium">Current Status</Text>
                <Text size="sm">Health: {currentHealth || 'Unknown'}</Text>
                <Text size="sm">Gold: {currentGold || 'Unknown'}</Text>
            </Col>
            
            {/* Health modification */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text weight="medium">Health Modification</Text>
                <Row gap="0.5rem">
                    <Input 
                        value={healthInput}
                        onChange={(e) => setHealthInput(e.target.value)}
                        placeholder="Health value"
                    />
                    <Button 
                        onClick={() => send('change-health', parseInt(healthInput))}
                        disabled={!addressesFound || isNaN(parseInt(healthInput))}
                    >
                        Change
                    </Button>
                </Row>
                <Row gap="0.5rem">
                    <Button variant="outline" onClick={() => {
                        setHealthInput('9999');
                        send('change-health', 9999);
                    }}>Max Health</Button>
                    <Button variant="outline" onClick={() => {
                        setHealthInput('1');
                        send('change-health', 1);
                    }}>Min Health</Button>
                </Row>
            </Col>
            
            {/* Gold modification */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text weight="medium">Gold Modification</Text>
                <Row gap="0.5rem">
                    <Input 
                        value={goldInput}
                        onChange={(e) => setGoldInput(e.target.value)}
                        placeholder="Gold value"
                    />
                    <Button 
                        onClick={() => send('change-gold', parseInt(goldInput))}
                        disabled={!addressesFound || isNaN(parseInt(goldInput))}
                    >
                        Change
                    </Button>
                </Row>
                <Row gap="0.5rem">
                    <Button variant="outline" onClick={() => {
                        setGoldInput('999999');
                        send('change-gold', 999999);
                    }}>Max Gold</Button>
                    <Button variant="outline" onClick={() => {
                        setGoldInput('0');
                        send('change-gold', 0);
                    }}>Reset Gold</Button>
                </Row>
            </Col>
            
            {/* Auto mode */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Row justify="space-between" items="center">
                    <Text weight="medium">Auto Mode</Text>
                    <Switch 
                        checked={autoMode}
                        onChange={(e) => {
                            const enabled = e.target.checked;
                            setState('auto-mode', enabled);
                            send('toggle-auto-mode', enabled);
                        }}
                        disabled={!addressesFound}
                    />
                </Row>
                <Text size="sm" muted>
                    {autoMode ? 
                        'Automatically maintains health and gold at maximum' : 
                        'Manual value changes required'
                    }
                </Text>
            </Col>
        </Container>
    );
};

export default RPGPanel;
```

**Step 3: Configure Target App in Settings**
```typescript
// Configure target app in src/main/config_initial.ts
{key: "target-app", default: "com.example.rpggame", store: true},
{key: "default-health", default: 9999, store: true},
{key: "default-gold", default: 999999, store: true},
```

---

## 📦 NPM Commands and Deployment Guide

### 🛠️ Development Commands

```bash
# Development mode (live reload)
npm run dev

# Type checking
npm run typecheck

# Code inspection and auto-fix
npm run lint
npm run lint:fix

# Build (deployment preparation)
npm run build

# Generate executables (all platforms)
npm run dist

# Generate Windows executable only
npm run dist:win

# Generate macOS executable only  
npm run dist:mac

# Generate Linux executable only
npm run dist:linux
```

### 📱 Deployment Preparation Checklist

#### 1. Code Inspection and Build Testing
```bash
# Check type errors
npm run typecheck

# Code style inspection
npm run lint

# Build testing
npm run build
```

#### 2. Configuration File Check
```typescript
// Check deployment settings in src/main/config_initial.ts
{key: "target-app", default: "actual_target_app_package_name", store: true},
{key: "auto-start", default: false, store: true}, // Recommended false for deployment
```

#### 3. Generate Executables
```bash
# Generate executable for current platform
npm run dist

# Generated file location: dist/ folder
# Windows: .exe file
# macOS: .dmg file  
# Linux: .AppImage file
```

### 🚀 Distributing to Users

#### Deployment Package Structure
```
deployment_folder/
├── YSSM-1.0.0-win.exe        # Windows executable
├── Usage_Guide.txt           # Simple usage guide
├── Target_App_Settings.txt   # Target app-specific configuration guide
└── Troubleshooting.txt       # Common problem solutions
```

#### User Guide Example
```
YSSM Application Usage Guide

1. Android Device Preparation
   - Enable USB debugging
   - Enable developer options
   - Connect to PC via USB

2. Application Execution
   - Run YSSM.exe
   - Ensure target app is running
   - Use features in Main tab

3. Configuration Changes
   - Change target app package name in Config tab
   - Adjust update interval and other settings

When problems occur:
- Check logs in Console tab
- Verify device connection status
- Ensure target app is running
```

---

## 🔧 Advanced Development Tips

### 🎯 Performance Optimization

```typescript
// Optimize memory access in Agent
const cachedAddresses = new Map<string, NativePointer>();

function getCachedAddress(key: string, finder: () => NativePointer): NativePointer | null {
    if (!cachedAddresses.has(key)) {
        try {
            const addr = finder();
            cachedAddresses.set(key, addr);
        } catch {
            return null;
        }
    }
    return cachedAddresses.get(key) || null;
}

// Usage example
const healthAddr = getCachedAddress('health', () => 
    Process.getModuleByName("libgame.so").base.add(0x123456)
);
```

### 🛡️ Safe Memory Manipulation

```typescript
function safeMemoryWrite(address: NativePointer, value: number, size: number = 4): boolean {
    try {
        // Check and change memory permissions
        Memory.protect(address, size, 'rw-');
        
        // Write value
        if (size === 4) address.writeInt(value);
        else if (size === 8) address.writeDouble(value);
        else if (size === 1) address.writeU8(value);
        
        // Verification: check if actually changed
        const written = size === 4 ? address.readInt() : 
                       size === 8 ? address.readDouble() : 
                       address.readU8();
        
        return written === value;
    } catch (error) {
        log(`Memory write failed: ${error}`);
        return false;
    }
}
```

### 🔍 Debugging Tools

```typescript
// Memory dump in Agent
function dumpMemory(address: NativePointer, size: number = 256) {
    try {
        const data = address.readByteArray(size);
        if (data) {
            log("Memory dump:", hexdump(data));
        }
    } catch (error) {
        log("Dump failed:", error);
    }
}

// Function call tracing
function traceFunction(functionAddr: NativePointer, name: string) {
    Interceptor.attach(functionAddr, {
        onEnter(args) {
            log(`📞 ${name} called`);
            log(`Arguments:`, args.map(arg => arg.toString()));
        },
        onLeave(retval) {
            log(`📤 ${name} return value:`, retval.toString());
        }
    });
}
```

---

## 🚨 Troubleshooting Guide

### Common Errors

#### 1. "Device not connected" Error
```bash
Solution:
1. Check if USB debugging is enabled
2. Verify device recognition with adb devices command
3. Check "Allow USB debugging" in developer options
4. Try replacing USB cable
```

#### 2. "Script injection failed" Error
```bash
Solution:
1. Ensure target app is running
2. Verify app package name is correct
3. Check rooting/jailbreak status
4. Disable anti-cheat programs
```

#### 3. "Memory access violation" Error
```bash
Solution:
1. Verify memory address is correct
2. Ensure Memory.protect() is called
3. Check for address changes due to game updates
4. Verify 32-bit/64-bit architecture
```

#### 4. "Interceptor.attach failed" Error
```bash
Solution:
1. When using emulator, set emulated option to true in fridaManager.loadScript() method
```

### 📊 Log Checking Methods

1. **Console Tab**: Check real-time logs from Agent
2. **Developer Tools**: Use `Ctrl+Shift+I` to check UI errors  
3. **Terminal**: Main Process logs when running `npm run dev`

---

## ⚖️ Important Notices

### 🎓 Educational Purposes Only
- Use only for reverse engineering learning
- Test only on your own software
- Utilize for educational and research purposes

### 🚫 Prohibited Uses
- Prohibited use in online games (account ban risk)
- No copyright infringement of others
- No commercial use
- No malicious use

### ⚖️ Legal Responsibility
- Use at your own risk
- Must comply with relevant laws
- Prohibited use for suspicious activities

---

## 📞 Getting Help

### Issue Reporting
- GitHub Issues: [Report Issue](https://github.com/MswTester/yongsan-sexmaster/issues)

### Learning Resources
- [Frida Official Documentation](https://frida.re/docs/)
- [Electron Official Documentation](https://www.electronjs.org/docs)
- [React Official Documentation](https://react.dev/)

---

## 📜 License

This project can only be used for educational purposes.

**⚠️ Before using this template, please check and comply with relevant laws in your region.**