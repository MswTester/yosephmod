import { app, BrowserWindow, ipcMain, globalShortcut } from 'electron';
import * as path from 'path';
import { FridaScriptManager } from './frida-manager';
import frida from 'frida';

// Development mode detection
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

// Keep a global reference of the window object to prevent garbage collection
let mainWindow: BrowserWindow | null = null;

// Managers
let scriptManager: FridaScriptManager;

// Global keybindings storage
interface KeyBinding {
  key: string;
  agentName: string;
  functionName: string;
  args?: any[];
}

let globalKeybindings: KeyBinding[] = [];

/**
 * Create the main browser window
 */
function createWindow() {
  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: true,
      webSecurity: false,
      preload: path.join(__dirname, 'preload.js')
    },
    show: false,
    autoHideMenuBar: true,
  });

  // Load the index.html file
  const htmlPath = path.join(__dirname, '../renderer/index.html');
  mainWindow.loadFile(htmlPath);

  // Emitted when the window is ready to be shown
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// This method will be called when Electron has finished initialization
app.whenReady().then(async () => {
  // Initialize managers
  scriptManager = new FridaScriptManager();
  
  // Set up message handler
  scriptManager.onMessage = (scriptName: string, message: any, data?: Buffer) => {
    mainWindow?.webContents.send('frida-message', { 
      agent: scriptName, 
      message,
      data: data ? Array.from(data) : undefined
    });
  };
  
  // Register global shortcuts
  registerGlobalShortcuts();
  
  createWindow();

  // On macOS it's common to re-create a window when the dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Global shortcut management
function registerGlobalShortcuts() {
  // Clear existing shortcuts
  globalShortcut.unregisterAll();
  
  // Register keybindings
  for (const binding of globalKeybindings) {
    try {
      globalShortcut.register(binding.key, () => {
        callAgentFunction(binding.agentName, binding.functionName, binding.args || []);
      });
      console.log(`🔑 Registered global shortcut: ${binding.key} -> ${binding.agentName}.${binding.functionName}`);
    } catch (error) {
      console.error(`Failed to register shortcut ${binding.key}:`, error);
    }
  }
}

// Call RPC function in agent
async function callAgentFunction(agentName: string, functionName: string, args: any[] = []) {
  if (!scriptManager || !scriptManager.isScriptLoaded(agentName)) {
    console.error(`Agent ${agentName} is not loaded`);
    return { success: false, error: 'Agent not loaded' };
  }
  
  try {
    const loadedScript = scriptManager.getLoadedScript(agentName);
    if (!loadedScript) {
      return { success: false, error: 'Agent not found' };
    }
    
    // Call RPC function
    const result = await loadedScript.script.exports[functionName](...args);
    console.log(`📞 Called ${agentName}.${functionName}() -> ${JSON.stringify(result)}`);
    
    // Send result to renderer
    mainWindow?.webContents.send('agent-rpc-result', {
      agent: agentName,
      function: functionName,
      args,
      result
    });
    
    return { success: true, result };
  } catch (error) {
    const errorMsg = (error as Error).message;
    console.error(`Failed to call ${agentName}.${functionName}():`, errorMsg);
    
    mainWindow?.webContents.send('agent-rpc-error', {
      agent: agentName,
      function: functionName,
      args,
      error: errorMsg
    });
    
    return { success: false, error: errorMsg };
  }
}

// Quit when all windows are closed, except on macOS
app.on('window-all-closed', async () => {
  // Clean up loaded scripts before quitting
  if (scriptManager) {
    await scriptManager.unloadAllScripts();
  }
  
  // Unregister all global shortcuts
  globalShortcut.unregisterAll();
  
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Hot reload setup for development
if (isDev) {
  const chokidar = require('chokidar');
  
  // Watch for agent file changes in development
  const agentsDir = path.join(__dirname, '../agents');
  const agentWatcher = chokidar.watch(path.join(agentsDir, '*.js'), {
    ignored: /node_modules/,
    persistent: true,
    ignoreInitial: true
  });
  
  agentWatcher.on('change', async (filePath: string) => {
    const agentName = path.basename(filePath, '.js');
    console.log(`📝 Agent file changed: ${agentName}`);
    
    if (scriptManager && scriptManager.isScriptLoaded(agentName)) {
      try {
        const result = await scriptManager.refreshScript(agentName);
        if (result.success) {
          mainWindow?.webContents.send('agent-reloaded', agentName);
        } else {
          mainWindow?.webContents.send('agent-error', { agent: agentName, error: result.error });
        }
      } catch (error) {
        console.error(`Failed to reload agent ${agentName}:`, error);
        mainWindow?.webContents.send('agent-error', { agent: agentName, error: (error as Error).message });
      }
    }
  });
  
  // Enable hot reload for Electron
  try {
    require('electron-reload')(__dirname, {
      electron: path.join(__dirname, '../../node_modules/.bin/electron'),
      hardResetMethod: 'exit'
    });
  } catch (error) {
    console.log('electron-reload not available');
  }
}

// IPC handlers
ipcMain.handle('ping', () => 'pong');

ipcMain.handle('load-agent', async (_event, agentName: string, targetProcess?: string | number, options?: any) => {
  if (!scriptManager) {
    return { success: false, error: 'Script manager not initialized' };
  }
  
  if (!targetProcess) {
    return { success: false, error: 'Target process must be specified' };
  }
  
  return await scriptManager.loadScript(agentName, targetProcess, options);
});

ipcMain.handle('unload-agent', async (_event, agentName: string) => {
  if (!scriptManager) {
    return { success: false, error: 'Script manager not initialized' };
  }
  
  return await scriptManager.unloadScript(agentName);
});

ipcMain.handle('reload-agent', async (_event, agentName: string, targetProcess?: string | number, options?: any) => {
  if (!scriptManager) {
    return { success: false, error: 'Script manager not initialized' };
  }
  
  if (!targetProcess) {
    return { success: false, error: 'Target process must be specified' };
  }
  
  return await scriptManager.reloadScript(agentName, targetProcess, options);
});

ipcMain.handle('list-agents', async () => {
  if (!scriptManager) {
    return { success: false, error: 'Script manager not initialized' };
  }
  
  try {
    const availableScripts = await scriptManager.getAvailableScripts();
    
    const agents = availableScripts.map(script => ({
      name: script.name,
      loaded: scriptManager.isScriptLoaded(script.name),
      metadata: script.metadata,
      path: isDev ? `src/agents/${script.name}.ts` : 'embedded'
    }));
    
    return { success: true, agents };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('get-processes', async () => {
  try {
    // Try to get local processes first, fallback to USB device
    let processes: frida.Process[] = [];
    
    try {
      // Try local processes first
      const device = await frida.getLocalDevice();
      processes = await device.enumerateProcesses();
    } catch (localError) {
      console.log('Local processes not available, trying USB device...');
      
      try {
        const device = await frida.getUsbDevice();
        processes = await device.enumerateProcesses();
      } catch (usbError) {
        console.log('USB device not available, returning empty list');
        return { success: true, processes: [] };
      }
    }
    
    return { success: true, processes };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// Additional IPC handlers for advanced functionality
ipcMain.handle('spawn-process', async (_event, program: string, options?: any) => {
  try {
    const pid = await frida.spawn(program, options);
    return { success: true, pid };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('resume-process', async (_event, pid: number) => {
  try {
    await frida.resume(pid);
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('kill-process', async (_event, pid: number) => {
  try {
    await frida.kill(pid);
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

// RPC handlers
ipcMain.handle('call-agent-function', async (_event, agentName: string, functionName: string, ...args: any[]) => {
  return await callAgentFunction(agentName, functionName, args);
});

// Keybinding handlers
ipcMain.handle('set-keybinding', (_event, key: string, agentName: string, functionName: string, args?: any[]) => {
  try {
    // Remove existing binding with same key
    globalKeybindings = globalKeybindings.filter(binding => binding.key !== key);
    
    // Add new binding
    globalKeybindings.push({ key, agentName, functionName, args });
    
    // Re-register shortcuts
    registerGlobalShortcuts();
    
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('remove-keybinding', (_event, key: string) => {
  try {
    globalKeybindings = globalKeybindings.filter(binding => binding.key !== key);
    registerGlobalShortcuts();
    return { success: true };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('get-keybindings', () => {
  return { success: true, keybindings: globalKeybindings };
});

// Agent management helpers
ipcMain.handle('get-agent-functions', async (_event, agentName: string) => {
  if (!scriptManager || !scriptManager.isScriptLoaded(agentName)) {
    return { success: false, error: 'Agent not loaded' };
  }
  
  try {
    const loadedScript = scriptManager.getLoadedScript(agentName);
    if (!loadedScript) {
      return { success: false, error: 'Agent not found' };
    }
    
    // Get available exported functions
    const functions = Object.keys(loadedScript.script.exports || {});
    return { success: true, functions };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

