import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';
import { FridaScriptManager } from './frida-manager';
// import frida from 'frida';

// Development mode detection
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

// Keep a global reference of the window object to prevent garbage collection
let mainWindow: BrowserWindow | null = null;

// Managers
let scriptManager: FridaScriptManager;

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
  scriptManager.on('frida-message', (scriptName: string, message: any, data?: Buffer) => {
    mainWindow?.webContents.send('frida-message', { 
      agent: scriptName, 
      message,
      data: data ? Array.from(data) : undefined
    });
  });

  createWindow();

  // On macOS it's common to re-create a window when the dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

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
    console.log(`Called ${agentName}.${functionName}() -> ${JSON.stringify(result)}`);
    
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

ipcMain.handle('call-agent-function', async (_event, agentName: string, functionName: string, ...args: any[]) => {
  return await callAgentFunction(agentName, functionName, args);
});