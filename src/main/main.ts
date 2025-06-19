import { app, BrowserWindow, ipcMain } from 'electron';
import * as path from 'path';
import { FridaManager } from './frida-manager';
import { ChangeEvent, StateManager } from './state-manager';
import ElectronStore from 'electron-store';
// import frida from 'frida';

// Development mode detection
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

// Keep a global reference of the window object to prevent garbage collection
let mainWindow: BrowserWindow | null = null;

// Managers
let fridaManager: FridaManager;
let stateManager: StateManager;

// Configuration
const store = new ElectronStore();

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
  stateManager = new StateManager();
  fridaManager = new FridaManager();

  // Set up state change broadcasting
  stateManager.on('state-changed', (changeEvent: ChangeEvent) => {
    // Update state in all windows
    const allWindows = BrowserWindow.getAllWindows();
    allWindows.forEach(window => {
      if (!window.isDestroyed()) {
        window.webContents.send('state-changed', changeEvent);
      }
    });

    // Update state in all agents
    fridaManager.emit('state-changed', changeEvent);
  });

  // Receive state from all agents
  fridaManager.on('recv-state-changed', (changeEvent: ChangeEvent) => {
    stateManager.setState(changeEvent.key, changeEvent.value);
  });

  fridaManager.on('recv-state-get-all', () => {
    let state = stateManager.getAllStates();
    fridaManager.emit('state-get-all', state);
  });

  createWindow();

  // On macOS it's common to re-create a window when the dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS
app.on('window-all-closed', async () => {
  // Clean up loaded scripts before quitting
  if (fridaManager) {
    fridaManager.unloadAllScripts();
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
    
    try {
      const result = await fridaManager.loadScript(agentName, 'test', 'attach');
      if (result.success) {
        console.log(`[*] Agent ${agentName} loaded successfully`);
      } else {
        console.error(`[*] Failed to load agent ${agentName}:`, result.error);
      }
    } catch (error) {
      console.error(`[*] Failed to reload agent ${agentName}:`, error);
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

ipcMain.handle('state-get', (_event, key: string) => {
  return stateManager.getState(key);
})

ipcMain.handle('state-set', (_event, key: string, value: any) => {
  stateManager.setState(key, value);
})

ipcMain.handle('state-get-all', () => {
  return stateManager.getAllStates();
})