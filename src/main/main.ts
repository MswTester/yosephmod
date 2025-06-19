import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { FridaManager } from './frida-manager';
import { ChangeEvent, StateManager } from './state-manager';
import { cwd } from 'process';
import init_config from './config_initial';
// import frida from 'frida';

// Development mode detection
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

// Keep a global reference of the window object to prevent garbage collection
let mainWindow: BrowserWindow | null = null;

// Managers
let fridaManager: FridaManager;
let stateManager: StateManager;

// Configuration
let store: any;

/**
 * Create the main browser window
 */
function createWindow() {
  const storedBounds: Electron.Rectangle | null = (store as any).get('mainBounds') as unknown as Electron.Rectangle
  // Create the browser window
  mainWindow = new BrowserWindow({
    x: storedBounds ? storedBounds.x : undefined,
    y: storedBounds ? storedBounds.y : undefined,
    width: storedBounds ? storedBounds.width : 1200,
    height: storedBounds ? storedBounds.height : 800,
    icon: path.join(cwd(), 'build/icon.png'),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: true,
      webSecurity: true,
      devTools: isDev,
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

  // Restore window bounds before window closed
  mainWindow.on('close', () => {
    const currentBounds = mainWindow?.getBounds();
    (store as any).set('mainBounds', currentBounds);
  })

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// This method will be called when Electron has finished initialization
app.whenReady().then(async () => {
  // Initialize electron-store using dynamic import
  try {
    const electronStoreModule = await eval('import("electron-store")');
    const ElectronStore = electronStoreModule.default;
    store = new ElectronStore();
  } catch (error) {
    console.error('Failed to import electron-store:', error);
    return;
  }

  // Initialize managers
  stateManager = new StateManager();
  fridaManager = new FridaManager();

  // Set up state change broadcasting
  stateManager.on('state-changed', (changeEvent: ChangeEvent, isStore: boolean) => {
    // Update state in all windows
    const allWindows = BrowserWindow.getAllWindows();
    allWindows.forEach(window => {
      if (!window.isDestroyed()) {
        window.webContents.send('state-changed', changeEvent);
      }
    });

    // Update state in all agents
    fridaManager.to('state-changed', changeEvent.key, changeEvent.value);

    // Store state
    if (isStore) {
      (store as any).set(changeEvent.key, changeEvent.value);
    }
  });

  // Receive state from all agents
  fridaManager.on('recv-state-changed', (changeEvent: ChangeEvent, isStore: boolean) => {
    stateManager.setState(changeEvent.key, changeEvent.value, isStore);
  });

  fridaManager.on('recv-state-get-all', () => {
    let state = stateManager.getAllStates();
    fridaManager.to('state-get-all', state);
  });

  // renderer -> agent
  ipcMain.on('to', (_event, channel: string, ...args: any[]) => {
    fridaManager.to(channel, ...args);
  })

  // Setup initial state
  init_config.forEach(config => {
    if(config.store){
      const val = store.get(config.key) || config.default;
      stateManager.setState(config.key, val, true);
    } else {
      stateManager.setState(config.key, config.default);
    }
  })

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
    console.log(`[*] Agent file changed: ${agentName}`);
    
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
      electron: path.join(cwd(), 'node_modules/.bin/electron'),
      hardResetMethod: 'exit'
    });
  } catch (error) {
    console.log('electron-reload not available');
  }
}

// IPC handlers (renderer -> process)
ipcMain.handle('ping', () => 'pong');

ipcMain.handle('state-get', (_event, key: string) => {
  return stateManager.getState(key);
})

ipcMain.handle('state-set', (_event, key: string, value: any, store: boolean) => {
  stateManager.setState(key, value, store);
})

ipcMain.handle('state-get-all', () => {
  return stateManager.getAllStates();
})