import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { FridaManager } from './frida-manager';
import { ChangeEvent, StateManager } from './state-manager';
import { argv, cwd } from 'process';
import init_config from './config_initial';
import os from 'os';
import init from './main_logic';
import { sendRenderer } from './util';

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
  const storedBounds: Electron.Rectangle | null = (store as any).get('main-bounds') as unknown as Electron.Rectangle
  // Create the browser window
  mainWindow = new BrowserWindow({
    x: storedBounds ? storedBounds.x : undefined,
    y: storedBounds ? storedBounds.y : undefined,
    width: storedBounds ? storedBounds.width : 400,
    height: storedBounds ? storedBounds.height : 600,
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
    (store as any).set('main-bounds', currentBounds);
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

  argv.forEach(arg => {
    if(arg === '--clear-store') {
      store.clear();
    }
  })

  // Clean up unused store fields
  init_config.forEach(config => {
    if (!store.has(config.key) || !config.store) {
      store.delete(config.key);
    }
  })

  // Initialize managers
  stateManager = new StateManager();
  fridaManager = new FridaManager();
  await fridaManager.initialize();

  // Set up state change broadcasting
  stateManager.on('state-changed', (changeEvent: ChangeEvent, isStore: boolean) => {
    sendRenderer('state-changed', changeEvent);

    // Update state in all agents
    fridaManager.send('state-changed', changeEvent.key, changeEvent.value);

    // Store state
    if (isStore) {
      (store as any).set(changeEvent.key, changeEvent.value);
    }
  });

  // Receive state from all agents
  fridaManager.on('recv-state-set', (key: string, value: any) => {
    const isStore = init_config.find(config => config.key === key)?.store;
    stateManager.setState(key, value, isStore);
  });

  fridaManager.on('recv-log', (...args: any[]) => {
    console.log("[AGENT]", ...args);
    sendRenderer('log', ...args);
  });

  fridaManager.on('recv-state-get-all', () => {
    const state = stateManager.getAllStates();
    fridaManager.send('state-get-all', Object.fromEntries(state));
  });

  fridaManager.on('recv-init', () => fridaManager.send('init'));

  // renderer -> agent
  ipcMain.on('to', (_event, channel: string, ...args: any[]) => {
    fridaManager.send(channel, ...args);
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
  
  init(fridaManager, stateManager);

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
      const result = await fridaManager.loadScript(agentName, 'test');
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
  const fileName = os.platform() === 'win32' ? 'electron.bat' : 'electron';
  try {
    require('electron-reload')(__dirname, {
      electron: path.join(cwd(), `node_modules/.bin/${fileName}`),
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

ipcMain.on('state-set', (_event, key: string, value: any) => {
  const isStore = init_config.find(config => config.key === key)?.store;
  stateManager.setState(key, value, isStore);
})

ipcMain.handle('state-get-all', () => {
  return stateManager.getAllStates();
})