import * as path from 'path';
import * as fs from 'fs-extra';
import { app } from 'electron';
import EventEmitter from 'events';

// Types
type ScriptName = string;
type ProcessIdentifier = string | number;

interface FridaScript {
  unload: () => Promise<void>;
  post: (message: any[]) => void;
  message: {
    connect: (callback: (message: any, data: Buffer | null) => void) => void;
  };
  destroyed: {
    connect: (callback: () => void) => void;
  };
  isDestroyed: boolean;
}

type FridaDeviceType = "local" | "remote" | "usb";

interface FridaDevice {
  id: string;
  type: FridaDeviceType;
  spawn: (args: string[]) => Promise<number>;
  attach: (pid: number, options: any) => Promise<any>;
  resume: (pid: number) => Promise<void>;
  getProcess: (name: string) => Promise<{ pid: number }>;
}

interface FridaManagerOptions {
  isDev?: boolean;
  scriptsPath?: string;
}

export class FridaManager extends EventEmitter {
  private frida: any;
  private loadedScripts: Map<ScriptName, FridaScript> = new Map();
  private availableScripts: Map<ScriptName, string> = new Map();
  public device: FridaDevice | null = null;
  public devices: FridaDevice[] = [];
  private isDev: boolean;
  private scriptsPath: string;

  constructor(options: FridaManagerOptions = {}) {
    super();
    this.isDev = options.isDev ?? (process.env.NODE_ENV === 'development' || !app.isPackaged);
    this.scriptsPath = options.scriptsPath ?? this.getDefaultScriptsPath();
  }

  /**
   * Initialize Frida manager
   * @throws {Error} If Frida initialization fails
   */
  public async initialize(): Promise<void> {
    try {
      // Dynamic import to avoid issues with Frida in renderer
      this.frida = (await new Function("return import('frida')")()).default;
      await this.loadAvailableScripts();
      await this.initializeDevices();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to initialize Frida: ${errorMessage}`);
    }
  }

  /**
   * Send a message to the Frida script
   * @param channel - Channel name
   * @param args - Arguments to send
   */
  public send(channel: string, ...args: any[]): void {
    this.emit('to', channel, ...args);
  }

  public async selectDeviceById(id: string): Promise<void> {
    this.device = await new this.frida.DeviceManager().findDeviceById(id, 5000)
    this.emit('recv-state-set', 'device', this.device?.id);
    this.emit('device-changed');
  }

  public async selectDeviceByType(type: FridaDeviceType): Promise<void> {
    this.device = await new this.frida.DeviceManager().findDeviceByType(type, 5000)
    this.emit('recv-state-set', 'device', this.device?.id);
    this.emit('device-changed');
  }

  /**
   * Initialize available Frida devices
   * @private
   */
  private async initializeDevices(): Promise<void> {
    try {
      const deviceManager = new this.frida.DeviceManager();
      this.devices = await deviceManager.enumerateDevices();
      if (this.devices.length > 0) {
        this.device = this.devices[0]; // Use first available device by default
        this.emit('recv-state-set', 'device', this.device?.id);
      }
      deviceManager.added.connect((device: FridaDevice) => {
        this.devices.push(device);
      })
      deviceManager.removed.connect((device: FridaDevice) => {
        this.devices.splice(this.devices.findIndex(d => d.id === device.id), 1);
      })
    } catch (error) {
      throw new Error(`Failed to initialize devices: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get the default scripts path based on environment
   * @private
   */
  private getDefaultScriptsPath(): string {
    return this.isDev
      ? path.join(__dirname, '../agents')  // Development: Use dist/agents directory
      : path.join(process.resourcesPath || path.join(process.cwd(), 'resources'), 'scripts'); // Production: Use resources/scripts
  }

  /**
   * Load available scripts from the scripts directory
   * @private
   */
  private async loadAvailableScripts(): Promise<void> {
    try {
      await fs.ensureDir(this.scriptsPath);
      const files = await fs.readdir(this.scriptsPath);
      const jsFiles = files.filter(file => file.endsWith('.js') && !file.includes('module.js'));
      
      await Promise.all(jsFiles.map(async (file) => {
        try {
          const scriptPath = path.join(this.scriptsPath, file);
          const source = await fs.readFile(scriptPath, 'utf8');
          const scriptName = path.basename(file, '.js');
          this.availableScripts.set(scriptName, source);
        } catch (error) {
          console.warn(`Failed to load script ${file}:`, error);
        }
      }));
    } catch (error) {
      throw new Error(`Failed to load scripts from ${this.scriptsPath}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get list of available script names
   */
  public async getAvailableScripts(): Promise<string[]> {
    if (this.availableScripts.size === 0) {
      await this.loadAvailableScripts();
    }
    return Array.from(this.availableScripts.keys());
  }

  /**
   * Check if a script is currently loaded
   * @param scriptName - Name of the script to check
   */
  public isScriptLoaded(scriptName: string): boolean {
    return this.loadedScripts.has(scriptName);
  }

  /**
   * Load and execute a Frida script
   * @param scriptName - Name of the script to load
   * @param targetProcess - Process name or PID to attach to
   * @param action - Whether to 'spawn' or 'attach' to the process
   * @param emulated - Whether to use emulated environment
   * @returns Object with success status and optional error message
   */
  public async loadScript(
    scriptName: string, 
    targetProcess: ProcessIdentifier,
    emulated: boolean = false,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Validate script name
      if (!scriptName || typeof scriptName !== 'string') {
        return { success: false, error: 'Invalid script name' };
      }

      // Validate target process
      if (!targetProcess || (typeof targetProcess !== 'string' && typeof targetProcess !== 'number')) {
        return { success: false, error: 'Invalid target process' };
      }

      // Check if script is already loaded
      if (this.loadedScripts.has(scriptName)) {
        await this.unloadScript(scriptName);
      }

      // Validate script source
      if (!this.availableScripts.has(scriptName)) {
        return { success: false, error: `Script '${scriptName}' is empty or invalid` };
      }

      if(!this.device) {
        return { success: false, error: 'Device not connected' };
      }

      // Create session with error handling
      let session: any;
      let pid: number;
      const attachOption = {realm: emulated ? "emulated" : "native" as any};
      
      try {
        if (typeof targetProcess === 'string') {
          // Spawn or attach by name
          console.log(`Spawning process: ${targetProcess}`);
          pid = await this.device.spawn([targetProcess]);
          if(!emulated) {
            session = await this.device.attach(pid, attachOption);
            this.emit('recv-state-set', 'session', pid);
          }
        } else {
          // Attach by PID
          console.log(`Attaching to process by PID: ${targetProcess}`);
          pid = targetProcess;
          if(!emulated) {
            session = await this.device.attach(pid, attachOption);
            this.emit('recv-state-set', 'session', pid);
          }
        }
      } catch (attachError) {
        return { 
          success: false, 
          error: `Failed to attach to process '${targetProcess}': ${(attachError as Error).message}` 
        };
      }
      if(emulated) {
        await this.device.resume(pid);
        session = await this.device.attach(pid, attachOption);
        this.emit('recv-state-set', 'session', pid);
      }

      // Create and load script with error handling
      let script: any;
      
      try {
        script = await session.createScript(this.availableScripts.get(scriptName)!);
        
        // Set up message handler
        script.message.connect((message: any, data: Buffer | null) => {
          let payload = [...message.payload]
          const channel = payload.shift();
          const args = payload;
          this.emit(`recv-${channel}`, ...args);
        });

        // clean up when device is changed
        const cleanUpSession = () => {
          this.unloadScript(scriptName);
          session.detach();
        }
        this.once('device-changed', cleanUpSession)

        // renderer -> agent
        const scriptHandler = (channel: string, ...args: any[]) => {
          script.post([channel, ...args])
        }
        this.on('to', scriptHandler)

        // Set up error handlers
        script.destroyed.connect(() => {
          this.emit('recv-state-set', 'session', null);
          this.off('to', scriptHandler)
          this.off('device-changed', cleanUpSession)
          this.loadedScripts.delete(scriptName);
          console.log(`[*] Script '${scriptName}' was destroyed`);
        });

        await script.load();
      } catch (scriptError) {
        // Clean up session if script creation/loading failed
        try {
          await session.detach();
        } catch (detachError) {
          console.error('Failed to detach session after script error:', detachError);
        }
        
        return { 
          success: false, 
          error: `Failed to create/load script '${scriptName}': ${(scriptError as Error).message}` 
        };
      }

      if(!emulated) {
        await this.device.resume(pid)
      }

      // Store loaded script
      this.loadedScripts.set(scriptName, script);

      // Session detached cleanup
      session.detached.connect(() => {
        this.emit('recv-state-set', 'session', null);
        this.unloadAllScripts();
        this.removeAllListeners('to')
      })

      console.log(`[*] Script '${scriptName}' loaded successfully`);
      return { success: true };

    } catch (error) {
      console.error(`Failed to load script '${scriptName}':`, error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }

  /**
   * Unload a loaded script
   * @param scriptName - Name of the script to unload
   */
  public async unloadScript(scriptName: string): Promise<{ success: boolean; error?: string }> {
    try {
      const script = this.loadedScripts.get(scriptName);
      if (!script) {
        return { success: false, error: `Script '${scriptName}' is not loaded` };
      }

      this.loadedScripts.delete(scriptName);
      
      // Unload script and detach session
      if(!script.isDestroyed) {
        await script.unload();
      }

      console.log(`[*] Script '${scriptName}' unloaded successfully`);
      return { success: true };
    } catch (error) {
      console.error(`Failed to unload script '${scriptName}':`, error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }

  /**
   * Unload all currently loaded scripts
   */
  public async unloadAllScripts(): Promise<{ success: boolean; error?: string }> {
    try {
      for (const scriptName of this.loadedScripts.keys()) {
        await this.unloadScript(scriptName);
      }
      console.log(`[*] All scripts unloaded successfully`);
      return { success: true };
    } catch (error) {
      console.error(`Failed to unload all scripts:`, error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }

  /**
   * Clean up resources
   */
  public async destroy(): Promise<void> {
    await this.unloadAllScripts();
    this.removeAllListeners();
  }
}