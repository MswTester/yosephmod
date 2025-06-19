import * as path from 'path';
import * as fs from 'fs-extra';
import frida from 'frida';
import { app } from 'electron';
import EventEmitter from 'events';
import { ChangeEvent, StateManager } from './state-manager';


export class FridaManager extends EventEmitter {
  private loadedScripts = new Map<string, frida.Script>();
  private isDev: boolean;
  private scriptsPath: string;
  private availableScripts = new Map<string, string>();

  constructor() {
    super();
    this.isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
    this.scriptsPath = this.getScriptsPath();
    this.initializeScripts();
  }

  private getScriptsPath(): string {
    if (this.isDev) {
      // Development: Use dist/agents directory
      return path.join(__dirname, '../agents');
    } else {
      // Production: Use resources/scripts directory
      const resourcesPath = process.resourcesPath || path.join(process.cwd(), 'resources');
      return path.join(resourcesPath, 'scripts');
    }
  }

  private async initializeScripts(): Promise<void> {
    if (this.isDev) {
      // In development, load scripts from file system
      try {
        const files = await fs.readdir(this.scriptsPath);
        const jsFiles = files.filter(file => file.endsWith('.js') && !file.includes('module.js'));
        for (const file of jsFiles) {
          const scriptPath = path.join(this.scriptsPath, file);
          const source = await fs.readFile(scriptPath, 'utf8');
          const scriptName = file.replace(/\.js$/, '');
          this.availableScripts.set(scriptName, source);
        }
      } catch (error) {
        console.error('Failed to load scripts from filesystem:', error);
      }
    } else {
      // In production, load embedded scripts from resources
      try {
        const files = await fs.readdir(this.scriptsPath);
        const jsFiles = files.filter(file => file.endsWith('.js') && !file.includes('module.js'));
        for (const file of jsFiles) {
          const scriptPath = path.join(this.scriptsPath, file);
          const source = await fs.readFile(scriptPath, 'utf8');
          const scriptName = file.replace(/\.js$/, '');
          this.availableScripts.set(scriptName, source);
        }
      } catch (error) {
        console.error('Failed to load embedded scripts:', error);
      }
    }
  }

  async getAvailableScripts(): Promise<string[]> {
    const scripts: string[] = [];

    if (this.isDev) {
      // Development mode: Read from file system
      try {
        if (await fs.pathExists(this.scriptsPath)) {
          const files = await fs.readdir(this.scriptsPath);
          const jsFiles = files.filter(file => file.endsWith('.js') && !file.includes('module.js'));

          for (const file of jsFiles) {
            const name = path.basename(file, '.js');
            scripts.push(name);
          }
        }
      } catch (error) {
        console.error('Failed to read scripts from filesystem:', error);
      }
    } else {
      // Production mode: Use embedded scripts
      scripts.push(...Array.from(this.availableScripts.keys()));
    }

    return scripts;
  }

  async loadScript(
    scriptName: string, 
    targetProcess: string | number,
    action: "spawn" | "attach",
    emulated?: boolean,
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

      // Create session with error handling
      let session: frida.Session;
      
      try {
        const attachOption = {realm: emulated ? "emulated" : "native" as any};
        if (typeof targetProcess === 'string') {
          // Spawn or attach by name
          if (action === "spawn") {
            console.log(`Spawning process: ${targetProcess}`);
            const pid = await frida.spawn([targetProcess]);
            session = await frida.attach(pid, attachOption);
          } else {
            console.log(`Attaching to process by name: ${targetProcess}`);
            session = await frida.attach(targetProcess, attachOption);
          }
        } else {
          // Attach by PID
          console.log(`Attaching to process by PID: ${targetProcess}`);
          session = await frida.attach(targetProcess, attachOption);
        }
      } catch (attachError) {
        return { 
          success: false, 
          error: `Failed to attach to process '${targetProcess}': ${(attachError as Error).message}` 
        };
      }

      // Create and load script with error handling
      let script: frida.Script;
      
      try {
        script = await session.createScript(this.availableScripts.get(scriptName)!);
        
        // Set up message handler
        script.message.connect((message: any, data: Buffer | null) => {
          const channel = message[0];
          const args = message.slice(1, message.length);
          this.emit(`recv-${channel}`, ...args, data);
        });

        // Set up error handlers
        script.destroyed.connect(() => {
          console.log(`Script '${scriptName}' was destroyed`);
          this.loadedScripts.delete(scriptName);
        });

        // Set state sync
        this.on('state-changed', (changeEvent: ChangeEvent) => {
          script.post(['state-changed', changeEvent]);
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

      // Store loaded script
      this.loadedScripts.set(scriptName, script);

      // Session detached cleanup
      session.detached.connect(() => {
        this.emit('session-detached', { 
          agent: scriptName 
        });
        this.unloadAllScripts();
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

  async unloadScript(scriptName: string): Promise<{ success: boolean; error?: string }> {
    try {
      const loadedScript = this.loadedScripts.get(scriptName);
      if (!loadedScript) {
        return { success: false, error: `Script '${scriptName}' is not loaded` };
      }

      // Unload script and detach session
      await loadedScript.unload();
      
      this.loadedScripts.delete(scriptName);

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

  async unloadAllScripts(): Promise<{ success: boolean; error?: string }> {
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
}