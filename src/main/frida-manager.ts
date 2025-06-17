import * as path from 'path';
import * as fs from 'fs-extra';
import frida from 'frida';
import { app } from 'electron';

interface ScriptInfo {
  name: string;
  source: string;
  metadata?: {
    version?: string;
    description?: string;
    author?: string;
    compiled?: boolean;
  };
}

interface LoadedScript {
  name: string;
  script: frida.Script;
  session: frida.Session;
  metadata?: ScriptInfo['metadata'];
}

export class FridaScriptManager {
  private loadedScripts = new Map<string, LoadedScript>();
  private isDev: boolean;
  private scriptsPath: string;
  private embeddedScripts = new Map<string, ScriptInfo>();

  constructor() {
    this.isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;
    this.scriptsPath = this.getScriptsPath();
    this.initializeEmbeddedScripts();
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

  private async initializeEmbeddedScripts(): Promise<void> {
    if (!this.isDev) {
      // In production, load embedded scripts from resources
      try {
        const manifestPath = path.join(this.scriptsPath, 'manifest.json');
        if (await fs.pathExists(manifestPath)) {
          const manifest = await fs.readJson(manifestPath);
          for (const scriptInfo of manifest.scripts) {
            const scriptPath = path.join(this.scriptsPath, scriptInfo.file);
            if (await fs.pathExists(scriptPath)) {
              const source = await fs.readFile(scriptPath, 'utf8');
              this.embeddedScripts.set(scriptInfo.name, {
                name: scriptInfo.name,
                source,
                metadata: scriptInfo.metadata
              });
            }
          }
        }
      } catch (error) {
        console.error('Failed to load embedded scripts:', error);
      }
    }
  }

  async getAvailableScripts(): Promise<ScriptInfo[]> {
    const scripts: ScriptInfo[] = [];

    if (this.isDev) {
      // Development mode: Read from file system
      try {
        if (await fs.pathExists(this.scriptsPath)) {
          const files = await fs.readdir(this.scriptsPath);
          const jsFiles = files.filter(file => file.endsWith('.js'));

          for (const file of jsFiles) {
            const scriptPath = path.join(this.scriptsPath, file);
            const source = await fs.readFile(scriptPath, 'utf8');
            const name = path.basename(file, '.js');
            
            // Try to extract metadata from comments
            const metadata = this.extractMetadata(source);
            
            scripts.push({
              name,
              source,
              metadata: {
                ...metadata,
                compiled: true
              }
            });
          }
        }
      } catch (error) {
        console.error('Failed to read scripts from filesystem:', error);
      }
    } else {
      // Production mode: Use embedded scripts
      scripts.push(...Array.from(this.embeddedScripts.values()));
    }

    return scripts;
  }

  private extractMetadata(source: string): ScriptInfo['metadata'] {
    const metadata: ScriptInfo['metadata'] = {};
    
    // Extract metadata from JSDoc-style comments
    const versionMatch = source.match(/@version\s+(.+)/);
    const descriptionMatch = source.match(/@description\s+(.+)/);
    const authorMatch = source.match(/@author\s+(.+)/);
    
    if (versionMatch) metadata.version = versionMatch[1].trim();
    if (descriptionMatch) metadata.description = descriptionMatch[1].trim();
    if (authorMatch) metadata.author = authorMatch[1].trim();
    
    return metadata;
  }

  async loadScript(
    scriptName: string, 
    targetProcess: string | number,
    options?: {
      spawn?: boolean;
      resume?: boolean;
    }
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

      // Get script source
      const scriptInfo = await this.getScriptInfo(scriptName);
      if (!scriptInfo) {
        return { success: false, error: `Script '${scriptName}' not found` };
      }

      // Validate script source
      if (!scriptInfo.source || scriptInfo.source.trim().length === 0) {
        return { success: false, error: `Script '${scriptName}' is empty or invalid` };
      }

      // Create session with error handling
      let session: frida.Session;
      
      try {
        if (typeof targetProcess === 'string') {
          // Spawn or attach by name
          if (options?.spawn) {
            console.log(`Spawning process: ${targetProcess}`);
            const pid = await frida.spawn(targetProcess);
            session = await frida.attach(pid);
            if (options.resume) {
              await frida.resume(pid);
            }
          } else {
            console.log(`Attaching to process by name: ${targetProcess}`);
            session = await frida.attach(targetProcess);
          }
        } else {
          // Attach by PID
          console.log(`Attaching to process by PID: ${targetProcess}`);
          session = await frida.attach(targetProcess);
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
        script = await session.createScript(scriptInfo.source);
        
        // Set up message handler
        script.message.connect((message: any, data: Buffer | null) => {
          this.handleScriptMessage(scriptName, message, data || undefined);
        });

        // Set up error handlers
        script.destroyed.connect(() => {
          console.log(`Script '${scriptName}' was destroyed`);
          this.loadedScripts.delete(scriptName);
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
      this.loadedScripts.set(scriptName, {
        name: scriptName,
        script,
        session,
        metadata: scriptInfo.metadata
      });

      console.log(`✅ Script '${scriptName}' loaded successfully`);
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
      await loadedScript.script.unload();
      await loadedScript.session.detach();
      
      this.loadedScripts.delete(scriptName);
      
      console.log(`✅ Script '${scriptName}' unloaded successfully`);
      return { success: true };

    } catch (error) {
      console.error(`Failed to unload script '${scriptName}':`, error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }

  async reloadScript(
    scriptName: string, 
    targetProcess?: string | number,
    options?: { spawn?: boolean; resume?: boolean }
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const loadedScript = this.loadedScripts.get(scriptName);
      let target = targetProcess;
      let loadOptions = options;

      // If script is already loaded and no new target specified, use existing target
      if (loadedScript && !target) {
        // Try to get PID from existing session
        try {
          // First unload the existing script
          await this.unloadScript(scriptName);
          
          // We need to re-specify the target for reload
          return { 
            success: false, 
            error: 'Target process must be specified for reload' 
          };
        } catch (error) {
          console.error('Error during script reload preparation:', error);
        }
      }

      if (!target) {
        return { 
          success: false, 
          error: 'Target process must be specified' 
        };
      }

      // Reload the script
      return await this.loadScript(scriptName, target, loadOptions);

    } catch (error) {
      console.error(`Failed to reload script '${scriptName}':`, error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }

  private async getScriptInfo(scriptName: string): Promise<ScriptInfo | null> {
    if (this.isDev) {
      // Development mode: Read from file system
      try {
        const scriptPath = path.join(this.scriptsPath, `${scriptName}.js`);
        if (await fs.pathExists(scriptPath)) {
          const source = await fs.readFile(scriptPath, 'utf8');
          const metadata = this.extractMetadata(source);
          return {
            name: scriptName,
            source,
            metadata: {
              ...metadata,
              compiled: true
            }
          };
        }
      } catch (error) {
        console.error(`Failed to read script '${scriptName}':`, error);
      }
    } else {
      // Production mode: Use embedded scripts
      return this.embeddedScripts.get(scriptName) || null;
    }

    return null;
  }

  private handleScriptMessage(scriptName: string, message: any, data?: Buffer): void {
    console.log(`[${scriptName}]`, message);
    
    // Emit to renderer process if needed
    // This will be handled by the main process that uses this manager
    this.onMessage?.(scriptName, message, data);
  }

  // Event handler for script messages
  public onMessage?: (scriptName: string, message: any, data?: Buffer) => void;

  getLoadedScripts(): Array<{ name: string; metadata?: ScriptInfo['metadata'] }> {
    return Array.from(this.loadedScripts.values()).map(script => ({
      name: script.name,
      metadata: script.metadata
    }));
  }

  isScriptLoaded(scriptName: string): boolean {
    return this.loadedScripts.has(scriptName);
  }

  getLoadedScript(scriptName: string): LoadedScript | undefined {
    return this.loadedScripts.get(scriptName);
  }

  async unloadAllScripts(): Promise<void> {
    const scriptNames = Array.from(this.loadedScripts.keys());
    for (const scriptName of scriptNames) {
      try {
        await this.unloadScript(scriptName);
      } catch (error) {
        console.error(`Failed to unload script '${scriptName}':`, error);
      }
    }
  }

  // Hot reload support for development
  async refreshScript(scriptName: string): Promise<{ success: boolean; error?: string }> {
    if (!this.isDev) {
      return { success: false, error: 'Hot reload only available in development mode' };
    }

    const loadedScript = this.loadedScripts.get(scriptName);
    if (!loadedScript) {
      return { success: false, error: `Script '${scriptName}' is not loaded` };
    }

    try {
      // Read updated script from filesystem
      const scriptPath = path.join(this.scriptsPath, `${scriptName}.js`);
      if (!await fs.pathExists(scriptPath)) {
        return { success: false, error: `Script file '${scriptName}.js' not found` };
      }

      const newSource = await fs.readFile(scriptPath, 'utf8');
      
      // Create new script with updated source
      const newScript = await loadedScript.session.createScript(newSource);
      
      // Set up message handler
      newScript.message.connect((message: any, data: Buffer | null) => {
        this.handleScriptMessage(scriptName, message, data || undefined);
      });

      // Unload old script and load new one
      await loadedScript.script.unload();
      await newScript.load();

      // Update stored script
      this.loadedScripts.set(scriptName, {
        ...loadedScript,
        script: newScript
      });

      console.log(`🔄 Script '${scriptName}' hot reloaded successfully`);
      return { success: true };

    } catch (error) {
      console.error(`Failed to hot reload script '${scriptName}':`, error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : String(error) 
      };
    }
  }
}