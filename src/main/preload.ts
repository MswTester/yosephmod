import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  send: (channel: string, data: any) => {
    // Whitelist channels
    const validChannels = ['toMain'];
    if (validChannels.includes(channel)) {
      ipcRenderer.send(channel, data);
    }
  },
  receive: (channel: string, func: (...args: any[]) => void) => {
    const validChannels = ['fromMain'];
    if (validChannels.includes(channel)) {
      // Deliberately strip event as it includes `sender`
      ipcRenderer.on(channel, (_event, ...args) => func(...args));
    }
  },
  invoke: (channel: string, ...args: any[]) => {
    const validChannels = [
      'ping',
      'load-agent',
      'unload-agent',
      'reload-agent',
      'list-agents',
      'get-processes',
      'spawn-process',
      'resume-process',
      'kill-process',
      'call-agent-function',
      'set-keybinding',
      'remove-keybinding',
      'get-keybindings',
      'get-agent-functions'
    ];
    if (validChannels.includes(channel)) {
      return ipcRenderer.invoke(channel, ...args);
    }
    return Promise.reject(new Error(`Invalid channel: ${channel}`));
  },
  
  // Frida-specific events
  onFridaMessage: (callback: (data: any) => void) => {
    ipcRenderer.on('frida-message', (_event, data) => callback(data));
  },
  
  onAgentReloaded: (callback: (agentName: string) => void) => {
    ipcRenderer.on('agent-reloaded', (_event, agentName) => callback(agentName));
  },
  
  onAgentError: (callback: (data: any) => void) => {
    ipcRenderer.on('agent-error', (_event, data) => callback(data));
  },
  
  // RPC result events
  onAgentRpcResult: (callback: (data: any) => void) => {
    ipcRenderer.on('agent-rpc-result', (_event, data) => callback(data));
  },
  
  onAgentRpcError: (callback: (data: any) => void) => {
    ipcRenderer.on('agent-rpc-error', (_event, data) => callback(data));
  }
});
