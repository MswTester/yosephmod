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
      'call-agent-function',
    ];
    if (validChannels.includes(channel)) {
      return ipcRenderer.invoke(channel, ...args);
    }
    return Promise.reject(new Error(`Invalid channel: ${channel}`));
  },
  
  // Frida-specific events
  onFridaMessage: (channel:string, callback: (data: any) => void) => {
    ipcRenderer.on(`frida-${channel}`, (_event, data) => callback(data));
  },

  sendFridaMessage: (channel:string, data: any) => {
    ipcRenderer.send(`frida-${channel}`, data);
  },
});
