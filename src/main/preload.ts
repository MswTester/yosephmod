import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  send: (channel: string, ...args: any[]) => {
    ipcRenderer.send(channel, ...args);
  },
  receive: (channel: string, func: (...args: any[]) => void) => {
    ipcRenderer.on(channel, (_event, ...args) => func(...args));
  },
  off: (channel: string, func: (...args: any[]) => void) => {
    ipcRenderer.off(channel, func);
  },
  invoke: (channel: string, ...args: any[]) => {
    return ipcRenderer.invoke(channel, ...args);
  },
});
