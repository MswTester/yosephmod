// Type definitions for the Electron API exposed in the renderer process
declare namespace NodeJS {
  interface Global {
    electronAPI: {
      send: (channel: string, data: any) => void;
      receive: (channel: string, func: (...args: any[]) => void) => void;
      invoke: (channel: string, ...args: any[]) => Promise<any>;
    };
  }
}

// Make the electronAPI available in the renderer process
declare const electronAPI: {
  send: (channel: string, data: any) => void;
  receive: (channel: string, func: (...args: any[]) => void) => void;
  invoke: (channel: string, ...args: any[]) => Promise<any>;
};

// Add type definitions for the window object
declare interface Window {
  electronAPI: {
    send: (channel: string, data: any) => void;
    receive: (channel: string, func: (...args: any[]) => void) => void;
    invoke: (channel: string, ...args: any[]) => Promise<any>;
  };
}
