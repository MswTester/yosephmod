// Type definitions for the Electron API exposed in the renderer process
declare namespace NodeJS {
  interface Global {
    electronAPI: {
      isDev: boolean,
      send: (channel: string, ...args: any[]) => void;
      receive: (channel: string, func: (...args: any[]) => void) => void;
      off: (channel: string, func: (...args: any[]) => void) => void;
      invoke: (channel: string, ...args: any[]) => Promise<any>;
    };
  }
}

// Make the electronAPI available in the renderer process
declare const electronAPI: {
  isDev: boolean,
  send: (channel: string, ...args: any[]) => void;
  receive: (channel: string, func: (...args: any[]) => void) => void;
  off: (channel: string, func: (...args: any[]) => void) => void;
  invoke: (channel: string, ...args: any[]) => Promise<any>;
};

// Add type definitions for the window object
declare interface Window {
  electronAPI: {
    isDev: boolean,
    send: (channel: string, ...args: any[]) => void;
    receive: (channel: string, func: (...args: any[]) => void) => void;
    off: (channel: string, func: (...args: any[]) => void) => void;
    invoke: (channel: string, ...args: any[]) => Promise<any>;
  };
}
