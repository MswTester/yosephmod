import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { ChangeEvent } from '../../main/state-manager';

export interface GlobalContextType {
  // State
  state: Map<string, any>;
  keymap: Map<string, boolean>;
  getState: (key: string) => any;
  setState: (key: string, value: any) => void;
  useOn: (channel: string, callback: (...args: any[]) => void) => void;
  emit: (channel: string, ...args: any[]) => void;
  // Frida
  exec: (command: string) => void;
  send: (channel: string, ...args: any[]) => void;
}

const GlobalContext = createContext<GlobalContextType | null>(null);

// Global window interface extension
declare global {
  interface Window {
    electronAPI: {
      isDev: boolean;
      send: (channel: string, ...args: any[]) => void;
      receive: (channel: string, func: (...args: any[]) => void) => void;
      off: (channel: string, func: (...args: any[]) => void) => void;
      invoke: (channel: string, ...args: any[]) => Promise<any>;
    };
  }
}

export const GlobalProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<Map<string, any>>(new Map());
  const [keymap, setKeymap] = useState<Map<string, boolean>>(new Map());

  const changeHandle = (changeEvent: ChangeEvent) => {
    setState(prevState => {
      const newState = new Map(prevState);
      newState.set(changeEvent.key, changeEvent.value);
      return newState;
    });
  }
  
  const keyHandle = (key: string, down: boolean) => {
    setKeymap(prevKeymap => {
      const newKeymap = new Map(prevKeymap);
      newKeymap.set(key, down);
      return newKeymap;
    });
  }

  useEffect(() => {
    window.electronAPI.receive('state-changed', changeHandle);
    window.electronAPI.receive('key-event', keyHandle);
    window.electronAPI.invoke('state-get-all').then((state: Map<string, any>) => {
      setState(state);
    });
    return () => {
      window.electronAPI.off('state-changed', changeHandle);
      window.electronAPI.off('key-event', keyHandle);
    }
  }, [])

  const getState = useCallback((key: string) => {
    return state.get(key);
  }, [state]);

  const updateState = useCallback((key: string, value: any) => {
    window.electronAPI.send('state-set', key, value);
  }, []);

  const emit = useCallback((channel: string, ...args: any[]) => {
    window.electronAPI.send(channel, ...args);
  }, []);

  const exec = useCallback((command: string) => {
    window.electronAPI.send('to', 'exec', command);
  }, []);

  const send = useCallback((channel: string, ...args: any[]) => {
    window.electronAPI.send('to', channel, ...args);
  }, []);

  const useOn = useCallback((channel: string, callback: (...args: any[]) => void) => {
    window.electronAPI.receive(channel, callback);
    return () => {
      window.electronAPI.off(channel, callback);
    }
  }, []);

  return (
    <GlobalContext.Provider value={{ state, keymap, getState, setState: updateState, emit, exec, send, useOn }}>
      {children}
    </GlobalContext.Provider>
  );
};

// Custom hook to use the Agent context
export const useGlobal = (): GlobalContextType => {
  const context = useContext(GlobalContext);
  if (!context) {
    throw new Error('useGlobal must be used within a GlobalProvider');
  }
  return context;
};
