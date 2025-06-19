import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { ChangeEvent } from '../../main/state-manager';

export interface GlobalContextType {
  // State
  state: Map<string, any>;
  getState: (key: string) => any;
  setState: (key: string, value: any) => void;
  // Frida
  exec: (command: string) => void;
  emit: (channel: string, ...args: any[]) => void;
}

const GlobalContext = createContext<GlobalContextType | null>(null);

// Global window interface extension
declare global {
  interface Window {
    electronAPI: {
      send: (channel: string, ...args: any[]) => void;
      receive: (channel: string, func: (...args: any[]) => void) => void;
      off: (channel: string, func: (...args: any[]) => void) => void;
      invoke: (channel: string, ...args: any[]) => Promise<any>;
    };
  }
}

export const GlobalProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<Map<string, any>>(new Map());

  const changeHandle = (changeEvent: ChangeEvent) => {
    setState(map => {
      map.set(changeEvent.key, changeEvent.value);
      return map;
    });
  }

  useEffect(() => {
    window.electronAPI.receive('state-changed', changeHandle);
    window.electronAPI.invoke('state-get-all').then((state: Map<string, any>) => {
      setState(state);
    });

    return () => {
      window.electronAPI.off('state-changed', changeHandle);
    }
  }, [])

  const getState = useCallback((key: string) => {
    return state.get(key);
  }, [state]);

  const updateState = useCallback((key: string, value: any) => {
    window.electronAPI.send('state-set', key, value);
  }, []);

  const exec = useCallback((command: string) => {
    window.electronAPI.send('to', 'exec', command);
  }, []);

  const emit = useCallback((channel: string, ...args: any[]) => {
    window.electronAPI.send('to', channel, ...args);
  }, []);

  return (
    <GlobalContext.Provider value={{ state, getState, setState: updateState, exec, emit }}>
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
