import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { ChangeEvent } from '../../main/state-manager';

export interface GlobalContextType {
  // State
  globalState: Map<string, any>;
  getState: (key: string) => any;
  setState: (key: string, value: any) => void;
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
  const [globalState, setGlobalState] = useState<Map<string, any>>(new Map());

  const changeHandle = (changeEvent: ChangeEvent) => {
    setGlobalState(map => {
      map.set(changeEvent.key, changeEvent.value);
      return map;
    });
  }

  useEffect(() => {
    window.electronAPI.receive('state-changed', changeHandle);
    window.electronAPI.invoke('state-get-all')

    return () => {
      window.electronAPI.off('state-changed', changeHandle);
    }
  }, [])

  const getState = useCallback((key: string) => {
    return globalState.get(key);
  }, [globalState]);

  const setState = useCallback((key: string, value: any) => {
    window.electronAPI.send('state-set', key, value);
  }, []);

  return (
    <GlobalContext.Provider value={{ globalState, getState, setState }}>
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
