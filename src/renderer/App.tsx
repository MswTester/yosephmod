import React, { useState, useEffect } from 'react';
import './App.css';

declare global {
  interface Window {
    electronAPI: {
      send: (channel: string, data: any) => void;
      receive: (channel: string, func: (...args: any[]) => void) => void;
      invoke: (channel: string, ...args: any[]) => Promise<any>;
    };
  }
}

const App: React.FC = () => {
  const [status, setStatus] = useState<string>('애플리케이션이 시작되었습니다.');
  const [pingResult, setPingResult] = useState<string>('');

  useEffect(() => {
    // Example of receiving messages from main process
    if (window.electronAPI) {
      window.electronAPI.receive('fromMain', (data: string) => {
        console.log(`Received ${data} from main process`);
        setStatus(`메인 프로세스로부터: ${data}`);
      });
    }
  }, []);

  const handlePing = async () => {
    try {
      if (window.electronAPI) {
        const result = await window.electronAPI.invoke('ping');
        setPingResult(`Ping 결과: ${result}`);
      } else {
        setPingResult('Electron API에 접근할 수 없습니다.');
      }
    } catch (error) {
      console.error('Ping failed:', error);
      setPingResult('Ping 실패');
    }
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>Yongsan SexMaster</h1>
      </header>
      <main className="app-main">
        <div className="status">
          <p>{status}</p>
          <button onClick={handlePing}>Ping 메인 프로세스</button>
          {pingResult && <p>{pingResult}</p>}
        </div>
      </main>
    </div>
  );
};

export default App;
