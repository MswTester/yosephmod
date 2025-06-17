import React, { useState, useEffect } from 'react';
import './App.css';

declare global {
  interface Window {
    electronAPI: {
      send: (channel: string, data: any) => void;
      receive: (channel: string, func: (...args: any[]) => void) => void;
      invoke: (channel: string, ...args: any[]) => Promise<any>;
      onFridaMessage: (callback: (data: any) => void) => void;
      onAgentReloaded: (callback: (agentName: string) => void) => void;
      onAgentError: (callback: (data: any) => void) => void;
      onAgentRpcResult: (callback: (data: any) => void) => void;
      onAgentRpcError: (callback: (data: any) => void) => void;
    };
  }
}

interface Agent {
  name: string;
  loaded: boolean;
  path: string;
}

interface Process {
  pid: number;
  name: string;
}

interface KeyBinding {
  key: string;
  agentName: string;
  functionName: string;
  args?: any[];
}

interface CheatStatus {
  enabled: boolean;
  health: number;
  coins: number;
  speedMultiplier: number;
}

type AppState = 'main' | 'cheats' | 'keybindings';

const App: React.FC = () => {
  const [appState, setAppState] = useState<AppState>('main');
  const [agents, setAgents] = useState<Agent[]>([]);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [selectedProcess, setSelectedProcess] = useState<Process | null>(null);
  const [fridaMessages, setFridaMessages] = useState<string[]>([]);
  const [status, setStatus] = useState<string>('Frida Script Manager 준비됨');
  const [keybindings, setKeybindings] = useState<KeyBinding[]>([]);
  const [cheatStatus, setCheatStatus] = useState<CheatStatus>({
    enabled: false,
    health: 100,
    coins: 1000,
    speedMultiplier: 1.0
  });
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [agentFunctions, setAgentFunctions] = useState<string[]>([]);

  useEffect(() => {
    if (window.electronAPI) {
      // Setup Frida event listeners
      window.electronAPI.onFridaMessage((data) => {
        const message = `[${data.agent}] ${JSON.stringify(data.message)}`;
        setFridaMessages(prev => [...prev.slice(-19), message]);
      });

      window.electronAPI.onAgentReloaded((agentName) => {
        setStatus(`에이전트 리로드됨: ${agentName}`);
        loadAgents();
      });

      window.electronAPI.onAgentError((data) => {
        setStatus(`에이전트 오류 [${data.agent}]: ${data.error}`);
      });
      
      window.electronAPI.onAgentRpcResult((data) => {
        setStatus(`RPC 성공 [${data.agent}.${data.function}]: ${JSON.stringify(data.result)}`);
        if (data.agent === 'cheat-agent' && data.function === 'getCheatStatus') {
          setCheatStatus(data.result);
        }
      });
      
      window.electronAPI.onAgentRpcError((data) => {
        setStatus(`RPC 오류 [${data.agent}.${data.function}]: ${data.error}`);
      });
      
      // Load initial data
      loadAgents();
      loadProcesses();
      loadKeybindings();
    }
  }, []);

  const loadProcesses = async () => {
    try {
      const result = await window.electronAPI.invoke('get-processes');
      if (result.success && result.processes) {
        setProcesses(result.processes);
        setStatus('프로세스 목록을 로드했습니다.');
      } else {
        setStatus('프로세스 목록 로드 실패');
      }
    } catch (error) {
      console.error('Process loading failed:', error);
      setStatus('프로세스 로드 중 오류 발생');
    }
  };
  
  const loadAgents = async () => {
    try {
      const result = await window.electronAPI.invoke('list-agents');
      if (result.success) {
        setAgents(result.agents);
      }
    } catch (error) {
      console.error('Failed to load agents:', error);
    }
  };
  
  const handleLoadAgent = async (agentName: string) => {
    if (!selectedProcess) {
      setStatus('먼저 프로세스를 선택해주세요.');
      return;
    }
    
    try {
      const target = selectedProcess.pid;
      const result = await window.electronAPI.invoke('load-agent', agentName, target);
      if (result.success) {
        setStatus(`에이전트 로드됨: ${agentName}`);
        loadAgents();
      } else {
        setStatus(`에이전트 로드 실패: ${result.error}`);
      }
    } catch (error) {
      setStatus(`에이전트 로드 실패: ${error}`);
    }
  };


  const handleUnloadAgent = async (agentName: string) => {
    try {
      const result = await window.electronAPI.invoke('unload-agent', agentName);
      if (result.success) {
        setStatus(`에이전트 언로드됨: ${agentName}`);
        loadAgents();
      } else {
        setStatus(`에이전트 언로드 실패: ${result.error}`);
      }
    } catch (error) {
      setStatus(`에이전트 언로드 실패: ${error}`);
    }
  };
  
  const loadKeybindings = async () => {
    try {
      const result = await window.electronAPI.invoke('get-keybindings');
      if (result.success) {
        setKeybindings(result.keybindings);
      }
    } catch (error) {
      console.error('Failed to load keybindings:', error);
    }
  };
  
  const callAgentFunction = async (agentName: string, functionName: string, ...args: any[]) => {
    try {
      const result = await window.electronAPI.invoke('call-agent-function', agentName, functionName, ...args);
      if (result.success) {
        setStatus(`${agentName}.${functionName}() 호출 성공`);
      } else {
        setStatus(`${agentName}.${functionName}() 호출 실패: ${result.error}`);
      }
      return result;
    } catch (error) {
      setStatus(`${agentName}.${functionName}() 호출 실패: ${error}`);
      return { success: false, error };
    }
  };
  
  const loadAgentFunctions = async (agentName: string) => {
    try {
      const result = await window.electronAPI.invoke('get-agent-functions', agentName);
      if (result.success) {
        setAgentFunctions(result.functions);
      }
    } catch (error) {
      console.error('Failed to load agent functions:', error);
    }
  };
  
  const addKeybinding = async (key: string, agentName: string, functionName: string, args?: any[]) => {
    try {
      const result = await window.electronAPI.invoke('set-keybinding', key, agentName, functionName, args);
      if (result.success) {
        setStatus(`키바인딩 추가됨: ${key} -> ${agentName}.${functionName}`);
        loadKeybindings();
      } else {
        setStatus(`키바인딩 추가 실패: ${result.error}`);
      }
    } catch (error) {
      setStatus(`키바인딩 추가 실패: ${error}`);
    }
  };
  
  const removeKeybinding = async (key: string) => {
    try {
      const result = await window.electronAPI.invoke('remove-keybinding', key);
      if (result.success) {
        setStatus(`키바인딩 제거됨: ${key}`);
        loadKeybindings();
      } else {
        setStatus(`키바인딩 제거 실패: ${result.error}`);
      }
    } catch (error) {
      setStatus(`키바인딩 제거 실패: ${error}`);
    }
  };

  const renderMainScreen = () => (
    <div className="main-screen">
      <div className="header">
        <h2>Frida Script Manager</h2>
        <div className="nav-buttons">
          <button onClick={() => setAppState('cheats')} className="nav-btn">치트</button>
          <button onClick={() => setAppState('keybindings')} className="nav-btn">키바인딩</button>
          <button onClick={loadProcesses} className="refresh-btn">프로세스 새로 고침</button>
        </div>
      </div>
      
      <div className="content">
        <div className="processes-section">
          <h3>실행중인 프로세스</h3>
          <div className="process-list">
            {processes.map((process) => (
              <div 
                key={process.pid} 
                className={`process-item ${selectedProcess?.pid === process.pid ? 'selected' : ''}`}
                onClick={() => setSelectedProcess(process)}
              >
                <div className="process-name">{process.name}</div>
                <div className="process-pid">PID: {process.pid}</div>
              </div>
            ))}
          </div>
        </div>
        
        <div className="agents-section">
          <h3>사용 가능한 스크립트</h3>
          <div className="agents-list">
            {agents.map((agent) => (
              <div key={agent.name} className="agent-item">
                <span className={`agent-name ${agent.loaded ? 'loaded' : ''}`}>
                  {agent.name} {agent.loaded ? '(실행중)' : '(대기중)'}
                </span>
                <div className="agent-controls">
                  <button 
                    onClick={() => handleLoadAgent(agent.name)} 
                    disabled={!selectedProcess || agent.loaded}
                  >
                    로드
                  </button>
                  <button 
                    onClick={() => handleUnloadAgent(agent.name)}
                    disabled={!agent.loaded}
                  >
                    언로드
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      
      <div className="messages-section">
        <h3>Frida 메시지</h3>
        <div className="messages-console">
          {fridaMessages.map((message, index) => (
            <div key={index} className="message-item">
              {message}
            </div>
          ))}
        </div>
      </div>
      
      <div className="status-bar">
        <div className="status-message">{status}</div>
        {selectedProcess && (
          <div className="selected-info">
            선택된 프로세스: {selectedProcess.name} (PID: {selectedProcess.pid})
          </div>
        )}
      </div>
    </div>
  );
  
  const renderCheatScreen = () => (
    <div className="cheat-screen">
      <div className="header">
        <h2>치트 컨트롤</h2>
        <div className="nav-buttons">
          <button onClick={() => setAppState('main')} className="nav-btn">메인</button>
          <button onClick={() => setAppState('keybindings')} className="nav-btn">키바인딩</button>
        </div>
      </div>
      
      <div className="cheat-controls">
        <div className="cheat-status">
          <h3>치트 상태</h3>
          <div className={`status-indicator ${cheatStatus.enabled ? 'enabled' : 'disabled'}`}>
            {cheatStatus.enabled ? '활성화' : '비활성화'}
          </div>
          <button 
            onClick={() => callAgentFunction('cheat-agent', 'toggleCheats')}
            className="toggle-btn"
          >
            치트 토글
          </button>
        </div>
        
        <div className="cheat-values">
          <div className="value-control">
            <label>체력:</label>
            <input 
              type="number" 
              value={cheatStatus.health} 
              onChange={(e) => setCheatStatus(prev => ({ ...prev, health: parseInt(e.target.value) || 0 }))}
            />
            <button onClick={() => callAgentFunction('cheat-agent', 'setHealth', cheatStatus.health)}>
              설정
            </button>
          </div>
          
          <div className="value-control">
            <label>코인:</label>
            <input 
              type="number" 
              value={cheatStatus.coins} 
              onChange={(e) => setCheatStatus(prev => ({ ...prev, coins: parseInt(e.target.value) || 0 }))}
            />
            <button onClick={() => callAgentFunction('cheat-agent', 'setCoins', cheatStatus.coins)}>
              설정
            </button>
          </div>
          
          <div className="value-control">
            <label>속도 배수:</label>
            <input 
              type="number" 
              step="0.1"
              value={cheatStatus.speedMultiplier} 
              onChange={(e) => setCheatStatus(prev => ({ ...prev, speedMultiplier: parseFloat(e.target.value) || 1.0 }))}
            />
            <button onClick={() => callAgentFunction('cheat-agent', 'setSpeedMultiplier', cheatStatus.speedMultiplier)}>
              설정
            </button>
          </div>
        </div>
        
        <div className="cheat-actions">
          <button onClick={() => callAgentFunction('cheat-agent', 'getCheatStatus')}>
            상태 새로고침
          </button>
          <button onClick={() => callAgentFunction('cheat-agent', 'scanMemoryForValue', 100, 'i32')}>
            메모리 스캔 (값: 100)
          </button>
        </div>
      </div>
      
      <div className="status-bar">
        <div className="status-message">{status}</div>
      </div>
    </div>
  );
  
  const renderKeybindingScreen = () => (
    <div className="keybinding-screen">
      <div className="header">
        <h2>키바인딩 설정</h2>
        <div className="nav-buttons">
          <button onClick={() => setAppState('main')} className="nav-btn">메인</button>
          <button onClick={() => setAppState('cheats')} className="nav-btn">치트</button>
        </div>
      </div>
      
      <div className="keybinding-controls">
        <div className="add-keybinding">
          <h3>새 키바인딩 추가</h3>
          <div className="keybinding-form">
            <select 
              value={selectedAgent} 
              onChange={(e) => {
                setSelectedAgent(e.target.value);
                if (e.target.value) loadAgentFunctions(e.target.value);
              }}
            >
              <option value="">에이전트 선택</option>
              {agents.filter(a => a.loaded).map(agent => (
                <option key={agent.name} value={agent.name}>{agent.name}</option>
              ))}
            </select>
            
            <select id="function-select">
              <option value="">함수 선택</option>
              {agentFunctions.map(func => (
                <option key={func} value={func}>{func}</option>
              ))}
            </select>
            
            <input 
              type="text" 
              placeholder="키조합 (예: Ctrl+F1)"
              id="key-input"
            />
            
            <button onClick={() => {
              const keyInput = document.getElementById('key-input') as HTMLInputElement;
              const functionSelect = document.getElementById('function-select') as HTMLSelectElement;
              
              if (keyInput.value && selectedAgent && functionSelect.value) {
                addKeybinding(keyInput.value, selectedAgent, functionSelect.value);
                keyInput.value = '';
                functionSelect.value = '';
              }
            }}>
              추가
            </button>
          </div>
        </div>
        
        <div className="keybinding-list">
          <h3>현재 키바인딩</h3>
          {keybindings.map((binding, index) => (
            <div key={index} className="keybinding-item">
              <span className="key">{binding.key}</span>
              <span className="arrow">→</span>
              <span className="function">{binding.agentName}.{binding.functionName}</span>
              <button 
                onClick={() => removeKeybinding(binding.key)}
                className="remove-btn"
              >
                제거
              </button>
            </div>
          ))}
        </div>
      </div>
      
      <div className="status-bar">
        <div className="status-message">{status}</div>
      </div>
    </div>
  );
  
  const renderCurrentScreen = () => {
    switch (appState) {
      case 'main':
        return renderMainScreen();
      case 'cheats':
        return renderCheatScreen();
      case 'keybindings':
        return renderKeybindingScreen();
      default:
        return renderMainScreen();
    }
  };
  
  return (
    <div className="app">
      {renderCurrentScreen()}
    </div>
  );
};

export default App;
