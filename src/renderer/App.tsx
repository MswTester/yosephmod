import React from 'react';
import { useAgent } from './contexts/AgentContext';
import './App.css';

const App: React.FC = () => {
  const { 
    globalState, 
    isConnected, 
    setSelectedProcess, 
    setSystemStatus 
  } = useAgent();

  const handleSelectProcess = async () => {
    try {
      await setSelectedProcess({ pid: 1234, name: 'test-process' });
    } catch (error) {
      console.error('Failed to select process:', error);
    }
  };

  const handleSetStatus = async () => {
    try {
      await setSystemStatus('New status from React!');
    } catch (error) {
      console.error('Failed to set status:', error);
    }
  };

  return (
    <div className="app">
      <div className="header">
        <h1>Enhanced Frida Agent Manager</h1>
        <div className="connection-status">
          Connection: {isConnected ? '✅ Connected' : '❌ Disconnected'}
        </div>
      </div>

      <div className="global-info">
        <div className="system-status">
          <h3>System Status</h3>
          <p>{globalState.systemStatus}</p>
          <button onClick={handleSetStatus}>Update Status</button>
        </div>

        <div className="selected-process">
          <h3>Selected Process</h3>
          <p>
            {globalState.selectedProcess 
              ? `${globalState.selectedProcess.name} (PID: ${globalState.selectedProcess.pid})`
              : 'None selected'
            }
          </p>
          <button onClick={handleSelectProcess}>Select Test Process</button>
        </div>

        <div className="message-count">
          <h3>Frida Messages</h3>
          <div className="recent-messages">
            {globalState.fridaMessages.slice(-5).map((msg, index) => (
              <div key={index} className="message">
                <strong>[{msg.agent}]</strong> {JSON.stringify(msg.message)}
              </div>
            ))}
          </div>
        </div>
      </div>
      
      <div className="usage-info">
        <h2>How to Use</h2>
        <ul>
          <li>Use <code>useAgent()</code> hook to access global state and functions</li>
          <li>Use <code>useAgentState(agentName)</code> for specific agent state</li>
          <li>Use <code>useAgentStateWithUpdates(agentName)</code> for real-time updates</li>
          <li>Use <code>useAgentDataWithUpdates(agentName, key)</code> for specific data updates</li>
          <li>All state changes are automatically synchronized across components</li>
        </ul>
      </div>
    </div>
  );
};

export default App;