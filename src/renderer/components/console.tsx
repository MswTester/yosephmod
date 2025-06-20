import React, { useState, useEffect, useRef } from 'react';
import { useGlobal } from '../contexts/globalContext';

interface LogEntry {
  id: string;
  timestamp: Date;
  message: string;
}

const Console: React.FC = () => {
  const { exec, send } = useGlobal();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [command, setCommand] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Add log entry
  const addLog = (message: string) => {
    const newLog: LogEntry = {
      id: Date.now().toString(),
      timestamp: new Date(),
      message,
    };
    setLogs(prev => [...prev, newLog]);
  };

  // Execute Frida command
  const handleExecuteCommand = () => {
    if (!command.trim()) return;
    
    addLog(`> ${command}`);
    exec(command);
    setCommand('');
  };

  // Clear logs
  const handleClearLogs = () => {
    setLogs([]);
  };

  // Export logs
  const handleExportLogs = () => {
    const logData = logs.map(log => ({
      timestamp: log.timestamp.toISOString(),
      message: log.message,
    }));
    
    const blob = new Blob([JSON.stringify(logData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `frida-logs-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Filter logs
  const filteredLogs = logs.filter(log => {
    const searchMatch = !searchTerm || 
      log.message.toLowerCase().includes(searchTerm.toLowerCase());
    return searchMatch;
  });

  // Auto scroll to bottom
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        handleClearLogs();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Simulate receiving logs from Frida (you would replace this with actual IPC)
  useEffect(() => {
    // Example: Listen for Frida output
    // window.electronAPI?.receive('frida-output', (data) => {
    //   addLog('info', data.message, 'frida');
    // });
    
    // Demo logs for testing
    const demoInterval = setInterval(() => {
      if (Math.random() > 0.7) {
        const levels: LogEntry['level'][] = ['info', 'warning', 'error', 'debug'];
        const level = levels[Math.floor(Math.random() * levels.length)];
        const messages = [
          'Frida script loaded successfully',
          'Hooking function at 0x12345678',
          'Memory allocation detected',
          'Function call intercepted',
          'Script execution completed'
        ];
        const message = messages[Math.floor(Math.random() * messages.length)];
        addLog(message);
      }
    }, 3000);

    return () => clearInterval(demoInterval);
  }, []);

  return (
    <Container padding="16px" height="100vh">
      <Column gap="16px" style={{ height: '100%' }}>
        {/* Header */}
        <Row justify="space-between" align="center">
          <Text size="lg" weight="semibold">Frida Console</Text>
          <Row gap="8px">
            <Button 
              variant="outline" 
              size="sm" 
              onClick={handleExportLogs}
              disabled={logs.length === 0}
            >
              Export
            </Button>
            <Button 
              variant="secondary" 
              size="sm" 
              onClick={handleClearLogs}
              disabled={logs.length === 0}
            >
              Clear
            </Button>
          </Row>
        </Row>

        {/* Controls */}
        <Accordion title="Console Settings" rounded="md" outline>
          <Column gap="12px">
            <Row gap="16px" align="center" wrap>
              <Row gap="8px" align="center">
                <Text size="sm">Auto-scroll:</Text>
                <Toggle 
                  checked={autoScroll} 
                  onChange={setAutoScroll}
                  size="sm"
                />
              </Row>
              
              <Row gap="8px" align="center">
                <Text size="sm">Filter:</Text>
                <Select
                  options={logLevelOptions}
                  value={filterLevel}
                  onChange={setFilterLevel}
                  size="sm"
                />
              </Row>
              
              <Row gap="8px" align="center" style={{ flex: 1, minWidth: '200px' }}>
                <Text size="sm">Search:</Text>
                <Input
                  value={searchTerm}
                  onChange={setSearchTerm}
                  placeholder="Search logs..."
                  size="sm"
                />
              </Row>
            </Row>
          </Column>
        </Accordion>

        {/* Log Display */}
        <Container 
          bgcolor="var(--foreground-color)"
          rounded="md"
          outline
          style={{ 
            flex: 1, 
            overflow: 'hidden',
            fontFamily: 'monospace',
            fontSize: '13px'
          }}
        >
          <div
            ref={logContainerRef}
            style={{
              height: '100%',
              overflowY: 'auto',
              padding: '12px'
            }}
          >
            {filteredLogs.length === 0 ? (
              <Text size="sm" textcolor="var(--text-muted-color)" align="center">
                {logs.length === 0 ? 'No logs yet...' : 'No logs match current filter'}
              </Text>
            ) : (
              <Column gap="4px">
                {filteredLogs.map(log => (
                  <Row key={log.id} gap="8px" align="flex-start">
                    <Text 
                      size="xs" 
                      textcolor="var(--text-muted-color)"
                      style={{ minWidth: '60px' }}
                    >
                      {log.timestamp.toLocaleTimeString()}
                    </Text>
                    <Text 
                      size="xs" 
                      textcolor={getLogLevelColor(log.level)}
                      weight="medium"
                      style={{ minWidth: '60px', textTransform: 'uppercase' }}
                    >
                      {log.level}
                    </Text>
                    {log.source && (
                      <Text 
                        size="xs" 
                        textcolor="var(--text-muted-color)"
                        style={{ minWidth: '80px' }}
                      >
                        [{log.source}]
                      </Text>
                    )}
                    <Text 
                      size="sm" 
                      style={{ 
                        wordBreak: 'break-word',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                      {log.message}
                    </Text>
                  </Row>
                ))}
              </Column>
            )}
          </div>
        </Container>

        {/* Command Input */}
        <Row gap="8px">
          <Input
            value={command}
            onChange={setCommand}
            placeholder="Enter Frida JavaScript command..."
            style={{ flex: 1 }}
            onKeyDown={(e: React.KeyboardEvent) => {
              if (e.key === 'Enter') {
                handleExecuteCommand();
              }
            }}
          />
          <Button 
            onClick={handleExecuteCommand}
            disabled={!command.trim()}
          >
            Execute
          </Button>
        </Row>

        {/* Status */}
        <Row justify="space-between" align="center">
          <Text size="xs" textcolor="var(--text-muted-color)">
            {logs.length} total logs | {filteredLogs.length} filtered
          </Text>
          <Text size="xs" textcolor="var(--text-muted-color)">
            Ctrl+L to clear | Enter to execute
          </Text>
        </Row>
      </Column>
    </Container>
  );
};

export default Console;