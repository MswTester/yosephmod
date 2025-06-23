import React, { useState, useEffect, useRef } from 'react';
import { useGlobal } from '../contexts/globalContext';
import {
  Container,
  Row,
  Col,
  Button,
  Input,
  Text,
  Separator,
} from './ui/primitive';

interface LogEntry {
  id: string;
  timestamp: Date;
  message: string;
}

const Console: React.FC = () => {
  const { state, exec, getState } = useGlobal();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [command, setCommand] = useState('');
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        setLogs([]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const scrollToBottom = () => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  useEffect(() => {
    const logHandle = (...args: any[]) => {
      console.log("[RENDERER]", ...args);
      setLogs((prevLogs) => [...prevLogs, { id: Date.now().toString(), timestamp: new Date(), message: args.join(' ') }]);
    };
    
    window.electronAPI.receive('log', logHandle)

    return () => {
      window.electronAPI.off('log', logHandle);
    }
  }, [])

  return (
    <Col h='100%'>
      <Container ref={scrollContainerRef} p=".4rem" gap='.1rem' overflow='auto' h='100%'>
        {logs.map((log) => (
          <Text key={log.id} size="sm" family="mono">
            <span style={{ opacity: 0.6 }}>
              [{log.timestamp.toLocaleTimeString()}]
            </span>{' '}
            {log.message}
          </Text>
        ))}
      </Container>
      <Separator />
      <Row gap='.4rem' p=".4rem" justify='center' items='center' w='100%'>
        <Input 
          family="mono"
          placeholder="Command" 
          value={command} 
          onChange={(e) => setCommand(e.target.value)} 
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey && command.trim() && getState('session')) {
              e.preventDefault();
              exec(command);
              setCommand('');
            }
          }}
          disabled={!getState('session')} 
        />
        <Button onClick={() => { exec(command); setCommand(''); }} disabled={!getState('session')}>Send</Button>
      </Row>
    </Col>
  );
};

export default Console;