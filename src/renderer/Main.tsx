// Example Codes - 기본 치트 기능들의 예제 코드
import React, { useState, useEffect } from 'react';
import { useGlobal } from './contexts/globalContext';
import {
    Container,
    Row,
    Col,
    Button,
    Input,
    Text,
    Heading,
    Switch,
    Slider
} from './components/ui/primitive';

const Main = () => {
    const { getState, setState, send, exec } = useGlobal();
    
    // 예제 상태들
    const [targetValue, setTargetValue] = useState<string>('1000');
    const [autoModeEnabled, setAutoModeEnabled] = useState<boolean>(false);
    const [speedMultiplier, setSpeedMultiplier] = useState<number>(1);
    const [customCommand, setCustomCommand] = useState<string>('');
    
    // 상태 동기화
    useEffect(() => {
        setAutoModeEnabled(getState('auto-mode') || false);
        setSpeedMultiplier(getState('speed-multiplier') || 1);
    }, [getState]);

    // 예제 1: 기본 값 변경 기능
    const handleChangeHealth = () => {
        const value = parseInt(targetValue);
        if (isNaN(value)) {
            alert('올바른 숫자를 입력하세요');
            return;
        }
        send('change-health', value);
    };

    const handleChangeGold = () => {
        const value = parseInt(targetValue);
        if (isNaN(value)) {
            alert('올바른 숫자를 입력하세요');
            return;
        }
        send('change-gold', value);
    };

    // 예제 2: 자동 모드 토글
    const toggleAutoMode = () => {
        const newState = !autoModeEnabled;
        setAutoModeEnabled(newState);
        setState('auto-mode', newState);
        send('toggle-auto-mode', newState);
    };

    // 예제 3: 속도 배율 변경
    const handleSpeedChange = (value: number) => {
        setSpeedMultiplier(value);
        setState('speed-multiplier', value);
        send('set-speed-multiplier', value);
    };

    // 예제 4: 메모리 스캔 기능
    const scanMemory = () => {
        const value = parseInt(targetValue);
        if (isNaN(value)) {
            alert('스캔할 값을 입력하세요');
            return;
        }
        send('scan-memory', value);
    };

    // 예제 5: 사용자 정의 코드 실행
    const executeCustomCommand = () => {
        if (!customCommand.trim()) {
            alert('실행할 코드를 입력하세요');
            return;
        }
        exec(customCommand);
    };

    // 예제 6: 프리셋 기능들
    const presetActions = [
        { name: '무적 모드', action: () => send('toggle-godmode') },
        { name: '무한 탄약', action: () => send('toggle-infinite-ammo') },
        { name: '벽 통과', action: () => send('toggle-noclip') },
        { name: '순간이동', action: () => send('teleport-to-player') },
    ];

    return (
        <Container h="100%" p="1rem" gap="1rem" overflowY="auto">
            {/* 메인 제목 */}
            <Heading size="lg" align="center">치트 컨트롤 패널</Heading>
            
            {/* 기본 값 변경 섹션 */}
            <Col gap="0.5rem" p="1rem" radius="8px" border="1px solid var(--border-color)">
                <Heading size="md">기본 값 변경</Heading>
                <Row gap="0.5rem" items="center">
                    <Text w="60px">값:</Text>
                    <Input 
                        value={targetValue}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTargetValue(e.target.value)}
                        placeholder="숫자 입력"
                        mw="100px"
                    />
                </Row>
                <Row gap="0.5rem">
                    <Button onClick={handleChangeHealth} variant="default" size="sm">
                        체력 변경
                    </Button>
                    <Button onClick={handleChangeGold} variant="outline" size="sm">
                        골드 변경
                    </Button>
                    <Button onClick={scanMemory} variant="outline" size="sm">
                        메모리 스캔
                    </Button>
                </Row>
            </Col>

            {/* 자동 모드 섹션 */}
            <Col gap="0.5rem" p="1rem" radius="8px" border="1px solid var(--border-color)">
                <Heading size="md">자동 모드</Heading>
                <Row justify="space-between" items="center">
                    <Text>자동 모드 활성화</Text>
                    <Switch 
                        checked={autoModeEnabled}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                            const newState = e.target.checked;
                            setAutoModeEnabled(newState);
                            setState('auto-mode', newState);
                            send('toggle-auto-mode', newState);
                        }}
                    />
                </Row>
            </Col>

            {/* 속도 조절 섹션 */}
            <Col gap="0.5rem" p="1rem" radius="8px" border="1px solid var(--border-color)">
                <Heading size="md">속도 조절</Heading>
                <Row justify="space-between" items="center">
                    <Text>속도 배율:</Text>
                    <Text weight="medium">{speedMultiplier}x</Text>
                </Row>
                <Slider
                    min={0.1}
                    max={5}
                    step={0.1}
                    value={speedMultiplier}
                    onChange={handleSpeedChange}
                />
            </Col>

            {/* 프리셋 기능들 */}
            <Col gap="0.5rem" p="1rem" radius="8px" border="1px solid var(--border-color)">
                <Heading size="md">빠른 기능</Heading>
                <Row gap="0.5rem" justify="space-between">
                    {presetActions.map((preset, index) => (
                        <Button 
                            key={index}
                            onClick={preset.action}
                            variant="outline"
                            size="sm"
                            w="100%"
                        >
                            {preset.name}
                        </Button>
                    ))}
                </Row>
            </Col>

            {/* 사용자 정의 코드 실행 */}
            <Col gap="0.5rem" p="1rem" radius="8px" border="1px solid var(--border-color)">
                <Heading size="md">사용자 정의 코드</Heading>
                <Input
                    value={customCommand}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setCustomCommand(e.target.value)}
                    placeholder="예: log('Hello World')"
                    mw="100%"
                />
                <Button onClick={executeCustomCommand} variant="default" size="sm" w="100%">
                    코드 실행
                </Button>
            </Col>

            {/* 상태 정보 표시 */}
            <Col gap="0.3rem" p="1rem" radius="8px" border="1px solid var(--border-color)">
                <Heading size="md">현재 상태</Heading>
                <Text size="sm">🔗 디바이스: {getState('device') || '연결되지 않음'}</Text>
                <Text size="sm">📱 세션: {getState('session') ? '연결됨' : '연결되지 않음'}</Text>
                <Text size="sm">🤖 자동 모드: {autoModeEnabled ? '활성화' : '비활성화'}</Text>
                <Text size="sm">⚡ 속도 배율: {speedMultiplier}x</Text>
            </Col>
        </Container>
    );
};

export default Main;