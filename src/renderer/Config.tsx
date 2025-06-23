// Example Codes - 설정 화면 예제 코드
import React, { useState, useEffect } from 'react';
import { useGlobal } from './contexts/globalContext';
import { 
    Col, 
    CollapsibleIcon, 
    Container, 
    Heading, 
    Input, 
    Row, 
    Switch, 
    Text, 
    Button,
    Slider,
    Select
} from './components/ui/primitive';

const Section = (props: { title: string, children: React.ReactNode }) => {
    const [isOpen, setIsOpen] = useState(false);
    return <Col gap='.5rem'>
        <Row onClick={() => setIsOpen(!isOpen)} gap='.4rem' items='center' cursor='pointer'>
            <CollapsibleIcon isOpen={isOpen} />
            <Heading size="md">
                {props.title}
            </Heading>
        </Row>
        {isOpen && props.children}
    </Col>
}

const Config = () => {
    const { getState, setState, send } = useGlobal();
    
    // 예제 설정 상태들
    const [autoStart, setAutoStart] = useState<boolean>(false);
    const [autoSave, setAutoSave] = useState<boolean>(true);
    const [targetApp, setTargetApp] = useState<string>('');
    const [updateInterval, setUpdateInterval] = useState<number>(1000);
    const [maxRetries, setMaxRetries] = useState<number>(3);
    const [logLevel, setLogLevel] = useState<string>('info');
    const [theme, setTheme] = useState<string>('dark');
    const [language, setLanguage] = useState<string>('ko');
    const [hotkeys, setHotkeys] = useState({
        toggleCheat: 'F1',
        speedHack: 'F2',
        godMode: 'F3'
    });

    // 상태 동기화
    useEffect(() => {
        setAutoStart(getState('auto-start') || false);
        setAutoSave(getState('auto-save') || true);
        setTargetApp(getState('target-app') || '');
        setUpdateInterval(getState('update-interval') || 1000);
        setMaxRetries(getState('max-retries') || 3);
        setLogLevel(getState('log-level') || 'info');
        setTheme(getState('theme') || 'dark');
        setLanguage(getState('language') || 'ko');
        setHotkeys(getState('hotkeys') || {
            toggleCheat: 'F1',
            speedHack: 'F2',
            godMode: 'F3'
        });
    }, [getState]);

    // 설정 변경 핸들러들
    const handleAutoStartChange = (checked: boolean) => {
        setAutoStart(checked);
        setState('auto-start', checked);
    };

    const handleAutoSaveChange = (checked: boolean) => {
        setAutoSave(checked);
        setState('auto-save', checked);
    };

    const handleTargetAppChange = (value: string) => {
        setTargetApp(value);
        setState('target-app', value);
    };

    const handleUpdateIntervalChange = (value: number) => {
        setUpdateInterval(value);
        setState('update-interval', value);
    };

    const handleMaxRetriesChange = (value: number) => {
        setMaxRetries(value);
        setState('max-retries', value);
    };

    const handleLogLevelChange = (value: string) => {
        setLogLevel(value);
        setState('log-level', value);
    };

    const handleThemeChange = (value: string) => {
        setTheme(value);
        setState('theme', value);
    };

    const handleLanguageChange = (value: string) => {
        setLanguage(value);
        setState('language', value);
    };

    const handleHotkeyChange = (key: string, value: string) => {
        const newHotkeys = { ...hotkeys, [key]: value };
        setHotkeys(newHotkeys);
        setState('hotkeys', newHotkeys);
    };

    // 설정 초기화
    const resetSettings = () => {
        if (confirm('모든 설정을 초기화하시겠습니까?')) {
            setState('auto-start', false);
            setState('auto-save', true);
            setState('target-app', '');
            setState('update-interval', 1000);
            setState('max-retries', 3);
            setState('log-level', 'info');
            setState('theme', 'dark');
            setState('language', 'ko');
            setState('hotkeys', {
                toggleCheat: 'F1',
                speedHack: 'F2',
                godMode: 'F3'
            });
        }
    };

    // 설정 내보내기/가져오기
    const exportSettings = () => {
        const settings = {
            autoStart,
            autoSave,
            targetApp,
            updateInterval,
            maxRetries,
            logLevel,
            theme,
            language,
            hotkeys
        };
        const dataStr = JSON.stringify(settings, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'yssm-settings.json';
        link.click();
        URL.revokeObjectURL(url);
    };

    const importSettings = () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        input.onchange = (e: any) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e: any) => {
                    try {
                        const settings = JSON.parse(e.target.result);
                        Object.entries(settings).forEach(([key, value]) => {
                            setState(key, value);
                        });
                        alert('설정을 성공적으로 가져왔습니다!');
                    } catch (error) {
                        alert('설정 파일을 읽는 중 오류가 발생했습니다.');
                    }
                };
                reader.readAsText(file);
            }
        };
        input.click();
    };

    return (
        <Container h="100%" p='.5rem' gap='1rem'>
            <Heading size="lg" align="center">설정</Heading>
            
            {/* 일반 설정 */}
            <Section title="일반 설정">
                <Row justify='space-between' items='center'>
                    <Text w="70%" truncate>자동 시작</Text>
                    <Switch checked={autoStart} onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleAutoStartChange(e.target.checked)} />
                </Row>
                <Row justify='space-between' items='center'>
                    <Text w="70%" truncate>자동 저장</Text>
                    <Switch checked={autoSave} onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleAutoSaveChange(e.target.checked)} />
                </Row>
                <Col gap="0.5rem">
                    <Text>대상 앱 패키지명</Text>
                    <Input
                        value={targetApp}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleTargetAppChange(e.target.value)}
                        placeholder="com.example.app"
                        mw="100%"
                    />
                </Col>
            </Section>

            {/* 성능 설정 */}
            <Section title="성능 설정">
                <Col gap="0.5rem">
                    <Row justify="space-between" items="center">
                        <Text>업데이트 간격 (ms)</Text>
                        <Text>{updateInterval}ms</Text>
                    </Row>
                    <Slider
                        min={100}
                        max={5000}
                        step={100}
                        value={updateInterval}
                        onChange={handleUpdateIntervalChange}
                    />
                </Col>
                <Col gap="0.5rem">
                    <Row justify="space-between" items="center">
                        <Text>최대 재시도 횟수</Text>
                        <Text>{maxRetries}회</Text>
                    </Row>
                    <Slider
                        min={1}
                        max={10}
                        step={1}
                        value={maxRetries}
                        onChange={handleMaxRetriesChange}
                    />
                </Col>
            </Section>

            {/* 로깅 설정 */}
            <Section title="로깅 설정">
                <Row justify="space-between" items="center">
                    <Text>로그 레벨</Text>
                    <Select
                        mw="100px"
                        value={logLevel}
                        onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleLogLevelChange(e.target.value)}
                    >
                        <option value="debug">Debug</option>
                        <option value="info">Info</option>
                        <option value="warn">Warning</option>
                        <option value="error">Error</option>
                    </Select>
                </Row>
            </Section>

            {/* 인터페이스 설정 */}
            <Section title="인터페이스">
                <Row justify="space-between" items="center">
                    <Text>테마</Text>
                    <Select
                        mw="100px"
                        value={theme}
                        onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleThemeChange(e.target.value)}
                    >
                        <option value="light">라이트</option>
                        <option value="dark">다크</option>
                        <option value="auto">자동</option>
                    </Select>
                </Row>
                <Row justify="space-between" items="center">
                    <Text>언어</Text>
                    <Select
                        mw="100px"
                        value={language}
                        onChange={(e: React.ChangeEvent<HTMLSelectElement>) => handleLanguageChange(e.target.value)}
                    >
                        <option value="ko">한국어</option>
                        <option value="en">English</option>
                        <option value="ja">日本語</option>
                    </Select>
                </Row>
            </Section>

            {/* 단축키 설정 */}
            <Section title="단축키">
                <Col gap="0.5rem">
                    <Row justify="space-between" items="center">
                        <Text>치트 토글</Text>
                        <Input
                            value={hotkeys.toggleCheat}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleHotkeyChange('toggleCheat', e.target.value)}
                            placeholder="F1"
                            mw="80px"
                        />
                    </Row>
                    <Row justify="space-between" items="center">
                        <Text>속도 핫</Text>
                        <Input
                            value={hotkeys.speedHack}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleHotkeyChange('speedHack', e.target.value)}
                            placeholder="F2"
                            mw="80px"
                        />
                    </Row>
                    <Row justify="space-between" items="center">
                        <Text>무적 모드</Text>
                        <Input
                            value={hotkeys.godMode}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleHotkeyChange('godMode', e.target.value)}
                            placeholder="F3"
                            mw="80px"
                        />
                    </Row>
                </Col>
            </Section>

            {/* 설정 관리 */}
            <Section title="설정 관리">
                <Row gap="0.5rem">
                    <Button onClick={exportSettings} variant="outline" size="sm">
                        설정 내보내기
                    </Button>
                    <Button onClick={importSettings} variant="outline" size="sm">
                        설정 가져오기
                    </Button>
                    <Button onClick={resetSettings} variant="outline" size="sm">
                        초기화
                    </Button>
                </Row>
            </Section>

            {/* 디바이스 정보 */}
            <Section title="디바이스 정보">
                <Col gap="0.2rem">
                    <Text size="sm">현재 디바이스: {getState('device') || '없음'}</Text>
                    <Text size="sm">세션 상태: {getState('session') ? '연결됨' : '연결되지 않음'}</Text>
                    <Text size="sm">앱 버전: v1.0.0</Text>
                </Col>
            </Section>
        </Container>
    );
};

export default Config;