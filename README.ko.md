# YosephMod - 완벽한 치트앱 개발 가이드

> 🎓 **교육 목적 전용** - 누구나 따라할 수 있는 완벽한 치트앱 제작 가이드

## 🚀 5분 만에 시작하기

### 1. 필요한 프로그램 설치
```bash
# Node.js 18+ 설치 (https://nodejs.org)
# Git 설치 (https://git-scm.com)
# 안드로이드 디바이스 + USB 디버깅 활성화
```

### 2. 프로젝트 다운로드 및 설치
```bash
git clone https://github.com/MswTester/yosephmod.git
cd yosephmod
npm install
```

### 3. 개발 모드 실행
```bash
npm run dev
```

---

## 🏗️ 시스템 아키텍처 이해하기

### 📋 전체 구조 개요
YosephMod은 **3개의 독립적인 파트**가 서로 통신하여 작동합니다:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Renderer     │◄──►│   Main Process  │◄──►│     Agent       │
│   (UI 화면)      │    │   (중계 서버)     │    │  (실제 치트)     │
│                 │    │                 │    │                 │
│ • React 기반     │    │ • Electron 메인  │    │ • Frida 스크립트 │
│ • 사용자 입력     │    │ • 통신 중계       │    │ • 메모리 조작     │
│ • 상태 표시       │    │ • 상태 관리       │    │ • 함수 후킹      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
     브라우저 환경          Node.js 환경          타겟 앱 내부 환경
```

### 🎯 각 파트별 상세 설명

#### 1️⃣ **Agent (에이전트)** - `src/agents/`
- **역할**: 실제 치트 기능을 수행하는 핵심
- **위치**: 타겟 게임/앱 프로세스 내부에서 실행
- **기술**: Frida JavaScript 엔진
- **기능**:
  - 메모리 읽기/쓰기
  - 함수 후킹 및 패치
  - 게임 로직 조작
  - 실시간 데이터 수집

```typescript
// src/agents/main-agent.ts 예제
on('change-health', (newValue: number) => {
    const healthAddress = findHealthAddress();
    if (healthAddress) {
        Memory.protect(healthAddress, 4, 'rw-');
        healthAddress.writeInt(newValue);
        setState('current-health', newValue); // UI로 자동 전송
    }
});
```

#### 2️⃣ **Main Process (메인 프로세스)** - `src/main/`
- **역할**: Agent와 Renderer 사이의 통신 중계자
- **위치**: 데스크톱 환경에서 실행 (Electron)
- **기술**: Node.js + Electron + Frida Node.js 바인딩
- **기능**:
  - FridaManager로 Agent 관리
  - StateManager로 전역 상태 관리
  - IPC 통신으로 UI와 연결
  - 파일 시스템 접근

```typescript
// src/main/main_logic.ts 예제
ipcMain.on('from-renderer', (event, channel, ...args) => {
    console.log(`UI -> Agent: ${channel}`, args);
    fridaManager.send(channel, ...args); // Agent로 전달
});

fridaManager.on('scan-complete', (address, value) => {
    sendRenderer('scan-complete', address, value); // UI로 전달
});
```

#### 3️⃣ **Renderer (렌더러)** - `src/renderer/`
- **역할**: 사용자 인터페이스 제공
- **위치**: Electron 창 내부의 브라우저 환경
- **기술**: React + TypeScript + Styled Components
- **기능**:
  - 치트 기능 제어 패널
  - 실시간 상태 모니터링
  - 설정 관리 UI
  - 로그 콘솔 표시

```typescript
// src/renderer/Main.tsx 예제
const handleChangeHealth = () => {
    const value = parseInt(targetValue);
    send('change-health', value); // Agent로 자동 전송
};

const currentHealth = getState('current-health'); // Agent에서 자동 업데이트
```

---

## ⚙️ 초기 설정 및 상태 관리 시스템

### 🔧 config_initial.ts 활용법

모든 앱의 설정과 초기값은 `src/main/config_initial.ts`에서 관리됩니다.

#### 설정 구조 이해하기
```typescript
interface setupConfig {
    key: string;        // 고유한 키 이름
    default: any;       // 기본값 (모든 타입 가능)
    store: boolean;     // true: 재시작 후 유지, false: 재시작 후 초기화
}
```

#### 실제 설정 예제들
```typescript
const init_config: setupConfig[] = [
    // 윈도우 설정 (자동 저장됨)
    {key: "main-bounds", default: {x: 0, y: 0, width: 400, height: 600}, store: true},
    
    // 타겟 앱 설정
    {key: "target-app", default: "com.example.app", store: true},
    
    // 치트 기본 설정
    {key: "auto-mode", default: false, store: true},
    {key: "speed-multiplier", default: 1.0, store: true},
    {key: "god-mode", default: false, store: true},
    
    // 게임 관련 설정
    {key: "default-health", default: 1000, store: true},
    {key: "default-gold", default: 999999, store: true},
    
    // 런타임 상태 (저장되지 않음)
    {key: "device", default: null, store: false},
    {key: "session", default: null, store: false},
    {key: "last-scan-results", default: [], store: false},
];
```

#### 새로운 설정 추가하는 방법
```typescript
// 1단계: config_initial.ts에 설정 추가
{key: "my-custom-setting", default: "default-value", store: true},

// 2단계: Agent에서 사용
const mySetting = state['my-custom-setting'];

// 3단계: UI에서 사용
const { getState, setState } = useGlobal();
const value = getState('my-custom-setting');
setState('my-custom-setting', 'new-value');
```

### 📊 StateManager 동작 원리

StateManager는 3개 파트 간의 상태 동기화를 자동으로 처리합니다:

```typescript
// Agent에서 상태 변경
setState('player-health', 1000);

// ⬇️ 자동으로 Main Process에 전송

// ⬇️ Main Process가 Renderer로 중계

// ⬇️ UI에서 즉시 확인 가능
const health = getState('player-health'); // 1000
```

---

## 🔄 통신 시스템 완벽 가이드

### 📡 통신 플로우 이해하기

#### 패턴 1: UI → Agent (명령 전송)
```typescript
// 1. UI에서 버튼 클릭
const handleClick = () => {
    send('do-something', param1, param2);
};

// 2. Main Process가 자동 중계 (해당 코드는 main.ts에 작성되어 있음)
ipcMain.on('send-to-agent', (event, channel, ...args) => {
    fridaManager.send(channel, ...args);
});

// 3. Agent에서 처리
on('do-something', (param1, param2) => {
    log("작업 수행 중...");
    // 실제 치트 로직 실행
    setState('task-result', 'success');
});
```

#### 패턴 2: Agent → UI (상태 업데이트)
```typescript
// 1. Agent에서 상태 변경
setState('health', newValue);

// 2. Main Process가 자동 감지 및 중계 (해당 코드는 main.ts에 작성되어 있음)
fridaManager.on('state-update', (key, value) => {
    sendRenderer('state-changed', key, value);
});

// 3. UI에서 자동 업데이트
const currentHealth = getState('health'); // 자동으로 최신값
```

### 🎛️ 이벤트 핸들링 시스템

#### Agent에서 이벤트 리스너 등록
```typescript
// src/agents/main-agent.ts
import { on, setState, log } from './module';

// 체력 변경 이벤트
on('change-health', (newValue: number) => {
    try {
        const address = findHealthAddress();
        if (address) {
            Memory.protect(address, 4, 'rw-');
            address.writeInt(newValue);
            setState('current-health', newValue);
            log(`✅ 체력이 ${newValue}로 변경됨`);
        }
    } catch (error) {
        log("❌ 체력 변경 실패:", error);
        setState('last-error', error.message);
    }
});

// 상태 변경 감지
onStateChanged((key: string, value: any) => {
    if (key === 'auto-mode' && value) {
        startAutoMode();
    }
});
```

#### UI에서 이벤트 발송
```typescript
// src/renderer/Main.tsx
import { useGlobal } from './contexts/globalContext';

const Main = () => {
    const { send, exec, getState, setState } = useGlobal();
    
    // 간단한 명령 전송
    const handleHealthChange = () => {
        send('change-health', 1000);
    };
    
    // 코드 직접 실행
    const executeCustomCode = () => {
        exec('log("Hello from UI!")');
    };
    
    // 상태 확인
    const currentHealth = getState('current-health');
    
    return (
        <Button onClick={handleHealthChange}>
            체력 변경 (현재: {currentHealth})
        </Button>
    );
};
```

---

## 🎨 UI 컴포넌트 및 상태 연동 가이드

### 🧩 Primitive 컴포넌트 시스템

YosephMod은 재사용 가능한 UI 컴포넌트를 제공합니다:

#### 기본 레이아웃 컴포넌트
```typescript
import { Container, Row, Col, Button, Input, Text } from './components/ui/primitive';

// 기본 레이아웃
<Container h="100%" p="1rem" gap="1rem">
    <Row justify="space-between" items="center">
        <Text size="lg">제목</Text>
        <Button variant="outline">버튼</Button>
    </Row>
    
    <Col gap="0.5rem">
        <Input placeholder="값 입력" />
        <Button variant="default">실행</Button>
    </Col>
</Container>
```

#### 상태와 연동된 UI 컴포넌트
```typescript
// src/renderer/Main.tsx
import React, { useState, useEffect } from 'react';
import { useGlobal } from './contexts/globalContext';
import { Switch, Slider, Text } from './components/ui/primitive';

const CheatPanel = () => {
    const { getState, setState, send } = useGlobal();
    
    // 로컬 상태
    const [inputValue, setInputValue] = useState('1000');
    
    // 전역 상태와 동기화
    const autoMode = getState('auto-mode') || false;
    const speedMultiplier = getState('speed-multiplier') || 1.0;
    
    // 자동 모드 토글
    const toggleAutoMode = () => {
        const newState = !autoMode;
        setState('auto-mode', newState);
        send('toggle-auto-mode', newState);
    };
    
    // 속도 변경
    const handleSpeedChange = (value: number) => {
        setState('speed-multiplier', value);
        send('set-speed-multiplier', value);
    };
    
    return (
        <Col gap="1rem" p="1rem">
            {/* 자동 모드 스위치 */}
            <Row justify="space-between" items="center">
                <Text>자동 모드</Text>
                <Switch 
                    checked={autoMode}
                    onChange={toggleAutoMode}
                />
            </Row>
            
            {/* 속도 슬라이더 */}
            <Col gap="0.5rem">
                <Text>속도 배율: {speedMultiplier}x</Text>
                <Slider
                    min={0.1}
                    max={5}
                    step={0.1}
                    value={speedMultiplier}
                    onChange={handleSpeedChange}
                />
            </Col>
            
            {/* 입력과 버튼 */}
            <Row gap="0.5rem">
                <Input 
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder="체력 값"
                />
                <Button 
                    onClick={() => send('change-health', parseInt(inputValue))}
                    disabled={isNaN(parseInt(inputValue))}
                >
                    변경
                </Button>
            </Row>
        </Col>
    );
};
```

### 📱 Config.tsx에서 설정 UI 구축
```typescript
// src/renderer/Config.tsx
import { Switch, Select, Input, Row, Col, Text, Button } from './components/ui/primitive';

const Config = () => {
    const { getState, setState } = useGlobal();
    
    return (
        <Container p="1rem" gap="1rem">
            {/* 기본 설정 */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text size="lg" weight="medium">기본 설정</Text>
                
                <Row justify="space-between" items="center">
                    <Text>자동 시작</Text>
                    <Switch 
                        checked={getState('auto-start')}
                        onChange={(checked) => setState('auto-start', checked)}
                    />
                </Row>
                
                <Row justify="space-between" items="center">
                    <Text>타겟 앱</Text>
                    <Input 
                        value={getState('target-app')}
                        onChange={(e) => setState('target-app', e.target.value)}
                        placeholder="com.example.app"
                    />
                </Row>
            </Col>
            
            {/* 성능 설정 */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text size="lg" weight="medium">성능 설정</Text>
                
                <Row justify="space-between" items="center">
                    <Text>업데이트 간격 (ms)</Text>
                    <Select 
                        value={getState('update-interval')}
                        onChange={(e) => setState('update-interval', parseInt(e.target.value))}
                    >
                        <option value="100">100ms</option>
                        <option value="500">500ms</option>
                        <option value="1000">1초</option>
                        <option value="5000">5초</option>
                    </Select>
                </Row>
            </Col>
        </Container>
    );
};
```

---

## 🔧 FridaManager 사용법 및 실제 치트앱 작동 예제

### 🎯 FridaManager 핵심 메서드

#### 디바이스 연결 및 스크립트 로딩
```typescript
// src/main/main_logic.ts
const init = async (fridaManager: FridaManager, stateManager: StateManager) => {
    try {
        // USB 디바이스 선택
        await fridaManager.selectDeviceByType('usb');
        console.log('✅ USB 디바이스 연결됨');
        
        // 타겟 앱에 스크립트 로딩
        const targetApp = stateManager.getState("target-app");
        const result = await fridaManager.loadScript("main-agent", targetApp);
        
        if (result.success) {
            console.log('✅ 스크립트 로딩 성공');
        } else {
            console.error('❌ 스크립트 로딩 실패:', result.error);
        }
    } catch (error) {
        console.error('❌ 초기화 실패:', error);
    }
};
```

#### Agent와의 통신 설정
```typescript
// Agent로 메시지 전송
fridaManager.send('channel-name', data1, data2);

// Agent에서 메시지 수신
fridaManager.on('message-from-agent', (data) => {
    console.log('Agent에서 받은 데이터:', data);
});

// 스크립트 상태 모니터링
fridaManager.on('script-destroyed', () => {
    console.log('스크립트 연결 끊김');
});
```

### 🎮 완전한 치트앱 작동 예제

#### 시나리오: RPG 게임 체력/골드 치트 만들기

**1단계: Agent에 치트 로직 구현**
```typescript
// src/agents/main-agent.ts
import { state, log, on, emit, setState } from './module';

let gameModuleBase: NativePointer | null = null;
let healthAddress: NativePointer | null = null;
let goldAddress: NativePointer | null = null;

// 초기화
on('init', () => {
    log("🚀 RPG 치트 에이전트 시작!");
    findGameAddresses();
});

// 게임 메모리 주소 찾기
function findGameAddresses() {
    try {
        // 게임 메인 모듈 찾기
        const gameModule = Process.getModuleByName("libgame.so");
        if (gameModule) {
            gameModuleBase = gameModule.base;
            log(`🎯 게임 모듈 발견: ${gameModuleBase}`);
            
            // 알려진 오프셋으로 주소 계산
            healthAddress = gameModuleBase.add(0x123456);
            goldAddress = gameModuleBase.add(0x789ABC);
            
            setState('addresses-found', true);
            log("✅ 메모리 주소 검색 완료");
        }
    } catch (error) {
        log("❌ 주소 검색 실패:", error);
        setState('addresses-found', false);
    }
}

// 체력 변경
on('change-health', (newValue: number) => {
    if (!healthAddress) {
        log("❌ 체력 주소를 찾을 수 없음");
        return;
    }
    
    try {
        Memory.protect(healthAddress, 4, 'rw-');
        healthAddress.writeInt(newValue);
        
        // 실제 값 확인
        const currentValue = healthAddress.readInt();
        setState('current-health', currentValue);
        
        log(`✅ 체력 변경: ${currentValue}`);
    } catch (error) {
        log("❌ 체력 변경 실패:", error);
    }
});

// 골드 변경
on('change-gold', (newValue: number) => {
    if (!goldAddress) {
        log("❌ 골드 주소를 찾을 수 없음");
        return;
    }
    
    try {
        Memory.protect(goldAddress, 4, 'rw-');
        goldAddress.writeInt(newValue);
        
        const currentValue = goldAddress.readInt();
        setState('current-gold', currentValue);
        
        log(`✅ 골드 변경: ${currentValue}`);
    } catch (error) {
        log("❌ 골드 변경 실패:", error);
    }
});

// 자동 모드
let autoInterval: any = null;
on('toggle-auto-mode', (enabled: boolean) => {
    if (enabled) {
        autoInterval = setInterval(() => {
            if (healthAddress && goldAddress) {
                // 체력과 골드를 최대치로 유지
                const maxHealth = state['default-health'] || 9999;
                const maxGold = state['default-gold'] || 999999;
                
                healthAddress.writeInt(maxHealth);
                goldAddress.writeInt(maxGold);
                
                setState('current-health', maxHealth);
                setState('current-gold', maxGold);
            }
        }, state['update-interval'] || 1000);
        
        log("🤖 자동 모드 활성화");
    } else {
        if (autoInterval) {
            clearInterval(autoInterval);
            autoInterval = null;
        }
        log("🤖 자동 모드 비활성화");
    }
});
```

**2단계: UI에 컨트롤 패널 구현**
```typescript
// src/renderer/Main.tsx
import React, { useState } from 'react';
import { useGlobal } from './contexts/globalContext';
import { Container, Row, Col, Button, Input, Text, Switch, Badge } from './components/ui/primitive';

const RPGCheatPanel = () => {
    const { getState, setState, send } = useGlobal();
    
    const [healthInput, setHealthInput] = useState('9999');
    const [goldInput, setGoldInput] = useState('999999');
    
    // 현재 상태
    const addressesFound = getState('addresses-found');
    const currentHealth = getState('current-health');
    const currentGold = getState('current-gold');
    const autoMode = getState('auto-mode') || false;
    
    return (
        <Container h="100%" p="1rem" gap="1rem">
            {/* 상태 표시 */}
            <Row justify="space-between" items="center">
                <Text size="lg" weight="medium">RPG 치트 패널</Text>
                <Badge variant={addressesFound ? 'default' : 'destructive'}>
                    {addressesFound ? '연결됨' : '연결 안됨'}
                </Badge>
            </Row>
            
            {/* 현재 값 표시 */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text weight="medium">현재 상태</Text>
                <Text size="sm">체력: {currentHealth || '알 수 없음'}</Text>
                <Text size="sm">골드: {currentGold || '알 수 없음'}</Text>
            </Col>
            
            {/* 체력 변경 */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text weight="medium">체력 변경</Text>
                <Row gap="0.5rem">
                    <Input 
                        value={healthInput}
                        onChange={(e) => setHealthInput(e.target.value)}
                        placeholder="체력 값"
                    />
                    <Button 
                        onClick={() => send('change-health', parseInt(healthInput))}
                        disabled={!addressesFound || isNaN(parseInt(healthInput))}
                    >
                        변경
                    </Button>
                </Row>
                <Row gap="0.5rem">
                    <Button variant="outline" onClick={() => {
                        setHealthInput('9999');
                        send('change-health', 9999);
                    }}>최대 체력</Button>
                    <Button variant="outline" onClick={() => {
                        setHealthInput('1');
                        send('change-health', 1);
                    }}>최소 체력</Button>
                </Row>
            </Col>
            
            {/* 골드 변경 */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Text weight="medium">골드 변경</Text>
                <Row gap="0.5rem">
                    <Input 
                        value={goldInput}
                        onChange={(e) => setGoldInput(e.target.value)}
                        placeholder="골드 값"
                    />
                    <Button 
                        onClick={() => send('change-gold', parseInt(goldInput))}
                        disabled={!addressesFound || isNaN(parseInt(goldInput))}
                    >
                        변경
                    </Button>
                </Row>
                <Row gap="0.5rem">
                    <Button variant="outline" onClick={() => {
                        setGoldInput('999999');
                        send('change-gold', 999999);
                    }}>최대 골드</Button>
                    <Button variant="outline" onClick={() => {
                        setGoldInput('0');
                        send('change-gold', 0);
                    }}>골드 초기화</Button>
                </Row>
            </Col>
            
            {/* 자동 모드 */}
            <Col gap="0.5rem" p="1rem" border="1px solid var(--border-color)">
                <Row justify="space-between" items="center">
                    <Text weight="medium">자동 모드</Text>
                    <Switch 
                        checked={autoMode}
                        onChange={(e) => {
                            const enabled = e.target.checked;
                            setState('auto-mode', enabled);
                            send('toggle-auto-mode', enabled);
                        }}
                        disabled={!addressesFound}
                    />
                </Row>
                <Text size="sm" muted>
                    {autoMode ? 
                        '체력과 골드를 자동으로 최대치로 유지합니다' : 
                        '수동으로 값을 변경해야 합니다'
                    }
                </Text>
            </Col>
        </Container>
    );
};

export default RPGCheatPanel;
```

**3단계: 설정에서 타겟 앱 지정**
```typescript
// src/main/config_initial.ts에서 타겟 앱 설정
{key: "target-app", default: "com.example.rpggame", store: true},
{key: "default-health", default: 9999, store: true},
{key: "default-gold", default: 999999, store: true},
```

---

## 📦 NPM 명령어 및 배포 가이드

### 🛠️ 개발 명령어

```bash
# 개발 모드 (실시간 리로드)
npm run dev

# 타입 체크
npm run typecheck

# 코드 검사 및 자동 수정
npm run lint
npm run lint:fix

# 빌드 (배포 준비)
npm run build

# 실행 파일 생성 (모든 플랫폼)
npm run dist

# Windows용 실행 파일만 생성
npm run dist:win

# macOS용 실행 파일만 생성  
npm run dist:mac

# Linux용 실행 파일만 생성
npm run dist:linux
```

### 📱 배포 준비 체크리스트

#### 1. 코드 검사 및 빌드 테스트
```bash
# 타입 오류 확인
npm run typecheck

# 코드 스타일 검사
npm run lint

# 빌드 테스트
npm run build
```

#### 2. 설정 파일 확인
```typescript
// src/main/config_initial.ts에서 배포용 설정 확인
{key: "target-app", default: "실제_타겟_앱_패키지명", store: true},
{key: "auto-start", default: false, store: true}, // 배포시 false 권장
```

#### 3. 실행 파일 생성
```bash
# 현재 플랫폼용 실행 파일 생성
npm run dist

# 생성된 파일 위치: dist/ 폴더
# Windows: .exe 파일
# macOS: .dmg 파일  
# Linux: .AppImage 파일
```

### 🚀 사용자에게 배포하기

#### 배포 패키지 구성
```
배포_폴더/
├── YosephMod-1.0.0-win.exe        # Windows 실행 파일
├── 사용법.txt                # 간단한 사용 가이드
├── 타겟앱_설정.txt            # 타겟 앱별 설정 가이드
└── 문제해결.txt              # 자주 발생하는 문제 해결법
```

#### 사용자 가이드 예제
```
YosephMod 치트앱 사용법

1. 안드로이드 기기 준비
   - USB 디버깅 활성화
   - 개발자 옵션 활성화
   - USB로 PC와 연결

2. 앱 실행
   - YosephMod.exe 실행
   - 타겟 앱이 실행 중인지 확인
   - Main 탭에서 치트 기능 사용

3. 설정 변경
   - Config 탭에서 타겟 앱 패키지명 변경
   - 업데이트 간격 등 조정

문제 발생시:
- Console 탭에서 로그 확인
- 디바이스 연결 상태 확인
- 타겟 앱이 실행 중인지 확인
```

---

## 🔧 고급 개발 팁

### 🎯 성능 최적화

```typescript
// Agent에서 메모리 접근 최적화
const cachedAddresses = new Map<string, NativePointer>();

function getCachedAddress(key: string, finder: () => NativePointer): NativePointer | null {
    if (!cachedAddresses.has(key)) {
        try {
            const addr = finder();
            cachedAddresses.set(key, addr);
        } catch {
            return null;
        }
    }
    return cachedAddresses.get(key) || null;
}

// 사용 예제
const healthAddr = getCachedAddress('health', () => 
    Process.getModuleByName("libgame.so").base.add(0x123456)
);
```

### 🛡️ 안전한 메모리 조작

```typescript
function safeMemoryWrite(address: NativePointer, value: number, size: number = 4): boolean {
    try {
        // 메모리 권한 확인 및 변경
        Memory.protect(address, size, 'rw-');
        
        // 값 쓰기
        if (size === 4) address.writeInt(value);
        else if (size === 8) address.writeDouble(value);
        else if (size === 1) address.writeU8(value);
        
        // 검증: 실제로 변경되었는지 확인
        const written = size === 4 ? address.readInt() : 
                       size === 8 ? address.readDouble() : 
                       address.readU8();
        
        return written === value;
    } catch (error) {
        log(`메모리 쓰기 실패: ${error}`);
        return false;
    }
}
```

### 🔍 디버깅 도구

```typescript
// Agent에서 메모리 덤프
function dumpMemory(address: NativePointer, size: number = 256) {
    try {
        const data = address.readByteArray(size);
        if (data) {
            log("메모리 덤프:", hexdump(data));
        }
    } catch (error) {
        log("덤프 실패:", error);
    }
}

// 함수 호출 추적
function traceFunction(functionAddr: NativePointer, name: string) {
    Interceptor.attach(functionAddr, {
        onEnter(args) {
            log(`📞 ${name} 호출됨`);
            log(`인자들:`, args.map(arg => arg.toString()));
        },
        onLeave(retval) {
            log(`📤 ${name} 반환값:`, retval.toString());
        }
    });
}
```

---

## 🚨 문제 해결 가이드

### 자주 발생하는 오류들

#### 1. "Device not connected" 오류
```bash
해결 방법:
1. USB 디버깅이 활성화되어 있는지 확인
2. adb devices 명령으로 기기 인식 확인
3. 개발자 옵션에서 "USB 디버깅 허용" 체크
4. USB 케이블 교체 시도
```

#### 2. "Script injection failed" 오류
```bash
해결 방법:
1. 타겟 앱이 실행 중인지 확인
2. 앱 패키지명이 정확한지 확인
3. 루팅/탈옥 상태 확인
4. 안티치트 프로그램 비활성화
```

#### 3. "Memory access violation" 오류
```bash
해결 방법:
1. 메모리 주소가 올바른지 확인
2. Memory.protect() 호출 확인
3. 게임 업데이트로 주소 변경 가능성 확인
4. 32비트/64비트 아키텍처 확인
```

#### 4. "Interceptor.attach failed" 오류
```bash
해결 방법:
1. 에뮬레이터 사용 시, fridaManager.loadScript() 메서드의 emulated 옵션을 true로 설정
```

### 📊 로그 확인 방법

1. **Console 탭**: Agent의 실시간 로그 확인
2. **개발자 도구**: `Ctrl+Shift+I`로 UI 오류 확인  
3. **터미널**: `npm run dev` 실행 시 Main Process 로그

---

## ⚖️ 중요한 주의사항

### 🎓 교육 목적 전용
- 리버스 엔지니어링 학습용으로만 사용
- 본인 소유의 소프트웨어에서만 테스트
- 교육 및 연구 목적으로 활용

### 🚫 금지 사항
- 온라인 게임에서 사용 금지 (계정 밴 위험)
- 타인의 저작권 침해 금지
- 상업적 목적 사용 금지
- 악의적 목적 사용 금지

### ⚖️ 법적 책임
- 사용자 본인의 책임하에 사용
- 관련 법률 준수 필수
- 의심스러운 활동에 사용 금지

---

## 📞 도움 받기

### 문제 신고
- GitHub Issues: [이슈 등록](https://github.com/MswTester/yosephmod/issues)

### 학습 자료
- [Frida 공식 문서](https://frida.re/docs/)
- [Electron 공식 문서](https://www.electronjs.org/docs)
- [React 공식 문서](https://react.dev/)

---

## 📜 라이선스

이 프로젝트는 교육 목적으로만 사용할 수 있습니다.

**⚠️ 이 템플릿을 사용하기 전에 해당 지역의 관련 법률을 확인하고 준수하세요.**