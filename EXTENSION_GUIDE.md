# Frida Script Manager - 확장 가이드

## 프로젝트 구조

```
yongsan-sexmaster/
├── src/
│   ├── main/                    # Electron 메인 프로세스
│   │   ├── main.ts             # 메인 애플리케이션 엔트리포인트
│   │   ├── preload.ts          # 프리로드 스크립트
│   │   └── frida-manager.ts    # Frida 스크립트 관리자
│   ├── renderer/               # React 렌더러 프로세스
│   │   ├── App.tsx            # 메인 React 컴포넌트
│   │   ├── App.css            # 스타일시트
│   │   ├── index.tsx          # React 엔트리포인트
│   │   ├── index.css          # 글로벌 CSS
│   │   └── index.html         # HTML 템플릿
│   ├── agents/                 # Frida 스크립트들
│   │   ├── example-agent.ts   # 예제 에이전트
│   │   └── hello-world.ts     # 간단한 Hello World 에이전트
│   └── types/
│       └── global.d.ts        # TypeScript 타입 정의
├── scripts/                   # 빌드 스크립트들
│   ├── build-agents.js        # 에이전트 컴파일 스크립트
│   └── copy-files.js          # 파일 복사 스크립트
└── dist/                      # 빌드 결과물
    ├── main/                  # 컴파일된 메인 프로세스
    ├── renderer/              # 컴파일된 렌더러
    └── agents/                # 컴파일된 Frida 스크립트들
```

## 핵심 기능

### 1. Frida 스크립트 관리
- TypeScript로 작성된 Frida 스크립트를 자동으로 컴파일
- 실시간 스크립트 로드/언로드
- 핫 리로드 지원 (개발 모드)

### 2. 프로세스 관리
- 시스템 프로세스 목록 조회
- 프로세스 선택 및 attach
- USB 디바이스 지원

### 3. 실시간 메시지 로깅
- Frida 스크립트로부터 오는 메시지 실시간 표시
- 콘솔 스타일 메시지 뷰어

## 새로운 Frida 스크립트 추가하기

### 1. 스크립트 파일 생성
`src/agents/` 폴더에 새로운 `.ts` 파일을 생성합니다:

```typescript
// src/agents/my-script.ts

/**
 * @description My custom Frida script
 * @author Your Name
 * @version 1.0.0
 */

console.log("My script loaded!");

// Hook a function
Java.perform(() => {
    const MainActivity = Java.use("com.example.MainActivity");
    
    MainActivity.onCreate.implementation = function(savedInstanceState) {
        console.log("MainActivity.onCreate called!");
        
        // Call original method
        this.onCreate(savedInstanceState);
        
        // Send message to UI
        send({
            type: "activity_created",
            activity: "MainActivity",
            timestamp: Date.now()
        });
    };
});
```

### 2. 자동 컴파일
스크립트는 빌드 시 자동으로 컴파일됩니다:
```bash
npm run build:agents
```

개발 모드에서는 파일이 변경될 때마다 자동으로 다시 컴파일됩니다.

## React UI 컴포넌트 확장하기

### 1. 새로운 상태 추가
`src/renderer/App.tsx`에서 상태를 추가할 수 있습니다:

```typescript
const [newFeature, setNewFeature] = useState<any>(null);
```

### 2. IPC 통신 추가
메인 프로세스와 통신하기 위해 새로운 IPC 핸들러를 추가합니다:

**메인 프로세스** (`src/main/main.ts`):
```typescript
ipcMain.handle('my-new-feature', async (_event, param1: string) => {
  // 새로운 기능 구현
  return { success: true, data: result };
});
```

**렌더러 프로세스** (`src/renderer/App.tsx`):
```typescript
const handleNewFeature = async () => {
  try {
    const result = await window.electronAPI.invoke('my-new-feature', 'parameter');
    if (result.success) {
      setNewFeature(result.data);
    }
  } catch (error) {
    console.error('New feature failed:', error);
  }
};
```

## 개발 환경 설정

### 1. 개발 서버 실행
```bash
npm run dev
```
이 명령어는:
- TypeScript 컴파일러를 watch 모드로 실행
- React 빌더를 watch 모드로 실행
- Frida 스크립트 컴파일러를 watch 모드로 실행
- Electron 앱 시작

### 2. 핫 리로드 확인
- React 컴포넌트 변경 시 자동 리로드
- Frida 스크립트 변경 시 자동 리컴파일 및 리로드
- 메인 프로세스 변경 시 Electron 재시작

### 3. 빌드 및 배포
```bash
npm run build    # 개발 빌드
npm run dist     # 배포용 빌드 (electron-builder)
```

## 고급 확장 예제

### 1. 커스텀 Frida Manager 기능 추가
`src/main/frida-manager.ts`를 확장하여 새로운 기능을 추가할 수 있습니다:

```typescript
export class FridaScriptManager {
  // ... 기존 코드 ...
  
  async executeCustomScript(scriptCode: string, targetPid: number): Promise<any> {
    try {
      const session = await frida.attach(targetPid);
      const script = await session.createScript(scriptCode);
      await script.load();
      return { success: true, script };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}
```

### 2. 새로운 UI 섹션 추가
`src/renderer/App.tsx`의 `renderMainScreen` 함수를 수정하여 새로운 UI 섹션을 추가할 수 있습니다:

```typescript
<div className="content">
  <div className="processes-section">
    {/* 기존 프로세스 섹션 */}
  </div>
  
  <div className="agents-section">
    {/* 기존 에이전트 섹션 */}
  </div>
  
  <div className="custom-section">
    <h3>커스텀 기능</h3>
    <button onClick={handleCustomFeature}>커스텀 실행</button>
  </div>
</div>
```

### 3. 스타일 커스터마이징
`src/renderer/App.css`에서 새로운 스타일을 추가합니다:

```css
.custom-section {
  background: #f8f9fa;
  padding: 1.5rem;
  border-radius: 8px;
  border: 1px solid var(--border-color);
}
```

## 디버깅 팁

### 1. 메인 프로세스 디버깅
```bash
# Chrome DevTools로 메인 프로세스 디버깅
npm run dev -- --inspect=5858
```

### 2. 렌더러 프로세스 디버깅
Electron 앱에서 `Ctrl+Shift+I`로 개발자 도구 열기

### 3. Frida 스크립트 디버깅
- `console.log()` 사용하여 메시지 섹션에서 로그 확인
- `send()` 함수로 구조화된 데이터 전송

## 성능 최적화

### 1. React 최적화
- `React.memo()` 사용하여 불필요한 리렌더링 방지
- `useMemo()`, `useCallback()` 훅 활용

### 2. Frida 스크립트 최적화
- 불필요한 함수 후킹 피하기
- 메시지 전송 빈도 제한

### 3. 빌드 최적화
- esbuild 설정 튜닝
- 번들 크기 최적화

이 가이드를 따라 프로젝트를 확장하고 커스터마이징할 수 있습니다.