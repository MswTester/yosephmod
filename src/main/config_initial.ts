// Example Codes - 초기 설정 예제 코드
interface setupConfig {
    key: string;
    default: any;
    store: boolean;
}

function createUniqueConfig<T extends setupConfig[]>(configArray: T): T {
    const keys = new Set<string>();
    for (const config of configArray) {
        if (keys.has(config.key)) {
            throw new Error(`Duplicate key found: ${config.key}`);
        }
        keys.add(config.key);
    }
    return configArray;
}

const init_config: setupConfig[] = createUniqueConfig([
    // 윈도우 설정 (저장됨)
    {key: "main-bounds", default: {x: 0, y: 0, width: 400, height: 600}, store: true},
    
    // 앱 일반 설정 (저장됨)
    {key: "auto-start", default: false, store: true},
    {key: "auto-save", default: true, store: true},
    {key: "target-app", default: "com.example.app", store: true},
    {key: "theme", default: "dark", store: true},
    {key: "language", default: "ko", store: true},
    
    // 성능 설정 (저장됨)
    {key: "update-interval", default: 1000, store: true},
    {key: "max-retries", default: 3, store: true},
    {key: "log-level", default: "info", store: true},
    
    // 단축키 설정 (저장됨)
    {key: "hotkeys", default: {
        toggleCheat: "F1",
        speedHack: "F2",
        godMode: "F3"
    }, store: true},
    
    // 치트 기본 설정 (저장됨)
    {key: "auto-mode", default: false, store: true},
    {key: "speed-multiplier", default: 1.0, store: true},
    {key: "god-mode", default: false, store: true},
    {key: "infinite-ammo", default: false, store: true},
    {key: "noclip", default: false, store: true},
    
    // 게임 관련 설정 (저장됨)
    {key: "default-health", default: 1000, store: true},
    {key: "default-gold", default: 999999, store: true},
    {key: "scan-range", default: {min: 0, max: 9999999}, store: true},
    
    // 런타임 상태 (저장되지 않음)
    {key: "device", default: null, store: false},
    {key: "session", default: null, store: false},
    {key: "script-status", default: "stopped", store: false},
    {key: "last-scan-results", default: [], store: false},
    {key: "memory-addresses", default: {}, store: false},
    
    // 고급 설정 (저장됨)
    {key: "memory-scan-delay", default: 100, store: true},
    {key: "injection-method", default: "spawn", store: true}, // spawn, attach
    {key: "emulated-mode", default: false, store: true},
    {key: "anti-detection", default: true, store: true},
]);

export default init_config;