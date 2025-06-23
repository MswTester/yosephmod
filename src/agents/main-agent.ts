// Example Codes - 메인 에이전트 예제 코드
import { state, log, on, emit, setState, Demangler, onStateChanged } from './module';

// 전역 변수들
let isGodMode = false;
let hasInfiniteAmmo = false;
let speedMultiplier = 1.0;
let autoModeEnabled = false;
let autoModeInterval: any = null;
let memoryAddresses: any = {};
let scanResults: any[] = [];

// 초기화
on('init', () => {
    log("🚀 YSSM Agent 로딩 완료!", state);
    
    // 상태 초기화
    isGodMode = state['god-mode'] || false;
    hasInfiniteAmmo = state['infinite-ammo'] || false;
    speedMultiplier = state['speed-multiplier'] || 1.0;
    autoModeEnabled = state['auto-mode'] || false;
    
    log("📊 현재 상태:", {
        godMode: isGodMode,
        infiniteAmmo: hasInfiniteAmmo,
        speedMultiplier: speedMultiplier,
        autoMode: autoModeEnabled
    });
    
    // 메모리 주소 찾기 시작
    findMemoryAddresses();
});

// 예제 1: 체력 변경 기능
on('change-health', (newValue: number) => {
    try {
        log(`💊 체력을 ${newValue}로 변경 시도...`);
        
        // 실제 구현에서는 메모리 스캔을 통해 주소를 찾아야 함
        const healthAddress = findHealthAddress();
        if (healthAddress) {
            Memory.protect(healthAddress, 4, 'rw-');
            healthAddress.writeInt(newValue);
            log(`✅ 체력이 ${newValue}로 변경되었습니다!`);
            setState('current-health', newValue);
        } else {
            log("❌ 체력 주소를 찾을 수 없습니다. 메모리 스캔을 먼저 실행하세요.");
        }
    } catch (error) {
        log("❌ 체력 변경 중 오류:", error);
    }
});

// 예제 2: 골드/코인 변경 기능
on('change-gold', (newValue: number) => {
    try {
        log(`💰 골드를 ${newValue}로 변경 시도...`);
        
        const goldAddress = findGoldAddress();
        if (goldAddress) {
            Memory.protect(goldAddress, 4, 'rw-');
            goldAddress.writeInt(newValue);
            log(`✅ 골드가 ${newValue}로 변경되었습니다!`);
            setState('current-gold', newValue);
        } else {
            log("❌ 골드 주소를 찾을 수 없습니다. 메모리 스캔을 먼저 실행하세요.");
        }
    } catch (error) {
        log("❌ 골드 변경 중 오류:", error);
    }
});

// 예제 3: 메모리 스캔 기능
on('scan-memory', (targetValue: number) => {
    try {
        log(`🔍 값 ${targetValue}에 대한 메모리 스캔 시작...`);
        
        scanResults = [];
        const ranges = Process.enumerateRanges('rw-');
        let foundCount = 0;
        
        ranges.forEach(range => {
            try {
                const pattern = targetValue.toString(16).padStart(8, '0');
                Memory.scan(range.base, range.size, pattern, {
                    onMatch: (address, size) => {
                        scanResults.push({
                            address: address,
                            value: targetValue,
                            size: size
                        });
                        foundCount++;
                        return 'keep'; // 계속 스캔
                    },
                    onError: (reason) => {
                        // 스캔 오류 무시
                    },
                    onComplete: () => {
                        // 완료
                    }
                });
            } catch (e) {
                // 범위 스캔 오류 무시
            }
        });
        
        log(`✅ 스캔 완료! ${foundCount}개의 주소에서 값 ${targetValue}를 발견했습니다.`);
        setState('last-scan-results', scanResults);
        
    } catch (error) {
        log("❌ 메모리 스캔 중 오류:", error);
    }
});

// 예제 4: 무적 모드 토글
on('toggle-godmode', () => {
    isGodMode = !isGodMode;
    setState('god-mode', isGodMode);
    log(`🛡️ 무적 모드: ${isGodMode ? '활성화' : '비활성화'}`);
    
    if (isGodMode) {
        enableGodMode();
    } else {
        disableGodMode();
    }
});

// 예제 5: 무한 탄약 토글
on('toggle-infinite-ammo', () => {
    hasInfiniteAmmo = !hasInfiniteAmmo;
    setState('infinite-ammo', hasInfiniteAmmo);
    log(`🔫 무한 탄약: ${hasInfiniteAmmo ? '활성화' : '비활성화'}`);
    
    if (hasInfiniteAmmo) {
        enableInfiniteAmmo();
    } else {
        disableInfiniteAmmo();
    }
});

// 예제 6: 속도 배율 설정
on('set-speed-multiplier', (multiplier: number) => {
    speedMultiplier = multiplier;
    setState('speed-multiplier', multiplier);
    log(`⚡ 속도 배율: ${multiplier}x`);
    
    applySpeedMultiplier(multiplier);
});

// 예제 7: 자동 모드 토글
on('toggle-auto-mode', (enabled: boolean) => {
    autoModeEnabled = enabled;
    setState('auto-mode', enabled);
    log(`🤖 자동 모드: ${enabled ? '활성화' : '비활성화'}`);
    
    if (enabled) {
        startAutoMode();
    } else {
        stopAutoMode();
    }
});

// 예제 8: 벽 통과 모드
on('toggle-noclip', () => {
    const noclipEnabled = !state['noclip'];
    setState('noclip', noclipEnabled);
    log(`🚶‍♂️ 벽 통과 모드: ${noclipEnabled ? '활성화' : '비활성화'}`);
    
    if (noclipEnabled) {
        enableNoclip();
    } else {
        disableNoclip();
    }
});

// 예제 9: 플레이어 순간이동
on('teleport-to-player', () => {
    try {
        log("📍 플레이어 위치로 순간이동...");
        
        // 예제 좌표 (실제로는 다른 플레이어 위치를 가져와야 함)
        const targetPosition = { x: 100.0, y: 50.0, z: 200.0 };
        teleportPlayer(targetPosition.x, targetPosition.y, targetPosition.z);
        
        log(`✅ 위치 (${targetPosition.x}, ${targetPosition.y}, ${targetPosition.z})로 순간이동 완료!`);
    } catch (error) {
        log("❌ 순간이동 중 오류:", error);
    }
});

// 예제 10: 상태 변경 감지
onStateChanged((key: string, value: any) => {
    log(`📊 상태 변경: ${key} = ${value}`);
    
    // 특정 상태 변경에 따른 처리
    switch (key) {
        case 'auto-mode':
            if (value !== autoModeEnabled) {
                autoModeEnabled = value;
                if (value) {
                    startAutoMode();
                } else {
                    stopAutoMode();
                }
            }
            break;
        case 'speed-multiplier':
            if (value !== speedMultiplier) {
                speedMultiplier = value;
                applySpeedMultiplier(value);
            }
            break;
    }
});

// 헬퍼 함수들

function findMemoryAddresses() {
    log("🔍 주요 메모리 주소 검색 중...");
    
    try {
        // 예제: 특정 함수나 변수의 주소 찾기
        const module = Process.getModuleByName("libc.so");
        if (module) {
            // 예제 주소들 (실제 게임에 맞게 수정 필요)
            memoryAddresses.health = module.base.add(0x12345678);
            memoryAddresses.gold = module.base.add(0x87654321);
            memoryAddresses.position = module.base.add(0x11111111);
            
            log("✅ 메모리 주소 검색 완료:", memoryAddresses);
            setState('memory-addresses', memoryAddresses);
        }
    } catch (error) {
        log("❌ 메모리 주소 검색 실패:", error);
    }
}

function findHealthAddress(): NativePointer | null {
    return memoryAddresses.health || null;
}

function findGoldAddress(): NativePointer | null {
    return memoryAddresses.gold || null;
}

function enableGodMode() {
    try {
        // 예제: 체력 감소 함수를 패치
        const healthDecreaseFunc = Module.getGlobalExportByName("decrease_health");
        if (healthDecreaseFunc) {
            Interceptor.replace(healthDecreaseFunc, new NativeCallback(() => {
                // 체력 감소를 무시
                log("🛡️ 체력 감소 차단됨 (무적 모드)");
            }, 'void', []));
        }
    } catch (error) {
        log("❌ 무적 모드 활성화 실패:", error);
    }
}

function disableGodMode() {
    try {
        // 원래 함수로 복원 (실제로는 더 복잡한 구현 필요)
        log("🛡️ 무적 모드 비활성화");
        Interceptor.revert(Module.getGlobalExportByName("decrease_health"));
    } catch (error) {
        log("❌ 무적 모드 비활성화 실패:", error);
    }
}

function enableInfiniteAmmo() {
    try {
        // 예제: 탄약 감소 함수를 패치
        const ammoDecreaseFunc = Module.getGlobalExportByName("use_ammo");
        if (ammoDecreaseFunc) {
            Interceptor.replace(ammoDecreaseFunc, new NativeCallback(() => {
                // 탄약 감소를 무시
                log("🔫 탄약 소모 차단됨 (무한 탄약)");
            }, 'void', []));
        }
    } catch (error) {
        log("❌ 무한 탄약 활성화 실패:", error);
    }
}

function disableInfiniteAmmo() {
    try {
        log("🔫 무한 탄약 비활성화");
        Interceptor.revert(Module.getGlobalExportByName("use_ammo"));
    } catch (error) {
        log("❌ 무한 탄약 비활성화 실패:", error);
    }
}

function applySpeedMultiplier(multiplier: number) {
    try {
        // 예제: 이동 속도 함수를 후킹
        const moveFunc = Module.getGlobalExportByName("player_move");
        if (moveFunc) {
            Interceptor.attach(moveFunc, {
                onEnter: function(args) {
                    // 이동 속도에 배율 적용
                    const speed = args[0].readFloat();
                    args[0] = ptr(speed * multiplier);
                }
            });
        }
        log(`⚡ 속도 배율 ${multiplier}x 적용됨`);
    } catch (error) {
        log("❌ 속도 배율 적용 실패:", error);
    }
}

function enableNoclip() {
    try {
        // 예제: 충돌 감지 함수를 비활성화
        const collisionFunc = Module.getGlobalExportByName("check_collision");
        if (collisionFunc) {
            Interceptor.replace(collisionFunc, new NativeCallback(() => {
                return 0; // 충돌 없음을 반환
            }, 'int', ['pointer', 'pointer']));
        }
        log("🚶‍♂️ 벽 통과 모드 활성화");
    } catch (error) {
        log("❌ 벽 통과 모드 활성화 실패:", error);
    }
}

function disableNoclip() {
    try {
        log("🚶‍♂️ 벽 통과 모드 비활성화");
        Interceptor.revert(Module.getGlobalExportByName("check_collision"));
    } catch (error) {
        log("❌ 벽 통과 모드 비활성화 실패:", error);
    }
}

function teleportPlayer(x: number, y: number, z: number) {
    try {
        if (memoryAddresses.position) {
            Memory.protect(memoryAddresses.position, 12, 'rw-');
            memoryAddresses.position.writeFloat(x);
            memoryAddresses.position.add(4).writeFloat(y);
            memoryAddresses.position.add(8).writeFloat(z);
        }
    } catch (error) {
        log("❌ 순간이동 실패:", error);
    }
}

function startAutoMode() {
    if (autoModeInterval) {
        clearInterval(autoModeInterval);
    }
    
    autoModeInterval = setInterval(() => {
        try {
            // 자동 모드에서 실행할 작업들
            log("🤖 자동 모드 실행 중...");
            
            // 예제: 자동으로 체력과 골드 최대치로 유지
            if (state['auto-restore-health']) {
                const healthAddr = findHealthAddress();
                if (healthAddr) {
                    const maxHealth = state['default-health'] || 1000;
                    healthAddr.writeInt(maxHealth);
                }
            }
            
            if (state['auto-restore-gold']) {
                const goldAddr = findGoldAddress();
                if (goldAddr) {
                    const maxGold = state['default-gold'] || 999999;
                    goldAddr.writeInt(maxGold);
                }
            }
            
        } catch (error) {
            log("❌ 자동 모드 실행 중 오류:", error);
        }
    }, state['update-interval'] || 1000);
    
    log("🤖 자동 모드 시작됨");
}

function stopAutoMode() {
    if (autoModeInterval) {
        clearInterval(autoModeInterval);
        autoModeInterval = null;
    }
    log("🤖 자동 모드 중지됨");
}

// 예제: C++ 함수 이름 복원 (Android/Linux 전용)
try {
    const mangledNames = [
        "_Z10gameUpdatev",
        "_Z12playerAttackv",
        "_Z15calculateDamagei"
    ];
    
    const demangledNames = Demangler.demangle(mangledNames);
    log("🔧 함수 이름 복원 결과:", demangledNames);
} catch (error) {
    log("⚠️ 함수 이름 복원 실패 (Windows에서는 지원되지 않음):", error);
}

// 디버그 정보 출력
log("🎮 YSSM Agent 준비 완료!");
log("📋 사용 가능한 명령어:");
log("  - change-health <value>");
log("  - change-gold <value>");
log("  - scan-memory <value>");
log("  - toggle-godmode");
log("  - toggle-infinite-ammo");
log("  - set-speed-multiplier <value>");
log("  - toggle-auto-mode");
log("  - toggle-noclip");
log("  - teleport-to-player");
