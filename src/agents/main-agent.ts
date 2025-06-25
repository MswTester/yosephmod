// Example Codes - 메인 에이전트 예제 코드
import { state, log, on, emit, setState, Demangler, onStateChanged } from './module';

on('init', () => {
    log("state initialized")
});

// From Process
// on("custom-event", (customArgs) => void);

// To Process
// emit("custom-event", customArgs);

// On State Changed
// onStateChanged((key, value) => void);

// Key Event
// onKey((key, down) => void);

// Change State
// setState('key', 'value');

// Get State
// state['key'];
