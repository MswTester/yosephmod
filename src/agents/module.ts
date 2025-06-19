export const state = new Map<string, any>();
const listeners = new Map<string, (...args: any[]) => void>()
export function on(channel: string, callback: (...args: any[]) => void){
    listeners.set(channel, callback)
}
export function emit(channel: string, ...args: any[]){
    send([channel, ...args])
}
export function log(...args: any[]){
    send(['log', ...args])
}

function api(message: any[]){
    const channel = message[0];
    const args = message.slice(1, message.length);
    try{
        if(listeners.has(channel)){
            listeners.get(channel)?.apply(null, args);
        }
    } catch(e) {
        console.error(e);
    } finally {
        recv(api);
    }
}
recv(api);

on('state-changed', (key: string, value: any) => {
    state.set(key, value);
});

on('state-get-all', (newState: Map<string, any>) => {
    state.clear();
    newState.forEach((value, key) => {
        state.set(key, value);
    });
});

emit('state-get-all')