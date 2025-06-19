const state = new Map<string, any>();
const listeners = new Map<string, (...args: any[]) => void>()

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

listeners.set('state-changed', (key: string, value: any) => {
    state.set(key, value);
});

listeners.set('state-get-all', (newState: Map<string, any>) => {
    state.clear();
    newState.forEach((value, key) => {
        state.set(key, value);
    });
});