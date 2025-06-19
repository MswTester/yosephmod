// Demangler
/*
 * Only for Linux/Android
 */
export namespace Demangler {
    type StringOrStringArray = string | string[];
    const _demangle = new NativeFunction(Module.getExportByName(null, "__cxa_demangle"), "pointer", ["pointer", "pointer", "pointer", "pointer"]);

    /** Demangle single symbol */
    export function demangle(mangled: string, intSize?: number): string;
    /** Demangle array of symbols */
    export function demangle(mangled: string[], intSize?: number): string[];
    /** @internal */
    export function demangle(mangled: StringOrStringArray, intSize: number = 4): StringOrStringArray {
        const isSingle = typeof mangled == "string";
        
        const status = Memory.alloc(intSize);
        status.writeInt(0);

        if (isSingle) {
            const result = _demangle(Memory.allocUtf8String(mangled), NULL, NULL, status);
            if (status.readInt() != 0)
                throw new Error(`Failed to demangle the symbol ${mangled}`);

            return result.readCString()!;
        }
        else {
            return mangled.map(element => {
                const result = _demangle(Memory.allocUtf8String(element), NULL, NULL, status);
                if (status.readInt() != 0)
                    throw new Error(`Failed to demangle the symbol ${element}`);

                return result.readCString()!;
            });
        }
    }
}

// Default Module
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

on('exec', (command: string) => {
    const res = eval(command);
    log('[EXEC]', res);
})