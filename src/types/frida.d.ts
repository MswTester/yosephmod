declare module 'frida' {
    export * from 'frida';
    const frida: typeof import('frida');
    export default frida;
}