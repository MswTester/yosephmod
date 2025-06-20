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
    {key: "main-bounds", default: {x: 0, y: 0, width: 400, height: 600}, store: true},
    {key: "device", default: null, store: false},
    {key: "session", default: null, store: false},
]);
export default init_config;