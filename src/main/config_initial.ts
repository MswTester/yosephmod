interface setupConfig {
    key: string;
    default: any;
    store: boolean;
}
const init_config: setupConfig[] = [
    {key: "mainBounds", default: {x: 0, y: 0, width: 1200, height: 800}, store: true},
    {key: "test", default: "0", store: false},
]
export default init_config