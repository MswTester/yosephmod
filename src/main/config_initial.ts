interface setupConfig {
    key: string;
    default: any;
    store: boolean;
}
const init_config: setupConfig[] = [
    {key: "mainBounds", default: {x: 0, y: 0, width: 800, height: 600}, store: true},
]
export default init_config