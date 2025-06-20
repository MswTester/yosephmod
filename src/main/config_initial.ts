interface setupConfig {
    key: string;
    default: any;
    store: boolean;
}
const init_config: setupConfig[] = [
    {key: "main-bounds", default: {x: 0, y: 0, width: 600, height: 800}, store: true},
]
export default init_config