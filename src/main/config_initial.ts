interface setupConfig {
    key: string;
    default: any;
    store: boolean;
}
export default function init_config(): setupConfig[] {
    return [
        {key: "", default: "", store: false}
    ]
}