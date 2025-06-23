import { ipcMain } from "electron";
import { FridaManager } from "./frida-manager"
import { StateManager } from "./state-manager"
import { sendRenderer } from "./util";
const init = async (fridaManager: FridaManager, stateManager: StateManager) => {
    // Example Code
    await fridaManager.selectDeviceByType('usb');
    const res = await fridaManager.loadScript("main-agent", stateManager.getState("target-app") as any);
    console.log(res);

    // Renderer -> Agent 통신 (UI에서 에이전트로)
    ipcMain.on('send-to-agent', (event, channel: string, ...args: any[]) => {
        console.log(`UI -> Agent: ${channel}`, args);
        fridaManager.send(channel, ...args);
    })

    // Agent -> Renderer 통신 (에이전트에서 UI로)
    fridaManager.on('send-to-renderer', (channel: string, ...args: any[]) => {
        console.log(`Agent -> UI: ${channel}`, args);
        sendRenderer(channel, ...args);
    })

    // 상태 변경 알림 (Agent -> Renderer)
    fridaManager.on('state-update', (key: string, value: any) => {
        console.log(`State update: ${key} =`, value);
        sendRenderer('state-changed', key, value);
    })
}
export default init;