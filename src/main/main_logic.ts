import { ipcMain } from "electron/main";
import { FridaManager } from "./frida-manager"
import { StateManager } from "./state-manager"
const init = async (fridaManager: FridaManager, stateManager: StateManager) => {
    await fridaManager.selectDeviceByType('usb');
    const res = await fridaManager.loadScript("main-agent", "com.HoYoverse.Nap");
    console.log(res);
}
export default init;