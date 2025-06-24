import { ipcMain } from "electron";
import { FridaManager } from "./frida-manager"
import { StateManager } from "./state-manager"
import { sendRenderer } from "./util";
const init = async (fridaManager: FridaManager, stateManager: StateManager) => {
    // From Agent
    // fridaManager.on("custom-event", (customArgs) => void);

    // To Agent
    // fridaManager.send("custom-event", customArgs);

    // From Renderer
    // ipcMain.on("custom-event", (customArgs) => void);

    // To Renderer
    // sendRenderer("custom-event", customArgs);

    // Change State
    // stateManager.setState('key', 'value', store);

    // Get State
    // stateManager.getState('key');
}
export default init;