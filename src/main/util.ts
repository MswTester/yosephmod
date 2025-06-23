import { BrowserWindow } from "electron";

export const sendRenderer = (channel: string, ...args: any[]) => {
    BrowserWindow.getAllWindows().forEach((window) => {
        if(!window.isDestroyed()) window.webContents.send(channel, ...args);
    })
}