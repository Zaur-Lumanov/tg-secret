import { spawn } from "node:child_process";
import { dirname } from "node:path";
import { isDangerous } from "tg-secret-core";

function launch(command: string, args: string[], windowsVerbatimArguments = false): void {
  const child = spawn(command, args, { detached: true, stdio: "ignore", windowsVerbatimArguments });
  child.on("error", () => undefined);
  child.unref();
}

/** Opens a file with the application associated with its type. No shell is involved. */
export function openWithSystem(path: string): void {
  if (isDangerous(path)) throw new Error("This file type can run programs. Use /reveal and decide for yourself.");
  if (process.platform === "win32") launch("explorer.exe", [path]);
  else if (process.platform === "darwin") launch("open", [path]);
  else launch("xdg-open", [path]);
}

/** Shows the file in the system file manager. */
export function revealInFolder(path: string): void {
  // explorer expects /select,"C:\path" literally; our file names never contain quotes
  if (process.platform === "win32") launch("explorer.exe", [`/select,"${path}"`], true);
  else if (process.platform === "darwin") launch("open", ["-R", path]);
  else launch("xdg-open", [dirname(path)]);
}
