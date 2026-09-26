import { homedir } from "node:os";
import { join, resolve } from "node:path";

/** Shared with the tg-secret CLI: accounts signed in there can be used from code and vice versa. */
export const SHARED_DIR_NAME = "tg-secret";
/** Used with `storage: "separate"`, next to the shared directory. */
export const SEPARATE_DIR_NAME = "tg-secret-core";

export interface DataDirOptions {
  /** An explicit directory for all data. Can't be combined with `storage`. */
  dataDir?: string;
  /**
   * - "shared" (default): the same directory as the tg-secret CLI;
   * - "separate": a directory of its own, next to the shared one.
   */
  storage?: "shared" | "separate";
}

/**
 * Where per-user application data lives on this platform. Windows uses the local (not the
 * roaming) profile: keys and downloads should not be synced to a domain server.
 */
export function platformDataRoot(): string {
  const env = process.env;
  switch (process.platform) {
    case "win32":
      return env.LOCALAPPDATA || join(homedir(), "AppData", "Local");
    case "darwin":
      return join(homedir(), "Library", "Application Support");
    default:
      return env.XDG_DATA_HOME || join(homedir(), ".local", "share");
  }
}

export function resolveDataDir(options: DataDirOptions = {}): string {
  if (options.dataDir !== undefined) {
    if (options.storage !== undefined) throw new Error('Specify either "dataDir" or "storage", not both');
    return resolve(options.dataDir);
  }
  return join(platformDataRoot(), options.storage === "separate" ? SEPARATE_DIR_NAME : SHARED_DIR_NAME);
}
