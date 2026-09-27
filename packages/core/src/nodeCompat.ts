/**
 * Must be imported first (before teleproto and the vault).
 *
 * The local password is hashed with crypto.argon2Sync, which Node.js has since 24.7.
 * On older versions, fail right away with a clear message instead of on the first unlock.
 *
 * Node.js 25+ has a built-in `localStorage`; reading it without `--localstorage-file` prints
 * "Warning: `--localstorage-file` was provided without a valid path". store2, a teleproto
 * dependency (for its StoreSession, which we don't use), reads it on load, so the warning
 * lands in the middle of the app's output. The core doesn't need localStorage: unless the
 * app enabled it on purpose, hide it for this process.
 */
import * as nodeCrypto from "node:crypto";

export const MIN_NODE = "24.7";

if (typeof (nodeCrypto as { argon2Sync?: unknown }).argon2Sync !== "function") {
  throw new Error(`tg-secret needs Node.js ${MIN_NODE} or newer, this is ${process.version}`);
}

const enabledOnPurpose = [...process.execArgv, process.env.NODE_OPTIONS ?? ""].some((a) => a.includes("--localstorage-file"));
const builtIn = Object.getOwnPropertyDescriptor(globalThis, "localStorage");

if (!enabledOnPurpose && builtIn?.get && builtIn.configurable) {
  Object.defineProperty(globalThis, "localStorage", { value: undefined, configurable: true, writable: true });
}

