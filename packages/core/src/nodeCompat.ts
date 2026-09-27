/**
 * Must be imported before teleproto.
 *
 * Node.js 25+ has a built-in `localStorage`; reading it without `--localstorage-file` prints
 * "Warning: `--localstorage-file` was provided without a valid path". store2, a teleproto
 * dependency (for its StoreSession, which we don't use), reads it on load, so the warning
 * lands in the middle of the app's output. The core doesn't need localStorage: unless the
 * app enabled it on purpose, hide it for this process.
 */
const enabledOnPurpose = [...process.execArgv, process.env.NODE_OPTIONS ?? ""].some((a) => a.includes("--localstorage-file"));
const builtIn = Object.getOwnPropertyDescriptor(globalThis, "localStorage");

if (!enabledOnPurpose && builtIn?.get && builtIn.configurable) {
  Object.defineProperty(globalThis, "localStorage", { value: undefined, configurable: true, writable: true });
}

export {};
