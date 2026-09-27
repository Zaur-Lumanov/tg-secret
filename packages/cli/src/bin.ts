#!/usr/bin/env node
/**
 * The `tg-secret` / `tg-secret-cli` command. Checks the Node.js version before loading
 * anything else: on an older one, the core would fail on import with a stack trace.
 */
const [major = 0, minor = 0] = process.versions.node.split(".").map(Number);
if (major < 24 || (major === 24 && minor < 7)) {
  console.error(`tg-secret needs Node.js 24.7 or newer, this is ${process.version}. Update Node.js: https://nodejs.org`);
  process.exit(1);
}

await import("./main.js");
