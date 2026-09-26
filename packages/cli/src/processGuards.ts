import { type DebugLogger, isNetworkError, silent } from "tg-secret-core";
import { c } from "./terminal.js";

/**
 * teleproto runs background loops (pings, reconnects, update fetching) whose failures can
 * surface as unhandled rejections. Network ones are expected and must not kill the app.
 */
export function installProcessGuards(debug: DebugLogger = silent): void {
  process.on("unhandledRejection", (reason) => {
    if (isNetworkError(reason)) debug("background", reason);
    else process.stderr.write(c.red(`Background error: ${reason instanceof Error ? reason.message : String(reason)}`) + "\n");
  });
  process.on("uncaughtException", (err) => {
    if (isNetworkError(err)) {
      debug("background", err);
      return;
    }
    process.stderr.write(c.red(`Fatal error: ${err.stack ?? err.message}`) + "\n");
    process.exit(1);
  });
}
