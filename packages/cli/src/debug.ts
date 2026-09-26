import type { DebugLogger } from "tg-secret-core";
import { c } from "./terminal.js";

/** With --debug, low-level details go to stderr, dimmed. */
export function debugLogger(enabled: boolean): DebugLogger | undefined {
  if (!enabled) return undefined;
  return (context, detail) => {
    const text = detail instanceof Error ? (detail.stack ?? detail.message) : String(detail);
    process.stderr.write(c.dim(`[debug] ${context}: ${text}`) + "\n");
  };
}
