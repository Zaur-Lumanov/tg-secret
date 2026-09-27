import "../nodeCompat.js"; // before teleproto (see the file)
import { TelegramClient } from "teleproto";
import { Logger, LogLevel } from "teleproto/extensions/Logger.js";
import { StringSession } from "teleproto/sessions/index.js";

/**
 * Receives low-level details that are otherwise handled silently: network errors the client
 * recovers from, raw updates. Nothing is logged unless one is passed.
 */
export type DebugLogger = (context: string, detail: unknown) => void;

export const silent: DebugLogger = () => undefined;

/**
 * Creates a teleproto client that never gives up reconnecting and does not print
 * its internal errors: connection problems are surfaced via connection state events.
 */
export function createClient(session: string, apiId: number, apiHash: string, debug: DebugLogger = silent): TelegramClient {
  const client = new TelegramClient(new StringSession(session), apiId, apiHash, {
    connectionRetries: Number.POSITIVE_INFINITY,
    reconnectRetries: Number.POSITIVE_INFINITY,
    retryDelay: 3000,
    autoReconnect: true,
    // silent from the start: the default logger prints a version banner in the constructor
    baseLogger: new Logger(LogLevel.NONE),
  });
  client.onError = async (err) => debug("teleproto", err);
  return client;
}

/**
 * The Telegram error code of an RPC error ("FLOOD_WAIT_7", "ENCRYPTION_DECLINED"…), or the
 * message of any other error. Match error codes against this, never against String(e):
 * teleproto gives each RPC error its own class with a human-readable message, and the code
 * is only in `errorMessage`.
 */
export function rpcCode(e: unknown): string {
  const err = e as { errorMessage?: unknown; message?: unknown } | undefined;
  if (typeof err?.errorMessage === "string") return err.errorMessage;
  return typeof err?.message === "string" ? err.message : String(e);
}

/**
 * Transport-level failures (as opposed to RPC errors returned by Telegram):
 * the request may simply be retried once the connection is back.
 */
export function isNetworkError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if ("errorMessage" in err || "code" in err && typeof (err as { code: unknown }).code === "number") return false;
  return /TIMEOUT|disconnected|not connected|connection|ECONN|ETIMEDOUT|ENETUNREACH|EHOSTUNREACH|EAI_AGAIN|socket|closed/i.test(
    err.message + " " + String((err as { code?: unknown }).code ?? ""),
  );
}
