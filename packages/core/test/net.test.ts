import assert from "node:assert/strict";
import { test } from "node:test";
import { isNetworkError, rpcCode } from "../src/net/client.js";
import { errorText } from "../src/secret/manager.js";
import { RPCMessageToError } from "teleproto/errors/index.js";

test("isNetworkError: transport failures are retryable, Telegram RPC errors are not", () => {
  const sys = Object.assign(new Error("connect ETIMEDOUT 149.154.167.51:80"), { code: "ETIMEDOUT" });
  assert.ok(isNetworkError(sys));
  assert.ok(isNetworkError(new Error("TIMEOUT")));
  assert.ok(isNetworkError(new Error("Cannot send requests while disconnected. Please reconnect.")));
  assert.ok(isNetworkError(new Error("Not connected")));
  assert.ok(isNetworkError(new Error("NetSocket was closed")));

  const rpc = Object.assign(new Error("400: PEER_ID_INVALID"), { code: 400, errorMessage: "PEER_ID_INVALID" });
  assert.ok(!isNetworkError(rpc));
  const flood = Object.assign(new Error("420: FLOOD_WAIT_30 (caused by messages.SendEncrypted) connection"), {
    code: 420,
    errorMessage: "FLOOD_WAIT_30",
  });
  assert.ok(!isNetworkError(flood));
  assert.ok(!isNetworkError(new Error("File not found")));
  assert.ok(!isNetworkError("TIMEOUT"));
});

test("rpcCode: the Telegram error code of teleproto's per-error classes, the message otherwise", () => {
  const rpc = (code: string) => RPCMessageToError({ errorCode: 400, errorMessage: code } as never, { className: "messages.SendEncrypted" } as never);
  // teleproto's messages are human-readable and don't contain the code
  assert.ok(!String(rpc("ENCRYPTION_DECLINED")).includes("ENCRYPTION_DECLINED"));
  assert.equal(rpcCode(rpc("ENCRYPTION_DECLINED")), "ENCRYPTION_DECLINED");
  assert.equal(rpcCode(rpc("FLOOD_WAIT_7")), "FLOOD_WAIT_7");
  assert.equal(rpcCode(new Error("Code is empty")), "Code is empty");
  assert.equal(rpcCode("plain"), "plain");
  assert.equal(errorText(rpc("FLOOD_WAIT_7")), "Telegram temporarily limited sending, try again in 7 s");
  assert.equal(errorText(rpc("USER_IS_BLOCKED")), "the user is blocked");
  assert.ok(!isNetworkError(rpc("TIMEOUT")), "an RPC error is never a transport failure");
});
