import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { openAccount } from "../src/account.js";
import type { Prompts } from "../src/prompts.js";
import { AccessManager } from "../src/security/access.js";
import { Vault, WrongPasswordError } from "../src/security/vault.js";
import { TgSecret } from "../src/tgSecret.js";

const noPrompts = new Proxy({}, { get: () => () => { throw new Error("unexpected prompt"); } }) as unknown as Prompts;

/** A session without a network connection, to test the event forwarding in isolation. */
function offlineSession(): { session: TgSecret; chats: EventEmitter } {
  const account = openAccount(mkdtempSync(join(tmpdir(), "tgf-")), "+79990000000");
  const Ctor = TgSecret as unknown as new (...args: unknown[]) => TgSecret;
  const session = new Ctor(account, noPrompts, undefined, () => undefined);
  const chats = new EventEmitter();
  (session as unknown as { forward(c: EventEmitter): void }).forward(chats);
  return { session, chats };
}

test("chat events are re-emitted by the session", () => {
  const { session, chats } = offlineSession();
  const seen: string[] = [];
  chats.on("message", (_chat, msg: { text: string }) => seen.push("manager:" + msg.text));
  session.on("message", (_chat, msg) => seen.push("session:" + msg.text));
  chats.emit("message", {}, { text: "hi" });
  assert.deepEqual(seen, ["manager:hi", "session:hi"]);
});

test("an error is delivered to whoever listens, and thrown only if nobody does", () => {
  const { session, chats } = offlineSession();
  assert.throws(() => chats.emit("error", new Error("boom")), /boom/);

  const errors: string[] = [];
  session.on("error", (e) => errors.push(e.message));
  assert.doesNotThrow(() => chats.emit("error", new Error("handled")));
  assert.deepEqual(errors, ["handled"]);
});

test("access: verify and change the password; the password slot can't be removed", async () => {
  const path = join(mkdtempSync(join(tmpdir(), "tga-")), "vault.json");
  const vault = Vault.create(path, "first-password", { memory: 1024, passes: 1, parallelism: 1 });
  const access = new AccessManager(vault, noPrompts, "79990000000");

  assert.equal(access.verifyPassword("first-password"), true);
  assert.equal(access.verifyPassword("nope-nope"), false);
  await assert.rejects(access.changePassword("nope-nope", "second-password"), WrongPasswordError);
  await assert.rejects(access.changePassword("first-password", "short"), /shorter than/);
  await assert.rejects(access.changePassword("first-password", "first-password"), /same as the current/);

  await access.changePassword("first-password", "second-password");
  assert.equal(access.verifyPassword("second-password"), true);
  assert.equal(access.verifyPassword("first-password"), false);

  const [password] = access.list();
  await assert.rejects(access.remove(password.id), /can't be removed/);
  await assert.rejects(access.remove("missing"), /not found/);
});
