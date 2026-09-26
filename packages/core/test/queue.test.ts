import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Api, type TelegramClient } from "teleproto";
import { SecretChatManager, setDeleteFlushPause, type ChatMessage, type SendStatus } from "../src/secret/manager.js";

setDeleteFlushPause(0);
import { SecretStore, type SecretChat } from "../src/secret/store.js";
import { TempFiles } from "../src/security/tempFiles.js";
import { Vault } from "../src/security/vault.js";

const FAST_KDF = { memory: 1024, passes: 1, parallelism: 1 };

type Handler = (req: unknown) => Promise<unknown>;

/** Just enough of TelegramClient for sending: invoke() is scripted by the test. */
function fakeClient(handler: { current: Handler }): TelegramClient {
  return {
    invoke: (req: unknown) => {
      if (req instanceof Api.updates.GetState) return Promise.resolve({ pts: 1, qts: 0, date: 0 });
      return handler.current(req);
    },
  } as unknown as TelegramClient;
}

function readyChat(): SecretChat {
  return {
    id: 42,
    accessHash: 1n,
    peerId: 7n,
    peerName: "Peer",
    isOriginator: true,
    state: "ready",
    createdAt: 0,
    key: randomBytes(256),
    peerLayer: 144,
    layerNotified: true,
    rawOutSeq: 0,
    rawInSeq: 0,
    ttl: 0,
    outbox: [],
  };
}

function newStore(): SecretStore {
  const dir = mkdtempSync(join(tmpdir(), "tgq-"));
  return new SecretStore(join(dir, "chats.enc"), Vault.create(join(dir, "vault.json"), "test-password", FAST_KDF));
}

function setup(handler: { current: Handler }, store?: SecretStore) {
  const s = store ?? newStore();
  if (!store) s.put(readyChat());
  const internals = s as unknown as { vault: Vault };
  const manager = new SecretChatManager(fakeClient(handler), s, {
    downloadsDir: mkdtempSync(join(tmpdir(), "tgd-")),
    vault: internals.vault,
    temp: new TempFiles(),
  });
  const events: string[] = [];
  manager.on("outgoing", (_c, msg: ChatMessage, prev?: SendStatus) => events.push(`${prev ?? "-"}>${msg.status}:${msg.text}`));
  manager.on("queueDrained", (sent, failed) => events.push(`drained:${sent}/${failed}`));
  manager.on("error", () => undefined);
  const setOnline = (online: boolean) =>
    (manager as unknown as { onConnectionState(s: number): void }).onConnectionState(online ? 1 : -1);
  return { manager, store: s, events, setOnline };
}

const tick = () => new Promise((r) => setTimeout(r, 20));
const netError = () => Object.assign(new Error("connect ETIMEDOUT 149.154.167.51:80"), { code: "ETIMEDOUT" });

test("offline: messages are queued, then sent in order after reconnect", async () => {
  const sent: string[] = [];
  const handler = { current: async (req: unknown) => { sent.push(String((req as { className: string }).className)); return {}; } };
  const { manager, events, setOnline, store } = setup(handler);

  setOnline(false);
  const p1 = manager.sendText(42, "first");
  const p2 = manager.sendText(42, "second");
  await tick();
  assert.deepEqual(events, ["sending>queued:first", "sending>queued:second"]);
  assert.equal(manager.pendingCount(), 2);
  assert.equal(sent.length, 0);

  setOnline(true);
  await Promise.all([p1, p2]);
  assert.deepEqual(events.slice(2), ["queued>sent:first", "queued>sent:second", "drained:2/0"]);
  assert.deepEqual(sent, ["messages.SendEncrypted", "messages.SendEncrypted"]);
  assert.equal(manager.pendingCount(), 0);
  assert.ok(store.get(42)!.outbox.every((e) => !e.pending));
});

test("network error while sending: queued, retried after reconnect", async () => {
  let calls = 0;
  const handler = {
    current: async () => {
      calls++;
      if (calls === 1) throw netError();
      return {};
    },
  };
  const { manager, events, setOnline } = setup(handler);

  const p = manager.sendText(42, "hello");
  await tick();
  assert.deepEqual(events, ["sending>queued:hello"]);
  setOnline(false);
  setOnline(true);
  await p;
  assert.deepEqual(events, ["sending>queued:hello", "queued>sent:hello", "drained:1/0"]);
  assert.equal(calls, 2);
});

test("queued message rejected by Telegram after reconnect is reported as failed, not thrown", async () => {
  const handler = {
    current: async () => {
      throw Object.assign(new Error("400: ENCRYPTION_DECLINED"), { code: 400, errorMessage: "ENCRYPTION_DECLINED" });
    },
  };
  const { manager, events, setOnline } = setup(handler);

  setOnline(false);
  const p = manager.sendText(42, "too late");
  await tick();
  setOnline(true);
  await p; // resolves: the failure is reported through the event
  assert.deepEqual(events, ["sending>queued:too late", "queued>failed:too late", "drained:0/1"]);
  assert.equal(manager.pendingCount(), 0);
});

test("errors of a message that was never queued are thrown to the caller", async () => {
  const handler = {
    current: async () => {
      throw Object.assign(new Error("400: PEER_ID_INVALID"), { code: 400, errorMessage: "PEER_ID_INVALID" });
    },
  };
  const { manager } = setup(handler);
  await assert.rejects(manager.sendText(42, "x"), /PEER_ID_INVALID/);
});

test("pending messages survive a restart and are sent by resumePending", async () => {
  const offline = { current: async (): Promise<unknown> => { throw netError(); } };
  const first = setup(offline);
  first.setOnline(false);
  void first.manager.sendText(42, "from the previous session");
  await tick();
  assert.equal(first.manager.pendingCount(), 1);

  // "restart": a new manager over the same store file
  const sent: string[] = [];
  const online = { current: async (req: unknown) => { sent.push((req as { className: string }).className); return {}; } };
  const old = first.store as unknown as { path: string; vault: Vault };
  const second = setup(online, new SecretStore(old.path, old.vault));
  second.manager.resumePending();
  await tick();
  assert.deepEqual(second.events, ["->queued:from the previous session", "queued>sent:from the previous session", "drained:1/0"]);
  assert.deepEqual(sent, ["messages.SendEncrypted"]);
  assert.equal(second.manager.pendingCount(), 0);
});

test("deleteChat: discards with delete_history, removes the chat and its downloaded files", async () => {
  const calls: { className: string; deleteHistory?: boolean }[] = [];
  const handler = { current: async (req: unknown) => { calls.push(req as never); return true; } };
  const { manager, store } = setup(handler);
  const downloads = (manager as unknown as { options: { downloadsDir: string } }).options.downloadsDir;
  const chatDir = join(downloads, "42");
  mkdirSync(chatDir, { recursive: true });
  writeFileSync(join(chatDir, "photo.jpg.enc"), "x");
  const key = store.get(42)!.key!;
  const deleted: boolean[] = [];
  manager.on("chatDeleted", (_c, byPeer) => deleted.push(byPeer));

  await manager.deleteChat(42);

  // "clear history" through the chat, a pause, then the discard with delete_history
  assert.deepEqual(calls.map((c) => c.className), ["messages.SendEncryptedService", "messages.DiscardEncryption"]);
  assert.equal(calls[1].deleteHistory, true);
  assert.equal(store.get(42), undefined);
  assert.ok(!existsSync(chatDir));
  assert.ok(key.every((b) => b === 0), "key wiped");
  assert.deepEqual(deleted, [false]);
});

test("peer deletes the chat with history: it is removed locally too", async () => {
  const { manager, store } = setup({ current: async () => ({}) });
  const deleted: boolean[] = [];
  manager.on("chatDeleted", (_c, byPeer) => deleted.push(byPeer));
  await (manager as unknown as { handleUpdate(u: unknown): Promise<void> }).handleUpdate(
    new Api.UpdateEncryption({ chat: new Api.EncryptedChatDiscarded({ id: 42, historyDeleted: true }), date: 0 }),
  );
  assert.equal(store.get(42), undefined);
  assert.deepEqual(deleted, [true]);
});

test("deleteChat refuses to run offline instead of deleting only locally", async () => {
  const { manager, store, setOnline } = setup({ current: async () => true });
  setOnline(false);
  await assert.rejects(manager.deleteChat(42), /no connection/);
  assert.ok(store.get(42), "chat kept");
});

test("sending into a chat the server already closed marks it discarded", async () => {
  const handler = {
    current: async () => {
      throw Object.assign(new Error("400: ENCRYPTION_DECLINED"), { code: 400, errorMessage: "ENCRYPTION_DECLINED" });
    },
  };
  const { manager, store } = setup(handler);
  const infos: string[] = [];
  let discarded = 0;
  manager.on("info", (_c, text) => infos.push(text));
  manager.on("discarded", () => discarded++);

  await assert.rejects(manager.sendText(42, "hello"), /ENCRYPTION_DECLINED/);
  assert.equal(store.get(42)!.state, "discarded");
  assert.equal(discarded, 1);
  assert.ok(infos.some((t) => t.includes("ended or deleted")));
});

test("clearHistory: encrypted flush for the peer, local files wiped, chat kept", async () => {
  const calls: string[] = [];
  const { manager, store } = setup({ current: async (req: unknown) => { calls.push((req as { className: string }).className); return {}; } });
  const chatDir = join((manager as unknown as { options: { downloadsDir: string } }).options.downloadsDir, "42");
  mkdirSync(chatDir, { recursive: true });
  writeFileSync(join(chatDir, "doc.pdf.enc"), "x");
  await manager.sendText(42, "before clearing");

  await manager.clearHistory(42);

  assert.deepEqual(calls, ["messages.SendEncrypted", "messages.SendEncryptedService"]);
  assert.equal(manager.getHistory(42).length, 0);
  assert.ok(!existsSync(chatDir));
  assert.equal(store.get(42)!.state, "ready");
});
