import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import bigInt from "big-integer";
import { Api, type TelegramClient } from "teleproto";
import { CustomFile } from "teleproto/client/uploads.js";
import { Raw } from "teleproto/events/index.js";
import { UpdateConnectionState } from "teleproto/network/index.js";
import { isNetworkError, rpcCode, silent, type DebugLogger } from "../net/client.js";
import type { TempFiles } from "../security/tempFiles.js";
import { secureDelete, type Vault } from "../security/vault.js";
import { extensionFor, prepareFile, sanitizeFileName, uniquePath } from "../media/files.js";
import {
  decryptFile,
  decryptSecretMessage,
  encryptFile,
  encryptSecretMessage,
  keyFingerprint,
  readFingerprint,
} from "./crypto.js";
import type { DecryptedMedia, FileMedia } from "./media.js";
import { bufToBig, computeSharedKey, generateKeyPair, validateDhParams } from "./dh.js";
import {
  DEFAULT_PEER_LAYER,
  OUR_LAYER,
  decodeEnvelope,
  encodeLayer,
  encodeMessage,
  type DecryptedAction,
  type DecryptedEnvelope,
  type DecryptedMessage,
} from "./schema.js";
import { wipeChat, type OutboxEntry, type SecretChat, type SecretStore } from "./store.js";

const OUTBOX_LIMIT = 200;
/** Between the encrypted "clear history" and the discard in deleteChat. */
export let DELETE_FLUSH_PAUSE_MS = 2000;
export function setDeleteFlushPause(ms: number): void {
  DELETE_FLUSH_PAUSE_MS = ms;
}
const HISTORY_LIMIT = 100;
/** Files are encrypted in memory; keep that bounded. */
export const MAX_SEND_SIZE = 512 * 1024 * 1024;

/** Delivery state of an outgoing message. */
export type SendStatus = "sending" | "queued" | "sent" | "failed";

export interface ChatMessage {
  randomId: bigint;
  out: boolean;
  status?: SendStatus;
  /** why sending failed */
  error?: string;
  date: number;
  text: string;
  ttl: number;
  media?: DecryptedMedia;
  /** session-wide number for file media, used by /view, /download… */
  mediaId?: number;
  /** outgoing: the source file on disk */
  localPath?: string;
  /** incoming: the downloaded file, encrypted with the account vault */
  encryptedPath?: string;
  /** incoming: decrypted temporary copy made for an external viewer */
  tempPath?: string;
}

/** Server-side reference of an encrypted file attached to an incoming message. */
interface RemoteFile {
  id: bigint;
  accessHash: bigint;
  dcId: number;
  size: number;
  fingerprint: number;
}

interface MediaEntry {
  chatId: number;
  msg: ChatMessage;
  remote?: RemoteFile;
}

export interface SecretChatEvents {
  request: [chat: SecretChat];
  ready: [chat: SecretChat];
  discarded: [chat: SecretChat];
  /** chat removed with its history and files: by us (/delete) or by the peer */
  chatDeleted: [chat: SecretChat, byPeer: boolean];
  message: [chat: SecretChat, msg: ChatMessage];
  deleted: [chat: SecretChat, randomIds: bigint[]];
  info: [chat: SecretChat, text: string];
  typing: [chat: SecretChat];
  read: [chat: SecretChat, maxDate: number];
  /** connection to Telegram lost / restored */
  connection: [online: boolean];
  /** encrypted messages recovered via updates.getDifference after a reconnect or restart */
  caughtUp: [count: number];
  /** delivery status of an outgoing message changed */
  outgoing: [chat: SecretChat, msg: ChatMessage, prev: SendStatus | undefined];
  /** every queued message has been either sent or has failed */
  queueDrained: [sent: number, failed: number];
  error: [error: Error, chat?: SecretChat];
}

const toBI = (v: bigint) => bigInt(v.toString());
const fromBI = (v: { toString(): string }) => BigInt(v.toString());
const randomLong = () => randomBytes(8).readBigInt64LE();
const now = () => Math.floor(Date.now() / 1000);

interface BufferedIncoming {
  env: DecryptedEnvelope;
  date: number;
  file?: RemoteFile;
}

export interface SecretChatManagerOptions {
  /** incoming files are saved (encrypted) to <downloadsDir>/<chatId>/ */
  downloadsDir: string;
  vault: Vault;
  temp: TempFiles;
  debug?: DebugLogger;
}

/** Thrown into pending operations when the session is locked. */
export class LockedError extends Error {
  constructor() {
    super("Session is locked");
  }
}

/**
 * Implements Telegram secret chats (end-to-end encryption, layer 73, MTProto 2.0)
 * on top of a teleproto client.
 * https://core.telegram.org/api/end-to-end
 */
export class SecretChatManager extends EventEmitter<SecretChatEvents> {
  private selfId = 0n;
  /** serializes update processing so seq_no bookkeeping is never interleaved */
  private updateChain: Promise<void> = Promise.resolve();
  private sendChain: Promise<unknown> = Promise.resolve();
  private readonly history = new Map<number, ChatMessage[]>();
  /** out-of-order messages waiting for a gap to be filled, per chat, keyed by raw seq */
  private readonly pending = new Map<number, Map<number, BufferedIncoming>>();
  private readonly resendRequested = new Map<number, number>();
  private maxQts = 0;
  private qtsTimer?: NodeJS.Timeout;
  private readonly media = new Map<number, MediaEntry>();
  private nextMediaId = 1;
  private online = true;
  private onlineWaiters: (() => void)[] = [];
  /** users seen in getDifference results, for naming incoming requests */
  private readonly users = new Map<string, Api.User>();
  /** set while a send is stuck on the network: later sends are queued behind it */
  private sendBlocked = false;
  private readonly inflight = new Map<ChatMessage, SecretChat>();
  private readonly everQueued = new WeakSet<ChatMessage>();
  private queueStats = { outstanding: 0, sent: 0, failed: 0 };
  private readonly debug: DebugLogger;

  constructor(
    private readonly client: TelegramClient,
    private readonly store: SecretStore,
    private readonly options: SecretChatManagerOptions,
  ) {
    super();
    this.debug = options.debug ?? silent;
  }

  async start(): Promise<void> {
    const me = await this.client.getMe();
    this.selfId = fromBI(me.id);
    this.client.addEventHandler(
      (update: UpdateConnectionState) => this.onConnectionState(update.state),
      new Raw({ types: [UpdateConnectionState] }),
    );
    this.client.addEventHandler(
      (update: Api.TypeUpdate) => void this.enqueue(() => this.handleUpdate(update)),
      new Raw({
        types: [
          Api.UpdateEncryption,
          Api.UpdateNewEncryptedMessage,
          Api.UpdateEncryptedChatTyping,
          Api.UpdateEncryptedMessagesRead,
        ],
      }),
    );
    // Fetch what arrived while we were offline; this also makes the server push updates to us.
    await this.enqueue(() => this.syncUpdates());
  }

  /** Runs update processing strictly one at a time, so seq_no bookkeeping is never interleaved. */
  private enqueue(job: () => Promise<void>): Promise<void> {
    this.updateChain = this.updateChain.then(() => (this.closed ? undefined : job())).catch((e: unknown) => {
      if (this.closed) return;
      if (isNetworkError(e)) this.debug("update", e);
      else this.emit("error", asError(e));
    });
    return this.updateChain;
  }

  isOnline(): boolean {
    return this.online;
  }

  private onConnectionState(state: number): void {
    const online = state === UpdateConnectionState.connected;
    if (online === this.online) return;
    this.online = online;
    this.emit("connection", online);
    if (!online) {
      for (const [msg, chat] of this.inflight) this.setStatus(chat, msg, "queued");
    } else {
      for (const resolve of this.onlineWaiters.splice(0)) resolve();
      void this.enqueue(() => this.syncUpdates());
    }
  }

  /** Resolves when the connection is back (or after a short pause if we think we are online). */
  private waitOnline(): Promise<void> {
    if (this.online) return new Promise((r) => setTimeout(r, 2000));
    return new Promise((r) => this.onlineWaiters.push(r));
  }

  private closed = false;

  /**
   * Ends this manager for /lock: pending sends stop (they stay queued on disk),
   * key material in memory is zeroed, decrypted temp copies are wiped.
   */
  close(): void {
    this.closed = true;
    for (const resolve of this.onlineWaiters.splice(0)) resolve();
    if (this.qtsTimer) clearTimeout(this.qtsTimer);
    for (const { msg } of this.media.values()) if (msg.media?._ === "file") msg.media.key.fill(0);
    this.media.clear();
    this.history.clear();
    this.pending.clear();
    this.inflight.clear();
    this.store.close();
    this.removeAllListeners();
  }

  /**
   * Catches up on the secret chat update queue (qts) with updates.getDifference.
   * Live updates only arrive while connected; everything else must be fetched.
   */
  private async syncUpdates(): Promise<void> {
    const state = this.store.updatesState;
    if (!state) {
      const s = await this.client.invoke(new Api.updates.GetState());
      this.store.updatesState = { pts: s.pts, qts: s.qts, date: s.date };
      return;
    }

    let recovered = 0;
    for (;;) {
      let diff: Api.updates.TypeDifference;
      try {
        diff = await this.client.invoke(
          new Api.updates.GetDifference({ pts: state.pts, date: state.date, qts: state.qts, ptsTotalLimit: 1000 }),
        );
      } catch (e) {
        if (isNetworkError(e)) throw e;
        // e.g. a state too old to be served: start over from the current position
        this.debug("getDifference", e);
        const s = await this.client.invoke(new Api.updates.GetState());
        this.store.updatesState = { pts: s.pts, qts: s.qts, date: s.date };
        return;
      }

      if (diff instanceof Api.updates.DifferenceEmpty) {
        state.date = diff.date;
        break;
      }
      if (diff instanceof Api.updates.DifferenceTooLong) {
        // regular messages don't interest us: skip ahead, keep our qts
        state.pts = diff.pts;
        continue;
      }

      for (const u of diff.users) if (u instanceof Api.User) this.users.set(u.id.toString(), u);
      for (const u of diff.otherUpdates) {
        if (u instanceof Api.UpdateEncryption) await this.guard(() => this.onEncryptionUpdate(u.chat));
      }
      for (const em of diff.newEncryptedMessages) {
        await this.guard(() => this.onEncryptedMessage(em));
        recovered++;
      }

      const next = diff instanceof Api.updates.Difference ? diff.state : diff.intermediateState;
      state.pts = next.pts;
      state.qts = next.qts;
      state.date = next.date;
      this.store.updatesState = state;
      if (diff instanceof Api.updates.Difference) break;
    }
    this.store.updatesState = state;
    this.ackQts(state.qts);
    if (recovered) this.emit("caughtUp", recovered);
  }

  /** One bad message must not stop the rest of a batch. */
  private async guard(job: () => Promise<void>): Promise<void> {
    try {
      await job();
    } catch (e) {
      this.emit("error", asError(e));
    }
  }

  /** Records a qts seen in a live update; a jump means something was missed. */
  private trackQts(qts: number): void {
    const state = this.store.updatesState;
    if (!state) return;
    if (qts > state.qts + 1) {
      void this.enqueue(() => this.syncUpdates());
    } else if (qts > state.qts) {
      state.qts = qts;
    }
  }

  /**
   * Invokes a request, waiting for the connection and retrying on transport failures.
   * The factory builds a fresh request object for every attempt.
   */
  private async invokeReliably<R>(request: () => Promise<R>, onQueued: () => void): Promise<R> {
    for (;;) {
      if (this.closed) throw new LockedError();
      if (!this.online) {
        this.sendBlocked = true;
        onQueued();
        await this.waitOnline();
      }
      try {
        const result = await request();
        this.sendBlocked = false;
        return result;
      } catch (e) {
        if (!isNetworkError(e)) throw e;
        this.debug("send", e);
        this.sendBlocked = true;
        onQueued();
        await this.waitOnline();
      }
    }
  }

  private setStatus(chat: SecretChat, msg: ChatMessage, status: SendStatus, error?: string): void {
    const prev = msg.status;
    if (prev === status) return;
    msg.status = status;
    if (error) msg.error = error;
    const q = this.queueStats;
    if (status === "queued") {
      this.everQueued.add(msg);
      q.outstanding++;
    }
    if (prev === "queued") {
      q.outstanding--;
      if (status === "sent") q.sent++;
      else q.failed++;
    }
    this.emit("outgoing", chat, msg, prev);
    if (prev === "queued" && q.outstanding === 0) {
      this.emit("queueDrained", q.sent, q.failed);
      this.queueStats = { outstanding: 0, sent: 0, failed: 0 };
    }
  }

  /** Number of messages waiting to be sent (they are kept on disk across restarts). */
  pendingCount(): number {
    return this.store.all().reduce((n, ch) => n + ch.outbox.filter((e) => e.pending && !e.service).length, 0);
  }

  /**
   * Sends messages that were still queued when the app was closed, in their original order.
   * Called once the UI listens to events, so their delivery is reported.
   */
  resumePending(): void {
    for (const chat of this.store.all()) {
      const pending = chat.outbox.filter((e) => e.pending).sort((a, b) => a.outSeqNo - b.outSeqNo);
      if (!pending.length) continue;
      if (chat.state !== "ready") {
        for (const e of pending) e.pending = false;
        this.store.put(chat);
        continue;
      }
      for (const entry of pending) {
        const msg: ChatMessage | undefined = entry.service
          ? undefined
          : { randomId: entry.randomId, out: true, date: now(), text: entry.preview ?? "", ttl: chat.ttl };
        if (msg) this.setStatus(chat, msg, "queued");
        const upload =
          !entry.file && entry.upload
            ? entry.upload.big
              ? new Api.InputEncryptedFileBigUploaded({ id: toBI(entry.upload.id), parts: entry.upload.parts, keyFingerprint: entry.upload.fingerprint })
              : new Api.InputEncryptedFileUploaded({
                  id: toBI(entry.upload.id),
                  parts: entry.upload.parts,
                  md5Checksum: "",
                  keyFingerprint: entry.upload.fingerprint,
                })
            : undefined;
        this.transmit(chat, entry, { upload, msg }).catch((e: unknown) => this.debug("resume", e));
      }
    }
  }

  list(): SecretChat[] {
    return this.store.all();
  }

  get(id: number): SecretChat | undefined {
    return this.store.get(id);
  }

  getHistory(id: number): ChatMessage[] {
    return this.history.get(id) ?? [];
  }

  // ------------------------------------------------------------ handshake

  private async getDhConfig(): Promise<{ g: number; p: bigint; random: Buffer }> {
    const cached = this.store.dh;
    const res = await this.client.invoke(
      new Api.messages.GetDhConfig({ version: cached?.version ?? 0, randomLength: 256 }),
    );
    if (res instanceof Api.messages.DhConfig) {
      const p = bufToBig(res.p);
      validateDhParams(res.g, p);
      this.store.dh = { version: res.version, g: res.g, p: res.p };
      return { g: res.g, p, random: res.random };
    }
    if (!cached) throw new Error("DH config not modified, but nothing is cached");
    return { g: cached.g, p: bufToBig(cached.p), random: res.random };
  }

  /** Starts a new secret chat with a user (username, phone or id). */
  async requestChat(user: string): Promise<SecretChat> {
    const entity = await this.client.getEntity(user);
    if (!(entity instanceof Api.User)) throw new Error("Secret chats are only possible with users");
    const { g, p, random } = await this.getDhConfig();
    const kp = generateKeyPair(g, p, random);

    const res = await this.client.invoke(
      new Api.messages.RequestEncryption({
        userId: entity,
        randomId: randomBytes(4).readInt32LE(),
        gA: kp.pub,
      }),
    );
    if (!(res instanceof Api.EncryptedChatWaiting)) {
      throw new Error(`Unexpected response to requestEncryption: ${res.className}`);
    }
    const chat: SecretChat = {
      id: res.id,
      accessHash: fromBI(res.accessHash),
      peerId: fromBI(entity.id),
      peerName: displayName(entity),
      isOriginator: true,
      state: "waiting",
      createdAt: now(),
      dhSecret: kp.secret,
      peerLayer: DEFAULT_PEER_LAYER,
      layerNotified: false,
      rawOutSeq: 0,
      rawInSeq: 0,
      ttl: 0,
      outbox: [],
    };
    this.store.put(chat);
    return chat;
  }

  async acceptChat(id: number): Promise<SecretChat> {
    const chat = this.require(id);
    if (chat.state !== "requested" || !chat.gA) throw new Error("This chat is not an incoming request");
    const { g, p, random } = await this.getDhConfig();
    const kp = generateKeyPair(g, p, random);
    const key = computeSharedKey(chat.gA, kp.secret, p);
    const fingerprint = keyFingerprint(key);

    const res = await this.client.invoke(
      new Api.messages.AcceptEncryption({
        peer: this.inputPeer(chat),
        gB: kp.pub,
        keyFingerprint: toBI(fingerprint),
      }),
    );
    if (!(res instanceof Api.EncryptedChat)) {
      throw new Error(`Unexpected response to acceptEncryption: ${res.className}`);
    }
    if (fromBI(res.keyFingerprint) !== fingerprint) throw new Error("Key fingerprint mismatch");

    chat.key = key;
    chat.gA = undefined;
    chat.state = "ready";
    this.store.put(chat);
    this.emit("ready", chat);
    await this.notifyLayer(chat);
    return chat;
  }

  async declineChat(id: number): Promise<void> {
    await this.discard(id, true);
  }

  async discard(id: number, deleteHistory = false): Promise<void> {
    const chat = this.require(id);
    try {
      await this.client.invoke(new Api.messages.DiscardEncryption({ chatId: id, deleteHistory }));
    } catch (e) {
      // ENCRYPTION_ALREADY_DECLINED etc. — the chat is gone either way
      if (!/ENCRYPTION_(ALREADY_DECLINED|ID_INVALID)/.test(rpcCode(e))) throw e;
    }
    this.markDiscarded(chat);
  }

  /**
   * Clears the history on both sides, the chat itself stays: an encrypted
   * decryptedMessageActionFlushHistory for the peer, local messages and files wiped.
   */
  async clearHistory(id: number): Promise<void> {
    const chat = this.requireReady(id);
    if (!this.online) throw new Error("no connection to Telegram — history was not cleared, try again once the connection is back");
    await this.sendService(chat, { _: "flushHistory" });
    this.wipeLocalHistory(chat);
  }

  private wipeLocalHistory(chat: SecretChat): void {
    this.dropFromHistory(chat.id, this.getHistory(chat.id).map((m) => m.randomId));
    this.history.delete(chat.id);
    rmSync(join(this.options.downloadsDir, String(chat.id)), { recursive: true, force: true });
  }

  /**
   * Deletes a chat for both sides (discardEncryption with delete_history) and removes
   * everything local: the chat and its keys, the history in memory, downloaded files.
   * An already finished chat is only removed locally.
   */
  async deleteChat(id: number): Promise<void> {
    const chat = this.require(id);
    if (chat.state !== "discarded" && !this.online) {
      throw new Error("no connection to Telegram — the chat was not deleted on either side, try again once the connection is back");
    }
    if (chat.state === "ready") {
      // Clear the history through the chat itself first: a live Telegram iOS doesn't apply
      // delete_history from the discard until restart. The pause lets the peer process the flush
      // before the discard arrives: sent back to back, the flush's state write seemed to undo
      // the "terminated" state on iOS (the chat stayed writable).
      try {
        await this.sendService(chat, { _: "flushHistory" });
        await new Promise((r) => setTimeout(r, DELETE_FLUSH_PAUSE_MS));
      } catch (e) {
        this.debug("flushHistory", e); // best effort: the discard still closes the chat
      }
    }
    // The same request official clients send (Telegram iOS RemovePeerChat.swift).
    if (chat.state !== "discarded") {
      try {
        const res = await this.client.invoke(new Api.messages.DiscardEncryption({ chatId: id, deleteHistory: true }));
        this.debug("discardEncryption", `chat ${id}, delete_history → ${String(res)}`);
      } catch (e) {
        this.debug("discardEncryption", e);
        if (!/ENCRYPTION_(ALREADY_DECLINED|ID_INVALID)/.test(rpcCode(e))) throw e;
      }
    }
    this.removeLocally(chat, false);
  }

  private removeLocally(chat: SecretChat, byPeer: boolean): void {
    chat.state = "discarded"; // anything still queued for this chat must not use the wiped key
    this.wipeLocalHistory(chat);
    this.pending.delete(chat.id);
    this.resendRequested.delete(chat.id);
    this.store.remove(chat.id);
    this.emit("chatDeleted", chat, byPeer);
  }

  private markDiscarded(chat: SecretChat): void {
    if (chat.state === "discarded") return;
    chat.state = "discarded";
    wipeChat(chat);
    chat.key = chat.prevKey = chat.dhSecret = chat.gA = undefined;
    chat.pendingRekey = undefined;
    chat.outbox = [];
    this.store.put(chat);
    this.emit("discarded", chat);
  }

  // ------------------------------------------------------------ sending

  async sendText(id: number, text: string): Promise<ChatMessage> {
    const chat = this.requireReady(id);
    const randomId = randomLong();
    const msg: ChatMessage = { randomId, out: true, date: now(), text, ttl: chat.ttl, status: "sending" };
    this.pushHistory(chat.id, msg);
    await this.deliver(msg, () => this.sendDecrypted(chat, { _: "message", randomId, ttl: chat.ttl, text }, { msg }));
    return msg;
  }

  /**
   * Awaits delivery. Once a message has been queued its outcome is reported through
   * "outgoing" events, so its failure is not thrown again to the caller.
   */
  private async deliver(msg: ChatMessage, send: () => Promise<void>): Promise<void> {
    try {
      await send();
    } catch (e) {
      if (!this.everQueued.has(msg)) throw e;
    }
  }

  /**
   * Sends a local file. asPhoto: compressed photo with preview (like "send as photo"
   * in official apps); otherwise the file is sent unchanged as a document.
   */
  async sendFile(id: number, path: string, caption = "", asPhoto = true): Promise<ChatMessage> {
    const chat = this.requireReady(id);
    const { size } = statSync(path);
    if (size > MAX_SEND_SIZE) throw new Error(`Files larger than ${MAX_SEND_SIZE / 1024 / 1024} MB are not supported`);

    const prepared = await prepareFile(path, readFileSync(path), asPhoto);
    const enc = encryptFile(prepared.data);

    const media: FileMedia = {
      _: "file",
      kind: prepared.kind,
      mimeType: prepared.mimeType,
      size: prepared.data.length,
      key: enc.key,
      iv: enc.iv,
      fileName: prepared.kind === "photo" ? undefined : prepared.fileName,
      w: prepared.w,
      h: prepared.h,
      thumb: prepared.thumb,
      caption: "",
    };
    const randomId = randomLong();
    const msg: ChatMessage = { randomId, out: true, date: now(), text: caption, ttl: chat.ttl, media, localPath: path, status: "sending" };
    this.pushHistory(chat.id, msg);

    await this.deliver(msg, async () => {
      this.inflight.set(msg, chat);
      let uploaded: Api.InputFile | Api.InputFileBig;
      try {
        // the upload needs the network too: wait for it just like the message itself
        uploaded = await this.invokeReliably(
          () => this.client.uploadFile({ file: new CustomFile(prepared.fileName, enc.data.length, "", enc.data), workers: 4 }),
          () => this.setStatus(chat, msg, "queued"),
        );
      } catch (e) {
        this.inflight.delete(msg);
        if (msg.status === "queued") this.setStatus(chat, msg, "failed", errorText(e));
        throw e;
      }
      const big = uploaded instanceof Api.InputFileBig;
      const inputFile = big
        ? new Api.InputEncryptedFileBigUploaded({ id: uploaded.id, parts: uploaded.parts, keyFingerprint: enc.fingerprint })
        : new Api.InputEncryptedFileUploaded({ id: uploaded.id, parts: uploaded.parts, md5Checksum: "", keyFingerprint: enc.fingerprint });
      const uploadRef = { id: fromBI(uploaded.id), parts: uploaded.parts, big, fingerprint: enc.fingerprint };
      await this.sendDecrypted(chat, { _: "message", randomId, ttl: chat.ttl, text: caption, media }, { upload: inputFile, uploadRef, msg });
    });
    return msg;
  }

  getMedia(mediaId: number): { chat: SecretChat; msg: ChatMessage; downloadable: boolean } {
    const entry = this.media.get(mediaId);
    const chat = entry && this.store.get(entry.chatId);
    if (!entry || !chat) throw new Error(`File #${mediaId} not found`);
    return { chat, msg: entry.msg, downloadable: !!entry.remote };
  }

  /** Downloads, verifies and decrypts an incoming file; returns the local path. */
  /** Downloads, verifies and decrypts an incoming file, then stores it encrypted with the vault. */
  async downloadMedia(mediaId: number): Promise<string> {
    const entry = this.media.get(mediaId);
    if (!entry) throw new Error(`File #${mediaId} not found`);
    if (entry.msg.encryptedPath) return entry.msg.encryptedPath;
    const media = entry.msg.media;
    const remote = entry.remote;
    if (media?._ !== "file" || !remote) throw new Error(`Message #${mediaId} has no file to download`);

    const data = await this.client.downloadFile(
      new Api.InputEncryptedFileLocation({ id: toBI(remote.id), accessHash: toBI(remote.accessHash) }),
      { dcId: remote.dcId, fileSize: bigInt(remote.size) },
    );
    if (!Buffer.isBuffer(data)) throw new Error("Failed to download the file");
    const plain = decryptFile(data.subarray(0, remote.size), media.key, media.iv, media.size, remote.fingerprint);

    const dir = join(this.options.downloadsDir, String(entry.chatId));
    mkdirSync(dir, { recursive: true });
    const path = uniquePath(dir, this.fileNameOf(entry.msg) + ".enc");
    try {
      this.options.vault.writeFile(path, "file", plain);
    } finally {
      plain.fill(0);
    }
    entry.msg.encryptedPath = path;
    return path;
  }

  private fileNameOf(msg: ChatMessage): string {
    const media = msg.media as FileMedia;
    return sanitizeFileName(media.fileName, `${media.kind}_${msg.date}${extensionFor(media.mimeType)}`);
  }

  /**
   * A plaintext path an external program can open: the source file for outgoing
   * messages, a decrypted temporary copy for incoming ones (downloaded first if needed).
   */
  async openablePath(mediaId: number): Promise<string> {
    const entry = this.media.get(mediaId);
    if (!entry) throw new Error(`File #${mediaId} not found`);
    const msg = entry.msg;
    if (msg.out) {
      if (!msg.localPath || !existsSync(msg.localPath)) throw new Error("The original file no longer exists");
      return msg.localPath;
    }
    if (msg.tempPath && existsSync(msg.tempPath)) return msg.tempPath;
    const encrypted = await this.downloadMedia(mediaId);
    const plain = this.options.vault.readFile(encrypted, "file");
    try {
      msg.tempPath = this.options.temp.write(this.fileNameOf(msg), plain);
    } finally {
      plain.fill(0);
    }
    return msg.tempPath;
  }

  async setTtl(id: number, ttl: number): Promise<void> {
    const chat = this.requireReady(id);
    chat.ttl = ttl;
    this.store.put(chat);
    await this.sendService(chat, { _: "setTtl", ttl });
  }

  async sendTyping(id: number): Promise<void> {
    const chat = this.requireReady(id);
    await this.client.invoke(new Api.messages.SetEncryptedTyping({ peer: this.inputPeer(chat), typing: true }));
  }

  async markRead(id: number, maxDate: number): Promise<void> {
    const chat = this.requireReady(id);
    await this.client.invoke(new Api.messages.ReadEncryptedHistory({ peer: this.inputPeer(chat), maxDate }));
  }

  async deleteMessages(id: number, randomIds: bigint[]): Promise<void> {
    const chat = this.requireReady(id);
    await this.sendService(chat, { _: "delete", randomIds });
    this.dropFromHistory(chat.id, randomIds);
  }

  private sendService(chat: SecretChat, action: DecryptedAction): Promise<void> {
    return this.sendDecrypted(chat, { _: "service", randomId: randomLong(), action });
  }

  private async notifyLayer(chat: SecretChat): Promise<void> {
    if (chat.layerNotified) return;
    chat.layerNotified = true;
    await this.sendService(chat, { _: "notifyLayer", layer: OUR_LAYER });
  }

  /** Wraps a message into DecryptedMessageLayer with the next seq_no, encrypts and sends it. */
  private sendDecrypted(
    chat: SecretChat,
    message: DecryptedMessage,
    opts: { upload?: Api.TypeInputEncryptedFile; uploadRef?: OutboxEntry["upload"]; msg?: ChatMessage } = {},
  ): Promise<void> {
    // seq_no = 2*raw + x, x: in_seq_no 0 / out_seq_no 1 for the chat originator, inverse for the other side
    const inSeqNo = 2 * chat.rawInSeq + (chat.isOriginator ? 0 : 1);
    const outSeqNo = 2 * chat.rawOutSeq + (chat.isOriginator ? 1 : 0);
    chat.rawOutSeq++;
    const entry: OutboxEntry = {
      inSeqNo,
      outSeqNo,
      randomId: message.randomId,
      service: message._ === "service",
      message: encodeMessage(message, chat.peerLayer),
      pending: true,
      preview: opts.msg && previewText(opts.msg),
      upload: opts.uploadRef,
    };
    chat.outbox.push(entry);
    if (chat.outbox.length > OUTBOX_LIMIT) chat.outbox.splice(0, chat.outbox.length - OUTBOX_LIMIT);
    this.store.put(chat);
    return this.transmit(chat, entry, { upload: opts.upload, msg: opts.msg });
  }

  /**
   * Sends an outbox entry. A file message is sent with the freshly uploaded file the first
   * time; the server's EncryptedFile is remembered so a resend can reference it again.
   */
  private transmit(
    chat: SecretChat,
    entry: OutboxEntry,
    { upload, msg }: { upload?: Api.TypeInputEncryptedFile; msg?: ChatMessage } = {},
  ): Promise<void> {
    // Something ahead of us is already waiting for the network: this one is queued too.
    if (msg && (!this.online || this.sendBlocked)) this.setStatus(chat, msg, "queued");
    const onQueued = () => msg && this.setStatus(chat, msg, "queued");

    const job = this.sendChain.then(async () => {
      if (msg) this.inflight.set(msg, chat);
      try {
        // re-read: the chat may have been discarded while the message waited in the queue
        const key = chat.state === "ready" ? chat.key : undefined;
        if (!key) throw new Error("ENCRYPTION_DECLINED");
        const payload = encodeLayer({ layer: OUR_LAYER, inSeqNo: entry.inSeqNo, outSeqNo: entry.outSeqNo }, entry.message);
        const data = encryptSecretMessage(key, chat.isOriginator ? 0 : 8, payload);
        const params = { peer: this.inputPeer(chat), randomId: toBI(entry.randomId), data };
        const file =
          upload ??
          (entry.file && new Api.InputEncryptedFile({ id: toBI(entry.file.id), accessHash: toBI(entry.file.accessHash) }));

        if (file) {
          const res = await this.invokeReliably(
            () => this.client.invoke(new Api.messages.SendEncryptedFile({ ...params, file })),
            onQueued,
          );
          if (res instanceof Api.messages.SentEncryptedFile && res.file instanceof Api.EncryptedFile) {
            entry.file = { id: fromBI(res.file.id), accessHash: fromBI(res.file.accessHash) };
          }
        } else if (entry.service) {
          await this.invokeReliably(() => this.client.invoke(new Api.messages.SendEncryptedService(params)), onQueued);
        } else {
          await this.invokeReliably(() => this.client.invoke(new Api.messages.SendEncrypted(params)), onQueued);
        }
      } catch (e) {
        // locked: the entry stays pending on disk and is sent after the next unlock
        if (this.closed) throw e;
        // RANDOM_ID_DUPLICATE: a retry after a lost response, the server already has the message.
        if (!/RANDOM_ID_DUPLICATE/.test(rpcCode(e))) {
          entry.pending = false; // not a network problem: retrying would not help
          this.store.save();
          // The server says the chat is gone: the peer closed it and we missed the update.
          if (CHAT_GONE.test(rpcCode(e)) && chat.state === "ready") {
            this.emit("info", chat, "the peer ended or deleted this chat");
            this.markDiscarded(chat);
          }
          if (msg) {
            this.inflight.delete(msg);
            this.setStatus(chat, msg, "failed", errorText(e));
          }
          throw e;
        }
      }
      entry.pending = false;
      entry.upload = undefined;
      this.store.save();
      if (msg) {
        this.inflight.delete(msg);
        this.setStatus(chat, msg, "sent");
      }
    });
    this.sendChain = job.catch(() => undefined);
    return job;
  }

  // ------------------------------------------------------------ updates

  private async handleUpdate(update: Api.TypeUpdate): Promise<void> {
    if (this.options.debug) {
      const detail = update instanceof Api.UpdateEncryption ? ` ${update.chat.className} id=${update.chat.id}` +
        (update.chat instanceof Api.EncryptedChatDiscarded ? ` historyDeleted=${!!update.chat.historyDeleted}` : "") : "";
      this.debug("update", update.className + detail);
    }
    if (update instanceof Api.UpdateEncryption) {
      await this.onEncryptionUpdate(update.chat);
    } else if (update instanceof Api.UpdateNewEncryptedMessage) {
      try {
        await this.onEncryptedMessage(update.message);
      } finally {
        this.trackQts(update.qts);
        this.ackQts(update.qts);
      }
    } else if (update instanceof Api.UpdateEncryptedChatTyping) {
      const chat = this.store.get(update.chatId);
      if (chat) this.emit("typing", chat);
    } else if (update instanceof Api.UpdateEncryptedMessagesRead) {
      const chat = this.store.get(update.chatId);
      if (chat) this.emit("read", chat, update.maxDate);
    }
  }

  /** Acknowledges received encrypted messages (messages.receivedQueue), batched. */
  private ackQts(qts: number): void {
    this.maxQts = Math.max(this.maxQts, qts);
    if (this.qtsTimer) return;
    this.qtsTimer = setTimeout(() => {
      this.qtsTimer = undefined;
      this.store.save();
      this.client
        .invoke(new Api.messages.ReceivedQueue({ maxQts: this.maxQts }))
        .catch((e: unknown) => this.debug("receivedQueue", e)); // the next ack or getDifference covers it
    }, 500);
  }

  private async onEncryptionUpdate(ec: Api.TypeEncryptedChat): Promise<void> {
    if (ec instanceof Api.EncryptedChatRequested) {
      if (fromBI(ec.participantId) !== this.selfId || this.store.get(ec.id)) return;
      const peerId = fromBI(ec.adminId);
      const chat: SecretChat = {
        id: ec.id,
        accessHash: fromBI(ec.accessHash),
        peerId,
        peerName: await this.resolveName(peerId),
        isOriginator: false,
        state: "requested",
        createdAt: now(),
        gA: ec.gA,
        peerLayer: DEFAULT_PEER_LAYER,
        layerNotified: false,
        rawOutSeq: 0,
        rawInSeq: 0,
        ttl: 0,
        outbox: [],
      };
      this.store.put(chat);
      this.emit("request", chat);
      return;
    }

    const chat = this.store.get(ec.id);
    if (!chat) return;

    if (ec instanceof Api.EncryptedChatDiscarded) {
      // the peer asked to delete the history too: honour it
      if (ec.historyDeleted) this.removeLocally(chat, true);
      else this.markDiscarded(chat);
    } else if (ec instanceof Api.EncryptedChatWaiting) {
      chat.accessHash = fromBI(ec.accessHash);
      this.store.put(chat);
    } else if (ec instanceof Api.EncryptedChat && chat.state === "waiting") {
      // The peer accepted our request: finish the DH exchange.
      const dh = this.store.dh;
      if (!chat.dhSecret || !dh) throw new Error(`Chat ${chat.id}: missing DH state`);
      const key = computeSharedKey(ec.gAOrB, chat.dhSecret, bufToBig(dh.p));
      if (keyFingerprint(key) !== fromBI(ec.keyFingerprint)) {
        await this.discard(chat.id);
        throw new Error(`Chat ${chat.id}: key fingerprint mismatch, chat discarded`);
      }
      chat.key = key;
      chat.dhSecret = undefined;
      chat.accessHash = fromBI(ec.accessHash);
      chat.state = "ready";
      this.store.put(chat);
      this.emit("ready", chat);
      await this.notifyLayer(chat);
    }
  }

  private async onEncryptedMessage(em: Api.TypeEncryptedMessage): Promise<void> {
    const chat = this.store.get(em.chatId);
    if (!chat || chat.state !== "ready" || !chat.key) return;

    const key = this.pickKey(chat, readFingerprint(em.bytes));
    const payload = decryptSecretMessage(key, chat.isOriginator ? 8 : 0, em.bytes);
    const env = decodeEnvelope(payload);
    const file =
      em instanceof Api.EncryptedMessage && em.file instanceof Api.EncryptedFile
        ? {
            id: fromBI(em.file.id),
            accessHash: fromBI(em.file.accessHash),
            dcId: em.file.dcId,
            size: Number(em.file.size.toString()),
            fingerprint: em.file.keyFingerprint,
          }
        : undefined;

    if (!env.layer) {
      // legacy layer-8 message, no sequence numbers
      await this.process(chat, env, em.date, file);
      return;
    }

    if (env.layer.layer > chat.peerLayer) {
      chat.peerLayer = env.layer.layer;
      this.store.put(chat);
    }

    const peerParity = chat.isOriginator ? 0 : 1;
    const out = env.layer.outSeqNo;
    if (out < 0 || (out - peerParity) % 2 !== 0) {
      throw new Error(`Chat ${chat.id}: invalid out_seq_no ${out}`);
    }
    const raw = (out - peerParity) / 2;

    if (raw < chat.rawInSeq) return; // duplicate
    if (raw > chat.rawInSeq) {
      // gap: stash the message and ask the peer to resend the missing range
      let queue = this.pending.get(chat.id);
      if (!queue) this.pending.set(chat.id, (queue = new Map()));
      queue.set(raw, { env, date: em.date, file });
      if (this.resendRequested.get(chat.id) !== chat.rawInSeq) {
        this.resendRequested.set(chat.id, chat.rawInSeq);
        const start = 2 * chat.rawInSeq + peerParity;
        const end = out - 2;
        this.emit("info", chat, `missed messages (seq ${start}..${end}), resend requested`);
        await this.sendService(chat, { _: "resend", startSeqNo: start, endSeqNo: end });
      }
      return;
    }

    await this.acceptInSequence(chat, env, em.date, file);
    const queue = this.pending.get(chat.id);
    while (queue?.has(chat.rawInSeq)) {
      const next = queue.get(chat.rawInSeq)!;
      queue.delete(chat.rawInSeq);
      await this.acceptInSequence(chat, next.env, next.date, next.file);
    }
  }

  private async acceptInSequence(chat: SecretChat, env: DecryptedEnvelope, date: number, file?: RemoteFile): Promise<void> {
    chat.rawInSeq++;
    this.store.put(chat);
    await this.process(chat, env, date, file);
  }

  /** Selects the key a message was encrypted with, switching to a pending PFS key if needed. */
  private pickKey(chat: SecretChat, fingerprint: bigint): Buffer {
    if (chat.key && keyFingerprint(chat.key) === fingerprint) return chat.key;
    if (chat.pendingRekey && chat.pendingRekey.fingerprint === fingerprint) {
      // The initiator already uses the new key: the exchange is complete.
      this.commitRekey(chat);
      return chat.key!;
    }
    if (chat.prevKey && keyFingerprint(chat.prevKey) === fingerprint) return chat.prevKey;
    throw new Error(`Chat ${chat.id}: message encrypted with an unknown key`);
  }

  private commitRekey(chat: SecretChat): void {
    if (!chat.pendingRekey) return;
    chat.prevKey = chat.key;
    chat.key = chat.pendingRekey.key;
    chat.pendingRekey = undefined;
    this.store.put(chat);
    this.emit("info", chat, "encryption key updated (PFS)");
  }

  private async process(chat: SecretChat, env: DecryptedEnvelope, date: number, file?: RemoteFile): Promise<void> {
    const m = env.message;
    if (m._ === "message") {
      const msg: ChatMessage = { randomId: m.randomId, out: false, date, text: m.text, ttl: m.ttl, media: m.media };
      this.pushHistory(chat.id, msg, m.media?._ === "file" ? file : undefined);
      this.emit("message", chat, msg);
      return;
    }
    await this.processAction(chat, m.action);
  }

  private async processAction(chat: SecretChat, a: DecryptedAction): Promise<void> {
    switch (a._) {
      case "notifyLayer":
        chat.peerLayer = Math.max(chat.peerLayer, a.layer);
        this.store.put(chat);
        await this.notifyLayer(chat);
        break;
      case "setTtl":
        chat.ttl = a.ttl;
        this.store.put(chat);
        this.emit("info", chat, a.ttl ? `the peer set the self-destruct timer: ${a.ttl} s` : "the peer turned off the self-destruct timer");
        break;
      case "delete":
        this.dropFromHistory(chat.id, a.randomIds);
        this.emit("deleted", chat, a.randomIds);
        break;
      case "flushHistory":
        this.wipeLocalHistory(chat);
        this.emit("info", chat, "the peer cleared the history");
        break;
      case "screenshot":
        this.emit("info", chat, "the peer took a screenshot");
        break;
      case "read":
        break;
      case "typing":
        this.emit("typing", chat);
        break;
      case "resend":
        await this.resend(chat, a.startSeqNo, a.endSeqNo);
        break;
      case "requestKey":
        await this.onRequestKey(chat, a.exchangeId, a.gA);
        break;
      case "commitKey":
        if (chat.pendingRekey?.exchangeId === a.exchangeId && chat.pendingRekey.fingerprint === a.fingerprint) {
          this.commitRekey(chat);
          await this.sendService(chat, { _: "noop" });
        } else {
          await this.sendService(chat, { _: "abortKey", exchangeId: a.exchangeId });
        }
        break;
      case "abortKey":
        if (chat.pendingRekey?.exchangeId === a.exchangeId) {
          chat.pendingRekey = undefined;
          this.store.put(chat);
        }
        break;
      case "acceptKey":
        // we never initiate re-keying, so there is nothing to accept
        await this.sendService(chat, { _: "abortKey", exchangeId: a.exchangeId });
        break;
      case "noop":
      case "unknown":
        break;
    }
  }

  /** PFS: the peer initiated re-keying, we act as side B. https://core.telegram.org/api/end-to-end/pfs */
  private async onRequestKey(chat: SecretChat, exchangeId: bigint, gA: Buffer): Promise<void> {
    const { g, p, random } = await this.getDhConfig();
    const kp = generateKeyPair(g, p, random);
    const key = computeSharedKey(gA, kp.secret, p);
    const fingerprint = keyFingerprint(key);
    chat.pendingRekey = { exchangeId, key, fingerprint };
    this.store.put(chat);
    // AcceptKey is still encrypted with the current key
    await this.sendService(chat, { _: "acceptKey", exchangeId, gB: kp.pub, fingerprint });
  }

  private async resend(chat: SecretChat, start: number, end: number): Promise<void> {
    const entries = chat.outbox.filter((e) => e.outSeqNo >= start && e.outSeqNo <= end);
    for (const e of entries) {
      await this.transmit(chat, e);
    }
    const expected = Math.floor((end - start) / 2) + 1;
    if (entries.length < expected) {
      this.emit("info", chat, `could not resend ${expected - entries.length} message(s) (not in outbox)`);
    }
  }

  // ------------------------------------------------------------ helpers

  private pushHistory(id: number, msg: ChatMessage, remote?: RemoteFile): void {
    if (msg.media?._ === "file") {
      msg.mediaId = this.nextMediaId++;
      this.media.set(msg.mediaId, { chatId: id, msg, remote });
    }
    let list = this.history.get(id);
    if (!list) this.history.set(id, (list = []));
    list.push(msg);
    if (list.length > HISTORY_LIMIT) list.splice(0, list.length - HISTORY_LIMIT);
  }

  /** Removes messages; files we downloaded for them are deleted from disk too. */
  private dropFromHistory(id: number, randomIds: bigint[]): void {
    const drop = new Set(randomIds);
    for (const [mediaId, entry] of this.media) {
      if (entry.chatId !== id || !drop.has(entry.msg.randomId)) continue;
      if (entry.msg.encryptedPath) rmSync(entry.msg.encryptedPath, { force: true });
      if (entry.msg.tempPath) {
        try {
          secureDelete(entry.msg.tempPath);
        } catch {
          // open in a viewer; the temp directory is wiped on exit
        }
      }
      this.media.delete(mediaId);
    }
    const list = this.history.get(id);
    if (list) this.history.set(id, list.filter((m) => !drop.has(m.randomId)));
  }

  private inputPeer(chat: SecretChat): Api.InputEncryptedChat {
    return new Api.InputEncryptedChat({ chatId: chat.id, accessHash: toBI(chat.accessHash) });
  }

  private require(id: number): SecretChat {
    const chat = this.store.get(id);
    if (!chat) throw new Error(`Secret chat ${id} not found`);
    return chat;
  }

  private requireReady(id: number): SecretChat {
    const chat = this.require(id);
    if (chat.state !== "ready") throw new Error(`Secret chat ${id} is not active (${chat.state})`);
    return chat;
  }

  private async resolveName(userId: bigint): Promise<string> {
    const known = this.users.get(userId.toString());
    if (known) return displayName(known);
    try {
      const entity = await this.client.getEntity(toBI(userId));
      if (entity instanceof Api.User) return displayName(entity);
    } catch {
      // not in the entity cache
    }
    return `user${userId}`;
  }
}

export function displayName(u: Api.User): string {
  const name = [u.firstName, u.lastName].filter(Boolean).join(" ");
  return name || (u.username ? `@${u.username}` : `user${u.id}`);
}

function asError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

/** Short description of an outgoing message for delivery notifications. */
export function previewText(msg: ChatMessage): string {
  const kind = msg.media?._ === "file" ? (msg.media.kind === "photo" ? "Photo" : (msg.media.fileName ?? "File")) : "";
  const text = [kind && `[${kind}]`, msg.text].filter(Boolean).join(" ");
  return text.length > 60 ? text.slice(0, 57) + "…" : text;
}

const CHAT_GONE = /ENCRYPTION_DECLINED|ENCRYPTION_ID_INVALID|CHAT_ID_INVALID/;

const KNOWN_ERRORS: [RegExp, string][] = [
  [/ENCRYPTION_DECLINED|ENCRYPTION_ID_INVALID|CHAT_ID_INVALID/, "the secret chat has ended"],
  [/FILE_PART|FILE_PARTS_INVALID|FILE_ID_INVALID/, "the uploaded file expired on the server — send it again"],
  [/FLOOD_WAIT_(\d+)/, "Telegram temporarily limited sending, try again in $1 s"],
  [/USER_IS_BLOCKED|YOU_BLOCKED_USER/, "the user is blocked"],
  [/MSG_TOO_LONG|MESSAGE_TOO_LONG/, "the message is too long"],
];

/** Human-readable text for errors returned by Telegram. */
export function errorText(e: unknown): string {
  const raw = rpcCode(e);
  for (const [re, text] of KNOWN_ERRORS) {
    const m = re.exec(raw);
    if (m) return text.replace("$1", m[1] ?? "");
  }
  return raw;
}
