import { existsSync } from "node:fs";
import type { Vault } from "../security/vault.js";

export type SecretChatState =
  | "waiting" // we requested, peer has not accepted yet
  | "requested" // peer requested, we have not accepted yet
  | "ready"
  | "discarded";

export interface OutboxEntry {
  inSeqNo: number;
  outSeqNo: number;
  randomId: bigint;
  service: boolean;
  /** serialized DecryptedMessage (without the layer wrapper) */
  message: Buffer;
  /** server copy of the attached encrypted file, for resending */
  file?: { id: bigint; accessHash: bigint };
  /** not yet accepted by the server: sent again after a reconnect or restart */
  pending?: boolean;
  /** short text shown in delivery notifications for messages restored after a restart */
  preview?: string;
  /** uploaded (but not yet sent) file parts, to send a pending file message after a restart */
  upload?: { id: bigint; parts: number; big: boolean; fingerprint: number };
}

export interface PendingRekey {
  exchangeId: bigint;
  key: Buffer;
  fingerprint: bigint;
}

export interface SecretChat {
  id: number;
  accessHash: bigint;
  peerId: bigint;
  peerName: string;
  /** true if we created the chat (admin_id == self) */
  isOriginator: boolean;
  state: SecretChatState;
  createdAt: number;

  /** our DH secret while the handshake is in progress */
  dhSecret?: Buffer;
  /** peer's g_a for an incoming request */
  gA?: Buffer;

  key?: Buffer;
  /** previous key, kept after PFS re-key to decrypt late messages */
  prevKey?: Buffer;
  pendingRekey?: PendingRekey;

  peerLayer: number;
  layerNotified: boolean;
  /** number of messages we sent inside the seq_no sequence */
  rawOutSeq: number;
  /** number of messages received from the peer inside the sequence */
  rawInSeq: number;
  ttl: number;
  /** last sent messages, kept to satisfy decryptedMessageActionResend */
  outbox: OutboxEntry[];
}

export interface DhConfigCache {
  version: number;
  g: number;
  p: Buffer;
}

/** Position in the account's update stream, for updates.getDifference catch-up. */
export interface UpdatesState {
  pts: number;
  qts: number;
  date: number;
}

interface StoreData {
  dh?: DhConfigCache;
  updates?: UpdatesState;
  chats: Record<string, SecretChat>;
}

// Buffer and bigint don't survive JSON natively: tag them.
function replacer(this: unknown, _key: string, value: unknown): unknown {
  if (typeof value === "bigint") return { $n: value.toString() };
  if (value && typeof value === "object" && (value as { type?: string }).type === "Buffer" && Array.isArray((value as { data?: unknown }).data)) {
    return { $b: Buffer.from((value as { data: number[] }).data).toString("hex") };
  }
  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (value && typeof value === "object") {
    const v = value as { $n?: string; $b?: string };
    if (typeof v.$n === "string") return BigInt(v.$n);
    if (typeof v.$b === "string") return Buffer.from(v.$b, "hex");
  }
  return value;
}

/**
 * Secret chat state (including the chats' encryption keys), stored encrypted with the
 * account vault and kept decrypted only in memory.
 */
export class SecretStore {
  private data: StoreData;
  private closed = false;

  constructor(
    private readonly path: string,
    private readonly vault: Vault,
  ) {
    this.data = existsSync(path)
      ? (JSON.parse(vault.readFile(path, "secret-chats").toString("utf8"), reviver) as StoreData)
      : { chats: {} };
  }

  get dh(): DhConfigCache | undefined {
    return this.data.dh;
  }

  set dh(value: DhConfigCache | undefined) {
    this.data.dh = value;
    this.save();
  }

  get updatesState(): UpdatesState | undefined {
    return this.data.updates;
  }

  set updatesState(value: UpdatesState | undefined) {
    this.data.updates = value;
    this.save();
  }

  get(id: number): SecretChat | undefined {
    return this.data.chats[String(id)];
  }

  put(chat: SecretChat): void {
    this.data.chats[String(chat.id)] = chat;
    this.save();
  }

  /** Forgets a chat completely; its key material in memory is zeroed first. */
  remove(id: number): void {
    const chat = this.data.chats[String(id)];
    if (!chat) return;
    wipeChat(chat);
    delete this.data.chats[String(id)];
    this.save();
  }

  all(): SecretChat[] {
    return Object.values(this.data.chats).sort((a, b) => a.createdAt - b.createdAt);
  }

  save(): void {
    if (this.closed) return; // a late write after /lock must not persist wiped keys
    this.vault.writeFile(this.path, "secret-chats", Buffer.from(JSON.stringify(this.data, replacer)));
  }

  /** Overwrites all key material held in memory with zeros and stops persisting. */
  close(): void {
    this.closed = true;
    for (const chat of Object.values(this.data.chats)) wipeChat(chat);
    this.data = { chats: {} };
  }
}

/** Overwrites a chat's keys and queued plaintext messages with zeros. */
export function wipeChat(chat: SecretChat): void {
  for (const b of [chat.key, chat.prevKey, chat.dhSecret, chat.gA, chat.pendingRekey?.key]) b?.fill(0);
  for (const e of chat.outbox) e.message.fill(0);
}
