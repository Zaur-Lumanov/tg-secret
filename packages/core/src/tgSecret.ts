import { EventEmitter } from "node:events";
import type { TelegramClient } from "teleproto";
import { lockAccount, openAccount, type Account } from "./account.js";
import { ensureAuthorized } from "./auth/login.js";
import { resolveDataDir, type DataDirOptions } from "./dataDir.js";
import type { DebugLogger } from "./net/client.js";
import type { Prompts } from "./prompts.js";
import { LockedError, SecretChatManager, type SecretChatEvents } from "./secret/manager.js";
import { SecretStore } from "./secret/store.js";
import { AccessManager } from "./security/access.js";
import { TempFiles } from "./security/tempFiles.js";
import type { Vault } from "./security/vault.js";

export interface OpenOptions extends DataDirOptions {
  /** in any format: "+79991234567", "7 (999) 123-45-67" */
  phone: string;
  /** how the core asks the user for codes, passwords, PINs and choices */
  prompts: Prompts;
  /** the local password of an already encrypted account, instead of asking (no retries) */
  password?: string;
  /** receives low-level details that are otherwise handled silently */
  debug?: DebugLogger;
}

export type TgSecretEvents = SecretChatEvents & {
  /** keys were wiped and the connection closed; unlock() continues */
  locked: [];
  unlocked: [];
};

interface Unlocked {
  client: TelegramClient;
  vault: Vault;
  chats: SecretChatManager;
  access: AccessManager;
}

/** Best effort: zero teleproto's copy of the authorization key before dropping the client. */
async function destroyClient(client: TelegramClient): Promise<void> {
  try {
    await client.disconnect();
  } catch {
    // already disconnected
  }
  client.session.getAuthKey()?.getKey()?.fill(0);
}

/**
 * A signed-in account with its secret chats: the entry point of the library.
 *
 *   const session = await TgSecret.open({ phone: "+79991234567", prompts });
 *   session.on("message", (chat, msg) => console.log(chat.peerName, msg.text));
 *   await session.chats.sendText(chatId, "hello");
 *   await session.close();
 *
 * The account is reserved for this process until close(). Chat events are re-emitted by the
 * session itself, so listeners survive lock() / unlock(); `chats` and `access` are available
 * only while unlocked.
 */
export class TgSecret extends EventEmitter<TgSecretEvents> {
  private current?: Unlocked;
  private readonly temp = new TempFiles();
  private closed = false;

  private constructor(
    readonly account: Account,
    private readonly prompts: Prompts,
    private readonly debug: DebugLogger | undefined,
    private readonly releaseAccount: () => void,
  ) {
    super();
  }

  /**
   * Opens the account: unlocks its local storage, signs in if needed (asking through the
   * prompts) and starts the secret chats. Throws AccountLockedError if another process has
   * it open, TooManyAttemptsError after too many wrong passwords.
   */
  static async open(options: OpenOptions): Promise<TgSecret> {
    TempFiles.sweepStale();
    const account = openAccount(resolveDataDir(options), options.phone);
    const release = lockAccount(account);
    const session = new TgSecret(account, options.prompts, options.debug, release);
    try {
      await session.start(options.password);
    } catch (e) {
      await session.close();
      throw e;
    }
    return session;
  }

  /** "+79991234567" */
  get phone(): string {
    return "+" + this.account.phone;
  }

  /** The account's display name; undefined while locked. */
  get name(): string | undefined {
    return this.account.info?.name;
  }

  get locked(): boolean {
    return !this.current;
  }

  get chats(): SecretChatManager {
    return this.unlocked().chats;
  }

  get access(): AccessManager {
    return this.unlocked().access;
  }

  /** Asks for the local password (or another unlock method) again and reconnects. */
  async unlock(): Promise<void> {
    if (this.closed) throw new Error("The session is closed");
    if (this.current) return;
    await this.start();
    this.emit("unlocked");
  }

  /**
   * Wipes the keys from memory, closes the connection and deletes temporary decrypted files.
   * The account stays reserved for this process; unsent messages are kept for unlock().
   */
  async lock(): Promise<void> {
    const cur = this.current;
    if (!cur) return;
    this.current = undefined;
    cur.chats.close();
    cur.vault.lock();
    this.temp.wipe();
    await destroyClient(cur.client);
    this.account.info = undefined;
    this.emit("locked");
  }

  /** lock() and release the account for other processes. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.lock();
    this.temp.wipe();
    this.releaseAccount();
  }

  private unlocked(): Unlocked {
    if (!this.current) throw new LockedError();
    return this.current;
  }

  private async start(password?: string): Promise<void> {
    const { client, vault } = await ensureAuthorized(this.prompts, this.account, { password, debug: this.debug });
    const chats = new SecretChatManager(client, new SecretStore(this.account.secretStorePath, vault), {
      downloadsDir: this.account.downloadsDir,
      vault,
      temp: this.temp,
      debug: this.debug,
    });
    this.forward(chats);
    try {
      await chats.start();
    } catch (e) {
      chats.close();
      vault.lock();
      await destroyClient(client);
      throw e;
    }
    this.current = { client, vault, chats, access: new AccessManager(vault, this.prompts, this.account.phone) };
  }

  /**
   * Re-emits every chat event on the session. An "error" nobody listens to (neither on the
   * manager nor on the session) is thrown, as EventEmitter does.
   */
  private forward(chats: SecretChatManager): void {
    const emitOwn = chats.emit.bind(chats) as (event: string, ...args: unknown[]) => boolean;
    const emitSession = this.emit.bind(this) as (event: string, ...args: unknown[]) => boolean;
    (chats as { emit: (event: string, ...args: unknown[]) => boolean }).emit = (event, ...args) => {
      if (event === "error" && chats.listenerCount("error") === 0 && this.listenerCount("error") === 0) {
        throw args[0];
      }
      const own = event === "error" && chats.listenerCount("error") === 0 ? false : emitOwn(event, ...args);
      const forwarded = event === "error" && this.listenerCount("error") === 0 ? false : emitSession(event, ...args);
      return own || forwarded;
    };
  }
}
