import { existsSync } from "node:fs";
import { type ChatMessage, type DecryptedMedia, describeSlot, errorText, type FileMedia, isDangerous, isNetworkError, previewText, type SecretChat, type SecretChatManager, type TgSecret } from "tg-secret-core";
import { renderIdenticon, renderKeyHex } from "./keyVisual.js";
import { openWithSystem, revealInFolder } from "./system.js";
import { c, type Terminal } from "./terminal.js";

/** Windows Hello exists only on Windows: elsewhere the CLI doesn't mention it at all. */
const HELLO = process.platform === "win32";
/** Touch ID likewise only on macOS. */
const TOUCH_ID = process.platform === "darwin";

const HELP = `
${c.bold("Commands:")}
  /chats                  list secret chats
  /new <@username|+phone> start a secret chat
  /accept <id>            accept an incoming request
  /decline <id>           decline an incoming request
  /open <id>              open a chat (plain text is then sent to it)
  /close                  close the current chat
  /history                show the current chat history (this session only)
  /ttl <sec>              self-destruct timer (0 turns it off)
  /key                    encryption key visualization to compare with the peer
  /discard [id]           end a secret chat (it stays in the list)
  /clean [id]             clear history on both sides (the chat stays)
  /delete [id]            delete the chat on both sides: from the dialog list, with history, keys and files

${c.bold("Security:")}
  /passwd                 change the local password
  /access                 list unlock methods
  /access add yubikey [name]   add a YubiKey (PIN + touch)
${HELLO ? "  /access add hello [name]     add Windows Hello\n" : ""}${TOUCH_ID ? "  /access add touchid [name]   add Touch ID\n" : ""}  /access remove <N>      remove an unlock method
  /lock                   lock: keys are wiped from memory, the screen is cleared

${c.bold("Files:")}
  /send <path> [caption]  send a photo (compressed, with preview) or a file
  /file <path> [caption]  send a file uncompressed (as a document)
  /media                  files of the current chat
  /view <N>               open file #N in the default app (via a temporary copy)
  /reveal <N>             show file #N in its folder (a temporary decrypted copy)
  /download <N>           download large file #N
  Quote paths with spaces; you can also drag a file into the terminal window.

  /help                   this help
  /quit                   exit
`;

const STATE_LABEL: Record<SecretChat["state"], string> = {
  waiting: c.yellow("waiting for confirmation"),
  requested: c.magenta("incoming request"),
  ready: c.green("active"),
  discarded: c.dim("ended"),
};

const TYPING_THROTTLE_MS = 5000;
/**
 * On a flaky network (a slow VPN) the connection drops and comes back every few seconds.
 * The prompt and the notices follow it only once a state has held this long.
 */
const OFFLINE_NOTICE_MS = 5000;
const ONLINE_NOTICE_MS = 10_000;
/** Incoming files up to this size are downloaded and decrypted automatically. */
const AUTO_DOWNLOAD_LIMIT = 20 * 1024 * 1024;

const KIND_LABEL: Record<FileMedia["kind"], string> = {
  photo: "📷 Photo",
  video: "🎬 Video",
  audio: "🎵 Audio",
  voice: "🎤 Voice message",
  round: "⏺ Video message",
  gif: "GIF",
  sticker: "Sticker",
  document: "📎 File",
};

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

export type ReplResult = "quit" | "lock";

/** Whether the input line is a message being written (as opposed to a command or an answer). */
export function isTypingMessage(line: string, asking: boolean): boolean {
  const text = line.trimStart();
  return !asking && text.length > 0 && !text.startsWith("/");
}

/** Splits "<path> caption", where the path may be quoted (drag & drop quotes paths with spaces). */
export function splitPathArg(rest: string): { path: string; caption: string } {
  const m = /^\s*(?:"([^"]+)"|'([^']+)'|(\S+))\s*([\s\S]*)$/.exec(rest);
  if (!m) throw new Error("Specify a file path");
  return { path: m[1] ?? m[2] ?? m[3], caption: m[4].trim() };
}

export class Repl {
  private current?: number;
  private lastTyping = 0;
  /** connection state as shown to the user; lags behind the real one, see OFFLINE_NOTICE_MS */
  private shownOnline = true;
  private connectionTimer?: NodeJS.Timeout;

  private finish?: (result: ReplResult) => void;
  private readonly secret: SecretChatManager;

  /** One REPL per unlocked session: after /lock the CLI creates a new one. */
  constructor(
    private readonly term: Terminal,
    private readonly session: TgSecret,
  ) {
    this.secret = session.chats;
  }

  /** Runs until /quit (or Ctrl+C) → "quit", or /lock → "lock". Detaches its listeners either way. */
  run(): Promise<ReplResult> {
    this.term.replActive = true;
    this.shownOnline = this.secret.isOnline();
    this.bindEvents();
    this.updatePrompt();
    this.secret.resumePending();
    this.term.print(c.dim("Type /help for the list of commands."));

    const onKeypress = () => this.onKeypress();
    const onLine = (line: string) => {
      this.handleLine(line.trim())
        .catch((e: unknown) => this.term.print(c.red(`Error: ${errText(e)}`)))
        .finally(() => this.finish && this.term.prompt());
    };
    const onClose = () => this.finish?.("quit");
    process.stdin.on("keypress", onKeypress);
    this.term.rl.on("line", onLine);
    this.term.rl.on("close", onClose);

    return new Promise<ReplResult>((resolve) => {
      this.finish = (result) => {
        this.finish = undefined;
        this.term.replActive = false;
        clearTimeout(this.connectionTimer);
        process.stdin.off("keypress", onKeypress);
        this.term.rl.off("line", onLine);
        this.term.rl.off("close", onClose);
        const pending = this.secret.pendingCount();
        if (pending) {
          this.term.log(
            c.yellow(
              result === "lock"
                ? `${pending} message(s) queued — they will be sent after unlocking.`
                : `${pending} message(s) queued — they are saved and will be sent on the next start.`,
            ),
          );
        }
        resolve(result);
      };
    });
  }

  private bindEvents(): void {
    const s = this.secret;
    s.on("request", (chat) =>
      this.term.print(c.magenta(`★ Incoming secret chat request from ${chat.peerName} — /accept ${chat.id} or /decline ${chat.id}`)),
    );
    s.on("ready", (chat) => {
      this.term.print(
        c.green(`✔ Secret chat ${chat.id} with ${chat.peerName} is established.`) +
          c.dim(` /open ${chat.id} — open, /clean ${chat.id} — clear, /delete ${chat.id} — delete`),
      );
      if (this.current === undefined) this.open(chat.id);
    });
    s.on("chatDeleted", (chat, byPeer) => {
      this.term.print(
        c.dim(
          byPeer
            ? `🗑 ${chat.peerName} deleted secret chat ${chat.id} with its history — local data and files were deleted too`
            : `🗑 Secret chat ${chat.id} with ${chat.peerName} deleted`,
        ),
      );
      if (this.current === chat.id) this.close();
    });
    s.on("discarded", (chat) => {
      this.term.print(c.dim(`✖ Secret chat ${chat.id} with ${chat.peerName} ended`));
      if (this.current === chat.id) this.close();
    });
    s.on("message", (chat, msg) => {
      this.term.print(this.formatMessage(chat, msg));
      if (this.current === chat.id) {
        this.secret.markRead(chat.id, msg.date).catch(() => undefined);
      }
      if (msg.mediaId !== undefined && msg.media?._ === "file") {
        if (msg.media.size <= AUTO_DOWNLOAD_LIMIT) {
          this.download(msg.mediaId).catch((e: unknown) => this.term.print(c.red(`File #${msg.mediaId}: ${errText(e)}`)));
        } else {
          this.term.print(c.dim(`  ↳ large file — download it: /download ${msg.mediaId}`));
        }
      }
    });
    s.on("deleted", (chat, ids) => this.term.print(c.dim(`[${chat.peerName}] messages deleted: ${ids.length}`)));
    s.on("info", (chat, text) => this.term.print(c.cyan(`[${chat.peerName}] ${text}`)));
    s.on("typing", (chat) => {
      if (this.current === chat.id) this.term.print(c.dim(`${chat.peerName} is typing…`));
    });
    s.on("read", (chat) => {
      if (this.current === chat.id) this.term.print(c.dim("✓✓ read"));
    });
    s.on("error", (err, chat) => this.term.print(c.red(`Error${chat ? ` [${chat.id}]` : ""}: ${errText(err)}`)));
    s.on("connection", (online) => {
      clearTimeout(this.connectionTimer);
      if (online === this.shownOnline) return; // a short drop: nothing was shown, nothing to take back
      this.connectionTimer = setTimeout(
        () => {
          this.shownOnline = online;
          this.updatePrompt();
          this.term.print(
            online
              ? c.green("✔ Connection to Telegram restored")
              : c.yellow("⚠ No connection to Telegram — reconnecting. Messages will be sent once the connection is back."),
          );
        },
        online ? ONLINE_NOTICE_MS : OFFLINE_NOTICE_MS,
      );
    });
    s.on("caughtUp", (count) => this.term.print(c.dim(`Missed messages received: ${count}`)));
    s.on("outgoing", (chat, msg, prev) => {
      const what = `"${previewText(msg)}"` + (this.current === chat.id ? "" : ` → ${chat.peerName}`);
      if (msg.status === "queued") {
        this.term.print(c.yellow(`⏳ Offline: ${what} queued for sending`));
      } else if (prev === "queued" && msg.status === "sent") {
        this.term.print(c.green(`✔ Sent from the queue: ${what}`));
      } else if (prev === "queued" && msg.status === "failed") {
        this.term.print(c.red(`✖ Failed to send ${what}: ${msg.error}`));
      }
    });
    s.on("queueDrained", (sent, failed) => {
      const total = sent + failed;
      if (total < 2) return; // a single message was already reported on its own
      this.term.print(
        failed
          ? c.yellow(`Queue processed: ${sent} of ${total} sent, ${failed} failed`)
          : c.green(`Queue processed: all ${total} message(s) sent`),
      );
    });
  }

  private async handleLine(line: string): Promise<void> {
    if (!line) return;
    if (!line.startsWith("/")) {
      if (this.current === undefined) {
        this.term.print(c.yellow("No chat is open. /chats — list, /open <id> — open."));
        return;
      }
      await this.secret.sendText(this.current, line);
      return;
    }

    const [cmd, ...args] = line.split(/\s+/);
    const rest = line.slice(cmd.length);
    switch (cmd) {
      case "/send":
      case "/file": {
        const chat = this.currentChat();
        const { path, caption } = splitPathArg(rest);
        if (!existsSync(path)) throw new Error(`File not found: ${path}`);
        this.term.print(c.dim("Encrypting and uploading…"));
        const msg = await this.secret.sendFile(chat.id, path, caption, cmd === "/send");
        this.term.print(this.formatMessage(chat, msg));
        break;
      }
      case "/media": {
        const chat = this.currentChat();
        const files = this.secret.getHistory(chat.id).filter((m) => m.mediaId !== undefined);
        this.term.print(...(files.length ? files.map((m) => this.formatMessage(chat, m)) : [c.dim("(no files)")]));
        break;
      }
      case "/download":
        await this.download(this.numArg(args[0]));
        break;
      case "/view":
        openWithSystem(await this.localFile(this.numArg(args[0])));
        break;
      case "/reveal":
        revealInFolder(await this.localFile(this.numArg(args[0])));
        break;
      case "/help":
        this.term.print(HELP);
        break;
      case "/chats":
        this.listChats();
        break;
      case "/new": {
        if (!args[0]) throw new Error("Usage: /new <@username|+phone>");
        this.term.print(c.dim("Fetching DH parameters and sending the request…"));
        const chat = await this.secret.requestChat(args[0]);
        this.term.print(c.yellow(`Request sent (chat ${chat.id}), waiting for ${chat.peerName} to accept.`));
        break;
      }
      case "/accept": {
        // the "ready" event opens the chat if none is open
        await this.secret.acceptChat(this.idArg(args[0]));
        break;
      }
      case "/decline":
        await this.secret.declineChat(this.idArg(args[0]));
        break;
      case "/open":
        this.open(this.idArg(args[0]));
        break;
      case "/close":
        this.close();
        break;
      case "/history": {
        const chat = this.currentChat();
        const history = this.secret.getHistory(chat.id);
        this.term.print(...(history.length ? history.map((m) => this.formatMessage(chat, m)) : [c.dim("(empty)")]));
        break;
      }
      case "/ttl": {
        const ttl = Number(args[0]);
        if (!Number.isInteger(ttl) || ttl < 0) throw new Error("Usage: /ttl <seconds>");
        await this.secret.setTtl(this.currentChat().id, ttl);
        this.term.print(c.cyan(ttl ? `Self-destruct timer: ${ttl} s` : "Self-destruct timer off"));
        break;
      }
      case "/key": {
        const chat = this.currentChat();
        if (!chat.key) throw new Error("The key is not established yet");
        this.term.print(
          c.bold(`Encryption key of the chat with ${chat.peerName}:`),
          ...renderIdenticon(chat.key),
          "",
          ...renderKeyHex(chat.key),
          c.dim("Compare it with the key image in the peer's app."),
        );
        break;
      }
      case "/clean": {
        const chat = args[0] ? this.secret.get(this.idArg(args[0])) : this.currentChat();
        if (!chat) throw new Error(`Chat ${args[0]} not found`);
        if (!(await this.confirm(`Clear the history of the chat with ${chat.peerName} on both sides? Messages and downloaded files will be deleted, the chat stays.`))) break;
        await this.secret.clearHistory(chat.id);
        this.term.print(c.dim(`🧹 History of the chat with ${chat.peerName} cleared on both sides`));
        break;
      }
      case "/delete": {
        const chat = args[0] ? this.secret.get(this.idArg(args[0])) : this.currentChat();
        if (!chat) throw new Error(`Chat ${args[0]} not found`);
        const scope =
          chat.state === "discarded"
            ? "The chat has already ended — its local data and downloaded files will be deleted."
            : "The conversation will be deleted on both sides; keys and downloaded files will be deleted locally.";
        if (!(await this.confirm(`Delete secret chat ${chat.id} with ${chat.peerName}? ${scope}`))) break;
        if (chat.state === "ready") this.term.print(c.dim("Clearing the peer's history and deleting the chat…"));
        await this.secret.deleteChat(chat.id);
        break;
      }
      case "/discard": {
        const id = args[0] ? this.idArg(args[0]) : this.currentChat().id;
        await this.secret.discard(id);
        break;
      }
      case "/passwd":
        await this.changePassword();
        break;
      case "/access":
        await this.access(args, rest);
        break;
      case "/lock":
        this.finish?.("lock");
        break;
      case "/quit":
      case "/exit":
        this.term.close();
        break;
      default:
        this.term.print(c.yellow(`Unknown command ${cmd}. /help — help.`));
    }
  }

  private listChats(): void {
    const chats = this.secret.list();
    if (!chats.length) {
      this.term.print(c.dim("No secret chats. /new <@username> — start one."));
      return;
    }
    this.term.print(
      ...chats.map((chat) => {
        const mark = chat.id === this.current ? "›" : " ";
        const ttl = chat.ttl ? c.dim(` ttl=${chat.ttl}s`) : "";
        return `${mark} ${c.bold(String(chat.id))}  ${chat.peerName}  ${STATE_LABEL[chat.state]}${ttl}`;
      }),
    );
  }

  private open(id: number): void {
    const chat = this.secret.get(id);
    if (!chat) throw new Error(`Chat ${id} not found`);
    if (chat.state !== "ready") throw new Error(`Chat ${id}: ${STATE_LABEL[chat.state]}`);
    this.current = id;
    this.updatePrompt();
    this.term.print(c.dim(`Secret chat with ${chat.peerName} opened. /key — verify the key, /close — close, /clean — clear history, /delete — delete the chat.`));
    const last = this.secret.getHistory(id).at(-1);
    if (last && !last.out) this.secret.markRead(id, last.date).catch(() => undefined);
  }

  private close(): void {
    this.current = undefined;
    this.updatePrompt();
  }

  private currentChat(): SecretChat {
    if (this.current === undefined) throw new Error("No chat is open");
    return this.secret.get(this.current)!;
  }

  private numArg(arg: string | undefined): number {
    const n = Number(arg?.replace(/^#/, ""));
    if (!arg || !Number.isInteger(n)) throw new Error("Specify a file number, e.g. /view 3 (see /media)");
    return n;
  }

  /** Local path of a file message, downloading it first if needed. */
  /** A plaintext path for an external program (a temporary decrypted copy for incoming files). */
  private async localFile(mediaId: number): Promise<string> {
    const { msg } = this.secret.getMedia(mediaId);
    if (!msg.out && !msg.encryptedPath) await this.download(mediaId);
    return this.secret.openablePath(mediaId);
  }

  private async download(mediaId: number): Promise<string> {
    const { msg } = this.secret.getMedia(mediaId);
    if (msg.encryptedPath) return msg.encryptedPath;
    if (msg.media?._ === "file" && msg.media.size > AUTO_DOWNLOAD_LIMIT) {
      this.term.print(c.dim(`Downloading #${mediaId} (${formatSize(msg.media.size)})…`));
    }
    const path = await this.secret.downloadMedia(mediaId);
    const lines = [c.dim(`  ↳ #${mediaId} saved encrypted — open: /view ${mediaId}, in folder: /reveal ${mediaId}`)];
    if (isDangerous(path.replace(/\.enc$/, ""))) {
      lines.push(c.yellow("  ⚠ executable file type — /view won't open it; don't run it unless you trust the sender"));
    }
    this.term.print(...lines);
    return path;
  }

  private idArg(arg: string | undefined): number {
    const id = Number(arg);
    if (!arg || !Number.isInteger(id)) throw new Error("Specify a numeric chat id (see /chats)");
    return id;
  }

  private updatePrompt(): void {
    const chat = this.current !== undefined ? this.secret.get(this.current) : undefined;
    const offline = this.shownOnline ? "" : c.yellow("[offline] ");
    this.term.setPrompt(offline + (chat ? `${c.green("🔒 " + chat.peerName)}> ` : "> "));
  }

  private async confirm(question: string): Promise<boolean> {
    const answer = await this.term.ask(c.yellow(`${question} (y/N) `));
    const yes = /^(y|yes)$/i.test(answer);
    if (!yes) this.term.print(c.dim("Cancelled"));
    return yes;
  }

  private listAccess(): void {
    const slots = this.session.access.list();
    this.term.print(
      c.bold("Unlock methods:"),
      ...slots.map((s, i) => {
        const since = s.createdAt ? c.dim(` — added ${new Date(s.createdAt * 1000).toLocaleDateString()}`) : "";
        return `  ${i + 1}) ${describeSlot(s)}${since}`;
      }),
      c.dim(`Add: /access add yubikey${HELLO ? " | /access add hello" : ""}${TOUCH_ID ? " | /access add touchid" : ""}, remove: /access remove <N>`),
    );
  }

  /** Adding or removing an unlock method is as sensitive as changing the password. */
  private async confirmPassword(): Promise<void> {
    const password = await this.term.askHidden("Local password to confirm: ");
    if (!this.session.access.verifyPassword(password)) throw new Error("Wrong local password");
  }

  private async access(args: string[], rest: string): Promise<void> {
    const [sub, what] = args;
    const access = this.session.access;
    if (!sub || sub === "list") return this.listAccess();

    if (sub === "add" && what === "yubikey") {
      const label = rest.replace(/^\s*add\s+yubikey\s*/i, "").trim() || "YubiKey";
      await this.confirmPassword();
      await access.addYubikey(label);
      this.term.print(c.green(`✔ YubiKey "${label}" added. Choose it in the unlock menu on start.`));
      return;
    }

    if (sub === "add" && what === "hello") {
      const problem = await access.windowsHelloProblem();
      if (problem) throw new Error(problem);
      const label = rest.replace(/^\s*add\s+hello\s*/i, "").trim() || "Windows Hello";
      await this.confirmPassword();
      await access.addWindowsHello(label);
      this.term.print(c.green(`✔ Windows Hello "${label}" added.`));
      return;
    }

    if (sub === "add" && what === "touchid") {
      const problem = await access.touchIdProblem();
      if (problem) throw new Error(problem);
      const label = rest.replace(/^\s*add\s+touchid\s*/i, "").trim() || "Touch ID";
      await this.confirmPassword();
      await access.addTouchId(label);
      this.term.print(c.green(`✔ Touch ID "${label}" added. Choose it in the unlock menu on start.`));
      return;
    }

    if (sub === "remove") {
      const slot = access.list()[Number(what) - 1];
      if (!slot) throw new Error("Specify a method number from /access");
      if (slot.type === "password") throw new Error("The password can't be removed: it stays as the fallback unlock method");
      if (!(await this.confirm(`Remove unlock method "${describeSlot(slot)}"?`))) return;
      await this.confirmPassword();
      await access.remove(slot.id);
      this.term.print(
        c.green("✔ Unlock method removed."),
        ...(slot.type === "yubikey-piv"
          ? [c.dim(`The key remains on the YubiKey in slot ${slot.pivSlot.toUpperCase()}; to delete it: ykman piv keys delete ${slot.pivSlot}`)]
          : []),
      );
      return;
    }

    throw new Error(`Usage: /access | /access add yubikey [name]${HELLO ? " | /access add hello [name]" : ""}${TOUCH_ID ? " | /access add touchid [name]" : ""} | /access remove <N>`);
  }

  private async changePassword(): Promise<void> {
    const current = await this.term.askHidden("Current local password: ");
    // check it before asking for a new one twice
    if (!this.session.access.verifyPassword(current)) throw new Error("Wrong current password, the password was not changed");
    await this.session.access.changePassword(current);
    this.term.print(c.green("✔ Local password changed"));
  }

  /**
   * Runs after readline has applied the key, so currentLine is up to date: Enter has
   * already cleared it, and a command or an answer to a question never counts as typing.
   */
  private onKeypress(): void {
    if (this.current === undefined || !isTypingMessage(this.term.currentLine, this.term.isAsking)) return;
    const t = Date.now();
    if (t - this.lastTyping < TYPING_THROTTLE_MS) return;
    this.lastTyping = t;
    this.secret.sendTyping(this.current).catch(() => undefined);
  }

  private formatMessage(chat: SecretChat, m: ChatMessage): string {
    const time = new Date(m.date * 1000).toLocaleTimeString();
    const who = m.out ? c.green("You") : c.cyan(chat.peerName);
    const prefix = this.current === chat.id ? "" : c.dim(`[${chat.id}] `);
    const ttl = m.ttl ? c.yellow(` 🔥${m.ttl}s`) : "";
    const media = m.media ? describeMedia(m.media, m.mediaId) : "";
    // layer <= 45 clients put the caption into the media, newer ones into the message text
    const caption = m.text || (m.media?._ === "file" ? m.media.caption : "");
    return `${prefix}${c.dim(time)} ${who}: ${[media, caption].filter(Boolean).join(" ")}${ttl}`;
  }
}

const osmLink = (lat: number, long: number): string =>
  `https://www.openstreetmap.org/?mlat=${lat}&mlon=${long}#map=16/${lat}/${long}`;

function describeMedia(m: DecryptedMedia, mediaId?: number): string {
  switch (m._) {
    case "file": {
      const details: string[] = [];
      if (m.fileName && m.kind !== "photo") details.push(m.fileName);
      if (m.w && m.h && ["photo", "video", "round", "gif"].includes(m.kind)) details.push(`${m.w}×${m.h}`);
      if (m.duration) details.push(`${Math.floor(m.duration / 60)}:${String(m.duration % 60).padStart(2, "0")}`);
      details.push(formatSize(m.size));
      const id = mediaId !== undefined ? ` #${mediaId}` : "";
      return c.magenta(`[${KIND_LABEL[m.kind]}${id}: ${details.join(", ")}]`);
    }
    case "geo":
      return c.magenta(`[📍 ${m.lat.toFixed(5)}, ${m.long.toFixed(5)}]`) + " " + osmLink(m.lat, m.long);
    case "venue":
      return c.magenta(`[📍 ${m.title}, ${m.address}]`) + " " + osmLink(m.lat, m.long);
    case "contact":
      return c.magenta(`[👤 ${[m.firstName, m.lastName].filter(Boolean).join(" ")} ${m.phone}]`);
    case "webpage":
      return m.url;
    case "external":
      return c.magenta(m.sticker ? `[Sticker ${m.alt ?? ""}]`.replace(" ]", "]") : "[GIF/document from Telegram servers]");
    case "unknown":
      return c.dim(`[unknown media type 0x${m.constructorId.toString(16)}]`);
  }
}

const errText = (e: unknown): string =>
  isNetworkError(e) ? "no connection to Telegram, try again once the connection is back" : errorText(e);
