# tg-secret-core — Telegram secret chats for Node.js

[![npm: tg-secret-core](https://img.shields.io/npm/v/tg-secret-core?label=tg-secret-core)](https://www.npmjs.com/package/tg-secret-core) [![CI](https://github.com/Zaur-Lumanov/tg-secret/actions/workflows/ci.yml/badge.svg)](https://github.com/Zaur-Lumanov/tg-secret/actions/workflows/ci.yml) [![Coverage](https://codecov.io/gh/Zaur-Lumanov/tg-secret/graph/badge.svg)](https://codecov.io/gh/Zaur-Lumanov/tg-secret) [![License: MIT](https://img.shields.io/npm/l/tg-secret-core)](https://github.com/Zaur-Lumanov/tg-secret/blob/main/LICENSE) ![Node.js 24.7+](https://img.shields.io/node/v/tg-secret-core)

A library for Telegram **secret chats** (end-to-end encrypted): sign in, start and accept secret chats, send and receive messages and files. It implements the secret chat layer on top of [teleproto](https://github.com/sanyok12345/teleproto) (the maintained successor of GramJS) and keeps everything on disk encrypted with a local password, a YubiKey, Windows Hello or Touch ID.

The [`tg-secret`](../cli/README.md) console client is built on it.

## Installation

```sh
npm install tg-secret-core
# or
yarn add tg-secret-core
```

Requires Node.js 24.7 or newer. The package is ESM; `require("tg-secret-core")` works too on these Node versions. TypeScript types are included.

Two optional dependencies are installed by default. If one fails to install, the library still works without the feature:

| Dependency | Gives | Without it |
|---|---|---|
| `sharp` | photo compression and previews | files are sent as documents, without previews |
| `koffi` | YubiKey access over PC/SC | YubiKey unlock works only through the Windows PIN dialog |

To skip them on purpose: `npm install tg-secret-core --omit=optional` (Yarn 1: `yarn add tg-secret-core --ignore-optional`).

## Quick start

```ts
import { TgSecret, type Prompts } from "tg-secret-core";
import { createInterface } from "node:readline/promises";

// How the library asks the user for codes, passwords and choices; here, plainly in the terminal.
const rl = createInterface({ input: process.stdin, output: process.stdout });
const prompts: Prompts = {
  notice: (level, ...lines) => console.log(...lines),
  text: (q) => rl.question(`${q.message}: `),
  secret: (q) => rl.question(`${q.message}: `), // a real app should hide the input
  confirm: async (q) => /^y/i.test(await rl.question(`${q.message} (y/n) `)),
  choose: async (q) => {
    q.options.forEach((o, i) => console.log(`${i + 1}) ${o.label}`));
    return q.options[Number(await rl.question(`${q.message}: `)) - 1]?.value ?? q.default;
  },
};

const session = await TgSecret.open({ phone: "+79991234567", prompts });
console.log(`Signed in as ${session.name}`);

session.on("request", (chat) => session.chats.acceptChat(chat.id));
session.on("message", (chat, msg) => console.log(`${chat.peerName}: ${msg.text}`));
session.on("error", (err) => console.error(err));

const chat = await session.chats.requestChat("@username");
session.on("ready", async (ready) => {
  if (ready.id === chat.id) await session.chats.sendText(chat.id, "hello");
});
```

The first `open()` of a number signs it in: API keys are obtained from my.telegram.org, then Telegram sends a login code, and finally a local password is chosen. All of it goes through `prompts`. Later calls only unlock the local storage.

## Opening a session

```ts
const session = await TgSecret.open(options);
```

| Option | Type | |
|---|---|---|
| `phone` | `string` | Required. Any format: `"+79991234567"`, `"7 (999) 123-45-67"`. |
| `prompts` | `Prompts` | Required. See [Prompts](#prompts). |
| `storage` | `"shared"` \| `"separate"` | Where data lives, see [Data directory](#data-directory). Default `"shared"`. |
| `dataDir` | `string` | An explicit data directory instead of `storage`. |
| `password` | `string` | The local password of an already signed-in account, instead of asking. A wrong one fails at once, without retries. |
| `debug` | `(context: string, detail: unknown) => void` | Receives low-level details that are otherwise handled silently (recovered network errors, raw updates). |

`open()` throws `AccountLockedError` if another process has the account open, and `TooManyAttemptsError` after 3 wrong passwords.

### The session

| Member | |
|---|---|
| `phone` | `"+79991234567"` |
| `name` | The account's display name; `undefined` while locked. |
| `locked` | `true` after `lock()`. |
| `chats` | Secret chats, see [Secret chats](#secret-chats). Only while unlocked. |
| `access` | Unlock methods, see [Unlock methods](#unlock-methods). Only while unlocked. |
| `lock()` | Wipes the keys from memory, closes the connection, deletes temporary decrypted files. Unsent messages are kept. The account stays reserved for this process. |
| `unlock()` | Asks for the local password (or another unlock method) through `prompts` again and reconnects. |
| `close()` | `lock()` and releases the account for other processes. |

Accessing `chats` or `access` while locked throws `LockedError`.

## Events

The session emits every secret chat event. Subscribe on the session, not on `chats`: the session's listeners survive `lock()` / `unlock()`.

| Event | Arguments | |
|---|---|---|
| `request` | `chat` | Incoming secret chat request. |
| `ready` | `chat` | A chat is established (ours accepted, or theirs accepted by us). |
| `discarded` | `chat` | A chat was ended. |
| `chatDeleted` | `chat, byPeer` | A chat was deleted with its history and files. |
| `message` | `chat, msg` | Incoming message. |
| `deleted` | `chat, randomIds` | The peer deleted messages. |
| `info` | `chat, text` | Service events in plain English: timer changed, screenshot taken, key updated… |
| `typing` | `chat` | The peer is typing. |
| `read` | `chat, maxDate` | The peer read messages up to this date. |
| `outgoing` | `chat, msg, prev` | The delivery status of an outgoing message changed (`sending`, `queued`, `sent`, `failed`). |
| `queueDrained` | `sent, failed` | Every queued message has been sent or has failed. |
| `connection` | `online` | Connection to Telegram lost / restored. |
| `caughtUp` | `count` | Messages missed while offline have been received. |
| `error` | `error, chat?` | An error in background processing. As with any `EventEmitter`, an `error` nobody listens to is thrown. |
| `locked`, `unlocked` | | After `lock()` / `unlock()`. |

## Secret chats

`session.chats`:

| Method | |
|---|---|
| `list()`, `get(id)` | Known chats (`SecretChat`: `id`, `peerName`, `state`, `ttl`…). |
| `requestChat(user)` | Starts a secret chat with `"@username"` or `"+phone"`. It is ready after the `ready` event. |
| `acceptChat(id)`, `declineChat(id)` | Answers an incoming request. |
| `sendText(id, text)` | Sends a message. Without a connection it is queued (see the `outgoing` event). |
| `sendFile(id, path, caption?, asPhoto = true)` | Sends a file; images are sent as compressed photos unless `asPhoto` is `false`. |
| `getHistory(id)` | Messages of the current session (history is not stored on disk). |
| `downloadMedia(mediaId)` | Downloads an incoming file (up to 20 MB this happens automatically) and returns the path of its encrypted copy. |
| `openablePath(mediaId)` | A plaintext path of the file: for an incoming one, a temporary decrypted copy (deleted on `lock()` / `close()`); for an outgoing one, the original file. |
| `setTtl(id, seconds)` | Self-destruct timer for new messages; `0` turns it off. |
| `markRead(id, maxDate)`, `sendTyping(id)` | Read receipts and the typing status. |
| `deleteMessages(id, randomIds)` | Deletes messages on both sides. |
| `clearHistory(id)` | Clears the history on both sides; the chat stays. |
| `discard(id)` | Ends the chat. |
| `deleteChat(id)` | Deletes the chat on both sides, with its history, keys and files. |
| `isOnline()`, `pendingCount()` | Connection state and the number of queued messages. |

To compare a chat's key with the peer's (as in the official apps), `keyVisualizationBytes(chat.key)` returns the 36 bytes the apps draw as an image.

## Prompts

The library never touches the terminal. Everything it needs from the user goes through a `Prompts` object:

```ts
interface Prompts {
  notice(level: NoticeLevel, ...lines: string[]): void;   // progress, warnings, results
  text(question: Question): Promise<string>;              // a visible answer
  secret(question: Question): Promise<string>;            // a password or PIN
  confirm(question: ConfirmQuestion): Promise<boolean>;   // has `default`
  choose<T>(question: ChoiceQuestion<T>): Promise<T>;     // has `options` and `default`
}
```

Every question has a `message` in English, without trailing punctuation, and a stable `id`. Use the `id` to answer programmatically, for example from a config or environment variables in a bot:

| `id` | Asked when |
|---|---|
| `my-telegram-org-code` | first sign-in: the code from my.telegram.org |
| `api-id`, `api-hash` | first sign-in, if the API keys can't be obtained automatically |
| `phone-code`, `cloud-password` | sign-in: the login code, the 2FA password |
| `new-local-password`, `repeat-local-password`, `weak-password` | choosing the local password |
| `local-password`, `unlock-method` | unlocking |
| `yubikey-pin`, `yubikey-pin-entry` | unlocking with a YubiKey |
| `yubikey-serial`, `yubikey-new-pin`, `yubikey-repeat-pin`, `yubikey-change-puk`, `yubikey-new-puk`, `yubikey-repeat-puk`, `yubikey-replace-management-key`, `yubikey-management-key`, `yubikey-use-retired-slot` | adding a YubiKey |

Notice levels: `title`, `info`, `hint`, `action` (the user has to do something outside the program, like touch a YubiKey), `success`, `warning`, `error`.

## Unlock methods

`session.access`:

| Method | |
|---|---|
| `list()` | Unlock methods (`Slot`): the password, YubiKeys, Windows Hello, Touch ID. `describeSlot(slot)` gives a readable name. |
| `verifyPassword(password)` | `true` if it is the local password. Changes nothing; use it to confirm sensitive actions. |
| `changePassword(current, next?)` | Without `next`, the new password is asked through `prompts`. |
| `addYubikey(label?)` | Sets up a YubiKey through [`ykman`](https://www.yubico.com/support/download/yubikey-manager/), asking its PIN and so on through `prompts`, and checks it with a test decryption. |
| `windowsHelloProblem()` | Why Windows Hello can't be added here (another OS, not set up, already added: one per account), or `undefined`. |
| `addWindowsHello(label?)` | Windows only. |
| `touchIdProblem()` | Why Touch ID can't be added here (another OS, unavailable, already added: one per account), or `undefined`. |
| `addTouchId(label?)` | macOS only: creates a Secure Enclave key usable only with Touch ID and checks it with one fingerprint. The package includes a small native helper for it (`native/tg-secret-touchid`). |
| `remove(slotId)` | Removes a method; the password can't be removed. |

## Data directory

| `storage` / `dataDir` | Directory |
|---|---|
| default, `storage: "shared"` | the per-user data directory shared with the `tg-secret` console client: `%LOCALAPPDATA%\tg-secret` on Windows, `~/Library/Application Support/tg-secret` on macOS, `$XDG_DATA_HOME/tg-secret` or `~/.local/share/tg-secret` on Linux |
| `storage: "separate"` | `tg-secret-core` next to the shared directory |
| `dataDir: "/some/path"` | that path |

With the shared directory, a number signed in with the console client can be opened from code and vice versa, but not at the same time: an account can be open in one process only (`AccountLockedError`). `resolveDataDir(options)` returns the directory, `listAccounts(dataDir)` the numbers stored there.

## Errors

| Error | |
|---|---|
| `AccountLockedError` | The account is open in another process. |
| `TooManyAttemptsError` | 3 wrong local passwords in a row. |
| `WrongPasswordError` | A wrong local password (e.g. in `changePassword`). |
| `LockedError` | `chats` or `access` used while locked; also rejects operations cut off by `lock()`. |

`isNetworkError(err)` tells transport failures (worth retrying) from errors returned by Telegram.

## More

- [Security model](../../docs/security.md)
- [Protocol](../../docs/protocol.md)

## License

MIT
