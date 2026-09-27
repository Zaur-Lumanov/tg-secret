# tg-secret

[![npm: tg-secret-cli](https://img.shields.io/npm/v/tg-secret-cli?label=tg-secret-cli)](https://www.npmjs.com/package/tg-secret-cli) [![npm: tg-secret-core](https://img.shields.io/npm/v/tg-secret-core?label=tg-secret-core)](https://www.npmjs.com/package/tg-secret-core) [![License: MIT](https://img.shields.io/npm/l/tg-secret-core)](https://github.com/zaur-lumanov/tg-secret/blob/main/LICENSE) ![Node.js 24.7+](https://img.shields.io/node/v/tg-secret-core)

Telegram **secret chats** (end-to-end encrypted) for Node.js: a console client and the library it is built on.

Secret chats are Telegram's device-to-device encrypted conversations. Most third-party clients and libraries don't support them. This project implements the secret chat layer (key exchange, MTProto 2.0 end-to-end encryption, encrypted media, re-keying) on top of [teleproto](https://github.com/sanyok12345/teleproto) (the maintained successor of GramJS), and keeps everything on disk encrypted with a local password, a YubiKey, Windows Hello or Touch ID.

## Packages

| Package | What it is | Install |
|---|---|---|
| [`tg-secret-cli`](packages/cli-alias) / [`tg-secret`](packages/cli) | The console client. Both packages are the same app and install both commands, `tg-secret` and `tg-secret-cli`. On npm: [tg-secret-cli](https://www.npmjs.com/package/tg-secret-cli), [tg-secret](https://www.npmjs.com/package/tg-secret). | `npm install -g tg-secret-cli`<br>`yarn global add tg-secret-cli` |
| [`tg-secret-core`](packages/core) | The library: sign-in, secret chats, encrypted storage, unlock methods. On npm: [tg-secret-core](https://www.npmjs.com/package/tg-secret-core). | `npm install tg-secret-core`<br>`yarn add tg-secret-core` |

## Console client

```sh
npm install -g tg-secret-cli     # or: yarn global add tg-secret-cli
tg-secret +79991234567
```

The first run signs the number in right in the console (API keys are obtained from my.telegram.org automatically) and asks you to choose a local password. Then:

```
/new @username      start a secret chat
/open <id>          open it; plain text is sent there
/send photo.jpg     send a photo or file
/help               all commands
```

Full guide: [packages/cli/README.md](packages/cli/README.md).

## Library

```ts
import { TgSecret } from "tg-secret-core";

const session = await TgSecret.open({ phone: "+79991234567", prompts });
session.on("message", (chat, msg) => console.log(`${chat.peerName}: ${msg.text}`));
await session.chats.sendText(chatId, "hello");
```

`prompts` is how the library asks for codes and passwords: in a terminal, a bot, a GUI — your choice. Full guide: [packages/core/README.md](packages/core/README.md).

## Features

- Secret chats: create, accept, decline, end, clear history and delete on both sides, self-destruct timer, key verification image
- Media: photos (with previews), videos, audio, voice messages, documents; sending and receiving, encrypted end to end
- Works through connection drops: messages are queued and sent once the connection is back; missed messages are fetched after reconnecting
- Everything on disk is encrypted: authorization keys, secret chat keys, downloaded files
- Unlock with a local password (Argon2id), a YubiKey (PIV, PIN + touch), Windows Hello or Touch ID
- Windows, macOS and Linux; Node.js 24.7 or newer

## Documentation

- [Console client](packages/cli/README.md)
- [Library](packages/core/README.md)
- [Security model](docs/security.md): what is encrypted, how unlocking works, what is not protected
- [Protocol](docs/protocol.md): what is implemented from the secret chat specification
- [Development](docs/development.md): repository layout, building, tests, commit conventions

## License

[MIT](LICENSE)
