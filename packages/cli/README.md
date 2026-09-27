# tg-secret — console client for Telegram secret chats

A terminal client for Telegram **secret chats** (end-to-end encrypted): start and accept chats, send messages and files, verify keys. Everything it stores on disk is encrypted with a local password, a YubiKey, Windows Hello or Touch ID.

Built on [`tg-secret-core`](../core/README.md).

## Installation

```sh
npm install -g tg-secret-cli
# or, with Yarn 1:
yarn global add tg-secret-cli
```

Yarn 2 and newer have no global installs: use `yarn dlx` below, or npm. With `yarn global add`, the commands land in Yarn's own bin directory (`yarn global bin`), which must be in `PATH`.

Requires Node.js 24.7 or newer. The same client is also published as `tg-secret`: both packages install both commands, `tg-secret` and `tg-secret-cli`, so use whichever you like. Install only one of the two packages globally: they provide the same commands, and if both are installed, uninstalling one of them removes the commands of the other too (install it again to get them back).

Without installing:

```sh
npx tg-secret-cli +79991234567
# or
yarn dlx tg-secret-cli +79991234567
```

## Getting started

```sh
tg-secret +79991234567
```

Without a number, the client lists the numbers that are already signed in and asks which one to use.

To only sign a number in, without opening the chat console (for example, to prepare it for your own program built on [`tg-secret-core`](../core/README.md)):

```sh
tg-secret auth +79991234567
```

### Command-line arguments

They work both for `tg-secret` and for `tg-secret auth`.


| Argument | What it does |
|---|---|
| `<number>` | Phone number in any format: `+79991234567`, `79991234567`, `+7 (999) 123-45-67`. |
| `--data-dir <dir>`, `--data-dir=<dir>` | Keep data in this directory instead of the default one (see [Data storage](#data-storage)). |
| `--debug` | Print network errors and secret chat events that are otherwise handled silently. |
| `--password <password>`, `--password=<password>` | Pass the local password as an argument instead of typing it. **Not recommended**, see below. |

About `--password`:
- **it is not recommended**: the password stays in plain text in the shell history (PowerShell, cmd, bash) and is visible to other programs in the process list while the client runs. The client clears the console right away so the command doesn't stay on screen, and after signing in it reminds you to change the password (`/passwd`). It can't clear the shell history;
- it only works for a number that is already signed in and encrypted; for a number that doesn't exist yet, or for an unencrypted old-format account, an error is printed and the client exits;
- with a wrong password the client exits immediately, there are no retries;
- it is used only for the first unlock: after `/lock` the password is asked in the console again.

## Sign-in and the local password

If the number is not signed in yet, the client signs in right in the console first:

1. **API keys.** The client signs in to my.telegram.org and takes the account's api_id/api_hash, creating an app if there is none yet. The code arrives as a message from "Telegram" in the app. If the site refuses (this happens with new accounts and VPNs), you are asked to enter the keys manually.
2. **Account sign-in.** A second code arrives; with two-step verification enabled, the cloud password is asked.
3. **Local password.** Entered twice, at least 8 characters; too simple passwords get a warning. This is not the Telegram cloud password: it encrypts all account data on this computer. Nothing is written to disk before this step.

On every start the client asks for the local password and exits after 3 wrong attempts. A forgotten password can't be recovered; you can only sign in again (secret chats are lost then).

An old-format (unencrypted) account is converted to the encrypted format on the first start: you are asked to choose a password, no new sign-in is needed.

### YubiKey, Windows Hello and Touch ID

Besides the password, the account can be unlocked with hardware. The password always remains as the fallback. Methods are added with `/access` (see [Security and exit](#security-and-exit)); on start the client shows a menu, and if a registered YubiKey is plugged in, it is offered by default (otherwise Touch ID, on a Mac).

**YubiKey (PIV, PIN + touch).** An RSA-2048 key is generated on the YubiKey; its private part never leaves the device. Unlocking requires the YubiKey itself, its PIN and a touch. After 3 wrong PINs in a row the YubiKey blocks the key until the PUK is entered. Several YubiKeys can be added (for example, a main and a backup one).
- The PIN can be entered in the console (Windows, Linux, macOS) or, on Windows, in the system smart card PIN dialog. The choice is asked on unlock and remembered.
- [YubiKey Manager](https://www.yubico.com/support/download/yubikey-manager/) (`ykman`) is needed, but only to set up the key. If the YubiKey has the factory PIN (123456), the client makes you change it and offers to replace the factory PUK and management key.
- No administrator rights are needed. Linux needs the `pcscd` service (package `pcscd` / `pcsc-lite`); over SSH or without a graphical session, access to it may need to be allowed with a polkit rule.
- The key is created in PIV slot 9D. If it is used by another program, the client offers a free retired slot (82–95); entering the PIN in the Windows dialog may not work with retired slots.

**Windows Hello (Windows PIN, fingerprint, face).** Windows only. Windows Hello keeps a key (in the TPM, if there is one) and uses it only after you confirm. The method is bound to this computer and Windows user: anyone who knows the Windows PIN and sits at the computer can open the client too.

**Touch ID.** macOS only (Apple Silicon, or an Intel Mac with a T2 chip). A key is created in the Secure Enclave and can be used only after a fingerprint; it never leaves the chip. The method is bound to this Mac. Enrolling a new fingerprint in macOS makes the key unusable (so someone who knows the Mac password can't add their own finger); then unlock with the password and add Touch ID again. With the lid closed Touch ID is unavailable, unless the keyboard has its own sensor.

## Data storage

Data lives in a per-user data directory:

| OS | Default directory |
|---|---|
| Windows | `%LOCALAPPDATA%\tg-secret` |
| macOS | `~/Library/Application Support/tg-secret` |
| Linux | `$XDG_DATA_HOME/tg-secret`, or `~/.local/share/tg-secret` |

Another directory can be chosen with `--data-dir`. The directory is shared with programs that use `tg-secret-core` with default settings. Each account is stored in `accounts/<number>/` inside it:

| File | Contents |
|---|---|
| `vault.json` | the master key, encrypted once per unlock method |
| `account.enc` | API keys, account name |
| `session.enc` | Telegram session (authorization key) |
| `secret-chats.enc` | secret chats: encryption keys, counters, send queue |
| `downloads/<chat>/*.enc` | incoming files |

Only the phone number is stored in plain text: it is the folder name.

An account can be open in one process at a time: while the client runs, the account folder holds a `lock` file, and a second client with the same number stops with an error. A lock left by a crashed process is taken over automatically.

Early development versions kept accounts in `./accounts` of the directory the client was started from. If such a folder is found, the client offers to move its accounts into the data directory; accounts that already exist there are left in place.

## Commands

A **dialog** is an open secret chat. Open one with `/open <id>`; a chat that has just been established opens by itself if no other dialog is open. In an open dialog, the input line is prefixed with `🔒 <peer name>>`.

Some commands work differently outside and inside a dialog:
- if a command's `[id]` argument is optional, inside a dialog it applies to the current dialog when omitted, while outside a dialog `id` is required;
- "dialog only" commands give a "No chat is open" error outside a dialog.

A chat `id` is the number from `/chats` and from notifications; it can be negative (for example, `-1349200632`), so type it in full, with the sign. File numbers `N` are the `#N` from messages; they are shared across all chats and valid until the client exits.

When the connection to Telegram is lost for more than 5 seconds, the client says so and the input line gets an `[offline]` prefix; it reports the connection as restored once it has held for 10 seconds. Shorter drops (a slow VPN, for example) are not reported.

### Messages

| Input | Outside a dialog | Inside a dialog |
|---|---|---|
| text not starting with `/` | A "No chat is open" hint. | Sends a message to the peer. If the timer is on (`/ttl`), the message self-destructs. Without a connection the message is queued and sent once the connection is back; the console reports whether it was sent. |
| `/history` | Error. | Shows the dialog's messages from the current run (history is not saved to disk). |

While you type a message, the peer sees "typing…". This event is not sent for commands (lines starting with `/`) or for answers to questions.

### Chats

| Command | Outside a dialog | Inside a dialog |
|---|---|---|
| `/chats` | List of secret chats: `id`, peer, state (waiting for confirmation, incoming request, active, ended) and timer. | Same; the current dialog is marked with `›`. |
| `/new <@username\|+phone>` | Sends the peer a secret chat request. Once they accept, the chat opens automatically. | Same, but the current dialog stays open; the new one can be opened with `/open`. |
| `/accept <id>` | Accepts an incoming request and opens the chat. `id` is required. | Accepts the request; the current dialog stays open. |
| `/decline <id>` | Declines an incoming request. `id` is required. | Same. |
| `/open <id>` | Opens a dialog. Only an active chat can be opened. | Switches to another dialog. |
| `/close` | Does nothing. | Closes the dialog (the chat itself is not ended). |
| `/discard [id]` | Ends chat `id`: no more messages can be sent, the history stays on both sides, and the chat stays in `/chats`. | Without `id`, ends the current dialog. |
| `/clean [id]` | Clears the history of chat `id` on both sides; the chat stays. Asks for confirmation, needs a connection. | Without `id`, clears the current dialog. |
| `/delete [id]` | Deletes chat `id` on both sides, with its history, keys and downloaded files. Asks for confirmation, needs a connection. For a chat that has already ended only your local data is deleted: an ended chat can't be deleted on the peer's side. | Without `id`, deletes the current dialog and closes it. |

If the peer deletes the chat with its history, it is deleted on your side too, together with the downloaded files.

### Dialog only

| Command | What it does |
|---|---|
| `/ttl <seconds>` | Turns on the self-destruct timer for new messages in the chat; `0` turns it off. The peer is notified, and the timer applies to both sides. |
| `/key` | Shows the image and hex of the encryption key. Compare it with the key image in the peer's app: if they match, the chat is not intercepted. |

### Files

| Command | Outside a dialog | Inside a dialog |
|---|---|---|
| `/send <path> [caption]` | Error. | Sends a file. Photos (JPEG, PNG, WebP, BMP, HEIC) are downscaled to 2560 pixels on the longer side and sent with a 90-pixel preview; other files are sent as is, as documents. |
| `/file <path> [caption]` | Error. | Sends a file uncompressed, as a document (images get a preview). |
| `/media` | Error. | The dialog's files from the current run, numbered `#N`. |
| `/view <N>` | Opens file `#N` in the default app. An incoming file is decrypted into a temporary copy. | Same. |
| `/reveal <N>` | Shows file `#N` in Explorer / Finder (for an incoming file — a temporary decrypted copy). | Same. |
| `/download <N>` | Downloads an incoming file larger than 20 MB (smaller ones are downloaded automatically). | Same. |

Quote a path with spaces, or drag the file into the terminal window. Sending a file without a connection is queued too.

Incoming files up to 20 MB are downloaded automatically and stored encrypted. Temporary copies for `/view` and `/reveal` are wiped on `/lock` and on exit, and those left after a crash are wiped on the next start. File names from the peer are sanitized: no paths, `..`, reserved Windows names or text-reversing characters. Executable types (`.exe`, `.bat`, `.lnk`, `.js`, `.ps1`, `.msi`…) are not opened with `/view` — only `/reveal` is available for them. If the peer deletes a message or clears the history, the downloaded file is deleted from disk.

### Security and exit

They work the same outside and inside a dialog.

| Command | What it does |
|---|---|
| `/passwd` | Changes the local password: first the current one (checked right away), then the new one twice. Only the master key is re-encrypted; the data and other unlock methods are not touched. |
| `/access` | Numbered list of unlock methods. |
| `/access add yubikey [name]` | Adds a YubiKey: confirmation with the local password, key setup with `ykman` (PIN, touch), then a test decryption. The method is saved only if the test passes. |
| `/access add hello [name]` | Adds Windows Hello (Windows only): confirmation with the password, then two confirmations in the Windows Hello dialog. One per account: while it is added, the command is not offered. |
| `/access add touchid [name]` | Adds Touch ID (macOS only): confirmation with the password, then one fingerprint to check the new key. One per account, like Windows Hello. |
| `/access remove <N>` | Removes unlock method `N` (with confirmation and the password). The password can't be removed. The key on the YubiKey remains; the client shows the `ykman` command to delete it too. |
| `/lock` | Locks the session: the connection is closed, keys in memory are wiped, temporary file copies are deleted, the screen and scrollback are cleared. The local password is needed to continue. Unsent messages are kept and sent after unlocking. |
| `/help` | Short command reference. |
| `/quit`, `/exit`, Ctrl+C | Exit. Unsent messages left in the queue are saved and sent on the next start. |

## Known limitations

- `/delete`: for a peer running Telegram for iOS, the chat is closed right away but disappears from their dialog list only after their app restarts. The client sends the same request as the official apps.
- Videos and audio are sent as documents, without duration and resolution.
- Files are encrypted in memory (up to 512 MB); the console freezes while a large file is being encrypted.
- Stickers and GIFs "from Telegram servers" are only displayed, not downloaded.
- Message history is kept only for the current run.
- Windows may open the Windows Hello and smart card PIN dialogs minimized or behind the terminal; the client brings them to the front, but if Windows doesn't allow it, open the dialog from the taskbar.

More in [Security model](../../docs/security.md).

## License

MIT
