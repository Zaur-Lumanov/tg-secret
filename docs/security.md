# Security model

This page describes what tg-secret protects on the local machine and what it doesn't. Secret chats themselves are end-to-end encrypted by the Telegram protocol ([Protocol](protocol.md)); this is about the data kept on disk and in memory.

## What is stored and how

Each account is a folder `accounts/<phone number>/` in the [data directory](../packages/core/README.md#data-directory). Everything in it is encrypted except the folder name (the phone number) and the `lock` file (a process id).

| File | Contents |
|---|---|
| `vault.json` | the wrapped master key, one copy per unlock method, plus the metadata of each method |
| `account.enc` | API keys (api_id / api_hash), account name |
| `session.enc` | the Telegram session, including the authorization key |
| `secret-chats.enc` | secret chats: keys, counters, the send queue |
| `downloads/<chat>/*.enc` | incoming files |

### Encryption

- A random 256-bit **master key** encrypts every file above with **AES-256-GCM**. Each file type has its own purpose tag, authenticated along with the data, so an encrypted session can't be swapped in for an encrypted chat file.
- The master key itself is stored only in `vault.json`, wrapped (AES-256-GCM) once per unlock method, each with that method's **key-encryption key** (KEK).
- Files are written atomically (a temporary file, then a rename), so a crash never leaves a half-written file.

### Unlock methods

| Method | How the KEK is obtained |
|---|---|
| Local password (always present) | Argon2id: 256 MiB of memory, 3 passes, parallelism 4 (about 0.35 s on a modern CPU). |
| YubiKey (PIV) | A random KEK, encrypted with RSA-OAEP to an RSA-2048 key generated on the YubiKey. Decrypting it needs the YubiKey, its PIN and a touch (touch policy "always"). The private key never leaves the device. |
| Windows Hello | Windows Hello signs a stored random challenge with a key it keeps (in the TPM when there is one) after the user confirms; the KEK is derived from the signature. The same approach as KeePassXC's quick unlock. |

The password can't be removed, so there is always a fallback. Changing the password re-wraps only the master key; the data isn't re-encrypted.

Consequences worth knowing:
- **Windows Hello** is bound to this computer and this Windows user. Anyone who can sign in to that Windows account (or knows its Windows Hello PIN) and runs the client can unlock it.
- **YubiKey**: after 3 wrong PINs the YubiKey blocks the key until the PUK is entered. A lost YubiKey can be removed with `/access remove`; the password still works.
- **A forgotten password** can't be recovered. Without another unlock method, the only way out is to sign in again; the secret chats are lost, since their keys can't be decrypted.

## In memory

- While locked (`/lock` in the console, `lock()` in the library), the connection is closed and the keys are wiped: the master key, the secret chat keys and the authorization key in the MTProto client's session.
- The master key is kept outside the JavaScript heap, in a Node.js `KeyObject`.
- What can't be wiped: the password as read by `readline`, strings JavaScript copied internally, data the MTProto client copied. **tg-secret doesn't protect against a memory dump of the running, unlocked process** (for example, by malware running as the same user).

## Temporary files

To open an incoming file in another program (`/view`, `openablePath()`), a decrypted copy is written to a per-process temporary folder. It is plaintext while it exists. The copies are wiped on lock and exit; on Windows, a file still held open by a viewer can't be deleted then and is wiped on the next start instead.

Executable file types received from a peer (`.exe`, `.bat`, `.lnk`, `.js`, `.ps1`, `.msi` and many more) are never opened automatically, and file names from the peer are sanitized (no paths, no reserved names, no text-reversing characters).

## Passing the password on the command line

`--password` puts the password into the shell history and makes it visible to other programs in the process list while the client runs. The client clears the screen and reminds you to change the password afterwards, but it can't clean the shell history. Prefer typing it.

## Converting an old unencrypted account

Accounts from early development versions were stored unencrypted. On conversion every file is encrypted, read back and compared, and only then is the plaintext overwritten with random data and deleted. On SSDs the old blocks may physically survive overwriting; to be sure, end the session in Telegram settings ("Devices") after the conversion and sign in again.

## One process per account

An account can be open in one process at a time. Two processes would both advance the secret chat counters and overwrite each other's state, breaking the chats. The `lock` file in the account folder holds the owner's process id; a lock left by a process that no longer exists is taken over.
