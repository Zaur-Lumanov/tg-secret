# Protocol

Telegram secret chats are specified in [End-to-end encryption](https://core.telegram.org/api/end-to-end) and the documents linked from it. [teleproto](https://github.com/sanyok12345/teleproto) (the maintained successor of GramJS) provides the MTProto transport, authorization and the regular API; the secret chat layer on top of it is implemented in `tg-secret-core` (`packages/core/src/secret`). The TL schema of the encrypted messages follows TDLib's `secret_api.tl`.

## Implemented

**Key exchange**
- Diffie-Hellman over `messages.getDhConfig` / `requestEncryption` / `acceptEncryption`, both as the initiator and as the responder
- Checks: `p` is a 2048-bit safe prime, `g` generates the right subgroup, `g_a` / `g_b` are in the allowed range, the key fingerprint matches
- Key visualization bytes, as the official apps show them (SHA-1 and SHA-256 of the key)

**Encryption**
- MTProto 2.0 end-to-end encryption: `msg_key` from SHA-256, the KDF, AES-256-IGE, padding rules
- Layer 144 (`decryptedMessageLayer`); the peer's layer is negotiated with `notifyLayer`, and older peers get messages they understand

**Sequencing**
- `seq_no` checks: duplicates are dropped, out-of-order messages are buffered and the gap is requested with `decryptedMessageActionResend`
- Resend requests from the peer are answered from the outbox, media included

**Messages and actions**
- Text with all entity types, self-destruct timer (TTL), deletion, clear history, typing, read receipts, screenshot notifications
- `messages.receivedQueue` acknowledgements
- Ending a chat, deleting it with history on both sides

**Perfect forward secrecy**
- Re-keying as the responding side: `requestKey` → `acceptKey` → `commitKey`, `abortKey`; the previous key is kept to decrypt messages that were already in flight
- The client doesn't start a re-key itself; the official apps do, and it answers them

**Media**
- Parsing of every media type in `secret_api.tl`: photos, videos, audio, voice messages, round videos, documents, stickers, geo points, venues, contacts, web pages
- Sending through `messages.sendEncryptedFile`, with a separate key and IV per file and the file-key fingerprint; photos are re-encoded as JPEG with a 90-pixel preview
- Downloads are verified against the fingerprint and size before decrypting

**Reliability**
- The update state (`pts`, `qts`, `date`) is stored, and messages missed while offline or while the client wasn't running are fetched with `updates.getDifference`
- Sending through a connection drop: the message is queued and sent after reconnecting, in order

## Not implemented

- Starting a PFS re-key from our side
- Video and audio metadata (duration, resolution) when sending: they go as documents
- Downloading stickers and GIFs that point to Telegram's servers (`externalDocument`): they are only displayed
