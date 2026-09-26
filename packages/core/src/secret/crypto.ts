import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export const sha1 = (...parts: Buffer[]): Buffer => {
  const h = createHash("sha1");
  for (const p of parts) h.update(p);
  return h.digest();
};

export const sha256 = (...parts: Buffer[]): Buffer => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

/**
 * AES-256-IGE (both directions). `iv` is 32 bytes: iv1 (prev ciphertext) + iv2 (prev plaintext).
 * IGE is inherently sequential, so this runs one ECB block at a time; buffers are reused
 * to keep multi-megabyte files reasonably fast.
 */
function aesIge(data: Buffer, key: Buffer, iv: Buffer, encrypt: boolean): Buffer {
  if (data.length % 16 !== 0) throw new Error("IGE: data length must be a multiple of 16");
  const ecb = (encrypt ? createCipheriv : createDecipheriv)("aes-256-ecb", key, null).setAutoPadding(false);
  // For encryption: x = prev ciphertext (iv1), y = prev plaintext (iv2); decryption swaps roles.
  const x = Buffer.from(iv.subarray(encrypt ? 0 : 16, encrypt ? 16 : 32));
  const y = Buffer.from(iv.subarray(encrypt ? 16 : 0, encrypt ? 32 : 16));
  const tmp = Buffer.alloc(16);
  const out = Buffer.alloc(data.length);
  for (let off = 0; off < data.length; off += 16) {
    for (let i = 0; i < 16; i++) tmp[i] = data[off + i] ^ x[i];
    const e = ecb.update(tmp);
    for (let i = 0; i < 16; i++) {
      const o = e[i] ^ y[i];
      out[off + i] = o;
      y[i] = data[off + i];
      x[i] = o;
    }
  }
  return out;
}

export const aesIgeEncrypt = (plain: Buffer, key: Buffer, iv: Buffer): Buffer => aesIge(plain, key, iv, true);
export const aesIgeDecrypt = (data: Buffer, key: Buffer, iv: Buffer): Buffer => aesIge(data, key, iv, false);

/** key_fingerprint = last 64 bits of SHA1(key), as a signed little-endian long. */
export function keyFingerprint(authKey: Buffer): bigint {
  return sha1(authKey).readBigInt64LE(12);
}

/** MTProto 2.0 KDF. x = 0 for messages from the chat originator, 8 for the other direction. */
function kdf(authKey: Buffer, msgKey: Buffer, x: 0 | 8): { key: Buffer; iv: Buffer } {
  const a = sha256(msgKey, authKey.subarray(x, x + 36));
  const b = sha256(authKey.subarray(40 + x, 40 + x + 36), msgKey);
  const key = Buffer.concat([a.subarray(0, 8), b.subarray(8, 24), a.subarray(24, 32)]);
  const iv = Buffer.concat([b.subarray(0, 8), a.subarray(8, 24), b.subarray(24, 32)]);
  return { key, iv };
}

const computeMsgKey = (authKey: Buffer, x: 0 | 8, padded: Buffer): Buffer =>
  sha256(authKey.subarray(88 + x, 88 + x + 32), padded).subarray(8, 24);

/**
 * Encrypts a serialized DecryptedMessageLayer.
 * Returns key_fingerprint + msg_key + encrypted_data, ready for messages.sendEncrypted.
 */
export function encryptSecretMessage(authKey: Buffer, x: 0 | 8, payload: Buffer): Buffer {
  const lenPrefix = Buffer.alloc(4);
  lenPrefix.writeUInt32LE(payload.length);
  const body = Buffer.concat([lenPrefix, payload]);
  // 12..1024 random bytes, total length divisible by 16
  let padLen = 16 - (body.length % 16);
  if (padLen < 12) padLen += 16;
  padLen += 16 * (randomBytes(1)[0] % 4); // a bit of extra length hiding
  const padded = Buffer.concat([body, randomBytes(padLen)]);

  const msgKey = computeMsgKey(authKey, x, padded);
  const { key, iv } = kdf(authKey, msgKey, x);
  const fp = Buffer.alloc(8);
  fp.writeBigInt64LE(keyFingerprint(authKey));
  return Buffer.concat([fp, msgKey, aesIgeEncrypt(padded, key, iv)]);
}

export function readFingerprint(data: Buffer): bigint {
  if (data.length < 8) throw new Error("Encrypted message too short");
  return data.readBigInt64LE(0);
}

/**
 * Decrypts an incoming encrypted message and returns the serialized payload
 * (without the length prefix and padding). Throws on any integrity failure.
 */
export function decryptSecretMessage(authKey: Buffer, x: 0 | 8, data: Buffer): Buffer {
  if (data.length < 8 + 16 + 16 || (data.length - 24) % 16 !== 0) {
    throw new Error("Encrypted message has invalid length");
  }
  if (readFingerprint(data) !== keyFingerprint(authKey)) {
    throw new Error("key_fingerprint mismatch");
  }
  const msgKey = data.subarray(8, 24);
  const { key, iv } = kdf(authKey, msgKey, x);
  const padded = aesIgeDecrypt(data.subarray(24), key, iv);

  const expected = computeMsgKey(authKey, x, padded);
  if (!expected.equals(msgKey)) throw new Error("msg_key mismatch");

  const len = padded.readUInt32LE(0);
  const padLen = padded.length - 4 - len;
  if (len % 4 !== 0 || padLen < 12 || padLen > 1024) {
    throw new Error("Invalid payload length / padding");
  }
  return Buffer.from(padded.subarray(4, 4 + len));
}

export interface EncryptedFileData {
  data: Buffer;
  key: Buffer;
  iv: Buffer;
  fingerprint: number;
}

/** Secret chat file key fingerprint: md5(key + iv), first 4 bytes XOR next 4, as int32. */
export function fileKeyFingerprint(key: Buffer, iv: Buffer): number {
  const d = createHash("md5").update(key).update(iv).digest();
  return d.readInt32LE(0) ^ d.readInt32LE(4);
}

/** Encrypts a file for a secret chat with a fresh random key/iv (AES-256-IGE, random padding to 16 bytes). */
export function encryptFile(plain: Buffer): EncryptedFileData {
  const key = randomBytes(32);
  const iv = randomBytes(32);
  const pad = (16 - (plain.length % 16)) % 16;
  const data = aesIgeEncrypt(Buffer.concat([plain, randomBytes(pad)]), key, iv);
  return { data, key, iv, fingerprint: fileKeyFingerprint(key, iv) };
}

export function decryptFile(data: Buffer, key: Buffer, iv: Buffer, size: number, fingerprint: number): Buffer {
  if (key.length !== 32 || iv.length !== 32) throw new Error("Invalid file key");
  if (fileKeyFingerprint(key, iv) !== fingerprint) throw new Error("File key fingerprint mismatch");
  if (data.length % 16 !== 0 || size > data.length) throw new Error("Invalid encrypted file size");
  return aesIgeDecrypt(data, key, iv).subarray(0, size);
}

/**
 * Key visualization as shown by official clients (layer >= 46):
 * first 128 bits of SHA1(key) + first 160 bits of SHA256(key) = 36 bytes,
 * drawn as a 12x12 identicon with 2 bits per cell, plus the same bytes as hex.
 */
export function keyVisualizationBytes(key: Buffer): Buffer {
  return Buffer.concat([sha1(key).subarray(0, 16), sha256(key).subarray(0, 20)]);
}
