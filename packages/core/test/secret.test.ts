import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import { test } from "node:test";
import { TLReader, TLWriter } from "../src/tl/binary.js";
import {
  aesIgeDecrypt,
  aesIgeEncrypt,
  decryptSecretMessage,
  encryptSecretMessage,
  keyFingerprint,
  sha1,
} from "../src/secret/crypto.js";
import { bigToBuf, bufToBig, computeSharedKey, generateKeyPair, isProbablePrime, modPow, validateDhParams } from "../src/secret/dh.js";
import { OUR_LAYER, decodeEnvelope, encodeLayer, encodeMessage } from "../src/secret/schema.js";

// RFC 3526 group 14 (2048-bit MODP) is a safe prime; g=2 is valid since p mod 8 = 7.
const P = BigInt(
  "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
);

test("TL bytes encoding round-trips short and long buffers with 4-byte alignment", () => {
  for (const len of [0, 1, 3, 253, 254, 1000]) {
    const data = randomBytes(len);
    const buf = new TLWriter().bytes(data).int(42).toBuffer();
    assert.equal(buf.length % 4, 0);
    const r = new TLReader(buf);
    assert.deepEqual(r.bytes(), data);
    assert.equal(r.int(), 42);
  }
});

test("AES-IGE: 1 block equals ECB when iv is zero, and round-trips", () => {
  const key = randomBytes(32);
  const block = randomBytes(16);
  const ecb = createCipheriv("aes-256-ecb", key, null).setAutoPadding(false).update(block);
  assert.deepEqual(aesIgeEncrypt(block, key, Buffer.alloc(32)), ecb);

  const iv = randomBytes(32);
  const plain = randomBytes(16 * 7);
  assert.deepEqual(aesIgeDecrypt(aesIgeEncrypt(plain, key, iv), key, iv), plain);
});

test("key fingerprint is the last 64 bits of SHA1(key)", () => {
  const key = randomBytes(256);
  assert.equal(keyFingerprint(key), sha1(key).readBigInt64LE(12));
});

test("DH: both sides derive the same key", () => {
  validateDhParams(2, P);
  const a = generateKeyPair(2, P, randomBytes(256));
  const b = generateKeyPair(2, P, randomBytes(256));
  const k1 = computeSharedKey(b.pub, a.secret, P);
  const k2 = computeSharedKey(a.pub, b.secret, P);
  assert.equal(k1.length, 256);
  assert.deepEqual(k1, k2);
});

test("DH: rejects g_a outside the safe range and a non-safe prime", () => {
  assert.throws(() => computeSharedKey(bigToBuf(2n), randomBytes(256), P));
  assert.throws(() => validateDhParams(2, P - 2n));
  assert.ok(isProbablePrime(P));
  assert.equal(modPow(3n, 4n, 5n), 1n);
  assert.equal(bufToBig(bigToBuf(123456789n)), 123456789n);
});

test("MTProto 2.0: originator -> responder message decrypts only with the right direction", () => {
  const key = randomBytes(256);
  const body = encodeMessage({ _: "message", randomId: 7n, ttl: 0, text: "hello 🔒" }, 73);
  const payload = encodeLayer({ layer: OUR_LAYER, inSeqNo: 0, outSeqNo: 1 }, body);

  const enc = encryptSecretMessage(key, 0, payload);
  assert.deepEqual(decryptSecretMessage(key, 0, enc), payload);
  assert.throws(() => decryptSecretMessage(key, 8, enc), /msg_key mismatch/);

  const tampered = Buffer.from(enc);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => decryptSecretMessage(key, 0, tampered));
  assert.throws(() => decryptSecretMessage(randomBytes(256), 0, enc), /fingerprint/);
});

test("schema: message and service envelopes round-trip", () => {
  const msg = decodeEnvelope(
    encodeLayer({ layer: 73, inSeqNo: 4, outSeqNo: 5 }, encodeMessage({ _: "message", randomId: -5n, ttl: 10, text: "hi" }, 73)),
  );
  assert.deepEqual(msg.layer, { layer: 73, inSeqNo: 4, outSeqNo: 5 });
  assert.deepEqual(msg.message, { _: "message", randomId: -5n, ttl: 10, text: "hi", media: undefined, silent: false });

  for (const peerLayer of [23, 46]) {
    const m = decodeEnvelope(encodeMessage({ _: "message", randomId: 1n, ttl: 0, text: "old" }, peerLayer)).message;
    assert.equal(m._ === "message" && m.text, "old");
  }

  const gB = randomBytes(256);
  const svc = decodeEnvelope(
    encodeLayer(
      { layer: 73, inSeqNo: 0, outSeqNo: 1 },
      encodeMessage({ _: "service", randomId: 9n, action: { _: "acceptKey", exchangeId: 3n, gB, fingerprint: -1n } }, 73),
    ),
  );
  assert.deepEqual(svc.message, { _: "service", randomId: 9n, action: { _: "acceptKey", exchangeId: 3n, gB, fingerprint: -1n } });

  const del = decodeEnvelope(encodeMessage({ _: "service", randomId: 1n, action: { _: "delete", randomIds: [1n, 2n] } }, 73));
  assert.deepEqual(del.message, { _: "service", randomId: 1n, action: { _: "delete", randomIds: [1n, 2n] } });
});
