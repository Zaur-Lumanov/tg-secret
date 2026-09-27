import assert from "node:assert/strict";
import { createECDH, randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { kekFromShared, touchIdProblem, wrapToPublicKey } from "../src/security/touchId.js";
import { Vault } from "../src/security/vault.js";

const FAST_KDF = { memory: 1024, passes: 1, parallelism: 1 };

/** A P-256 key standing in for the Secure Enclave one: the helper's derive is plain ECDH. */
const enclave = () => {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  return ecdh;
};

test("the Secure Enclave side of ECDH gives the same KEK as enrollment", () => {
  const se = enclave();
  const { ephemeralPublicKey, kek } = wrapToPublicKey(se.getPublicKey());
  assert.equal(ephemeralPublicKey.length, 65); // X9.63 uncompressed, as CryptoKit expects
  assert.deepEqual(kekFromShared(se.computeSecret(ephemeralPublicKey)), kek);
  assert.notDeepEqual(kekFromShared(enclave().computeSecret(ephemeralPublicKey)), kek);
});

test("each enrollment gets its own one-time key and KEK", () => {
  const se = enclave();
  const a = wrapToPublicKey(se.getPublicKey());
  const b = wrapToPublicKey(se.getPublicKey());
  assert.notDeepEqual(a.ephemeralPublicKey, b.ephemeralPublicKey);
  assert.notDeepEqual(a.kek, b.kek);
});

test("a Touch ID slot unlocks the vault", () => {
  const path = join(mkdtempSync(join(tmpdir(), "tg-touchid-")), "vault.json");
  const vault = Vault.create(path, "correct horse battery", FAST_KDF);
  const se = enclave();
  const { ephemeralPublicKey, kek } = wrapToPublicKey(se.getPublicKey());
  const slot = vault.addSlot(
    { type: "touch-id", label: "Touch ID", seKey: randomBytes(16).toString("base64"), ephemeralPublicKey: ephemeralPublicKey.toString("base64") },
    kek,
  );
  vault.lock();
  const again = kekFromShared(se.computeSecret(ephemeralPublicKey));
  Vault.unlockWithKek(path, slot.id, again).lock();
  assert.equal(Vault.slots(path).find((s) => s.id === slot.id)?.type, "touch-id");
});

test("Touch ID is reported unavailable off macOS", { skip: process.platform === "darwin" }, async () => {
  assert.match((await touchIdProblem()) ?? "", /only available on macOS/);
});
