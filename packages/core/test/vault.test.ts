import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { accountState, migrateLegacy, openAccount, readSession } from "../src/account.js";
import { SecretStore } from "../src/secret/store.js";
import { checkPassword } from "../src/security/password.js";
import { Vault, WrongPasswordError } from "../src/security/vault.js";

const FAST_KDF = { memory: 1024, passes: 1, parallelism: 1 };
const tmp = () => mkdtempSync(join(tmpdir(), "tgv-"));

test("vault: unlock with the right password only; data round-trips", () => {
  const path = join(tmp(), "vault.json");
  const v = Vault.create(path, "correct horse", FAST_KDF);
  const blob = v.encrypt("session", Buffer.from("secret session"));
  assert.ok(!blob.includes(Buffer.from("secret session")));

  const again = Vault.unlock(path, "correct horse");
  assert.equal(again.decrypt("session", blob).toString(), "secret session");
  assert.throws(() => Vault.unlock(path, "wrong horse"), WrongPasswordError);
});

test("vault: ciphertexts are bound to their purpose and tamper-evident", () => {
  const v = Vault.create(join(tmp(), "vault.json"), "password123", FAST_KDF);
  const blob = v.encrypt("session", Buffer.from("x"));
  assert.throws(() => v.decrypt("secret-chats", blob), /corrupted or was modified/);
  const tampered = Buffer.from(blob);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => v.decrypt("session", tampered), /corrupted or was modified/);
});

test("vault: password change keeps existing data readable and invalidates the old password", () => {
  const dir = tmp();
  const path = join(dir, "vault.json");
  const v = Vault.create(path, "old-password", FAST_KDF);
  v.writeFile(join(dir, "session.enc"), "session", Buffer.from("auth key"));

  assert.throws(() => v.changePassword("not-the-old-one", "new-password", FAST_KDF), WrongPasswordError);
  v.changePassword("old-password", "new-password", FAST_KDF);

  assert.throws(() => Vault.unlock(path, "old-password"), WrongPasswordError);
  const reopened = Vault.unlock(path, "new-password");
  assert.equal(reopened.readFile(join(dir, "session.enc"), "session").toString(), "auth key");
});

test("vault: locked vault refuses to work", () => {
  const v = Vault.create(join(tmp(), "vault.json"), "password123", FAST_KDF);
  v.lock();
  assert.throws(() => v.encrypt("file", Buffer.from("x")), /vault is locked/);
});

test("secret store: encrypted on disk, close() zeroes keys and stops writes", () => {
  const dir = tmp();
  const vault = Vault.create(join(dir, "vault.json"), "password123", FAST_KDF);
  const store = new SecretStore(join(dir, "chats.enc"), vault);
  const key = randomBytes(256);
  store.put({
    id: 1, accessHash: 2n, peerId: 3n, peerName: "Peer", isOriginator: true, state: "ready", createdAt: 0,
    key, peerLayer: 144, layerNotified: true, rawOutSeq: 0, rawInSeq: 0, ttl: 0, outbox: [],
  });
  const onDisk = readFileSync(join(dir, "chats.enc"));
  assert.ok(!onDisk.includes(Buffer.from(key.toString("hex"))) && !onDisk.includes(Buffer.from("Peer")));

  const reopened = new SecretStore(join(dir, "chats.enc"), vault);
  assert.deepEqual(reopened.get(1)?.key, key);

  const chat = store.get(1)!;
  store.close();
  assert.ok(chat.key!.every((b) => b === 0));
  store.save();
  assert.deepEqual(readFileSync(join(dir, "chats.enc")), onDisk, "no write after close");
});

test("migration: legacy plaintext account becomes encrypted with nothing lost", () => {
  // point every path of the account into a temp dir
  const account = openAccount(tmp(), "+79990000000");
  const dir = tmp();
  Object.assign(account, {
    dir,
    vaultPath: join(dir, "vault.json"),
    infoPath: join(dir, "account.enc"),
    sessionPath: join(dir, "session.enc"),
    secretStorePath: join(dir, "secret-chats.enc"),
    downloadsDir: join(dir, "downloads"),
  });
  writeFileSync(join(dir, "account.json"), JSON.stringify({ phone: "+79990000000", apiId: 1, apiHash: "a".repeat(32) }));
  writeFileSync(join(dir, "session.txt"), "1SESSIONSTRING\n");
  writeFileSync(join(dir, "secret-chats.json"), JSON.stringify({ chats: {} }));
  mkdirSync(join(dir, "downloads", "5"), { recursive: true });
  writeFileSync(join(dir, "downloads", "5", "photo.jpg"), "jpeg bytes");
  assert.equal(accountState(account), "legacy");

  const vault = Vault.create(account.vaultPath, "password123", FAST_KDF);
  assert.deepEqual(migrateLegacy(account, vault), { files: 4 });

  assert.equal(accountState(account), "encrypted");
  for (const f of ["account.json", "session.txt", "secret-chats.json", join("downloads", "5", "photo.jpg")]) {
    assert.ok(!existsSync(join(dir, f)), `${f} must be deleted`);
  }
  assert.equal(readSession(account, vault), "1SESSIONSTRING");
  assert.equal(vault.readFile(join(dir, "downloads", "5", "photo.jpg.enc"), "file").toString(), "jpeg bytes");
  assert.equal(new SecretStore(account.secretStorePath, vault).all().length, 0);
  // running it again (e.g. after an interruption) is a no-op
  assert.deepEqual(migrateLegacy(account, vault), { files: 0 });
});

test("password policy: minimum length is enforced, weak passwords get a warning", () => {
  assert.ok(checkPassword("short").error);
  assert.ok(checkPassword("12345678").warning);
  assert.ok(checkPassword("aaaaaaaa").warning);
  assert.ok(checkPassword("abcdefgh").warning);
  assert.deepEqual(checkPassword("Quiet-forest-42 🌲"), {});
});
