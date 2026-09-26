import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { openAccount, type Account } from "../src/account.js";
import { openVault } from "../src/auth/login.js";
import type { Prompts } from "../src/prompts.js";
import { Vault } from "../src/security/vault.js";

/** An account whose files all live in a fresh temp directory. */
function tempAccount(): Account {
  const dir = mkdtempSync(join(tmpdir(), "tga-"));
  return {
    ...openAccount(dir, "+79990000000"),
    dir,
    vaultPath: join(dir, "vault.json"),
    infoPath: join(dir, "account.enc"),
    sessionPath: join(dir, "session.enc"),
    secretStorePath: join(dir, "secret-chats.enc"),
    downloadsDir: join(dir, "downloads"),
  };
}

// no interactive prompt may happen when the password comes from the command line
const noPrompts = new Proxy({}, { get: () => () => { throw new Error("unexpected prompt"); } }) as unknown as Prompts;

test("--password for an account that doesn't exist yet is an error", async () => {
  await assert.rejects(openVault(noPrompts, tempAccount(), "whatever1"), /not found/);
});

test("--password for an unencrypted (legacy) account is an error", async () => {
  const account = tempAccount();
  writeFileSync(join(account.dir, "session.txt"), "x");
  await assert.rejects(openVault(noPrompts, account, "whatever1"), /has no local password yet/);
});

test("--password unlocks an encrypted account; a wrong one fails without retries", async () => {
  const account = tempAccount();
  Vault.create(account.vaultPath, "right-password", { memory: 1024, passes: 1, parallelism: 1 });
  const vault = await openVault(noPrompts, account, "right-password");
  assert.ok(vault && !vault.locked);
  await assert.rejects(openVault(noPrompts, account, "wrong-password"), /Wrong local password/);
});
