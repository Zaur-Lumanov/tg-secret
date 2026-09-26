import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { offerAccountsMove } from "../src/moveAccounts.js";
import type { Terminal } from "../src/terminal.js";

function fakeTerm(answer: string): Terminal {
  return { ask: async () => answer, log: () => undefined } as unknown as Terminal;
}

function oldLayout(): { cwd: string; dataDir: string } {
  const cwd = mkdtempSync(join(tmpdir(), "tgm-old-"));
  const dataDir = mkdtempSync(join(tmpdir(), "tgm-new-"));
  for (const phone of ["79990000001", "79990000002"]) {
    mkdirSync(join(cwd, "accounts", phone), { recursive: true });
    writeFileSync(join(cwd, "accounts", phone, "vault.json"), phone);
  }
  // already present in the new location: must stay untouched in both places
  mkdirSync(join(dataDir, "accounts", "79990000002"), { recursive: true });
  writeFileSync(join(dataDir, "accounts", "79990000002", "vault.json"), "newer");
  return { cwd, dataDir };
}

test("accounts from ./accounts are moved into the data directory on confirmation", async (t) => {
  const { cwd, dataDir } = oldLayout();
  const before = process.cwd();
  process.chdir(cwd);
  t.after(() => process.chdir(before));

  await offerAccountsMove(fakeTerm(""), dataDir);

  assert.equal(readFileSync(join(dataDir, "accounts", "79990000001", "vault.json"), "utf8"), "79990000001");
  assert.ok(!existsSync(join(cwd, "accounts", "79990000001")));
  assert.equal(readFileSync(join(dataDir, "accounts", "79990000002", "vault.json"), "utf8"), "newer");
  assert.ok(existsSync(join(cwd, "accounts", "79990000002")), "a clashing account is left where it was");
});

test("nothing is moved when the user declines", async (t) => {
  const { cwd, dataDir } = oldLayout();
  const before = process.cwd();
  process.chdir(cwd);
  t.after(() => process.chdir(before));

  await offerAccountsMove(fakeTerm("n"), dataDir);

  assert.ok(existsSync(join(cwd, "accounts", "79990000001")));
  assert.ok(!existsSync(join(dataDir, "accounts", "79990000001")));
});
