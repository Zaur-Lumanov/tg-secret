import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { AccountLockedError, lockAccount, openAccount } from "../src/account.js";

const freshAccount = () => openAccount(mkdtempSync(join(tmpdir(), "tgl-")), "+79990000000");
/** The pid of a process that has already exited. */
const deadPid = () => spawnSync(process.execPath, ["-e", ""]).pid!;

test("an account can be open in one process only", () => {
  const account = freshAccount();
  const release = lockAccount(account);
  // another process holding it looks like this: its live pid in the lock file
  release();
  mkdirSync(account.dir, { recursive: true });
  writeFileSync(join(account.dir, "lock"), String(process.ppid));
  assert.throws(() => lockAccount(account), (e: unknown) => e instanceof AccountLockedError && /already open/.test(String(e)));
});

test("a lock left by a dead process is taken over; release removes it", () => {
  const account = freshAccount();
  mkdirSync(account.dir, { recursive: true });
  writeFileSync(join(account.dir, "lock"), String(deadPid()));
  const release = lockAccount(account);
  release();
  assert.ok(!existsSync(join(account.dir, "lock")));
  assert.ok(!existsSync(account.dir), "an empty account directory is removed");
});

test("an empty lock file is respected while fresh and taken over when old", () => {
  const account = freshAccount();
  mkdirSync(account.dir, { recursive: true });
  const path = join(account.dir, "lock");
  writeFileSync(path, "");
  assert.throws(() => lockAccount(account), AccountLockedError);
  const old = new Date(Date.now() - 60_000);
  utimesSync(path, old, old);
  lockAccount(account)();
});
