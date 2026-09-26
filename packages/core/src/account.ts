import { existsSync, mkdirSync, readdirSync, readFileSync, rmdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { processAlive } from "./security/tempFiles.js";
import { secureDelete, type Vault } from "./security/vault.js";

/** Directory with one sub-directory per authorized phone number, inside the data directory. */
export const accountsDir = (dataDir: string): string => join(dataDir, "accounts");

export interface AccountInfo {
  phone: string;
  apiId: number;
  apiHash: string;
  userId?: string;
  name?: string;
}

export interface Account {
  phone: string;
  dir: string;
  /** wrapped master key; its presence means the account is encrypted */
  vaultPath: string;
  infoPath: string;
  sessionPath: string;
  secretStorePath: string;
  /** encrypted incoming files */
  downloadsDir: string;
  info?: AccountInfo;
}

/** Files of the old, unencrypted layout. */
const LEGACY = { info: "account.json", session: "session.txt", chats: "secret-chats.json" };

/** "+7 (999) 123-45-67" -> "79991234567" */
export function normalizePhone(input: string): string {
  const digits = input.replace(/\D/g, "");
  if (digits.length < 7 || digits.length > 15) throw new Error(`Invalid phone number: ${input}`);
  return digits;
}

export function openAccount(dataDir: string, phoneInput: string): Account {
  const phone = normalizePhone(phoneInput);
  const dir = join(accountsDir(dataDir), phone);
  return {
    phone,
    dir,
    vaultPath: join(dir, "vault.json"),
    infoPath: join(dir, "account.enc"),
    sessionPath: join(dir, "session.enc"),
    secretStorePath: join(dir, "secret-chats.enc"),
    downloadsDir: join(dir, "downloads"),
  };
}

export type AccountState = "new" | "legacy" | "encrypted";

export function accountState(account: Account): AccountState {
  if (existsSync(account.vaultPath)) return "encrypted";
  return Object.values(LEGACY).some((f) => existsSync(join(account.dir, f))) ? "legacy" : "new";
}

export function loadAccountInfo(account: Account, vault: Vault): AccountInfo | undefined {
  account.info = existsSync(account.infoPath) ? vault.readJson<AccountInfo>(account.infoPath, "account") : undefined;
  return account.info;
}

export function saveAccountInfo(account: Account, vault: Vault, info: AccountInfo): void {
  vault.writeJson(account.infoPath, "account", info);
  account.info = info;
}

export function readSession(account: Account, vault: Vault): string {
  return existsSync(account.sessionPath) ? vault.readFile(account.sessionPath, "session").toString("utf8") : "";
}

export function writeSession(account: Account, vault: Vault, session: string): void {
  vault.writeFile(account.sessionPath, "session", Buffer.from(session, "utf8"));
}

/** Removes API keys and session, keeping the vault and secret chat state. */
export function forgetAccount(account: Account): void {
  rmSync(account.infoPath, { force: true });
  rmSync(account.sessionPath, { force: true });
  account.info = undefined;
}

function* walk(dir: string): Generator<string> {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

/**
 * Encrypts an account stored in the old plaintext layout. Every file is written encrypted,
 * read back and compared before its plaintext original is overwritten and deleted, so an
 * interruption at any point loses nothing (the next start simply continues the migration).
 */
export function migrateLegacy(account: Account, vault: Vault): { files: number } {
  const steps: [string, string, Parameters<Vault["writeFile"]>[1]][] = [
    [join(account.dir, LEGACY.info), account.infoPath, "account"],
    [join(account.dir, LEGACY.session), account.sessionPath, "session"],
    [join(account.dir, LEGACY.chats), account.secretStorePath, "secret-chats"],
  ];
  for (const p of walk(account.downloadsDir)) {
    if (!p.endsWith(".enc") && !p.endsWith(".tmp")) steps.push([p, p + ".enc", "file"]);
  }

  let files = 0;
  for (const [from, to, purpose] of steps) {
    if (!existsSync(from)) continue;
    const plain = readFileSync(from);
    try {
      // the old session.txt may carry a trailing newline
      const data = purpose === "session" ? Buffer.from(plain.toString("utf8").trim()) : plain;
      vault.writeFile(to, purpose, data);
      if (!vault.readFile(to, purpose).equals(data)) throw new Error(`Verification of encrypted ${to} failed`);
    } finally {
      plain.fill(0);
    }
    secureDelete(from);
    files++;
  }
  return { files };
}

export class AccountLockedError extends Error {}

/** A lock file that is still empty this long after creation was left by a crash. */
const EMPTY_LOCK_GRACE_MS = 10_000;

/**
 * Only one process at a time may use an account: two would both advance the secret chat
 * counters and overwrite each other's secret-chats.enc. The lock is a file holding the
 * owner's pid; one left behind by a process that no longer exists is taken over.
 * Returns the release function; the lock is also released when the process exits.
 */
export function lockAccount(account: Account): () => void {
  mkdirSync(account.dir, { recursive: true, mode: 0o700 });
  const path = join(account.dir, "lock");
  for (;;) {
    try {
      writeFileSync(path, String(process.pid), { flag: "wx" });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    let owner = 0;
    let age = 0;
    try {
      owner = Number(readFileSync(path, "utf8"));
      age = Date.now() - statSync(path).mtimeMs;
    } catch {
      continue; // released meanwhile
    }
    const held = owner ? owner !== process.pid && processAlive(owner) : age < EMPTY_LOCK_GRACE_MS;
    if (held) {
      throw new AccountLockedError(
        `Account +${account.phone} is already open in another process${owner ? ` (pid ${owner})` : ""}. Close it first.`,
      );
    }
    rmSync(path, { force: true });
  }

  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    process.off("exit", release);
    try {
      if (Number(readFileSync(path, "utf8")) === process.pid) rmSync(path, { force: true });
      rmdirSync(account.dir); // only succeeds for an account that was never signed in
    } catch {
      // not ours anymore, or the directory has data
    }
  };
  process.on("exit", release);
  return release;
}

/** True if another live process holds the account's lock (see lockAccount). */
export function accountInUse(account: Account): boolean {
  try {
    const owner = Number(readFileSync(join(account.dir, "lock"), "utf8"));
    return owner > 0 && owner !== process.pid && processAlive(owner);
  } catch {
    return false;
  }
}

export interface AccountListItem {
  phone: string;
  state: AccountState;
}

export function listAccounts(dataDir: string): AccountListItem[] {
  const root = accountsDir(dataDir);
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .filter((name) => /^\d{7,15}$/.test(name))
    .map((name) => ({ phone: "+" + name, state: accountState(openAccount(dataDir, name)) }))
    .filter((a) => a.state !== "new");
}
