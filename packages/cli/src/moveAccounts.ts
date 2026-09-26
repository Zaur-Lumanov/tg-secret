import { cpSync, existsSync, mkdirSync, readdirSync, renameSync, rmdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { accountInUse, accountsDir, listAccounts, openAccount } from "tg-secret-core";
import { c, type Terminal } from "./terminal.js";

/** Moves a directory, also across drives (rename fails there with EXDEV). */
function moveDir(from: string, to: string): void {
  try {
    renameSync(from, to);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EXDEV") throw e;
    cpSync(from, to, { recursive: true, errorOnExist: true });
    rmSync(from, { recursive: true, force: true });
  }
}

/**
 * Earlier versions kept accounts in ./accounts of the directory the client was started from.
 * If that folder has accounts, offers to move them into the data directory. Accounts that
 * already exist there, or are open in another process, are left where they are.
 */
export async function offerAccountsMove(term: Terminal, dataDir: string): Promise<void> {
  const oldRoot = process.cwd();
  const from = accountsDir(oldRoot);
  const to = accountsDir(dataDir);
  if (resolve(from) === resolve(to)) return;

  const movable = listAccounts(oldRoot)
    .map((a) => a.phone.slice(1))
    .filter((phone) => !existsSync(join(to, phone)) && !accountInUse(openAccount(oldRoot, phone)));
  if (!movable.length) return;

  term.log(
    c.yellow(`Found ${movable.length} account(s) in the old location ${from}: ${movable.map((p) => "+" + p).join(", ")}.`),
    c.dim(`Accounts are now kept in ${to}.`),
  );
  const answer = await term.ask(c.yellow("Move them there? (Y/n) "));
  if (/^n/i.test(answer)) {
    term.log(c.dim(`Not moved. To keep using them where they are, start with --data-dir "${oldRoot}".`));
    return;
  }

  mkdirSync(to, { recursive: true, mode: 0o700 });
  for (const phone of movable) moveDir(join(from, phone), join(to, phone));
  try {
    if (readdirSync(from).length === 0) rmdirSync(from);
  } catch {
    // something else is still there
  }
  term.log(c.green(`✔ Moved ${movable.length} account(s) to ${to}`));
}
