import { randomInt } from "node:crypto";
import type { TelegramClient } from "teleproto";
import {
  accountState,
  forgetAccount,
  loadAccountInfo,
  migrateLegacy,
  readSession,
  saveAccountInfo,
  writeSession,
  type Account,
  type AccountInfo,
} from "../account.js";
import { createClient, rpcCode, type DebugLogger } from "../net/client.js";
import type { Prompts } from "../prompts.js";
import { displayName } from "../secret/manager.js";
import { askNewPassword } from "../security/password.js";
import { unlockInteractive } from "../security/unlock.js";
import { Vault, WrongPasswordError } from "../security/vault.js";
import { MyTelegramOrg, type ApiCredentials } from "./myTelegramOrg.js";

/** A password from the command line gets no retries: a wrong one ends the process. */
function unlockWithArgument(path: string, password: string): Vault {
  try {
    return Vault.unlock(path, password);
  } catch (e) {
    if (e instanceof WrongPasswordError) throw new Error("Wrong local password (--password)");
    throw e;
  }
}

/** Errors after which it makes sense to ask for the code / password again. */
const RETRYABLE = /PHONE_CODE_INVALID|PHONE_CODE_EMPTY|PASSWORD_HASH_INVALID|Code is empty|Password is empty/;

export interface Session {
  client: TelegramClient;
  vault: Vault;
}

/**
 * Unlocks the account's vault with the local password. An account in the old plaintext
 * layout is encrypted first. Returns undefined for a brand-new account (no vault yet).
 */
export async function openVault(prompts: Prompts, account: Account, password?: string): Promise<Vault | undefined> {
  const state = accountState(account);
  if (password !== undefined && state !== "encrypted") {
    throw new Error(
      state === "new"
        ? `Account +${account.phone} not found: a password argument only works for an already signed-in number. Run without --password to sign in.`
        : `Account +${account.phone} has no local password yet. Run without --password to set one.`,
    );
  }
  switch (state) {
    case "encrypted": {
      const vault =
        password !== undefined
          ? unlockWithArgument(account.vaultPath, password)
          : await unlockInteractive(prompts, account.vaultPath, account.phone);
      // finishes a migration that was interrupted after the vault had been created
      migrateLegacy(account, vault);
      return vault;
    }
    case "legacy": {
      prompts.notice("warning", `The data of +${account.phone} (authorization and secret chat keys) is stored on disk unencrypted.`);
      prompts.notice("hint", "Set a local password — everything will be encrypted, no need to sign in again.");
      const vault = Vault.create(account.vaultPath, await askNewPassword(prompts));
      const { files } = migrateLegacy(account, vault);
      prompts.notice("success", `✔ Files encrypted: ${files}; the plaintext copies were overwritten and deleted.`);
      return vault;
    }
    case "new":
      return undefined;
  }
}

/**
 * Returns a connected, authorized client and the unlocked vault for the account.
 * Missing pieces are obtained interactively: local password, API keys from my.telegram.org,
 * the MTProto login. For a new account the local password is created after the login,
 * and nothing is written to disk before that.
 */
export interface AuthorizeOptions {
  /** local password for an already encrypted account, instead of asking (no retries) */
  password?: string;
  debug?: DebugLogger;
}

export async function ensureAuthorized(prompts: Prompts, account: Account, options: AuthorizeOptions = {}): Promise<Session> {
  const { password, debug } = options;
  const phone = "+" + account.phone;
  let vault = await openVault(prompts, account, password);

  let info: AccountInfo | undefined = vault && loadAccountInfo(account, vault);
  if (!info) {
    prompts.notice("title", `Number ${phone} is not signed in yet.`);
    const creds = await obtainApiCredentials(prompts, phone);
    info = { phone, ...creds };
  }

  const client = createClient(vault ? readSession(account, vault) : "", info.apiId, info.apiHash, debug);
  const slow = setTimeout(() => prompts.notice("warning", "No connection to Telegram, still trying…"), 5000);
  try {
    await client.connect();
  } finally {
    clearTimeout(slow);
  }

  if (!(await client.checkAuthorization())) {
    prompts.notice("title", "Signing in to Telegram");
    try {
      await client.start({
        phoneNumber: phone,
        phoneCode: async (viaApp) =>
          prompts.text({ id: "phone-code", message: `Confirmation code${viaApp ? " (sent to the Telegram app)" : " (SMS)"}` }),
        password: (hint) => prompts.secret({ id: "cloud-password", message: `2FA cloud password${hint ? ` (hint: ${hint})` : ""}` }),
        onError: async (err) => {
          prompts.notice("error", `Error: ${err.message}`);
          return !RETRYABLE.test(rpcCode(err)); // true = stop
        },
      });
    } catch (e) {
      if (/API_ID_INVALID|API_ID_PUBLISHED_FLOOD/.test(rpcCode(e))) {
        // don't keep unusable keys: the next run will obtain them again
        forgetAccount(account);
        throw new Error("Telegram rejected api_id/api_hash — this number's data was reset, sign in again.");
      }
      throw e;
    }
  }

  const me = await client.getMe();
  info = { ...info, userId: me.id.toString(), name: displayName(me) };

  if (!vault) {
    prompts.notice("title", "Choose a local password.");
    prompts.notice(
      "hint",
      "It encrypts the authorization and secret chat keys on this computer. It is not your Telegram cloud password.",
      "It can't be recovered: if you forget it, you'll have to sign in again and secret chats will be lost.",
    );
    vault = Vault.create(account.vaultPath, await askNewPassword(prompts));
  }
  saveAccountInfo(account, vault, info);
  writeSession(account, vault, String(client.session.save()));
  return { client, vault };
}

async function obtainApiCredentials(prompts: Prompts, phone: string): Promise<ApiCredentials> {
  prompts.notice(
    "hint",
    "Step 1/2: getting API keys (api_id/api_hash) from my.telegram.org.",
    "The code arrives as a message from \"Telegram\" in the app (not by SMS).",
  );
  const org = new MyTelegramOrg();
  try {
    await org.sendCode(phone);
    for (let attempt = 1; ; attempt++) {
      const code = await prompts.text({ id: "my-telegram-org-code", message: "Code for my.telegram.org" });
      try {
        await org.login(code);
        break;
      } catch (e) {
        if (attempt >= 3) throw e;
        prompts.notice("error", `Rejected: ${(e as Error).message}`);
      }
    }
    let creds = await org.getCredentials();
    if (!creds) {
      prompts.notice("hint", "No app yet — creating one…");
      creds = await org.createApp({
        title: "tg secret cli",
        shortName: `tgsecretcli${randomInt(1000, 9999)}`,
        platform: "desktop",
      });
    }
    prompts.notice("success", `API keys received (api_id ${creds.apiId}).`);
    prompts.notice("hint", "Step 2/2: signing in — another code will arrive.");
    return creds;
  } catch (e) {
    prompts.notice("warning", `Could not get the keys automatically: ${(e as Error).message}`);
    prompts.notice("hint", "Enter them manually (https://my.telegram.org/apps → API development tools).");
    return askCredentials(prompts);
  } finally {
    await org.logout();
  }
}

async function askCredentials(prompts: Prompts): Promise<ApiCredentials> {
  for (;;) {
    const apiId = Number(await prompts.text({ id: "api-id", message: "api_id" }));
    const apiHash = (await prompts.text({ id: "api-hash", message: "api_hash" })).toLowerCase();
    if (Number.isInteger(apiId) && apiId > 0 && /^[0-9a-f]{32}$/.test(apiHash)) return { apiId, apiHash };
    prompts.notice("error", "api_id is a number, api_hash is 32 hex characters. Try again.");
  }
}
