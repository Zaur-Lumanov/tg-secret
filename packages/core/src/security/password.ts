import type { Prompts, Question } from "../prompts.js";
import { Vault, WrongPasswordError } from "./vault.js";

export const MIN_PASSWORD_LENGTH = 8;
export const UNLOCK_ATTEMPTS = 3;

const COMMON = new Set([
  "password", "password1", "passw0rd", "qwerty123", "qwertyui", "12345678", "123456789", "1234567890",
  "11111111", "00000000", "iloveyou", "abc12345", "qwerty12", "asdfghjk", "zxcvbnm1", "1q2w3e4r",
  "1qaz2wsx", "qwertyuiop", "87654321", "admin123", "letmein1", "telegram",
]);

/** Returns an error that forbids the password, or a warning the user may override. */
export function checkPassword(pw: string): { error?: string; warning?: string } {
  if ([...pw].length < MIN_PASSWORD_LENGTH) return { error: `The password is shorter than ${MIN_PASSWORD_LENGTH} characters` };
  const lower = pw.toLowerCase();
  if (COMMON.has(lower)) return { warning: "it is one of the most common passwords" };
  if (/^(.)\1+$/u.test(pw)) return { warning: "the password is a single repeated character" };
  if ("0123456789012345678998765432109876543210".includes(pw) || "abcdefghijklmnopqrstuvwxyz".includes(lower)) {
    return { warning: "the password is a simple sequence of characters" };
  }
  if (/^\d+$/.test(pw) && pw.length < 12) return { warning: "a digits-only password is easy to guess" };
  return {};
}

/** Thrown after UNLOCK_ATTEMPTS wrong passwords in a row. */
export class TooManyAttemptsError extends Error {
  constructor(attempts: number) {
    super(`Wrong password (${attempts}/${UNLOCK_ATTEMPTS})`);
  }
}

/** Asks for a new password twice until both entries match and it passes the checks. */
export async function askNewPassword(prompts: Prompts): Promise<string> {
  for (;;) {
    const pw = await prompts.secret({ id: "new-local-password", message: `New local password (min. ${MIN_PASSWORD_LENGTH} characters)` });
    const { error, warning } = checkPassword(pw);
    if (error) {
      prompts.notice("error", error);
      continue;
    }
    if (warning && !(await prompts.confirm({ id: "weak-password", message: `Weak password: ${warning}. Use it anyway?`, default: false }))) {
      continue;
    }
    const again = await prompts.secret({ id: "repeat-local-password", message: "Repeat the password" });
    if (again !== pw) {
      prompts.notice("error", "The passwords don't match, try again.");
      continue;
    }
    return pw;
  }
}

/** Asks until something is typed: an empty answer (a stray Enter) is not a password attempt. */
export async function askPassword(prompts: Prompts, question: Question): Promise<string> {
  for (;;) {
    const pw = await prompts.secret(question);
    if (pw !== "") return pw;
  }
}

/** Unlocks the vault with the password; throws TooManyAttemptsError after UNLOCK_ATTEMPTS wrong ones. */
export async function unlockVault(prompts: Prompts, path: string, phone: string): Promise<Vault> {
  for (let attempt = 1; ; attempt++) {
    const pw = await askPassword(prompts, { id: "local-password", message: `Local password for +${phone}` });
    try {
      return Vault.unlock(path, pw);
    } catch (e) {
      if (!(e instanceof WrongPasswordError)) throw e;
      if (attempt >= UNLOCK_ATTEMPTS) throw new TooManyAttemptsError(attempt);
      prompts.notice("error", `Wrong password (${attempt}/${UNLOCK_ATTEMPTS})`);
    }
  }
}
