import { randomBytes } from "node:crypto";
import type { Prompts } from "../prompts.js";
import { askNewPassword, checkPassword } from "./password.js";
import { Vault, WrongPasswordError, type Slot } from "./vault.js";
import { deleteHello, enrollHello, isHelloSupported } from "./windowsHello.js";
import { enrollYubikey, pivKekConsole } from "./yubikey.js";

/**
 * Unlock methods of an unlocked account: the local password (always present) plus any
 * number of YubiKeys and Windows Hello keys. Asking the user to confirm such changes with
 * the password is up to the caller (see verifyPassword).
 */
export class AccessManager {
  constructor(
    private readonly vault: Vault,
    private readonly prompts: Prompts,
    private readonly phone: string,
  ) {}

  list(): Slot[] {
    return Vault.slots(this.vault.path);
  }

  /** True if this is the local password; never changes anything. */
  verifyPassword(password: string): boolean {
    try {
      Vault.unlock(this.vault.path, password).lock();
      return true;
    } catch (e) {
      if (e instanceof WrongPasswordError) return false;
      throw e;
    }
  }

  /**
   * Replaces the local password. Without `next` the new one is asked through the prompts
   * (twice, with the strength checks). Only the master key is re-encrypted.
   */
  async changePassword(current: string, next?: string): Promise<void> {
    if (!this.verifyPassword(current)) throw new WrongPasswordError();
    next ??= await askNewPassword(this.prompts);
    const { error } = checkPassword(next);
    if (error) throw new Error(error);
    if (next === current) throw new Error("The new password is the same as the current one");
    this.vault.changePassword(current, next);
  }

  /**
   * Sets up a YubiKey through ykman (asking for its PIN and the like through the prompts),
   * then decrypts once with it as a check. The method is saved only if the check passes.
   */
  async addYubikey(label = "YubiKey"): Promise<Slot> {
    // no "+" in the subject: it separates attributes in RFC 4514 names
    const enrolled = await enrollYubikey(this.prompts, label, `CN=tg-secret ${this.phone}`);
    try {
      this.prompts.notice("hint", "Verifying: decrypting with the key, as on unlock.");
      const check = await pivKekConsole(this.prompts, { ...enrolled.slot, id: "", key: "", createdAt: 0 });
      const ok = check.equals(enrolled.kek);
      check.fill(0);
      if (!ok) throw new Error("verification failed: the YubiKey returned a different key, the method was not added");
      return this.vault.addSlot(enrolled.slot, enrolled.kek);
    } finally {
      enrolled.kek.fill(0);
    }
  }

  /** Why Windows Hello can't be added here, or undefined if it can. */
  async windowsHelloProblem(): Promise<string | undefined> {
    if (process.platform !== "win32") return "Windows Hello is only available on Windows";
    if (!(await isHelloSupported())) return "Windows Hello is not set up: enable a PIN or biometrics in Windows Settings";
    return undefined;
  }

  /** Windows only: creates a Windows Hello key (two confirmations in the Windows dialog). */
  async addWindowsHello(label = "Windows Hello"): Promise<Slot> {
    const problem = await this.windowsHelloProblem();
    if (problem) throw new Error(problem);
    // no "/" or "\": Windows Hello rejects such names with NTE_INVALID_PARAMETER (0x80090027)
    const credentialName = `tg-secret_${this.phone}_${randomBytes(4).toString("hex")}`;
    this.prompts.notice("action", "Confirm in the Windows Hello dialog (twice: key creation and verification)…");
    const { challenge, kek } = await enrollHello(credentialName);
    try {
      return this.vault.addSlot({ type: "windows-hello", label, credentialName, challenge }, kek);
    } finally {
      kek.fill(0);
    }
  }

  /**
   * Removes an unlock method; the password can't be removed. A Windows Hello key is deleted
   * from Windows too; a YubiKey keeps its key (delete it with `ykman piv keys delete <slot>`).
   */
  async remove(slotId: string): Promise<Slot> {
    const slot = this.list().find((s) => s.id === slotId);
    if (!slot) throw new Error("Unlock method not found");
    this.vault.removeSlot(slot.id);
    if (slot.type === "windows-hello") await deleteHello(slot.credentialName).catch(() => undefined);
    return slot;
  }
}
