import { randomBytes } from "node:crypto";
import type { Prompts } from "../prompts.js";
import { askNewPassword, checkPassword } from "./password.js";
import { Vault, WrongPasswordError, type Slot } from "./vault.js";
import { enrollTouchId, touchIdKek, touchIdProblem } from "./touchId.js";
import { deleteHello, enrollHello, isHelloSupported } from "./windowsHello.js";
import { enrollYubikey, pivKekConsole } from "./yubikey.js";

/**
 * Unlock methods of an unlocked account: the local password (always present) plus any
 * number of YubiKeys, Windows Hello and Touch ID keys. Asking the user to confirm such changes with
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

  /**
   * Windows Hello and Touch ID are one per account: they are bound to this computer and user,
   * so a second one would unlock with the same person and the same device.
   */
  private alreadyAdded(type: "windows-hello" | "touch-id", name: string): string | undefined {
    if (!this.list().some((s) => s.type === type)) return undefined;
    return `${name} is already added; to set it up again, remove it first`;
  }

  /** Why Windows Hello can't be added here (not Windows, not set up, already added), or undefined if it can. */
  async windowsHelloProblem(): Promise<string | undefined> {
    if (process.platform !== "win32") return "Windows Hello is only available on Windows";
    const added = this.alreadyAdded("windows-hello", "Windows Hello");
    if (added) return added;
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

  /** Why Touch ID can't be added here (not macOS, unavailable, already added), or undefined if it can. */
  async touchIdProblem(): Promise<string | undefined> {
    if (process.platform !== "darwin") return "Touch ID is only available on macOS";
    return this.alreadyAdded("touch-id", "Touch ID") ?? touchIdProblem();
  }

  /**
   * macOS only: creates a Secure Enclave key usable only with Touch ID, then derives the KEK
   * once with it as a check (one fingerprint). The method is saved only if the check passes.
   */
  async addTouchId(label = "Touch ID"): Promise<Slot> {
    const problem = await this.touchIdProblem();
    if (problem) throw new Error(problem);
    const { seKey, ephemeralPublicKey, kek } = await enrollTouchId();
    try {
      this.prompts.notice("action", "Verifying: touch the Touch ID sensor…");
      const check = await touchIdKek({ seKey, ephemeralPublicKey }, `add Touch ID to tg-secret for +${this.phone}`);
      const ok = check.equals(kek);
      check.fill(0);
      if (!ok) throw new Error("verification failed: Touch ID returned a different key, the method was not added");
      return this.vault.addSlot({ type: "touch-id", label, seKey, ephemeralPublicKey }, kek);
    } finally {
      kek.fill(0);
    }
  }

  /**
   * Removes an unlock method; the password can't be removed. A Windows Hello key is deleted
   * from Windows too; a Touch ID key exists only as the blob in its slot, so it goes with it;
   * a YubiKey keeps its key (delete it with `ykman piv keys delete <slot>`).
   */
  async remove(slotId: string): Promise<Slot> {
    const slot = this.list().find((s) => s.id === slotId);
    if (!slot) throw new Error("Unlock method not found");
    this.vault.removeSlot(slot.id);
    if (slot.type === "windows-hello") await deleteHello(slot.credentialName).catch(() => undefined);
    return slot;
  }
}
