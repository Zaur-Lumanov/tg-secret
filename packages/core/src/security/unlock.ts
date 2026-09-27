import type { Prompts } from "../prompts.js";
import { askPassword, TooManyAttemptsError, UNLOCK_ATTEMPTS, unlockVault } from "./password.js";
import { helloKek } from "./windowsHello.js";
import { connectedYubikeys, pivKekConsole, pivKekWindows } from "./yubikey.js";
import { Vault, WrongPasswordError, type PivSlot, type Slot } from "./vault.js";

export function describeSlot(slot: Slot): string {
  switch (slot.type) {
    case "password":
      return "Local password";
    case "yubikey-piv":
      return `YubiKey "${slot.label}" (serial ${slot.serial}, slot ${slot.pivSlot.toUpperCase()})`;
    case "windows-hello":
      return `Windows Hello "${slot.label}"`;
  }
}

/** Obtains the KEK of a hardware slot, asking the user whatever that method needs. */
export async function slotKek(prompts: Prompts, slot: Exclude<Slot, { type: "password" }>, vaultPath: string): Promise<Buffer> {
  if (slot.type === "windows-hello") {
    if (process.platform !== "win32") throw new Error("Windows Hello is only available on Windows");
    prompts.notice("action", "Confirm in the Windows Hello dialog (if you can't see it, it may be on the taskbar)…");
    return helloKek(slot.credentialName, slot.challenge);
  }
  return pivKek(prompts, slot, vaultPath);
}

async function pivKek(prompts: Prompts, slot: PivSlot, vaultPath: string): Promise<Buffer> {
  if (process.platform !== "win32") return pivKekConsole(prompts, slot);
  const entry = await prompts.choose<"console" | "windows">({
    id: "yubikey-pin-entry",
    message: "Where to enter the YubiKey PIN",
    options: [
      { value: "console", label: "in the console" },
      { value: "windows", label: "in a Windows dialog" },
    ],
    default: slot.pinEntry ?? "console",
  });
  if (entry !== slot.pinEntry) Vault.updateSlotMeta(vaultPath, slot.id, { pinEntry: entry });
  return entry === "windows" ? pivKekWindows(prompts, slot) : pivKekConsole(prompts, slot);
}

/**
 * Unlocks the vault with any of its methods. With only a password it is the plain password
 * prompt; otherwise a menu, defaulting to a registered YubiKey that is plugged in.
 * Wrong passwords still count towards the 3-attempt limit (then TooManyAttemptsError);
 * hardware failures return to the menu.
 */
export async function unlockInteractive(prompts: Prompts, path: string, phone: string): Promise<Vault> {
  const slots = Vault.slots(path);
  if (!slots.some((s) => s.type !== "password")) return unlockVault(prompts, path, phone);

  const connected = await connectedYubikeys();
  const preferred = slots.find((s) => s.type === "yubikey-piv" && connected.has(s.serial)) ?? slots[0];
  let passwordFailures = 0;

  for (;;) {
    const slot = await prompts.choose({
      id: "unlock-method",
      message: `Unlock +${phone}`,
      options: slots.map((s) => ({ value: s, label: describeSlot(s) })),
      default: preferred,
    });
    try {
      if (slot.type === "password") {
        return Vault.unlock(path, await askPassword(prompts, { id: "local-password", message: "Local password" }));
      }
      const kek = await slotKek(prompts, slot, path);
      try {
        return Vault.unlockWithKek(path, slot.id, kek);
      } finally {
        kek.fill(0);
      }
    } catch (e) {
      if (e instanceof WrongPasswordError) {
        passwordFailures++;
        if (passwordFailures >= UNLOCK_ATTEMPTS) throw new TooManyAttemptsError(passwordFailures);
        prompts.notice("error", `Wrong password (${passwordFailures}/${UNLOCK_ATTEMPTS})`);
      } else {
        prompts.notice("error", e instanceof Error ? e.message : String(e));
      }
    }
  }
}
