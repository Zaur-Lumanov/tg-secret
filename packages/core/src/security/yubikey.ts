/**
 * YubiKey PIV as an unlock method.
 *
 * Setup (ykman): an RSA-2048 key is generated on the YubiKey (PIN + touch required to use it)
 * with a self-signed certificate, so Windows can see it as a smart card. A random KEK is
 * encrypted to the public key with RSA-OAEP(SHA-1); only the YubiKey can decrypt it.
 *
 * Unlock, two ways to the same key:
 *  - console: PIN asked here, the card is driven directly over PC/SC (Windows, Linux, macOS);
 *  - windows: Windows decrypts through its smart card support and shows its own PIN dialog.
 */
import { execFileSync, spawn } from "node:child_process";
import { publicEncrypt, randomBytes, constants, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Prompts } from "../prompts.js";
import { PcscContext } from "./pcsc.js";
import { oaepDecodeSha1, Piv } from "./piv.js";
import { withDialogInFront } from "./foreground.js";
import { PowerShellError, runPowerShell } from "./powershell.js";
import type { PivSlot } from "./vault.js";

/** Retired key management slots, used when 9D is already taken by something else. */
const RETIRED_SLOTS = Array.from({ length: 20 }, (_, i) => (0x82 + i).toString(16));

export function findYkman(): string | undefined {
  try {
    const out = execFileSync(process.platform === "win32" ? "where" : "which", ["ykman"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const first = out.split(/\r?\n/).find(Boolean);
    if (first) return first.trim();
  } catch {
    // not on PATH
  }
  const candidates = [
    "C:\\Program Files\\Yubico\\YubiKey Manager CLI\\ykman.exe",
    "C:\\Program Files\\Yubico\\YubiKey Manager\\ykman.exe",
    "/Applications/YubiKey Manager.app/Contents/MacOS/ykman",
    "/usr/local/bin/ykman",
    "/opt/homebrew/bin/ykman",
  ];
  return candidates.find((p) => existsSync(p));
}

/** Factory defaults of every YubiKey PIV applet. */
const DEFAULT_PIN = "123456";
const DEFAULT_PUK = "12345678";
const DEFAULT_MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708";

/** ykman options whose value is a secret: masked in anything we print. */
const SECRET_OPTIONS = new Set(["--pin", "--new-pin", "--puk", "--new-puk", "--management-key", "--new-management-key"]);

export const maskArgs = (args: string[]): string[] => args.map((a, i) => (i > 0 && SECRET_OPTIONS.has(args[i - 1]) ? "***" : a));

/**
 * Runs ykman without ever giving it the console: every secret is passed as an option, stdin is
 * closed. Sharing the console with a child is unreliable on Windows — keystrokes race between
 * Node's pending console read and the child, so a PIN could partly end up in our own input line.
 *
 * ykman also gets its own throwaway data/config folder (XDG_*): it writes a device history file
 * on every call, and a folder it can't write (e.g. created by an elevated run) makes it crash.
 */
export class Ykman {
  private readonly home = mkdtempSync(join(tmpdir(), "tg-secret-ykman-"));
  private readonly env = { ...process.env, XDG_DATA_HOME: this.home, XDG_CONFIG_HOME: this.home };

  constructor(
    private readonly path: string,
    /** receives ykman's output lines, e.g. "Touch your YubiKey…" */
    private readonly onOutput: (line: string) => void,
  ) {}

  private failure(args: string[], stderr: string, fallback: string): Error {
    const lines = stderr
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const error = lines.find((l) => l.startsWith("ERROR:"))?.slice(6).trim() ?? lines.pop() ?? fallback;
    return new Error(`ykman ${maskArgs(args).join(" ")}: ${error}`);
  }

  /** Quick command; its output is returned. */
  text(args: string[]): string {
    try {
      return execFileSync(this.path, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: this.env });
    } catch (e) {
      throw this.failure(args, String((e as { stderr?: unknown }).stderr ?? ""), (e as Error).message);
    }
  }

  /** Longer command; ykman's messages (e.g. "Touch your YubiKey…") are shown as they come. */
  exec(args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.path, args, { stdio: ["ignore", "pipe", "pipe"], env: this.env });
      let stderr = "";
      const show = (chunk: Buffer) => {
        for (const line of chunk.toString("utf8").split(/\r?\n/)) {
          if (line.trim() && !line.startsWith("ERROR:")) this.onOutput(line.trim());
        }
      };
      child.stdout.on("data", show);
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString("utf8");
        show(d);
      });
      child.on("error", reject);
      child.on("close", (code) => (code === 0 ? resolve() : reject(this.failure(args, stderr, `exit code ${code}`))));
    });
  }

  dispose(): void {
    rmSync(this.home, { recursive: true, force: true });
  }
}

export interface PivInfo {
  defaultPin: boolean;
  defaultPuk: boolean;
  defaultManagementKey: boolean;
  /** the management key is stored on the YubiKey and unlocked with the PIN */
  managementKeyProtected: boolean;
  pinTriesLeft?: number;
  usedSlots: Set<string>;
}

export function parsePivInfo(text: string): PivInfo {
  const tries = /PIN tries remaining:\s*(\d+)/i.exec(text)?.[1];
  return {
    defaultPin: /Using default PIN/i.test(text),
    defaultPuk: /Using default PUK/i.test(text),
    defaultManagementKey: /Using default Management key/i.test(text),
    managementKeyProtected: /protected by PIN/i.test(text),
    pinTriesLeft: tries === undefined ? undefined : Number(tries),
    usedSlots: new Set([...text.matchAll(/^Slot ([0-9A-F]{2})\b/gim)].map((m) => m[1].toLowerCase())),
  };
}

/** PIV PIN/PUK: 6–8 characters, entered twice. */
async function askNewSecret(prompts: Prompts, what: "pin" | "puk"): Promise<string> {
  const name = `YubiKey ${what.toUpperCase()}`;
  for (;;) {
    const value = await prompts.secret({ id: `yubikey-new-${what}`, message: `New ${name} (6–8 characters)` });
    const bytes = Buffer.byteLength(value, "utf8");
    if (bytes < 6 || bytes > 8) {
      prompts.notice("error", `${name} must be 6 to 8 characters long (Latin letters and digits)`);
      continue;
    }
    if ((await prompts.secret({ id: `yubikey-repeat-${what}`, message: `Repeat ${name}` })) !== value) {
      prompts.notice("error", `${name} does not match, try again`);
      continue;
    }
    return value;
  }
}

// ---------------------------------------------------------------- setup

export interface EnrolledPiv {
  slot: Omit<PivSlot, "id" | "key" | "createdAt">;
  kek: Buffer;
}

/**
 * Interactive setup through ykman. Nothing is changed on the YubiKey without asking,
 * and the result is verified with a real unlock before it is saved.
 */
export async function enrollYubikey(prompts: Prompts, label: string, subject: string): Promise<EnrolledPiv> {
  const path = findYkman();
  if (!path) {
    throw new Error("ykman (YubiKey Manager CLI) not found. Install it: https://www.yubico.com/support/download/yubikey-manager/");
  }
  const ykman = new Ykman(path, (line) => prompts.notice("hint", `  ykman: ${line}`));
  try {
    return await enrollWith(ykman, prompts, label, subject);
  } finally {
    ykman.dispose();
  }
}

async function enrollWith(ykman: Ykman, prompts: Prompts, label: string, subject: string): Promise<EnrolledPiv> {
  const serials = ykman.text(["list", "--serials"]).split(/\s+/).filter(Boolean).map(Number);
  if (!serials.length) throw new Error("YubiKey not found — insert the key");
  const serial =
    serials.length === 1
      ? serials[0]
      : await prompts.choose({
          id: "yubikey-serial",
          message: "Several YubiKeys are connected, choose one",
          options: serials.map((s) => ({ value: s, label: `serial ${s}` })),
          default: serials[0],
        });
  const device = ["--device", String(serial)];

  const info = parsePivInfo(ykman.text([...device, "piv", "info"]));
  if (info.pinTriesLeft !== undefined && info.pinTriesLeft < 3) {
    prompts.notice("warning", `Warning: PIN tries left: ${info.pinTriesLeft}. At 0 the PIN is blocked (unblock it with the PUK).`);
  }

  // PIN
  let pin: string;
  if (info.defaultPin) {
    prompts.notice("warning", `YubiKey ${serial} has the factory PIN (123456), which makes key protection pointless. Set your own.`);
    pin = await askNewSecret(prompts, "pin");
    await ykman.exec([...device, "piv", "access", "change-pin", "--pin", DEFAULT_PIN, "--new-pin", pin]);
    prompts.notice("success", "✔ YubiKey PIN changed");
  } else {
    pin = await prompts.secret({ id: "yubikey-pin", message: `YubiKey ${serial} PIN` });
  }

  // PUK
  if (
    info.defaultPuk &&
    (await prompts.confirm({
      id: "yubikey-change-puk",
      message: "The PUK is the factory one (12345678). The PUK unblocks the PIN after failed attempts — change it now?",
      default: true,
    }))
  ) {
    const puk = await askNewSecret(prompts, "puk");
    await ykman.exec([...device, "piv", "access", "change-puk", "--puk", DEFAULT_PUK, "--new-puk", puk]);
    prompts.notice("success", "✔ YubiKey PUK changed");
  }

  // Management key: authorizes writing keys and certificates to the PIV applet.
  let management: string[] = [];
  if (info.defaultManagementKey) {
    if (
      await prompts.confirm({
        id: "yubikey-replace-management-key",
        message: "The management key is the factory one: anyone can overwrite PIV keys with it. Replace it with a random one protected by the PIN?",
        default: true,
      })
    ) {
      await ykman.exec([
        ...device, "piv", "access", "change-management-key",
        "--management-key", DEFAULT_MANAGEMENT_KEY, "--pin", pin, "--protect", "--force",
      ]);
      prompts.notice("success", "✔ Management key replaced and protected by the PIN");
    } else {
      management = ["--management-key", DEFAULT_MANAGEMENT_KEY];
    }
  } else if (!info.managementKeyProtected) {
    management = ["--management-key", await prompts.secret({ id: "yubikey-management-key", message: "YubiKey management key (hex)" })];
  }

  let pivSlot = "9d";
  if (info.usedSlots.has("9d")) {
    const free = RETIRED_SLOTS.find((s) => !info.usedSlots.has(s));
    if (!free) throw new Error("No free PIV slots on the YubiKey");
    const useFree = await prompts.confirm({
      id: "yubikey-use-retired-slot",
      message: `Slot 9D is already in use (possibly by another program). Use free slot ${free.toUpperCase()}? Entering the PIN in the Windows dialog may not work with it.`,
      default: true,
    });
    if (!useFree) {
      throw new Error("Cancelled");
    }
    pivSlot = free;
  }

  const dir = mkdtempSync(join(tmpdir(), "tg-secret-yk-"));
  try {
    const pubPath = join(dir, "public.pem");
    prompts.notice("hint", `Generating an RSA-2048 key in slot ${pivSlot.toUpperCase()} (up to half a minute)…`);
    await ykman.exec([
      ...device, "piv", "keys", "generate",
      "--algorithm", "rsa2048", "--pin-policy", "once", "--touch-policy", "always",
      ...management, "--pin", pin, pivSlot, pubPath,
    ]);
    prompts.notice("action", "Creating a certificate so Windows can see the key. Touch the YubiKey when it blinks.");
    await ykman.exec([
      ...device, "piv", "certificates", "generate",
      "--subject", subject, "--valid-days", "3650",
      ...management, "--pin", pin, pivSlot, pubPath,
    ]);

    const certPem = ykman.text([...device, "piv", "certificates", "export", pivSlot, "-"]);
    const thumbprint = new X509Certificate(certPem).fingerprint.replace(/:/g, "").toUpperCase();

    const kek = randomBytes(32);
    const encryptedKek = publicEncrypt(
      { key: readFileSync(pubPath), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
      kek,
    ).toString("base64");
    return { slot: { type: "yubikey-piv", label, serial, pivSlot, certThumbprint: thumbprint, encryptedKek }, kek };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- unlock

/** Serial numbers of YubiKeys currently reachable over PC/SC (USB or NFC). Never throws. */
export async function connectedYubikeys(): Promise<Map<number, string>> {
  const found = new Map<number, string>();
  let ctx: PcscContext | undefined;
  try {
    ctx = new PcscContext();
    for (const reader of ctx.readers()) {
      try {
        const serial = await ctx.withCard(reader, async (card) => {
          const piv = new Piv(card);
          await piv.select();
          return piv.serial();
        });
        found.set(serial, reader);
      } catch {
        // empty reader, another kind of card, or busy
      }
    }
  } catch {
    // no PC/SC service, or no readers at all
  } finally {
    ctx?.close();
  }
  return found;
}

/** Console path: PIN asked here, the YubiKey decrypts the KEK after the touch. */
export async function pivKekConsole(prompts: Prompts, slot: PivSlot): Promise<Buffer> {
  const reader = (await connectedYubikeys()).get(slot.serial);
  if (!reader) throw new Error(`YubiKey ${slot.serial} not found — insert the key`);
  const pin = await prompts.secret({ id: "yubikey-pin", message: `YubiKey ${slot.serial} PIN` });
  const ctx = new PcscContext();
  try {
    return await ctx.withCard(reader, async (card) => {
      const piv = new Piv(card);
      await piv.select();
      await piv.verifyPin(pin);
      prompts.notice("action", "Touch the YubiKey (it is blinking)…");
      const em = await piv.rsaRaw(parseInt(slot.pivSlot, 16), Buffer.from(slot.encryptedKek, "base64"));
      try {
        return oaepDecodeSha1(em);
      } finally {
        em.fill(0);
      }
    });
  } finally {
    ctx.close();
  }
}

const WINDOWS_ERRORS: Record<string, string> = {
  CERT_NOT_FOUND:
    "Windows can't see this YubiKey's certificate. Unplug and reinsert the key (Windows picks up certificates on insertion) or enter the PIN in the console.",
  NO_PRIVATE_KEY: "Windows could not find the private key for the YubiKey certificate. Try entering the PIN in the console.",
};

/** Windows path: Windows shows its smart card PIN dialog and decrypts through the smart card stack. */
export async function pivKekWindows(prompts: Prompts, slot: PivSlot): Promise<Buffer> {
  prompts.notice("action", "Enter the PIN in the Windows dialog, then touch the YubiKey when it blinks…");
  try {
    const script = String.raw`
$tp = [Console]::In.ReadLine(); $data = [Convert]::FromBase64String([Console]::In.ReadLine())
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $tp } | Select-Object -First 1
if (-not $cert) { [Console]::Error.WriteLine('CERT_NOT_FOUND: '); exit 2 }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if (-not $rsa) { [Console]::Error.WriteLine('NO_PRIVATE_KEY: '); exit 3 }
$plain = $rsa.Decrypt($data, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
[Console]::Out.Write([Convert]::ToBase64String($plain))`;
    const out = await withDialogInFront(() => runPowerShell(script, `${slot.certThumbprint}\n${slot.encryptedKek}\n`));
    return Buffer.from(out, "base64");
  } catch (e) {
    if (e instanceof PowerShellError && WINDOWS_ERRORS[e.code]) throw new Error(WINDOWS_ERRORS[e.code]);
    throw e;
  }
}
