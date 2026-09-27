/**
 * Touch ID as an unlock method (macOS). A native helper (native/touchid.swift) creates a
 * P-256 key inside the Secure Enclave that can be used only after Touch ID, for every use.
 * On enrollment the core makes a one-time P-256 key pair; ECDH between it and the Secure
 * Enclave key gives the KEK. The one-time private key is dropped, so afterwards the KEK can
 * only be computed again by the Secure Enclave, with its public half and a fingerprint.
 * The same scheme as age-plugin-se.
 */
import { spawn } from "node:child_process";
import { createECDH, hkdfSync } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseFailure } from "./powershell.js";

/** same relative path from src/security and dist/security */
const HELPER = fileURLToPath(new URL("../../native/tg-secret-touchid", import.meta.url));

export class TouchIdError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

function runHelper(command: string, stdin = ""): Promise<string[]> {
  if (!existsSync(HELPER)) {
    return Promise.reject(
      new TouchIdError(
        "the Touch ID helper is not built: run `yarn build` in the repository (needs the Xcode Command Line Tools)",
        "NOT_BUILT",
      ),
    );
  }
  return new Promise((resolve, reject) => {
    const child = spawn(HELPER, [command]);
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (err += d.toString("utf8")));
    child.on("error", reject);
    child.on("close", (status) => {
      if (status === 0) return resolve(out.trim().split("\n"));
      const failure = parseFailure(err, status);
      reject(new TouchIdError(failure.message, failure.code));
    });
    child.stdin.end(stdin);
  });
}

const KEK_INFO = Buffer.from("tg-secret touch-id kek");

export const kekFromShared = (shared: Buffer): Buffer => Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), KEK_INFO, 32));

/** Why Touch ID can't be used on this computer, or undefined if it can. */
export async function touchIdProblem(): Promise<string | undefined> {
  if (process.platform !== "darwin") return "Touch ID is only available on macOS";
  try {
    await runHelper("check");
    return undefined;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

/** The enrollment math: a one-time key pair against the Secure Enclave public key. */
export function wrapToPublicKey(publicKey: Buffer): { ephemeralPublicKey: Buffer; kek: Buffer } {
  const ecdh = createECDH("prime256v1");
  const ephemeralPublicKey = ecdh.generateKeys();
  const shared = ecdh.computeSecret(publicKey);
  try {
    return { ephemeralPublicKey, kek: kekFromShared(shared) };
  } finally {
    shared.fill(0);
  }
}

/** Creates a Secure Enclave key (no fingerprint needed yet) and the new slot's KEK. */
export async function enrollTouchId(): Promise<{ seKey: string; ephemeralPublicKey: string; kek: Buffer }> {
  const [seKey, publicKey] = await runHelper("create");
  const { ephemeralPublicKey, kek } = wrapToPublicKey(Buffer.from(publicKey, "base64"));
  return { seKey, ephemeralPublicKey: ephemeralPublicKey.toString("base64"), kek };
}

/** Asks for Touch ID; `reason` completes the system dialog's "… is trying to <reason>". */
export async function touchIdKek(slot: { seKey: string; ephemeralPublicKey: string }, reason: string): Promise<Buffer> {
  const [shared] = await runHelper("derive", `${reason.replace(/\n/g, " ")}\n${slot.seKey}\n${slot.ephemeralPublicKey}\n`);
  const bytes = Buffer.from(shared, "base64");
  try {
    return kekFromShared(bytes);
  } finally {
    bytes.fill(0);
  }
}
