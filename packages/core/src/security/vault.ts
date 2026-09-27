import {
  argon2Sync,
  createCipheriv,
  createDecipheriv,
  createSecretKey,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Local encryption of account data.
 *
 *   unlock slot → KEK ──AES-256-GCM──▶ wrapped master key (one copy per slot in vault.json)
 *   master key (random, 256 bit) ──AES-256-GCM──▶ session, API keys, secret chat keys, files
 *
 * Slots: the password (Argon2id → KEK, always present), YubiKey PIV (KEK decrypted by the
 * key's RSA private key), Windows Hello (KEK derived from a Windows Hello signature),
 * Touch ID (KEK from ECDH with a Secure Enclave key).
 * Changing the password or adding a slot only re-wraps the master key. Each ciphertext is
 * bound to its purpose (GCM additional data), so e.g. a file can't be swapped for the session.
 */

const MAGIC = Buffer.from("TGSV1");
const IV_LEN = 12;
const TAG_LEN = 16;

export interface KdfParams {
  alg: "argon2id";
  /** KiB */
  memory: number;
  passes: number;
  parallelism: number;
  salt: string;
}

interface SlotBase {
  id: string;
  /** base64 of MAGIC + iv + tag + master key wrapped with this slot's KEK */
  key: string;
  createdAt: number;
}

export interface PasswordSlot extends SlotBase {
  type: "password";
  kdf: KdfParams;
}

export interface PivSlot extends SlotBase {
  type: "yubikey-piv";
  label: string;
  serial: number;
  /** PIV key slot, hex: "9d", "82"… */
  pivSlot: string;
  /** SHA-1 of the slot's certificate, used to find the key through Windows */
  certThumbprint: string;
  /** the KEK, RSA-OAEP(SHA-1) encrypted to the YubiKey's public key, base64 */
  encryptedKek: string;
  /** Windows only: where the PIN was entered last time */
  pinEntry?: "console" | "windows";
}

export interface HelloSlot extends SlotBase {
  type: "windows-hello";
  label: string;
  /** name of the Windows Hello key credential */
  credentialName: string;
  /** signed by Windows Hello; the signature hashed gives the KEK */
  challenge: string;
}

export interface TouchIdSlot extends SlotBase {
  type: "touch-id";
  label: string;
  /** the Secure Enclave key (CryptoKit dataRepresentation): only this Mac can use it, after Touch ID */
  seKey: string;
  /** X9.63 public key of a one-time P-256 key; ECDH with the Secure Enclave key gives the KEK */
  ephemeralPublicKey: string;
}

export type Slot = PasswordSlot | PivSlot | HelloSlot | TouchIdSlot;
/** A slot as it is being added: the vault fills in id, key and createdAt. */
export type NewSlot = Omit<PivSlot, keyof SlotBase> | Omit<HelloSlot, keyof SlotBase> | Omit<TouchIdSlot, keyof SlotBase>;

interface VaultFile {
  version: 2;
  slots: Slot[];
}

interface VaultFileV1 {
  version: 1;
  kdf: KdfParams;
  key: string;
}

function readVaultFile(path: string): VaultFile {
  const file = JSON.parse(readFileSync(path, "utf8")) as VaultFile | VaultFileV1;
  if (file.version === 1) {
    return { version: 2, slots: [{ id: "password", type: "password", kdf: file.kdf, key: file.key, createdAt: 0 }] };
  }
  if (file.version !== 2 || !Array.isArray(file.slots)) throw new Error("Unsupported vault.json format");
  return file;
}

function passwordSlot(file: VaultFile): PasswordSlot {
  const slot = file.slots.find((s): s is PasswordSlot => s.type === "password");
  if (!slot || slot.kdf.alg !== "argon2id") throw new Error("vault.json has no password");
  return slot;
}

/** ~0.4 s and 256 MiB per attempt: cheap for the user, expensive for brute force. */
export const DEFAULT_KDF = { memory: 256 * 1024, passes: 3, parallelism: 4 };

export class WrongPasswordError extends Error {
  constructor() {
    super("Wrong password");
  }
}

export type Purpose = "account" | "session" | "secret-chats" | "file";

function deriveKek(password: string, kdf: KdfParams): Buffer {
  const message = Buffer.from(password.normalize("NFC"), "utf8");
  try {
    return argon2Sync("argon2id", {
      message,
      nonce: Buffer.from(kdf.salt, "base64"),
      memory: kdf.memory,
      passes: kdf.passes,
      parallelism: kdf.parallelism,
      tagLength: 32,
    });
  } finally {
    message.fill(0);
  }
}

function seal(key: KeyObject | Buffer, aad: string, plain: Buffer): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad));
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), data]);
}

function open(key: KeyObject | Buffer, aad: string, blob: Buffer): Buffer {
  if (blob.length < MAGIC.length + IV_LEN + TAG_LEN || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("The file is not data encrypted by this client");
  }
  let off = MAGIC.length;
  const iv = blob.subarray(off, (off += IV_LEN));
  const tag = blob.subarray(off, (off += TAG_LEN));
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(blob.subarray(off)), decipher.final()]);
}

/** Writes via a temp file + fsync + rename, so a crash never leaves a half-written file. */
export function atomicWrite(path: string, data: Buffer | string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, typeof data === "string" ? Buffer.from(data) : data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/**
 * Best-effort removal of a plaintext file: overwrite with random bytes, then unlink.
 * On SSDs and copy-on-write file systems the old blocks may survive; see README.
 */
export function secureDelete(path: string): void {
  if (!existsSync(path)) return;
  const { size } = statSync(path);
  const fd = openSync(path, "r+");
  try {
    for (let off = 0; off < size; off += 1 << 20) {
      const chunk = randomBytes(Math.min(1 << 20, size - off));
      writeSync(fd, chunk, 0, chunk.length, off);
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  unlinkSync(path);
}

function makePasswordSlot(raw: Buffer, password: string, cost: typeof DEFAULT_KDF): PasswordSlot {
  const kdf: KdfParams = { alg: "argon2id", ...cost, salt: randomBytes(16).toString("base64") };
  const kek = deriveKek(password, kdf);
  try {
    return {
      id: "password",
      type: "password",
      kdf,
      key: seal(kek, "vault-key", raw).toString("base64"),
      createdAt: Math.floor(Date.now() / 1000),
    };
  } finally {
    kek.fill(0);
  }
}

export class Vault {
  /** The master key lives in a KeyObject (native memory, not the JS heap). */
  private key?: KeyObject;

  private constructor(
    readonly path: string,
    key: KeyObject,
  ) {
    this.key = key;
  }

  static exists(path: string): boolean {
    return existsSync(path);
  }

  static create(path: string, password: string, kdfCost = DEFAULT_KDF): Vault {
    const raw = randomBytes(32);
    try {
      const vault = new Vault(path, createSecretKey(raw));
      const file: VaultFile = { version: 2, slots: [makePasswordSlot(raw, password, kdfCost)] };
      atomicWrite(path, JSON.stringify(file, null, 2));
      return vault;
    } finally {
      raw.fill(0);
    }
  }

  /** Unlock slots (with wrapped keys) as stored in vault.json; readable without unlocking. */
  static slots(path: string): Slot[] {
    return readVaultFile(path).slots;
  }

  static unlock(path: string, password: string): Vault {
    const slot = passwordSlot(readVaultFile(path));
    const kek = deriveKek(password, slot.kdf);
    try {
      return Vault.open(path, slot, kek, () => new WrongPasswordError());
    } finally {
      kek.fill(0);
    }
  }

  /** Unlocks with a KEK obtained from a hardware slot (YubiKey, Windows Hello). */
  static unlockWithKek(path: string, slotId: string, kek: Buffer): Vault {
    const slot = readVaultFile(path).slots.find((s) => s.id === slotId);
    if (!slot) throw new Error("Unlock method not found in vault.json");
    return Vault.open(path, slot, kek, () => new Error("The key does not match the vault"));
  }

  private static open(path: string, slot: Slot, kek: Buffer, onFail: () => Error): Vault {
    let raw: Buffer;
    try {
      raw = open(kek, "vault-key", Buffer.from(slot.key, "base64"));
    } catch {
      throw onFail();
    }
    try {
      return new Vault(path, createSecretKey(raw));
    } finally {
      raw.fill(0);
    }
  }

  /** Stores non-secret per-slot preferences (e.g. where a PIN was entered). */
  static updateSlotMeta(path: string, id: string, patch: Partial<Pick<PivSlot, "pinEntry" | "label">>): void {
    const file = readVaultFile(path);
    const slot = file.slots.find((s) => s.id === id);
    if (!slot || slot.type === "password") return;
    Object.assign(slot, patch);
    atomicWrite(path, JSON.stringify(file, null, 2));
  }

  /** Re-wraps the same master key with a new password; data files and other slots stay untouched. */
  changePassword(oldPassword: string, newPassword: string, kdfCost = DEFAULT_KDF): void {
    // proves knowledge of the old password (and that it's this vault)
    Vault.unlock(this.path, oldPassword).lock();
    const file = readVaultFile(this.path);
    const raw = this.requireKey().export();
    try {
      const updated = makePasswordSlot(raw, newPassword, kdfCost);
      file.slots = file.slots.map((s) => (s.type === "password" ? updated : s));
      atomicWrite(this.path, JSON.stringify(file, null, 2));
    } finally {
      raw.fill(0);
    }
  }

  /** Adds an unlock slot whose KEK was produced by a hardware authenticator. */
  addSlot(slot: NewSlot, kek: Buffer): Slot {
    const file = readVaultFile(this.path);
    const raw = this.requireKey().export();
    try {
      const full = {
        ...slot,
        id: randomBytes(6).toString("hex"),
        createdAt: Math.floor(Date.now() / 1000),
        key: seal(kek, "vault-key", raw).toString("base64"),
      } as Slot;
      file.slots.push(full);
      atomicWrite(this.path, JSON.stringify(file, null, 2));
      return full;
    } finally {
      raw.fill(0);
    }
  }

  removeSlot(id: string): void {
    const file = readVaultFile(this.path);
    const slot = file.slots.find((s) => s.id === id);
    if (!slot) throw new Error("Unlock method not found");
    if (slot.type === "password") throw new Error("The password can't be removed: it stays as the fallback unlock method");
    file.slots = file.slots.filter((s) => s.id !== id);
    atomicWrite(this.path, JSON.stringify(file, null, 2));
  }

  private requireKey(): KeyObject {
    if (!this.key) throw new Error("The vault is locked");
    return this.key;
  }

  get locked(): boolean {
    return !this.key;
  }

  /** Drops the master key. The KeyObject's native memory is released by the GC. */
  lock(): void {
    this.key = undefined;
  }

  encrypt(purpose: Purpose, plain: Buffer): Buffer {
    return seal(this.requireKey(), purpose, plain);
  }

  decrypt(purpose: Purpose, blob: Buffer): Buffer {
    try {
      return open(this.requireKey(), purpose, blob);
    } catch (e) {
      if (this.locked) throw e;
      throw new Error(`Failed to decrypt data (${purpose}): the file is corrupted or was modified`);
    }
  }

  writeFile(path: string, purpose: Purpose, plain: Buffer): void {
    atomicWrite(path, this.encrypt(purpose, plain));
  }

  readFile(path: string, purpose: Purpose): Buffer {
    return this.decrypt(purpose, readFileSync(path));
  }

  writeJson(path: string, purpose: Purpose, value: unknown): void {
    const plain = Buffer.from(JSON.stringify(value));
    try {
      this.writeFile(path, purpose, plain);
    } finally {
      plain.fill(0);
    }
  }

  readJson<T>(path: string, purpose: Purpose): T {
    const plain = this.readFile(path, purpose);
    try {
      return JSON.parse(plain.toString("utf8")) as T;
    } finally {
      plain.fill(0);
    }
  }
}
