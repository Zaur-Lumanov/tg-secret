import { randomBytes } from "node:crypto";

export const bufToBig = (buf: Buffer): bigint =>
  buf.length === 0 ? 0n : BigInt("0x" + buf.toString("hex"));

/** Big-endian, left-padded to `size` bytes. */
export function bigToBuf(value: bigint, size = 256): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const raw = Buffer.from(hex, "hex");
  if (raw.length > size) throw new Error("bigToBuf: value does not fit");
  return Buffer.concat([Buffer.alloc(size - raw.length), raw]);
}

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function randomBelow(n: bigint): bigint {
  const bytes = Math.ceil(n.toString(16).length / 2) + 8;
  return bufToBig(randomBytes(bytes)) % n;
}

export function isProbablePrime(n: bigint, rounds = 24): boolean {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r++;
  }
  outer: for (let i = 0; i < rounds; i++) {
    const a = 2n + randomBelow(n - 4n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let j = 0; j < r - 1; j++) {
      x = (x * x) % n;
      if (x === n - 1n) continue outer;
    }
    return false;
  }
  return true;
}

/**
 * Validates DH parameters from messages.getDhConfig:
 * p is a 2048-bit safe prime and g generates a subgroup of order (p-1)/2.
 * https://core.telegram.org/mtproto/security_guidelines
 */
export function validateDhParams(g: number, p: bigint): void {
  if (p.toString(2).length !== 2048) throw new Error("DH: p is not 2048-bit");
  const ok = (() => {
    switch (g) {
      case 2: return p % 8n === 7n;
      case 3: return p % 3n === 2n;
      case 4: return true;
      case 5: return [1n, 4n].includes(p % 5n);
      case 6: return [19n, 23n].includes(p % 24n);
      case 7: return [3n, 5n, 6n].includes(p % 7n);
      default: return false;
    }
  })();
  if (!ok) throw new Error(`DH: g=${g} is not a valid generator for p`);
  if (!isProbablePrime(p) || !isProbablePrime((p - 1n) / 2n)) {
    throw new Error("DH: p is not a safe prime");
  }
}

/** Checks that g_a / g_b is in the safe range [2^(2048-64), p - 2^(2048-64)]. */
export function checkGA(gA: bigint, p: bigint): void {
  const bound = 1n << (2048n - 64n);
  if (gA <= 1n || gA >= p - 1n || gA < bound || gA > p - bound) {
    throw new Error("DH: g_a/g_b is out of the safe range");
  }
}

export interface DhKeyPair {
  /** secret exponent (256 bytes) */
  secret: Buffer;
  /** g^secret mod p, 256 bytes big-endian */
  pub: Buffer;
}

/** Generates a DH key pair, mixing server-provided randomness into the secret as the docs require. */
export function generateKeyPair(g: number, p: bigint, serverRandom: Buffer): DhKeyPair {
  for (;;) {
    const secret = randomBytes(256);
    for (let i = 0; i < Math.min(secret.length, serverRandom.length); i++) secret[i] ^= serverRandom[i];
    const pubBig = modPow(BigInt(g), bufToBig(secret), p);
    try {
      checkGA(pubBig, p);
    } catch {
      continue;
    }
    return { secret, pub: bigToBuf(pubBig) };
  }
}

/** Computes the shared 256-byte key: (otherPub ^ secret) mod p. */
export function computeSharedKey(otherPub: Buffer, secret: Buffer, p: bigint): Buffer {
  const other = bufToBig(otherPub);
  checkGA(other, p);
  return bigToBuf(modPow(other, bufToBig(secret), p));
}
